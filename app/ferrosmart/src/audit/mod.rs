// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! FerroSMART's audit records (`docs/architecture.md` §13.2).
//!
//! Every token request is recorded as the authorization server's audit event
//! of ITI-71 Get Authorization Token in the form of BALP 1.1.4's profile
//! `IHE.IUA.71`: type `110114` User Authentication, subtype `ITI-71`, the
//! client and the authorization server as agents, the person as
//! `agent:user` when one logged in, and the request itself, its secrets
//! left out, as the one `token-request` entity. Every login at the upstream
//! provider is recorded as a DICOM User Authentication event of type
//! `110122` Login (DICOM PS3.15 A.5.3.12), whose `AuditEvent` form is our
//! own design.
//!
//! Each record is a FHIR R4 `AuditEvent` written through `ihe-atna` into
//! FerroSMART's own store, in the transaction of the action it records: an
//! issued token and its record commit together, and a request that writes
//! nothing else commits its record alone or fails. With
//! `[ferrosmart.audit.feed]` the store is the outbox the `ihe-atna`
//! forwarder delivers from to an Audit Record Repository over the ITI-20
//! ATX: FHIR Feed (ITI TF-2 §3.20.4.2). No specification governs where the
//! records are kept or the failing closed: our own design.
//!
//! None of these events is an access to personal electronic health data, so
//! none is an access record of Regulation (EU) 2025/327 Annex II 3.2; the
//! patient picker, which reads Patient resources, writes that record.

pub mod exchanges;
pub mod outbox;

use self::outbox::StoreOutbox;

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use ihe_atna::balp::{
    APPLICATION, Coded, DCM, Described, Detail, Direction, Entity, EventKind, Exchange,
    IHE_TRANSACTIONS, LOGOUT, NetworkAddress, Observer, Outcome, Peer, RecordError, SYSTEM_OBJECT,
    USER_AUTHENTICATION,
};
use ihe_atna::user::{OnBehalfOf, User};
use secrecy::ExposeSecret as _;
use tokio::sync::Notify;
use url::Url;

use crate::store::audit::AuditRow;
use crate::store::{Store, StoreError, Transaction};

/// The canonical URL of BALP 1.1.4's profile of the ITI-71 audit event.
pub const IUA_71: &str = "https://profiles.ihe.net/ITI/BALP/StructureDefinition/IHE.IUA.71";

/// The subtype of the ITI-71 audit event (BALP 1.1.4 `IHE.IUA.71`,
/// `AuditEvent.subtype`).
pub const USER_AUTHORIZATION: Coded =
    Coded::fixed(IHE_TRANSACTIONS, "ITI-71", "User Authorization");

/// The type of the authorization server's own agent (BALP 1.1.4
/// `IHE.IUA.71`, `agent:auth-server`).
pub const AUTHZ_OAUTH_SERVICE: Coded = Coded::fixed(
    "https://profiles.ihe.net/ITI/BALP/CodeSystem/UserAgentTypes",
    "AuthzOauthService",
    "OAuth Authorization Server",
);

/// The token request parameters whose values a record leaves out.
///
/// They are the PKCE verifier the profile names, and the credentials RFC
/// 6749 has kept confidential (§10.3 to §10.5) with the client assertion of
/// RFC 7521.
pub const WITHHELD: [&str; 5] = [
    "code_verifier",
    "code",
    "refresh_token",
    "client_secret",
    "client_assertion",
];

/// How a client that named no `client_id` is shown as the source of a
/// token request. No specification governs the words: our own design.
pub const UNIDENTIFIED_CLIENT: &str = "unidentified client";

/// Why a record could not be stored.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RecordFailure {
    /// The `AuditEvent` could not be written.
    #[error("the AuditEvent could not be written")]
    Write(#[source] RecordError),
    /// The written `AuditEvent` is no UTF-8 text.
    #[error("the AuditEvent is no UTF-8 text")]
    Text(#[source] std::str::Utf8Error),
    /// The store could not keep it.
    #[error("the audit record could not be stored")]
    Store(#[source] StoreError),
}

/// FerroSMART as the recording system, and the wake of the feed's
/// forwarder.
#[derive(Debug, Clone)]
pub struct Audit {
    /// The recording system.
    observer: Arc<Observer>,
    /// Woken once a record is stored, so the forwarder sends it.
    stored: Arc<Notify>,
}

impl Audit {
    /// Returns the audit lane that names `observer` as the recording system.
    #[must_use]
    pub fn new(observer: Observer) -> Self {
        Self {
            observer: Arc::new(observer),
            stored: Arc::new(Notify::new()),
        }
    }

    /// Returns the row `exchange` is stored as: `kind`, and the person and
    /// the client it names.
    ///
    /// # Errors
    ///
    /// Returns the [`RecordFailure`] of an `AuditEvent` that could not be
    /// written.
    pub fn row(
        &self,
        exchange: &Exchange,
        kind: &'static str,
        subject: Option<&str>,
        client_id: Option<&str>,
    ) -> Result<AuditRow, RecordFailure> {
        let record = exchange
            .audit_event(&self.observer)
            .map_err(RecordFailure::Write)?
            .into_bytes();
        let document = std::str::from_utf8(record.expose_secret())
            .map_err(RecordFailure::Text)?
            .to_owned();
        Ok(AuditRow {
            recorded_at: exchange.recorded.to_string(),
            kind,
            outcome: exchange.outcome.code(),
            subject: subject.map(str::to_owned),
            client_id: client_id.map(str::to_owned),
            document,
        })
    }

    /// Stores the record `row` alone in `store`.
    ///
    /// # Errors
    ///
    /// Returns [`RecordFailure::Store`] when the store cannot keep it.
    pub async fn record(&self, store: &Store, row: &AuditRow) -> Result<(), RecordFailure> {
        store
            .record_audit(row)
            .await
            .map_err(RecordFailure::Store)?;
        self.committed();
        Ok(())
    }

    /// Writes the record of `exchange` in `tx` and commits both: the write
    /// and its record are kept together or not at all.
    ///
    /// # Errors
    ///
    /// Returns the [`RecordFailure`] of a record that could not be written,
    /// or of a commit that failed; nothing is kept then.
    pub async fn commit(
        &self,
        mut tx: Transaction,
        exchange: &Exchange,
        kind: &'static str,
        subject: Option<&str>,
        client_id: Option<&str>,
    ) -> Result<(), RecordFailure> {
        let row = self.row(exchange, kind, subject, client_id)?;
        tx.record(&row).await.map_err(RecordFailure::Store)?;
        tx.commit().await.map_err(RecordFailure::Store)?;
        self.committed();
        Ok(())
    }

    /// Commits `tx` with the record of `happening`.
    ///
    /// # Errors
    ///
    /// As [`Audit::commit`].
    pub async fn commit_happening(
        &self,
        tx: Transaction,
        happening: &Happening<'_>,
    ) -> Result<(), RecordFailure> {
        self.commit(
            tx,
            &happened(happening),
            happening.event.code(),
            happening.subject,
            happening.client_id,
        )
        .await
    }

    /// Wakes the forwarder once a record committed.
    pub fn committed(&self) {
        self.stored.notify_one();
    }

    /// Returns the outbox the feed's forwarder delivers from: `store`, read
    /// again once a record commits or every `idle`.
    #[must_use]
    pub fn outbox(&self, store: Store, idle: Duration) -> StoreOutbox {
        StoreOutbox {
            store,
            stored: Arc::clone(&self.stored),
            idle,
            waiting: AtomicUsize::new(0),
            refused: AtomicUsize::new(0),
        }
    }
}

/// FerroSMART's own code system of the audit events no IHE or BALP pattern
/// describes. No specification governs the codes: our own design
/// (`docs/architecture.md` §13.2).
pub const OWN_EVENTS: &str = "urn:ferrosmart:audit-event";

/// DICOM `110113` Security Alert (DICOM PS3.15 A.5.3.11).
pub const SECURITY_ALERT: Coded = Coded::fixed(DCM, "110113", "Security Alert");

/// DICOM `110137` User Security Attributes Changed (DICOM PS3.15
/// A.5.3.11, an `EventTypeCode` of Security Alert).
pub const SECURITY_ATTRIBUTES_CHANGED: Coded =
    Coded::fixed(DCM, "110137", "User Security Attributes Changed");

/// A write FerroSMART records beside the token requests and the logins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// An authorization code issued to an app.
    CodeIssued,
    /// A person's consent remembered for a client.
    ConsentRemembered,
    /// A remembered consent withdrawn, with the tokens it covered.
    ConsentWithdrawn,
    /// A code issued to a professional with no consent page, on the
    /// administrator's registration (`docs/architecture.md` §13.6 item 6).
    ConsentAdministrative,
    /// A code issued with no consent page for a first-party app
    /// (`docs/architecture.md` §13.6 item 6).
    ConsentFirstParty,
    /// An access token revoked at `/revoke` (RFC 7009).
    TokenRevoked,
    /// A grant revoked at `/revoke` by its refresh token (RFC 7009 §2.1).
    GrantRevoked,
    /// A refresh token rotated (OAuth 2.1 draft §4.3.1).
    RefreshRotated,
    /// A rotated refresh token presented again by its client within the
    /// repeat window, answered with the same successor
    /// (`docs/architecture.md` §13.6 item 11).
    RefreshRepeated,
    /// A rotated refresh token presented again, its grant revoked (RFC 9700
    /// §4.14.2).
    RefreshReused,
    /// An authorization code redeemed again, the tokens it gave revoked
    /// (OAuth 2.1 draft §4.1.3).
    CodeReused,
    /// An upstream session ended by a back-channel logout, with the grants
    /// under it (OpenID Connect Back-Channel Logout 1.0 §2.7).
    SessionEnded,
    /// A person's logout at the end-session endpoint, with the online
    /// grants it ended (OpenID Connect RP-Initiated Logout 1.0 §2).
    LoggedOut,
    /// A launch an EHR registered at `POST /launch` (`docs/architecture.md`
    /// §13.6 item 3).
    LaunchRegistered,
    /// A launch an app redeemed at the authorization endpoint.
    LaunchRedeemed,
    /// A launch registration or redemption refused.
    LaunchRefused,
    /// The short-lived token the patient picker searches with, issued for
    /// the signed-in person (`docs/architecture.md` §13.6 item 4).
    PickerToken,
    /// A client registered through the admin API (`docs/architecture.md`
    /// §13.8).
    ClientCreated,
    /// A client changed through the admin API.
    ClientUpdated,
    /// A client disabled through the admin API, with every grant and token
    /// it held.
    ClientDisabled,
    /// A client deleted at its RFC 7592 registration endpoint.
    ClientDeleted,
    /// A disabled client enabled through the admin API.
    ClientEnabled,
    /// A person's recent patients forgotten at the management page
    /// (`docs/architecture.md` §13.6 item 4).
    RecentForgotten,
}

impl Event {
    /// The code the store files the record under, and its own subtype in
    /// [`OWN_EVENTS`].
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CodeIssued => "authorization-code",
            Self::ConsentRemembered => "consent-remembered",
            Self::ConsentWithdrawn => "consent-withdrawn",
            Self::ConsentAdministrative => "consent-administrative",
            Self::ConsentFirstParty => "consent-first-party",
            Self::TokenRevoked => "token-revoked",
            Self::GrantRevoked => "grant-revoked",
            Self::RefreshRotated => "refresh-rotated",
            Self::RefreshRepeated => "refresh-repeated",
            Self::RefreshReused => "refresh-reused",
            Self::CodeReused => "code-reused",
            Self::SessionEnded => "session-ended",
            Self::LoggedOut => "logged-out",
            Self::PickerToken => "picker-token",
            Self::LaunchRegistered => "launch-registered",
            Self::LaunchRedeemed => "launch-redeemed",
            Self::LaunchRefused => "launch-refused",
            Self::ClientCreated => "client-created",
            Self::ClientUpdated => "client-updated",
            Self::ClientDisabled => "client-disabled",
            Self::ClientDeleted => "client-deleted",
            Self::ClientEnabled => "client-enabled",
            Self::RecentForgotten => "recent-patients-forgotten",
        }
    }

    /// The outcome the record states: a minor failure for a refused launch,
    /// success for every other write (DICOM PS3.15 A.5.3, `EventOutcomeIndicator`).
    const fn outcome(self) -> Outcome {
        match self {
            Self::LaunchRefused => Outcome::MinorFailure,
            _ => Outcome::Success,
        }
    }

    /// The words of the code.
    const fn display(self) -> &'static str {
        match self {
            Self::CodeIssued => "Authorization code issued",
            Self::ConsentRemembered => "Consent remembered",
            Self::ConsentWithdrawn => "Consent withdrawn",
            Self::ConsentAdministrative => "Consent by the administrator's registration",
            Self::ConsentFirstParty => "Consent by first-party registration",
            Self::TokenRevoked => "Access token revoked",
            Self::GrantRevoked => "Grant revoked",
            Self::RefreshRotated => "Refresh token rotated",
            Self::RefreshRepeated => "Refresh token repeated within the window",
            Self::RefreshReused => "Refresh token reused",
            Self::CodeReused => "Authorization code reused",
            Self::SessionEnded => "Upstream session ended",
            Self::LoggedOut => "Person logged out",
            Self::LaunchRegistered => "EHR launch registered",
            Self::LaunchRedeemed => "EHR launch redeemed",
            Self::LaunchRefused => "EHR launch refused",
            Self::PickerToken => "Patient picker token issued",
            Self::ClientCreated => "Client registered",
            Self::ClientUpdated => "Client changed",
            Self::ClientDisabled => "Client disabled",
            Self::ClientDeleted => "Client deleted",
            Self::ClientEnabled => "Client enabled",
            Self::RecentForgotten => "Recent patients forgotten",
        }
    }

    /// The `type`, the subtypes and the `action` the record takes: DICOM
    /// User Authentication with `110123` Logout for a session end (DICOM
    /// PS3.15 A.5.3.12), and DICOM User Authentication or Security Alert
    /// with an [`OWN_EVENTS`] subtype for the rest.
    fn kind(self) -> (Coded, Vec<Coded>, &'static str) {
        let own = Coded::fixed(OWN_EVENTS, self.code(), self.display());
        match self {
            Self::SessionEnded | Self::LoggedOut => (USER_AUTHENTICATION, vec![LOGOUT, own], "E"),
            Self::CodeIssued | Self::LaunchRegistered | Self::PickerToken => {
                (USER_AUTHENTICATION, vec![own], "C")
            }
            Self::RefreshRotated | Self::RefreshRepeated | Self::LaunchRedeemed => {
                (USER_AUTHENTICATION, vec![own], "E")
            }
            Self::ConsentRemembered | Self::ConsentAdministrative | Self::ConsentFirstParty => {
                (SECURITY_ALERT, vec![SECURITY_ATTRIBUTES_CHANGED, own], "C")
            }
            Self::ConsentWithdrawn | Self::ClientDisabled | Self::ClientDeleted => {
                (SECURITY_ALERT, vec![SECURITY_ATTRIBUTES_CHANGED, own], "D")
            }
            Self::ClientCreated => (SECURITY_ALERT, vec![SECURITY_ATTRIBUTES_CHANGED, own], "C"),
            Self::ClientUpdated | Self::ClientEnabled => {
                (SECURITY_ALERT, vec![SECURITY_ATTRIBUTES_CHANGED, own], "U")
            }
            Self::TokenRevoked | Self::GrantRevoked | Self::RecentForgotten => {
                (SECURITY_ALERT, vec![own], "D")
            }
            Self::RefreshReused | Self::CodeReused | Self::LaunchRefused => {
                (SECURITY_ALERT, vec![own], "E")
            }
        }
    }
}

/// One recorded write, as its record names it.
#[derive(Debug, Clone)]
pub struct Happening<'a> {
    /// What happened.
    pub event: Event,
    /// FerroSMART's issuer, which a person's subject is FerroSMART's own
    /// under.
    pub issuer: &'a str,
    /// The client it concerns, when one.
    pub client_id: Option<&'a str>,
    /// The person it concerns, by their pairwise subject, when one.
    pub subject: Option<&'a str>,
    /// The address the request came from.
    pub from: std::net::IpAddr,
    /// The endpoint the request came to.
    pub endpoint: &'a Url,
    /// What the record holds of the write, such as a grant id or a count,
    /// never a code, a token or a secret.
    pub details: Vec<(&'static str, String)>,
}

/// Returns the record of `happening`. Its form is our own design where the
/// event has no IHE or BALP pattern; see [`Event`].
#[must_use]
pub fn happened(happening: &Happening<'_>) -> Exchange {
    let (event_type, subtypes, action) = happening.event.kind();
    let on_behalf = happening.subject.map_or(OnBehalfOf::System, |subject| {
        let user = match happening.client_id {
            Some(client_id) => User::new(
                happening.issuer.to_owned(),
                subject.to_owned(),
                client_id.to_owned(),
            ),
            None => User::local(subject.to_owned()).with_issuer(Some(happening.issuer.to_owned())),
        };
        OnBehalfOf::User(user)
    });
    let entities = if happening.details.is_empty() {
        Vec::new()
    } else {
        vec![Entity::Described(Described {
            what: None,
            kind: SYSTEM_OBJECT,
            role: Some(SECURITY_RESOURCE),
            name: Some(happening.event.code().to_owned()),
            description: None,
            details: happening
                .details
                .iter()
                .map(|(kind, value)| Detail::new(*kind, value.as_str()))
                .collect(),
            security_labels: Vec::new(),
        })]
    };
    Exchange {
        kind: EventKind {
            profile: "",
            event_type,
            subtypes,
            action,
            client: APPLICATION,
            server: AUTHZ_OAUTH_SERVICE,
        },
        recorded: jiff::Timestamp::now(),
        outcome: happening.event.outcome(),
        outcome_description: None,
        direction: Direction::Received {
            client: Peer {
                who: happening
                    .client_id
                    .unwrap_or(UNIDENTIFIED_CLIENT)
                    .to_owned(),
                network: NetworkAddress::Ip(happening.from),
            },
            endpoint: NetworkAddress::uri(happening.endpoint),
        },
        on_behalf,
        entities,
        security: Vec::new(),
    }
}

/// The participant object role of a security resource (FHIR R4
/// `object-role` `13`).
pub const SECURITY_RESOURCE: Coded = Coded::fixed(
    "http://terminology.hl7.org/CodeSystem/object-role",
    "13",
    "Security Resource",
);

/// The address the stack names a request's client by.
///
/// Every audited request has one. A request that came over no connection,
/// which no record could name, is refused `503` before it writes anything
/// (no specification governs the refusal: our own design).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Connected(pub std::net::IpAddr);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Connected {
    type Rejection = NoConnection;

    fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(
            parts
                .extensions
                .get::<ferrohealth_server::client_address::ClientAddress>()
                .map(|address| Self(address.0))
                .ok_or(NoConnection),
        )
    }
}

/// The refusal of a request that came over no connection: `503`, never
/// stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoConnection;

impl axum::response::IntoResponse for NoConnection {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("a request came over no connection, so it cannot be recorded");
        let mut response = http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        response.headers_mut().insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("no-store"),
        );
        response
    }
}
