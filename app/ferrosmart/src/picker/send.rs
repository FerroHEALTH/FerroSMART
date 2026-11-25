// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The requests the picker sends: as the signed-in person under a grant of
//! their own, or as FerroSMART's Backend Services client on their behalf,
//! each with its token's record, its access record and its revocation
//! (`docs/architecture.md` §13.6 item 4, §13.33).

use std::net::IpAddr;

use ehds_logging::classify::Evidence;
use ehds_logging::label::LabelPolicy;
use ehds_logging::map::CategoryMap;
use ehds_logging::record::{
    AccessRecord, Accessor, Coded, Origin, Outcome, Professional, Purpose, Request,
};
use ehds_logging::retention::RetentionPolicy;
use ihe_atna::balp::NetworkAddress;
use serde_json::Value;

use super::{Access, Ask, PICKER_ROUTE, PickerError, REQUEST_TIMEOUT, TOKEN_SECONDS, purpose};
use crate::audit::{self, Event, Happening};
use crate::server::AppState;
use crate::store::Pending;
use crate::store::grant::NewGrant;
use crate::token::mint::{Authentication, Grant, mint};
use crate::token::sender::Confirmation;

/// The person a lookup is sent as, or on whose behalf FerroSMART reads:
/// who logged in, for which client, at which resource server.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Person<'a> {
    /// Their FerroSMART `sub`.
    pub(crate) subject: &'a str,
    /// Their `fhirUser`, when they have one.
    pub(crate) fhir_user: Option<&'a str>,
    /// Their mapped roles.
    pub(crate) roles: &'a [String],
    /// The client the lookup serves.
    pub(crate) client_id: Option<&'a str>,
    /// The name the record gives them.
    pub(crate) display_name: Option<&'a str>,
    /// Their login, which every token issued for them repeats.
    pub(crate) login: Authentication,
}

impl<'a> Person<'a> {
    /// Returns the person signed in for `pending`, none before the login.
    pub(super) fn of(pending: &'a Pending) -> Option<Self> {
        Some(Self {
            subject: pending.subject.as_deref()?,
            fhir_user: pending.fhir_user.as_deref(),
            roles: &pending.roles,
            client_id: pending.client_id.as_deref(),
            display_name: pending.display_name.as_deref(),
            login: Authentication {
                auth_time: pending.auth_time,
                acr: pending.acr,
            },
        })
    }
}

/// Sends `ask` as the signed-in person of `pending`, as [`as_the`] does.
pub(super) async fn as_person(
    state: &AppState,
    pending: &Pending,
    from: IpAddr,
    ask: &Ask<'_>,
) -> Result<Value, PickerError> {
    let person = Person::of(pending).ok_or(PickerError::Unreadable)?;
    as_the(state, &person, from, ask).await
}

/// Sends `ask` as `person` under a grant of their own, records the access,
/// revokes the grant with its token and returns the answer.
///
/// The person's login authorizes FerroSMART, as its own client, to read
/// what the person may see while they choose: the grant names them, their
/// `fhirUser`, roles and login, the one base and the one scope of `ask`, and
/// its token lives [`TOKEN_SECONDS`]. A resource server that exchanges the
/// token on (RFC 8693 §2.1) finds it under that grant. The grant and its
/// lifetime are our own design (`docs/architecture.md` §13.6 item 4).
pub(super) async fn as_the(
    state: &AppState,
    person: &Person<'_>,
    from: IpAddr,
    ask: &Ask<'_>,
) -> Result<Value, PickerError> {
    let client = crate::backend::client(state)
        .await
        .map_err(PickerError::Backend)?;
    let (grant_id, issued) = granted(state, &client, person, ask).await?;
    let settings = state.settings();
    let endpoint = settings.endpoint_url(PICKER_ROUTE);
    let happening = |event, details| Happening {
        event,
        issuer: &settings.issuer,
        client_id: Some(&client.client_id),
        subject: Some(person.subject),
        from,
        endpoint: &endpoint,
        details,
    };
    let mut tx = state
        .store()
        .begin()
        .await
        .map_err(|error| PickerError::Record(audit::RecordFailure::Store(error)))?;
    tx.insert_token(&issued.record())
        .await
        .map_err(|error| PickerError::Record(audit::RecordFailure::Store(error)))?;
    let details = vec![
        ("jti", issued.jti().to_owned()),
        ("grant", grant_id.clone()),
    ];
    state
        .audit()
        .commit_happening(tx, &happening(Event::PickerToken, details))
        .await
        .map_err(PickerError::Record)?;
    let fetched = fetch(state, ask, &issued.response.access_token).await;
    let asker = Asker {
        person,
        from,
        audience: ask.audience,
        purpose: ask.purpose,
        token_id: issued.jti(),
        backend: None,
    };
    let recorded = record_access(state, &asker, (ask.describe)(&fetched)).await;
    let mut tx = state
        .store()
        .begin()
        .await
        .map_err(|error| PickerError::Record(audit::RecordFailure::Store(error)))?;
    tx.revoke_grant(&grant_id)
        .await
        .map_err(|error| PickerError::Record(audit::RecordFailure::Store(error)))?;
    let revoked = state
        .audit()
        .commit_happening(
            tx,
            &happening(Event::GrantRevoked, vec![("grant", grant_id.clone())]),
        )
        .await
        .map_err(PickerError::Record);
    recorded?;
    revoked?;
    fetched
}

/// Records a grant of `person` to FerroSMART's own `client` for the one
/// base and scope of `ask`, and returns its id with the token minted under
/// it.
async fn granted(
    state: &AppState,
    client: &crate::clients::Client,
    person: &Person<'_>,
    ask: &Ask<'_>,
) -> Result<(String, crate::token::Issued), PickerError> {
    let grant_id = crate::authorize::random().map_err(PickerError::Random)?;
    let no_context = Value::Object(serde_json::Map::new());
    state
        .store()
        .create_grant(&NewGrant {
            id: &grant_id,
            client_id: &client.client_id,
            subject: person.subject,
            fhir_user: person.fhir_user,
            audience: ask.audience,
            scope: ask.scope,
            context: &no_context,
            auth_time: person.login.auth_time,
            access: None,
            upstream_session: None,
            basis: None,
            roles: person.roles,
            acr: person.login.acr,
            dpop_jkt: None,
        })
        .await
        .map_err(|error| PickerError::Record(audit::RecordFailure::Store(error)))?;
    let issued = mint(
        state,
        client,
        Grant {
            subject: person.subject,
            audience: ask.audience,
            scope: ask.scope,
            fhir_user: person.fhir_user,
            code_hash: None,
            token_type: "Bearer",
            longest: Some(std::time::Duration::from_secs(TOKEN_SECONDS)),
            identity: None,
            under: Some(&grant_id),
            context: &serde_json::Map::new(),
            roles: person.roles,
            login: Some(person.login),
            confirmation: &Confirmation::default(),
        },
    )
    .map_err(|refusal| PickerError::Issue {
        description: refusal.description,
    })?;
    Ok((grant_id, issued))
}

/// Reads `ask` for `person` as FerroSMART's Backend Services client,
/// records the access, revokes the token and returns the answer.
///
/// No runtime user authorization exists for such a read, so FerroSMART
/// asks with its own client credentials token, [`crate::backend::SCOPE`]
/// (SMART App Launch 2.2.0, Backend Services). One token serves one read
/// of the one matched patient (GDPR Art 5(1)(c), Art 25), and the access
/// record names the person on whose behalf FerroSMART read; Regulation (EU)
/// 2025/327 Annex II 3.2(b) is silent on a system's access, so both are our
/// own design (`docs/architecture.md` §13.33).
pub(super) async fn as_backend(
    state: &AppState,
    person: &Person<'_>,
    from: IpAddr,
    ask: &Ask<'_>,
) -> Result<Value, PickerError> {
    let token = crate::backend::token(state, ask.audience)
        .await
        .map_err(PickerError::Backend)?;
    let fetched = fetch(
        state,
        ask,
        secrecy::ExposeSecret::expose_secret(&token.value),
    )
    .await;
    let asker = Asker {
        person,
        from,
        audience: ask.audience,
        purpose: ask.purpose,
        token_id: &token.jti,
        backend: Some(&token.client_id),
    };
    let recorded = record_access(state, &asker, (ask.describe)(&fetched)).await;
    let settings = state.settings();
    let endpoint = settings.endpoint_url(PICKER_ROUTE);
    let revoked = revoke(
        state,
        &token.jti,
        Happening {
            event: Event::TokenRevoked,
            issuer: &settings.issuer,
            client_id: Some(&token.client_id),
            subject: Some(person.subject),
            from,
            endpoint: &endpoint,
            details: vec![("jti", token.jti.clone())],
        },
    )
    .await;
    recorded?;
    revoked?;
    fetched
}

/// Sends `ask` with the bearer `token`.
async fn fetch(state: &AppState, ask: &Ask<'_>, token: &str) -> Result<Value, PickerError> {
    let mut request = state
        .fhir()
        .get(ask.url.clone())
        .bearer_auth(token)
        .header(http::header::ACCEPT, ask.accept)
        .timeout(REQUEST_TIMEOUT);
    if let Some(declared) = ask.purpose {
        request = request.header(declared.header, &declared.purpose.code);
    }
    let answer = request.send().await.map_err(PickerError::Fetch)?;
    let status = answer.status();
    if !status.is_success() {
        return Err(PickerError::Refused(status));
    }
    answer.json::<Value>().await.map_err(PickerError::Fetch)
}

/// Revokes the access token `jti` with the record `happening`.
async fn revoke(state: &AppState, jti: &str, happening: Happening<'_>) -> Result<(), PickerError> {
    let mut tx = state
        .store()
        .begin()
        .await
        .map_err(|error| PickerError::Record(audit::RecordFailure::Store(error)))?;
    tx.revoke_access_token(jti)
        .await
        .map_err(|error| PickerError::Record(audit::RecordFailure::Store(error)))?;
    state
        .audit()
        .commit_happening(tx, &happening)
        .await
        .map_err(PickerError::Record)
}

/// Who sent one request of the picker, from where and to which server.
struct Asker<'a> {
    /// The person it was sent as, or on whose behalf.
    person: &'a Person<'a>,
    /// The browser's address.
    from: IpAddr,
    /// The base of the resource server asked.
    audience: &'a str,
    /// The purpose of use the request declared.
    purpose: Option<purpose::Declared<'a>>,
    /// The `jti` of the token it was sent with.
    token_id: &'a str,
    /// FerroSMART's Backend Services client, when the request was its own.
    backend: Option<&'a str>,
}

/// Stores the access record of one request `asker` sent, as `access`
/// describes it (Regulation (EU) 2025/327 Annex II 3.2).
async fn record_access(
    state: &AppState,
    asker: &Asker<'_>,
    access: Access,
) -> Result<(), PickerError> {
    let Asker {
        person,
        from,
        audience,
        backend,
        ..
    } = *asker;
    let settings = state.settings();
    let recorded = jiff::Timestamp::now();
    // NOTE: Regulation (EU) 2025/327 Art 14(1), a Patient's demographics and an
    // EHR's id are none of the priority categories, so the access has no category.
    let categories = CategoryMap::default().classify(&Evidence::no_category());
    let origins = vec![Origin {
        endpoint: Some(audience.to_owned()),
        node: None,
        system_id: None,
        status: None,
        rows: None,
        version: None,
        created_ehr: None,
        categories: None,
    }];
    let keys = || origins.iter().filter_map(Origin::key);
    let retention = RetentionPolicy::default().retain(recorded, &categories, keys());
    let labels = LabelPolicy::default().label(&categories, keys());
    let outcome = if access.delivered.is_some() {
        Outcome::Success
    } else {
        Outcome::MinorFailure
    };
    let record = AccessRecord {
        action: access.action,
        recorded,
        outcome,
        outcome_description: None,
        accessor: accessor(&settings.issuer, asker),
        subject: access.subject,
        categories,
        delivered: access.delivered,
        origins,
        origin_count: None,
        request: Request {
            client_address: Some(from),
            ..access.request
        },
        retention,
        labels,
        emergency: None,
        inserted: None,
        transformations: Vec::new(),
    };
    let endpoint = NetworkAddress::uri(&settings.endpoint_url(PICKER_ROUTE));
    let exchange = ehds_logging::balp::exchange(&record, &endpoint);
    // NOTE: no specification governs a system read's beneficiary: our own design,
    // the record's row names the person on whose behalf FerroSMART read.
    let client_id = backend.or(person.client_id);
    let row = state
        .audit()
        .row(&exchange, "access", Some(person.subject), client_id)
        .map_err(PickerError::Record)?;
    state
        .audit()
        .record(state.store(), &row)
        .await
        .map_err(PickerError::Record)
}

/// Returns who `asker` names under FerroSMART's `issuer` as the access
/// record's accessor: the person, or FerroSMART's Backend Services client.
fn accessor(issuer: &str, asker: &Asker<'_>) -> Accessor {
    let person = asker.person;
    let (subject, client_id, roles, name) = match asker.backend {
        // NOTE: IHE IUA ITI-71 §3.71.4.2.2.1, a client credentials token's `sub` is
        // its client, which acts with no role of a person's.
        Some(client) => (client, Some(client), Vec::new(), None),
        None => (
            person.subject,
            person.client_id,
            person
                .roles
                .iter()
                .map(|role| Coded {
                    system: None,
                    code: role.clone(),
                })
                .collect(),
            person.display_name.map(str::to_owned),
        ),
    };
    Accessor {
        issuer: Some(issuer.to_owned()),
        subject: subject.to_owned(),
        client_id: client_id.map(str::to_owned),
        audience: Some(asker.audience.to_owned()),
        provider: None,
        acting: None,
        roles,
        token_id: Some(asker.token_id.to_owned()),
        assurance: None,
        professional: Professional {
            name,
            ..Professional::default()
        },
        alt_id: None,
        purposes: asker
            .purpose
            .map(|declared| Purpose {
                system: Some(declared.purpose.system.clone()),
                code: declared.purpose.code.clone(),
            })
            .into_iter()
            .collect(),
        policies: Vec::new(),
        relayed: None,
        binding: None,
        actors: Vec::new(),
        represents: None,
        acts_for: None,
        facilities: Vec::new(),
    }
}
