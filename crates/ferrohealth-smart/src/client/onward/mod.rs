// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The onward grants: a token a product obtains for another service on
//! behalf of the caller behind a verified token, and the one check every
//! such token passes before it is used.
//!
//! Two grants carry it, chosen by the issuer's profile
//! ([`crate::profile::onward`]): token exchange (RFC 8693 §2.1), the
//! caller's token as `subject_token` with an optional `actor_token` and the
//! target as `resource` (RFC 8707 §2) or `audience`, and the JWT bearer
//! grant (RFC 7523 §2.1), the caller's token as `assertion` with `scope`
//! naming the target. The client authenticates as configured in its
//! [`ClientCredentials`](crate::client::ClientCredentials), `private_key_jwt`
//! (RFC 7523 §2.2) the form RFC 9700 §2.5 recommends.
//!
//! The issued token is decoded and refused unless its issuer is the one
//! asked, its `aud` lies inside the target's audiences, its `exp` is within
//! the issuer's `max_onward_lifetime` of its `iat`, it carries the
//! profile's `expect`, it names the requesting client as its actor, and it
//! names the caller's person: by the profile's `person_equality` claims on
//! a `persons` issuer, by the attested `person_mapping` of its
//! `[auth.issuer.<name>.federation]` table on a `federation` issuer, whose token also
//! keeps the subject's consent decision reference. A `patients` issuer
//! exchanges a patient's own token alone, and its token must read as a
//! patient token of that issuer and name the subject token's patient
//! context, beside `person_equality`. A failed exchange
//! is a typed error carrying the upstream status, and the client never
//! falls back to its own credentials. The rules beyond the two RFCs are our
//! own design.

pub(crate) mod check;
pub mod exchange;

use std::fmt;

use http::StatusCode;
use secrecy::SecretString;
use serde_json::Map;
use serde_json::Value;

use crate::client::OAuthError;
use crate::client::TokenError;
use crate::federation::Field;
use crate::kind::Actor;
use crate::kind::CallerKind;
use crate::kind::Unclassified;
use crate::profile::onward::PreviewVariant;
use crate::resource::Caller;
use crate::resource::PatientClaim;
use crate::resource::ResourceError;
use crate::resource::Via;

/// A token type identifier of RFC 8693 §3, naming what a subject or an
/// actor token is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenType {
    /// `urn:ietf:params:oauth:token-type:access_token`, an access token of
    /// the authorization server asked.
    #[default]
    AccessToken,
    /// `urn:ietf:params:oauth:token-type:jwt`, a JWT of any issuer.
    Jwt,
}

impl TokenType {
    /// Returns the identifier.
    #[must_use]
    pub const fn uri(self) -> &'static str {
        match self {
            Self::AccessToken => "urn:ietf:params:oauth:token-type:access_token",
            Self::Jwt => "urn:ietf:params:oauth:token-type:jwt",
        }
    }

    /// Returns the type `uri` names, when it is one the client accepts as
    /// an issued token.
    #[must_use]
    pub fn from_uri(uri: &str) -> Option<Self> {
        [Self::AccessToken, Self::Jwt]
            .into_iter()
            .find(|token_type| token_type.uri() == uri)
    }
}

/// The verified token a caller presented, as the subject of an onward
/// grant.
///
/// The `Debug` rendering names the issuer, the kind and the type, never the
/// token or a claim.
#[derive(Clone)]
pub struct SubjectToken {
    /// The token, as the caller presented it.
    token: SecretString,
    /// What the token is.
    token_type: TokenType,
    /// The issuer that signed it.
    issuer: String,
    /// Its verified claims.
    claims: Map<String, Value>,
    /// Who stands behind it.
    kind: CallerKind,
    /// The path of the deployment's patient claim the caller carried, when
    /// its resource server names one.
    patient_claim: Option<String>,
}

impl fmt::Debug for SubjectToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubjectToken")
            .field("issuer", &self.issuer)
            .field("kind", &self.kind)
            .field("token_type", &self.token_type)
            .finish_non_exhaustive()
    }
}

impl SubjectToken {
    /// Returns the subject `caller` makes of `token`, the bearer token it
    /// was admitted with, as an access token (RFC 8693 §3).
    ///
    /// # Errors
    ///
    /// [`OnwardError::NoSubjectToken`] when the caller holds no verified
    /// token: it authenticated with Basic, or names no issuer or no claim,
    /// as a caller only an edge asserts does. When `token` is a JWS whose
    /// payload reads, its claims must be the caller's.
    pub fn from_caller(caller: &Caller, token: SecretString) -> Result<Self, OnwardError> {
        let issuer = caller
            .issuer()
            .filter(|_issuer| caller.via() == Via::Bearer && !caller.claims().is_empty())
            .ok_or(OnwardError::NoSubjectToken)?;
        // NOTE: no specification governs this: our own design; an opaque token is
        // legitimately not of this form, and its introspected claims stand.
        if let Ok(claims) = check::decode(secrecy::ExposeSecret::expose_secret(&token))
            && claims != *caller.claims()
        {
            return Err(OnwardError::NoSubjectToken);
        }
        Ok(Self {
            token,
            token_type: TokenType::AccessToken,
            issuer: issuer.to_owned(),
            claims: caller.claims().clone(),
            kind: caller.kind().clone(),
            patient_claim: caller
                .extension::<PatientClaim>()
                .map(|claim| claim.path().to_owned()),
        })
    }

    /// Returns this subject sent as `token_type`.
    #[must_use]
    pub const fn with_token_type(mut self, token_type: TokenType) -> Self {
        self.token_type = token_type;
        self
    }

    /// Returns the issuer that signed the token.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns who stands behind the token.
    #[must_use]
    pub const fn kind(&self) -> &CallerKind {
        &self.kind
    }

    /// Returns what the token is sent as.
    #[must_use]
    pub const fn token_type(&self) -> TokenType {
        self.token_type
    }

    /// Returns the verified claims.
    pub(crate) const fn claims(&self) -> &Map<String, Value> {
        &self.claims
    }

    /// Returns the token.
    pub(crate) const fn token(&self) -> &SecretString {
        &self.token
    }

    /// Returns the claims a patient context is named by: the `patient`
    /// launch context, the `ehrId` of the openEHR launch context, and the
    /// deployment's patient claim, when the caller carried one.
    pub(crate) fn patient_context(&self) -> impl Iterator<Item = &str> {
        ["patient", "ehrId"]
            .into_iter()
            .chain(self.patient_claim.as_deref())
    }
}

/// The actor's own access token of a delegated exchange (RFC 8693 §2.1),
/// with the actor the issued token's `act` must name (§4.1).
///
/// The `Debug` rendering names the actor and the type, never the token.
#[derive(Clone)]
pub struct ActorToken {
    /// The token.
    token: SecretString,
    /// What the token is.
    token_type: TokenType,
    /// The actor it identifies.
    actor: Actor,
}

impl fmt::Debug for ActorToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActorToken")
            .field("actor", &self.actor)
            .field("token_type", &self.token_type)
            .finish_non_exhaustive()
    }
}

impl ActorToken {
    /// Returns the actor token `token` of `actor`, an access token.
    #[must_use]
    pub const fn new(token: SecretString, actor: Actor) -> Self {
        Self {
            token,
            token_type: TokenType::AccessToken,
            actor,
        }
    }

    /// Returns this actor token sent as `token_type`.
    #[must_use]
    pub const fn with_token_type(mut self, token_type: TokenType) -> Self {
        self.token_type = token_type;
        self
    }

    /// Returns the actor the token identifies.
    #[must_use]
    pub const fn actor(&self) -> &Actor {
        &self.actor
    }

    /// Returns what the token is sent as.
    #[must_use]
    pub const fn token_type(&self) -> TokenType {
        self.token_type
    }

    /// Returns the token.
    pub(crate) const fn token(&self) -> &SecretString {
        &self.token
    }
}

/// The service an onward token is for.
///
/// The audiences are the set an issued token's `aud` must lie inside, never
/// derived from a scope; the indicators are what the request names the
/// service by, as `resource` or `audience` under the issuer's profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The audiences an issued token may name.
    audiences: Vec<String>,
    /// The `resource` or `audience` values the request names.
    indicators: Vec<String>,
    /// The `scope` the request names.
    scope: Option<String>,
    /// The claim a chained federation route carries from the subject token
    /// to the issued one.
    correlation_claim: Option<String>,
}

impl Target {
    /// Returns the target whose tokens name only `audiences`, named by no
    /// indicator and no scope.
    #[must_use]
    pub fn new<I, S>(audiences: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            audiences: audiences.into_iter().map(Into::into).collect(),
            indicators: Vec::new(),
            scope: None,
            correlation_claim: None,
        }
    }

    /// Returns this target named by `indicator` as well, sent as `resource`
    /// or `audience` (RFC 8693 §2.1 admits several of each).
    #[must_use]
    pub fn with_indicator(mut self, indicator: impl Into<String>) -> Self {
        self.indicators.push(indicator.into());
        self
    }

    /// Returns this target asked for with `scope` (RFC 6749 §3.3).
    #[must_use]
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Returns this target reached over a chained federation route, whose
    /// issued token must carry the subject token's value of `claim`.
    #[must_use]
    pub fn with_correlation_claim(mut self, claim: impl Into<String>) -> Self {
        self.correlation_claim = Some(claim.into());
        self
    }

    /// Returns the audiences an issued token may name.
    #[must_use]
    pub fn audiences(&self) -> &[String] {
        &self.audiences
    }

    /// Returns the `resource` or `audience` values the request names.
    #[must_use]
    pub fn indicators(&self) -> &[String] {
        &self.indicators
    }

    /// Returns the `scope` the request names.
    #[must_use]
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    /// Returns the correlation claim of a chained route.
    #[must_use]
    pub fn correlation_claim(&self) -> Option<&str> {
        self.correlation_claim.as_deref()
    }
}

/// Why an issued token fails the onward check. Each names a check or a
/// configured claim, never a claim value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Rejected {
    /// The token is not a JWS whose payload is a JSON object.
    #[error("the issued token is not a JWT")]
    NotJwt,
    /// The token's `iss` is not the issuer asked.
    #[error("the issued token's iss is not the issuer asked")]
    Issuer,
    /// The token's `aud` is absent or names an audience outside the
    /// target's.
    #[error("the issued token's aud lies outside the target's audiences")]
    Audience,
    /// The token lacks a claim the check reads.
    #[error("the issued token lacks {claim}")]
    MissingClaim {
        /// The claim.
        claim: &'static str,
    },
    /// The token's `exp` is later than its `iat` plus the issuer's
    /// `max_onward_lifetime`.
    #[error("the issued token outlives the issuer's max_onward_lifetime")]
    Lifetime,
    /// The token, or the subject token it was issued for, has expired.
    #[error("the issued token or its subject token has expired")]
    Expired,
    /// The token's `exp` lies past an assertion window the caller carries,
    /// plus 60 s of drift.
    #[error("the issued token outlives the caller's {0}")]
    AssertionWindow(AssertionWindow),
    /// The token names another actor than the requesting client, or none.
    #[error("the issued token does not name the requesting client as its actor")]
    Actor,
    /// `iss` or `sub` differs between the subject token and the issued
    /// token, or is absent from one.
    #[error("the issued token names another person: {claim} differs")]
    Person {
        /// The claim.
        claim: String,
    },
    /// The subject token's issuer is not one the federation issuer
    /// `exchanges_from`.
    #[error("the federation issuer is not trusted to map the subject token's issuer")]
    NotMapped,
    /// The token does not read as the federation issuer's table requires.
    #[error("the issued token does not read under the federation table")]
    Federation(#[source] Unclassified),
    /// The token's `professional.hp_identifier` is not the subject token's
    /// `person_mapping` claim, or a person's exchange issued an
    /// organisation's token.
    #[error("the issued token does not name the mapped person")]
    PersonMapping,
    /// The token does not carry the subject token's consent decision
    /// reference with the same value.
    #[error("the issued token does not carry the subject token's consent decision reference")]
    Consent,
    /// The token does not carry the subject token's correlation claim of a
    /// chained route, or its correlation id, with the same value.
    #[error("the issued token does not carry the subject token's correlation claim")]
    Correlation,
    /// The token issued for a patient's own token does not name a
    /// `Patient` as its `fhirUser`.
    #[error("the issued token is not a patient's token")]
    Patient,
    /// A claim of the subject token's patient context differs on the token
    /// issued for a patient's own token, or is absent from it.
    #[error("the issued token names another patient: {claim} differs")]
    PatientContext {
        /// The claim.
        claim: String,
    },
}

/// An eHDSI assertion window a MyHealth@EU contact-point caller carries,
/// which no onward token issued on its behalf may outlive (SAML Profile
/// 10.0.0 §2.1, §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssertionWindow {
    /// The HP Identity Assertion's `NotOnOrAfter`,
    /// [`Field::AssertionNotOnOrAfter`].
    Identity,
    /// The Treatment Relationship Confirmation's `NotOnOrAfter`,
    /// [`Field::TrcNotOnOrAfter`].
    Treatment,
}

impl AssertionWindow {
    /// Returns the field that carries the window's end.
    #[must_use]
    pub const fn field(self) -> Field {
        match self {
            Self::Identity => Field::AssertionNotOnOrAfter,
            Self::Treatment => Field::TrcNotOnOrAfter,
        }
    }
}

impl fmt::Display for AssertionWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.field().as_str())
    }
}

/// An onward token the product could not obtain or may not use.
///
/// No variant carries a token, a secret or a key.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OnwardError {
    /// The issuer's settings break a rule.
    #[error("the onward issuer's settings break a rule")]
    Settings(#[source] Box<ResourceError>),
    /// The issuer's profile sets no `max_onward_lifetime`.
    #[error("the onward issuer's profile sets no max_onward_lifetime")]
    MaxOnwardLifetime,
    /// The `[auth.issuer.<name>.federation]` table of a `federation` issuer lacks a key
    /// the onward check reads.
    #[error("auth.federation.{key} is not set for the onward grants")]
    Federation {
        /// The key.
        key: &'static str,
    },
    /// The caller holds no verified token to exchange.
    #[error("the caller holds no verified token to exchange")]
    NoSubjectToken,
    /// A patient's token names no patient context for the issued token to
    /// keep.
    #[error("the patient's token names no patient context")]
    NoPatientContext,
    /// A chained route's target names a correlation claim the subject token
    /// does not carry.
    #[error("the subject token carries no correlation claim for the chained route")]
    NoCorrelation,
    /// A JWT bearer grant was asked for a caller that is not a user
    /// principal.
    #[error("the JWT bearer grant exchanges a user principal's token only")]
    UserPrincipalRequired,
    /// The request uses a variant the issuer's profile labels preview.
    #[error("the issuer labels {} preview", variant.as_str())]
    Preview {
        /// The variant.
        variant: PreviewVariant,
    },
    /// A JWT bearer grant was given an actor token, which it has no
    /// parameter for (RFC 7523 §2.1).
    #[error("the JWT bearer grant carries no actor token")]
    ActorToken,
    /// A JWT bearer grant was given an indicator; it names its target in
    /// `scope`.
    #[error("the JWT bearer grant names its target in scope, never as resource or audience")]
    Indicator,
    /// A JWT bearer grant was given no `scope` naming its target.
    #[error("the JWT bearer grant needs a scope naming its target")]
    NoScope,
    /// The target names no audience.
    #[error("the target names no audience")]
    NoAudience,
    /// A `resource` indicator is not an absolute URI without a fragment
    /// (RFC 8707 §2).
    #[error("a resource indicator is not an absolute URI without a fragment")]
    Resource,
    /// The scope names `offline_access`, which asks for a refresh token.
    #[error("an onward grant never asks for offline_access")]
    OfflineAccess,
    /// The subject token does not name the requesting client in its `aud`,
    /// which the issuer's profile requires.
    #[error("the subject token does not name the requesting client in its aud")]
    SubjectAudience,
    /// The token endpoint could not be reached or read, or refused the
    /// request, with its status.
    #[error(transparent)]
    Token(#[from] TokenError),
    /// The token endpoint answered `interaction_required`: the caller must
    /// authenticate again, answering the challenge when one is returned.
    #[error("the token endpoint answered {status}: interaction_required")]
    InteractionRequired {
        /// The status it answered.
        status: StatusCode,
        /// The OAuth error.
        error: OAuthError,
        /// The claims challenge the response returned, as received.
        challenge: Option<String>,
    },
    /// The response carries a refresh token, which the client never asks
    /// for and refuses.
    #[error("the token endpoint issued a refresh token")]
    RefreshToken,
    /// A token-exchange response names no `issued_token_type`, or one the
    /// client does not use (RFC 8693 §2.2.1).
    #[error("the token endpoint issued a token of type {found:?}")]
    IssuedTokenType {
        /// The type it named.
        found: Option<String>,
    },
    /// The issued token fails the onward check.
    #[error("the issued token fails the onward check")]
    Rejected(#[from] Rejected),
}

impl OnwardError {
    /// Returns the status the authorization server answered, when the
    /// failure carries one.
    #[must_use]
    pub const fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Token(error) => error.status(),
            Self::InteractionRequired { status, .. } => Some(*status),
            _ => None,
        }
    }
}
