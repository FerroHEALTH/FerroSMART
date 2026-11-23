// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Why a request is refused at the gate, and the status and challenge it is
//! answered with.
//!
//! A missing credential is challenged without an error code and an invalid
//! one with `invalid_token`; a token that grants no permission for the
//! request is `403` with `insufficient_scope`; two credentials or a
//! malformed `Authorization` value is `400` with `invalid_request`
//! (RFC 6750 §3.1); a token whose authentication event falls short of what
//! the resource requires is `401` with `insufficient_user_authentication`
//! (RFC 9470 §3). Each refusal of a credential carries a stable reason code
//! ([`Reason`]) as the challenge's `error_description` (RFC 6750 §3), so an
//! operator sees why a token was refused; the code names a check, never a
//! claim value or a scope. The body a product sends with the status is the
//! product's own (a FHIR `OperationOutcome`, an openEHR error body).

use http::StatusCode;

use crate::federation::contact::EhdsiCode;
use crate::kind::Unclassified;
use crate::resource::Caller;
use crate::resource::Rejection;

/// The authentication schemes a gate admits, which a missing-credential
/// challenge lists (RFC 9110 §11.6.1 allows several challenges).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Schemes {
    /// Whether a `Bearer` token is admitted (RFC 6750).
    pub bearer: bool,
    /// Whether a `Basic` credential is admitted (RFC 7617).
    pub basic: bool,
    /// Whether a `DPoP`-bound token is admitted (RFC 9449 §7.1).
    pub dpop: bool,
}

/// Why a request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The request carries no credential of a scheme the gate admits.
    Missing(Schemes),
    /// The request carries two credentials, or an `Authorization` value
    /// that is no credential at all (RFC 6750 §3.1, `invalid_request`).
    InvalidRequest,
    /// The bearer token does not hold (RFC 6750 §3.1, `invalid_token`).
    InvalidToken,
    /// The token of a `DPoP` request does not hold, or is not bound to the
    /// proof's key (RFC 9449 §7.1, `invalid_token` under the `DPoP` scheme).
    InvalidDpopToken,
    /// The `DPoP` proof does not hold (RFC 9449 §7.1, `invalid_dpop_proof`).
    InvalidDpopProof,
    /// The Basic credential does not hold.
    InvalidBasic,
    /// The credential holds, and it grants no permission for the request
    /// (RFC 6750 §3.1, `insufficient_scope`).
    Forbidden,
    /// The token could not be checked at all: the authorization server's key
    /// set, or the upstream a product's verifier calls, could not be read.
    Unavailable,
    /// The token holds, and the authentication event behind it does not
    /// meet what the resource requires (RFC 9470 §3,
    /// `insufficient_user_authentication`).
    StepUp(StepUp),
    /// The route is one the gate cannot classify, which fails closed (no
    /// specification governs this: our own design).
    Unclassified,
}

impl Refusal {
    /// Returns the status the refusal is answered with.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::Missing(_)
            | Self::InvalidToken
            | Self::InvalidDpopToken
            | Self::InvalidDpopProof
            | Self::InvalidBasic
            | Self::StepUp(_) => StatusCode::UNAUTHORIZED,
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::Forbidden | Self::Unclassified => StatusCode::FORBIDDEN,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// Returns the `WWW-Authenticate` value of the refusal, `realm` named
    /// on each challenge when given, or `None` for a status that carries no
    /// challenge.
    ///
    /// The Basic challenge always names a realm and the UTF-8 charset
    /// (RFC 7617 §2, §2.1), the realm given or an empty one.
    #[must_use]
    pub fn challenge(&self, realm: Option<&str>) -> Option<String> {
        self.challenge_described(realm, None)
    }

    /// Returns [`Refusal::challenge`] with `description` as the
    /// `error_description` of the challenge that carries an error code.
    fn challenge_described(
        &self,
        realm: Option<&str>,
        description: Option<&str>,
    ) -> Option<String> {
        let quoted = realm.map(quote);
        // NOTE: RFC 9110 §11.3, auth-params follow the scheme after one
        // space and are comma-separated; RFC 6750 §3 puts realm before error.
        let challenge = |scheme: &str, error: Option<&str>, extra: Vec<String>| {
            let mut params: Vec<String> = Vec::new();
            if let Some(realm) = &quoted {
                params.push(format!("realm={realm}"));
            }
            if let Some(error) = error {
                params.push(format!("error=\"{error}\""));
                if let Some(description) = description {
                    params.push(format!("error_description=\"{description}\""));
                }
            }
            params.extend(extra);
            if params.is_empty() {
                scheme.to_owned()
            } else {
                format!("{scheme} {}", params.join(", "))
            }
        };
        let bearer_with = |error: Option<&str>, extra| challenge("Bearer", error, extra);
        let bearer = |error: Option<&str>| bearer_with(error, Vec::new());
        // NOTE: RFC 9449 §7.1, the `DPoP` challenge takes `realm` and `error` as
        // the `Bearer` one does; `algs` is a SHOULD this challenge leaves out.
        let dpop = |error: Option<&str>| challenge("DPoP", error, Vec::new());
        let basic = || {
            let realm = quoted.as_deref().unwrap_or("\"\"");
            format!("Basic realm={realm}, charset=\"UTF-8\"")
        };
        match self {
            Self::Missing(schemes) => {
                let mut challenges = Vec::new();
                if schemes.bearer {
                    challenges.push(bearer(None));
                }
                if schemes.bearer && schemes.dpop {
                    challenges.push(dpop(None));
                }
                if schemes.basic {
                    challenges.push(basic());
                }
                if challenges.is_empty() {
                    None
                } else {
                    Some(challenges.join(", "))
                }
            }
            Self::InvalidRequest => Some(bearer(Some("invalid_request"))),
            Self::InvalidToken => Some(bearer(Some("invalid_token"))),
            Self::InvalidDpopToken => Some(dpop(Some("invalid_token"))),
            Self::InvalidDpopProof => Some(dpop(Some("invalid_dpop_proof"))),
            Self::InvalidBasic => Some(basic()),
            Self::Forbidden => Some(bearer(Some("insufficient_scope"))),
            // NOTE: RFC 9470 §3, the error code with `acr_values` and `max_age` as
            // auth-params; values are quoted strings, max_age a non-negative integer.
            Self::StepUp(step_up) => {
                let mut extra = Vec::new();
                if !step_up.acr_values.is_empty() {
                    extra.push(format!("acr_values=\"{}\"", step_up.acr_values.join(" ")));
                }
                if let Some(max_age) = step_up.max_age {
                    extra.push(format!("max_age=\"{max_age}\""));
                }
                Some(bearer_with(Some("insufficient_user_authentication"), extra))
            }
            Self::Unavailable | Self::Unclassified => None,
        }
    }

    /// Returns the RFC 6750 §3.1 error code (or this crate's name for a
    /// refusal that has none), never a claim value.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Missing(_) => "missing",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidToken => "invalid_token",
            Self::InvalidDpopToken => "invalid_dpop_token",
            Self::InvalidDpopProof => "invalid_dpop_proof",
            Self::InvalidBasic => "invalid_basic",
            Self::Forbidden => "insufficient_scope",
            Self::Unavailable => "unavailable",
            Self::StepUp(_) => "insufficient_user_authentication",
            Self::Unclassified => "unclassified",
        }
    }
}

/// What the resource requires of the authentication event behind a token,
/// and the challenge that tells the client (RFC 9470 §3).
///
/// What a resource requires is the product's decision ("out of scope" of
/// RFC 9470 §3); the crate checks it against the token's `acr` and
/// `auth_time` claims (§6) and renders the challenge.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StepUp {
    /// The authentication context class references, one of which the
    /// authentication event must carry, in order of preference; empty for
    /// no requirement.
    acr_values: Vec<String>,
    /// The longest time in seconds since the last active authentication
    /// event, when the resource requires one.
    max_age: Option<u64>,
}

/// An `acr` value that cannot travel in the challenge.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "the acr value {value:?} is empty or carries a space, a quote, a backslash or a byte outside visible ASCII"
)]
pub struct AcrValueError {
    /// The value refused.
    pub value: String,
}

impl StepUp {
    /// Returns a step-up challenge that names no requirement.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns this challenge requiring one of `values`, in order of
    /// preference.
    ///
    /// # Errors
    ///
    /// Returns [`AcrValueError`] for a value that is empty or carries a
    /// byte outside visible ASCII, a space (the list separator of RFC 9470
    /// §3), a quote or a backslash.
    pub fn with_acr_values<I, S>(mut self, values: I) -> Result<Self, AcrValueError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for value in values {
            let value = value.into();
            let travels = !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\');
            if !travels {
                return Err(AcrValueError { value });
            }
            self.acr_values.push(value);
        }
        Ok(self)
    }

    /// Returns this challenge requiring an authentication event at most
    /// `seconds` old.
    #[must_use]
    pub const fn with_max_age(mut self, seconds: u64) -> Self {
        self.max_age = Some(seconds);
        self
    }

    /// Returns the `acr` values one of which is required.
    #[must_use]
    pub fn acr_values(&self) -> &[String] {
        &self.acr_values
    }

    /// Returns the longest time since the authentication event, in seconds.
    #[must_use]
    pub const fn max_age(&self) -> Option<u64> {
        self.max_age
    }

    /// Returns whether `caller`'s authentication event meets the
    /// requirement: its `acr` is one of the values, when any is named, and
    /// its `auth_time` is at most `max_age` seconds ago, when one is named.
    ///
    /// A token without the claim a requirement reads does not meet it
    /// (RFC 9470 §6 conveys both in the access token).
    #[must_use]
    pub fn satisfied_by(&self, caller: &Caller) -> bool {
        let acr = self.acr_values.is_empty()
            || caller
                .acr()
                .is_some_and(|acr| self.acr_values.iter().any(|value| value == acr));
        let recent = self.max_age.is_none_or(|max_age| {
            caller.auth_time().is_some_and(|auth_time| {
                let elapsed = jiff::Timestamp::now().as_second().saturating_sub(auth_time);
                u64::try_from(elapsed).map_or(true, |elapsed| elapsed <= max_age)
            })
        });
        acr && recent
    }

    /// Returns the refusal that answers with this challenge.
    #[must_use]
    pub fn into_refusal(self) -> Refusal {
        Refusal::StepUp(self)
    }
}

/// Which check refused a credential, by a stable reason code.
///
/// The gate logs the code at info with the token's issuer, client id and
/// key id, and [`Denied::challenge`] sends it as the `error_description`
/// of the `401` or `403` (RFC 6750 §3), so an operator reads why a token was
/// refused without debug logging. A code names a check and never carries a
/// claim value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    /// Two `Authorization` header fields arrived (RFC 6750 §3.1).
    TwoCredentials,
    /// The `Authorization` value is not a scheme and a credential.
    MalformedHeader,
    /// The bearer token is outside the `b64token` syntax of RFC 6750 §2.1.
    NotB64Token,
    /// The token does not parse as a JWS in compact serialization.
    Malformed,
    /// The header names an algorithm outside the configured set.
    Algorithm,
    /// The `typ` header names another kind of token (RFC 9068 §4).
    Type,
    /// No key of the issuer's set verifies the token.
    UnknownKey,
    /// The signature does not verify.
    Signature,
    /// The token has expired.
    Expired,
    /// The token is not yet valid (`nbf`).
    NotYetValid,
    /// The token was issued in the future beyond the clock skew.
    IssuedInFuture,
    /// The `iss` claim is not the configured issuer.
    Issuer,
    /// The `iss` claim names no issuer the product trusts.
    UntrustedIssuer,
    /// The `aud` claim names no configured audience.
    Audience,
    /// A claim the token profile requires is absent.
    MissingClaim,
    /// The `sub` claim is not a string.
    Subject,
    /// The `sub` claim is empty or whitespace only, which identifies no
    /// principal (RFC 9068 §2.2, RFC 7519 §4.1.2).
    BlankSubject,
    /// The introspection endpoint answered that the token is not active
    /// (RFC 7662 §2.2).
    Inactive,
    /// The key set could not be read to check the token.
    KeySetUnavailable,
    /// The issuer's metadata or key set has not been read since the start.
    IssuerUnread,
    /// An upstream a product's verifier calls could not be read to check
    /// the token.
    UpstreamUnavailable,
    /// The Basic credential is not the RFC 7617 §2 form.
    BasicMalformed,
    /// The Basic user is unknown or the password does not match.
    BasicRejected,
    /// The Basic credential's verification did not complete.
    BasicIncomplete,
    /// The credential holds, and it grants no permission for the request.
    ScopeNotGranted,
    /// The route is one the gate cannot classify.
    RouteUnclassified,
    /// The party source could not answer for the caller's login.
    PartySourceUnavailable,
    /// The token matches no step of the caller classification for its
    /// issuer's kind, with the step's code ([`crate::kind::Unclassified::code`]).
    Unclassified(&'static str),
    /// The product refuses the caller's party binding, with the outcome's
    /// code ([`crate::party::Outcome::refusal_reason`]).
    Party(&'static str),
    /// A sender-constrained token or its `DPoP` proof failed a check
    /// ([`crate::sender`]).
    Sender(crate::sender::Check),
    /// A reason a product's own [`crate::resource::Verifier`] names: a
    /// code in the same form (lower-case ASCII words joined by `-`), which
    /// the challenge carries only in that form.
    Other(&'static str),
}

impl Reason {
    /// Returns the stable reason code: the info log names it, and the
    /// `WWW-Authenticate` `error_description` carries it.
    ///
    /// A code is lower-case ASCII words joined by `-`, and never changes
    /// meaning once published; the book lists every code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TwoCredentials => "two-credentials",
            Self::MalformedHeader => "malformed-header",
            Self::NotB64Token => "not-b64token",
            Self::Malformed => "malformed-token",
            Self::Algorithm => "algorithm-refused",
            Self::Type => "type-mismatch",
            Self::UnknownKey => "key-unknown",
            Self::Signature => "signature-invalid",
            Self::Expired => "expired",
            Self::NotYetValid => "not-yet-valid",
            Self::IssuedInFuture => "issued-in-future",
            Self::Issuer => "issuer-mismatch",
            Self::UntrustedIssuer => "issuer-unknown",
            Self::Audience => "audience-mismatch",
            Self::MissingClaim => "claim-missing",
            Self::Subject => "subject-not-string",
            Self::BlankSubject => "subject-blank",
            Self::Inactive => "token-inactive",
            Self::KeySetUnavailable => "key-set-unavailable",
            Self::IssuerUnread => "issuer-unread",
            Self::UpstreamUnavailable => "upstream-unavailable",
            Self::BasicMalformed => "basic-malformed",
            Self::BasicRejected => "basic-rejected",
            Self::BasicIncomplete => "basic-incomplete",
            Self::ScopeNotGranted => "scope-not-granted",
            Self::RouteUnclassified => "route-unclassified",
            Self::PartySourceUnavailable => "party-source-unavailable",
            Self::Sender(check) => check.as_str(),
            Self::Unclassified(code) | Self::Party(code) | Self::Other(code) => code,
        }
    }
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refusal at the gate with the reason behind it.
///
/// The product answers with [`Refusal::status`] and [`Denied::challenge`],
/// which carries the reason code as `error_description`. A contact point also answers [`Denied::ehdsi`], the
/// MyHealth@EU Requirements Catalogue 10.0.0 §1.25 code of the refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    /// What the request is answered with.
    refusal: Refusal,
    /// Which check refused it, when one did.
    reason: Option<Reason>,
    /// The §1.25 code the contact-point check refused the token with.
    ehdsi: Option<EhdsiCode>,
}

impl Denied {
    /// Returns the denial answered with `refusal`, refused by `reason`.
    #[must_use]
    pub const fn new(refusal: Refusal, reason: Option<Reason>) -> Self {
        Self {
            refusal,
            reason,
            ehdsi: None,
        }
    }

    /// Returns what the request is answered with.
    #[must_use]
    pub const fn refusal(&self) -> &Refusal {
        &self.refusal
    }

    /// Returns which check refused the credential, or `None` when no
    /// credential was examined (none arrived).
    #[must_use]
    pub const fn reason(&self) -> Option<Reason> {
        self.reason
    }

    /// Returns the stable code the info log names: the reason's
    /// ([`Reason::as_str`]), or for a denial no check refused, the
    /// refusal's (`credential-missing`, `credential-unchecked`).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match (self.reason, &self.refusal) {
            (Some(reason), _) => reason.as_str(),
            (None, Refusal::Missing(_)) => "credential-missing",
            (None, Refusal::Forbidden) => "scope-not-granted",
            (None, Refusal::Unclassified) => "route-unclassified",
            (None, Refusal::StepUp(_)) => "authentication-insufficient",
            (None, _) => "credential-unchecked",
        }
    }

    /// Returns the `WWW-Authenticate` value of the denial, `realm` named on
    /// each challenge when given, or `None` for a status that carries no
    /// challenge.
    ///
    /// The challenge is [`Refusal::challenge`]'s with the reason code as
    /// `error_description` (RFC 6750 §3) on every `Bearer` or `DPoP`
    /// challenge that carries an error code. A missing credential carries
    /// none (RFC 6750 §3.1), and neither does Basic, whose scheme defines
    /// no such parameter (RFC 7617 §2).
    #[must_use]
    pub fn challenge(&self, realm: Option<&str>) -> Option<String> {
        let described = matches!(
            self.refusal,
            Refusal::InvalidRequest
                | Refusal::InvalidToken
                | Refusal::InvalidDpopToken
                | Refusal::InvalidDpopProof
                | Refusal::Forbidden
                | Refusal::StepUp(_)
        );
        let code = self.code();
        // NOTE: RFC 6750 §3, `error-description` is visible ASCII without
        // `"` or `\`; a product code outside the code form is left out.
        let travels = !code.is_empty()
            && code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        self.refusal
            .challenge_described(realm, (described && travels).then_some(code))
    }

    /// Returns the MyHealth@EU Requirements Catalogue 10.0.0 §1.25 code
    /// the contact-point check of [`crate::federation::contact`] refused the
    /// token with, by its code name ([`EhdsiCode::as_str`]) and requirement
    /// id ([`EhdsiCode::requirement`]).
    ///
    /// `None` for every other refusal, which a contact point answers with
    /// `ERROR_SEC_GENERIC` ([`EhdsiCode::of`]).
    #[must_use]
    pub const fn ehdsi(&self) -> Option<EhdsiCode> {
        self.ehdsi
    }

    /// Returns this denial answered with `refusal` instead, keeping the
    /// reason and the §1.25 code.
    #[cfg(feature = "axum")]
    #[must_use]
    pub(crate) fn answered_with(self, refusal: Refusal) -> Self {
        Self { refusal, ..self }
    }

    /// Returns the refusal, dropping the reason.
    #[must_use]
    pub fn into_refusal(self) -> Refusal {
        self.refusal
    }
}

impl From<Refusal> for Denied {
    fn from(refusal: Refusal) -> Self {
        Self::new(refusal, None)
    }
}

impl From<Denied> for Refusal {
    fn from(denied: Denied) -> Self {
        denied.refusal
    }
}

impl From<&Rejection> for Denied {
    fn from(rejection: &Rejection) -> Self {
        let reason = match rejection {
            Rejection::Missing => None,
            Rejection::Invalid { reason } => Some(*reason),
            Rejection::Unclassified { reason } => Some(Reason::Unclassified(reason.code())),
            Rejection::Unavailable { .. } => Some(Reason::KeySetUnavailable),
            Rejection::Unread { .. } => Some(Reason::IssuerUnread),
            Rejection::Upstream { .. } => Some(Reason::UpstreamUnavailable),
        };
        let ehdsi = match rejection {
            Rejection::Unclassified {
                reason: Unclassified::ContactPoint { code, .. },
            } => Some(*code),
            _ => None,
        };
        Self {
            ehdsi,
            ..Self::new(Refusal::from(rejection), reason)
        }
    }
}

impl From<&Rejection> for Refusal {
    fn from(rejection: &Rejection) -> Self {
        match rejection {
            Rejection::Missing => Self::Missing(Schemes {
                bearer: true,
                basic: false,
                dpop: false,
            }),
            Rejection::Invalid {
                reason: Reason::Sender(check),
            } if check.is_proof() => Self::InvalidDpopProof,
            Rejection::Invalid { .. } | Rejection::Unclassified { .. } => Self::InvalidToken,
            Rejection::Unavailable { .. }
            | Rejection::Unread { .. }
            | Rejection::Upstream { .. } => Self::Unavailable,
        }
    }
}

/// Returns `realm` as an RFC 9110 §5.6.4 quoted string.
fn quote(realm: &str) -> String {
    let mut quoted = String::with_capacity(realm.len().saturating_add(2));
    quoted.push('"');
    for character in realm.chars() {
        if character == '"' || character == '\\' {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use super::{Denied, Reason, Refusal, Schemes, StepUp};
    use crate::federation::contact::EhdsiCode;
    use crate::kind::Unclassified;
    use crate::resource::{Caller, Rejection};
    use http::StatusCode;

    #[test]
    fn a_denial_carries_its_reason_and_the_challenge_names_none() {
        let denied = Denied::from(&Rejection::Invalid {
            reason: Reason::Expired,
        });
        assert_eq!(&Refusal::InvalidToken, denied.refusal());
        assert_eq!(Some(Reason::Expired), denied.reason());
        assert_eq!("expired", Reason::Expired.to_string());
        assert_eq!(
            Some(String::from("Bearer error=\"invalid_token\"")),
            denied.refusal().challenge(None),
            "RFC 6750 §3.1: the reason stays off the wire"
        );
        assert_eq!(None, Denied::from(&Rejection::Missing).reason());
        assert_eq!(
            Refusal::InvalidToken,
            Refusal::from(Denied::new(Refusal::InvalidToken, None))
        );
    }

    /// Every code the crate names, each with what names it.
    fn every_code() -> Vec<(String, &'static str)> {
        let reasons = [
            (Reason::TwoCredentials, "two-credentials"),
            (Reason::MalformedHeader, "malformed-header"),
            (Reason::NotB64Token, "not-b64token"),
            (Reason::Malformed, "malformed-token"),
            (Reason::Algorithm, "algorithm-refused"),
            (Reason::Type, "type-mismatch"),
            (Reason::UnknownKey, "key-unknown"),
            (Reason::Signature, "signature-invalid"),
            (Reason::Expired, "expired"),
            (Reason::NotYetValid, "not-yet-valid"),
            (Reason::IssuedInFuture, "issued-in-future"),
            (Reason::Issuer, "issuer-mismatch"),
            (Reason::UntrustedIssuer, "issuer-unknown"),
            (Reason::Audience, "audience-mismatch"),
            (Reason::MissingClaim, "claim-missing"),
            (Reason::Subject, "subject-not-string"),
            (Reason::BlankSubject, "subject-blank"),
            (Reason::Inactive, "token-inactive"),
            (Reason::KeySetUnavailable, "key-set-unavailable"),
            (Reason::IssuerUnread, "issuer-unread"),
            (Reason::UpstreamUnavailable, "upstream-unavailable"),
            (Reason::BasicMalformed, "basic-malformed"),
            (Reason::BasicRejected, "basic-rejected"),
            (Reason::BasicIncomplete, "basic-incomplete"),
            (Reason::ScopeNotGranted, "scope-not-granted"),
            (Reason::RouteUnclassified, "route-unclassified"),
            (Reason::PartySourceUnavailable, "party-source-unavailable"),
        ];
        let mut codes: Vec<(String, &'static str)> = reasons
            .iter()
            .map(|(reason, code)| {
                assert_eq!(*code, reason.as_str(), "{reason:?}");
                (format!("{reason:?}"), *code)
            })
            .collect();
        codes.extend(unclassified_codes());
        codes.extend(sender_and_party_codes());
        codes
    }

    /// The code of every classification step.
    fn unclassified_codes() -> Vec<(String, &'static str)> {
        let mut codes = Vec::new();
        let unclassified = [
            (Unclassified::ScopeForm, "scope-form"),
            (Unclassified::NoClient, "client-missing"),
            (Unclassified::FhirUser, "fhir-user-refused"),
            (Unclassified::ActorChain, "actor-chain-refused"),
            (
                Unclassified::ExternalIncomplete { missing: vec![] },
                "professional-incomplete",
            ),
            (
                Unclassified::RequiredFields { missing: vec![] },
                "required-fields-missing",
            ),
            (
                Unclassified::OutOfBounds { field: "f" },
                "attribute-out-of-bounds",
            ),
            (Unclassified::Attribute { field: "f" }, "attribute-refused"),
            (
                Unclassified::SourcesDisagree { field: "f" },
                "sources-disagree",
            ),
            (
                Unclassified::AuthorizationDetails,
                "authorization-details-refused",
            ),
            (
                Unclassified::NoOrganisationStatement,
                "organisation-statement-missing",
            ),
            (Unclassified::AssuranceTooLow, "assurance-too-low"),
            (Unclassified::Presentations, "presentations-unreadable"),
            (
                Unclassified::ContactPoint {
                    code: EhdsiCode::SecDataIntegrityNotEnsured,
                    missing: vec![],
                },
                "contact-point-refused",
            ),
            (
                Unclassified::NoStep {
                    kind: crate::kind::IssuerKind::Federation,
                },
                "kind-unclassified",
            ),
        ];
        for (step, code) in unclassified {
            let denied = Denied::from(&Rejection::Unclassified {
                reason: step.clone(),
            });
            assert_eq!(
                Some(Reason::Unclassified(code)),
                denied.reason(),
                "{step:?}"
            );
            codes.push((format!("{step:?}"), code));
        }
        codes
    }

    /// The code of every sender check and every refused party outcome.
    fn sender_and_party_codes() -> Vec<(String, &'static str)> {
        use crate::sender::Check;
        let mut codes = Vec::new();
        let checks = [
            (Check::ProofMissing, "dpop-proof-missing"),
            (Check::ProofRepeated, "dpop-proof-repeated"),
            (Check::ProofMalformed, "dpop-proof-malformed"),
            (Check::ProofClaim, "dpop-proof-claim-missing"),
            (Check::ProofJti, "dpop-proof-jti-too-long"),
            (Check::ProofType, "dpop-proof-type"),
            (Check::ProofAlgorithm, "dpop-proof-algorithm"),
            (Check::ProofKey, "dpop-proof-key"),
            (Check::ProofSignature, "dpop-proof-signature"),
            (Check::ProofMethod, "dpop-proof-method"),
            (Check::ProofUri, "dpop-proof-uri"),
            (Check::ProofStale, "dpop-proof-stale"),
            (Check::ProofFuture, "dpop-proof-issued-in-future"),
            (Check::ProofTokenHash, "dpop-proof-token-hash"),
            (Check::ProofReplayed, "dpop-proof-replayed"),
            (Check::ProofRequestUnknown, "dpop-request-unknown"),
            (Check::KeyMismatch, "dpop-key-mismatch"),
            (Check::NotKeyBound, "dpop-key-unbound"),
            (Check::KeyBoundAsBearer, "dpop-bound-as-bearer"),
            (Check::CertificateMissing, "certificate-missing"),
            (Check::CertificateMismatch, "certificate-mismatch"),
            (Check::ConfirmationUnknown, "confirmation-unknown"),
            (Check::ConstraintRequired, "sender-constraint-required"),
            (Check::Unsupported, "dpop-unsupported"),
        ];
        for (check, code) in checks {
            assert_eq!(code, Reason::Sender(check).as_str(), "{check:?}");
            codes.push((format!("{check:?}"), code));
        }
        let outcomes = [
            (crate::party::Outcome::Unbound, "refused-unbound"),
            (
                crate::party::Outcome::Ambiguous { count: 2 },
                "refused-ambiguous",
            ),
            (
                crate::party::Outcome::Deprovisioned,
                "refused-deprovisioned",
            ),
            (
                crate::party::Outcome::KeyClaimMissing,
                "refused-key-claim-missing",
            ),
            (
                crate::party::Outcome::GroupsUnavailable(crate::party::GroupsCause::Malformed),
                "refused-groups-unavailable",
            ),
        ];
        for (outcome, code) in outcomes {
            assert_eq!(
                Some(Reason::Party(code)),
                outcome.refusal_reason(),
                "{outcome:?}"
            );
            codes.push((format!("{outcome:?}"), code));
        }
        codes
    }

    #[test]
    fn every_reason_code_is_pinned_unique_and_in_the_code_form() {
        let codes = every_code();
        let mut seen = std::collections::BTreeMap::new();
        for (named, code) in &codes {
            assert!(
                code.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
                "{named}: {code}"
            );
            if let Some(other) = seen.insert(*code, named) {
                panic!("{code} names both {other} and {named}");
            }
        }
    }

    #[test]
    fn the_challenge_carries_the_code_where_rfc_6750_has_an_error() {
        let expired = Denied::new(Refusal::InvalidToken, Some(Reason::Expired));
        assert_eq!(
            Some(String::from(
                "Bearer realm=\"ferro\", error=\"invalid_token\", error_description=\"expired\""
            )),
            expired.challenge(Some("ferro"))
        );
        let delegate = Denied::from(&Rejection::Unclassified {
            reason: Unclassified::ActorChain,
        });
        assert_eq!(
            Some(String::from(
                "Bearer error=\"invalid_token\", error_description=\"actor-chain-refused\""
            )),
            delegate.challenge(None)
        );
        let unbound = Denied::new(
            Refusal::Forbidden,
            crate::party::Outcome::Unbound.refusal_reason(),
        );
        assert_eq!(
            Some(String::from(
                "Bearer error=\"insufficient_scope\", error_description=\"refused-unbound\""
            )),
            unbound.challenge(None)
        );
        let missing = Denied::from(Refusal::Missing(Schemes {
            bearer: true,
            basic: false,
            dpop: false,
        }));
        assert_eq!("credential-missing", missing.code());
        assert_eq!(
            Some(String::from("Bearer")),
            missing.challenge(None),
            "RFC 6750 §3.1: no error information without a credential"
        );
        let basic = Denied::new(Refusal::InvalidBasic, Some(Reason::BasicRejected));
        assert_eq!(
            Some(String::from("Basic realm=\"\", charset=\"UTF-8\"")),
            basic.challenge(None),
            "RFC 7617 §2 defines no error_description"
        );
        let product = Denied::new(Refusal::InvalidToken, Some(Reason::Other("Not A Code")));
        assert_eq!(
            Some(String::from("Bearer error=\"invalid_token\"")),
            product.challenge(None),
            "a product reason outside the code form stays off the wire"
        );
        let unavailable = Denied::new(Refusal::Unavailable, Some(Reason::KeySetUnavailable));
        assert_eq!(None, unavailable.challenge(None));
        assert_eq!("key-set-unavailable", unavailable.code());
    }

    #[test]
    fn a_contact_point_denial_carries_its_code_and_others_none() {
        let rejection = Rejection::Unclassified {
            reason: Unclassified::ContactPoint {
                code: EhdsiCode::SecDataIntegrityNotEnsured,
                missing: vec!["exp"],
            },
        };
        let denied = Denied::from(&rejection);
        assert_eq!(Some(EhdsiCode::SecDataIntegrityNotEnsured), denied.ehdsi());
        assert_eq!(
            Some(Reason::Unclassified("contact-point-refused")),
            denied.reason()
        );
        #[cfg(feature = "axum")]
        {
            let dpop = denied.answered_with(Refusal::InvalidDpopToken);
            assert_eq!(&Refusal::InvalidDpopToken, dpop.refusal());
            assert_eq!(
                Some(EhdsiCode::SecDataIntegrityNotEnsured),
                dpop.ehdsi(),
                "the DPoP challenge keeps the code"
            );
        }
        assert_eq!(
            "11.01.02",
            EhdsiCode::SecDataIntegrityNotEnsured.requirement()
        );
        let invalid = Denied::from(&Rejection::Invalid {
            reason: Reason::Expired,
        });
        assert_eq!(None, invalid.ehdsi());
        assert_eq!(None, Denied::from(Refusal::Forbidden).ehdsi());
    }

    #[test]
    fn an_upstream_failure_of_a_product_verifier_answers_503() {
        let rejection = Rejection::upstream(
            "introspection endpoint",
            std::io::Error::other("connection refused"),
        );
        let denied = Denied::from(&rejection);
        assert_eq!(&Refusal::Unavailable, denied.refusal());
        assert_eq!(Some(Reason::UpstreamUnavailable), denied.reason());
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, denied.refusal().status());
        assert_eq!(None, denied.refusal().challenge(Some("ferro")));
        let source = std::error::Error::source(&rejection).map(ToString::to_string);
        assert_eq!(Some(String::from("connection refused")), source);
    }

    #[test]
    fn the_step_up_challenge_is_rfc_9470s() {
        let bare = StepUp::new().into_refusal();
        assert_eq!(StatusCode::UNAUTHORIZED, bare.status());
        assert_eq!(
            Some(String::from(
                "Bearer realm=\"ferro\", error=\"insufficient_user_authentication\""
            )),
            bare.challenge(Some("ferro"))
        );
        let both = StepUp::new()
            .with_acr_values(["urn:acr:high", "myACR"])
            .expect("visible ASCII")
            .with_max_age(5)
            .into_refusal();
        assert_eq!(
            Some(String::from(
                "Bearer error=\"insufficient_user_authentication\", acr_values=\"urn:acr:high myACR\", max_age=\"5\""
            )),
            both.challenge(None)
        );
        assert_eq!("insufficient_user_authentication", both.reason());
        for bad in ["", "a b", "a\"b", "a\\b", "ä"] {
            assert!(StepUp::new().with_acr_values([bad]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_step_up_requirement_reads_acr_and_auth_time() {
        let caller = |acr: Option<&str>, auth_time: Option<i64>| {
            let mut claims = serde_json::Map::new();
            if let Some(acr) = acr {
                claims.insert(String::from("acr"), serde_json::json!(acr));
            }
            if let Some(auth_time) = auth_time {
                claims.insert(String::from("auth_time"), serde_json::json!(auth_time));
            }
            Caller::new(
                String::from("doc"),
                None,
                "",
                None,
                crate::kind::CallerKind::Person,
            )
            .with_claims(claims)
        };
        let now = jiff::Timestamp::now().as_second();
        let level = StepUp::new()
            .with_acr_values(["high"])
            .expect("visible ASCII");
        assert!(level.satisfied_by(&caller(Some("high"), None)));
        assert!(
            !level.satisfied_by(&caller(Some("low"), None)),
            "another acr"
        );
        assert!(!level.satisfied_by(&caller(None, None)), "no acr");
        let recent = StepUp::new().with_max_age(300);
        assert!(recent.satisfied_by(&caller(None, Some(now - 10))));
        assert!(
            !recent.satisfied_by(&caller(None, Some(now - 3600))),
            "too old"
        );
        assert!(!recent.satisfied_by(&caller(None, None)), "no auth_time");
        assert!(
            StepUp::new().satisfied_by(&caller(None, None)),
            "no requirement"
        );
    }

    #[test]
    fn a_missing_credential_lists_every_admitted_scheme() {
        let both = Refusal::Missing(Schemes {
            bearer: true,
            basic: true,
            dpop: false,
        });
        assert_eq!(StatusCode::UNAUTHORIZED, both.status());
        assert_eq!(
            Some(String::from(
                "Bearer realm=\"ferro\", Basic realm=\"ferro\", charset=\"UTF-8\""
            )),
            both.challenge(Some("ferro"))
        );
        assert_eq!(
            Some(String::from("Bearer, Basic realm=\"\", charset=\"UTF-8\"")),
            both.challenge(None)
        );
    }

    #[test]
    fn the_error_codes_are_rfc_6750s() {
        assert_eq!(
            Some(String::from("Bearer error=\"invalid_token\"")),
            Refusal::InvalidToken.challenge(None)
        );
        assert_eq!(
            Some(String::from(
                "Bearer realm=\"a \\\"b\\\"\", error=\"insufficient_scope\""
            )),
            Refusal::Forbidden.challenge(Some("a \"b\""))
        );
        assert_eq!(StatusCode::FORBIDDEN, Refusal::Forbidden.status());
        assert_eq!(
            Some(String::from(
                "Bearer realm=\"ferro\", error=\"invalid_request\""
            )),
            Refusal::InvalidRequest.challenge(Some("ferro"))
        );
        assert_eq!(StatusCode::BAD_REQUEST, Refusal::InvalidRequest.status());
        assert_eq!(None, Refusal::Unavailable.challenge(Some("ferro")));
        assert_eq!(
            StatusCode::SERVICE_UNAVAILABLE,
            Refusal::Unavailable.status()
        );
    }
}
