// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The onward check: the rules an issued token passes before it is used,
//! run on the token as issued and again on every cache hit.
//!
//! The token is decoded, never verified: it arrived from the token endpoint
//! over the TLS connection the client opened (RFC 6749 §3.2), and RFC 8693
//! §2.3 keeps its signature opaque to the client. Which rules apply beside
//! the audience, the lifetime, the expected form and the actor depends on
//! the route the issuer's kind decides. No specification governs the check:
//! our own design over RFC 8693 §2.1 and §4.1 and RFC 8707 §2.

use serde_json::Map;
use serde_json::Value;

use crate::client::onward::AssertionWindow;
use crate::client::onward::Rejected;
use crate::client::onward::SubjectToken;
use crate::client::onward::Target;
use crate::federation::Attribute;
use crate::federation::Context;
use crate::federation::External;
use crate::federation::Field;
use crate::kind::Actor;
use crate::kind::CallerKind;
use crate::kind::IssuerKind;
use crate::profile::Profile;
use crate::resource::Settings;
use crate::roles::lookup;

/// What one onward issuer holds every token it issues to.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Route<'a> {
    /// The issuer's settings: its identifier, kind, profile and tables.
    pub(crate) issuer: &'a Settings,
    /// The requesting client, the actor a token names when no actor token
    /// was sent.
    pub(crate) client_id: &'a str,
    /// The issuer's `max_onward_lifetime`, in seconds.
    pub(crate) lifetime: u64,
}

/// Returns the claims of `token`, a JWS in compact serialization whose
/// payload is a JSON object (RFC 7515 §7.1).
pub(crate) fn decode(token: &str) -> Result<Map<String, Value>, Rejected> {
    let mut parts = token.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Rejected::NotJwt);
    };
    crate::jws::object(payload).ok_or(Rejected::NotJwt)
}

/// Checks `issued`, the claims of a token `route` issued for `target` on
/// behalf of `subject`, at `now` in seconds since the epoch; `actor` is the
/// actor token's actor, when one was sent.
pub(crate) fn check(
    route: &Route<'_>,
    target: &Target,
    subject: &SubjectToken,
    actor: Option<&Actor>,
    issued: &Map<String, Value>,
    now: i64,
) -> Result<(), Rejected> {
    let settings = route.issuer;
    if issued.get("iss").and_then(Value::as_str) != Some(settings.issuer.as_str()) {
        return Err(Rejected::Issuer);
    }
    audience(issued, target)?;
    lifetime(issued, subject, route.lifetime, now)?;
    named_actor(route, actor, issued)?;
    match settings.kind {
        IssuerKind::Federation => federation(settings, target, subject, issued),
        IssuerKind::Smart if *subject.kind() == CallerKind::Patient => {
            person(subject, issued)?;
            patient(subject, issued)
        }
        IssuerKind::Smart => person(subject, issued),
    }
}

/// Checks that `issued` names an audience and only audiences of `target`.
fn audience(issued: &Map<String, Value>, target: &Target) -> Result<(), Rejected> {
    // NOTE: RFC 7519 §4.1.3, `aud` is one string or an array of strings; RFC
    // 8707 §2 has a token for one target never reach another.
    let Ok(Some(named)) = crate::jws::claims::audience(issued) else {
        return Err(Rejected::Audience);
    };
    let inside = named
        .iter()
        .all(|value| target.audiences().iter().any(|listed| listed == value));
    if named.is_empty() || !inside {
        return Err(Rejected::Audience);
    }
    Ok(())
}

/// Checks that `issued` lives no longer than `lifetime` seconds from its
/// `iat`, and that neither it nor the subject token has expired at `now`.
fn lifetime(
    issued: &Map<String, Value>,
    subject: &SubjectToken,
    lifetime: u64,
    now: i64,
) -> Result<(), Rejected> {
    let iat = issued
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or(Rejected::MissingClaim { claim: "iat" })?;
    let exp = issued
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(Rejected::MissingClaim { claim: "exp" })?;
    let limit = iat.saturating_add(i64::try_from(lifetime).unwrap_or(i64::MAX));
    if exp > limit {
        return Err(Rejected::Lifetime);
    }
    let subject_expired = subject
        .claims()
        .get("exp")
        .and_then(Value::as_i64)
        .is_some_and(|subject_exp| subject_exp <= now);
    if exp <= now || subject_expired {
        return Err(Rejected::Expired);
    }
    windows(subject, exp)
}

/// The clock drift the eHDSI windows admit: "within 60 seconds of the
/// validity window boundaries" (SAML Profile 10.0.0 §2.1, §4.1).
const DRIFT: i64 = 60;

/// Checks that an `exp` does not outlive the identity assertion or the
/// treatment confirmation window a contact-point caller carries, plus the
/// drift; a caller without them is not held.
fn windows(subject: &SubjectToken, exp: i64) -> Result<(), Rejected> {
    let Some(external) = subject.kind().external() else {
        return Ok(());
    };
    for window in [AssertionWindow::Identity, AssertionWindow::Treatment] {
        let Some(end) = external.field(window.field()) else {
            continue;
        };
        // NOTE: SAML Profile 10.0.0 §2.1 and §4.1 bound the assertions; a token issued on
        // their strength may not outlive them, and an unreadable end fails closed (our own design).
        let within = end
            .text()
            .and_then(|text| text.parse::<i64>().ok())
            .is_some_and(|end| exp <= end.saturating_add(DRIFT));
        if !within {
            return Err(Rejected::AssertionWindow(window));
        }
    }
    Ok(())
}

/// Checks that `issued` names the requesting client as its actor: in `act`
/// (RFC 8693 §4.1), or, with no `act`, as its `client_id`.
fn named_actor(
    route: &Route<'_>,
    actor: Option<&Actor>,
    issued: &Map<String, Value>,
) -> Result<(), Rejected> {
    let profile = &route.issuer.profile;
    match issued.get("act") {
        Some(act) => {
            let token_issuer = issued.get("iss").and_then(Value::as_str).unwrap_or("");
            let named = crate::kind::actor(act, token_issuer, profile.max_actor_chain)
                .map_err(|_chain| Rejected::Actor)?;
            let expected = actor.cloned().unwrap_or_else(|| Actor {
                issuer: route.issuer.issuer.clone(),
                sub: route.client_id.to_owned(),
            });
            if named == expected {
                Ok(())
            } else {
                Err(Rejected::Actor)
            }
        }
        // NOTE: RFC 8693 §4.1, a delegated token names its actor in `act`, so
        // an actor token sent and no `act` issued is no delegation.
        None if actor.is_some() => Err(Rejected::Actor),
        None if Profile::client(issued) == Some(route.client_id) => Ok(()),
        None => Err(Rejected::Actor),
    }
}

/// Checks that `issued` names the subject token's person by `iss` and
/// `sub`, which together name one user (OpenID Connect Core 1.0 §5.7).
fn person(subject: &SubjectToken, issued: &Map<String, Value>) -> Result<(), Rejected> {
    for claim in ["iss", "sub"] {
        let held = subject.claims().get(claim).filter(|value| !value.is_null());
        if held.is_none() || held != issued.get(claim) {
            return Err(Rejected::Person {
                claim: claim.to_owned(),
            });
        }
    }
    Ok(())
}

/// Checks that `issued` names a `Patient` as its `fhirUser` and the
/// subject token's patient context by every claim of it the subject token
/// carries.
fn patient(subject: &SubjectToken, issued: &Map<String, Value>) -> Result<(), Rejected> {
    let fhir_user = issued.get("fhirUser").and_then(Value::as_str);
    if fhir_user.and_then(crate::kind::fhir_user_type) != Some("Patient") {
        return Err(Rejected::Patient);
    }
    for claim in subject.patient_context() {
        let held = lookup(subject.claims(), claim).filter(|value| !value.is_null());
        if held.is_some() && held != lookup(issued, claim) {
            return Err(Rejected::PatientContext {
                claim: claim.to_owned(),
            });
        }
    }
    Ok(())
}

/// Checks that a `federation` issuer is trusted to map the subject token's
/// issuer, that `issued` reads under its table, that it names the mapped
/// professional, that it keeps the subject's consent decision reference
/// and correlation id, and that a chained route carries the correlation
/// claim.
fn federation(
    settings: &Settings,
    target: &Target,
    subject: &SubjectToken,
    issued: &Map<String, Value>,
) -> Result<(), Rejected> {
    let section = settings.federation.as_ref().ok_or(Rejected::NotMapped)?;
    if !section
        .exchanges_from
        .iter()
        .any(|listed| listed == subject.issuer())
    {
        return Err(Rejected::NotMapped);
    }
    let assessment = settings
        .assurance
        .as_ref()
        .map(|assurance| assurance.assess(issued))
        .unwrap_or_default();
    let context = Context {
        section,
        audiences: target.audiences(),
        level: assessment.level,
        levels: settings
            .assurance
            .as_ref()
            .map(|assurance| &assurance.levels),
    };
    let classified = crate::kind::classify(
        IssuerKind::Federation,
        &settings.profile,
        Some(&context),
        issued,
        &settings.issuer,
    )
    .map_err(Rejected::Federation)?;
    let subject_is_person = !matches!(
        subject.kind(),
        CallerKind::System | CallerKind::ExternalOrganisation(_)
    );
    match &classified.kind {
        CallerKind::ExternalPerson(external) => {
            // NOTE: RFC 9396 §12, "No additional transformation or
            // normalization is to be done in evaluating equivalence".
            let mapped = section
                .person_mapping
                .as_deref()
                .and_then(|path| lookup(subject.claims(), path))
                .and_then(Value::as_str);
            let named = external
                .field(Field::ProfessionalHpIdentifier)
                .and_then(Attribute::text);
            if mapped.is_none() || mapped != named {
                return Err(Rejected::PersonMapping);
            }
        }
        CallerKind::ExternalOrganisation(_) if !subject_is_person => {}
        _ => return Err(Rejected::PersonMapping),
    }
    let held = subject.kind().external();
    let kept = classified.kind.external();
    // NOTE: IHE BALP 1.1.4 3:5.7.6 records the Consent an authorization rests on; an
    // onward token that drops or swaps the subject's is refused (our own design).
    if let Some(reference) = held.and_then(External::consent_reference)
        && kept.and_then(External::consent_reference) != Some(reference)
    {
        return Err(Rejected::Consent);
    }
    // NOTE: no specification governs this: our own design; each hop of a chained
    // organisation request carries the requester's correlation id unchanged.
    if let Some(id) = held.and_then(External::correlation_id)
        && kept.and_then(External::correlation_id) != Some(id)
    {
        return Err(Rejected::Correlation);
    }
    if let Some(claim) = target.correlation_claim() {
        let held = lookup(subject.claims(), claim).filter(|value| !value.is_null());
        if held.is_none() || held != lookup(issued, claim) {
            return Err(Rejected::Correlation);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::decode;
    use crate::client::onward::Rejected;
    use base64::Engine as _;

    fn segment(json: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
    }

    #[test]
    fn a_compact_jws_decodes_to_its_claims() {
        let token = format!("{}.{}.sig", segment("{}"), segment(r#"{"sub":"a"}"#));
        let claims = decode(&token).expect("the payload reads");
        assert_eq!(Some("a"), claims.get("sub").and_then(|sub| sub.as_str()));
    }

    #[test]
    fn anything_but_a_compact_jws_object_is_not_a_jwt() {
        let object = segment(r#"{"sub":"a"}"#);
        for token in [
            String::from("opaque"),
            format!("{object}.{object}"),
            format!("h.{object}.s.extra.parts"),
            format!("h.{}.s", segment("[1]")),
            String::from("h.%%%.s"),
        ] {
            assert_eq!(Err(Rejected::NotJwt), decode(&token), "{token}");
        }
    }
}
