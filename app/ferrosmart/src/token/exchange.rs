// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The token exchange of a patient's own token for a token at the openEHR
//! base paired with its FHIR base (RFC 8693 §2; `docs/architecture.md`
//! §13.29).
//!
//! A product that serves a person at a FHIR base reads the person's own
//! EHR at the paired openEHR base as them, so the CDR applies the person's
//! own-access rules and names them in its access record. The issued token
//! has the subject token's `sub`, `fhirUser`, `patient`, `acr` and
//! `auth_time`, the patient's `ehrId` at the openEHR base, and the
//! exchanging client as `client_id`, with no `act`: the product acts for
//! the person, never as someone else (3.14).

use std::net::IpAddr;
use std::time::Duration;

use serde_json::{Map, Value};

use crate::clients::{Client, ClientKind, GrantType};
use crate::form::Params;
use crate::server::AppState;
use crate::store::grant::GrantRecord;

use super::mint::{Authentication, Grant, mint};
use super::{Issued, Refusal, server_error};

/// The `grant_type` of a token exchange (RFC 8693 §2.1).
pub const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// The token type of an access token (RFC 8693 §3), the one subject token
/// type taken and the one token type issued.
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// The widest scope an exchanged token carries: the person's compositions,
/// read (SMART on openEHR, the `patient` context).
pub const EXCHANGE_CEILING: &str = "patient/composition-*.r";

/// The longest an exchanged token lives.
///
/// It stays below `access_token_lifetime` and never passes its subject
/// token. No specification governs the value: our own design, the most
/// SMART Backend Services allows a backend's token.
pub const EXCHANGE_LIFETIME: Duration = Duration::from_secs(300);

/// The token exchange grant (RFC 8693 §2.1) of the confidential client of
/// `headers` and `form`, from the address `from`.
pub(super) async fn token_exchange(
    state: &AppState,
    headers: &http::HeaderMap,
    form: &Params,
    from: IpAddr,
) -> Result<Issued, Refusal> {
    let client = super::grants::identify(state, headers, form).await?;
    // NOTE: RFC 8693 §2.1, the client authenticates as RFC 6749 §3.2.1 has it, so a
    // public client, which cannot, is refused.
    if client.kind == ClientKind::Public || !client.grant_types.contains(&GrantType::TokenExchange)
    {
        return Err(Refusal {
            error: "unauthorized_client",
            description: "the client may not use this grant",
        });
    }
    let subject_token = read_request(form)?;
    let (jti, record) = patient_token(state, subject_token).await?;
    let grant = record
        .grant
        .as_ref()
        .ok_or(Refusal::request("the subject token is not a patient's own"))?;
    let patient = own_patient(&record.audience, grant)
        .ok_or(Refusal::request("the subject token is not a patient's own"))?;
    let scope = exchanged_scope(&client, &record.scope, form.get("scope"))?;
    let person = crate::picker::Person {
        subject: &record.subject,
        fhir_user: grant.fhir_user.as_deref(),
        roles: &grant.roles,
        client_id: Some(&client.client_id),
        display_name: None,
    };
    let (base, ehr_id) = crate::picker::paired_ehr(
        state,
        &person,
        from,
        &record.audience,
        &patient.id,
    )
    .await
    .map_err(|error| server_error("the patient's EHR could not be looked up", &error))?
    .ok_or(Refusal {
        error: "invalid_target",
        description: "no openEHR base paired with the subject token's holds the patient's EHR",
    })?;
    target(&client, &record.audience, &base, form)?;
    let now = jiff::Timestamp::now().as_second();
    let left = u64::try_from(record.expires_at.saturating_sub(now))
        .ok()
        .filter(|seconds| *seconds > 0)
        .ok_or(Refusal::request("the subject token has expired"))?;
    let mut context = Map::new();
    context.insert(String::from("patient"), Value::String(patient.id.clone()));
    context.insert(String::from("ehrId"), Value::String(ehr_id));
    let issued = mint(
        state,
        &client,
        Grant {
            subject: &record.subject,
            audience: &base,
            scope: &scope,
            fhir_user: Some(&patient.fhir_user),
            code_hash: None,
            token_type: "Bearer",
            // NOTE: RFC 8693 §2.2.1 leaves the lifetime to the server; the token never
            // outlives the one it was exchanged for.
            longest: Some(EXCHANGE_LIFETIME.min(Duration::from_secs(left))),
            identity: None,
            under: Some(&grant.id),
            context: &context,
            roles: &grant.roles,
            login: Some(Authentication {
                auth_time: grant.auth_time,
                acr: grant.acr,
            }),
        },
    )?;
    tracing::info!(
        target: "ferrosmart::audit",
        event = "token.exchange",
        client_id = %client.client_id,
        subject_jti = %jti,
        issued_jti = %issued.jti,
        "a patient's token was exchanged for their openEHR base"
    );
    Ok(issued.exchanged())
}

/// Returns the subject token of the request `form`, refused unless it is an
/// access token exchanged with no actor for an access token (RFC 8693 §2.1).
fn read_request(form: &Params) -> Result<&str, Refusal> {
    let subject_token = form
        .get("subject_token")
        .ok_or(Refusal::request("the request carries no subject_token"))?;
    if form.get("subject_token_type") != Some(ACCESS_TOKEN_TYPE) {
        return Err(Refusal::request(
            "the subject_token_type is not an access token",
        ));
    }
    // NOTE: RFC 8693 §1.1, an actor makes the exchange a delegation, which the
    // product acting for the person themselves never is (3.14).
    if form.get("actor_token").is_some() || form.get("actor_token_type").is_some() {
        return Err(Refusal::request("an actor token is not taken"));
    }
    if form
        .get("requested_token_type")
        .is_some_and(|requested| requested != ACCESS_TOKEN_TYPE)
    {
        return Err(Refusal::request(
            "the requested_token_type is not an access token",
        ));
    }
    Ok(subject_token)
}

/// Returns the `jti` and the record of the live access token FerroSMART
/// issued whose value is `token`.
async fn patient_token(
    state: &AppState,
    token: &str,
) -> Result<(String, crate::store::grant::AccessRecord), Refusal> {
    let refused = Refusal::request("the subject token is not an active access token");
    // NOTE: RFC 8693 §2.2.2, a subject token that is not valid is invalid_request.
    let jti = crate::introspect::own_access_token(state, token).ok_or(refused.clone())?;
    let record = state
        .store()
        .access_token(&jti)
        .await
        .map_err(|error| server_error("the token record cannot be read", &error))?
        .filter(|record| record.active)
        .ok_or(refused)?;
    Ok((jti, record))
}

/// The person a patient's own token names.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnPatient {
    /// The patient's id at the FHIR base.
    id: String,
    /// Their `fhirUser`, absolute.
    fhir_user: String,
}

/// Returns the patient of `grant` at the FHIR `base` when its token is the
/// person's own access: `fhirUser` naming `Patient/<x>` (relative to the
/// base or absolute under it), `patient` naming `<x>`, and `patient/`
/// scopes alone (`docs/architecture.md` §13.13).
fn own_patient(base: &str, grant: &GrantRecord) -> Option<OwnPatient> {
    let fhir_user = grant.fhir_user.as_deref()?;
    let base = base.trim_end_matches('/');
    let relative = fhir_user
        .strip_prefix(base)
        .and_then(|rest| rest.strip_prefix('/'))
        .unwrap_or(fhir_user);
    let id = relative.strip_prefix("Patient/")?;
    let patient = grant.context.get("patient").and_then(Value::as_str)?;
    let clinical: Vec<&str> = grant
        .scope
        .split(' ')
        .filter(|scope| {
            ["patient/", "user/", "system/"]
                .iter()
                .any(|context| scope.starts_with(context))
        })
        .collect();
    let own = id == patient
        && !id.is_empty()
        && !clinical.is_empty()
        && clinical.iter().all(|scope| scope.starts_with("patient/"));
    own.then(|| OwnPatient {
        id: id.to_owned(),
        fhir_user: format!("{base}/Patient/{id}"),
    })
}

/// Returns the scope the exchanged token carries: the `requested` scopes,
/// or [`EXCHANGE_CEILING`] when none is named, each within that ceiling and
/// the client's, and only while the subject token's `held` scope reads.
fn exchanged_scope(
    client: &Client,
    held: &str,
    requested: Option<&str>,
) -> Result<String, Refusal> {
    let invalid = |description| Refusal {
        error: "invalid_scope",
        description,
    };
    // NOTE: RFC 8693 §2.1, the scope of the issued token is no wider than what the
    // subject token lets its holder do: a patient read.
    let reads = held.split(' ').any(|scope| {
        scope.starts_with("patient/")
            && scope.rsplit_once('.').is_some_and(|(_, permissions)| {
                matches!(permissions, "read" | "*") || permissions.contains('r')
            })
    });
    if !reads {
        return Err(invalid("the subject token reads nothing of the patient"));
    }
    let ceiling = [String::from(EXCHANGE_CEILING)];
    let mut granted: Vec<&str> = Vec::new();
    for scope in requested
        .unwrap_or(EXCHANGE_CEILING)
        .split(' ')
        .filter(|scope| !scope.is_empty())
    {
        let admitted =
            crate::scopes::admits(&ceiling, scope) && crate::scopes::admits(&client.scopes, scope);
        if !admitted {
            return Err(invalid(
                "a requested scope is wider than the exchange allows",
            ));
        }
        if !granted.contains(&scope) {
            granted.push(scope);
        }
    }
    if granted.is_empty() {
        return Err(invalid("the request names no scope"));
    }
    Ok(granted.join(" "))
}

/// Checks that `client` serves the subject token's FHIR base `fhir_base`
/// and may name the paired openEHR `base`, and that the request names no
/// other target (RFC 8693 §2.1, `resource` and `audience`).
fn target(client: &Client, fhir_base: &str, base: &str, form: &Params) -> Result<(), Refusal> {
    let refused = |description| Refusal {
        error: "invalid_target",
        description,
    };
    for named in [form.get("resource"), form.get("audience")]
        .into_iter()
        .flatten()
    {
        if named != base {
            return Err(refused("the target is not the paired openEHR base"));
        }
    }
    if !client.reaches(fhir_base) || !client.reaches(base) {
        return Err(refused("the client does not serve both bases"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const BASE: &str = "https://ehr.example.org/fhir";

    fn grant(fhir_user: &str, patient: &str, scope: &str) -> GrantRecord {
        GrantRecord {
            id: String::from("g-1"),
            client_id: String::from("portal"),
            subject: String::from("s-1"),
            fhir_user: Some(fhir_user.to_owned()),
            audience: String::from(BASE),
            scope: scope.to_owned(),
            context: json!({ "patient": patient }),
            access: None,
            roles: Vec::new(),
            auth_time: None,
            acr: None,
        }
    }

    #[test]
    fn a_patient_s_own_token_names_their_record_relative_or_absolute() {
        for fhir_user in ["Patient/p-1", "https://ehr.example.org/fhir/Patient/p-1"] {
            let own = own_patient(
                BASE,
                &grant(fhir_user, "p-1", "openid patient/Observation.rs"),
            );
            assert_eq!(
                Some(String::from("https://ehr.example.org/fhir/Patient/p-1")),
                own.map(|own| own.fhir_user),
                "{fhir_user}"
            );
        }
    }

    #[test]
    fn a_professional_another_patient_or_a_user_scope_is_not_the_person() {
        for (fhir_user, patient, scope) in [
            ("Practitioner/d-1", "p-1", "patient/Observation.rs"),
            ("Patient/p-2", "p-1", "patient/Observation.rs"),
            (
                "Patient/p-1",
                "p-1",
                "patient/Observation.rs user/Patient.rs",
            ),
            ("Patient/p-1", "p-1", "openid fhirUser"),
            (
                "https://other.example.org/fhir/Patient/p-1",
                "p-1",
                "patient/Observation.rs",
            ),
        ] {
            assert_eq!(
                None,
                own_patient(BASE, &grant(fhir_user, patient, scope)),
                "{fhir_user} {scope}"
            );
        }
    }
}
