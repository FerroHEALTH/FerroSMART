// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The caller read from a token's standard claims through the public API: a
//! signed token in, a `Caller` with its `CallerKind` out, every refusal a
//! typed `Rejection::Unclassified`.

use std::error::Error as StdError;

use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrohealth_smart::jws::compact::Header;
use ferrohealth_smart::kind::Actor;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::kind::Unclassified;
use ferrohealth_smart::profile::Profile;
use ferrohealth_smart::resource::Caller;
use ferrohealth_smart::resource::Compartment;
use ferrohealth_smart::resource::Rejection;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::Settings;
use ferrohealth_smart::scope::Permission;
use serde_json::Value;
use serde_json::json;

use crate::support::SigningKey;
use crate::support::ec_key;
use crate::support::mint_with;
use crate::support::now;
use crate::support::temp_file;

/// The issuer of every case; its key set is a file, so nothing is read.
const ISSUER: &str = "https://smart.example.org";
/// The audience of every case.
const AUDIENCE: &str = "https://ehr.example.org/fhir";
/// The client a person's token was issued to.
const APP: &str = "growth-chart";
/// The client of the machine's client credentials grant.
const MACHINE: &str = "machine-client";
/// The patient of the cases.
const PATIENT: &str = "synthetic-patient";

type Outcome = Result<(), Box<dyn StdError>>;

/// An issuer with its key.
struct Harness {
    /// The signing key, published in the key set file.
    key: SigningKey,
}

impl Harness {
    /// Returns the harness.
    fn new() -> Self {
        Self {
            key: ec_key("k1", Algorithm::Es256),
        }
    }

    /// Returns the caller `claims` authenticate as, under the profile as
    /// `tweak` leaves it.
    async fn admit(
        &self,
        tweak: impl FnOnce(&mut Profile),
        claims: &Value,
    ) -> Result<Caller, Rejection> {
        let set = json!({ "keys": [self.key.jwk.clone()] }).to_string();
        let mut settings = Settings::new(ISSUER, AUDIENCE, IssuerKind::Smart);
        settings.jwks_file = Some(temp_file("classify-jwks.json", set.as_bytes()));
        tweak(&mut settings.profile);
        let server = ResourceServer::discover(settings)
            .await
            .expect("the key set file reads");
        let mut header = Header::new(Algorithm::Es256);
        header.kid = Some(String::from("k1"));
        header.typ = Some(String::from("at+jwt"));
        server
            .authenticate(&mint_with(&self.key, &header, claims))
            .await
    }
}

/// The claims of a user's token through [`APP`] granting `scope`.
fn user(scope: &str) -> Value {
    json!({
        "iss": ISSUER, "aud": AUDIENCE, "sub": "pairwise-person-1",
        "client_id": APP, "iat": now(), "exp": now() + 300,
        "jti": "jti-user", "scope": scope,
    })
}

/// Returns `claims` with `name` set to `value`.
fn with(mut claims: Value, name: &str, value: Value) -> Value {
    if let Some(object) = claims.as_object_mut() {
        object.insert(name.to_owned(), value);
    }
    claims
}

/// The claims of a user's token whose `fhirUser` is `fhir_user`, with the
/// patient in context.
fn with_fhir_user(fhir_user: &str, scope: &str) -> Value {
    with(
        with(user(scope), "fhirUser", json!(fhir_user)),
        "patient",
        json!(PATIENT),
    )
}

/// Returns the classification refusal of `outcome`.
fn refused(outcome: Result<Caller, Rejection>) -> Option<Unclassified> {
    match outcome {
        Err(Rejection::Unclassified { reason }) => Some(reason),
        _ => None,
    }
}

/// No change to the profile.
fn keep(_: &mut Profile) {}

// NOTE: RFC 9068 §2.2 and §5: a client credentials token's `sub` names its
// client; SMART App Launch 2.2.0, Backend Services.
#[tokio::test]
async fn a_client_credentials_token_is_a_system() -> Outcome {
    let claims = json!({
        "iss": ISSUER, "aud": AUDIENCE, "sub": MACHINE, "client_id": MACHINE,
        "iat": now(), "exp": now() + 300, "jti": "jti-app", "scope": "system/Observation.rs",
    });
    let caller = Harness::new().admit(keep, &claims).await?;
    assert_eq!(&CallerKind::System, caller.kind());
    assert_eq!(Some(MACHINE), caller.client_id());
    assert_eq!(
        Some(Compartment::Any),
        caller.reach(Permission::Read, "Observation")
    );
    Ok(())
}

// NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, `fhirUser`: the
// user's resource is a Patient, Practitioner, PractitionerRole, RelatedPerson
// or Person.
#[tokio::test]
async fn a_user_is_named_by_the_type_of_their_fhir_user() -> Outcome {
    let h = Harness::new();
    for (fhir_user, kind) in [
        (format!("Patient/{PATIENT}"), CallerKind::Patient),
        (String::from("Practitioner/p-1"), CallerKind::Practitioner),
        (
            String::from("PractitionerRole/r-1"),
            CallerKind::PractitionerRole,
        ),
        (String::from("RelatedPerson/r-1"), CallerKind::RelatedPerson),
        (String::from("Person/p-1"), CallerKind::Person),
        (
            String::from("https://fhir.example.org/r4/Practitioner/p-1"),
            CallerKind::Practitioner,
        ),
    ] {
        let caller = h
            .admit(keep, &with_fhir_user(&fhir_user, "user/Observation.rs"))
            .await?;
        assert_eq!(&kind, caller.kind(), "{fhir_user}");
        assert_eq!(Some(fhir_user.as_str()), caller.fhir_user());
        assert_eq!(Some(APP), caller.client_id(), "the client is recorded");
    }
    let caller = h.admit(keep, &user("user/Observation.rs")).await?;
    assert_eq!(&CallerKind::User, caller.kind(), "no fhirUser, no type");
    Ok(())
}

#[tokio::test]
async fn a_fhir_user_of_no_user_type_is_refused() -> Outcome {
    let h = Harness::new();
    for fhir_user in [
        json!("Device/d-1"),
        json!("Group/Patient/p-1"),
        json!("Patient"),
        json!(["Patient/p-1"]),
    ] {
        let claims = with(user("user/Observation.rs"), "fhirUser", fhir_user.clone());
        assert_eq!(
            Some(Unclassified::FhirUser),
            refused(h.admit(keep, &claims).await),
            "{fhir_user}"
        );
    }
    Ok(())
}

// NOTE: Regulation (EU) 2025/327 Art 5: only the patient's own token is the
// person's access; SMART App Launch 2.2.0, `launch/patient` sets the context.
#[tokio::test]
async fn the_patients_own_token_is_the_person() -> Outcome {
    let h = Harness::new();
    let own = with_fhir_user(&format!("Patient/{PATIENT}"), "patient/Observation.rs");
    let caller = h.admit(keep, &own).await?;
    assert!(caller.is_the_person());
    assert_eq!(
        Some(PATIENT),
        caller.person().and_then(|person| person.patient)
    );
    assert_eq!(
        Some(Compartment::Patient(String::from(PATIENT))),
        caller.reach(Permission::Read, "Observation")
    );
    let other = with_fhir_user("Patient/another-patient", "patient/Observation.rs");
    assert!(!h.admit(keep, &other).await?.is_the_person());
    Ok(())
}

// NOTE: Regulation (EU) 2025/327 Art 4(2): a natural person may authorise
// others to act for them; SMART names the representative a RelatedPerson.
#[tokio::test]
async fn a_related_person_represents_the_patient_in_context() -> Outcome {
    let caller = Harness::new()
        .admit(
            keep,
            &with_fhir_user("RelatedPerson/r-1", "patient/Observation.rs"),
        )
        .await?;
    assert_eq!(&CallerKind::RelatedPerson, caller.kind());
    assert_eq!(Some(PATIENT), caller.represented());
    assert!(!caller.is_the_person());
    Ok(())
}

// NOTE: RFC 8693 §4.1: `act` names "the acting party to whom authority has
// been delegated" by `iss` and `sub`; prior actors are informational only.
#[tokio::test]
async fn an_rfc_8693_actor_is_read_as_asserted() -> Outcome {
    let h = Harness::new();
    let own = with_fhir_user(&format!("Patient/{PATIENT}"), "patient/Observation.rs");
    let caller = h
        .admit(keep, &with(own.clone(), "act", json!({ "sub": "actor-1" })))
        .await?;
    assert_eq!(&CallerKind::Patient, caller.kind());
    assert_eq!(
        Some(&Actor {
            issuer: String::from(ISSUER),
            sub: String::from("actor-1"),
        }),
        caller.actor()
    );
    assert!(!caller.is_the_person(), "an actor acts for the patient");
    let elsewhere = with(
        own.clone(),
        "act",
        json!({ "sub": "actor-1", "iss": "https://other.example.org" }),
    );
    let caller = h.admit(keep, &elsewhere).await?;
    assert_eq!(
        Some("https://other.example.org"),
        caller.actor().map(|actor| actor.issuer.as_str()),
        "the actor is its issuer and its sub together"
    );
    let chain = with(
        own,
        "act",
        json!({ "sub": "actor-1", "act": { "sub": "prior" } }),
    );
    assert_eq!(
        Some(Unclassified::ActorChain),
        refused(h.admit(keep, &chain).await),
        "a chain deeper than one actor is refused unless admitted"
    );
    let deeper = |profile: &mut Profile| profile.max_actor_chain = 2;
    assert!(h.admit(deeper, &chain).await.is_ok());
    Ok(())
}

// NOTE: RFC 9068 §4 has the resource server check that `aud` names it, and
// RFC 8707 lets the issuer issue a token only for what its client may reach.
#[tokio::test]
async fn any_client_of_a_token_for_this_server_is_admitted_and_another_audience_is_not() -> Outcome
{
    let h = Harness::new();
    let claims = with(
        user("user/Observation.rs"),
        "client_id",
        json!("any-registered-app"),
    );
    let caller = h.admit(keep, &claims).await?;
    assert_eq!(Some("any-registered-app"), caller.client_id());
    let elsewhere = with(claims, "aud", json!("https://elsewhere.example.org/fhir"));
    assert!(matches!(
        h.admit(keep, &elsewhere).await,
        Err(Rejection::Invalid {
            reason: ferrohealth_smart::refusal::Reason::Audience
        })
    ));
    Ok(())
}

// NOTE: RFC 9068 §2.2.3: `scope` is one space-delimited string.
#[tokio::test]
async fn a_scope_that_is_no_string_is_refused() -> Outcome {
    let claims = with(
        user("user/Observation.rs"),
        "scope",
        json!(["user/Observation.rs"]),
    );
    assert_eq!(
        Some(Unclassified::ScopeForm),
        refused(Harness::new().admit(keep, &claims).await)
    );
    Ok(())
}

// NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, `launch/patient`:
// the authorization server sets the patient context.
#[tokio::test]
async fn the_patient_claim_is_the_launch_context() -> Outcome {
    let caller = Harness::new()
        .admit(
            keep,
            &with_fhir_user("Practitioner/p-1", "launch/patient patient/Observation.rs"),
        )
        .await?;
    assert_eq!(Some(PATIENT), caller.patient());
    assert!(!caller.is_the_person());
    assert_eq!(
        Some(Compartment::Patient(String::from(PATIENT))),
        caller.reach(Permission::Read, "Observation"),
        "a practitioner confined to its launch context"
    );
    Ok(())
}

// NOTE: owner ruling of 2026-11-05: a Basic credential is a person's; a machine
// uses the client credentials grant (RFC 6749 §4.4) and is classified by its token.
#[test]
fn a_basic_credential_is_a_user_and_never_a_system() {
    let caller = Caller::basic(String::from("etl"), "system/*.rs");
    assert_eq!(&CallerKind::User, caller.kind());
}

#[test]
fn no_module_names_a_vendor() -> Outcome {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let text = std::fs::read_to_string(&path)?.to_lowercase();
            let words: Vec<&str> = text.split(|c: char| !c.is_ascii_alphanumeric()).collect();
            for vendor in ["entra", "keycloak", "okta", "azure", "microsoft"] {
                assert!(
                    !words.contains(&vendor),
                    "{} names {vendor}",
                    path.display()
                );
            }
        }
    }
    Ok(())
}
