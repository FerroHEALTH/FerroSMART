// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The subject read from a `ferrohealth-smart` 0.9.0 caller of every kind
//! its classification gives.

use std::collections::BTreeMap;

use ferrohealth_authz::request::Subject;
use ferrohealth_smart::federation::Attribute;
use ferrohealth_smart::federation::External;
use ferrohealth_smart::federation::Field;
use ferrohealth_smart::kind::Actor;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::resource::Caller;
use serde_json::json;

/// Returns a caller of `kind` holding a role and a claim.
fn caller(kind: CallerKind) -> Caller {
    let claims = json!({ "org": { "unit": "ward-7" } });
    Caller::new(
        String::from("synthetic-subject"),
        Some(String::from("synthetic-client")),
        "user/Observation.rs",
        None,
        kind,
    )
    .with_roles(vec![String::from("clinician")])
    .with_claims(claims.as_object().cloned().unwrap_or_default())
}

// NOTE: NIST SP 800-162 §2: the decision reads the attributes of the subject; the subject
// carries the caller's id, roles, scopes and the named claims, whatever its kind.
#[test]
fn a_subject_is_read_from_a_caller_of_every_kind() {
    for kind in [
        CallerKind::Person,
        CallerKind::System,
        CallerKind::Patient,
        CallerKind::Delegated { actor: actor() },
        CallerKind::Representative {
            represented: String::from("synthetic-represented"),
            ground: None,
        },
        CallerKind::Guest(Box::new(CallerKind::Person)),
    ] {
        let subject = Subject::of(&caller(kind.clone()), &[("unit", "org.unit")]);
        assert_eq!("synthetic-subject", subject.id(), "{kind:?}");
        assert_eq!([String::from("clinician")], subject.roles(), "{kind:?}");
        assert_eq!(
            [String::from("user/Observation.rs")],
            subject.scopes(),
            "{kind:?}"
        );
        assert_eq!(
            Some("ward-7"),
            subject.attributes().get("unit").map(String::as_str),
            "{kind:?}"
        );
    }
}

/// Asserts that the subject of a caller of `kind` carries that kind, which
/// a policy reads by `name`.
fn carries(kind: &CallerKind, name: &str) {
    let subject = Subject::of(&caller(kind.clone()), &[]);
    assert_eq!(Some(kind), subject.kind(), "{name}");
    assert_eq!(Some(name), subject.kind().map(CallerKind::as_str), "{name}");
}

// NOTE: NIST SP 800-162 §2: the subject's attributes include who stands behind the credential,
// so a policy tells a person from a system caller (#262).
#[test]
fn a_person_subject_carries_its_kind() {
    carries(&CallerKind::Person, "person");
}

#[test]
fn a_system_subject_carries_its_kind() {
    carries(&CallerKind::System, "system");
}

#[test]
fn a_patient_subject_carries_its_kind() {
    carries(&CallerKind::Patient, "patient");
}

#[test]
fn a_delegated_subject_carries_its_kind() {
    carries(&CallerKind::Delegated { actor: actor() }, "delegated");
}

#[test]
fn a_representative_subject_carries_its_kind() {
    carries(
        &CallerKind::Representative {
            represented: String::from("synthetic-represented"),
            ground: None,
        },
        "representative",
    );
}

#[test]
fn a_guest_subject_carries_its_kind() {
    carries(&CallerKind::Guest(Box::new(CallerKind::Person)), "guest");
}

#[test]
fn a_subject_built_by_hand_carries_the_kind_it_is_given() {
    let subject = Subject::new("synthetic-subject");
    assert_eq!(None, subject.kind());
    let subject = subject.with_kind(CallerKind::System);
    assert_eq!(Some(&CallerKind::System), subject.kind());
}

#[test]
fn the_subject_debug_names_the_kind_and_no_represented_subject() {
    let kind = CallerKind::Representative {
        represented: String::from("synthetic-represented"),
        ground: None,
    };
    let rendered = format!("{:?}", Subject::of(&caller(kind), &[]));
    assert!(rendered.contains("representative"), "{rendered}");
    assert!(!rendered.contains("synthetic-represented"), "{rendered}");
}

/// Returns an external party asserted by a `federation` token, built for
/// the test.
fn external() -> External {
    External::new(
        "synthetic-remote-subject",
        BTreeMap::from([(
            Field::ProfessionalName,
            Attribute::Text(String::from("Synthetic Professional")),
        )]),
    )
}

#[test]
fn an_external_person_subject_carries_its_kind() {
    carries(
        &CallerKind::ExternalPerson(Box::new(external())),
        "external_person",
    );
}

#[test]
fn an_external_organisation_subject_carries_its_kind() {
    carries(
        &CallerKind::ExternalOrganisation(Box::new(external())),
        "external_organisation",
    );
}

/// The RFC 8693 §4.1 actor of a delegated caller.
fn actor() -> Actor {
    Actor {
        issuer: String::from("https://as.example.org"),
        sub: String::from("actor-1"),
    }
}
