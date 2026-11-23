// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! No `Debug` rendering of a type that holds token claims carries a claim
//! value beyond `sub`, `client_id` and `iss`: a value planted in every other
//! claim never appears in it.

use std::sync::Arc;

use ferrohealth_smart::assurance::AssuranceLevel;
use ferrohealth_smart::assurance::AssuranceSection;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::resource::Access;
use ferrohealth_smart::resource::Caller;
use ferrohealth_smart::resource::PatientClaim;
use ferrohealth_smart::scope::Permission;

/// The value planted in every claim a rendering must not carry.
const PLANTED: &str = "PLANTED-CLAIM-VALUE";

/// Returns a caller whose every claim beyond `sub`, `client_id` and `iss`
/// holds [`PLANTED`].
fn planted(kind: CallerKind) -> Caller {
    let claims = serde_json::json!({
        "sub": "synthetic-sub",
        "client_id": "synthetic-client",
        "iss": "https://as.example.org",
        "acr": PLANTED,
        "email": format!("{PLANTED}@example.org"),
        "patient_id": PLANTED,
        "ehrId": PLANTED,
        "roles": [PLANTED],
        "authorization_details": [{ "type": PLANTED }],
    });
    let claims = claims.as_object().cloned().expect("an object");
    let assurance = AssuranceSection {
        levels: std::collections::BTreeMap::from([(String::from(PLANTED), AssuranceLevel::High)]),
        ..AssuranceSection::default()
    }
    .assess(&claims);
    Caller::new(
        String::from("synthetic-sub"),
        Some(String::from("synthetic-client")),
        &format!("patient/{PLANTED}.rs {PLANTED}"),
        Some(String::from(PLANTED)),
        kind,
    )
    .with_issuer(String::from("https://as.example.org"))
    .with_roles(vec![String::from(PLANTED)])
    .with_assurance(assurance)
    .with_actor(ferrohealth_smart::kind::Actor {
        issuer: String::from(PLANTED),
        sub: String::from(PLANTED),
    })
    .with_claims(claims)
    .with_extension(PatientClaim::new("patient_id").expect("a valid path"))
}

#[test]
fn a_callers_debug_names_sub_client_iss_and_kind_alone() {
    let caller = planted(CallerKind::Person);
    let rendered = format!("{caller:?}");
    assert!(!rendered.contains(PLANTED), "{rendered}");
    for shown in [
        "synthetic-sub",
        "synthetic-client",
        "https://as.example.org",
        "Person",
    ] {
        assert!(rendered.contains(shown), "{shown} in {rendered}");
    }
    let pretty = format!("{caller:#?}");
    assert!(!pretty.contains(PLANTED), "{pretty}");
}

#[test]
fn no_type_holding_a_claim_renders_it() {
    let caller = planted(CallerKind::Patient);
    let representative = planted(CallerKind::RelatedPerson);
    let renderings = [
        format!("{:?}", Access::Caller(Arc::new(caller.clone()))),
        format!("{:?}", caller.assurance()),
        format!("{:?}", caller.person()),
        format!("{:?}", caller.reach(Permission::Read, PLANTED)),
        format!("{:?}", representative.kind()),
        format!("{representative:?}"),
    ];
    for rendered in renderings {
        assert!(!rendered.contains(PLANTED), "{rendered}");
    }
}
