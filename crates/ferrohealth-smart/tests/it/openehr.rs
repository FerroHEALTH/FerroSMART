// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The SMART on openEHR grammar beside the FHIR one: the rules the draft
//! leaves to the resource server, each pinned, the `ehrId` of the launch
//! context, and the discovery document of a platform.

use std::error::Error as StdError;
use std::sync::Arc;

use ferrohealth_smart::openehr::granted;
use ferrohealth_smart::openehr::patient_grant;
use ferrohealth_smart::resource::Compartment;
use ferrohealth_smart::resource::Honoured;
use ferrohealth_smart::resource::configuration::SmartOptions;
use ferrohealth_smart::scope::Permission as FhirPermission;
use jsonwebtoken::Algorithm;
use openehr_sdt::smart_scopes::Permission;
use openehr_sdt::smart_scopes::ResourceFamily;
use openehr_sdt::smart_scopes::SmartScope;

use crate::support::Issuer;
use crate::support::ec_key;
use crate::support::mint;
use crate::support::server;

const NONE: Honoured = Honoured {
    backend: false,
    patient: false,
};

/// Returns whether `scope` grants `permission` on `family` for the resource
/// `named` under `honoured`.
fn grants(
    scope: &str,
    family: ResourceFamily,
    permission: Permission,
    named: Option<&str>,
    honoured: Honoured,
) -> bool {
    granted(
        &SmartScope::parse_all(scope),
        family,
        permission,
        named,
        honoured,
    )
}

#[test]
fn the_permission_letters_are_read_in_any_order() {
    // NOTE: master08 §Resource Scopes lists the five letters and fixes no
    // order, so `.rs` and `.sr` are one grant; a letter outside the five
    // grants nothing.
    for scope in [
        "user/aql-*.rs",
        "user/aql-*.sr",
        "user/aql-*.cruds",
        "user/aql-*.sdurc",
    ] {
        assert!(
            grants(scope, ResourceFamily::Aql, Permission::Search, None, NONE),
            "{scope}"
        );
        assert!(
            grants(scope, ResourceFamily::Aql, Permission::Read, None, NONE),
            "{scope}"
        );
    }
    assert!(!grants(
        "user/aql-*.rx",
        ResourceFamily::Aql,
        Permission::Read,
        None,
        NONE
    ));
    assert!(!grants(
        "user/aql-*.",
        ResourceFamily::Aql,
        Permission::Read,
        None,
        NONE
    ));
}

#[test]
fn a_star_matches_within_a_segment_and_two_stars_across() {
    // NOTE: master08 §Resource Scopes, the pattern table: `*::Template.v0`,
    // `MyHospital::*` and the bare `*`; `**` is the other wildcard it names.
    let composition = |scope: &str, named: &str| {
        grants(
            scope,
            ResourceFamily::Composition,
            Permission::Read,
            Some(named),
            NONE,
        )
    };
    assert!(composition(
        "user/composition-MyHospital::*.r",
        "MyHospital::Vitals.v1"
    ));
    assert!(!composition(
        "user/composition-MyHospital::*.r",
        "Other::Vitals.v1"
    ));
    assert!(composition(
        "user/composition-*::Template.v0.r",
        "MyHospital::Template.v0"
    ));
    assert!(
        !composition("user/composition-*::Template.v0.r", "a::b::Template.v0"),
        "* stays in one segment"
    );
    assert!(
        composition("user/composition-**::Template.v0.r", "a::b::Template.v0"),
        "** crosses segments"
    );
    assert!(
        composition("user/composition-*.r", "a::b::c"),
        "a bare * is every id"
    );
    assert!(composition("user/composition-**.r", "a::b::c"));
    assert!(composition(
        "user/composition-MyHospital::Template.v0.r",
        "MyHospital::Template.v0"
    ));
    assert!(!composition(
        "user/composition-MyHospital::Template.v0.r",
        "MyHospital::Template.v1"
    ));
}

#[test]
fn an_operation_naming_no_resource_needs_a_bare_wildcard() {
    for scope in ["user/composition-*.c", "user/composition-**.c"] {
        assert!(
            grants(
                scope,
                ResourceFamily::Composition,
                Permission::Create,
                None,
                NONE
            ),
            "{scope}"
        );
    }
    assert!(
        !grants(
            "user/composition-MyHospital::*.c",
            ResourceFamily::Composition,
            Permission::Create,
            None,
            NONE
        ),
        "a specific pattern cannot be shown to match an unseen template"
    );
}

#[test]
fn the_ehr_families_are_held_to_the_composition_family() {
    // NOTE: no specification governs this: our own design, an EHR, its
    // status, its directory and a contribution are the EHR's data, so a
    // product classifies them under `composition-` with the operation's
    // permission over every template.
    assert!(grants(
        "user/composition-*.r",
        ResourceFamily::Composition,
        Permission::Read,
        None,
        NONE
    ));
    assert!(!grants(
        "user/template-*.r",
        ResourceFamily::Composition,
        Permission::Read,
        None,
        NONE
    ));
    assert!(!grants(
        "user/aql-*.r",
        ResourceFamily::Composition,
        Permission::Read,
        None,
        NONE
    ));
}

#[test]
fn a_system_wide_aql_grant_counts_only_for_a_listed_backend_client() {
    // NOTE: master08 §Resource Scopes, `system/aql-*.rs` "would grant access
    // to all registered and ad-hoc AQL queries system-wide".
    let backend = Honoured {
        backend: true,
        patient: false,
    };
    assert!(!grants(
        "system/aql-*.s",
        ResourceFamily::Aql,
        Permission::Search,
        None,
        NONE
    ));
    assert!(grants(
        "system/aql-*.s",
        ResourceFamily::Aql,
        Permission::Search,
        None,
        backend
    ));
    assert!(grants(
        "system/aql-org.example::vitals.s",
        ResourceFamily::Aql,
        Permission::Search,
        Some("org.example::vitals"),
        NONE
    ));
}

#[test]
fn a_patient_grant_is_confined_to_the_bound_ehr() {
    // NOTE: master08 §Resource Scopes, a patient grant reaches "data within
    // that patient's EHR"; master07 §Context Selection places the `ehrId` in
    // the token response, so it counts only for an issuer the product binds.
    let bound = Honoured {
        backend: false,
        patient: true,
    };
    assert!(!grants(
        "patient/composition-*.r",
        ResourceFamily::Composition,
        Permission::Read,
        None,
        NONE
    ));
    assert!(grants(
        "patient/composition-*.r",
        ResourceFamily::Composition,
        Permission::Read,
        None,
        bound
    ));
    assert!(grants(
        "patient/aql-*.s",
        ResourceFamily::Aql,
        Permission::Search,
        None,
        bound
    ));
    assert!(
        !grants(
            "patient/aql-*.r",
            ResourceFamily::Aql,
            Permission::Read,
            None,
            bound
        ),
        "a definition"
    );
    assert!(!grants(
        "patient/template-*.r",
        ResourceFamily::Template,
        Permission::Read,
        None,
        bound
    ));
    assert!(patient_grant(&SmartScope::parse_all(
        "openid launch/patient patient/composition-*.r"
    )));
    assert!(!patient_grant(&SmartScope::parse_all(
        "patient/composition-*.r user/aql-*.s"
    )));
}

#[test]
fn the_fhir_v1_suffixes_grant_nothing_under_the_openehr_grammar() {
    // NOTE: master08 §Resource Scopes defines the five letters alone; the
    // SMART App Launch v1 `.read` and `.write` are not applied here.
    for scope in [
        "user/composition-*.read",
        "user/composition-*.write",
        "user/composition-*.*",
    ] {
        assert!(
            !grants(
                scope,
                ResourceFamily::Composition,
                Permission::Read,
                None,
                NONE
            ),
            "{scope}"
        );
        assert!(
            !grants(
                scope,
                ResourceFamily::Composition,
                Permission::Create,
                None,
                NONE
            ),
            "{scope}"
        );
    }
}

#[tokio::test]
async fn both_grammars_coexist_in_one_claim_and_the_ehr_id_is_read() -> Result<(), Box<dyn StdError>>
{
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let server = server(issuer.settings()).await;
    let mut claims =
        issuer.claims("openid launch/patient patient/Observation.rs patient/composition-*.rs");
    claims["patient"] = serde_json::json!("p-1");
    claims["ehrId"] = serde_json::json!("7d44b88c-4199-4bad-97dc-d78268e01398");
    let caller = server.authenticate(&mint(&key, &claims)).await?;
    assert_eq!(
        Some(Compartment::Patient(String::from("p-1"))),
        caller.reach(FhirPermission::Read, "Observation"),
        "the FHIR grammar keeps its grant"
    );
    assert_eq!(None, caller.reach(FhirPermission::Read, "Condition"));
    let bound = Honoured {
        backend: false,
        patient: true,
    };
    assert!(
        granted(
            &caller.openehr_scopes(),
            ResourceFamily::Composition,
            Permission::Read,
            None,
            bound
        ),
        "the openEHR grammar keeps its grant"
    );
    assert!(!granted(
        &caller.openehr_scopes(),
        ResourceFamily::Template,
        Permission::Read,
        None,
        bound
    ));
    assert_eq!(
        Some("7d44b88c-4199-4bad-97dc-d78268e01398"),
        caller.ehr_id()
    );
    let scopes = caller.openehr_scopes();
    assert!(
        scopes.iter().any(
            |scope| matches!(scope, SmartScope::Other(other) if other == "patient/Observation.rs")
        ),
        "a FHIR scope is inert under the openEHR parser, never a grant"
    );
    let plain = server
        .authenticate(&mint(&key, &issuer.claims("openid")))
        .await?;
    assert_eq!(None, plain.ehr_id());
    Ok(())
}

#[tokio::test]
async fn the_discovery_document_of_a_platform_names_its_services() -> Result<(), Box<dyn StdError>>
{
    // NOTE: master04 §Services, `org.openehr.rest` is required and
    // `org.fhir.rest` recommended; §Capabilities names the three openEHR
    // capabilities.
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let server = server(issuer.settings()).await;
    let options = SmartOptions::default().with_openehr(
        "https://platform.example.org/openehr/rest/v1",
        Some("https://platform.example.org/fhir"),
    );
    let document = server.smart_configuration(&options);
    assert_eq!(
        serde_json::json!({
            "org.openehr.rest": { "baseUrl": "https://platform.example.org/openehr/rest/v1" },
            "org.fhir.rest": { "baseUrl": "https://platform.example.org/fhir" }
        }),
        document["services"]
    );
    let capabilities = document["capabilities"].as_array().ok_or("a list")?;
    for expected in [
        "context-openehr-ehr",
        "openehr-permission-v1",
        "launch-base64-json",
        "permission-patient",
    ] {
        assert!(
            capabilities.contains(&serde_json::json!(expected)),
            "{expected}"
        );
    }
    let fhir_only = server.smart_configuration(&SmartOptions::default());
    assert!(
        fhir_only.get("services").is_none(),
        "a FHIR surface names no services"
    );
    drop(Arc::new(()));
    Ok(())
}
