// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! What a token of the deployment's own issuers states beside its kind: the
//! IHE IUA professional attributes and purposes of use a `persons` issuer's
//! `[auth.issuer.<name>.attributes]` table reads (ITI TF-2 §3.71.4.2.2.1.1, RFC 9396),
//! and the patient's representative a `patients` token's `act` names under
//! `act_represents_patient` (RFC 8693 §4.1). Every key is generated when the
//! case runs and published in a key set file, so nothing is fetched.

use std::collections::BTreeMap;
use std::error::Error as StdError;

use ferrohealth_smart::federation::Attribute;
use ferrohealth_smart::federation::Code;
use ferrohealth_smart::federation::FederationError;
use ferrohealth_smart::federation::Field;
use ferrohealth_smart::federation::Mapping;
use ferrohealth_smart::federation::Source;
use ferrohealth_smart::federation::person::AttributesSection;
use ferrohealth_smart::kind::Actor;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::kind::Unclassified;
use ferrohealth_smart::profile::ProfileError;
use ferrohealth_smart::resource::Caller;
use ferrohealth_smart::resource::Rejection;
use ferrohealth_smart::resource::ResourceError;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::Settings;
use jsonwebtoken::Algorithm;
use jsonwebtoken::Header;
use serde_json::Value;
use serde_json::json;

use crate::support::ec_key;
use crate::support::mint_with;
use crate::support::now;
use crate::support::temp_file;

const ISSUER: &str = "https://as.example.org/realms/ferro";
const AUDIENCE: &str = "https://ehr.example.org/openehr";
const FIRST_PARTY: &str = "first-party-app";

type Outcome = Result<(), Box<dyn StdError>>;

/// Returns the caller `claims` authenticate on an issuer of `kind` whose
/// settings `tweak` leaves.
async fn admit(
    kind: IssuerKind,
    tweak: impl FnOnce(&mut Settings),
    claims: &Value,
) -> Result<Caller, Rejection> {
    let key = ec_key("k1", Algorithm::ES256);
    let set = json!({ "keys": [key.jwk.clone()] }).to_string();
    let mut settings = Settings::new(ISSUER, AUDIENCE, kind);
    settings.jwks_file = Some(temp_file("attributes-jwks.json", set.as_bytes()));
    tweak(&mut settings);
    let server = ResourceServer::discover(settings)
        .await
        .expect("the settings hold and the key set file reads");
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(String::from("k1"));
    header.typ = Some(String::from("at+jwt"));
    server.authenticate(&mint_with(&key, &header, claims)).await
}

/// The claims of a person's token through the first-party client, with
/// `extra` members.
fn person(extra: &Value) -> Value {
    let mut claims = json!({
        "iss": ISSUER, "aud": AUDIENCE, "sub": "user-5ba552d67",
        "client_id": FIRST_PARTY, "iat": now(), "exp": now() + 300,
        "jti": "jti-person", "scope": "user/Observation.rs",
    });
    if let (Some(claims), Some(extra)) = (claims.as_object_mut(), extra.as_object()) {
        claims.extend(extra.clone());
    }
    claims
}

/// The IUA extension of a professional, as §3.71.4.2.2.1.1 shows it.
fn iua() -> Value {
    json!({ "extensions": { "ihe_iua": {
        "subject_name": "Dr. John Smith",
        "subject_organization": "Central Hospital",
        "subject_organization_id": "urn:oid:1.2.3.4",
        "national_provider_identifier": "123456789",
        "subject_role": [{ "system": "urn:oid:2.16.840.1.113883.6.96", "code": "158965000" }],
        "purpose_of_use": [
            { "system": "http://terminology.hl7.org/CodeSystem/v3-ActReason", "code": "TREAT" },
            { "system": "http://terminology.hl7.org/CodeSystem/v3-ActReason", "code": "ETREAT" }
        ],
        "person_id": "patient-identifier-never-read"
    }}})
}

/// A table of the IUA mapping, with `fields` over it.
fn table(fields: BTreeMap<Field, Vec<Source>>) -> AttributesSection {
    AttributesSection {
        issuer: ferrohealth_secret::secret_url::SecretUrl::new(ISSUER),
        mapping: Some(Mapping::Iua),
        fields,
        authorization_details_purposes: false,
    }
}

/// A coding of `system` and `code`.
fn code(system: &str, code: &str) -> Code {
    Code {
        system: Some(String::from(system)),
        code: String::from(code),
    }
}

#[tokio::test]
async fn the_iua_mapping_reads_the_professional_of_a_persons_token() -> Outcome {
    let caller = admit(
        IssuerKind::Persons,
        |settings| settings.attributes = Some(table(BTreeMap::new())),
        &person(&iua()),
    )
    .await?;
    assert_eq!(&CallerKind::Person, caller.kind());
    let attributes = caller.attributes().ok_or("the table is read")?;
    let text = |field| attributes.field(field).and_then(Attribute::text);
    assert_eq!(Some("Dr. John Smith"), text(Field::ProfessionalName));
    assert_eq!(Some("123456789"), text(Field::ProfessionalHpIdentifier));
    assert_eq!(
        Some("urn:oid:1.2.3.4"),
        text(Field::ProfessionalHealthcareProviderIdentifier)
    );
    assert_eq!(
        Some("Central Hospital"),
        text(Field::ProviderHealthcareProviderName)
    );
    assert_eq!(
        [code("urn:oid:2.16.840.1.113883.6.96", "158965000")],
        attributes.roles()
    );
    let reason = "http://terminology.hl7.org/CodeSystem/v3-ActReason";
    assert_eq!(
        [code(reason, "ETREAT"), code(reason, "TREAT")],
        attributes.purposes(),
        "sorted"
    );
    let debug = format!("{attributes:?}");
    assert!(!debug.contains("John Smith") && !debug.contains("123456789"));
    Ok(())
}

#[tokio::test]
async fn a_claim_source_of_the_table_reads_its_own_path() -> Outcome {
    let fields = BTreeMap::from([(
        Field::ProfessionalHpIdentifier,
        vec![Source::Claim(String::from("uzi"))],
    )]);
    let caller = admit(
        IssuerKind::Persons,
        |settings| {
            settings.attributes = Some(AttributesSection {
                mapping: None,
                ..table(fields)
            });
        },
        &person(&json!({ "uzi": "900012345" })),
    )
    .await?;
    let attributes = caller.attributes().ok_or("the table is read")?;
    assert_eq!(
        Some("900012345"),
        attributes
            .field(Field::ProfessionalHpIdentifier)
            .and_then(Attribute::text)
    );
    assert_eq!(1, attributes.fields().len(), "no mapping, one field");
    Ok(())
}

#[tokio::test]
async fn a_constant_source_states_its_value_for_every_token() -> Outcome {
    let fields = BTreeMap::from([(
        Field::ProfessionalCountryCode,
        vec![Source::Constant(String::from("NL"))],
    )]);
    let caller = admit(
        IssuerKind::Persons,
        |settings| settings.attributes = Some(table(fields)),
        &person(&json!({})),
    )
    .await?;
    let attributes = caller.attributes().ok_or("the table is read")?;
    assert_eq!(
        Some("NL"),
        attributes
            .field(Field::ProfessionalCountryCode)
            .and_then(Attribute::text)
    );
    assert!(
        attributes.field(Field::ProfessionalName).is_none(),
        "an absent claim is an absent field"
    );
    assert_eq!(Vec::<Code>::new(), attributes.purposes().to_vec());
    Ok(())
}

#[tokio::test]
async fn the_authorization_details_purposes_join_the_iua_ones() -> Outcome {
    let mut claims = person(&iua());
    claims["authorization_details"] = json!([
        { "type": "openehr", "purpose_of_use": "http://terminology.hl7.org/CodeSystem/v3-ActReason|TREAT" },
        { "type": "openehr", "purpose_of_use": "urn:oid:1.0.14265.1|3" },
        { "type": "openehr" }
    ]);
    let read = |purposes| {
        let claims = claims.clone();
        async move {
            admit(
                IssuerKind::Persons,
                |settings| {
                    settings.attributes = Some(AttributesSection {
                        authorization_details_purposes: purposes,
                        ..table(BTreeMap::new())
                    });
                },
                &claims,
            )
            .await
        }
    };
    let reason = "http://terminology.hl7.org/CodeSystem/v3-ActReason";
    let caller = read(true).await?;
    assert_eq!(
        [
            code(reason, "ETREAT"),
            code(reason, "TREAT"),
            code("urn:oid:1.0.14265.1", "3"),
        ],
        caller.attributes().ok_or("read")?.purposes(),
        "sorted and without duplicates"
    );
    let caller = read(false).await?;
    assert_eq!(2, caller.attributes().ok_or("read")?.purposes().len());
    Ok(())
}

#[tokio::test]
async fn a_claim_in_the_wrong_shape_is_refused() -> Outcome {
    let shapes = [
        (
            json!({ "extensions": { "ihe_iua": { "subject_role": "doctor" } } }),
            "professional.hp_professional_role",
        ),
        (
            json!({ "extensions": { "ihe_iua": { "subject_name": { "given": "John" } } } }),
            "professional.name",
        ),
        (
            json!({ "extensions": { "ihe_iua": { "subject_name": "John\u{202E}Smith" } } }),
            "professional.name",
        ),
        (
            json!({ "authorization_details": [{ "purpose_of_use": ["TREAT"] }] }),
            "purpose_of_use",
        ),
    ];
    for (extra, field) in shapes {
        let outcome = admit(
            IssuerKind::Persons,
            |settings| {
                settings.attributes = Some(AttributesSection {
                    authorization_details_purposes: true,
                    ..table(BTreeMap::new())
                });
            },
            &person(&extra),
        )
        .await;
        assert!(
            matches!(
                &outcome,
                Err(Rejection::Unclassified { reason: Unclassified::Attribute { field: named } })
                    if *named == field
            ),
            "{field}: {outcome:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_machine_token_carries_its_purposes_and_no_professional() -> Outcome {
    let mut app = person(&iua());
    app["sub"] = json!(FIRST_PARTY);
    let caller = admit(
        IssuerKind::Persons,
        |settings| settings.attributes = Some(table(BTreeMap::new())),
        &app,
    )
    .await?;
    assert_eq!(&CallerKind::System, caller.kind());
    let attributes = caller.attributes().ok_or("the purposes are read")?;
    let reason = "http://terminology.hl7.org/CodeSystem/v3-ActReason";
    assert_eq!(
        [code(reason, "ETREAT"), code(reason, "TREAT")],
        attributes.purposes()
    );
    assert_eq!(
        vec![&Field::PurposeOfUse],
        attributes.fields().keys().collect::<Vec<_>>(),
        "a machine states no professional"
    );
    assert_eq!(Vec::<Code>::new(), attributes.roles().to_vec());
    let caller = admit(IssuerKind::Persons, |_| {}, &person(&iua())).await?;
    assert!(
        caller.attributes().is_none(),
        "an issuer without a table states nothing"
    );
    Ok(())
}

#[tokio::test]
async fn a_coding_with_an_empty_code_names_no_code() -> Outcome {
    let claims = person(&json!({ "extensions": { "ihe_iua": {
        "subject_role": [{ "system": "", "code": "158965000" }],
        "purpose_of_use": [
            { "system": "http://terminology.hl7.org/CodeSystem/v3-ActReason", "code": "" },
            ""
        ]
    }}}));
    let caller = admit(
        IssuerKind::Persons,
        |settings| settings.attributes = Some(table(BTreeMap::new())),
        &claims,
    )
    .await?;
    let attributes = caller.attributes().ok_or("the table is read")?;
    assert_eq!(
        Vec::<Code>::new(),
        attributes.purposes().to_vec(),
        "an empty code is no purpose of use"
    );
    assert!(attributes.field(Field::PurposeOfUse).is_none());
    assert_eq!(
        [Code {
            system: None,
            code: String::from("158965000"),
        }],
        attributes.roles(),
        "an empty system is no system"
    );
    Ok(())
}

#[tokio::test]
async fn an_attributes_table_on_a_federation_issuer_or_with_another_source_is_refused() {
    let mut settings = Settings::new(ISSUER, AUDIENCE, IssuerKind::Federation);
    settings.federation = Some(crate::federation::iua());
    assert!(settings.validate().is_ok(), "the federation table holds");
    settings.attributes = Some(table(BTreeMap::new()));
    assert!(matches!(
        settings.validate(),
        Err(ResourceError::Kind {
            key: "attributes",
            ..
        })
    ));
    let mut settings = Settings::new(ISSUER, AUDIENCE, IssuerKind::Persons);
    settings.attributes = Some(table(BTreeMap::from([(
        Field::PurposeOfUse,
        vec![Source::AuthorizationDetails(String::from("purpose"))],
    )])));
    assert!(matches!(
        settings.validate(),
        Err(ResourceError::Federation(FederationError::Unattested))
    ));
}

#[test]
fn a_patients_or_machines_table_names_the_purpose_of_use_alone() {
    for kind in [IssuerKind::Patients, IssuerKind::Machines] {
        let mut settings = Settings::new(ISSUER, AUDIENCE, kind);
        settings.attributes = Some(table(BTreeMap::from([(
            Field::PurposeOfUse,
            vec![Source::Claim(String::from("purpose"))],
        )])));
        assert!(settings.validate().is_ok(), "{kind:?}");
        settings.attributes = Some(table(BTreeMap::from([(
            Field::ProfessionalCountryCode,
            vec![Source::Constant(String::from("NL"))],
        )])));
        assert!(
            matches!(
                settings.validate(),
                Err(ResourceError::Federation(FederationError::PurposeOnly {
                    field: "professional.country_code"
                }))
            ),
            "{kind:?}"
        );
    }
}

/// The claims of a patient's token naming only the record subject.
fn patient(extra: &Value) -> Value {
    let mut members = json!({
        "sub": "patient-sub-1",
        "scope": "launch/patient patient/Observation.rs",
        "patient": "synthetic-patient",
    });
    if let (Some(members), Some(extra)) = (members.as_object_mut(), extra.as_object()) {
        members.extend(extra.clone());
    }
    person(&members)
}

#[tokio::test]
async fn a_patients_token_with_act_is_refused_unless_the_issuer_reads_a_representative() -> Outcome
{
    let act = json!({ "act": { "sub": "representative-7" } });
    let outcome = admit(IssuerKind::Patients, |_| {}, &patient(&act)).await;
    assert!(
        matches!(
            outcome,
            Err(Rejection::Unclassified {
                reason: Unclassified::PatientActor
            })
        ),
        "never the patient's own access: {outcome:?}"
    );
    let caller = admit(IssuerKind::Patients, |_| {}, &patient(&json!({}))).await?;
    assert_eq!(&CallerKind::Patient, caller.kind(), "no act, the patient");
    Ok(())
}

#[tokio::test]
async fn a_patients_token_act_names_the_patients_representative() -> Outcome {
    // NOTE: RFC 8693 §4.1, only the top-level `act` is the current actor; the
    // nested one is informational.
    let act = json!({ "act": {
        "iss": "https://idp.example.org", "sub": "representative-7",
        "act": { "sub": "earlier-actor", "act": { "sub": "earliest-actor" } }
    }});
    let caller = admit(
        IssuerKind::Patients,
        |settings| settings.profile.act_represents_patient = true,
        &patient(&act),
    )
    .await?;
    assert_eq!(
        &CallerKind::PatientRepresentative {
            actor: Actor {
                issuer: String::from("https://idp.example.org"),
                sub: String::from("representative-7"),
            }
        },
        caller.kind()
    );
    assert!(
        !caller.is_the_person(),
        "a representative's access is not the person's own"
    );
    let caller = admit(
        IssuerKind::Patients,
        |settings| settings.profile.act_represents_patient = true,
        &patient(&json!({ "act": { "sub": "representative-8" } })),
    )
    .await?;
    assert!(
        matches!(caller.kind(), CallerKind::PatientRepresentative { actor } if actor.issuer == ISSUER),
        "an act without iss is the token's issuer's"
    );
    let outcome = admit(
        IssuerKind::Patients,
        |settings| settings.profile.act_represents_patient = true,
        &patient(&json!({ "act": "representative-9" })),
    )
    .await;
    assert!(matches!(
        outcome,
        Err(Rejection::Unclassified {
            reason: Unclassified::ActorChain
        })
    ));
    Ok(())
}

#[tokio::test]
async fn a_patient_and_their_representative_carry_their_purposes_and_no_professional() -> Outcome {
    let reason = "http://terminology.hl7.org/CodeSystem/v3-ActReason";
    let tables = |settings: &mut Settings| {
        settings.profile.act_represents_patient = true;
        settings.attributes = Some(table(BTreeMap::new()));
    };
    let claims = |extra: &Value| {
        let mut claims = patient(&iua());
        if let (Some(claims), Some(extra)) = (claims.as_object_mut(), extra.as_object()) {
            claims.extend(extra.clone());
        }
        claims
    };
    let own = admit(IssuerKind::Patients, tables, &claims(&json!({}))).await?;
    let represented = admit(
        IssuerKind::Patients,
        tables,
        &claims(&json!({ "act": { "sub": "representative-7" } })),
    )
    .await?;
    assert_eq!(&CallerKind::Patient, own.kind());
    assert!(matches!(
        represented.kind(),
        CallerKind::PatientRepresentative { .. }
    ));
    for caller in [own, represented] {
        let attributes = caller.attributes().ok_or("the purposes are read")?;
        assert_eq!(
            [code(reason, "ETREAT"), code(reason, "TREAT")],
            attributes.purposes()
        );
        assert!(
            attributes.field(Field::ProfessionalName).is_none() && attributes.roles().is_empty(),
            "a patients token states no professional"
        );
    }
    Ok(())
}

#[test]
fn act_represents_patient_outside_a_patients_issuer_is_refused() {
    let mut settings = Settings::new(ISSUER, AUDIENCE, IssuerKind::Persons);
    settings.profile.act_represents_patient = true;
    assert!(matches!(
        settings.validate(),
        Err(ResourceError::Profile(ProfileError::Kind {
            key: "act_represents_patient",
            ..
        }))
    ));
}

#[test]
fn the_attributes_tables_load_from_toml_and_name_their_issuers() -> Outcome {
    let text = format!(
        r#"[issuer.i1]
issuer = "{ISSUER}"
kind = "persons"
audience = ["{AUDIENCE}"]

[issuer.i1.profile]

[issuer.i2]
issuer = "https://patients.example.org"
kind = "patients"
audience = ["{AUDIENCE}"]

[issuer.i2.profile]
act_represents_patient = true

[issuer.i1.attributes]
mapping = "iua"
authorization_details_purposes = true

[issuer.i1.attributes.fields]
"professional.country_code" = [{{ constant = "NL" }}]

[issuer.i2.attributes]
mapping = "iua"
"#
    );
    let section: ferrohealth_smart::config::AuthSection = toml::from_str(&text)?;
    let resolved = section.resolve(&[])?;
    let persons = resolved
        .issuers
        .iter()
        .find(|settings| settings.issuer == ISSUER)
        .ok_or("the persons issuer")?;
    let table = persons.attributes.as_ref().ok_or("its table")?;
    assert!(table.authorization_details_purposes);
    assert_eq!(Some(Mapping::Iua), table.mapping);
    let patients = resolved
        .issuers
        .iter()
        .find(|settings| settings.kind == IssuerKind::Patients)
        .ok_or("the patients issuer")?;
    assert!(patients.profile.act_represents_patient);
    assert_eq!(
        Some(Mapping::Iua),
        patients.attributes.as_ref().ok_or("its table")?.mapping
    );
    let professional = text.replace(
        "[issuer.i2.attributes]\nmapping = \"iua\"",
        "[issuer.i2.attributes]\nmapping = \"iua\"\n\n\
         [issuer.i2.attributes.fields]\n\"professional.name\" = [{ constant = \"x\" }]",
    );
    let refused: ferrohealth_smart::config::AuthSection = toml::from_str(&professional)?;
    assert!(
        matches!(
            refused.resolve(&[]),
            Err(ferrohealth_smart::config::ConfigError::Attributes { .. })
        ),
        "a patients issuer states only the purpose of use"
    );
    let twice = text.replace(
        "[issuer.i2.attributes]",
        "[issuer.i1.attributes]\nmapping = \"iua\"\n\n[issuer.i2.attributes]",
    );
    assert!(
        toml::from_str::<ferrohealth_smart::config::AuthSection>(&twice).is_err(),
        "one attributes table per issuer"
    );
    Ok(())
}
