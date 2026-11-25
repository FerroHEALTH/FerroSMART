// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The MyHealth@EU contact-point profile through the public API: a token of
//! NCPeH-A's authorization server, bound to the client certificate, carries
//! what was read from the HP Identity Assertion and the Treatment
//! Relationship Confirmation; every refusal carries its MyHealth@EU
//! Requirements Catalogue 10.0.0 §1.25 code name.

use std::collections::BTreeMap;
use std::error::Error as StdError;

use ferrohealth_smart::federation::Attribute;
use ferrohealth_smart::federation::FederationSection;
use ferrohealth_smart::federation::Field;
use ferrohealth_smart::federation::Mapping;
use ferrohealth_smart::federation::Source;
use ferrohealth_smart::federation::contact::AUTHENTICATION_CLASSES;
use ferrohealth_smart::federation::contact::EhdsiCode;
use ferrohealth_smart::federation::contact::NameIdFormat;
use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrohealth_smart::jws::compact::Header;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::kind::Unclassified;
use ferrohealth_smart::refusal::Reason;
use ferrohealth_smart::resource::Caller;
use ferrohealth_smart::resource::Rejection;
use ferrohealth_smart::resource::ResourceError;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::Settings;
use ferrohealth_smart::sender::Binding;
use ferrohealth_smart::sender::ClientCertificate;
use ferrohealth_smart::sender::SenderConstraint;
use serde_json::Value;
use serde_json::json;

use crate::support::SigningKey;
use crate::support::ec_key;
use crate::support::mint_with;
use crate::support::now;
use crate::support::temp_file;

type Outcome = Result<(), Box<dyn StdError>>;

/// NCPeH-A's authorization server.
const ISSUER: &str = "https://ncpeh-a.example.org";
/// This node's audience.
const AUDIENCE: &str = "https://ehr.example.org/openehr";
/// The synthetic DER bytes of the client certificate the token is bound to.
const CERTIFICATE: &[u8] = b"synthetic client certificate DER";

/// The table of a contact point: the eHDSI mapping, the country and the
/// issuing authority taken from NCP-B's identity, configured.
fn table() -> FederationSection {
    FederationSection {
        issuer: ferrohealth_secret::secret_url::SecretUrl::new(ISSUER),
        contact_point: Some(true),
        mapping: Some(Mapping::Ehdsi),
        fields: BTreeMap::from([
            (
                Field::ProfessionalCountryCode,
                vec![Source::Constant(String::from("BE"))],
            ),
            (
                Field::ProfessionalIssuingAuthorityName,
                vec![Source::Constant(String::from("NCP-B Belgium"))],
            ),
        ]),
        countries: vec![String::from("BE"), String::from("NL"), String::from("PT")],
        ..FederationSection::default()
    }
}

/// The claims of a contact-point token: eHDSI SAML Profile 10.0.0 §2.3's
/// mandatory attributes, the §2.1 assertion window and the TRC's.
fn token() -> Value {
    let now = now();
    json!({
        "iss": ISSUER, "sub": "hp-nameid", "client_id": "ncpeh-b", "aud": AUDIENCE,
        "jti": "jti-1", "iat": now, "exp": now + 600,
        "scope": "patient/*.rs",
        "cnf": { "x5t#S256": ClientCertificate::from_der(CERTIFICATE).thumbprint() },
        "ehdsi": {
            "professional": {
                "hp_identifier": "CN=Synthetic Doctor,O=Hospital,C=BE",
                "name": "Synthetic Doctor",
                "hp_professional_role": [{ "system": "2.16.840.1.113883.2.9.6.2.7", "code": "221" }],
                "authentication_method": AUTHENTICATION_CLASSES[4]
            },
            "provider": {
                "healthcare_provider_identifier": "urn:oid:1.2.3.4",
                "facility_type": "Hospital",
                "home_community_id": "urn:oid:1.2.3"
            },
            "point_of_care": "Synthetic Hospital",
            "purpose_of_use": "TREATMENT",
            "assertion": {
                "issuer": "https://ncp-b.example.org",
                "id": "urn:uuid:ida-1",
                "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
                "not_before": now - 60,
                "not_on_or_after": now + 3600
            },
            "trc": {
                "id": "urn:uuid:trc-1",
                "not_before": now - 60,
                "not_on_or_after": now + 3600
            },
            "patient": { "id": "synthetic-patient^^^&1.2.3&ISO" }
        }
    })
}

/// The contact-point issuer of the cases.
struct Harness {
    /// The signing key, in the key set file.
    key: SigningKey,
}

impl Harness {
    fn new() -> Self {
        Self {
            key: ec_key("cp", Algorithm::Es256),
        }
    }

    /// Returns the settings of the issuer under `section`, sender-constrained.
    fn settings(&self, section: FederationSection) -> Settings {
        let set = json!({ "keys": [self.key.jwk.clone()] }).to_string();
        let mut settings = Settings::new(ISSUER, AUDIENCE, IssuerKind::Federation);
        settings.jwks_file = Some(temp_file("contact-point-jwks.json", set.as_bytes()));
        settings.sender_constraint = SenderConstraint::Required;
        settings.federation = Some(section);
        settings
    }

    /// Returns the caller `claims` authenticate over the bound connection.
    async fn admit(&self, claims: &Value) -> Result<Caller, Rejection> {
        self.admit_under(table(), claims).await
    }

    /// Returns the caller `claims` authenticate over the bound connection,
    /// the issuer under `section`.
    async fn admit_under(
        &self,
        section: FederationSection,
        claims: &Value,
    ) -> Result<Caller, Rejection> {
        let server = ResourceServer::discover(self.settings(section))
            .await
            .expect("the key set file reads");
        let mut header = Header::new(Algorithm::Es256);
        header.kid = Some(String::from("cp"));
        header.typ = Some(String::from("at+jwt"));
        let binding = Binding::bearer().with_certificate(&ClientCertificate::from_der(CERTIFICATE));
        server
            .authenticate_bound(&mint_with(&self.key, &header, claims), &binding)
            .await
    }
}

/// Returns the §1.25 code and the missing fields of a refusal.
fn code(outcome: Result<Caller, Rejection>) -> Option<(EhdsiCode, Vec<&'static str>)> {
    match outcome {
        Err(Rejection::Unclassified {
            reason: Unclassified::ContactPoint { code, missing },
        }) => Some((code, missing)),
        _ => None,
    }
}

/// Returns `claims` with the `ehdsi` member at `pointer` removed.
fn without(pointer: &str) -> Value {
    let mut claims = token();
    let (parent, member) = pointer.rsplit_once('/').expect("a member");
    claims
        .pointer_mut(&format!("/ehdsi{parent}"))
        .and_then(Value::as_object_mut)
        .expect("the parent object")
        .remove(member);
    claims
}

#[tokio::test]
async fn a_complete_contact_point_token_is_an_external_person() -> Outcome {
    let caller = Harness::new().admit(&token()).await?;
    let CallerKind::ExternalPerson(person) = caller.kind() else {
        panic!("an external person: {caller:?}");
    };
    assert_eq!(
        Some(&Attribute::Text(String::from(AUTHENTICATION_CLASSES[4]))),
        person.field(Field::ProfessionalAuthenticationMethod),
        "the class is recorded as received"
    );
    assert_eq!(
        Some(&Attribute::Text(String::from("BE"))),
        person.field(Field::ProfessionalCountryCode),
        "the country is configured, not asserted"
    );
    Ok(())
}

// NOTE: MyHealth@EU Requirements Catalogue 10.0.0 §1.25, requirement 01: each
// missing piece of HP information has its own code name.
#[tokio::test]
async fn each_missing_attribute_is_refused_with_its_code_name() -> Outcome {
    let h = Harness::new();
    let cases = [
        (
            "/professional/hp_identifier",
            EhdsiCode::HpiInsufficientInformation,
            "professional.hp_identifier",
        ),
        (
            "/assertion/name_id_format",
            EhdsiCode::HpiInsufficientInformation,
            "assertion.name_id_format",
        ),
        (
            "/professional/name",
            EhdsiCode::HpiInsufficientInformation,
            "professional.name",
        ),
        (
            "/professional/hp_professional_role",
            EhdsiCode::HpiInsufficientInformation,
            "professional.hp_professional_role",
        ),
        (
            "/provider/healthcare_provider_identifier",
            EhdsiCode::HpiHaiNoInformation,
            "provider.healthcare_provider_identifier",
        ),
        (
            "/point_of_care",
            EhdsiCode::HpiPocNoInformation,
            "point_of_care",
        ),
        (
            "/provider/facility_type",
            EhdsiCode::HpiPocNoInformation,
            "provider.facility_type",
        ),
        (
            "/provider/home_community_id",
            EhdsiCode::HpiPocNoInformation,
            "provider.home_community_id",
        ),
        (
            "/professional/authentication_method",
            EhdsiCode::HpiAuthenticationNotReceived,
            "professional.authentication_method",
        ),
        (
            "/purpose_of_use",
            EhdsiCode::HpiInsufficientInformation,
            "purpose_of_use",
        ),
        (
            "/assertion/id",
            EhdsiCode::SecDataIntegrityNotEnsured,
            "assertion.id",
        ),
        ("/trc/id", EhdsiCode::SecDataIntegrityNotEnsured, "trc.id"),
    ];
    for (pointer, want, field) in cases {
        let refused = code(h.admit(&without(pointer)).await);
        assert_eq!(Some((want, vec![field])), refused, "{pointer}");
        assert!(want.as_str().starts_with("ERROR_"), "{want}");
    }
    assert_eq!(
        "ERROR_HPI_AUTHENTICATION_NOT_RECEIVED",
        EhdsiCode::HpiAuthenticationNotReceived.as_str()
    );
    Ok(())
}

/// Returns the token with no TRC and no patient: a discovery-phase token.
fn discovery() -> Value {
    let mut claims = token();
    let ehdsi = claims
        .get_mut("ehdsi")
        .and_then(Value::as_object_mut)
        .expect("the ehdsi claim");
    ehdsi.remove("trc");
    ehdsi.remove("patient");
    claims
}

// NOTE: eHDSI SAML Profile 10.0.0 §4: the TRC is issued once the patient is identified,
// so the discovery phase presents the identity assertion alone (FerroHEALTH/FerroSMART#314).
#[tokio::test]
async fn a_discovery_phase_token_is_admitted_with_no_patient() -> Outcome {
    let caller = Harness::new().admit(&discovery()).await?;
    let CallerKind::ExternalPerson(person) = caller.kind() else {
        panic!("an external person: {caller:?}");
    };
    assert!(person.field(Field::TrcId).is_none(), "no TRC");
    assert!(person.trc_patient().is_none(), "no patient to read data of");
    Ok(())
}

#[tokio::test]
async fn a_discovery_phase_token_is_held_to_the_identity_assertion_window() -> Outcome {
    let h = Harness::new();
    let mut late = discovery();
    late["ehdsi"]["assertion"]["not_on_or_after"] = json!(now() + 120);
    let integrity = Some((EhdsiCode::SecDataIntegrityNotEnsured, vec!["exp"]));
    assert_eq!(integrity, code(h.admit(&late).await), "past the IdA");
    let mut long = discovery();
    long["ehdsi"]["assertion"]["not_before"] = json!(now() - 4 * 3600);
    assert_eq!(integrity, code(h.admit(&long).await), "past 4 hours");
    Ok(())
}

// NOTE: eHDSI SAML Profile 10.0.0 §4: a care role is part of the treatment
// relationship, so a token that carries one carries the whole TRC (#751).
#[tokio::test]
async fn an_attested_care_role_comes_with_the_treatment_confirmation() -> Outcome {
    let h = Harness::new();
    let mut section = table();
    section.fields.insert(
        Field::TrcCareRole,
        vec![Source::Claim(String::from("ehdsi.trc.care_role"))],
    );
    let role = json!([{ "system": "urn:example:care-role", "code": "treating" }]);
    let mut claims = token();
    claims["ehdsi"]["trc"]["care_role"] = role.clone();
    let caller = h.admit_under(section.clone(), &claims).await?;
    let CallerKind::ExternalPerson(person) = caller.kind() else {
        panic!("an external person: {caller:?}");
    };
    assert!(person.field(Field::TrcCareRole).is_some());
    let mut alone = discovery();
    alone["ehdsi"]["trc"] = json!({ "care_role": role });
    assert_eq!(
        Some((
            EhdsiCode::SecDataIntegrityNotEnsured,
            vec!["trc.id", "trc.not_before", "trc.not_on_or_after"]
        )),
        code(h.admit_under(section, &alone).await)
    );
    Ok(())
}

#[tokio::test]
async fn a_partial_treatment_confirmation_is_refused() -> Outcome {
    let h = Harness::new();
    let integrity = EhdsiCode::SecDataIntegrityNotEnsured;
    let mut no_window = token();
    let trc = no_window
        .pointer_mut("/ehdsi/trc")
        .and_then(Value::as_object_mut)
        .ok_or("the trc object")?;
    trc.remove("not_before");
    trc.remove("not_on_or_after");
    assert_eq!(
        Some((integrity, vec!["trc.not_before", "trc.not_on_or_after"])),
        code(h.admit(&no_window).await)
    );
    let mut patient_only = discovery();
    patient_only["ehdsi"]["patient"] = json!({ "id": "synthetic-patient^^^&1.2.3&ISO" });
    assert_eq!(
        Some((
            integrity,
            vec!["trc.id", "trc.not_before", "trc.not_on_or_after"]
        )),
        code(h.admit(&patient_only).await)
    );
    Ok(())
}

#[cfg(feature = "ehdsi-assertion")]
#[tokio::test]
async fn the_discovery_phase_claim_the_crate_writes_is_admitted() -> Outcome {
    let identity = crate::ehdsi_assertion::validated_identity().await;
    let mut claims = token();
    claims["ehdsi"] =
        ferrohealth_smart::federation::assertion::identity::ehdsi_claim(&identity, None);
    let caller = Harness::new().admit(&claims).await?;
    let CallerKind::ExternalPerson(person) = caller.kind() else {
        panic!("an external person: {caller:?}");
    };
    assert_eq!(
        Some(identity.id()),
        person.field(Field::AssertionId).and_then(Attribute::text)
    );
    assert!(person.trc_patient().is_none());
    Ok(())
}

// NOTE: eHDSI SAML Profile 10.0.0 §2.1: the NameID identifies the HP under its
// @Format, so the caller carries the pair, read from one place.
#[tokio::test]
async fn the_caller_carries_the_name_id_with_its_format() -> Outcome {
    let caller = Harness::new().admit(&token()).await?;
    let name_id = caller.name_id().ok_or("a NameID")?;
    assert_eq!("CN=Synthetic Doctor,O=Hospital,C=BE", name_id.value());
    assert_eq!(NameIdFormat::X509SubjectName, name_id.format());
    assert_eq!(
        "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
        name_id.format().as_str()
    );
    let CallerKind::ExternalPerson(person) = caller.kind() else {
        panic!("an external person: {caller:?}");
    };
    assert_eq!(
        Some(name_id.value()),
        person
            .field(Field::ProfessionalHpIdentifier)
            .and_then(Attribute::text),
        "the NameID is professional.hp_identifier"
    );
    let rendered = format!("{name_id:?}");
    assert!(!rendered.contains("Synthetic Doctor"), "{rendered}");
    assert!(rendered.contains("X509SubjectName"), "{rendered}");
    Ok(())
}

/// The request message's UUID a contact point relays (eHDSI `NCPeH`
/// Components Specifications 10.0.0 §3.5, the WS-Addressing `MessageID`).
const MESSAGE_ID: &str = "urn:uuid:98f4bf0c-f21a-48bc-8518-958c9d9dc4c1";

/// Returns the contact-point token relaying `message_id` under the `ehdsi`
/// mapping's default claim.
fn relaying(message_id: &str) -> Value {
    let mut claims = token();
    claims
        .pointer_mut("/ehdsi")
        .and_then(Value::as_object_mut)
        .expect("the ehdsi object")
        .insert(String::from("message_id"), json!(message_id));
    claims
}

#[tokio::test]
async fn the_caller_carries_the_relayed_message_id_and_never_renders_it() -> Outcome {
    let caller = Harness::new().admit(&relaying(MESSAGE_ID)).await?;
    let message_id = caller.message_id().ok_or("a message id")?;
    assert_eq!(MESSAGE_ID, message_id.as_str());
    let CallerKind::ExternalPerson(person) = caller.kind() else {
        panic!("an external person: {caller:?}");
    };
    assert_eq!(
        Some(MESSAGE_ID),
        person.field(Field::MessageId).and_then(Attribute::text),
        "the ehdsi mapping reads ehdsi.message_id"
    );
    for rendered in [format!("{message_id:?}"), format!("{caller:?}")] {
        assert!(!rendered.contains("98f4bf0c"), "{rendered}");
    }
    Ok(())
}

#[tokio::test]
async fn a_contact_point_token_without_a_message_id_is_admitted() -> Outcome {
    let caller = Harness::new().admit(&token()).await?;
    assert!(caller.message_id().is_none());
    Ok(())
}

#[tokio::test]
async fn a_message_id_with_a_control_character_or_too_long_is_refused() {
    let h = Harness::new();
    let long = "a".repeat(257);
    for bad in ["urn:uuid:1\u{0}2", "urn:uuid:\u{202e}12", long.as_str()] {
        assert!(h.admit(&relaying(bad)).await.is_err(), "{bad:?}");
    }
}

// NOTE: eHDSI SAML Profile 10.0.0 §2.1: the @Format "MUST be" one of three URNs.
#[tokio::test]
async fn each_of_the_three_formats_is_admitted_and_another_refused() -> Outcome {
    let h = Harness::new();
    for format in NameIdFormat::ALL {
        let mut claims = token();
        claims["ehdsi"]["assertion"]["name_id_format"] = json!(format.as_str());
        let caller = h.admit(&claims).await?;
        assert_eq!(
            Some(format),
            caller.name_id().map(|name_id| name_id.format()),
            "{format}"
        );
        assert_eq!(Ok(format), format.as_str().parse::<NameIdFormat>());
    }
    for other in [
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailaddress",
        "",
    ] {
        let mut claims = token();
        claims["ehdsi"]["assertion"]["name_id_format"] = json!(other);
        assert_eq!(
            Some((
                EhdsiCode::HpiInsufficientInformation,
                vec!["assertion.name_id_format"]
            )),
            code(h.admit(&claims).await),
            "{other:?}"
        );
        assert!(other.parse::<NameIdFormat>().is_err(), "{other:?}");
    }
    Ok(())
}

// NOTE: no specification governs the form: our own design, in which the format is
// one string and a coded value refuses the token naming the field.
#[tokio::test]
async fn a_coded_format_is_refused_naming_the_field() -> Outcome {
    let mut claims = token();
    claims["ehdsi"]["assertion"]["name_id_format"] = json!([NameIdFormat::Unspecified.as_str()]);
    let refused = Harness::new().admit(&claims).await;
    assert!(
        matches!(
            refused,
            Err(Rejection::Unclassified {
                reason: Unclassified::Attribute {
                    field: "assertion.name_id_format"
                }
            })
        ),
        "{refused:?}"
    );
    Ok(())
}

#[test]
fn the_format_field_loads_from_toml_by_its_name() -> Outcome {
    let section: FederationSection = toml::from_str(
        "[fields]\n\"assertion.name_id_format\" = [{ claim = \"saml.name_id_format\" }]\n",
    )?;
    assert_eq!(
        Some(&vec![Source::Claim(String::from("saml.name_id_format"))]),
        section.fields.get(&Field::AssertionNameIdFormat)
    );
    assert_eq!(
        "assertion.name_id_format",
        Field::AssertionNameIdFormat.as_str()
    );
    Ok(())
}

// NOTE: eHDSI SAML Profile 10.0.0 §2.3: purpose of use is TREATMENT or EMERGENCY,
// and "If a HP requests claims for another purpose of use, the request must be rejected".
#[tokio::test]
async fn a_purpose_other_than_treatment_or_emergency_is_refused() -> Outcome {
    let h = Harness::new();
    let mut claims = token();
    claims["ehdsi"]["purpose_of_use"] = json!("EMERGENCY");
    assert!(h.admit(&claims).await.is_ok(), "EMERGENCY");
    claims["ehdsi"]["purpose_of_use"] = json!("RESEARCH");
    assert_eq!(
        Some((
            EhdsiCode::HpiInsufficientInformation,
            vec!["purpose_of_use"]
        )),
        code(h.admit(&claims).await)
    );
    Ok(())
}

// NOTE: eHDSI SAML Profile 10.0.0 §2.3: `on-behalf-of` is mandatory for the
// structural role "44 - Other Clerical Support Workers".
#[tokio::test]
async fn role_44_without_on_behalf_of_is_refused() -> Outcome {
    let h = Harness::new();
    let mut claims = token();
    claims["ehdsi"]["professional"]["hp_professional_role"] =
        json!([{ "system": "2.16.840.1.113883.2.9.6.2.7", "code": "44" }]);
    assert_eq!(
        Some((
            EhdsiCode::HpiInsufficientInformation,
            vec!["professional.on_behalf_of"]
        )),
        code(h.admit(&claims).await)
    );
    claims["ehdsi"]["professional"]["on_behalf_of"] = json!("221");
    assert!(h.admit(&claims).await.is_ok(), "with on_behalf_of");
    Ok(())
}

// NOTE: Requirements Catalogue 10.0.0 requirements 01 and 01.02: country A must not
// deny access on the description of the HP, the role or the point of care.
#[tokio::test]
async fn an_unusual_role_or_point_of_care_is_not_refused() -> Outcome {
    let mut claims = token();
    claims["ehdsi"]["professional"]["hp_professional_role"] =
        json!([{ "system": "urn:oid:9.9.9", "code": "veterinary-locum" }]);
    claims["ehdsi"]["point_of_care"] = json!("Mobile unit 7, harbour side");
    assert!(Harness::new().admit(&claims).await.is_ok());
    Ok(())
}

// NOTE: Requirements Catalogue 10.0.0 requirement 01 has country B send the HP's
// information, so a token without a professional is ERROR_HPI_NO_INFORMATION.
#[tokio::test]
async fn a_token_without_a_professional_is_refused_never_an_organisation() -> Outcome {
    let mut claims = token();
    if let Some(ehdsi) = claims.get_mut("ehdsi").and_then(Value::as_object_mut) {
        ehdsi.remove("professional");
    }
    claims["sub"] = json!("ncpeh-b");
    assert_eq!(
        Some((EhdsiCode::HpiNoInformation, Vec::new())),
        code(Harness::new().admit(&claims).await)
    );
    Ok(())
}

// NOTE: eHDSI SAML Profile 10.0.0 §2.1 lists seven classes and judges no level;
// Interoperability Specifications 8.0.1 §2.4.3: no country rejects another's assurance.
#[tokio::test]
async fn each_of_the_seven_classes_is_admitted_and_an_unknown_one_refused() -> Outcome {
    let h = Harness::new();
    for class in AUTHENTICATION_CLASSES {
        let mut claims = token();
        claims["ehdsi"]["professional"]["authentication_method"] = json!(class);
        let caller = h.admit(&claims).await?;
        assert!(
            matches!(caller.kind(), CallerKind::ExternalPerson(_)),
            "{class}"
        );
    }
    let mut claims = token();
    claims["ehdsi"]["professional"]["authentication_method"] =
        json!("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");
    assert_eq!(
        Some((
            EhdsiCode::HpiAuthenticationNotReceived,
            vec!["professional.authentication_method"]
        )),
        code(h.admit(&claims).await)
    );
    Ok(())
}

// NOTE: eHDSI SAML Profile 10.0.0 §2.1 and §4: the IdA lives at most 4 h and the
// TRC at most 2 h, with 60 s of drift; the token never outlives either window.
#[tokio::test]
async fn an_issued_token_never_outlives_the_ida_or_the_trc() -> Outcome {
    let h = Harness::new();
    let integrity = Some((EhdsiCode::SecDataIntegrityNotEnsured, vec!["exp"]));
    let mut past_ida = token();
    past_ida["ehdsi"]["assertion"]["not_on_or_after"] = json!(now() + 120);
    assert_eq!(integrity, code(h.admit(&past_ida).await), "past the IdA");
    let mut past_trc = token();
    past_trc["ehdsi"]["trc"]["not_on_or_after"] = json!(now() + 120);
    assert_eq!(integrity, code(h.admit(&past_trc).await), "past the TRC");
    let mut long_ida = token();
    long_ida["ehdsi"]["assertion"]["not_before"] = json!(now() - 4 * 3600);
    assert_eq!(
        integrity,
        code(h.admit(&long_ida).await),
        "an IdA window over 4 h"
    );
    let mut long_trc = token();
    long_trc["ehdsi"]["trc"]["not_before"] = json!(now() - 2 * 3600);
    assert_eq!(
        integrity,
        code(h.admit(&long_trc).await),
        "a TRC window over 2 h"
    );
    Ok(())
}

// NOTE: Requirements Catalogue 10.0.0 §1.25 names no code for an unreadable key
// set and places ERROR_REGISTRY_NOT_AVAILABLE under requirement 05, so it is requirement 11's.
#[tokio::test]
async fn every_rejection_maps_to_a_code_name() -> Outcome {
    let invalid = Rejection::Invalid {
        reason: Reason::Signature,
    };
    assert_eq!(EhdsiCode::SecGeneric, EhdsiCode::of(&invalid));
    let unavailable = Rejection::upstream("key set", std::io::Error::other("down"));
    assert_eq!(EhdsiCode::SecGeneric, EhdsiCode::of(&unavailable));
    assert_eq!("ERROR_SEC_GENERIC", EhdsiCode::of(&unavailable).as_str());
    let refused = Harness::new().admit(&without("/point_of_care")).await;
    let refused = refused.err().ok_or("a refusal")?;
    assert_eq!(EhdsiCode::HpiPocNoInformation, EhdsiCode::of(&refused));
    Ok(())
}

// NOTE: a contact point's tokens live up to the IdA's 4 h, so it requires
// sender-constrained tokens; without the key it fails to load naming it.
#[tokio::test]
async fn a_contact_point_without_sender_constraint_required_fails_to_load() -> Outcome {
    let h = Harness::new();
    let mut settings = h.settings(table());
    settings.sender_constraint = SenderConstraint::None;
    let refused = ResourceServer::discover(settings).await;
    assert!(
        matches!(refused, Err(ResourceError::ContactPointSender)),
        "{refused:?}"
    );
    let message = refused
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(message.contains("sender_constraint"), "{message}");
    Ok(())
}

#[test]
fn a_contact_point_takes_no_provider_prefixes_and_configures_its_country() {
    let prefixed = FederationSection {
        provider_identifier_prefixes: vec![String::from("urn:oid:")],
        ..table()
    };
    assert!(
        prefixed.validate().is_err(),
        "no narrower bound on another country's identifiers"
    );
    let unconfigured = FederationSection {
        fields: BTreeMap::new(),
        ..table()
    };
    assert!(
        unconfigured.validate().is_err(),
        "the assertion carries no country and no issuing authority"
    );
    assert!(table().validate().is_ok());
}

/// The gate in front of a contact point, whose refusal carries the §1.25 code.
#[cfg(feature = "axum")]
mod gate {
    use std::sync::Arc;

    use ferrohealth_smart::federation::contact::EhdsiCode;
    use ferrohealth_smart::guard::Gate;
    use ferrohealth_smart::jws::algorithm::Algorithm;
    use ferrohealth_smart::jws::compact::Header;
    use ferrohealth_smart::refusal::Denied;
    use ferrohealth_smart::refusal::Refusal;
    use ferrohealth_smart::resource::ResourceServer;
    use ferrohealth_smart::sender::ClientCertificate;
    use http::Request;
    use http::header;
    use serde_json::Value;

    use super::CERTIFICATE;
    use super::Harness;
    use super::Outcome;
    use super::table;
    use super::without;
    use crate::support::mint_with;

    /// Returns the denial the gate answers `token` with over the bound
    /// connection.
    async fn deny(h: &Harness, token: &str) -> Result<Denied, Box<dyn std::error::Error>> {
        let server = ResourceServer::discover(h.settings(table())).await?;
        let gate = Gate::default().with_bearer(Arc::new(server));
        let (mut parts, ()) = Request::get("/fhir/Patient")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(())?
            .into_parts();
        parts
            .extensions
            .insert(ClientCertificate::from_der(CERTIFICATE));
        let denied = gate
            .authenticate_request(&parts)
            .await
            .err()
            .ok_or("a refusal")?;
        Ok(denied)
    }

    /// Returns `claims` signed by the contact point's key.
    fn signed(h: &Harness, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::Es256);
        header.kid = Some(String::from("cp"));
        header.typ = Some(String::from("at+jwt"));
        mint_with(&h.key, &header, claims)
    }

    // NOTE: MyHealth@EU Requirements Catalogue 10.0.0 §1.25, requirement 01: the
    // gate's refusal names the code the contact-point check refused the token with.
    #[tokio::test]
    async fn a_contact_point_refusal_from_the_gate_carries_its_code() -> Outcome {
        let h = Harness::new();
        let denied = deny(&h, &signed(&h, &without("/point_of_care"))).await?;
        assert_eq!(&Refusal::InvalidToken, denied.refusal());
        assert_eq!(Some(EhdsiCode::HpiPocNoInformation), denied.ehdsi());
        let code = denied.ehdsi().ok_or("a code")?;
        assert_eq!("ERROR_HPI_POC_NO_INFORMATION", code.as_str());
        assert_eq!("01", code.requirement());
        assert_eq!(
            Some(String::from("Bearer error=\"invalid_token\"")),
            denied.refusal().challenge(None),
            "RFC 6750 §3.1: the code stays off the challenge"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_refusal_before_the_contact_point_check_carries_no_code() -> Outcome {
        let h = Harness::new();
        let mut forged = signed(&h, &super::token());
        forged.push('A');
        let denied = deny(&h, &forged).await?;
        assert_eq!(&Refusal::InvalidToken, denied.refusal());
        assert_eq!(None, denied.ehdsi(), "ERROR_SEC_GENERIC is EhdsiCode::of's");
        Ok(())
    }
}
