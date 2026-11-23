// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `federation` kind through the public API: an IHE IUA token, a Nuts
//! RFC021 introspection response and an RFC 9396 `authorization_details`
//! entry in, an `ExternalPerson` or `ExternalOrganisation` out, every
//! refusal a typed `Rejection::Unclassified`.

use std::collections::BTreeMap;
use std::error::Error as StdError;

use ferrohealth_smart::assurance::AssuranceLevel;
use ferrohealth_smart::assurance::AssuranceSection;
use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::federation::Attribute;
use ferrohealth_smart::federation::Code;
use ferrohealth_smart::federation::External;
use ferrohealth_smart::federation::FederationSection;
use ferrohealth_smart::federation::Field;
use ferrohealth_smart::federation::Mapping;
use ferrohealth_smart::federation::Source;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::kind::Unclassified;
use ferrohealth_smart::resource::Caller;
use ferrohealth_smart::resource::Rejection;
use ferrohealth_smart::resource::ResourceError;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::Settings;
use jsonwebtoken::Algorithm;
use jsonwebtoken::Header;
use serde_json::Value;
use serde_json::json;

use crate::support::SigningKey;
use crate::support::ec_key;
use crate::support::mint_with;
use crate::support::now;
use crate::support::temp_file;

type Outcome = Result<(), Box<dyn StdError>>;

/// The federation issuer of the JWT cases; its key set is a file.
const ISSUER: &str = "https://sts.partner.example.org";
/// This node's audience.
const AUDIENCE: &str = "https://ehr.example.org/openehr";
/// The URA prefix the provider identifiers carry.
const PREFIX: &str = "urn:oid:2.16.528.1.1007.3.3.";

/// The table of a domestic IUA issuer: the IUA mapping, the country and the
/// issuing authority configured, the bounds declared.
pub(crate) fn iua() -> FederationSection {
    FederationSection {
        issuer: ferrohealth_secret::secret_url::SecretUrl::new(ISSUER),
        contact_point: Some(false),
        mapping: Some(Mapping::Iua),
        fields: BTreeMap::from([
            (
                Field::ProfessionalCountryCode,
                vec![Source::Constant(String::from("NL"))],
            ),
            (
                Field::ProfessionalIssuingAuthorityName,
                vec![Source::Constant(String::from("CIBG"))],
            ),
        ]),
        countries: vec![String::from("NL")],
        issuing_authorities: vec![String::from("CIBG")],
        provider_identifier_prefixes: vec![String::from(PREFIX)],
        ..FederationSection::default()
    }
}

/// The assurance mapping of the federation issuer.
fn assurance() -> AssuranceSection {
    AssuranceSection {
        levels: BTreeMap::from([
            (String::from("urn:acr:low"), AssuranceLevel::Low),
            (
                String::from("urn:acr:substantial"),
                AssuranceLevel::Substantial,
            ),
            (String::from("urn:acr:high"), AssuranceLevel::High),
        ]),
        ..AssuranceSection::default()
    }
}

/// The claims of an IUA token naming a professional, shaped as the IHE IUA
/// §3.71.4.2.2.1.3 example with the required claims of §3.71.4.2.2.1.
pub(crate) fn professional() -> Value {
    json!({
        "iss": ISSUER, "sub": "b3ca1045-aa8b-42f9-9fd9-e0cbf5cb90a7",
        "client_id": "partner-app", "aud": AUDIENCE, "jti": "jti-1",
        "exp": now() + 300, "nbf": now(), "iat": now(), "scope": "user/*.rs",
        "acr": "urn:acr:high",
        "extensions": {
            "ihe_iua": {
                "subject_name": "Dr. Synthetic Smith",
                "subject_organization": "Synthetic Hospital",
                "subject_organization_id": format!("{PREFIX}12345678"),
                "home_community_id": "urn:oid:1.2.3.4.5.6.7.8",
                "national_provider_identifier": "900012345",
                "person_id": "urn:uuid:fb45ea81-33f3-4600-9940-95cd46852e84",
                "subject_role": [{
                    "system": "http://terminology.hl7.org/CodeSystem/practitioner-role",
                    "code": "pharmacist",
                    "display": "Pharmacist"
                }],
                "purpose_of_use": [{
                    "system": "http://terminology.hl7.org/CodeSystem/v3-ActReason",
                    "code": "TREAT",
                    "display": "treatment"
                }]
            }
        }
    })
}

/// The federation issuer of the JWT cases.
pub(crate) struct Harness {
    /// The signing key, in the key set file.
    key: SigningKey,
}

impl Harness {
    pub(crate) fn new() -> Self {
        Self {
            key: ec_key("fed", Algorithm::ES256),
        }
    }

    /// Returns the settings of the issuer under `section`.
    fn settings(&self, section: FederationSection) -> Settings {
        let set = json!({ "keys": [self.key.jwk.clone()] }).to_string();
        let mut settings = Settings::new(ISSUER, AUDIENCE, IssuerKind::Federation);
        settings.jwks_file = Some(temp_file("federation-jwks.json", set.as_bytes()));
        // NOTE: IHE IUA §3.71.4.2.2.1.3 types its example `IUA-JWT`; the profile
        // lists it, and HMAC stays refused (our own design, against §3.71.4.2.2.1).
        settings.profile.token_types = vec![String::from("IUA-JWT")];
        settings.assurance = Some(assurance());
        settings.federation = Some(section);
        settings
    }

    /// Returns the caller `claims` authenticate under `section`.
    pub(crate) async fn admit(
        &self,
        section: FederationSection,
        claims: &Value,
    ) -> Result<Caller, Rejection> {
        let server = ResourceServer::discover(self.settings(section))
            .await
            .expect("the key set file reads");
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(String::from("fed"));
        header.typ = Some(String::from("IUA-JWT"));
        server
            .authenticate(&mint_with(&self.key, &header, claims))
            .await
    }
}

/// Returns the classification refusal of `outcome`.
pub(crate) fn refused(outcome: Result<Caller, Rejection>) -> Option<Unclassified> {
    match outcome {
        Err(Rejection::Unclassified { reason }) => Some(reason),
        _ => None,
    }
}

/// Returns the external party a caller names.
fn external(caller: &Caller) -> Option<&External> {
    match caller.kind() {
        CallerKind::ExternalPerson(external) | CallerKind::ExternalOrganisation(external) => {
            Some(external)
        }
        _ => None,
    }
}

// NOTE: IHE IUA §3.71.4.2.2.1.1: `subject_name` is "The user's name as String" and
// `subject_role` an "array of FHIR Coding data type"; `person_id` is the patient's.
#[tokio::test]
async fn an_iua_token_is_an_external_person_as_asserted() -> Outcome {
    let caller = Harness::new().admit(iua(), &professional()).await?;
    assert!(
        matches!(caller.kind(), CallerKind::ExternalPerson(_)),
        "{caller:?}"
    );
    let person = external(&caller).ok_or("an external party")?;
    assert_eq!(
        Some(&Attribute::Text(String::from("Dr. Synthetic Smith"))),
        person.field(Field::ProfessionalName)
    );
    assert_eq!(
        Some(&Attribute::Codes(vec![Code {
            system: Some(String::from(
                "http://terminology.hl7.org/CodeSystem/practitioner-role"
            )),
            code: String::from("pharmacist"),
        }])),
        person.field(Field::ProfessionalHpProfessionalRole)
    );
    assert!(
        person
            .fields()
            .values()
            .all(|value| value.text() != Some("urn:uuid:fb45ea81-33f3-4600-9940-95cd46852e84")),
        "person_id is never read as the professional"
    );
    assert_eq!(
        "b3ca1045-aa8b-42f9-9fd9-e0cbf5cb90a7",
        person.remote_subject()
    );
    assert!(
        caller.roles().is_empty(),
        "a federation token contributes no role"
    );
    Ok(())
}

// NOTE: no field names a country (#492): a Dutch UZI token and another token
// carry the professional's identifier and role in the same generic fields, each
// value with its own code system (2026/2099 Annex Table 1).
#[tokio::test]
async fn a_uzi_token_and_another_token_share_the_generic_fields() -> Outcome {
    let section = FederationSection {
        fields: {
            let mut fields = iua().fields;
            fields.insert(
                Field::ProfessionalHpIdentifier,
                vec![Source::Claim(String::from(
                    "extensions.ihe_iua.hp_identifier",
                ))],
            );
            fields
        },
        ..iua()
    };
    let token = |identifier: Value, role: Value| {
        let mut claims = professional();
        claims["extensions"]["ihe_iua"]["hp_identifier"] = identifier;
        claims["extensions"]["ihe_iua"]["subject_role"] = role;
        claims
    };
    let coded = |system: &str, code: &str| {
        Attribute::Codes(vec![Code {
            system: Some(String::from(system)),
            code: String::from(code),
        }])
    };
    for (case, system, number, role_system, role) in [
        (
            "a UZI token",
            "urn:oid:2.16.528.1.1007.3.1",
            "900012345",
            "urn:oid:2.16.840.1.113883.2.4.15.111",
            "17.000",
        ),
        (
            "another token",
            "urn:oid:1.2.250.1.71.4.2.1",
            "810000123456",
            "urn:oid:1.2.250.1.213.1.1.4.5",
            "10",
        ),
    ] {
        let claims = token(
            json!([{ "system": system, "code": number }]),
            json!([{ "system": role_system, "code": role }]),
        );
        let caller = Harness::new().admit(section.clone(), &claims).await?;
        let person = external(&caller).ok_or("an external party")?;
        assert_eq!(
            Some(&coded(system, number)),
            person.field(Field::ProfessionalHpIdentifier),
            "{case}"
        );
        assert_eq!(
            Some(&coded(role_system, role)),
            person.field(Field::ProfessionalHpProfessionalRole),
            "{case}"
        );
    }
    let unsystemed = token(json!(["900012345"]), json!(["17.000"]));
    let caller = Harness::new().admit(section, &unsystemed).await?;
    let person = external(&caller).ok_or("an external party")?;
    assert_eq!(
        Some(&Attribute::Codes(vec![Code {
            system: None,
            code: String::from("17.000"),
        }])),
        person.field(Field::ProfessionalHpProfessionalRole),
        "a value without a code system is kept unsystemed, for a consumer to refuse"
    );
    Ok(())
}

// NOTE: the products ship no country content (owner rule, #492): no field of the
// federation model is named after a country.
#[test]
fn no_field_names_a_country() -> Outcome {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/federation/mod.rs"),
    )?;
    for country in ["\"nl.", "\"de.", "\"be.", "\"fr.", " Nl", "Dutch"] {
        assert!(
            !text.contains(country),
            "the federation model names {country:?}"
        );
    }
    Ok(())
}

// NOTE: 2026/2099 Annex Table 1 makes every professional field mandatory, so a
// partial professional is refused naming each missing field, never an organisation.
#[tokio::test]
async fn a_partial_professional_is_refused_naming_the_missing_fields() -> Outcome {
    let mut claims = professional();
    let iua = claims
        .pointer_mut("/extensions/ihe_iua")
        .and_then(Value::as_object_mut)
        .ok_or("the extension")?;
    iua.remove("subject_role");
    iua.remove("national_provider_identifier");
    let outcome = Harness::new().admit(self::iua(), &claims).await;
    assert_eq!(
        Some(Unclassified::ExternalIncomplete {
            missing: vec![
                "professional.hp_identifier",
                "professional.hp_professional_role"
            ]
        }),
        refused(outcome)
    );
    Ok(())
}

// NOTE: IHE IUA §3.71.4.2.2.1: `sub` is the client_id when no user is known; with
// no professional field, only an explicit organisation statement makes an organisation.
#[tokio::test]
async fn an_organisation_needs_an_attested_statement() -> Outcome {
    let organisation = json!({
        "iss": ISSUER, "sub": "partner-app", "client_id": "partner-app",
        "aud": AUDIENCE, "jti": "jti-2", "exp": now() + 300, "iat": now(),
        "scope": "system/*.rs",
        "authorization_details": [{
            "type": "nl_organisation_access",
            "locations": [AUDIENCE],
            "ura": format!("{PREFIX}87654321")
        }]
    });
    let unattested = FederationSection {
        mapping: None,
        fields: BTreeMap::new(),
        ..iua()
    };
    assert_eq!(
        Some(Unclassified::NoOrganisationStatement),
        refused(
            Harness::new()
                .admit(unattested.clone(), &organisation)
                .await
        ),
        "an issuer that does not attest authorization_details states nothing"
    );
    let attested = FederationSection {
        attests_authorization_details: true,
        organisation_types: vec![String::from("nl_organisation_access")],
        authorization_details_type: Some(String::from("nl_organisation_access")),
        fields: BTreeMap::from([(
            Field::ProviderFacilityType,
            vec![Source::AuthorizationDetails(String::from("ura"))],
        )]),
        ..unattested
    };
    let caller = Harness::new()
        .admit(attested.clone(), &organisation)
        .await?;
    assert!(
        matches!(caller.kind(), CallerKind::ExternalOrganisation(_)),
        "{caller:?}"
    );
    let mut elsewhere = organisation.clone();
    elsewhere["authorization_details"][0]["locations"] = json!(["https://other.example.org"]);
    assert_eq!(
        Some(Unclassified::AuthorizationDetails),
        refused(Harness::new().admit(attested.clone(), &elsewhere).await),
        "RFC 9396 §12: locations is the audience restriction"
    );
    let mut padded = organisation.clone();
    padded["authorization_details"][0]["locations"] = json!([format!("{AUDIENCE}/")]);
    assert_eq!(
        Some(Unclassified::AuthorizationDetails),
        refused(Harness::new().admit(attested.clone(), &padded).await),
        "RFC 9396 §12: compared with no normalization"
    );
    let mut wrong = organisation;
    wrong["authorization_details"][0]["type"] = json!("another_type");
    assert_eq!(
        Some(Unclassified::AuthorizationDetails),
        refused(Harness::new().admit(attested, &wrong).await),
        "an entry of another type"
    );
    Ok(())
}

#[test]
fn an_authorization_details_source_without_the_attestation_fails_to_load() {
    let section = FederationSection {
        fields: BTreeMap::from([(
            Field::ProviderFacilityType,
            vec![Source::AuthorizationDetails(String::from("ura"))],
        )]),
        ..iua()
    };
    assert!(section.validate().is_err());
}

#[tokio::test]
async fn two_sources_that_disagree_refuse_the_token() -> Outcome {
    let mut section = iua();
    section.fields.insert(
        Field::ProfessionalName,
        vec![
            Source::Claim(String::from("extensions.ihe_iua.subject_name")),
            Source::Claim(String::from("display_name")),
        ],
    );
    let mut claims = professional();
    claims["display_name"] = json!("Dr. Another Name");
    assert_eq!(
        Some(Unclassified::SourcesDisagree {
            field: "professional.name"
        }),
        refused(Harness::new().admit(section.clone(), &claims).await)
    );
    claims["display_name"] = json!("Dr. Synthetic Smith");
    assert!(
        Harness::new().admit(section, &claims).await.is_ok(),
        "agreeing sources"
    );
    Ok(())
}

#[tokio::test]
async fn a_country_outside_the_bounds_is_refused() -> Outcome {
    let mut section = iua();
    section.fields.insert(
        Field::ProfessionalCountryCode,
        vec![Source::Constant(String::from("BE"))],
    );
    assert_eq!(
        Some(Unclassified::OutOfBounds {
            field: "professional.country_code"
        }),
        refused(Harness::new().admit(section, &professional()).await)
    );
    let mut claims = professional();
    claims["extensions"]["ihe_iua"]["subject_organization_id"] = json!("urn:oid:9.9.9");
    assert_eq!(
        Some(Unclassified::OutOfBounds {
            field: "professional.healthcare_provider_identifier"
        }),
        refused(Harness::new().admit(iua(), &claims).await)
    );
    Ok(())
}

// NOTE: no specification governs the attribute checks: our own design, against a
// value that renders other than it reads (U+202E RIGHT-TO-LEFT OVERRIDE).
#[tokio::test]
async fn an_attribute_holding_a_bidi_control_is_refused() -> Outcome {
    let mut claims = professional();
    claims["extensions"]["ihe_iua"]["subject_name"] = json!("Dr. \u{202E}htimS");
    assert_eq!(
        Some(Unclassified::Attribute {
            field: "professional.name"
        }),
        refused(Harness::new().admit(iua(), &claims).await)
    );
    claims["extensions"]["ihe_iua"]["subject_name"] = json!("Dr.\u{0007}Smith");
    assert!(
        refused(Harness::new().admit(iua(), &claims).await).is_some(),
        "a C0 control"
    );
    Ok(())
}

// NOTE: Commission Implementing Regulation (EU) 2026/2099 Art. 6(3): "at least the
// assurance level substantial"; holding a domestic issuer to it is our own design.
#[tokio::test]
async fn a_professional_below_level_substantial_is_refused() -> Outcome {
    let mut claims = professional();
    claims["acr"] = json!("urn:acr:low");
    assert_eq!(
        Some(Unclassified::AssuranceTooLow),
        refused(Harness::new().admit(iua(), &claims).await)
    );
    claims["acr"] = json!("urn:acr:substantial");
    assert!(Harness::new().admit(iua(), &claims).await.is_ok());
    Ok(())
}

#[test]
fn a_prefixed_contact_point_or_an_undeclared_one_fails_to_load() {
    let contact = FederationSection {
        contact_point: Some(true),
        ..iua()
    };
    let refusal = contact.validate().err().map(|error| error.to_string());
    assert!(
        refusal
            .as_deref()
            .is_some_and(|text| text.contains("provider_identifier_prefixes")),
        "{refusal:?}"
    );
    let undeclared = FederationSection {
        contact_point: None,
        ..iua()
    };
    assert!(undeclared.validate().is_err());
    let unbounded = FederationSection {
        countries: Vec::new(),
        ..iua()
    };
    assert!(
        unbounded.validate().is_err(),
        "a domestic issuer declares countries"
    );
    let no_country = FederationSection {
        fields: BTreeMap::new(),
        ..iua()
    };
    assert!(
        no_country.validate().is_err(),
        "IUA has no country or issuing authority default"
    );
}

#[tokio::test]
async fn a_federation_issuer_without_its_table_or_with_roles_fails_to_load() -> Outcome {
    let h = Harness::new();
    let mut settings = h.settings(iua());
    settings.federation = None;
    assert!(matches!(
        ResourceServer::discover(settings).await,
        Err(ResourceError::Kind { .. })
    ));
    let mut settings = h.settings(iua());
    settings.role_claims = vec![String::from("roles")];
    assert!(matches!(
        ResourceServer::discover(settings).await,
        Err(ResourceError::Kind { .. })
    ));
    Ok(())
}

#[test]
fn the_federation_tables_load_from_toml_and_name_their_issuers() -> Outcome {
    let text = format!(
        r#"[issuer.i1]
issuer = "{ISSUER}"
kind = "federation"
audience = ["{AUDIENCE}"]

[issuer.i1.profile]
token_types = ["IUA-JWT"]

[issuer.i1.federation]
contact_point = false
mapping = "iua"
countries = ["NL"]
issuing_authorities = ["CIBG"]
provider_identifier_prefixes = ["{PREFIX}"]

[issuer.i1.federation.fields]
"professional.country_code" = [{{ constant = "NL" }}]
"professional.issuing_authority_name" = [{{ constant = "CIBG" }}]
"#
    );
    let section: AuthSection = toml::from_str(&text)?;
    let resolved = section.resolve(&[])?;
    let settings = resolved.issuers.first().ok_or("one issuer")?;
    assert!(settings.federation.is_some());
    let stray: AuthSection = toml::from_str(&text.replace("kind = \"federation\"\n", ""))?;
    assert!(matches!(
        stray.resolve(&[]),
        Err(ConfigError::Federation { .. })
    ));
    Ok(())
}

/// The Nuts RFC021 §6 introspection cases.
#[cfg(feature = "fetch")]
mod nuts {
    use std::sync::Arc;

    use ferrohealth_smart::client::ClientCredentials;
    use ferrohealth_smart::client::Endpoint;
    use ferrohealth_smart::resource::introspection::IntrospectionAuth;
    use ferrohealth_smart::resource::introspection::IntrospectionSettings;
    use ferrohealth_smart::resource::introspection::Introspector;
    use secrecy::SecretString;
    use wiremock::Mock;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::method;
    use wiremock::matchers::path;

    use super::*;
    use crate::support::Issuer;

    /// The table of a Nuts issuer: the presentations in `vps`, one declared
    /// user-authenticated credential type, its fields in the subject.
    fn table(issuer: &str) -> FederationSection {
        FederationSection {
            issuer: ferrohealth_secret::secret_url::SecretUrl::new(issuer),
            contact_point: Some(false),
            presentations_claim: Some(String::from("vps")),
            user_credential_types: vec![String::from("EmployeeCredential")],
            fields: BTreeMap::from([
                (
                    Field::ProfessionalName,
                    vec![Source::Presentation(String::from("name"))],
                ),
                (
                    Field::ProfessionalHpIdentifier,
                    vec![Source::Presentation(String::from("identifier"))],
                ),
                (
                    Field::ProfessionalHpProfessionalRole,
                    vec![Source::Presentation(String::from("roleName"))],
                ),
                (
                    Field::ProfessionalHealthcareProviderIdentifier,
                    vec![Source::Presentation(String::from("organization.ura"))],
                ),
                (
                    Field::ProviderHealthcareProviderIdentifier,
                    vec![Source::Presentation(String::from("organization.ura"))],
                ),
                (
                    Field::ProfessionalCountryCode,
                    vec![Source::Constant(String::from("NL"))],
                ),
                (
                    Field::ProfessionalIssuingAuthorityName,
                    vec![Source::Constant(String::from("CIBG"))],
                ),
                (
                    Field::Assurance,
                    vec![Source::Presentation(String::from("assurance"))],
                ),
            ]),
            countries: vec![String::from("NL")],
            issuing_authorities: vec![String::from("CIBG")],
            provider_identifier_prefixes: vec![String::from(PREFIX)],
            ..FederationSection::default()
        }
    }

    /// Returns the active response of a Nuts token whose presentation holds
    /// a credential of `types`.
    fn response(issuer: &str, types: &[&str]) -> Value {
        json!({
            "active": true,
            "iss": issuer,
            "sub": "did:web:holder.example.org",
            "client_id": "did:web:requester.example.org",
            "exp": now() + 300,
            "scope": "system/*.rs",
            "vps": [{
                "type": ["VerifiablePresentation"],
                "verifiableCredential": [{
                    "type": types,
                    "credentialSubject": {
                        "name": "Synthetic Nurse",
                        "identifier": "900067890",
                        "roleName": "nurse",
                        "assurance": "urn:acr:high",
                        "organization": { "ura": format!("{PREFIX}11112222") }
                    }
                }]
            }]
        })
    }

    /// Returns the caller the introspection `answer` describes.
    async fn admit(types: &[&str]) -> Result<Caller, Box<dyn StdError>> {
        let issuer = Issuer::bare().await;
        issuer
            .mount_metadata("/.well-known/oauth-authorization-server")
            .await;
        Mock::given(method("POST"))
            .and(path("/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response(&issuer.uri(), types)))
            .mount(&issuer.server)
            .await;
        let auth = IntrospectionAuth::Client(Box::new(ClientCredentials::new(
            Endpoint::Issuer(issuer.uri()),
            String::from("ferro-rs"),
            SecretString::from("synthetic-secret"),
        )));
        let mut settings =
            IntrospectionSettings::new(issuer.uri(), AUDIENCE, auth, IssuerKind::Federation);
        settings.assurance = Some(assurance());
        settings.federation = Some(table(&issuer.uri()));
        let introspector = Arc::new(Introspector::discover(settings).await?);
        Ok(introspector.authenticate("synthetic-opaque-token").await?)
    }

    // NOTE: Nuts RFC021 §8: the grant "is meant to be used in a machine to machine
    // context", so a token without a declared user credential is the organisation's.
    #[tokio::test]
    async fn a_nuts_token_without_a_user_credential_is_an_organisation() -> Outcome {
        let caller = admit(&["VerifiableCredential", "NutsOrganizationCredential"]).await?;
        assert!(
            matches!(caller.kind(), CallerKind::ExternalOrganisation(_)),
            "{caller:?}"
        );
        Ok(())
    }

    // NOTE: Nuts RFC021 §6: `vps` holds "The Verifiable Presentations that were used
    // to request the access token"; a declared user credential names the professional.
    #[tokio::test]
    async fn a_nuts_token_with_a_declared_user_credential_is_a_person() -> Outcome {
        let caller = admit(&["VerifiableCredential", "EmployeeCredential"]).await?;
        let CallerKind::ExternalPerson(person) = caller.kind() else {
            panic!("an external person: {caller:?}");
        };
        assert_eq!(
            Some(&Attribute::Text(String::from("Synthetic Nurse"))),
            person.field(Field::ProfessionalName)
        );
        Ok(())
    }
}
