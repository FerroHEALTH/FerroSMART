// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The external callers a party binding never looks up: an IHE IUA token
//! naming another party's professional, and an attested organisation
//! statement, each classified through the public API.

use std::collections::BTreeMap;
use std::error::Error as StdError;

use ferrohealth_smart::assurance::AssuranceLevel;
use ferrohealth_smart::assurance::AssuranceSection;
use ferrohealth_smart::federation::FederationSection;
use ferrohealth_smart::federation::Field;
use ferrohealth_smart::federation::Mapping;
use ferrohealth_smart::federation::Source;
use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrohealth_smart::jws::compact::Header;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::resource::Caller;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::Settings;
use serde_json::Value;
use serde_json::json;

use crate::support::ec_key;
use crate::support::mint_with;
use crate::support::now;
use crate::support::temp_file;

/// The federation issuer; its `sub` values name users in its namespace.
const ISSUER: &str = "https://sts.partner.example.org";
/// This node's audience.
const AUDIENCE: &str = "https://ehr.example.org/openehr";
/// The provider identifier prefix the issuer may assert.
const PREFIX: &str = "urn:oid:2.16.528.1.1007.3.3.";
/// The `sub` of the external professional, the same value as the persons
/// issuer's login, which is never matched.
const REMOTE: &str = super::LOGIN;

/// Returns the table of a domestic IUA issuer that attests organisation
/// statements.
fn section() -> FederationSection {
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
        attests_authorization_details: true,
        organisation_types: vec![String::from("nl_organisation_access")],
        authorization_details_type: Some(String::from("nl_organisation_access")),
        ..FederationSection::default()
    }
}

/// Returns the claims of an IUA token naming a professional, as the IHE IUA
/// §3.71.4.2.2.1.3 example shapes them.
fn professional() -> Value {
    json!({
        "iss": ISSUER, "sub": REMOTE, "client_id": "partner-app", "aud": AUDIENCE,
        "jti": "jti-1", "exp": now() + 300, "nbf": now(), "iat": now(),
        "scope": "user/*.rs", "acr": "urn:acr:high",
        "extensions": { "ihe_iua": {
            "subject_name": "Dr. Synthetic Smith",
            "subject_organization": "Synthetic Hospital",
            "subject_organization_id": format!("{PREFIX}12345678"),
            "national_provider_identifier": "900012345",
            "subject_role": [{
                "system": "http://terminology.hl7.org/CodeSystem/practitioner-role",
                "code": "pharmacist"
            }],
            "purpose_of_use": [{
                "system": "http://terminology.hl7.org/CodeSystem/v3-ActReason",
                "code": "TREAT"
            }]
        } }
    })
}

/// Returns the claims of an attested organisation statement (RFC 9396).
fn organisation() -> Value {
    json!({
        "iss": ISSUER, "sub": "partner-app", "client_id": "partner-app",
        "aud": AUDIENCE, "jti": "jti-2", "exp": now() + 300, "iat": now(),
        "scope": "system/*.rs",
        "authorization_details": [{
            "type": "nl_organisation_access",
            "locations": [AUDIENCE],
            "ura": format!("{PREFIX}87654321")
        }]
    })
}

/// Returns an external professional and an external organisation, each
/// classified from a signed token.
pub(super) async fn externals() -> Result<Vec<Caller>, Box<dyn StdError>> {
    let key = ec_key("fed", Algorithm::Es256);
    let set = json!({ "keys": [key.jwk.clone()] }).to_string();
    let mut settings = Settings::new(ISSUER, AUDIENCE, IssuerKind::Federation);
    settings.jwks_file = Some(temp_file("party-federation-jwks.json", set.as_bytes()));
    settings.profile.token_types = vec![String::from("IUA-JWT")];
    settings.assurance = Some(AssuranceSection {
        levels: BTreeMap::from([(String::from("urn:acr:high"), AssuranceLevel::High)]),
        ..AssuranceSection::default()
    });
    let mut organisation_section = section();
    organisation_section.mapping = None;
    organisation_section.fields = BTreeMap::from([(
        Field::ProviderFacilityType,
        vec![Source::AuthorizationDetails(String::from("ura"))],
    )]);
    let mut header = Header::new(Algorithm::Es256);
    header.kid = Some(String::from("fed"));
    header.typ = Some(String::from("IUA-JWT"));
    let mut callers = Vec::new();
    for (table, claims) in [
        (section(), professional()),
        (organisation_section, organisation()),
    ] {
        let mut settings = settings.clone();
        settings.federation = Some(table);
        let server = ResourceServer::discover(settings).await?;
        callers.push(
            server
                .authenticate(&mint_with(&key, &header, &claims))
                .await?,
        );
    }
    assert!(
        matches!(
            callers.as_slice(),
            [first, second]
                if matches!(first.kind(), CallerKind::ExternalPerson(_))
                    && matches!(second.kind(), CallerKind::ExternalOrganisation(_))
        ),
        "an external person and an external organisation: {callers:?}"
    );
    Ok(callers)
}
