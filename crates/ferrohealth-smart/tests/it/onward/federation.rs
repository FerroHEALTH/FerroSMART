// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The federation exchange: an onward token of another party's issuer,
//! which by design names no local person `sub`, checked by the attested
//! `person_mapping` of its `[auth.issuer.<name>.federation]` table, the field set of
//! 2026/2099 Annex Table 1 and, on a chained route, the correlation claim.

use std::collections::BTreeMap;

use ferrohealth_smart::assurance::AssuranceLevel;
use ferrohealth_smart::assurance::AssuranceSection;
use ferrohealth_smart::client::onward::OnwardError;
use ferrohealth_smart::client::onward::Rejected;
use ferrohealth_smart::client::onward::Target;
use ferrohealth_smart::client::onward::exchange::Onward;
use ferrohealth_smart::federation::FederationSection;
use ferrohealth_smart::federation::Field;
use ferrohealth_smart::federation::Mapping;
use ferrohealth_smart::federation::Source;
use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::kind::Unclassified;
use ferrohealth_smart::resource::Settings;
use serde_json::Value;
use serde_json::json;
use wiremock::MockServer;
use wiremock::ResponseTemplate;

use super::ClientKey;
use super::TestClock;
use super::answer;
use super::endpoint;
use super::sign;
use super::subject_of;
use crate::support::SigningKey;
use crate::support::ec_key;
use crate::support::now;

/// The other party's authorization server, of kind `federation`.
const FEDERATION: &str = "https://sts.partner.example.org";
/// The issuer of the caller's own token.
const HOME: &str = "https://as.example.org";
/// The other party's service the onward token is for.
const PARTNER: &str = "https://ehr.partner.example.org/openehr";
/// The URA prefix the provider identifiers carry.
const PREFIX: &str = "urn:oid:2.16.528.1.1007.3.3.";
/// The token endpoint route.
const ROUTE: &str = "/token";

/// Returns the table of the federation issuer: the IHE IUA mapping with
/// the country and issuing authority it lacks, its bounds, the home issuer
/// it maps, and the subject claim it maps from.
pub(crate) fn section() -> FederationSection {
    FederationSection {
        issuer: ferrohealth_secret::secret_url::SecretUrl::new(FEDERATION),
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
        exchanges_from: vec![String::from(HOME)],
        person_mapping: Some(String::from("hp_identifier")),
        ..FederationSection::default()
    }
}

/// Returns the settings of the federation issuer over `section`.
fn settings(section: FederationSection) -> Settings {
    let mut settings = Settings::new(FEDERATION, "bridge", IssuerKind::Federation);
    settings.profile.max_onward_lifetime = Some(3600);
    settings.federation = Some(section);
    settings.assurance = Some(AssuranceSection {
        levels: BTreeMap::from([(String::from("urn:acr:high"), AssuranceLevel::High)]),
        ..AssuranceSection::default()
    });
    settings
}

/// The case's token endpoint, keys and client.
pub(crate) struct Case {
    /// The token endpoint.
    server: MockServer,
    /// The key both authorization servers sign with.
    key: SigningKey,
    /// The client.
    onward: Onward,
}

impl Case {
    /// Starts the case over `section`.
    pub(crate) async fn start(section: FederationSection) -> Self {
        let server = MockServer::start().await;
        let client = ClientKey::new();
        let onward = Onward::with_clock(
            settings(section),
            client.credentials(endpoint(&server, ROUTE), "bridge"),
            TestClock::now(),
        )
        .expect("the client builds");
        Self {
            server,
            key: ec_key("fed", Algorithm::Es256),
            onward,
        }
    }

    /// Returns the outcome of exchanging the claims `subject` of a caller
    /// of `kind`, answered with `issued`, for `target`.
    pub(crate) async fn exchange(
        &self,
        subject: &Value,
        kind: CallerKind,
        issued: &Value,
        target: &Target,
    ) -> Result<(), OnwardError> {
        answer(
            &self.server,
            ROUTE,
            ResponseTemplate::new(200).set_body_json(json!({
                "access_token": sign(&self.key, issued),
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "token_type": "Bearer",
                "expires_in": 300
            })),
        )
        .await;
        let subject = subject_of(&sign(&self.key, subject), subject, kind);
        self.onward.token(&subject, None, target).await.map(drop)
    }

    /// Returns how many requests reached the token endpoint.
    pub(crate) async fn calls(&self) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .len()
    }
}

/// Returns the claims of a professional's token of the home issuer.
pub(crate) fn professional() -> Value {
    json!({
        "iss": HOME, "sub": "local-person-1", "aud": "bridge", "client_id": "portal",
        "iat": now(), "exp": now() + 600, "jti": "subject-1",
        "hp_identifier": "900012345", "txn": "correlation-1"
    })
}

/// Returns the claims of the IHE IUA token the federation issuer issues
/// for the professional, shaped as IHE IUA §3.71.4.2.2.1.3.
pub(crate) fn issued() -> Value {
    json!({
        "iss": FEDERATION, "sub": "b3ca1045-aa8b-42f9-9fd9-e0cbf5cb90a7",
        "client_id": "bridge", "aud": PARTNER, "jti": "issued-1",
        "iat": now(), "exp": now() + 300, "acr": "urn:acr:high", "txn": "correlation-1",
        "extensions": {
            "ihe_iua": {
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
            }
        }
    })
}

/// Returns the partner target.
pub(crate) fn partner() -> Target {
    Target::new([PARTNER]).with_indicator(PARTNER)
}

#[tokio::test]
async fn a_mapped_professional_is_accepted() {
    let case = Case::start(section()).await;
    let outcome = case
        .exchange(&professional(), CallerKind::Person, &issued(), &partner())
        .await;
    assert!(outcome.is_ok(), "{outcome:?}");
}

#[tokio::test]
async fn a_subject_issuer_outside_exchanges_from_is_refused_before_sending() {
    let mut subject = professional();
    subject["iss"] = json!("https://elsewhere.example.org");
    let case = Case::start(section()).await;
    let outcome = case
        .exchange(&subject, CallerKind::Person, &issued(), &partner())
        .await;
    assert!(
        matches!(outcome, Err(OnwardError::Rejected(Rejected::NotMapped))),
        "{outcome:?}"
    );
    assert_eq!(0, case.calls().await);
}

#[tokio::test]
async fn a_token_issued_by_another_authorization_server_is_refused() {
    let mut token = issued();
    token["iss"] = json!("https://sts.other.example.org");
    let case = Case::start(section()).await;
    let outcome = case
        .exchange(&professional(), CallerKind::Person, &token, &partner())
        .await;
    assert!(
        matches!(outcome, Err(OnwardError::Rejected(Rejected::Issuer))),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn another_hp_identifier_than_the_mapped_claim_is_refused() {
    let mut token = issued();
    token["extensions"]["ihe_iua"]["national_provider_identifier"] = json!("900099999");
    let case = Case::start(section()).await;
    let outcome = case
        .exchange(&professional(), CallerKind::Person, &token, &partner())
        .await;
    assert!(
        matches!(outcome, Err(OnwardError::Rejected(Rejected::PersonMapping))),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_subject_without_the_mapped_claim_is_refused() {
    let mut subject = professional();
    subject
        .as_object_mut()
        .map(|claims| claims.remove("hp_identifier"));
    let case = Case::start(section()).await;
    let outcome = case
        .exchange(&subject, CallerKind::Person, &issued(), &partner())
        .await;
    assert!(
        matches!(outcome, Err(OnwardError::Rejected(Rejected::PersonMapping))),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_token_missing_a_required_field_is_refused_naming_it() {
    // NOTE: Commission Implementing Regulation (EU) 2026/2099 Annex Table 1:
    // `hp_professional_role` is a required field of the professional.
    let mut token = issued();
    token["extensions"]["ihe_iua"]
        .as_object_mut()
        .map(|claims| claims.remove("subject_role"));
    let case = Case::start(section()).await;
    let outcome = case
        .exchange(&professional(), CallerKind::Person, &token, &partner())
        .await;
    assert!(
        matches!(
            &outcome,
            Err(OnwardError::Rejected(Rejected::Federation(Unclassified::ExternalIncomplete { missing })))
                if missing.contains(&"professional.hp_professional_role")
        ),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_token_carrying_only_the_tables_constants_is_an_incomplete_professional() {
    // NOTE: Commission Implementing Regulation (EU) 2026/2099 Annex Table 1:
    // the configured country and issuing authority name a professional, whose
    // other required fields this token lacks.
    let mut token = issued();
    token["sub"] = json!("bridge");
    token
        .as_object_mut()
        .map(|claims| claims.remove("extensions"));
    let case = Case::start(section()).await;
    let outcome = case
        .exchange(&professional(), CallerKind::Person, &token, &partner())
        .await;
    assert!(
        matches!(
            &outcome,
            Err(OnwardError::Rejected(Rejected::Federation(Unclassified::ExternalIncomplete { missing })))
                if missing.contains(&"professional.hp_identifier")
        ),
        "{outcome:?}"
    );
}

/// Returns a table whose issuer states an organisation's access in an
/// attested `authorization_details` entry and names no professional field.
pub(crate) fn organisations() -> FederationSection {
    FederationSection {
        issuer: ferrohealth_secret::secret_url::SecretUrl::new(FEDERATION),
        contact_point: Some(false),
        fields: BTreeMap::from([(
            Field::ProviderHealthcareProviderIdentifier,
            vec![Source::Claim(String::from("organisation_id"))],
        )]),
        countries: vec![String::from("NL")],
        issuing_authorities: vec![String::from("CIBG")],
        provider_identifier_prefixes: vec![String::from(PREFIX)],
        attests_authorization_details: true,
        authorization_details_type: Some(String::from("organisation_access")),
        organisation_types: vec![String::from("organisation_access")],
        exchanges_from: vec![String::from(HOME)],
        person_mapping: Some(String::from("hp_identifier")),
        ..FederationSection::default()
    }
}

/// Returns the claims of an organisation's token, its access stated in an
/// `authorization_details` entry naming the partner (RFC 9396 §2).
pub(crate) fn organisation_token() -> Value {
    json!({
        "iss": FEDERATION, "sub": "bridge", "client_id": "bridge", "aud": PARTNER,
        "jti": "issued-1", "iat": now(), "exp": now() + 300,
        "organisation_id": format!("{PREFIX}12345678"),
        "authorization_details": [{ "type": "organisation_access", "locations": [PARTNER] }]
    })
}

#[tokio::test]
async fn an_organisation_exchange_of_a_system_is_accepted_on_its_access_statement() {
    let mut subject = professional();
    subject["sub"] = json!("portal");
    let case = Case::start(organisations()).await;
    let outcome = case
        .exchange(
            &subject,
            CallerKind::System,
            &organisation_token(),
            &partner(),
        )
        .await;
    assert!(outcome.is_ok(), "{outcome:?}");
}

#[tokio::test]
async fn a_persons_exchange_answered_with_an_organisation_token_is_refused() {
    let case = Case::start(organisations()).await;
    let outcome = case
        .exchange(
            &professional(),
            CallerKind::Person,
            &organisation_token(),
            &partner(),
        )
        .await;
    assert!(
        matches!(outcome, Err(OnwardError::Rejected(Rejected::PersonMapping))),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn an_organisation_token_without_its_access_statement_is_refused() {
    let mut token = organisation_token();
    token
        .as_object_mut()
        .map(|claims| claims.remove("authorization_details"));
    let mut subject = professional();
    subject["sub"] = json!("portal");
    let case = Case::start(organisations()).await;
    let outcome = case
        .exchange(&subject, CallerKind::System, &token, &partner())
        .await;
    assert!(
        matches!(
            outcome,
            Err(OnwardError::Rejected(Rejected::Federation(
                Unclassified::NoOrganisationStatement
            )))
        ),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_chained_route_carries_the_subject_tokens_correlation_claim() {
    let chained = partner().with_correlation_claim("txn");
    let case = Case::start(section()).await;
    let outcome = case
        .exchange(&professional(), CallerKind::Person, &issued(), &chained)
        .await;
    assert!(outcome.is_ok(), "{outcome:?}");
    let mut token = issued();
    token["txn"] = json!("correlation-2");
    let case = Case::start(section()).await;
    let outcome = case
        .exchange(&professional(), CallerKind::Person, &token, &chained)
        .await;
    assert!(
        matches!(outcome, Err(OnwardError::Rejected(Rejected::Correlation))),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_federation_issuer_without_exchanges_from_or_person_mapping_refuses_to_build() {
    let client = ClientKey::new();
    let server = MockServer::start().await;
    for (key, section) in [
        (
            "exchanges_from",
            FederationSection {
                exchanges_from: Vec::new(),
                ..section()
            },
        ),
        (
            "person_mapping",
            FederationSection {
                person_mapping: None,
                ..section()
            },
        ),
    ] {
        let built = Onward::new(
            settings(section),
            client.credentials(endpoint(&server, ROUTE), "bridge"),
        );
        assert!(
            matches!(&built, Err(OnwardError::Federation { key: missing }) if *missing == key),
            "{key}: {built:?}"
        );
    }
}
