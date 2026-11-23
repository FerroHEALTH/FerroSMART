// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `nl` profile through the configuration: the harmonised `BgZ` and
//! `eOverdracht` authentication of the openEHR Federation Tier specification
//! 1.0.1 Annex B §B.4a, whose two `authorization_details` examples of
//! §B.4a.3 are the cases' tokens, re-signed with a test key and bound to a
//! client certificate.

use std::error::Error as StdError;

use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::federation::Attribute;
use ferrohealth_smart::federation::Code;
use ferrohealth_smart::federation::FederationError;
use ferrohealth_smart::federation::Field;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::kind::Unclassified;
use ferrohealth_smart::profile::ProfileError;
use ferrohealth_smart::refusal::Reason;
use ferrohealth_smart::resource::Caller;
use ferrohealth_smart::resource::Rejection;
use ferrohealth_smart::resource::ResourceError;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::sender::Binding;
use ferrohealth_smart::sender::ClientCertificate;
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

/// The requesting care provider, which signs its own access tokens.
const ISSUER: &str = "https://zorgaanbieder-a.example.org";
/// This node: the `locations` of the §B.4a.3 examples.
const AUDIENCE: &str = "https://fhir.zorgaanbieder-b.nl/fhir";
/// The requesting care provider's URA, configured on its issuer table.
const URA: &str = "87654321";
/// The code system of the URA register, the OID of the §B.4a.3 example.
const URA_SYSTEM: &str = "urn:oid:2.16.528.1.1007.3.3";
/// The client the requesting care provider's system authenticates as.
const CLIENT: &str = "zorgaanbieder-a-system";
/// The synthetic DER bytes of the client certificate the token is bound to.
const CERTIFICATE: &[u8] = b"synthetic client certificate DER";
/// The §B.4a.3 purpose of use.
const PURPOSE: &str = "http://terminology.hl7.org/CodeSystem/v3-ActReason|TREAT";
/// The §B.4a.3 organisation type of the query use case.
const ORGANISATION_TYPE: &str = "https://www.cbs.nl/standaard-bedrijfsindeling|8610";

/// The first §B.4a.3 example entry, directed sending.
fn directed() -> Value {
    json!({
        "type": "nl-gis-v1",
        "purpose_of_use": PURPOSE,
        "locations": [AUDIENCE],
        "locations_organization_id": "urn:oid:2.16.528.1.1007.3.3.12345678"
    })
}

/// The second §B.4a.3 example entry, the query use case of §B.4a.4.
fn query() -> Value {
    json!({
        "type": "nl-gis-v1",
        "subject_organisation_type": ORGANISATION_TYPE,
        "purpose_of_use": PURPOSE,
        "locations": [AUDIENCE],
        "locations_organization_id": "urn:oid:2.16.528.1.1007.3.3.12345678"
    })
}

/// The claims of a client credentials token carrying `entry`, bound to the
/// client certificate.
fn token(entry: &Value) -> Value {
    json!({
        "iss": ISSUER, "sub": CLIENT, "client_id": CLIENT, "aud": AUDIENCE,
        "jti": "jti-1", "iat": now(), "exp": now() + 300,
        "cnf": { "x5t#S256": ClientCertificate::from_der(CERTIFICATE).thumbprint() },
        "authorization_details": [entry]
    })
}

/// The book's example issuer table, which the cases load.
fn example() -> Result<toml::Table, Box<dyn StdError>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../website/book/src/integrate/profiles/nl-annex-b.toml");
    let mut file: toml::Table = std::fs::read_to_string(path)?.parse()?;
    let nl = file
        .remove("auth")
        .and_then(|auth| auth.get("issuer")?.get("nl").cloned())
        .ok_or("the example names [auth.issuer.nl]")?;
    match nl {
        toml::Value::Table(table) => Ok(table),
        _ => Err("[auth.issuer.nl] is a table".into()),
    }
}

/// Sets every key of `over` over `base`, table by table.
fn merge(base: &mut toml::Table, over: toml::Table) {
    for (key, value) in over {
        match (base.get_mut(&key), value) {
            (Some(toml::Value::Table(lower)), toml::Value::Table(upper)) => merge(lower, upper),
            (_, value) => {
                base.insert(key, value);
            }
        }
    }
}

/// The issuer of the cases, configured with the book's example profile file.
struct Harness {
    /// The signing key, in the key set file.
    key: SigningKey,
    /// The key set file.
    jwks: String,
}

impl Harness {
    fn new() -> Self {
        let key = ec_key("nl", Algorithm::ES256);
        let set = json!({ "keys": [key.jwk.clone()] }).to_string();
        let jwks = temp_file("nl-jwks.json", set.as_bytes())
            .display()
            .to_string();
        Self { key, jwks }
    }

    /// Returns the configuration of the book's example issuer table as
    /// `i1`, with the deployment's issuer, audience and key set, and the
    /// keys of `over` set over it, a TOML text relative to the issuer table.
    fn config(&self, over: &str) -> String {
        let mut table = example().expect("the book's example reads");
        let deployment = format!(
            "issuer = \"{ISSUER}\"\naudience = [\"{AUDIENCE}\"]\njwks_file = \"{jwks}\"\n{over}",
            jwks = self.jwks,
        );
        merge(&mut table, deployment.parse().expect("the keys parse"));
        let mut issuer = toml::Table::new();
        issuer.insert(String::from("i1"), toml::Value::Table(table));
        let mut section = toml::Table::new();
        section.insert(String::from("issuer"), toml::Value::Table(issuer));
        toml::to_string(&section).expect("the section renders")
    }

    /// The configuration a deployment of the profile writes.
    fn deployed(&self) -> String {
        self.config(&Self::deployment(""))
    }

    /// The keys a deployment sets, after `extra`, a text whose own table
    /// headers end before them.
    fn deployment(extra: &str) -> String {
        format!(
            "{extra}\n[profile]\ntoken_types = [\"at+jwt\"]\n\
             [federation.fields]\n\"provider.healthcare_provider_identifier\" = [{{ constant = \"{URA}\", system = \"{URA_SYSTEM}\" }}]\n"
        )
    }

    /// Returns what loading `config` refuses, as the issuer's rule broken.
    fn refusal(config: &str) -> Option<ResourceError> {
        let section: AuthSection = toml::from_str(config).ok()?;
        match section.resolve(&[]) {
            Err(ConfigError::Issuer { source, .. }) => Some(*source),
            _ => None,
        }
    }

    /// Returns the caller `claims` authenticate as under `config`, over the
    /// bound connection.
    async fn admit(&self, config: &str, claims: &Value) -> Result<Caller, Box<dyn StdError>> {
        let section: AuthSection = toml::from_str(config)?;
        let settings = section
            .resolve(&[])?
            .issuers
            .into_iter()
            .next()
            .ok_or("one issuer")?;
        let server = ResourceServer::discover(settings).await?;
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(String::from("nl"));
        header.typ = Some(String::from("at+jwt"));
        let binding = Binding::bearer().with_certificate(&ClientCertificate::from_der(CERTIFICATE));
        Ok(server
            .authenticate_bound(&mint_with(&self.key, &header, claims), &binding)
            .await?)
    }
}

/// Returns the classification refusal of `outcome`.
fn refused(outcome: Result<Caller, Box<dyn StdError>>) -> Option<Unclassified> {
    match outcome
        .err()?
        .downcast::<Rejection>()
        .ok()
        .map(|boxed| *boxed)
    {
        Some(Rejection::Unclassified { reason }) => Some(reason),
        _ => None,
    }
}

// NOTE: Annex B §B.4a.2: client credentials, "no interactive user", and the
// §B.4a.3 entry carries the purpose and, for a query (§B.4a.4), the organisation type.
#[tokio::test]
async fn the_query_example_is_an_external_organisation() -> Outcome {
    let h = Harness::new();
    let caller = h.admit(&h.deployed(), &token(&query())).await?;
    let CallerKind::ExternalOrganisation(organisation) = caller.kind() else {
        return Err(format!("an external organisation: {caller:?}").into());
    };
    let text = |field| organisation.field(field).and_then(Attribute::text);
    assert_eq!(Some(PURPOSE), text(Field::PurposeOfUse));
    assert_eq!(Some(ORGANISATION_TYPE), text(Field::ProviderFacilityType));
    assert_eq!(
        Some(&Attribute::Codes(vec![Code {
            system: Some(String::from(URA_SYSTEM)),
            code: String::from(URA),
        }])),
        organisation.field(Field::ProviderHealthcareProviderIdentifier),
        "the issuer's configured URA, with its code system"
    );
    assert_eq!(CLIENT, organisation.remote_subject());
    assert!(
        organisation
            .fields()
            .values()
            .all(|value| value.text() != Some("urn:oid:2.16.528.1.1007.3.3.12345678")),
        "locations_organization_id names this node, never the requester"
    );
    assert!(
        caller.roles().is_empty(),
        "a federation token contributes no role"
    );
    Ok(())
}

// NOTE: Annex B §B.4a.4: for the query use case the "Organization type must
// travel", and the directed-sending example of §B.4a.3 carries none.
#[tokio::test]
async fn the_directed_sending_example_lacks_the_organisation_type_a_query_needs() -> Outcome {
    let h = Harness::new();
    let outcome = h.admit(&h.deployed(), &token(&directed())).await;
    assert_eq!(
        Some(Unclassified::RequiredFields {
            missing: vec!["provider.facility_type"]
        }),
        refused(outcome)
    );
    Ok(())
}

#[tokio::test]
async fn a_deployment_that_only_receives_directed_sending_relaxes_the_required_fields() -> Outcome {
    let h = Harness::new();
    let config = h.config(&Harness::deployment(
        "[federation]\nrequired_fields = [\"purpose_of_use\", \"provider.healthcare_provider_identifier\"]",
    ));
    let caller = h.admit(&config, &token(&directed())).await?;
    assert!(
        matches!(caller.kind(), CallerKind::ExternalOrganisation(_)),
        "{caller:?}"
    );
    Ok(())
}

// NOTE: RFC 9396 §12: `locations` is the audience restriction, and the §B.4a.3
// entries are of the type `nl-gis-v1`.
#[tokio::test]
async fn an_entry_for_another_node_or_of_another_type_is_refused() -> Outcome {
    let h = Harness::new();
    let mut elsewhere = query();
    elsewhere["locations"] = json!(["https://fhir.zorgaanbieder-c.example.org/fhir"]);
    let mut other_type = query();
    other_type["type"] = json!("nl-gis-v2");
    for entry in [elsewhere, other_type] {
        let outcome = h.admit(&h.deployed(), &token(&entry)).await;
        assert_eq!(Some(Unclassified::AuthorizationDetails), refused(outcome));
    }
    Ok(())
}

// NOTE: Annex B §B.4a.2: "there is no interactive user in the exchange", so a
// token whose `sub` names someone other than the client names a professional.
#[tokio::test]
async fn a_token_naming_a_user_is_refused_as_an_incomplete_professional() -> Outcome {
    let h = Harness::new();
    let mut claims = token(&query());
    claims["sub"] = json!("a-clinician");
    let outcome = h.admit(&h.deployed(), &claims).await;
    assert!(
        matches!(
            refused(outcome),
            Some(Unclassified::ExternalIncomplete { .. })
        ),
        "a user is never an organisation"
    );
    Ok(())
}

// NOTE: Annex B §B.4a.2: FAPI 2.0 brings "sender-constrained access tokens", so
// an unbound token is refused and an issuer without the constraint fails to load.
#[tokio::test]
async fn the_profile_requires_sender_constrained_tokens() -> Outcome {
    let h = Harness::new();
    let mut claims = token(&query());
    if let Some(object) = claims.as_object_mut() {
        object.remove("cnf");
    }
    let unbound = h.admit(&h.deployed(), &claims).await;
    assert!(
        matches!(
            unbound
                .err()
                .and_then(|error| error.downcast::<Rejection>().ok())
                .as_deref(),
            Some(Rejection::Invalid {
                reason: Reason::Sender(_)
            })
        ),
        "an unbound token is refused by the sender constraint"
    );
    let unconstrained = h.config(&Harness::deployment("sender_constraint = \"none\""));
    assert!(matches!(
        Harness::refusal(&unconstrained),
        Some(ResourceError::SenderConstraintRequired)
    ));
    Ok(())
}

// NOTE: Annex B §B.4a.2 names no `typ`, and §B.4a.1 makes the URA "the
// system-wide unique organization identifier", which only the deployment knows.
#[test]
fn the_profile_fails_to_load_without_the_type_or_the_ura() {
    let h = Harness::new();
    let untyped = h.config(&format!(
        "[federation.fields]\n\"provider.healthcare_provider_identifier\" = [{{ constant = \"{URA}\", system = \"{URA_SYSTEM}\" }}]"
    ));
    assert!(matches!(
        Harness::refusal(&untyped),
        Some(ResourceError::Profile(ProfileError::Empty {
            key: "token_types"
        }))
    ));
    let no_ura = h.config("[profile]\ntoken_types = [\"at+jwt\"]");
    assert!(matches!(
        Harness::refusal(&no_ura),
        Some(ResourceError::Federation(FederationError::NoSource {
            field: "provider.healthcare_provider_identifier"
        }))
    ));
}

#[test]
fn the_federation_table_is_refused_on_a_smart_issuer() {
    let h = Harness::new();
    let smart = h.deployed().replace("kind = \"federation\"\n", "");
    let section: AuthSection = toml::from_str(&smart).expect("the section parses");
    assert!(matches!(
        section.resolve(&[]),
        Err(ConfigError::Federation { .. })
    ));
}

#[test]
fn the_books_example_carries_the_annex_values() -> Outcome {
    let section: AuthSection = toml::from_str(&Harness::new().deployed())?;
    let entry = section.issuer.get("i1").ok_or("the issuer table")?;
    assert_eq!(Some(IssuerKind::Federation), entry.kind);
    let federation = entry.federation.as_ref().ok_or("a federation table")?;
    assert_eq!(
        Some(String::from("nl-gis-v1")),
        federation.authorization_details_type
    );
    assert_eq!(vec![String::from("NL")], federation.countries);
    assert_eq!(
        vec![String::from("urn:oid:2.16.528.1.1007.3.3.")],
        federation.provider_identifier_prefixes
    );
    assert!(federation.attests_authorization_details);
    assert!(federation.requires_sender_constraint);
    assert_eq!(Some(false), federation.contact_point);
    Ok(())
}
