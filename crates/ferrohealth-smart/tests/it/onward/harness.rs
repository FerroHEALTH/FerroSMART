// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The harness token endpoint and the three profiles every criterion runs
//! under: a standards-only authorization server, the `entra` preset and the
//! `keycloak` preset, each with a person's subject token and the token its
//! exchange issues.

use std::sync::Arc;

use base64::Engine as _;
use ferrohealth_smart::client::onward::ActorToken;
use ferrohealth_smart::client::onward::OnwardError;
use ferrohealth_smart::client::onward::SubjectToken;
use ferrohealth_smart::client::onward::Target;
use ferrohealth_smart::client::onward::exchange::Onward;
use ferrohealth_smart::client::onward::exchange::OnwardToken;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::profile::Marker;
use ferrohealth_smart::profile::Preset;
use ferrohealth_smart::profile::Profile;
use ferrohealth_smart::profile::ProfileKeys;
use ferrohealth_smart::profile::onward::OnwardGrant;
use ferrohealth_smart::resource::Settings;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Validation;
use jsonwebtoken::jwk::Jwk;
use secrecy::SecretString;
use serde_json::Value;
use serde_json::json;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::Request;
use wiremock::Respond;
use wiremock::ResponseTemplate;
use wiremock::matchers::method;
use wiremock::matchers::path;

use super::ClientKey;
use super::TestClock;
use super::endpoint;
use super::form;
use super::param;
use super::sign;
use super::subject_of;
use crate::support::SigningKey;
use crate::support::ec_key;

/// The token endpoint route of every harness.
pub(crate) const ROUTE: &str = "/token";

/// The Entra ID tenant of the cases, in the placeholder form Microsoft's
/// documents use.
pub(crate) const TENANT: &str = "aaaabbbb-0000-cccc-1111-dddd2222eeee";

/// The middle tier's application id under the `entra` preset, the client
/// id of the "Second case" example.
pub(crate) const ENTRA_CLIENT: &str = "11112222-bbbb-3333-cccc-4444dddd5555";

/// The downstream API's application id under the `entra` preset.
pub(crate) const ENTRA_TARGET: &str = "22223333-cccc-4444-dddd-5555eeee6666";

/// The profile a harness runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flavor {
    /// A standards-only authorization server with token exchange.
    Generic,
    /// A standards-only authorization server with the JWT bearer grant.
    GenericJwtBearer,
    /// The `entra` preset: the on-behalf-of flow.
    Entra,
    /// The `keycloak` preset: the standard token exchange.
    Keycloak,
}

/// The three profiles every criterion runs under, standards-only first.
pub(crate) const FLAVORS: [Flavor; 3] = [Flavor::Generic, Flavor::Entra, Flavor::Keycloak];

impl Flavor {
    /// Returns the issuer identifier.
    pub(crate) fn issuer(self) -> String {
        match self {
            Self::Generic | Self::GenericJwtBearer => String::from("https://as.example.org"),
            Self::Entra => format!("https://login.microsoftonline.com/{TENANT}/v2.0"),
            Self::Keycloak => String::from("https://kc.example.org/realms/test"),
        }
    }

    /// Returns the requesting client.
    pub(crate) const fn client_id(self) -> &'static str {
        match self {
            Self::Generic | Self::GenericJwtBearer => "bridge",
            Self::Entra => ENTRA_CLIENT,
            Self::Keycloak => "requester-client",
        }
    }

    /// Returns the grant the flavor's profile names.
    pub(crate) const fn grant(self) -> OnwardGrant {
        match self {
            Self::Generic | Self::Keycloak => OnwardGrant::TokenExchange,
            Self::GenericJwtBearer | Self::Entra => OnwardGrant::JwtBearer,
        }
    }

    /// Returns the settings of the flavor's issuer, with a lifetime of
    /// `lifetime` seconds.
    pub(crate) fn settings(self, lifetime: u64) -> Settings {
        let keys = ProfileKeys {
            max_onward_lifetime: Some(ferrohealth_config::units::Duration::from_secs(lifetime)),
            ..ProfileKeys::default()
        };
        let mut settings = Settings::new(self.issuer(), self.client_id(), IssuerKind::Persons);
        settings.profile = match self {
            Self::Generic => Profile::resolve(Preset::Rfc9068, &keys),
            Self::GenericJwtBearer => Profile::resolve(
                Preset::Rfc9068,
                &ProfileKeys {
                    onward_grant: Some(OnwardGrant::JwtBearer),
                    ..keys
                },
            ),
            Self::Entra => Profile::resolve(Preset::Entra, &keys),
            Self::Keycloak => Profile::resolve(
                Preset::Keycloak,
                &ProfileKeys {
                    app_only: Some(vec![Marker::Subjects(vec![String::from(
                        "service-account-synthetic",
                    )])]),
                    ..keys
                },
            ),
        }
        .expect("the preset reads");
        settings
    }

    /// Returns the client a person signs in through.
    const fn front_client(self) -> &'static str {
        match self {
            Self::Generic | Self::GenericJwtBearer => "portal",
            Self::Entra => "33334444-dddd-5555-eeee-6666ffff7777",
            Self::Keycloak => "initial-client",
        }
    }

    /// Returns the claims of a person's token addressed to the requesting
    /// client, issued at `now`.
    pub(crate) fn subject_claims(self, now: i64) -> Value {
        let issuer = self.issuer();
        match self {
            Self::Generic | Self::GenericJwtBearer => json!({
                "iss": issuer, "sub": "person-1", "aud": self.client_id(),
                "client_id": self.front_client(), "iat": now, "exp": now + 600,
                "jti": "subject-1", "scope": "user/*.rs"
            }),
            Self::Entra => json!({
                "iss": issuer, "aud": ENTRA_CLIENT, "sub": "pairwise-for-the-middle-tier",
                "oid": "00000000-0000-0000-66f3-3332eca7ea81", "tid": TENANT,
                "azp": self.front_client(), "ver": "2.0", "scp": "access_as_user",
                "iat": now, "exp": now + 600, "uti": "subject-uti", "acct": 0
            }),
            Self::Keycloak => json!({
                "iss": issuer, "sub": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
                "aud": [self.client_id()], "azp": self.front_client(),
                "iat": now, "exp": now + 600, "jti": "subject-1", "scope": "default-scope1"
            }),
        }
    }

    /// Returns the claims of the token an exchange of `subject` issues at
    /// `now`, living 300 seconds.
    pub(crate) fn issued_claims(self, subject: &Value, now: i64) -> Value {
        let issuer = self.issuer();
        match self {
            Self::Generic | Self::GenericJwtBearer => json!({
                "iss": issuer, "sub": subject["sub"], "aud": "https://ehr.example.org",
                "client_id": self.client_id(), "iat": now, "exp": now + 300,
                "jti": "issued-1", "scope": "user/*.rs"
            }),
            // NOTE: Microsoft, "Access token claims reference": `sub` is pairwise per
            // application while `oid` and `tid` stay; `azp` names the caller.
            Self::Entra => json!({
                "iss": issuer, "aud": ENTRA_TARGET, "sub": "pairwise-for-the-downstream-api",
                "oid": subject["oid"], "tid": subject["tid"], "azp": ENTRA_CLIENT,
                "ver": "2.0", "scp": "Data.Read", "iat": now, "exp": now + 300,
                "uti": "issued-uti"
            }),
            // NOTE: Keycloak 26.8.2 token-exchange.adoc, Example 2: `azp` is the
            // requester and `aud` only the requested audience.
            Self::Keycloak => json!({
                "iss": issuer, "sub": subject["sub"], "azp": "requester-client",
                "scope": "optional-scope2", "aud": ["target-client2"],
                "resource_access": { "target-client2": { "roles": ["target-client2-role"] } },
                "iat": now, "exp": now + 300, "jti": "issued-1"
            }),
        }
    }

    /// Returns the target the flavor's exchanges are for.
    pub(crate) fn target(self) -> Target {
        match self {
            Self::Generic => Target::new(["https://ehr.example.org"])
                .with_indicator("https://ehr.example.org/api"),
            Self::GenericJwtBearer => {
                Target::new(["https://ehr.example.org"]).with_scope("https://ehr.example.org/read")
            }
            Self::Entra => {
                Target::new([ENTRA_TARGET]).with_scope(format!("api://{ENTRA_TARGET}/.default"))
            }
            Self::Keycloak => Target::new(["target-client2"])
                .with_indicator("target-client2")
                .with_scope("optional-scope2"),
        }
    }

    /// Returns the success response carrying `token`.
    pub(crate) fn response(self, token: &str) -> Value {
        match self.grant() {
            OnwardGrant::TokenExchange => json!({
                "access_token": token,
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "token_type": "Bearer",
                "expires_in": 300
            }),
            OnwardGrant::JwtBearer => json!({
                "token_type": "Bearer", "scope": "Data.Read", "expires_in": 300,
                "ext_expires_in": 0, "access_token": token
            }),
            other => panic!("the stub answers no {other:?}"),
        }
    }
}

/// One profile's authorization server and the client of its onward grants.
pub(crate) struct Harness {
    /// The profile.
    pub(crate) flavor: Flavor,
    /// The token endpoint.
    pub(crate) server: MockServer,
    /// The key the authorization server signs with.
    pub(crate) key: SigningKey,
    /// The requesting client's key.
    pub(crate) client: ClientKey,
    /// The clock the client reads.
    pub(crate) clock: Arc<TestClock>,
    /// The client.
    pub(crate) onward: Onward,
}

impl Harness {
    /// Starts the harness of `flavor` with a lifetime of 3600 seconds.
    pub(crate) async fn start(flavor: Flavor) -> Self {
        Self::with_settings(flavor, flavor.settings(3600)).await
    }

    /// Starts the harness of `flavor` over `settings`.
    pub(crate) async fn with_settings(flavor: Flavor, settings: Settings) -> Self {
        let server = MockServer::start().await;
        let client = ClientKey::new();
        let mut credentials = client.credentials(endpoint(&server, ROUTE), flavor.client_id());
        if flavor == Flavor::Keycloak {
            credentials = ferrohealth_smart::client::ClientCredentials::new(
                endpoint(&server, ROUTE),
                flavor.client_id().to_owned(),
                SecretString::from("password"),
            );
        }
        let clock = TestClock::now();
        let onward = Onward::with_clock(settings, credentials, clock.clone())
            .expect("the onward client builds");
        Self {
            flavor,
            server,
            key: ec_key("as-2026", Algorithm::ES256),
            client,
            clock,
            onward,
        }
    }

    /// Returns the current time of the case.
    pub(crate) fn now(&self) -> i64 {
        ferrohealth_smart::client::onward::exchange::WallClock::now(&*self.clock)
    }

    /// Returns a person's subject token and its claims.
    pub(crate) fn person(&self) -> (SubjectToken, Value) {
        let claims = self.flavor.subject_claims(self.now());
        (self.subject(&claims, CallerKind::Person), claims)
    }

    /// Returns the subject token of a caller of `kind` with `claims`.
    pub(crate) fn subject(&self, claims: &Value, kind: CallerKind) -> SubjectToken {
        subject_of(&sign(&self.key, claims), claims, kind)
    }

    /// Mounts the harness token endpoint, answering a request that passes
    /// its checks with `issued` signed, expecting `actor` as the actor, and
    /// returns the token it issues.
    pub(crate) async fn issue(&self, issued: &Value, actor: Option<&str>) -> String {
        let token = sign(&self.key, issued);
        Mock::given(method("POST"))
            .and(path(ROUTE))
            .respond_with(Endpoint {
                flavor: self.flavor,
                client_jwk: self.client.key.jwk.clone(),
                audience: format!("{}{ROUTE}", self.server.uri()),
                actor: actor.map(str::to_owned),
                response: self.flavor.response(&token),
            })
            .mount(&self.server)
            .await;
        token
    }

    /// Mounts `response` as the token endpoint's answer.
    pub(crate) async fn answer(&self, response: ResponseTemplate) {
        super::answer(&self.server, ROUTE, response).await;
    }

    /// Returns how many requests reached the token endpoint.
    pub(crate) async fn calls(&self) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .len()
    }

    /// Returns a token for the flavor's target on behalf of `subject`.
    pub(crate) async fn token(
        &self,
        subject: &SubjectToken,
        actor: Option<&ActorToken>,
    ) -> Result<OnwardToken, OnwardError> {
        self.onward
            .token(subject, actor, &self.flavor.target())
            .await
    }
}

/// The harness token endpoint: it answers `response` to a request that
/// carries the grant's parameters and authenticates the client, and
/// `400 invalid_request` naming the failed check to any other.
struct Endpoint {
    /// The profile.
    flavor: Flavor,
    /// The client's public key.
    client_jwk: Value,
    /// The token endpoint URL, the client assertion's `aud`.
    audience: String,
    /// The `sub` the actor token must carry.
    actor: Option<String>,
    /// The success response.
    response: Value,
}

impl Respond for Endpoint {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        match self.verify(request) {
            Ok(()) => ResponseTemplate::new(200).set_body_json(&self.response),
            Err(failed) => ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_request", "error_description": failed
            })),
        }
    }
}

impl Endpoint {
    /// Returns which check `request` fails, if any.
    fn verify(&self, request: &Request) -> Result<(), String> {
        let form = form(request);
        let grant = self.flavor.grant();
        if param(&form, "grant_type") != Some(grant.grant_type()) {
            return Err(String::from("grant_type"));
        }
        match grant {
            OnwardGrant::TokenExchange => {
                for name in ["subject_token", "subject_token_type"] {
                    param(&form, name).ok_or(name)?;
                }
                if param(&form, "assertion").is_some() {
                    return Err(String::from("assertion under token exchange"));
                }
                let actor = param(&form, "actor_token");
                if actor.is_some() != param(&form, "actor_token_type").is_some() {
                    return Err(String::from("actor_token_type without actor_token"));
                }
                let sent = actor.and_then(sub_of);
                if sent != self.actor {
                    return Err(String::from("actor_token"));
                }
            }
            OnwardGrant::JwtBearer => {
                param(&form, "assertion").ok_or("assertion")?;
                param(&form, "scope").ok_or("scope")?;
                for name in ["subject_token", "actor_token", "resource", "audience"] {
                    if param(&form, name).is_some() {
                        return Err(format!("{name} under the JWT bearer grant"));
                    }
                }
            }
            other => return Err(format!("the stub checks no {other:?}")),
        }
        if self.flavor == Flavor::Keycloak {
            let expected = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode("requester-client:password")
            );
            let sent = request
                .headers
                .get(http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok());
            return (sent == Some(expected.as_str()))
                .then_some(())
                .ok_or_else(|| String::from("client_secret_basic"));
        }
        self.verify_assertion(&form)
    }

    /// Returns whether the request authenticates with a `private_key_jwt`
    /// assertion the client key signed (RFC 7523 §2.2 and §3).
    fn verify_assertion(&self, form: &[(String, String)]) -> Result<(), String> {
        if param(form, "client_assertion_type")
            != Some(ferrohealth_smart::client::assertion::ASSERTION_TYPE)
        {
            return Err(String::from("client_assertion_type"));
        }
        let assertion = param(form, "client_assertion").ok_or("client_assertion")?;
        let jwk: Jwk = serde_json::from_value(self.client_jwk.clone())
            .map_err(|_jwk| String::from("the client JWK"))?;
        let key = DecodingKey::from_jwk(&jwk).map_err(|_key| String::from("the client key"))?;
        let mut validation = Validation::new(Algorithm::ES384);
        validation.set_audience(&[&self.audience]);
        validation.set_issuer(&[self.flavor.client_id()]);
        jsonwebtoken::decode::<Value>(assertion, &key, &validation)
            .map(|_verified| ())
            .map_err(|_unverified| String::from("client_assertion"))
    }
}

/// Returns the `sub` of a JWS `token`'s payload.
fn sub_of(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("sub")?.as_str().map(str::to_owned)
}
