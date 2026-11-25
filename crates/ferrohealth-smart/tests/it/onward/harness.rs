// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The harness token endpoint and the profiles every criterion runs under:
//! an RFC 9068 authorization server with token exchange, and one with the
//! JWT bearer grant, each with a person's subject token and the token its
//! exchange issues.

use std::sync::Arc;

use base64::Engine as _;
use ferrohealth_smart::client::onward::ActorToken;
use ferrohealth_smart::client::onward::OnwardError;
use ferrohealth_smart::client::onward::SubjectToken;
use ferrohealth_smart::client::onward::Target;
use ferrohealth_smart::client::onward::exchange::Onward;
use ferrohealth_smart::client::onward::exchange::OnwardToken;
use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrohealth_smart::jws::claims::Validation;
use ferrohealth_smart::jws::jwk::Jwk;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::profile::Profile;
use ferrohealth_smart::profile::ProfileKeys;
use ferrohealth_smart::profile::onward::OnwardGrant;
use ferrohealth_smart::resource::Settings;
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

/// The profile a harness runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flavor {
    /// A standards-only authorization server with token exchange.
    Generic,
    /// A standards-only authorization server with the JWT bearer grant.
    GenericJwtBearer,
}

/// The profile every criterion runs under.
pub(crate) const FLAVORS: [Flavor; 1] = [Flavor::Generic];

impl Flavor {
    /// Returns the issuer identifier.
    pub(crate) fn issuer(self) -> String {
        match self {
            Self::Generic | Self::GenericJwtBearer => String::from("https://as.example.org"),
        }
    }

    /// Returns the requesting client.
    pub(crate) const fn client_id(self) -> &'static str {
        match self {
            Self::Generic | Self::GenericJwtBearer => "bridge",
        }
    }

    /// Returns the grant the flavor's profile names.
    pub(crate) const fn grant(self) -> OnwardGrant {
        match self {
            Self::Generic => OnwardGrant::TokenExchange,
            Self::GenericJwtBearer => OnwardGrant::JwtBearer,
        }
    }

    /// Returns the settings of the flavor's issuer, with a lifetime of
    /// `lifetime` seconds.
    pub(crate) fn settings(self, lifetime: u64) -> Settings {
        let keys = ProfileKeys {
            max_onward_lifetime: Some(ferrohealth_config::units::Duration::from_secs(lifetime)),
            ..ProfileKeys::default()
        };
        let mut settings = Settings::new(self.issuer(), self.client_id(), IssuerKind::Smart);
        settings.profile = Profile::default().with_keys(ProfileKeys {
            onward_grant: Some(self.grant()),
            ..keys
        });
        settings
    }

    /// Returns the client a person signs in through.
    const fn front_client(self) -> &'static str {
        match self {
            Self::Generic | Self::GenericJwtBearer => "portal",
        }
    }

    /// Returns the claims of a person's token addressed to the requesting
    /// client, issued at `now`.
    pub(crate) fn subject_claims(self, now: i64) -> Value {
        json!({
            "iss": self.issuer(), "sub": "person-1", "aud": self.client_id(),
            "client_id": self.front_client(), "iat": now, "exp": now + 600,
            "jti": "subject-1", "scope": "user/*.rs"
        })
    }

    /// Returns the claims of the token an exchange of `subject` issues at
    /// `now`, living 300 seconds.
    pub(crate) fn issued_claims(self, subject: &Value, now: i64) -> Value {
        json!({
            "iss": self.issuer(), "sub": subject["sub"], "aud": "https://ehr.example.org",
            "client_id": self.client_id(), "iat": now, "exp": now + 300,
            "jti": "issued-1", "scope": "user/*.rs"
        })
    }

    /// Returns the target the flavor's exchanges are for.
    pub(crate) fn target(self) -> Target {
        match self {
            Self::Generic => Target::new(["https://ehr.example.org"])
                .with_indicator("https://ehr.example.org/api"),
            Self::GenericJwtBearer => {
                Target::new(["https://ehr.example.org"]).with_scope("https://ehr.example.org/read")
            }
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
        let credentials = client.credentials(endpoint(&server, ROUTE), flavor.client_id());
        let clock = TestClock::now();
        let onward = Onward::with_clock(settings, credentials, clock.clone())
            .expect("the onward client builds");
        Self {
            flavor,
            server,
            key: ec_key("as-2026", Algorithm::Es256),
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
        let jws = ferrohealth_smart::jws::compact::decode(assertion)
            .map_err(|_unread| String::from("client_assertion"))?;
        if jws.header().alg != Algorithm::Es384 {
            return Err(String::from("client_assertion"));
        }
        let claims = jws
            .verify_claims(&jwk)
            .map_err(|_unverified| String::from("client_assertion"))?;
        Validation::default()
            .with_audiences([self.audience.as_str()])
            .with_issuer(self.flavor.client_id())
            .check(&claims)
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
