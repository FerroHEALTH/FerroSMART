// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `idp-entra` adapter against a `wiremock` Microsoft Graph and token
//! endpoint: the overage resolved at the URL the adapter builds, never at
//! `_claim_sources`, and every Graph failure a typed `GroupsUnavailable`.

use std::time::Instant;

use ferrohealth_smart::client::TokenError;
use ferrohealth_smart::config::credentials::OauthSection;
use ferrohealth_smart::idp::entra::GraphError;
use ferrohealth_smart::idp::entra::GraphSection;
use ferrohealth_smart::idp::entra::NAME;
use ferrohealth_smart::idp::entra::ReadError;
use ferrohealth_smart::party::adapter::BodyExcerpt;
use ferrohealth_smart::profile::Preset;
use ferrohealth_smart::profile::ProfileKeys;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::Settings;
use jsonwebtoken::Algorithm;
use jsonwebtoken::Header;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::body_json;
use wiremock::matchers::header;
use wiremock::matchers::method;
use wiremock::matchers::path;

use super::*;
use crate::support::ec_key;
use crate::support::mint_with;
use crate::support::now;
use crate::support::temp_file;

/// The Graph token the stub token endpoint issues.
const GRAPH_TOKEN: &str = "synthetic-graph-token";
/// The service principal of the app-only cases, a GUID.
const APP: &str = "0f4c8d2e-1a3b-4c5d-8e9f-a0b1c2d3e4f5";
/// Where the token's `_claim_sources` points, which is never called.
const CLAIM_SOURCE: &str = "/claim-source/v1.0/users/getMemberObjects";

/// A Graph and its token endpoint, both stubbed.
struct Graph {
    /// The stub.
    server: MockServer,
}

impl Graph {
    /// Returns a Graph whose token endpoint issues [`GRAPH_TOKEN`], and
    /// whose `_claim_sources` location must never be called.
    async fn start() -> Self {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": GRAPH_TOKEN, "token_type": "Bearer", "expires_in": 3600
            })))
            .mount(&server)
            .await;
        Mock::given(path(CLAIM_SOURCE))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": ["forged"] })))
            .named("the token's _claim_sources")
            .expect(0)
            .mount(&server)
            .await;
        Self { server }
    }

    /// Returns the Graph access table of the stub.
    fn section(&self) -> GraphSection {
        GraphSection {
            base_url: format!("{}/v1.0", self.server.uri()),
            credentials: OauthSection {
                token_endpoint: ferrohealth_secret::secret_url::SecretUrl::new(format!(
                    "{}/token",
                    self.server.uri()
                )),
                client_id: String::from("synthetic-graph-reader"),
                client_secret: Some(SecretString::from("synthetic-graph-secret")),
                scope: String::from("https://graph.microsoft.com/.default"),
                ..OauthSection::default()
            },
            ..GraphSection::default()
        }
    }

    /// Answers `getMemberObjects` of `collection`/`id` with `answer`,
    /// `expect` times.
    async fn members(&self, collection: &str, id: &str, answer: ResponseTemplate, expect: u64) {
        Mock::given(method("POST"))
            .and(path(format!("/v1.0/{collection}/{id}/getMemberObjects")))
            .and(header(
                "authorization",
                format!("Bearer {GRAPH_TOKEN}").as_str(),
            ))
            .and(header("content-type", "application/json"))
            .and(body_json(json!({ "securityEnabledOnly": false })))
            .respond_with(answer)
            .expect(expect)
            .mount(&self.server)
            .await;
    }

    /// Returns the claims of a user token shaped as the overage example of
    /// "Access token claims reference", whose source points at the stub.
    fn overage(&self) -> Value {
        json!({
            "oid": LOGIN,
            "_claim_names": { "groups": "src1" },
            "_claim_sources": {
                "src1": { "endpoint": format!("{}{CLAIM_SOURCE}", self.server.uri()) }
            }
        })
    }
}

/// Returns the profile of an issuer naming the adapter.
fn adapter_profile() -> Profile {
    Profile {
        adapter: Some(String::from(NAME)),
        ..profile()
    }
}

/// Returns the binding over `source` with the adapter `section` builds.
fn binding_with(source: &Arc<FakeSource>, section: &GraphSection) -> PartyBinding {
    let adapter = Arc::new(section.adapter().expect("the Graph access builds"));
    let concrete = Arc::clone(source);
    let dynamic: Arc<dyn PartySource> = concrete;
    PartyBinding::new(dynamic)
        .with_adapter(NAME, adapter)
        .with_issuer(table(), IssuerKind::Persons, &adapter_profile())
        .expect("the table binds")
}

/// Returns the source finding the professional `p-1`, a member of `g-2`
/// under the identifier `group-2`.
fn member_of_group_2() -> Arc<FakeSource> {
    FakeSource::answering(Lookup::Parties(vec![
        record("p-1", Markers::PROFESSIONAL)
            .with_memberships(vec![Membership::new(group_ref("g-2"), "group-2")]),
    ]))
}

/// Returns the adapter failure of `outcome`.
fn adapter_failure(outcome: Option<Outcome>) -> Result<AdapterError, Box<dyn StdError>> {
    match outcome {
        Some(Outcome::GroupsUnavailable(GroupsCause::Adapter(error))) => Ok(error),
        other => Err(format!("an adapter failure, not {other:?}").into()),
    }
}

// NOTE: Microsoft, "Access token claims reference", §Groups overage claim: the URL in
// `_claim_sources` is "an Azure AD Graph URL", and a service should "use the `idtyp` optional
// claim ... to construct a Microsoft Graph URL"; the adapter builds users/{oid}/getMemberObjects.
#[tokio::test]
async fn an_overage_is_resolved_at_the_adapter_built_url_and_never_at_claim_sources() -> Outcome2 {
    let graph = Graph::start().await;
    let answer = ResponseTemplate::new(200).set_body_json(json!({
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#Collection(Edm.String)",
        "value": ["group-1", "group-2", "group-3"]
    }));
    graph.members("users", LOGIN, answer, 1).await;
    let source = member_of_group_2();
    let party = bound(
        binding_with(&source, &graph.section())
            .resolve(&person(&graph.overage()))
            .await?,
    )?;
    assert_eq!(vec![group_ref("g-2")], party.groups, "the matching group");
    assert_eq!(1, source.calls());
    graph.server.verify().await;
    Ok(())
}

// NOTE: Microsoft, "Access token claims reference", `hasgroups`: the client "should use the
// Microsoft Graph API to determine the groups (`.../users/{userID}/getMemberObjects`)".
#[tokio::test]
async fn hasgroups_is_resolved_the_same_way() -> Outcome2 {
    let graph = Graph::start().await;
    let answer = ResponseTemplate::new(200).set_body_json(json!({ "value": ["group-2"] }));
    graph.members("users", LOGIN, answer, 1).await;
    let claims = json!({ "oid": LOGIN, "hasgroups": true });
    let party = bound(
        binding_with(&member_of_group_2(), &graph.section())
            .resolve(&person(&claims))
            .await?,
    )?;
    assert_eq!(vec![group_ref("g-2")], party.groups);
    Ok(())
}

// NOTE: Microsoft, "Optional claims reference", `idtyp`: "The value is `app` when the token is
// an app-only token"; `getMemberObjects` has the `/servicePrincipals/{id}` form for one.
#[tokio::test]
async fn an_app_only_token_reads_its_service_principal_and_a_user_token_its_user() -> Outcome2 {
    let graph = Graph::start().await;
    let answer = || ResponseTemplate::new(200).set_body_json(json!({ "value": ["group-9"] }));
    graph.members("servicePrincipals", APP, answer(), 1).await;
    graph.members("users", LOGIN, answer(), 1).await;
    let adapter = graph.section().adapter()?;
    let app = caller(
        CallerKind::System,
        None,
        &json!({ "oid": APP, "idtyp": "app" }),
    );
    assert_eq!(
        vec![String::from("group-9")],
        adapter.resolve_groups(&app).await?
    );
    let user = person(&json!({ "oid": LOGIN, "idtyp": "user" }));
    assert_eq!(
        vec![String::from("group-9")],
        adapter.resolve_groups(&user).await?
    );
    graph.server.verify().await;
    Ok(())
}

// NOTE: Microsoft, "Access token claims reference", `oid`: "String, a GUID"; a token without
// one, or with an `idtyp` the adapter has no URL for, never reaches Graph.
#[tokio::test]
async fn a_token_without_a_guid_oid_or_with_another_idtyp_never_calls_graph() -> Outcome2 {
    let graph = Graph::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .named("any Graph call")
        .expect(0)
        .mount(&graph.server)
        .await;
    let adapter = graph.section().adapter()?;
    for (claims, named) in [
        (json!({}), "oid"),
        (json!({ "oid": 7 }), "oid"),
        (json!({ "oid": "../../me" }), "oid"),
        (json!({ "oid": LOGIN, "idtyp": "device" }), "idtyp"),
        (json!({ "oid": LOGIN, "idtyp": true }), "idtyp"),
    ] {
        let refused = adapter.resolve_groups(&person(&claims)).await;
        assert!(
            matches!(&refused, Err(AdapterError::Claim { claim }) if claim == named),
            "{claims}: {refused:?}"
        );
    }
    Ok(())
}

// NOTE: Microsoft, "Microsoft Graph throttling guidance": a throttled request "Returns HTTP
// status code 429 Too Many Requests" and "includes the `Retry-After` response header".
#[tokio::test]
async fn a_throttled_graph_is_groups_unavailable_carrying_429_and_retry_after() -> Outcome2 {
    let graph = Graph::start().await;
    let throttled = ResponseTemplate::new(429).insert_header("Retry-After", "10");
    graph.members("users", LOGIN, throttled, 1).await;
    let source = member_of_group_2();
    let error = adapter_failure(
        binding_with(&source, &graph.section())
            .resolve(&person(&graph.overage()))
            .await?,
    )?;
    assert!(
        matches!(
            error,
            AdapterError::Status { status: StatusCode::TOO_MANY_REQUESTS, retry_after: Some(after), body: None }
                if after == Duration::from_secs(10)
        ),
        "{error:?}"
    );
    assert_eq!(0, source.calls(), "no lookup on a failed adapter");
    Ok(())
}

// NOTE: Microsoft Graph v1.0, `directoryObject: getMemberObjects`: "If successful, this method
// returns `200 OK`"; a Graph that refuses the permission is the status it answers.
#[tokio::test]
async fn a_graph_refusing_the_permission_is_groups_unavailable_carrying_its_status() -> Outcome2 {
    let graph = Graph::start().await;
    graph
        .members("users", LOGIN, ResponseTemplate::new(403), 1)
        .await;
    let error = adapter_failure(
        binding_with(&member_of_group_2(), &graph.section())
            .resolve(&person(&graph.overage()))
            .await?,
    )?;
    assert!(
        matches!(
            error,
            AdapterError::Status {
                status: StatusCode::FORBIDDEN,
                retry_after: None,
                body: None,
            }
        ),
        "{error:?}"
    );
    Ok(())
}

// NOTE: no specification governs the excerpt: our own design, in which a refusal carries a bounded
// excerpt of the upstream error body with every claim value of the token and every JWS withheld.
#[tokio::test]
async fn a_graph_403_carries_a_bounded_redacted_excerpt_of_its_error_body() -> Outcome2 {
    let graph = Graph::start().await;
    let jws = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.c2lnbmF0dXJl";
    // The members in the order Graph writes them, so the excerpt opens with the code and message.
    let padding = "x".repeat(4096);
    let refused = ResponseTemplate::new(403)
        .insert_header("content-type", "application/json")
        .set_body_string(format!(
            r#"{{"error":{{"code":"Authorization_RequestDenied","message":"Insufficient privileges to read the memberships of '{LOGIN}'.","innerError":{{"date":"2026-11-06T10:00:00","request-id":"b1e3c1d0-0000-4000-8000-000000000001","echo":"{jws}","padding":"{padding}"}}}}}}"#
        ));
    graph.members("users", LOGIN, refused, 1).await;
    let error = adapter_failure(
        binding_with(&member_of_group_2(), &graph.section())
            .resolve(&person(&graph.overage()))
            .await?,
    )?;
    let AdapterError::Status {
        status,
        body: Some(body),
        ..
    } = &error
    else {
        return Err(format!("a status carrying its body, not {error:?}").into());
    };
    assert_eq!(StatusCode::FORBIDDEN, *status);
    let excerpt = body.as_str();
    assert!(excerpt.contains("Authorization_RequestDenied"), "{excerpt}");
    assert!(excerpt.contains("Insufficient privileges"), "{excerpt}");
    assert!(
        excerpt.chars().count() <= BodyExcerpt::MAX_CHARS,
        "{excerpt}"
    );
    for withheld in [LOGIN, jws, GRAPH_TOKEN] {
        assert!(!excerpt.contains(withheld), "{withheld} in {excerpt}");
        assert!(
            !error.to_string().contains(withheld),
            "{withheld} in {error}"
        );
        assert!(
            !format!("{error:?}").contains(withheld),
            "{withheld} in {error:?}"
        );
    }
    assert!(
        error.to_string().contains("Authorization_RequestDenied"),
        "{error}"
    );
    Ok(())
}

// NOTE: RFC 6749 §5.2: a refused client credentials request is an error response; without
// a Graph token there is no Graph call, and the cause is the token error.
#[tokio::test]
async fn without_a_graph_token_the_outcome_is_groups_unavailable() -> Outcome2 {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({ "error": "invalid_client" })),
        )
        .mount(&server)
        .await;
    Mock::given(path_regex_any_graph())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let graph = Graph { server };
    let error = adapter_failure(
        binding_with(&member_of_group_2(), &graph.section())
            .resolve(&person(&json!({ "oid": LOGIN, "hasgroups": true })))
            .await?,
    )?;
    let AdapterError::Unreadable { source } = &error else {
        return Err(format!("an unreadable answer, not {error:?}").into());
    };
    assert!(
        source.downcast_ref::<TokenError>().is_some(),
        "the token error is the cause: {source:?}"
    );
    Ok(())
}

/// Matches any path under the Graph root of the stub.
fn path_regex_any_graph() -> wiremock::matchers::PathRegexMatcher {
    wiremock::matchers::path_regex("^/v1.0/")
}

// NOTE: no specification governs the Graph call: our own design, in which the overage of
// an issuer whose profile names no adapter stays the generic outcome.
#[tokio::test]
async fn without_the_adapter_on_the_issuer_an_overage_stays_groups_unavailable() -> Outcome2 {
    let graph = Graph::start().await;
    let outcome = binding(&member_of_group_2())
        .resolve(&person(&graph.overage()))
        .await?;
    assert!(
        matches!(
            outcome,
            Some(Outcome::GroupsUnavailable(GroupsCause::Overage))
        ),
        "{outcome:?}"
    );
    graph.server.verify().await;
    Ok(())
}

// NOTE: no specification governs the bound: our own design, in which the adapter's budget
// ends the call and the outcome carries the timeout.
#[tokio::test]
async fn a_graph_slower_than_the_budget_is_groups_unavailable_carrying_the_timeout() -> Outcome2 {
    let graph = Graph::start().await;
    let slow = ResponseTemplate::new(200)
        .set_body_json(json!({ "value": ["group-2"] }))
        .set_delay(Duration::from_secs(5));
    graph.members("users", LOGIN, slow, 1).await;
    // The budget covers the token fetch too, so it leaves a loaded runner room to reach Graph.
    let section = GraphSection {
        timeout: ferrohealth_config::units::Duration::from_millis(1000),
        ..graph.section()
    };
    let started = Instant::now();
    let error = adapter_failure(
        binding_with(&member_of_group_2(), &section)
            .resolve(&person(&graph.overage()))
            .await?,
    )?;
    assert!(
        matches!(error, AdapterError::Timeout { timeout } if timeout == Duration::from_millis(1000)),
        "{error:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the budget ended the call"
    );
    Ok(())
}

// NOTE: no specification governs the bound: our own design, in which an answer past
// `max_response_size` is never read.
#[tokio::test]
async fn an_answer_past_the_size_bound_is_unreadable() -> Outcome2 {
    let graph = Graph::start().await;
    let large = ResponseTemplate::new(200).set_body_json(json!({
        "value": (0..64).map(|n| format!("group-{n}")).collect::<Vec<_>>()
    }));
    graph.members("users", LOGIN, large, 1).await;
    let section = GraphSection {
        max_response_size: ferrohealth_config::units::ByteSize::from_bytes(256),
        ..graph.section()
    };
    let error = adapter_failure(
        binding_with(&member_of_group_2(), &section)
            .resolve(&person(&graph.overage()))
            .await?,
    )?;
    let AdapterError::Unreadable { source } = &error else {
        return Err(format!("an unreadable answer, not {error:?}").into());
    };
    assert!(
        matches!(
            source.downcast_ref::<ReadError>(),
            Some(ReadError::TooLarge { limit: 256 })
        ),
        "{source:?}"
    );
    Ok(())
}

// NOTE: RFC 6750 §3.1: `401` answers an invalid token, so the Graph token is renewed once
// and the call sent again.
#[tokio::test]
async fn a_graph_refusing_the_token_once_is_answered_under_a_renewed_token() -> Outcome2 {
    let graph = Graph::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v1.0/users/{LOGIN}/getMemberObjects")))
        .respond_with(ResponseTemplate::new(401))
        .up_to_n_times(1)
        .expect(1)
        .with_priority(1)
        .mount(&graph.server)
        .await;
    let answer = ResponseTemplate::new(200).set_body_json(json!({ "value": ["group-2"] }));
    graph.members("users", LOGIN, answer, 1).await;
    let party = bound(
        binding_with(&member_of_group_2(), &graph.section())
            .resolve(&person(&graph.overage()))
            .await?,
    )?;
    assert_eq!(vec![group_ref("g-2")], party.groups);
    let tokens = graph
        .server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|request| request.url.path() == "/token")
        .count();
    assert_eq!(2, tokens, "one fetch and one renewal");
    Ok(())
}

// NOTE: no specification governs the Graph call: our own design, in which nothing is
// cached, so each request of an overage token reads Graph once.
#[tokio::test]
async fn every_overage_request_reads_graph_once() -> Outcome2 {
    let graph = Graph::start().await;
    let answer = ResponseTemplate::new(200).set_body_json(json!({ "value": ["group-2"] }));
    graph.members("users", LOGIN, answer, 3).await;
    let binding = binding_with(&member_of_group_2(), &graph.section());
    for _ in 0..3 {
        bound(binding.resolve(&person(&graph.overage())).await?)?;
    }
    graph.server.verify().await;
    Ok(())
}

/// A check of the refusal a Graph table builds to.
type Refusal = fn(&GraphError) -> bool;

// NOTE: no specification governs the configuration: our own design; the Graph root is
// `https` (or loopback `http`) and every bound is above zero.
#[test]
fn a_graph_table_breaking_a_rule_fails_to_build() {
    let good = GraphSection {
        credentials: OauthSection {
            token_endpoint: ferrohealth_secret::secret_url::SecretUrl::new(String::from(
                "https://login.example.org/token",
            )),
            client_id: String::from("synthetic-graph-reader"),
            client_secret: Some(SecretString::from("synthetic-graph-secret")),
            ..OauthSection::default()
        },
        ..GraphSection::default()
    };
    assert!(good.adapter().is_ok(), "the defaults with a grant build");
    let cases: [(GraphSection, Refusal); 6] = [
        (
            GraphSection {
                base_url: String::from("not a url"),
                ..good.clone()
            },
            |error| matches!(error, GraphError::BaseUrl { .. }),
        ),
        (
            GraphSection {
                base_url: String::from("http://graph.example.org/v1.0"),
                ..good.clone()
            },
            |error| matches!(error, GraphError::Insecure { .. }),
        ),
        (
            GraphSection {
                base_url: String::from("https://graph.example.org/v1.0?x=1"),
                ..good.clone()
            },
            |error| matches!(error, GraphError::Insecure { .. }),
        ),
        (
            GraphSection {
                timeout: ferrohealth_config::units::Duration::ZERO,
                ..good.clone()
            },
            |error| matches!(error, GraphError::Zero { key: "timeout" }),
        ),
        (
            GraphSection {
                max_response_size: ferrohealth_config::units::ByteSize::ZERO,
                ..good.clone()
            },
            |error| {
                matches!(
                    error,
                    GraphError::Zero {
                        key: "max_response_size"
                    }
                )
            },
        ),
        (GraphSection::default(), |error| {
            matches!(error, GraphError::Credentials { .. })
        }),
    ];
    for (position, (section, expected)) in cases.into_iter().enumerate() {
        let refused = section.adapter();
        assert!(
            refused.as_ref().err().is_some_and(expected),
            "case {position}: {refused:?}"
        );
    }
}

#[test]
fn a_graph_table_reads_from_toml_and_refuses_an_unknown_key() {
    let read: GraphSection = toml::from_str(
        r#"
timeout = "1500ms"
security_enabled_only = true

[credentials]
token_endpoint = "https://login.example.org/token"
client_id = "synthetic-graph-reader"
"#,
    )
    .expect("the table reads");
    assert_eq!(
        ferrohealth_config::units::Duration::from_millis(1500),
        read.timeout
    );
    assert!(read.security_enabled_only);
    assert_eq!("https://graph.microsoft.com/v1.0", read.base_url);
    assert!(toml::from_str::<GraphSection>("claim_sources = true").is_err());
}

// NOTE: Microsoft, "Access token claims reference": `oid` is the person key of the entra
// preset and the overage claim replaces `groups`; a signed token is resolved end to end.
#[tokio::test]
async fn a_signed_overage_token_is_classified_and_bound_with_its_graph_groups() -> Outcome2 {
    let graph = Graph::start().await;
    let answer = ResponseTemplate::new(200).set_body_json(json!({ "value": ["group-2"] }));
    graph.members("users", LOGIN, answer, 1).await;
    let key = ec_key("k1", Algorithm::ES256);
    let set = json!({ "keys": [key.jwk.clone()] }).to_string();
    let mut settings = Settings::new(ISSUER, "api://ferro", IssuerKind::Persons);
    settings.jwks_file = Some(temp_file("party-entra-overage-jwks.json", set.as_bytes()));
    settings.profile = Profile::resolve(
        Preset::Entra,
        &ProfileKeys {
            adapter: Some(String::from(NAME)),
            ..ProfileKeys::default()
        },
    )?;
    let server = ResourceServer::discover(settings.clone()).await?;
    let mut claims = graph.overage();
    let extra = json!({
        "iss": ISSUER, "aud": "api://ferro", "sub": "pairwise-sub-of-this-app",
        "tid": "tenant-1", "azp": CLIENT, "uti": "uti-overage", "ver": "2.0",
        "iat": now(), "exp": now() + 300, "scp": "user/Observation.rs", "acct": 0
    });
    if let (Some(claims), Some(extra)) = (claims.as_object_mut(), extra.as_object()) {
        claims.extend(extra.clone());
    }
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(String::from("k1"));
    header.typ = Some(String::from("JWT"));
    let caller = server
        .authenticate(&mint_with(&key, &header, &claims))
        .await?;
    assert_eq!(&CallerKind::Person, caller.kind());
    let adapter = Arc::new(graph.section().adapter()?);
    let source = member_of_group_2();
    let concrete = Arc::clone(&source);
    let dynamic: Arc<dyn PartySource> = concrete;
    let binding = PartyBinding::new(dynamic)
        .with_adapter(NAME, adapter)
        .with_issuer(table(), IssuerKind::Persons, &settings.profile)?;
    let party = bound(binding.resolve(&caller).await?)?;
    assert_eq!(vec![group_ref("g-2")], party.groups);
    graph.server.verify().await;
    Ok(())
}

// NOTE: no specification governs the budget: our own design. The adapter's latency lies
// outside a product's lookup budget (FerroEHR's 2 ms at p99 excludes it), so it is measured
// on its own, against a Graph answering after 50 ms, and must stay within the adapter's timeout.
#[tokio::test]
async fn the_p99_of_an_overage_request_stays_within_the_adapter_timeout() -> Outcome2 {
    const REQUESTS: usize = 100;
    let graph = Graph::start().await;
    let delayed = ResponseTemplate::new(200)
        .set_body_json(json!({ "value": ["group-1", "group-2"] }))
        .set_delay(Duration::from_millis(50));
    graph.members("users", LOGIN, delayed, 100).await;
    let section = graph.section();
    let budget = section.timeout.get();
    let binding = binding_with(&member_of_group_2(), &section);
    let caller = person(&graph.overage());
    let mut latencies = Vec::with_capacity(REQUESTS);
    for _ in 0..REQUESTS {
        let started = Instant::now();
        bound(binding.resolve(&caller).await?)?;
        latencies.push(started.elapsed());
    }
    latencies.sort();
    // NOTE: the nearest-rank p99 of 100 samples is the 99th, at index 98.
    let p99 = latencies[98];
    println!(
        "idp-entra: p99 {p99:?} over {REQUESTS} overage requests with 50 ms injected Graph \
         latency, outside the 2 ms lookup budget, against an adapter timeout of {budget:?}"
    );
    assert!(
        p99 >= Duration::from_millis(50),
        "the Graph latency is in the path"
    );
    assert!(
        p99 <= budget,
        "p99 {p99:?} passes the adapter timeout {budget:?}"
    );
    Ok(())
}
