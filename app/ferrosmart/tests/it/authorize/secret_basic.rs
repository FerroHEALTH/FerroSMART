// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! `client_secret_basic` toward an upstream provider, the administrator's
//! choice per provider beside the default `private_key_jwt` (#679).

use base64::Engine as _;

use super::*;

/// The secret the cases register FerroSMART with, invented for them.
const SECRET: &str = "synthetic-upstream-secret";

/// Returns the configuration of one provider at `issuer` that FerroSMART
/// authenticates at with [`SECRET`], read from a file under `keys`.
fn with_secret(issuer: &str, keys: &Keys) -> String {
    let file = keys.dir.path().join("upstream-secret");
    std::fs::write(&file, SECRET).expect("the secret is written");
    format!(
        "[ferrosmart]\nissuer = {ISSUER:?}\n\
         [[ferrosmart.upstream]]\nname = \"idp\"\n\
         [ferrosmart.upstream.oidc]\nissuer = {issuer:?}\nclient_id = {UPSTREAM_CLIENT:?}\n\
         [ferrosmart.upstream.oidc.client_secret_basic]\nsecret_file = {:?}\n\
         {ASSURANCE}\
         [[ferrosmart.client]]\nclient_id = \"app\"\nkind = \"public\"\n\
         redirect_uris = [{REDIRECT:?}]\ngrant_types = [\"authorization_code\"]\nscopes = [\"openid\"]\n\
         resources = [{RESOURCE:?}]",
        file.display().to_string()
    )
}

#[tokio::test]
async fn a_provider_s_token_request_carries_the_secret_as_http_basic() {
    let provider = Provider::start().await;
    let keys = Keys::new();
    let settings = config(&with_secret(&provider.server.uri(), &keys), &keys)
        .resolve()
        .expect("resolves");
    let providers = crate::support::providers(&settings).await;
    let login = providers.named("idp").expect("the provider");
    let party = login.oidc().expect("an OpenID Connect provider");
    let begun = party.authorization_request().expect("a request");
    provider.answer(begun.pending.nonce(), &[]).await;
    let mut answer = ferrohealth_smart::oidc::Callback::default();
    answer.code = Some(ferrohealth_secret::secret::Secret::new(String::from(
        "synthetic-upstream-code",
    )));
    answer.state = Some(begun.pending.state().to_owned());
    party
        .exchange(&begun.pending, &answer)
        .await
        .expect("the provider answers");
    let requests = provider.server.received_requests().await.expect("recorded");
    let token = requests
        .iter()
        .find(|request| request.url.path() == "/token")
        .expect("a token request");
    // NOTE: RFC 6749 §2.3.1, the client id and secret form-encoded, then Basic.
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{UPSTREAM_CLIENT}:{SECRET}"))
    );
    assert_eq!(
        Some(expected.as_str()),
        token
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        "the secret goes as HTTP Basic"
    );
    let body = String::from_utf8_lossy(&token.body);
    assert!(
        !body.contains("client_assertion"),
        "no assertion beside the secret: {body}"
    );
}

#[tokio::test]
async fn a_provider_that_does_not_list_the_method_is_refused_at_start() {
    let server = MockServer::start().await;
    let uri = server.uri();
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": uri,
            "authorization_endpoint": format!("{uri}/authorize"),
            "token_endpoint": format!("{uri}/token"),
            "jwks_uri": format!("{uri}/jwks"),
            "token_endpoint_auth_methods_supported": ["private_key_jwt"]
        })))
        .mount(&server)
        .await;
    let keys = Keys::new();
    let settings = config(&with_secret(&uri, &keys), &keys)
        .resolve()
        .expect("resolves");
    // NOTE: RFC 8414 §2, token_endpoint_auth_methods_supported names what the
    // token endpoint takes; a method it does not list is refused before any login.
    let refused = ferrosmart::upstream::Providers::connect(
        &settings.upstreams,
        &settings.endpoint_url(ferrosmart::authorize::CALLBACK_ROUTE),
        &settings.endpoint_url(ferrosmart::logout::end_session::END_SESSION_RETURN_ROUTE),
        None,
    )
    .await
    .expect_err("refused");
    assert!(
        matches!(
            refused,
            ferrosmart::upstream::UpstreamError::Method {
                method: "client_secret_basic"
            }
        ),
        "{refused}"
    );
}

#[test]
fn the_secret_never_shows_in_a_debug_rendering() {
    let keys = Keys::new();
    let settings = config(&with_secret("https://idp.example.org", &keys), &keys)
        .resolve()
        .expect("resolves");
    let rendered = format!("{settings:?}");
    assert!(
        !rendered.contains(SECRET),
        "the secret redacts itself: {rendered}"
    );
    let ferrosmart::upstream::Protocol::Oidc(oidc) =
        &settings.upstreams.first().expect("a provider").protocol
    else {
        panic!("the provider speaks OpenID Connect");
    };
    assert_eq!("client_secret_basic", oidc.authentication.method());
}

#[test]
fn both_methods_none_or_a_secret_without_its_value_is_refused_at_load() {
    let keys = Keys::new();
    let base = with_secret("https://idp.example.org", &keys);
    let both = base.replace(
        "[[ferrosmart.client]]",
        &format!(
            "{}[[ferrosmart.client]]",
            crate::support::upstream_assertion(keys.dir.path())
        ),
    );
    let neither = base.replace(
        base.get(
            base.find("[ferrosmart.upstream.oidc.client_secret_basic]")
                .expect("the table")
                ..base.find("[[ferrosmart.client]]").expect("the client"),
        )
        .expect("the table"),
        "",
    );
    let empty = base.replace(
        base.get(
            base.find("secret_file = ").expect("the key")
                ..base.find("[[ferrosmart.client]]").expect("the client"),
        )
        .expect("the key"),
        "",
    );
    for text in [&both, &neither, &empty] {
        assert!(config(text, &keys).resolve().is_err(), "{text}");
    }
    // NOTE: OpenID Connect Core 1.0 §9, with neither table private_key_jwt is taken,
    // and its assertion key is what is missing (#733).
    assert!(
        matches!(
            config(&neither, &keys).resolve(),
            Err(ferrosmart::config::error::Error::Missing {
                key: "ferrosmart.upstream.oidc.private_key_jwt.keys.private_key_file"
            })
        ),
        "{neither}"
    );
    let misplaced = crate::support::upstream_assertion(keys.dir.path()).replace(
        "[ferrosmart.upstream.oidc.private_key_jwt.keys]\n",
        "[ferrosmart.upstream.oidc.private_key_jwt]\nsecret = \"synthetic\"\n\
         [ferrosmart.upstream.oidc.private_key_jwt.keys]\n",
    );
    let misplaced = neither.replace(
        "[[ferrosmart.client]]",
        &format!("{misplaced}[[ferrosmart.client]]"),
    );
    assert!(
        ferrosmart::config::Config::from_sources(
            Some(&misplaced),
            &std::collections::BTreeMap::new()
        )
        .is_err(),
        "a secret under private_key_jwt is an unknown key"
    );
}
