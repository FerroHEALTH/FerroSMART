// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! What the client registry admits and refuses, each rule its own case.

use ferrosmart::clients::{
    AuthMethod, Client, ClientError, ClientKeys, ClientMetadata, GrantType, Material, resolve,
};
use serde_json::{Value, json};

/// Returns the client `section` registers.
fn admit(section: &ClientMetadata) -> Result<Client, ClientError> {
    resolve(section, Material::default())
}

/// Returns the client `section` registers with the JWK Set `set` by value.
fn admit_with(section: &ClientMetadata, set: &Value) -> Result<Client, ClientError> {
    resolve(
        section,
        Material {
            jwks: Some(set.clone()),
            secret_hash: None,
        },
    )
}

/// Returns a Backend Services client with its JWK Set at a URL.
fn backend(client_id: &str) -> ClientMetadata {
    ClientMetadata {
        client_id: client_id.to_owned(),
        auth_method: AuthMethod::PrivateKeyJwt,
        jwks_uri: String::from("https://export.example.org/jwks.json"),
        scopes: vec![String::from("system/Patient.rs")],
        grant_types: vec![GrantType::ClientCredentials],
        ..ClientMetadata::default()
    }
}

/// Returns a client that registers its JWK Set by value.
fn by_value() -> ClientMetadata {
    ClientMetadata {
        jwks_uri: String::new(),
        ..backend("by-value")
    }
}

#[test]
fn a_backend_services_client_registers_its_jwk_set_by_url() {
    let client = admit(&backend("export")).expect("admitted");
    assert_eq!("export", client.name, "the name defaults to the client id");
    assert!(
        matches!(&client.keys, Some(ClientKeys::Uri(url)) if url.as_str() == "https://export.example.org/jwks.json")
    );
    assert_eq!(vec![GrantType::ClientCredentials], client.grant_types);
}

#[test]
fn a_jwk_set_by_value_holds_bare_public_keys_with_kty_and_kid() {
    let set = json!({"keys": [
        {"kty": "RSA", "kid": "r1", "n": "AQAB", "e": "AQAB", "alg": "RS384"},
        {"kty": "EC", "kid": "e1", "crv": "P-384", "x": "AA", "y": "AA"}
    ]});
    let client = admit_with(&by_value(), &set).expect("admitted");
    assert!(matches!(&client.keys, Some(ClientKeys::Set(kept)) if *kept == set));
    // NOTE: SMART App Launch 2.2.0, Client Authentication: Asymmetric,
    // Registering a client: `kty`, `kid` and the bare key members.
    for (key, rule) in [
        (
            json!({"kty": "RSA", "n": "AQAB", "e": "AQAB"}),
            "has no `kid`",
        ),
        (
            json!({"kty": "oct", "kid": "s", "k": "AA"}),
            "is no RSA or EC key",
        ),
        (
            json!({"kty": "RSA", "kid": "r", "n": "AQAB"}),
            "lacks a bare key member",
        ),
        (
            json!({"kty": "EC", "kid": "e", "crv": "P-256", "x": "AA", "y": "AA", "d": "AA"}),
            "carries a private member",
        ),
    ] {
        assert!(
            matches!(admit_with(&by_value(), &json!({"keys": [key]})), Err(ClientError::Jwk { rule: refused, .. }) if refused == rule),
            "{rule}"
        );
    }
    assert!(matches!(
        admit_with(&by_value(), &json!({"keys": []})),
        Err(ClientError::Rule { .. })
    ));
}

#[test]
fn a_confidential_asymmetric_client_registers_exactly_one_jwk_set() {
    let neither = ClientMetadata {
        jwks_uri: String::new(),
        ..backend("neither")
    };
    assert!(matches!(admit(&neither), Err(ClientError::Rule { .. })));
    let set = json!({"keys": [{"kty": "RSA", "kid": "r", "n": "AQAB", "e": "AQAB"}]});
    assert!(matches!(
        admit_with(&backend("both"), &set),
        Err(ClientError::Rule { .. })
    ));
    let plain = ClientMetadata {
        jwks_uri: String::from("http://export.example.org/jwks.json"),
        ..backend("plain")
    };
    assert!(matches!(admit(&plain), Err(ClientError::JwksUri { .. })));
}

#[test]
fn a_public_client_neither_registers_keys_nor_uses_client_credentials() {
    let keyed = ClientMetadata {
        auth_method: AuthMethod::None,
        ..backend("keyed")
    };
    assert!(matches!(admit(&keyed), Err(ClientError::Rule { .. })));
    let public = ClientMetadata {
        client_id: String::from("app"),
        auth_method: AuthMethod::None,
        grant_types: vec![GrantType::ClientCredentials],
        ..ClientMetadata::default()
    };
    assert!(matches!(admit(&public), Err(ClientError::Rule { .. })));
}

#[test]
fn an_authorization_code_client_registers_absolute_redirect_uris() {
    let app = |uris: Vec<&str>| ClientMetadata {
        client_id: String::from("app"),
        auth_method: AuthMethod::None,
        redirect_uris: uris.into_iter().map(String::from).collect(),
        grant_types: vec![GrantType::AuthorizationCode, GrantType::AuthorizationCode],
        ..ClientMetadata::default()
    };
    let admitted = admit(&app(vec!["https://app.example.org/callback"])).expect("admitted");
    assert_eq!(
        vec![GrantType::AuthorizationCode],
        admitted.grant_types,
        "once"
    );
    assert!(matches!(admit(&app(vec![])), Err(ClientError::Rule { .. })));
    // NOTE: RFC 6749 §3.1.2, absolute and without a fragment.
    for uri in ["/callback", "https://app.example.org/callback#done"] {
        assert!(
            matches!(admit(&app(vec![uri])), Err(ClientError::RedirectUri { .. })),
            "{uri}"
        );
    }
}

#[test]
fn the_registry_refuses_a_missing_id_a_bad_scope_and_no_grant() {
    assert!(matches!(admit(&backend("")), Err(ClientError::NoClientId)));
    let scoped = ClientMetadata {
        scopes: vec![String::from("system/Patient.rs extra")],
        ..backend("scoped")
    };
    assert!(matches!(admit(&scoped), Err(ClientError::Scope { .. })));
    let idle = ClientMetadata {
        grant_types: Vec::new(),
        ..backend("idle")
    };
    assert!(matches!(admit(&idle), Err(ClientError::Rule { .. })));
}

#[test]
fn a_refresh_token_continues_an_authorization_code_grant_only() {
    // NOTE: SMART App Launch 2.2.0, Backend Services: refresh tokens SHOULD NOT be issued.
    let backend_refresh = ClientMetadata {
        grant_types: vec![GrantType::ClientCredentials, GrantType::RefreshToken],
        ..backend("export")
    };
    assert!(matches!(
        admit(&backend_refresh),
        Err(ClientError::Rule { .. })
    ));
    let app = ClientMetadata {
        client_id: String::from("app"),
        auth_method: AuthMethod::None,
        redirect_uris: vec![String::from("https://app.example.org/callback")],
        grant_types: vec![GrantType::RefreshToken, GrantType::AuthorizationCode],
        ..ClientMetadata::default()
    };
    let admitted = admit(&app).expect("admitted");
    assert_eq!(
        vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        admitted.grant_types
    );
}

// NOTE: docs/architecture.md §13.17, a launch registration names the app by its
// launch URL, so two clients may not register one (#659).
#[test]
fn a_launch_url_is_normalized_and_registered_once() {
    let app = |client_id: &str, launch_uri: &str| ClientMetadata {
        client_id: client_id.to_owned(),
        auth_method: AuthMethod::None,
        redirect_uris: vec![String::from("https://app.example.org/callback")],
        grant_types: vec![GrantType::AuthorizationCode],
        launch_uri: launch_uri.to_owned(),
        ..ClientMetadata::default()
    };
    let client = admit(&app(
        "one",
        "HTTPS://App.Example.ORG:443/a/../%6Caunch?x=%7e",
    ))
    .expect("admitted");
    assert_eq!(
        Some("https://app.example.org/launch?x=~"),
        client.launch_uri.as_deref(),
        "RFC 3986 §6.2.2"
    );
    for refused in [
        "http://app.example.org/launch",
        "https://app.example.org/launch#start",
        "/launch",
    ] {
        assert!(
            matches!(
                admit(&app("one", refused)),
                Err(ClientError::LaunchUri { .. })
            ),
            "{refused}"
        );
    }
}

// NOTE: RFC 7591 §2, the app's URLs the consent page links and draws (#668).
#[test]
fn the_app_s_urls_are_absolute_https_urls() {
    let app = |key: &str, value: &str| {
        let mut section = ClientMetadata {
            client_id: String::from("app"),
            auth_method: AuthMethod::None,
            redirect_uris: vec![String::from("https://app.example.org/callback")],
            grant_types: vec![GrantType::AuthorizationCode],
            ..ClientMetadata::default()
        };
        match key {
            "client_uri" => section.client_uri = value.to_owned(),
            "logo_uri" => section.logo_uri = value.to_owned(),
            "policy_uri" => section.policy_uri = value.to_owned(),
            _ => section.tos_uri = value.to_owned(),
        }
        section
    };
    for key in ["client_uri", "logo_uri", "policy_uri", "tos_uri"] {
        assert!(
            admit(&app(key, "https://app.example.org/x")).is_ok(),
            "{key}"
        );
        for refused in [
            "http://app.example.org/x",
            "https://app.example.org/x#y",
            "/x",
        ] {
            assert!(
                matches!(
                    admit(&app(key, refused)),
                    Err(ClientError::AboutUri { key: named, .. }) if named == key
                ),
                "{key} = {refused}"
            );
        }
    }
    let admitted = admit(&app("logo_uri", "https://cdn.example.org/logo.png")).expect("admitted");
    let about = &admitted.about;
    assert_eq!(
        Some("https://cdn.example.org/logo.png"),
        about.logo.as_ref().map(url::Url::as_str)
    );
    assert_eq!(None, about.home);
}

/// Returns a client authenticating by `auth_method` that registers
/// `redirect`, first party when `first_party`, its JWK Set at a URL when it
/// authenticates with a key.
fn redirecting(auth_method: AuthMethod, redirect: &str, first_party: bool) -> ClientMetadata {
    ClientMetadata {
        client_id: String::from("app"),
        auth_method,
        jwks_uri: if auth_method == AuthMethod::PrivateKeyJwt {
            String::from("https://app.example.org/jwks.json")
        } else {
            String::new()
        },
        redirect_uris: vec![redirect.to_owned()],
        grant_types: vec![GrantType::AuthorizationCode],
        scopes: vec![String::from("openid")],
        first_party,
        ..ClientMetadata::default()
    }
}

// NOTE: RFC 8252 §8.6 and §7.2, a claimed https redirect assures a public client's
// identity; a custom scheme or a loopback redirect does not.
#[test]
fn a_public_client_is_assured_only_by_a_claimed_https_redirect() {
    for (redirect, assured) in [
        ("https://app.example.org/callback", true),
        ("com.example.app:/callback", false),
        ("http://127.0.0.1:8400/callback", false),
        ("http://[::1]:8400/callback", false),
        ("https://127.0.0.1/callback", false),
        ("https://localhost/callback", false),
    ] {
        let client = admit(&redirecting(AuthMethod::None, redirect, false)).expect("admitted");
        assert_eq!(assured, client.assured_by(redirect), "{redirect}");
    }
}

#[test]
fn a_confidential_client_is_assured_whatever_its_redirect() {
    let redirect = "com.example.app:/callback";
    let client = admit(&redirecting(AuthMethod::PrivateKeyJwt, redirect, false)).expect("admitted");
    assert!(
        client.assured_by(redirect),
        "it authenticates at the token endpoint"
    );
}

// NOTE: RFC 8252 §8.6, client apply warns of a public app no sign-in can assure,
// since every one would show the consent page the registration would spare.
#[test]
fn a_public_app_without_a_claimed_https_redirect_is_warned_of() {
    let warned = |kind, redirect, first_party| {
        let client = admit(&redirecting(kind, redirect, first_party)).expect("admitted");
        ferrosmart::clients::unassured_public(&client)
    };
    let warning = warned(AuthMethod::None, "com.example.app:/callback", true);
    assert!(
        warning
            .as_deref()
            .is_some_and(|text| text.contains("\"app\"")),
        "{warning:?}"
    );
    assert!(
        warned(AuthMethod::None, "http://127.0.0.1:8400/callback", true).is_some(),
        "a loopback redirect"
    );
    assert!(
        warned(AuthMethod::None, "https://app.example.org/callback", true).is_none(),
        "a claimed https redirect"
    );
    assert!(
        warned(AuthMethod::None, "com.example.app:/callback", false).is_some(),
        "an app of another party"
    );
    assert!(
        warned(AuthMethod::PrivateKeyJwt, "com.example.app:/callback", true).is_none(),
        "a confidential client"
    );
}

// NOTE: OpenID Connect Dynamic Client Registration 1.0 §2, default_acr_values;
// FerroSMART knows the eIDAS levels (docs/architecture.md §13.28).
#[test]
fn default_acr_values_name_eidas_levels_alone() {
    let with = |values: &[&str]| ClientMetadata {
        default_acr_values: values.iter().map(|value| String::from(*value)).collect(),
        ..backend("export")
    };
    let client = admit(&with(&[
        "http://eidas.europa.eu/LoA/high",
        "http://eidas.europa.eu/LoA/substantial",
    ]))
    .expect("admitted");
    assert_eq!(
        Some(ferrohealth_smart::assurance::AssuranceLevel::Substantial),
        client.default_acr(),
        "any listed value answers, so the lowest"
    );
    assert!(matches!(
        admit(&with(&["urn:example:loa:2"])),
        Err(ClientError::Rule { .. })
    ));
}
