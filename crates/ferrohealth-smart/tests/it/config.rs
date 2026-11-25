// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The configuration sections: what each resolves to, and every rule that
//! refuses the start.

use std::time::Duration;

use ferrohealth_smart::basic::PasswordStore;
use ferrohealth_smart::basic::StoreError;
use ferrohealth_smart::client::ClientAuth;
use ferrohealth_smart::client::Endpoint;
use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::BasicGrants;
use ferrohealth_smart::config::BasicSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::credentials::CredentialsSection;
use ferrohealth_smart::config::credentials::Outbound;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::resource::Settings;

/// Returns a section of `top` keys and one `persons` issuer table.
fn one_issuer(top: &str) -> AuthSection {
    toml::from_str(&format!(
        "{top}\n[issuer.i1]\nissuer = \"https://as.example.org\"\naudience = [\"a\"]\n"
    ))
    .expect("the section parses")
}

#[test]
fn each_issuer_table_carries_its_own_settings() {
    let section: AuthSection = toml::from_str(
        r#"
        realm = "ferrobridge"

        [issuer.i2]
        issuer = "https://one.example.org"
        audience = ["https://bridge.example.org/fhir"]

        [issuer.i3]
        issuer = "https://two.example.org"
        audience = ["https://other.example.org"]
        clock_skew = "10s"
        jwks_file = "/etc/ferro/two.jwks"
        role_claims = []
        "#,
    )
    .expect("the section parses");
    assert_eq!(2, section.issuer.len(), "two issuer tables");
    let resolved = section.resolve(&[]).expect("the section resolves");
    assert_eq!(2, resolved.issuers.len());
    let one = &resolved.issuers[0];
    assert_eq!(IssuerKind::Smart, one.kind);
    assert_eq!(
        vec![String::from("https://bridge.example.org/fhir")],
        one.audience
    );
    assert_eq!(
        Duration::from_secs(60),
        one.clock_skew,
        "the table's default"
    );
    assert_eq!(Duration::from_secs(600), one.jwks_max_age);
    assert_eq!(3, one.role_claims.len(), "RFC 9068 §2.2.3.1 defaults");
    let two = &resolved.issuers[1];
    assert_eq!(IssuerKind::Smart, two.kind);
    assert_eq!(Duration::from_secs(10), two.clock_skew);
    assert_eq!(
        Some(std::path::PathBuf::from("/etc/ferro/two.jwks")),
        two.jwks_file
    );
    assert_eq!(Vec::<String>::new(), two.role_claims);
    assert_eq!(Some(String::from("ferrobridge")), resolved.realm);
    assert_eq!(
        Some(&IssuerKind::Smart),
        resolved.kinds.get("https://two.example.org")
    );
    assert!(resolved.basic.is_none());
}

#[test]
fn a_section_that_breaks_a_rule_refuses_the_start() {
    let unknown = toml::from_str::<AuthSection>("jwks_refresh_interval_ms = 1000");
    assert!(unknown.is_err(), "deny_unknown_fields");
    let none = AuthSection::default();
    assert!(matches!(
        none.resolve(&[]),
        Err(ConfigError::Missing { key: "auth.issuer" })
    ));
    let table = |extra: &str| -> AuthSection {
        toml::from_str(&format!(
            "[issuer.i4]\nissuer = \"https://as.example.org\"\naudience = [\"a\"]\n{extra}"
        ))
        .expect("parses")
    };
    assert!(matches!(
        table("clock_skew = \"301s\"").resolve(&[]),
        Err(ConfigError::Issuer { .. })
    ));
    assert!(
        toml::from_str::<AuthSection>(
            "[issuer.i4]\nissuer = \"https://as.example.org\"\naudience = [\"a\"]\nalgorithms = [\"HS256\"]"
        )
        .is_err(),
        "RFC 8725 §3.1: no issuer table can name a symmetric algorithm"
    );
    let off: AuthSection = toml::from_str("enabled = false").expect("parses");
    assert_eq!(
        off.resolve(&[]).expect("resolves").issuers,
        Vec::<Settings>::new()
    );
    let both: AuthSection = toml::from_str(
        r#"
        [issuer.i5]
        issuer = "https://as.example.org"
        audience = ["a"]
        [[basic.users]]
        user = "etl"
        password_hash = "$argon2id$v=19$m=19456,t=2,p=1$c3ludGhldGljLXNhbHQtMTY$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        password_hash_file = "/run/secrets/etl.phc"
        "#,
    )
    .expect("parses");
    assert!(matches!(both.resolve(&[]), Err(ConfigError::Secret { .. })));
}

#[test]
fn the_credentials_table_is_basic_or_oauth_and_never_both() {
    let basic: CredentialsSection =
        toml::from_str("user = \"bridge\"\npassword = \"synthetic\"").expect("parses");
    assert!(matches!(basic.resolve(), Ok(Some(Outbound::Basic(_)))));
    let empty: CredentialsSection = toml::from_str("").expect("parses");
    assert!(matches!(empty.resolve(), Ok(None)));
    let both: CredentialsSection = toml::from_str(
        "user = \"bridge\"\npassword = \"x\"\n[oauth]\nissuer = \"https://as.example.org\"\nclient_id = \"c\"\nclient_secret = \"s\"",
    )
    .expect("parses");
    assert!(matches!(both.resolve(), Err(ConfigError::Exclusive { .. })));
    let oauth: CredentialsSection = toml::from_str(
        r#"
        [oauth]
        token_endpoint = "https://as.example.org/token"
        client_id = "ferrobridge"
        client_auth = "client_secret_post"
        client_secret = "synthetic"
        scope = "system/CodeSystem.rs"
        resource = "https://term.example.org/fhir"
        refresh_margin = "5s"
        "#,
    )
    .expect("parses");
    let Ok(Some(Outbound::Oauth(grant))) = oauth.resolve() else {
        panic!("the grant resolves");
    };
    assert_eq!(ClientAuth::ClientSecretPost, grant.client_auth);
    assert!(matches!(grant.endpoint, Endpoint::Token(_)));
    assert_eq!(Some(String::from("system/CodeSystem.rs")), grant.scope);
    assert_eq!(Duration::from_millis(5000), grant.refresh_margin);
    let keyless: CredentialsSection = toml::from_str(
        "[oauth]\nissuer = \"https://as.example.org\"\nclient_id = \"c\"\nclient_auth = \"private_key_jwt\"",
    )
    .expect("parses");
    assert!(matches!(
        keyless.resolve(),
        Err(ConfigError::Missing {
            key: "credentials.oauth.private_key_file"
        })
    ));
    let two: CredentialsSection = toml::from_str(
        "[oauth]\nissuer = \"https://as.example.org\"\ntoken_endpoint = \"https://as.example.org/token\"\nclient_id = \"c\"\nclient_secret = \"s\"",
    )
    .expect("parses");
    assert!(matches!(two.resolve(), Err(ConfigError::Exclusive { .. })));
}

#[test]
fn a_capability_is_one_smart_defines_or_a_full_uri() {
    let section = one_issuer(
        r#"capabilities = ["launch-ehr", "context-openehr-episode", "https://example.org/capability/x"]"#,
    );
    let resolved = section.resolve(&[]).expect("every capability is defined");
    assert_eq!(3, resolved.capabilities.len());
    for capability in ["launch-anything", "permission-v3", "x:y", "two words", ""] {
        let section = AuthSection {
            capabilities: vec![String::from(capability)],
            ..AuthSection::default()
        };
        assert!(
            matches!(section.resolve(&[]), Err(ConfigError::Capability { .. })),
            "SMART App Launch 2.2.0, Conformance, Capabilities reserves {capability:?}"
        );
    }
}

#[test]
fn the_product_scope_is_an_extension_scope() {
    let section = one_issuer("product_scope = \"__ferro.operator\"");
    assert_eq!(
        Some(String::from("__ferro.operator")),
        section.resolve(&[]).expect("resolves").product_scope
    );
    let none = one_issuer("");
    assert_eq!(None, none.resolve(&[]).expect("resolves").product_scope);
    for scope in ["ferro.operator", "system/*.rs", "__", "__two words"] {
        let section = AuthSection {
            product_scope: String::from(scope),
            ..AuthSection::default()
        };
        assert!(
            matches!(section.resolve(&[]), Err(ConfigError::ProductScope { .. })),
            "SMART App Launch 2.2.0, Scopes and Launch Context, Extensibility refuses {scope:?}"
        );
    }
}

#[test]
fn the_listed_scopes_reach_the_discovery_options() {
    let section = one_issuer(
        "capabilities = [\"launch-ehr\"]\nscopes_supported = [\"system/Condition.rs\", \"openid\"]",
    );
    let options = section.resolve(&[]).expect("resolves").smart_options();
    assert_eq!(
        vec![String::from("system/Condition.rs"), String::from("openid")],
        options.scopes_supported
    );
    assert_eq!(vec![String::from("launch-ehr")], options.capabilities);
    assert!(
        options.permissions.is_empty(),
        "the product declares the permission capabilities its routes enforce"
    );
    let bad = AuthSection {
        scopes_supported: vec![String::from("two words")],
        ..AuthSection::default()
    };
    assert!(matches!(bad.resolve(&[]), Err(ConfigError::Scope { .. })));
}

#[test]
fn the_grant_checks_its_issuer_and_resource_at_load() {
    let grant = |extra: &str| -> Result<Option<Outbound>, ConfigError> {
        let section: CredentialsSection = toml::from_str(&format!(
            "[oauth]\nclient_id = \"c\"\nclient_secret = \"s\"\n{extra}"
        ))
        .expect("parses");
        section.resolve()
    };
    assert!(matches!(
        grant("issuer = \"https://as.example.org/realms/ferro\""),
        Ok(Some(Outbound::Oauth(_)))
    ));
    for issuer in [
        "http://as.example.org",
        "https://as.example.org/?realm=ferro",
        "https://as.example.org/#ferro",
        "not a url",
    ] {
        assert!(
            matches!(
                grant(&format!("issuer = \"{issuer}\"")),
                Err(ConfigError::OauthIssuer { .. })
            ),
            "RFC 8414 §2 refuses {issuer:?}"
        );
    }
    let endpoint = "token_endpoint = \"https://as.example.org/token\"";
    assert!(matches!(
        grant(&format!(
            "{endpoint}\nresource = \"https://term.example.org/fhir\""
        )),
        Ok(Some(Outbound::Oauth(_)))
    ));
    assert!(
        matches!(
            grant(&format!(
                "{endpoint}\nresource = \"https://term.example.org/fhir#x\""
            )),
            Err(ConfigError::Fragment {
                key: "credentials.oauth.resource"
            })
        ),
        "RFC 8707 §2: the URI MUST NOT include a fragment component"
    );
}

/// A synthetic Argon2id PHC string, which verifies no password.
const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c3ludGhldGljLXNhbHQtMTY$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn an_enabled_section_with_basic_users_and_no_issuer_is_basic_only() {
    let section: AuthSection = toml::from_str(&format!(
        r#"
        enabled = true
        [basic]
        cache_ttl = "30s"
        [[basic.users]]
        user = "etl"
        password_hash = "{PHC}"
        "#
    ))
    .expect("the section parses");
    let resolved = section.resolve(&[]).expect("a Basic-only section resolves");
    assert!(resolved.enabled);
    assert!(resolved.issuers.is_empty(), "no issuer");
    assert_eq!(1, resolved.basic.as_ref().map_or(0, PasswordStore::len));
}

#[test]
fn an_enabled_section_that_admits_no_credential_fails_closed() {
    for text in [
        "enabled = true",
        "enabled = true\n[basic]\nusers = []",
        "enabled = true\n[issuer]",
        "enabled = true\n[issuer]\n[basic]\nusers = []",
    ] {
        let section: AuthSection = toml::from_str(text).expect("parses");
        assert!(
            matches!(
                section.resolve(&[]),
                Err(ConfigError::Missing { key: "auth.issuer" })
            ),
            "{text}"
        );
    }
}

#[test]
fn a_rendered_section_carries_every_key_and_no_secret() {
    let auth: AuthSection = toml::from_str(&format!(
        r#"
        [issuer.i6]
        issuer = "https://as.example.org"
        audience = ["https://fhir.example.org"]
        role_claims = ["roles"]
        [[basic.users]]
        user = "etl"
        password_hash = "{PHC}"
        [[basic.users]]
        user = "ops"
        password_hash_file = "/run/secrets/ops.phc"
        "#
    ))
    .expect("parses");
    let credentials: CredentialsSection = toml::from_str(
        r#"
        user = "bridge"
        password = "synthetic-basic-password"
        "#,
    )
    .expect("parses");
    let oauth: CredentialsSection = toml::from_str(
        r#"
        [oauth]
        token_endpoint = "https://as.example.org/token"
        client_id = "ferro"
        client_secret = "synthetic-client-secret"
        "#,
    )
    .expect("parses");
    let rendered = [
        serde_json::to_string(&auth).expect("serializes"),
        serde_json::to_string(&credentials).expect("serializes"),
        serde_json::to_string(&oauth).expect("serializes"),
        toml::to_string(&auth).expect("renders as TOML"),
        toml::to_string(&oauth).expect("renders as TOML"),
    ];
    for text in &rendered {
        for secret in [PHC, "synthetic-basic-password", "synthetic-client-secret"] {
            assert!(!text.contains(secret), "a secret is rendered: {text}");
        }
    }
    let auth_json = serde_json::to_value(&auth).expect("serializes");
    assert_eq!(
        serde_json::json!("***"),
        auth_json["basic"]["users"][0]["password_hash"]
    );
    assert_eq!(
        serde_json::json!("/run/secrets/ops.phc"),
        auth_json["basic"]["users"][1]["password_hash_file"],
        "a path is no secret"
    );
    assert!(
        auth_json["basic"]["users"][1]
            .get("password_hash")
            .is_none()
    );
    assert_eq!(
        serde_json::json!(["roles"]),
        auth_json["issuer"]["i6"]["role_claims"]
    );
    let oauth_json = serde_json::to_value(&oauth).expect("serializes");
    assert_eq!(
        serde_json::json!("***"),
        oauth_json["oauth"]["client_secret"]
    );
    assert_eq!(serde_json::json!("ferro"), oauth_json["oauth"]["client_id"]);
    let read_back: AuthSection =
        toml::from_str(&rendered[3]).expect("the rendering reads back as a section");
    assert_eq!(
        Some("https://as.example.org"),
        read_back
            .issuer
            .values()
            .next()
            .map(|entry| entry.issuer.expose()),
        "the issuer reads back"
    );
}

/// The userinfo of a token endpoint or an issuer never reaches a rendering
/// of the section, serialized or `Debug`.
#[test]
fn the_grant_masks_the_userinfo_of_its_urls() {
    let oauth = ferrohealth_smart::config::credentials::OauthSection {
        token_endpoint: ferrohealth_secret::secret_url::SecretUrl::new(String::from(
            "https://u:URL_PW_SENTINEL@idp.example.org/token",
        )),
        client_id: String::from("svc"),
        ..ferrohealth_smart::config::credentials::OauthSection::default()
    };
    let rendered = toml::to_string(&oauth).expect("renders");
    let debug = format!("{oauth:?}");
    for shown in [&rendered, &debug] {
        assert!(!shown.contains("URL_PW_SENTINEL"), "{shown}");
        assert!(shown.contains("idp.example.org/token"), "{shown}");
    }
    let issuer = ferrohealth_smart::config::credentials::OauthSection {
        issuer: ferrohealth_secret::secret_url::SecretUrl::new(
            "https://a:ISSUER_PW_SENTINEL@as.example.org",
        ),
        ..ferrohealth_smart::config::credentials::OauthSection::default()
    };
    assert!(
        !toml::to_string(&issuer)
            .expect("renders")
            .contains("ISSUER_PW_SENTINEL")
    );
}

/// Every endpoint URL of `[auth]` and `[<lane>.credentials]` is a
/// `SecretUrl`: a password in its userinfo reaches no rendering, serialized
/// or `Debug`, and the host and path stay (#429).
#[test]
fn every_endpoint_url_masks_its_userinfo_in_every_rendering() {
    let auth: AuthSection = toml::from_str(
        r#"
[issuer.i7]
issuer = "https://idp.example"
audience = ["a"]
[issuer.i7.introspection]
endpoint = "https://u:INTROSPECT_PW@idp.example/introspect"
[issuer.i7.introspection.client]
token_endpoint = "https://u:CLIENT_PW@idp.example/client-token"
client_id = "rs"
[issuer.i7.introspection.bearer]
token_endpoint = "https://u:BEARER_PW@idp.example/bearer-token"
client_id = "rs"
"#,
    )
    .expect("the section parses");
    let credentials: CredentialsSection = toml::from_str(
        r#"
[oauth]
token_endpoint = "https://u:OAUTH_PW@as.example/oauth-token"
client_id = "svc"
[onward]
issuer = "https://onward.example"
token_endpoint = "https://u:ONWARD_PW@onward.example/onward-token"
"#,
    )
    .expect("the section parses");
    let renderings = [
        toml::to_string(&auth).expect("renders"),
        serde_json::to_string(&auth).expect("renders"),
        format!("{auth:?}"),
        toml::to_string(&credentials).expect("renders"),
        serde_json::to_string(&credentials).expect("renders"),
        format!("{credentials:?}"),
    ];
    for (index, shown) in renderings.iter().enumerate() {
        for password in [
            "INTROSPECT_PW",
            "CLIENT_PW",
            "BEARER_PW",
            "OAUTH_PW",
            "ONWARD_PW",
        ] {
            assert!(!shown.contains(password), "rendering {index}: {password}");
        }
    }
    for (index, path) in [
        (0, "idp.example/introspect"),
        (0, "idp.example/client-token"),
        (0, "idp.example/bearer-token"),
        (3, "as.example/oauth-token"),
        (3, "onward.example/onward-token"),
    ] {
        assert!(renderings[index].contains(path), "{path}");
        assert!(renderings[index + 2].contains(path), "Debug: {path}");
    }
}

/// Every issuer identifier of `[auth]` and `[<lane>.credentials]` is a
/// `SecretUrl` too: a password in its userinfo reaches no rendering,
/// serialized or `Debug`, before validation has run (RFC 3986 §3.2.1), and
/// the host stays (#445).
#[test]
fn every_issuer_identifier_masks_its_userinfo_in_every_rendering() {
    let auth: AuthSection = toml::from_str(
        r#"
[issuer.i8]
issuer = "https://u:AUTH_ISSUER_PW@idp.example/realms/r"
audience = ["a"]
"#,
    )
    .expect("the section parses");
    let credentials: CredentialsSection = toml::from_str(
        r#"
[oauth]
issuer = "https://u:OAUTH_ISSUER_PW@as.example/realms/r"
client_id = "svc"
[onward]
issuer = "https://u:ONWARD_ISSUER_PW@onward.example/realms/r"
"#,
    )
    .expect("the section parses");
    let renderings = [
        toml::to_string(&auth).expect("renders"),
        serde_json::to_string(&auth).expect("renders"),
        format!("{auth:?}"),
        toml::to_string(&credentials).expect("renders"),
        serde_json::to_string(&credentials).expect("renders"),
        format!("{credentials:?}"),
    ];
    for (index, shown) in renderings.iter().enumerate() {
        for (table, sentinel) in [
            ("auth.issuer", "AUTH_ISSUER_PW"),
            ("oauth", "OAUTH_ISSUER_PW"),
            ("onward", "ONWARD_ISSUER_PW"),
        ] {
            assert!(!shown.contains(sentinel), "rendering {index}: {table}");
        }
    }
    for (index, host) in [
        (0, "idp.example/realms/r"),
        (3, "as.example/realms/r"),
        (3, "onward.example/realms/r"),
    ] {
        for offset in 0..3 {
            assert!(
                renderings[index + offset].contains(host),
                "{offset}: {host}"
            );
        }
    }
    let first = auth.issuer.values().next().expect("the issuer");
    assert_eq!(
        "https://u:AUTH_ISSUER_PW@idp.example/realms/r",
        first.issuer.expose(),
        "the identifier itself is held as written"
    );
}

/// An `[auth.issuer.<name>]` table with its attributes, federation and
/// party tables nested under it holds its identifier as a `SecretUrl`: a
/// password in its userinfo reaches no rendering, serialized or `Debug`,
/// nor the refusal of the start (RFC 3986 §3.2.1, #456).
#[test]
fn every_table_of_an_issuer_masks_its_userinfo() {
    let auth: AuthSection = toml::from_str(
        r#"
[issuer.i10]
issuer = "https://u:TABLE_ISSUER_PW@idp.example/realms/r"
audience = ["a"]

[issuer.i10.attributes]
mapping = "iua"

[issuer.i10.federation]
contact_point = false

[issuer.i10.party]
identifier_issuer = "urn:example:people"
identifier_type = "guid"
"#,
    )
    .expect("the section parses");
    let refused = auth
        .clone()
        .resolve(&[])
        .expect_err("the userinfo is refused");
    let renderings = [
        toml::to_string(&auth).expect("renders"),
        serde_json::to_string(&auth).expect("renders"),
        format!("{auth:?}"),
        format!("{refused} {refused:?}"),
    ];
    for (index, shown) in renderings.iter().enumerate() {
        assert!(
            !shown.contains("TABLE_ISSUER_PW"),
            "rendering {index}: an issuer's password"
        );
        assert!(
            shown.contains("idp.example/realms/r"),
            "rendering {index}: the host"
        );
    }
    for table in ["attributes", "federation", "party"] {
        assert_eq!(
            1,
            renderings[0]
                .matches(&format!("[issuer.i10.{table}]"))
                .count(),
            "{table} renders"
        );
    }
}

/// Every problem of a grant is named under the product's own table, at once.
#[test]
fn the_grant_names_every_problem_under_the_products_table() {
    let empty = ferrohealth_smart::config::credentials::OauthSection::default();
    let problems = empty.problems("terminology.server.oauth");
    let joined = problems.join("\n");
    for key in [
        "terminology.server.oauth: set issuer or token_endpoint",
        "terminology.server.oauth.client_id",
        "terminology.server.oauth requires client_secret or client_secret_file",
    ] {
        assert!(joined.contains(key), "{key} unnamed in {joined}");
    }
    assert!(!joined.contains("credentials.oauth"), "{joined}");
    let both = ferrohealth_smart::config::credentials::OauthSection {
        issuer: ferrohealth_secret::secret_url::SecretUrl::new("https://as.example.org"),
        token_endpoint: ferrohealth_secret::secret_url::SecretUrl::new(String::from(
            "https://as.example.org/token",
        )),
        client_id: String::from("svc"),
        client_secret: Some(secrecy::SecretString::from("s")),
        client_secret_file: Some(std::path::PathBuf::from("/run/secret")),
        resource: String::from("https://rs.example.org/#frag"),
        ..ferrohealth_smart::config::credentials::OauthSection::default()
    };
    let problems = both.problems("audit.fhir_feed.oauth").join("\n");
    for key in [
        "set one of issuer and token_endpoint",
        "set one of client_secret and client_secret_file",
        "audit.fhir_feed.oauth.resource carries a fragment",
    ] {
        assert!(problems.contains(key), "{key} unnamed in {problems}");
    }
    let mutual = ferrohealth_smart::config::credentials::OauthSection {
        token_endpoint: ferrohealth_secret::secret_url::SecretUrl::new(String::from(
            "https://as.example.org/token",
        )),
        client_id: String::from("svc"),
        client_auth: ClientAuth::TlsClientAuth,
        ..ferrohealth_smart::config::credentials::OauthSection::default()
    };
    let problems = mutual.problems("audit.fhir_feed.oauth").join("\n");
    assert!(
        problems.contains(
            "audit.fhir_feed.oauth.tls.client_identity_file is required by a mutual-TLS client_auth"
        ),
        "{problems}"
    );
    let sound = ferrohealth_smart::config::credentials::OauthSection {
        token_endpoint: ferrohealth_secret::secret_url::SecretUrl::new(String::from(
            "https://as.example.org/token",
        )),
        client_id: String::from("svc"),
        client_secret: Some(secrecy::SecretString::from("s")),
        ..ferrohealth_smart::config::credentials::OauthSection::default()
    };
    assert_eq!(sound.problems("x"), Vec::<String>::new());
}

#[test]
fn the_basic_cache_keeps_a_verified_credential_for_five_minutes_unless_set_to_zero() {
    let five = ferrohealth_config::units::Duration::from_mins(5);
    let defaulted: BasicSection = toml::from_str("users = []").expect("the section parses");
    assert_eq!(five, defaulted.cache_ttl);
    assert_eq!(five, BasicSection::default().cache_ttl);
    let off: BasicSection =
        toml::from_str("users = []\ncache_ttl = \"0s\"").expect("the section parses");
    assert!(off.cache_ttl.is_zero());
}

#[test]
fn a_misspelt_key_in_an_issuer_entry_is_refused_by_its_name() {
    let refused = toml::from_str::<AuthSection>(
        r#"
        [issuer.i11]
        issuer = "https://one.example.org"
        jwks_fiel = "/etc/ferro/one.jwks"
        "#,
    )
    .expect_err("an unknown key in an issuer entry is refused");
    assert!(
        refused.to_string().contains("jwks_fiel"),
        "the refusal names the key: {refused}"
    );
}

#[test]
fn an_issuer_that_is_no_table_of_tables_is_refused() {
    let refused = toml::from_str::<AuthSection>("issuer = 7\n").expect_err("a number is no issuer");
    assert!(
        refused.to_string().contains("expected a map"),
        "the refusal says what the key takes: {refused}"
    );
}

// NOTE: a Basic credential is a person's (owner ruling on #215); a `system/` scope is a backend
// service's (SMART App Launch 2.2.0, Scopes and Launch Context), so the grant refuses it (#274).
#[test]
fn a_basic_grant_with_a_system_scope_fails_to_load_naming_the_user_and_the_scope() {
    let section: AuthSection = toml::from_str(&format!(
        r#"
        enabled = true
        [[basic.users]]
        user = "batch-loader"
        password_hash = "{PHC}"
        "#
    ))
    .expect("the section parses");
    let grants: BasicGrants = toml::from_str(
        r#"
        [batch-loader]
        scopes = ["user/CodeSystem.r", "system/CodeSystem.cud"]
        "#,
    )
    .expect("the grants parse");
    let store = section
        .resolve(&[])
        .expect("the credential resolves")
        .basic
        .expect("a Basic store");
    let refused = store.with_grants(&grants);
    let Err(source) = &refused else {
        panic!("a refusal, not {refused:?}");
    };
    let StoreError::SystemScope { username, scope } = source else {
        panic!("a system scope, not {source:?}");
    };
    assert_eq!("batch-loader", username);
    assert_eq!("system/CodeSystem.cud", scope);
    let message = source.to_string();
    assert!(
        message.contains("batch-loader") && message.contains("system/CodeSystem.cud"),
        "{message}"
    );
}

// NOTE: #479: a Basic user's scope and roles are the product's to grant, so the credential table
// refuses both keys as unknown, naming the fields it reads.
#[test]
fn a_basic_user_setting_roles_or_scopes_is_refused_as_an_unknown_key() {
    for key in ["roles = [\"auditor\"]", "scopes = [\"user/*.rs\"]"] {
        let refused = toml::from_str::<AuthSection>(&format!(
            "[[basic.users]]\nuser = \"etl\"\npassword_hash = \"{PHC}\"\n{key}\n"
        ));
        let Err(error) = refused else {
            panic!("{key}: refused, not {refused:?}");
        };
        let message = error.to_string();
        assert!(message.contains("unknown field"), "{key}: {message}");
        assert!(
            message.contains("`user`, `password_hash`, `password_hash_file`"),
            "{key}: {message}"
        );
    }
}

#[test]
fn a_credential_only_basic_user_resolves_and_is_granted_by_the_product() {
    let section: AuthSection = toml::from_str(&format!(
        r#"
        enabled = true
        [[basic.users]]
        user = "etl"
        password_hash = "{PHC}"
        [[basic.users]]
        user = "ops"
        password_hash = "{PHC}"
        "#
    ))
    .expect("the section parses");
    let grants: BasicGrants = toml::from_str(
        r#"
        [etl]
        scopes = ["user/*.rs"]
        roles = ["auditor"]
        "#,
    )
    .expect("the grants parse");
    let store = section
        .resolve(&[])
        .expect("a credential-only section resolves")
        .basic
        .expect("a Basic store")
        .with_grants(&grants)
        .expect("the grants hold");
    assert_eq!(vec!["etl", "ops"], store.users().collect::<Vec<_>>());
}

#[test]
fn a_basic_grant_refuses_an_unknown_key_and_an_unknown_user() {
    let refused = toml::from_str::<BasicGrants>("[etl]\nscope = \"user/*.rs\"\n");
    let Err(error) = refused else {
        panic!("refused, not {refused:?}");
    };
    let message = error.to_string();
    assert!(
        message.contains("unknown field `scope`, expected `scopes` or `roles`"),
        "{message}"
    );
    let grants: BasicGrants =
        toml::from_str("[nobody]\nroles = [\"auditor\"]\n").expect("the grants parse");
    assert!(matches!(
        PasswordStore::new().with_grants(&grants),
        Err(StoreError::UnknownUser { username }) if username == "nobody"
    ));
}

/// Returns an enabled section with one `persons` issuer at `issuer`, its
/// key set read from `jwks_file` when one is given.
fn issuer_at(issuer: &str, jwks_file: Option<&std::path::Path>) -> AuthSection {
    let file = jwks_file.map_or_else(String::new, |path| {
        format!("jwks_file = {:?}\n", path.display().to_string())
    });
    toml::from_str(&format!(
        "enabled = true\n[issuer.i12]\nissuer = \"{issuer}\"\naudience = [\"a\"]\n{file}"
    ))
    .expect("the section parses")
}

#[test]
fn an_issuer_with_userinfo_is_refused_masked() {
    for issuer in [
        "https://user:hunter2@as.example.org",
        "https://user@as.example.org/realms/x",
    ] {
        let refused = issuer_at(issuer, None).resolve(&[]);
        let Err(ConfigError::IssuerUserinfo { issuer: shown }) = &refused else {
            panic!("{issuer} is refused for its userinfo, got {refused:?}");
        };
        assert!(
            !shown.contains("hunter2") && !shown.contains("user@"),
            "{shown}"
        );
        let message = refused.map(|_| ()).unwrap_err().to_string();
        assert!(!message.contains("hunter2"), "{message}");
    }
}

#[test]
fn a_jwks_file_with_a_symmetric_key_is_refused_naming_the_key() {
    let file = crate::support::temp_file(
        "symmetric.jwks",
        br#"{"keys":[{"kty":"RSA","kid":"rsa","n":"AQAB","e":"AQAB"},{"kty":"oct","kid":"shared","k":"c2VjcmV0"}]}"#,
    );
    let refused = issuer_at("https://as.example.org", Some(&file)).resolve(&[]);
    assert!(
        matches!(
            &refused,
            Err(ConfigError::JwksSymmetricKey { index: 1, kid: Some(kid), .. }) if kid == "shared"
        ),
        "{refused:?}"
    );
    assert!(!format!("{refused:?}").contains("c2VjcmV0"));
}

#[test]
fn a_jwks_file_with_private_key_material_is_refused_naming_the_member() {
    let file = crate::support::temp_file(
        "private.jwks",
        br#"{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"AA","d":"cHJpdmF0ZQ"}]}"#,
    );
    let refused = issuer_at("https://as.example.org", Some(&file)).resolve(&[]);
    assert!(
        matches!(
            &refused,
            Err(ConfigError::JwksPrivateKey {
                index: 0,
                kid: None,
                member: "d",
                ..
            })
        ),
        "{refused:?}"
    );
    assert!(
        !refused
            .map(|_| ())
            .unwrap_err()
            .to_string()
            .contains("cHJpdmF0ZQ")
    );
}

#[test]
fn a_basic_hash_below_the_owasp_floor_is_refused_naming_the_user_and_the_floor() {
    for weak in ["m=8,t=1,p=1", "m=19456,t=1,p=1", "m=19455,t=2,p=1"] {
        let phc = PHC.replace("m=19456,t=2,p=1", weak);
        let section: AuthSection = toml::from_str(&format!(
            "enabled = true\n[[basic.users]]\nuser = \"etl\"\npassword_hash = \"{phc}\"\n"
        ))
        .expect("the section parses");
        let refused = section.resolve(&[]);
        let Err(ConfigError::Basic {
            source: source @ StoreError::Weak { username, .. },
        }) = &refused
        else {
            panic!("{weak} is refused as weak, got {refused:?}");
        };
        assert_eq!(username, "etl");
        assert!(source.to_string().contains("m=19456,t=2,p=1"), "{source}");
    }
}

// NOTE: no specification governs the configuration model: our own design, in which
// a resource server holds one table per issuer, so a second table naming it is refused.
#[test]
fn one_issuer_in_two_tables_is_refused_naming_both() {
    let section: AuthSection = toml::from_str(
        "[issuer.i13]\nissuer = \"https://user:secret@as.example.org\"\naudience = [\"a\"]\n\
         [issuer.i14]\nissuer = \"https://as.example.org\"\naudience = [\"a\"]\n\
         [issuer.i15]\nissuer = \"https://user:secret@as.example.org\"\naudience = [\"a\"]\n",
    )
    .expect("the section parses");
    let refused = section.resolve(&[]);
    let Err(ConfigError::DuplicateIssuer {
        key,
        issuer,
        first,
        second,
    }) = &refused
    else {
        panic!("a duplicate issuer is refused: {refused:?}");
    };
    assert_eq!("auth.issuer", *key);
    assert_eq!(
        ("i13", "i15"),
        (first.as_str(), second.as_str()),
        "both tables named"
    );
    assert!(
        !issuer.contains("secret"),
        "the userinfo is masked: {issuer}"
    );
    let shown = refused
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(!shown.contains("secret"), "{shown}");
}

/// The section of one SMART issuer table, with `extra` keys.
fn smart_issuer(extra: &str) -> AuthSection {
    toml::from_str(&format!(
        "[issuer.smart]\nissuer = \"https://smart.example.org\"\n\
         jwks_file = \"/dev/null\"\n{extra}"
    ))
    .expect("the section parses")
}

// NOTE: RFC 9068 §4, the resource server checks `aud` against itself; no
// specification governs the default: our own design (#730), its own base URLs.
#[test]
fn the_audience_defaults_to_the_bases_the_product_resolves_for() {
    let base = "https://ehr.example.org/openehr/v1";
    let resolved = smart_issuer("").resolve(&[base]).expect("resolves");
    let settings = resolved.issuers.first().expect("one issuer");
    assert_eq!(vec![String::from(base)], settings.audience);
    let resolved = smart_issuer("audience = [\"https://other.example.org\"]\n")
        .resolve(&[base])
        .expect("resolves");
    let settings = resolved.issuers.first().expect("one issuer");
    assert_eq!(
        vec![String::from("https://other.example.org")],
        settings.audience,
        "an explicit audience wins"
    );
    assert!(
        smart_issuer("").resolve(&[]).is_err(),
        "no audience at all is refused"
    );
}

// NOTE: SMART App Launch 2.2.0: every issuer is a SMART authorization server
// unless its table declares `kind = "federation"`.
#[test]
fn an_issuer_table_names_only_its_issuer() {
    let base = ["https://ehr.example.org"];
    let resolved = smart_issuer("").resolve(&base).expect("resolves");
    assert_eq!(
        Some(&IssuerKind::Smart),
        resolved.kinds.get("https://smart.example.org")
    );
    assert_eq!(
        Some(String::from("https://smart.example.org")),
        resolved.names.get("smart").cloned(),
        "the issuer reads by its name"
    );
}

// NOTE: no specification governs the party binding: our own design (#730), the
// issuer's identifier and FerroSMART's pairwise `sub` when the table names none.
#[test]
fn the_party_table_defaults_to_the_issuer_and_the_pairwise_identifier_type() {
    let base = ["https://ehr.example.org"];
    let resolved = smart_issuer("[issuer.smart.party]\n")
        .resolve(&base)
        .expect("resolves");
    let table = resolved.party.first().expect("one party table");
    assert_eq!("https://smart.example.org", table.issuer.expose());
    assert_eq!("https://smart.example.org", table.identifier_issuer);
    assert_eq!("pairwise", table.identifier_type);
    let resolved = smart_issuer(
        "[issuer.smart.party]\nidentifier_issuer = \"urn:example:login\"\nidentifier_type = \"login\"\n",
    )
    .resolve(&base)
    .expect("resolves");
    let table = resolved.party.first().expect("one party table");
    assert_eq!(
        "urn:example:login", table.identifier_issuer,
        "explicit wins"
    );
    assert_eq!("login", table.identifier_type, "explicit wins");
}

#[test]
fn a_profile_key_on_the_issuer_table_itself_is_unknown() {
    let old: Result<AuthSection, _> =
        toml::from_str("[issuer.own]\nissuer = \"https://idp.example.org\"\nmax_actor_chain = 2\n");
    assert!(old.is_err(), "profile keys sit in the profile table");
}
