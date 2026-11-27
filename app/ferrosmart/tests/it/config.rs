// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! What the configuration refuses, each refusal its own case.

use ferrosmart::config::error::Error;

use crate::support::{ASSURANCE, Keys, config, ec_key};

#[test]
fn a_configuration_with_an_issuer_and_a_key_resolves() {
    let keys = Keys::new();
    let settings = config(
        "[ferrosmart]\nissuer = \"https://smart.example.org\"",
        &keys,
    )
    .resolve()
    .expect("resolves");
    assert_eq!("https://smart.example.org", settings.issuer);
    assert_eq!(
        300,
        settings.access_token_lifetime.as_secs(),
        "five minutes"
    );
    assert_eq!(
        "https://smart.example.org/token",
        settings.endpoint("/token")
    );
    assert_eq!(
        "/.well-known/oauth-authorization-server",
        settings.metadata_path()
    );
}

#[test]
fn an_issuer_with_a_path_serves_under_it_and_its_metadata_beside_it() {
    let keys = Keys::new();
    let settings = config(
        "[server]\nbase_path = \"/smart\"\n[ferrosmart]\nissuer = \"https://example.org/smart\"",
        &keys,
    )
    .resolve()
    .expect("resolves");
    assert_eq!("https://example.org/smart/jwks", settings.endpoint("/jwks"));
    // NOTE: RFC 8414 §3, the well-known suffix between the host and the path.
    assert_eq!(
        "/.well-known/oauth-authorization-server/smart",
        settings.metadata_path()
    );
}

#[test]
fn a_missing_issuer_is_refused() {
    let keys = Keys::new();
    assert!(matches!(
        config("", &keys).resolve(),
        Err(Error::Missing {
            key: "ferrosmart.issuer"
        })
    ));
}

#[test]
fn an_issuer_outside_rfc_8414_is_refused() {
    let keys = Keys::new();
    for issuer in [
        "http://smart.example.org",
        "https://smart.example.org/?tenant=1",
        "https://smart.example.org/#top",
        "no url",
    ] {
        assert!(
            matches!(
                config(&format!("[ferrosmart]\nissuer = {issuer:?}"), &keys).resolve(),
                Err(Error::Issuer { .. })
            ),
            "{issuer}"
        );
    }
}

#[test]
fn an_issuer_path_other_than_the_base_path_is_refused() {
    let keys = Keys::new();
    assert!(matches!(
        config(
            "[ferrosmart]\nissuer = \"https://example.org/smart\"",
            &keys
        )
        .resolve(),
        Err(Error::IssuerPath)
    ));
}

#[test]
fn a_style_url_other_than_https_is_refused() {
    let keys = Keys::new();
    for style in ["http://ehr.example.org/style.json", "style.json"] {
        let refused = config(
            &format!(
                "[ferrosmart]\nissuer = \"https://smart.example.org\"\n\
                 [ferrosmart.branding]\nsmart_style_url = {style:?}"
            ),
            &keys,
        )
        .resolve();
        assert!(matches!(refused, Err(Error::StyleUrl)), "{style}");
    }
}

#[test]
fn the_audit_feed_is_optional_and_https_only() {
    let keys = Keys::new();
    let base = "[ferrosmart]\nissuer = \"https://smart.example.org\"\n";
    let local = config(base, &keys)
        .resolve()
        .expect("resolves without a feed");
    assert!(local.audit.feed.is_none(), "the records stay in the store");
    assert_eq!(
        "smart.example.org", local.audit.observer.source_id,
        "the issuer's host"
    );
    let fed = config(
        &format!("{base}[ferrosmart.audit.feed]\nurl = \"https://audit.example.org/fhir\""),
        &keys,
    )
    .resolve()
    .expect("resolves with a feed");
    assert!(fed.audit.feed.is_some(), "the records are forwarded");
    // NOTE: ihe-atna 0.22.0 FeedRepository::new, a record names people, so the feed is https.
    let cleartext = config(
        &format!("{base}[ferrosmart.audit.feed]\nurl = \"http://audit.example.org/fhir\""),
        &keys,
    )
    .resolve();
    assert!(
        matches!(cleartext, Err(Error::AuditBase { .. })),
        "an http repository is refused"
    );
}

#[test]
fn a_zero_token_lifetime_is_refused() {
    let keys = Keys::new();
    assert!(matches!(
        config(
            "[ferrosmart]\nissuer = \"https://smart.example.org\"\naccess_token_lifetime = \"0s\"",
            &keys
        )
        .resolve(),
        Err(Error::Zero {
            key: "ferrosmart.access_token_lifetime"
        })
    ));
}

// NOTE: SMART App Launch 2.2.0, App Launch, Response: no greater than one hour.
#[test]
fn a_token_lifetime_over_one_hour_is_refused() {
    let keys = Keys::new();
    let with = |lifetime: &str| {
        config(
            &format!(
                "[ferrosmart]\nissuer = \"https://smart.example.org\"\naccess_token_lifetime = \"{lifetime}\""
            ),
            &keys,
        )
    };
    assert!(with("1h").resolve().is_ok(), "one hour is the most");
    assert!(matches!(with("61min").resolve(), Err(Error::LongLifetime)));
}

#[test]
fn the_refresh_idle_times_default_and_refuse_zero() {
    let keys = Keys::new();
    let settings = config(
        "[ferrosmart]\nissuer = \"https://smart.example.org\"",
        &keys,
    )
    .resolve()
    .expect("resolves");
    assert_eq!(30 * 86_400, settings.refresh_idle.as_secs(), "thirty days");
    assert_eq!(8 * 3600, settings.online_idle.as_secs(), "eight hours");
    for key in ["refresh_idle", "online_idle"] {
        let text = format!("[ferrosmart]\nissuer = \"https://smart.example.org\"\n{key} = \"0s\"");
        let refused = config(&text, &keys).resolve();
        assert!(
            matches!(&refused, Err(Error::Zero { key: named }) if named.ends_with(key)),
            "{key}"
        );
    }
}

#[test]
fn a_missing_or_unreadable_key_is_refused() {
    let keys = Keys::new();
    let missing = format!(
        "[ferrosmart]\nissuer = \"https://smart.example.org\"\n[ferrosmart.keys]\nprivate_key_files = [{:?}]",
        keys.dir.path().join("absent.pem").display().to_string()
    );
    assert!(matches!(
        config(&missing, &keys).resolve(),
        Err(Error::KeyFile {
            key: "ferrosmart.keys.private_key_files",
            ..
        })
    ));
    let none = ferrosmart::config::Config::from_sources(
        Some(&format!(
            "[ferrosmart]\nissuer = \"https://smart.example.org\"\n[ferrosmart.database]\nurl = {:?}",
            crate::support::UNREACHED_DATABASE
        )),
        &std::collections::BTreeMap::new(),
    )
    .expect("reads");
    assert!(matches!(
        none.resolve(),
        Err(Error::Missing {
            key: "ferrosmart.keys.private_key_files"
        })
    ));
}

#[test]
fn a_key_that_cannot_sign_rs256_is_refused() {
    let keys = Keys::new();
    let ec = ec_key(keys.dir.path(), "ec.pem");
    let text = format!(
        "[ferrosmart]\nissuer = \"https://smart.example.org\"\n[ferrosmart.keys]\nprivate_key_files = [{:?}]",
        ec.display().to_string()
    );
    assert!(matches!(
        config(&text, &keys).resolve(),
        Err(Error::TokenKeyType { .. })
    ));
}

#[test]
fn a_ring_that_names_one_key_twice_is_refused() {
    let keys = Keys::new();
    let text = format!(
        "[ferrosmart]\nissuer = \"https://smart.example.org\"\n[ferrosmart.keys]\nprivate_key_files = [{current:?}, {current:?}]",
        current = keys.current.display().to_string()
    );
    assert!(matches!(
        config(&text, &keys).resolve(),
        Err(Error::RepeatedKey { .. })
    ));
}

#[test]
fn an_unknown_key_is_refused_when_the_file_loads() {
    let refused = ferrosmart::config::Config::from_sources(
        Some("[ferrosmart]\nissuer = \"https://smart.example.org\"\nsigning_key = \"x\""),
        &std::collections::BTreeMap::new(),
    );
    assert!(matches!(refused, Err(Error::Load(_))));
}

// NOTE: RFC 6749 §2, registration is the server's: a client lives in the store alone.
#[test]
fn a_client_table_is_refused_as_an_unknown_key() {
    let refused = ferrosmart::config::Config::from_sources(
        Some(
            "[ferrosmart]\nissuer = \"https://smart.example.org\"\n\
             [[ferrosmart.client]]\nclient_id = \"app\"\nkind = \"public\"",
        ),
        &std::collections::BTreeMap::new(),
    );
    assert!(matches!(refused, Err(Error::Load(_))));
}

#[test]
fn a_missing_database_url_is_refused() {
    let keys = Keys::new();
    let text = format!(
        "[ferrosmart]\nissuer = \"https://smart.example.org\"\n[ferrosmart.database]\nmax_connections = 4\n[ferrosmart.keys]\nprivate_key_files = [{:?}]",
        keys.current.display().to_string()
    );
    assert!(matches!(
        config(&text, &keys).resolve(),
        Err(Error::Secret(_))
    ));
}

// NOTE: openEHR ITS-REST 1.1.0, ehr_get_by_subject, the namespace an EHR is looked
// up by is matched against `EHR_STATUS.subject`, which only an openEHR server holds.
#[test]
fn a_subject_namespace_belongs_to_an_openehr_base_and_is_never_empty() {
    let keys = Keys::new();
    let with = |kind: &str, namespace: &str| {
        config(
            &format!(
                "[ferrosmart]\nissuer = \"https://smart.example.org\"\n\
                 [[ferrosmart.resource]]\nbase = \"https://ehr.example.org/openehr/v1\"\n\
                 kind = {kind:?}\nsubject_namespace = {namespace:?}"
            ),
            &keys,
        )
        .resolve()
        .map_err(Box::new)
    };
    let settings = with("openehr", "examples").expect("resolves");
    assert_eq!(
        Some("examples"),
        settings
            .subject_namespaces
            .get("https://ehr.example.org/openehr/v1")
            .map(String::as_str)
    );
    for (kind, namespace) in [("fhir", "examples"), ("openehr", " ")] {
        let refused = with(kind, namespace).map(|_| ()).map_err(|error| *error);
        assert!(
            matches!(refused, Err(Error::Resource { .. })),
            "{kind} {namespace:?}"
        );
    }
}

// NOTE: docs/architecture.md §13.6 item 9 (#674), a fhirUser lookup searches a FHIR
// base by an identifier whose claim and absolute system the deployment names.
#[test]
fn a_fhir_user_lookup_belongs_to_a_fhir_base_with_a_claim_and_a_system() {
    let keys = Keys::new();
    let with = |kind: &str, claim: &str, system: &str| {
        config(
            &format!(
                "[ferrosmart]\nissuer = \"https://smart.example.org\"\n\
                 [[ferrosmart.resource]]\nbase = \"https://ehr.example.org/api\"\nkind = {kind:?}\n\
                 [[ferrosmart.resource.fhir_user_lookup]]\nresource_type = \"Patient\"\n\
                 claim = {claim:?}\nsystem = {system:?}"
            ),
            &keys,
        )
        .resolve()
        .map_err(Box::new)
    };
    let settings = with("fhir", "staff_id", "urn:example:staff").expect("resolves");
    assert_eq!(
        Some(1),
        settings
            .fhir_user_lookups
            .get("https://ehr.example.org/api")
            .map(Vec::len)
    );
    for (kind, claim, system) in [
        ("openehr", "staff_id", "urn:example:staff"),
        ("fhir", " ", "urn:example:staff"),
        ("fhir", "staff_id", "not a uri"),
    ] {
        let refused = with(kind, claim, system)
            .map(|_| ())
            .map_err(|error| *error);
        assert!(
            matches!(refused, Err(Error::Resource { .. })),
            "{kind} {claim:?} {system:?}"
        );
    }
}

// NOTE: SMART on openEHR draft, Service Discovery, `org.fhir.rest` is the FHIR API
// of a platform whose openEHR API is `org.openehr.rest`; the pair is configuration.
#[test]
fn a_fhir_base_pairs_an_openehr_base_with_a_configured_fhir_server() {
    const OPENEHR: &str = "https://ehr.example.org/openehr/v1";
    const FHIR: &str = "https://ehr.example.org/fhir";
    let keys = Keys::new();
    let with = |tables: &str| {
        config(
            &format!("[ferrosmart]\nissuer = \"https://smart.example.org\"\n{tables}"),
            &keys,
        )
        .resolve()
        .map_err(Box::new)
    };
    let fhir = format!("[[ferrosmart.resource]]\nbase = {FHIR:?}\n");
    let openehr = |keys: &str| {
        format!("[[ferrosmart.resource]]\nbase = {OPENEHR:?}\nkind = \"openehr\"\n{keys}\n")
    };
    let paired = format!(
        "subject_namespace = \"examples\"\nfhir_base = {FHIR:?}\nsubject_system = \"urn:example:mrn\""
    );
    let settings = with(&format!("{fhir}{}", openehr(&paired))).expect("resolves");
    let pairing = settings.pairings.get(OPENEHR).expect("a pairing");
    assert_eq!(FHIR, pairing.fhir_base);
    assert_eq!("urn:example:mrn", pairing.subject_system);
    assert!(
        !settings.pairings.contains_key(FHIR),
        "the FHIR base is paired with nothing"
    );
    let refused = [
        ("no FHIR base of that URL is configured", openehr(&paired)),
        (
            "the paired base is itself openEHR",
            format!(
                "{}[[ferrosmart.resource]]\nbase = {FHIR:?}\nkind = \"openehr\"\n",
                openehr(&paired)
            ),
        ),
        (
            "no subject system",
            format!(
                "{fhir}{}",
                openehr(&format!(
                    "subject_namespace = \"examples\"\nfhir_base = {FHIR:?}"
                ))
            ),
        ),
        (
            "a subject system and no FHIR base",
            format!(
                "{fhir}{}",
                openehr("subject_namespace = \"examples\"\nsubject_system = \"urn:example:mrn\"")
            ),
        ),
        (
            "an empty subject system",
            format!(
                "{fhir}{}",
                openehr(&format!(
                    "subject_namespace = \"examples\"\nfhir_base = {FHIR:?}\nsubject_system = \" \""
                ))
            ),
        ),
        (
            "no subject namespace",
            format!(
                "{fhir}{}",
                openehr(&format!(
                    "fhir_base = {FHIR:?}\nsubject_system = \"urn:example:mrn\""
                ))
            ),
        ),
        (
            "a FHIR base that names a pair",
            format!(
                "{fhir}fhir_base = {FHIR:?}\nsubject_system = \"urn:example:mrn\"\n{}",
                openehr("subject_namespace = \"examples\"")
            ),
        ),
    ];
    for (why, tables) in refused {
        let answer = with(&tables).map(|_| ()).map_err(|error| *error);
        assert!(matches!(answer, Err(Error::Resource { .. })), "{why}");
    }
}

/// The upstream table with `extra` under it, the issuer of every case, and
/// `keys`' current key as the token key.
fn upstream(keys: &Keys, extra: &str) -> String {
    let current = keys.current.display().to_string();
    format!(
        "[ferrosmart]\nissuer = \"https://smart.example.org\"\n\
         [ferrosmart.keys]\nprivate_key_files = [{current:?}]\n\
         [[ferrosmart.upstream]]\nname = \"idp\"\n{ASSURANCE}\
         [ferrosmart.upstream.oidc]\nissuer = \"https://idp.example.org\"\nclient_id = \"ferrosmart\"\n{extra}"
    )
}

/// The `[ferrosmart.upstream.oidc.private_key_jwt]` table with `extra` in it and
/// a fresh assertion key under `keys`.
fn private_key_jwt(keys: &Keys, extra: &str) -> String {
    let key = crate::support::rsa_key(keys.dir.path(), "assertion.pem");
    upstream(
        keys,
        &format!(
            "[ferrosmart.upstream.oidc.private_key_jwt]\n{extra}\n\
             [ferrosmart.upstream.oidc.private_key_jwt.keys]\nprivate_key_file = {:?}\n",
            key.display().to_string()
        ),
    )
}

// NOTE: OpenID Connect Core 1.0 §9: a secret is named only in the client_secret_basic table (#679).
#[test]
fn an_upstream_client_secret_is_refused_when_the_file_loads() {
    let keys = Keys::new();
    for secret in [
        "client_secret = \"synthetic\"\n",
        "client_secret_file = \"/run/secrets/upstream\"\n",
    ] {
        let text = private_key_jwt(&keys, "").replace(
            "client_id = \"ferrosmart\"\n",
            &format!("client_id = \"ferrosmart\"\n{secret}"),
        );
        let refused = ferrosmart::config::Config::from_sources(
            Some(&text),
            &std::collections::BTreeMap::new(),
        );
        assert!(matches!(refused, Err(Error::Load(_))), "{secret}");
    }
}

// NOTE: OpenID Connect Core 1.0 §9: no public client; private_key_jwt unless the
// entry names client_secret_basic, so an entry with no key for it is refused (#733).
#[test]
fn an_upstream_takes_private_key_jwt_and_is_refused_without_its_key() {
    let keys = Keys::new();
    assert!(matches!(
        config(&upstream(&keys, ""), &keys).resolve(),
        Err(Error::Missing {
            key: "ferrosmart.upstream.oidc.private_key_jwt.keys.private_key_file"
        })
    ));
    assert!(config(&private_key_jwt(&keys, ""), &keys).resolve().is_ok());
    let keys_alone = upstream(&keys, &crate::support::upstream_assertion(keys.dir.path()));
    let settings = config(&keys_alone, &keys)
        .resolve()
        .expect("the keys table alone selects private_key_jwt");
    let ferrosmart::upstream::Protocol::Oidc(oidc) =
        &settings.upstreams.first().expect("a provider").protocol
    else {
        panic!("the provider speaks OpenID Connect");
    };
    assert_eq!("private_key_jwt", oidc.authentication.method());
}

// NOTE: RFC 7518 §3.1: the ring holds RSA keys, which sign RS* and PS* alone.
#[test]
fn a_private_key_jwt_algorithm_the_key_cannot_sign_is_refused() {
    let keys = Keys::new();
    for (algorithm, refused) in [
        ("PS256", false),
        ("RS512", false),
        ("ES256", true),
        ("none", true),
    ] {
        let text = private_key_jwt(&keys, &format!("algorithm = \"{algorithm}\""));
        assert_eq!(
            refused,
            config(&text, &keys).resolve().is_err(),
            "{algorithm}"
        );
    }
}

// NOTE: RFC 7515 §4.1.8: the certificate named by x5t#S256 is the signing key's.
#[test]
fn a_certificate_of_another_key_is_refused() {
    let keys = Keys::new();
    let other = rcgen::KeyPair::generate().expect("a key");
    let certificate = rcgen::CertificateParams::new(vec![String::from("other.example.org")])
        .expect("parameters")
        .self_signed(&other)
        .expect("a certificate");
    let path = keys.dir.path().join("other.crt");
    std::fs::write(&path, certificate.pem()).expect("written");
    let text = private_key_jwt(
        &keys,
        &format!("certificate_file = {:?}", path.display().to_string()),
    );
    assert!(matches!(
        config(&text, &keys).resolve(),
        Err(Error::Key { .. })
    ));
}

// NOTE: RFC 8725 §3.12: a key that signs client assertions never signs a token.
#[test]
fn an_assertion_ring_holding_a_token_key_or_none_is_refused() {
    let keys = Keys::new();
    let text = upstream(
        &keys,
        &format!(
            "[ferrosmart.upstream.oidc.private_key_jwt]\n[ferrosmart.upstream.oidc.private_key_jwt.keys]\n\
         next_private_key_file = {:?}\nprivate_key_file = {:?}\n",
            crate::support::rsa_key(keys.dir.path(), "next.pem")
                .display()
                .to_string(),
            keys.current.display().to_string()
        ),
    );
    assert!(matches!(
        config(&text, &keys).resolve(),
        Err(Error::Upstream { .. })
    ));
    let text = upstream(&keys, "[ferrosmart.upstream.oidc.private_key_jwt]\n");
    assert!(matches!(
        config(&text, &keys).resolve(),
        Err(Error::Missing {
            key: "ferrosmart.upstream.oidc.private_key_jwt.keys.private_key_file"
        })
    ));
}

// NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, Extensibility, an
// extension scope starts with two underscores; any other non-SMART scope stays out.
#[test]
fn a_role_may_grant_an_extension_scope_and_no_other_non_smart_scope() {
    let keys = Keys::new();
    let role = |scope: &str| {
        format!(
            "[ferrosmart]\nissuer = \"https://smart.example.org\"\n\
             [[ferrosmart.role]]\nname = \"administrator\"\nscopes = [\"user/Patient.rs\", {scope:?}]"
        )
    };
    let settings = config(&role("__ferroehr.platform"), &keys)
        .resolve()
        .expect("an extension scope is admitted");
    assert_eq!(
        Some(&vec![
            String::from("user/Patient.rs"),
            String::from("__ferroehr.platform")
        ]),
        settings.roles.get("administrator")
    );
    for refused in ["admin", "system/Patient.rs", "__", "_ferroehr.platform"] {
        assert!(
            matches!(
                config(&role(refused), &keys).resolve(),
                Err(Error::Role { .. })
            ),
            "{refused}"
        );
    }
}

// NOTE: docs/architecture.md §13.6 item 4 (#716), an openEHR base lists the purposes
// of use its server accepts, each a header value, and the header they go in.
#[test]
fn the_purposes_of_use_belong_to_an_openehr_base_and_each_is_a_header_value() {
    let keys = Keys::new();
    let with = |kind: &str, table: &str| {
        config(
            &format!(
                "[ferrosmart]\nissuer = \"https://smart.example.org\"\n\
                 [[ferrosmart.resource]]\nbase = \"https://ehr.example.org/openehr/v1\"\n\
                 kind = {kind:?}\n{table}"
            ),
            &keys,
        )
        .resolve()
        .map_err(Box::new)
    };
    let purpose = |code: &str, system: &str, display: &str| {
        format!(
            "[[ferrosmart.resource.purpose]]\ncode = {code:?}\nsystem = {system:?}\n\
             display = {display:?}\n"
        )
    };
    let treatment = purpose(
        "TREAT",
        "http://terminology.hl7.org/CodeSystem/v3-ActReason",
        "Treatment",
    );
    let settings = with("openehr", &treatment).expect("resolves");
    let purposes = settings
        .purposes
        .get("https://ehr.example.org/openehr/v1")
        .expect("listed");
    assert_eq!("x-purpose-of-use", purposes.header.as_str(), "the default");
    assert_eq!("Treatment", purposes.get("TREAT").expect("TREAT").display);
    let named = with(
        "openehr",
        &format!("purpose_header = \"X-Purpose\"\n{treatment}"),
    )
    .expect("resolves");
    assert_eq!(
        Some("x-purpose"),
        named
            .purposes
            .get("https://ehr.example.org/openehr/v1")
            .map(|purposes| purposes.header.as_str())
    );
    assert!(
        with("openehr", "").expect("resolves").purposes.is_empty(),
        "no purposes, no header"
    );
    for (kind, table) in [
        ("fhir", treatment.clone()),
        (
            "openehr",
            String::from("purpose_header = \"x-purpose-of-use\"\n"),
        ),
        (
            "openehr",
            format!("purpose_header = \"bad header\"\n{treatment}"),
        ),
        (
            "openehr",
            purpose("TREAT,ETREAT", "urn:example:purpose", "Both"),
        ),
        (
            "openehr",
            purpose("TRE AT", "urn:example:purpose", "Spaced"),
        ),
        ("openehr", purpose("", "urn:example:purpose", "Empty")),
        ("openehr", purpose("TREAT", "not a uri", "Treatment")),
        ("openehr", purpose("TREAT", "urn:example:purpose", " ")),
        ("openehr", format!("{treatment}{treatment}")),
    ] {
        let refused = with(kind, &table).map(|_| ()).map_err(|error| *error);
        assert!(
            matches!(refused, Err(Error::Resource { .. })),
            "{kind} {table}"
        );
    }
}

// NOTE: RFC 7591 §5, an app's own registration is held to patient-facing scopes:
// an open registration names them, and never a user/ or system/ scope.
#[test]
fn an_open_registration_names_a_patient_facing_scope() {
    let keys = Keys::new();
    for (registration, admitted) in [
        (
            "open = true\nscope = \"openid patient/Observation.rs\"",
            true,
        ),
        ("open = false\nscope = \"user/Observation.rs\"", true),
        ("open = true", false),
        ("open = true\nscope = \"openid user/Observation.rs\"", false),
        ("open = true\nscope = \"system/Patient.rs\"", false),
    ] {
        let text = format!(
            "[ferrosmart]\nissuer = \"https://smart.example.org\"\n[ferrosmart.registration]\n{registration}"
        );
        let resolved = config(&text, &keys).resolve();
        assert_eq!(admitted, resolved.is_ok(), "{registration}: {resolved:?}");
    }
}

// NOTE: SMART App Launch 2.2.0, User Access Brands, Organization.name: the
// deployment's one name, which a brand naming none takes.
#[test]
fn the_deployment_s_name_is_one_key_the_brand_takes_by_default() {
    let keys = Keys::new();
    let text = "[ferrosmart]\nname = \"Example Hospital\"\nissuer = \"https://smart.example.org\"\n\
                [[ferrosmart.resource]]\nbase = \"https://fhir.example.org/r4\"\n\
                [ferrosmart.brand]\nwebsite = \"https://example.org\"\n\
                [[ferrosmart.brand.endpoint]]\nbase = \"https://fhir.example.org/r4\"\n\
                fhir_version = [\"4.0.1\"]\ncontact = [\"https://developer.example.org\"]\n";
    let settings = config(text, &keys).resolve().expect("resolves");
    assert_eq!("Example Hospital", settings.name);
    let brands = settings.brand.expect("a Bundle");
    let instants = brands
        .digests()
        .into_keys()
        .map(|resource| (resource, String::from("2026-11-23T00:00:00Z")))
        .collect();
    let changed = ferrosmart::brands::Changed::new(&brands, &instants).expect("changed");
    let bundle = brands.bundle(&changed).to_string();
    assert!(bundle.contains("\"name\":\"Example Hospital\""), "{bundle}");
    let refused = ferrosmart::config::Config::from_sources(
        Some(
            "[ferrosmart]\nissuer = \"https://smart.example.org\"\n[ferrosmart.branding]\nname = \"x\"",
        ),
        &std::collections::BTreeMap::new(),
    );
    assert!(
        matches!(refused, Err(Error::Load(_))),
        "the branding name is gone"
    );
}

/// The environment of a case that names its own `[ferrosmart.backend]`, or
/// none: the unreached database and the resource server `kind`.
fn backend_environment(kind: &str) -> std::collections::BTreeMap<String, String> {
    std::collections::BTreeMap::from([
        (
            String::from("FERROSMART__FERROSMART__DATABASE__URL"),
            String::from(crate::support::UNREACHED_DATABASE),
        ),
        (
            String::from("FERROSMART__FERROSMART__RESOURCE"),
            format!("[{{ base = \"https://ehr.example.org/v1\", kind = \"{kind}\" }}]"),
        ),
    ])
}

/// Returns the configuration of `text` over [`backend_environment`].
fn with_backend(text: &str, kind: &str) -> ferrosmart::config::Config {
    ferrosmart::config::Config::from_sources(Some(text), &backend_environment(kind))
        .expect("the configuration reads")
}

// NOTE: SMART App Launch 2.2.0, Backend Services; docs/architecture.md §13.33, a
// login at a FHIR base reads the person's own record as FerroSMART's client.
#[test]
fn a_login_at_a_fhir_base_needs_the_backend_client() {
    let keys = Keys::new();
    let text = private_key_jwt(&keys, "");
    assert!(matches!(
        with_backend(&text, "fhir").resolve(),
        Err(Error::Backend {
            rule: "people log in at a FHIR base, so `[ferrosmart.backend]` is set"
        })
    ));
    assert!(
        with_backend(&text, "openehr").resolve().is_ok(),
        "no FHIR base, no backend client"
    );
    let key = crate::support::ml_dsa_key(keys.dir.path(), "backend.pem");
    let backend = format!(
        "[ferrosmart.backend.keys]\nprivate_key_file = {:?}\n",
        key.display().to_string()
    );
    let settings = with_backend(&format!("{text}{backend}"), "fhir")
        .resolve()
        .expect("resolves");
    let resolved = settings.backend.expect("the backend client");
    // NOTE: IHE IUA §3.71.4.2.2.1, the client is FerroSMART under its issuer
    // identifier, so no `client_id` is configured.
    assert_eq!("https://smart.example.org", resolved.client_id);
    let named = format!("{text}[ferrosmart.backend]\nclient_id = \"ferrosmart\"\n{backend}");
    assert!(
        ferrosmart::config::Config::from_sources(Some(&named), &backend_environment("fhir"))
            .is_err(),
        "client_id is an unknown key"
    );
}

// NOTE: SMART App Launch 2.2.0, Client Authentication: Asymmetric, the server
// validates RS384 and ES384, and RFC 8725 §3.12 keeps assertion keys off tokens.
#[test]
fn a_backend_client_outside_the_asymmetric_profile_is_refused() {
    let keys = Keys::new();
    let text = private_key_jwt(&keys, "");
    let ec = ec_key(keys.dir.path(), "backend.pem").display().to_string();
    let rsa = crate::support::rsa_key(keys.dir.path(), "backend-rsa.pem")
        .display()
        .to_string();
    let pq = crate::support::ml_dsa_key(keys.dir.path(), "backend-ml-dsa.pem")
        .display()
        .to_string();
    let token = keys.current.display().to_string();
    for (table, refused) in [
        (
            format!(
                "algorithm = \"RS384\"\n[ferrosmart.backend.keys]\nprivate_key_file = {rsa:?}\n"
            ),
            None,
        ),
        (
            format!(
                "algorithm = \"ES256\"\n[ferrosmart.backend.keys]\nprivate_key_file = {ec:?}\n"
            ),
            Some("`algorithm` is `ES384`, `RS384`, `ML-DSA-44`, `ML-DSA-65` or `ML-DSA-87`"),
        ),
        (
            format!(
                "algorithm = \"ML-DSA-65\"\n[ferrosmart.backend.keys]\nprivate_key_file = {pq:?}\n"
            ),
            None,
        ),
        (
            format!(
                "algorithm = \"RS384\"\n[ferrosmart.backend.keys]\nprivate_key_file = {token:?}\n"
            ),
            Some("the assertion keys share no key with `[ferrosmart.keys]`"),
        ),
    ] {
        let resolved =
            with_backend(&format!("{text}[ferrosmart.backend]\n{table}"), "fhir").resolve();
        match refused {
            None => assert!(resolved.is_ok(), "{table}"),
            Some(rule) => assert!(
                matches!(&resolved, Err(Error::Backend { rule: named }) if *named == rule),
                "{table}"
            ),
        }
    }
}
