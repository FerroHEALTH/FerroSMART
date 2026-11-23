// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The eIDAS level of assurance of an OpenID Connect login: held to the
//! deployment's floor, the client's minimum and the level `acr_values`
//! asks, and carried into every token as `acr` beside `auth_time`
//! (`docs/architecture.md` §13.28).

use super::*;

/// The `acr` of each eIDAS level.
const LOW: &str = "http://eidas.europa.eu/LoA/low";
/// The `acr` of the level substantial.
const SUBSTANTIAL: &str = "http://eidas.europa.eu/LoA/substantial";
/// The `acr` of the level high.
const HIGH: &str = "http://eidas.europa.eu/LoA/high";
/// The scope every case asks.
const SCOPE: &str = "openid fhirUser user/Observation.rs";

/// Starts FerroSMART whose app registers `default_acr_values` of `acr`, when
/// set.
async fn smart_holding(acr: Option<&str>) -> Smart {
    let grants = acr.map_or_else(
        || String::from("[\"authorization_code\"]"),
        |acr| format!("[\"authorization_code\"]\ndefault_acr_values = [{acr:?}]"),
    );
    Smart::start_with(
        &grants,
        "[\"openid\", \"fhirUser\", \"user/Observation.rs\"]",
        "[\"user/Observation.rs\"]",
    )
    .await
}

/// Sends the authorization request `overrides`, logs in upstream with an ID
/// Token whose `acr` is `acr`, when set, and returns the upstream request
/// and where the callback sends the browser.
async fn log_in(smart: &Smart, overrides: &[(&str, &str)], acr: Option<&str>) -> (Url, Url) {
    let (status, headers, page) = smart.get(&authorize_path(overrides), None).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    // NOTE: a null acr takes the stub's own away, so the ID Token names none.
    let claims = json!({
        "sub": "synthetic-person", "roles": ["clinician"],
        "fhir_user": "Practitioner/synthetic-1",
        "nonce": param(&upstream, "nonce").expect("a nonce"),
        "acr": acr,
    });
    smart.provider.answer_claims(&claims).await;
    let callback = format!(
        "/callback?code=synthetic-upstream-code&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, headers, page) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    (upstream, location(&headers))
}

#[tokio::test]
async fn a_login_carries_its_eidas_level_and_auth_time_into_both_tokens() {
    let smart = Smart::start().await;
    let before = jiff::Timestamp::now().as_second();
    let body = with_claims(&smart, SCOPE, &json!({})).await;
    let access = jwt_claims(&body, "access_token");
    let id = jwt_claims(&body, "id_token");
    // NOTE: RFC 9068 §2.2.1 and OpenID Connect Core 1.0 §2, acr and auth_time.
    assert_eq!(json!(SUBSTANTIAL), access["acr"]);
    assert_eq!(json!(SUBSTANTIAL), id["acr"]);
    let auth_time = access["auth_time"].as_i64().expect("auth_time");
    assert!(auth_time >= before, "{access}");
    assert_eq!(access["auth_time"], id["auth_time"]);
    let high = with_claims(&smart, SCOPE, &json!({ "acr": "urn:synthetic:loa:high" })).await;
    assert_eq!(json!(HIGH), jwt_claims(&high, "access_token")["acr"]);
    smart.stop().await;
}

#[tokio::test]
async fn a_login_below_the_floor_or_naming_no_mapped_value_is_refused_and_recorded() {
    let smart = Smart::start().await;
    for acr in [
        Some("urn:synthetic:loa:low"),
        Some("urn:synthetic:loa:other"),
        None,
    ] {
        let (upstream, back) = log_in(&smart, &[("scope", SCOPE)], acr).await;
        // NOTE: OpenID Connect Core 1.0 §3.1.2.1, the provider is asked for the floor.
        assert_eq!(
            Some(String::from(
                "urn:synthetic:loa:substantial urn:synthetic:loa:high"
            )),
            param(&upstream, "acr_values")
        );
        assert_eq!(
            REDIRECT,
            format!("{}{}", back.origin().ascii_serialization(), back.path())
        );
        assert_eq!(
            Some(String::from("access_denied")),
            param(&back, "error"),
            "{acr:?}"
        );
    }
    let stored = records(&smart.store).await;
    assert_eq!(3, stored.len(), "{stored:?}");
    for login in &stored {
        assert_eq!(json!("110122"), login["subtype"][0]["code"]);
        assert_eq!(json!("4"), login["outcome"]);
    }
    smart.stop().await;
}

#[tokio::test]
async fn a_client_s_default_acr_values_answer_a_request_without_acr_values() {
    let smart = smart_holding(Some(HIGH)).await;
    let (upstream, back) = log_in(
        &smart,
        &[("scope", SCOPE)],
        Some("urn:synthetic:loa:substantial"),
    )
    .await;
    assert_eq!(
        Some(String::from("urn:synthetic:loa:high")),
        param(&upstream, "acr_values")
    );
    // NOTE: RFC 9470 §5, a level the request needs and the login misses.
    assert_eq!(
        Some(String::from("unmet_authentication_requirements")),
        param(&back, "error")
    );
    let (_, back) = log_in(&smart, &[("scope", SCOPE)], Some("urn:synthetic:loa:high")).await;
    assert_eq!("/consent", back.path(), "a login at the level goes on");
    // NOTE: OpenID Connect Core 1.0 §3.1.2.1, the request's own acr_values win.
    let (_, back) = log_in(
        &smart,
        &[("scope", SCOPE), ("acr_values", LOW)],
        Some("urn:synthetic:loa:substantial"),
    )
    .await;
    assert_eq!("/consent", back.path(), "the request asks for less");
    smart.stop().await;
}

#[tokio::test]
async fn acr_values_naming_an_eidas_level_holds_the_login_to_it() {
    let smart = Smart::start().await;
    let (upstream, back) = log_in(
        &smart,
        &[("scope", SCOPE), ("acr_values", HIGH)],
        Some("urn:synthetic:loa:substantial"),
    )
    .await;
    assert_eq!(
        Some(String::from("urn:synthetic:loa:high")),
        param(&upstream, "acr_values")
    );
    assert_eq!(
        Some(String::from("unmet_authentication_requirements")),
        param(&back, "error")
    );
    let (upstream, back) = log_in(
        &smart,
        &[
            ("scope", SCOPE),
            ("acr_values", &format!("urn:other {LOW}")),
        ],
        Some("urn:synthetic:loa:substantial"),
    )
    .await;
    assert_eq!(
        Some(String::from(
            "urn:synthetic:loa:substantial urn:synthetic:loa:high"
        )),
        param(&upstream, "acr_values"),
        "a level below the floor asks for the floor"
    );
    assert_eq!("/consent", back.path());
    smart.stop().await;
}

#[tokio::test]
async fn a_refresh_keeps_the_login_s_level_and_time() {
    let (smart, body) = launch_with("offline_access").await;
    let first = jwt_claims(&body, "access_token");
    assert_eq!(json!(SUBSTANTIAL), first["acr"]);
    let refresh_token = body["refresh_token"].as_str().expect("a refresh token");
    let (status, refreshed) = refresh(&smart, refresh_token).await;
    assert_eq!(StatusCode::OK, status, "{refreshed}");
    let again = jwt_claims(&refreshed, "access_token");
    // NOTE: RFC 9470 §6.1, acr and auth_time do not change on a renewal.
    assert_eq!(first["acr"], again["acr"]);
    assert_eq!(first["auth_time"], again["auth_time"]);
    smart.stop().await;
}

#[tokio::test]
async fn both_documents_name_the_eidas_levels_the_providers_map() {
    let smart = Smart::start().await;
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let (status, _, body) = smart.get(path, None).await;
        assert_eq!(StatusCode::OK, status, "{path}");
        let document: Value = serde_json::from_str(&body).expect("JSON");
        // NOTE: RFC 9470 §7, acr_values_supported.
        assert_eq!(
            json!([LOW, SUBSTANTIAL, HIGH]),
            document["acr_values_supported"],
            "{path}"
        );
    }
    smart.stop().await;
}

#[test]
fn a_provider_whose_values_miss_the_floor_or_its_minimum_is_refused_at_load() {
    let keys = Keys::new();
    let assertion = crate::support::upstream_assertion(keys.dir.path());
    let text = |floor: &str, assurance: &str| {
        format!(
            "[ferrosmart]\nissuer = {ISSUER:?}\n{floor}\
             [[ferrosmart.upstream]]\nname = \"idp\"\n{assurance}\
             [ferrosmart.upstream.oidc]\nissuer = \"https://idp.example.org\"\nclient_id = \"ferrosmart\"\n{assertion}"
        )
    };
    let low = "[ferrosmart.upstream.assurance]\nlevels = { \"urn:idp:password\" = \"low\" }\n";
    for (floor, assurance) in [
        ("", ""),
        ("", low),
        (
            "assurance_minimum = \"high\"\n",
            "[ferrosmart.upstream.assurance]\nlevels = { \"urn:idp:app\" = \"substantial\" }\n",
        ),
        (
            "assurance_minimum = \"none\"\n",
            "[ferrosmart.upstream.assurance]\nlevels = { \"urn:idp:password\" = \"low\" }\nminimum = \"substantial\"\n",
        ),
    ] {
        let refused = config(&text(floor, assurance), &keys).resolve();
        assert!(
            matches!(
                refused,
                Err(ferrosmart::config::error::Error::Assurance { .. })
            ),
            "{floor}{assurance}: {refused:?}"
        );
    }
    for (floor, assurance) in [
        ("", ASSURANCE),
        ("assurance_minimum = \"none\"\n", ""),
        ("assurance_minimum = \"low\"\n", low),
    ] {
        assert!(
            config(&text(floor, assurance), &keys).resolve().is_ok(),
            "{floor}{assurance}"
        );
    }
}
