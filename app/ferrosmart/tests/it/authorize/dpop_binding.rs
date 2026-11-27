// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The authorization code bound to a `DPoP` key (RFC 9449 §10): by the
//! `dpop_jkt` parameter of the authorization request, and by a `DPoP`
//! header on the pushed request (§10.1).

use ferrohealth_smart::client::dpop::{DpopKey, Role};
use http::Method;

use super::*;

/// Returns a fresh P-256 `DPoP` key.
fn dpop_key() -> DpopKey {
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("a key");
    DpopKey::from_pem(pair.serialize_pem().as_bytes()).expect("a DPoP key")
}

/// Returns a proof of `key` for a `POST` to `route`.
fn proof(key: &DpopKey, route: &str) -> String {
    let url = Url::parse(&format!("{ISSUER}{route}")).expect("a URL");
    key.proof(&Method::POST, &url, Role::Authorization, None)
        .expect("a proof")
}

/// Posts the form `pairs` to `route` with `dpop` as the `DPoP` header.
async fn post_proved(
    smart: &Smart,
    route: &str,
    pairs: &[(&str, &str)],
    dpop: Option<&str>,
) -> (StatusCode, Value) {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    let mut request =
        Request::post(route).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(dpop) = dpop {
        request = request.header("DPoP", dpop);
    }
    let (status, _, body) = smart
        .send(request.body(Body::from(body)).expect("a request"))
        .await;
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

/// Approves the consent page of the flow from `path` and returns the code.
async fn code_from(smart: &Smart, path: &str) -> String {
    let (cookie, token) = to_consent_at(smart, &["clinician"], path).await;
    let (_, headers, _) = smart
        .post(
            "/consent",
            &[
                ("form_token", &token),
                ("decision", "approve"),
                ("scope", "user/Observation.rs"),
            ],
            Some(&cookie),
        )
        .await;
    param(&location(&headers), "code").expect("a code")
}

/// Redeems `code` with `dpop` as the `DPoP` header.
async fn redeem(smart: &Smart, code: &str, dpop: Option<&str>) -> (StatusCode, Value) {
    post_proved(
        smart,
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
            ("client_id", "app"),
        ],
        dpop,
    )
    .await
}

/// Returns the default authorization request as form pairs.
fn request_pairs() -> Vec<(String, String)> {
    let path = authorize_path(&[]);
    let query = path
        .split_once('?')
        .map(|(_, query)| query)
        .expect("a query");
    url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

// NOTE: RFC 9449 §10, the code of a request naming dpop_jkt is redeemed only with
// a proof of that key; a request without a proof or with another key's is refused.
#[tokio::test]
async fn a_code_bound_by_dpop_jkt_is_redeemed_with_that_key_alone() {
    let smart = Smart::start().await;
    let key = dpop_key();
    let code = code_from(&smart, &authorize_path(&[("dpop_jkt", key.thumbprint())])).await;
    for other in [None, Some(proof(&dpop_key(), "/token"))] {
        let (status, body) = redeem(&smart, &code, other.as_deref()).await;
        assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
        assert_eq!(json!("invalid_dpop_proof"), body["error"]);
    }
    let (status, body) = redeem(&smart, &code, Some(&proof(&key, "/token"))).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    assert_eq!(json!("DPoP"), body["token_type"]);
    smart.stop().await;
}

// NOTE: RFC 9449 §10.1, a DPoP header on the pushed request binds the code as
// dpop_jkt would, and a dpop_jkt that disagrees with the header is refused.
#[tokio::test]
async fn a_dpop_header_on_the_pushed_request_binds_the_code() {
    let smart = Smart::start().await;
    let key = dpop_key();
    let owned = request_pairs();
    let mut pairs: Vec<(&str, &str)> = owned
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let other = dpop_key();
    let mut disagreeing = pairs.clone();
    disagreeing.push(("dpop_jkt", other.thumbprint()));
    let (status, body) =
        post_proved(&smart, "/par", &disagreeing, Some(&proof(&key, "/par"))).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
    assert_eq!(json!("invalid_dpop_proof"), body["error"]);

    pairs.retain(|(name, _)| *name != "dpop_jkt");
    let (status, body) = post_proved(&smart, "/par", &pairs, Some(&proof(&key, "/par"))).await;
    assert_eq!(StatusCode::CREATED, status, "{body}");
    let request_uri = body["request_uri"].as_str().expect("a request_uri");
    let path = format!(
        "/authorize?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([("client_id", "app"), ("request_uri", request_uri)])
            .finish()
    );
    let code = code_from(&smart, &path).await;
    let (status, body) = redeem(&smart, &code, Some(&proof(&other, "/token"))).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
    assert_eq!(json!("invalid_dpop_proof"), body["error"]);
    let (status, body) = redeem(&smart, &code, Some(&proof(&key, "/token"))).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    smart.stop().await;
}
