// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The EUDI Wallet through the W3C Digital Credentials API (#840): the page
//! that offers it, its module, the signed request with its origin, and the
//! answer the page posts back in the browser that began the request.

use super::kit::{Credential, now};
use super::*;

/// The issuer's origin, which the page is served from.
const ORIGIN: &str = "https://smart.example.org";

/// The wallet page of a request, with what its module reads.
struct Offered {
    /// The browser's cookie.
    cookie: String,
    /// The page.
    page: String,
    /// The signed request the module passes to the API.
    request: Value,
    /// The page form's token.
    form_token: String,
}

impl Offered {
    /// Returns the request's ephemeral encryption key.
    fn jwk(&self) -> Value {
        self.request
            .pointer("/client_metadata/jwks/keys/0")
            .expect("a key")
            .clone()
    }

    /// Returns the claim `name` of the request as text.
    fn text(&self, name: &str) -> String {
        self.request
            .get(name)
            .and_then(Value::as_str)
            .expect("a text claim")
            .to_owned()
    }
}

/// Begins a login and reads the wallet page.
async fn offered(wallet: &Wallet) -> Offered {
    let path = authorize_path(&[("scope", SCOPE), ("aud", &wallet.base())]);
    let (_, headers, _) = wallet.smart.get(&path, None).await;
    let cookie = set_cookie(&headers);
    let (status, headers, page) = wallet.smart.get("/wallet", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    let policy = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|value| value.to_str().ok())
        .expect("a policy");
    assert!(policy.contains("script-src 'self'"), "{policy}");
    let token = attribute(&page, "data-request", "");
    let request = read_jws(&token).1;
    let form_token = attribute(&page, "name=\"form_token\" value", "");
    Offered {
        cookie,
        page,
        request,
        form_token,
    }
}

/// Posts the page's form with `data` as the API's answer, in the browser of
/// `offered`.
async fn post_data(
    wallet: &Wallet,
    offered: &Offered,
    data: &Value,
) -> (StatusCode, http::HeaderMap, String) {
    let data = data.to_string();
    wallet
        .smart
        .post(
            "/wallet/dc",
            &[("form_token", &offered.form_token), ("data", &data)],
            Some(&offered.cookie),
        )
        .await
}

/// Returns the answer `data` the API hands the page for `credential`,
/// bound to `aud`.
fn answered(wallet: &Wallet, offered: &Offered, credential: &Credential, aud: &str) -> Value {
    let presentation = credential.present(
        &wallet.pki.issuer,
        &wallet.holder,
        aud,
        &offered.text("nonce"),
        now(),
    );
    let payload = json!({"vp_token": {"pid": [presentation]}});
    json!({"response": kit::sealed(&payload, &offered.jwk())})
}

#[tokio::test]
async fn the_page_offers_the_api_with_a_request_signed_for_its_origin() {
    let wallet = Wallet::start().await;
    let offered = offered(&wallet).await;
    // NOTE: OpenID4VP 1.0 Appendix A.2 and A.3.2, HAIP 1.0 §5.2.
    assert_eq!("dc_api.jwt", offered.request["response_mode"]);
    assert_eq!(json!([ORIGIN]), offered.request["expected_origins"]);
    assert!(
        offered.request.get("response_uri").is_none(),
        "{}",
        offered.request
    );
    assert!(
        offered.request.get("state").is_none(),
        "{}",
        offered.request
    );
    assert!(
        offered.request["client_id"]
            .as_str()
            .expect("a client_id")
            .starts_with("x509_hash:")
    );
    assert!(
        offered.page.contains("href=\"eu-eaap://"),
        "the link works with no script"
    );
    assert!(
        offered
            .page
            .contains("src=\"https://smart.example.org/wallet/dc.js\""),
        "{}",
        offered.page
    );
    let (status, headers, module) = wallet.smart.get("/wallet/dc.js", None).await;
    assert_eq!(StatusCode::OK, status);
    assert_eq!(
        Some("text/javascript; charset=utf-8"),
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        "an ES module"
    );
    assert!(
        module.contains("\"openid4vp-v1-signed\""),
        "the signed protocol"
    );
    assert!(!module.contains("eval("), "no eval under script-src 'self'");
    wallet.stop().await;
}

#[tokio::test]
async fn a_pid_through_the_api_logs_the_person_in() {
    let wallet = Wallet::start().await;
    let offered = offered(&wallet).await;
    let data = answered(
        &wallet,
        &offered,
        &Credential::pid(),
        &format!("origin:{ORIGIN}"),
    );
    let (status, headers, page) = post_data(&wallet, &offered, &data).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    assert_eq!("/consent", location(&headers).path());
    let pending = wallet
        .smart
        .store
        .pending(&offered.cookie)
        .await
        .expect("reads")
        .expect("the request");
    assert_eq!(
        Some(ferrosmart::upstream::pairwise(kit::PID, "NL:999990019")),
        pending.subject
    );
    assert_eq!(Some("Patient/p-1"), pending.fhir_user.as_deref());
    wallet.stop().await;
}

/// Returns the answer `data` the API hands the page for the PID as an
/// mdoc, its device signature over the handover of `origin`.
fn answered_mdoc(wallet: &Wallet, offered: &Offered, origin: &str) -> Value {
    use ferrosmart::wallet::mdoc::{Handover, session_transcript};
    let thumbprint = mdoc::thumbprint(&offered.jwk());
    let transcript = session_transcript(&Handover::DigitalCredentials {
        origin,
        nonce: &offered.text("nonce"),
        thumbprint: &thumbprint,
    });
    let presentation = mdoc::Mdoc::pid().present(&wallet.pki.issuer, &wallet.holder, &transcript);
    let payload = json!({"vp_token": {mdoc::MDOC: [presentation]}});
    json!({"response": kit::sealed(&payload, &offered.jwk())})
}

#[tokio::test]
async fn a_pid_mdoc_through_the_api_logs_the_person_in_under_the_page_s_origin() {
    let wallet = Wallet::start().await;
    let first = offered(&wallet).await;
    // NOTE: OpenID4VP 1.0 Appendix B.2.6.2, the handover names the origin with no prefix.
    let data = answered_mdoc(&wallet, &first, ORIGIN);
    let (status, headers, page) = post_data(&wallet, &first, &data).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    assert_eq!("/consent", location(&headers).path());
    let other = offered(&wallet).await;
    let data = answered_mdoc(&wallet, &other, &format!("origin:{ORIGIN}"));
    let (status, headers, page) = post_data(&wallet, &other, &data).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    assert_eq!(
        Some("access_denied".to_owned()),
        param(&location(&headers), "error")
    );
    let recorded = logins(&wallet.smart.store).await;
    let login = recorded.last().expect("recorded");
    assert!(login.contains("bad_holder_binding"), "{login}");
    wallet.stop().await;
}

#[tokio::test]
async fn a_presentation_bound_to_the_client_id_is_refused_over_the_api() {
    let wallet = Wallet::start().await;
    let offered = offered(&wallet).await;
    // NOTE: OpenID4VP 1.0 Appendix A.4, over the API the audience is the origin, never the client.
    let data = answered(
        &wallet,
        &offered,
        &Credential::pid(),
        &offered.text("client_id"),
    );
    let (status, headers, page) = post_data(&wallet, &offered, &data).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    let back = location(&headers);
    assert!(back.as_str().starts_with(REDIRECT), "{back}");
    assert_eq!(Some("access_denied".to_owned()), param(&back, "error"));
    let recorded = logins(&wallet.smart.store).await;
    let login = recorded.last().expect("recorded");
    assert!(login.contains("bad_holder_binding"), "{login}");
    wallet.stop().await;
}

#[tokio::test]
async fn an_unencrypted_or_declined_answer_over_the_api_sends_access_denied() {
    let wallet = Wallet::start().await;
    for data in [
        json!({"vp_token": {"pid": ["x~"]}}),
        json!({"error": "access_denied"}),
    ] {
        let offered = offered(&wallet).await;
        let (status, headers, page) = post_data(&wallet, &offered, &data).await;
        assert_eq!(StatusCode::SEE_OTHER, status, "{data}: {page}");
        assert_eq!(
            Some("access_denied".to_owned()),
            param(&location(&headers), "error")
        );
    }
    let recorded = logins(&wallet.smart.store).await;
    assert!(
        recorded
            .iter()
            .any(|login| login.contains("unencrypted_response")),
        "{recorded:?}"
    );
    wallet.stop().await;
}

#[tokio::test]
async fn an_answer_without_the_page_s_token_or_cookie_is_refused() {
    let wallet = Wallet::start().await;
    let offered = offered(&wallet).await;
    let data = answered(
        &wallet,
        &offered,
        &Credential::pid(),
        &format!("origin:{ORIGIN}"),
    )
    .to_string();
    let (status, headers, _) = wallet
        .smart
        .post(
            "/wallet/dc",
            &[("form_token", "forged"), ("data", &data)],
            Some(&offered.cookie),
        )
        .await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    assert!(
        headers.get(header::LOCATION).is_none(),
        "nothing redirected"
    );
    let (status, headers, _) = wallet
        .smart
        .post(
            "/wallet/dc",
            &[("form_token", &offered.form_token), ("data", &data)],
            None,
        )
        .await;
    assert_ne!(StatusCode::SEE_OTHER, status);
    assert!(
        headers.get(header::LOCATION).is_none(),
        "nothing redirected"
    );
    wallet.stop().await;
}

#[tokio::test]
async fn without_the_api_the_browser_goes_straight_to_the_wallet() {
    let wallet = Wallet::start_with("digital_credentials_api = false\n").await;
    let path = authorize_path(&[("scope", SCOPE), ("aud", &wallet.base())]);
    let (status, headers, page) = wallet.smart.get(&path, None).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    let to = location(&headers);
    assert_eq!("eu-eaap", to.scheme(), "{to}");
    assert!(param(&to, "request_uri").is_some(), "{to}");
    wallet.stop().await;
}
