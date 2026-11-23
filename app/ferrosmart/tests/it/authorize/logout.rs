// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The front-channel logout URI (OpenID Connect Front-Channel Logout 1.0)
//! and the end-session endpoint (OpenID Connect RP-Initiated Logout 1.0).

use ferrosmart::clients::{ClientError, Material};
use ferrosmart::logout::end_session::LOGOUT_COOKIE;

use super::*;

/// The upstream session id the cases give the login.
const SID: &str = "synthetic-sid";

/// Gives every upstream session of `smart` the session id [`SID`], as a
/// provider that sends `sid` in its ID Token would have.
async fn with_sid(smart: &Smart) {
    use sqlx::Connection as _;
    let mut connection =
        sqlx::PgConnection::connect(secrecy::ExposeSecret::expose_secret(&smart.database.url))
            .await
            .expect("connects");
    sqlx::query("UPDATE upstream_session SET sid = $1")
        .bind(SID)
        .execute(&mut connection)
        .await
        .expect("updated");
}

/// Returns how many records of `event` the store of `smart` holds.
async fn recorded(smart: &Smart, event: &str) -> usize {
    events(&records(&smart.store).await)
        .iter()
        .filter(|each| *each == event)
        .count()
}

/// Returns the header `name` of `headers` as text.
fn text<'a>(headers: &'a http::HeaderMap, name: &header::HeaderName) -> &'a str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
}

#[tokio::test]
async fn a_front_channel_logout_ends_the_online_access_grants_of_its_session() {
    let (smart, body) = launch_with("online_access").await;
    with_sid(&smart).await;
    let token = body["refresh_token"].as_str().expect("a refresh token");
    let path = format!(
        "/frontchannel-logout?iss={}&sid={SID}",
        url::form_urlencoded::byte_serialize(smart.provider.server.uri().as_bytes())
            .collect::<String>()
    );
    let (status, headers, _) = smart.get(&path, None).await;
    assert_eq!(StatusCode::OK, status, "the logout succeeds");
    // NOTE: Front-Channel Logout 1.0 §2, the response SHOULD carry no-store.
    assert_eq!("no-store", text(&headers, &header::CACHE_CONTROL));
    let policy = text(&headers, &header::CONTENT_SECURITY_POLICY);
    assert!(
        policy.contains(&format!("frame-ancestors {}", smart.provider.server.uri())),
        "only the provider may frame it: {policy}"
    );
    assert!(
        headers.get(header::X_FRAME_OPTIONS).is_none(),
        "no X-Frame-Options, which would refuse the provider's frame"
    );
    let (status, refused) = refresh(&smart, token).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{refused}");
    assert_eq!(json!("invalid_grant"), refused["error"]);
    assert_eq!(1, recorded(&smart, "session-ended").await);
    let (status, _, _) = smart.get(&path, None).await;
    assert_eq!(StatusCode::OK, status, "a second logout succeeds");
    assert_eq!(
        1,
        recorded(&smart, "session-ended").await,
        "a logout that ends nothing writes nothing"
    );
    smart.stop().await;
}

#[tokio::test]
async fn a_front_channel_logout_without_both_parameters_or_from_another_issuer_ends_nothing() {
    let (smart, body) = launch_with("online_access").await;
    with_sid(&smart).await;
    let token = body["refresh_token"].as_str().expect("a refresh token");
    let issuer: String =
        url::form_urlencoded::byte_serialize(smart.provider.server.uri().as_bytes()).collect();
    for path in [
        format!("/frontchannel-logout?sid={SID}"),
        format!("/frontchannel-logout?iss={issuer}"),
        String::from("/frontchannel-logout"),
        format!("/frontchannel-logout?iss=https%3A%2F%2Fother.example.org&sid={SID}"),
    ] {
        let (status, headers, _) = smart.get(&path, None).await;
        // NOTE: Front-Channel Logout 1.0 §2, iss and sid come together, and the RP
        // ignores a request they do not match.
        assert_eq!(StatusCode::BAD_REQUEST, status, "{path}");
        assert_eq!("no-store", text(&headers, &header::CACHE_CONTROL));
    }
    let (status, renewed) = refresh(&smart, token).await;
    assert_eq!(StatusCode::OK, status, "the grant lives on: {renewed}");
    assert_eq!(0, recorded(&smart, "session-ended").await);
    smart.stop().await;
}

#[tokio::test]
async fn discovery_names_the_end_session_endpoint() {
    let smart = Smart::start().await;
    // NOTE: RP-Initiated Logout 1.0 §2.1, end_session_endpoint in discovery; §7.1
    // registers it as RFC 8414 metadata too.
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let (status, _, body) = smart.get(path, None).await;
        assert_eq!(StatusCode::OK, status, "{path}");
        let document: Value = serde_json::from_str(&body).expect("JSON");
        assert_eq!(
            json!(format!("{ISSUER}/logout")),
            document["end_session_endpoint"],
            "{path}"
        );
    }
    smart.stop().await;
}

/// Sends `request` with the logout cookie `cookie`, if any.
async fn with_logout_cookie(
    smart: &Smart,
    request: http::request::Builder,
    cookie: Option<&str>,
    body: Body,
) -> (StatusCode, http::HeaderMap, String) {
    let request = match cookie {
        Some(cookie) => request.header(header::COOKIE, format!("{LOGOUT_COOKIE}={cookie}")),
        None => request,
    };
    smart.send(request.body(body).expect("a request")).await
}

/// Posts the confirmation form `decision` with `token` and `cookie`.
async fn confirm(
    smart: &Smart,
    cookie: &str,
    token: &str,
    decision: &str,
) -> (StatusCode, http::HeaderMap, String) {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([("form_token", token), ("decision", decision)])
        .finish();
    let request = Request::post("/logout/confirm")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    with_logout_cookie(smart, request, Some(cookie), Body::from(body)).await
}

/// Returns the logout cookie a response set.
fn logout_cookie(headers: &http::HeaderMap) -> String {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .filter_map(|pair| pair.split_once('='))
        .find(|(name, _)| *name == LOGOUT_COOKIE)
        .map(|(_, value)| value.to_owned())
        .expect("the logout cookie")
}

/// Returns the end-session request of `pairs`.
fn end_session_path(pairs: &[(&str, &str)]) -> String {
    format!(
        "/logout?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish()
    )
}

#[tokio::test]
async fn a_confirmed_logout_ends_the_online_grants_and_returns_through_the_provider() {
    let (smart, body) = launch_with("online_access").await;
    let token = body["refresh_token"].as_str().expect("a refresh token");
    let hint = body["id_token"].as_str().expect("an ID Token");
    let path = end_session_path(&[
        ("id_token_hint", hint),
        ("post_logout_redirect_uri", POST_LOGOUT),
        ("state", "synthetic-logout-state"),
    ]);
    let (status, headers, page) = smart.get(&path, None).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(page.contains("Log out?"), "{page}");
    // NOTE: RP-Initiated Logout 1.0 §2, nothing ends before the person says yes.
    let (status, _) = refresh(&smart, token).await;
    assert_eq!(
        StatusCode::OK,
        status,
        "the grant lives until the person confirms"
    );
    let policy = text(&headers, &header::CONTENT_SECURITY_POLICY);
    assert!(
        policy.contains(&smart.provider.server.uri()) && policy.contains("https://app.example.org"),
        "the form's answer may go on to the provider and the app: {policy}"
    );
    let cookie = logout_cookie(&headers);
    let (status, headers, _) = confirm(&smart, &cookie, &form_token(&page), "logout").await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let upstream = location(&headers);
    assert_eq!(
        format!("{}/logout", smart.provider.server.uri()),
        format!(
            "{}{}",
            upstream.origin().ascii_serialization(),
            upstream.path()
        )
    );
    assert_eq!(
        Some(String::from(UPSTREAM_CLIENT)),
        param(&upstream, "client_id")
    );
    assert_eq!(
        Some(format!("{ISSUER}/logout/return")),
        param(&upstream, "post_logout_redirect_uri")
    );
    let upstream_state = param(&upstream, "state").expect("a state for the provider");
    assert_ne!(
        "synthetic-logout-state", upstream_state,
        "FerroSMART's own state"
    );
    let (status, refused) = refresh(&smart, token).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{refused}");
    assert_eq!(1, recorded(&smart, "logged-out").await);
    let back = format!("/logout/return?state={upstream_state}");
    let (status, headers, _) =
        with_logout_cookie(&smart, Request::get(&back), Some(&cookie), Body::empty()).await;
    // NOTE: RP-Initiated Logout 1.0 §3, the registered redirect with the RP's state.
    assert_eq!(StatusCode::SEE_OTHER, status);
    let app = location(&headers);
    assert_eq!(
        POST_LOGOUT,
        format!("{}{}", app.origin().ascii_serialization(), app.path())
    );
    assert_eq!(
        Some(String::from("synthetic-logout-state")),
        param(&app, "state")
    );
    let (status, _, _) =
        with_logout_cookie(&smart, Request::get(&back), Some(&cookie), Body::empty()).await;
    assert_eq!(StatusCode::NOT_FOUND, status, "the return is taken once");
    smart.stop().await;
}

#[tokio::test]
async fn a_logout_without_a_hint_never_redirects_to_the_app() {
    let (smart, body) = launch_with("online_access").await;
    let token = body["refresh_token"].as_str().expect("a refresh token");
    let path = end_session_path(&[
        ("client_id", "app"),
        ("post_logout_redirect_uri", POST_LOGOUT),
        ("state", "synthetic-logout-state"),
    ]);
    let (status, headers, page) = smart.get(&path, None).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    let cookie = logout_cookie(&headers);
    let (_, headers, _) = confirm(&smart, &cookie, &form_token(&page), "logout").await;
    let upstream_state = param(&location(&headers), "state").expect("a state");
    let back = format!("/logout/return?state={upstream_state}");
    let (status, headers, page) =
        with_logout_cookie(&smart, Request::get(&back), Some(&cookie), Body::empty()).await;
    // NOTE: RP-Initiated Logout 1.0 §3, without an id_token_hint the OP MUST NOT
    // perform the post-logout redirection.
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(headers.get(header::LOCATION).is_none());
    assert!(page.contains("You are logged out"), "{page}");
    let (status, _) = refresh(&smart, token).await;
    assert_eq!(
        StatusCode::OK,
        status,
        "with no hint FerroSMART knows no person, so the upstream logout ends the grant"
    );
    assert_eq!(
        1,
        recorded(&smart, "logged-out").await,
        "the logout is recorded"
    );
    smart.stop().await;
}

#[tokio::test]
async fn a_person_who_stays_signed_in_keeps_their_grants() {
    let (smart, body) = launch_with("online_access").await;
    let token = body["refresh_token"].as_str().expect("a refresh token");
    let hint = body["id_token"].as_str().expect("an ID Token");
    let (_, headers, page) = smart
        .get(&end_session_path(&[("id_token_hint", hint)]), None)
        .await;
    let cookie = logout_cookie(&headers);
    let (status, headers, page) = confirm(&smart, &cookie, &form_token(&page), "stay").await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(headers.get(header::LOCATION).is_none());
    assert!(page.contains("You are still signed in"), "{page}");
    let (status, renewed) = refresh(&smart, token).await;
    assert_eq!(StatusCode::OK, status, "{renewed}");
    assert_eq!(0, recorded(&smart, "logged-out").await);
    smart.stop().await;
}

#[tokio::test]
async fn a_confirmation_with_another_form_token_is_refused() {
    let (smart, body) = launch_with("online_access").await;
    let token = body["refresh_token"].as_str().expect("a refresh token");
    let hint = body["id_token"].as_str().expect("an ID Token");
    let (_, headers, _) = smart
        .get(&end_session_path(&[("id_token_hint", hint)]), None)
        .await;
    let cookie = logout_cookie(&headers);
    let (status, headers, _) = confirm(&smart, &cookie, "synthetic-forged", "logout").await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    assert!(headers.get(header::LOCATION).is_none());
    let (status, _) = refresh(&smart, token).await;
    assert_eq!(StatusCode::OK, status, "nothing ended");
    smart.stop().await;
}

#[tokio::test]
async fn a_logout_request_that_does_not_check_is_a_page_and_no_redirect() {
    let (smart, body) = launch_with("online_access").await;
    let hint = body["id_token"].as_str().expect("an ID Token");
    let access = body["access_token"].as_str().expect("an access token");
    let cases: [(&[(&str, &str)], &str); 5] = [
        // NOTE: RP-Initiated Logout 1.0 §2, the OP MUST validate it issued the hint.
        (&[("id_token_hint", "not-a-token")], "did not issue"),
        (&[("id_token_hint", access)], "did not issue"),
        // NOTE: RP-Initiated Logout 1.0 §2, client_id MUST match the hint's.
        (
            &[("id_token_hint", hint), ("client_id", "another-app")],
            "issued to another app",
        ),
        (&[("client_id", "unknown-app")], "not registered here"),
        // NOTE: RP-Initiated Logout 1.0 §3, only a registered URI, matched exactly.
        (
            &[
                ("id_token_hint", hint),
                (
                    "post_logout_redirect_uri",
                    "https://app.example.org/elsewhere",
                ),
            ],
            "did not register",
        ),
    ];
    for (pairs, words) in cases {
        let (status, headers, page) = smart.get(&end_session_path(pairs), None).await;
        assert_eq!(StatusCode::BAD_REQUEST, status, "{pairs:?}");
        assert!(headers.get(header::LOCATION).is_none(), "{pairs:?}");
        assert!(page.contains(words), "{pairs:?}: {page}");
    }
    smart.stop().await;
}

#[test]
fn post_logout_redirect_uris_need_the_code_grant_and_absolute_urls() {
    let section = |grant: GrantType, uri: &str| ClientMetadata {
        client_id: String::from("app"),
        kind: ClientKind::Public,
        redirect_uris: vec![String::from(REDIRECT)],
        post_logout_redirect_uris: vec![String::from(uri)],
        grant_types: vec![grant],
        scopes: vec![String::from("openid")],
        ..ClientMetadata::default()
    };
    assert!(
        resolve(
            &section(GrantType::AuthorizationCode, POST_LOGOUT),
            Material::default()
        )
        .is_ok()
    );
    assert!(matches!(
        resolve(
            &section(GrantType::ClientCredentials, POST_LOGOUT),
            Material::default()
        ),
        Err(ClientError::Rule { .. })
    ));
    for uri in ["/logged-out", "https://app.example.org/logged-out#top"] {
        assert!(
            matches!(
                resolve(
                    &section(GrantType::AuthorizationCode, uri),
                    Material::default()
                ),
                Err(ClientError::PostLogoutRedirectUri { .. })
            ),
            "{uri}"
        );
    }
}
