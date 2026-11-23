// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! An app that registered itself (RFC 7591): its metadata is self-asserted
//! (§5), so it carries no organisation approval, the person always sees the
//! consent page with a notice and only the links on its redirect URI's
//! host, and an error before the person signed in is a page, never a
//! redirect (RFC 9700 §4.11.2). The rows are written as the registration
//! endpoint will write them.

use sqlx::Connection as _;

use super::public_redirect::login;
use super::*;

/// The scope every request of these cases asks for.
const SCOPE: &str = "openid fhirUser user/Observation.rs";

/// Runs `statement` against the case's database.
async fn execute(smart: &Smart, statement: &'static str) -> Result<u64, sqlx::Error> {
    let url = secrecy::ExposeSecret::expose_secret(&smart.database.url).to_owned();
    let mut connection = sqlx::PgConnection::connect(&url).await?;
    Ok(sqlx::query(statement)
        .execute(&mut connection)
        .await?
        .rows_affected())
}

/// Marks the app `app` as one that registered itself.
async fn registers_itself(smart: &Smart) {
    let marked = execute(
        smart,
        "UPDATE client SET registered_by = 'self' WHERE client_id = 'app'",
    )
    .await
    .expect("the row is marked");
    assert_eq!(1, marked, "one row is the app");
}

/// Approves `SCOPE` on the consent page `cookie` holds, remembering it
/// when `remember`, and returns where the browser goes.
async fn approve(smart: &Smart, cookie: &str, remember: bool) -> Url {
    let (_, _, page) = smart.get("/consent", Some(cookie)).await;
    let mut decision = vec![
        ("form_token", form_token(&page)),
        ("decision", String::from("approve")),
        ("scope", String::from("user/Observation.rs")),
    ];
    if remember {
        decision.push(("remember", String::from("yes")));
    }
    let pairs: Vec<(&str, &str)> = decision
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    let (status, headers, _) = smart.post("/consent", &pairs, Some(cookie)).await;
    assert_eq!(
        StatusCode::SEE_OTHER,
        status,
        "the decision sends the browser on"
    );
    location(&headers)
}

#[tokio::test]
async fn an_error_before_the_login_is_a_page_for_an_app_that_registered_itself() {
    let smart = Smart::start().await;
    let path = authorize_path(&[("response_type", "token")]);
    let (status, headers, _) = smart.get(&path, None).await;
    assert_eq!(
        StatusCode::SEE_OTHER,
        status,
        "an administered app is sent back"
    );
    assert_eq!(
        Some(String::from("unsupported_response_type")),
        param(&location(&headers), "error")
    );

    registers_itself(&smart).await;
    let (status, headers, page) = smart.get(&path, None).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{page}");
    assert!(headers.get(header::LOCATION).is_none(), "never sent back");
    assert!(page.contains("request cannot be accepted"), "{page}");
    smart.stop().await;
}

#[tokio::test]
async fn a_decline_at_the_provider_is_a_page_for_an_app_that_registered_itself() {
    let smart = Smart::start().await;
    registers_itself(&smart).await;
    let path = authorize_path(&[("scope", SCOPE)]);
    let (status, headers, _) = smart.get(&path, None).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "on to the provider");
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    let callback = format!(
        "/callback?error=access_denied&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    assert!(headers.get(header::LOCATION).is_none(), "never sent back");
    smart.stop().await;
}

#[tokio::test]
async fn an_app_that_registered_itself_always_gets_the_page_with_its_notice() {
    let smart = Smart::start().await;
    let (cookie, back) = login(&smart, REDIRECT, SCOPE).await;
    assert_eq!("/consent", back.path());
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
    assert!(!page.contains("registered itself"), "{page}");
    assert!(page.contains("https://cdn.example.org/app.png"), "{page}");
    let code = approve(&smart, &cookie, true).await;
    assert!(code.as_str().starts_with(REDIRECT));
    let (_, back) = login(&smart, REDIRECT, SCOPE).await;
    assert!(
        back.as_str().starts_with(REDIRECT),
        "the remembered consent answers for an administered app: {back}"
    );

    registers_itself(&smart).await;
    let (cookie, back) = login(&smart, REDIRECT, SCOPE).await;
    assert_eq!(
        "/consent",
        back.path(),
        "no remembered consent answers for it"
    );
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
    assert!(
        page.contains("Synthetic App registered itself with this server"),
        "the notice: {page}"
    );
    assert!(
        !page.contains("name=\"remember\""),
        "nothing to remember: {page}"
    );
    assert!(
        page.contains("https://app.example.org/privacy")
            && page.contains("https://app.example.org/terms")
            && page.contains("https://app.example.org/\""),
        "the links on the redirect URI's host: {page}"
    );
    assert!(
        !page.contains("https://cdn.example.org/app.png"),
        "no logo from another host: {page}"
    );
    let code = approve(&smart, &cookie, true).await;
    assert!(code.as_str().starts_with(REDIRECT));
    let (_, back) = login(&smart, REDIRECT, SCOPE).await;
    assert_eq!("/consent", back.path(), "the page again");
    smart.stop().await;
}

#[tokio::test]
async fn the_row_of_an_app_that_registered_itself_is_never_first_party() {
    let smart = Smart::start().await;
    registers_itself(&smart).await;
    let client = smart
        .store
        .client("app")
        .await
        .expect("reads")
        .expect("registered");
    assert_eq!(
        ferrosmart::clients::Registration::Dynamic,
        client.registration
    );
    assert!(!client.first_party());
    let marked = execute(
        &smart,
        "UPDATE client SET first_party = true WHERE client_id = 'app'",
    )
    .await;
    assert!(
        marked.is_err(),
        "the store refuses the first-party mark on it"
    );
    smart.stop().await;
}
