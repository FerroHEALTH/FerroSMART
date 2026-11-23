// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The list of PID providers the Commission publishes (#794): a PID whose
//! issuer the list names is trusted, a list that does not verify or has
//! expired refuses every wallet login, and a read that fails keeps the last
//! list that verified until its next update.

use super::kit::{Authority, Credential, OPERATOR, now, providers_list};
use super::*;

/// A list a case writes for the certificates of its server.
type ListOf<'a> = Box<dyn Fn(&Pki) -> String + 'a>;

/// The table of a list read from `file`, signed by `signer`, read again
/// every `refresh`.
fn list_table(dir: &std::path::Path, signer: &Authority, list: &str, refresh: &str) -> String {
    format!(
        "[ferrosmart.upstream.openid4vp.pid_providers_list]\nfile = {}\n\
         signing_certificate_files = [{}]\nrefresh = {refresh:?}\n",
        written(dir, "pid-providers.jwt", list),
        written(dir, "list-signer.pem", &signer.pem),
    )
}

/// Begins a login and posts the PID `issuer` issued, returning the answer.
async fn present(wallet: &Wallet, issuer: &Authority) -> (StatusCode, Value) {
    let begun = wallet.begin().await;
    let presentation = Credential::pid().present(
        issuer,
        &wallet.holder,
        &begun.text("client_id"),
        &begun.text("nonce"),
        now(),
    );
    wallet.answer(&begun, &presentation).await
}

#[tokio::test]
async fn a_pid_from_a_listed_provider_is_trusted_and_another_is_not() {
    let signer = Authority::list_signer("EU", OPERATOR);
    let wallet = Wallet::start_built(|pki, dir| {
        let list = providers_list(&signer, &[&pki.issuer], now() + 3600);
        list_table(dir, &signer, &list, "1h")
    })
    .await;
    let (status, body) = present(&wallet, &wallet.pki.issuer).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let (status, body) = present(&wallet, &wallet.pki.stranger).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
    assert_eq!(json!("untrusted_issuer"), body["error_description"]);
    wallet.stop().await;
}

#[tokio::test]
async fn a_list_that_does_not_verify_or_has_expired_refuses_every_login() {
    let signer = Authority::list_signer("EU", OPERATOR);
    let forger = Authority::list_signer("EU", OPERATOR);
    let misnamed = Authority::list_signer("NL", "Another Operator");
    let cases: [(&str, ListOf<'_>, &Authority); 3] = [
        (
            "signed by another key",
            Box::new(|pki: &Pki| providers_list(&forger, &[&pki.issuer], now() + 3600)),
            &signer,
        ),
        (
            "past its next update",
            Box::new(|pki: &Pki| providers_list(&signer, &[&pki.issuer], now() - 1)),
            &signer,
        ),
        (
            "signed by a certificate naming another operator",
            Box::new(|pki: &Pki| providers_list(&misnamed, &[&pki.issuer], now() + 3600)),
            &misnamed,
        ),
    ];
    for (case, list, trusted) in cases {
        let wallet =
            Wallet::start_built(|pki, dir| list_table(dir, trusted, &list(pki), "1h")).await;
        let (status, body) = present(&wallet, &wallet.pki.issuer).await;
        assert_eq!(StatusCode::BAD_REQUEST, status, "{case}: {body}");
        assert_eq!(
            json!("trusted_list_unavailable"),
            body["error_description"],
            "{case}"
        );
        let recorded = logins(&wallet.smart.store).await;
        assert!(
            recorded
                .last()
                .is_some_and(|login| login.contains("trusted_list_unavailable")),
            "{case}: {recorded:?}"
        );
        wallet.stop().await;
    }
}

#[tokio::test]
async fn a_failed_read_keeps_the_last_list_that_verified() {
    let signer = Authority::list_signer("EU", OPERATOR);
    let forger = Authority::list_signer("EU", OPERATOR);
    let mut file = std::path::PathBuf::new();
    let wallet = Wallet::start_built(|pki, dir| {
        let list = providers_list(&signer, &[&pki.issuer], now() + 3600);
        file = dir.join("pid-providers.jwt");
        list_table(dir, &signer, &list, "1s")
    })
    .await;
    let (status, body) = present(&wallet, &wallet.pki.issuer).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let replacement = providers_list(&forger, &[&wallet.pki.stranger], now() + 3600);
    std::fs::write(&file, replacement).expect("written");
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (status, body) = present(&wallet, &wallet.pki.issuer).await;
    assert_eq!(
        StatusCode::OK,
        status,
        "the last list that verified stays: {body}"
    );
    let (status, body) = present(&wallet, &wallet.pki.stranger).await;
    assert_eq!(
        StatusCode::BAD_REQUEST,
        status,
        "the forged list is never read: {body}"
    );
    wallet.stop().await;
}

#[tokio::test]
async fn anchor_files_join_the_list() {
    let signer = Authority::list_signer("EU", OPERATOR);
    let wallet = Wallet::start_built(|pki, dir| {
        let list = providers_list(&signer, &[&pki.issuer], now() + 3600);
        format!(
            "issuer_anchor_files = [{}]\n{}",
            written(dir, "other-root.pem", &pki.other_root.pem),
            list_table(dir, &signer, &list, "1h")
        )
    })
    .await;
    for issuer in [&wallet.pki.issuer, &wallet.pki.stranger] {
        let (status, body) = present(&wallet, issuer).await;
        assert_eq!(StatusCode::OK, status, "{body}");
    }
    wallet.stop().await;
}
