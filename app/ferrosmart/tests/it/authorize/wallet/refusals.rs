// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Every refusal of a presentation at the response URI: a `400` naming the
//! reason, a `110122` Login record of the failure, and no login.

use super::kit::{Authority, Credential, Holder, now, status_list};
use super::*;

/// Posts `presentation` to `begun` and checks it is refused as `reason`,
/// recorded, and leaves the request open with no one logged in.
async fn refused_as(wallet: &Wallet, begun: &Begun, presentation: &str, reason: &str) {
    let (status, body) = wallet.answer(begun, presentation).await;
    assert_refused(wallet, begun, status, &body, reason).await;
}

/// Checks the answer `status` and `body` refuse as `reason`.
async fn assert_refused(
    wallet: &Wallet,
    begun: &Begun,
    status: StatusCode,
    body: &Value,
    reason: &str,
) {
    // NOTE: the response URI refuses with a 4xx, so the wallet and a conformance run see it.
    assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
    assert_eq!(json!(reason), body["error_description"], "{body}");
    assert!(body.get("redirect_uri").is_none(), "no way back: {body}");
    let recorded = logins(&wallet.smart.store).await;
    let login = recorded.last().expect("the refusal is recorded");
    assert!(!login.contains("\"outcome\":\"0\""), "{login}");
    assert!(login.contains(reason), "the record names {reason}: {login}");
    let pending = wallet
        .smart
        .store
        .pending(&begun.cookie)
        .await
        .expect("reads")
        .expect("the request stays open");
    assert_eq!(None, pending.subject, "no one logged in");
}

/// Returns the presentation `credential` gives for `begun`, issued by
/// `signer` and bound by `holder` with `aud`, `nonce` and `iat`.
fn bound(
    credential: &Credential,
    signer: &Authority,
    holder: &Holder,
    (aud, nonce, iat): (&str, &str, i64),
) -> String {
    credential.present(signer, holder, aud, nonce, iat)
}

#[tokio::test]
async fn a_pid_from_an_issuer_under_another_anchor_is_untrusted() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let presentation = Credential::pid().present(
        &wallet.pki.stranger,
        &wallet.holder,
        &begun.text("client_id"),
        &begun.text("nonce"),
        now(),
    );
    refused_as(&wallet, &begun, &presentation, "untrusted_issuer").await;
    wallet.stop().await;
}

#[tokio::test]
async fn a_pid_whose_signature_does_not_verify_is_invalid() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let issued = Credential::pid().issued(&wallet.pki.issuer, &wallet.holder);
    let other = Credential::pid().issued(&wallet.pki.issuer, &wallet.holder);
    let (jwt, disclosures) = issued.split_once('~').expect("an SD-JWT");
    let (signing_input, _) = jwt.rsplit_once('.').expect("a JWS");
    let (_, foreign) = other
        .split_once('~')
        .and_then(|(jwt, _)| jwt.rsplit_once('.'))
        .expect("a JWS");
    let mut payload: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(signing_input.split('.').nth(1).expect("a payload"))
            .expect("base64url"),
    )
    .expect("JSON");
    payload["exp"] = json!(now() + 999_999);
    let header = signing_input.split('.').next().expect("a header");
    let tampered = format!(
        "{header}.{}.{foreign}~{disclosures}",
        URL_SAFE_NO_PAD.encode(payload.to_string())
    );
    let binding = wallet.holder.bind(
        &tampered,
        &begun.text("client_id"),
        &begun.text("nonce"),
        now(),
    );
    refused_as(
        &wallet,
        &begun,
        &format!("{tampered}{binding}"),
        "invalid_credential",
    )
    .await;
    wallet.stop().await;
}

#[tokio::test]
async fn a_credential_of_a_type_not_asked_for_is_unrequested() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let mut credential = Credential::pid();
    credential.vct = String::from("urn:eudi:other:1");
    let presentation = wallet.presentation(&credential, &begun);
    refused_as(&wallet, &begun, &presentation, "unrequested_credential").await;
    wallet.stop().await;
}

#[tokio::test]
async fn a_pid_past_its_exp_is_expired() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let mut credential = Credential::pid();
    credential.exp = now() - 10;
    let presentation = wallet.presentation(&credential, &begun);
    refused_as(&wallet, &begun, &presentation, "expired").await;
    wallet.stop().await;
}

#[tokio::test]
async fn a_pid_the_status_list_names_invalid_is_revoked() {
    let wallet = Wallet::start().await;
    let uri = format!("{}/status/1", wallet.status.uri());
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/status/1"))
        .and(matchers::header("accept", "application/statuslist+jwt"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/statuslist+jwt")
                .set_body_string(status_list(&wallet.pki.issuer, &uri, 64, &[7])),
        )
        .mount(&wallet.status)
        .await;
    let begun = wallet.begin().await;
    let mut credential = Credential::pid();
    credential.status = Some(json!({"status_list": {"idx": 7, "uri": uri}}));
    let presentation = wallet.presentation(&credential, &begun);
    refused_as(&wallet, &begun, &presentation, "revoked").await;
    wallet.stop().await;
}

#[tokio::test]
async fn a_status_list_that_cannot_be_read_or_trusted_leaves_the_status_unavailable() {
    let wallet = Wallet::start().await;
    let trusted = format!("{}/status/stranger", wallet.status.uri());
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/status/stranger"))
        .respond_with(ResponseTemplate::new(200).set_body_string(status_list(
            &wallet.pki.stranger,
            &trusted,
            64,
            &[],
        )))
        .mount(&wallet.status)
        .await;
    let begun = wallet.begin().await;
    for uri in [
        format!("{}/status/missing", wallet.status.uri()),
        trusted.clone(),
    ] {
        let mut credential = Credential::pid();
        credential.status = Some(json!({"status_list": {"idx": 1, "uri": uri}}));
        let presentation = wallet.presentation(&credential, &begun);
        refused_as(&wallet, &begun, &presentation, "status_unavailable").await;
    }
    let mut credential = Credential::pid();
    credential.status = Some(json!({"status_list": {"idx": 999, "uri": trusted}}));
    let presentation = wallet.presentation(&credential, &begun);
    refused_as(&wallet, &begun, &presentation, "status_unavailable").await;
    wallet.stop().await;
}

#[tokio::test]
async fn a_key_binding_that_does_not_hold_is_refused() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let (client_id, nonce) = (begun.text("client_id"), begun.text("nonce"));
    let credential = Credential::pid();
    let issuer = &wallet.pki.issuer;
    let holder = &wallet.holder;
    let cases = [
        (
            "another audience",
            bound(
                &credential,
                issuer,
                holder,
                ("x509_hash:other", &nonce, now()),
            ),
        ),
        (
            "another nonce",
            bound(
                &credential,
                issuer,
                holder,
                (&client_id, "another-nonce", now()),
            ),
        ),
        (
            "an iat in the past",
            bound(
                &credential,
                issuer,
                holder,
                (&client_id, &nonce, now() - 3600),
            ),
        ),
        (
            "an iat in the future",
            bound(
                &credential,
                issuer,
                holder,
                (&client_id, &nonce, now() + 3600),
            ),
        ),
        ("no key binding", credential.issued(issuer, holder)),
    ];
    for (case, presentation) in cases {
        let (status, body) = wallet.answer(&begun, &presentation).await;
        assert_eq!(
            json!("bad_holder_binding"),
            body["error_description"],
            "{case}: {body}"
        );
        assert_refused(&wallet, &begun, status, &body, "bad_holder_binding").await;
    }
    let stranger = Holder::new();
    let presented = credential.issued(issuer, holder);
    let foreign_key = format!(
        "{presented}{}",
        stranger.bind(&presented, &client_id, &nonce, now())
    );
    refused_as(&wallet, &begun, &foreign_key, "bad_holder_binding").await;
    let other = credential.issued(issuer, holder);
    let other_hash = format!(
        "{presented}{}",
        holder.bind(&other, &client_id, &nonce, now())
    );
    refused_as(&wallet, &begun, &other_hash, "bad_holder_binding").await;
    wallet.stop().await;
}

#[tokio::test]
async fn two_presentations_racing_for_one_nonce_admit_one() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let first = wallet.presentation(&Credential::pid(), &begun);
    let second = wallet.presentation(&Credential::pid(), &begun);
    let (one, two) = tokio::join!(
        wallet.answer(&begun, &first),
        wallet.answer(&begun, &second)
    );
    let mut statuses = [one.0, two.0];
    statuses.sort();
    assert_eq!(
        [StatusCode::OK, StatusCode::BAD_REQUEST],
        statuses,
        "{one:?} {two:?}"
    );
    let (winner, loser) = if one.0 == StatusCode::OK {
        (one.1, two.1)
    } else {
        (two.1, one.1)
    };
    assert_eq!(
        json!("replayed_nonce"),
        loser["error_description"],
        "{loser}"
    );
    // NOTE: OpenID4VP 1.0 §14.1.2, the nonce stays answered after the code is taken.
    let (status, _, _) = wallet.come_back(&winner, Some(&begun.cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let (status, body) = wallet.answer(&begun, &first).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
    wallet.stop().await;
}

#[tokio::test]
async fn a_pid_without_the_administrative_number_names_no_one() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let mut credential = Credential::pid();
    credential.withheld = vec![String::from("personal_administrative_number")];
    let presentation = wallet.presentation(&credential, &begun);
    refused_as(&wallet, &begun, &presentation, "no_administrative_number").await;
    wallet.stop().await;
}

#[tokio::test]
async fn a_pid_leaving_out_a_claim_asked_for_is_refused() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let mut credential = Credential::pid();
    credential.withheld = vec![String::from("given_name")];
    let presentation = wallet.presentation(&credential, &begun);
    refused_as(&wallet, &begun, &presentation, "missing_claim").await;
    wallet.stop().await;
}

#[tokio::test]
async fn a_vp_token_in_the_clear_is_refused_as_unencrypted() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let presentation = wallet.presentation(&Credential::pid(), &begun);
    let vp_token = json!({"pid": [presentation]}).to_string();
    let (status, body) = wallet
        .post(&[("vp_token", &vp_token), ("state", &begun.text("state"))])
        .await;
    assert_refused(&wallet, &begun, status, &body, "unencrypted_response").await;
    wallet.stop().await;
}

#[tokio::test]
async fn an_answer_that_does_not_open_or_answers_nothing_is_malformed() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let presentation = wallet.presentation(&Credential::pid(), &begun);
    let payload = json!({"vp_token": {"pid": [presentation]}, "state": begun.text("state")});
    let mut foreign = ferrosmart::wallet::jwe::EphemeralKey::generate()
        .expect("a key")
        .public_jwk(&begun.text("state"))
        .expect("a JWK");
    foreign["kid"] = begun.jwk()["kid"].clone();
    let (status, body) = wallet
        .post(&[("response", &kit::sealed(&payload, &foreign))])
        .await;
    assert_refused(&wallet, &begun, status, &body, "malformed_response").await;
    let two =
        json!({"vp_token": {"pid": [presentation, presentation]}, "state": begun.text("state")});
    let (status, body) = wallet
        .post(&[("response", &kit::sealed(&two, &begun.jwk()))])
        .await;
    assert_refused(&wallet, &begun, status, &body, "malformed_response").await;
    let mut unknown = begun.jwk();
    unknown["kid"] = json!("no-such-request");
    let (status, body) = wallet
        .post(&[("response", &kit::sealed(&payload, &unknown))])
        .await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
    wallet.stop().await;
}
