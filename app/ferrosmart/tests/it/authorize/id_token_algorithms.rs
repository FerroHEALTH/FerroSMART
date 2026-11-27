// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A client's `id_token_signed_response_alg` (OpenID Connect Dynamic Client
//! Registration 1.0 §2) choosing an ID Token signed PS256, ES256 or `EdDSA`,
//! the algorithms FAPI 2.0 Security Profile §5.4.1 admits, beside RS256.

use super::*;

/// Starts FerroSMART whose pool signs every algorithm and whose app
/// registers `algorithm` for its ID Tokens.
async fn signing(keys: &Keys, algorithm: &str) -> Smart {
    let path = |path: std::path::PathBuf| path.display().to_string();
    let pool = format!(
        "[ferrosmart.keys]\nprivate_key_files = [{:?}, {:?}, {:?}]\nps256_private_key_files = [{:?}]\n",
        path(crate::support::rsa_key(keys.dir.path(), "rsa.pem")),
        path(crate::support::p256_key(keys.dir.path(), "p256.pem")),
        path(crate::support::ed25519_key(keys.dir.path(), "ed25519.pem")),
        path(crate::support::rsa_key(keys.dir.path(), "ps256.pem")),
    );
    Smart::start_setting(
        "[\"authorization_code\"]",
        &format!(
            "[\"openid\", \"fhirUser\", \"user/Observation.rs\"]\nid_token_signed_response_alg = {algorithm:?}"
        ),
        "[\"user/Observation.rs\"]",
        "",
        &[REDIRECT],
        &pool,
    )
    .await
}

#[tokio::test]
async fn an_id_token_is_signed_with_the_algorithm_its_client_registers() {
    for algorithm in ["PS256", "ES256", "EdDSA", "RS256"] {
        let keys = Keys::new();
        let smart = signing(&keys, algorithm).await;
        let body = with_claims(&smart, "openid fhirUser", &json!({})).await;
        let token = body["id_token"].as_str().expect("an ID Token");
        let jws = ferrohealth_smart::jws::compact::decode(token).expect("a JWS");
        assert_eq!(algorithm, jws.header().alg.name());
        let (_, _, set) = smart.get("/jwks", None).await;
        let set: Value = serde_json::from_str(&set).expect("JSON");
        let published: Vec<ferrohealth_smart::jws::jwk::Jwk> = set["keys"]
            .as_array()
            .expect("keys")
            .iter()
            .map(|key| ferrohealth_smart::jws::jwk::Jwk::try_from(key).expect("a key"))
            .collect();
        let key = ferrohealth_smart::jws::jwk::select(
            &published,
            jws.header().kid.as_deref(),
            jws.header().alg,
        )
        .expect("the signing key is published");
        jws.verify_claims(key).expect("the ID Token verifies");
        // NOTE: OpenID Connect Discovery 1.0 §3, every algorithm an ID Token may carry.
        let (_, _, document) = smart.get("/.well-known/openid-configuration", None).await;
        let document: Value = serde_json::from_str(&document).expect("JSON");
        assert_eq!(
            json!(["RS256", "ES256", "EdDSA", "PS256"]),
            document["id_token_signing_alg_values_supported"]
        );
        smart.stop().await;
    }
}
