// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! An access token signed with ML-DSA (RFC 9964) by an `AKP` key of the
//! issuer's set verifies when the issuer's algorithms name it, and a key of
//! another parameter set or whose `alg` disagrees with the header verifies
//! nothing (RFC 7517 §4.4, RFC 8725 §3.1).

use std::error::Error as StdError;

use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrohealth_smart::jws::compact::Header;
use ferrohealth_smart::refusal::Reason;
use ferrohealth_smart::resource::Rejection;

use crate::support::Issuer;
use crate::support::mint;
use crate::support::mint_with;
use crate::support::ml_dsa_key;
use crate::support::rsa_key;
use crate::support::server;

#[tokio::test]
async fn an_ml_dsa_token_verifies_only_when_configured() -> Result<(), Box<dyn StdError>> {
    for algorithm in [Algorithm::MlDsa44, Algorithm::MlDsa65, Algorithm::MlDsa87] {
        let key = ml_dsa_key("pq", algorithm);
        let issuer = Issuer::start(&[&key]).await;
        let token = mint(&key, &issuer.claims("system/Condition.r"));
        let default = server(issuer.settings()).await;
        assert!(
            matches!(
                default.authenticate(&token).await,
                Err(Rejection::Invalid {
                    reason: Reason::Algorithm
                })
            ),
            "{algorithm} outside the default set"
        );
        let mut settings = issuer.settings();
        settings.algorithms.push(algorithm);
        let configured = server(settings).await;
        let caller = configured.authenticate(&token).await?;
        assert_eq!("synthetic-client-sub", caller.subject(), "{algorithm}");
    }
    Ok(())
}

#[tokio::test]
async fn an_akp_key_of_another_parameter_set_verifies_nothing() -> Result<(), Box<dyn StdError>> {
    let published = ml_dsa_key("pq", Algorithm::MlDsa44);
    let signer = ml_dsa_key("pq", Algorithm::MlDsa65);
    let issuer = Issuer::start(&[&published]).await;
    let mut settings = issuer.settings();
    settings.algorithms = vec![Algorithm::MlDsa44, Algorithm::MlDsa65];
    let server = server(settings).await;
    let token = mint(&signer, &issuer.claims("system/Condition.r"));
    assert!(
        matches!(
            server.authenticate(&token).await,
            Err(Rejection::Invalid {
                reason: Reason::UnknownKey
            })
        ),
        "RFC 9964 §5: the ML-DSA-44 key verifies no ML-DSA-65 token"
    );
    Ok(())
}

#[tokio::test]
async fn a_key_whose_alg_disagrees_with_the_header_verifies_nothing()
-> Result<(), Box<dyn StdError>> {
    let mut key = rsa_key("rsa", Algorithm::Rs256);
    key.jwk["alg"] = serde_json::json!("RS256");
    let issuer = Issuer::start(&[&key]).await;
    let server = server(issuer.settings()).await;
    let claims = issuer.claims("system/Condition.r");
    assert!(server.authenticate(&mint(&key, &claims)).await.is_ok());
    key.signing = ferrohealth_smart::jws::key::SigningKey::new(
        key.signing.private_key().clone(),
        Algorithm::Ps256,
    )?;
    let mut header = Header::new(Algorithm::Ps256);
    header.kid = Some(String::from("rsa"));
    header.typ = Some(String::from("at+jwt"));
    assert!(
        matches!(
            server
                .authenticate(&mint_with(&key, &header, &claims))
                .await,
            Err(Rejection::Invalid {
                reason: Reason::UnknownKey
            })
        ),
        "RFC 7517 §4.4: a key whose alg is RS256 verifies no PS256 token"
    );
    Ok(())
}
