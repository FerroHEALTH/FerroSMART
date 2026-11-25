// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The assertion key read without a configured algorithm, each EC key by its
//! curve (RFC 7518 §3.4), and the JWS of a product's own claims it signs
//! under the `typ` the product names (RFC 7515 §7.1, RFC 8725 §3.11).

use std::error::Error as StdError;
use std::time::Duration;

use ferrohealth_smart::client::assertion::AssertionError;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrohealth_smart::client::keys::KeyRing;
use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrohealth_smart::jws::claims::Validation;
use serde::Serialize;

use crate::support::ec_key;
use crate::support::ed_key;
use crate::support::header;
use crate::support::ml_dsa_key;
use crate::support::p521_pem;
use crate::support::rsa_key;
use crate::support::verified;

/// The claims of a product's own token.
#[derive(Serialize)]
struct Own<'a> {
    iss: &'a str,
    sub: &'a str,
    exp: i64,
}

#[test]
fn an_ec_key_signs_the_algorithm_of_its_curve() -> Result<(), Box<dyn StdError>> {
    for (generated, expected) in [
        (Algorithm::Es256, Algorithm::Es256),
        (Algorithm::Es384, Algorithm::Es384),
    ] {
        let key = AssertionKey::from_pem(&ec_key("unused", generated).pem, None, None)?;
        assert_eq!(expected, key.algorithm(), "RFC 7518 §3.4");
        assert_eq!(
            serde_json::to_value(expected)?,
            key.public_jwk()["alg"],
            "the published key names its algorithm"
        );
        assert!(
            key.assertion("synthetic-client", "https://as.example.org/token", "JWT")
                .is_ok()
        );
    }
    assert_eq!(
        Algorithm::Rs384,
        AssertionKey::from_pem(&rsa_key("unused", Algorithm::Rs256).pem, None, None)?.algorithm()
    );
    assert_eq!(
        Algorithm::EdDsa,
        AssertionKey::from_pem(&ed_key("unused").pem, None, None)?.algorithm()
    );
    Ok(())
}

#[test]
fn an_ml_dsa_key_signs_its_parameter_set_and_publishes_an_akp_key() -> Result<(), Box<dyn StdError>>
{
    for algorithm in [Algorithm::MlDsa44, Algorithm::MlDsa65, Algorithm::MlDsa87] {
        let key = AssertionKey::from_pem(&ml_dsa_key("unused", algorithm).pem, None, None)?;
        assert_eq!(algorithm, key.algorithm(), "RFC 9964 §5");
        let public = key.public_jwk();
        assert_eq!("AKP", public["kty"], "RFC 9964 §3");
        assert_eq!(
            algorithm.name(),
            public["alg"],
            "RFC 9964 §3: alg is REQUIRED"
        );
        assert_eq!(key.kid(), public["kid"]);
        assert!(
            public.get("priv").is_none(),
            "RFC 9964 §3: no priv in a public key"
        );
        let assertion = key.assertion("synthetic-client", "https://as.example.org/token", "JWT")?;
        assert_eq!(algorithm, header(&assertion).alg);
        let claims = verified(&assertion, &public);
        assert_eq!(
            Some(&serde_json::json!("synthetic-client")),
            claims.get("sub")
        );
        for other in [Algorithm::Es256, Algorithm::Rs256] {
            assert!(
                matches!(
                    key.clone().with_algorithm(other),
                    Err(AssertionError::Algorithm { .. })
                ),
                "{algorithm} signs nothing else"
            );
        }
    }
    let other_set = ml_dsa_key("unused", Algorithm::MlDsa44);
    assert!(
        matches!(
            AssertionKey::from_pem(&other_set.pem, Some(Algorithm::MlDsa65), None),
            Err(AssertionError::Algorithm {
                algorithm: Algorithm::MlDsa65
            })
        ),
        "an ML-DSA-44 key signs no ML-DSA-65"
    );
    Ok(())
}

#[test]
fn an_ec_key_on_another_curve_is_refused_without_an_algorithm() {
    let refused = AssertionKey::from_pem(&p521_pem(), None, None);
    assert!(
        matches!(refused, Err(AssertionError::Curve)),
        "a P-521 key signs neither ES256 nor ES384: {refused:?}"
    );
}

#[test]
fn a_configured_algorithm_still_overrides_the_curve() {
    let p256 = ec_key("unused", Algorithm::Es256);
    assert!(
        AssertionKey::from_pem(&p256.pem, Some(Algorithm::Es384), None).is_err(),
        "a P-256 key cannot sign ES384"
    );
    assert!(AssertionKey::from_pem(&p256.pem, Some(Algorithm::Es256), None).is_ok());
}

#[test]
fn the_rings_current_key_signs_a_products_own_claims_under_its_type()
-> Result<(), Box<dyn StdError>> {
    let current = AssertionKey::from_pem(&ec_key("unused", Algorithm::Es256).pem, None, None)?;
    let previous = AssertionKey::from_pem(&ec_key("unused", Algorithm::Es384).pem, None, None)?;
    let ring = KeyRing::new(current).with_previous_for(previous, Duration::from_secs(60))?;
    let key = ring.current();
    let claims = Own {
        iss: "urn:example:product",
        sub: "synthetic-subject",
        exp: jiff::Timestamp::now().as_second().saturating_add(60),
    };
    let token = key.sign("example+jwt", &claims)?;

    let header = header(&token);
    assert_eq!(Algorithm::Es256, header.alg);
    assert_eq!(
        Some(String::from("example+jwt")),
        header.typ,
        "RFC 8725 §3.11"
    );
    assert_eq!(Some(key.kid().to_owned()), header.kid);
    let read = verified(&token, &key.public_jwk());
    Validation::default()
        .with_issuer("urn:example:product")
        .with_required(&["exp", "sub"])
        .check(&read)?;
    assert_eq!(
        Some(&serde_json::json!("synthetic-subject")),
        read.get("sub")
    );
    let published = ring.published();
    assert!(
        published["keys"]
            .as_array()
            .ok_or("keys")?
            .iter()
            .any(|jwk| jwk["kid"] == key.kid()),
        "the published set verifies what the current key signs"
    );
    Ok(())
}

#[test]
fn a_client_assertion_lives_sixty_seconds() -> Result<(), Box<dyn StdError>> {
    let key = AssertionKey::from_pem(&ec_key("unused", Algorithm::Es256).pem, None, None)?;
    let assertion = key.assertion("synthetic-client", "https://as.example.org/token", "JWT")?;

    let claims = verified(&assertion, &key.public_jwk());
    Validation::default()
        .with_audiences(["https://as.example.org/token"])
        .with_required(&["exp", "iat"])
        .check(&claims)?;
    let iat = claims
        .get("iat")
        .and_then(serde_json::Value::as_i64)
        .ok_or("iat")?;
    let exp = claims
        .get("exp")
        .and_then(serde_json::Value::as_i64)
        .ok_or("exp")?;
    assert_eq!(
        60,
        exp - iat,
        "within SMART App Launch 2.2.0's five minutes and an issuer's 120-second cap"
    );
    Ok(())
}

#[test]
fn an_rsa_key_signs_any_rsa_algorithm_and_an_ec_key_only_its_own() -> Result<(), Box<dyn StdError>>
{
    let rsa = AssertionKey::from_pem(
        &rsa_key("unused", Algorithm::Rs256).pem,
        Some(Algorithm::Rs256),
        None,
    )?;
    assert_eq!(
        Algorithm::Ps256,
        rsa.with_algorithm(Algorithm::Ps256)?.algorithm()
    );
    let ec = AssertionKey::from_pem(&ec_key("unused", Algorithm::Es256).pem, None, None)?;
    for other in [Algorithm::Es384, Algorithm::Rs256] {
        assert!(
            matches!(
                ec.clone().with_algorithm(other),
                Err(AssertionError::Algorithm { algorithm }) if algorithm == other
            ),
            "RFC 7518 §3.4: an EC key signs with its curve's algorithm"
        );
    }
    Ok(())
}

#[cfg(feature = "oidc")]
#[test]
fn a_certificate_of_another_key_or_no_certificate_is_refused() -> Result<(), Box<dyn StdError>> {
    let own = rcgen::KeyPair::generate()?;
    let other = rcgen::KeyPair::generate()?;
    let theirs = rcgen::CertificateParams::new(vec![String::from("other.example.org")])?
        .self_signed(&other)?;
    let key = AssertionKey::from_pem(own.serialize_pem().as_bytes(), None, None)?;
    assert!(matches!(
        key.clone().with_certificate(theirs.pem().as_bytes()),
        Err(AssertionError::CertificateKey)
    ));
    assert!(matches!(
        key.clone().with_certificate(own.serialize_pem().as_bytes()),
        Err(AssertionError::Certificate)
    ));
    let mine =
        rcgen::CertificateParams::new(vec![String::from("own.example.org")])?.self_signed(&own)?;
    let named = key.with_certificate(mine.pem().as_bytes())?;
    let token = named.sign(
        "synthetic+jwt",
        &Own {
            iss: "a",
            sub: "a",
            exp: 1,
        },
    )?;
    assert!(header(&token).x5t_s256.is_some(), "RFC 7515 §4.1.8");
    Ok(())
}
