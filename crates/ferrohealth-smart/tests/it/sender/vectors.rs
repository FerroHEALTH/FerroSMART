// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The official examples: RFC 9449 Figures 2 and 4 (a proof), 9 (a
//! `cnf.jkt` claims set), 13 and 14 (a protected resource request and its
//! proof), and RFC 8705 Figure 2 (an `x5t#S256` claims set) with the
//! Appendix A certificate (Figures 5 and 6).

use std::error::Error as StdError;

use base64::Engine as _;
use ferrohealth_smart::jws::jwk::Jwk;
use ferrohealth_smart::sender::Binding;
use ferrohealth_smart::sender::Check;
use ferrohealth_smart::sender::ClientCertificate;
use ferrohealth_smart::sender::SenderConstraint;
use ferrohealth_smart::sender::proof::Presented;
use http::Method;
use serde_json::json;

use super::Bound;
use super::EXTERNAL;
use super::assert_refused;
use super::check;
use super::dpop_key;
use super::jti;
use super::proof;
use super::proofs;
use crate::support::now;

/// The `DPoP` proof of RFC 9449 Figure 2, whose decoded content is Figure 4.
const FIGURE_2: &str = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg";

/// The `DPoP` proof of RFC 9449 Figure 13, whose decoded content is
/// Figure 14.
const FIGURE_13: &str = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA";

/// The access token of RFC 9449 Figure 13.
const FIGURE_13_TOKEN: &str = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";

/// The `cnf.jkt` of RFC 9449 Figure 9, the thumbprint of the Figure 4 key.
const FIGURE_9_JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

/// The certificate of RFC 8705 Figure 6, without its PEM armour.
const FIGURE_6: &str = "MIIBBjCBrAIBAjAKBggqhkjOPQQDAjAPMQ0wCwYDVQQDDARtdGxzMB4XDTE4MTAxODEyMzcwOVoXDTIyMDUwMjEyMzcwOVowDzENMAsGA1UEAwwEbXRsczBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNcnyxwqV6hY8QnhxxzFQ03C7HKW9OylMbnQZjjJ/Au08/coZwxS7LfA4vOLS9WuneIXhbGGWvsDSb0tH6IxLm8wCgYIKoZIzj0EAwIDSQAwRgIhAP0RC1E+vwJD/D1AGHGzuri+hlV/PpQEKTWUVeORWz83AiEA5x2eXZOVbUlJSGQgjwD5vaUaKlLR50Q2DmFfQj1L+SY=";

/// The `cnf."x5t#S256"` of RFC 8705 Figure 5.
const FIGURE_5: &str = "A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0";

/// The `cnf."x5t#S256"` of RFC 8705 Figure 2.
const FIGURE_2_X5T: &str = "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2";

/// Returns the Appendix A certificate of RFC 8705.
fn appendix_a() -> ClientCertificate {
    let der = base64::engine::general_purpose::STANDARD
        .decode(FIGURE_6)
        .expect("Figure 6 is base64");
    ClientCertificate::from_der(&der)
}

#[test]
fn the_figure_4_key_has_the_figure_9_thumbprint() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 9449 §6.1, Figure 9's `jkt` "is the hash of the public key
    // from the DPoP proofs in the examples", the Figure 4 `jwk`.
    let jwk: Jwk = serde_json::from_value(json!({
        "kty": "EC",
        "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
        "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
        "crv": "P-256"
    }))?;
    assert_eq!(FIGURE_9_JKT, jwk.thumbprint());
    Ok(())
}

#[test]
fn the_figure_2_proof_is_a_token_request_proof_a_resource_refuses() {
    // NOTE: RFC 9449 §4.2 and §7, Figure 2 carries no `ath`, which a proof
    // presented with an access token "MUST also contain".
    let check = check();
    let headers = proofs(&[FIGURE_2]);
    let outcome = check.check(&Presented {
        method: &Method::POST,
        path: "/token",
        headers: &headers,
        token: FIGURE_13_TOKEN,
        certificate: None,
    });
    assert!(
        matches!(
            outcome,
            Err(ferrohealth_smart::resource::Rejection::Invalid {
                reason: ferrohealth_smart::refusal::Reason::Sender(Check::ProofClaim)
            })
        ),
        "{outcome:?}"
    );
}

#[test]
fn the_figure_13_proof_passes_every_check_but_its_2019_iat() {
    // NOTE: RFC 9449 §4.3 and §7.1, Figure 13's request to Figure 14's `htu`;
    // its signature, `htm`, `htu` and `ath` hold, and its `iat` of 2019 is
    // outside any window, so the check refuses it as stale and nothing else.
    let check = super::check_over(std::sync::Arc::new(
        ferrohealth_smart::sender::replay::MemoryReplayStore::new(),
    ));
    let headers = proofs(&[FIGURE_13]);
    let presented = Presented {
        method: &Method::GET,
        path: "/protectedresource",
        headers: &headers,
        token: FIGURE_13_TOKEN,
        certificate: None,
    };
    let outcome = check.check(&presented);
    assert!(
        matches!(
            outcome,
            Err(ferrohealth_smart::resource::Rejection::Invalid {
                reason: ferrohealth_smart::refusal::Reason::Sender(Check::ProofStale)
            })
        ),
        "{outcome:?}"
    );
    let another_token = check.check(&Presented {
        token: "another-token",
        ..presented
    });
    assert!(
        matches!(
            another_token,
            Err(ferrohealth_smart::resource::Rejection::Invalid {
                reason: ferrohealth_smart::refusal::Reason::Sender(Check::ProofTokenHash)
            })
        ),
        "Figure 14's ath names the Figure 13 token alone: {another_token:?}"
    );
}

#[test]
fn the_figure_13_request_resigned_now_is_accepted() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 9449 Figure 14, re-signed with a test key and an `iat` of now,
    // since the figure's private key is not published and its `iat` is 2019.
    let key = dpop_key();
    let claims = json!({
        "jti": "e1j3V_bKic8-LAEB",
        "htm": "GET",
        "htu": "https://resource.example.org/protectedresource",
        "iat": now(),
        "ath": "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
    });
    let headers = proofs(&[&proof(&key, &claims)]);
    let proven = check().check(&Presented {
        method: &Method::GET,
        path: "/protectedresource",
        headers: &headers,
        token: FIGURE_13_TOKEN,
        certificate: None,
    })?;
    assert_eq!(key.jkt, proven.key().jkt());
    Ok(())
}

#[tokio::test]
async fn the_figure_9_claims_set_resigned_is_bound_to_its_key() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 9449 Figure 9, re-signed by a test issuer with `exp` and `nbf`
    // moved to now and `aud`, `client_id`, `iat`, `jti` and `scope` added for RFC
    // 9068 §2.2; its `jkt` is the test DPoP key's, the figure's being unpublished.
    let bound = Bound::start().await;
    let key = dpop_key();
    let mut claims = json!({
        "sub": "someone@example.com",
        "iss": bound.issuer.uri(),
        "nbf": now() - 5,
        "exp": now() + 300,
        "cnf": { "jkt": key.jkt }
    });
    claims["aud"] = json!(crate::support::AUDIENCE);
    claims["client_id"] = json!(crate::support::CLIENT);
    claims["iat"] = json!(now());
    claims["jti"] = json!(jti());
    claims["scope"] = json!("openid");
    let token = crate::support::mint(&bound.key, &claims);
    let server = bound.server(SenderConstraint::None).await;
    let htu = format!("{EXTERNAL}/protectedresource");
    let headers = proofs(&[&proof(&key, &super::proof_claims("GET", &htu, &token))]);
    let caller = check()
        .authenticate(
            server.as_ref(),
            &Presented {
                method: &Method::GET,
                path: "/protectedresource",
                headers: &headers,
                token: &token,
                certificate: None,
            },
        )
        .await?;
    assert_eq!("someone@example.com", caller.subject());
    assert_refused(
        &server.authenticate(&token).await,
        Check::KeyBoundAsBearer,
        "RFC 9449 §7.2: the Figure 9 token as a bearer token",
    );
    Ok(())
}

#[test]
fn the_appendix_a_certificate_has_the_figure_5_thumbprint() {
    // NOTE: RFC 8705 Appendix A, Figure 5 "and the X.509 certificate from
    // which it was calculated", Figure 6.
    assert_eq!(FIGURE_5, appendix_a().thumbprint());
}

#[tokio::test]
async fn the_figure_2_claims_set_is_accepted_with_the_appendix_a_certificate()
-> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 8705 Figure 2 with Figure 5's `x5t#S256`, re-signed by a test
    // issuer with `exp` and `nbf` moved to now and the RFC 9068 §2.2 claims added.
    let bound = Bound::start().await;
    let claims = json!({
        "iss": bound.issuer.uri(),
        "sub": "ty.webb@example.com",
        "exp": now() + 300,
        "nbf": now() - 5,
        "cnf": { "x5t#S256": FIGURE_5 },
        "aud": crate::support::AUDIENCE,
        "client_id": crate::support::CLIENT,
        "iat": now(),
        "jti": jti(),
        "scope": "openid",
    });
    let token = crate::support::mint(&bound.key, &claims);
    let server = bound.server(SenderConstraint::Required).await;
    let caller = server
        .authenticate_bound(&token, &Binding::bearer().with_certificate(&appendix_a()))
        .await?;
    assert_eq!("ty.webb@example.com", caller.subject());
    Ok(())
}

#[tokio::test]
async fn the_figure_2_thumbprint_as_published_names_no_appendix_a_certificate() {
    // NOTE: RFC 8705 Figure 2's `x5t#S256` is not Figure 5's: it is the hash of
    // no certificate the RFC publishes, so the Appendix A one does not match it.
    let bound = Bound::start().await;
    let token = bound.token(Some(json!({ "x5t#S256": FIGURE_2_X5T })));
    let server = bound.server(SenderConstraint::Required).await;
    let outcome = server
        .authenticate_bound(&token, &Binding::bearer().with_certificate(&appendix_a()))
        .await;
    assert_refused(
        &outcome,
        Check::CertificateMismatch,
        "Figure 2 as published",
    );
}
