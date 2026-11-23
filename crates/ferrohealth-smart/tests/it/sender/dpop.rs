// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A `DPoP`-bound token with a valid proof is admitted, and each check of
//! RFC 9449 §4.3 and §7.1 refuses the proof or the token that fails it.

use std::error::Error as StdError;
use std::future::Future;
use std::sync::Arc;

use ferrohealth_smart::resource::Caller;
use ferrohealth_smart::resource::Rejection;
use ferrohealth_smart::sender::Check;
use ferrohealth_smart::sender::SenderConstraint;
use ferrohealth_smart::sender::proof::Presented;
use ferrohealth_smart::sender::proof::ProofCheck;
use ferrohealth_smart::sender::proof::ProofSettings;
use ferrohealth_smart::sender::replay::MemoryReplayStore;
use http::HeaderMap;
use http::Method;
use jsonwebtoken::Algorithm;
use serde_json::Value;
use serde_json::json;

use super::Bound;
use super::DpopKey;
use super::EXTERNAL;
use super::assert_refused;
use super::check;
use super::dpop_key;
use super::proof;
use super::proof_claims;
use super::proof_header;
use super::proofs;
use super::signed;
use crate::support::now;

/// The path every case addresses.
const PATH: &str = "/fhir/Observation/o-1";

/// One `DPoP` case: a bound token, its issuer and the client's key.
struct Case {
    /// The issuer and its server.
    bound: Bound,
    /// The client's `DPoP` key.
    key: DpopKey,
    /// A token of the issuer bound to `key`.
    token: String,
}

impl Case {
    /// Starts an issuer and mints a token bound to a fresh key.
    async fn start() -> Self {
        let bound = Bound::start().await;
        let key = dpop_key();
        let token = bound.token(Some(json!({ "jkt": key.jkt })));
        Self { bound, key, token }
    }

    /// Returns the claims of a fresh proof of `GET` on the case's path.
    fn claims(&self) -> Value {
        proof_claims("GET", &format!("{EXTERNAL}{PATH}"), &self.token)
    }

    /// Returns the outcome of `GET` on the case's path with `headers`,
    /// checked by `check`.
    async fn send(&self, check: &ProofCheck, headers: &HeaderMap) -> Result<Caller, Rejection> {
        let server = self.bound.server(SenderConstraint::None).await;
        check
            .authenticate(
                server.as_ref(),
                &Presented {
                    method: &Method::GET,
                    path: PATH,
                    headers,
                    token: &self.token,
                    certificate: None,
                },
            )
            .await
    }

    /// Returns the outcome of the proof `claims` signed by the case's key.
    async fn with_claims(&self, claims: &Value) -> Result<Caller, Rejection> {
        self.send(&check(), &proofs(&[&proof(&self.key, claims)]))
            .await
    }
}

#[tokio::test]
async fn a_dpop_bound_token_with_a_valid_proof_is_admitted() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 9449 §7.1, the proof checked by §4.3 and its key matching the
    // token's `cnf.jkt` (§6.1).
    let case = Case::start().await;
    let caller = case.with_claims(&case.claims()).await?;
    assert_eq!("synthetic-client-sub", caller.subject());
    Ok(())
}

#[tokio::test]
async fn a_missing_proof_is_refused() {
    // NOTE: RFC 9449 §7.1, "a resource server MUST check that a DPoP proof
    // was also received in the DPoP header field".
    let case = Case::start().await;
    let outcome = case.send(&check(), &HeaderMap::new()).await;
    assert_refused(&outcome, Check::ProofMissing, "no DPoP header");
}

#[tokio::test]
async fn two_proofs_are_refused() {
    // NOTE: RFC 9449 §4.3 check 1, "not more than one DPoP HTTP request
    // header field".
    let case = Case::start().await;
    let one = proof(&case.key, &case.claims());
    let two = proof(&case.key, &case.claims());
    let outcome = case.send(&check(), &proofs(&[&one, &two])).await;
    assert_refused(&outcome, Check::ProofRepeated, "two DPoP headers");
}

#[tokio::test]
async fn a_wrong_htu_is_refused() {
    // NOTE: RFC 9449 §4.3 check 9, `htu` matches the request's URI.
    let case = Case::start().await;
    let mut claims = case.claims();
    claims["htu"] = json!(format!("{EXTERNAL}/fhir/Observation/o-2"));
    assert_refused(
        &case.with_claims(&claims).await,
        Check::ProofUri,
        "another path",
    );
    claims["htu"] = json!(format!("https://other.example.org{PATH}"));
    assert_refused(
        &case.with_claims(&claims).await,
        Check::ProofUri,
        "another host",
    );
}

#[tokio::test]
async fn a_wrong_htm_is_refused() {
    // NOTE: RFC 9449 §4.3 check 8, `htm` matches the request's method.
    let case = Case::start().await;
    let mut claims = case.claims();
    claims["htm"] = json!("POST");
    assert_refused(&case.with_claims(&claims).await, Check::ProofMethod, "POST");
    claims["htm"] = json!("get");
    assert_refused(
        &case.with_claims(&claims).await,
        Check::ProofMethod,
        "RFC 9110 §9.1: the method is case-sensitive",
    );
}

#[tokio::test]
async fn a_stale_iat_is_refused() {
    // NOTE: RFC 9449 §4.3 check 11 and §11.1, a proof is accepted only "for a
    // limited time after their creation"; the default window is 60 seconds.
    let case = Case::start().await;
    let mut claims = case.claims();
    claims["iat"] = json!(now() - 600);
    assert_refused(&case.with_claims(&claims).await, Check::ProofStale, "stale");
}

#[tokio::test]
async fn an_iat_beyond_the_skew_is_refused() {
    // NOTE: RFC 9449 §11.1, a server "MAY accept" an `iat` "in the reasonably
    // near future"; one beyond the clock skew is not.
    let case = Case::start().await;
    let mut claims = case.claims();
    claims["iat"] = json!(now() + 600);
    assert_refused(
        &case.with_claims(&claims).await,
        Check::ProofFuture,
        "ahead",
    );
}

#[tokio::test]
async fn a_mismatched_jkt_is_refused() {
    // NOTE: RFC 9449 §4.3 check 12, the token's bound key "matches the public
    // key from the DPoP proof".
    let case = Case::start().await;
    let other = dpop_key();
    let headers = proofs(&[&proof(&other, &case.claims())]);
    assert_refused(
        &case.send(&check(), &headers).await,
        Check::KeyMismatch,
        "another key",
    );
}

#[tokio::test]
async fn a_wrong_ath_is_refused() {
    // NOTE: RFC 9449 §4.3 check 12, `ath` "equals the hash of that access
    // token".
    let case = Case::start().await;
    let mut claims = case.claims();
    claims["ath"] = json!(super::ath("another-token"));
    assert_refused(
        &case.with_claims(&claims).await,
        Check::ProofTokenHash,
        "another token's hash",
    );
}

#[tokio::test]
async fn a_proof_missing_a_required_claim_is_refused() {
    // NOTE: RFC 9449 §4.2 and §4.3 check 3, `jti`, `htm`, `htu`, `iat` and,
    // with an access token, `ath`.
    let case = Case::start().await;
    for claim in ["jti", "htm", "htu", "iat", "ath"] {
        let mut claims = case.claims();
        if let Some(members) = claims.as_object_mut() {
            members.remove(claim);
        }
        assert_refused(&case.with_claims(&claims).await, Check::ProofClaim, claim);
    }
}

#[tokio::test]
async fn a_proof_of_another_type_is_refused() {
    // NOTE: RFC 9449 §4.3 check 4 and §11.5, `typ` is `dpop+jwt`, so a JWT
    // made for another purpose is not spent as a proof.
    let case = Case::start().await;
    for typ in [json!("at+jwt"), json!("JWT"), Value::Null] {
        let mut header = proof_header(&case.key);
        header["typ"] = typ.clone();
        let jwt = signed(
            &header,
            &case.claims(),
            &case_encoding(&case),
            Algorithm::ES256,
        );
        assert_refused(
            &case.send(&check(), &proofs(&[&jwt])).await,
            Check::ProofType,
            &typ.to_string(),
        );
    }
    let mut header = proof_header(&case.key);
    header["typ"] = json!("application/DPoP+JWT");
    let jwt = signed(
        &header,
        &case.claims(),
        &case_encoding(&case),
        Algorithm::ES256,
    );
    assert!(
        case.send(&check(), &proofs(&[&jwt])).await.is_ok(),
        "RFC 7515 §4.1.9: the media type with its prefix, in any case"
    );
}

/// Returns the private half of the case's key.
fn case_encoding(case: &Case) -> jsonwebtoken::EncodingKey {
    case.key.encoding.clone()
}

#[tokio::test]
async fn a_proof_whose_jwk_carries_a_private_key_is_refused() {
    // NOTE: RFC 9449 §4.3 check 7, the `jwk` "does not contain a private key".
    let case = Case::start().await;
    let mut header = proof_header(&case.key);
    header["jwk"]["d"] = json!("c3ludGhldGljLXByaXZhdGUtc2NhbGFy");
    let jwt = signed(
        &header,
        &case.claims(),
        &case_encoding(&case),
        Algorithm::ES256,
    );
    assert_refused(
        &case.send(&check(), &proofs(&[&jwt])).await,
        Check::ProofKey,
        "a private member",
    );
    let mut header = proof_header(&case.key);
    if let Some(members) = header.as_object_mut() {
        members.remove("jwk");
    }
    let jwt = signed(
        &header,
        &case.claims(),
        &case_encoding(&case),
        Algorithm::ES256,
    );
    assert_refused(
        &case.send(&check(), &proofs(&[&jwt])).await,
        Check::ProofKey,
        "no jwk",
    );
}

#[tokio::test]
async fn a_symmetric_or_absent_algorithm_is_refused() {
    // NOTE: RFC 9449 §4.3 check 5 and §11.6, "the algorithm none MUST NOT be
    // allowed", nor a MAC.
    let case = Case::start().await;
    for alg in ["none", "HS256"] {
        let mut header = proof_header(&case.key);
        header["alg"] = json!(alg);
        let jwt = signed(
            &header,
            &case.claims(),
            &case_encoding(&case),
            Algorithm::ES256,
        );
        assert_refused(
            &case.send(&check(), &proofs(&[&jwt])).await,
            Check::ProofAlgorithm,
            alg,
        );
    }
}

#[tokio::test]
async fn a_proof_signed_by_another_key_is_refused() {
    // NOTE: RFC 9449 §4.3 check 6, the signature "verifies with the public
    // key contained in the jwk".
    let case = Case::start().await;
    let other = dpop_key();
    let jwt = signed(
        &proof_header(&case.key),
        &case.claims(),
        &other.encoding,
        Algorithm::ES256,
    );
    assert_refused(
        &case.send(&check(), &proofs(&[&jwt])).await,
        Check::ProofSignature,
        "the jwk is not the signer",
    );
}

#[tokio::test]
async fn a_malformed_proof_is_refused() {
    // NOTE: RFC 9449 §4.3 check 2, "a single and well-formed JWT".
    let case = Case::start().await;
    for jwt in ["not-a-jwt", "a.b.c", "a b.c.d"] {
        let headers = {
            let mut headers = HeaderMap::new();
            headers.insert(
                ferrohealth_smart::sender::proof::DPOP,
                http::HeaderValue::from_str(jwt).expect("a header value"),
            );
            headers
        };
        assert_refused(
            &case.send(&check(), &headers).await,
            Check::ProofMalformed,
            jwt,
        );
    }
}

#[tokio::test]
async fn an_unbound_token_with_the_dpop_scheme_is_refused() {
    // NOTE: RFC 9449 §7.1, the proof's key must match "the public key to
    // which the access token is bound", which an unbound token names none of.
    let bound = Bound::start().await;
    let key = dpop_key();
    let token = bound.token(None);
    let server = bound.server(SenderConstraint::None).await;
    let headers = proofs(&[&proof(
        &key,
        &proof_claims("GET", &format!("{EXTERNAL}{PATH}"), &token),
    )]);
    let outcome = check()
        .authenticate(
            server.as_ref(),
            &Presented {
                method: &Method::GET,
                path: PATH,
                headers: &headers,
                token: &token,
                certificate: None,
            },
        )
        .await;
    assert_refused(&outcome, Check::NotKeyBound, "a bearer token as DPoP");
}

#[tokio::test]
async fn behind_a_proxy_the_htu_names_the_configured_external_url() -> Result<(), Box<dyn StdError>>
{
    // NOTE: RFC 9449 §4.3 check 9 holds `htu` to the URI "for the HTTP request
    // in which the JWT was received", which behind a proxy is the external one.
    let case = Case::start().await;
    let external = "https://ehr.example.org/api";
    let check = ProofCheck::new(
        ProofSettings::new(external.parse()?),
        Arc::new(MemoryReplayStore::new()),
    )?;
    let addressed = proof_claims("GET", &format!("{external}{PATH}"), &case.token);
    let caller = case
        .send(&check, &proofs(&[&proof(&case.key, &addressed)]))
        .await?;
    assert_eq!("synthetic-client-sub", caller.subject());
    let internal = proof_claims("GET", &format!("http://10.0.0.7:8080{PATH}"), &case.token);
    assert_refused(
        &case
            .send(&check, &proofs(&[&proof(&case.key, &internal)]))
            .await,
        Check::ProofUri,
        "the URI the server sees",
    );
    Ok(())
}

#[tokio::test]
async fn a_product_verifier_refuses_a_dpop_request_by_default() {
    // NOTE: no specification governs this: our own design; a verifier that
    // reads no `cnf` never admits a request that proves a key.
    struct Plain;
    impl ferrohealth_smart::resource::Verifier for Plain {
        fn verify<'a>(
            &'a self,
            _token: &'a str,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<Caller, Rejection>> + Send + 'a>>
        {
            Box::pin(std::future::ready(Ok(Caller::new(
                String::from("plain"),
                None,
                "",
                None,
                ferrohealth_smart::kind::CallerKind::Person,
            ))))
        }
    }
    let key = dpop_key();
    let token = "synthetic-opaque-token";
    let headers = proofs(&[&proof(
        &key,
        &proof_claims("GET", &format!("{EXTERNAL}{PATH}"), token),
    )]);
    let outcome = check()
        .authenticate(
            &Plain,
            &Presented {
                method: &Method::GET,
                path: PATH,
                headers: &headers,
                token,
                certificate: None,
            },
        )
        .await;
    assert_refused(&outcome, Check::Unsupported, "a plain verifier");
}

#[tokio::test]
async fn a_proof_at_the_token_endpoint_carries_no_token_hash() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 9449 §4.2 and §5, a proof sent to the token endpoint presents no
    // access token, so it carries no `ath`; the other checks of §4.3 hold.
    let key = dpop_key();
    let url = format!("{EXTERNAL}/token");
    let mut claims = proof_claims("POST", &url, "unused");
    if let Some(members) = claims.as_object_mut() {
        members.remove("ath");
    }
    let check = check();
    let admitted =
        check.check_token_request(&Method::POST, "/token", &proofs(&[&proof(&key, &claims)]))?;
    assert_eq!(key.jkt, admitted.key().jkt());
    claims["htu"] = json!(format!("{EXTERNAL}/elsewhere"));
    claims["jti"] = json!("another-jti");
    assert!(
        check
            .check_token_request(&Method::POST, "/token", &proofs(&[&proof(&key, &claims)]))
            .is_err(),
        "§4.3 check 9, the htu names this endpoint"
    );
    Ok(())
}
