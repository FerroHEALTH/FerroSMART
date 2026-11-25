// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Sender-constrained tokens: the RFC 9449 and RFC 8705 examples, the `DPoP`
//! proof checks, the replay store, the certificate binding, the issuer's
//! constraint and the gate in front of a router.
//!
//! Every `DPoP` key and signing key is generated when the case runs; the
//! examples' own keys sign nothing here, since their private halves are
//! not published.

mod config;
mod dpop;
#[cfg(feature = "axum")]
mod gate;
mod introspection;
mod mtls;
mod replay;
mod vectors;

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use base64::Engine as _;
use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrohealth_smart::jws::key::SigningKey as JwsKey;
use ferrohealth_smart::refusal::Reason;
use ferrohealth_smart::resource::Caller;
use ferrohealth_smart::resource::Rejection;
use ferrohealth_smart::sender::Check;
use ferrohealth_smart::sender::SenderConstraint;
use ferrohealth_smart::sender::proof::DPOP;
use ferrohealth_smart::sender::proof::ProofCheck;
use ferrohealth_smart::sender::proof::ProofSettings;
use ferrohealth_smart::sender::replay::MemoryReplayStore;
use ferrohealth_smart::sender::replay::ReplayStore;
use http::HeaderMap;
use http::HeaderValue;
use serde_json::Value;
use serde_json::json;

use crate::support::Issuer;
use crate::support::SigningKey;
use crate::support::ec_key;
use crate::support::mint;
use crate::support::now;
use crate::support::server;

/// The external base URL of the surface the cases address, the host of
/// RFC 9449 Figure 13.
pub(crate) const EXTERNAL: &str = "https://resource.example.org";

/// A client's `DPoP` key, generated for the case.
pub(crate) struct DpopKey {
    /// The private half.
    encoding: JwsKey,
    /// The public half, the proof's `jwk` header.
    jwk: Value,
    /// Its RFC 7638 SHA-256 thumbprint, the `cnf.jkt` a bound token names.
    pub(crate) jkt: String,
}

/// Returns a fresh ES256 `DPoP` key.
pub(crate) fn dpop_key() -> DpopKey {
    let key = ec_key("dpop", Algorithm::Es256);
    let public = key.signing.public_jwk();
    let jkt = public.thumbprint();
    let mut jwk = public.to_value();
    // NOTE: RFC 9449 §4.2 puts the public key alone in `jwk`; the members a
    // key set adds are left out.
    if let Some(members) = jwk.as_object_mut() {
        members.retain(|name, _| matches!(name.as_str(), "kty" | "crv" | "x" | "y"));
    }
    DpopKey {
        encoding: key.signing,
        jwk,
        jkt,
    }
}

/// Returns `header` and `claims` signed by `encoding` under `alg`, the
/// compact JWS assembled by hand so a case controls every header member.
pub(crate) fn signed(header: &Value, claims: &Value, encoding: &JwsKey, alg: Algorithm) -> String {
    assert_eq!(
        alg,
        encoding.algorithm(),
        "the key signs the case's algorithm"
    );
    let encode = |value: &Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(value).expect("the JSON serializes"))
    };
    let input = format!("{}.{}", encode(header), encode(claims));
    let signature = encoding.sign(input.as_bytes()).expect("the input signs");
    format!(
        "{input}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
    )
}

/// Returns the proof header RFC 9449 §4.2 requires, for `key`.
pub(crate) fn proof_header(key: &DpopKey) -> Value {
    json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": key.jwk })
}

/// Returns `claims` signed by `key` as a `DPoP` proof.
pub(crate) fn proof(key: &DpopKey, claims: &Value) -> String {
    signed(&proof_header(key), claims, &key.encoding, Algorithm::Es256)
}

/// Returns a `jti` no other proof of the run carries.
pub(crate) fn jti() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "synthetic-jti-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// Returns the base64url SHA-256 of `token`, the `ath` of RFC 9449 §4.2.
pub(crate) fn ath(token: &str) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref())
}

/// Returns the claims of a fresh proof of `method` on `htu` for `token`.
pub(crate) fn proof_claims(method: &str, htu: &str, token: &str) -> Value {
    json!({
        "jti": jti(),
        "htm": method,
        "htu": htu,
        "iat": now(),
        "ath": ath(token),
    })
}

/// Returns headers carrying each of `proofs` in its own `DPoP` field.
pub(crate) fn proofs(proofs: &[&str]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for proof in proofs {
        headers.append(DPOP, HeaderValue::from_str(proof).expect("a header value"));
    }
    headers
}

/// Returns the proof check of [`EXTERNAL`] over `store`.
pub(crate) fn check_over(store: Arc<dyn ReplayStore>) -> ProofCheck {
    ProofCheck::new(ProofSettings::new(EXTERNAL.parse().expect("a URL")), store)
        .expect("the settings hold")
}

/// Returns the proof check of [`EXTERNAL`] over its own in-memory store.
pub(crate) fn check() -> ProofCheck {
    check_over(Arc::new(MemoryReplayStore::new()))
}

/// The issuer of the cases with its signing key.
pub(crate) struct Bound {
    /// The stub authorization server.
    pub(crate) issuer: Issuer,
    /// Its signing key.
    pub(crate) key: SigningKey,
}

impl Bound {
    /// Starts an issuer with a fresh ES256 key.
    pub(crate) async fn start() -> Self {
        let key = ec_key("issuer", Algorithm::Es256);
        let issuer = Issuer::start(&[&key]).await;
        Self { issuer, key }
    }

    /// Returns a token of this issuer whose claims carry `cnf`, when given.
    pub(crate) fn token(&self, cnf: Option<Value>) -> String {
        let mut claims = self.issuer.claims("system/Observation.rs");
        if let Some(cnf) = cnf
            && let Some(members) = claims.as_object_mut()
        {
            members.insert(String::from("cnf"), cnf);
        }
        mint(&self.key, &claims)
    }

    /// Returns the resource server of this issuer under `constraint`.
    pub(crate) async fn server(
        &self,
        constraint: SenderConstraint,
    ) -> Arc<ferrohealth_smart::resource::ResourceServer> {
        let mut settings = self.issuer.settings();
        settings.sender_constraint = constraint;
        server(settings).await
    }
}

/// Asserts that `outcome` is refused by `check`.
pub(crate) fn assert_refused(outcome: &Result<Caller, Rejection>, check: Check, case: &str) {
    assert!(
        matches!(
            outcome,
            Err(Rejection::Invalid { reason: Reason::Sender(found) }) if *found == check
        ),
        "{case}: expected {check:?}, got {outcome:?}"
    );
}
