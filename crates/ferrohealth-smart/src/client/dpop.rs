// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The client half of `DPoP` (RFC 9449): the key a client grant binds its
//! tokens to, and the proof it signs for every request.
//!
//! A [`DpopKey`] signs one proof per request: a JWS typed [`PROOF_TYPE`]
//! whose header carries the public key, and whose claims bind the request's
//! method (`htm`) and its URL without query and fragment (`htu`), with a
//! fresh `jti` and `iat`, and, on a request that presents an access token,
//! `ath`, the hash of that token (RFC 9449 §4.2). A token request proves
//! itself in the crate's token client; a resource request proves itself
//! through the seam a product's own HTTP client calls, [`DpopKey::proof`],
//! or through [`TokenSource::send`](crate::client::cache::TokenSource::send).
//!
//! A server that demands a nonce sends one in [`NONCE_HEADER`]: the token
//! endpoint with `400` and [`USE_NONCE`] (RFC 9449 §8), a resource with
//! `401` and a `DPoP` challenge naming it (§9). The request is sent once
//! more with the nonce in a new proof. Every nonce a server sends is kept
//! per origin and per [`Role`], so the token endpoint's never reaches a
//! resource on the same origin (§9), and goes into the next proof to that
//! server.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;

use base64::Engine as _;
use http::HeaderMap;
use http::Method;
use http::StatusCode;
use serde::Serialize;
use url::Url;

use crate::jws::JwsError;
use crate::jws::algorithm::Algorithm;
use crate::jws::compact::Header;
use crate::jws::jwk::Jwk;
use crate::jws::key::KeyError;
use crate::jws::key::PrivateKey;
use crate::jws::key::SigningKey;

/// The header a proof travels in (RFC 9449 §4.1).
pub const HEADER: &str = "DPoP";

/// The authentication scheme a `DPoP`-bound token is sent under (RFC 9449
/// §7.1), and the `token_type` the token endpoint names it by (§5).
pub const SCHEME: &str = "DPoP";

/// The header a server sends a nonce in (RFC 9449 §8, §9).
pub const NONCE_HEADER: &str = "DPoP-Nonce";

/// The JOSE `typ` of a proof (RFC 9449 §4.2).
pub const PROOF_TYPE: &str = "dpop+jwt";

/// The `error` a server names when it demands a nonce (RFC 9449 §8, §9).
pub const USE_NONCE: &str = "use_dpop_nonce";

/// A `DPoP` key that cannot be read.
///
/// No variant carries the key or any part of it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DpopKeyError {
    /// The PEM is no EC or ML-DSA private key.
    #[error("the DPoP key is not an EC or ML-DSA private key in PEM form")]
    Key {
        /// What the key reader reported, when it read no key at all.
        #[source]
        source: Option<KeyError>,
    },
    /// The key is on neither P-256 nor P-384, the curves ES256 and ES384
    /// sign with (RFC 7518 §3.4).
    #[error("the DPoP key is on neither P-256 (ES256) nor P-384 (ES384)")]
    Curve,
}

/// A proof that could not be signed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DpopError {
    /// The random source for `jti` failed.
    #[error("the random source for the DPoP proof id failed")]
    Random,
    /// The proof could not be signed.
    #[error("the DPoP proof could not be signed")]
    Sign {
        /// What the signer reported.
        #[source]
        source: JwsError,
    },
    /// The signed proof is no header field value.
    #[error("the DPoP proof is not a header field value")]
    Header,
}

/// The part a server plays toward a `DPoP`-bound client, which keeps the
/// nonces of each apart (RFC 9449 §9: the nonces of an authorization server
/// and of a resource server are never confused).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// The authorization server: a token endpoint (§8).
    Authorization,
    /// A resource server (§9).
    Resource,
}

/// The key a client's tokens are bound to, and the nonces its servers sent.
///
/// It is shared as an `Arc` by the grant that obtains the tokens and the
/// product's client that sends them. `Debug` shows the algorithm and the
/// thumbprint alone.
pub struct DpopKey {
    /// The private half, with the algorithm every proof is signed with.
    signing: SigningKey,
    /// The RFC 7638 SHA-256 thumbprint of the public half.
    thumbprint: String,
    /// The last nonce each server sent, by role and origin.
    nonces: Mutex<BTreeMap<(Role, String), String>>,
}

impl std::fmt::Debug for DpopKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopKey")
            .field("algorithm", &self.signing.algorithm())
            .field("thumbprint", &self.thumbprint)
            .finish_non_exhaustive()
    }
}

/// The claims of one proof (RFC 9449 §4.2).
#[derive(Serialize)]
struct Claims<'a> {
    /// The unique id of the proof.
    jti: String,
    /// The request's method.
    htm: &'a str,
    /// The request's URL without query and fragment.
    htu: &'a str,
    /// The issue time.
    iat: i64,
    /// The hash of the access token the request presents.
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<String>,
    /// The nonce the server sent last.
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
}

impl DpopKey {
    /// Returns the private key `pem` holds: an EC key, PKCS#8 or SEC 1, a
    /// P-256 key signing ES256 and a P-384 key ES384 (RFC 7518 §3.4), or an
    /// ML-DSA key, PKCS#8 (RFC 9881 §6), signing with its parameter set
    /// (RFC 9964 §2), each an asymmetric algorithm as RFC 9449 §4.2 asks.
    ///
    /// # Errors
    ///
    /// Returns [`DpopKeyError::Key`] for a PEM that is no EC or ML-DSA
    /// private key and [`DpopKeyError::Curve`] for an EC key on another
    /// curve.
    pub fn from_pem(pem: &[u8]) -> Result<Self, DpopKeyError> {
        let private = PrivateKey::from_pem(pem).map_err(|source| match source {
            KeyError::Curve => DpopKeyError::Curve,
            source => DpopKeyError::Key {
                source: Some(source),
            },
        })?;
        let Some(
            algorithm @ (Algorithm::Es256
            | Algorithm::Es384
            | Algorithm::MlDsa44
            | Algorithm::MlDsa65
            | Algorithm::MlDsa87),
        ) = private.algorithm()
        else {
            return Err(DpopKeyError::Key { source: None });
        };
        let signing = SigningKey::new(private, algorithm).map_err(|source| DpopKeyError::Key {
            source: Some(source),
        })?;
        let thumbprint = signing.public_jwk().thumbprint();
        Ok(Self {
            signing,
            thumbprint,
            nonces: Mutex::new(BTreeMap::new()),
        })
    }

    /// Returns the algorithm every proof is signed with.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.signing.algorithm()
    }

    /// Returns the public key every proof carries.
    #[must_use]
    pub const fn public_jwk(&self) -> &Jwk {
        self.signing.public_jwk()
    }

    /// Returns the key's RFC 7638 SHA-256 thumbprint, the `jkt` a token
    /// bound to it names (RFC 9449 §6.1).
    #[must_use]
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    /// Returns the proof of a request with `method` to `url`, a server in
    /// `role`, presenting `access_token` when it carries one, with the nonce
    /// that server sent last (RFC 9449 §4.2).
    ///
    /// The proof's `htu` is `url` without its query and fragment, and its
    /// `ath` the base64url SHA-256 of `access_token` (§4.2, §7.1).
    ///
    /// # Errors
    ///
    /// Returns [`DpopError::Random`] when no `jti` could be drawn and
    /// [`DpopError::Sign`] when the signature failed.
    pub fn proof(
        &self,
        method: &Method,
        url: &Url,
        role: Role,
        access_token: Option<&str>,
    ) -> Result<String, DpopError> {
        let nonce = self.nonce(role, url);
        let mut htu = url.clone();
        htu.set_query(None);
        htu.set_fragment(None);
        let mut random = [0u8; 16];
        aws_lc_rs::rand::fill(&mut random).map_err(|_unspecified| DpopError::Random)?;
        let claims = Claims {
            jti: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random),
            htm: method.as_str(),
            htu: htu.as_str(),
            iat: jiff::Timestamp::now().as_second(),
            ath: access_token.map(ath),
            nonce: nonce.as_deref(),
        };
        let mut header = Header::new(self.signing.algorithm());
        header.typ = Some(String::from(PROOF_TYPE));
        header.jwk = Some(self.signing.public_jwk().clone());
        crate::jws::compact::encode(&header, &claims, &self.signing)
            .map_err(|source| DpopError::Sign { source })
    }

    /// Keeps `nonce` as the one the server in `role` at the origin of `url`
    /// sent last, for the next proof to it (RFC 9449 §8, §9).
    pub fn remember(&self, role: Role, url: &Url, nonce: &str) {
        self.lock()
            .insert((role, url.origin().ascii_serialization()), nonce.to_owned());
    }

    /// Returns the nonce the server in `role` at the origin of `url` sent
    /// last, when it sent one.
    fn nonce(&self, role: Role, url: &Url) -> Option<String> {
        self.lock()
            .get(&(role, url.origin().ascii_serialization()))
            .cloned()
    }

    /// Returns the guard of the nonces.
    fn lock(&self) -> MutexGuard<'_, BTreeMap<(Role, String), String>> {
        // NOTE: no specification governs this: our own design; a panic while the
        // lock was held leaves at worst a stale nonce, which the server replaces.
        self.nonces.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Returns the `ath` of `access_token`: the base64url SHA-256 of its ASCII
/// octets (RFC 9449 §4.2).
#[must_use]
pub fn ath(access_token: &str) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, access_token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref())
}

/// Returns the nonce `headers` carry in [`NONCE_HEADER`], when they carry
/// one of the RFC 9449 §8.1 syntax.
#[must_use]
pub fn nonce(headers: &HeaderMap) -> Option<&str> {
    // NOTE: RFC 9449 §8.1, nonce = 1*NQCHAR; a value outside that syntax is
    // legitimately unusable, and the server is answered as if it sent none.
    headers
        .get(NONCE_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| matches!(byte, 0x21 | 0x23..=0x5B | 0x5D..=0x7E))
        })
}

/// Returns the nonce a resource's answer demands: a `401` whose `DPoP`
/// challenge names [`USE_NONCE`], with a nonce in [`NONCE_HEADER`] (RFC
/// 9449 §9, Figure 24).
#[must_use]
pub fn resource_challenge(status: StatusCode, headers: &HeaderMap) -> Option<&str> {
    if status != StatusCode::UNAUTHORIZED {
        return None;
    }
    let demands = headers
        .get_all(http::header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(names_use_nonce);
    if demands { nonce(headers) } else { None }
}

/// Returns whether the challenge `value` is a `DPoP` challenge whose
/// `error` is [`USE_NONCE`] (RFC 9449 §7.1, RFC 9110 §11.6.1).
fn names_use_nonce(value: &str) -> bool {
    let value = value.trim_start();
    let Some((scheme, parameters)) = value.split_once(' ') else {
        return false;
    };
    scheme.eq_ignore_ascii_case(SCHEME)
        && parameters.split(',').any(|parameter| {
            parameter.split_once('=').is_some_and(|(name, value)| {
                name.trim().eq_ignore_ascii_case("error")
                    && value.trim().trim_matches('"') == USE_NONCE
            })
        })
}

/// Returns whether a token endpoint's answer is its demand for a nonce: a
/// `400` whose RFC 6749 §5.2 error is [`USE_NONCE`] (RFC 9449 §8).
#[cfg(feature = "fetch")]
pub(crate) fn demands_nonce(status: StatusCode, body: &str) -> bool {
    // NOTE: RFC 6749 §5.2 makes the error body JSON; a body that is not one is
    // legitimately not a nonce demand, and the answer is read as it came.
    status == StatusCode::BAD_REQUEST
        && serde_json::from_str::<crate::client::OAuthError>(body)
            .is_ok_and(|refused| refused.error == USE_NONCE)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "fetch")]
    use super::demands_nonce;
    use super::{ath, names_use_nonce, nonce, resource_challenge};
    use http::HeaderMap;
    use http::HeaderValue;
    use http::StatusCode;

    #[test]
    fn the_ath_is_the_rfc_9449_example() {
        // NOTE: RFC 9449 §7.1, Figures 13 and 14, the example token and its ath.
        assert_eq!(
            "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo",
            ath("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU")
        );
    }

    #[test]
    fn the_resource_challenge_is_the_rfc_9449_example() {
        // NOTE: RFC 9449 §9, Figure 24.
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static(
                "DPoP error=\"use_dpop_nonce\", error_description=\"Resource server requires nonce in DPoP proof\"",
            ),
        );
        headers.insert(
            super::NONCE_HEADER,
            HeaderValue::from_static("eyJ7S_zG.eyJH0-Z.HX4w-7v"),
        );
        assert_eq!(
            Some("eyJ7S_zG.eyJH0-Z.HX4w-7v"),
            resource_challenge(StatusCode::UNAUTHORIZED, &headers)
        );
        assert_eq!(None, resource_challenge(StatusCode::FORBIDDEN, &headers));
        assert!(!names_use_nonce("Bearer error=\"use_dpop_nonce\""));
        assert!(!names_use_nonce("DPoP error=\"invalid_token\""));
    }

    #[test]
    fn a_nonce_outside_the_rfc_9449_syntax_is_not_used() {
        let mut headers = HeaderMap::new();
        headers.insert(super::NONCE_HEADER, HeaderValue::from_static("a\"b"));
        assert_eq!(None, nonce(&headers));
        headers.insert(super::NONCE_HEADER, HeaderValue::from_static(""));
        assert_eq!(None, nonce(&headers));
    }

    #[cfg(feature = "fetch")]
    #[test]
    fn the_token_endpoint_nonce_demand_is_the_rfc_9449_example() {
        // NOTE: RFC 9449 §8, Figure 20.
        let body = r#"{"error": "use_dpop_nonce", "error_description": "Authorization server requires nonce in DPoP proof"}"#;
        assert!(demands_nonce(StatusCode::BAD_REQUEST, body));
        assert!(!demands_nonce(StatusCode::UNAUTHORIZED, body));
        assert!(!demands_nonce(
            StatusCode::BAD_REQUEST,
            r#"{"error": "invalid_grant"}"#
        ));
    }
}
