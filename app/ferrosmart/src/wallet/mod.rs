// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The EUDI Wallet verifier: the OpenID4VP 1.0 machinery of the HAIP 1.0
//! profile for a PID presented as an SD-JWT VC (`docs/architecture.md`
//! §13.32).
//!
//! It holds no configuration and does no I/O: [`request`] builds the signed
//! request object, [`jwe`] opens the encrypted response, [`sdjwt`] checks the
//! presentation, [`x509`] the certificate paths that authenticate an issuer,
//! and [`status`] a Token Status List. The provider entry
//! (`crate::upstream::wallet`) fetches what they read and the routes
//! (`crate::authorize::wallet`) answer the wallet.

pub mod jwe;
pub mod request;
pub mod sdjwt;
pub mod status;
pub mod x509;

use base64::Engine as _;

/// The credential format of an SD-JWT VC (HAIP 1.0 §5.3.2).
pub const SD_JWT_VC: &str = "dc+sd-jwt";

/// The one signature algorithm the verifier accepts and signs with (HAIP 1.0
/// §7).
pub const ES256: &str = "ES256";

/// Why a presentation is refused, each a stable reason the record names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// The answer carries a VP Token outside an encrypted `response` (HAIP
    /// 1.0 §5.1).
    #[error("unencrypted_response")]
    UnencryptedResponse,
    /// The answer is not an encrypted response this verifier can open, or
    /// not a VP Token for the request.
    #[error("malformed_response")]
    MalformedResponse,
    /// The credential is not an SD-JWT VC, or its signature or disclosures
    /// do not verify (RFC 9901 §7.1).
    #[error("invalid_credential")]
    InvalidCredential,
    /// The issuer's certificate path does not end at a configured anchor
    /// (HAIP 1.0 §6.1.1).
    #[error("untrusted_issuer")]
    UntrustedIssuer,
    /// The credential's `vct` is not one the request asked for (OpenID4VP
    /// 1.0 §8.6, Appendix B.3.5).
    #[error("unrequested_credential")]
    UnrequestedCredential,
    /// The credential is past its `exp` or before its `nbf` (RFC 7519
    /// §4.1.4, §4.1.5).
    #[error("expired")]
    Expired,
    /// The Token Status List names the credential other than valid.
    #[error("revoked")]
    Revoked,
    /// The Token Status List could not be read or verified, so no statement
    /// about the credential's status can be made.
    #[error("status_unavailable")]
    StatusUnavailable,
    /// The Key Binding JWT is missing, or its key, signature, `aud`,
    /// `nonce`, `sd_hash` or `iat` does not hold (RFC 9901 §7.3).
    #[error("bad_holder_binding")]
    BadHolderBinding,
    /// The request's nonce was already answered (OpenID4VP 1.0 §14.1.2).
    #[error("replayed_nonce")]
    ReplayedNonce,
    /// The credential discloses no value for the identifier claim.
    #[error("no_administrative_number")]
    NoAdministrativeNumber,
    /// The credential leaves out a claim the request asked for (OpenID4VP
    /// 1.0 §8.6).
    #[error("missing_claim")]
    MissingClaim,
}

/// Returns the base64url encoding of `bytes`, without padding.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Returns the bytes of the base64url text `text`, without padding.
///
/// # Errors
/// Returns [`base64::DecodeError`] for any other text.
pub fn decode(text: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text)
}

/// Returns the SHA-256 of `bytes`.
#[must_use]
pub fn sha256(bytes: &[u8]) -> Vec<u8> {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

/// Returns the JSON object the base64url segment `segment` encodes.
fn json_object(segment: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
    let bytes = decode(segment).ok()?;
    match serde_json::from_slice(&bytes).ok()? {
        serde_json::Value::Object(object) => Some(object),
        _ => None,
    }
}

/// A compact JWS split into its parts, its header and claims read.
#[derive(Clone)]
pub(crate) struct Jws<'a> {
    /// The protected header.
    pub(crate) header: serde_json::Map<String, serde_json::Value>,
    /// The claims.
    pub(crate) claims: serde_json::Map<String, serde_json::Value>,
    /// The signing input: the header and payload segments with their dot.
    pub(crate) signing_input: &'a str,
    /// The signature segment.
    pub(crate) signature: &'a str,
}

impl std::fmt::Debug for Jws<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Jws(..)")
    }
}

impl<'a> Jws<'a> {
    /// Reads the compact JWS `token`, whose header and payload are JSON
    /// objects (RFC 7515 §7.1); none for anything else.
    pub(crate) fn parse(token: &'a str) -> Option<Self> {
        let (signing_input, signature) = token.rsplit_once('.')?;
        let (header, payload) = signing_input.split_once('.')?;
        if signature.is_empty() || signature.contains('.') {
            return None;
        }
        Some(Self {
            header: json_object(header)?,
            claims: json_object(payload)?,
            signing_input,
            signature,
        })
    }

    /// Returns the header parameter `name` as text.
    pub(crate) fn header_text(&self, name: &str) -> Option<&str> {
        self.header.get(name).and_then(serde_json::Value::as_str)
    }

    /// Returns the claim `name` as text.
    pub(crate) fn text(&self, name: &str) -> Option<&str> {
        self.claims.get(name).and_then(serde_json::Value::as_str)
    }

    /// Returns the claim `name` as a whole number of seconds.
    pub(crate) fn seconds(&self, name: &str) -> Option<i64> {
        self.claims.get(name).and_then(serde_json::Value::as_i64)
    }

    /// Whether the JWS is signed with ES256 by the P-256 point `point`, the
    /// one algorithm the verifier accepts (HAIP 1.0 §7).
    pub(crate) fn verifies_with(&self, point: &[u8]) -> bool {
        if self.header_text("alg") != Some(ES256) {
            return false;
        }
        let key = jsonwebtoken::DecodingKey::from_ec_der(point);
        jsonwebtoken::crypto::verify(
            self.signature,
            self.signing_input.as_bytes(),
            &key,
            jsonwebtoken::Algorithm::ES256,
        )
        .unwrap_or(false)
    }
}

/// Returns the uncompressed P-256 point of the public JWK `jwk`, none for any
/// other key (RFC 7518 §6.2.1).
pub(crate) fn p256_point(jwk: &serde_json::Value) -> Option<Vec<u8>> {
    let text = |name: &str| jwk.get(name).and_then(serde_json::Value::as_str);
    if text("kty") != Some("EC") || text("crv") != Some("P-256") || jwk.get("d").is_some() {
        return None;
    }
    let x = decode(text("x")?).ok()?;
    let y = decode(text("y")?).ok()?;
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    Some(point)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_compact_jws_reads_its_header_and_claims() {
        let header = encode(br#"{"alg":"ES256","typ":"kb+jwt"}"#);
        let claims = encode(br#"{"nonce":"n","iat":5}"#);
        let token = format!("{header}.{claims}.c2ln");
        let jws = Jws::parse(&token).expect("the token should read");
        assert_eq!(jws.header_text("typ"), Some("kb+jwt"));
        assert_eq!(jws.text("nonce"), Some("n"));
        assert_eq!(jws.seconds("iat"), Some(5));
        assert_eq!(jws.signing_input, format!("{header}.{claims}"));
    }

    #[test]
    fn a_jws_of_other_shapes_is_not_read() {
        let header = encode(br#"{"alg":"ES256"}"#);
        let array = encode(b"[1]");
        assert!(Jws::parse(&format!("{header}.{array}.c2ln")).is_none());
        assert!(Jws::parse(&format!("{header}.{header}.")).is_none());
        assert!(Jws::parse(&format!("{header}.{header}.a.b")).is_none());
        assert!(Jws::parse("not a token").is_none());
    }

    #[test]
    fn only_a_public_p256_jwk_gives_a_point() {
        let coordinate = encode(&[7; 32]);
        let public =
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": coordinate, "y": coordinate});
        assert_eq!(p256_point(&public).map(|point| point.len()), Some(65));
        let private = serde_json::json!({"kty": "EC", "crv": "P-256", "x": coordinate, "y": coordinate, "d": coordinate});
        assert!(p256_point(&private).is_none());
        let other =
            serde_json::json!({"kty": "EC", "crv": "P-384", "x": coordinate, "y": coordinate});
        assert!(p256_point(&other).is_none());
    }
}
