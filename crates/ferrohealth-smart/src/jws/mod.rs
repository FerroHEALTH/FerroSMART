// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! JSON Web Signature (RFC 7515) over `aws-lc-rs`: the one place the crate
//! signs and verifies a JWS, for every [`algorithm::Algorithm`] the family
//! uses, ML-DSA (RFC 9964) among them.
//!
//! A verifier names the algorithms it accepts, reads the header's `alg`
//! against them, and verifies with a key that may be used for that
//! algorithm alone ([`jwk::Jwk::verifies`]), so neither `none` nor an
//! algorithm confusion verifies a token (RFC 8725 §3.1, §3.2). The
//! segments of a JWS can also be read without checking its signature
//! by a caller that selects a key by the payload's `iss`
//! (RFC 7519 §7.2), or reads a value an upstream verified.

pub mod algorithm;
pub mod claims;
pub mod compact;
pub mod jwk;
pub mod key;

use base64::Engine as _;
use serde_json::Map;
use serde_json::Value;

/// A JWS that cannot be read, signed or verified.
///
/// No variant carries the token, a key or a claim value.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwsError {
    /// The token is not three base64url segments, or its header is no JSON
    /// object of members of their form.
    #[error("the JWS is not a compact serialization with a JSON header")]
    Malformed,
    /// The header's `alg` is no [`algorithm::Algorithm`]: `none`, a symmetric
    /// algorithm or an unknown one.
    #[error("the JWS names an algorithm this crate does not verify")]
    Algorithm,
    /// The header lists `crit` extensions, none of which this reader
    /// understands (RFC 7515 §4.1.11).
    #[error("the JWS header lists critical extensions")]
    Critical,
    /// The header's `jwk` is no public key of a supported type.
    #[error("the JWS header's jwk is not a supported public key")]
    HeaderKey {
        /// Why the key was refused.
        #[source]
        source: jwk::JwkError,
    },
    /// The key may not sign or verify under the algorithm.
    #[error("the key may not be used with {algorithm}")]
    KeyAlgorithm {
        /// The algorithm.
        algorithm: algorithm::Algorithm,
    },
    /// The signature does not verify.
    #[error("the JWS signature does not verify")]
    Signature,
    /// The verified payload is no JSON object, or repeats a name.
    #[error("the JWS payload is not a JSON object")]
    Payload,
    /// The claims could not be serialized.
    #[error("the claims could not be serialized")]
    Claims {
        /// What the serializer reported.
        #[source]
        source: serde_json::Error,
    },
    /// The signer failed.
    #[error("the JWS could not be signed")]
    Sign,
}

/// Returns the JSON object one `segment` of a compact JWS encodes, its
/// header or its payload, each base64url without padding (RFC 7515 §2,
/// §7.1); `None` for a segment that is not base64url or not an object.
pub(crate) fn object(segment: &str) -> Option<Map<String, Value>> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(feature = "axum")]
/// The longest token whose header and payload a refusal log line reads.
const NAMED_TOKEN_LIMIT: usize = 16 * 1024;

#[cfg(feature = "axum")]
/// The longest value a refusal log line names.
const NAMED_VALUE_LIMIT: usize = 256;

#[cfg(feature = "axum")]
/// What a refusal log line names of a token, read without checking
/// anything: its `iss`, its client (`client_id`, else `azp`) and its
/// header's `kid`, each only when it is visible ASCII of a bounded length.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Named {
    /// The `iss` claim.
    pub(crate) issuer: Option<String>,
    /// The `client_id` claim, else the `azp` claim.
    pub(crate) client_id: Option<String>,
    /// The header's `kid`.
    pub(crate) kid: Option<String>,
}

#[cfg(feature = "axum")]
impl Named {
    /// Returns what `token` names, empty for anything that is not a compact
    /// JWS within the bound.
    pub(crate) fn of(token: &str) -> Self {
        let mut segments = token.split('.');
        let (Some(header), Some(payload), Some(_), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Self::default();
        };
        if token.len() > NAMED_TOKEN_LIMIT {
            return Self::default();
        }
        let header = object(header).unwrap_or_default();
        let payload = object(payload).unwrap_or_default();
        let text = |map: &Map<String, Value>, key: &str| {
            map.get(key)
                .and_then(Value::as_str)
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= NAMED_VALUE_LIMIT
                        && value.bytes().all(|byte| byte.is_ascii_graphic())
                })
                .map(str::to_owned)
        };
        Self {
            issuer: text(&payload, "iss"),
            client_id: text(&payload, "client_id").or_else(|| text(&payload, "azp")),
            kid: text(&header, "kid"),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "axum")]
    use super::Named;
    use super::object;

    #[cfg(feature = "axum")]
    #[test]
    fn a_refused_token_names_its_issuer_client_and_key_only() {
        use base64::Engine as _;
        let encode = |value: serde_json::Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
        };
        let token = format!(
            "{}.{}.c2ln",
            encode(serde_json::json!({"alg": "ES256", "kid": "k1"})),
            encode(serde_json::json!({
                "iss": "https://as.example.org",
                "azp": "app",
                "sub": "someone",
                "name": "A Person"
            }))
        );
        let named = Named::of(&token);
        assert_eq!(Some("https://as.example.org"), named.issuer.as_deref());
        assert_eq!(Some("app"), named.client_id.as_deref());
        assert_eq!(Some("k1"), named.kid.as_deref());
        let forged = format!(
            "{}.{}.c2ln",
            encode(serde_json::json!({"kid": "a\nb"})),
            encode(serde_json::json!({"iss": "x y", "client_id": "c"}))
        );
        let named = Named::of(&forged);
        assert_eq!(None, named.kid, "a control character is left out");
        assert_eq!(None, named.issuer, "a space is left out");
        assert_eq!(Some("c"), named.client_id.as_deref());
        assert_eq!(Named::default(), Named::of("opaque"));
    }

    #[test]
    fn a_segment_reads_as_the_object_it_encodes() {
        // `{"iss":"https://as.example.org"}`, base64url without padding.
        let read = object("eyJpc3MiOiJodHRwczovL2FzLmV4YW1wbGUub3JnIn0").expect("an object");
        assert_eq!(
            Some("https://as.example.org"),
            read.get("iss").and_then(serde_json::Value::as_str)
        );
    }

    #[test]
    fn a_segment_that_is_no_base64url_object_reads_as_none() {
        // `[1]` is JSON and no object; `e30=` is `{}` with the padding RFC 7515 §2 omits.
        for segment in ["WzFd", "e30=", "not base64", ""] {
            assert_eq!(None, object(segment), "{segment:?}");
        }
    }
}
