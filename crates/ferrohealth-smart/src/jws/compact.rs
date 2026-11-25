// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The JWS Compact Serialization (RFC 7515 §7.1): a header, a payload and
//! a signature, each base64url without padding, joined by `.`.
//!
//! A header names its algorithm in `alg`, which must be an [`Algorithm`]
//! (RFC 7515 §4.1.1, RFC 8725 §3.1); a header that lists `crit` extensions
//! is refused, since this reader understands none (RFC 7515 §4.1.11). A
//! header or payload object that repeats a member name is refused (RFC 7515
//! §5.2, RFC 7519 §4).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use serde_json::Map;
use serde_json::Value;

use crate::jws::JwsError;
use crate::jws::algorithm::Algorithm;
use crate::jws::jwk::Jwk;
use crate::jws::key::SigningKey;

/// The JOSE header parameters this crate writes and reads (RFC 7515
/// §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Header {
    /// The signature algorithm (`alg`, §4.1.1).
    pub alg: Algorithm,
    /// The key id (`kid`, §4.1.4).
    pub kid: Option<String>,
    /// The media type of the whole JWS (`typ`, §4.1.9).
    pub typ: Option<String>,
    /// The media type of the payload (`cty`, §4.1.10).
    pub cty: Option<String>,
    /// The public key the JWS is signed with (`jwk`, §4.1.3).
    pub jwk: Option<Jwk>,
    /// The SHA-256 thumbprint of the signer's X.509 certificate
    /// (`x5t#S256`, §4.1.8).
    pub x5t_s256: Option<String>,
}

impl Header {
    /// Returns a header naming `alg` and nothing else.
    #[must_use]
    pub const fn new(alg: Algorithm) -> Self {
        Self {
            alg,
            kid: None,
            typ: None,
            cty: None,
            jwk: None,
            x5t_s256: None,
        }
    }

    /// Returns the header as a JSON object.
    fn to_value(&self) -> Value {
        let mut members = Map::new();
        members.insert(String::from("alg"), Value::from(self.alg.name()));
        let texts = [
            ("kid", &self.kid),
            ("typ", &self.typ),
            ("cty", &self.cty),
            ("x5t#S256", &self.x5t_s256),
        ];
        for (name, value) in texts {
            if let Some(value) = value {
                members.insert(name.to_owned(), Value::from(value.as_str()));
            }
        }
        if let Some(jwk) = &self.jwk {
            members.insert(String::from("jwk"), jwk.to_value());
        }
        Value::Object(members)
    }

    /// Returns the header the object `members` describes.
    fn from_members(members: &Map<String, Value>) -> Result<Self, JwsError> {
        if members.contains_key("crit") {
            return Err(JwsError::Critical);
        }
        // NOTE: no specification governs a `null` member: our own design reads it as absent.
        let text = |name: &str| match members.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(value)) => Ok(Some(value.clone())),
            Some(_) => Err(JwsError::Malformed),
        };
        let alg = text("alg")?.ok_or(JwsError::Malformed)?;
        let alg = alg.parse().map_err(|_unknown| JwsError::Algorithm)?;
        let jwk = match members.get("jwk") {
            None => None,
            Some(value) => {
                Some(Jwk::try_from(value).map_err(|source| JwsError::HeaderKey { source })?)
            }
        };
        Ok(Self {
            alg,
            kid: text("kid")?,
            typ: text("typ")?,
            cty: text("cty")?,
            jwk,
            x5t_s256: text("x5t#S256")?,
        })
    }
}

/// Returns the compact JWS of `claims` under `header`, signed by `key`.
///
/// # Errors
///
/// Returns [`JwsError::KeyAlgorithm`] when `header` names another algorithm
/// than `key` signs with, [`JwsError::Claims`] when `claims` do not
/// serialize, and [`JwsError::Sign`] when the signer fails.
pub fn encode(
    header: &Header,
    claims: &impl Serialize,
    key: &SigningKey,
) -> Result<String, JwsError> {
    if header.alg != key.algorithm() {
        return Err(JwsError::KeyAlgorithm {
            algorithm: header.alg,
        });
    }
    let payload = serde_json::to_vec(claims).map_err(|source| JwsError::Claims { source })?;
    let mut token = URL_SAFE_NO_PAD.encode(header.to_value().to_string());
    token.push('.');
    token.push_str(&URL_SAFE_NO_PAD.encode(payload));
    let signature = key.sign(token.as_bytes())?;
    token.push('.');
    token.push_str(&URL_SAFE_NO_PAD.encode(signature));
    Ok(token)
}

/// A compact JWS read into its parts, its signature not yet checked.
pub struct Unverified<'a> {
    /// The header.
    header: Header,
    /// The header as the object it encodes.
    members: Map<String, Value>,
    /// The signing input: the encoded header, `.`, the encoded payload.
    signing_input: &'a str,
    /// The payload.
    payload: Vec<u8>,
    /// The signature.
    signature: Vec<u8>,
}

impl std::fmt::Debug for Unverified<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unverified")
            .field("alg", &self.header.alg)
            .field("kid", &self.header.kid)
            .finish_non_exhaustive()
    }
}

/// Returns the compact JWS `token` read into its parts.
///
/// # Errors
///
/// Returns [`JwsError::Malformed`] for a token that is not three base64url
/// segments with a header object that repeats no name and whose members are
/// of their form, [`JwsError::Algorithm`] for an `alg` that is no
/// [`Algorithm`], [`JwsError::Critical`] for a header with `crit`, and
/// [`JwsError::HeaderKey`] for a `jwk` that is no supported public key.
pub fn decode(token: &str) -> Result<Unverified<'_>, JwsError> {
    let mut segments = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(JwsError::Malformed);
    };
    let segment = |text: &str| {
        URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_malformed| JwsError::Malformed)
    };
    let members = object(&segment(header)?).ok_or(JwsError::Malformed)?;
    let signing_input = token
        .get(..header.len().saturating_add(1).saturating_add(payload.len()))
        .ok_or(JwsError::Malformed)?;
    Ok(Unverified {
        header: Header::from_members(&members)?,
        members,
        signing_input,
        payload: segment(payload)?,
        signature: segment(signature)?,
    })
}

/// Returns the JSON object `bytes` encode, `None` for bytes that are no
/// object or an object that repeats a name.
fn object(bytes: &[u8]) -> Option<Map<String, Value>> {
    crate::metadata::repeats_no_name(bytes).ok()?;
    serde_json::from_slice(bytes).ok()
}

impl Unverified<'_> {
    /// Returns the header.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// Returns the header as the JSON object it encodes, every member
    /// included.
    #[must_use]
    pub const fn header_members(&self) -> &Map<String, Value> {
        &self.members
    }

    /// Returns the payload once its signature verifies with `key` under the
    /// header's `alg`.
    ///
    /// # Errors
    ///
    /// Returns [`JwsError::KeyAlgorithm`] when `key` may not verify under
    /// the header's `alg`, and [`JwsError::Signature`] when the signature
    /// does not verify.
    pub fn verify(&self, key: &Jwk) -> Result<&[u8], JwsError> {
        key.verify(
            self.header.alg,
            self.signing_input.as_bytes(),
            &self.signature,
        )?;
        Ok(&self.payload)
    }

    /// Returns the claims of the payload once its signature verifies with
    /// `key` under the header's `alg` (RFC 7519 §7.2).
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Unverified::verify`], and
    /// [`JwsError::Payload`] for a payload that is no JSON object or one
    /// that repeats a name.
    pub fn verify_claims(&self, key: &Jwk) -> Result<Map<String, Value>, JwsError> {
        object(self.verify(key)?).ok_or(JwsError::Payload)
    }
}
