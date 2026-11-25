// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A public JSON Web Key (RFC 7517 §4) of a key type the family signs with:
//! `RSA` and `EC` (RFC 7518 §6.2, §6.3), `OKP` with `crv` `Ed25519` (RFC 8037
//! §2) and `AKP` with an ML-DSA `alg` (RFC 9964 §3, §5).
//!
//! A key is read whole or not at all: every key parameter is checked when it
//! is read (RFC 9964 §7.3), and a key that carries a private member is
//! refused, since a public key never holds one (RFC 7517 §8.1.1, RFC 9964
//! §3). A key whose `alg`, `use` or `key_ops` rule out an algorithm never
//! verifies under it ([`Jwk::verifies`]).

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Map;
use serde_json::Value;

use crate::jws::algorithm::Algorithm;
use crate::jws::algorithm::KeyKind;

/// The members of a private key (RFC 7518 §6.2.2, §6.3.2, §6.4.1; RFC 8037
/// §2; RFC 9964 §3), none of which a public key carries.
const PRIVATE_MEMBERS: [&str; 9] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"];

/// A public key of [`Algorithm`]'s key types, with its common parameters.
#[derive(Clone, PartialEq, Eq)]
pub struct Jwk {
    /// The `kid` (RFC 7517 §4.5).
    kid: Option<String>,
    /// The `use` (RFC 7517 §4.2).
    key_use: Option<String>,
    /// The `key_ops` (RFC 7517 §4.3).
    key_ops: Option<Vec<String>>,
    /// The `alg` (RFC 7517 §4.4), required on an `AKP` key.
    alg: Option<Algorithm>,
    /// The key type's parameters.
    params: Params,
}

/// The parameters of one key type, as octets.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Params {
    /// `kty` `RSA`: the modulus `n` and the exponent `e`.
    Rsa {
        /// The modulus.
        n: Vec<u8>,
        /// The exponent.
        e: Vec<u8>,
    },
    /// `kty` `EC` on P-256 or P-384: the coordinates `x` and `y`.
    Ec {
        /// The curve.
        curve: Curve,
        /// The x coordinate.
        x: Vec<u8>,
        /// The y coordinate.
        y: Vec<u8>,
    },
    /// `kty` `OKP` with `crv` `Ed25519`: the public key `x`.
    Ed25519 {
        /// The public key.
        x: Vec<u8>,
    },
    /// `kty` `AKP`: the public key `pub` of the parameter set `alg` names.
    Akp {
        /// The public key.
        public: Vec<u8>,
    },
}

/// A curve of an `EC` key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Curve {
    /// P-256.
    P256,
    /// P-384.
    P384,
}

impl Curve {
    /// Returns the curve's `crv` name (RFC 7518 §6.2.1.1).
    const fn name(self) -> &'static str {
        match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
        }
    }

    /// Returns the length of one coordinate in octets (RFC 7518 §6.2.1.2).
    pub(crate) const fn coordinate_length(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
        }
    }
}

/// A JWK that cannot be read as a public key of a supported type.
///
/// No variant carries any part of the key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JwkError {
    /// The JWK is no JSON object.
    #[error("the JWK is not a JSON object")]
    NotObject,
    /// The `kty` is absent, symmetric (`oct`) or of a type this crate does
    /// not read.
    #[error("the JWK's key type is not RSA, EC, OKP or AKP")]
    KeyType,
    /// A member is absent where it is required, not a string where one is
    /// required, or not base64url without padding.
    #[error("the JWK's {name} member is absent or not of its form")]
    Member {
        /// The member.
        name: &'static str,
    },
    /// The `crv` names no curve this crate reads for the key type.
    #[error("the JWK's curve is not P-256, P-384 or Ed25519")]
    Curve,
    /// The `alg` names no algorithm of [`Algorithm`], or one of another key
    /// type; for an `AKP` key, an `alg` that is no ML-DSA parameter set.
    #[error("the JWK's alg is not an algorithm of its key type")]
    Algorithm,
    /// A key parameter has another length than its key type sets.
    #[error("the JWK's {name} has another length than its key type sets")]
    Length {
        /// The member.
        name: &'static str,
    },
    /// The JWK carries a private key member.
    #[error("the JWK carries a private key member")]
    Private,
}

impl fmt::Debug for Jwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Jwk")
            .field("kty", &self.key_type())
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .finish_non_exhaustive()
    }
}

impl Jwk {
    /// Returns a key of `params` with no common parameter but `alg`.
    pub(crate) const fn new(params: Params, alg: Option<Algorithm>) -> Self {
        Self {
            kid: None,
            key_use: None,
            key_ops: None,
            alg,
            params,
        }
    }

    /// Returns the key's parameters.
    pub(crate) const fn params(&self) -> &Params {
        &self.params
    }

    /// Returns the key's `kty`.
    #[must_use]
    pub const fn key_type(&self) -> &'static str {
        match self.params {
            Params::Rsa { .. } => "RSA",
            Params::Ec { .. } => "EC",
            Params::Ed25519 { .. } => "OKP",
            Params::Akp { .. } => "AKP",
        }
    }

    /// Returns the key's `kid`, when it names one.
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// Returns the key's `alg`, when it names one.
    #[must_use]
    pub const fn algorithm(&self) -> Option<Algorithm> {
        self.alg
    }

    /// Returns this key under `kid`.
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// Returns this key for signatures only (`use` `sig`, RFC 7517 §4.2).
    #[must_use]
    pub fn with_signature_use(mut self) -> Self {
        self.key_use = Some(String::from("sig"));
        self
    }

    /// Returns this key restricted to `algorithm` (RFC 7517 §4.4).
    ///
    /// # Errors
    ///
    /// Returns [`JwkError::Algorithm`] when the key cannot sign under
    /// `algorithm`.
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Result<Self, JwkError> {
        if !self.fits(algorithm) {
            return Err(JwkError::Algorithm);
        }
        self.alg = Some(algorithm);
        Ok(self)
    }

    /// Returns whether this key may verify a signature under `algorithm`:
    /// its `use` is absent or `sig` (RFC 7517 §4.2), its `key_ops` are
    /// absent or name `verify` (§4.3), its `alg` is absent or `algorithm`
    /// (§4.4), and its type and curve or parameter set are `algorithm`'s
    /// (RFC 7518 §3.1, RFC 8037 §3.1, RFC 9964 §5).
    #[must_use]
    pub fn verifies(&self, algorithm: Algorithm) -> bool {
        self.key_use
            .as_deref()
            .is_none_or(|key_use| key_use == "sig")
            && self
                .key_ops
                .as_ref()
                .is_none_or(|operations| operations.iter().any(|operation| operation == "verify"))
            && self.fits(algorithm)
    }

    /// Returns whether the key's type, curve or parameter set and its `alg`
    /// admit `algorithm`.
    pub(crate) fn fits(&self, algorithm: Algorithm) -> bool {
        if self.alg.is_some_and(|named| named != algorithm) {
            return false;
        }
        match (&self.params, algorithm.key_kind()) {
            (Params::Rsa { .. }, KeyKind::Rsa)
            | (Params::Ed25519 { .. }, KeyKind::Ed25519)
            | (
                Params::Ec {
                    curve: Curve::P256, ..
                },
                KeyKind::P256,
            )
            | (
                Params::Ec {
                    curve: Curve::P384, ..
                },
                KeyKind::P384,
            ) => true,
            // NOTE: RFC 9964 §3, an AKP key always names its `alg`, which fixes its parameter set.
            (Params::Akp { .. }, KeyKind::MlDsa) => self.alg == Some(algorithm),
            _ => false,
        }
    }

    /// Returns the key's RFC 7638 §3 SHA-256 thumbprint, base64url without
    /// padding.
    ///
    /// The required members of the key type (RFC 7638 §3.2; RFC 8037 §2 for
    /// `OKP`; RFC 9964 §6 for `AKP`, `alg`, `kty` and `pub`) are written in
    /// lexicographic order with no whitespace.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        let text = |octets: &[u8]| URL_SAFE_NO_PAD.encode(octets);
        let canonical = match &self.params {
            Params::Rsa { n, e } => {
                format!(
                    "{{\"e\":\"{}\",\"kty\":\"RSA\",\"n\":\"{}\"}}",
                    text(e),
                    text(n)
                )
            }
            Params::Ec { curve, x, y } => format!(
                "{{\"crv\":\"{}\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
                curve.name(),
                text(x),
                text(y)
            ),
            Params::Ed25519 { x } => {
                format!(
                    "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}",
                    text(x)
                )
            }
            Params::Akp { public } => format!(
                "{{\"alg\":\"{}\",\"kty\":\"AKP\",\"pub\":\"{}\"}}",
                self.alg.map_or("", Algorithm::name),
                text(public)
            ),
        };
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, canonical.as_bytes());
        URL_SAFE_NO_PAD.encode(digest.as_ref())
    }

    /// Returns the key as a JSON object.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut members = Map::new();
        let mut put = |name: &str, value: Value| {
            members.insert(name.to_owned(), value);
        };
        let text = |octets: &[u8]| Value::String(URL_SAFE_NO_PAD.encode(octets));
        put("kty", Value::from(self.key_type()));
        match &self.params {
            Params::Rsa { n, e } => {
                put("n", text(n));
                put("e", text(e));
            }
            Params::Ec { curve, x, y } => {
                put("crv", Value::from(curve.name()));
                put("x", text(x));
                put("y", text(y));
            }
            Params::Ed25519 { x } => {
                put("crv", Value::from("Ed25519"));
                put("x", text(x));
            }
            Params::Akp { public } => put("pub", text(public)),
        }
        if let Some(kid) = &self.kid {
            put("kid", Value::from(kid.as_str()));
        }
        if let Some(key_use) = &self.key_use {
            put("use", Value::from(key_use.as_str()));
        }
        if let Some(operations) = &self.key_ops {
            put("key_ops", Value::from(operations.clone()));
        }
        if let Some(alg) = self.alg {
            put("alg", Value::from(alg.name()));
        }
        Value::Object(members)
    }
}

impl TryFrom<&Value> for Jwk {
    type Error = JwkError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let members = value.as_object().ok_or(JwkError::NotObject)?;
        if PRIVATE_MEMBERS
            .iter()
            .any(|name| members.contains_key(*name))
        {
            return Err(JwkError::Private);
        }
        let alg = match optional_text(members, "alg")? {
            None => None,
            Some(name) => Some(
                name.parse::<Algorithm>()
                    .map_err(|_unknown| JwkError::Algorithm)?,
            ),
        };
        let key_ops = match members.get("key_ops") {
            None => None,
            Some(Value::Array(items)) => Some(
                items
                    .iter()
                    .map(|item| item.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
                    .ok_or(JwkError::Member { name: "key_ops" })?,
            ),
            Some(_) => return Err(JwkError::Member { name: "key_ops" }),
        };
        let params = match optional_text(members, "kty")? {
            Some("RSA") => Params::Rsa {
                n: octets(members, "n")?,
                e: octets(members, "e")?,
            },
            Some("EC") => {
                let curve = match optional_text(members, "crv")? {
                    Some("P-256") => Curve::P256,
                    Some("P-384") => Curve::P384,
                    _ => return Err(JwkError::Curve),
                };
                Params::Ec {
                    curve,
                    x: sized(members, "x", curve.coordinate_length())?,
                    y: sized(members, "y", curve.coordinate_length())?,
                }
            }
            Some("OKP") => match optional_text(members, "crv")? {
                Some("Ed25519") => Params::Ed25519 {
                    x: sized(members, "x", ED25519_PUBLIC_LENGTH)?,
                },
                _ => return Err(JwkError::Curve),
            },
            Some("AKP") => {
                let length = alg
                    .and_then(ml_dsa_public_length)
                    .ok_or(JwkError::Algorithm)?;
                Params::Akp {
                    public: sized(members, "pub", length)?,
                }
            }
            _ => return Err(JwkError::KeyType),
        };
        let jwk = Self {
            kid: optional_text(members, "kid")?.map(str::to_owned),
            key_use: optional_text(members, "use")?.map(str::to_owned),
            key_ops,
            alg,
            params,
        };
        if alg.is_some_and(|alg| !jwk.fits(alg)) {
            return Err(JwkError::Algorithm);
        }
        Ok(jwk)
    }
}

impl serde::Serialize for Jwk {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_value().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Jwk {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Self::try_from(&value).map_err(serde::de::Error::custom)
    }
}

/// Returns the key of `keys` that verifies a signature under `alg` by the
/// key `kid` names.
///
/// A key verifies only the algorithm its type, curve or parameter set and
/// its `alg`, `use` and `key_ops` admit ([`Jwk::verifies`]). A JWS without a
/// `kid` (RFC 7515 §4.1.4 makes it optional) verifies with the one such key
/// when `keys` hold exactly one; two or more candidates verify nothing, so
/// a rotation never decides which key verifies.
#[must_use]
pub fn select<'a>(keys: &'a [Jwk], kid: Option<&str>, alg: Algorithm) -> Option<&'a Jwk> {
    let mut candidates = keys.iter().filter(|key| key.verifies(alg));
    if let Some(kid) = kid {
        return candidates.find(|key| key.kid() == Some(kid));
    }
    let only = candidates.next()?;
    candidates.next().is_none().then_some(only)
}

/// The length of an Ed25519 public key in octets (RFC 8032 §5.1.5).
pub(crate) const ED25519_PUBLIC_LENGTH: usize = 32;

/// Returns the length of the public key of the ML-DSA parameter set
/// `algorithm` names (RFC 9964 §5, Table 1), `None` for another algorithm.
pub(crate) const fn ml_dsa_public_length(algorithm: Algorithm) -> Option<usize> {
    match algorithm {
        Algorithm::MlDsa44 => Some(1312),
        Algorithm::MlDsa65 => Some(1952),
        Algorithm::MlDsa87 => Some(2592),
        _ => None,
    }
}

/// Returns the string member `name`, when present.
fn optional_text<'a>(
    members: &'a Map<String, Value>,
    name: &'static str,
) -> Result<Option<&'a str>, JwkError> {
    match members.get(name) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(JwkError::Member { name }),
    }
}

/// Returns the octets of the base64url member `name` (RFC 7518 §2), which
/// must be present and not empty.
fn octets(members: &Map<String, Value>, name: &'static str) -> Result<Vec<u8>, JwkError> {
    optional_text(members, name)?
        .and_then(|text| URL_SAFE_NO_PAD.decode(text).ok())
        .filter(|octets| !octets.is_empty())
        .ok_or(JwkError::Member { name })
}

/// Returns the octets of the base64url member `name`, which must be
/// `length` octets long.
fn sized(
    members: &Map<String, Value>,
    name: &'static str,
    length: usize,
) -> Result<Vec<u8>, JwkError> {
    let read = octets(members, name)?;
    if read.len() != length {
        return Err(JwkError::Length { name });
    }
    Ok(read)
}

#[cfg(test)]
mod tests {
    use super::Jwk;
    use super::JwkError;

    #[test]
    fn the_thumbprint_is_the_rfc_7638_example() {
        // NOTE: RFC 7638 §3.1, the example key and its thumbprint
        // `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`.
        let jwk: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        }))
        .expect("the example key parses");
        assert_eq!(
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
            jwk.thumbprint()
        );
    }

    #[test]
    fn a_symmetric_key_or_an_unsupported_curve_reads_as_no_key() {
        let symmetric = serde_json::json!({ "kty": "oct", "k": "c2VjcmV0" });
        assert_eq!(Err(JwkError::Private), Jwk::try_from(&symmetric));
        let p521 = serde_json::json!({ "kty": "EC", "crv": "P-521", "x": "AA", "y": "AA" });
        assert_eq!(Err(JwkError::Curve), Jwk::try_from(&p521));
        let x25519 = serde_json::json!({ "kty": "OKP", "crv": "X25519", "x": "AA" });
        assert_eq!(Err(JwkError::Curve), Jwk::try_from(&x25519));
        let short = serde_json::json!({ "kty": "OKP", "crv": "Ed25519", "x": "AA" });
        assert_eq!(Err(JwkError::Length { name: "x" }), Jwk::try_from(&short));
        let padded = serde_json::json!({ "kty": "RSA", "n": "AQAB", "e": "AQ==" });
        assert_eq!(Err(JwkError::Member { name: "e" }), Jwk::try_from(&padded));
    }
}
