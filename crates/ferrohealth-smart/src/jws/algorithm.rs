// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The JWS signature algorithms the family signs and verifies with: RSA and
//! ECDSA (RFC 7518 §3.1), `EdDSA` over Ed25519 (RFC 8037 §3.1) and ML-DSA
//! (RFC 9964 §5).
//!
//! Every algorithm here is asymmetric. Neither `none` nor an HMAC algorithm
//! has a value, so no setting, header or key can name one (RFC 8725 §3.1,
//! §3.2): such a name fails to parse.

use std::fmt;
use std::str::FromStr;

/// A JWS signature algorithm, by its registered name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    /// `RS256`, RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7518 §3.3).
    Rs256,
    /// `RS384`, RSASSA-PKCS1-v1_5 with SHA-384 (RFC 7518 §3.3).
    Rs384,
    /// `RS512`, RSASSA-PKCS1-v1_5 with SHA-512 (RFC 7518 §3.3).
    Rs512,
    /// `PS256`, RSASSA-PSS with SHA-256 (RFC 7518 §3.5).
    Ps256,
    /// `PS384`, RSASSA-PSS with SHA-384 (RFC 7518 §3.5).
    Ps384,
    /// `PS512`, RSASSA-PSS with SHA-512 (RFC 7518 §3.5).
    Ps512,
    /// `ES256`, ECDSA on P-256 with SHA-256 (RFC 7518 §3.4).
    Es256,
    /// `ES384`, ECDSA on P-384 with SHA-384 (RFC 7518 §3.4).
    Es384,
    /// `EdDSA` with an Ed25519 key (RFC 8037 §3.1).
    EdDsa,
    /// `ML-DSA-44` (RFC 9964 §5).
    MlDsa44,
    /// `ML-DSA-65` (RFC 9964 §5).
    MlDsa65,
    /// `ML-DSA-87` (RFC 9964 §5).
    MlDsa87,
}

/// Every algorithm, in the order of the registry.
const ALL: [Algorithm; 12] = [
    Algorithm::Rs256,
    Algorithm::Rs384,
    Algorithm::Rs512,
    Algorithm::Ps256,
    Algorithm::Ps384,
    Algorithm::Ps512,
    Algorithm::Es256,
    Algorithm::Es384,
    Algorithm::EdDsa,
    Algorithm::MlDsa44,
    Algorithm::MlDsa65,
    Algorithm::MlDsa87,
];

/// The kind of key an algorithm signs with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyKind {
    /// An RSA key (`kty` `RSA`).
    Rsa,
    /// An EC key on P-256 (`kty` `EC`, `crv` `P-256`).
    P256,
    /// An EC key on P-384 (`kty` `EC`, `crv` `P-384`).
    P384,
    /// An Ed25519 key (`kty` `OKP`, `crv` `Ed25519`).
    Ed25519,
    /// An ML-DSA key of the algorithm's parameter set (`kty` `AKP`).
    MlDsa,
}

impl Algorithm {
    /// Returns every algorithm.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &ALL
    }

    /// Returns the algorithm's registered name, the `alg` value of a header
    /// or a JWK.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::EdDsa => "EdDSA",
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    /// Returns whether the algorithm signs with an RSA key, `RS256` to
    /// `PS512`.
    #[must_use]
    pub const fn is_rsa(self) -> bool {
        matches!(self.key_kind(), KeyKind::Rsa)
    }

    /// Returns whether the algorithm is one of the ML-DSA parameter sets.
    #[must_use]
    pub const fn is_ml_dsa(self) -> bool {
        matches!(self.key_kind(), KeyKind::MlDsa)
    }

    /// Returns the kind of key the algorithm signs with.
    pub(crate) const fn key_kind(self) -> KeyKind {
        match self {
            Self::Rs256 | Self::Rs384 | Self::Rs512 | Self::Ps256 | Self::Ps384 | Self::Ps512 => {
                KeyKind::Rsa
            }
            Self::Es256 => KeyKind::P256,
            Self::Es384 => KeyKind::P384,
            Self::EdDsa => KeyKind::Ed25519,
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => KeyKind::MlDsa,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A name that is no algorithm of [`Algorithm`]: an unregistered one,
/// `none`, a symmetric one, or one this crate does not implement.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the signature algorithm is not one of {}", names())]
pub struct UnknownAlgorithm;

/// Returns the names of every algorithm, comma-separated.
fn names() -> String {
    ALL.iter()
        .map(|algorithm| algorithm.name())
        .collect::<Vec<_>>()
        .join(", ")
}

impl FromStr for Algorithm {
    type Err = UnknownAlgorithm;

    /// Reads an algorithm by its registered name, compared exactly
    /// (RFC 7515 §4.1.1: the value is case-sensitive).
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        ALL.iter()
            .copied()
            .find(|algorithm| algorithm.name() == name)
            .ok_or(UnknownAlgorithm)
    }
}

impl serde::Serialize for Algorithm {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.name())
    }
}

impl<'de> serde::Deserialize<'de> for Algorithm {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        name.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::Algorithm;

    #[test]
    fn every_name_reads_back_as_its_algorithm() {
        for algorithm in Algorithm::all() {
            assert_eq!(Ok(*algorithm), algorithm.name().parse(), "{algorithm}");
        }
    }

    #[test]
    fn none_and_the_symmetric_names_read_as_no_algorithm() {
        // NOTE: RFC 8725 §3.1 and §3.2, neither `none` nor an HMAC algorithm verifies a token.
        for name in ["none", "HS256", "HS384", "HS512", "es256", "ML-DSA-65 ", ""] {
            assert!(name.parse::<Algorithm>().is_err(), "{name:?}");
        }
    }
}
