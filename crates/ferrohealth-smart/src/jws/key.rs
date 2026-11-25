// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The signature of a JWS (RFC 7515 §5.1, §5.2) under each [`Algorithm`]
//! over `aws-lc-rs`: verification with a public [`Jwk`], and signing with a
//! [`SigningKey`] read from a PEM private key.
//!
//! An ECDSA signature is the fixed-width `R || S` (RFC 7518 §3.4), an
//! ML-DSA signature the pure FIPS 204 signature with an empty context
//! (RFC 9964 §5). An RSA key is at least 2048 bits (RFC 7518 §3.3, §3.5).

use std::fmt;
use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature;
use aws_lc_rs::signature::EcdsaKeyPair;
use aws_lc_rs::signature::Ed25519KeyPair;
use aws_lc_rs::signature::KeyPair as _;
use aws_lc_rs::signature::PqdsaKeyPair;
use aws_lc_rs::signature::RsaKeyPair;
use aws_lc_rs::signature::UnparsedPublicKey;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject as _;

use crate::jws::JwsError;
use crate::jws::algorithm::Algorithm;
use crate::jws::jwk::Curve;
use crate::jws::jwk::Jwk;
use crate::jws::jwk::Params;

impl Jwk {
    /// Checks `signature` over `message`, the JWS signing input, under
    /// `algorithm` with this key.
    ///
    /// # Errors
    ///
    /// Returns [`JwsError::KeyAlgorithm`] when this key may not verify under
    /// `algorithm` ([`Jwk::verifies`]), and [`JwsError::Signature`] when the
    /// signature does not verify.
    pub fn verify(
        &self,
        algorithm: Algorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), JwsError> {
        if !self.verifies(algorithm) {
            return Err(JwsError::KeyAlgorithm { algorithm });
        }
        let verified = match (self.params(), algorithm) {
            (Params::Rsa { n, e }, _) => {
                let parameters = match algorithm {
                    Algorithm::Rs256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                    Algorithm::Rs384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                    Algorithm::Rs512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                    Algorithm::Ps256 => &signature::RSA_PSS_2048_8192_SHA256,
                    Algorithm::Ps384 => &signature::RSA_PSS_2048_8192_SHA384,
                    _ => &signature::RSA_PSS_2048_8192_SHA512,
                };
                signature::RsaPublicKeyComponents {
                    n: significant(n),
                    e: significant(e),
                }
                .verify(parameters, message, signature)
            }
            (Params::Ec { curve, x, y }, _) => {
                let mut point = Vec::with_capacity(1 + x.len() + y.len());
                point.push(0x04);
                point.extend_from_slice(x);
                point.extend_from_slice(y);
                let parameters = match curve {
                    Curve::P256 => &signature::ECDSA_P256_SHA256_FIXED,
                    Curve::P384 => &signature::ECDSA_P384_SHA384_FIXED,
                };
                UnparsedPublicKey::new(parameters, point).verify(message, signature)
            }
            (Params::Ed25519 { x }, _) => {
                UnparsedPublicKey::new(&signature::ED25519, x).verify(message, signature)
            }
            (Params::Akp { public }, Algorithm::MlDsa44) => {
                UnparsedPublicKey::new(&signature::ML_DSA_44, public).verify(message, signature)
            }
            (Params::Akp { public }, Algorithm::MlDsa65) => {
                UnparsedPublicKey::new(&signature::ML_DSA_65, public).verify(message, signature)
            }
            (Params::Akp { public }, _) => {
                UnparsedPublicKey::new(&signature::ML_DSA_87, public).verify(message, signature)
            }
        };
        verified.map_err(|_unverified| JwsError::Signature)
    }
}

/// Returns a big-endian integer without its leading zero octets, the form
/// the RSA verifier reads and a certificate's DER integer is compared in.
pub(crate) fn significant(octets: &[u8]) -> &[u8] {
    let start = octets
        .iter()
        .position(|octet| *octet != 0)
        .unwrap_or(octets.len());
    octets.get(start..).unwrap_or_default()
}

/// A private key that cannot be read or cannot sign as asked.
///
/// No variant carries the key or any part of it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// The text holds no private key in PEM form: PKCS#8 (`PRIVATE KEY`),
    /// PKCS#1 (`RSA PRIVATE KEY`) or SEC 1 (`EC PRIVATE KEY`).
    #[error("the text holds no private key in PEM form")]
    Pem,
    /// The private key is of no type this crate signs with: RSA of at least
    /// 2048 bits, EC on P-256 or P-384, Ed25519 or ML-DSA.
    #[error("the private key is not an RSA, EC, Ed25519 or ML-DSA key this crate signs with")]
    Unsupported,
    /// The EC key is on neither P-256 nor P-384, the curves ES256 and ES384
    /// sign with (RFC 7518 §3.4).
    #[error("the EC key is on neither P-256 (ES256) nor P-384 (ES384)")]
    Curve,
    /// The algorithm cannot sign with this key: another key type, curve or
    /// ML-DSA parameter set.
    #[error("the algorithm {algorithm} cannot sign with this key")]
    Algorithm {
        /// The algorithm.
        algorithm: Algorithm,
    },
    /// An ML-DSA seed is not 32 octets or the algorithm is no ML-DSA
    /// parameter set (RFC 9964 §4).
    #[error("the ML-DSA seed is not 32 octets of an ML-DSA parameter set")]
    Seed,
}

/// The key pair a private key holds.
enum Pair {
    /// An RSA key.
    Rsa(RsaKeyPair),
    /// An EC key, with its curve.
    Ec(EcdsaKeyPair, Curve),
    /// An Ed25519 key.
    Ed25519(Ed25519KeyPair),
    /// An ML-DSA key, with the algorithm of its parameter set.
    MlDsa(PqdsaKeyPair, Algorithm),
}

/// A private key of a type the family signs with, and its public half.
///
/// `Debug` shows the key type alone.
#[derive(Clone)]
pub struct PrivateKey {
    /// The key pair, shared by every clone.
    pair: Arc<Pair>,
    /// The public half.
    public: Jwk,
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("kty", &self.public.key_type())
            .finish_non_exhaustive()
    }
}

/// The ML-DSA parameter sets, each with its algorithm.
const ML_DSA: [(&signature::PqdsaSigningAlgorithm, Algorithm); 3] = [
    (&signature::ML_DSA_44_SIGNING, Algorithm::MlDsa44),
    (&signature::ML_DSA_65_SIGNING, Algorithm::MlDsa65),
    (&signature::ML_DSA_87_SIGNING, Algorithm::MlDsa87),
];

impl PrivateKey {
    /// Returns the private key `pem` holds: PKCS#8 for every type (an
    /// ML-DSA key as RFC 9881 §6 writes it, seed, expanded key or both),
    /// PKCS#1 for an RSA key, SEC 1 for an EC key.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Pem`] for a text that holds no private key,
    /// [`KeyError::Curve`] for an EC key on another curve than P-256 or
    /// P-384, and [`KeyError::Unsupported`] for a key of another type.
    pub fn from_pem(pem: &[u8]) -> Result<Self, KeyError> {
        match PrivateKeyDer::from_pem_slice(pem).map_err(|_unread| KeyError::Pem)? {
            PrivateKeyDer::Pkcs1(der) => RsaKeyPair::from_der(der.secret_pkcs1_der())
                .map(|pair| Self::of(Pair::Rsa(pair)))
                .map_err(|_rejected| KeyError::Unsupported),
            PrivateKeyDer::Sec1(der) => ec(der.secret_sec1_der()),
            PrivateKeyDer::Pkcs8(der) => Self::from_pkcs8(der.secret_pkcs8_der()),
            _ => Err(KeyError::Unsupported),
        }
    }

    /// Returns the private key the PKCS#8 document `der` holds (RFC 5958).
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Curve`] for an EC key on another curve than
    /// P-256 or P-384, and [`KeyError::Unsupported`] for a key of another
    /// type.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, KeyError> {
        if let Ok(pair) = RsaKeyPair::from_pkcs8(der) {
            return Ok(Self::of(Pair::Rsa(pair)));
        }
        if let Ok(pair) = Ed25519KeyPair::from_pkcs8(der) {
            return Ok(Self::of(Pair::Ed25519(pair)));
        }
        for (parameters, algorithm) in ML_DSA {
            if let Ok(pair) = PqdsaKeyPair::from_pkcs8(parameters, der) {
                return Ok(Self::of(Pair::MlDsa(pair, algorithm)));
            }
        }
        ec(der)
    }

    /// Returns the ML-DSA key of `algorithm`'s parameter set that the
    /// 32-octet `seed` expands to, the `priv` of an `AKP` JWK (RFC 9964 §4).
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Seed`] for a seed of another length or an
    /// algorithm that is no ML-DSA parameter set.
    pub fn from_ml_dsa_seed(algorithm: Algorithm, seed: &[u8]) -> Result<Self, KeyError> {
        let (parameters, _) = ML_DSA
            .iter()
            .find(|(_, named)| *named == algorithm)
            .ok_or(KeyError::Seed)?;
        let pair = PqdsaKeyPair::from_seed(parameters, seed).map_err(|_rejected| KeyError::Seed)?;
        Ok(Self::of(Pair::MlDsa(pair, algorithm)))
    }

    /// Returns `pair` with its public half.
    fn of(pair: Pair) -> Self {
        let params = match &pair {
            Pair::Rsa(pair) => Params::Rsa {
                n: pair
                    .public_key()
                    .modulus()
                    .big_endian_without_leading_zero()
                    .to_vec(),
                e: pair
                    .public_key()
                    .exponent()
                    .big_endian_without_leading_zero()
                    .to_vec(),
            },
            Pair::Ec(pair, curve) => {
                // NOTE: SEC 1 §2.3.3, the public key is the uncompressed point 0x04 || x || y.
                let point = pair.public_key().as_ref();
                let length = curve.coordinate_length();
                Params::Ec {
                    curve: *curve,
                    x: point.get(1..=length).unwrap_or_default().to_vec(),
                    y: point
                        .get(length.saturating_add(1)..)
                        .unwrap_or_default()
                        .to_vec(),
                }
            }
            Pair::Ed25519(pair) => Params::Ed25519 {
                x: pair.public_key().as_ref().to_vec(),
            },
            Pair::MlDsa(pair, _) => Params::Akp {
                public: pair.public_key().as_ref().to_vec(),
            },
        };
        let alg = match &pair {
            Pair::MlDsa(_, algorithm) => Some(*algorithm),
            _ => None,
        };
        Self {
            pair: Arc::new(pair),
            public: Jwk::new(params, alg),
        }
    }

    /// Returns the one algorithm the key signs with: an EC key's by its
    /// curve (RFC 7518 §3.4), `EdDSA` for an Ed25519 key, and an ML-DSA
    /// key's by its parameter set; `None` for an RSA key, which signs with
    /// any of `RS256` to `PS512`.
    #[must_use]
    pub fn algorithm(&self) -> Option<Algorithm> {
        match &*self.pair {
            Pair::Rsa(_) => None,
            Pair::Ec(_, Curve::P256) => Some(Algorithm::Es256),
            Pair::Ec(_, Curve::P384) => Some(Algorithm::Es384),
            Pair::Ed25519(_) => Some(Algorithm::EdDsa),
            Pair::MlDsa(_, algorithm) => Some(*algorithm),
        }
    }

    /// Returns the public half, with no common parameter but an `AKP`
    /// key's `alg`.
    #[must_use]
    pub const fn public_jwk(&self) -> &Jwk {
        &self.public
    }
}

/// Returns the EC key `der` holds, PKCS#8 or SEC 1, on P-256 or P-384.
fn ec(der: &[u8]) -> Result<PrivateKey, KeyError> {
    let curves = [
        (&signature::ECDSA_P256_SHA256_FIXED_SIGNING, Curve::P256),
        (&signature::ECDSA_P384_SHA384_FIXED_SIGNING, Curve::P384),
    ];
    for (parameters, curve) in curves {
        if let Ok(pair) = EcdsaKeyPair::from_private_key_der(parameters, der) {
            return Ok(PrivateKey::of(Pair::Ec(pair, curve)));
        }
    }
    // NOTE: RFC 7518 §3.4; a P-521 key is an EC key on a curve no algorithm here signs with.
    if EcdsaKeyPair::from_private_key_der(&signature::ECDSA_P521_SHA512_FIXED_SIGNING, der).is_ok()
    {
        return Err(KeyError::Curve);
    }
    Err(KeyError::Unsupported)
}

/// A private key bound to the one algorithm it signs with.
///
/// `Debug` shows the algorithm alone.
#[derive(Clone)]
pub struct SigningKey {
    /// The private key.
    private: PrivateKey,
    /// The algorithm every signature is made with.
    algorithm: Algorithm,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Returns `private` signing with `algorithm`.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Algorithm`] when `algorithm` cannot sign with
    /// the key: another key type, curve or ML-DSA parameter set.
    pub fn new(private: PrivateKey, algorithm: Algorithm) -> Result<Self, KeyError> {
        if !private.public.fits(algorithm) {
            return Err(KeyError::Algorithm { algorithm });
        }
        Ok(Self { private, algorithm })
    }

    /// Returns the algorithm every signature is made with.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the private key.
    #[must_use]
    pub const fn private_key(&self) -> &PrivateKey {
        &self.private
    }

    /// Returns the public half, with no common parameter but an `AKP`
    /// key's `alg`.
    #[must_use]
    pub const fn public_jwk(&self) -> &Jwk {
        &self.private.public
    }

    /// Returns the signature of `message`, the JWS signing input, under this
    /// key's algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`JwsError::Sign`] when the signer fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JwsError> {
        let random = SystemRandom::new();
        let failed = |_unspecified| JwsError::Sign;
        match &*self.private.pair {
            Pair::Rsa(pair) => {
                let encoding: &'static dyn signature::RsaEncoding = match self.algorithm {
                    Algorithm::Rs256 => &signature::RSA_PKCS1_SHA256,
                    Algorithm::Rs384 => &signature::RSA_PKCS1_SHA384,
                    Algorithm::Rs512 => &signature::RSA_PKCS1_SHA512,
                    Algorithm::Ps256 => &signature::RSA_PSS_SHA256,
                    Algorithm::Ps384 => &signature::RSA_PSS_SHA384,
                    _ => &signature::RSA_PSS_SHA512,
                };
                let mut signed = vec![0; pair.public_modulus_len()];
                pair.sign(encoding, &random, message, &mut signed)
                    .map_err(failed)?;
                Ok(signed)
            }
            Pair::Ec(pair, _) => Ok(pair
                .sign(&random, message)
                .map_err(failed)?
                .as_ref()
                .to_vec()),
            Pair::Ed25519(pair) => Ok(pair.sign(message).as_ref().to_vec()),
            Pair::MlDsa(pair, _) => {
                let mut signed = vec![0; pair.algorithm().signature_len()];
                let length = pair.sign(message, &mut signed).map_err(failed)?;
                signed.truncate(length);
                Ok(signed)
            }
        }
    }
}
