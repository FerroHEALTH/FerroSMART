// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The client assertion of `private_key_jwt` (RFC 7523 §2.2), the one
//! private key the library holds.
//!
//! The key signs the product's own client assertion to the token endpoint;
//! no resource server accepts the assertion as an access token (RFC 9068
//! §4, the `typ` and `aud` checks). It also signs a JWT of the product's own
//! claims ([`AssertionKey::sign`]), each kind under its own `typ` (RFC 8725
//! §3.11), so the one key the product publishes verifies both. The assertion
//! carries the header `alg`, `kid` and `typ`, and the claims `iss` and `sub`
//! both the client id, `aud`, `exp` at most five minutes ahead and a unique
//! `jti`; one assertion per request (RFC 7523 §3). Its `aud` and `typ` follow
//! the grant's security profile: the token endpoint under `JWT` (SMART App
//! Launch 2.2.0, Client Authentication: Asymmetric), or under FAPI 2.0 the
//! issuer identifier under `client-authentication+jwt` (FAPI 2.0 §5.3.3.1,
//! RFC 10070 §4). The product serves the matching public keys as a JWK Set
//! (RFC 7517 §5) at a route of its own.

use base64::Engine as _;
use serde::Serialize;

use crate::jws::JwsError;
use crate::jws::algorithm::Algorithm;
use crate::jws::compact::Header;
use crate::jws::key::KeyError;
use crate::jws::key::PrivateKey;
use crate::jws::key::SigningKey;

/// How long a client assertion is valid: 60 seconds.
///
/// SMART App Launch 2.2.0 (Client Authentication: Asymmetric) sets `exp`
/// "no more than five minutes in the future", a ceiling. An assertion is
/// signed for one request and sent at once (RFC 7523 §3), so its lifetime
/// covers only clock skew and transit, and an authorization server may
/// accept less than five minutes: mock-oauth2-server refuses an assertion
/// that lives longer than 120 seconds. The value is our own design.
pub const ASSERTION_LIFETIME_SECONDS: i64 = 60;

/// The `client_assertion_type` of a JWT assertion (RFC 7523 §2.2).
pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// A key that cannot sign a client assertion.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AssertionError {
    /// The PEM is no RSA, EC, Ed25519 or ML-DSA private key.
    #[error("the private key is not an RSA, EC, Ed25519 or ML-DSA key in PEM form")]
    Key {
        /// What the key reader reported.
        #[source]
        source: KeyError,
    },
    /// The algorithm belongs to another key type, curve or ML-DSA parameter
    /// set.
    #[error("the algorithm {algorithm} cannot sign with this key")]
    Algorithm {
        /// The algorithm.
        algorithm: Algorithm,
    },
    /// The random source for `jti` failed.
    #[error("the random source for the assertion id failed")]
    Random,
    /// The assertion could not be signed.
    #[error("the assertion could not be signed")]
    Sign {
        /// What the signer reported.
        #[source]
        source: JwsError,
    },
    /// The EC key is on neither P-256 nor P-384, the curves ES256 and ES384
    /// sign with (RFC 7518 §3.4).
    #[error("the EC key is on neither P-256 (ES256) nor P-384 (ES384)")]
    Curve,
    /// The certificate is no X.509 certificate in PEM form.
    #[error("the certificate is not an X.509 certificate in PEM form")]
    Certificate,
    /// The certificate carries another public key than the signing key's.
    #[error("the certificate carries another public key than the signing key")]
    CertificateKey,
}

/// The key a product signs its client assertions with, and its public
/// half.
#[derive(Clone)]
pub struct AssertionKey {
    /// The private half, with the algorithm the assertion is signed with.
    signing: SigningKey,
    /// The `kid` the public half is published under.
    kid: String,
    /// The `x5t#S256` of the key's certificate, for a party that knows the
    /// key by its certificate (RFC 7515 §4.1.8).
    certificate_thumbprint: Option<String>,
}

impl std::fmt::Debug for AssertionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssertionKey")
            .field("algorithm", &self.signing.algorithm())
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl AssertionKey {
    /// Returns the key `pem` holds, signing with `algorithm`, published
    /// under `kid`.
    ///
    /// Without `algorithm`, an EC key signs with the algorithm of its curve,
    /// ES256 for P-256 and ES384 for P-384 (RFC 7518 §3.4), an Ed25519 key
    /// with `EdDSA`, an ML-DSA key (RFC 9881 §6) with its parameter set
    /// (RFC 9964 §5), and an RSA key with RS384, which SMART's asymmetric
    /// client profile has a client support. Without `kid`, the key is
    /// published under its RFC 7638 SHA-256 thumbprint (the default is our
    /// own design; the thumbprint is the RFC's).
    ///
    /// # Errors
    ///
    /// Returns [`AssertionError::Key`] for a PEM that is no supported private
    /// key, [`AssertionError::Curve`] for an EC key on another curve than
    /// P-256 or P-384, and [`AssertionError::Algorithm`] for an algorithm of
    /// another key type, curve or parameter set.
    pub fn from_pem(
        pem: &[u8],
        algorithm: Option<Algorithm>,
        kid: Option<String>,
    ) -> Result<Self, AssertionError> {
        let private = PrivateKey::from_pem(pem).map_err(|source| match source {
            KeyError::Curve => AssertionError::Curve,
            source => AssertionError::Key { source },
        })?;
        let algorithm = algorithm
            .or_else(|| private.algorithm())
            .unwrap_or(Algorithm::Rs384);
        let signing = SigningKey::new(private, algorithm)
            .map_err(|_other| AssertionError::Algorithm { algorithm })?;
        let kid = kid.unwrap_or_else(|| signing.public_jwk().thumbprint());
        Ok(Self {
            signing,
            kid,
            certificate_thumbprint: None,
        })
    }

    /// Returns this key signing with `algorithm`, another algorithm of an
    /// RSA key's family (RS256 to PS512, RFC 7518 §3.3 and §3.5), as the
    /// party it authenticates to names it. An EC, Ed25519 or ML-DSA key
    /// signs with the one algorithm of its curve or parameter set.
    ///
    /// # Errors
    ///
    /// Returns [`AssertionError::Algorithm`] for an algorithm of another key
    /// type, or any other one for an EC, Ed25519 or ML-DSA key.
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Result<Self, AssertionError> {
        self.signing = SigningKey::new(self.signing.private_key().clone(), algorithm)
            .map_err(|_other| AssertionError::Algorithm { algorithm })?;
        Ok(self)
    }

    /// Returns this key naming its X.509 certificate `pem` by its SHA-256
    /// thumbprint in the header of every JWT it signs (`x5t#S256`, RFC 7515
    /// §4.1.8), for a party that knows the key by its certificate.
    ///
    /// # Errors
    ///
    /// Returns [`AssertionError::Certificate`] for a text that is no PEM
    /// X.509 certificate, and [`AssertionError::CertificateKey`] for a
    /// certificate of another key.
    #[cfg(feature = "oidc")]
    pub fn with_certificate(mut self, pem: &[u8]) -> Result<Self, AssertionError> {
        use x509_parser::prelude::FromDer as _;
        let (_, pem) =
            x509_parser::pem::parse_x509_pem(pem).map_err(|_unread| AssertionError::Certificate)?;
        let (_, certificate) = x509_parser::certificate::X509Certificate::from_der(&pem.contents)
            .map_err(|_unread| AssertionError::Certificate)?;
        if !self.holds(certificate.public_key()) {
            return Err(AssertionError::CertificateKey);
        }
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &pem.contents);
        self.certificate_thumbprint =
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref()));
        Ok(self)
    }

    /// Whether `key`, a certificate's subject public key, is this key's
    /// public half.
    #[cfg(feature = "oidc")]
    fn holds(&self, key: &x509_parser::x509::SubjectPublicKeyInfo<'_>) -> bool {
        use x509_parser::public_key::PublicKey;
        let own = self.signing.public_jwk().to_value();
        let decoded = |name: &str| {
            own.get(name)
                .and_then(serde_json::Value::as_str)
                .and_then(|text| {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(text)
                        .ok()
                })
                .unwrap_or_default()
        };
        let bits = key.subject_public_key.data.as_ref();
        match own.get("kty").and_then(serde_json::Value::as_str) {
            Some("RSA") => match key.parsed() {
                Ok(PublicKey::RSA(rsa)) => {
                    significant(rsa.modulus) == significant(&decoded("n"))
                        && significant(rsa.exponent) == significant(&decoded("e"))
                }
                _ => false,
            },
            Some("EC") => {
                let mut uncompressed = vec![0x04];
                uncompressed.extend(decoded("x"));
                uncompressed.extend(decoded("y"));
                bits == uncompressed.as_slice()
            }
            // NOTE: RFC 8410 §4 and RFC 9881 §4, an Ed25519 or ML-DSA public key is the
            // raw key in the subjectPublicKey bit string.
            Some("OKP") => bits == decoded("x").as_slice(),
            Some("AKP") => bits == decoded("pub").as_slice(),
            _ => false,
        }
    }

    /// Returns the algorithm the assertion is signed with.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.signing.algorithm()
    }

    /// Returns the `kid` the public half is published under.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Returns the public half as the JWK the product publishes (RFC 7517
    /// §4), with its `kid`, `use` and `alg`.
    #[must_use]
    pub fn public_jwk(&self) -> serde_json::Value {
        let mut jwk = self
            .signing
            .public_jwk()
            .clone()
            .with_kid(self.kid.as_str())
            .with_signature_use()
            .to_value();
        if let Some(members) = jwk.as_object_mut() {
            members.insert(
                String::from("alg"),
                serde_json::Value::from(self.signing.algorithm().name()),
            );
        }
        jwk
    }

    /// Returns the compact JWS (RFC 7515 §7.1) of `claims`, signed with this
    /// key's algorithm, its header naming the key's `kid` and `typ`.
    ///
    /// Give each kind of token the product signs a `typ` of its own (RFC 8725
    /// §3.11), never `JWT` or `client-authentication+jwt`, the types of the
    /// client assertion, so a token of one kind is never read as another.
    ///
    /// # Errors
    ///
    /// Returns [`AssertionError::Sign`] when the claims could not be
    /// serialized or the signature failed.
    pub fn sign(&self, typ: &str, claims: &impl Serialize) -> Result<String, AssertionError> {
        let mut header = Header::new(self.signing.algorithm());
        header.kid = Some(self.kid.clone());
        header.typ = Some(typ.to_owned());
        header.x5t_s256.clone_from(&self.certificate_thumbprint);
        crate::jws::compact::encode(&header, claims, &self.signing)
            .map_err(|source| AssertionError::Sign { source })
    }

    /// Returns the assertion of `client_id` for the sole audience
    /// `audience`, typed `typ`, signed now and valid for
    /// [`ASSERTION_LIFETIME_SECONDS`]. A token client takes both from the
    /// grant's security profile.
    ///
    /// # Errors
    ///
    /// Returns [`AssertionError::Random`] when no `jti` could be drawn and
    /// [`AssertionError::Sign`] when the signature failed.
    pub fn assertion(
        &self,
        client_id: &str,
        audience: &str,
        typ: &str,
    ) -> Result<String, AssertionError> {
        let now = jiff::Timestamp::now().as_second();
        let mut random = [0u8; 16];
        aws_lc_rs::rand::fill(&mut random).map_err(|_unspecified| AssertionError::Random)?;
        let claims = Claims {
            iss: client_id,
            sub: client_id,
            aud: audience,
            exp: now.saturating_add(ASSERTION_LIFETIME_SECONDS),
            iat: now,
            jti: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random),
        };
        self.sign(typ, &claims)
    }
}

/// Returns a big-endian integer without its leading zero octets, as a DER
/// integer and a JWK member each write it differently (RFC 7518 §6.3.1).
#[cfg(feature = "oidc")]
fn significant(octets: &[u8]) -> &[u8] {
    let start = octets
        .iter()
        .position(|octet| *octet != 0)
        .unwrap_or(octets.len());
    octets.get(start..).unwrap_or_default()
}

/// The claims of a client assertion (RFC 7523 §3; SMART App Launch 2.2.0,
/// Client Authentication: Asymmetric).
#[derive(Serialize)]
struct Claims<'a> {
    /// The client id.
    iss: &'a str,
    /// The client id.
    sub: &'a str,
    /// The authorization server: its token endpoint or issuer identifier.
    aud: &'a str,
    /// The expiry.
    exp: i64,
    /// The issue time.
    iat: i64,
    /// The unique id of this assertion.
    jti: String,
}

/// Returns the JWK Set (RFC 7517 §5) of `keys`, the current and the
/// successor key during a rotation.
#[must_use]
pub fn jwk_set(keys: &[&AssertionKey]) -> serde_json::Value {
    serde_json::json!({
        "keys": keys.iter().map(|key| key.public_jwk()).collect::<Vec<_>>()
    })
}
