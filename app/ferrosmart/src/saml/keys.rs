// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The keys of the SAML exchange.
//!
//! They are the identity provider's signing keys,
//! which FerroSMART trusts from its metadata, and FerroSMART's own signing
//! and decryption keys, each paired with the certificate its metadata
//! publishes (saml-metadata-2.0-os §2.4.1.1).
//!
//! A trusted key is read from a certificate, and the certificate is only
//! its carrier: its validity dates, issuer and extensions are not checked,
//! since the trust comes from the metadata that lists it (no specification
//! in the pinned set governs this: our own design, as the SAML V2.0
//! Metadata Interoperability Profile has it).

use std::fmt;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::OaepPrivateDecryptingKey;
use aws_lc_rs::rsa::PrivateDecryptingKey;
use aws_lc_rs::signature;
use aws_lc_rs::signature::EcdsaKeyPair;
use aws_lc_rs::signature::KeyPair;
use aws_lc_rs::signature::RsaKeyPair;
use x509_parser::oid_registry::OID_EC_P256;
use x509_parser::oid_registry::OID_NIST_EC_P384;
use x509_parser::oid_registry::OID_NIST_EC_P521;
use x509_parser::prelude::FromDer;
use x509_parser::prelude::X509Certificate;
use x509_parser::public_key::PublicKey;

/// The smallest RSA modulus accepted for any key of the exchange, the
/// floor `RSA_PKCS1_2048_8192_*` holds too (no SAML specification sets
/// one: our own design, after NIST SP 800-131A).
const MIN_RSA_BITS: usize = 2048;

/// A key or certificate FerroSMART cannot use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// The bytes are not one PEM block with the expected label.
    #[error("the PEM input is not one {0} block")]
    Pem(&'static str),
    /// The bytes are not one DER X.509 certificate.
    #[error("the certificate is not a DER X.509 certificate")]
    Certificate,
    /// The key is neither RSA of at least 2048 bits nor on P-256, P-384 or
    /// P-521.
    #[error("the key is neither RSA of at least 2048 bits nor on P-256, P-384 or P-521")]
    Unsupported,
    /// The private key is not a PKCS#8 key of a supported kind.
    #[error("the private key is not a PKCS#8 RSA or ECDSA key of a supported kind")]
    PrivateKey,
    /// The certificate does not carry the private key's public half.
    #[error("the certificate does not carry the private key's public key")]
    Mismatch,
}

/// The kind of a trusted public key, which decides the signature
/// algorithms it may verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KeyKind {
    /// An RSA key of at least 2048 bits.
    Rsa,
    /// An ECDSA key on P-256.
    P256,
    /// An ECDSA key on P-384.
    P384,
    /// An ECDSA key on P-521.
    P521,
}

/// One signing key of the identity provider, trusted from its metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustedKey {
    /// The kind of the key.
    kind: KeyKind,
    /// The bytes `aws-lc-rs` verifies with: the `SubjectPublicKeyInfo` of
    /// an RSA key, the uncompressed point of an ECDSA key.
    public: Vec<u8>,
    /// The end of the certificate's validity (RFC 5280 §4.1.2.5).
    not_after: Option<jiff::Timestamp>,
}

impl fmt::Debug for TrustedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedKey")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl TrustedKey {
    /// Returns the key the DER certificate `der` carries.
    ///
    /// # Errors
    ///
    /// [`KeyError::Certificate`] when `der` is not one certificate, and
    /// [`KeyError::Unsupported`] for a key of another kind or a short RSA
    /// modulus.
    pub fn from_certificate_der(der: &[u8]) -> Result<Self, KeyError> {
        let (rest, certificate) =
            X509Certificate::from_der(der).map_err(|_malformed| KeyError::Certificate)?;
        if !rest.is_empty() {
            return Err(KeyError::Certificate);
        }
        let spki = certificate.public_key();
        let kind = key_kind(&certificate)?;
        let public = match kind {
            KeyKind::Rsa => spki.raw.to_vec(),
            KeyKind::P256 | KeyKind::P384 | KeyKind::P521 => spki.subject_public_key.data.to_vec(),
        };
        // NOTE: RFC 5280 §4.1.2.5, a notAfter past jiff's range is reported as none;
        // the key verifies all the same.
        let not_after =
            jiff::Timestamp::from_second(certificate.validity().not_after.timestamp()).ok();
        Ok(Self {
            kind,
            public,
            not_after,
        })
    }

    /// Returns the key the one PEM certificate `pem` carries, as a
    /// deployment configures a key that must sign the metadata.
    ///
    /// # Errors
    ///
    /// [`KeyError::Pem`] when `pem` is not one `CERTIFICATE` block, and the
    /// errors of [`TrustedKey::from_certificate_der`].
    pub fn from_certificate_pem(pem: &[u8]) -> Result<Self, KeyError> {
        Self::from_certificate_der(&pem_block(pem, "CERTIFICATE")?)
    }

    /// Returns the end of the certificate's validity, when it lies in the
    /// range of an instant.
    #[must_use]
    pub const fn not_after(&self) -> Option<jiff::Timestamp> {
        self.not_after
    }

    /// The kind of the key.
    pub(super) fn kind(&self) -> KeyKind {
        self.kind
    }

    /// The bytes `aws-lc-rs` verifies with.
    pub(super) fn public(&self) -> &[u8] {
        &self.public
    }
}

/// Returns the kind of the key `certificate` carries.
fn key_kind(certificate: &X509Certificate<'_>) -> Result<KeyKind, KeyError> {
    let spki = certificate.public_key();
    match spki.parsed().map_err(|_malformed| KeyError::Certificate)? {
        PublicKey::RSA(rsa) if rsa.key_size() >= MIN_RSA_BITS => Ok(KeyKind::Rsa),
        PublicKey::EC(_) => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.as_oid().ok())
                .ok_or(KeyError::Unsupported)?;
            if curve == OID_EC_P256 {
                Ok(KeyKind::P256)
            } else if curve == OID_NIST_EC_P384 {
                Ok(KeyKind::P384)
            } else if curve == OID_NIST_EC_P521 {
                Ok(KeyKind::P521)
            } else {
                Err(KeyError::Unsupported)
            }
        }
        _ => Err(KeyError::Unsupported),
    }
}

/// Returns the DER contents of the one PEM block of `pem` labelled `label`.
fn pem_block(pem: &[u8], label: &'static str) -> Result<Vec<u8>, KeyError> {
    let (rest, block) =
        x509_parser::pem::parse_x509_pem(pem).map_err(|_unread| KeyError::Pem(label))?;
    let rest_is_blank = rest.iter().all(u8::is_ascii_whitespace);
    if block.label == label && rest_is_blank {
        Ok(block.contents)
    } else {
        Err(KeyError::Pem(label))
    }
}

/// A certificate FerroSMART publishes in its metadata, with the
/// `SubjectPublicKeyInfo` it carries.
#[derive(Clone, PartialEq, Eq)]
struct Certificate {
    /// The certificate, DER.
    der: Vec<u8>,
    /// The `subjectPublicKey` bit string's bytes.
    public: Vec<u8>,
    /// The whole `SubjectPublicKeyInfo`, DER.
    spki: Vec<u8>,
}

impl Certificate {
    /// Reads the one PEM certificate of `pem`.
    fn from_pem(pem: &[u8]) -> Result<Self, KeyError> {
        let der = pem_block(pem, "CERTIFICATE")?;
        let (rest, certificate) =
            X509Certificate::from_der(&der).map_err(|_malformed| KeyError::Certificate)?;
        if !rest.is_empty() {
            return Err(KeyError::Certificate);
        }
        key_kind(&certificate)?;
        let spki = certificate.public_key();
        let public = spki.subject_public_key.data.to_vec();
        let spki = spki.raw.to_vec();
        Ok(Self { der, public, spki })
    }
}

/// The private half of FerroSMART's signing key.
enum Signer {
    /// An RSA key, signing RSASSA-PKCS1-v1_5 with SHA-256.
    Rsa(RsaKeyPair),
    /// An ECDSA key on P-256, signing with SHA-256.
    P256(EcdsaKeyPair),
    /// An ECDSA key on P-384, signing with SHA-384.
    P384(EcdsaKeyPair),
}

/// FerroSMART's key that signs its `AuthnRequest` and `ArtifactResolve`
/// messages, with the certificate its metadata publishes for `use="signing"`.
pub struct SigningKey {
    /// The private key.
    signer: Signer,
    /// The certificate.
    certificate: Certificate,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("algorithm", &self.algorithm())
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Returns the key of the PKCS#8 PEM `private_key` (`PRIVATE KEY`),
    /// paired with the PEM certificate `certificate` that carries its
    /// public half.
    ///
    /// # Errors
    ///
    /// [`KeyError::Pem`] for input that is not one block of its label,
    /// [`KeyError::PrivateKey`] for a key that is neither RSA of at least
    /// 2048 bits nor ECDSA on P-256 or P-384, [`KeyError::Certificate`] and
    /// [`KeyError::Unsupported`] for the certificate, and
    /// [`KeyError::Mismatch`] when the two halves differ.
    pub fn from_pem(private_key: &[u8], certificate: &[u8]) -> Result<Self, KeyError> {
        let pkcs8 = pem_block(private_key, "PRIVATE KEY")?;
        let certificate = Certificate::from_pem(certificate)?;
        let signer = if let Ok(rsa) = RsaKeyPair::from_pkcs8(&pkcs8) {
            if rsa.public_modulus_len().saturating_mul(8) < MIN_RSA_BITS {
                return Err(KeyError::PrivateKey);
            }
            Signer::Rsa(rsa)
        } else if let Ok(ec) =
            EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8)
        {
            Signer::P256(ec)
        } else if let Ok(ec) =
            EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P384_SHA384_FIXED_SIGNING, &pkcs8)
        {
            Signer::P384(ec)
        } else {
            return Err(KeyError::PrivateKey);
        };
        let public = match &signer {
            Signer::Rsa(rsa) => rsa.public_key().as_ref().to_vec(),
            Signer::P256(ec) | Signer::P384(ec) => ec.public_key().as_ref().to_vec(),
        };
        if public != certificate.public {
            return Err(KeyError::Mismatch);
        }
        Ok(Self {
            signer,
            certificate,
        })
    }

    /// The XML Signature algorithm URI the key signs with (xmldsig-core1
    /// §6.4.2, §6.4.3; RFC 6931 §2.3.2, §2.3.6).
    #[must_use]
    pub fn algorithm(&self) -> &'static str {
        match self.signer {
            Signer::Rsa(_) => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            Signer::P256(_) => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            Signer::P384(_) => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
        }
    }

    /// The certificate the metadata publishes, DER.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate.der
    }

    /// Returns the signature of `message`: PKCS#1 v1.5, or the ECDSA `r`
    /// and `s` concatenated as xmldsig-core1 §6.4.3 encodes them.
    pub(super) fn sign(&self, message: &[u8]) -> Result<Vec<u8>, aws_lc_rs::error::Unspecified> {
        let rng = SystemRandom::new();
        match &self.signer {
            Signer::Rsa(rsa) => {
                let mut out = vec![0_u8; rsa.public_modulus_len()];
                rsa.sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut out)?;
                Ok(out)
            }
            Signer::P256(ec) | Signer::P384(ec) => Ok(ec.sign(&rng, message)?.as_ref().to_vec()),
        }
    }
}

/// One of FerroSMART's RSA keys that decrypt the content keys of an
/// encrypted element, with the certificate its metadata publishes for
/// `use="encryption"`.
pub struct DecryptionKey {
    /// The private key.
    key: OaepPrivateDecryptingKey,
    /// The certificate.
    certificate: Certificate,
}

impl fmt::Debug for DecryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptionKey").finish_non_exhaustive()
    }
}

impl DecryptionKey {
    /// Returns the RSA key of the PKCS#8 PEM `private_key`, paired with
    /// the PEM certificate `certificate` that carries its public half.
    ///
    /// # Errors
    ///
    /// [`KeyError::Pem`] for input that is not one block of its label,
    /// [`KeyError::PrivateKey`] for a key that is not RSA of at least 2048
    /// bits, [`KeyError::Certificate`] and [`KeyError::Unsupported`] for
    /// the certificate, and [`KeyError::Mismatch`] when the two halves
    /// differ.
    pub fn from_pem(private_key: &[u8], certificate: &[u8]) -> Result<Self, KeyError> {
        let pkcs8 = pem_block(private_key, "PRIVATE KEY")?;
        let certificate = Certificate::from_pem(certificate)?;
        let key =
            PrivateDecryptingKey::from_pkcs8(&pkcs8).map_err(|_rejected| KeyError::PrivateKey)?;
        if key.key_size_bits() < MIN_RSA_BITS {
            return Err(KeyError::PrivateKey);
        }
        let public = key
            .public_key()
            .as_der()
            .map_err(|_unspecified| KeyError::PrivateKey)?;
        if public.as_ref() != certificate.spki.as_slice() {
            return Err(KeyError::Mismatch);
        }
        let key =
            OaepPrivateDecryptingKey::new(key).map_err(|_unspecified| KeyError::PrivateKey)?;
        Ok(Self { key, certificate })
    }

    /// The certificate the metadata publishes, DER.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate.der
    }

    /// The RSA-OAEP decryption key.
    pub(super) fn oaep(&self) -> &OaepPrivateDecryptingKey {
        &self.key
    }
}
