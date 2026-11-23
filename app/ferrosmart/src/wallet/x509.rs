// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The X.509 certificate paths that authenticate an issuer.
//!
//! They authenticate a credential's issuer and the signer of its status
//! list: a chain from the JOSE header, leaf first, that ends at one of the
//! configured trust anchors (HAIP 1.0 §6.1.1, draft-ietf-oauth-sd-jwt-vc-13
//! §3.5).

use x509_parser::extensions::ParsedExtension;
use x509_parser::oid_registry::OID_EC_P256;
use x509_parser::prelude::{ASN1Time, FromDer, X509Certificate};

/// Why the configured anchors cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AnchorError {
    /// A file holds no PEM `CERTIFICATE` block, or one that is not a DER
    /// certificate.
    #[error("a trust anchor file holds no readable PEM certificate")]
    Unreadable,
    /// No anchor is configured.
    #[error("no trust anchor is configured")]
    None,
}

/// One trust anchor: a certificate whose key ends a path.
#[derive(Clone, PartialEq, Eq)]
struct Anchor {
    /// The certificate, DER.
    der: Vec<u8>,
}

/// The trust anchors of the PID providers.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Anchors {
    /// The anchors, in configuration order.
    anchors: Vec<Anchor>,
}

impl std::fmt::Debug for Anchors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Anchors")
            .field("count", &self.anchors.len())
            .finish()
    }
}

/// Returns the DER certificates of every PEM `CERTIFICATE` block of `pem`.
///
/// # Errors
/// Returns [`AnchorError::Unreadable`] when `pem` holds none, or one that is
/// not a DER certificate.
pub fn certificates(pem: &[u8]) -> Result<Vec<Vec<u8>>, AnchorError> {
    let mut found = Vec::new();
    for block in x509_parser::pem::Pem::iter_from_buffer(pem) {
        let block = block.map_err(|_unread| AnchorError::Unreadable)?;
        if block.label != "CERTIFICATE" {
            continue;
        }
        let (rest, _certificate) = X509Certificate::from_der(&block.contents)
            .map_err(|_malformed| AnchorError::Unreadable)?;
        if !rest.is_empty() {
            return Err(AnchorError::Unreadable);
        }
        found.push(block.contents);
    }
    if found.is_empty() {
        return Err(AnchorError::Unreadable);
    }
    Ok(found)
}

impl Anchors {
    /// Returns the anchors the PEM files `files` hold, each file one or more
    /// certificates.
    ///
    /// # Errors
    /// Returns [`AnchorError::Unreadable`] for a file of no readable
    /// certificate, and [`AnchorError::None`] when there is none at all.
    pub fn from_pem(files: &[Vec<u8>]) -> Result<Self, AnchorError> {
        let mut anchors = Vec::new();
        for file in files {
            anchors.extend(certificates(file)?.into_iter().map(|der| Anchor { der }));
        }
        if anchors.is_empty() {
            return Err(AnchorError::None);
        }
        Ok(Self { anchors })
    }

    /// Returns the base64url key identifier of each anchor that carries one,
    /// the values of a DCQL `aki` trusted authorities query (OpenID4VP 1.0
    /// §6.1.1.1).
    #[must_use]
    pub fn key_identifiers(&self) -> Vec<String> {
        self.anchors
            .iter()
            .filter_map(|anchor| {
                let (_, certificate) = X509Certificate::from_der(&anchor.der).ok()?;
                certificate.extensions().iter().find_map(|extension| {
                    match extension.parsed_extension() {
                        ParsedExtension::SubjectKeyIdentifier(identifier) => {
                            Some(super::encode(identifier.0))
                        }
                        _ => None,
                    }
                })
            })
            .collect()
    }

    /// Returns the P-256 point of the leaf of `chain` (DER certificates,
    /// leaf first, the anchor left out) once every certificate is valid at
    /// `now` (seconds since the epoch), each is signed by the next, the
    /// last by an anchor, and every signer is a certificate authority.
    ///
    /// # Errors
    /// Returns [`PathError`] naming the first check that fails.
    pub fn verify(&self, chain: &[Vec<u8>], now: i64) -> Result<Vec<u8>, PathError> {
        let at = ASN1Time::from_timestamp(now).map_err(|_out_of_range| PathError::Time)?;
        let parsed = chain
            .iter()
            .map(|der| match X509Certificate::from_der(der) {
                Ok(([], certificate)) => Ok(certificate),
                _ => Err(PathError::Malformed),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let leaf = parsed.first().ok_or(PathError::Empty)?;
        // NOTE: HAIP 1.0 §6.1.1, the certificate that signs is never self-signed.
        if leaf.subject().as_raw() == leaf.issuer().as_raw() {
            return Err(PathError::SelfSigned);
        }
        for (index, certificate) in parsed.iter().enumerate() {
            if !certificate.validity().is_valid_at(at) {
                return Err(PathError::Expired);
            }
            if let Some(signer) = parsed.get(index + 1) {
                signed_by(certificate, signer)?;
            }
        }
        let last = parsed.last().ok_or(PathError::Empty)?;
        let anchored = self.anchors.iter().any(|anchor| {
            X509Certificate::from_der(&anchor.der).is_ok_and(|(_, root)| {
                root.validity().is_valid_at(at) && signed_by(last, &root).is_ok()
            })
        });
        if !anchored {
            return Err(PathError::Unanchored);
        }
        p256(leaf).ok_or(PathError::Key)
    }
}

/// Checks that `signer` is a certificate authority that names and signs
/// `certificate` (RFC 5280 §6.1.3).
fn signed_by(
    certificate: &X509Certificate<'_>,
    signer: &X509Certificate<'_>,
) -> Result<(), PathError> {
    if certificate.issuer().as_raw() != signer.subject().as_raw() {
        return Err(PathError::Issuer);
    }
    if !signer.is_ca() {
        return Err(PathError::NotAuthority);
    }
    certificate
        .verify_signature(Some(signer.public_key()))
        .map_err(|_unverified| PathError::Signature)
}

/// Returns the uncompressed point of the P-256 key `certificate` carries.
fn p256(certificate: &X509Certificate<'_>) -> Option<Vec<u8>> {
    let spki = certificate.public_key();
    let curve = spki.algorithm.parameters.as_ref()?.as_oid().ok()?;
    (curve == OID_EC_P256).then(|| spki.subject_public_key.data.to_vec())
}

/// Why a certificate path is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PathError {
    /// The header carries no certificate.
    #[error("the path holds no certificate")]
    Empty,
    /// A certificate is not one DER X.509 certificate.
    #[error("a certificate of the path does not read")]
    Malformed,
    /// The leaf is self-signed.
    #[error("the leaf certificate is self-signed")]
    SelfSigned,
    /// A certificate is outside its validity.
    #[error("a certificate of the path is outside its validity")]
    Expired,
    /// A certificate's issuer is not the next certificate's subject.
    #[error("a certificate's issuer is not the next certificate")]
    Issuer,
    /// A signer is not a certificate authority.
    #[error("a signer of the path is not a certificate authority")]
    NotAuthority,
    /// A signature does not verify.
    #[error("a certificate's signature does not verify")]
    Signature,
    /// No configured anchor signs the last certificate.
    #[error("no trust anchor signs the path")]
    Unanchored,
    /// The leaf's key is not on P-256.
    #[error("the leaf's key is not on P-256")]
    Key,
    /// The time is outside what a certificate can state.
    #[error("the time cannot be compared with a certificate's validity")]
    Time,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyIdMethod, KeyPair,
        PKCS_ECDSA_P256_SHA256,
    };

    struct Authority {
        params: CertificateParams,
        key: KeyPair,
        der: Vec<u8>,
        pem: String,
    }

    fn params(name: &str, ca: bool) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params should build");
        params.distinguished_name.push(DnType::CommonName, name);
        params.key_identifier_method = KeyIdMethod::Sha256;
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2100, 1, 1);
        if ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        }
        params
    }

    fn key() -> KeyPair {
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("a key should generate")
    }

    fn signed(params: CertificateParams, key: KeyPair, signer: Option<&Authority>) -> Authority {
        let certificate = match signer {
            Some(signer) => {
                params.signed_by(&key, &Issuer::from_params(&signer.params, &signer.key))
            }
            None => params.self_signed(&key),
        }
        .expect("the certificate should sign");
        Authority {
            params,
            key,
            der: certificate.der().to_vec(),
            pem: certificate.pem(),
        }
    }

    fn authority(name: &str, signer: Option<&Authority>) -> Authority {
        signed(params(name, true), key(), signer)
    }

    fn leaf(name: &str, signer: &Authority) -> Vec<u8> {
        signed(params(name, false), key(), Some(signer)).der
    }

    fn anchors(root: &Authority) -> Anchors {
        Anchors::from_pem(&[root.pem.clone().into_bytes()]).expect("the anchor should read")
    }

    fn now() -> i64 {
        jiff::Timestamp::now().as_second()
    }

    #[test]
    fn a_path_through_an_intermediate_to_an_anchor_verifies() {
        let root = authority("root", None);
        let middle = authority("middle", Some(&root));
        let chain = vec![leaf("issuer", &middle), middle.der.clone()];
        let point = anchors(&root)
            .verify(&chain, now())
            .expect("the path should verify");
        assert_eq!(point.len(), 65);
    }

    #[test]
    fn a_path_to_another_root_is_unanchored() {
        let root = authority("root", None);
        let other = authority("other", None);
        let chain = vec![leaf("issuer", &other)];
        assert_eq!(
            anchors(&root).verify(&chain, now()),
            Err(PathError::Unanchored)
        );
    }

    #[test]
    fn a_self_signed_leaf_is_refused() {
        let root = authority("root", None);
        let chain = vec![root.der.clone()];
        assert_eq!(
            anchors(&root).verify(&chain, now()),
            Err(PathError::SelfSigned)
        );
    }

    #[test]
    fn a_leaf_signing_another_leaf_is_not_an_authority() {
        let root = authority("root", None);
        let not_ca = signed(params("not-ca", false), key(), Some(&root));
        let chain = vec![leaf("issuer", &not_ca), not_ca.der.clone()];
        assert_eq!(
            anchors(&root).verify(&chain, now()),
            Err(PathError::NotAuthority)
        );
    }

    #[test]
    fn a_path_past_its_validity_is_expired() {
        let root = authority("root", None);
        let chain = vec![leaf("issuer", &root)];
        let past_2100 = 4_102_444_800 + 1;
        assert_eq!(
            anchors(&root).verify(&chain, past_2100),
            Err(PathError::Expired)
        );
    }

    #[test]
    fn the_anchor_key_identifier_is_a_dcql_aki_value() {
        let root = authority("root", None);
        assert_eq!(anchors(&root).key_identifiers().len(), 1);
    }

    #[test]
    fn a_file_without_a_certificate_is_unreadable() {
        assert_eq!(certificates(b"nothing"), Err(AnchorError::Unreadable));
        assert_eq!(Anchors::from_pem(&[]), Err(AnchorError::None));
    }
}
