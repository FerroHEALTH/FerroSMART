// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The list of PID providers the Commission publishes, read and verified.
//!
//! Implementing Regulation (EU) 2024/2980 Art 5(2), as amended by 2026/1731,
//! has the Commission publish the list, signed or sealed, with the
//! specification of its structure, its URL and its signing certificates
//! (Art 5(4)). No published act names the structure yet; this module reads
//! the one the Architecture and Reference Framework points to, ETSI TS 119
//! 602 V1.1.1 Annex D, in its JSON binding (Annex A.1) under a compact JAdES
//! baseline B signature (Annex D.4).

use std::str::FromStr as _;

use base64::Engine as _;
use serde_json::Value;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

use super::Jws;

/// The `LoTEType` of the PID providers list (ETSI TS 119 602 Table D.1).
pub const PID_PROVIDERS_LIST: &str = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList";

/// The service type of a PID provider's issuance (ETSI TS 119 602 Table D.3).
const ISSUANCE: &str = "http://uri.etsi.org/19602/SvcType/PID/Issuance";

/// The service type of a PID provider's status information (ETSI TS 119 602
/// Table D.3).
const REVOCATION: &str = "http://uri.etsi.org/19602/SvcType/PID/Revocation";

/// How far in the future a list's issue time may lie, in seconds, for the
/// clocks of publisher and reader (no specification sets one: our own
/// design).
const CLOCK_SKEW: i64 = 300;

/// Why a list is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ListError {
    /// The text is not a compact JWS whose payload is a list.
    #[error("the list is not a compact JWS of a list of trusted entities")]
    Malformed,
    /// No configured certificate verifies the signature.
    #[error("no configured certificate verifies the list's signature")]
    Signature,
    /// The signer's subject does not name the list's territory and operator
    /// (ETSI TS 119 602 §6.8.0).
    #[error("the signing certificate does not name the list's territory and operator")]
    Signer,
    /// The list is of another type.
    #[error("the list is not the list of PID providers")]
    Type,
    /// The list's next update has passed, or it names none (§6.3.15).
    #[error("the list is past its next update")]
    Expired,
    /// The list was issued in the future.
    #[error("the list was issued after now")]
    Future,
}

/// A verified list of PID providers.
#[derive(Clone, PartialEq, Eq)]
pub struct ProvidersList {
    /// When it was issued, in seconds since the epoch.
    pub issued_at: i64,
    /// When it must be replaced by, in seconds since the epoch.
    pub next_update: i64,
    /// The certificates of the providers' issuance services, DER.
    pub issuance: Vec<Vec<u8>>,
    /// The certificates of the providers' status services, DER.
    pub revocation: Vec<Vec<u8>>,
}

impl std::fmt::Debug for ProvidersList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvidersList")
            .field("issued_at", &self.issued_at)
            .field("next_update", &self.next_update)
            .field("issuance", &self.issuance.len())
            .field("revocation", &self.revocation.len())
            .finish()
    }
}

/// Reads the compact JAdES list `text` signed by one of `signers` (DER
/// certificates) at `now`, seconds since the epoch.
///
/// # Errors
/// Returns the [`ListError`] of the first check that fails.
pub fn read(text: &str, signers: &[Vec<u8>], now: i64) -> Result<ProvidersList, ListError> {
    let jws = Jws::parse(text.trim()).ok_or(ListError::Malformed)?;
    let signer = signers
        .iter()
        .find(|signer| named_by(&jws, signer) && verifies(&jws, signer))
        .ok_or(ListError::Signature)?;
    let information = jws
        .claims
        .get("LoTE")
        .and_then(|lote| lote.get("ListAndSchemeInformation"))
        .ok_or(ListError::Malformed)?;
    if !signed_for(signer, information) {
        return Err(ListError::Signer);
    }
    if information.get("LoTEType").and_then(Value::as_str) != Some(PID_PROVIDERS_LIST) {
        return Err(ListError::Type);
    }
    let issued_at = instant(information.get("ListIssueDateTime")).ok_or(ListError::Malformed)?;
    if issued_at > now + CLOCK_SKEW {
        return Err(ListError::Future);
    }
    // NOTE: ETSI TS 119 602 §6.3.15, a list whose next update has passed is discarded as
    // expired; a null next update closes the list.
    let next_update = instant(information.get("NextUpdate")).ok_or(ListError::Expired)?;
    if now >= next_update {
        return Err(ListError::Expired);
    }
    let mut list = ProvidersList {
        issued_at,
        next_update,
        issuance: Vec::new(),
        revocation: Vec::new(),
    };
    let entities = jws
        .claims
        .get("LoTE")
        .and_then(|lote| lote.get("TrustedEntitiesList"))
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    for service in entities
        .iter()
        .filter_map(|entity| entity.get("TrustedEntityServices")?.as_array())
        .flatten()
        .filter_map(|service| service.get("ServiceInformation"))
    {
        let certificates = certificates(service)?;
        match service.get("ServiceTypeIdentifier").and_then(Value::as_str) {
            Some(REVOCATION) => list.revocation.extend(certificates),
            None | Some(ISSUANCE) => list.issuance.extend(certificates),
            Some(_) => {}
        }
    }
    Ok(list)
}

/// Returns the DER certificates of the service `service` (ETSI TS 119 602
/// §6.6.3.1: standard base64).
fn certificates(service: &Value) -> Result<Vec<Vec<u8>>, ListError> {
    service
        .get("ServiceDigitalIdentity")
        .and_then(|identity| identity.get("X509Certificates"))
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .map(|certificate| {
            certificate
                .get("val")
                .and_then(Value::as_str)
                .and_then(|text| base64::engine::general_purpose::STANDARD.decode(text).ok())
                .ok_or(ListError::Malformed)
        })
        .collect()
}

/// Returns the instant of the RFC 3339 date-time `value`, in seconds since
/// the epoch (ETSI TS 119 602 §6.1.3).
fn instant(value: Option<&Value>) -> Option<i64> {
    let text = value?.as_str()?;
    jiff::Timestamp::from_str(text)
        .ok()
        .map(jiff::Timestamp::as_second)
}

/// Whether the header of `jws` names `signer`, by `x5t#S256` or as the
/// first `x5c` certificate, or names no certificate at all.
fn named_by(jws: &Jws<'_>, signer: &[u8]) -> bool {
    if let Some(thumbprint) = jws.header_text("x5t#S256") {
        return super::decode(thumbprint).is_ok_and(|named| named == super::sha256(signer));
    }
    if let Some(first) = jws
        .header
        .get("x5c")
        .and_then(Value::as_array)
        .and_then(|chain| chain.first())
    {
        return first
            .as_str()
            .and_then(|text| base64::engine::general_purpose::STANDARD.decode(text).ok())
            .is_some_and(|named| named == signer);
    }
    true
}

/// Whether the signature of `jws` verifies under the key of the
/// certificate `signer`, with the algorithm its header names for that key.
fn verifies(jws: &Jws<'_>, signer: &[u8]) -> bool {
    let Ok((_, certificate)) = X509Certificate::from_der(signer) else {
        return false;
    };
    let Some(algorithm) = jws
        .header_text("alg")
        .and_then(|alg| jsonwebtoken::Algorithm::from_str(alg).ok())
    else {
        return false;
    };
    let spki = certificate.public_key();
    let key = match (spki.parsed(), algorithm) {
        (Ok(PublicKey::EC(_)), jsonwebtoken::Algorithm::ES256 | jsonwebtoken::Algorithm::ES384) => {
            jsonwebtoken::DecodingKey::from_ec_der(&spki.subject_public_key.data)
        }
        (
            Ok(PublicKey::RSA(_)),
            jsonwebtoken::Algorithm::RS256
            | jsonwebtoken::Algorithm::RS384
            | jsonwebtoken::Algorithm::RS512
            | jsonwebtoken::Algorithm::PS256
            | jsonwebtoken::Algorithm::PS384
            | jsonwebtoken::Algorithm::PS512,
        ) => jsonwebtoken::DecodingKey::from_rsa_der(&spki.subject_public_key.data),
        _ => return false,
    };
    jsonwebtoken::crypto::verify(jws.signature, jws.signing_input.as_bytes(), &key, algorithm)
        .unwrap_or(false)
}

/// Whether the subject of `signer` names the list's `SchemeTerritory` as its
/// country and one of its `SchemeOperatorName` values as its organization
/// (ETSI TS 119 602 §6.8.0).
fn signed_for(signer: &[u8], information: &Value) -> bool {
    let Ok((_, certificate)) = X509Certificate::from_der(signer) else {
        return false;
    };
    let subject = certificate.subject();
    let country = subject
        .iter_country()
        .next()
        .and_then(|attribute| attribute.as_str().ok());
    let organization: Vec<&str> = subject
        .iter_organization()
        .filter_map(|attribute| attribute.as_str().ok())
        .collect();
    let territory = information.get("SchemeTerritory").and_then(Value::as_str);
    let operators: Vec<&str> = information
        .get("SchemeOperatorName")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter_map(|name| name.get("value").and_then(Value::as_str))
        .collect();
    country.is_some()
        && country == territory
        && organization.iter().any(|name| operators.contains(name))
}
