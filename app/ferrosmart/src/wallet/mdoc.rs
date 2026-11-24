// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A presentation of an ISO mdoc: the `DeviceResponse` a VP Token carries
//! for an `mso_mdoc` credential query (OpenID4VP 1.0 Appendix B.2.5; HAIP
//! 1.0 §5.3.1).
//!
//! The structures are defined in ISO/IEC 18013-5, whose text was not
//! available; they are read as OpenID4VP Appendix B.2, RFC 8949, RFC 9052
//! and draft-ietf-oauth-status-list-20 §6.3 describe them, and where only
//! the ISO text governs, as the EU's Apache-2.0 reference libraries and
//! multipaz both implement them (`docs/specs/mdoc-references/`). As with an
//! SD-JWT VC, [`Presentation::issuer_chain`] names the issuer's certificate
//! path and [`Presentation::verify`] checks the rest against its key.

use ciborium::value::Value;
use serde_json::Map;

use super::cose::{self, Sign1, embed, embedded, field, map};
use super::sdjwt::{CLOCK_SKEW, StatusReference};
use super::{Refusal, sha256};

/// The digest algorithm the verifier accepts for `valueDigests` (HAIP 1.0
/// §8).
const SHA_256: &str = "SHA-256";

/// The `kty` of an elliptic curve key and the `crv` of P-256 (RFC 9053
/// §7.1).
const EC2: i64 = 2;

/// The `crv` of P-256 (RFC 9053 §7.1).
const P_256: i64 = 1;

/// The tag of an RFC 3339 date-time text (RFC 8949 §3.4.1).
const DATE_TIME: u64 = 0;

/// The tag of an RFC 3339 full-date text (RFC 8943 §1).
const FULL_DATE: u64 = 1004;

/// How the request reached the wallet, which the session transcript binds
/// (OpenID4VP 1.0 Appendix B.2.6).
#[derive(Debug, Clone, Copy)]
pub enum Handover<'a> {
    /// By redirect, the answer posted to the response URI (B.2.6.1).
    Redirect {
        /// The request's `client_id`, its prefix included.
        client_id: &'a str,
        /// The request's `nonce`.
        nonce: &'a str,
        /// The SHA-256 JWK Thumbprint of the key the response is encrypted to.
        thumbprint: &'a [u8],
        /// The request's `response_uri`.
        response_uri: &'a str,
    },
    /// Over the Digital Credentials API (B.2.6.2).
    DigitalCredentials {
        /// The page's origin, with no `origin:` prefix.
        origin: &'a str,
        /// The request's `nonce`.
        nonce: &'a str,
        /// The SHA-256 JWK Thumbprint of the key the response is encrypted to.
        thumbprint: &'a [u8],
    },
}

/// Returns the `SessionTranscript` of `handover`: the device engagement
/// and the reader key null, and the OpenID4VP handover over the SHA-256 of
/// its information (OpenID4VP 1.0 Appendix B.2.6).
#[must_use]
pub fn session_transcript(handover: &Handover<'_>) -> Value {
    let text = |text: &str| Value::Text(text.to_owned());
    let (name, info) = match handover {
        Handover::Redirect {
            client_id,
            nonce,
            thumbprint,
            response_uri,
        } => (
            "OpenID4VPHandover",
            vec![
                text(client_id),
                text(nonce),
                Value::Bytes(thumbprint.to_vec()),
                text(response_uri),
            ],
        ),
        Handover::DigitalCredentials {
            origin,
            nonce,
            thumbprint,
        } => (
            "OpenID4VPDCAPIHandover",
            vec![text(origin), text(nonce), Value::Bytes(thumbprint.to_vec())],
        ),
    };
    let hash = sha256(&cose::encode(&Value::Array(info)));
    Value::Array(vec![
        Value::Null,
        Value::Null,
        Value::Array(vec![text(name), Value::Bytes(hash)]),
    ])
}

/// What the request expects of an mdoc.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    /// The document type asked for, which is also the namespace of its
    /// elements (PID Rulebook §3.1.1).
    pub doctype: &'a str,
    /// The data elements asked for, by identifier.
    pub elements: &'a [String],
    /// The session transcript of the request.
    pub transcript: &'a Value,
    /// The time, in seconds since the epoch.
    pub now: i64,
}

/// Where an MSO says its revocation status is read
/// (draft-ietf-oauth-status-list-20 §6.3).
#[derive(Clone, PartialEq, Eq)]
pub enum MsoStatus {
    /// An index in a Token Status List in CWT format.
    StatusList(StatusReference),
    /// An identifier in an identifier list in CWT format (from the
    /// reference libraries; see the module's documentation).
    IdentifierList {
        /// The MSO's identifier.
        id: Vec<u8>,
        /// The URI of the list.
        uri: String,
    },
}

impl std::fmt::Debug for MsoStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StatusList(reference) => f.debug_tuple("StatusList").field(reference).finish(),
            Self::IdentifierList { uri, .. } => f
                .debug_struct("IdentifierList")
                .field("uri", uri)
                .finish_non_exhaustive(),
        }
    }
}

/// An mdoc that verified, with the elements it discloses.
#[derive(Clone)]
pub struct Verified {
    /// The elements of the requested namespace, as JSON.
    pub claims: Map<String, serde_json::Value>,
    /// Where the revocation status is read, when the MSO names it.
    pub status: Option<MsoStatus>,
}

impl std::fmt::Debug for Verified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verified")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// One `DeviceResponse` of one document, read.
#[derive(Clone)]
pub struct Presentation {
    /// The document's `docType`.
    doctype: String,
    /// The issuer-signed items by namespace, each the tag 24 item as sent.
    namespaces: Vec<(String, Vec<Value>)>,
    /// The `issuerAuth`.
    issuer_auth: Sign1,
    /// The `deviceSigned` map, when there is one.
    device_signed: Option<Vec<(Value, Value)>>,
}

impl std::fmt::Debug for Presentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Presentation(..)")
    }
}

impl Presentation {
    /// Reads the base64url `DeviceResponse` `text`: version 1, status 0,
    /// and one document (OpenID4VP 1.0 Appendix B.2.5; HAIP 1.0 §5.3.1).
    ///
    /// # Errors
    /// Returns [`Refusal::InvalidCredential`] for text of any other shape.
    pub fn parse(text: &str) -> Result<Self, Refusal> {
        Self::read(text).ok_or(Refusal::InvalidCredential)
    }

    /// Reads `text`, none for any other shape.
    fn read(text: &str) -> Option<Self> {
        let response = cose::decode(&super::decode(text).ok()?)?;
        let response = map(&response)?;
        let version = field(response, "version")?.as_text()?;
        if !version.starts_with("1.") || cose::integer(field(response, "status")?)? != 0 {
            return None;
        }
        let [document] = field(response, "documents")?.as_array()?.as_slice() else {
            return None;
        };
        let document = map(document)?;
        let doctype = field(document, "docType")?.as_text()?.to_owned();
        let issuer_signed = map(field(document, "issuerSigned")?)?;
        let issuer_auth = Sign1::read(field(issuer_signed, "issuerAuth")?, false)?;
        let mut namespaces = Vec::new();
        if let Some(value) = field(issuer_signed, "nameSpaces") {
            for (name, items) in map(value)? {
                let items = items.as_array()?;
                if items.is_empty() {
                    return None;
                }
                namespaces.push((name.as_text()?.to_owned(), items.clone()));
            }
        }
        let device_signed = match field(document, "deviceSigned") {
            Some(value) => Some(map(value)?.to_vec()),
            None => None,
        };
        Some(Self {
            doctype,
            namespaces,
            issuer_auth,
            device_signed,
        })
    }

    /// Returns the issuer's certificate path from the `issuerAuth`'s
    /// `x5chain`, leaf first (RFC 9360 §2).
    ///
    /// # Errors
    /// Returns [`Refusal::UntrustedIssuer`] when it carries none that reads.
    pub fn issuer_chain(&self) -> Result<Vec<Vec<u8>>, Refusal> {
        self.issuer_auth.x5chain().ok_or(Refusal::UntrustedIssuer)
    }

    /// Checks the mdoc against the issuer's P-256 key `issuer`, a key a
    /// trusted certificate path carries, and `expected`: the MSO's
    /// signature, the document type, the validity, the digests, the
    /// elements and the device signature, in that order.
    ///
    /// # Errors
    /// Returns the [`Refusal`] of the first check that fails.
    pub fn verify(&self, issuer: &[u8], expected: &Expected<'_>) -> Result<Verified, Refusal> {
        if !self.issuer_auth.verifies_with(issuer, None) {
            return Err(Refusal::InvalidCredential);
        }
        let mso = self
            .issuer_auth
            .payload()
            .and_then(Mso::read)
            .ok_or(Refusal::InvalidCredential)?;
        if mso.doctype != self.doctype {
            return Err(Refusal::InvalidCredential);
        }
        if self.doctype != expected.doctype {
            return Err(Refusal::UnrequestedCredential);
        }
        mso.valid_at(expected.now)?;
        let claims = self.disclosed(&mso, expected)?;
        self.device_authenticated(&mso, expected)?;
        let status = match &mso.status {
            Some(status) => Some(status_of(status).ok_or(Refusal::StatusUnavailable)?),
            None => None,
        };
        Ok(Verified { claims, status })
    }

    /// Returns the issuer-signed elements once each matches its digest in
    /// the MSO and all are of the requested namespace and asked for.
    fn disclosed(
        &self,
        mso: &Mso,
        expected: &Expected<'_>,
    ) -> Result<Map<String, serde_json::Value>, Refusal> {
        let mut claims = Map::new();
        for (namespace, items) in &self.namespaces {
            let digests = mso
                .digests
                .iter()
                .find(|(name, _)| name == namespace)
                .map(|(_, digests)| digests)
                .ok_or(Refusal::InvalidCredential)?;
            for item in items {
                let (identifier, value) =
                    signed_item(item, digests).ok_or(Refusal::InvalidCredential)?;
                if namespace != expected.doctype || !expected.elements.contains(&identifier) {
                    return Err(Refusal::UnrequestedCredential);
                }
                let value = json(&value).ok_or(Refusal::InvalidCredential)?;
                if claims.insert(identifier, value).is_some() {
                    return Err(Refusal::InvalidCredential);
                }
            }
        }
        Ok(claims)
    }

    /// Checks the `deviceSignature` over the `DeviceAuthentication` of the
    /// request's session transcript under the MSO's device key; a document
    /// with no device signature, a `deviceMac` (HAIP 1.0 §7 names the
    /// signature), or device-signed elements nobody asked for is refused.
    fn device_authenticated(&self, mso: &Mso, expected: &Expected<'_>) -> Result<(), Refusal> {
        let device_signed = self
            .device_signed
            .as_deref()
            .ok_or(Refusal::BadHolderBinding)?;
        let namespaces = field(device_signed, "nameSpaces").ok_or(Refusal::BadHolderBinding)?;
        let elements = embedded(namespaces)
            .and_then(cose::decode)
            .ok_or(Refusal::BadHolderBinding)?;
        if !map(&elements).ok_or(Refusal::BadHolderBinding)?.is_empty() {
            return Err(Refusal::UnrequestedCredential);
        }
        let auth = field(device_signed, "deviceAuth")
            .and_then(map)
            .ok_or(Refusal::BadHolderBinding)?;
        let signature = match (field(auth, "deviceSignature"), field(auth, "deviceMac")) {
            (Some(signature), None) => Sign1::read(signature, false),
            _ => None,
        }
        .ok_or(Refusal::BadHolderBinding)?;
        let authentication = Value::Array(vec![
            Value::Text(String::from("DeviceAuthentication")),
            expected.transcript.clone(),
            Value::Text(self.doctype.clone()),
            namespaces.clone(),
        ]);
        let bytes = cose::encode(&embed(cose::encode(&authentication)));
        if signature.payload().is_none() && signature.verifies_with(&mso.device_key, Some(&bytes)) {
            Ok(())
        } else {
            Err(Refusal::BadHolderBinding)
        }
    }
}

/// Returns the identifier and value of the issuer-signed item `item` once
/// the SHA-256 of its encoding is the MSO's digest for its `digestID`.
fn signed_item(item: &Value, digests: &Digests) -> Option<(String, Value)> {
    let decoded = cose::decode(embedded(item)?)?;
    let entries = map(&decoded)?;
    let id = u64::try_from(field(entries, "digestID")?.as_integer()?).ok()?;
    field(entries, "random")?.as_bytes()?;
    let identifier = field(entries, "elementIdentifier")?.as_text()?.to_owned();
    let value = field(entries, "elementValue")?.clone();
    let (_, digest) = digests.iter().find(|(digest_id, _)| *digest_id == id)?;
    (*digest == sha256(&cose::encode(item))).then_some((identifier, value))
}

/// The digests of one namespace's elements, by `digestID`.
type Digests = Vec<(u64, Vec<u8>)>;

/// The Mobile Security Object, read.
struct Mso {
    /// The document type.
    doctype: String,
    /// The digests by namespace and `digestID`.
    digests: Vec<(String, Digests)>,
    /// The device key's uncompressed P-256 point.
    device_key: Vec<u8>,
    /// When it was signed, in seconds since the epoch.
    signed: i64,
    /// When it becomes valid.
    valid_from: i64,
    /// When it stops being valid.
    valid_until: i64,
    /// Its `status`, when it carries one.
    status: Option<Value>,
}

impl Mso {
    /// Reads the `issuerAuth` payload `payload`, the tag 24 item of the MSO.
    fn read(payload: &[u8]) -> Option<Self> {
        let mso = cose::decode(embedded(&cose::decode(payload)?)?)?;
        let mso = map(&mso)?;
        field(mso, "version")?.as_text()?;
        if field(mso, "digestAlgorithm")?.as_text()? != SHA_256 {
            return None;
        }
        let mut digests = Vec::new();
        for (namespace, ids) in map(field(mso, "valueDigests")?)? {
            let ids = map(ids)?
                .iter()
                .map(|(id, digest)| {
                    Some((
                        u64::try_from(id.as_integer()?).ok()?,
                        digest.as_bytes()?.clone(),
                    ))
                })
                .collect::<Option<Vec<_>>>()?;
            digests.push((namespace.as_text()?.to_owned(), ids));
        }
        let key_info = map(field(mso, "deviceKeyInfo")?)?;
        let device_key = p256_key(field(key_info, "deviceKey")?)?;
        let validity = map(field(mso, "validityInfo")?)?;
        let instant = |name: &str| date_time(field(validity, name)?);
        Some(Self {
            doctype: field(mso, "docType")?.as_text()?.to_owned(),
            digests,
            device_key,
            signed: instant("signed")?,
            valid_from: instant("validFrom")?,
            valid_until: instant("validUntil")?,
            status: field(mso, "status").cloned(),
        })
        .filter(|mso| mso.valid_from <= mso.valid_until)
    }

    /// Checks `signed`, `validFrom` and `validUntil` at `now`, with
    /// [`CLOCK_SKEW`] for the issuer's clock.
    fn valid_at(&self, now: i64) -> Result<(), Refusal> {
        if self.signed > now + CLOCK_SKEW || self.valid_from > now + CLOCK_SKEW {
            return Err(Refusal::Expired);
        }
        if now >= self.valid_until {
            return Err(Refusal::Expired);
        }
        Ok(())
    }
}

/// Returns the status mechanism the MSO's `status` map names
/// (draft-ietf-oauth-status-list-20 §6.3).
fn status_of(status: &Value) -> Option<MsoStatus> {
    let status = map(status)?;
    if let Some(list) = field(status, "status_list") {
        let list = map(list)?;
        return Some(MsoStatus::StatusList(StatusReference {
            uri: field(list, "uri")?.as_text()?.to_owned(),
            idx: u64::try_from(field(list, "idx")?.as_integer()?).ok()?,
        }));
    }
    let list = map(field(status, "identifier_list")?)?;
    Some(MsoStatus::IdentifierList {
        id: field(list, "id")?.as_bytes()?.clone(),
        uri: field(list, "uri")?.as_text()?.to_owned(),
    })
}

/// Returns the uncompressed point of the `COSE_Key` `key`, an EC2 key on
/// P-256 with both coordinates (RFC 9053 §7.1.1).
fn p256_key(key: &Value) -> Option<Vec<u8>> {
    let key = map(key)?;
    let coordinate = |label: i64| {
        cose::label(key, label)?
            .as_bytes()
            .filter(|bytes| bytes.len() == 32)
    };
    if cose::label(key, 1).and_then(cose::integer) != Some(EC2)
        || cose::label(key, -1).and_then(cose::integer) != Some(P_256)
    {
        return None;
    }
    let mut point = vec![0x04];
    point.extend_from_slice(coordinate(-2)?);
    point.extend_from_slice(coordinate(-3)?);
    Some(point)
}

/// Returns the seconds since the epoch of the tagged date-time `value`.
fn date_time(value: &Value) -> Option<i64> {
    match value {
        Value::Tag(DATE_TIME, text) => text
            .as_text()?
            .parse::<jiff::Timestamp>()
            .ok()
            .map(jiff::Timestamp::as_second),
        _ => None,
    }
}

/// Returns the JSON of the element value `value`: a date as its text, a
/// byte string as base64url, a map of text keys as an object.
fn json(value: &Value) -> Option<serde_json::Value> {
    Some(match value {
        Value::Null => serde_json::Value::Null,
        Value::Bool(flag) => serde_json::Value::Bool(*flag),
        Value::Integer(number) => i64::try_from(*number)
            .map(serde_json::Value::from)
            .or_else(|_| u64::try_from(*number).map(serde_json::Value::from))
            .ok()?,
        Value::Float(number) => serde_json::Number::from_f64(*number)?.into(),
        Value::Text(text) => serde_json::Value::String(text.clone()),
        Value::Bytes(bytes) => serde_json::Value::String(super::encode(bytes)),
        Value::Tag(DATE_TIME | FULL_DATE, text) => {
            serde_json::Value::String(text.as_text()?.to_owned())
        }
        Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(json).collect::<Option<_>>()?)
        }
        Value::Map(_) => {
            let mut object = Map::new();
            for (key, item) in map(value)? {
                object.insert(key.as_text()?.to_owned(), json(item)?);
            }
            serde_json::Value::Object(object)
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(text.get(at..at + 2).expect("a pair"), 16).expect("hex"))
            .collect()
    }

    /// The JWK Thumbprint of OpenID4VP 1.0 Appendix B.2.6's example key.
    const THUMBPRINT: &str = "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047";

    /// The nonce of OpenID4VP 1.0 Appendix B.2.6's examples.
    const NONCE: &str = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA";

    #[test]
    fn the_redirect_transcript_is_the_openid4vp_example() {
        // NOTE: OpenID4VP 1.0 Appendix B.2.6.1, the example SessionTranscript.
        let thumbprint = hex(THUMBPRINT);
        let transcript = session_transcript(&Handover::Redirect {
            client_id: "x509_san_dns:example.com",
            nonce: NONCE,
            thumbprint: &thumbprint,
            response_uri: "https://example.com/response",
        });
        assert_eq!(
            hex(
                "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"
            ),
            cose::encode(&transcript)
        );
    }

    #[test]
    fn the_digital_credentials_transcript_is_the_openid4vp_example() {
        // NOTE: OpenID4VP 1.0 Appendix B.2.6.2, the example SessionTranscript.
        let thumbprint = hex(THUMBPRINT);
        let transcript = session_transcript(&Handover::DigitalCredentials {
            origin: "https://example.com",
            nonce: NONCE,
            thumbprint: &thumbprint,
        });
        assert_eq!(
            hex(
                "83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a"
            ),
            cose::encode(&transcript)
        );
    }

    #[test]
    fn a_status_names_a_status_list_or_an_identifier_list() {
        let text = |text: &str| Value::Text(text.to_owned());
        let list = Value::Map(vec![(
            text("status_list"),
            Value::Map(vec![
                (text("idx"), Value::Integer(7.into())),
                (text("uri"), text("https://status.example/1")),
            ]),
        )]);
        assert_eq!(
            Some(MsoStatus::StatusList(StatusReference {
                uri: String::from("https://status.example/1"),
                idx: 7
            })),
            status_of(&list)
        );
        let identifiers = Value::Map(vec![(
            text("identifier_list"),
            Value::Map(vec![
                (text("id"), Value::Bytes(vec![1, 2])),
                (text("uri"), text("https://status.example/2")),
            ]),
        )]);
        assert!(matches!(
            status_of(&identifiers),
            Some(MsoStatus::IdentifierList { .. })
        ));
        assert_eq!(
            None,
            status_of(&Value::Map(vec![(text("other"), Value::Null)]))
        );
    }

    #[test]
    fn an_element_value_reads_as_json() {
        let date = Value::Tag(FULL_DATE, Box::new(Value::Text(String::from("1980-04-02"))));
        assert_eq!(Some(serde_json::json!("1980-04-02")), json(&date));
        assert_eq!(
            Some(serde_json::json!("AQI")),
            json(&Value::Bytes(vec![1, 2]))
        );
        let place = Value::Map(vec![(
            Value::Text(String::from("country")),
            Value::Text(String::from("NL")),
        )]);
        assert_eq!(Some(serde_json::json!({"country": "NL"})), json(&place));
        let keyed_by_number = Value::Map(vec![(Value::Integer(1.into()), Value::Null)]);
        assert_eq!(None, json(&keyed_by_number));
    }

    #[test]
    fn a_device_key_on_another_curve_or_compressed_is_not_read() {
        let int = |number: i64| Value::Integer(number.into());
        let key = |crv: i64, y: Value| {
            Value::Map(vec![
                (int(1), int(EC2)),
                (int(-1), int(crv)),
                (int(-2), Value::Bytes(vec![3; 32])),
                (int(-3), y),
            ])
        };
        assert_eq!(
            Some(65),
            p256_key(&key(P_256, Value::Bytes(vec![4; 32]))).map(|point| point.len())
        );
        assert_eq!(None, p256_key(&key(2, Value::Bytes(vec![4; 32]))));
        assert_eq!(None, p256_key(&key(P_256, Value::Bool(true))));
    }

    #[test]
    fn a_device_response_of_another_shape_does_not_read() {
        let text = |text: &str| Value::Text(text.to_owned());
        let response = |status: i64, documents: Vec<Value>| {
            super::super::encode(&cose::encode(&Value::Map(vec![
                (text("version"), text("1.0")),
                (text("documents"), Value::Array(documents)),
                (text("status"), Value::Integer(status.into())),
            ])))
        };
        assert!(Presentation::parse(&response(10, Vec::new())).is_err());
        assert!(
            Presentation::parse(&response(0, Vec::new())).is_err(),
            "no document"
        );
        assert!(Presentation::parse("not base64url!").is_err());
    }
}
