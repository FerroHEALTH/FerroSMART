// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A Token Status List in JWT or CWT format and one credential's status in
//! it, and the identifier list an mdoc's MSO may name instead.
//!
//! The rules are draft-ietf-oauth-status-list-20 §4, §5.1, §5.2, §7 and
//! §8.3, the revision Implementing Regulation (EU) 2026/1731 names; HAIP 1.0
//! §6.1 pins -14, which agrees on every rule read here. The identifier list
//! is defined in ISO/IEC 18013-5, whose text was not available: it is read
//! as the reference libraries build it (`docs/specs/mdoc-references/`).

use std::io::Read as _;

use ciborium::value::Value;

use super::cose::{self, Sign1, field, label, map};
use super::sdjwt::StatusReference;
use super::{Jws, Refusal};

/// The largest status list FerroSMART decompresses, in bytes (no
/// specification sets one: our own design, room for 16 million credentials
/// at 8 bits each).
const MAX_LIST_BYTES: u64 = 16 * 1024 * 1024;

/// The status value of a valid credential (draft-ietf-oauth-status-list-20
/// §7.1).
const VALID: u8 = 0x00;

/// A Status List Token, read.
#[derive(Debug, Clone)]
pub struct StatusToken<'a> {
    /// The token.
    jws: Jws<'a>,
}

impl<'a> StatusToken<'a> {
    /// Reads the compact Status List Token `text`.
    ///
    /// # Errors
    /// Returns [`Refusal::StatusUnavailable`] for text of another shape or a
    /// `typ` other than `statuslist+jwt` (§5.1).
    pub fn parse(text: &'a str) -> Result<Self, Refusal> {
        let jws = Jws::parse(text.trim()).ok_or(Refusal::StatusUnavailable)?;
        if jws.header_text("typ") != Some("statuslist+jwt") {
            return Err(Refusal::StatusUnavailable);
        }
        Ok(Self { jws })
    }

    /// Returns the `x5c` chain of the token's signer, DER, leaf first (HAIP
    /// 1.0 §6.1).
    ///
    /// # Errors
    /// Returns [`Refusal::StatusUnavailable`] when the header carries none
    /// that reads.
    pub fn chain(&self) -> Result<Vec<Vec<u8>>, Refusal> {
        use base64::Engine as _;
        let entries = self
            .jws
            .header
            .get("x5c")
            .and_then(serde_json::Value::as_array)
            .filter(|entries| !entries.is_empty())
            .ok_or(Refusal::StatusUnavailable)?;
        entries
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .and_then(|text| base64::engine::general_purpose::STANDARD.decode(text).ok())
                    .ok_or(Refusal::StatusUnavailable)
            })
            .collect()
    }

    /// Checks the token against its signer's P-256 key `signer` and returns
    /// the status of `reference` in it at `now` (§8.3 steps 3 to 7): none
    /// once valid, [`Refusal::Revoked`] for any other value.
    ///
    /// # Errors
    /// Returns [`Refusal::StatusUnavailable`] when the token does not verify,
    /// names another list, is expired, or does not hold the index, and
    /// [`Refusal::Revoked`] for a status other than valid.
    pub fn check(
        &self,
        signer: &[u8],
        reference: &StatusReference,
        now: i64,
    ) -> Result<(), Refusal> {
        let jws = &self.jws;
        if !jws.verifies_with(signer) || jws.seconds("iat").is_none() {
            return Err(Refusal::StatusUnavailable);
        }
        if jws.text("sub") != Some(reference.uri.as_str()) {
            return Err(Refusal::StatusUnavailable);
        }
        if jws.seconds("exp").is_some_and(|exp| now >= exp) {
            return Err(Refusal::StatusUnavailable);
        }
        let list = jws
            .claims
            .get("status_list")
            .ok_or(Refusal::StatusUnavailable)?;
        let bits = list
            .get("bits")
            .and_then(serde_json::Value::as_u64)
            .filter(|bits| matches!(bits, 1 | 2 | 4 | 8))
            .ok_or(Refusal::StatusUnavailable)?;
        let compressed = list
            .get("lst")
            .and_then(serde_json::Value::as_str)
            .and_then(|text| super::decode(text).ok())
            .ok_or(Refusal::StatusUnavailable)?;
        status_in(&compressed, bits, reference.idx)
    }
}

/// Returns `Ok` when index `index` of the compressed list `compressed`, of
/// `bits` bits per credential, is valid (§8.3 steps 5 to 7).
fn status_in(compressed: &[u8], bits: u64, index: u64) -> Result<(), Refusal> {
    let bytes = inflate(compressed).ok_or(Refusal::StatusUnavailable)?;
    match status_at(&bytes, bits, index) {
        Some(VALID) => Ok(()),
        Some(_) => Err(Refusal::Revoked),
        None => Err(Refusal::StatusUnavailable),
    }
}

/// The CWT claim keys a revocation list reads (RFC 8392 §3.1.2, §3.1.4,
/// §3.1.6; draft-ietf-oauth-status-list-20 §5.2).
const SUB: i64 = 2;

/// The `exp` claim.
const EXP: i64 = 4;

/// The `iat` claim.
const IAT: i64 = 6;

/// The `status_list` claim (§5.2).
const STATUS_LIST: i64 = 65533;

/// The `IdentifierList` claim, as the reference libraries key it.
const IDENTIFIER_LIST: i64 = 65530;

/// The CoAP Content-Format of a Status List Token in CWT format, which its
/// `typ` may carry instead of the media type (§5.2, §14.8).
const STATUS_LIST_COAP: i64 = 279;

/// The kind of a revocation list in CWT format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CwtKind {
    /// A Token Status List (§5.2).
    StatusList,
    /// An identifier list.
    IdentifierList,
}

impl CwtKind {
    /// Returns the media type the list is fetched and typed as.
    #[must_use]
    pub const fn media_type(self) -> &'static str {
        match self {
            Self::StatusList => "application/statuslist+cwt",
            Self::IdentifierList => "application/identifierlist+cwt",
        }
    }
}

/// A revocation list in CWT format, read.
#[derive(Debug, Clone)]
pub struct CwtList {
    /// Its kind.
    kind: CwtKind,
    /// The `COSE_Sign1_Tagged`.
    sign1: Sign1,
    /// The claims set.
    claims: Vec<(Value, Value)>,
}

impl CwtList {
    /// Reads the CWT `bytes` of `kind`: a tagged `COSE_Sign1` with no CWT
    /// tag, whose `typ` is the kind's (§5.2).
    ///
    /// # Errors
    /// Returns [`Refusal::StatusUnavailable`] for bytes of another shape.
    pub fn parse(bytes: &[u8], kind: CwtKind) -> Result<Self, Refusal> {
        Self::read(bytes, kind).ok_or(Refusal::StatusUnavailable)
    }

    /// Reads `bytes`, none for any other shape.
    fn read(bytes: &[u8], kind: CwtKind) -> Option<Self> {
        let sign1 = Sign1::read(&cose::decode(bytes)?, true)?;
        let typed = match sign1.header(cose::TYP)? {
            Value::Text(media_type) => media_type == kind.media_type(),
            other => kind == CwtKind::StatusList && cose::integer(other) == Some(STATUS_LIST_COAP),
        };
        let claims = map(&cose::decode(sign1.payload()?)?)?.to_vec();
        typed.then_some(Self {
            kind,
            sign1,
            claims,
        })
    }

    /// Returns the `x5chain` of the list's signer, DER, leaf first.
    ///
    /// # Errors
    /// Returns [`Refusal::StatusUnavailable`] when it carries none that
    /// reads.
    pub fn chain(&self) -> Result<Vec<Vec<u8>>, Refusal> {
        self.sign1.x5chain().ok_or(Refusal::StatusUnavailable)
    }

    /// Checks the list against its signer's P-256 key `signer`: the
    /// signature, an `iat`, `sub` naming `uri`, and an `exp` ahead of
    /// `now` when there is one (§8.3 steps 3 and 4).
    fn checked(&self, signer: &[u8], uri: &str, now: i64) -> Result<(), Refusal> {
        let number = |key: i64| label(&self.claims, key).and_then(cose::integer);
        let holds = self.sign1.verifies_with(signer, None)
            && number(IAT).is_some()
            && label(&self.claims, SUB).and_then(Value::as_text) == Some(uri)
            && label(&self.claims, EXP).is_none_or(|_| number(EXP).is_some_and(|exp| now < exp));
        if holds {
            Ok(())
        } else {
            Err(Refusal::StatusUnavailable)
        }
    }

    /// Checks the Token Status List against `signer` and returns the status
    /// of `reference` in it at `now`.
    ///
    /// # Errors
    /// Returns [`Refusal::StatusUnavailable`] when the list does not verify,
    /// names another list, is expired, or does not hold the index, and
    /// [`Refusal::Revoked`] for a status other than valid.
    pub fn status(
        &self,
        signer: &[u8],
        reference: &StatusReference,
        now: i64,
    ) -> Result<(), Refusal> {
        if self.kind != CwtKind::StatusList {
            return Err(Refusal::StatusUnavailable);
        }
        self.checked(signer, &reference.uri, now)?;
        let list = label(&self.claims, STATUS_LIST)
            .and_then(map)
            .ok_or(Refusal::StatusUnavailable)?;
        let bits = field(list, "bits")
            .and_then(cose::integer)
            .and_then(|bits| u64::try_from(bits).ok())
            .filter(|bits| matches!(bits, 1 | 2 | 4 | 8))
            .ok_or(Refusal::StatusUnavailable)?;
        let compressed = field(list, "lst")
            .and_then(Value::as_bytes)
            .ok_or(Refusal::StatusUnavailable)?;
        status_in(compressed, bits, reference.idx)
    }

    /// Checks the identifier list at `uri` against `signer` at `now`: the
    /// MSO of identifier `id` is revoked when the list's `identifiers` map
    /// holds it.
    ///
    /// # Errors
    /// Returns [`Refusal::StatusUnavailable`] when the list does not verify,
    /// names another list or is expired, and [`Refusal::Revoked`] when it
    /// holds `id`.
    pub fn identifier(&self, signer: &[u8], uri: &str, id: &[u8], now: i64) -> Result<(), Refusal> {
        if self.kind != CwtKind::IdentifierList {
            return Err(Refusal::StatusUnavailable);
        }
        self.checked(signer, uri, now)?;
        let identifiers = label(&self.claims, IDENTIFIER_LIST)
            .and_then(map)
            .and_then(|list| field(list, "identifiers"))
            .and_then(map)
            .ok_or(Refusal::StatusUnavailable)?;
        if identifiers
            .iter()
            .any(|(listed, _)| listed.as_bytes().is_some_and(|listed| listed == id))
        {
            Err(Refusal::Revoked)
        } else {
            Ok(())
        }
    }
}

/// Returns the ZLIB-decompressed `compressed`, none when it does not inflate
/// or grows past [`MAX_LIST_BYTES`] (§8.3 step 5).
fn inflate(compressed: &[u8]) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    flate2::read::ZlibDecoder::new(compressed)
        .take(MAX_LIST_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (u64::try_from(bytes.len()).ok()? <= MAX_LIST_BYTES).then_some(bytes)
}

/// Returns the status of `index` in the list `bytes` of `bits` bits per
/// credential, packed from the least significant bit (§4.1 step 3); none
/// past the end.
fn status_at(bytes: &[u8], bits: u64, index: u64) -> Option<u8> {
    let per_byte = 8_u64.checked_div(bits)?;
    let byte = bytes.get(usize::try_from(index.checked_div(per_byte)?).ok()?)?;
    let shift = index.checked_rem(per_byte)? * bits;
    let mask = u8::try_from((1_u16 << bits) - 1).ok()?;
    Some((byte >> shift) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_draft_example_list_reads_as_published() {
        // NOTE: draft-ietf-oauth-status-list-20 §4.1, the example with bits=1.
        let bytes = [0xB9, 0xA3];
        let expected = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
        for (index, status) in expected.iter().enumerate() {
            assert_eq!(
                status_at(&bytes, 1, u64::try_from(index).expect("a small index")),
                Some(*status)
            );
        }
        assert_eq!(status_at(&bytes, 1, 16), None);
    }

    #[test]
    fn two_bits_per_credential_read_by_their_pairs() {
        // NOTE: draft-ietf-oauth-status-list-20 §4.1, the example with bits=2.
        let bytes = [0xC9, 0x44, 0xF9];
        let expected = [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3];
        for (index, status) in expected.iter().enumerate() {
            assert_eq!(
                status_at(&bytes, 2, u64::try_from(index).expect("a small index")),
                Some(*status)
            );
        }
    }

    /// The Status List Token in CWT format of draft-ietf-oauth-status-list-20 §5.2.
    const CWT_EXAMPLE: &str = "d2845820a2012610781a6170706c69636174696f6e2f7374617475736c6973742b637774a1044231325850a502782168747470733a2f2f6578616d706c652e636f6d2f7374617475736c697374732f31061a648c5bea041a8898dfea19fffe19a8c019fffda2646269747301636c73744a78dadbb918000217015d584093fa4d01032b18c35e2fe1101b77fd6cc9440022caa4694450c4e4e9feab4e99d1fa6d9772ce2bf3a12e0323ded7c982c5e101a5e67f0cbc1e2b6f57ce99c279";

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(text.get(at..at + 2).expect("a pair"), 16).expect("hex"))
            .collect()
    }

    #[test]
    fn the_draft_cwt_example_reads_as_a_status_list_of_its_uri() {
        let list = CwtList::parse(&hex(CWT_EXAMPLE), CwtKind::StatusList)
            .expect("the example should read");
        assert_eq!(
            Some("https://example.com/statuslists/1"),
            label(&list.claims, SUB).and_then(Value::as_text)
        );
        let compressed = label(&list.claims, STATUS_LIST)
            .and_then(map)
            .and_then(|list| field(list, "lst"))
            .and_then(Value::as_bytes)
            .expect("a list");
        assert_eq!(Err(Refusal::Revoked), status_in(compressed, 1, 0));
        assert_eq!(Ok(()), status_in(compressed, 1, 1));
        assert!(
            CwtList::parse(&hex(CWT_EXAMPLE), CwtKind::IdentifierList).is_err(),
            "the typ names a status list"
        );
    }

    #[test]
    fn a_cwt_list_under_another_key_is_unavailable() {
        let list = CwtList::parse(&hex(CWT_EXAMPLE), CwtKind::StatusList)
            .expect("the example should read");
        let key = aws_lc_rs::signature::EcdsaKeyPair::generate(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        )
        .expect("a key");
        let reference = StatusReference {
            uri: String::from("https://example.com/statuslists/1"),
            idx: 1,
        };
        let point = aws_lc_rs::signature::KeyPair::public_key(&key)
            .as_ref()
            .to_vec();
        assert_eq!(
            Err(Refusal::StatusUnavailable),
            list.status(&point, &reference, 1_686_920_000)
        );
    }

    #[test]
    fn the_compressed_example_inflates() {
        // NOTE: draft-ietf-oauth-status-list-20 §4.2, "lst" of the bits=1 example.
        let compressed = super::super::decode("eNrbuRgAAhcBXQ").expect("the example should decode");
        assert_eq!(inflate(&compressed), Some(vec![0xB9, 0xA3]));
        assert_eq!(inflate(b"not zlib"), None);
    }
}
