// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A Token Status List in JWT format and one credential's status in it.
//!
//! The rules are draft-ietf-oauth-status-list-20 §4, §5.1, §7 and §8.3, the
//! revision Implementing Regulation (EU) 2026/1731 names; HAIP 1.0 §6.1 pins
//! -14, which agrees on every rule read here.

use std::io::Read as _;

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
        let bytes = inflate(&compressed).ok_or(Refusal::StatusUnavailable)?;
        match status_at(&bytes, bits, reference.idx) {
            Some(VALID) => Ok(()),
            Some(_) => Err(Refusal::Revoked),
            None => Err(Refusal::StatusUnavailable),
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

    #[test]
    fn the_compressed_example_inflates() {
        // NOTE: draft-ietf-oauth-status-list-20 §4.2, "lst" of the bits=1 example.
        let compressed = super::super::decode("eNrbuRgAAhcBXQ").expect("the example should decode");
        assert_eq!(inflate(&compressed), Some(vec![0xB9, 0xA3]));
        assert_eq!(inflate(b"not zlib"), None);
    }
}
