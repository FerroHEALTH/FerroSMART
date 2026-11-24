// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! CBOR (RFC 8949) as the mdoc verifier reads it, and the `COSE_Sign1`
//! signature (RFC 9052 §4.2, §4.4) under ECDSA P-256 with SHA-256 (RFC 9053
//! §2.1; RFC 9864 §2.1; HAIP 1.0 §7), with its `x5chain` (RFC 9360 §2).

use ciborium::value::Value;

/// The `alg` header parameter (RFC 9052 §3.1).
const ALG: i64 = 1;

/// The `typ` header parameter (RFC 9596 §2).
pub(crate) const TYP: i64 = 16;

/// The `x5chain` header parameter (RFC 9360 §2).
const X5CHAIN: i64 = 33;

/// ECDSA with SHA-256 (RFC 9053 §2.1), and the fully specified ECDSA with
/// P-256 and SHA-256 (RFC 9864 §2.1): the two names of HAIP 1.0 §7's suite.
const P256_ALGORITHMS: [i64; 2] = [-7, -9];

/// The tag of a `COSE_Sign1_Tagged` (RFC 9052 §2).
pub(crate) const SIGN1_TAG: u64 = 18;

/// The tag of an encoded CBOR data item (RFC 8949 §3.4.5.1).
pub(crate) const ENCODED_CBOR: u64 = 24;

/// Returns the one CBOR data item `bytes` encode, none for bytes of
/// another shape or with bytes left over.
pub(crate) fn decode(bytes: &[u8]) -> Option<Value> {
    let mut reader = bytes;
    let value = ciborium::de::from_reader(&mut reader).ok()?;
    reader.is_empty().then_some(value)
}

/// Returns the encoding of `value`, its lengths as short as possible (RFC
/// 8949 §4.2.1).
#[expect(
    clippy::expect_used,
    reason = "a CBOR value always encodes, and writing to a vector cannot fail"
)]
pub(crate) fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).expect("a CBOR value should encode");
    bytes
}

/// Returns the entries of the map `value` once no key repeats (RFC 8949
/// §5.6), none for any other item.
pub(crate) fn map(value: &Value) -> Option<&[(Value, Value)]> {
    let Value::Map(entries) = value else {
        return None;
    };
    let repeated = entries.iter().enumerate().any(|(index, (key, _))| {
        entries
            .get(index + 1..)
            .is_some_and(|rest| rest.iter().any(|(other, _)| other == key))
    });
    (!repeated).then_some(entries.as_slice())
}

/// Returns the value of the text key `key` in the map `entries`.
pub(crate) fn field<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(name, _)| name.as_text() == Some(key))
        .map(|(_, value)| value)
}

/// Returns the value of the integer key `key` in the map `entries`.
pub(crate) fn label(entries: &[(Value, Value)], key: i64) -> Option<&Value> {
    entries
        .iter()
        .find(|(name, _)| integer(name) == Some(key))
        .map(|(_, value)| value)
}

/// Returns the integer `value` holds.
pub(crate) fn integer(value: &Value) -> Option<i64> {
    value
        .as_integer()
        .and_then(|number| i64::try_from(number).ok())
}

/// Returns the bytes the encoded CBOR data item `value` wraps: tag 24 over
/// a byte string (RFC 8949 §3.4.5.1).
pub(crate) fn embedded(value: &Value) -> Option<&[u8]> {
    match value {
        Value::Tag(ENCODED_CBOR, inner) => inner.as_bytes().map(Vec::as_slice),
        _ => None,
    }
}

/// Returns `bytes` as an encoded CBOR data item, tag 24 over a byte string.
pub(crate) fn embed(bytes: Vec<u8>) -> Value {
    Value::Tag(ENCODED_CBOR, Box::new(Value::Bytes(bytes)))
}

/// One `COSE_Sign1`, read.
#[derive(Clone)]
pub(crate) struct Sign1 {
    /// The protected header as signed.
    protected_bytes: Vec<u8>,
    /// The protected header, read.
    protected: Vec<(Value, Value)>,
    /// The unprotected header.
    unprotected: Vec<(Value, Value)>,
    /// The payload, none when it is detached.
    payload: Option<Vec<u8>>,
    /// The signature.
    signature: Vec<u8>,
}

impl std::fmt::Debug for Sign1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sign1(..)")
    }
}

impl Sign1 {
    /// Reads the `COSE_Sign1` structure `value`, tagged when `tagged`,
    /// whose two headers name no label twice (RFC 9052 §3, §4.2).
    pub(crate) fn read(value: &Value, tagged: bool) -> Option<Self> {
        let array = match (value, tagged) {
            (Value::Tag(SIGN1_TAG, inner), true) => inner.as_array()?,
            (Value::Array(array), false) => array,
            _ => return None,
        };
        let [protected, unprotected, payload, signature] = array.as_slice() else {
            return None;
        };
        let protected_bytes = protected.as_bytes()?.clone();
        // NOTE: RFC 9052 §3, an empty protected header is the zero-length byte string.
        let protected = if protected_bytes.is_empty() {
            Vec::new()
        } else {
            map(&decode(&protected_bytes)?)?.to_vec()
        };
        let unprotected = map(unprotected)?.to_vec();
        if protected
            .iter()
            .any(|(key, _)| unprotected.iter().any(|(other, _)| other == key))
        {
            return None;
        }
        let payload = match payload {
            Value::Bytes(bytes) => Some(bytes.clone()),
            Value::Null => None,
            _ => return None,
        };
        Some(Self {
            protected_bytes,
            protected,
            unprotected,
            payload,
            signature: signature.as_bytes()?.clone(),
        })
    }

    /// Returns the header parameter `key`, protected or not.
    pub(crate) fn header(&self, key: i64) -> Option<&Value> {
        label(&self.protected, key).or_else(|| label(&self.unprotected, key))
    }

    /// Returns the payload, none when it is detached.
    pub(crate) fn payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }

    /// Returns the DER certificates of the `x5chain` header, leaf first: one
    /// byte string, or an array of more than one (RFC 9360 §2).
    pub(crate) fn x5chain(&self) -> Option<Vec<Vec<u8>>> {
        match self.header(X5CHAIN)? {
            Value::Bytes(certificate) => Some(vec![certificate.clone()]),
            Value::Array(chain) if chain.len() > 1 => chain
                .iter()
                .map(|certificate| certificate.as_bytes().cloned())
                .collect(),
            _ => None,
        }
    }

    /// Whether the signature verifies under the P-256 point `point`, with
    /// `alg` protected and one of the suite's two names, over the payload
    /// or, when it is detached, over `detached` (RFC 9052 §4.4).
    pub(crate) fn verifies_with(&self, point: &[u8], detached: Option<&[u8]>) -> bool {
        let alg = label(&self.protected, ALG).and_then(integer);
        if !alg.is_some_and(|alg| P256_ALGORITHMS.contains(&alg)) {
            return false;
        }
        let payload = match (&self.payload, detached) {
            (Some(payload), None) => payload.clone(),
            (None, Some(detached)) => detached.to_vec(),
            _ => return false,
        };
        let structure = Value::Array(vec![
            Value::Text(String::from("Signature1")),
            Value::Bytes(self.protected_bytes.clone()),
            Value::Bytes(Vec::new()),
            Value::Bytes(payload),
        ]);
        aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED,
            point,
        )
        .verify(&encode(&structure), &self.signature)
        .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
    use ciborium::value::Integer;

    fn int(number: i64) -> Value {
        Value::Integer(Integer::from(number))
    }

    fn key() -> EcdsaKeyPair {
        EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).expect("a key")
    }

    fn signed(key: &EcdsaKeyPair, alg: i64, payload: Option<&[u8]>, detached: &[u8]) -> Value {
        let protected = encode(&Value::Map(vec![(int(ALG), int(alg))]));
        let body = payload.unwrap_or(detached).to_vec();
        let structure = Value::Array(vec![
            Value::Text(String::from("Signature1")),
            Value::Bytes(protected.clone()),
            Value::Bytes(Vec::new()),
            Value::Bytes(body),
        ]);
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let signature = key.sign(&rng, &encode(&structure)).expect("signs");
        Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(vec![(int(X5CHAIN), Value::Bytes(vec![1, 2, 3]))]),
            payload.map_or(Value::Null, |payload| Value::Bytes(payload.to_vec())),
            Value::Bytes(signature.as_ref().to_vec()),
        ])
    }

    #[test]
    fn a_sign1_verifies_under_either_name_of_the_p256_suite() {
        let key = key();
        let point = key.public_key().as_ref().to_vec();
        for alg in P256_ALGORITHMS {
            let value = signed(&key, alg, Some(b"payload"), b"");
            let sign1 = Sign1::read(&value, false).expect("reads");
            assert!(sign1.verifies_with(&point, None), "alg {alg}");
            assert_eq!(Some(vec![vec![1, 2, 3]]), sign1.x5chain());
        }
    }

    #[test]
    fn a_detached_payload_is_the_one_signed() {
        let key = key();
        let point = key.public_key().as_ref().to_vec();
        let value = signed(&key, -7, None, b"detached");
        let sign1 = Sign1::read(&value, false).expect("reads");
        assert!(sign1.verifies_with(&point, Some(b"detached")));
        assert!(!sign1.verifies_with(&point, Some(b"other")));
        assert!(!sign1.verifies_with(&point, None));
    }

    #[test]
    fn another_algorithm_or_key_does_not_verify() {
        let key = key();
        let value = signed(&key, -35, Some(b"payload"), b"");
        let sign1 = Sign1::read(&value, false).expect("reads");
        assert!(!sign1.verifies_with(key.public_key().as_ref(), None));
        let value = signed(&key, -7, Some(b"payload"), b"");
        let sign1 = Sign1::read(&value, false).expect("reads");
        assert!(!sign1.verifies_with(self::key().public_key().as_ref(), None));
    }

    #[test]
    fn a_tag_is_read_only_where_it_is_asked_for() {
        let value = signed(&key(), -7, Some(b"payload"), b"");
        let tagged = Value::Tag(SIGN1_TAG, Box::new(value.clone()));
        assert!(Sign1::read(&tagged, true).is_some());
        assert!(Sign1::read(&value, true).is_none());
        assert!(Sign1::read(&tagged, false).is_none());
    }

    #[test]
    fn a_map_with_a_repeated_key_or_trailing_bytes_does_not_read() {
        let repeated = Value::Map(vec![(int(1), int(2)), (int(1), int(3))]);
        assert!(map(&repeated).is_none());
        let mut bytes = encode(&int(1));
        assert_eq!(Some(int(1)), decode(&bytes));
        bytes.push(0);
        assert_eq!(None, decode(&bytes));
    }
}
