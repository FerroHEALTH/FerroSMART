// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The encrypted authorization response.
//!
//! It is an unsigned JWE under ECDH-ES on P-256 to the request's own
//! ephemeral key, its content under A128GCM or A256GCM (OpenID4VP 1.0 §8.3,
//! HAIP 1.0 §5, RFC 7516, RFC 7518 §4.6, §5.3).

use aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, ECDH_P256, PrivateKey, UnparsedPublicKey};
use aws_lc_rs::encoding::{AsBigEndian, EcPrivateKeyBin};

use super::{decode, encode, json_object};

/// The content encryption algorithms the verifier lists, both of which
/// HAIP 1.0 §5 has it support.
pub const ENC_VALUES: [&str; 2] = ["A128GCM", "A256GCM"];

/// The key agreement algorithm (HAIP 1.0 §5).
pub const ALG: &str = "ECDH-ES";

/// Why a response cannot be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JweError {
    /// The key could not be made, stored or read back.
    #[error("the ephemeral key cannot be used")]
    Key,
    /// The text is not a compact JWE of five parts with a JSON header.
    #[error("the response is not a compact JWE")]
    Malformed,
    /// The header names an algorithm, an encryption or a key the request
    /// did not offer.
    #[error("the response is not encrypted as the request asked")]
    Unexpected,
    /// The content does not decrypt under the agreed key.
    #[error("the response does not decrypt")]
    Decrypt,
}

/// The ephemeral key of one request, which the wallet encrypts its response
/// to; never rendered by `Debug`.
pub struct EphemeralKey {
    /// The private key.
    private: PrivateKey,
}

impl std::fmt::Debug for EphemeralKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EphemeralKey(..)")
    }
}

impl EphemeralKey {
    /// Generates a key for a new request.
    ///
    /// # Errors
    /// Returns [`JweError::Key`] when the generator fails.
    pub fn generate() -> Result<Self, JweError> {
        let private = PrivateKey::generate(&ECDH_P256).map_err(|_failed| JweError::Key)?;
        Ok(Self { private })
    }

    /// Returns the key as the request keeps it: its private scalar,
    /// base64url.
    ///
    /// # Errors
    /// Returns [`JweError::Key`] when the scalar cannot be read out.
    pub fn stored(&self) -> Result<String, JweError> {
        let scalar: EcPrivateKeyBin<'static> = self
            .private
            .as_be_bytes()
            .map_err(|_failed| JweError::Key)?;
        Ok(encode(scalar.as_ref()))
    }

    /// Reads back the key `stored` returned.
    ///
    /// # Errors
    /// Returns [`JweError::Key`] for any other text.
    pub fn from_stored(stored: &str) -> Result<Self, JweError> {
        let scalar = decode(stored).map_err(|_unread| JweError::Key)?;
        let private =
            PrivateKey::from_private_key(&ECDH_P256, &scalar).map_err(|_rejected| JweError::Key)?;
        Ok(Self { private })
    }

    /// Returns the public JWK the request's `client_metadata.jwks` carries,
    /// named `kid` (OpenID4VP 1.0 §5.1, §8.3).
    ///
    /// # Errors
    /// Returns [`JweError::Key`] when the public key cannot be computed.
    pub fn public_jwk(&self, kid: &str) -> Result<serde_json::Value, JweError> {
        let public = self
            .private
            .compute_public_key()
            .map_err(|_failed| JweError::Key)?;
        let point = public.as_ref();
        let (x, y) = point
            .get(1..33)
            .zip(point.get(33..65))
            .ok_or(JweError::Key)?;
        Ok(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": encode(x),
            "y": encode(y),
            "use": "enc",
            "alg": ALG,
            "kid": kid,
        }))
    }

    /// Returns the SHA-256 JWK Thumbprint of the public key (RFC 7638 §3),
    /// which an mdoc's session transcript binds (OpenID4VP 1.0 Appendix
    /// B.2.6).
    ///
    /// # Errors
    /// Returns [`JweError::Key`] when the public key cannot be computed.
    pub fn thumbprint(&self) -> Result<Vec<u8>, JweError> {
        let jwk = self.public_jwk("")?;
        let text = |name: &str| jwk.get(name).and_then(serde_json::Value::as_str);
        let (Some(x), Some(y)) = (text("x"), text("y")) else {
            return Err(JweError::Key);
        };
        Ok(thumbprint_of(x, y))
    }

    /// Returns the plaintext of the compact JWE `jwe`, encrypted to this key
    /// named `kid`.
    ///
    /// # Errors
    /// Returns [`JweError::Malformed`] for text of another shape,
    /// [`JweError::Unexpected`] for an algorithm, encryption or key the
    /// request did not offer, and [`JweError::Decrypt`] when it does not
    /// decrypt.
    pub fn decrypt(&self, jwe: &str, kid: &str) -> Result<Vec<u8>, JweError> {
        let mut segments = jwe.split('.');
        let (Some(protected), Some(encrypted_key), Some(iv), Some(ciphertext), Some(tag), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Err(JweError::Malformed);
        };
        let header = json_object(protected).ok_or(JweError::Malformed)?;
        let text = |name: &str| header.get(name).and_then(serde_json::Value::as_str);
        // NOTE: RFC 7518 §4.6, under direct key agreement the encrypted key is empty.
        if text("alg") != Some(ALG) || !encrypted_key.is_empty() || text("kid") != Some(kid) {
            return Err(JweError::Unexpected);
        }
        if header.get("zip").is_some() {
            return Err(JweError::Unexpected);
        }
        let (algorithm, length) = match text("enc") {
            Some("A128GCM") => (&AES_128_GCM, 16),
            Some("A256GCM") => (&AES_256_GCM, 32),
            _ => return Err(JweError::Unexpected),
        };
        let peer = header
            .get("epk")
            .and_then(super::p256_point)
            .ok_or(JweError::Malformed)?;
        let party = |name: &str| match text(name) {
            Some(value) => decode(value).map_err(|_unread| JweError::Malformed),
            None => Ok(Vec::new()),
        };
        let other = other_info(
            text("enc").unwrap_or_default(),
            &party("apu")?,
            &party("apv")?,
            length,
        );
        let key = agreement::agree(
            &self.private,
            UnparsedPublicKey::new(&ECDH_P256, &peer),
            JweError::Decrypt,
            |shared| Ok(concat_kdf(shared, &other, length)),
        )?;
        let iv = decode(iv).map_err(|_unread| JweError::Malformed)?;
        let mut sealed = decode(ciphertext).map_err(|_unread| JweError::Malformed)?;
        sealed.extend(decode(tag).map_err(|_unread| JweError::Malformed)?);
        let nonce = Nonce::try_assume_unique_for_key(&iv).map_err(|_length| JweError::Malformed)?;
        let key =
            LessSafeKey::new(UnboundKey::new(algorithm, &key).map_err(|_length| JweError::Key)?);
        // NOTE: RFC 7516 §5.2 step 14, the additional data is the ASCII of the encoded header.
        let plain = key
            .open_in_place(nonce, Aad::from(protected.as_bytes()), &mut sealed)
            .map_err(|_failed| JweError::Decrypt)?;
        Ok(plain.to_vec())
    }
}

/// Returns the `kid` the header of the compact JWE `jwe` names, which finds
/// the request it answers.
#[must_use]
pub fn kid(jwe: &str) -> Option<String> {
    let protected = jwe.split('.').next()?;
    json_object(protected)?
        .get("kid")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// Returns the SHA-256 JWK Thumbprint of the P-256 key whose base64url
/// coordinates are `x` and `y`: the digest of its required members in
/// lexicographic order (RFC 7638 §3.2, §3.3).
fn thumbprint_of(x: &str, y: &str) -> Vec<u8> {
    let members = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    super::sha256(members.as_bytes())
}

/// Returns the `OtherInfo` of the Concat KDF for the encryption `enc` of
/// `length` bytes (RFC 7518 §4.6.2).
fn other_info(enc: &str, apu: &[u8], apv: &[u8], length: usize) -> Vec<u8> {
    let mut info = Vec::new();
    for field in [enc.as_bytes(), apu, apv] {
        info.extend(u32::try_from(field.len()).unwrap_or(u32::MAX).to_be_bytes());
        info.extend_from_slice(field);
    }
    info.extend(u32::try_from(length * 8).unwrap_or(u32::MAX).to_be_bytes());
    info
}

/// Returns the `length` bytes the single-step Concat KDF derives over SHA-256
/// from the shared secret `z` (NIST SP 800-56A §5.8.1, RFC 7518 §4.6.2); one
/// round, since `length` is at most the digest's 32 bytes.
fn concat_kdf(z: &[u8], other: &[u8], length: usize) -> Vec<u8> {
    let mut context = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    context.update(&1_u32.to_be_bytes());
    context.update(z);
    context.update(other);
    let digest = context.finish();
    digest.as_ref().iter().take(length).copied().collect()
}

/// Returns the compact JWE of `plaintext` encrypted to the public JWK `to`
/// with the encryption `enc`, as a wallet sends it: the counterpart of
/// [`EphemeralKey::decrypt`], for tests.
///
/// # Errors
/// Returns [`JweError::Unexpected`] for another key or encryption, and
/// [`JweError::Key`] when the key agreement or the encryption fails.
pub fn encrypt(plaintext: &[u8], to: &serde_json::Value, enc: &str) -> Result<String, JweError> {
    let (algorithm, length) = match enc {
        "A128GCM" => (&AES_128_GCM, 16),
        "A256GCM" => (&AES_256_GCM, 32),
        _ => return Err(JweError::Unexpected),
    };
    let point = super::p256_point(to).ok_or(JweError::Unexpected)?;
    let kid = to
        .get("kid")
        .and_then(serde_json::Value::as_str)
        .ok_or(JweError::Unexpected)?;
    let ephemeral = PrivateKey::generate(&ECDH_P256).map_err(|_failed| JweError::Key)?;
    let epk = EphemeralKey { private: ephemeral };
    let mut epk_jwk = epk.public_jwk("")?;
    if let Some(object) = epk_jwk.as_object_mut() {
        for member in ["use", "alg", "kid"] {
            object.remove(member);
        }
    }
    let header = serde_json::json!({"alg": ALG, "enc": enc, "kid": kid, "epk": epk_jwk});
    let protected = encode(header.to_string().as_bytes());
    let other = other_info(enc, &[], &[], length);
    let key = agreement::agree(
        &epk.private,
        UnparsedPublicKey::new(&ECDH_P256, &point),
        JweError::Key,
        |shared| Ok(concat_kdf(shared, &other, length)),
    )?;
    let mut iv = [0_u8; 12];
    aws_lc_rs::rand::fill(&mut iv).map_err(|_failed| JweError::Key)?;
    let key = LessSafeKey::new(UnboundKey::new(algorithm, &key).map_err(|_length| JweError::Key)?);
    let mut sealed = plaintext.to_vec();
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(iv),
            Aad::from(protected.as_bytes()),
            &mut sealed,
        )
        .map_err(|_failed| JweError::Key)?;
    Ok(format!(
        "{protected}..{}.{}.{}",
        encode(&iv),
        encode(&sealed),
        encode(tag.as_ref())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_thumbprint_is_the_openid4vp_example() {
        // NOTE: OpenID4VP 1.0 Appendix B.2.6.1, the example JWK and the thumbprint its handover carries.
        let thumbprint = thumbprint_of(
            "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
            "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
        );
        let expected: Vec<u8> = [
            0x42, 0x83, 0xec, 0x92, 0x7a, 0xe0, 0xf2, 0x08, 0xda, 0xaa, 0x2d, 0x02, 0x6a, 0x81,
            0x4f, 0x2b, 0x22, 0xdc, 0xa5, 0x2c, 0xf8, 0x5f, 0xfa, 0x8f, 0x3f, 0x86, 0x26, 0xc6,
            0xbd, 0x66, 0x90, 0x47,
        ]
        .to_vec();
        assert_eq!(expected, thumbprint);
        let key = EphemeralKey::generate().expect("a key should generate");
        assert_eq!(32, key.thumbprint().expect("a thumbprint").len());
    }

    #[test]
    fn a_response_encrypted_to_the_request_key_decrypts_under_either_encryption() {
        let key = EphemeralKey::generate().expect("a key should generate");
        let jwk = key.public_jwk("state-1").expect("the JWK should compute");
        for enc in ENC_VALUES {
            let jwe = encrypt(b"{\"vp_token\":{}}", &jwk, enc).expect("the response should seal");
            assert_eq!(kid(&jwe).as_deref(), Some("state-1"));
            let plain = key
                .decrypt(&jwe, "state-1")
                .expect("the response should open");
            assert_eq!(plain, b"{\"vp_token\":{}}");
        }
    }

    #[test]
    fn the_stored_key_is_the_same_key() {
        let key = EphemeralKey::generate().expect("a key should generate");
        let jwk = key.public_jwk("k").expect("the JWK should compute");
        let again = EphemeralKey::from_stored(&key.stored().expect("the key should store"))
            .expect("the key should read back");
        let jwe = encrypt(b"x", &jwk, "A256GCM").expect("the response should seal");
        assert_eq!(
            again.decrypt(&jwe, "k").expect("the response should open"),
            b"x"
        );
    }

    #[test]
    fn the_published_jwk_carries_no_private_part() {
        let key = EphemeralKey::generate().expect("a key should generate");
        let jwk = key.public_jwk("k").expect("the JWK should compute");
        assert!(jwk.get("d").is_none());
        assert_eq!(jwk["alg"], "ECDH-ES");
        assert_eq!(jwk["use"], "enc");
    }

    #[test]
    fn a_response_to_another_key_or_kid_does_not_open() {
        let key = EphemeralKey::generate().expect("a key should generate");
        let other = EphemeralKey::generate().expect("a key should generate");
        let jwk = other.public_jwk("k").expect("the JWK should compute");
        let jwe = encrypt(b"x", &jwk, "A128GCM").expect("the response should seal");
        assert_eq!(key.decrypt(&jwe, "k"), Err(JweError::Decrypt));
        assert_eq!(other.decrypt(&jwe, "other"), Err(JweError::Unexpected));
    }

    #[test]
    fn a_tampered_or_truncated_response_is_refused() {
        let key = EphemeralKey::generate().expect("a key should generate");
        let jwk = key.public_jwk("k").expect("the JWK should compute");
        let jwe = encrypt(b"payload", &jwk, "A128GCM").expect("the response should seal");
        let mut parts: Vec<String> = jwe.split('.').map(str::to_owned).collect();
        parts[3] = encode(b"another payload");
        assert_eq!(key.decrypt(&parts.join("."), "k"), Err(JweError::Decrypt));
        assert_eq!(key.decrypt("a.b.c", "k"), Err(JweError::Malformed));
    }

    #[test]
    fn the_kdf_matches_rfc_7518_appendix_c() {
        let z = [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ];
        let other = other_info("A128GCM", b"Alice", b"Bob", 16);
        assert_eq!(
            encode(&concat_kdf(&z, &other, 16)),
            "VqqN6vgjbSBcIijNcacQGg"
        );
    }
}
