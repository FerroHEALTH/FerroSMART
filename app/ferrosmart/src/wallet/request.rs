// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The signed request object a wallet fetches, and the URL that invokes it.
//!
//! The wallet fetches the object from the `request_uri` (OpenID4VP 1.0 §5,
//! §5.10, §6, §8.3; HAIP 1.0 §5, §5.1; ETSI TS 119 472-2 V1.2.1 §6.3.2.2 and
//! §6.4.2, as Implementing Regulation (EU) 2024/2979 Annex II, amended by
//! 2026/1731, applies them).

use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use base64::Engine as _;
use serde_json::{Value, json};
use url::Url;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::jwe::{ENC_VALUES, EphemeralKey};
use super::{ES256, SD_JWT_VC, encode, sha256};

/// The `aud` of a request object sent to a wallet the verifier cannot name
/// in advance (OpenID4VP 1.0 §5.8).
const AUDIENCE: &str = "https://self-issued.me/v2";

/// The media type of a request object (RFC 9101 §10.2).
pub const MEDIA_TYPE: &str = "application/oauth-authz-req+jwt";

/// The `id` of the one credential query.
pub const CREDENTIAL_ID: &str = "pid";

/// Why the verifier's own keys and certificates cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VerifierError {
    /// The access key is not a PKCS#8 P-256 key.
    #[error("the access key is not a PKCS#8 P-256 key")]
    Key,
    /// The access certificate file holds no certificate, or one that does
    /// not read.
    #[error("the access certificate does not read")]
    Certificate,
    /// The access certificate does not carry the access key's public key.
    #[error("the access certificate does not carry the access key")]
    Mismatch,
    /// The access certificate is self-signed (HAIP 1.0 §5).
    #[error("the access certificate is self-signed")]
    SelfSigned,
    /// The request object could not be signed.
    #[error("the request object could not be signed")]
    Sign,
}

/// The verifier: its access key and certificate path, its registration
/// certificate and what it asks for.
#[derive(Clone)]
pub struct Verifier {
    /// The key that signs every request object.
    key: jsonwebtoken::EncodingKey,
    /// The access certificate first and its path up to the anchor, standard
    /// base64 as `x5c` carries them.
    chain: Vec<String>,
    /// `x509_hash:` and the base64url SHA-256 of the access certificate
    /// (OpenID4VP 1.0 §5.9.3).
    client_id: String,
    /// The registration certificate, base64url.
    registration: String,
    /// Where the wallet posts its response.
    response_uri: String,
    /// The DCQL query.
    query: Value,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// What a verifier asks of every wallet.
#[derive(Debug, Clone)]
pub struct Asks<'a> {
    /// The credential types accepted.
    pub vct_values: &'a [String],
    /// The claim paths requested, each a list of names (OpenID4VP 1.0 §7.1).
    pub claims: &'a [Vec<String>],
    /// The base64url key identifiers of the trusted issuers' anchors.
    pub key_identifiers: &'a [String],
}

impl Verifier {
    /// Returns the verifier of the PKCS#8 PEM key `key`, the PEM certificate
    /// path `chain` (the access certificate first, the anchor left out), the
    /// registration certificate `registration` as its registrar serialized
    /// it, answering at `response_uri` and asking `asks`.
    ///
    /// # Errors
    /// Returns [`VerifierError`] when the key, the certificate or their pair
    /// cannot be used.
    pub fn new(
        key: &[u8],
        chain: &[u8],
        registration: &[u8],
        response_uri: &Url,
        asks: &Asks<'_>,
    ) -> Result<Self, VerifierError> {
        let der = super::x509::certificates(chain).map_err(|_unread| VerifierError::Certificate)?;
        let leaf = der.first().ok_or(VerifierError::Certificate)?;
        let (_, certificate) =
            X509Certificate::from_der(leaf).map_err(|_unread| VerifierError::Certificate)?;
        if certificate.subject().as_raw() == certificate.issuer().as_raw() {
            return Err(VerifierError::SelfSigned);
        }
        let pkcs8 = pem_contents(key).ok_or(VerifierError::Key)?;
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8)
            .map_err(|_rejected| VerifierError::Key)?;
        if pair.public_key().as_ref() != certificate.public_key().subject_public_key.data.as_ref() {
            return Err(VerifierError::Mismatch);
        }
        Ok(Self {
            key: jsonwebtoken::EncodingKey::from_ec_der(&pkcs8),
            chain: der
                .iter()
                .map(|der| base64::engine::general_purpose::STANDARD.encode(der))
                .collect(),
            client_id: format!("x509_hash:{}", encode(&sha256(leaf))),
            registration: encode(registration.trim_ascii()),
            response_uri: response_uri.to_string(),
            query: dcql(asks),
        })
    }

    /// Returns the verifier's client identifier, `x509_hash:` and the hash
    /// of its access certificate.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Returns the URL that invokes the wallet at `endpoint` with the
    /// request at `request_uri`, which the wallet may fetch by `post`
    /// (OpenID4VP 1.0 §5.10, §9).
    #[must_use]
    pub fn invocation(&self, endpoint: &Url, request_uri: &Url) -> Url {
        let mut url = endpoint.clone();
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("request_uri", request_uri.as_str())
            .append_pair("request_uri_method", "post");
        url
    }

    /// Returns the request object of one request, signed with the access
    /// key.
    ///
    /// # Errors
    /// Returns [`VerifierError::Sign`] when signing fails, and
    /// [`VerifierError::Key`] when the ephemeral key cannot be published.
    pub fn request_object(&self, request: &Request<'_>) -> Result<String, VerifierError> {
        let jwk = request
            .key
            .public_jwk(request.state)
            .map_err(|_failed| VerifierError::Key)?;
        let mut claims = json!({
            "aud": AUDIENCE,
            "client_id": self.client_id,
            "response_type": "vp_token",
            "response_mode": "direct_post.jwt",
            "response_uri": self.response_uri,
            "nonce": request.nonce,
            "state": request.state,
            "dcql_query": self.query,
            "client_metadata": {
                "jwks": {"keys": [jwk]},
                "encrypted_response_enc_values_supported": ENC_VALUES,
                "vp_formats_supported": {
                    SD_JWT_VC: {"sd-jwt_alg_values": [ES256], "kb-jwt_alg_values": [ES256]},
                },
            },
            "verifier_info": [{"format": "registration_cert", "data": self.registration}],
            "iat": request.issued_at,
            "exp": request.expires_at,
        });
        if let (Some(wallet_nonce), Some(object)) = (request.wallet_nonce, claims.as_object_mut()) {
            object.insert(String::from("wallet_nonce"), Value::from(wallet_nonce));
        }
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.typ = Some(String::from("oauth-authz-req+jwt"));
        header.x5c = Some(self.chain.clone());
        // NOTE: ETSI TS 119 472-2 OIDFVP-HAIP-REDIRECTS_RO-03, iat is a protected header parameter.
        header.extras.insert("iat", request.issued_at);
        jsonwebtoken::encode(&header, &claims, &self.key).map_err(|_failed| VerifierError::Sign)
    }
}

/// One request: what its object carries beside the verifier's own values.
#[derive(Debug)]
pub struct Request<'a> {
    /// The `state`, which also names the ephemeral key.
    pub state: &'a str,
    /// The `nonce`.
    pub nonce: &'a str,
    /// The ephemeral key the response is encrypted to.
    pub key: &'a EphemeralKey,
    /// The `wallet_nonce` a wallet posted to the `request_uri` (OpenID4VP
    /// 1.0 §5.10).
    pub wallet_nonce: Option<&'a str>,
    /// When the object is signed, in seconds since the epoch.
    pub issued_at: i64,
    /// When the request lapses, in seconds since the epoch.
    pub expires_at: i64,
}

/// Returns the DCQL query of `asks`: one SD-JWT VC of the accepted types
/// from an issuer under the trusted anchors, with the claims asked for
/// (OpenID4VP 1.0 §6, Appendix B.3.5; HAIP 1.0 §5).
fn dcql(asks: &Asks<'_>) -> Value {
    let claims: Vec<Value> = asks.claims.iter().map(|path| json!({"path": path})).collect();
    let mut credential = json!({
        "id": CREDENTIAL_ID,
        "format": SD_JWT_VC,
        "meta": {"vct_values": asks.vct_values},
        "claims": claims,
    });
    if !asks.key_identifiers.is_empty()
        && let Some(object) = credential.as_object_mut()
    {
        object.insert(
            String::from("trusted_authorities"),
            json!([{"type": "aki", "values": asks.key_identifiers}]),
        );
    }
    json!({"credentials": [credential]})
}

/// Returns the DER contents of the one `PRIVATE KEY` block of `pem`.
fn pem_contents(pem: &[u8]) -> Option<Vec<u8>> {
    let (rest, block) = x509_parser::pem::parse_x509_pem(pem).ok()?;
    (block.label == "PRIVATE KEY" && rest.iter().all(u8::is_ascii_whitespace)).then_some(block.contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_query_asks_one_sd_jwt_vc_with_its_claims_and_anchors() {
        let vct = [String::from("urn:eudi:pid:1")];
        let claims = [
            vec![String::from("family_name")],
            vec![String::from("address"), String::from("country")],
        ];
        let anchors = [String::from("s9tIpPmhxdiuNkHMEWNpYim8S8Y")];
        let query = dcql(&Asks {
            vct_values: &vct,
            claims: &claims,
            key_identifiers: &anchors,
        });
        let credential = &query["credentials"][0];
        assert_eq!(credential["format"], "dc+sd-jwt");
        assert_eq!(credential["meta"]["vct_values"][0], "urn:eudi:pid:1");
        assert_eq!(credential["claims"][1]["path"], json!(["address", "country"]));
        assert_eq!(credential["trusted_authorities"][0]["type"], "aki");
    }
}
