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
use super::{ES256, Format, encode, sha256};

/// The `aud` of a request object sent to a wallet the verifier cannot name
/// in advance (OpenID4VP 1.0 §5.8).
const AUDIENCE: &str = "https://self-issued.me/v2";

/// The media type of a request object (RFC 9101 §10.2).
pub const MEDIA_TYPE: &str = "application/oauth-authz-req+jwt";

/// The `id` of the credential query for the PID as an SD-JWT VC.
pub const CREDENTIAL_ID: &str = "pid";

/// The `id` of the credential query for the PID as an mdoc.
pub const MDOC_CREDENTIAL_ID: &str = "pid_mdoc";

/// The COSE algorithms of the issuer's and the device's signatures on an
/// mdoc: ES256 and ESP256 (OpenID4VP 1.0 Appendix B.2.2; HAIP 1.0 §7; RFC
/// 9864 §2.1).
const MDOC_ALGORITHMS: [i64; 2] = [-7, -9];

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
    /// The `vp_formats_supported` of the client metadata.
    formats: Value,
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
    /// The credential formats asked for, of which the wallet presents one.
    pub formats: &'a [Format],
    /// The credential types accepted as an SD-JWT VC.
    pub vct_values: &'a [String],
    /// The claim paths requested of an SD-JWT VC, each a list of names
    /// (OpenID4VP 1.0 §7.1).
    pub claims: &'a [Vec<String>],
    /// The document type accepted as an mdoc, also the namespace of its
    /// elements.
    pub doctype: &'a str,
    /// The data elements requested of an mdoc.
    pub elements: &'a [String],
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
            formats: formats_supported(asks.formats),
        })
    }

    /// Returns the URI the wallet posts its response to.
    #[must_use]
    pub fn response_uri(&self) -> &str {
        &self.response_uri
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
            "client_id": self.client_id,
            "response_type": "vp_token",
            "nonce": request.nonce,
            "dcql_query": self.query,
            "client_metadata": {
                "jwks": {"keys": [jwk]},
                "encrypted_response_enc_values_supported": ENC_VALUES,
                "vp_formats_supported": self.formats,
            },
            "verifier_info": [{"format": "registration_cert", "data": self.registration}],
            "iat": request.issued_at,
            "exp": request.expires_at,
        });
        let Some(object) = claims.as_object_mut() else {
            return Err(VerifierError::Sign);
        };
        let mut put = |name: &str, value: Value| object.insert(name.to_owned(), value);
        match request.lane {
            Lane::Redirect { wallet_nonce } => {
                put("aud", Value::from(AUDIENCE));
                put("response_mode", Value::from("direct_post.jwt"));
                put("response_uri", Value::from(self.response_uri.as_str()));
                put("state", Value::from(request.state));
                if let Some(wallet_nonce) = wallet_nonce {
                    put("wallet_nonce", Value::from(wallet_nonce));
                }
            }
            // NOTE: OpenID4VP 1.0 Appendix A.2, a signed request names its origins and the
            // dc_api.jwt response mode; HAIP 1.0 §5.2.
            Lane::DigitalCredentials { origin } => {
                put("response_mode", Value::from("dc_api.jwt"));
                put("expected_origins", json!([origin]));
            }
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
    /// How the wallet is reached.
    pub lane: Lane<'a>,
    /// When the object is signed, in seconds since the epoch.
    pub issued_at: i64,
    /// When the request lapses, in seconds since the epoch.
    pub expires_at: i64,
}

/// How a request reaches the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane<'a> {
    /// By redirect, the answer posted to the response URI, with the
    /// `wallet_nonce` a wallet posted to the `request_uri` (OpenID4VP 1.0
    /// §5.10).
    Redirect {
        /// The `wallet_nonce`.
        wallet_nonce: Option<&'a str>,
    },
    /// Over the Digital Credentials API from the page at `origin`
    /// (OpenID4VP 1.0 Appendix A).
    DigitalCredentials {
        /// The page's origin.
        origin: &'a str,
    },
}

/// Returns the `vp_formats_supported` of `formats`: ES256 for an SD-JWT
/// VC and its Key Binding JWT, ES256 and ESP256 for an mdoc's issuer and
/// device signatures (OpenID4VP 1.0 Appendix B.2.2, B.3.4; HAIP 1.0 §7).
fn formats_supported(formats: &[Format]) -> Value {
    let mut supported = serde_json::Map::new();
    for format in formats {
        let algorithms = match format {
            Format::SdJwtVc => json!({"sd-jwt_alg_values": [ES256], "kb-jwt_alg_values": [ES256]}),
            Format::Mdoc => json!({
                "issuerauth_alg_values": MDOC_ALGORITHMS,
                "deviceauth_alg_values": MDOC_ALGORITHMS,
            }),
        };
        supported.insert(format.identifier().to_owned(), algorithms);
    }
    Value::Object(supported)
}

/// Returns the DCQL query of `asks`: the PID in each format asked for,
/// from an issuer under the trusted anchors, with the claims asked for,
/// and with more than one format a credential set of which the wallet
/// presents one (OpenID4VP 1.0 §6, §6.2, Appendix B.2.3, B.3.5; HAIP 1.0
/// §5).
fn dcql(asks: &Asks<'_>) -> Value {
    let credentials: Vec<Value> = asks
        .formats
        .iter()
        .map(|format| {
            let mut credential = match format {
                Format::SdJwtVc => json!({
                    "id": CREDENTIAL_ID,
                    "format": format.identifier(),
                    "meta": {"vct_values": asks.vct_values},
                    "claims": asks.claims.iter().map(|path| json!({"path": path})).collect::<Vec<_>>(),
                }),
                Format::Mdoc => json!({
                    "id": MDOC_CREDENTIAL_ID,
                    "format": format.identifier(),
                    "meta": {"doctype_value": asks.doctype},
                    "claims": asks
                        .elements
                        .iter()
                        .map(|element| json!({"path": [asks.doctype, element]}))
                        .collect::<Vec<_>>(),
                }),
            };
            if !asks.key_identifiers.is_empty()
                && let Some(object) = credential.as_object_mut()
            {
                object.insert(
                    String::from("trusted_authorities"),
                    json!([{"type": "aki", "values": asks.key_identifiers}]),
                );
            }
            credential
        })
        .collect();
    if credentials.len() < 2 {
        return json!({"credentials": credentials});
    }
    let options: Vec<Value> = credentials
        .iter()
        .map(|credential| json!([credential["id"]]))
        .collect();
    json!({"credentials": credentials, "credential_sets": [{"options": options}]})
}

/// Returns the DER contents of the one `PRIVATE KEY` block of `pem`.
fn pem_contents(pem: &[u8]) -> Option<Vec<u8>> {
    let (rest, block) = x509_parser::pem::parse_x509_pem(pem).ok()?;
    (block.label == "PRIVATE KEY" && rest.iter().all(u8::is_ascii_whitespace))
        .then_some(block.contents)
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
            formats: &[Format::SdJwtVc],
            vct_values: &vct,
            claims: &claims,
            doctype: "eu.europa.ec.eudi.pid.1",
            elements: &[],
            key_identifiers: &anchors,
        });
        assert!(query.get("credential_sets").is_none(), "one format, no set");
        let credential = &query["credentials"][0];
        assert_eq!(credential["format"], "dc+sd-jwt");
        assert_eq!(credential["meta"]["vct_values"][0], "urn:eudi:pid:1");
        assert_eq!(
            credential["claims"][1]["path"],
            json!(["address", "country"])
        );
        assert_eq!(credential["trusted_authorities"][0]["type"], "aki");
    }

    #[test]
    fn the_query_offers_the_pid_in_both_formats_as_one_choice() {
        let vct = [String::from("urn:eudi:pid:1")];
        let claims = [vec![String::from("family_name")]];
        let elements = [String::from("family_name"), String::from("birth_date")];
        let query = dcql(&Asks {
            formats: &[Format::SdJwtVc, Format::Mdoc],
            vct_values: &vct,
            claims: &claims,
            doctype: "eu.europa.ec.eudi.pid.1",
            elements: &elements,
            key_identifiers: &[],
        });
        let mdoc = &query["credentials"][1];
        assert_eq!("mso_mdoc", mdoc["format"]);
        assert_eq!("pid_mdoc", mdoc["id"]);
        assert_eq!("eu.europa.ec.eudi.pid.1", mdoc["meta"]["doctype_value"]);
        assert_eq!(
            json!(["eu.europa.ec.eudi.pid.1", "birth_date"]),
            mdoc["claims"][1]["path"]
        );
        // NOTE: OpenID4VP 1.0 §6.2, one set whose options are each a format: the wallet presents one.
        assert_eq!(
            json!([{"options": [["pid"], ["pid_mdoc"]]}]),
            query["credential_sets"]
        );
        let supported = formats_supported(&[Format::SdJwtVc, Format::Mdoc]);
        assert_eq!(
            json!([-7, -9]),
            supported["mso_mdoc"]["deviceauth_alg_values"]
        );
    }
}
