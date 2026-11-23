// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A test wallet: the certificates of the verifier and of a PID provider,
//! the PID as an SD-JWT VC with its Key Binding JWT, a Token Status List,
//! and the encrypted answer, each made when the case runs.

use std::io::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyIdMethod, KeyPair,
    PKCS_ECDSA_P256_SHA256,
};
use serde_json::{Value, json};

/// The PID's credential type.
pub(super) const PID: &str = "urn:eudi:pid:1";

/// A certificate with its key.
pub(super) struct Authority {
    /// The parameters it was made from, which sign under it.
    params: CertificateParams,
    /// Its key.
    pub(super) key: KeyPair,
    /// The certificate, DER.
    pub(super) der: Vec<u8>,
    /// The certificate, PEM.
    pub(super) pem: String,
}

impl Authority {
    /// Makes a certificate named `name`, a certificate authority when `ca`,
    /// signed by `signer` or by itself.
    pub(super) fn new(name: &str, ca: bool, signer: Option<&Self>) -> Self {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("a key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.distinguished_name.push(DnType::CommonName, name);
        params.key_identifier_method = KeyIdMethod::Sha256;
        if ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        }
        let certificate = match signer {
            Some(signer) => {
                params.signed_by(&key, &Issuer::from_params(&signer.params, &signer.key))
            }
            None => params.self_signed(&key),
        }
        .expect("the certificate signs");
        Self {
            params,
            key,
            der: certificate.der().to_vec(),
            pem: certificate.pem(),
        }
    }

    /// Signs `claims` under `header` with this certificate's key.
    pub(super) fn sign(&self, header: &Header, claims: &Value) -> String {
        jsonwebtoken::encode(
            header,
            claims,
            &EncodingKey::from_ec_der(&self.key.serialize_der()),
        )
        .expect("signs")
    }

    /// Returns the header of a JWS this certificate signs, carrying it as
    /// `x5c`.
    pub(super) fn header(&self, typ: &str) -> Header {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some(typ.to_owned());
        header.x5c = Some(vec![STANDARD.encode(&self.der)]);
        header
    }
}

/// The certificates of a case.
pub(super) struct Pki {
    /// The verifier's access certificate.
    pub(super) access: Authority,
    /// The PID providers' anchor FerroSMART is configured with.
    pub(super) pid_root: Authority,
    /// The PID provider, under the anchor.
    pub(super) issuer: Authority,
    /// A provider under another root.
    pub(super) stranger: Authority,
}

impl Pki {
    /// Makes the certificates.
    pub(super) fn new() -> Self {
        let rp_root = Authority::new("rp-root", true, None);
        let access = Authority::new("ferrosmart-access", false, Some(&rp_root));
        let pid_root = Authority::new("pid-root", true, None);
        let issuer = Authority::new("pid-provider", false, Some(&pid_root));
        let other_root = Authority::new("other-root", true, None);
        let stranger = Authority::new("other-provider", false, Some(&other_root));
        Self {
            access,
            pid_root,
            issuer,
            stranger,
        }
    }
}

/// The holder's key, which the PID binds.
pub(super) struct Holder {
    /// The key.
    key: KeyPair,
}

impl Holder {
    /// Makes a key.
    pub(super) fn new() -> Self {
        Self {
            key: KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("a key"),
        }
    }

    /// Returns the public JWK.
    pub(super) fn jwk(&self) -> Value {
        let point = self.key.public_key_raw();
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.get(1..33).expect("an x")),
            "y": URL_SAFE_NO_PAD.encode(point.get(33..65).expect("a y")),
        })
    }

    /// Returns the Key Binding JWT over `hashed` for `aud` and `nonce`,
    /// issued at `iat`.
    pub(super) fn bind(&self, hashed: &str, aud: &str, nonce: &str, iat: i64) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some(String::from("kb+jwt"));
        let sd_hash = URL_SAFE_NO_PAD.encode(aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA256,
            hashed.as_bytes(),
        ));
        let claims = json!({"iat": iat, "aud": aud, "nonce": nonce, "sd_hash": sd_hash});
        jsonwebtoken::encode(
            &header,
            &claims,
            &EncodingKey::from_ec_der(&self.key.serialize_der()),
        )
        .expect("signs")
    }
}

/// Returns the time now in seconds since the epoch.
pub(super) fn now() -> i64 {
    jiff::Timestamp::now().as_second()
}

/// A PID as its provider issues it.
pub(super) struct Credential {
    /// The type.
    pub(super) vct: String,
    /// The selectively disclosable claims, by name.
    pub(super) claims: Vec<(String, Value)>,
    /// The names of the claims the holder leaves out of the presentation.
    pub(super) withheld: Vec<String>,
    /// The `exp`.
    pub(super) exp: i64,
    /// The `status` claim, if any.
    pub(super) status: Option<Value>,
}

impl Credential {
    /// Returns a PID of a Dutch person, valid for a day, with no status.
    pub(super) fn pid() -> Self {
        Self {
            vct: String::from(PID),
            claims: vec![
                (String::from("family_name"), json!("Jansen")),
                (String::from("given_name"), json!("Eva")),
                (String::from("birthdate"), json!("1980-04-02")),
                (
                    String::from("personal_administrative_number"),
                    json!("999990019"),
                ),
                (String::from("issuing_country"), json!("NL")),
            ],
            withheld: Vec::new(),
            exp: now() + 24 * 3600,
            status: None,
        }
    }

    /// Returns the presentation `signer` issued, bound by `holder` for
    /// `aud` and `nonce` at `iat`: the SD-JWT with its disclosures and Key
    /// Binding JWT.
    pub(super) fn present(
        &self,
        signer: &Authority,
        holder: &Holder,
        aud: &str,
        nonce: &str,
        iat: i64,
    ) -> String {
        let hashed = self.issued(signer, holder);
        let binding = holder.bind(&hashed, aud, nonce, iat);
        format!("{hashed}{binding}")
    }

    /// Returns the SD-JWT `signer` issued for `holder`, with the disclosures
    /// the holder presents and the closing `~`.
    pub(super) fn issued(&self, signer: &Authority, holder: &Holder) -> String {
        let mut digests = Vec::new();
        let mut disclosed = Vec::new();
        for (index, (name, value)) in self.claims.iter().enumerate() {
            let disclosure =
                URL_SAFE_NO_PAD.encode(json!([format!("salt-{index}"), name, value]).to_string());
            digests.push(URL_SAFE_NO_PAD.encode(aws_lc_rs::digest::digest(
                &aws_lc_rs::digest::SHA256,
                disclosure.as_bytes(),
            )));
            if !self.withheld.contains(name) {
                disclosed.push(disclosure);
            }
        }
        let mut payload = json!({
            "vct": self.vct,
            "iat": now() - 60,
            "exp": self.exp,
            "cnf": {"jwk": holder.jwk()},
            "_sd_alg": "sha-256",
            "_sd": digests,
        });
        if let (Some(status), Some(object)) = (&self.status, payload.as_object_mut()) {
            object.insert(String::from("status"), status.clone());
        }
        let jwt = signer.sign(&signer.header("dc+sd-jwt"), &payload);
        let mut out = jwt;
        for disclosure in disclosed {
            out.push('~');
            out.push_str(&disclosure);
        }
        out.push('~');
        out
    }
}

/// Returns a Status List Token for `uri` that `signer` signs, in which
/// each index of `revoked` is invalid among `size` credentials, one bit each.
pub(super) fn status_list(signer: &Authority, uri: &str, size: usize, revoked: &[usize]) -> String {
    let mut bytes = vec![0_u8; size.div_ceil(8)];
    for index in revoked {
        *bytes.get_mut(index / 8).expect("within the list") |= 1 << (index % 8);
    }
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&bytes).expect("compresses");
    let lst = URL_SAFE_NO_PAD.encode(encoder.finish().expect("compresses"));
    let claims = json!({
        "sub": uri,
        "iat": now() - 60,
        "exp": now() + 3600,
        "status_list": {"bits": 1, "lst": lst},
    });
    signer.sign(&signer.header("statuslist+jwt"), &claims)
}

/// Returns the encrypted answer a wallet posts: `payload` sealed to the
/// request's `jwk` with A256GCM.
pub(super) fn sealed(payload: &Value, jwk: &Value) -> String {
    ferrosmart::wallet::jwe::encrypt(payload.to_string().as_bytes(), jwk, "A256GCM").expect("seals")
}
