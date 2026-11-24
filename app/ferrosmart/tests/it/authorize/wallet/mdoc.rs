// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The PID as an ISO mdoc (#793): a `DeviceResponse` made when the case
//! runs, under the request's session transcript, accepted through both
//! lanes and refused for every reason an SD-JWT VC is.

use std::io::Write as _;

use ciborium::value::{Integer, Value as Cbor};
use ferrosmart::wallet::mdoc::{Handover, session_transcript};

use super::kit::{Authority, Holder, now};
use super::refusals::assert_refused;
use super::*;

/// The PID's document type and namespace (PID Rulebook §3.1.1).
pub(super) const DOCTYPE: &str = "eu.europa.ec.eudi.pid.1";

/// The `id` of the mdoc credential query.
pub(super) const MDOC: &str = "pid_mdoc";

fn text(text: &str) -> Cbor {
    Cbor::Text(text.to_owned())
}

fn int(number: i64) -> Cbor {
    Cbor::Integer(Integer::from(number))
}

fn encode(value: &Cbor) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).expect("encodes");
    bytes
}

/// Returns `value` as an encoded CBOR data item, tag 24.
fn embedded(value: &Cbor) -> Cbor {
    Cbor::Tag(24, Box::new(Cbor::Bytes(encode(value))))
}

fn date(seconds: i64) -> Cbor {
    Cbor::Tag(
        0,
        Box::new(text(
            &jiff::Timestamp::from_second(seconds)
                .expect("an instant")
                .to_string(),
        )),
    )
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

/// Returns the raw ECDSA P-256 signature of `message` under `key`.
fn signature(key: &rcgen::KeyPair, message: &[u8]) -> Vec<u8> {
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &key.serialize_der())
        .expect("a P-256 key");
    pair.sign(&SystemRandom::new(), message)
        .expect("signs")
        .as_ref()
        .to_vec()
}

/// Returns a `COSE_Sign1` under `key` with `alg`, its header carrying
/// `unprotected`, over `payload`, or over `detached` with no payload.
fn sign1(
    key: &rcgen::KeyPair,
    protected: Vec<(Cbor, Cbor)>,
    unprotected: Vec<(Cbor, Cbor)>,
    payload: Option<Vec<u8>>,
    detached: &[u8],
) -> Cbor {
    let protected = encode(&Cbor::Map(protected));
    let signed = Cbor::Array(vec![
        text("Signature1"),
        Cbor::Bytes(protected.clone()),
        Cbor::Bytes(Vec::new()),
        Cbor::Bytes(payload.clone().unwrap_or_else(|| detached.to_vec())),
    ]);
    Cbor::Array(vec![
        Cbor::Bytes(protected),
        Cbor::Map(unprotected),
        payload.map_or(Cbor::Null, Cbor::Bytes),
        Cbor::Bytes(signature(key, &encode(&signed))),
    ])
}

/// Returns the `x5chain` header of `signer`'s certificate.
fn x5chain(signer: &Authority) -> Vec<(Cbor, Cbor)> {
    vec![(int(33), Cbor::Bytes(signer.der.clone()))]
}

/// Returns the device key of `holder` as a `COSE_Key`.
fn device_key(holder: &Holder) -> Cbor {
    let point = holder.point();
    Cbor::Map(vec![
        (int(1), int(2)),
        (int(-1), int(1)),
        (int(-2), Cbor::Bytes(point.get(1..33).expect("x").to_vec())),
        (int(-3), Cbor::Bytes(point.get(33..65).expect("y").to_vec())),
    ])
}

/// A PID as its provider issues it as an mdoc.
pub(super) struct Mdoc {
    /// The document type.
    doctype: String,
    /// The elements of the PID namespace.
    elements: Vec<(String, Cbor)>,
    /// The elements the holder leaves out.
    withheld: Vec<String>,
    /// Elements of another namespace the holder presents.
    other_namespace: Vec<(String, Cbor)>,
    /// The `validFrom` and `validUntil`.
    validity: (i64, i64),
    /// The MSO's `status`, if any.
    status: Option<Cbor>,
    /// Whether an element's value is changed after its digest is taken.
    altered: bool,
    /// Whether the MSO's signature is broken.
    forged: bool,
}

impl Mdoc {
    /// Returns a PID of a Dutch person, valid for a day, with no status.
    pub(super) fn pid() -> Self {
        let full_date = Cbor::Tag(1004, Box::new(text("1980-04-02")));
        Self {
            doctype: DOCTYPE.to_owned(),
            elements: vec![
                (String::from("family_name"), text("Jansen")),
                (String::from("given_name"), text("Eva")),
                (String::from("birth_date"), full_date),
                (
                    String::from("personal_administrative_number"),
                    text("999990019"),
                ),
                (String::from("issuing_country"), text("NL")),
            ],
            withheld: Vec::new(),
            other_namespace: Vec::new(),
            validity: (now() - 60, now() + 24 * 3600),
            status: None,
            altered: false,
            forged: false,
        }
    }

    /// Returns the base64url `DeviceResponse` `signer` issued for `holder`,
    /// signed by the holder over `transcript`.
    pub(super) fn present(&self, signer: &Authority, holder: &Holder, transcript: &Cbor) -> String {
        let (namespace, mut items, digests) =
            items_of(&self.doctype, &self.elements, &self.withheld);
        let mut namespaces = vec![(text(&namespace), Cbor::Array(items.clone()))];
        let mut value_digests = vec![(text(&namespace), digests)];
        if !self.other_namespace.is_empty() {
            let (other, other_items, other_digests) =
                items_of("org.example.other.1", &self.other_namespace, &[]);
            namespaces.push((text(&other), Cbor::Array(other_items)));
            value_digests.push((text(&other), other_digests));
        }
        if self.altered {
            let item = Cbor::Map(vec![
                (text("digestID"), int(0)),
                (text("random"), Cbor::Bytes(vec![9; 16])),
                (text("elementIdentifier"), text("family_name")),
                (text("elementValue"), text("Someone Else")),
            ]);
            *items.first_mut().expect("an item") = embedded(&item);
            *namespaces.first_mut().expect("a namespace") = (text(&namespace), Cbor::Array(items));
        }
        let mut mso = vec![
            (text("version"), text("1.0")),
            (text("digestAlgorithm"), text("SHA-256")),
            (text("valueDigests"), Cbor::Map(value_digests)),
            (
                text("deviceKeyInfo"),
                Cbor::Map(vec![(text("deviceKey"), device_key(holder))]),
            ),
            (text("docType"), text(&self.doctype)),
            (
                text("validityInfo"),
                Cbor::Map(vec![
                    (text("signed"), date(self.validity.0)),
                    (text("validFrom"), date(self.validity.0)),
                    (text("validUntil"), date(self.validity.1)),
                ]),
            ),
        ];
        if let Some(status) = &self.status {
            mso.push((text("status"), status.clone()));
        }
        let payload = encode(&embedded(&Cbor::Map(mso)));
        let mut issuer_auth = sign1(
            &signer.key,
            vec![(int(1), int(-7))],
            x5chain(signer),
            Some(payload),
            &[],
        );
        if self.forged
            && let Cbor::Array(parts) = &mut issuer_auth
        {
            *parts.get_mut(3).expect("a signature") = Cbor::Bytes(vec![7; 64]);
        }
        let device_namespaces = embedded(&Cbor::Map(Vec::new()));
        let authentication = Cbor::Array(vec![
            text("DeviceAuthentication"),
            transcript.clone(),
            text(&self.doctype),
            device_namespaces.clone(),
        ]);
        let detached = encode(&embedded(&authentication));
        let device_signature = sign1(
            &holder.key,
            vec![(int(1), int(-9))],
            Vec::new(),
            None,
            &detached,
        );
        let document = Cbor::Map(vec![
            (text("docType"), text(&self.doctype)),
            (
                text("issuerSigned"),
                Cbor::Map(vec![
                    (text("nameSpaces"), Cbor::Map(namespaces)),
                    (text("issuerAuth"), issuer_auth),
                ]),
            ),
            (
                text("deviceSigned"),
                Cbor::Map(vec![
                    (text("nameSpaces"), device_namespaces),
                    (
                        text("deviceAuth"),
                        Cbor::Map(vec![(text("deviceSignature"), device_signature)]),
                    ),
                ]),
            ),
        ]);
        let response = Cbor::Map(vec![
            (text("version"), text("1.0")),
            (text("documents"), Cbor::Array(vec![document])),
            (text("status"), int(0)),
        ]);
        URL_SAFE_NO_PAD.encode(encode(&response))
    }
}

/// Returns `namespace`, the items of `elements` but `withheld`, and the
/// digests of all of them.
fn items_of(
    namespace: &str,
    elements: &[(String, Cbor)],
    withheld: &[String],
) -> (String, Vec<Cbor>, Cbor) {
    let mut items = Vec::new();
    let mut digests = Vec::new();
    for (id, (name, value)) in (0_i64..).zip(elements) {
        let item = embedded(&Cbor::Map(vec![
            (text("digestID"), int(id)),
            (
                text("random"),
                Cbor::Bytes(sha256(format!("salt-{id}").as_bytes())),
            ),
            (text("elementIdentifier"), text(name)),
            (text("elementValue"), value.clone()),
        ]));
        digests.push((int(id), Cbor::Bytes(sha256(&encode(&item)))));
        if !withheld.contains(name) {
            items.push(item);
        }
    }
    (namespace.to_owned(), items, Cbor::Map(digests))
}

/// Returns a revocation list in CWT format of `typ` at `uri` that `signer`
/// signs, carrying `list` as the claim `key`.
fn cwt_list(signer: &Authority, typ: &str, uri: &str, key: i64, list: Cbor) -> Vec<u8> {
    let claims = Cbor::Map(vec![
        (int(2), text(uri)),
        (int(6), int(now() - 60)),
        (int(4), int(now() + 3600)),
        (int(key), list),
    ]);
    let mut protected = vec![(int(1), int(-7)), (int(16), text(typ))];
    protected.extend(x5chain(signer));
    let token = sign1(
        &signer.key,
        protected,
        Vec::new(),
        Some(encode(&claims)),
        &[],
    );
    encode(&Cbor::Tag(18, Box::new(token)))
}

/// Returns a Token Status List in CWT format at `uri` in which each index
/// of `revoked` is invalid among 64 credentials (draft-ietf-oauth-status-list-20 §5.2).
fn status_list(signer: &Authority, uri: &str, revoked: &[usize]) -> Vec<u8> {
    let mut bytes = [0_u8; 8];
    for index in revoked {
        *bytes.get_mut(index / 8).expect("within the list") |= 1 << (index % 8);
    }
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&bytes).expect("compresses");
    let list = Cbor::Map(vec![
        (text("bits"), int(1)),
        (
            text("lst"),
            Cbor::Bytes(encoder.finish().expect("compresses")),
        ),
    ]);
    cwt_list(signer, "application/statuslist+cwt", uri, 65533, list)
}

/// Returns an identifier list in CWT format at `uri` holding `identifiers`.
fn identifier_list(signer: &Authority, uri: &str, identifiers: &[&[u8]]) -> Vec<u8> {
    let listed = identifiers
        .iter()
        .map(|id| (Cbor::Bytes(id.to_vec()), Cbor::Map(Vec::new())))
        .collect();
    let list = Cbor::Map(vec![(text("identifiers"), Cbor::Map(listed))]);
    cwt_list(signer, "application/identifierlist+cwt", uri, 65530, list)
}

/// Returns the SHA-256 JWK Thumbprint of the public JWK `jwk` (RFC 7638 §3).
pub(super) fn thumbprint(jwk: &Value) -> Vec<u8> {
    let members = json!({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]});
    sha256(members.to_string().as_bytes())
}

impl Wallet {
    /// Starts FerroSMART asking for the PID as an mdoc alone.
    async fn start_mdoc() -> Self {
        Self::start_with("credential_formats = [\"mso_mdoc\"]\n").await
    }

    /// Returns the session transcript of `begun` by redirect, with `nonce`.
    fn transcript(begun: &Begun, nonce: &str) -> Cbor {
        let thumbprint = thumbprint(&begun.jwk());
        session_transcript(&Handover::Redirect {
            client_id: &begun.text("client_id"),
            nonce,
            thumbprint: &thumbprint,
            response_uri: &begun.text("response_uri"),
        })
    }

    /// Returns the holder's mdoc presentation of `mdoc` for `begun`.
    fn mdoc(&self, mdoc: &Mdoc, begun: &Begun) -> String {
        mdoc.present(
            &self.pki.issuer,
            &self.holder,
            &Self::transcript(begun, &begun.text("nonce")),
        )
    }

    /// Posts the encrypted answer carrying the mdoc `presentation` to
    /// `begun`.
    async fn answer_mdoc(&self, begun: &Begun, presentation: &str) -> (StatusCode, Value) {
        let payload = json!({"vp_token": {MDOC: [presentation]}, "state": begun.text("state")});
        self.post(&[("response", &kit::sealed(&payload, &begun.jwk()))])
            .await
    }

    /// Posts `presentation` to `begun` and checks it is refused as `reason`.
    async fn mdoc_refused(&self, begun: &Begun, presentation: &str, reason: &str) {
        let (status, body) = self.answer_mdoc(begun, presentation).await;
        assert_refused(self, begun, status, &body, reason).await;
    }

    /// Serves `body` of `media_type` at `path` of the status server and
    /// returns its URL.
    async fn serve_list(&self, path: &str, media_type: &str, body: Vec<u8>) -> String {
        Mock::given(matchers::method("GET"))
            .and(matchers::path(path))
            .and(matchers::header("accept", media_type))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", media_type)
                    .set_body_bytes(body),
            )
            .mount(&self.status)
            .await;
        format!("{}{path}", self.status.uri())
    }
}

#[tokio::test]
async fn the_request_asks_for_the_pid_in_both_formats_of_which_the_wallet_presents_one() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let query = &begun.object["dcql_query"];
    let mdoc = &query["credentials"][1];
    assert_eq!("mso_mdoc", mdoc["format"]);
    assert_eq!(MDOC, mdoc["id"]);
    assert_eq!(DOCTYPE, mdoc["meta"]["doctype_value"]);
    assert!(
        mdoc["claims"]
            .as_array()
            .expect("claims")
            .contains(&json!({"path": [DOCTYPE, "personal_administrative_number"]}))
    );
    assert_eq!("aki", mdoc["trusted_authorities"][0]["type"]);
    assert_eq!(
        json!([{"options": [["pid"], [MDOC]]}]),
        query["credential_sets"]
    );
    let formats = &begun.object["client_metadata"]["vp_formats_supported"];
    assert_eq!(
        json!([-7, -9]),
        formats["mso_mdoc"]["issuerauth_alg_values"]
    );
    assert!(formats.get("dc+sd-jwt").is_some(), "{formats}");
    wallet.stop().await;
}

#[tokio::test]
async fn a_pid_presented_as_an_mdoc_logs_the_same_person_in() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let (status, body) = wallet
        .answer_mdoc(&begun, &wallet.mdoc(&Mdoc::pid(), &begun))
        .await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let (status, headers, page) = wallet.come_back(&body, Some(&begun.cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    assert_eq!("/consent", location(&headers).path());
    let pending = wallet
        .smart
        .store
        .pending(&begun.cookie)
        .await
        .expect("reads")
        .expect("the request");
    assert_eq!(
        Some(ferrosmart::upstream::pairwise(kit::PID, "NL:999990019")),
        pending.subject,
        "the same pairwise subject as the SD-JWT VC"
    );
    assert_eq!(Some("Patient/p-1"), pending.fhir_user.as_deref());
    assert_eq!(Some("Eva Jansen"), pending.display_name.as_deref());
    wallet.stop().await;
}

#[tokio::test]
async fn an_mdoc_only_entry_asks_for_no_sd_jwt_vc_and_takes_none() {
    let wallet = Wallet::start_mdoc().await;
    let begun = wallet.begin().await;
    let query = &begun.object["dcql_query"];
    assert_eq!(
        1,
        query["credentials"].as_array().expect("credentials").len()
    );
    assert!(query.get("credential_sets").is_none(), "{query}");
    let presentation = wallet.presentation(&Credential::pid(), &begun);
    let (status, body) = wallet.answer(&begun, &presentation).await;
    assert_refused(&wallet, &begun, status, &body, "malformed_response").await;
    let (status, body) = wallet
        .answer_mdoc(&begun, &wallet.mdoc(&Mdoc::pid(), &begun))
        .await;
    assert_eq!(StatusCode::OK, status, "{body}");
    wallet.stop().await;
}

#[tokio::test]
async fn an_mdoc_with_a_valid_status_or_off_the_identifier_list_is_accepted() {
    let wallet = Wallet::start().await;
    let statuses = wallet
        .serve_list(
            "/mdoc/status/1",
            "application/statuslist+cwt",
            status_list(
                &wallet.pki.issuer,
                &format!("{}/mdoc/status/1", wallet.status.uri()),
                &[3],
            ),
        )
        .await;
    let identifiers = wallet
        .serve_list(
            "/mdoc/identifiers/1",
            "application/identifierlist+cwt",
            identifier_list(
                &wallet.pki.issuer,
                &format!("{}/mdoc/identifiers/1", wallet.status.uri()),
                &[b"someone-else"],
            ),
        )
        .await;
    for status in [
        Cbor::Map(vec![(
            text("status_list"),
            Cbor::Map(vec![(text("idx"), int(7)), (text("uri"), text(&statuses))]),
        )]),
        Cbor::Map(vec![(
            text("identifier_list"),
            Cbor::Map(vec![
                (text("id"), Cbor::Bytes(b"this-mso".to_vec())),
                (text("uri"), text(&identifiers)),
            ]),
        )]),
    ] {
        let begun = wallet.begin().await;
        let mut mdoc = Mdoc::pid();
        mdoc.status = Some(status);
        let (status, body) = wallet
            .answer_mdoc(&begun, &wallet.mdoc(&mdoc, &begun))
            .await;
        assert_eq!(StatusCode::OK, status, "{body}");
    }
    wallet.stop().await;
}

#[tokio::test]
async fn an_mdoc_from_an_issuer_under_another_anchor_is_untrusted() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let presentation = Mdoc::pid().present(
        &wallet.pki.stranger,
        &wallet.holder,
        &Wallet::transcript(&begun, &begun.text("nonce")),
    );
    wallet
        .mdoc_refused(&begun, &presentation, "untrusted_issuer")
        .await;
    wallet.stop().await;
}

#[tokio::test]
async fn an_mdoc_whose_signature_or_digest_does_not_verify_is_invalid() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let mut forged = Mdoc::pid();
    forged.forged = true;
    wallet
        .mdoc_refused(&begun, &wallet.mdoc(&forged, &begun), "invalid_credential")
        .await;
    let mut altered = Mdoc::pid();
    altered.altered = true;
    wallet
        .mdoc_refused(&begun, &wallet.mdoc(&altered, &begun), "invalid_credential")
        .await;
    wallet
        .mdoc_refused(&begun, "not-cbor", "invalid_credential")
        .await;
    wallet.stop().await;
}

#[tokio::test]
async fn an_mdoc_of_another_type_or_with_elements_not_asked_for_is_unrequested() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let mut other = Mdoc::pid();
    other.doctype = String::from("org.iso.18013.5.1.mDL");
    wallet
        .mdoc_refused(
            &begun,
            &wallet.mdoc(&other, &begun),
            "unrequested_credential",
        )
        .await;
    let mut more = Mdoc::pid();
    more.elements
        .push((String::from("resident_address"), text("Damrak 1")));
    wallet
        .mdoc_refused(
            &begun,
            &wallet.mdoc(&more, &begun),
            "unrequested_credential",
        )
        .await;
    let mut elsewhere = Mdoc::pid();
    elsewhere.other_namespace = vec![(String::from("family_name"), text("Jansen"))];
    wallet
        .mdoc_refused(
            &begun,
            &wallet.mdoc(&elsewhere, &begun),
            "unrequested_credential",
        )
        .await;
    wallet.stop().await;
}

#[tokio::test]
async fn an_mdoc_outside_its_validity_is_expired() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let mut past = Mdoc::pid();
    past.validity = (now() - 7200, now() - 10);
    wallet
        .mdoc_refused(&begun, &wallet.mdoc(&past, &begun), "expired")
        .await;
    let mut future = Mdoc::pid();
    future.validity = (now() + 3600, now() + 7200);
    wallet
        .mdoc_refused(&begun, &wallet.mdoc(&future, &begun), "expired")
        .await;
    wallet.stop().await;
}

#[tokio::test]
async fn a_device_signature_over_another_transcript_or_key_is_refused() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    // NOTE: OpenID4VP 1.0 Appendix B.2.6.1, the transcript binds the request's nonce.
    let other_nonce = Mdoc::pid().present(
        &wallet.pki.issuer,
        &wallet.holder,
        &Wallet::transcript(&begun, &format!("{}INVALID", begun.text("nonce"))),
    );
    wallet
        .mdoc_refused(&begun, &other_nonce, "bad_holder_binding")
        .await;
    let thumbprint = thumbprint(&begun.jwk());
    let api_transcript = session_transcript(&Handover::DigitalCredentials {
        origin: "https://smart.example.org",
        nonce: &begun.text("nonce"),
        thumbprint: &thumbprint,
    });
    let other_lane = Mdoc::pid().present(&wallet.pki.issuer, &wallet.holder, &api_transcript);
    wallet
        .mdoc_refused(&begun, &other_lane, "bad_holder_binding")
        .await;
    let someone = signed_by_other_device(&wallet, &begun);
    wallet
        .mdoc_refused(&begun, &someone, "bad_holder_binding")
        .await;
    wallet.stop().await;
}

/// Returns an mdoc whose MSO binds the case's holder and whose device
/// signature another key made.
fn signed_by_other_device(wallet: &Wallet, begun: &Begun) -> String {
    let transcript = Wallet::transcript(begun, &begun.text("nonce"));
    let genuine = Mdoc::pid().present(&wallet.pki.issuer, &wallet.holder, &transcript);
    let stolen = Mdoc::pid().present(&wallet.pki.issuer, &Holder::new(), &transcript);
    let read = |text: &str| -> Cbor {
        ciborium::de::from_reader(URL_SAFE_NO_PAD.decode(text).expect("base64url").as_slice())
            .expect("CBOR")
    };
    let mut response = read(&genuine);
    let mut stolen = read(&stolen);
    let replacement = device_signed(&mut stolen).clone();
    *device_signed(&mut response) = replacement;
    URL_SAFE_NO_PAD.encode(encode(&response))
}

/// Returns the value of the text key `key` of the map `map`.
fn entry<'a>(map: &'a mut Cbor, key: &str) -> Option<&'a mut Cbor> {
    match map {
        Cbor::Map(entries) => entries
            .iter_mut()
            .find(|(name, _)| name.as_text() == Some(key))
            .map(|(_, value)| value),
        _ => None,
    }
}

/// Returns the `deviceSigned` of the one document of `response`.
fn device_signed(response: &mut Cbor) -> &mut Cbor {
    let documents = entry(response, "documents").expect("documents");
    let document = documents
        .as_array_mut()
        .and_then(|documents| documents.first_mut())
        .expect("a document");
    entry(document, "deviceSigned").expect("deviceSigned")
}

#[tokio::test]
async fn an_mdoc_the_status_list_or_identifier_list_names_is_revoked() {
    let wallet = Wallet::start().await;
    let statuses = format!("{}/mdoc/status/2", wallet.status.uri());
    let statuses = wallet
        .serve_list(
            "/mdoc/status/2",
            "application/statuslist+cwt",
            status_list(&wallet.pki.issuer, &statuses, &[7]),
        )
        .await;
    let identifiers = format!("{}/mdoc/identifiers/2", wallet.status.uri());
    let identifiers = wallet
        .serve_list(
            "/mdoc/identifiers/2",
            "application/identifierlist+cwt",
            identifier_list(&wallet.pki.issuer, &identifiers, &[b"decoy", b"this-mso"]),
        )
        .await;
    for status in [
        Cbor::Map(vec![(
            text("status_list"),
            Cbor::Map(vec![(text("idx"), int(7)), (text("uri"), text(&statuses))]),
        )]),
        Cbor::Map(vec![(
            text("identifier_list"),
            Cbor::Map(vec![
                (text("id"), Cbor::Bytes(b"this-mso".to_vec())),
                (text("uri"), text(&identifiers)),
            ]),
        )]),
    ] {
        let begun = wallet.begin().await;
        let mut mdoc = Mdoc::pid();
        mdoc.status = Some(status);
        wallet
            .mdoc_refused(&begun, &wallet.mdoc(&mdoc, &begun), "revoked")
            .await;
    }
    wallet.stop().await;
}

#[tokio::test]
async fn an_mdoc_status_that_cannot_be_read_or_trusted_is_unavailable() {
    let wallet = Wallet::start().await;
    let stranger = format!("{}/mdoc/status/stranger", wallet.status.uri());
    let stranger = wallet
        .serve_list(
            "/mdoc/status/stranger",
            "application/statuslist+cwt",
            status_list(&wallet.pki.stranger, &stranger, &[]),
        )
        .await;
    let missing = format!("{}/mdoc/status/missing", wallet.status.uri());
    let unknown = Cbor::Map(vec![(text("other_mechanism"), Cbor::Map(Vec::new()))]);
    for status in [
        Cbor::Map(vec![(
            text("status_list"),
            Cbor::Map(vec![(text("idx"), int(1)), (text("uri"), text(&stranger))]),
        )]),
        Cbor::Map(vec![(
            text("status_list"),
            Cbor::Map(vec![(text("idx"), int(1)), (text("uri"), text(&missing))]),
        )]),
        unknown,
    ] {
        let begun = wallet.begin().await;
        let mut mdoc = Mdoc::pid();
        mdoc.status = Some(status);
        wallet
            .mdoc_refused(&begun, &wallet.mdoc(&mdoc, &begun), "status_unavailable")
            .await;
    }
    wallet.stop().await;
}

#[tokio::test]
async fn an_mdoc_answered_twice_is_a_replay() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let presentation = wallet.mdoc(&Mdoc::pid(), &begun);
    let (status, body) = wallet.answer_mdoc(&begun, &presentation).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let (status, body) = wallet.answer_mdoc(&begun, &presentation).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
    assert_eq!(json!("replayed_nonce"), body["error_description"], "{body}");
    wallet.stop().await;
}

#[tokio::test]
async fn an_mdoc_without_the_identifier_or_a_claim_asked_for_is_refused() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let mut anonymous = Mdoc::pid();
    anonymous.withheld = vec![String::from("personal_administrative_number")];
    wallet
        .mdoc_refused(
            &begun,
            &wallet.mdoc(&anonymous, &begun),
            "no_administrative_number",
        )
        .await;
    let mut partial = Mdoc::pid();
    partial.withheld = vec![String::from("given_name")];
    wallet
        .mdoc_refused(&begun, &wallet.mdoc(&partial, &begun), "missing_claim")
        .await;
    wallet.stop().await;
}

#[tokio::test]
async fn an_answer_in_both_formats_is_malformed() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let sd_jwt = wallet.presentation(&Credential::pid(), &begun);
    let mdoc = wallet.mdoc(&Mdoc::pid(), &begun);
    let payload =
        json!({"vp_token": {"pid": [sd_jwt], MDOC: [mdoc]}, "state": begun.text("state")});
    let (status, body) = wallet
        .post(&[("response", &kit::sealed(&payload, &begun.jwk()))])
        .await;
    assert_refused(&wallet, &begun, status, &body, "malformed_response").await;
    wallet.stop().await;
}

#[tokio::test]
async fn a_refused_mdoc_is_recorded_without_its_content() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let mut partial = Mdoc::pid();
    partial.withheld = vec![String::from("given_name")];
    wallet
        .mdoc_refused(&begun, &wallet.mdoc(&partial, &begun), "missing_claim")
        .await;
    let recorded = logins(&wallet.smart.store).await;
    let login = recorded.last().expect("recorded");
    for value in ["999990019", "Jansen", DOCTYPE] {
        assert!(!login.contains(value), "no credential content: {login}");
    }
    wallet.stop().await;
}
