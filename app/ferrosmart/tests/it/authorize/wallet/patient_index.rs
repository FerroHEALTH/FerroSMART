// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The patient of a wallet login resolved at a stub FerroPIX (#857): the
//! PID's administrative number cross-referenced by PIXm or PDQm into the
//! FHIR server's own system, that identifier searched there, and the launch
//! refused when the index finds no patient or several.

use super::mdoc::{self, Mdoc};
use super::*;

/// The system of the FHIR server's own patients in the index.
const HOSPITAL: &str = "urn:example:hospital";

/// The wallet table naming the system of Dutch administrative numbers.
const SYSTEMS: &str = "identifier_systems = { NL = \"http://fhir.nl/fhir/NamingSystem/bsn\" }\n";

impl Wallet {
    /// Starts FerroSMART with the FHIR server's patient index on its own
    /// mock, asked by `transaction`, the wallet table ending with
    /// `wallet_extra`, and the FHIR server finding `h-7` of the hospital
    /// alone.
    async fn start_indexed(transaction: &str, wallet_extra: &str) -> Self {
        let pix = MockServer::start().await;
        let resource = format!(
            "[ferrosmart.resource.patient_index]\nbase = \"{}/pix\"\n\
             transaction = {transaction:?}\nsystem = {HOSPITAL:?}\n",
            pix.uri()
        );
        let mut wallet = Self::start_at(
            |pki, dir| {
                format!(
                    "issuer_anchor_files = [{}]\n{SYSTEMS}{wallet_extra}",
                    written(dir, "pid-root.pem", &pki.pid_root.pem)
                )
            },
            &resource,
        )
        .await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/fhir/Patient"))
            .and(matchers::query_param(
                "identifier",
                format!("{HOSPITAL}|h-7"),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resourceType": "Bundle",
                "type": "searchset",
                "entry": [{"resource": {"resourceType": "Patient", "id": "p-7"}}],
            })))
            .mount(&wallet.fhir)
            .await;
        // NOTE: FHIR R4 search, a search that matches nothing answers an empty searchset.
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/fhir/Patient"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    json!({"resourceType": "Bundle", "type": "searchset", "total": 0}),
                ),
            )
            .with_priority(10)
            .mount(&wallet.fhir)
            .await;
        wallet.pix = Some(pix);
        wallet
    }

    /// Returns the patient index mock.
    fn pix(&self) -> &MockServer {
        self.pix.as_ref().expect("an index")
    }

    /// Comes back from the wallet's accepted answer `answered` and returns
    /// where the browser is sent.
    async fn log_in_with(&self, begun: &Begun, answered: (StatusCode, Value)) -> Url {
        let (status, body) = answered;
        assert_eq!(StatusCode::OK, status, "{body}");
        let (status, headers, page) = self.come_back(&body, Some(&begun.cookie)).await;
        assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
        location(&headers)
    }

    /// Returns the request `begun` left, after the login.
    async fn pending_of(&self, begun: &Begun) -> ferrosmart::store::Pending {
        self.smart
            .store
            .pending(&begun.cookie)
            .await
            .expect("reads")
            .expect("the request")
    }
}

/// Returns the claims of the bearer token the index received at `path`.
async fn token_at(pix: &MockServer, path: &str) -> Value {
    let received = pix.received_requests().await.expect("recorded");
    let request = received
        .iter()
        .find(|request| request.url.path() == path)
        .expect("the index was asked");
    let bearer = request
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .expect("a bearer token");
    read_jws(bearer).1
}

/// Mounts the ITI-83 answer `status` with `body` at the index.
async fn pixm_answers(pix: &MockServer, status: u16, body: Value) {
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/pix/Patient/$ihe-pix"))
        .and(matchers::query_param(
            "sourceIdentifier",
            format!("{BSN}|999990019"),
        ))
        .and(matchers::query_param("targetSystem", HOSPITAL))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(pix)
        .await;
}

/// Returns the ITI-83 answer naming the hospital identifiers `values`.
fn cross_reference(values: &[&str]) -> Value {
    let mut parameter: Vec<Value> = values
        .iter()
        .map(|value| json!({"name": "targetIdentifier", "valueIdentifier": {"system": HOSPITAL, "value": value}}))
        .collect();
    parameter
        .push(json!({"name": "targetId", "valueReference": {"reference": "Patient/person-1"}}));
    json!({"resourceType": "Parameters", "parameter": parameter})
}

#[tokio::test]
async fn pixm_resolves_an_sd_jwt_vc_login_to_the_patient_of_the_fhir_server() {
    let wallet = Wallet::start_indexed("pixm", "").await;
    pixm_answers(wallet.pix(), 200, cross_reference(&["h-7"])).await;
    let begun = wallet.begin().await;
    let presentation = wallet.presentation(&Credential::pid(), &begun);
    let to = wallet
        .log_in_with(&begun, wallet.answer(&begun, &presentation).await)
        .await;
    assert_eq!("/consent", to.path());
    let pending = wallet.pending_of(&begun).await;
    assert_eq!(
        Some("Patient/p-7"),
        pending.fhir_user.as_deref(),
        "the index's cross-reference, never the BSN search at the FHIR server"
    );
    let token = token_at(wallet.pix(), "/pix/Patient/$ihe-pix").await;
    assert_eq!(json!("system/Patient.rs"), token["scope"]);
    assert_eq!(json!(ISSUER), token["sub"], "FerroSMART asks as itself");
    assert_eq!(json!(ISSUER), token["client_id"]);
    assert!(token.get("fhirUser").is_none(), "{token}");
    let person = &pending.person_claims;
    assert_eq!(
        (Some("Eva"), Some("Jansen"), Some("1980-04-02")),
        (
            person.given_name.as_deref(),
            person.family_name.as_deref(),
            person.birthdate.as_deref()
        ),
        "the PID's names and birth date as the subject's claims"
    );
    wallet.stop().await;
}

#[tokio::test]
async fn pdqm_resolves_an_mdoc_login_to_the_same_patient() {
    let elements = "mdoc_claims = [\"family_name\", \"given_name\", \"birth_date\", \
                    \"nationality\", \"personal_administrative_number\", \"issuing_country\"]\n";
    let wallet = Wallet::start_indexed("pdqm", elements).await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/pix/Patient"))
        .and(matchers::query_param(
            "identifier",
            format!("{BSN}|999990019"),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "resourceType": "Bundle",
            "type": "searchset",
            "entry": [{"resource": {"resourceType": "Patient", "id": "person-1", "identifier": [
                {"system": BSN, "value": "999990019"},
                {"system": HOSPITAL, "value": "h-7"},
            ]}}],
        })))
        .mount(wallet.pix())
        .await;
    let begun = wallet.begin().await;
    let mut mdoc = Mdoc::pid();
    mdoc.elements
        .push((String::from("nationality"), mdoc::texts(&["NL", "BE"])));
    let presentation = wallet.mdoc(&mdoc, &begun);
    let to = wallet
        .log_in_with(&begun, wallet.answer_mdoc(&begun, &presentation).await)
        .await;
    assert_eq!("/consent", to.path());
    let pending = wallet.pending_of(&begun).await;
    assert_eq!(Some("Patient/p-7"), pending.fhir_user.as_deref());
    let token = token_at(wallet.pix(), "/pix/Patient").await;
    assert_eq!(json!("system/Patient.rs"), token["scope"]);
    let person = &pending.person_claims;
    assert_eq!(
        Some("1980-04-02"),
        person.birthdate.as_deref(),
        "the mdoc's birth_date as birthdate"
    );
    assert_eq!(
        Some(json!(["NL", "BE"])),
        person.nationalities,
        "the mdoc's nationality as nationalities"
    );
    wallet.stop().await;
}

/// Logs in through an index whose ITI-83 answers `status` with `body` and
/// checks the app is sent `error` with no code.
async fn refused(status: u16, body: Value, error: &str) {
    let wallet = Wallet::start_indexed("pixm", "").await;
    pixm_answers(wallet.pix(), status, body).await;
    let begun = wallet.begin().await;
    let presentation = wallet.presentation(&Credential::pid(), &begun);
    let back = wallet
        .log_in_with(&begun, wallet.answer(&begun, &presentation).await)
        .await;
    assert!(back.as_str().starts_with(REDIRECT), "{back}");
    assert_eq!(Some(error.to_owned()), param(&back, "error"), "{back}");
    assert_eq!(None, param(&back, "code"), "no code: {back}");
    let recorded = logins(&wallet.smart.store).await;
    let login = recorded.last().expect("the refusal is recorded");
    assert!(login.contains("patient index"), "{login}");
    assert!(!login.contains("999990019"), "{login}");
    wallet.stop().await;
}

/// Returns an `OperationOutcome` with one error issue of `code`.
fn outcome(code: &str) -> Value {
    json!({"resourceType": "OperationOutcome", "issue": [{"severity": "error", "code": code}]})
}

#[tokio::test]
async fn an_identifier_the_index_does_not_know_refuses_the_launch() {
    Box::pin(refused(404, outcome("not-found"), "access_denied")).await;
}

#[tokio::test]
async fn an_identifier_of_several_patients_refuses_the_launch() {
    let several = cross_reference(&["h-7", "h-8"]);
    Box::pin(refused(200, several, "access_denied")).await;
}

#[tokio::test]
async fn an_index_answering_several_persons_refuses_the_launch() {
    Box::pin(refused(409, outcome("multiple-matches"), "access_denied")).await;
}

#[tokio::test]
async fn a_cross_reference_into_no_patient_of_the_fhir_server_refuses_the_launch() {
    Box::pin(refused(200, cross_reference(&["h-9"]), "access_denied")).await;
}

#[tokio::test]
async fn an_index_that_fails_refuses_the_launch_as_the_server_error() {
    Box::pin(refused(500, json!({}), "server_error")).await;
}

#[tokio::test]
async fn a_country_with_no_identifier_system_refuses_the_launch() {
    let wallet = Wallet::start_indexed("pixm", "").await;
    let begun = wallet.begin().await;
    let mut credential = Credential::pid();
    for (name, value) in &mut credential.claims {
        if name == "issuing_country" {
            *value = json!("BE");
        }
    }
    let presentation = wallet.presentation(&credential, &begun);
    let back = wallet
        .log_in_with(&begun, wallet.answer(&begun, &presentation).await)
        .await;
    assert_eq!(Some("access_denied".to_owned()), param(&back, "error"));
    let received = wallet.pix().received_requests().await.expect("recorded");
    assert!(received.is_empty(), "the index is never asked");
    wallet.stop().await;
}

#[tokio::test]
async fn a_patient_index_is_for_a_fhir_base_with_absolute_urls() {
    let keys = Keys::new();
    let resource = |table: &str| {
        format!(
            "[ferrosmart]\nissuer = {ISSUER:?}\n[ferrosmart.database]\nurl = {:?}\n\
             [[ferrosmart.resource]]\nbase = \"https://fhir.example.org\"\n{table}\
             [ferrosmart.resource.patient_index]\nbase = \"https://pix.example.org/fhir\"\nsystem = {HOSPITAL:?}\n",
            crate::support::UNREACHED_DATABASE
        )
    };
    let openehr = config(&resource("kind = \"openehr\"\n"), &keys)
        .resolve()
        .expect_err("refused");
    assert!(openehr.to_string().contains("FHIR base"), "{openehr}");
    let relative = resource("").replace("https://pix.example.org/fhir", "pix");
    let refused = config(&relative, &keys).resolve().expect_err("refused");
    assert!(refused.to_string().contains("absolute URL"), "{refused}");
    let systems = format!(
        "[ferrosmart]\nissuer = {ISSUER:?}\n[ferrosmart.database]\nurl = {:?}\n\
         [[ferrosmart.upstream]]\nname = \"wallet\"\n[ferrosmart.upstream.openid4vp]\n\
         identifier_systems = {{ nl = \"http://fhir.nl/fhir/NamingSystem/bsn\" }}\n",
        crate::support::UNREACHED_DATABASE
    );
    let refused = config(&systems, &keys).resolve().expect_err("refused");
    assert!(refused.to_string().contains("alpha-2"), "{refused}");
}
