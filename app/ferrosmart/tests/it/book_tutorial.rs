// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The book's tutorial, "Your first system client", run against a fresh
//! server: every request the page marks is sent in order, and its answer
//! held to the marker.
//!
//! The page marks its client document with `<!-- book-client -->` before a
//! `json` fence, and each request with `<!-- book-request: NAME status=N
//! [capture=VAR:/pointer] [expect=/pointer=JSON] ... -->` before an `http`
//! fence. In a request, `$ASSERTION` is a fresh client assertion of the
//! page's client and `$VAR` a value an earlier request captured. The case
//! starts the server at the quickstart's issuer and resource, so the page
//! shows the addresses a reader runs. No specification governs the check:
//! our own design.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrosmart::server::{AppState, router};
use ferrosmart::store::Store;
use http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::support::{Database, Keys, audit, config, ec_key, from_client};

/// The page, from the workspace root.
const PAGE: &str = "website/book/src/tutorial/first-system-client.md";

/// The issuer of the quickstart, which the page names.
const ISSUER: &str = "http://localhost:8080";

/// The resource server of the quickstart, which the page names.
const RESOURCE: &str = "http://localhost:8090/fhir";

/// The `kid` the page's key carries.
const KID: &str = "my-key-1";

/// The fewest requests the page holds.
const REQUESTS: usize = 6;

/// One marked request of the page.
#[derive(Debug)]
struct Step {
    /// The marker's name.
    name: String,
    /// The status the answer carries.
    status: u16,
    /// The values to capture, by name and JSON pointer.
    captures: Vec<(String, String)>,
    /// The JSON pointers the answer holds, each with its value.
    expects: Vec<(String, Value)>,
    /// The `http` block that follows the marker.
    request: String,
}

/// Returns the fenced block that opens at or after `from` in `lines`, with
/// the language `language`.
fn fence(lines: &[&str], from: usize, language: &str) -> String {
    let open = format!("```{language}");
    let start = lines
        .iter()
        .skip(from)
        .position(|line| line.trim() == open)
        .map(|offset| from + offset + 1)
        .expect("a fence follows the marker");
    lines
        .iter()
        .skip(start)
        .take_while(|line| line.trim() != "```")
        .copied()
        .collect::<Vec<_>>()
        .join("\n")
}

/// Returns the marker of `line`, the text between `<!-- book-request:` and
/// `-->`, when it is one.
fn marker(line: &str) -> Option<&str> {
    line.trim()
        .strip_prefix("<!-- book-request:")?
        .strip_suffix("-->")
        .map(str::trim)
}

/// Returns the page's client document and its marked requests, in order.
fn read_page() -> (Value, Vec<Step>) {
    let text = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(PAGE),
    )
    .expect("the tutorial page reads");
    let lines: Vec<&str> = text.lines().collect();
    let mut client = None;
    let mut steps = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if line.trim() == "<!-- book-client -->" {
            let document: Value =
                serde_json::from_str(&fence(&lines, index, "json")).expect("the client is JSON");
            client = Some(document);
            continue;
        }
        let Some(spec) = marker(line) else {
            continue;
        };
        let mut words = spec.split_whitespace();
        let name = words.next().expect("a marker names its request").to_owned();
        let mut step = Step {
            name,
            status: 0,
            captures: Vec::new(),
            expects: Vec::new(),
            request: fence(&lines, index, "http"),
        };
        for word in words {
            let (key, value) = word.split_once('=').expect("a marker word is key=value");
            match key {
                "status" => step.status = value.parse().expect("a status"),
                "capture" => {
                    let (var, pointer) = value.split_once(':').expect("capture=VAR:/pointer");
                    step.captures.push((var.to_owned(), pointer.to_owned()));
                }
                "expect" => {
                    let (pointer, literal) = value.split_once('=').expect("expect=/pointer=JSON");
                    let expected = serde_json::from_str(literal).expect("an expected JSON value");
                    step.expects.push((pointer.to_owned(), expected));
                }
                other => assert!(
                    other.is_empty(),
                    "a marker word the case does not read: {other}"
                ),
            }
        }
        steps.push(step);
    }
    (client.expect("the page holds a client document"), steps)
}

/// Returns `request` with each `$VAR` of `values` and every `$ASSERTION`
/// replaced, an assertion of `key` drawn fresh for each.
fn filled(request: &str, values: &BTreeMap<String, String>, key: &AssertionKey) -> String {
    let mut text = request.to_owned();
    for (var, value) in values {
        text = text.replace(&format!("${var}"), value);
    }
    while text.contains("$ASSERTION") {
        let now = jiff::Timestamp::now().as_second();
        let mut jti = [0_u8; 16];
        aws_lc_rs::rand::fill(&mut jti).expect("the random source draws");
        let claims = json!({
            "iss": "first-system",
            "sub": "first-system",
            "aud": format!("{ISSUER}/token"),
            "exp": now + 120,
            "jti": jti.iter().fold(String::new(), |mut text, byte| {
                use std::fmt::Write as _;
                write!(text, "{byte:02x}").expect("a String takes every write");
                text
            }),
        });
        let assertion = key.sign("JWT", &claims).expect("the assertion signs");
        text = text.replacen("$ASSERTION", &assertion, 1);
    }
    text
}

/// Returns the request the `http` block `text` writes: its request line,
/// its headers, and its body, each body line trimmed and joined.
fn request_of(text: &str) -> Request<Body> {
    let mut lines = text.lines();
    let line = lines.next().expect("a request line");
    let mut parts = line.split_whitespace();
    let method: Method = parts
        .next()
        .expect("a method")
        .parse()
        .expect("a known method");
    let target = parts.next().expect("a target");
    let mut builder = Request::builder().method(method).uri(target);
    for header_line in lines.by_ref() {
        if header_line.trim().is_empty() {
            break;
        }
        let (name, value) = header_line.split_once(':').expect("a header line");
        builder = builder.header(name.trim(), value.trim());
    }
    let body: String = lines.map(str::trim).collect();
    builder.body(Body::from(body)).expect("a request")
}

/// Returns the JSON text of `value` at `pointer` for a capture.
fn captured(value: &Value, pointer: &str) -> String {
    match value
        .pointer(pointer)
        .expect("the answer holds the captured pointer")
    {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

#[tokio::test]
async fn the_tutorial_runs_as_the_book_shows_it() {
    let (mut client, steps) = read_page();
    assert!(
        steps.len() >= REQUESTS,
        "{PAGE} holds {} marked requests, fewer than {REQUESTS}",
        steps.len()
    );
    let keys = Keys::new();
    let pem = std::fs::read(ec_key(keys.dir.path(), "first-system.pem")).expect("the key reads");
    let key = AssertionKey::from_pem(
        &pem,
        Some(ferrohealth_smart::jws::algorithm::Algorithm::Es384),
        Some(String::from(KID)),
    )
    .expect("the client's key");
    client["jwks"] = json!({"keys": [key.public_jwk()]});
    let database = Database::create().await;
    let text = format!(
        "[ferrosmart]\nissuer = {ISSUER:?}\n[ferrosmart.database]\nurl = {:?}\n\
         [[ferrosmart.resource]]\nbase = {RESOURCE:?}\nkind = \"fhir\"\n",
        secrecy::ExposeSecret::expose_secret(&database.url)
    );
    let settings = config(&text, &keys).resolve().expect("resolves");
    let store = Store::connect(&settings.database_url, 2)
        .await
        .expect("connects");
    store.migrate().await.expect("migrates");
    let state = Arc::new(AppState::new(
        settings.clone(),
        store.clone(),
        audit(&settings),
    ));
    crate::support::apply(&state, &[client]).await;
    let app = router(state);
    let mut values = BTreeMap::new();
    for step in &steps {
        let request = request_of(&filled(&step.request, &values, &key));
        let response = app
            .clone()
            .oneshot(from_client(request))
            .await
            .expect("an answer");
        let status = response.status();
        let content_type = response.headers().get(header::CONTENT_TYPE).cloned();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("the body")
            .to_bytes();
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        assert_eq!(
            StatusCode::from_u16(step.status).expect("a status"),
            status,
            "step {}: the answer {body} ({content_type:?})",
            step.name
        );
        for (pointer, expected) in &step.expects {
            assert_eq!(
                Some(expected),
                body.pointer(pointer),
                "step {}: {pointer} in {body}",
                step.name
            );
        }
        for (var, pointer) in &step.captures {
            values.insert(var.clone(), captured(&body, pointer));
        }
    }
    database.drop(store).await;
}
