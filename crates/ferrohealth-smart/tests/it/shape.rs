// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The token shape the resource server accepts, test-first against the
//! official example: the RFC 9068 Figure 2 header and claims set re-signed
//! with a test key.

use std::error::Error as StdError;

use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::profile::Profile;
use ferrohealth_smart::refusal::Reason;
use ferrohealth_smart::resource::Caller;
use ferrohealth_smart::resource::Rejection;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::Settings;
use jsonwebtoken::Algorithm;
use jsonwebtoken::Header;
use serde_json::Value;
use serde_json::json;

use crate::support::SigningKey;
use crate::support::mint_with;
use crate::support::now;
use crate::support::rsa_key;
use crate::support::temp_file;

type Outcome = Result<(), Box<dyn StdError>>;

/// Returns the caller `claims`, signed by `key` under `typ`, authenticate at
/// the `persons` issuer and for the audience they name, under `profile`.
async fn admit(
    key: &SigningKey,
    typ: &str,
    claims: &Value,
    profile: Profile,
) -> Result<Caller, Rejection> {
    let text = |claim: &str| {
        claims
            .get(claim)
            .and_then(Value::as_str)
            .unwrap_or_default()
    };
    let (issuer, audience) = (text("iss"), text("aud"));
    let set = json!({ "keys": [key.jwk.clone()] }).to_string();
    let mut settings = Settings::new(issuer, audience, IssuerKind::Smart);
    settings.jwks_file = Some(temp_file("shape-jwks.json", set.as_bytes()));
    settings.profile = profile;
    let server = ResourceServer::discover(settings)
        .await
        .expect("the key set file reads");
    let mut header = Header::new(key.alg);
    header.kid = Some(key.kid.clone());
    header.typ = Some(typ.to_owned());
    server.authenticate(&mint_with(key, &header, claims)).await
}

/// Returns the default profile with the required claims of RFC 9068 §2.2
/// alone: Figure 2 carries `scope`, which the section lists as OPTIONAL.
fn profile() -> Profile {
    let mut profile = Profile::default();
    profile.required_claims.retain(|claim| claim != "scope");
    profile
}

/// The RFC 9068 Figure 2 claims set, its `exp` and `iat` moved to the
/// present: the figure's lie in 2021, which every check would refuse.
fn figure_2() -> Value {
    json!({
        "iss": "https://authorization-server.example.com/",
        "sub": "5ba552d67",
        "aud": "https://rs.example.com/",
        "exp": now() + 300,
        "iat": now(),
        "jti": "dbe39bf3a3ba4238a513f51d6e1691c4",
        "client_id": "s6BhdRkqt3",
        "scope": "openid profile reademail"
    })
}

// NOTE: RFC 9068 §3 Figure 2 is the header {"typ":"at+JWT","alg":"RS256",
// "kid":"RjEwOwOA"} and its claims; §4 accepts `typ` "at+jwt", case aside.
#[tokio::test]
async fn the_rfc_9068_figure_2_token_passes_the_core() -> Outcome {
    let key = rsa_key("RjEwOwOA", Algorithm::RS256);
    let caller = admit(&key, "at+JWT", &figure_2(), profile()).await?;
    assert_eq!("5ba552d67", caller.subject(), "the resource owner");
    assert_eq!(Some("s6BhdRkqt3"), caller.client_id());
    assert_eq!(&CallerKind::User, caller.kind(), "a user with no fhirUser");
    assert!(caller.has_scope("reademail"));
    Ok(())
}

// NOTE: RFC 9068 §4: the resource server "MUST verify that the typ header value
// is at+jwt or application/at+jwt and reject tokens carrying any other value".
#[tokio::test]
async fn the_figure_2_token_typed_jwt_is_refused() -> Outcome {
    let key = rsa_key("RjEwOwOA", Algorithm::RS256);
    let outcome = admit(&key, "JWT", &figure_2(), profile()).await;
    assert!(
        matches!(
            outcome,
            Err(Rejection::Invalid {
                reason: Reason::Type
            })
        ),
        "{outcome:?}"
    );
    Ok(())
}

// NOTE: RFC 9068 §2.2 lists `client_id`, `iat` and `jti` as REQUIRED.
#[tokio::test]
async fn the_figure_2_token_without_a_required_claim_is_refused() -> Outcome {
    let key = rsa_key("RjEwOwOA", Algorithm::RS256);
    for claim in ["client_id", "iat", "jti"] {
        let mut claims = figure_2();
        claims.as_object_mut().ok_or("an object")?.remove(claim);
        let outcome = admit(&key, "at+jwt", &claims, profile()).await;
        assert!(
            matches!(
                outcome,
                Err(Rejection::Invalid {
                    reason: Reason::MissingClaim
                })
            ),
            "{claim}: {outcome:?}"
        );
    }
    Ok(())
}
