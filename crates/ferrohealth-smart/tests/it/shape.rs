// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The token shape each profile accepts, test-first against the official
//! examples: the RFC 9068 Figure 2 header and claims set re-signed with a
//! test key, and tokens shaped as the Entra ID, Okta and Keycloak documents
//! show them.

use std::error::Error as StdError;

use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::profile::Marker;
use ferrohealth_smart::profile::Preset;
use ferrohealth_smart::profile::Profile;
use ferrohealth_smart::profile::ProfileKeys;
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
    let mut settings = Settings::new(issuer, audience, IssuerKind::Persons);
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

/// Returns `preset`'s profile.
fn profile(preset: Preset) -> Result<Profile, Box<dyn StdError>> {
    Ok(Profile::resolve(preset, &ProfileKeys::default())?)
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
    let caller = admit(&key, "at+JWT", &figure_2(), profile(Preset::Rfc9068)?).await?;
    assert_eq!("5ba552d67", caller.subject(), "the resource owner");
    assert_eq!(Some("s6BhdRkqt3"), caller.client_id());
    assert_eq!(&CallerKind::Person, caller.kind());
    assert!(caller.has_scope("reademail"));
    Ok(())
}

// NOTE: RFC 9068 §4: the resource server "MUST verify that the typ header value
// is at+jwt or application/at+jwt and reject tokens carrying any other value".
#[tokio::test]
async fn the_figure_2_token_typed_jwt_is_refused() -> Outcome {
    let key = rsa_key("RjEwOwOA", Algorithm::RS256);
    let outcome = admit(&key, "JWT", &figure_2(), profile(Preset::Rfc9068)?).await;
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
        let outcome = admit(&key, "at+jwt", &claims, profile(Preset::Rfc9068)?).await;
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

/// The claims of an Entra ID v2.0 user token, as the "Access token claims
/// reference" payload table names them.
fn entra_user() -> Value {
    json!({
        "aud": "api://ehr.example.org",
        "iss": "https://login.example.org/tenant-1/v2.0",
        "iat": now(), "nbf": now(), "exp": now() + 300,
        "azp": "first-party-app", "azpacr": "0",
        "name": "Synthetic Person", "oid": "oid-1", "preferred_username": "synthetic",
        "scp": "user/Observation.rs openid",
        "sub": "pairwise-1", "tid": "tenant-1", "uti": "uti-1", "ver": "2.0",
        "acct": 0
    })
}

// NOTE: Microsoft, "Access token claims reference": header `typ` "always `JWT`",
// `scp` "a space separated list of scopes", and `azp` naming the client.
#[tokio::test]
async fn an_entra_v2_token_without_client_id_passes_the_entra_profile() -> Outcome {
    let key = rsa_key("entra-kid", Algorithm::RS256);
    let caller = admit(&key, "JWT", &entra_user(), profile(Preset::Entra)?).await?;
    assert_eq!(&CallerKind::Person, caller.kind());
    assert_eq!(Some("first-party-app"), caller.client_id());
    assert!(caller.has_scope("user/Observation.rs"));
    let refused = admit(&key, "JWT", &entra_user(), profile(Preset::Rfc9068)?).await;
    assert!(
        matches!(
            refused,
            Err(Rejection::Invalid {
                reason: Reason::Type
            })
        ),
        "the same token fails the RFC 9068 core: {refused:?}"
    );
    Ok(())
}

// NOTE: Microsoft, "Access token claims reference": the client credentials flow
// carries "this set of permission in place of user scopes" in `roles`.
#[tokio::test]
async fn an_entra_app_only_token_carries_its_permissions_in_roles() -> Outcome {
    let key = rsa_key("entra-kid", Algorithm::RS256);
    let mut claims = entra_user();
    let object = claims.as_object_mut().ok_or("an object")?;
    for claim in ["scp", "name", "preferred_username", "acct"] {
        object.remove(claim);
    }
    object.insert(String::from("idtyp"), json!("app"));
    object.insert(String::from("roles"), json!(["system/Observation.rs"]));
    let caller = admit(&key, "JWT", &claims, profile(Preset::Entra)?).await?;
    assert_eq!(&CallerKind::System, caller.kind());
    assert!(caller.has_scope("system/Observation.rs"));
    Ok(())
}

// NOTE: Okta, "OpenID Connect & OAuth 2.0 API": `scp` is an "Array of scopes",
// `cid` the client and `uid` the user.
#[tokio::test]
async fn an_okta_token_with_scp_as_an_array_passes() -> Outcome {
    let key = rsa_key("okta-kid", Algorithm::RS256);
    let mut okta = profile(Preset::Okta)?;
    okta.token_types = vec![String::from("JWT")];
    let claims = json!({
        "ver": 1, "jti": "AT.synthetic", "iss": "https://example.okta.com/oauth2/default",
        "aud": "api://default", "iat": now(), "exp": now() + 300,
        "cid": "first-party-app", "uid": "00u-synthetic", "sub": "person@example.org",
        "scp": ["openid", "user/Observation.rs"]
    });
    let caller = admit(&key, "JWT", &claims, okta.clone()).await?;
    assert_eq!(&CallerKind::Person, caller.kind());
    assert!(caller.has_scope("user/Observation.rs"));
    let mut string = claims.clone();
    string["scp"] = json!("openid user/Observation.rs");
    assert!(
        matches!(
            admit(&key, "JWT", &string, okta).await,
            Err(Rejection::Unclassified { .. })
        ),
        "a string where the profile reads an array"
    );
    Ok(())
}

// NOTE: Keycloak 26.8.2 `con-protocol-mappers.adoc`, "Using lightweight access
// token": `exp`, `iat`, `jti`, `iss`, `typ`, `azp`, `sid` and `scope` stay.
#[tokio::test]
async fn a_keycloak_token_of_the_lightweight_claims_passes() -> Outcome {
    let key = rsa_key("keycloak-kid", Algorithm::RS256);
    let mut keycloak = profile(Preset::Keycloak)?;
    keycloak.app_only = vec![Marker::Subjects(vec![String::from("service-account-sub")])];
    let claims = json!({
        "exp": now() + 300, "iat": now(), "jti": "onrtac:synthetic",
        "iss": "https://kc.example.org/realms/ferro", "aud": "ehr", "sub": "user-uuid",
        "typ": "Bearer", "azp": "first-party-app", "sid": "session-1",
        "scope": "openid user/Observation.rs"
    });
    let caller = admit(&key, "JWT", &claims, keycloak).await?;
    assert_eq!(&CallerKind::Person, caller.kind());
    assert_eq!(Some("first-party-app"), caller.client_id());
    Ok(())
}
