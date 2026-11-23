// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A `DPoP`-bound token checked by introspection (RFC 9449 §6.2): the
//! response's `cnf.jkt` held to the proof, `token_type = DPoP` admitted
//! with it, and a held response checked again on every request.

use std::error::Error as StdError;

use ferrohealth_smart::client::ClientCredentials;
use ferrohealth_smart::client::Endpoint;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::refusal::Reason;
use ferrohealth_smart::resource::Rejection;
use ferrohealth_smart::resource::introspection::IntrospectionAuth;
use ferrohealth_smart::resource::introspection::IntrospectionSettings;
use ferrohealth_smart::resource::introspection::Introspector;
use ferrohealth_smart::sender::Check;
use ferrohealth_smart::sender::SenderConstraint;
use ferrohealth_smart::sender::proof::Presented;
use http::Method;
use secrecy::SecretString;
use serde_json::Value;
use serde_json::json;
use wiremock::Mock;
use wiremock::ResponseTemplate;
use wiremock::matchers::method;
use wiremock::matchers::path;

use super::EXTERNAL;
use super::assert_refused;
use super::check;
use super::dpop_key;
use super::proof;
use super::proof_claims;
use super::proofs;
use crate::support::AUDIENCE;
use crate::support::CLIENT;
use crate::support::Issuer;
use crate::support::now;

/// The access token of RFC 9449 Figure 13, opaque to the resource server.
const TOKEN: &str = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";

/// Returns an issuer whose introspection endpoint answers the response
/// `build` makes for it.
async fn answering(build: impl FnOnce(&Issuer) -> Value) -> Issuer {
    let issuer = Issuer::bare().await;
    issuer
        .mount_metadata("/.well-known/oauth-authorization-server")
        .await;
    let response = build(&issuer);
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .mount(&issuer.server)
        .await;
    issuer
}

/// Returns the introspector of `issuer` under `constraint`.
async fn introspector(
    issuer: &Issuer,
    constraint: SenderConstraint,
) -> Result<Introspector, Box<dyn StdError>> {
    let auth = IntrospectionAuth::Client(Box::new(ClientCredentials::new(
        Endpoint::Issuer(issuer.uri()),
        String::from("ferro-rs"),
        SecretString::from("synthetic-secret"),
    )));
    let mut settings =
        IntrospectionSettings::new(issuer.uri(), AUDIENCE, auth, IssuerKind::Persons);
    settings.sender_constraint = constraint;
    Ok(Introspector::discover(settings).await?)
}

/// Returns the RFC 9449 Figure 11 response with its times moved to now,
/// the members SMART App Launch 2.2.0 requires added, and `cnf.jkt` the
/// test key's, since the figure's key is not published.
fn figure_11(issuer: &Issuer, jkt: &str, token_type: Option<&str>) -> Value {
    let mut response = json!({
        "active": true,
        "sub": "someone@example.com",
        "iss": issuer.uri(),
        "nbf": now() - 5,
        "exp": now() + 300,
        "cnf": { "jkt": jkt },
        "scope": "system/Observation.rs",
        "client_id": CLIENT,
    });
    if let Some(token_type) = token_type
        && let Some(members) = response.as_object_mut()
    {
        members.insert(String::from("token_type"), json!(token_type));
    }
    response
}

#[tokio::test]
async fn an_introspected_dpop_token_is_admitted_with_its_proof() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 9449 §6.2, the response's `cnf.jkt` binds the token and its
    // `token_type`, when present, "MUST contain the value DPoP".
    let key = dpop_key();
    for token_type in [None, Some("DPoP")] {
        let issuer = answering(|issuer| figure_11(issuer, &key.jkt, token_type)).await;
        let introspector = introspector(&issuer, SenderConstraint::Required).await?;
        let htu = format!("{EXTERNAL}/protectedresource");
        let headers = proofs(&[&proof(&key, &proof_claims("GET", &htu, TOKEN))]);
        let caller = check()
            .authenticate(
                &introspector,
                &Presented {
                    method: &Method::GET,
                    path: "/protectedresource",
                    headers: &headers,
                    token: TOKEN,
                    certificate: None,
                },
            )
            .await?;
        assert_eq!("someone@example.com", caller.subject(), "{token_type:?}");
        assert_refused(
            &introspector.authenticate(TOKEN).await,
            Check::KeyBoundAsBearer,
            "the held response, now as bearer",
        );
    }
    Ok(())
}

/// Builds a response for an issuer and a `jkt`.
type Build = fn(&Issuer, &str) -> Value;

#[tokio::test]
async fn a_token_type_that_disagrees_with_cnf_is_refused() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 9449 §6.2, a DPoP-bound response names `DPoP`, and a `DPoP`
    // response without a `jkt` binds the token to nothing.
    let key = dpop_key();
    let cases: [(&str, Build); 2] = [
        ("a bound bearer", |issuer, jkt| {
            figure_11(issuer, jkt, Some("Bearer"))
        }),
        ("an unbound DPoP", |issuer, jkt| {
            let mut response = figure_11(issuer, jkt, Some("DPoP"));
            if let Some(members) = response.as_object_mut() {
                members.remove("cnf");
            }
            response
        }),
    ];
    for (name, build) in cases {
        let issuer = answering(|issuer| build(issuer, &key.jkt)).await;
        let outcome = introspector(&issuer, SenderConstraint::None)
            .await?
            .authenticate(TOKEN)
            .await;
        assert!(
            matches!(
                outcome,
                Err(Rejection::Invalid {
                    reason: Reason::Type
                })
            ),
            "{name}: {outcome:?}"
        );
    }
    Ok(())
}
