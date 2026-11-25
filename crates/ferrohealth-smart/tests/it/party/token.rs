// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A signed token in, its caller read from its standard claims, its login
//! looked up by its `sub`, and its party out.

use std::error::Error as StdError;
use std::sync::Arc;

use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrohealth_smart::jws::compact::Header;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::party::Markers;
use ferrohealth_smart::party::Membership;
use ferrohealth_smart::party::PartyRef;
use ferrohealth_smart::party::binding::PartyBinding;
use ferrohealth_smart::party::source::Lookup;
use ferrohealth_smart::party::source::PartySource;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::Settings;
use serde_json::json;

use super::FakeSource;
use super::ISSUER;
use super::LOGIN;
use super::bound;
use super::record;
use super::table;
use crate::support::ec_key;
use crate::support::mint_with;
use crate::support::now;
use crate::support::temp_file;

/// The audience of the case.
const AUDIENCE: &str = "api://ferro";
/// The deployment's own client.
const CLIENT: &str = "first-party-app";

// NOTE: OpenID Connect Core 1.0 §5.7: `sub` is the stable identifier of the
// End-User; the table's `guid` type compares it in lower case.
#[tokio::test]
async fn a_token_is_looked_up_by_its_sub_in_lower_case() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::Es256);
    let set = json!({ "keys": [key.jwk.clone()] }).to_string();
    let mut settings = Settings::new(ISSUER, AUDIENCE, IssuerKind::Smart);
    settings.jwks_file = Some(temp_file("party-entra-jwks.json", set.as_bytes()));
    let server = ResourceServer::discover(settings.clone()).await?;
    let claims = json!({
        "iss": ISSUER, "aud": AUDIENCE, "sub": LOGIN.to_ascii_uppercase(),
        "client_id": CLIENT, "jti": "jti-person", "iat": now(), "exp": now() + 300,
        "scope": "user/Observation.rs", "fhirUser": "Practitioner/pr-1",
        "groups": ["group-1", "group-2"]
    });
    let mut header = Header::new(Algorithm::Es256);
    header.kid = Some(String::from("k1"));
    header.typ = Some(String::from("at+jwt"));
    let caller = server
        .authenticate(&mint_with(&key, &header, &claims))
        .await?;
    assert_eq!(&CallerKind::Practitioner, caller.kind());
    let group = PartyRef::new("ferro-demographic", "GROUP", "g-2");
    let source = FakeSource::with(move |query| {
        Ok(if query.value == LOGIN {
            Lookup::Parties(vec![
                record("p-1", Markers::PROFESSIONAL)
                    .with_memberships(vec![Membership::new(group.clone(), "group-2")]),
            ])
        } else {
            Lookup::Parties(Vec::new())
        })
    });
    let concrete = Arc::clone(&source);
    let dynamic: Arc<dyn PartySource> = concrete;
    let binding = PartyBinding::new(dynamic).with_issuer(table(), IssuerKind::Smart)?;
    let party = bound(binding.resolve(&caller).await?)?;
    assert_eq!("p-1", party.party.id());
    assert_eq!(LOGIN, party.identifier.value(), "the sub, in lower case");
    assert_eq!(
        vec![PartyRef::new("ferro-demographic", "GROUP", "g-2")],
        party.groups
    );
    assert_eq!(1, source.calls());
    Ok(())
}
