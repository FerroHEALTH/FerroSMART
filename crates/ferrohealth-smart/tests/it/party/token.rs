// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A signed token in, its caller classified under the `entra` preset, its
//! login looked up by the preset's `person_key`, and its party out.

use std::error::Error as StdError;
use std::sync::Arc;

use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::party::Markers;
use ferrohealth_smart::party::Membership;
use ferrohealth_smart::party::PartyRef;
use ferrohealth_smart::party::binding::PartyBinding;
use ferrohealth_smart::party::source::Lookup;
use ferrohealth_smart::party::source::PartySource;
use ferrohealth_smart::profile::Preset;
use ferrohealth_smart::profile::Profile;
use ferrohealth_smart::profile::ProfileKeys;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::Settings;
use jsonwebtoken::Algorithm;
use jsonwebtoken::Header;
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

// NOTE: Microsoft, "Access token claims reference": `oid` is "The immutable identifier
// for the requestor", a GUID, and `sub` "a pairwise identifier"; the entra preset keys on `oid`.
#[tokio::test]
async fn an_entra_token_is_looked_up_by_its_oid_in_lower_case() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let set = json!({ "keys": [key.jwk.clone()] }).to_string();
    let mut settings = Settings::new(ISSUER, AUDIENCE, IssuerKind::Persons);
    settings.jwks_file = Some(temp_file("party-entra-jwks.json", set.as_bytes()));
    settings.profile = Profile::resolve(Preset::Entra, &ProfileKeys::default())?;
    assert_eq!("oid", settings.profile.person_key);
    let server = ResourceServer::discover(settings.clone()).await?;
    let claims = json!({
        "iss": ISSUER, "aud": AUDIENCE, "sub": "pairwise-sub-of-this-app",
        "oid": LOGIN.to_ascii_uppercase(), "tid": "tenant-1", "azp": CLIENT,
        "uti": "uti-person", "ver": "2.0", "iat": now(), "exp": now() + 300,
        "scp": "user/Observation.rs", "acct": 0,
        "groups": ["group-1", "group-2"]
    });
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(String::from("k1"));
    header.typ = Some(String::from("JWT"));
    let caller = server
        .authenticate(&mint_with(&key, &header, &claims))
        .await?;
    assert_eq!(&CallerKind::Person, caller.kind());
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
    let binding =
        PartyBinding::new(dynamic).with_issuer(table(), IssuerKind::Persons, &settings.profile)?;
    let party = bound(binding.resolve(&caller).await?)?;
    assert_eq!("p-1", party.party.id());
    assert_eq!(LOGIN, party.identifier.value(), "the oid, in lower case");
    assert_eq!(
        vec![PartyRef::new("ferro-demographic", "GROUP", "g-2")],
        party.groups
    );
    assert_eq!(1, source.calls());
    Ok(())
}
