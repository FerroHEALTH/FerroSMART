// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The profile keys of the onward grants on `[auth.issuer.<name>]`, their
//! preset values, and the issuers an onward client refuses to build for.

use std::collections::BTreeMap;

use ferrohealth_smart::client::onward::OnwardError;
use ferrohealth_smart::client::onward::exchange::Onward;
use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::profile::Profile;
use ferrohealth_smart::profile::ProfileError;
use ferrohealth_smart::profile::onward::OnwardGrant;
use ferrohealth_smart::profile::onward::OnwardIndicator;
use ferrohealth_smart::profile::onward::PreviewVariant;
use ferrohealth_smart::resource::ResourceError;
use ferrohealth_smart::resource::Settings;
use wiremock::MockServer;

use super::ClientKey;
use super::endpoint;

/// Returns the `[auth]` section of one `persons` issuer with the profile
/// keys `keys`.
fn section(keys: &str) -> AuthSection {
    toml::from_str(&format!(
        "[issuer.i2]\nissuer = \"https://as.example.org\"\naudience = [\"a\"]\n\
         [issuer.i2.profile]\n{keys}\n"
    ))
    .expect("the section parses")
}

#[test]
fn the_onward_keys_on_an_issuer_table_set_its_profile() {
    let resolved = section(
        "max_onward_lifetime = \"900s\"\nonward_grant = \"jwt_bearer\"\nonward_indicator = \"audience\"\n\
         onward_parameters = { requested_token_use = \"on_behalf_of\" }\n\
         onward_client_id = true\nonward_subject_audience = true\nonward_preview = [\"actor_token\"]",
    )
    .resolve(&[])
    .expect("the section resolves");
    let profile = &resolved.issuers.first().expect("one issuer").profile;
    assert_eq!(Some(900), profile.max_onward_lifetime);
    assert_eq!(OnwardGrant::JwtBearer, profile.onward_grant);
    assert_eq!(OnwardIndicator::Audience, profile.onward_indicator);
    assert_eq!(
        BTreeMap::from([(
            String::from("requested_token_use"),
            String::from("on_behalf_of")
        )]),
        profile.onward_parameters
    );
    assert!(profile.onward_client_id && profile.onward_subject_audience);
    assert_eq!(vec![PreviewVariant::ActorToken], profile.onward_preview);
}

#[test]
fn a_parameter_the_client_writes_itself_fails_to_load() {
    for parameter in [
        "grant_type",
        "subject_token",
        "assertion",
        "scope",
        "client_id",
    ] {
        let refused =
            section(&format!("onward_parameters = {{ {parameter} = \"x\" }}")).resolve(&[]);
        assert!(
            matches!(&refused, Err(ConfigError::Issuer { source, .. }) if matches!(&**source, ResourceError::Profile(ProfileError::Reserved { parameter: named }) if named == parameter)),
            "{parameter}: {refused:?}"
        );
    }
}

#[test]
fn a_refresh_token_asked_for_fails_to_load() {
    let refused = section(
        "onward_parameters = { requested_token_type = \"urn:ietf:params:oauth:token-type:refresh_token\" }",
    )
    .resolve(&[]);
    assert!(
        matches!(&refused, Err(ConfigError::Issuer { source, .. })
            if matches!(**source, ResourceError::Profile(ProfileError::RefreshToken))),
        "{refused:?}"
    );
}

#[test]
fn a_zero_onward_lifetime_fails_to_load() {
    let refused = section("max_onward_lifetime = \"0s\"").resolve(&[]);
    assert!(
        matches!(&refused, Err(ConfigError::Issuer { source, .. })
            if matches!(**source, ResourceError::Profile(ProfileError::Empty { key: "max_onward_lifetime" }))),
        "{refused:?}"
    );
}

#[test]
fn the_default_grant_is_token_exchange_with_resource() {
    let profile = Profile::default();
    assert_eq!(OnwardGrant::TokenExchange, profile.onward_grant);
    assert_eq!(OnwardIndicator::Resource, profile.onward_indicator);
    assert!(profile.onward_parameters.is_empty() && profile.onward_preview.is_empty());
    assert_eq!(
        None, profile.max_onward_lifetime,
        "no source states a lifetime, so the deployment sets it"
    );
}

#[tokio::test]
async fn an_issuer_without_max_onward_lifetime_refuses_to_build() {
    let server = MockServer::start().await;
    let settings = Settings::new("https://as.example.org", "bridge", IssuerKind::Smart);
    let built = Onward::new(
        settings,
        ClientKey::new().credentials(endpoint(&server, "/token"), "bridge"),
    );
    assert!(
        matches!(built, Err(OnwardError::MaxOnwardLifetime)),
        "{built:?}"
    );
}

#[tokio::test]
async fn credentials_without_their_methods_credential_refuse_to_build() {
    let server = MockServer::start().await;
    let mut settings = Settings::new("https://as.example.org", "bridge", IssuerKind::Smart);
    settings.profile.max_onward_lifetime = Some(600);
    let mut credentials = ClientKey::new().credentials(endpoint(&server, "/token"), "bridge");
    credentials.assertion_keys = None;
    let built = Onward::new(settings, credentials);
    assert!(matches!(built, Err(OnwardError::Token(_))), "{built:?}");
}
