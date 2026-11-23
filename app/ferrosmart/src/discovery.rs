// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The documents that describe the authorization server: its RFC 8414
//! metadata and its SMART configuration.
//!
//! Both list only what the server supports (`docs/architecture.md` §13.5,
//! Discovery and metadata). The SMART document is built by the same
//! builder the resource servers use
//! ([`ferrohealth_smart::resource::configuration`]), from the metadata, so
//! the two never disagree.

use ferrohealth_smart::metadata::ServerMetadata;
use ferrohealth_smart::resource::configuration::{
    self, OpenIdConnect, PermissionCapability, Purpose, SmartOptions,
};
use serde_json::{Value, json};

use crate::config::settings::Settings;

/// The token endpoint's route under the issuer.
pub const TOKEN_ROUTE: &str = "/token";
/// The JWK Set's route under the issuer.
pub const JWKS_ROUTE: &str = "/jwks";

/// The route of the JWK Set of FerroSMART's upstream client assertion keys.
///
/// It stands apart from [`JWKS_ROUTE`], so the provider trusts those keys
/// alone and a resource server never sees them (RFC 8725 §3.12; no
/// specification names the route: our own design).
pub const UPSTREAM_JWKS_ROUTE: &str = "/upstream-jwks";
/// The SMART configuration's route under the issuer (SMART App Launch
/// 2.2.0, Conformance, Using well-known).
pub const SMART_CONFIGURATION_ROUTE: &str = "/.well-known/smart-configuration";
/// The introspection endpoint's route under the issuer (RFC 7662 §2).
pub const INTROSPECT_ROUTE: &str = "/introspect";
/// The revocation endpoint's route under the issuer (RFC 7009 §2).
pub const REVOKE_ROUTE: &str = "/revoke";

/// The OpenID Connect discovery document's route under the issuer
/// (OpenID Connect Discovery 1.0 §4).
pub const OPENID_CONFIGURATION_ROUTE: &str = "/.well-known/openid-configuration";

/// The algorithms a client assertion may be signed with: the two of which
/// "The FHIR authorization server SHALL be capable of validating signatures
/// with at least one" (SMART App Launch 2.2.0, Client Authentication:
/// Asymmetric, Registering a client).
const ASSERTION_ALGORITHMS: [&str; 2] = ["RS384", "ES384"];

/// Returns the RFC 8414 §2 metadata of the server `settings` describe;
/// with `login`, the authorization code flow and its endpoint too.
///
/// `response_types_supported` is REQUIRED and lists the response types the
/// server supports: none without the authorization endpoint, `code` with
/// it. The token endpoint takes `private_key_jwt`, and with `login` also a
/// confidential symmetric client's secret (`client_secret_basic`,
/// `client_secret_post`) and `none`, a public client's (RFC 7591 §2).
#[must_use]
pub fn metadata(settings: &Settings, login: bool) -> ServerMetadata {
    let strings = |values: &[&str]| Some(values.iter().map(|&value| value.to_owned()).collect());
    let mut metadata = ServerMetadata {
        issuer: settings.issuer.clone(),
        jwks_uri: Some(settings.endpoint(JWKS_ROUTE)),
        token_endpoint: Some(settings.endpoint(TOKEN_ROUTE)),
        token_endpoint_auth_methods_supported: strings(&["private_key_jwt"]),
        token_endpoint_auth_signing_alg_values_supported: strings(&ASSERTION_ALGORITHMS),
        grant_types_supported: strings(crate::token::grant_types(false)),
        response_types_supported: Some(Vec::new()),
        introspection_endpoint: Some(settings.endpoint(INTROSPECT_ROUTE)),
        revocation_endpoint: Some(settings.endpoint(REVOKE_ROUTE)),
        registration_endpoint: Some(settings.endpoint(crate::admin::register::REGISTER_ROUTE)),
        ..ServerMetadata::default()
    };
    if login {
        metadata.authorization_endpoint =
            Some(settings.endpoint(crate::authorize::AUTHORIZE_ROUTE));
        metadata.grant_types_supported = strings(crate::token::grant_types(true));
        metadata.token_endpoint_auth_methods_supported = strings(&[
            "private_key_jwt",
            "client_secret_basic",
            "client_secret_post",
            "none",
        ]);
        metadata.response_types_supported = strings(&["code"]);
        metadata.code_challenge_methods_supported = strings(&["S256"]);
        let mut scopes: Vec<String> = APP_LAUNCH_SCOPES
            .iter()
            .map(|&scope| scope.to_owned())
            .collect();
        // NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, Extensibility, the
        // server advertises its extension scopes; a role is what grants one.
        let extensions: std::collections::BTreeSet<&String> = settings
            .roles
            .values()
            .flatten()
            .filter(|scope| crate::scopes::is_extension(scope))
            .collect();
        scopes.extend(extensions.into_iter().cloned());
        metadata.scopes_supported = Some(scopes);
    }
    metadata
}

/// The scopes of an app launch that FerroSMART honours whatever a client
/// registers: identity, launch context and refresh. "The server SHALL
/// support all scopes listed here" (SMART App Launch 2.2.0, Conformance,
/// Metadata, `scopes_supported`), so the resource scopes, which a client's
/// ceiling and a person's roles decide, are left out; the extension scopes
/// a role lists follow them.
const APP_LAUNCH_SCOPES: [&str; 9] = [
    "openid",
    "fhirUser",
    "profile",
    "email",
    "launch",
    "launch/patient",
    "launch/encounter",
    "offline_access",
    "online_access",
];

/// The capabilities every app launch document lists beside those the
/// builder derives from the metadata (SMART App Launch 2.2.0, Conformance,
/// Capabilities): the EHR launch with its patient, encounter and banner
/// context (`docs/architecture.md` §13.6 item 3), and the `POST` form of the
/// authorization endpoint.
const APP_LAUNCH: [&str; 5] = [
    "launch-ehr",
    "context-ehr-patient",
    "context-ehr-encounter",
    "context-banner",
    "authorize-post",
];

/// Returns the capabilities `settings` add to [`APP_LAUNCH`]:
/// `context-standalone-patient` when the patient picker can search one of
/// the resource servers, `context-standalone-encounter` when one of them is
/// a FHIR server, and `context-style` when the token response carries a
/// `smart_style_url`.
fn configured_capabilities(settings: &Settings) -> Vec<String> {
    let mut capabilities: Vec<String> = APP_LAUNCH
        .iter()
        .map(|&capability| capability.to_owned())
        .collect();
    let searchable = settings.resources.iter().any(|base| {
        !settings.openehr_resources.contains(base) || settings.subject_namespaces.contains_key(base)
    });
    if searchable {
        capabilities.push(String::from("context-standalone-patient"));
    }
    // NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, Standalone apps: the
    // picker offers a patient's encounters at a FHIR server, never at an openEHR one.
    if settings
        .resources
        .iter()
        .any(|base| !settings.openehr_resources.contains(base))
    {
        capabilities.push(String::from("context-standalone-encounter"));
    }
    if !settings.branding.smart_style_url.is_empty() {
        capabilities.push(String::from("context-style"));
    }
    capabilities
}
/// Returns the RFC 8414 document of `metadata`: its members with how the
/// introspection and revocation endpoints authenticate a client, which
/// RFC 8414 §2 has default to `client_secret_basic` when absent.
///
/// The introspection endpoint takes a confidential client as the token
/// endpoint does, by its `private_key_jwt` assertion or its client secret
/// (or a bearer token, which is no client authentication method;
/// `docs/architecture.md` §13.6 item 8); the revocation endpoint takes the
/// same, and `none` with the `client_id` of a public client (RFC 7009 §2.1,
/// RFC 6749 §2.3).
///
/// # Panics
///
/// Never: the metadata is plain strings and lists, which `serde_json`
/// always serializes.
#[must_use]
#[expect(
    clippy::expect_used,
    reason = "ServerMetadata is plain strings and lists, which serde_json always serializes"
)]
pub fn metadata_document(metadata: &ServerMetadata) -> Value {
    let mut document =
        serde_json::to_value(metadata).expect("the metadata should serialize as JSON");
    if let Some(members) = document.as_object_mut() {
        members.insert(
            String::from("introspection_endpoint_auth_methods_supported"),
            json!([
                "private_key_jwt",
                "client_secret_basic",
                "client_secret_post"
            ]),
        );
        members.insert(
            String::from("introspection_endpoint_auth_signing_alg_values_supported"),
            json!(ASSERTION_ALGORITHMS),
        );
        members.insert(
            String::from("revocation_endpoint_auth_methods_supported"),
            json!([
                "private_key_jwt",
                "client_secret_basic",
                "client_secret_post",
                "none"
            ]),
        );
        members.insert(
            String::from("revocation_endpoint_auth_signing_alg_values_supported"),
            json!(ASSERTION_ALGORITHMS),
        );
    }
    add_launch_registration(&mut document, metadata);
    add_end_session(&mut document, metadata);
    document
}

/// Adds `acr_values_supported` to `document`, when a provider maps a value.
///
/// It lists the eIDAS URIs of the levels the providers' values map to,
/// lowest first, which tells a client the server honours `acr_values` and
/// `max_age` (RFC 9470 §7; OpenID Connect Discovery 1.0 §3).
pub fn add_acr_values(document: &mut Value, settings: &Settings) {
    let mut levels: Vec<_> = settings
        .upstreams
        .iter()
        .flat_map(|upstream| upstream.assurance.levels())
        .collect();
    levels.sort_unstable();
    levels.dedup();
    if let (false, Some(members)) = (levels.is_empty(), document.as_object_mut()) {
        let uris: Vec<&str> = levels.into_iter().map(crate::assurance::uri).collect();
        members.insert(String::from("acr_values_supported"), json!(uris));
    }
}

/// Adds the pushed authorization request endpoint and whether every
/// authorization request must arrive through it to `document` (RFC 9126
/// §5), which describes the login.
pub fn add_pushed_requests(document: &mut Value, settings: &Settings) {
    if let Some(members) = document.as_object_mut() {
        members.insert(
            String::from("pushed_authorization_request_endpoint"),
            json!(settings.endpoint(crate::authorize::par::PAR_ROUTE)),
        );
        members.insert(
            String::from("require_pushed_authorization_requests"),
            json!(settings.require_pushed_authorization_requests),
        );
    }
}

/// Adds `end_session_endpoint` (`{issuer}/logout`) to `document` when
/// `metadata` describes the login, which alone gives a person a session to
/// end (OpenID Connect RP-Initiated Logout 1.0 §2.1; the member is
/// registered for RFC 8414 metadata too, §7.1).
fn add_end_session(document: &mut Value, metadata: &ServerMetadata) {
    add_issuer_route(
        document,
        metadata,
        "end_session_endpoint",
        crate::logout::end_session::END_SESSION_ROUTE,
    );
}

/// Returns the SMART configuration of `metadata` for the server `settings`
/// describe.
///
/// Without `login` it is the Backend Services document (SMART App Launch
/// 2.2.0, Backend Services, Retrieve `.well-known/smart-configuration`);
/// with it, the App Launch document, whose capabilities the builder derives
/// from the metadata (`client-public`, `client-confidential-asymmetric`,
/// `launch-standalone`), with `sso-openid-connect`, the capabilities of
/// the configuration (the picker, the style document), the refresh tokens FerroSMART issues
/// (`permission-offline`, `permission-online`) and the v2 scopes it grants
/// (`permission-patient`, `permission-user`, `permission-v2`).
#[must_use]
pub fn smart_configuration(settings: &Settings, metadata: &ServerMetadata, login: bool) -> Value {
    let mut document = smart_document(settings, metadata, login);
    // NOTE: SMART App Launch 2.2.0, Conformance, Metadata, management_endpoint
    // (RECOMMENDED): where the person sees and withdraws what they remembered.
    if login && let Some(members) = document.as_object_mut() {
        let manage = format!(
            "{}{}",
            metadata.issuer.trim_end_matches('/'),
            crate::authorize::MANAGE_ROUTE
        );
        members.insert(String::from("management_endpoint"), Value::String(manage));
    }
    add_launch_registration(&mut document, metadata);
    document
}

/// Adds `launch_registration_endpoint`, FerroSMART's EHR launch API (`POST
/// {issuer}/launch`, `docs/architecture.md` §13.17), to `document` when
/// `metadata` describes the app launch, which alone redeems a launch.
///
/// SMART App Launch 2.2.0 defines no member for it; its Conformance,
/// Metadata lets a server add metadata, and RFC 8414 §2 "Additional
/// authorization server metadata parameters MAY also be used". The name is
/// our own design.
fn add_launch_registration(document: &mut Value, metadata: &ServerMetadata) {
    add_issuer_route(
        document,
        metadata,
        "launch_registration_endpoint",
        crate::launch::LAUNCH_ROUTE,
    );
}

/// Adds the member `name`, the issuer's `route`, to `document` when
/// `metadata` describes the app launch.
fn add_issuer_route(document: &mut Value, metadata: &ServerMetadata, name: &str, route: &str) {
    if metadata.authorization_endpoint.is_none() {
        return;
    }
    if let Some(members) = document.as_object_mut() {
        let endpoint = format!("{}{route}", metadata.issuer.trim_end_matches('/'));
        members.insert(String::from(name), Value::String(endpoint));
    }
}

/// Returns the SMART document the builder writes from `metadata`.
fn smart_document(settings: &Settings, metadata: &ServerMetadata, login: bool) -> Value {
    let options = if login {
        SmartOptions {
            purpose: Purpose::AppLaunch,
            openid_connect: OpenIdConnect::Advertised,
            capabilities: configured_capabilities(settings),
            scopes_supported: metadata.scopes_supported.clone().unwrap_or_default(),
            permissions: [
                PermissionCapability::Offline,
                PermissionCapability::Online,
                PermissionCapability::Patient,
                PermissionCapability::User,
                PermissionCapability::V1,
                PermissionCapability::V2,
            ]
            .into_iter()
            .collect(),
            ..SmartOptions::default()
        }
    } else {
        SmartOptions {
            purpose: Purpose::BackendServices,
            ..SmartOptions::default()
        }
    };
    configuration::document(metadata, &options)
}

/// Returns the OpenID Connect discovery document of `metadata`.
///
/// It is the RFC 8414 members with the three OpenID Connect Discovery 1.0
/// §3 requires beside them, `subject_types_supported` (`pairwise`, 13.6
/// item 9), `id_token_signing_alg_values_supported` (`RS256`, which "MUST
/// be included") and the claims an ID Token carries, and the `display`
/// values and page languages FerroSMART supports (13.25). It names no
/// `claims_locales_supported`: no claim it returns depends on a language.
///
/// # Panics
///
/// Never: the metadata is plain strings and lists, which `serde_json`
/// always serializes.
#[must_use]
#[expect(
    clippy::expect_used,
    reason = "ServerMetadata is plain strings and lists, which serde_json always serializes"
)]
pub fn openid_configuration(metadata: &ServerMetadata) -> Value {
    let mut document =
        serde_json::to_value(metadata).expect("the metadata should serialize as JSON");
    if let Some(members) = document.as_object_mut() {
        members.insert(
            String::from("subject_types_supported"),
            serde_json::json!(["pairwise"]),
        );
        members.insert(
            String::from("id_token_signing_alg_values_supported"),
            serde_json::json!(["RS256"]),
        );
        // NOTE: OpenID Connect Core 1.0 §3.1.2.1 and §15.1: every display value is
        // taken, and the pages answer at any size.
        members.insert(
            String::from("display_values_supported"),
            serde_json::json!(["page", "popup", "touch", "wap"]),
        );
        members.insert(
            String::from("ui_locales_supported"),
            serde_json::json!(crate::pages::ui_locales()),
        );
        members.insert(
            String::from("claims_supported"),
            serde_json::json!([
                "iss",
                "sub",
                "aud",
                "exp",
                "iat",
                "auth_time",
                "acr",
                "nonce",
                "fhirUser",
                "name",
                "preferred_username",
                "email",
                "email_verified"
            ]),
        );
    }
    add_end_session(&mut document, metadata);
    document
}
