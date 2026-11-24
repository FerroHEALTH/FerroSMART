// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! What an operator reads off the configuration for one upstream provider.
//!
//! That is the person's pairwise subject (`ferrosmart subject`) and what the
//! provider must be configured with (`ferrosmart upstream registration`).
//! Both read the configuration tree alone, with no key, secret or database
//! read, so they run wherever the configuration is. No specification
//! governs either command: our own design (`docs/architecture.md` §13.10).

use std::fmt;

use crate::config::FerroSmartSection;
use crate::config::error::Error;
use crate::upstream::preset::Defaults;
use crate::upstream::saml::SamlSection;
use crate::upstream::wallet::WalletSection;
use crate::upstream::{OidcSection, UpstreamSection, pairwise};

/// Returns the `[[ferrosmart.upstream]]` entry `name` of `section`.
///
/// # Errors
/// Returns [`Error::NoUpstream`], with the configured names, when no entry
/// has that name.
pub fn entry<'a>(section: &'a FerroSmartSection, name: &str) -> Result<&'a UpstreamSection, Error> {
    section
        .upstream
        .iter()
        .find(|upstream| upstream.name == name)
        .ok_or_else(|| Error::NoUpstream {
            name: name.to_owned(),
            known: section
                .upstream
                .iter()
                .map(|upstream| upstream.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        })
}

/// Returns the FerroSMART `sub` of the person `subject` at the provider
/// `name`: the pairwise identifier the callback derives from the
/// provider's issuer exactly as configured (13.6 item 9).
///
/// # Errors
/// Returns [`Error::NoUpstream`] for an unknown name, and
/// [`Error::Upstream`] when the entry names no issuer.
pub fn subject(section: &FerroSmartSection, name: &str, subject: &str) -> Result<String, Error> {
    let issuer = entry(section, name)?
        .issuer()
        .filter(|issuer| !issuer.is_empty())
        .ok_or(Error::Upstream {
            rule: "the entry has one protocol table, which names the provider's issuer",
        })?;
    Ok(pairwise(issuer, subject))
}

/// What one provider must be configured with: one line per setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// The provider's name.
    pub name: String,
    /// The protocol, in words.
    pub protocol: &'static str,
    /// Each setting with its value, in the order an administrator enters
    /// them.
    pub lines: Vec<(&'static str, String)>,
}

impl Registration {
    /// Returns the registration of the provider `name` of `section`.
    ///
    /// # Errors
    /// Returns [`Error::Missing`] without an issuer, [`Error::NoUpstream`]
    /// for an unknown name, [`Error::Upstream`] for an entry with no single
    /// protocol table, and [`Error::Preset`] when its preset does not read.
    pub fn of(section: &FerroSmartSection, name: &str) -> Result<Self, Error> {
        if section.issuer.is_empty() {
            return Err(Error::Missing {
                key: "ferrosmart.issuer",
            });
        }
        let upstream = entry(section, name)?;
        let at = Endpoints(section.issuer.trim_end_matches('/'));
        let (protocol, mut lines) = match (&upstream.oidc, &upstream.saml, &upstream.openid4vp) {
            (Some(oidc), None, None) => (
                "OpenID Connect",
                oidc_lines(oidc, &upstream.defaults()?, &at)?,
            ),
            (None, Some(saml), None) => ("SAML 2.0", saml_lines(section, saml, &at)),
            (None, None, Some(wallet)) => ("OpenID4VP, the EUDI Wallet", wallet_lines(wallet, &at)),
            _ => {
                return Err(Error::Upstream {
                    rule: "one of `[ferrosmart.upstream.oidc]`, `[ferrosmart.upstream.saml]` and `[ferrosmart.upstream.openid4vp]` is set",
                });
            }
        };
        let roles: Vec<&str> = section.role.iter().map(|role| role.name.as_str()).collect();
        if !roles.is_empty() {
            lines.push(("roles", roles.join(", ")));
        }
        Ok(Self {
            name: upstream.name.clone(),
            protocol,
            lines,
        })
    }

    /// Returns the value of the setting `key`, if the registration has it.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.lines
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value.as_str())
    }
}

impl fmt::Display for Registration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Register FerroSMART at the provider `{}` ({}) with:",
            self.name, self.protocol
        )?;
        let width = self
            .lines
            .iter()
            .map(|(key, _)| key.len())
            .max()
            .unwrap_or_default();
        for (key, value) in &self.lines {
            writeln!(f, "  {key:<width$}  {value}")?;
        }
        Ok(())
    }
}

/// FerroSMART's endpoints under its issuer, without a trailing slash.
struct Endpoints<'a>(&'a str);

impl Endpoints<'_> {
    /// Returns the URL of `route`.
    fn at(&self, route: &str) -> String {
        format!("{}{route}", self.0)
    }
}

/// The settings of an OpenID Connect provider whose table is `oidc`, with
/// `defaults` its preset's.
fn oidc_lines(
    oidc: &OidcSection,
    defaults: &Defaults,
    endpoints: &Endpoints<'_>,
) -> Result<Vec<(&'static str, String)>, Error> {
    let effective = oidc.effective(defaults);
    let at = |route: &str| endpoints.at(route);
    let mut lines = vec![
        ("issuer", oidc.issuer.clone()),
        ("client id", oidc.client_id.clone()),
        ("client type", String::from("confidential web client")),
        // NOTE: RFC 7636 §4.2, FerroSMART sends an S256 challenge on every request.
        ("grant", String::from("authorization code, PKCE S256")),
        ("redirect URI", at(crate::authorize::CALLBACK_ROUTE)),
        (
            "post-logout redirect URI",
            at(crate::logout::end_session::END_SESSION_RETURN_ROUTE),
        ),
        (
            "back-channel logout URI",
            at(crate::logout::BACKCHANNEL_LOGOUT_ROUTE),
        ),
        // NOTE: OpenID Connect Front-Channel Logout 1.0 §2, iss and sid on the request.
        (
            "front-channel logout URI",
            format!(
                "{}, with iss and sid, where the provider has no back-channel logout",
                at(crate::logout::front::FRONTCHANNEL_LOGOUT_ROUTE)
            ),
        ),
    ];
    match (&oidc.private_key_jwt, &oidc.client_secret_basic) {
        (Some(_), Some(_)) => {
            return Err(Error::Upstream {
                rule: "one of `private_key_jwt` and `client_secret_basic` is set, never both",
            });
        }
        (None, Some(_)) => lines.push((
            "client authentication",
            String::from("client_secret_basic, the secret the provider issues"),
        )),
        (jwt, None) => {
            lines.push((
                "client authentication",
                format!("private_key_jwt, signed {}", effective.algorithm),
            ));
            lines.push(("JWK Set URL", at(crate::discovery::UPSTREAM_JWKS_ROUTE)));
            if let Some(path) = jwt.as_ref().and_then(|jwt| jwt.certificate_file.as_ref()) {
                lines.push(("certificate", path.display().to_string()));
            }
            if let Some(kid) = jwt
                .as_ref()
                .map(|jwt| &jwt.keys.kid)
                .filter(|kid| !kid.is_empty())
            {
                lines.push(("key id", kid.clone()));
            }
        }
    }
    lines.push(("scopes", effective.scopes.join(" ")));
    if !effective.fhir_user_claim.is_empty() {
        lines.push((
            "fhirUser claim",
            format!("{}, in the ID Token", effective.fhir_user_claim),
        ));
    }
    lines.push((
        "role claims",
        format!("{}, in the ID Token", effective.role_claims.join(", ")),
    ));
    Ok(lines)
}

/// The settings of the SAML 2.0 identity provider whose table is `saml`,
/// with FerroSMART as the service provider `section` describes.
fn saml_lines(
    section: &FerroSmartSection,
    saml: &SamlSection,
    endpoints: &Endpoints<'_>,
) -> Vec<(&'static str, String)> {
    let at = |route: &str| endpoints.at(route);
    let entity_id = section
        .saml
        .as_ref()
        .map(|sp| sp.entity_id.clone())
        .filter(|entity_id| !entity_id.is_empty())
        .unwrap_or_else(|| at(crate::upstream::saml::METADATA_ROUTE));
    let mut lines = vec![
        ("identity provider", saml.entity_id.clone()),
        ("service provider entity ID", entity_id),
        (
            "service provider metadata",
            at(crate::upstream::saml::METADATA_ROUTE),
        ),
        (
            "assertion consumer service",
            format!(
                "{}, HTTP-POST and HTTP-Artifact",
                at(crate::upstream::saml::ACS_ROUTE)
            ),
        ),
    ];
    for (key, value) in [
        ("name ID format", saml.name_id_format.clone()),
        ("subject attribute", saml.subject_attribute.clone()),
        ("authentication contexts", saml.authn_contexts.join(", ")),
        (
            "attributes",
            saml.claims.values().cloned().collect::<Vec<_>>().join(", "),
        ),
    ] {
        if !value.is_empty() {
            lines.push((key, value));
        }
    }
    lines
}

/// The settings of the wallet entry `wallet`: what the registrar of
/// wallet-relying parties records, and what the access certificate names
/// (Implementing Regulation (EU) 2025/848 Art 5, Annex I).
fn wallet_lines(wallet: &WalletSection, endpoints: &Endpoints<'_>) -> Vec<(&'static str, String)> {
    let at = |route: &str| endpoints.at(route);
    vec![
        (
            "request URI",
            format!("{}/{{state}}", at("/wallet/request")),
        ),
        ("response URI", at(crate::upstream::wallet::RESPONSE_ROUTE)),
        ("redirect URI", at(crate::upstream::wallet::COMPLETE_ROUTE)),
        ("credential types", wallet.vct_values.join(", ")),
        ("attributes", wallet.claims.join(", ")),
    ]
}
