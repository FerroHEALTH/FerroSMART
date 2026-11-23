// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The defaults of one `[auth.issuer.<name>]` table and of its
//! `[auth.issuer.introspection]` table, and the rules one table is checked
//! against when `[auth]` resolves.

use jsonwebtoken::Algorithm;

use crate::config::AuthMode;
use crate::config::ConfigError;
use crate::config::IntrospectionSection;
use crate::config::IssuerEntry;
use crate::kind::IssuerKind;
use crate::profile::ProfileKeys;
use crate::sender::SenderConstraint;
use ferrohealth_config::units::Duration;

impl Default for IssuerEntry {
    fn default() -> Self {
        Self {
            issuer: ferrohealth_secret::secret_url::SecretUrl::default(),
            kind: None,
            audience: Vec::new(),
            algorithms: vec![
                Algorithm::RS256,
                Algorithm::RS384,
                Algorithm::PS256,
                Algorithm::PS384,
                Algorithm::ES256,
                Algorithm::ES384,
            ],
            clock_skew: Duration::from_secs(60),
            jwks_max_age: Duration::from_mins(10),
            jwks_refresh_interval: Duration::from_secs(60),
            jwks_file: String::new(),
            timeout: Duration::from_secs(10),
            mode: AuthMode::Jwt,
            introspection: None,
            federation: None,
            attributes: None,
            party: None,
            assurance: None,
            sender_constraint: SenderConstraint::None,
            role_claims: None,
            profile: ProfileKeys::default(),
        }
    }
}

impl Default for IntrospectionSection {
    fn default() -> Self {
        Self {
            endpoint: ferrohealth_secret::secret_url::SecretUrl::default(),
            cache_max_age: Duration::from_secs(60),
            cache_capacity: 10_000,
            client: None,
            bearer: None,
        }
    }
}

/// Checks the issuer-level rules of `entry` and returns its kind: an
/// identifier without userinfo, a key set file with no secret, and an
/// introspection table under `mode = "introspection"` alone.
pub(super) fn check_entry(entry: &IssuerEntry) -> Result<IssuerKind, ConfigError> {
    if entry.issuer.is_empty() {
        return Err(ConfigError::Missing { key: "auth.issuer" });
    }
    // NOTE: OpenID Connect Core 1.0 §1.2: an issuer identifier holds scheme, host, port and
    // path; userinfo is refused before any later error could quote the URL.
    if let Ok(url) = url::Url::parse(entry.issuer.expose().trim())
        && (!url.username().is_empty() || url.password().is_some())
    {
        return Err(ConfigError::IssuerUserinfo {
            issuer: crate::config::shown(&entry.issuer),
        });
    }
    if !entry.jwks_file.is_empty() {
        check_jwks_file(entry)?;
    }
    let kind = entry.kind.unwrap_or_default();
    if entry.mode == AuthMode::Jwt && entry.introspection.is_some() {
        return Err(ConfigError::Exclusive {
            left: "auth.issuer.introspection",
            right: "auth.issuer.mode = \"jwt\"",
        });
    }
    if !entry
        .role_claims
        .iter()
        .flatten()
        .all(|path| crate::roles::well_formed(path))
    {
        return Err(ConfigError::Missing {
            key: "auth.issuer.role_claims",
        });
    }
    Ok(kind)
}

/// The JWK members that carry private or symmetric key material, as the
/// example private and symmetric keys of RFC 7517 Appendix A.2 and A.3 show.
const SECRET_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Refuses a `jwks_file` that holds a symmetric key or private key
/// material, which a verifier never holds (RFC 7517 §5; RFC 8725 §3.1).
/// A file that cannot be read or parsed is left to the read of the key
/// set, which refuses it; no key value is ever quoted.
fn check_jwks_file(entry: &IssuerEntry) -> Result<(), ConfigError> {
    let Ok(text) = std::fs::read_to_string(&entry.jwks_file) else {
        return Ok(());
    };
    // NOTE: a file that is no JSON is legitimately left to the key set read, which refuses it.
    let Ok(set) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Ok(());
    };
    let keys = set
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    for (index, key) in keys.iter().enumerate() {
        let kid = key
            .get("kid")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        if key.get("kty").and_then(serde_json::Value::as_str) == Some("oct") {
            return Err(ConfigError::JwksSymmetricKey {
                issuer: crate::config::shown(&entry.issuer),
                index,
                kid,
            });
        }
        if let Some(member) = SECRET_MEMBERS
            .iter()
            .find(|member| key.get(**member).is_some())
        {
            return Err(ConfigError::JwksPrivateKey {
                issuer: crate::config::shown(&entry.issuer),
                index,
                kid,
                member,
            });
        }
    }
    Ok(())
}
