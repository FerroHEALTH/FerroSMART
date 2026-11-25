// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The Logout Token of OpenID Connect Back-Channel Logout 1.0 §2.4, which
//! a provider posts to a relying party's back-channel logout URI (§2.5).
//!
//! [`RelyingParty::logout_token`] checks it as §2.6 has the relying party
//! check it: signed by the provider's key under an algorithm accepted for
//! ID Tokens, `iss`, `aud`, `iat` and `exp` as for an ID Token, `sub` or
//! `sid` or both, the back-channel logout event, and no `nonce`. An
//! encrypted Logout Token is refused, since the relying party negotiates no
//! ID Token encryption. The optional checks of §2.6 (the `jti` not seen
//! before, the `iss`, `sub` and `sid` of a current session) are the
//! caller's, which holds the sessions; the claims carry what they need.

use std::fmt;

use serde::Deserialize;

use crate::oidc::{Audience, OidcError, RelyingParty};

/// The member of the `events` claim that declares a JWT a Logout Token
/// (OpenID Connect Back-Channel Logout 1.0 §2.4).
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// The claims of a checked Logout Token (OpenID Connect Back-Channel Logout
/// 1.0 §2.4).
///
/// Its `Debug` rendering names the issuer alone.
#[derive(Clone, Deserialize)]
#[non_exhaustive]
pub struct LogoutClaims {
    /// The issuer.
    #[serde(rename = "iss")]
    pub issuer: String,
    /// The person to log out, at the provider; with no `sid`, every one of
    /// their sessions.
    #[serde(rename = "sub", default)]
    pub subject: Option<String>,
    /// The provider's session to log out.
    #[serde(rename = "sid", default)]
    pub session: Option<String>,
    /// The token's id, for the caller's replay check.
    pub jti: String,
    /// When the token expires, in seconds since the epoch, until which the
    /// caller keeps its `jti`.
    #[serde(rename = "exp")]
    pub expires_at: i64,
    /// When the token was issued, in seconds since the epoch.
    #[serde(rename = "iat")]
    pub issued_at: i64,
    /// The audience.
    #[serde(rename = "aud")]
    audience: Audience,
    /// The events the token declares.
    #[serde(default)]
    events: serde_json::Map<String, serde_json::Value>,
    /// A `nonce`, which a Logout Token must not carry, `null` included.
    #[serde(default, deserialize_with = "present")]
    nonce: Option<serde_json::Value>,
}

/// Reads a member that is present, whatever its value, `null` included.
fn present<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error> {
    serde_json::Value::deserialize(deserializer).map(Some)
}

impl fmt::Debug for LogoutClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LogoutClaims")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl RelyingParty {
    /// Checks the Logout Token `token` the provider posted (OpenID Connect
    /// Back-Channel Logout 1.0 §2.6), and returns its claims.
    ///
    /// # Errors
    ///
    /// Returns the key errors of the ID Token check ([`OidcError::Key`],
    /// [`OidcError::KeySet`], [`OidcError::KeySetBody`],
    /// [`OidcError::Discovery`]), [`OidcError::LogoutToken`] when the
    /// signature, `iss`, `aud`, `iat` or `exp` do not verify,
    /// [`OidcError::Audience`] for an audience beyond this client, and
    /// [`OidcError::LogoutClaims`] for a token with neither `sub` nor `sid`,
    /// without the back-channel logout event, or with a `nonce`. Each is a
    /// `400` to the provider (§2.6, §2.8).
    pub async fn logout_token(&self, token: &str) -> Result<LogoutClaims, OidcError> {
        let (jws, key) = self.signing_key(token).await?;
        // NOTE: Back-Channel Logout 1.0 §2.6 items 2 to 4: the signature, `alg`,
        // `iss`, `aud`, `iat` and `exp` are checked as they are for an ID Token.
        let claims: LogoutClaims = self
            .verified(&jws, &key, &["exp", "iat"])
            .map_err(|source| OidcError::LogoutToken { source })?;
        if !claims
            .audience
            .is_trusted(&self.client_id, &self.trusted_audiences)
        {
            return Err(OidcError::Audience);
        }
        let rule = |rule| OidcError::LogoutClaims { rule };
        if claims.subject.is_none() && claims.session.is_none() {
            return Err(rule("names neither sub nor sid"));
        }
        if !claims
            .events
            .get(BACKCHANNEL_LOGOUT_EVENT)
            .is_some_and(serde_json::Value::is_object)
        {
            return Err(rule("declares no back-channel logout event"));
        }
        if claims.nonce.is_some() {
            return Err(rule("carries a nonce"));
        }
        Ok(claims)
    }
}
