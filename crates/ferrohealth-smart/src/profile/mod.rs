// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The issuer profile: what one authorization server's tokens look like.
//!
//! Every issuer's tokens are read by the standards: RFC 9068 for the token
//! shape, `client_id` for the client and `sub` equal to it for a token with
//! no user (RFC 9068 §2.2), `scope` as one string (RFC 9068 §2.2.3), and
//! RFC 8693 §4.1 for an actor. A table may narrow the token types and the
//! required claims of a federation issuer, and the onward grants
//! (`client::onward`) read their keys here too.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;
use serde_json::Map;
use serde_json::Value;

use crate::profile::onward::OnwardGrant;
use crate::profile::onward::OnwardIndicator;
use crate::profile::onward::PreviewVariant;

pub mod onward;

/// The claim a token names its client in (RFC 9068 §2.2).
pub const CLIENT_CLAIM: &str = "client_id";

/// The claim a token carries its scopes in (RFC 9068 §2.2.3).
pub const SCOPE_CLAIM: &str = "scope";

/// The profile keys, each optional, set on one `[auth.issuer.<name>]` table
/// over the defaults.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProfileKeys {
    /// [`Profile::max_actor_chain`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_actor_chain: Option<usize>,
    /// [`Profile::token_types`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_types: Option<Vec<String>>,
    /// [`Profile::required_claims`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_claims: Option<Vec<String>>,
    /// [`Profile::max_onward_lifetime`], a duration such as `"10min"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_onward_lifetime: Option<ferrohealth_config::units::Duration>,
    /// [`Profile::onward_grant`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onward_grant: Option<OnwardGrant>,
    /// [`Profile::onward_indicator`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onward_indicator: Option<OnwardIndicator>,
    /// [`Profile::onward_parameters`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onward_parameters: Option<BTreeMap<String, String>>,
    /// [`Profile::onward_client_id`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onward_client_id: Option<bool>,
    /// [`Profile::onward_subject_audience`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onward_subject_audience: Option<bool>,
    /// [`Profile::onward_preview`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onward_preview: Option<Vec<PreviewVariant>>,
}

/// What one issuer's tokens look like, every key resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// The deepest `act` chain admitted, 1 by default: prior actors are
    /// "informational only" (RFC 8693 §4.1).
    pub max_actor_chain: usize,
    /// The accepted `typ` header values; `at+jwt` and `application/at+jwt`
    /// by default (RFC 9068 §4).
    pub token_types: Vec<String>,
    /// The claims every token must carry; the RFC 9068 §2.2 set with
    /// `scope` by default.
    pub required_claims: Vec<String>,
    /// The longest an onward token this issuer issues may live, in seconds
    /// from its `iat`; required on an issuer the onward grants use.
    pub max_onward_lifetime: Option<u64>,
    /// The grant the issuer issues onward tokens under; token exchange by
    /// default (RFC 8693 §2.1).
    pub onward_grant: OnwardGrant,
    /// The token-exchange parameter a target is named in; `resource` by
    /// default (RFC 8707 §2).
    pub onward_indicator: OnwardIndicator,
    /// The parameters an onward request carries beside the grant's own.
    pub onward_parameters: BTreeMap<String, String>,
    /// Whether an onward request names `client_id` beside a client
    /// assertion, which RFC 7523 §3 leaves optional.
    pub onward_client_id: bool,
    /// Whether the subject token must name the requesting client in its
    /// `aud` before it is sent.
    pub onward_subject_audience: bool,
    /// The grant variants the issuer labels preview, which are refused.
    pub onward_preview: Vec<PreviewVariant>,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            max_actor_chain: 1,
            token_types: vec![String::from("at+jwt"), String::from("application/at+jwt")],
            required_claims: [
                "iss",
                "exp",
                "aud",
                "sub",
                "client_id",
                "iat",
                "jti",
                "scope",
            ]
            .iter()
            .map(|&claim| claim.to_owned())
            .collect(),
            max_onward_lifetime: None,
            onward_grant: OnwardGrant::TokenExchange,
            onward_indicator: OnwardIndicator::Resource,
            onward_parameters: BTreeMap::new(),
            onward_client_id: false,
            onward_subject_audience: false,
            onward_preview: Vec::new(),
        }
    }
}

/// A profile that breaks a rule.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProfileError {
    /// A key the issuer needs is empty.
    #[error("the profile key {key} is empty")]
    Empty {
        /// The key.
        key: &'static str,
    },
    /// `onward_parameters` names a parameter the client writes itself.
    #[error("onward_parameters names {parameter:?}, which the client writes itself")]
    Reserved {
        /// The parameter.
        parameter: String,
    },
    /// `onward_parameters` asks for a refresh token.
    #[error("onward_parameters asks for a refresh token")]
    RefreshToken,
}

/// Why a scope claim does not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeFormError;

impl Profile {
    /// Returns the default profile with every key `keys` names set over it.
    #[must_use]
    pub fn with_keys(mut self, keys: ProfileKeys) -> Self {
        let ProfileKeys {
            max_actor_chain,
            token_types,
            required_claims,
            max_onward_lifetime,
            onward_grant,
            onward_indicator,
            onward_parameters,
            onward_client_id,
            onward_subject_audience,
            onward_preview,
        } = keys;
        set(&mut self.max_actor_chain, max_actor_chain);
        set(&mut self.token_types, token_types);
        set(&mut self.required_claims, required_claims);
        // NOTE: RFC 7519 §2, a NumericDate counts whole seconds, so a lifetime bound
        // holds its whole seconds; rounding down only tightens it.
        if let Some(lifetime) = max_onward_lifetime {
            self.max_onward_lifetime = Some(lifetime.as_secs());
        }
        set(&mut self.onward_grant, onward_grant);
        set(&mut self.onward_indicator, onward_indicator);
        set(&mut self.onward_parameters, onward_parameters);
        set(&mut self.onward_client_id, onward_client_id);
        set(&mut self.onward_subject_audience, onward_subject_audience);
        set(&mut self.onward_preview, onward_preview);
        self
    }

    /// Checks the profile: no empty list of token types, and onward
    /// parameters the client does not write itself.
    ///
    /// # Errors
    ///
    /// The [`ProfileError`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.token_types.is_empty() {
            return Err(ProfileError::Empty { key: "token_types" });
        }
        onward::validate(&self.onward_parameters, self.max_onward_lifetime)
    }

    /// Returns the client `claims` name in `client_id`.
    #[must_use]
    pub fn client(claims: &Map<String, Value>) -> Option<&str> {
        claims.get(CLIENT_CLAIM).and_then(Value::as_str)
    }

    /// Returns whether `claims` name no user: `sub` equals `client_id`, as
    /// a client credentials token's does (RFC 9068 §2.2, §5).
    #[must_use]
    pub fn app_only(claims: &Map<String, Value>) -> bool {
        Self::client(claims)
            .is_some_and(|client| claims.get("sub").and_then(Value::as_str) == Some(client))
    }

    /// Returns the scope tokens of `claims`, one space-delimited string
    /// (RFC 9068 §2.2.3); none when the claim is absent.
    ///
    /// # Errors
    ///
    /// [`ScopeFormError`] when the claim is not a string.
    pub fn scope(claims: &Map<String, Value>) -> Result<String, ScopeFormError> {
        match claims.get(SCOPE_CLAIM) {
            None => Ok(String::new()),
            Some(Value::String(scope)) => Ok(scope.clone()),
            Some(_) => Err(ScopeFormError),
        }
    }

    /// Returns whether `typ` is a header value the profile accepts,
    /// compared without regard to case (RFC 7515 §4.1.9).
    #[must_use]
    pub fn accepts_type(&self, typ: Option<&str>) -> bool {
        typ.is_some_and(|typ| {
            self.token_types
                .iter()
                .any(|accepted| typ.eq_ignore_ascii_case(accepted))
        })
    }
}

/// Replaces `slot` with `value` when one is set.
fn set<T>(slot: &mut T, value: Option<T>) {
    if let Some(value) = value {
        *slot = value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: RFC 9068 §2.1 and §2.2: `typ` `at+jwt`, and the claims every token
    // carries, with `scope` (SMART App Launch 2.2.0, Obtain access token).
    #[test]
    fn the_defaults_are_rfc_9068_with_scope() {
        let profile = Profile::default();
        assert!(profile.accepts_type(Some("AT+JWT")));
        assert!(profile.accepts_type(Some("application/at+jwt")));
        assert!(!profile.accepts_type(Some("JWT")));
        assert!(profile.required_claims.iter().any(|claim| claim == "scope"));
        assert_eq!(1, profile.max_actor_chain);
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn every_key_set_on_the_issuer_wins_over_the_default() {
        let keys = ProfileKeys {
            max_actor_chain: Some(3),
            token_types: Some(vec![String::from("jwt")]),
            required_claims: Some(vec![String::from("iss")]),
            max_onward_lifetime: Some(ferrohealth_config::units::Duration::from_mins(10)),
            onward_grant: Some(OnwardGrant::JwtBearer),
            onward_indicator: Some(OnwardIndicator::Audience),
            onward_parameters: Some(BTreeMap::from([(
                String::from("requested_token_use"),
                String::from("on_behalf_of"),
            )])),
            onward_client_id: Some(true),
            onward_subject_audience: Some(true),
            onward_preview: Some(vec![PreviewVariant::ActorToken]),
        };
        let profile = Profile::default().with_keys(keys.clone());
        let back = ProfileKeys {
            max_actor_chain: Some(profile.max_actor_chain),
            token_types: Some(profile.token_types),
            required_claims: Some(profile.required_claims),
            max_onward_lifetime: profile
                .max_onward_lifetime
                .map(ferrohealth_config::units::Duration::from_secs),
            onward_grant: Some(profile.onward_grant),
            onward_indicator: Some(profile.onward_indicator),
            onward_parameters: Some(profile.onward_parameters),
            onward_client_id: Some(profile.onward_client_id),
            onward_subject_audience: Some(profile.onward_subject_audience),
            onward_preview: Some(profile.onward_preview),
        };
        assert_eq!(keys, back);
    }

    // NOTE: RFC 9068 §2.2 and §5: a client credentials token's `sub` is its
    // `client_id`.
    #[test]
    fn a_token_whose_sub_is_its_client_is_app_only() {
        let claims = |sub: &str| {
            serde_json::json!({ "sub": sub, "client_id": "svc" })
                .as_object()
                .cloned()
                .expect("an object")
        };
        assert!(Profile::app_only(&claims("svc")));
        assert!(!Profile::app_only(&claims("person-1")));
    }

    #[test]
    fn a_scope_that_is_no_string_does_not_read() {
        let claims = serde_json::json!({ "scope": ["a", "b"] });
        let claims = claims.as_object().cloned().expect("an object");
        assert_eq!(Err(ScopeFormError), Profile::scope(&claims));
    }
}
