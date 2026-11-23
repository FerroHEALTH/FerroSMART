// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `[<lane>.credentials.onward]` table: the onward target of one lane
//! and the issuer of its onward tokens, beside the lane's own client
//! credentials grant, which it authenticates with.
//!
//! The issuer is described in the table itself, its kind, preset, profile
//! keys and tables, because the issuer of onward tokens is not always one
//! whose tokens the surface admits: a `federation` issuer of another
//! party's node must never become an `[auth.issuer.<name>]` of this one. No
//! specification governs the configuration model: our own design.

use ferrohealth_secret::secret_url::SecretUrl;
use serde::Deserialize;
use serde::Serialize;

use crate::assurance::AssuranceSection;
use crate::federation::FederationSection;
use crate::kind::IssuerKind;
use crate::profile::ProfileKeys;

/// One `[<lane>.credentials.onward]` table.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct OnwardSection {
    /// The identifier of the issuer of the onward tokens, whose metadata
    /// names its token endpoint unless `token_endpoint` is set. It renders
    /// with any userinfo masked, as [`SecretUrl`] renders itself.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub issuer: SecretUrl,
    /// `federation` for another party's issuer; unset for a SMART
    /// authorization server.
    pub kind: Option<IssuerKind>,
    /// The `profile` table: the keys set over the defaults;
    /// `max_onward_lifetime` is required.
    pub profile: ProfileKeys,
    /// The token endpoint itself; empty to discover it from `issuer`. It
    /// renders with its userinfo and its query masked.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub token_endpoint: SecretUrl,
    /// The client id at this issuer; empty for the lane's own.
    pub client_id: String,
    /// The audiences an onward token may name, at least one.
    pub audiences: Vec<String>,
    /// The `resource` or `audience` values the request names, as the
    /// profile's `onward_indicator` says.
    pub indicators: Vec<String>,
    /// The `scope` the request names; empty for none.
    pub scope: String,
    /// The claim a chained federation route carries from the subject token
    /// to the onward token; empty for none.
    pub correlation_claim: String,
    /// What a `federation` issuer asserts, over its preset's defaults;
    /// `exchanges_from` and `person_mapping` are required.
    pub federation: Option<FederationSection>,
    /// The assurance level the issuer's tokens carry.
    pub assurance: Option<AssuranceSection>,
    /// Whether the lane holds the tokens it obtains until they near their
    /// `exp`. `false` exchanges a token at the issuer on every call, a
    /// setting for a performance measurement's self-test, never for
    /// production. `true` by default.
    pub cache: bool,
    /// Whether every token exchange sent without an actor token names the
    /// lane's client as its actor with an assertion signed by the current
    /// key of its `oauth` table's key ring (RFC 8693 §2.1;
    /// [`Onward::with_actor_assertion`]). `false` by default.
    ///
    /// [`Onward::with_actor_assertion`]: crate::client::onward::exchange::Onward::with_actor_assertion
    pub actor_assertion: bool,
}

impl Default for OnwardSection {
    fn default() -> Self {
        Self {
            issuer: SecretUrl::default(),
            kind: None,
            profile: ProfileKeys::default(),
            token_endpoint: SecretUrl::default(),
            client_id: String::new(),
            audiences: Vec::new(),
            indicators: Vec::new(),
            scope: String::new(),
            correlation_claim: String::new(),
            federation: None,
            assurance: None,
            cache: true,
            actor_assertion: false,
        }
    }
}

/// What a `[<lane>.credentials.onward]` table resolves to: the client and
/// the target it obtains tokens for.
#[cfg(feature = "fetch")]
#[derive(Debug, Clone)]
pub struct OnwardLane {
    /// The client of the issuer's onward grants.
    pub onward: crate::client::onward::exchange::Onward,
    /// The lane's target.
    pub target: crate::client::onward::Target,
}

#[cfg(feature = "fetch")]
mod resolve {
    use crate::client::ClientCredentials;
    use crate::client::Endpoint;
    use crate::client::onward::Target;
    use crate::client::onward::exchange::Onward;
    use crate::config::ConfigError;
    use crate::config::credentials::CredentialsSection;
    use crate::config::onward::OnwardLane;
    use crate::config::onward::OnwardSection;
    use crate::config::read::parse_url;
    use crate::federation::FederationSection;
    use crate::profile::Profile;
    use crate::resource::ResourceError;
    use crate::resource::Settings;
    use crate::scope::is_scope_token;

    impl CredentialsSection {
        /// Resolves the onward table: `None` when the lane declares none.
        ///
        /// # Errors
        ///
        /// [`ConfigError::Exclusive`] beside a Basic `user`,
        /// [`ConfigError::Missing`] without the `oauth` table it
        /// authenticates with, and as [`OauthSection::resolve`] and
        /// [`OnwardSection::resolve`] do.
        ///
        /// [`OauthSection::resolve`]: crate::config::credentials::OauthSection::resolve
        pub fn onward(&self) -> Result<Option<OnwardLane>, ConfigError> {
            let Some(section) = &self.onward else {
                return Ok(None);
            };
            if !self.user.is_empty() {
                return Err(ConfigError::Exclusive {
                    left: "credentials.user",
                    right: "credentials.onward",
                });
            }
            let oauth = self.oauth.as_ref().ok_or(ConfigError::Missing {
                key: "credentials.oauth, which credentials.onward authenticates with",
            })?;
            self.check_actor_key(oauth)?;
            section.resolve(oauth.resolve()?).map(Some)
        }

        /// Resolves the `onward` table as [`CredentialsSection::onward`]
        /// does, the `oauth` table's TLS built by `tls`.
        ///
        /// # Errors
        ///
        /// Returns [`ConfigError`] as [`CredentialsSection::onward`] does,
        /// and [`ConfigError::TlsBuild`] when `tls` refuses the `oauth`
        /// table's TLS.
        pub fn onward_with_tls(
            &self,
            tls: &dyn crate::config::TlsBuilder,
        ) -> Result<Option<OnwardLane>, ConfigError> {
            let Some(section) = &self.onward else {
                return Ok(None);
            };
            match &self.oauth {
                Some(oauth) if self.user.is_empty() => {
                    self.check_actor_key(oauth)?;
                    section.resolve(oauth.resolve_with_tls(tls)?).map(Some)
                }
                _ => self.onward(),
            }
        }
    }

    impl OnwardSection {
        /// Resolves the table into the client of its issuer, authenticating
        /// as `credentials` with the table's token endpoint and client id,
        /// and its target.
        ///
        /// # Errors
        ///
        /// [`ConfigError::Missing`] naming `credentials.onward.issuer` or
        /// `audiences` when unset; [`ConfigError::Scope`] for a scope token
        /// outside RFC 6749 §3.3; [`ConfigError::Issuer`] for a profile or
        /// table the issuer's rules refuse; and
        /// [`ConfigError::Onward`] for an issuer the onward client refuses
        /// (another kind, no `max_onward_lifetime`, a federation table
        /// without `exchanges_from` or `person_mapping`) or a target its
        /// grant cannot ask for.
        pub fn resolve(
            &self,
            mut credentials: ClientCredentials,
        ) -> Result<OnwardLane, ConfigError> {
            if self.issuer.is_empty() {
                return Err(ConfigError::Missing {
                    key: "credentials.onward.issuer",
                });
            }
            let kind = self.kind.unwrap_or_default();
            if self.audiences.iter().all(String::is_empty) {
                return Err(ConfigError::Missing {
                    key: "credentials.onward.audiences",
                });
            }
            if let Some(bad) = self
                .scope
                .split(' ')
                .filter(|token| !token.is_empty())
                .find(|token| !is_scope_token(token))
            {
                return Err(ConfigError::Scope {
                    scope: bad.to_owned(),
                });
            }
            credentials.endpoint = if self.token_endpoint.is_empty() {
                Endpoint::Issuer(self.issuer.expose().to_owned())
            } else {
                Endpoint::Token(parse_url(
                    self.token_endpoint.expose(),
                    "credentials.onward.token_endpoint",
                )?)
            };
            if !self.client_id.is_empty() {
                credentials.client_id.clone_from(&self.client_id);
            }
            let refused = |source: ResourceError| ConfigError::Issuer {
                issuer: crate::config::shown(&self.issuer),
                source: Box::new(source),
            };
            // NOTE: no specification governs this: our own design; the onward
            // check never reads `audience`, which the settings require one of.
            let mut settings =
                Settings::new(self.issuer.expose(), credentials.client_id.clone(), kind);
            settings.profile = Profile::default().with_keys(self.profile.clone());
            settings.assurance.clone_from(&self.assurance);
            settings.federation = self.federation.clone().map(|table| FederationSection {
                issuer: self.issuer.clone(),
                ..table
            });
            settings.validate().map_err(refused)?;
            let mut target = Target::new(
                self.audiences
                    .iter()
                    .filter(|audience| !audience.is_empty())
                    .cloned(),
            );
            for indicator in &self.indicators {
                target = target.with_indicator(indicator.clone());
            }
            if !self.scope.is_empty() {
                target = target.with_scope(self.scope.clone());
            }
            if !self.correlation_claim.is_empty() {
                target = target.with_correlation_claim(self.correlation_claim.clone());
            }
            let mut onward =
                Onward::new(settings, credentials).map_err(|source| ConfigError::Onward {
                    source: Box::new(source),
                })?;
            if !self.cache {
                tracing::warn!(
                    issuer = crate::config::shown(&self.issuer),
                    "the onward token cache is off: every call exchanges a token at the issuer"
                );
                onward = onward.without_cache();
            }
            if self.actor_assertion {
                onward =
                    onward
                        .with_actor_assertion()
                        .map_err(|source| ConfigError::OnwardActor {
                            source: Box::new(source),
                        })?;
            }
            onward
                .check_target(&target)
                .map_err(|source| ConfigError::Onward {
                    source: Box::new(source),
                })?;
            Ok(OnwardLane { onward, target })
        }
    }
}
