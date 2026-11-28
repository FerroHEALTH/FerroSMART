// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A remote policy decision point (feature `remote`), in the NIST SP 800-162
//! sense of a PDP the PEP consults over the network.
//!
//! Each resource type is bound to one policy of the remote point. For each
//! combination the engine posts `{server}{policy}` with a flat JSON object
//! of the attributes the binding names, read from the combination's resource
//! attributes, then for `kind` from the subject's caller kind (the name
//! `ferrohealth_smart::kind::CallerKind::as_str` gives), and then from the
//! subject's attributes: a `200` permits, any `4xx` denies,
//! and the body of the answer is not read, so the point imposes no policy
//! language. Any other answer, a redirect included, and any failure to reach
//! the point is no decision: an [`AuthzError::Remote`] carrying the status
//! when there was one. Under a client credentials grant the call carries the
//! token of `ferrohealth-smart`, sent once more under a new token on a
//! `401`; a second `401` is no decision either. A point built with
//! [`RemotePdp::with_client`] calls over the product's own HTTP client and
//! tries a call again, under the `retry` table of the endpoint, when the
//! point could not be reached or answered a `5xx`. The wire contract and the
//! retry rule are our own design; no specification governs them.

use std::collections::BTreeMap;
use std::time::Duration;

use ferrohealth_smart::client::cache::TokenSource;
use ferrohealth_smart::client::outbound::Authorization;
use ferrohealth_smart::client::outbound::OutboundClient;
use ferrohealth_smart::config::endpoint::RetrySection;
use ferrohealth_smart::kind::CallerKind;
use http::StatusCode;
use url::Url;

use crate::engine::AuthzError;
use crate::engine::PolicyEngine;
use crate::request::Combination;
use crate::request::Decision;
use crate::request::Request;

/// The policy one resource type is decided by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The policy's path under the server.
    pub policy: String,
    /// The attributes the posted object carries, when they have a value.
    pub parameters: Vec<String>,
}

/// How the remote point is reached.
#[derive(Debug, Clone)]
pub struct RemoteSettings {
    /// The base URL; it ends with `/`, and every policy path joins it.
    pub server: Url,
    /// The policy of each resource type.
    pub bindings: BTreeMap<String, Binding>,
    /// How long establishing the connection may take.
    pub connect_timeout: Duration,
    /// How long one call may take.
    pub request_timeout: Duration,
}

/// Why a remote point gave no decision.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RemoteError {
    /// The settings do not hold.
    #[error("the remote policy point settings are refused: {reason}")]
    Settings {
        /// Which rule is broken.
        reason: &'static str,
    },
    /// No policy is bound to the request's resource type.
    #[error("no remote policy is bound to the resource type {resource_type}")]
    Unbound {
        /// The resource type.
        resource_type: String,
    },
    /// The call failed before an answer.
    #[error("the remote policy point could not be reached")]
    Transport(#[source] reqwest::Error),
    /// No token could be obtained for the call.
    #[error("no token for the remote policy point could be obtained")]
    Token(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The point answered a status that is no decision.
    #[error("the remote policy point answered {status}, which is no decision")]
    Status {
        /// The status.
        status: StatusCode,
    },
}

/// The remote policy decision point.
#[derive(Debug)]
pub struct RemotePdp {
    client: reqwest::Client,
    /// The outbound client `client` came from, held so the connections to
    /// its URL stay cleared for revocation while the point lives.
    #[expect(dead_code, reason = "held for its lifetime, never read")]
    outbound: Option<OutboundClient>,
    settings: RemoteSettings,
    retry: RetrySection,
    token: Option<TokenSource>,
    basic: Option<http::HeaderValue>,
    per_try: Option<Duration>,
}

impl RemotePdp {
    /// Returns the point `settings` describe, authorized by `token` when
    /// given; without one, credentials in the server URL travel as HTTP
    /// Basic, as the HTTP client sends them. Each call is tried once.
    ///
    /// # Errors
    ///
    /// [`AuthzError::Remote`] when the server URL is not `http` or `https`
    /// or does not end with `/`, or the HTTP client cannot be built.
    pub fn new(settings: RemoteSettings, token: Option<TokenSource>) -> Result<Self, AuthzError> {
        check(&settings)?;
        let client = reqwest::Client::builder()
            .connect_timeout(settings.connect_timeout)
            .timeout(settings.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| remote(RemoteError::Transport(error)))?;
        let retry = RetrySection {
            max_attempts: 1,
            ..RetrySection::default()
        };
        Ok(Self {
            per_try: Some(settings.request_timeout),
            client,
            outbound: None,
            settings,
            retry,
            token,
            basic: None,
        })
    }

    /// Returns the point `settings` describe, reached over `client` and
    /// tried again as `retry` allows, authorized by `token` when given.
    ///
    /// The product builds `client` from the integration's
    /// [`EndpointSection`](ferrohealth_smart::config::endpoint::EndpointSection),
    /// so its TLS and its connect timeout are the section's, and turns its
    /// redirects off: a redirect is no decision. Each try is bounded by
    /// `settings.request_timeout`; `settings.connect_timeout` is not read,
    /// since the client carries its own. A call is tried again when the
    /// point could not be reached, the try timed out, or the point answered
    /// a `5xx`, up to `retry.max_attempts` tries in all, waiting
    /// `retry.initial_backoff` before the second and twice as long before
    /// each later one, never longer than `retry.max_backoff`. A `4xx` is a
    /// decision, and a redirect or a second `401` are faults another try
    /// does not mend, so none of them is tried again.
    ///
    /// # Errors
    ///
    /// [`AuthzError::Remote`] when the server URL is not `http` or `https`
    /// or does not end with `/`, `retry.max_attempts` is 0, or
    /// `retry.initial_backoff` is longer than `retry.max_backoff`.
    pub fn with_client(
        settings: RemoteSettings,
        client: reqwest::Client,
        retry: RetrySection,
        token: Option<TokenSource>,
    ) -> Result<Self, AuthzError> {
        check(&settings)?;
        if retry.max_attempts == 0 {
            return Err(remote(RemoteError::Settings {
                reason: "retry.max_attempts is 0; 1 tries once",
            }));
        }
        if retry.initial_backoff > retry.max_backoff {
            return Err(remote(RemoteError::Settings {
                reason: "retry.initial_backoff is longer than retry.max_backoff",
            }));
        }
        Ok(Self {
            per_try: Some(settings.request_timeout),
            client,
            outbound: None,
            settings,
            retry,
            token,
            basic: None,
        })
    }

    /// Returns the point at `outbound`'s URL, deciding the resource types
    /// `bindings` name, reached over `outbound`'s HTTP engine with its
    /// authorization and tried again as its retry table allows, as
    /// [`RemotePdp::with_client`] tries.
    ///
    /// The product builds `outbound` from `[authz.abac.remote.endpoint]`
    /// with [`OutboundClient::build`], so the engine carries the table's TLS
    /// and timeouts and follows no redirect. A Basic credential is sent on
    /// every call; a client credentials token is renewed once on a `401`.
    ///
    /// # Errors
    ///
    /// [`AuthzError::Remote`] when the URL is not `http` or `https` or does
    /// not end with `/`, or the endpoint's credential is a kind the point
    /// does not send.
    pub fn from_outbound(
        bindings: BTreeMap<String, Binding>,
        outbound: &OutboundClient,
    ) -> Result<Self, AuthzError> {
        let settings = RemoteSettings {
            server: outbound.url().clone(),
            bindings,
            connect_timeout: Duration::ZERO,
            request_timeout: Duration::ZERO,
        };
        check(&settings)?;
        let (token, basic) = match outbound.authorization() {
            None => (None, None),
            Some(Authorization::Bearer(source)) => (Some(source.clone()), None),
            Some(Authorization::Basic(credential)) => (None, Some(credential.header_value())),
            Some(_) => {
                return Err(remote(RemoteError::Settings {
                    reason: "the endpoint's credential is no kind the point sends",
                }));
            }
        };
        Ok(Self {
            client: outbound.http().clone(),
            outbound: Some(outbound.clone()),
            settings,
            retry: *outbound.retry(),
            token,
            basic,
            per_try: None,
        })
    }

    /// Asks the point about one combination, as often as the retry table
    /// allows: `Ok(true)` permits.
    async fn permits(
        &self,
        binding: &Binding,
        request: &Request<'_>,
        combination: &Combination<'_>,
    ) -> Result<bool, AuthzError> {
        let url = self
            .settings
            .server
            .join(&binding.policy)
            .map_err(|_unjoinable| {
                remote(RemoteError::Settings {
                    reason: "a policy path does not join the server URL",
                })
            })?;
        let body = body(binding, request, combination);
        let max_backoff = Duration::from(self.retry.max_backoff);
        let mut backoff = Duration::from(self.retry.initial_backoff);
        let mut attempt = 1;
        loop {
            match self.try_once(&url, &body).await {
                Err(error) if attempt < self.retry.max_attempts && retried(&error) => {
                    tracing::warn!(
                        attempt,
                        delay_ms = backoff.as_millis(),
                        "retrying a call to the remote policy point"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = backoff.saturating_mul(2).min(max_backoff);
                    attempt += 1;
                }
                outcome => return outcome.map_err(remote),
            }
        }
    }

    /// Posts `body` to `url` once: `Ok(true)` permits.
    async fn try_once(
        &self,
        url: &Url,
        body: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<bool, RemoteError> {
        let send = |bearer: Option<http::HeaderValue>| {
            let mut call = self.client.post(url.clone()).json(body);
            if let Some(per_try) = self.per_try {
                call = call.timeout(per_try);
            }
            if let Some(bearer) = bearer.or_else(|| self.basic.clone()) {
                call = call.header(http::header::AUTHORIZATION, bearer);
            }
            call.send()
        };
        let response = match &self.token {
            None => send(None).await.map_err(RemoteError::Transport)?,
            Some(token) => {
                let response = token
                    .call(|bearer| send(Some(bearer)))
                    .await
                    .map_err(|error| RemoteError::Token(Box::new(error)))?;
                if response.status() == StatusCode::UNAUTHORIZED {
                    return Err(RemoteError::Status {
                        status: StatusCode::UNAUTHORIZED,
                    });
                }
                response
            }
        };
        let status = response.status();
        if status == StatusCode::OK {
            Ok(true)
        } else if status.is_client_error() {
            Ok(false)
        } else {
            Err(RemoteError::Status { status })
        }
    }
}

/// Checks the server URL, as every constructor does.
fn check(settings: &RemoteSettings) -> Result<(), AuthzError> {
    if !matches!(settings.server.scheme(), "http" | "https") {
        return Err(remote(RemoteError::Settings {
            reason: "the server is not an http or https URL",
        }));
    }
    if !settings.server.path().ends_with('/') {
        return Err(remote(RemoteError::Settings {
            reason: "the server URL does not end with /",
        }));
    }
    Ok(())
}

/// Whether another try may reach a decision: the point was not reached, or
/// it answered a `5xx`.
fn retried(error: &RemoteError) -> bool {
    match error {
        RemoteError::Transport(_) => true,
        RemoteError::Status { status } => status.is_server_error(),
        RemoteError::Settings { .. } | RemoteError::Unbound { .. } | RemoteError::Token(_) => false,
    }
}

#[async_trait::async_trait]
impl PolicyEngine for RemotePdp {
    async fn decide(&self, request: &Request<'_>) -> Result<Decision, AuthzError> {
        let binding = self
            .settings
            .bindings
            .get(request.resource_type())
            .ok_or_else(|| {
                remote(RemoteError::Unbound {
                    resource_type: request.resource_type().to_owned(),
                })
            })?;
        for combination in request.combinations() {
            if !self.permits(binding, request, &combination).await? {
                return Ok(Decision::Deny {
                    policies: vec![binding.policy.clone()],
                });
            }
        }
        Ok(Decision::Permit {
            policies: vec![binding.policy.clone()],
        })
    }
}

/// The posted object: each parameter with a value, from the combination
/// first, then the subject's caller kind for `kind`, and the subject's
/// attributes after.
fn body(
    binding: &Binding,
    request: &Request<'_>,
    combination: &Combination<'_>,
) -> serde_json::Map<String, serde_json::Value> {
    binding
        .parameters
        .iter()
        .filter_map(|name| {
            combination
                .get(name.as_str())
                .copied()
                .or_else(|| {
                    (name == "kind")
                        .then(|| request.subject().kind().map(CallerKind::as_str))
                        .flatten()
                })
                .or_else(|| request.subject().attributes().get(name).map(String::as_str))
                .map(|value| (name.clone(), serde_json::Value::String(value.to_owned())))
        })
        .collect()
}

/// Wraps a remote failure.
fn remote(error: RemoteError) -> AuthzError {
    AuthzError::Remote(Box::new(error))
}
