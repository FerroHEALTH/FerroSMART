// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `tower` layer in front of every route of an `axum` router: the
//! credential check, the type-level scope check and the audit line.
//!
//! The product tells the layer what each route is ([`Classify`]): the
//! interaction it records, what it requires of the caller
//! ([`Requirement`]), which grammar that requirement is checked against
//! (SMART on FHIR or SMART on openEHR), the matched route template and the
//! target name for the audit line. A request without a valid credential
//! answers `401`, one whose credential grants no permission for the
//! interaction `403` (RFC 6750 §3.1), and the body of either is the
//! product's ([`Render`]). What a scope reaches inside a type (the patient
//! compartment, the launch context's EHR) is checked by the handler, which
//! reads the [`Access`] the layer leaves on the request.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::time::Instant;

use axum::body::Body;
use axum::response::Response;
use http::Extensions;
use http::HeaderMap;
use http::HeaderName;
use http::Method;
use http::Request;
use http::Uri;
use http::header;
use tower::Layer;
use tower::Service;

use crate::audit::Actor;
use crate::audit::AuditLine;
use crate::basic::PasswordStore;
use crate::extract::HeaderOnly;
use crate::refusal::Refusal;
use crate::refusal::Schemes;
use crate::resource::Access;
use crate::resource::Caller;
use crate::resource::Honoured;
use crate::resource::Rejection;
use crate::resource::Verifier;
use crate::scope::Permission;

/// What a route requires of the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Requirement {
    /// No credential: a client reaches the route before it holds a token
    /// (the capability statement, the SMART discovery document).
    Public,
    /// A valid credential, whatever it grants.
    Caller,
    /// A valid credential granting `permission` on `resource_type` under the
    /// SMART on FHIR grammar (SMART App Launch 2.2.0, Scopes and Launch
    /// Context).
    Fhir {
        /// The permission the interaction needs.
        permission: Permission,
        /// The FHIR resource type the route addresses.
        resource_type: String,
    },
    /// A valid credential granting `permission` on a resource of `family`
    /// under the SMART on openEHR grammar (`master08 §Resource Scopes`);
    /// `resource` is the template id or query name the route addresses, or
    /// `None` for an operation only a bare `*` or `**` covers.
    #[cfg(feature = "openehr")]
    OpenEhr {
        /// The resource family the route addresses.
        family: openehr_sdt::smart_scopes::ResourceFamily,
        /// The permission the operation needs.
        permission: openehr_sdt::smart_scopes::Permission,
        /// The resource the route names, when the product can see it.
        resource: Option<String>,
    },
    /// A valid credential whose `scope` claim names this scope verbatim (a
    /// product's own operator or admin scope).
    Scope(String),
    /// A valid credential of a client the product lists by `client_id`,
    /// which is how a surface no scope covers (the DEMOGRAPHIC API) is
    /// reached (no specification governs this: our own design).
    Client(Vec<String>),
    /// Either requirement.
    Either(Box<Requirement>, Box<Requirement>),
    /// No caller is admitted: a route the product mounted without a
    /// classification fails closed.
    Refused,
}

impl Requirement {
    /// Returns whether `access` meets this requirement, `honoured` saying
    /// what the product honours for the caller beyond a `user/` grant.
    #[must_use]
    pub fn met_by(&self, access: &Access, honoured: Honoured) -> bool {
        match self {
            Self::Public | Self::Caller => true,
            Self::Fhir {
                permission,
                resource_type,
            } => access.reach(*permission, resource_type).is_some(),
            #[cfg(feature = "openehr")]
            Self::OpenEhr {
                family,
                permission,
                resource,
            } => {
                access.caller().is_some_and(|caller| {
                    crate::openehr::granted(
                        &caller.openehr_scopes(),
                        *family,
                        *permission,
                        resource.as_deref(),
                        honoured,
                    )
                }) || matches!(access, Access::Open)
            }
            Self::Scope(scope) => access.has_scope(scope),
            Self::Client(clients) => access
                .caller()
                .and_then(Caller::client_id)
                .is_some_and(|client| clients.iter().any(|listed| listed == client)),
            Self::Either(left, right) => {
                left.met_by(access, honoured) || right.met_by(access, honoured)
            }
            Self::Refused => false,
        }
    }
}

/// What the layer learned about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The interaction the audit line records.
    interaction: &'static str,
    /// What the route requires.
    requirement: Requirement,
    /// The matched route template the audit line records.
    route: Option<String>,
    /// The product's name for what was addressed, which the audit line
    /// records.
    addressed: Option<String>,
}

impl Target {
    /// Returns a target recorded as `interaction` with `requirement`.
    #[must_use]
    pub const fn new(interaction: &'static str, requirement: Requirement) -> Self {
        Self {
            interaction,
            requirement,
            route: None,
            addressed: None,
        }
    }

    /// Returns this target under the matched `route` template.
    #[must_use]
    pub fn route(mut self, route: impl Into<String>) -> Self {
        self.route = Some(route.into());
        self
    }

    /// Returns this target addressing `target`, the product's name for it
    /// (`Condition/c-1`, `ehr/…/composition`).
    #[must_use]
    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.addressed = Some(target.into());
        self
    }

    /// Returns the interaction.
    #[must_use]
    pub const fn interaction(&self) -> &'static str {
        self.interaction
    }

    /// Returns the requirement.
    #[must_use]
    pub const fn requirement(&self) -> &Requirement {
        &self.requirement
    }

    /// Returns the matched route template.
    #[must_use]
    pub fn route_template(&self) -> Option<&str> {
        self.route.as_deref()
    }

    /// Returns the product's name for what was addressed.
    #[must_use]
    pub fn target_name(&self) -> Option<&str> {
        self.addressed.as_deref()
    }
}

/// How a product reads what a request is.
///
/// `None` is a route outside the guarded surface, which passes untouched
/// and writes no audit line.
pub trait Classify: Send + Sync + 'static {
    /// Returns what `method` on `uri` is, reading the router's extensions
    /// (the matched route template) when it needs them.
    fn classify(&self, method: &Method, uri: &Uri, extensions: &Extensions) -> Option<Target>;
}

impl<F> Classify for F
where
    F: Fn(&Method, &Uri, &Extensions) -> Option<Target> + Send + Sync + 'static,
{
    fn classify(&self, method: &Method, uri: &Uri, extensions: &Extensions) -> Option<Target> {
        self(method, uri, extensions)
    }
}

/// How a product answers a refusal: the body is its own, the status and the
/// `WWW-Authenticate` challenge are [`Refusal`]'s.
pub trait Render: Send + Sync + 'static {
    /// Returns the response of `refusal`.
    fn render(&self, refusal: &Refusal) -> Response;
}

impl<F> Render for F
where
    F: Fn(&Refusal) -> Response + Send + Sync + 'static,
{
    fn render(&self, refusal: &Refusal) -> Response {
        self(refusal)
    }
}

/// The interaction a handler answered a request as, left on the response
/// when it differs from the classified one (one route serving two Bundle
/// types), which the audit line reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnsweredAs(pub &'static str);

/// What a product honours for a caller, read from its issuer or client
/// lists once the credential holds.
type Honours = Arc<dyn Fn(&Caller) -> Honoured + Send + Sync>;

/// The credentials a layer checks against: a verifier for bearer tokens,
/// the password store for Basic, or neither on an open surface.
#[derive(Clone)]
pub struct Gate {
    /// The verifier of bearer tokens, when they are admitted.
    bearer: Option<Arc<dyn Verifier>>,
    /// The password store, when Basic credentials are admitted.
    basic: Option<Arc<PasswordStore>>,
    /// The protection space the challenges name (RFC 6750 §3, RFC 7617 §2).
    realm: Option<String>,
    /// What the product honours for a caller.
    honours: Honours,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            bearer: None,
            basic: None,
            realm: None,
            honours: Arc::new(|_caller| Honoured::default()),
        }
    }
}

impl std::fmt::Debug for Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gate")
            .field("bearer", &self.bearer.is_some())
            .field("basic", &self.basic)
            .field("realm", &self.realm)
            .finish_non_exhaustive()
    }
}

impl Gate {
    /// Returns the gate of a surface that authenticates no caller.
    #[must_use]
    pub fn open() -> Self {
        Self::default()
    }

    /// Returns this gate admitting the bearer tokens `verifier` checks.
    #[must_use]
    pub fn with_bearer(mut self, verifier: Arc<dyn Verifier>) -> Self {
        self.bearer = Some(verifier);
        self
    }

    /// Returns this gate admitting the Basic credentials `store` holds.
    #[must_use]
    pub fn with_basic(mut self, store: Arc<PasswordStore>) -> Self {
        self.basic = Some(store);
        self
    }

    /// Returns this gate naming `realm` on every challenge.
    #[must_use]
    pub fn with_realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = Some(realm.into());
        self
    }

    /// Returns this gate reading what the product honours for a caller
    /// from `honours`: whether the caller is a listed backend client and
    /// whether its issuer is bound to the product's EHR space.
    #[must_use]
    pub fn with_honoured(
        mut self,
        honours: impl Fn(&Caller) -> Honoured + Send + Sync + 'static,
    ) -> Self {
        self.honours = Arc::new(honours);
        self
    }

    /// Returns whether the gate admits no credential at all.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.bearer.is_none() && self.basic.is_none()
    }

    /// Returns the schemes the gate admits.
    #[must_use]
    pub const fn schemes(&self) -> Schemes {
        Schemes {
            bearer: self.bearer.is_some(),
            basic: self.basic.is_some(),
        }
    }

    /// Returns the realm the challenges name.
    #[must_use]
    pub fn realm(&self) -> Option<&str> {
        self.realm.as_deref()
    }

    /// Returns what the product honours for `access`.
    #[must_use]
    pub fn honoured(&self, access: &Access) -> Honoured {
        access
            .caller()
            .map_or_else(Honoured::default, |caller| (self.honours)(caller))
    }

    /// Returns who calls with `headers`, or the refusal.
    ///
    /// The token is read from the `Authorization` header alone, never from
    /// a query or a form body (RFC 9700 §4.3.2), and the scheme is compared
    /// case-insensitively (RFC 9110 §11.1); a scheme the gate does not admit
    /// is a missing credential.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal::Missing`] for no admitted credential,
    /// [`Refusal::InvalidRequest`] for two credentials or a value that is
    /// no credential, [`Refusal::InvalidToken`] or [`Refusal::InvalidBasic`]
    /// for one that does not hold, and [`Refusal::Unavailable`] when a token
    /// could not be checked.
    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<Access, Refusal> {
        if self.is_open() {
            return Ok(Access::Open);
        }
        let missing = Refusal::Missing(self.schemes());
        let mut values = headers.get_all(header::AUTHORIZATION).iter();
        let value = match (values.next(), values.next()) {
            (None, _) => return Err(missing),
            (Some(_), Some(_)) => return Err(Refusal::InvalidRequest),
            (Some(value), None) => value,
        };
        let text = value.to_str().map_err(|_opaque| Refusal::InvalidRequest)?;
        let (scheme, credential) = text.split_once(' ').ok_or(Refusal::InvalidRequest)?;
        let credential = credential.trim();
        if credential.is_empty() {
            return Err(Refusal::InvalidRequest);
        }
        let caller = match (
            scheme.eq_ignore_ascii_case("Bearer"),
            scheme.eq_ignore_ascii_case("Basic"),
        ) {
            (true, _) => {
                let verifier = self.bearer.as_ref().ok_or(missing)?;
                match verifier.verify(credential).await {
                    Ok(caller) => caller,
                    Err(rejection) => {
                        match &rejection {
                            Rejection::Invalid { reason } => {
                                tracing::debug!(reason, "an access token was refused");
                            }
                            Rejection::Unavailable { source } => {
                                tracing::error!(
                                    error = %source,
                                    "the authorization server's key set could not be read"
                                );
                            }
                            Rejection::Missing => {}
                        }
                        return Err(Refusal::from(&rejection));
                    }
                }
            }
            (_, true) => {
                let store = Arc::clone(self.basic.as_ref().ok_or(missing)?);
                let value = value.clone();
                let verified = tokio::task::spawn_blocking(move || store.verify(&value))
                    .await
                    .map_err(|_cancelled| Refusal::InvalidBasic)?;
                match verified {
                    Ok(verified) => Caller::basic(verified.username, &verified.scope),
                    Err(_invalid) => return Err(Refusal::InvalidBasic),
                }
            }
            _ => return Err(missing),
        };
        Ok(Access::Caller(Arc::new(caller)))
    }
}

/// The layer that guards a router with a [`Gate`], classifying each request
/// with `C`.
pub struct AuthLayer<C> {
    /// The credentials admitted.
    gate: Arc<Gate>,
    /// What each request is.
    classify: Arc<C>,
    /// How a refusal is answered.
    render: Arc<dyn Render>,
    /// The header the audit line reads the request id from.
    request_id: HeaderName,
}

impl<C> Clone for AuthLayer<C> {
    fn clone(&self) -> Self {
        Self {
            gate: Arc::clone(&self.gate),
            classify: Arc::clone(&self.classify),
            render: Arc::clone(&self.render),
            request_id: self.request_id.clone(),
        }
    }
}

impl<C> std::fmt::Debug for AuthLayer<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthLayer")
            .field("gate", &self.gate)
            .field("request_id", &self.request_id)
            .finish_non_exhaustive()
    }
}

impl<C: Classify> AuthLayer<C> {
    /// Returns a layer over `gate`, classifying with `classify`.
    ///
    /// A refusal is answered with its status and challenge and no body
    /// ([`HeaderOnly`]) until [`AuthLayer::with_render`] names the product's
    /// body; the audit line reads the request id from `x-request-id`.
    #[must_use]
    pub fn new(gate: Gate, classify: C) -> Self {
        let render = match gate.realm() {
            Some(realm) => HeaderOnly::with_realm(realm),
            None => HeaderOnly::default(),
        };
        Self {
            gate: Arc::new(gate),
            classify: Arc::new(classify),
            render: Arc::new(render),
            request_id: HeaderName::from_static("x-request-id"),
        }
    }

    /// Returns this layer answering a refusal with `render`.
    #[must_use]
    pub fn with_render(mut self, render: impl Render) -> Self {
        self.render = Arc::new(render);
        self
    }

    /// Returns this layer reading the request id from `name`.
    #[must_use]
    pub fn with_request_id_header(mut self, name: HeaderName) -> Self {
        self.request_id = name;
        self
    }
}

impl<S, C> Layer<S> for AuthLayer<C> {
    type Service = AuthService<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            gate: Arc::clone(&self.gate),
            classify: Arc::clone(&self.classify),
            render: Arc::clone(&self.render),
            request_id: self.request_id.clone(),
        }
    }
}

/// The service [`AuthLayer`] wraps around `S`.
pub struct AuthService<S, C> {
    /// The guarded service.
    inner: S,
    /// The credentials admitted.
    gate: Arc<Gate>,
    /// What each request is.
    classify: Arc<C>,
    /// How a refusal is answered.
    render: Arc<dyn Render>,
    /// The header the audit line reads the request id from.
    request_id: HeaderName,
}

impl<S: Clone, C> Clone for AuthService<S, C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            gate: Arc::clone(&self.gate),
            classify: Arc::clone(&self.classify),
            render: Arc::clone(&self.render),
            request_id: self.request_id.clone(),
        }
    }
}

impl<S: std::fmt::Debug, C> std::fmt::Debug for AuthService<S, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthService")
            .field("inner", &self.inner)
            .field("gate", &self.gate)
            .finish_non_exhaustive()
    }
}

impl<S, C> Service<Request<Body>> for AuthService<S, C>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    C: Classify,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        // NOTE: tower's readiness contract, the service polled ready is the
        // one that takes the call, so the clone keeps the ready one.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let gate = Arc::clone(&self.gate);
        let classify = Arc::clone(&self.classify);
        let render = Arc::clone(&self.render);
        let request_id = self.request_id.clone();
        Box::pin(async move {
            let started = Instant::now();
            let at = jiff::Timestamp::now();
            let Some(target) =
                classify.classify(request.method(), request.uri(), request.extensions())
            else {
                return inner.call(request).await;
            };
            let method = request.method().clone();
            let request_id = request
                .headers()
                .get(&request_id)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let (access, response) = match admit(&gate, &target, request.headers()).await {
                Err((access, refusal)) => (access, render.render(&refusal)),
                Ok(access) => {
                    request.extensions_mut().insert(access.clone());
                    (Some(access), inner.call(request).await?)
                }
            };
            let answered = response
                .extensions()
                .get::<AnsweredAs>()
                .map_or(target.interaction, |answered| answered.0);
            AuditLine::new(&method, answered, response.status())
                .timed(at, started.elapsed())
                .by(Actor::of(access.as_ref()))
                .on(target.route_template(), target.target_name())
                .request(request_id.as_deref())
                .write();
            Ok(response)
        })
    }
}

/// Returns the access of a request with `headers` to `target`, or the
/// refusal with the access it was refused under, so the audit line names a
/// caller whose credential held and whose grant did not.
///
/// A public target is admitted without a credential; a refused target is
/// refused before any credential is read.
async fn admit(
    gate: &Gate,
    target: &Target,
    headers: &HeaderMap,
) -> Result<Access, (Option<Access>, Refusal)> {
    match target.requirement() {
        Requirement::Refused => return Err((None, Refusal::Unclassified)),
        Requirement::Public => return Ok(Access::Open),
        _ => {}
    }
    let access = gate
        .authenticate(headers)
        .await
        .map_err(|refusal| (None, refusal))?;
    let honoured = gate.honoured(&access);
    if gate.is_open() || target.requirement().met_by(&access, honoured) {
        Ok(access)
    } else {
        Err((Some(access), Refusal::Forbidden))
    }
}

#[cfg(test)]
mod tests {
    use super::{Requirement, Target};
    use crate::resource::{Access, Caller, Honoured};
    use crate::scope::Permission;
    use std::sync::Arc;

    fn access(scope: &str) -> Access {
        Access::Caller(Arc::new(Caller::new(
            String::from("sub"),
            Some(String::from("client-1")),
            scope,
            None,
            false,
        )))
    }

    fn fhir(permission: Permission) -> Requirement {
        Requirement::Fhir {
            permission,
            resource_type: String::from("Condition"),
        }
    }

    #[test]
    fn a_requirement_reads_the_permission_the_scope_the_client_or_either() {
        let none = Honoured::default();
        let read = fhir(Permission::Read);
        assert!(read.met_by(&access("system/Condition.r"), none));
        assert!(!read.met_by(&access("system/Condition.c"), none));
        let operator = Requirement::Scope(String::from("__operator"));
        assert!(operator.met_by(&access("__operator"), none));
        assert!(!operator.met_by(&access("system/*.cruds"), none));
        let either = Requirement::Either(Box::new(read), Box::new(operator));
        assert!(either.met_by(&access("__operator"), none));
        assert!(either.met_by(&access("system/Condition.r"), none));
        assert!(!either.met_by(&access("system/Condition.c"), none));
        let client = Requirement::Client(vec![String::from("client-1")]);
        assert!(client.met_by(&access(""), none));
        assert!(!Requirement::Client(vec![String::from("other")]).met_by(&access(""), none));
        assert!(
            !client.met_by(&Access::Open, none),
            "an open surface names no client"
        );
        assert!(!Requirement::Refused.met_by(&Access::Open, none));
        assert!(Requirement::Caller.met_by(&access(""), none));
    }

    #[test]
    fn a_target_carries_what_the_path_names() {
        let target = Target::new("read", Requirement::Caller)
            .route("/fhir/{type}/{id}")
            .target("Condition/c-1");
        assert_eq!("read", target.interaction());
        assert_eq!(Some("/fhir/{type}/{id}"), target.route_template());
        assert_eq!(Some("Condition/c-1"), target.target_name());
        assert_eq!(&Requirement::Caller, target.requirement());
    }
}
