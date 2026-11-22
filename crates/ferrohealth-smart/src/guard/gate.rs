// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! How a [`Gate`] reads who calls: the `Authorization` header, or the one
//! header the product names in its place, a
//! bearer token held to the `b64token` syntax and checked by the verifier,
//! a Basic credential checked against the password store, and every refusal
//! a [`Denied`] logged at info with its reason code and the token's issuer,
//! client id and key id.

use std::sync::Arc;

use http::HeaderMap;
use http::HeaderValue;
use http::Method;
use http::request::Parts;

use crate::basic::PasswordStore;
use crate::guard::Gate;
use crate::jws::Named;
use crate::refusal::Denied;
use crate::refusal::Reason;
use crate::refusal::Refusal;
use crate::resource::Access;
use crate::resource::Caller;
use crate::resource::Rejection;
use crate::resource::Verifier;
use crate::sender::Binding;
use crate::sender::Check;
use crate::sender::ClientCertificate;
use crate::sender::SenderConstraint;
use crate::sender::proof::Presented;
use crate::sender::proof::ProofCheck;

/// The request line a credential is held to: what a `DPoP` proof's `htm` and
/// `htu` name, and the client certificate of the connection.
#[derive(Clone, Copy)]
struct Line<'a> {
    /// The request's method.
    method: &'a Method,
    /// The request's path.
    path: &'a str,
    /// The client certificate the product's TLS layer read.
    certificate: Option<&'a ClientCertificate>,
}

impl Gate {
    /// Returns who calls with `headers`, or the denial, for a request whose
    /// method, path and connection the gate is not given.
    ///
    /// A `DPoP` request is then refused, since its proof cannot be held to
    /// the request ([`Check::ProofRequestUnknown`]), and a certificate-bound
    /// token for want of the certificate; [`Gate::authenticate_request`]
    /// reads all three. Every other rule is that method's.
    ///
    /// # Errors
    ///
    /// Returns the [`Denied`] of [`Gate::authenticate_request`].
    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<Access, Denied> {
        self.authenticate_with(headers, None).await
    }

    /// Returns who calls with the request `parts`, or the denial.
    ///
    /// The token is read from the `Authorization` header, or the header
    /// [`Gate::with_credential_header`] names, never from
    /// a query or a form body (RFC 9700 §4.3.2), and the scheme is compared
    /// case-insensitively (RFC 9110 §11.1); a scheme the gate does not admit
    /// is a missing credential. A bearer token outside the `b64token` syntax
    /// of RFC 6750 §2.1, and a caller whose subject is blank (RFC 9068
    /// §2.2), are refused as a token that does not hold. The `DPoP` scheme
    /// is admitted when [`Gate::with_dpop`] names a proof check, and every
    /// caller's `cnf` is held to what the request proves: the `DPoP` proof's
    /// key and the [`ClientCertificate`] the product put in the request's
    /// extensions ([`crate::sender`]).
    ///
    /// # Errors
    ///
    /// Returns a [`Denied`] whose refusal is [`Refusal::Missing`] for no
    /// admitted credential, [`Refusal::InvalidRequest`] for two credentials
    /// or a value that is no credential, [`Refusal::InvalidToken`],
    /// [`Refusal::InvalidDpopToken`], [`Refusal::InvalidDpopProof`] or
    /// [`Refusal::InvalidBasic`] for one that does not hold, and
    /// [`Refusal::Unavailable`] when a token could not be checked; its
    /// [`Denied::reason`] names the check for the product's log.
    pub async fn authenticate_request(&self, parts: &Parts) -> Result<Access, Denied> {
        let line = Line {
            method: &parts.method,
            path: parts.uri.path(),
            certificate: parts.extensions.get::<ClientCertificate>(),
        };
        self.authenticate_with(&parts.headers, Some(line)).await
    }

    /// Returns who calls with `headers` on the request `line`, when known,
    /// logging a refusal at info.
    async fn authenticate_with(
        &self,
        headers: &HeaderMap,
        line: Option<Line<'_>>,
    ) -> Result<Access, Denied> {
        let outcome = self.authenticated(headers, line).await;
        if let Err(denied) = &outcome {
            log_refusal(denied, &self.named(headers));
        }
        outcome
    }

    /// Returns what the bearer or `DPoP` credential of `headers` names for
    /// a refusal's log line, empty for a Basic credential or none.
    pub(super) fn named(&self, headers: &HeaderMap) -> Named {
        let basic = !self.credential.is_bare()
            && headers
                .get(self.credential.name())
                .and_then(|value| value.to_str().ok())
                .and_then(|text| text.split_once(' '))
                .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("Basic"));
        match self.credential(headers) {
            Some(token) if !basic => Named::of(token),
            _ => Named::default(),
        }
    }

    /// Returns who calls with `headers` on the request `line`, when known.
    async fn authenticated(
        &self,
        headers: &HeaderMap,
        line: Option<Line<'_>>,
    ) -> Result<Access, Denied> {
        if self.is_open() {
            return Ok(Access::Open);
        }
        let missing = || Denied::from(Refusal::Missing(self.schemes()));
        let malformed = |reason| Denied::new(Refusal::InvalidRequest, Some(reason));
        let mut values = headers.get_all(self.credential.name()).iter();
        let value = match (values.next(), values.next()) {
            (None, _) => return Err(missing()),
            (Some(_), Some(_)) => return Err(malformed(Reason::TwoCredentials)),
            (Some(value), None) => value,
        };
        let text = value
            .to_str()
            .map_err(|_opaque| malformed(Reason::MalformedHeader))?;
        let mut binding = Binding::bearer();
        if let Some(certificate) = line.and_then(|line| line.certificate) {
            binding = binding.with_certificate(certificate);
        }
        if self.credential.is_bare() {
            let token = text.trim();
            if token.is_empty() {
                return Err(malformed(Reason::MalformedHeader));
            }
            let verifier = self.bearer.as_ref().ok_or_else(missing)?;
            let caller = bearer(verifier.as_ref(), token, &binding).await?;
            return Ok(Access::Caller(Arc::new(caller)));
        }
        let (scheme, credential) = text
            .split_once(' ')
            .ok_or_else(|| malformed(Reason::MalformedHeader))?;
        let credential = credential.trim();
        if credential.is_empty() {
            return Err(malformed(Reason::MalformedHeader));
        }
        let caller = if scheme.eq_ignore_ascii_case("Bearer") {
            let verifier = self.bearer.as_ref().ok_or_else(missing)?;
            bearer(verifier.as_ref(), credential, &binding).await?
        } else if scheme.eq_ignore_ascii_case("DPoP") {
            let verifier = self.bearer.as_ref().ok_or_else(missing)?;
            let check = self.proof.as_ref().ok_or_else(missing)?;
            dpop(check, verifier.as_ref(), credential, headers, line).await?
        } else if scheme.eq_ignore_ascii_case("Basic") {
            let store = Arc::clone(self.basic.as_ref().ok_or_else(missing)?);
            basic(store, value.clone()).await?
        } else {
            return Err(missing());
        };
        Ok(Access::Caller(Arc::new(caller)))
    }

    /// Returns the credential text of `headers`: the one field of the
    /// credential header, after its scheme unless the header is bare, or
    /// `None` when there is no single non-empty field.
    ///
    /// A product that hands the verified credential on (an RFC 8693 token
    /// exchange) reads it here, under the rules [`Gate::authenticate`]
    /// applied.
    #[must_use]
    pub fn credential<'h>(&self, headers: &'h HeaderMap) -> Option<&'h str> {
        let mut values = headers.get_all(self.credential.name()).iter();
        let (Some(value), None) = (values.next(), values.next()) else {
            return None;
        };
        let text = value.to_str().ok()?;
        let credential = if self.credential.is_bare() {
            text
        } else {
            text.split_once(' ')?.1
        }
        .trim();
        (!credential.is_empty()).then_some(credential)
    }
}

/// Returns the caller `token` authenticates under `verifier` with what the
/// request proves, `binding`.
async fn bearer(verifier: &dyn Verifier, token: &str, binding: &Binding) -> Result<Caller, Denied> {
    // NOTE: RFC 6750 §2.1 fixes the `b64token` syntax, and §3.1 answers a
    // token that is "malformed" with `invalid_token`.
    if !is_b64token(token) {
        return Err(invalid_token(Reason::NotB64Token));
    }
    let outcome = verifier.verify_bound(token, binding).await;
    held(outcome.and_then(|caller| confirmed(caller, binding)))
}

/// Returns the caller the `DPoP` request carrying `token` authenticates:
/// the proof in `headers` checked against the request `line` by `check`,
/// the token by `verifier`.
async fn dpop(
    check: &ProofCheck,
    verifier: &dyn Verifier,
    token: &str,
    headers: &HeaderMap,
    line: Option<Line<'_>>,
) -> Result<Caller, Denied> {
    // NOTE: RFC 9449 §7.1, the `DPoP` credentials are `token68`, the
    // `b64token` alphabet of RFC 6750 §2.1.
    if !is_b64token(token) {
        return Err(dpop_denied(&Rejection::Invalid {
            reason: Reason::NotB64Token,
        }));
    }
    let Some(line) = line else {
        return Err(dpop_denied(&Rejection::Invalid {
            reason: Reason::Sender(Check::ProofRequestUnknown),
        }));
    };
    let presented = Presented {
        method: line.method,
        path: line.path,
        headers,
        token,
        certificate: line.certificate,
    };
    held(check.authenticate(verifier, &presented).await).map_err(|denied| {
        match denied.refusal() {
            // NOTE: RFC 9449 §7.2, the challenge of a request whose scheme is
            // known is that scheme's.
            Refusal::InvalidToken => denied.answered_with(Refusal::InvalidDpopToken),
            _ => denied,
        }
    })
}

/// Returns `caller` once its `cnf` holds to `binding`, the check of
/// [`crate::sender`] held over every verifier.
fn confirmed(caller: Caller, binding: &Binding) -> Result<Caller, Rejection> {
    crate::sender::confirm(SenderConstraint::None, caller.claims(), binding)
        .map(|()| caller)
        .map_err(|check| Rejection::Invalid {
            reason: Reason::Sender(check),
        })
}

/// Returns the denial of a `DPoP` request refused with `rejection`.
fn dpop_denied(rejection: &Rejection) -> Denied {
    let denied = Denied::from(rejection);
    match denied.refusal() {
        Refusal::InvalidToken => denied.answered_with(Refusal::InvalidDpopToken),
        _ => denied,
    }
}

/// Returns the verifier's `outcome` as the gate answers it, logging an
/// upstream failure and holding the blank-subject rule.
fn held(outcome: Result<Caller, Rejection>) -> Result<Caller, Denied> {
    match outcome {
        // NOTE: RFC 9068 §2.2 requires `sub`, held here over every verifier.
        Ok(caller) if caller.subject().trim().is_empty() => {
            Err(invalid_token(Reason::BlankSubject))
        }
        Ok(caller) => Ok(caller),
        Err(rejection) => {
            match &rejection {
                Rejection::Unavailable { source } => {
                    tracing::error!(
                        error = %source,
                        "the authorization server's key set could not be read"
                    );
                }
                Rejection::Unread { source } => {
                    tracing::warn!(
                        error = %source,
                        "the issuer's metadata or key set has not been read yet"
                    );
                }
                Rejection::Upstream { upstream, source } => {
                    tracing::error!(
                        upstream = *upstream,
                        error = %source,
                        "an upstream of the token verifier could not be read"
                    );
                }
                Rejection::Missing | Rejection::Invalid { .. } | Rejection::Unclassified { .. } => {
                }
            }
            Err(Denied::from(&rejection))
        }
    }
}

/// Returns the caller the Basic credential `value` authenticates in
/// `store`: from the verified-credential cache on this task, else with the
/// key derivation on a blocking thread.
async fn basic(store: Arc<PasswordStore>, value: HeaderValue) -> Result<Caller, Denied> {
    let checked = match store.cached(&value) {
        Some(verified) => Ok(verified),
        None => tokio::task::spawn_blocking(move || store.check(&value))
            .await
            .map_err(|_cancelled| {
                Denied::new(Refusal::InvalidBasic, Some(Reason::BasicIncomplete))
            })?,
    };
    match checked {
        Ok(verified) => Ok(Caller::basic(verified.username, &verified.scope)
            .with_roles(verified.roles)
            .with_cached(verified.cached)),
        Err(reason) => Err(Denied::new(Refusal::InvalidBasic, Some(reason))),
    }
}

/// Returns the denial of a bearer token that does not hold for `reason`.
fn invalid_token(reason: Reason) -> Denied {
    Denied::new(Refusal::InvalidToken, Some(reason))
}

/// Logs `denied` at info with its reason code and what the refused token
/// `named`, never the token or a claim that identifies a person.
pub(super) fn log_refusal(denied: &Denied, named: &Named) {
    tracing::info!(
        reason = denied.code(),
        status = denied.refusal().status().as_u16(),
        issuer = named.issuer.as_deref().unwrap_or("-"),
        client_id = named.client_id.as_deref().unwrap_or("-"),
        kid = named.kid.as_deref().unwrap_or("-"),
        "a request was refused"
    );
}

/// Returns whether `token` is a `b64token` (RFC 6750 §2.1):
/// `1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`.
fn is_b64token(token: &str) -> bool {
    let body = token.trim_end_matches('=');
    !body.is_empty()
        && body.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use argon2::{Argon2, PasswordHasher};
    use base64::Engine as _;
    use http::HeaderValue;
    use secrecy::SecretString;

    use super::{basic, is_b64token};
    use crate::basic::PasswordStore;
    use crate::refusal::Reason;

    /// A password drawn when the test runs.
    fn drawn() -> String {
        let mut bytes = [0_u8; 16];
        aws_lc_rs::rand::fill(&mut bytes).unwrap();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// The `Basic` header value of `user` and `password`.
    fn header(user: &str, password: &str) -> HeaderValue {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        HeaderValue::from_str(&format!("Basic {token}")).unwrap()
    }

    #[test]
    fn a_cached_credential_needs_no_blocking_thread_and_a_wrong_one_still_derives() {
        let (password, changed) = (drawn(), drawn());
        let mut salt = [0_u8; 16];
        aws_lc_rs::rand::fill(&mut salt).unwrap();
        let hash = Argon2::default()
            .hash_password_with_salt(password.as_bytes(), &salt)
            .unwrap()
            .to_string();
        let store = Arc::new(
            PasswordStore::new()
                .with_user("alice", SecretString::from(hash))
                .and_then(|store| store.with_scope("alice", "user/*.rs"))
                .and_then(|store| store.with_cache(Duration::from_secs(60)))
                .unwrap(),
        );
        assert!(!store.check(&header("alice", &password)).unwrap().cached);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            // The one blocking thread is held, so a check that needs it waits.
            let (release, held) = std::sync::mpsc::channel::<()>();
            let blocker = tokio::task::spawn_blocking(move || held.recv());
            let hit = tokio::time::timeout(
                Duration::from_secs(5),
                basic(Arc::clone(&store), header("alice", &password)),
            )
            .await
            .expect("a cache hit never waits for the blocking pool")
            .expect("the cached credential is admitted");
            assert!(hit.cached(), "admitted from the cache");
            let wrong = tokio::spawn(basic(Arc::clone(&store), header("alice", &changed)));
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(!wrong.is_finished(), "a miss waits for the blocking thread");
            release.send(()).unwrap();
            blocker.await.unwrap().unwrap();
            let refused = wrong
                .await
                .unwrap()
                .expect_err("a wrong password is refused");
            assert_eq!(Some(Reason::BasicRejected), refused.reason());
        });
    }

    #[test]
    fn a_b64token_is_the_rfc_6750_alphabet_with_trailing_padding() {
        for token in [
            "abc",
            "a.b.c",
            "A-Z_0~9+/",
            "abc==",
            "eyJhbGciOiJFUzI1NiJ9.e30.c2ln",
        ] {
            assert!(is_b64token(token), "{token}");
        }
        for token in ["", "==", "a b", "a=b", "a,b", "a\"b", "ä", "a;b", "=abc"] {
            assert!(!is_b64token(token), "{token}");
        }
    }
}
