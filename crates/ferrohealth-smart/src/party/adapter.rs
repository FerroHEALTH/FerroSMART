// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The vendor adapter seam: [`IdpAdapter`], the code an issuer's profile
//! names by `adapter` where data cannot express a vendor's behaviour.
//!
//! The one case is a groups overage: an identity provider that leaves the
//! group claim out of a token above its limit puts an overage marker in its
//! place (`_claim_names` naming the claim, or `hasgroups` set to `true`), and
//! the groups are read from the provider's own interface, which the issuer
//! profile's preset documents. The party lookup calls the adapter before it
//! decides the outcome, and an adapter failure is [`GroupsCause::Adapter`]
//! carrying the upstream status, never an empty set of groups. No
//! specification governs the seam: our own design.
//!
//! [`GroupsCause::Adapter`]: crate::party::GroupsCause::Adapter

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use http::StatusCode;
use serde_json::Value;

use crate::config::REDACTED;
use crate::resource::Caller;

/// Why an adapter could not read a caller's groups.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum AdapterError {
    /// The identity provider answered with a status other than success.
    #[error(
        "the identity provider answered {status}{}",
        body.as_ref().map_or_else(String::new, |body| format!(": {body}"))
    )]
    Status {
        /// The status.
        status: StatusCode,
        /// The `Retry-After` the identity provider gave, when it gave one.
        retry_after: Option<Duration>,
        /// The excerpt of the error body it answered with, when it gave one
        /// that could be read.
        body: Option<BodyExcerpt>,
    },
    /// The identity provider did not answer in time.
    #[error("the identity provider did not answer within {timeout:?}")]
    Timeout {
        /// The time allowed.
        timeout: Duration,
    },
    /// The token lacks a claim the adapter reads, or carries it in a form the
    /// adapter refuses; nothing was called.
    #[error("the token carries no usable {claim:?} claim for the adapter")]
    Claim {
        /// The claim.
        claim: String,
    },
    /// The identity provider could not be reached, or its answer does not
    /// read.
    #[error("the identity provider could not be read")]
    Unreadable {
        /// What failed.
        #[source]
        source: Arc<dyn std::error::Error + Send + Sync + 'static>,
    },
}

/// The code a profile's `adapter` names, registered with the party binding
/// under that name.
pub trait IdpAdapter: Send + Sync + 'static {
    /// Returns the groups the identity provider holds for `caller`, whose
    /// token carries a groups overage marker in place of its group claim.
    ///
    /// The values are compared with a membership's identifier as the token's
    /// group claim would be.
    fn resolve_groups<'a>(
        &'a self,
        caller: &'a Caller,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, AdapterError>> + Send + 'a>>;
}

/// A bounded, redacted excerpt of the error body an identity provider
/// answered a refusal with, for the log.
///
/// It is the body read as UTF-8, with every string and number a claim of the
/// caller's token carries, and every run that reads as a compact JWS
/// (RFC 7515 §7.1), replaced by [`crate::config::REDACTED`]; every control
/// character becomes a space, and the text is cut to
/// [`BodyExcerpt::MAX_CHARS`] after the redaction, so no cut leaves part of
/// a withheld value. No specification governs the excerpt: our own design.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyExcerpt(String);

impl BodyExcerpt {
    /// The most characters an excerpt holds.
    pub const MAX_CHARS: usize = 256;

    /// Returns the excerpt of `body`, the error body the identity provider
    /// answered a call on behalf of `caller` with; `None` for a body with
    /// nothing to show.
    #[must_use]
    pub fn new(body: &[u8], caller: &Caller) -> Option<Self> {
        let mut text = String::from_utf8_lossy(body).into_owned();
        let mut withheld = Vec::new();
        for value in caller.claims().values() {
            leaves(value, &mut withheld);
        }
        withheld.push(caller.subject().to_owned());
        withheld.retain(|value| !value.is_empty());
        withheld.sort_by_key(|value| std::cmp::Reverse(value.len()));
        withheld.dedup();
        for value in &withheld {
            text = text.replace(value.as_str(), REDACTED);
        }
        let text = without_jws(&text);
        let excerpt: String = text
            .trim()
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .take(Self::MAX_CHARS)
            .collect();
        (!excerpt.trim().is_empty()).then_some(Self(excerpt))
    }

    /// Returns the excerpt.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BodyExcerpt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Adds every string and number `value` holds, at any depth, to `into`.
fn leaves(value: &Value, into: &mut Vec<String>) {
    match value {
        Value::String(text) => into.push(text.clone()),
        Value::Number(number) => into.push(number.to_string()),
        Value::Array(items) => items.iter().for_each(|item| leaves(item, into)),
        Value::Object(members) => members.values().for_each(|member| leaves(member, into)),
        Value::Bool(_) | Value::Null => {}
    }
}

/// Returns `text` with every run of base64url characters and dots that
/// reads as a compact JWS, three or more segments the first of which opens
/// a JSON object (`eyJ`), replaced by [`REDACTED`].
fn without_jws(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.starts_with("eyJ") && run.matches('.').count() >= 2 {
            out.push_str(REDACTED);
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::kind::CallerKind;

    fn caller(claims: &Value) -> Caller {
        let claims = claims.as_object().cloned().expect("an object");
        Caller::new(
            String::from("synthetic-subject"),
            None,
            "",
            None,
            CallerKind::Person,
        )
        .with_claims(claims)
    }

    #[test]
    fn every_claim_value_at_any_depth_is_withheld() {
        let caller = caller(&json!({
            "oid": "synthetic-oid-1",
            "nested": { "tid": "synthetic-tenant", "list": ["synthetic-group"] },
            "exp": 1_893_456_000
        }));
        let body = "no synthetic-oid-1 in synthetic-tenant or synthetic-group at 1893456000 \
                    for synthetic-subject";
        let excerpt = BodyExcerpt::new(body.as_bytes(), &caller).expect("an excerpt");
        assert_eq!("no *** in *** or *** at *** for ***", excerpt.as_str());
    }

    #[test]
    fn a_compact_jws_is_withheld() {
        let body = "echo eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln and eyJ.not";
        let excerpt = BodyExcerpt::new(body.as_bytes(), &caller(&json!({}))).expect("an excerpt");
        assert_eq!("echo *** and eyJ.not", excerpt.as_str());
    }

    #[test]
    fn control_characters_become_spaces_and_the_excerpt_is_bounded() {
        let body = format!("line\r\nbreak\u{1b}[31m{}", "y".repeat(1000));
        let excerpt = BodyExcerpt::new(body.as_bytes(), &caller(&json!({}))).expect("an excerpt");
        assert!(
            excerpt.as_str().starts_with("line  break [31m"),
            "{excerpt}"
        );
        assert_eq!(BodyExcerpt::MAX_CHARS, excerpt.as_str().chars().count());
    }

    #[test]
    fn an_empty_body_has_no_excerpt() {
        assert_eq!(None, BodyExcerpt::new(b" \n\t ", &caller(&json!({}))));
    }
}
