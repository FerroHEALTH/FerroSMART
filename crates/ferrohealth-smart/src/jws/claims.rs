// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The registered claims of a JWT a verifier checks (RFC 7519 §4.1, §7.2;
//! RFC 8725 §3.8, §3.9): `iss`, `aud`, `exp` and `nbf` within a leeway, and
//! the claims a profile requires.

use std::time::Duration;

use serde_json::Map;
use serde_json::Value;

/// A claim set that fails a check.
///
/// No variant carries a claim value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClaimError {
    /// A required claim is absent.
    #[error("the claim {name} is absent")]
    Missing {
        /// The claim.
        name: &'static str,
    },
    /// A registered claim is not of its form: `iss` and `sub` a string,
    /// `aud` a string or an array of strings, `exp`, `nbf` and `iat` a
    /// number (RFC 7519 §4.1).
    #[error("the claim {name} is not of its form")]
    Format {
        /// The claim.
        name: &'static str,
    },
    /// The token expired (`exp`, RFC 7519 §4.1.4).
    #[error("the token expired")]
    Expired,
    /// The token is not yet valid (`nbf`, RFC 7519 §4.1.5).
    #[error("the token is not yet valid")]
    NotYetValid,
    /// The `iss` is not the expected issuer (RFC 7519 §4.1.1).
    #[error("the token's issuer is not the expected one")]
    Issuer,
    /// The `aud` names none of the expected audiences (RFC 7519 §4.1.3).
    #[error("the token's audience names none of the expected ones")]
    Audience,
}

/// A JWT that fails to verify: its JWS, its claims, or their shape.
///
/// No variant carries the token or a claim value.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwtError {
    /// The JWS cannot be read or does not verify.
    #[error(transparent)]
    Jws(#[from] crate::jws::JwsError),
    /// A claim fails its check.
    #[error(transparent)]
    Claim(#[from] ClaimError),
    /// The verified claims are not of the shape the reader expects.
    #[error("the JWT claims are not of the expected shape")]
    Shape {
        /// What the JSON reader reported.
        #[source]
        source: serde_json::Error,
    },
}

/// The checks one kind of JWT is held to.
///
/// By default nothing is required, `exp` and `nbf` are checked when present
/// with no leeway, and `iss` and `aud` are not compared.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Validation {
    /// The issuers `iss` must equal one of, when set.
    issuers: Option<Vec<String>>,
    /// The audiences `aud` must name one of, when set.
    audiences: Option<Vec<String>>,
    /// The claims that must be present.
    required: Vec<&'static str>,
    /// The leeway `exp` and `nbf` are checked with.
    leeway: Duration,
}

impl Validation {
    /// Returns the checks with `issuer` as the one issuer `iss` must equal;
    /// `iss` is then required.
    #[must_use]
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuers = Some(vec![issuer.into()]);
        self
    }

    /// Returns the checks with `audiences`, of which `aud` must name one;
    /// `aud` is then required.
    #[must_use]
    pub fn with_audiences<I, S>(mut self, audiences: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.audiences = Some(audiences.into_iter().map(Into::into).collect());
        self
    }

    /// Returns the checks with `names` required beside the others.
    #[must_use]
    pub fn with_required(mut self, names: &[&'static str]) -> Self {
        self.required.extend_from_slice(names);
        self
    }

    /// Returns the checks with `leeway` on `exp` and `nbf`.
    #[must_use]
    pub const fn with_leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    /// Checks `claims` now.
    ///
    /// # Errors
    ///
    /// Returns the [`ClaimError`] of the first check that fails: a required
    /// claim absent, a registered claim of another form, `exp` passed or
    /// `nbf` ahead beyond the leeway, then `iss` and `aud`.
    pub fn check(&self, claims: &Map<String, Value>) -> Result<(), ClaimError> {
        let now = jiff::Timestamp::now().as_duration().as_secs_f64();
        self.check_at(claims, now)
    }

    /// Checks `claims` at `now`, seconds since the epoch.
    fn check_at(&self, claims: &Map<String, Value>, now: f64) -> Result<(), ClaimError> {
        let implied = [
            self.issuers.as_ref().map(|_| "iss"),
            self.audiences.as_ref().map(|_| "aud"),
        ];
        for name in self
            .required
            .iter()
            .copied()
            .chain(implied.into_iter().flatten())
        {
            if !claims.contains_key(name) {
                return Err(ClaimError::Missing { name });
            }
        }
        for name in ["iss", "sub"] {
            if claims.get(name).is_some_and(|value| !value.is_string()) {
                return Err(ClaimError::Format { name });
            }
        }
        let date = |name: &'static str| match claims.get(name) {
            None => Ok(None),
            Some(value) => value.as_f64().map(Some).ok_or(ClaimError::Format { name }),
        };
        let leeway = self.leeway.as_secs_f64();
        let exp = date("exp")?;
        let nbf = date("nbf")?;
        date("iat")?;
        // NOTE: RFC 7519 §4.1.4, the current time MUST be before `exp`, with a small leeway.
        if exp.is_some_and(|exp| now >= exp + leeway) {
            return Err(ClaimError::Expired);
        }
        // NOTE: RFC 7519 §4.1.5, the current time MUST be at or after `nbf`, with a small leeway.
        if nbf.is_some_and(|nbf| now + leeway < nbf) {
            return Err(ClaimError::NotYetValid);
        }
        if let Some(issuers) = &self.issuers {
            let issuer = claims.get("iss").and_then(Value::as_str);
            if !issuers
                .iter()
                .any(|expected| Some(expected.as_str()) == issuer)
            {
                return Err(ClaimError::Issuer);
            }
        }
        let audience = audience(claims)?.unwrap_or_default();
        // NOTE: RFC 7519 §4.1.3, a recipient that does not identify itself with a value of `aud` rejects the JWT.
        if let Some(audiences) = &self.audiences
            && !audience
                .iter()
                .any(|named| audiences.iter().any(|expected| expected == named))
        {
            return Err(ClaimError::Audience);
        }
        Ok(())
    }
}

/// Returns the values of the `aud` claim of `claims`, one string or an
/// array of strings (RFC 7519 §4.1.3), `None` when it is absent.
///
/// # Errors
///
/// Returns [`ClaimError::Format`] for an `aud` of another form.
pub(crate) fn audience(claims: &Map<String, Value>) -> Result<Option<Vec<&str>>, ClaimError> {
    let malformed = ClaimError::Format { name: "aud" };
    match claims.get("aud") {
        None => Ok(None),
        Some(Value::String(one)) => Ok(Some(vec![one.as_str()])),
        Some(Value::Array(items)) => items
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .map(Some)
            .ok_or(malformed),
        Some(_) => Err(malformed),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::{ClaimError, Validation};

    const NOW: f64 = 1_000_000.0;

    fn check(validation: &Validation, claims: &serde_json::Value) -> Result<(), ClaimError> {
        validation.check_at(claims.as_object().expect("an object"), NOW)
    }

    #[test]
    fn the_times_hold_within_the_leeway() {
        let strict = Validation::default();
        let lenient = Validation::default().with_leeway(Duration::from_secs(60));
        let expired = json!({ "exp": 999_990 });
        assert_eq!(Err(ClaimError::Expired), check(&strict, &expired));
        assert_eq!(Ok(()), check(&lenient, &expired));
        assert_eq!(
            Err(ClaimError::Expired),
            check(&strict, &json!({ "exp": 1_000_000 }))
        );
        let early = json!({ "nbf": 1_000_030 });
        assert_eq!(Err(ClaimError::NotYetValid), check(&strict, &early));
        assert_eq!(Ok(()), check(&lenient, &early));
        assert_eq!(Ok(()), check(&strict, &json!({ "exp": 1_000_000.5 })));
        assert_eq!(
            Err(ClaimError::Format { name: "exp" }),
            check(&strict, &json!({ "exp": "1000100" }))
        );
    }

    #[test]
    fn the_issuer_and_one_audience_must_match() {
        let validation = Validation::default()
            .with_issuer("https://as.example.org")
            .with_audiences(["a", "b"]);
        let claims =
            |iss: serde_json::Value, aud: serde_json::Value| json!({ "iss": iss, "aud": aud });
        assert_eq!(
            Ok(()),
            check(
                &validation,
                &claims(json!("https://as.example.org"), json!("b"))
            )
        );
        assert_eq!(
            Ok(()),
            check(
                &validation,
                &claims(json!("https://as.example.org"), json!(["x", "a"]))
            )
        );
        assert_eq!(
            Err(ClaimError::Audience),
            check(
                &validation,
                &claims(json!("https://as.example.org"), json!(["x"]))
            )
        );
        assert_eq!(
            Err(ClaimError::Issuer),
            check(
                &validation,
                &claims(json!("https://other.example.org"), json!("a"))
            )
        );
        assert_eq!(
            Err(ClaimError::Format { name: "iss" }),
            check(&validation, &claims(json!(1), json!("a")))
        );
        assert_eq!(
            Err(ClaimError::Missing { name: "aud" }),
            check(&validation, &json!({ "iss": "https://as.example.org" }))
        );
    }

    #[test]
    fn a_required_claim_must_be_present() {
        let validation = Validation::default().with_required(&["sub", "exp"]);
        assert_eq!(
            Err(ClaimError::Missing { name: "sub" }),
            check(&validation, &json!({ "exp": 1_000_100 }))
        );
        assert_eq!(
            Ok(()),
            check(&validation, &json!({ "sub": "s", "exp": 1_000_100 }))
        );
    }
}
