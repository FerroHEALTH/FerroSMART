// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The parameters of an OAuth request, a query or a form body.

use std::collections::BTreeSet;

/// The parameters of a request, each named once unless the caller admits a
/// repeat.
#[derive(Debug, Clone, Default)]
pub struct Params(Vec<(String, String)>);

/// A parameter named more than once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a parameter is repeated")]
pub struct Repeated;

impl Params {
    /// Reads `encoded`, refusing a parameter named twice unless `repeatable`
    /// lists it ("Request and response parameters MUST NOT be included more
    /// than once", RFC 6749 §3.1, §3.2).
    ///
    /// # Errors
    /// Returns [`Repeated`] for a parameter named twice.
    pub fn parse(encoded: &[u8], repeatable: &[&str]) -> Result<Self, Repeated> {
        let pairs: Vec<(String, String)> =
            url::form_urlencoded::parse(encoded).into_owned().collect();
        let mut names = BTreeSet::new();
        let repeated = pairs
            .iter()
            .any(|(name, _)| !repeatable.contains(&name.as_str()) && !names.insert(name.as_str()));
        if repeated {
            return Err(Repeated);
        }
        Ok(Self(pairs))
    }

    /// Returns the value of `name`, an empty value as absent ("Parameters
    /// sent without a value MUST be treated as if they were omitted", RFC
    /// 6749 §3.1).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, value)| key == name && !value.is_empty())
            .map(|(_, value)| value.as_str())
    }

    /// Returns every value of `name`, in the order sent.
    #[must_use]
    pub fn all(&self, name: &str) -> Vec<&str> {
        self.0
            .iter()
            .filter(|(key, value)| key == name && !value.is_empty())
            .map(|(_, value)| value.as_str())
            .collect()
    }

    /// Returns every parameter name, in order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|(name, _)| name.as_str())
    }

    /// Returns every parameter as a name and a value, in order.
    pub fn pairs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }
}
