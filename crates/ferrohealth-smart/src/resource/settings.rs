// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! What a deployment configures its resource server with, and the rules
//! [`Settings::validate`] holds it to before the start.

use std::time::Duration;

use crate::jws::algorithm::Algorithm;

use crate::kind::IssuerKind;
use crate::profile::Profile;
use crate::resource::MAX_CLOCK_SKEW;
use crate::resource::ResourceError;
use crate::resource::Settings;
use crate::resource::rules;
use crate::sender::SenderConstraint;

impl Settings {
    /// Returns settings for tokens of `issuer`, an issuer of `kind`,
    /// addressed to `audience`.
    ///
    /// RS256, RS384, PS256, PS384, ES256 and ES384 are accepted under the
    /// `rfc9068` profile, the clock skew is 60 seconds, the key set is used
    /// for 600 seconds and read again at most once a minute, a call to the
    /// authorization server may take 10 seconds.
    #[must_use]
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>, kind: IssuerKind) -> Self {
        Self {
            issuer: issuer.into(),
            audience: vec![audience.into()],
            algorithms: vec![
                Algorithm::Rs256,
                Algorithm::Rs384,
                Algorithm::Ps256,
                Algorithm::Ps384,
                Algorithm::Es256,
                Algorithm::Es384,
            ],
            kind,
            profile: Profile::default(),
            clock_skew: Duration::from_secs(60),
            jwks_max_age: Duration::from_secs(600),
            jwks_refresh_interval: Duration::from_secs(60),
            jwks_file: None,
            timeout: Duration::from_secs(10),
            // NOTE: no specification governs this: our own design; another party's
            // issuer asserts no role of this deployment.
            role_claims: if kind == IssuerKind::Federation {
                Vec::new()
            } else {
                crate::roles::default_claims()
            },
            assurance: None,
            federation: None,
            attributes: None,
            sender_constraint: SenderConstraint::None,
            tls: crate::client::Tls::default(),
        }
    }

    /// Checks the settings: the issuer URL rule, at least one audience, at
    /// least one algorithm, the clock skew bound, and no list beside the
    /// product's standing.
    ///
    /// # Errors
    ///
    /// Returns the [`ResourceError`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), ResourceError> {
        crate::metadata::issuer_url(&self.issuer)?;
        if self.audience.iter().all(String::is_empty) {
            return Err(ResourceError::NoAudience);
        }
        if self.algorithms.is_empty() {
            return Err(ResourceError::NoAlgorithm);
        }
        if self.clock_skew > MAX_CLOCK_SKEW {
            return Err(ResourceError::ClockSkew {
                skew: self.clock_skew,
            });
        }
        rules::check_issuer_rules(
            self.kind,
            &self.profile,
            self.assurance.as_ref(),
            self.federation.as_ref(),
            self.sender_constraint,
            &self.role_claims,
        )?;
        rules::check_attributes(self.kind, self.attributes.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_CLOCK_SKEW, ResourceError, Settings};
    use crate::kind::IssuerKind;
    use std::time::Duration;

    #[test]
    fn the_settings_rules_refuse_the_start() {
        let mut settings = Settings::new("https://as.example.org", "aud", IssuerKind::Smart);
        assert!(settings.validate().is_ok());
        settings.clock_skew = MAX_CLOCK_SKEW + Duration::from_secs(1);
        assert!(matches!(
            settings.validate(),
            Err(ResourceError::ClockSkew { .. })
        ));
        let mut settings = Settings::new("https://as.example.org", "", IssuerKind::Smart);
        assert!(matches!(
            settings.validate(),
            Err(ResourceError::NoAudience)
        ));
        settings.audience = vec![String::from("aud")];
        settings.issuer = String::from("http://as.example.org");
        assert!(matches!(
            settings.validate(),
            Err(ResourceError::Discovery(_))
        ));
    }
}
