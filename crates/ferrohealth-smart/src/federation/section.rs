// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The rules of one `[auth.issuer.<name>.federation]` table: the sources of
//! its fields, and the checks it passes before the issuer loads.

use std::collections::BTreeMap;

use crate::federation::FederationError;
use crate::federation::FederationSection;
use crate::federation::Field;
use crate::federation::Mapping;
use crate::federation::Source;

impl FederationSection {
    /// Returns the sources of every field: the mapping's, with the table's
    /// own over them.
    #[must_use]
    pub fn sources(&self) -> BTreeMap<Field, Vec<Source>> {
        Mapping::with_fields(self.mapping, &self.fields)
    }

    /// Checks the table: a declared `contact_point`, the countries, the
    /// domestic bounds (a contact point takes no provider prefixes), a source for every field and
    /// every required field, the attestation an `authorization_details`
    /// source needs, and the `country_code` and `issuing_authority_name` no
    /// mapping carries.
    ///
    /// # Errors
    ///
    /// The [`FederationError`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), FederationError> {
        match self.contact_point {
            None => {
                return Err(FederationError::Missing {
                    key: "contact_point",
                });
            }
            Some(true) if !self.provider_identifier_prefixes.is_empty() => {
                return Err(FederationError::ContactPointPrefixes);
            }
            Some(_) => {}
        }
        let contact_point = self.contact_point == Some(true);
        let bounds = [
            ("countries", self.countries.is_empty()),
            (
                "issuing_authorities",
                !contact_point && self.issuing_authorities.is_empty(),
            ),
            (
                "provider_identifier_prefixes",
                !contact_point && self.provider_identifier_prefixes.is_empty(),
            ),
        ];
        if let Some((key, _)) = bounds.iter().find(|(_, empty)| *empty) {
            return Err(FederationError::Missing { key });
        }
        let sources = self.sources();
        for (field, list) in &sources {
            if list.is_empty() {
                return Err(FederationError::NoSource {
                    field: field.as_str(),
                });
            }
        }
        if let Some(field) = self
            .required_fields
            .iter()
            .find(|field| !sources.contains_key(field))
        {
            return Err(FederationError::NoSource {
                field: field.as_str(),
            });
        }
        let all = || sources.values().flatten();
        if all().any(|source| matches!(source, Source::AuthorizationDetails(_)))
            && (!self.attests_authorization_details || self.authorization_details_type.is_none())
        {
            return Err(FederationError::Unattested);
        }
        if all().any(|source| matches!(source, Source::Presentation(_)))
            && self.presentations_claim.is_none()
        {
            return Err(FederationError::Presentations);
        }
        // NOTE: IHE IUA §3.71.4.2.2.1.1 and eHDSI SAML Profile 10.0.0 §2.3 carry no
        // country and no issuing authority, so such a table names a source for both.
        if self.mapping.is_some() || contact_point {
            for field in [
                Field::ProfessionalCountryCode,
                Field::ProfessionalIssuingAuthorityName,
            ] {
                if !sources.contains_key(&field) {
                    return Err(FederationError::NoSource {
                        field: field.as_str(),
                    });
                }
            }
        }
        Ok(())
    }
}
