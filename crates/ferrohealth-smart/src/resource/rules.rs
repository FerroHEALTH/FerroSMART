// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The rules an issuer's settings are held to beside its keys, shared by the
//! JWT and the introspection settings.

use crate::assurance::AssuranceSection;
use crate::federation::FederationSection;
use crate::federation::person::AttributesSection;
use crate::kind::IssuerKind;
use crate::profile::Profile;
use crate::resource::ResourceError;
use crate::sender::SenderConstraint;

/// Checks what an issuer of `kind` is configured with beside its keys: its
/// profile, its assurance mapping, its federation table, and the settings
/// its kind refuses.
pub(super) fn check_issuer_rules(
    kind: IssuerKind,
    profile: &Profile,
    assurance: Option<&AssuranceSection>,
    federation: Option<&FederationSection>,
    sender_constraint: SenderConstraint,
    role_claims: &[String],
) -> Result<(), ResourceError> {
    profile.validate()?;
    match (kind, federation) {
        (IssuerKind::Federation, Some(section)) => {
            section.validate()?;
            // NOTE: MyHealth@EU tokens live up to the 4 h of the identity assertion
            // (eHDSI SAML Profile 10.0.0 §2.1), so a contact point is sender-constrained.
            if section.contact_point == Some(true)
                && sender_constraint != SenderConstraint::Required
            {
                return Err(ResourceError::ContactPointSender);
            }
            if section.requires_sender_constraint && sender_constraint != SenderConstraint::Required
            {
                return Err(ResourceError::SenderConstraintRequired);
            }
        }
        (IssuerKind::Federation, None) | (_, Some(_)) => {
            return Err(ResourceError::Kind {
                key: "federation",
                kind,
            });
        }
        (_, None) => {}
    }
    if let Some(assurance) = assurance {
        assurance.validate()?;
    }
    // NOTE: no specification governs this: our own design; another party's
    // issuer asserts no role of this deployment.
    if !role_claims.is_empty() && kind == IssuerKind::Federation {
        return Err(ResourceError::Kind {
            key: "role_claims",
            kind,
        });
    }
    Ok(())
}

/// Refuses an `[auth.issuer.<name>.attributes]` table on a `federation` issuer, which
/// reads its own `[auth.issuer.<name>.federation]` table, and checks the table of any
/// other.
pub(super) fn check_attributes(
    kind: IssuerKind,
    attributes: Option<&AttributesSection>,
) -> Result<(), ResourceError> {
    match (kind, attributes) {
        (IssuerKind::Federation, Some(_)) => Err(ResourceError::Kind {
            key: "attributes",
            kind,
        }),
        (_, Some(section)) => Ok(section.validate()?),
        (_, None) => Ok(()),
    }
}
