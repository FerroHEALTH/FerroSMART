// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The SMART on openEHR grant check, over the grammar `openehr-sdt` parses.
//!
//! The grammar is the ITS-REST "SMART on openEHR" draft, status
//! DEVELOPMENT, vendored under `docs/specs/smart-on-openehr/` and cited as
//! `master08 §Resource Scopes` and so on: `<compartment>/<resource>.<permissions>`,
//! the resource one of `template-`, `composition-` and `aql-` with a
//! pattern. The parser is [`openehr_sdt::smart_scopes`], the one every
//! product reads the grammar with; this module adds what the draft leaves
//! to the resource server, carried over from FerroFED's gate: which grant
//! covers which operation, and which grant a product honours for which
//! caller.
//!
//! Where the draft is silent these rules are ours (no specification
//! governs them: our own design): the permission letters are read in any
//! order; `*` matches within one `::` segment and `**` across them, a bare
//! `*` or `**` every id; an operation that names no resource is covered only
//! by such a bare wildcard; `system/aql-*` counts only for a listed backend
//! client; a `patient/` grant counts only for a bound issuer and only on EHR
//! data; the FHIR v1 suffixes are not applied; and both grammars coexist in
//! one `scope` claim.

use openehr_sdt::smart_scopes::Compartment;
use openehr_sdt::smart_scopes::Permission;
use openehr_sdt::smart_scopes::ResourceFamily;
use openehr_sdt::smart_scopes::ResourceScope;
use openehr_sdt::smart_scopes::ResourceSelector;
use openehr_sdt::smart_scopes::SmartScope;

use crate::resource::Honoured;

/// Returns whether `scopes` grant `permission` on a resource of `family`.
///
/// `named` is the resource the request addresses, when the product can see
/// it; `None` is an operation only a pattern covering every resource (`*`
/// or `**`) covers. `honoured` says what the caller's issuer or client lets
/// count beyond a `user/` grant.
#[must_use]
pub fn granted(
    scopes: &[SmartScope],
    family: ResourceFamily,
    permission: Permission,
    named: Option<&str>,
    honoured: Honoured,
) -> bool {
    scopes.iter().any(|scope| match scope {
        SmartScope::Resource(resource) => {
            covers(resource, family, permission, named)
                && counts(resource, family, permission, honoured)
        }
        SmartScope::Launch
        | SmartScope::LaunchContext(_)
        | SmartScope::Identity(_)
        | SmartScope::Other(_) => false,
    })
}

/// Returns the scopes of `scopes` that cover `permission` on a resource of
/// `family` named `named`, the grant an exchanged token asks for.
#[must_use]
pub fn covering(
    scopes: &[SmartScope],
    family: ResourceFamily,
    permission: Permission,
    named: Option<&str>,
    honoured: Honoured,
) -> Vec<SmartScope> {
    scopes
        .iter()
        .filter(|scope| {
            granted(
                std::slice::from_ref(*scope),
                family,
                permission,
                named,
                honoured,
            )
        })
        .cloned()
        .collect()
}

/// Returns whether every one of `covering`, the scopes that cover an
/// operation, is a `patient/` grant, so the operation is confined to the
/// token's EHR.
#[must_use]
pub fn confined(covering: &[SmartScope]) -> bool {
    !covering.is_empty()
        && covering.iter().all(|scope| {
            matches!(scope, SmartScope::Resource(resource) if resource.compartment == Compartment::Patient)
        })
}

/// Returns whether every one of `covering`, the scopes that cover an
/// operation, is a `system/` grant.
///
/// A `system/` scope is granted "to backend applications acting without a
/// user context" (`master08 §Resource Scopes`).
#[must_use]
pub fn backend_only(covering: &[SmartScope]) -> bool {
    !covering.is_empty()
        && covering.iter().all(|scope| {
            matches!(scope, SmartScope::Resource(resource) if resource.compartment == Compartment::System)
        })
}

/// Returns whether `granted`, a token's whole grant, is a patient grant: it
/// holds a resource scope, and every resource scope it holds is a
/// `patient/` one.
///
/// A scope that is no resource scope (`openid`, `launch/patient`) grants no
/// data, so it neither makes nor breaks a patient grant. A patient grant
/// reaches "data within that patient's EHR" alone (`master08 §Resource
/// Scopes`), so a product refuses it on the DEMOGRAPHIC API.
#[must_use]
pub fn patient_grant(granted: &[SmartScope]) -> bool {
    let resources: Vec<SmartScope> = granted
        .iter()
        .filter(|scope| matches!(scope, SmartScope::Resource(_)))
        .cloned()
        .collect();
    confined(&resources)
}

/// Returns whether `scope` is of `family`, holds `permission` and covers
/// the resource `named`, or every resource when the request names none.
fn covers(
    scope: &ResourceScope,
    family: ResourceFamily,
    permission: Permission,
    named: Option<&str>,
) -> bool {
    if scope.resource.family() != family || !scope.permissions.contains(permission) {
        return false;
    }
    let pattern = scope.resource.pattern();
    match named {
        Some(name) => pattern.matches(name),
        None => every(scope),
    }
}

/// Returns whether `scope`'s pattern covers every resource of its family.
fn every(scope: &ResourceScope) -> bool {
    matches!(scope.resource.pattern().as_str(), "*" | "**")
}

/// Returns whether a product honours `scope` for this caller on an
/// operation of `family` needing `permission`: a `patient/` grant only
/// where the issuer is bound to the product's EHR space and only on an
/// EHR's data, and a `system/aql-*` grant only for a backend client the
/// product lists.
fn counts(
    scope: &ResourceScope,
    family: ResourceFamily,
    permission: Permission,
    honoured: Honoured,
) -> bool {
    // NOTE: master07 §Context Selection, the `ehrId` of the launch context
    // means nothing outside the platform that issued it, so a patient grant
    // counts only once its issuer is bound to this product's EHR space.
    if scope.compartment == Compartment::Patient {
        return honoured.patient && on_ehr_data(family, permission);
    }
    // NOTE: master08 §Resource Scopes, `system/aql-*.rs` "would grant access
    // to all registered and ad-hoc AQL queries system-wide".
    let system_wide_aql = scope.compartment == Compartment::System
        && matches!(scope.resource, ResourceSelector::Aql(_))
        && every(scope);
    !system_wide_aql || honoured.backend
}

/// Returns whether an operation of `family` needing `permission` reaches a
/// patient's EHR data, the only data a `patient/` grant covers: "access is
/// restricted to data within that patient's EHR" (`master08 §Resource
/// Scopes`).
///
/// The `composition-` family covers an EHR's resources, and an `aql-` grant
/// covers running a query; reading or storing a query definition, and
/// every template, is no EHR's data.
const fn on_ehr_data(family: ResourceFamily, permission: Permission) -> bool {
    match family {
        ResourceFamily::Composition => true,
        ResourceFamily::Aql => matches!(permission, Permission::Search),
        ResourceFamily::Template => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{backend_only, confined, covering, granted, patient_grant};
    use crate::resource::Honoured;
    use openehr_sdt::smart_scopes::{Permission, ResourceFamily, SmartScope};

    const NONE: Honoured = Honoured {
        backend: false,
        patient: false,
    };

    const BACKEND: Honoured = Honoured {
        backend: true,
        patient: false,
    };

    const PATIENT: Honoured = Honoured {
        backend: false,
        patient: true,
    };

    #[test]
    fn an_operation_naming_no_resource_needs_a_bare_wildcard() {
        for scope in ["user/aql-*.rs", "user/aql-**.cruds"] {
            assert!(
                granted(
                    &SmartScope::parse_all(scope),
                    ResourceFamily::Aql,
                    Permission::Search,
                    None,
                    NONE
                ),
                "{scope}"
            );
        }
        for scope in [
            "patient/aql-*.s",
            "user/aql-org.example::*.s",
            "user/aql-*.r",
            "user/composition-*.s",
            "aql-*.s",
            "openid",
        ] {
            assert!(
                !granted(
                    &SmartScope::parse_all(scope),
                    ResourceFamily::Aql,
                    Permission::Search,
                    None,
                    NONE
                ),
                "{scope}"
            );
        }
    }

    #[test]
    fn a_named_resource_is_covered_by_its_own_pattern() {
        let scopes = SmartScope::parse_all("user/aql-org.example::*.s");
        assert!(granted(
            &scopes,
            ResourceFamily::Aql,
            Permission::Search,
            Some("org.example::vitals"),
            NONE
        ));
        assert!(!granted(
            &scopes,
            ResourceFamily::Aql,
            Permission::Search,
            Some("org.other::vitals"),
            NONE
        ));
    }

    #[test]
    fn a_system_wide_aql_grant_counts_only_for_a_backend_client() {
        let scopes = SmartScope::parse_all("system/aql-*.s");
        assert!(!granted(
            &scopes,
            ResourceFamily::Aql,
            Permission::Search,
            None,
            NONE
        ));
        assert!(granted(
            &scopes,
            ResourceFamily::Aql,
            Permission::Search,
            None,
            BACKEND
        ));
        let named = SmartScope::parse_all("system/aql-org.example::vitals.s");
        assert!(granted(
            &named,
            ResourceFamily::Aql,
            Permission::Search,
            Some("org.example::vitals"),
            NONE
        ));
    }

    #[test]
    fn a_patient_grant_counts_only_for_a_bound_issuer_and_only_on_ehr_data() {
        let scopes = SmartScope::parse_all("patient/aql-*.rs patient/composition-*.crud");
        assert!(
            !granted(&scopes, ResourceFamily::Aql, Permission::Search, None, NONE),
            "unbound issuer"
        );
        assert!(granted(
            &scopes,
            ResourceFamily::Aql,
            Permission::Search,
            None,
            PATIENT
        ));
        assert!(granted(
            &scopes,
            ResourceFamily::Composition,
            Permission::Read,
            None,
            PATIENT
        ));
        assert!(
            !granted(
                &scopes,
                ResourceFamily::Aql,
                Permission::Read,
                None,
                PATIENT
            ),
            "a definition"
        );
        let template = SmartScope::parse_all("patient/template-*.cruds");
        assert!(!granted(
            &template,
            ResourceFamily::Template,
            Permission::Read,
            None,
            PATIENT
        ));
    }

    #[test]
    fn a_grant_of_patient_resource_scopes_alone_is_a_patient_grant() {
        assert!(patient_grant(&SmartScope::parse_all(
            "openid launch/patient patient/composition-*.r"
        )));
        assert!(!patient_grant(&SmartScope::parse_all(
            "patient/composition-*.r user/aql-*.s"
        )));
        assert!(!patient_grant(&SmartScope::parse_all(
            "openid launch/patient"
        )));
    }

    #[test]
    fn the_covering_scopes_say_whether_an_operation_is_confined_or_backend_only() {
        let scopes = SmartScope::parse_all("patient/aql-*.s user/aql-*.s system/composition-*.r");
        let search = covering(
            &scopes,
            ResourceFamily::Aql,
            Permission::Search,
            None,
            PATIENT,
        );
        assert_eq!(2, search.len());
        assert!(!confined(&search));
        let read = covering(
            &scopes,
            ResourceFamily::Composition,
            Permission::Read,
            None,
            NONE,
        );
        assert!(backend_only(&read));
        assert!(!backend_only(&search));
        assert!(!confined(&[]));
    }
}
