// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! What a route is: the behaviour of [`Requirement`], whether an
//! [`Access`] meets it, and of [`Target`], what the audit line records of
//! one classified request.

use crate::guard::Requirement;
use crate::guard::Target;
use crate::resource::Access;
use crate::resource::Honoured;
use crate::resource::Via;

impl Requirement {
    /// Returns the requirement that the caller authenticated with HTTP Basic
    /// as one of `users`, a [`Requirement::Client`] that lists no bearer
    /// client.
    #[must_use]
    pub fn basic_users<I, S>(users: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::Client {
            client_ids: Vec::new(),
            basic_users: users.into_iter().map(Into::into).collect(),
        }
    }

    /// Returns whether `access` meets this requirement, `honoured` saying
    /// what the product honours for the caller beyond a `user/` grant.
    #[must_use]
    #[cfg_attr(
        not(feature = "openehr"),
        expect(
            clippy::only_used_in_recursion,
            reason = "`honoured` is read by the SMART on openEHR requirement alone"
        )
    )]
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
            Self::Client {
                client_ids,
                basic_users,
            } => access.caller().is_some_and(|caller| match caller.via() {
                Via::Bearer => caller
                    .client_id()
                    .is_some_and(|client| client_ids.iter().any(|listed| listed == client)),
                Via::Basic => basic_users.iter().any(|listed| listed == caller.subject()),
            }),
            Self::Role(role) => access.caller().is_some_and(|caller| caller.has_role(role)),
            Self::AnyRole => access
                .caller()
                .is_some_and(|caller| !caller.roles().is_empty()),
            Self::WithoutRole(role) => access.caller().is_some_and(|caller| !caller.has_role(role)),
            Self::Either(left, right) => {
                left.met_by(access, honoured) || right.met_by(access, honoured)
            }
            Self::All(requirements) => {
                access.caller().is_some()
                    && requirements
                        .iter()
                        .all(|requirement| requirement.met_by(access, honoured))
            }
            Self::Refused => false,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::{Requirement, Target};
    use crate::kind::CallerKind;
    use crate::resource::{Access, Caller, Honoured};
    use crate::scope::Permission;
    use std::sync::Arc;

    fn access(scope: &str) -> Access {
        Access::Caller(Arc::new(Caller::new(
            String::from("sub"),
            Some(String::from("client-1")),
            scope,
            None,
            CallerKind::Person,
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
        let client = clients(&["client-1"], &[]);
        assert!(client.met_by(&access(""), none));
        assert!(!clients(&["other"], &[]).met_by(&access(""), none));
        assert!(
            !client.met_by(&Access::Open, none),
            "an open surface names no client"
        );
        assert!(!Requirement::Refused.met_by(&Access::Open, none));
        assert!(Requirement::Caller.met_by(&access(""), none));
    }

    fn holding(roles: &[&str]) -> Access {
        Access::Caller(Arc::new(
            Caller::new(String::from("sub"), None, "", None, CallerKind::Person)
                .with_roles(roles.iter().map(|role| (*role).to_owned()).collect()),
        ))
    }

    #[test]
    fn role_requirements_judge_the_roles_the_caller_holds() {
        let none = Honoured::default();
        let admin = Requirement::Role(String::from("ADMIN"));
        assert!(admin.met_by(&holding(&["admin"]), none));
        assert!(!admin.met_by(&holding(&["clinician"]), none));
        assert!(
            !admin.met_by(&Access::Open, none),
            "an open surface holds no role"
        );
        assert!(Requirement::AnyRole.met_by(&holding(&["clinician"]), none));
        assert!(!Requirement::AnyRole.met_by(&holding(&[]), none));
        let write = Requirement::All(vec![
            Requirement::AnyRole,
            Requirement::WithoutRole(String::from("READONLY")),
        ]);
        assert!(write.met_by(&holding(&["clinician"]), none));
        assert!(
            !write.met_by(&holding(&["clinician", "readonly"]), none),
            "a restriction overrides a grant"
        );
        assert!(!write.met_by(&holding(&[]), none));
        assert!(Requirement::All(Vec::new()).met_by(&holding(&[]), none));
        assert!(!Requirement::All(Vec::new()).met_by(&Access::Open, none));
    }

    fn clients(client_ids: &[&str], basic_users: &[&str]) -> Requirement {
        Requirement::Client {
            client_ids: client_ids.iter().map(|id| (*id).to_owned()).collect(),
            basic_users: basic_users.iter().map(|user| (*user).to_owned()).collect(),
        }
    }

    fn basic(user: &str) -> Access {
        Access::Caller(Arc::new(Caller::basic(String::from(user), "")))
    }

    #[test]
    fn a_client_requirement_matches_each_list_against_its_own_scheme() {
        let none = Honoured::default();
        let demographic = clients(&["client-1"], &["etl"]);
        assert!(
            demographic.met_by(&basic("etl"), none),
            "a listed Basic user"
        );
        assert!(demographic.met_by(&access(""), none), "a listed client");
        assert!(
            !demographic.met_by(&basic("mallory"), none),
            "an unlisted Basic user"
        );
        assert!(
            !demographic.met_by(&basic("client-1"), none),
            "a Basic user-id never passes for a client id"
        );
        let by_basic_name = clients(&[], &["sub"]);
        assert!(
            !by_basic_name.met_by(&access(""), none),
            "a bearer subject never passes for a Basic user-id"
        );
    }

    #[cfg(feature = "openehr")]
    #[test]
    fn an_openehr_requirement_admits_a_system_caller_by_its_openehr_scope_alone() {
        use crate::openehr::smart_scopes::{Permission, ResourceFamily};
        let none = Honoured::default();
        let read = Requirement::OpenEhr {
            family: ResourceFamily::Composition,
            permission: Permission::Read,
            resource: None,
        };
        let caller = |scope: &str| {
            Access::Caller(Arc::new(Caller::new(
                String::from("svc"),
                None,
                scope,
                None,
                CallerKind::System,
            )))
        };
        assert!(!read.met_by(&caller("openid"), none), "no resource scope");
        assert!(
            !read.met_by(&caller("system/template-*.r"), none),
            "an openEHR scope: only its scopes"
        );
        assert!(
            !read.met_by(&caller("system/Observation.r"), none),
            "a FHIR scope: only its scopes"
        );
        assert!(read.met_by(&caller("system/composition-*.r"), none));
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
