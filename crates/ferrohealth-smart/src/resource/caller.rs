// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The identity one valid credential carries, and what it reaches: the
//! behaviour of [`Caller`], [`Compartment`] and [`Access`].

use crate::assurance::Assessment;
use crate::federation::person::Attributes;
use crate::kind::Actor;
use crate::kind::CallerKind;
use crate::party::Outcome;
use crate::resource::Access;
use crate::resource::Caller;
use crate::resource::Compartment;
use crate::resource::PatientClaim;
use crate::resource::PersonContext;
use crate::resource::Via;
use crate::scope::Evaluator;
use crate::scope::Permission;
use crate::scope::Reach;
use crate::scope::Scopes;

impl Caller {
    /// Returns the caller of a token whose claims say so, a caller of
    /// `kind`.
    ///
    /// `scope` is the space-delimited `scope` claim (RFC 6749 §3.3).
    #[must_use]
    pub fn new(
        subject: String,
        client_id: Option<String>,
        scope: &str,
        patient: Option<String>,
        kind: CallerKind,
    ) -> Self {
        Self {
            subject,
            client_id,
            kind,
            actor: None,
            assurance: Assessment::default(),
            scope: scope
                .split(' ')
                .filter(|token| !token.is_empty())
                .map(str::to_owned)
                .collect(),
            scopes: Scopes::parse(scope),
            patient,
            via: Via::Bearer,
            issuer: None,
            claims: serde_json::Map::new(),
            roles: Vec::new(),
            cached: false,
            extensions: http::Extensions::new(),
            party: None,
            attributes: None,
        }
    }

    /// Returns the caller a Basic credential authenticates: the user-id as
    /// the subject, no client, and the space-delimited `scope` its
    /// configuration grants it, so the same check serves a Basic caller and
    /// a bearer caller (no specification governs this: our own design).
    ///
    /// A Basic credential is a user's, so the caller is always a
    /// [`CallerKind::User`], never a [`CallerKind::System`]: a machine
    /// authenticates with the client credentials grant (RFC 6749 §4.4) and
    /// is classified from its token. A `system/` scope in `scope` is a
    /// backend service's grant (SMART App Launch 2.2.0, Scopes and Launch
    /// Context), so the caller is granted none of them: it neither reaches a
    /// resource through one nor holds one as a scope.
    #[must_use]
    pub fn basic(username: String, scope: &str) -> Self {
        let personal: Vec<&str> = scope
            .split(' ')
            .filter(|token| !crate::basic::is_system_scope(token))
            .collect();
        let mut caller = Self::new(username, None, &personal.join(" "), None, CallerKind::User);
        caller.via = Via::Basic;
        caller
    }

    /// Returns this caller carrying `assurance`, what its token says about
    /// the authentication behind it.
    #[must_use]
    pub fn with_assurance(mut self, assurance: Assessment) -> Self {
        self.assurance = assurance;
        self
    }

    /// Returns this caller carrying what its token states under the
    /// issuer's `[auth.issuer.<name>.attributes]` table.
    #[must_use]
    pub fn with_attributes(mut self, attributes: Attributes) -> Self {
        self.attributes = Some(attributes);
        self
    }

    /// Returns what the caller's token states under its issuer's
    /// `[auth.issuer.<name>.attributes]` table (IHE IUA §3.71.4.2.2.1.1): the
    /// professional of a user other than a `Patient` or a `RelatedPerson`,
    /// and the purposes of use of every caller.
    #[must_use]
    pub fn attributes(&self) -> Option<&Attributes> {
        self.attributes.as_ref()
    }

    /// Returns this caller carrying `actor`, the current RFC 8693 §4.1
    /// actor its token names.
    #[must_use]
    pub fn with_actor(mut self, actor: Actor) -> Self {
        self.actor = Some(actor);
        self
    }

    /// Returns the current RFC 8693 §4.1 actor the token names, read as the
    /// issuer asserts it.
    #[must_use]
    pub const fn actor(&self) -> Option<&Actor> {
        self.actor.as_ref()
    }

    /// Returns the `fhirUser` claim, the user's FHIR resource (SMART App
    /// Launch 2.2.0, Scopes for requesting identity data).
    #[must_use]
    pub fn fhir_user(&self) -> Option<&str> {
        self.claim_text("fhirUser")
    }

    /// Returns who stands behind the credential.
    #[must_use]
    pub const fn kind(&self) -> &CallerKind {
        &self.kind
    }

    /// Returns what the token says about the authentication behind it,
    /// under its issuer's assurance mapping; nothing for a Basic caller or
    /// an issuer that maps none.
    #[must_use]
    pub const fn assurance(&self) -> &Assessment {
        &self.assurance
    }

    /// Returns this caller with `scopes` as its clinical scopes, read under
    /// a product's resource table.
    #[must_use]
    pub fn with_scopes(mut self, scopes: Scopes) -> Self {
        self.scopes = scopes;
        self
    }

    /// Returns this caller signed by `issuer`.
    #[must_use]
    pub fn with_issuer(mut self, issuer: String) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Returns this caller carrying `claims`.
    #[must_use]
    pub fn with_claims(mut self, claims: serde_json::Map<String, serde_json::Value>) -> Self {
        self.claims = claims;
        self
    }

    /// Returns this caller holding `roles`.
    #[must_use]
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    /// Returns this caller also holding `roles`, the roles a product grants
    /// a verified caller from its own data, beside the ones it holds.
    ///
    /// Each item is read like a role claim that is one string: each of its
    /// whitespace-separated words is a role, kept as spelled and added once
    /// ([`crate::roles`]). Every reader of the roles sees them
    /// ([`Caller::roles`], [`Caller::has_role`]). No specification governs
    /// the grant: our own design.
    #[must_use]
    pub fn with_granted_roles<I, S>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for role in roles {
            for word in role.as_ref().split_whitespace() {
                crate::roles::push(&mut self.roles, word);
            }
        }
        self
    }

    /// Returns this caller also granted the scope `tokens`, the scopes a
    /// product grants a verified caller from its own data, beside the ones
    /// its credential carries.
    ///
    /// Each item is a scope token or a space-delimited scope (RFC 6749
    /// §3.3); a token the caller already holds is added once. A Basic caller
    /// is a person, so it is granted no `system/` scope, the same rule as
    /// [`Caller::basic`]. Every reader of the scope sees the tokens added
    /// ([`Caller::scope`], [`Caller::has_scope`], [`Caller::scopes`],
    /// `Caller::openehr_scopes` with the `openehr` feature, and the reach a
    /// scope grants). A clinical scope among them is read like
    /// [`Scopes::parse`]; a product that holds a resource table re-reads
    /// [`Caller::scope`] with [`Scopes::parse_known`] and
    /// [`Caller::with_scopes`]. No specification governs the grant: our own
    /// design.
    #[must_use]
    pub fn with_granted_scope<I, S>(mut self, tokens: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let held = self.scope.len();
        for item in tokens {
            for token in item.as_ref().split(' ') {
                let personal = !(self.via == Via::Basic && crate::basic::is_system_scope(token));
                if !token.is_empty() && personal && !self.scope.iter().any(|had| had == token) {
                    self.scope.push(token.to_owned());
                }
            }
        }
        let joined = self.scope.get(held..).unwrap_or_default().join(" ");
        self.scopes.extend(Scopes::parse(&joined));
        self
    }

    /// Returns the roles the caller holds, as the token's claims or the Basic
    /// user's configuration spell them ([`crate::roles`]).
    #[must_use]
    pub fn roles(&self) -> &[String] {
        &self.roles
    }

    /// Returns whether the caller holds `role`, ignoring ASCII case.
    #[must_use]
    pub fn has_role(&self, role: &str) -> bool {
        crate::roles::holds(&self.roles, role)
    }

    /// Returns the string at the dotted claim `path` of the token, trimmed,
    /// or `None` when it is absent, not a string, or blank; a Basic caller
    /// carries no claim.
    #[must_use]
    pub fn claim_text(&self, path: &str) -> Option<&str> {
        crate::roles::claim_text(&self.claims, path)
    }

    /// Returns this caller carrying `value`, which a handler reads with
    /// [`Caller::extension`].
    ///
    /// A product's own [`Verifier`](crate::resource::Verifier) attaches its
    /// per-issuer policy this way; the crate reads one extension, the
    /// [`PatientClaim`] (no specification governs this: our own design).
    #[must_use]
    pub fn with_extension<T: Clone + Send + Sync + 'static>(mut self, value: T) -> Self {
        self.extensions.insert(value);
        self
    }

    /// Returns this caller carrying every value of `extensions` beside its
    /// own.
    pub(crate) fn with_extensions(mut self, extensions: http::Extensions) -> Self {
        self.extensions.extend(extensions);
        self
    }

    /// Returns this caller marked as admitted from the verified-credential
    /// cache, or not.
    #[must_use]
    pub const fn with_cached(mut self, cached: bool) -> Self {
        self.cached = cached;
        self
    }

    /// Returns the product's value of type `T`, when its resource server or
    /// verifier attached one.
    #[must_use]
    pub fn extension<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.extensions.get::<T>()
    }

    /// Returns this caller carrying `outcome`, what its login resolved to
    /// ([`crate::party::binding::PartyBinding::resolve`]).
    #[must_use]
    pub fn with_party(mut self, outcome: Outcome) -> Self {
        self.party = Some(outcome);
        self
    }

    /// Returns what the caller's login resolved to, or `None` when no party
    /// binding looked it up.
    #[must_use]
    pub const fn party(&self) -> Option<&Outcome> {
        self.party.as_ref()
    }

    /// Returns whether the caller was admitted from a cache: a Basic
    /// credential from the verified-credential cache (`[auth.basic]
    /// cache_ttl_seconds`) without the key derivation, or a bearer token
    /// from a held introspection response without a call to the endpoint.
    ///
    /// A JWT bearer caller, and a credential checked on this request, are
    /// `false`, so a product that records each fresh authentication records
    /// it once per cache lifetime (no specification governs the cache: our
    /// own design).
    #[must_use]
    pub const fn cached(&self) -> bool {
        self.cached
    }

    /// Returns the Basic user-id when the caller authenticated with HTTP
    /// Basic (RFC 7617) and its user-id is one of `users`.
    ///
    /// A bearer caller never matches, whatever its subject, the scheme rule
    /// of `guard::Requirement::Client` (no specification governs the list:
    /// our own design).
    #[must_use]
    pub fn basic_user_in<S: AsRef<str>>(&self, users: &[S]) -> Option<&str> {
        (self.via == Via::Basic && users.iter().any(|user| user.as_ref() == self.subject))
            .then_some(self.subject.as_str())
    }

    /// Returns the `acr` claim, the authentication context class the
    /// authentication event satisfied (RFC 9068 §2.2.1; RFC 9470 §6).
    #[must_use]
    pub fn acr(&self) -> Option<&str> {
        self.claims.get("acr").and_then(serde_json::Value::as_str)
    }

    /// Returns the `auth_time` claim, when the authentication event took
    /// place, in seconds since the epoch (RFC 9068 §2.2.1; RFC 9470 §6).
    #[must_use]
    pub fn auth_time(&self) -> Option<i64> {
        self.claims
            .get("auth_time")
            .and_then(serde_json::Value::as_i64)
    }

    /// Returns the subject: the token's `sub` or the Basic user-id.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the token's client, when it names one.
    #[must_use]
    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    /// Returns the `patient` launch context, when the token carries one.
    #[must_use]
    pub fn patient(&self) -> Option<&str> {
        self.patient.as_deref()
    }

    /// Returns the `ehrId` of the SMART on openEHR launch context, when the
    /// token carries it as a claim.
    ///
    /// The draft places it in the token response (`master07 §Context
    /// Selection`); reading it from an `ehrId` claim is the same convention
    /// as `patient` (no specification governs it: our own design).
    #[must_use]
    pub fn ehr_id(&self) -> Option<&str> {
        self.claims.get("ehrId").and_then(serde_json::Value::as_str)
    }

    /// Returns every token of the `scope` claim read under the SMART on
    /// openEHR grammar, a token outside it as [`SmartScope::Other`].
    ///
    /// [`SmartScope::Other`]: crate::openehr::smart_scopes::SmartScope::Other
    #[cfg(feature = "openehr")]
    #[must_use]
    pub fn openehr_scopes(&self) -> Vec<crate::openehr::smart_scopes::SmartScope> {
        self.scope
            .iter()
            .map(|token| crate::openehr::smart_scopes::SmartScope::parse(token))
            .collect()
    }

    /// Returns whether the request is the natural person's own access: a
    /// [`CallerKind::Patient`] whose `fhirUser` is the `Patient` its
    /// `patient` launch context names, with no actor.
    ///
    /// Regulation (EU) 2025/327 Art. 5 has information the person inserts
    /// "clearly distinguishable as having been inserted by the natural
    /// person", so only the patient's own token is the person's; a
    /// representative is a `RelatedPerson` (Art 4(2)) and an actor acts for
    /// them (RFC 8693 §4.1). A Basic caller never is.
    #[must_use]
    pub fn is_the_person(&self) -> bool {
        self.kind == CallerKind::Patient
            && self.actor.is_none()
            && self.patient().is_some_and(|patient| {
                self.fhir_user()
                    .and_then(crate::kind::fhir_user_parts)
                    .is_some_and(|(_, id)| id == patient)
            })
    }

    /// Returns the patient a [`CallerKind::RelatedPerson`] represents: the
    /// `patient` launch context of their token (Regulation (EU) 2025/327
    /// Art 4(2)).
    #[must_use]
    pub fn represented(&self) -> Option<&str> {
        (self.kind == CallerKind::RelatedPerson)
            .then(|| self.patient())
            .flatten()
    }

    /// Returns the patient the request is bound to when
    /// [`Caller::is_the_person`] holds, or `None` when it does not.
    ///
    /// The context carries what the token names: the `patient` launch
    /// context, the `ehrId` of the openEHR launch context, and the value of
    /// the deployment's patient claim, each `None` when absent.
    #[must_use]
    pub fn person(&self) -> Option<PersonContext<'_>> {
        self.is_the_person().then(|| PersonContext {
            patient: self.patient(),
            ehr_id: self.ehr_id(),
            claim: self.patient_claim_value(),
        })
    }

    /// Returns the value of the deployment's patient claim, when it names
    /// one and the token carries it as a string that is not blank.
    fn patient_claim_value(&self) -> Option<&str> {
        self.extension::<PatientClaim>()
            .and_then(|claim| self.claim_text(claim.path()))
    }

    /// Returns the scheme the credential arrived with.
    #[must_use]
    pub const fn via(&self) -> Via {
        self.via
    }

    /// Returns the issuer that signed the token, when one did.
    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// Returns whether the `scope` claim names `scope`, compared verbatim.
    ///
    /// This is how a product reads its own scope (an operator or admin
    /// scope) that is no SMART clinical scope.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scope.iter().any(|granted| granted == scope)
    }

    /// Returns every token of the `scope` claim, as granted.
    #[must_use]
    pub fn scope(&self) -> &[String] {
        &self.scope
    }

    /// Returns the clinical scopes the token grants.
    #[must_use]
    pub const fn scopes(&self) -> &Scopes {
        &self.scopes
    }

    /// Returns every claim of the token, for the product's own reading.
    #[must_use]
    pub const fn claims(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.claims
    }

    /// Returns the claim `name`, when the token carries it.
    #[must_use]
    pub fn claim(&self, name: &str) -> Option<&serde_json::Value> {
        self.claims.get(name)
    }

    /// Returns which data `permission` on `resource_type` reaches, or `None`
    /// when the token does not grant it.
    ///
    /// A token with no resource scope of either grammar reaches everything
    /// when its subject is on the deployment's allowlist and nothing
    /// otherwise. A `patient/`
    /// scope reaches the patient in the `patient` claim, and nothing when the
    /// token carries no such claim. A granular scope grants nothing here;
    /// [`Caller::reach_with`] evaluates it.
    #[must_use]
    pub fn reach(&self, permission: Permission, resource_type: &str) -> Option<Compartment> {
        self.reach_with(permission, resource_type, &|_constraint| false)
    }

    /// Returns which data `permission` on `resource_type` reaches, a
    /// granular scope admitted when `evaluate` says the resource satisfies
    /// its constraint.
    #[must_use]
    pub fn reach_with(
        &self,
        permission: Permission,
        resource_type: &str,
        evaluate: Evaluator<'_>,
    ) -> Option<Compartment> {
        match self
            .scopes
            .reach_with(permission, resource_type, evaluate)?
        {
            Reach::Any => Some(Compartment::Any),
            Reach::Patient => self.patient.clone().map(Compartment::Patient),
        }
    }
}

impl Compartment {
    /// Returns whether this compartment reaches the data of `patient`, the
    /// patient a resource belongs to, or `None` when the resource belongs to
    /// no patient.
    ///
    /// "If the app has any patient-level scopes, they will be scoped to
    /// Patient 123" (SMART App Launch 2.2.0, Scopes and Launch Context,
    /// §Launch context arrives with your `access_token`), so a patient
    /// compartment reaches only that patient's resources, and a resource of
    /// no patient is outside every patient's compartment.
    #[must_use]
    pub fn admits(&self, patient: Option<&str>) -> bool {
        match self {
            Self::Any => true,
            Self::Patient(launched) => patient == Some(launched.as_str()),
        }
    }
}

impl Access {
    /// Returns the caller, or `None` on an open surface.
    #[must_use]
    pub fn caller(&self) -> Option<&Caller> {
        match self {
            Self::Open => None,
            Self::Caller(caller) => Some(caller),
        }
    }

    /// Returns whether the caller's `scope` claim names `scope`; an open
    /// surface has no caller and so no scope.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.caller().is_some_and(|caller| caller.has_scope(scope))
    }

    /// Returns the product's value of type `T` on the caller, or `None` on
    /// an open surface or when none was attached.
    #[must_use]
    pub fn extension<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.caller().and_then(Caller::extension::<T>)
    }

    /// Returns the Basic user-id when the caller authenticated with HTTP
    /// Basic and its user-id is one of `users`; an open surface has no
    /// caller and matches none.
    #[must_use]
    pub fn basic_user_in<S: AsRef<str>>(&self, users: &[S]) -> Option<&str> {
        self.caller().and_then(|caller| caller.basic_user_in(users))
    }

    /// Returns what the caller's login resolved to, or `None` on an open
    /// surface or when no party binding looked it up.
    #[must_use]
    pub fn party(&self) -> Option<&Outcome> {
        self.caller().and_then(Caller::party)
    }

    /// Returns the caller's roles; none on an open surface.
    #[must_use]
    pub fn roles(&self) -> &[String] {
        self.caller().map_or(&[], Caller::roles)
    }

    /// Returns the caller's claims, or `None` on an open surface.
    #[must_use]
    pub fn claims(&self) -> Option<&serde_json::Map<String, serde_json::Value>> {
        self.caller().map(Caller::claims)
    }

    /// Returns the `ehrId` of the caller's launch context, when the token
    /// carries one.
    #[must_use]
    pub fn ehr_id(&self) -> Option<&str> {
        self.caller().and_then(Caller::ehr_id)
    }

    /// Returns which data `permission` on `resource_type` reaches.
    #[must_use]
    pub fn reach(&self, permission: Permission, resource_type: &str) -> Option<Compartment> {
        match self {
            Self::Open => Some(Compartment::Any),
            Self::Caller(caller) => caller.reach(permission, resource_type),
        }
    }

    /// Returns which data `permission` on `resource_type` reaches, a
    /// granular scope evaluated by `evaluate`.
    #[must_use]
    pub fn reach_with(
        &self,
        permission: Permission,
        resource_type: &str,
        evaluate: Evaluator<'_>,
    ) -> Option<Compartment> {
        match self {
            Self::Open => Some(Compartment::Any),
            Self::Caller(caller) => caller.reach_with(permission, resource_type, evaluate),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::kind::{Actor, CallerKind};
    use crate::resource::{Access, Caller, Compartment, PatientClaim, PatientClaimError, Via};
    use crate::scope::Permission;

    #[test]
    fn a_token_with_no_clinical_scope_reaches_nothing() {
        let system = Caller::new(
            String::from("svc"),
            None,
            "openid",
            None,
            CallerKind::System,
        );
        assert_eq!(None, system.reach(Permission::Create, "Condition"));
        assert!(system.has_scope("openid"));
        assert!(!system.has_scope("open"));
        let other = Caller::new(String::from("svc"), None, "", None, CallerKind::Person);
        assert_eq!(None, other.reach(Permission::Read, "Condition"));
        assert_eq!(other.scope(), Vec::<String>::new());
    }

    #[test]
    fn a_system_caller_gets_only_its_scopes() {
        let caller = Caller::new(
            String::from("svc"),
            None,
            "system/Condition.r",
            None,
            CallerKind::System,
        );
        assert_eq!(None, caller.reach(Permission::Create, "Condition"));
        assert_eq!(
            Some(Compartment::Any),
            caller.reach(Permission::Read, "Condition")
        );
    }

    #[cfg(feature = "openehr")]
    #[test]
    fn an_openehr_scope_makes_a_token_scoped_on_a_fhir_route_too() {
        let caller = Caller::new(
            String::from("svc"),
            None,
            "system/composition-*.r",
            None,
            CallerKind::System,
        );
        assert_eq!(
            None,
            caller.reach(Permission::Read, "Condition"),
            "the two grammars share one scope claim"
        );
    }

    #[test]
    fn a_patient_scope_without_a_patient_claim_reaches_nothing() {
        let without = Caller::new(
            String::from("app"),
            None,
            "patient/*.rs",
            None,
            CallerKind::Person,
        );
        assert_eq!(None, without.reach(Permission::Read, "Condition"));
        let with = Caller::new(
            String::from("app"),
            None,
            "patient/*.rs",
            Some(String::from("123")),
            CallerKind::Person,
        );
        assert_eq!(
            Some(Compartment::Patient(String::from("123"))),
            with.reach(Permission::Read, "Condition")
        );
    }

    #[test]
    fn a_basic_user_matches_its_list_and_a_bearer_subject_never_does() {
        let basic = Caller::basic(String::from("scrape"), "");
        assert_eq!(Some("scrape"), basic.basic_user_in(&["feed", "scrape"]));
        assert_eq!(None, basic.basic_user_in(&["feed"]), "an unlisted user");
        let bearer = Caller::new(String::from("scrape"), None, "", None, CallerKind::Person);
        assert_eq!(
            None,
            bearer.basic_user_in(&["scrape"]),
            "a bearer subject never passes for a Basic user-id"
        );
        assert_eq!(None, Access::Open.basic_user_in(&["scrape"]));
        assert_eq!(
            Some("scrape"),
            Access::Caller(std::sync::Arc::new(basic)).basic_user_in(&[String::from("scrape")])
        );
    }

    #[test]
    fn an_extension_rides_on_the_caller_and_equality_ignores_it() {
        #[derive(Debug, Clone, PartialEq)]
        struct Policy(&'static str);
        let plain = Caller::new(String::from("svc"), None, "", None, CallerKind::Person);
        let extended = plain.clone().with_extension(Policy("issuer-a"));
        assert_eq!(Some(&Policy("issuer-a")), extended.extension::<Policy>());
        assert_eq!(None, plain.extension::<Policy>());
        assert_eq!(plain, extended, "equality ignores the extensions");
        let access = Access::Caller(std::sync::Arc::new(extended));
        assert_eq!(Some(&Policy("issuer-a")), access.extension::<Policy>());
        assert_eq!(None, Access::Open.extension::<Policy>());
        assert!(!plain.cached(), "a bearer caller is never from the cache");
    }

    #[test]
    fn acr_and_auth_time_are_read_from_the_claims() {
        let mut claims = serde_json::Map::new();
        claims.insert(String::from("acr"), serde_json::json!("urn:acr:high"));
        claims.insert(String::from("auth_time"), serde_json::json!(1_700_000_000));
        let caller = Caller::new(String::from("svc"), None, "", None, CallerKind::Person)
            .with_claims(claims);
        assert_eq!(Some("urn:acr:high"), caller.acr());
        assert_eq!(Some(1_700_000_000), caller.auth_time());
        let bare = Caller::new(String::from("svc"), None, "", None, CallerKind::Person);
        assert_eq!(None, bare.acr());
        assert_eq!(None, bare.auth_time());
    }

    #[test]
    fn a_patient_compartment_admits_its_patient_alone() {
        let compartment = Compartment::Patient(String::from("123"));
        assert!(compartment.admits(Some("123")));
        assert!(!compartment.admits(Some("124")));
        assert!(!compartment.admits(None));
        assert!(Compartment::Any.admits(None));
    }

    /// A bearer caller of `kind` under a deployment whose patient claim is
    /// `patient_id`, carrying that claim when `claimed` names a value.
    fn bearer(kind: CallerKind, claimed: Option<&str>) -> Caller {
        let mut claims = serde_json::Map::new();
        if let Some(value) = claimed {
            claims.insert(String::from("patient_id"), serde_json::json!(value));
        }
        claims.insert(String::from("ehrId"), serde_json::json!("ehr-9"));
        claims.insert(String::from("fhirUser"), serde_json::json!("Patient/123"));
        Caller::new(
            String::from("sub-1"),
            None,
            "patient/*.rs",
            Some(String::from("123")),
            kind,
        )
        .with_claims(claims)
        .with_extension(PatientClaim::new("patient_id").expect("a valid path"))
    }

    #[test]
    fn only_a_patient_caller_is_the_person_whatever_its_scopes() {
        assert!(bearer(CallerKind::Patient, None).is_the_person());
        for kind in [
            CallerKind::Person,
            CallerKind::System,
            CallerKind::Practitioner,
            CallerKind::RelatedPerson,
            CallerKind::User,
        ] {
            let caller = bearer(kind.clone(), Some("p-7"));
            assert!(!caller.is_the_person(), "{kind:?}");
            assert!(caller.person().is_none(), "{kind:?}");
        }
        let acted = bearer(CallerKind::Patient, None).with_actor(Actor {
            issuer: String::from("https://as.example.org"),
            sub: String::from("actor-1"),
        });
        assert!(!acted.is_the_person(), "an actor acts for the patient");
        let other = Caller::new(
            String::from("sub-1"),
            None,
            "patient/*.rs",
            Some(String::from("456")),
            CallerKind::Patient,
        )
        .with_claims(
            serde_json::json!({ "fhirUser": "Patient/123" })
                .as_object()
                .cloned()
                .expect("an object"),
        );
        assert!(
            !other.is_the_person(),
            "a patient context other than the fhirUser"
        );
        let basic = Caller::basic(String::from("etl"), "patient/Observation.rs");
        assert!(!basic.is_the_person(), "a Basic user is never the person");
    }

    // NOTE: Regulation (EU) 2025/327 Art 4(2): a representative acts for the
    // patient in their launch context.
    #[test]
    fn a_related_person_represents_the_patient_in_context() {
        let related = bearer(CallerKind::RelatedPerson, None);
        assert_eq!(Some("123"), related.represented());
        assert_eq!(None, bearer(CallerKind::Practitioner, None).represented());
    }

    #[test]
    fn the_person_context_names_what_the_token_binds() {
        let caller = bearer(CallerKind::Patient, Some("p-7"));
        let person = caller.person().expect("a patient caller is the person");
        assert_eq!(Some("123"), person.patient);
        assert_eq!(Some("ehr-9"), person.ehr_id);
        assert_eq!(Some("p-7"), person.claim);
        let blank = bearer(CallerKind::Patient, Some("  "));
        assert_eq!(None, blank.person().and_then(|person| person.claim));
    }

    #[test]
    fn a_malformed_patient_claim_path_is_refused() {
        for path in ["", "person..patient_id", ".", "patient id"] {
            assert_eq!(Err(PatientClaimError), PatientClaim::new(path), "{path:?}");
        }
        assert_eq!(
            Ok("person.patient_id"),
            PatientClaim::new("person.patient_id")
                .as_ref()
                .map(PatientClaim::path)
        );
    }

    #[test]
    fn a_basic_caller_is_a_user_and_never_a_system() {
        let caller = Caller::basic(String::from("etl"), "system/*.rs");
        assert_eq!(&CallerKind::User, caller.kind());
        assert_ne!(&CallerKind::System, caller.kind());
    }

    // NOTE: a Basic credential is a person's (owner ruling on #215), so no scope string a
    // product hands `Caller::basic` gives it a backend service's `system/` reach (#274).
    #[test]
    fn a_basic_caller_never_carries_system_reach() {
        let caller = Caller::basic(
            String::from("batch-loader"),
            "system/*.cruds system/Condition.r user/Observation.r __ferro.admin",
        );
        assert_eq!(None, caller.reach(Permission::Read, "Condition"));
        assert_eq!(None, caller.reach(Permission::Create, "Patient"));
        assert!(
            !caller.has_scope("system/*.cruds"),
            "the scope is not granted"
        );
        assert!(
            caller
                .scope()
                .iter()
                .all(|token| !token.starts_with("system/")),
            "{:?}",
            caller.scope()
        );
        assert_eq!(
            Some(Compartment::Any),
            caller.reach(Permission::Read, "Observation"),
            "a user/ scope still reaches"
        );
        assert!(
            caller.has_scope("__ferro.admin"),
            "a product scope still counts"
        );
    }

    #[test]
    fn a_basic_caller_carries_its_configured_scope() {
        let caller = Caller::basic(String::from("alice"), "user/Condition.r");
        assert_eq!("alice", caller.subject());
        assert_eq!(None, caller.client_id());
        assert_eq!(Via::Basic, caller.via());
        assert_eq!(None, caller.issuer());
        assert_eq!(
            Some(Compartment::Any),
            caller.reach(Permission::Read, "Condition")
        );
        assert_eq!(None, caller.reach(Permission::Delete, "Condition"));
        let none = Caller::basic(String::from("bob"), "");
        assert_eq!(None, none.reach(Permission::Read, "Condition"));
    }
}
