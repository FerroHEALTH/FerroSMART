// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The party binding through the public API: a caller in, its login looked
//! up through a test `PartySource`, and one typed outcome or a typed source
//! error out. Every source is a fake that records each call, so a case
//! asserts how often the library asked.

use std::error::Error as StdError;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;

use argon2::Argon2;
use argon2::password_hash::PasswordHasher;
use ferrohealth_smart::basic::PasswordStore;
use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::party::Bound;
use ferrohealth_smart::party::GroupsCause;
use ferrohealth_smart::party::Marker;
use ferrohealth_smart::party::Markers;
use ferrohealth_smart::party::Membership;
use ferrohealth_smart::party::Outcome;
use ferrohealth_smart::party::PartyRef;
use ferrohealth_smart::party::PartyState;
use ferrohealth_smart::party::Represented;
use ferrohealth_smart::party::binding::PartyBinding;
use ferrohealth_smart::party::config::PartyError;
use ferrohealth_smart::party::config::PartySection;
use ferrohealth_smart::party::source::Lookup;
use ferrohealth_smart::party::source::PartyRecord;
use ferrohealth_smart::party::source::PartySource;
use ferrohealth_smart::party::source::Query;
use ferrohealth_smart::party::source::SourceError;
use ferrohealth_smart::resource::Caller;
use secrecy::SecretString;
use serde_json::Value;
use serde_json::json;

mod config;
mod federation;
mod groups;
#[cfg(all(feature = "axum", feature = "fetch"))]
mod guard;
mod token;

type Outcome2 = Result<(), Box<dyn StdError>>;

/// The `persons` issuer of the cases.
pub(crate) const ISSUER: &str = "https://login.example.org/tenant-1/v2.0";
/// The issuer of the login identifiers its persons carry.
pub(crate) const IDENTIFIERS: &str = "urn:example:ferro:login";
/// The issuer of the group identifiers its tokens name.
pub(crate) const GROUPS: &str = "urn:example:ferro:groups";
/// The deployment's own client.
const CLIENT: &str = "first-party-app";
/// The login of the person in the cases, a GUID in lower case.
pub(crate) const LOGIN: &str = "5ba552d6-7c3e-4a1f-9d2b-0e8f6a7b1c2d";

/// What a fake source saw of one query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Seen {
    /// The identifier issuer.
    pub(crate) identifier_issuer: String,
    /// The identifier type.
    pub(crate) identifier_type: String,
    /// The key value.
    pub(crate) value: String,
    /// The group identifier issuer.
    pub(crate) group_identifier_issuer: Option<String>,
}

/// How a fake source answers.
type Answer = Box<dyn Fn(&Query<'_>) -> Result<Lookup, SourceError> + Send + Sync>;

/// A product's store, faked: every query recorded, every answer `answer`'s.
pub(crate) struct FakeSource {
    /// The answer to the next query.
    answer: Mutex<Answer>,
    /// Every query, in order.
    seen: Mutex<Vec<Seen>>,
}

impl FakeSource {
    /// Returns a source answering every query with `lookup`.
    pub(crate) fn answering(lookup: Lookup) -> Arc<Self> {
        Self::with(move |_query| Ok(lookup.clone()))
    }

    /// Returns a source answering with `answer`.
    pub(crate) fn with(
        answer: impl Fn(&Query<'_>) -> Result<Lookup, SourceError> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(Box::new(answer)),
            seen: Mutex::new(Vec::new()),
        })
    }

    /// Answers every later query with `lookup`.
    fn answer_with(&self, lookup: Lookup) {
        *self.answer.lock().expect("not poisoned") = Box::new(move |_query| Ok(lookup.clone()));
    }

    /// Returns every query seen.
    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("not poisoned").clone()
    }

    /// Returns how many queries were seen.
    pub(crate) fn calls(&self) -> usize {
        self.seen.lock().expect("not poisoned").len()
    }
}

impl PartySource for FakeSource {
    fn lookup<'a>(
        &'a self,
        query: &'a Query<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<Lookup, SourceError>> + Send + 'a>> {
        self.seen.lock().expect("not poisoned").push(Seen {
            identifier_issuer: query.identifier_issuer.to_owned(),
            identifier_type: query.identifier_type.to_owned(),
            value: query.value.to_owned(),
            group_identifier_issuer: query.group_identifier_issuer.map(str::to_owned),
        });
        let answer = (self.answer.lock().expect("not poisoned"))(query);
        Box::pin(std::future::ready(answer))
    }
}

/// The `[auth.issuer.<name>.party]` table of the cases: GUID logins, groups read from
/// `groups`.
pub(crate) fn table() -> PartySection {
    PartySection {
        issuer: ferrohealth_secret::secret_url::SecretUrl::new(ISSUER),
        identifier_issuer: String::from(IDENTIFIERS),
        identifier_type: String::from("guid"),
        group_claim: String::from("groups"),
        group_identifier_issuer: String::from(GROUPS),
    }
}

/// Returns the binding of the issuer over `source`.
fn binding(source: &Arc<FakeSource>) -> PartyBinding {
    binding_of(source, table())
}

/// Returns the binding of the issuer under `table` over `source`.
fn binding_of(source: &Arc<FakeSource>, table: PartySection) -> PartyBinding {
    let concrete = Arc::clone(source);
    let source: Arc<dyn PartySource> = concrete;
    PartyBinding::new(source)
        .with_issuer(table, IssuerKind::Smart)
        .expect("the table binds")
}

/// Returns a caller of the issuer of `kind`, whose `sub` is `key` (blank
/// for none) and whose token carries `claims`.
fn caller(kind: CallerKind, key: Option<&str>, claims: &Value) -> Caller {
    let claims = claims.as_object().cloned().unwrap_or_default();
    Caller::new(
        key.unwrap_or_default().to_owned(),
        Some(String::from(CLIENT)),
        "user/*.rs",
        None,
        kind,
    )
    .with_issuer(String::from(ISSUER))
    .with_claims(claims)
}

/// Returns a practitioner caller carrying [`LOGIN`] and `claims`.
fn person(claims: &Value) -> Caller {
    caller(CallerKind::Practitioner, Some(LOGIN), claims)
}

/// Returns the reference of the `PERSON` `id`.
pub(crate) fn person_ref(id: &str) -> PartyRef {
    PartyRef::new("ferro-demographic", "PERSON", id)
}

/// Returns the reference of the `GROUP` `id`.
fn group_ref(id: &str) -> PartyRef {
    PartyRef::new("ferro-demographic", "GROUP", id)
}

/// Returns the active record of the `PERSON` `id` carrying `markers`.
pub(crate) fn record(id: &str, markers: Markers) -> PartyRecord {
    PartyRecord::new(person_ref(id), PartyState::Active, markers)
}

/// Returns the one professional the source finds.
pub(crate) fn one_professional() -> Lookup {
    Lookup::Parties(vec![record("p-1", Markers::PROFESSIONAL)])
}

/// Returns the bound party of `outcome`.
pub(crate) fn bound(outcome: Option<Outcome>) -> Result<Bound, Box<dyn StdError>> {
    match outcome {
        Some(Outcome::Party(bound)) => Ok(*bound),
        other => Err(format!("a bound party, not {other:?}").into()),
    }
}

// NOTE: no specification governs the binding: our own design, which reads the source on
// every request and holds no cache, so a change in the store binds the next request.
#[tokio::test]
async fn one_match_binds_its_party_and_every_request_reads_the_source() -> Outcome2 {
    let source = FakeSource::answering(one_professional());
    let binding = binding(&source);
    let caller = person(&json!({}));
    let first = bound(binding.resolve(&caller).await?)?;
    assert_eq!(person_ref("p-1"), first.party);
    assert_eq!(IDENTIFIERS, first.identifier.issuer());
    assert_eq!("guid", first.identifier.identifier_type());
    assert_eq!(LOGIN, first.identifier.value());
    assert_eq!(Markers::PROFESSIONAL, first.markers);
    assert!(!first.provisional);
    assert_eq!(1, source.calls(), "one call per request");
    source.answer_with(Lookup::Parties(vec![record("p-2", Markers::PROFESSIONAL)]));
    let second = bound(binding.resolve(&caller).await?)?;
    assert_eq!(
        person_ref("p-2"),
        second.party,
        "no cache: the store's change binds"
    );
    assert_eq!(
        2,
        source.calls(),
        "the second request read the source again"
    );
    Ok(())
}

// NOTE: no specification governs the duplicate rule: our own design, in which two
// parties carrying one login are refused and never resolved to either.
#[tokio::test]
async fn two_matching_parties_are_ambiguous() -> Outcome2 {
    let source = FakeSource::answering(Lookup::Parties(vec![
        record("p-1", Markers::PROFESSIONAL),
        record("p-2", Markers::PROFESSIONAL),
    ]));
    let outcome = binding(&source).resolve(&person(&json!({}))).await?;
    assert!(
        matches!(outcome, Some(Outcome::Ambiguous { count: 2 })),
        "{outcome:?}"
    );
    let once = FakeSource::answering(Lookup::Parties(vec![
        record("p-1", Markers::PROFESSIONAL),
        record("p-1", Markers::PROFESSIONAL),
    ]));
    let outcome = binding(&once).resolve(&person(&json!({}))).await?;
    assert!(
        matches!(outcome, Some(Outcome::Party(_))),
        "one party reported twice is one party: {outcome:?}"
    );
    Ok(())
}

// NOTE: no specification governs the binding: our own design; no party is Unbound and a
// key that is the tombstone of a deleted party is Deprovisioned, never a new party.
#[tokio::test]
async fn no_party_is_unbound_and_a_tombstone_is_deprovisioned() -> Outcome2 {
    let none = FakeSource::answering(Lookup::Parties(Vec::new()));
    let outcome = binding(&none).resolve(&person(&json!({}))).await?;
    assert!(matches!(outcome, Some(Outcome::Unbound)), "{outcome:?}");
    let tombstone = FakeSource::answering(Lookup::Deprovisioned);
    let outcome = binding(&tombstone).resolve(&person(&json!({}))).await?;
    assert!(
        matches!(outcome, Some(Outcome::Deprovisioned)),
        "{outcome:?}"
    );
    Ok(())
}

// NOTE: openEHR RM Common §Abandoned and Inactive States (`rm-common master06`, vendored
// under docs/specs/openehr-rm/development/) names `800|inactive|` and `801|abandoned|`;
// the product reports the state and the outcome keeps the party.
#[tokio::test]
async fn an_inactive_or_abandoned_party_is_refused_with_its_reference_and_incomplete_binds()
-> Outcome2 {
    for (state, name) in [
        (PartyState::Inactive, "inactive"),
        (PartyState::Abandoned, "abandoned"),
    ] {
        let source = FakeSource::answering(Lookup::Parties(vec![PartyRecord::new(
            person_ref("p-1"),
            state,
            Markers::PROFESSIONAL,
        )]));
        let outcome = binding(&source)
            .resolve(&person(&json!({})))
            .await?
            .ok_or("looked up")?;
        assert_eq!(name, outcome.as_str());
        assert_eq!(
            Some(&person_ref("p-1")),
            outcome.party(),
            "{name} keeps the party"
        );
    }
    let incomplete = FakeSource::answering(Lookup::Parties(vec![PartyRecord::new(
        person_ref("p-1"),
        PartyState::Incomplete,
        Markers::PROFESSIONAL,
    )]));
    let party = bound(binding(&incomplete).resolve(&person(&json!({}))).await?)?;
    assert!(party.provisional, "an incomplete party binds, provisional");
    Ok(())
}

// NOTE: RFC 7519 §4.1.2: `sub` identifies the principal, so a blank one is refused
// before any lookup.
#[tokio::test]
async fn a_token_without_the_key_claim_is_key_claim_missing() -> Outcome2 {
    let source = FakeSource::answering(one_professional());
    let binding = binding(&source);
    for key in [None, Some(""), Some("  ")] {
        let outcome = binding
            .resolve(&caller(CallerKind::Practitioner, key, &json!({})))
            .await?;
        assert!(
            matches!(outcome, Some(Outcome::KeyClaimMissing)),
            "{key:?}: {outcome:?}"
        );
    }
    assert_eq!(0, source.calls(), "no key, no lookup");
    Ok(())
}

/// Returns a `RelatedPerson` caller with `represented` in context.
fn representative(represented: &str) -> Caller {
    let claims = json!({}).as_object().cloned().unwrap_or_default();
    Caller::new(
        String::from(LOGIN),
        Some(String::from(CLIENT)),
        "user/*.rs",
        Some(represented.to_owned()),
        CallerKind::RelatedPerson,
    )
    .with_issuer(String::from(ISSUER))
    .with_claims(claims)
}

// NOTE: no specification governs the binding: our own design, in which a representative
// is looked up by their own login, never by the subject they represent.
#[tokio::test]
async fn a_representative_is_looked_up_by_its_own_login() -> Outcome2 {
    let source = FakeSource::answering(Lookup::Parties(vec![
        record("p-9", Markers::REPRESENTATIVE).with_represents(vec![
            Represented::new(person_ref("subject-1")).with_relationship("254|parent|"),
        ]),
    ]));
    let party = bound(
        binding(&source)
            .resolve(&representative("subject-1"))
            .await?,
    )?;
    assert_eq!(
        vec![Seen {
            identifier_issuer: String::from(IDENTIFIERS),
            identifier_type: String::from("guid"),
            value: String::from(LOGIN),
            group_identifier_issuer: Some(String::from(GROUPS)),
        }],
        source.seen(),
        "the representative's own key, never the represented subject"
    );
    let relationship = party.represents.first().ok_or("a recorded relationship")?;
    assert_eq!(&person_ref("subject-1"), relationship.subject());
    assert_eq!(Some("254|parent|"), relationship.relationship());
    Ok(())
}

// NOTE: no specification governs the markers: our own design; a RelatedPerson needs
// `representative`, a Practitioner or a Person `professional`, and both bind either.
#[tokio::test]
async fn a_caller_on_a_party_without_its_marker_is_wrong_marker_and_both_bind_either() -> Outcome2 {
    let professional =
        FakeSource::answering(Lookup::Parties(vec![record("p-1", Markers::PROFESSIONAL)]));
    let outcome = binding(&professional)
        .resolve(&representative("subject-1"))
        .await?;
    assert!(
        matches!(
            &outcome,
            Some(Outcome::WrongMarker { party, needed: Marker::Representative, markers })
                if *party == person_ref("p-1") && *markers == Markers::PROFESSIONAL
        ),
        "{outcome:?}"
    );
    let represents = FakeSource::answering(Lookup::Parties(vec![record(
        "p-2",
        Markers::REPRESENTATIVE,
    )]));
    for kind in [
        CallerKind::Person,
        CallerKind::Practitioner,
        CallerKind::User,
    ] {
        let outcome = binding(&represents)
            .resolve(&caller(kind.clone(), Some(LOGIN), &json!({})))
            .await?;
        assert!(
            matches!(
                outcome,
                Some(Outcome::WrongMarker {
                    needed: Marker::Professional,
                    ..
                })
            ),
            "{kind:?}: {outcome:?}"
        );
    }
    let both = FakeSource::answering(Lookup::Parties(vec![record("p-3", Markers::BOTH)]));
    for caller in [
        caller(CallerKind::Person, Some(LOGIN), &json!({})),
        caller(CallerKind::PractitionerRole, Some(LOGIN), &json!({})),
        representative("subject-1"),
    ] {
        let party = bound(binding(&both).resolve(&caller).await?)?;
        assert_eq!(person_ref("p-3"), party.party);
    }
    Ok(())
}

// NOTE: RFC 7519 §4.1.2: `sub` is "locally unique in the context of the issuer", so a
// federation token's subject is never matched here; patients and systems are never looked up.
#[tokio::test]
async fn callers_that_are_never_looked_up_never_reach_the_source() -> Outcome2 {
    let source = FakeSource::answering(one_professional());
    let binding = binding(&source);
    for kind in [CallerKind::Patient, CallerKind::System] {
        let outcome = binding
            .resolve(&caller(kind.clone(), Some(LOGIN), &json!({})))
            .await?;
        assert!(outcome.is_none(), "{kind:?}: {outcome:?}");
    }
    for external in federation::externals().await? {
        let outcome = binding.resolve(&external).await?;
        assert!(outcome.is_none(), "{:?}: {outcome:?}", external.kind());
    }
    assert_eq!(0, source.calls(), "no call reached the source");
    Ok(())
}

// NOTE: no vendored specification governs GUID case: our own design, in which a GUID key
// is put in lower case before the match, as its `identifier_type` declares.
#[tokio::test]
async fn an_upper_case_guid_claim_matches_its_lower_case_stored_form() -> Outcome2 {
    let source = FakeSource::with(|query| {
        Ok(if query.value == LOGIN {
            one_professional()
        } else {
            Lookup::Parties(Vec::new())
        })
    });
    let upper = LOGIN.to_ascii_uppercase();
    let outcome = binding(&source)
        .resolve(&caller(CallerKind::Person, Some(&upper), &json!({})))
        .await?;
    assert!(matches!(outcome, Some(Outcome::Party(_))), "{outcome:?}");
    let exact = PartySection {
        identifier_type: String::from("login"),
        ..table()
    };
    let outcome = binding_of(&source, exact)
        .resolve(&caller(CallerKind::Person, Some(&upper), &json!({})))
        .await?;
    assert!(
        matches!(outcome, Some(Outcome::Unbound)),
        "any other type is compared exactly: {outcome:?}"
    );
    Ok(())
}

/// The failure of the fake store.
#[derive(Debug, thiserror::Error)]
#[error("the synthetic store is down")]
struct StoreDown;

// NOTE: no specification governs the binding: our own design, in which a source that
// fails is a typed error and never read as no match.
#[tokio::test]
async fn a_failing_source_is_an_error_and_never_unbound() -> Outcome2 {
    let source = FakeSource::with(|_query| Err(SourceError::new(StoreDown)));
    let outcome = binding(&source).resolve(&person(&json!({}))).await;
    let error = outcome.expect_err("a source error");
    assert!(
        error
            .source()
            .is_some_and(|cause| cause.downcast_ref::<StoreDown>().is_some()),
        "the store's failure is the cause"
    );
    Ok(())
}

// NOTE: RFC 6749 §4.4: a machine authenticates with the client credentials grant, so a
// Basic credential is a user's, looked up through the user path by its mapped key.
#[tokio::test]
async fn a_basic_user_is_a_person_looked_up_by_its_mapped_key() -> Outcome2 {
    let source = FakeSource::answering(one_professional());
    let binding = binding(&source).with_basic_user("clinician", IDENTIFIERS, LOGIN)?;
    let basic = Caller::basic(String::from("clinician"), "user/*.rs");
    assert_eq!(&CallerKind::User, basic.kind(), "never a System");
    let party = bound(binding.resolve(&basic).await?)?;
    assert_eq!(person_ref("p-1"), party.party);
    assert_eq!(
        Some(LOGIN),
        source.seen().first().map(|seen| seen.value.as_str())
    );
    let unmapped = binding
        .resolve(&Caller::basic(String::from("stranger"), "user/*.rs"))
        .await?;
    assert!(
        matches!(unmapped, Some(Outcome::KeyClaimMissing)),
        "{unmapped:?}"
    );
    Ok(())
}

#[test]
fn every_basic_user_maps_to_a_key_and_only_under_a_bound_table() -> Outcome2 {
    let source = FakeSource::answering(one_professional());
    let mapped = binding(&source).with_basic_user("clinician", IDENTIFIERS, LOGIN)?;
    assert!(matches!(
        binding(&source).with_basic_user("clinician", "urn:example:other", LOGIN),
        Err(PartyError::BasicKey { .. })
    ));
    let hash = || {
        SecretString::from(
            Argon2::default()
                .hash_password_with_salt(b"synthetic-pw", b"synthetic-salt-16")
                .expect("the hash")
                .to_string(),
        )
    };
    let store = PasswordStore::new()
        .with_user("clinician", hash())?
        .with_scope("clinician", "user/*.rs")?
        .with_user("machine", hash())?
        .with_scope("machine", "user/*.rs")?;
    assert_eq!(
        Err(PartyError::BasicUnmapped {
            user: String::from("machine")
        }),
        mapped.check_basic(&store)
    );
    Ok(())
}

// NOTE: no specification governs the binding: our own design; the Debug of an outcome
// carries no key value, no group and no represented subject.
#[tokio::test]
async fn no_debug_rendering_carries_the_key_a_group_or_a_represented_subject() -> Outcome2 {
    let source = FakeSource::answering(Lookup::Parties(vec![
        record("p-1", Markers::BOTH)
            .with_memberships(vec![Membership::new(group_ref("g-hidden"), "group-1")])
            .with_represents(vec![Represented::new(person_ref("subject-hidden"))]),
    ]));
    let outcome = binding(&source)
        .resolve(&person(&json!({ "groups": ["group-1"] })))
        .await?
        .ok_or("looked up")?;
    let text = format!("{outcome:?}");
    for (position, hidden) in [LOGIN, "g-hidden", "subject-hidden", "group-1"]
        .iter()
        .enumerate()
    {
        assert!(
            !text.contains(hidden),
            "value {position} reaches the Debug rendering"
        );
    }
    Ok(())
}
