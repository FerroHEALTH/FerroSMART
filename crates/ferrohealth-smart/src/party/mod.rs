// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The party a person's login belongs to: one lookup through a source the
//! product supplies, with one match rule, one duplicate rule and one
//! stable-claim rule, and one typed [`Outcome`].
//!
//! A user other than a `Patient` of an issuer that has an
//! `[auth.issuer.<name>.party]` table ([`PartySection`]) is looked up by the
//! token's `sub` (OpenID Connect Core 1.0 §5.7), put in the canonical form
//! its `identifier_type` declares, against the identifiers of the table's
//! `identifier_issuer` in the product's [`PartySource`]. A Basic user is
//! looked up by the key the product maps it to, through the same path. A
//! `RelatedPerson` is looked up by their own login, never by the patient
//! they represent. `Patient`, `System`, `ExternalPerson` and
//! `ExternalOrganisation` callers are never looked up: a `federation`
//! token's `sub` names a user in another issuer's namespace.
//!
//! The library calls the source on every request and holds no cache. Two
//! parties carrying one login are [`Outcome::Ambiguous`], never resolved to
//! either, and a failing source is a [`SourceError`], never an
//! [`Outcome::Unbound`]. What each outcome means is the product's to decide.
//! No specification governs resolving a login to a party: our own design.
//!
//! [`PartySection`]: config::PartySection
//! [`PartySource`]: source::PartySource
//! [`SourceError`]: source::SourceError

use std::fmt;

pub mod binding;
pub mod config;
pub mod source;

/// A reference to a party in the product's store: its namespace, its type
/// and its identifier, the parts of an openEHR `PARTY_REF`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PartyRef {
    /// The namespace the identifier is unique in.
    namespace: String,
    /// The party's type, such as `PERSON` or `GROUP`.
    type_name: String,
    /// The identifier.
    id: String,
}

impl PartyRef {
    /// Returns the reference to the party `id` of `type_name` in
    /// `namespace`.
    #[must_use]
    pub fn new(
        namespace: impl Into<String>,
        type_name: impl Into<String>,
        id: impl Into<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            type_name: type_name.into(),
            id: id.into(),
        }
    }

    /// Returns the namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Returns the party's type.
    #[must_use]
    pub fn type_name(&self) -> &str {
        &self.type_name
    }

    /// Returns the identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl fmt::Display for PartyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.namespace, self.type_name, self.id)
    }
}

/// A binding marker: what a party is bound for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    /// The party is a professional, which a `Person` or `Delegated` caller
    /// needs.
    Professional,
    /// The party represents another, which a `Representative` caller
    /// needs.
    Representative,
}

impl Marker {
    /// Returns the name the audit line and the product's records use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Professional => "professional",
            Self::Representative => "representative",
        }
    }
}

/// The binding markers the source reports for a party: one, both or none.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Markers {
    /// The party is a professional.
    pub professional: bool,
    /// The party represents another.
    pub representative: bool,
}

impl Markers {
    /// A professional only.
    pub const PROFESSIONAL: Self = Self {
        professional: true,
        representative: false,
    };
    /// A representative only.
    pub const REPRESENTATIVE: Self = Self {
        professional: false,
        representative: true,
    };
    /// Both a professional and a representative.
    pub const BOTH: Self = Self {
        professional: true,
        representative: true,
    };

    /// Returns whether the markers carry `marker`.
    #[must_use]
    pub const fn carry(self, marker: Marker) -> bool {
        match marker {
            Marker::Professional => self.professional,
            Marker::Representative => self.representative,
        }
    }
}

/// The state the source reports a party in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PartyState {
    /// The party is usable.
    Active,
    /// The party is usable and its record is incomplete, such as one
    /// created at a first login; the outcome marks it provisional.
    Incomplete,
    /// The party is not usable: inactive (openEHR `800|inactive|`, as the
    /// product reports it; openEHR RM Common, Change Control Package,
    /// §Abandoned and Inactive States, `rm-common master06`).
    Inactive,
    /// The party is not usable: abandoned (openEHR `801|abandoned|`, as the
    /// product reports it; openEHR RM Common, Change Control Package,
    /// §Abandoned and Inactive States, `rm-common master06`).
    Abandoned,
}

/// The identifier a login matched: the configured issuer and type, and the
/// key value in its canonical form.
///
/// The `Debug` rendering leaves out the value.
#[derive(Clone, PartialEq, Eq)]
pub struct Identifier {
    /// The `identifier_issuer` of the `[auth.issuer.<name>.party]` table.
    issuer: String,
    /// The `identifier_type` of the table.
    kind: String,
    /// The key value, canonical.
    value: String,
}

impl Identifier {
    /// Returns the identifier `value` of `identifier_type` under `issuer`.
    pub(crate) const fn new(issuer: String, kind: String, value: String) -> Self {
        Self {
            issuer,
            kind,
            value,
        }
    }

    /// Returns the issuer of the identifier.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns the type of the identifier.
    #[must_use]
    pub fn identifier_type(&self) -> &str {
        &self.kind
    }

    /// Returns the key value in its canonical form.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identifier")
            .field("issuer", &self.issuer)
            .field("identifier_type", &self.kind)
            .finish_non_exhaustive()
    }
}

/// A subject a representative has a recorded representation relationship
/// to, as the source reports it.
///
/// The `Debug` rendering names neither the subject nor the relationship.
#[derive(Clone, PartialEq, Eq)]
pub struct Represented {
    /// The represented subject.
    subject: PartyRef,
    /// The coded type of the relationship, when the source records one.
    relationship: Option<String>,
}

impl Represented {
    /// Returns a relationship to `subject` with no coded type.
    #[must_use]
    pub const fn new(subject: PartyRef) -> Self {
        Self {
            subject,
            relationship: None,
        }
    }

    /// Returns this relationship of the coded type `relationship`.
    #[must_use]
    pub fn with_relationship(mut self, relationship: impl Into<String>) -> Self {
        self.relationship = Some(relationship.into());
        self
    }

    /// Returns the represented subject.
    #[must_use]
    pub const fn subject(&self) -> &PartyRef {
        &self.subject
    }

    /// Returns the coded type of the relationship.
    #[must_use]
    pub fn relationship(&self) -> Option<&str> {
        self.relationship.as_deref()
    }
}

impl fmt::Debug for Represented {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Represented").finish_non_exhaustive()
    }
}

/// A group a party belongs to, as the source reports it: the group and the
/// value of its identifier under the table's `group_identifier_issuer`,
/// which a token's group claim names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    /// The group.
    group: PartyRef,
    /// The group's identifier value.
    identifier: String,
}

impl Membership {
    /// Returns the membership of `group`, whose identifier is `identifier`.
    #[must_use]
    pub fn new(group: PartyRef, identifier: impl Into<String>) -> Self {
        Self {
            group,
            identifier: identifier.into(),
        }
    }

    /// Returns the group.
    #[must_use]
    pub const fn group(&self) -> &PartyRef {
        &self.group
    }

    /// Returns the group's identifier value.
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.identifier
    }
}

/// A party bound to a login.
///
/// The `Debug` rendering names the party and the markers, and never the
/// key value, a group or a represented subject.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Bound {
    /// The party.
    pub party: PartyRef,
    /// The identifier that matched.
    pub identifier: Identifier,
    /// The binding markers the source reports for the party.
    pub markers: Markers,
    /// The groups the token names that the party belongs to, in the
    /// source's order.
    pub groups: Vec<PartyRef>,
    /// The subjects the party has a recorded representation relationship
    /// to; whether one covers the request is the product's check.
    pub represents: Vec<Represented>,
    /// The party's record is incomplete ([`PartyState::Incomplete`]).
    pub provisional: bool,
}

impl fmt::Debug for Bound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bound")
            .field("party", &self.party)
            .field("markers", &self.markers)
            .field("provisional", &self.provisional)
            .finish_non_exhaustive()
    }
}

/// Why the groups a token asserts cannot be read.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum GroupsCause {
    /// The token carries a groups overage marker in place of the group
    /// claim.
    Overage,
    /// The group claim is not an array of strings.
    Malformed,
}

/// What a login resolves to.
///
/// Each outcome is the product's to answer; the library never picks one of
/// two matches. The `Debug` rendering carries no key value and no party
/// attribute.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Outcome {
    /// One party carries the login and has the marker the caller's kind
    /// needs.
    Party(Box<Bound>),
    /// One party carries the login and lacks the marker the caller's kind
    /// needs.
    WrongMarker {
        /// The party.
        party: PartyRef,
        /// The markers it carries.
        markers: Markers,
        /// The marker the caller's kind needs.
        needed: Marker,
    },
    /// No party carries the login.
    Unbound,
    /// Two or more parties carry the login.
    Ambiguous {
        /// How many.
        count: usize,
    },
    /// The one party carrying the login is inactive.
    Inactive {
        /// The party.
        party: PartyRef,
    },
    /// The one party carrying the login is abandoned.
    Abandoned {
        /// The party.
        party: PartyRef,
    },
    /// The login's key is the tombstone of a deleted party.
    Deprovisioned,
    /// The credential carries no key: the token lacks its profile's
    /// `person_key` claim, or the Basic user maps to no key.
    KeyClaimMissing,
    /// The groups the token asserts cannot be read.
    GroupsUnavailable(GroupsCause),
}

impl Outcome {
    /// Returns the name the audit line records.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Party(_) => "party",
            Self::WrongMarker { .. } => "wrong_marker",
            Self::Unbound => "unbound",
            Self::Ambiguous { .. } => "ambiguous",
            Self::Inactive { .. } => "inactive",
            Self::Abandoned { .. } => "abandoned",
            Self::Deprovisioned => "deprovisioned",
            Self::KeyClaimMissing => "key_claim_missing",
            Self::GroupsUnavailable(_) => "groups_unavailable",
        }
    }

    /// Returns the reason a product refuses the caller with when it
    /// refuses this outcome, or `None` for a bound party.
    ///
    /// The code is `refused-` and the outcome (`refused-unbound`,
    /// `refused-wrong-marker`), so the log and the challenge name the
    /// outcome the refusal rests on.
    #[must_use]
    pub const fn refusal_reason(&self) -> Option<crate::refusal::Reason> {
        let code = match self {
            Self::Party(_) => return None,
            Self::WrongMarker { .. } => "refused-wrong-marker",
            Self::Unbound => "refused-unbound",
            Self::Ambiguous { .. } => "refused-ambiguous",
            Self::Inactive { .. } => "refused-inactive",
            Self::Abandoned { .. } => "refused-abandoned",
            Self::Deprovisioned => "refused-deprovisioned",
            Self::KeyClaimMissing => "refused-key-claim-missing",
            Self::GroupsUnavailable(_) => "refused-groups-unavailable",
        };
        Some(crate::refusal::Reason::Party(code))
    }

    /// Returns the party the outcome names: the bound party, or the one
    /// refused for its marker or its state.
    #[must_use]
    pub fn party(&self) -> Option<&PartyRef> {
        match self {
            Self::Party(bound) => Some(&bound.party),
            Self::WrongMarker { party, .. }
            | Self::Inactive { party }
            | Self::Abandoned { party } => Some(party),
            _ => None,
        }
    }

    /// Returns the bound party, when one is.
    #[must_use]
    pub fn bound(&self) -> Option<&Bound> {
        match self {
            Self::Party(bound) => Some(bound),
            _ => None,
        }
    }
}
