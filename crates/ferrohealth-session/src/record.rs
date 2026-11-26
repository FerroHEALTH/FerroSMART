// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! What a session holds: what a completed sign-in leaves, and the view of
//! it one request reads.

use std::fmt;
use std::time::Duration;

use crate::lifetime::{millis, seconds_up};
use ferrohealth_secret::secret::Secret;
use ferrohealth_ui::view::session::Left;

/// How a session authenticates the console's calls to its own server.
#[derive(Clone, PartialEq, Eq)]
pub enum Credential {
    /// The operator's access token, sent as a bearer token (RFC 6750 §2.1).
    Bearer(Secret),
    /// A user name and password the console checked itself, sent with HTTP
    /// Basic (RFC 7617 §2).
    Basic {
        /// The user name.
        username: String,
        /// The password.
        password: Secret,
    },
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bearer(_) => f.write_str("Bearer(..)"),
            Self::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .finish_non_exhaustive(),
        }
    }
}

/// What a completed sign-in leaves the session.
pub struct SignedIn {
    pub(crate) operator: Option<String>,
    pub(crate) subject: Option<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) credential: Credential,
    pub(crate) expires_in: Option<Duration>,
    pub(crate) refresh_token: Option<Secret>,
    pub(crate) id_token: Option<Secret>,
}

impl fmt::Debug for SignedIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedIn")
            .field("operator", &self.operator)
            .field("subject", &self.subject)
            .field("scopes", &self.scopes)
            .field("credential", &self.credential)
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

impl SignedIn {
    /// What the relying party's completed sign-in leaves: the operator's
    /// name from the verified ID Token's `name` or `preferred_username`
    /// (OpenID Connect Core 1.0 §5.1), its `sub`, the granted scopes
    /// (RFC 6749 §5.1), the access token with its lifetime, the refresh
    /// token, and the ID Token a sign-out hints with (OpenID Connect
    /// RP-Initiated Logout 1.0 §2).
    #[must_use]
    pub fn from_oidc(signed_in: ferrohealth_smart::oidc::SignedIn) -> Self {
        Self {
            operator: signed_in.claims.display_name().map(str::to_owned),
            subject: Some(signed_in.claims.subject.clone()),
            scopes: signed_in.scopes,
            credential: Credential::Bearer(signed_in.access_token),
            expires_in: signed_in.expires_in,
            refresh_token: signed_in.refresh_token,
            id_token: Some(signed_in.id_token),
        }
    }

    /// A sign-in the console checked itself with `username` and `password`,
    /// which every call to its own server then carries.
    #[must_use]
    pub fn basic(username: impl Into<String>, password: Secret) -> Self {
        let username = username.into();
        Self {
            operator: Some(username.clone()),
            subject: None,
            scopes: Vec::new(),
            credential: Credential::Basic { username, password },
            expires_in: None,
            refresh_token: None,
            id_token: None,
        }
    }
}

/// One request's view of its live session.
#[derive(Clone)]
pub struct Session {
    pub(crate) operator: Option<String>,
    pub(crate) subject: Option<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) credential: Credential,
    pub(crate) signed_in_at: i64,
    pub(crate) left: Left,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("operator", &self.operator)
            .field("scopes", &self.scopes)
            .field("credential", &self.credential)
            .field("signed_in_at", &self.signed_in_at)
            .field("left", &self.left)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// The operator's name as the provider or the sign-in gave it.
    #[must_use]
    pub fn operator(&self) -> Option<&str> {
        self.operator.as_deref()
    }

    /// The `sub` of the verified ID Token, for an OpenID Connect sign-in.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    /// The scopes the provider granted, empty for a Basic sign-in.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// What the console's calls to its own server carry.
    #[must_use]
    pub const fn credential(&self) -> &Credential {
        &self.credential
    }

    /// When the operator signed in, in whole seconds since the Unix epoch,
    /// rounded up.
    #[must_use]
    pub const fn signed_in_at(&self) -> i64 {
        seconds_up(self.signed_in_at)
    }

    /// What the session has left as this request found it.
    #[must_use]
    pub const fn left(&self) -> Left {
        self.left
    }
}

/// What one request carries.
#[derive(Debug, Clone)]
pub enum Held {
    /// A live session.
    SignedIn(Session),
    /// A live session whose access token expired and could not yet be
    /// refreshed; the next request tries again, and its lifetimes still end
    /// it.
    TokenExpired,
    /// A cookie that names no live session.
    Ended,
    /// No session cookie.
    Absent,
}

/// What an ended session held that the provider is told about.
pub struct Ended {
    /// The ID Token of the sign-in, the hint of the end-session request.
    pub id_token: Option<Secret>,
    /// The token a revocation names, with its `token_type_hint`: the refresh
    /// token when the provider issued one, since revoking it ends its access
    /// tokens too (RFC 7009 §2.1), and the access token otherwise; `None`
    /// for a Basic sign-in.
    pub revocable: Option<(Secret, ferrohealth_smart::oidc::TokenTypeHint)>,
}

impl fmt::Debug for Ended {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ended")
            .field("hint", &self.revocable.as_ref().map(|(_, hint)| hint))
            .finish_non_exhaustive()
    }
}

/// The session record the store keeps, with its times in milliseconds since
/// the Unix epoch.
#[derive(Clone)]
pub(crate) struct Record {
    pub(crate) operator: Option<String>,
    pub(crate) subject: Option<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) credential: Credential,
    pub(crate) expires: Option<i64>,
    pub(crate) lifetime: Option<Duration>,
    pub(crate) refresh_token: Option<Secret>,
    pub(crate) id_token: Option<Secret>,
    pub(crate) signed_in: i64,
    pub(crate) touched: i64,
}

impl Record {
    /// The record a sign-in at `now` begins.
    pub(crate) fn begin(signed_in: SignedIn, now: i64) -> Self {
        let mut record = Self {
            operator: signed_in.operator,
            subject: signed_in.subject,
            scopes: signed_in.scopes,
            credential: signed_in.credential,
            expires: None,
            lifetime: None,
            refresh_token: signed_in.refresh_token,
            id_token: signed_in.id_token,
            signed_in: now,
            touched: now,
        };
        record.token_issued(signed_in.expires_in, now);
        record
    }

    /// Counts the access token's `lifetime` from `now`, when it was issued.
    pub(crate) fn token_issued(&mut self, lifetime: Option<Duration>, now: i64) {
        self.expires = lifetime.map(|lifetime| now.saturating_add(millis(lifetime)));
        self.lifetime = lifetime;
    }

    /// The times its lifetimes are counted from.
    pub(crate) fn times(&self) -> crate::lifetime::Times {
        crate::lifetime::Times {
            signed_in: self.signed_in,
            touched: self.touched,
            last_token: if self.refresh_token.is_some() {
                None
            } else {
                self.expires
            },
        }
    }

    /// Whether the access token is still valid at `now`.
    pub(crate) fn token_valid(&self, now: i64) -> bool {
        self.expires.is_none_or(|expires| now < expires)
    }

    /// The view a request reads, with `left`.
    pub(crate) fn session(&self, left: Left) -> Session {
        Session {
            operator: self.operator.clone(),
            subject: self.subject.clone(),
            scopes: self.scopes.clone(),
            credential: self.credential.clone(),
            signed_in_at: self.signed_in,
            left,
        }
    }

    /// What the provider is told when the record ends.
    pub(crate) fn ended(self) -> Ended {
        use ferrohealth_smart::oidc::TokenTypeHint;
        let revocable = match (self.refresh_token, self.credential) {
            (Some(refresh), _) => Some((refresh, TokenTypeHint::RefreshToken)),
            (None, Credential::Bearer(access)) => Some((access, TokenTypeHint::AccessToken)),
            (None, Credential::Basic { .. }) => None,
        };
        Ended {
            id_token: self.id_token,
            revocable,
        }
    }
}
