// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Withdrawing an organisation approval the configuration no longer gives
//! (`docs/architecture.md` §13.6 item 6).
//!
//! An administrator gives and clears a client's approval in its
//! `[[ferrosmart.client]]` table. At every start, before the clients are
//! registered, an approval stored in PostgreSQL that the configuration no
//! longer gives in the same form is withdrawn: every grant issued on it is
//! revoked with its tokens, as withdrawing a remembered consent revokes
//! the grants it covered, and the withdrawal commits with its record. A
//! changed scope set, approver or time is a new approval. No specification
//! governs this: our own design.

use std::net::IpAddr;

use url::Url;

use crate::audit::{self, Audit, RecordFailure};
use crate::clients::{Approval, Client};
use crate::store::Store;

/// Where a withdrawal is recorded as made: the host FerroSMART runs on,
/// since the configuration changed there, and its issuer.
#[derive(Debug, Clone, Copy)]
pub struct Origin<'a> {
    /// FerroSMART's issuer.
    pub issuer: &'a str,
    /// The issuer as a URL, the endpoint the record names.
    pub endpoint: &'a Url,
    /// The address FerroSMART listens on.
    pub host: IpAddr,
}

/// Withdraws each approval `store` holds that `clients` no longer give,
/// and returns the client ids whose approval was withdrawn.
///
/// # Errors
/// Returns [`RecordFailure`] when the approvals cannot be read or a
/// withdrawal cannot be committed with its record; that withdrawal is then
/// not made.
pub async fn withdraw_lapsed(
    store: &Store,
    lane: &Audit,
    clients: &[Client],
    origin: Origin<'_>,
) -> Result<Vec<String>, RecordFailure> {
    let stored = store.approvals().await.map_err(RecordFailure::Store)?;
    let mut withdrawn = Vec::new();
    for (client_id, approval) in stored {
        let given = clients
            .iter()
            .find(|client| client.client_id == client_id)
            .and_then(Client::approval);
        if given == Some(&approval) {
            continue;
        }
        let mut tx = store.begin().await.map_err(RecordFailure::Store)?;
        let revoked = tx
            .withdraw_approval(&client_id, approval.approved_at)
            .await
            .map_err(RecordFailure::Store)?;
        lane.commit_happening(
            tx,
            &audit::Happening {
                event: audit::Event::ApprovalWithdrawn,
                issuer: origin.issuer,
                client_id: Some(&client_id),
                subject: None,
                from: origin.host,
                endpoint: origin.endpoint,
                details: withdrawn_details(&approval, revoked),
            },
        )
        .await?;
        tracing::info!(
            target: "ferrosmart::audit",
            event = "organisation_approval.withdrawn",
            client_id = %client_id,
            revoked,
            "an organisation approval was withdrawn"
        );
        withdrawn.push(client_id);
    }
    Ok(withdrawn)
}

/// What the record of a withdrawn `approval` holds: its scopes, approver,
/// time and mark, and the `revoked` grants issued on it.
#[must_use]
pub fn withdrawn_details(approval: &Approval, revoked: u64) -> Vec<(&'static str, String)> {
    vec![
        ("scope", approval.scopes.join(" ")),
        ("approved_by", approval.approved_by.clone()),
        ("approved_at", approval.approved_at.to_string()),
        ("first_party", approval.first_party.to_string()),
        ("revoked", revoked.to_string()),
    ]
}
