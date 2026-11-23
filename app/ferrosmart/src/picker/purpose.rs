// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The purpose of use a professional's lookup at an openEHR resource server
//! declares (`docs/architecture.md` §13.6 item 4).
//!
//! An openEHR server such as FerroEHR decides a professional's request by
//! their roles and by the purpose of use the request declares in a header.
//! The person chooses one of the purposes the server's
//! `[[ferrosmart.resource]]` table lists on the picker page, the lookup and
//! the look-up-again of the choice send it in the table's header, and the
//! pending request keeps it in between, so the two declare the same one. A
//! patient's own lookup declares none. No specification governs a picker's
//! purpose: our own design.

use axum::response::Response;
use http::HeaderName;

use crate::config::settings::PurposeOfUse;
use crate::form::Params;
use crate::pages::{self, Fault};
use crate::server::AppState;
use crate::store::Pending;

/// The form field that carries the chosen purpose's code.
pub const FIELD: &str = "purpose_of_use";

/// A purpose a lookup declares, and the header its server reads it from.
#[derive(Debug, Clone, Copy)]
pub struct Declared<'a> {
    /// The header.
    pub header: &'a HeaderName,
    /// The purpose.
    pub purpose: &'a PurposeOfUse,
}

/// Returns the purpose the lookups of `pending` declare, as `form` chose
/// it, kept on the request from its first lookup on, with the request as
/// it then stands; `None` when the resource server lists no purposes.
///
/// One listed purpose needs no choice. A form that names no purpose while
/// several are listed, a code the server does not list, or a code other
/// than the one the request kept is refused.
///
/// # Errors
/// Returns the page that refuses the choice, or says the store failed.
pub(super) async fn declared<'s>(
    state: &'s AppState,
    pending: &Pending,
    form: &Params,
) -> Result<(Pending, Option<Declared<'s>>), Box<Response>> {
    let Some(purposes) = state.settings().purposes.get(&pending.audience) else {
        return Ok((pending.clone(), None));
    };
    let refuse = || Box::new(pages::fault(state, Fault::BadRequest));
    let sent = form.get(FIELD).filter(|code| !code.is_empty());
    let code = match (
        pending.purpose_of_use.as_deref(),
        sent,
        purposes.codes.as_slice(),
    ) {
        (Some(kept), Some(sent), _) if kept != sent => return Err(refuse()),
        (Some(kept), _, _) => kept,
        (None, Some(sent), _) => sent,
        (None, None, [only]) => only.code.as_str(),
        (None, None, _) => return Err(refuse()),
    };
    let purpose = purposes.get(code).ok_or_else(refuse)?;
    match state
        .store()
        .keep_purpose_of_use(&pending.id, &purpose.code)
        .await
    {
        Ok(true) => Ok((
            Pending {
                purpose_of_use: Some(purpose.code.clone()),
                ..pending.clone()
            },
            Some(Declared {
                header: &purposes.header,
                purpose,
            }),
        )),
        Ok(false) => Err(refuse()),
        Err(error) => Err(Box::new(pages::server_error(state, &error))),
    }
}

/// The person has yet to choose among the purposes a server lists.
#[derive(Debug, Clone, Copy)]
pub(super) struct Unchosen;

/// Returns the purpose a lookup of `pending` declares with no choice on a
/// form: none when the server lists none, else the one the request kept or
/// the only one listed.
///
/// # Errors
/// Returns [`Unchosen`] while the person has yet to choose one.
pub(super) fn kept<'s>(
    state: &'s AppState,
    pending: &Pending,
) -> Result<Option<Declared<'s>>, Unchosen> {
    let Some(purposes) = state.settings().purposes.get(&pending.audience) else {
        return Ok(None);
    };
    let code = match (pending.purpose_of_use.as_deref(), purposes.codes.as_slice()) {
        (Some(kept), _) => kept,
        (None, [only]) => only.code.as_str(),
        (None, _) => return Err(Unchosen),
    };
    let purpose = purposes.get(code).ok_or(Unchosen)?;
    Ok(Some(Declared {
        header: &purposes.header,
        purpose,
    }))
}
