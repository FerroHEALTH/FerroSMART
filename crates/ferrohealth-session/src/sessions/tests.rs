// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

use std::time::Duration;

use ferrohealth_secret::secret::Secret;
use ferrohealth_smart::oidc::{PendingSignIn, TokenTypeHint};
use http::header::COOKIE;
use http::{HeaderMap, HeaderValue};

use super::{SessionError, Sessions};
use crate::clock::ManualClock;
use crate::config::SessionSection;
use crate::cookies::CookieNames;
use crate::justification::{Justified, MAX_JUSTIFICATIONS};
use crate::record::{Credential, Held, SignedIn};
use crate::return_path::ReturnPath;

const START: i64 = 1_800_000_000;

fn section() -> SessionSection {
    SessionSection {
        sign_in_timeout: ferrohealth_config::units::Duration::from_secs(60),
        max_sign_ins: 4,
        idle_timeout: ferrohealth_config::units::Duration::from_secs(60),
        absolute_timeout: ferrohealth_config::units::Duration::from_mins(10),
        max_sessions: 2,
        ..SessionSection::default()
    }
}

fn store() -> (Sessions, ManualClock) {
    store_of(&section())
}

fn store_of(section: &SessionSection) -> (Sessions, ManualClock) {
    let now = ManualClock::new(START);
    let settings = section.check().expect("a valid section");
    (
        Sessions::with_clock(
            settings,
            CookieNames::for_console("synthetic_console"),
            now.clock(),
        ),
        now,
    )
}

fn signed_in() -> SignedIn {
    SignedIn {
        operator: Some(String::from("Synthetic Operator")),
        subject: Some(String::from("synthetic-subject")),
        scopes: vec![String::from("openid"), String::from("profile")],
        credential: Credential::Bearer(Secret::new("synthetic-access-token")),
        expires_in: None,
        refresh_token: None,
        id_token: Some(Secret::new("synthetic-id-token")),
    }
}

/// The request `Cookie` header that sends back what `set` set.
fn sent(set: &HeaderValue) -> HeaderMap {
    let pair = set
        .to_str()
        .expect("ASCII")
        .split(';')
        .next()
        .expect("a pair")
        .to_owned();
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, pair.parse().expect("a header"));
    headers
}

fn is_removal(cookies: &[HeaderValue]) -> bool {
    cookies
        .iter()
        .any(|cookie| cookie.to_str().is_ok_and(|text| text.contains("Max-Age=0")))
}

#[test]
fn a_pending_sign_in_is_taken_once_with_its_return_path() {
    let (sessions, _now) = store();
    let pending = PendingSignIn::mint().expect("minted");
    let state = pending.state().to_owned();
    let back = ReturnPath::parse("/sources?page=2", "/sign-in");
    let cookie = sessions.begin(pending, back).expect("begun");
    assert!(cookie.to_str().expect("ASCII").contains("Max-Age=60"));
    let taken = sessions.take_pending(&sent(&cookie)).expect("usable");
    assert!(is_removal(&taken.cookies), "the sign-in cookie is removed");
    let pending = taken.value.expect("pending");
    assert_eq!(state, pending.sign_in.state());
    assert_eq!(
        Some("/sources?page=2"),
        pending.back.as_ref().map(ReturnPath::as_str)
    );
    let again = sessions.take_pending(&sent(&cookie)).expect("usable");
    assert!(again.value.is_none(), "a memory sign-in is taken once");
}

#[test]
fn an_expired_sign_in_is_refused() {
    let (sessions, now) = store();
    let cookie = sessions
        .begin(PendingSignIn::mint().expect("minted"), None)
        .expect("begun");
    now.advance(60);
    let taken = sessions.take_pending(&sent(&cookie)).expect("usable");
    assert!(taken.value.is_none());
}

/// Reads the session `cookie` names every 50 s, `reads` times.
fn active(sessions: &Sessions, now: &ManualClock, cookie: HeaderValue, reads: u32) -> HeaderValue {
    for _ in 0..reads {
        now.advance(50);
        sessions.held(&sent(&cookie)).expect("usable");
    }
    cookie
}

/// The last millisecond of the second `START`, where a clock counted in
/// whole seconds lies the furthest behind the time.
const LATE: i64 = START * 1000 + 999;

/// A sign-in with a 1 s timeout begun at `LATE`, with its cookie.
fn late_sign_in() -> (Sessions, ManualClock, HeaderValue) {
    let (sessions, now) = store_of(&SessionSection {
        sign_in_timeout: ferrohealth_config::units::Duration::from_secs(1),
        ..section()
    });
    now.set_millis(LATE);
    let cookie = sessions
        .begin(PendingSignIn::mint().expect("minted"), None)
        .expect("begun");
    (sessions, now, cookie)
}

/// A session of `signed_in` established at `LATE`, with its cookie.
fn late_session(signed_in: SignedIn) -> (Sessions, ManualClock, HeaderValue) {
    let (sessions, now) = store();
    now.set_millis(LATE);
    let cookie = sessions
        .establish(&HeaderMap::new(), signed_in)
        .expect("room");
    (sessions, now, cookie)
}

#[test]
fn a_sign_in_begun_late_in_a_second_lasts_its_whole_timeout() {
    let (sessions, now, cookie) = late_sign_in();
    now.advance_millis(999);
    let taken = sessions.take_pending(&sent(&cookie)).expect("usable");
    assert!(taken.value.is_some(), "999 ms into a 1 s sign-in timeout");
}

#[test]
fn a_sign_in_begun_late_in_a_second_ends_within_a_second_of_its_timeout() {
    let (sessions, now, cookie) = late_sign_in();
    now.advance_millis(2000);
    let taken = sessions.take_pending(&sent(&cookie)).expect("usable");
    assert!(taken.value.is_none(), "2 s into a 1 s timeout");
}

#[test]
fn an_idle_lifetime_begun_late_in_a_second_lasts_its_whole_length() {
    let (sessions, now, cookie) = late_session(signed_in());
    now.advance_millis(59_999);
    let left = sessions.left(&sent(&cookie), false).expect("usable").value;
    assert_eq!(
        Some(1),
        left.map(|left| left.idle),
        "59.999 s into a 60 s idle lifetime, rounded up"
    );
}

#[test]
fn an_idle_lifetime_begun_late_in_a_second_ends_within_a_second_of_its_length() {
    let (sessions, now, cookie) = late_session(signed_in());
    now.advance_millis(61_000);
    let held = sessions.held(&sent(&cookie)).expect("usable").value;
    assert!(matches!(held, Held::Ended), "{held:?}");
}

#[test]
fn an_absolute_lifetime_begun_late_in_a_second_lasts_its_whole_length() {
    let (sessions, now, cookie) = late_session(signed_in());
    let cookie = active(&sessions, &now, cookie, 11);
    now.advance_millis(49_999);
    let held = sessions.held(&sent(&cookie)).expect("usable").value;
    assert!(
        matches!(held, Held::SignedIn(_)),
        "599.999 s into a 600 s absolute lifetime: {held:?}"
    );
}

#[test]
fn a_memory_access_token_begun_late_in_a_second_lasts_its_whole_lifetime() {
    let (sessions, now, cookie) = late_session(SignedIn {
        expires_in: Some(Duration::from_secs(30)),
        ..signed_in()
    });
    now.advance_millis(29_999);
    let held = sessions.held(&sent(&cookie)).expect("usable").value;
    assert!(
        matches!(held, Held::SignedIn(_)),
        "29.999 s into a 30 s access token: {held:?}"
    );
}

#[test]
fn a_session_carries_the_sign_in_time_and_what_the_sign_in_left() {
    let (sessions, _now) = store();
    let cookie = sessions
        .establish(&HeaderMap::new(), signed_in())
        .expect("room");
    let held = sessions.held(&sent(&cookie)).expect("usable").value;
    let Held::SignedIn(session) = held else {
        panic!("{held:?}");
    };
    assert_eq!(START, session.signed_in_at(), "the sign-in time");
    assert_eq!(Some("Synthetic Operator"), session.operator());
    assert_eq!(Some("synthetic-subject"), session.subject());
    assert_eq!(2, session.scopes().len(), "the granted scopes");
    assert_eq!(
        &Credential::Bearer(Secret::new("synthetic-access-token")),
        session.credential(),
        "the access token"
    );
    assert_eq!((60, 600), (session.left().idle, session.left().absolute));
}

#[test]
fn the_idle_lifetime_ends_a_session_and_activity_moves_it() {
    let (sessions, now) = store();
    let cookie = sessions
        .establish(&HeaderMap::new(), signed_in())
        .expect("room");
    now.advance(50);
    let held = sessions.held(&sent(&cookie)).expect("usable");
    assert!(matches!(held.value, Held::SignedIn(_)));
    assert!(held.cookies.is_empty(), "a live read sets no cookie");
    now.advance(50);
    assert!(
        matches!(
            sessions.held(&sent(&cookie)).expect("usable").value,
            Held::SignedIn(_)
        ),
        "the read at 50 s started the idle lifetime again"
    );
    now.advance(60);
    let held = sessions.held(&sent(&cookie)).expect("usable");
    assert!(matches!(held.value, Held::Ended), "sixty idle seconds");
    assert!(
        is_removal(&held.cookies),
        "an ended session's cookie is removed"
    );
}

#[test]
fn the_absolute_lifetime_ends_a_session_whatever_the_activity() {
    let (sessions, now) = store();
    let cookie = sessions
        .establish(&HeaderMap::new(), signed_in())
        .expect("room");
    let cookie = active(&sessions, &now, cookie, 12);
    let held = sessions.held(&sent(&cookie)).expect("usable").value;
    assert!(
        matches!(held, Held::Ended),
        "600 s from the sign-in: {held:?}"
    );
}

#[test]
fn a_watch_read_never_counts_as_activity_and_an_extension_does() {
    let (sessions, now) = store();
    let cookie = sessions
        .establish(&HeaderMap::new(), signed_in())
        .expect("room");
    now.advance(30);
    let read = sessions.left(&sent(&cookie), false).expect("usable");
    assert!(read.cookies.is_empty(), "a read sets nothing");
    let read = read.value.expect("live");
    assert_eq!((30, 570), (read.idle, read.absolute));
    let again = sessions
        .left(&sent(&cookie), false)
        .expect("usable")
        .value
        .expect("live");
    assert_eq!(read, again, "the read moved nothing");
    let extended = sessions.left(&sent(&cookie), true).expect("usable");
    assert_eq!((60, 570), {
        let left = extended.value.expect("live");
        (left.idle, left.absolute)
    });
    assert!(extended.cookies.is_empty(), "an extension sets no cookie");
}

#[test]
fn an_ended_session_hands_back_its_hint_and_its_revocable_token() {
    let (sessions, _now) = store();
    let cookie = sessions
        .establish(&HeaderMap::new(), signed_in())
        .expect("room");
    let ended = sessions.end(&sent(&cookie)).expect("usable");
    assert!(is_removal(&ended.cookies), "the cookie is removed");
    let ended = ended.value.expect("held");
    assert_eq!(
        Some("synthetic-id-token"),
        ended.id_token.as_ref().map(Secret::expose)
    );
    let (token, hint) = ended.revocable.expect("a bearer session");
    assert_eq!(
        ("synthetic-access-token", TokenTypeHint::AccessToken),
        (token.expose(), hint)
    );
    assert!(
        matches!(
            sessions.held(&sent(&cookie)).expect("usable").value,
            Held::Ended
        ),
        "an ended memory session is gone"
    );
}

#[test]
fn a_basic_sign_in_carries_its_password_and_nothing_to_revoke() {
    let (sessions, _now) = store();
    let signed_in = SignedIn::basic("synthetic-user", Secret::new("synthetic-password"));
    let cookie = sessions
        .establish(&HeaderMap::new(), signed_in)
        .expect("room");
    let Held::SignedIn(session) = sessions.held(&sent(&cookie)).expect("usable").value else {
        panic!("live");
    };
    assert!(
        matches!(session.credential(), Credential::Basic { username, password }
            if username == "synthetic-user" && password.expose() == "synthetic-password")
    );
    let ended = sessions
        .end(&sent(&cookie))
        .expect("usable")
        .value
        .expect("held");
    assert!(ended.revocable.is_none(), "nothing to revoke");
}

#[test]
fn an_access_token_no_refresh_token_replaces_ends_the_session() {
    let (sessions, now) = store();
    let cookie = sessions
        .establish(
            &HeaderMap::new(),
            SignedIn {
                expires_in: Some(Duration::from_secs(30)),
                ..signed_in()
            },
        )
        .expect("room");
    let left = sessions
        .left(&sent(&cookie), false)
        .expect("usable")
        .value
        .expect("live");
    assert_eq!((30, 30), (left.idle, left.absolute));
    now.advance(30);
    assert!(matches!(
        sessions.held(&sent(&cookie)).expect("usable").value,
        Held::Ended
    ));
}

#[test]
fn a_memory_session_with_a_refresh_token_outlives_its_access_token() {
    let (sessions, now) = store();
    let cookie = sessions
        .establish(
            &HeaderMap::new(),
            SignedIn {
                expires_in: Some(Duration::from_secs(30)),
                refresh_token: Some(Secret::new("synthetic-refresh-token")),
                ..signed_in()
            },
        )
        .expect("room");
    now.advance(30);
    assert!(
        matches!(
            sessions.held(&sent(&cookie)).expect("usable").value,
            Held::TokenExpired
        ),
        "live, waiting for its refresh"
    );
}

#[test]
fn a_full_sign_in_pool_drops_its_oldest_and_never_touches_the_sessions() {
    let (sessions, _now) = store();
    let session = sessions
        .establish(&HeaderMap::new(), signed_in())
        .expect("room");
    let first = sessions
        .begin(PendingSignIn::mint().expect("minted"), None)
        .expect("begun");
    let mut last = first.clone();
    for _ in 0..100 {
        last = sessions
            .begin(PendingSignIn::mint().expect("minted"), None)
            .expect("begun");
    }
    let occupancy = sessions.occupancy().expect("usable");
    assert_eq!(
        (4, 1),
        (occupancy.sign_ins, occupancy.sessions),
        "the bound holds"
    );
    assert!(
        sessions
            .take_pending(&sent(&first))
            .expect("usable")
            .value
            .is_none(),
        "dropped"
    );
    assert!(
        sessions
            .take_pending(&sent(&last))
            .expect("usable")
            .value
            .is_some(),
        "kept"
    );
    assert!(matches!(
        sessions.held(&sent(&session)).expect("usable").value,
        Held::SignedIn(_)
    ));
}

#[test]
fn a_full_session_pool_refuses_a_new_session_and_keeps_the_live_ones() {
    let (sessions, _now) = store();
    let first = sessions
        .establish(&HeaderMap::new(), signed_in())
        .expect("room");
    let second = sessions
        .establish(&HeaderMap::new(), signed_in())
        .expect("room");
    let refused = sessions.establish(&HeaderMap::new(), signed_in());
    assert!(matches!(refused, Err(SessionError::Full)), "{refused:?}");
    for kept in [first, second] {
        assert!(matches!(
            sessions.held(&sent(&kept)).expect("usable").value,
            Held::SignedIn(_)
        ));
    }
}

#[test]
fn signing_in_again_ends_the_session_the_browser_held() {
    let (sessions, _now) = store();
    let first = sessions
        .establish(&HeaderMap::new(), signed_in())
        .expect("room");
    let second = sessions
        .establish(&sent(&first), signed_in())
        .expect("room");
    let third = sessions.establish(&sent(&second), signed_in());
    assert!(third.is_ok(), "the pool of two never fills: {third:?}");
    assert!(matches!(
        sessions.held(&sent(&first)).expect("usable").value,
        Held::Ended
    ));
}

#[test]
fn a_poisoned_memory_store_answers_poisoned_everywhere() {
    let (sessions, _now) = store();
    let cookie = sessions
        .establish(&HeaderMap::new(), signed_in())
        .expect("room");
    sessions.memory().poison();
    assert!(matches!(
        sessions.held(&sent(&cookie)),
        Err(SessionError::Poisoned)
    ));
    assert!(matches!(
        sessions.begin(PendingSignIn::mint().expect("minted"), None),
        Err(SessionError::Poisoned)
    ));
    assert!(matches!(
        sessions.end(&sent(&cookie)),
        Err(SessionError::Poisoned)
    ));
}

#[test]
fn no_token_password_or_id_reaches_a_debug_rendering() {
    let (sessions, _now) = store();
    let cookie = sessions
        .establish(
            &HeaderMap::new(),
            SignedIn {
                refresh_token: Some(Secret::new("synthetic-refresh-token")),
                ..signed_in()
            },
        )
        .expect("room");
    let held = sessions.held(&sent(&cookie)).expect("usable");
    let ended = sessions.end(&sent(&cookie)).expect("usable");
    let id = sent(&cookie)
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|pair| pair.split_once('='))
        .map(|(_, id)| id.to_owned())
        .expect("an id");
    let shown = format!(
        "{sessions:?} {:?} {:?} {:?}",
        held.value,
        ended.value,
        signed_in()
    );
    for secret in [
        "synthetic-access-token",
        "synthetic-id-token",
        "synthetic-refresh-token",
        &id,
    ] {
        assert!(!shown.contains(secret), "{shown}");
    }
    let basic = SignedIn::basic("synthetic-user", Secret::new("synthetic-password"));
    assert!(
        !format!("{basic:?}").contains("synthetic-password"),
        "the password"
    );
}

#[test]
fn a_session_preference_carries_no_max_age_and_reads_back() {
    let (sessions, _now) = store();
    let cookie = sessions
        .session_preference("sidebar", "rail")
        .expect("a cookie");
    let text = cookie.to_str().expect("text");
    assert_eq!(
        "__Host-synthetic_console_sidebar=rail; HttpOnly; SameSite=Lax; Secure; Path=/", text,
        "no Max-Age, so the browser drops it with its session"
    );
    assert!(!text.contains("Expires"));
    let kept = sessions
        .preference("sidebar", "rail", Duration::from_secs(60))
        .expect("a cookie");
    assert!(
        kept.to_str().expect("text").ends_with("; Max-Age=60"),
        "the kept form keeps its Max-Age"
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        HeaderValue::from_static("__Host-synthetic_console_sidebar=rail"),
    );
    assert_eq!(
        Some(String::from("rail")),
        sessions.preference_in(&headers, "sidebar")
    );
}

/// A store with one signed-in session, and the headers that
/// carry it.
fn justified_store() -> (Sessions, ManualClock, HeaderMap) {
    let (sessions, now) = store();
    let cookie = sessions
        .establish(&HeaderMap::new(), signed_in())
        .expect("established");
    (sessions, now, sent(&cookie))
}

/// States a justification of `purpose` for `object` for `lifetime`.
fn justify(
    sessions: &Sessions,
    headers: &HeaderMap,
    object: &str,
    purpose: &str,
    lifetime: Duration,
) -> Justified {
    sessions
        .justify(
            headers,
            object,
            purpose,
            Secret::new("synthetic reason"),
            lifetime,
        )
        .expect("usable")
}

/// Whether the session `headers` carry holds a justification for `object`.
fn holds(sessions: &Sessions, headers: &HeaderMap, object: &str) -> bool {
    sessions
        .justification(headers, object)
        .expect("usable")
        .is_some()
}

#[test]
fn a_justification_is_kept_for_its_object_until_it_ends() {
    let (sessions, now, headers) = justified_store();
    let kept = justify(
        &sessions,
        &headers,
        "ehr-1",
        "TREAT",
        Duration::from_secs(45),
    );
    assert_eq!(kept, Justified::Kept(START + 45));
    let held = sessions
        .justification(&headers, "ehr-1")
        .expect("usable")
        .expect("kept");
    assert_eq!(held.purpose(), "TREAT");
    assert_eq!(held.reason().expose(), "synthetic reason");
    assert_eq!(held.ends_at(), START + 45);
    assert!(
        !format!("{held:?}").contains("synthetic reason"),
        "the reason never reaches a Debug rendering"
    );
    assert!(
        !holds(&sessions, &headers, "ehr-2"),
        "a justification covers its one object"
    );
    now.advance(45);
    assert!(
        !holds(&sessions, &headers, "ehr-1"),
        "a justification ends at its end time"
    );
}

#[test]
fn a_justification_ends_on_request_and_with_its_session() {
    let (sessions, _now, headers) = justified_store();
    let minute = Duration::from_mins(1);
    justify(&sessions, &headers, "ehr-1", "ETREAT", minute);
    sessions
        .end_justification(&headers, "ehr-1")
        .expect("usable");
    assert!(!holds(&sessions, &headers, "ehr-1"));
    justify(&sessions, &headers, "ehr-2", "ETREAT", minute);
    sessions.end(&headers).expect("ended");
    assert!(
        !holds(&sessions, &headers, "ehr-2"),
        "a justification ends with its session"
    );
}

#[test]
fn a_session_keeps_a_bounded_number_of_justifications() {
    let (sessions, _now, headers) = justified_store();
    for (index, lifetime) in (0..=MAX_JUSTIFICATIONS).zip(1_u64..) {
        let object = format!("object-{index}");
        justify(
            &sessions,
            &headers,
            &object,
            "TREAT",
            Duration::from_mins(lifetime),
        );
    }
    assert!(
        !holds(&sessions, &headers, "object-0"),
        "the one that ends first is dropped"
    );
    assert!(holds(
        &sessions,
        &headers,
        &format!("object-{MAX_JUSTIFICATIONS}")
    ));
}
