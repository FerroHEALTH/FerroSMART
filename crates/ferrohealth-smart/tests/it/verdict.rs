// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The held verdict of a verified token: kept until the token's `exp` and
//! no longer (RFC 7519 §4.1.4), dropped whole when the key set is read
//! again and has changed, bounded and reported, and never admitting a token
//! a fresh check would refuse.

use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;

use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrohealth_smart::refusal::Reason;
use ferrohealth_smart::resource::IssuerSet;
use ferrohealth_smart::resource::Rejection;
use ferrohealth_smart::resource::Verifier;

use crate::support::Issuer;
use crate::support::JWKS_PATH;
use crate::support::ec_key;
use crate::support::mint;
use crate::support::now;
use crate::support::server;

#[tokio::test]
async fn a_token_past_its_exp_is_refused_though_its_verdict_was_held()
-> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::Es256);
    let issuer = Issuer::start(&[&key]).await;
    let mut settings = issuer.settings();
    settings.clock_skew = Duration::ZERO;
    let server = server(settings).await;
    let mut claims = issuer.claims("user/Observation.rs");
    claims["exp"] = serde_json::json!(now() + 1);
    let token = mint(&key, &claims);
    server.authenticate(&token).await?;
    assert_eq!(1, server.cache_usage().entries, "the verdict is held");
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    let outcome = server.authenticate(&token).await;
    assert!(
        matches!(
            outcome,
            Err(Rejection::Invalid {
                reason: Reason::Expired
            })
        ),
        "{outcome:?}"
    );
    assert_eq!(0, server.cache_usage().entries, "dropped at its exp");
    Ok(())
}

#[tokio::test]
async fn a_withdrawn_key_refuses_its_held_token_and_drops_every_verdict()
-> Result<(), Box<dyn StdError>> {
    let kept = ec_key("kept", Algorithm::Es256);
    let withdrawn = ec_key("withdrawn", Algorithm::Es256);
    let issuer = Issuer::bare().await;
    issuer
        .mount_metadata("/.well-known/oauth-authorization-server")
        .await;
    issuer.mount_keys(&[&kept, &withdrawn], Some(3)).await;
    issuer.mount_keys(&[&kept], None).await;
    let mut settings = issuer.settings();
    settings.jwks_max_age = Duration::ZERO;
    settings.jwks_refresh_interval = Duration::from_secs(3600);
    let server = server(settings).await;
    let doomed = mint(&withdrawn, &issuer.claims("user/Observation.rs"));
    let still = mint(&kept, &issuer.claims("user/Observation.rs"));
    server.authenticate(&doomed).await?;
    server.authenticate(&still).await?;
    assert_eq!(2, server.cache_usage().entries, "both verdicts are held");
    let outcome = server.authenticate(&doomed).await;
    assert!(
        matches!(
            outcome,
            Err(Rejection::Invalid {
                reason: Reason::UnknownKey
            })
        ),
        "{outcome:?}"
    );
    assert_eq!(4, issuer.reads(JWKS_PATH).await, "the set was read again");
    assert_eq!(
        0,
        server.cache_usage().entries,
        "the changed set dropped every verdict"
    );
    server.authenticate(&still).await?;
    assert_eq!(1, server.cache_usage().entries, "verified again and held");
    Ok(())
}

#[tokio::test]
async fn the_verdicts_are_bounded_and_reported() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::Es256);
    let issuer = Issuer::start(&[&key]).await;
    let server = server(issuer.settings()).await;
    let empty = server.cache_usage();
    assert_eq!(10_000, empty.capacity);
    assert_eq!((0, 0), (empty.entries, empty.bytes));
    let token = mint(&key, &issuer.claims("user/Observation.rs"));
    for _ in 0..3 {
        server.authenticate(&token).await?;
    }
    let usage = server.cache_usage();
    assert_eq!(1, usage.entries, "one verdict per token");
    assert!(usage.bytes > 200, "the claims are counted: {usage:?}");
    Ok(())
}

#[tokio::test]
async fn an_issuer_set_answers_a_held_token_from_its_issuer() -> Result<(), Box<dyn StdError>> {
    let one_key = ec_key("one", Algorithm::Es256);
    let two_key = ec_key("two", Algorithm::Es256);
    let one = Issuer::start(&[&one_key]).await;
    let two = Issuer::start(&[&two_key]).await;
    let set = Arc::new(
        IssuerSet::new()
            .with(server(one.settings()).await)
            .with(server(two.settings()).await),
    );
    let token = mint(&two_key, &two.claims("user/Observation.rs"));
    let first = set.verify(&token).await?;
    let second = set.verify(&token).await?;
    assert_eq!(first, second, "the same caller both times");
    assert_eq!(Some(two.uri().as_str()), second.issuer());
    let usage = set.verdict_usage();
    assert_eq!(1, usage.entries, "held once, by its issuer");
    assert_eq!(20_000, usage.capacity);
    Ok(())
}
