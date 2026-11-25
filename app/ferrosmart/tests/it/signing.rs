// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The scheduled rotation of the token signing keys against a real
//! PostgreSQL, with the clock moved (`docs/architecture.md` §13.11).

use std::time::Duration;

use ferrosmart::config::error::Error;
use ferrosmart::signing::SigningKeys;
use ferrosmart::store::Store;
use serde_json::Value;

use crate::support::{Database, Keys, config, rsa_key};

/// The moment every case starts at, in seconds since the Unix epoch.
const START: i64 = 1_800_000_000;

/// Returns the configuration of a pool of `files` rotating every `period`.
fn pool(files: &[std::path::PathBuf], period: &str) -> String {
    let files: Vec<String> = files
        .iter()
        .map(|file| format!("{:?}", file.display().to_string()))
        .collect();
    format!(
        "[ferrosmart]\nissuer = \"https://smart.example.org\"\n[ferrosmart.keys]\n\
         private_key_files = [{}]\nrotation_period = {period:?}",
        files.join(", ")
    )
}

/// Returns the signing keys of a pool of three fresh keys under `keys`.
fn three(keys: &Keys) -> (SigningKeys, [String; 3]) {
    let files = [
        keys.current.clone(),
        rsa_key(keys.dir.path(), "second.pem"),
        rsa_key(keys.dir.path(), "third.pem"),
    ];
    let settings = config(&pool(&files, "30d"), keys)
        .resolve()
        .expect("resolves");
    let keys = std::sync::Arc::try_unwrap(settings.keys).expect("one owner");
    let kids: Vec<String> = keys.pool().map(|key| key.kid().to_owned()).collect();
    (keys, kids.try_into().expect("three keys"))
}

/// Returns the `kid`s of the JWK Set `published`, in order.
fn kids(published: &Value) -> Vec<String> {
    published["keys"]
        .as_array()
        .expect("a key list")
        .iter()
        .map(|key| key["kid"].as_str().expect("a kid").to_owned())
        .collect()
}

/// Returns the seconds of `span`.
fn seconds(span: Duration) -> i64 {
    i64::try_from(span.as_secs()).expect("in range")
}

#[tokio::test]
async fn the_keys_rotate_on_the_schedule_with_the_clock_moved() {
    let database = Database::create().await;
    let store = Store::connect(&database.url, 2).await.expect("connects");
    store.migrate().await.expect("migrates");
    let keys = Keys::new();
    let (signing, [first, second, third]) = three(&keys);
    let schedule = *signing.schedule();

    signing.refresh(&store, START).await.expect("refreshes");
    let ring = signing
        .ring(ferrohealth_smart::jws::algorithm::Algorithm::Rs256)
        .expect("the RS256 ring");
    assert_eq!(first, ring.current().kid(), "the first key signs at once");
    assert_eq!(
        vec![first.clone(), second.clone()],
        kids(&ring.published()),
        "the next key is published before it signs"
    );

    let before = START + seconds(schedule.period) - 1;
    signing.refresh(&store, before).await.expect("refreshes");
    assert_eq!(
        first,
        signing
            .ring(ferrohealth_smart::jws::algorithm::Algorithm::Rs256)
            .expect("the RS256 ring")
            .current()
            .kid(),
        "no rotation before the period"
    );

    let rotated = START + seconds(schedule.period);
    signing.refresh(&store, rotated).await.expect("refreshes");
    let ring = signing
        .ring(ferrohealth_smart::jws::algorithm::Algorithm::Rs256)
        .expect("the RS256 ring");
    assert_eq!(
        second,
        ring.current().kid(),
        "the next key signs after the period"
    );
    assert_eq!(
        vec![second.clone(), first.clone(), third.clone()],
        kids(&ring.published()),
        "the old key stays published beside the new next one"
    );
    let token = ring
        .current()
        .sign("at+jwt", &serde_json::json!({"sub": "alice"}));
    let header = jsonwebtoken::decode_header(token.expect("signs")).expect("a header");
    assert_eq!(Some(second.clone()), header.kid);

    let held = rotated + seconds(schedule.retirement) - 1;
    signing.refresh(&store, held).await.expect("refreshes");
    assert!(
        kids(
            &signing
                .ring(ferrohealth_smart::jws::algorithm::Algorithm::Rs256)
                .expect("the RS256 ring")
                .published()
        )
        .contains(&first),
        "published until every token it signed has expired"
    );
    signing
        .refresh(&store, rotated + seconds(schedule.retirement))
        .await
        .expect("refreshes");
    assert_eq!(
        vec![second, third],
        kids(
            &signing
                .ring(ferrohealth_smart::jws::algorithm::Algorithm::Rs256)
                .expect("the RS256 ring")
                .published()
        ),
        "the retired key is no longer published"
    );
    drop(signing);
    database.drop(store).await;
}

#[tokio::test]
async fn replicas_agree_on_the_signing_key_through_the_store() {
    let database = Database::create().await;
    let store = Store::connect(&database.url, 2).await.expect("connects");
    store.migrate().await.expect("migrates");
    let keys = Keys::new();
    let files = [
        rsa_key(keys.dir.path(), "a.pem"),
        rsa_key(keys.dir.path(), "b.pem"),
    ];
    let replica = |files: &[std::path::PathBuf]| {
        let settings = config(&pool(files, "30d"), &keys)
            .resolve()
            .expect("resolves");
        std::sync::Arc::try_unwrap(settings.keys).expect("one owner")
    };
    let first = replica(&files);
    let reversed = [files[1].clone(), files[0].clone()];
    let second = replica(&reversed);

    first.refresh(&store, START).await.expect("refreshes");
    second.refresh(&store, START + 10).await.expect("refreshes");
    assert_eq!(
        first
            .ring(ferrohealth_smart::jws::algorithm::Algorithm::Rs256)
            .expect("the RS256 ring")
            .current()
            .kid(),
        second
            .ring(ferrohealth_smart::jws::algorithm::Algorithm::Rs256)
            .expect("the RS256 ring")
            .current()
            .kid(),
        "the store's active key signs on both, whatever order each names the files in"
    );
    assert_eq!(
        first
            .ring(ferrohealth_smart::jws::algorithm::Algorithm::Rs256)
            .expect("the RS256 ring")
            .published(),
        second
            .ring(ferrohealth_smart::jws::algorithm::Algorithm::Rs256)
            .expect("the RS256 ring")
            .published()
    );

    let rotated = START + seconds(first.schedule().period);
    second.refresh(&store, rotated).await.expect("refreshes");
    first
        .refresh(&store, rotated + 30)
        .await
        .expect("refreshes");
    assert_eq!(
        first
            .ring(ferrohealth_smart::jws::algorithm::Algorithm::Rs256)
            .expect("the RS256 ring")
            .current()
            .kid(),
        second
            .ring(ferrohealth_smart::jws::algorithm::Algorithm::Rs256)
            .expect("the RS256 ring")
            .current()
            .kid()
    );
    assert_ne!(
        first.pool().next().expect("a key").kid(),
        first
            .ring(ferrohealth_smart::jws::algorithm::Algorithm::Rs256)
            .expect("the RS256 ring")
            .current()
            .kid(),
        "the rotation one replica made holds on the other"
    );
    drop((first, second));
    database.drop(store).await;
}

#[tokio::test]
async fn a_single_key_keeps_signing_past_its_period() {
    let database = Database::create().await;
    let store = Store::connect(&database.url, 2).await.expect("connects");
    store.migrate().await.expect("migrates");
    let keys = Keys::new();
    let settings = config(&pool(std::slice::from_ref(&keys.current), "30d"), &keys)
        .resolve()
        .expect("resolves");
    let signing = &settings.keys;
    signing.refresh(&store, START).await.expect("refreshes");
    let later = START + 10 * seconds(signing.schedule().period);
    signing.refresh(&store, later).await.expect("refreshes");
    assert_eq!(
        signing.pool().next().expect("a key").kid(),
        signing
            .ring(ferrohealth_smart::jws::algorithm::Algorithm::Rs256)
            .expect("the RS256 ring")
            .current()
            .kid()
    );
    assert_eq!(
        1,
        kids(
            &signing
                .ring(ferrohealth_smart::jws::algorithm::Algorithm::Rs256)
                .expect("the RS256 ring")
                .published()
        )
        .len()
    );
    drop(settings);
    database.drop(store).await;
}

#[test]
fn a_rotation_period_shorter_than_a_key_s_retirement_is_refused() {
    let keys = Keys::new();
    let text = pool(std::slice::from_ref(&keys.current), "1h");
    assert!(matches!(
        config(&text, &keys).resolve(),
        Err(Error::RotationPeriod { .. })
    ));
}
