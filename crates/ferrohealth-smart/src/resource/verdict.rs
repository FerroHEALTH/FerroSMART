// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The verdicts of verified access tokens, so a token's signature is
//! checked once and not on every request it is presented on.
//!
//! A verdict is what the check of a token's signature, header and claims
//! established: the claims, with the key that verified them. It is held
//! under the SHA-256 of the token, so no token is held in memory, until the
//! token's `exp` and never past it (RFC 7519 §4.1.4), and the whole map is
//! dropped when the issuer's key set is read again and has changed. The
//! steps that read the request or the product's standing (the sender
//! constraint, the classification) run on every request, a held verdict
//! included. The map is bounded in entries and in bytes. No specification
//! asks for the signature to be recomputed per request: our own design.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;

use crate::jws::algorithm::Algorithm;
use serde_json::Map;
use serde_json::Value;

use crate::usage::CacheUsage;

/// The most verdicts one resource server holds at once.
pub(super) const CAPACITY: usize = 10_000;

/// The most bytes, by [`weigh`]'s estimate, the verdicts of one resource
/// server take at once.
pub(super) const BYTE_CAPACITY: usize = 16 * 1024 * 1024;

/// What the check of one token established.
#[derive(Debug)]
pub(super) struct Verified {
    /// The token's claims.
    pub(super) claims: Map<String, Value>,
    /// The algorithm the token was signed with.
    pub(super) alg: Algorithm,
    /// The `kid` of the token's header.
    pub(super) kid: Option<String>,
    /// The generation of the key set that verified it.
    pub(super) generation: u64,
}

/// One held verdict.
#[derive(Debug)]
struct Entry {
    /// The token's `exp`, in seconds since the epoch.
    exp: i64,
    /// The verdict.
    verified: Arc<Verified>,
    /// An estimate of the bytes the entry takes.
    bytes: usize,
}

/// The verdicts and the key set generation they were reached under.
#[derive(Debug, Default)]
struct Held {
    /// The generation of the key set every held verdict was reached under.
    generation: u64,
    /// The verdicts, by the SHA-256 of the token.
    entries: BTreeMap<[u8; 32], Entry>,
    /// The sum of the entries' bytes.
    bytes: usize,
}

impl Held {
    /// Removes the verdict under `key`.
    fn remove(&mut self, key: &[u8; 32]) {
        if let Some(entry) = self.entries.remove(key) {
            self.bytes = self.bytes.saturating_sub(entry.bytes);
        }
    }
}

/// The verdicts of one resource server.
#[derive(Debug)]
pub(super) struct Verdicts {
    /// The most entries held at once.
    capacity: usize,
    /// The most bytes held at once.
    byte_capacity: usize,
    /// The verdicts.
    held: Mutex<Held>,
}

impl Verdicts {
    /// Returns an empty map holding at most `capacity` verdicts in at most
    /// `byte_capacity` bytes.
    pub(super) fn new(capacity: usize, byte_capacity: usize) -> Self {
        Self {
            capacity,
            byte_capacity,
            held: Mutex::new(Held::default()),
        }
    }

    /// Returns the verdict held under `key` when the token's `exp` is still
    /// ahead of `now`, dropping one whose `exp` has come.
    pub(super) fn get(&self, key: &[u8; 32], now: i64) -> Option<Arc<Verified>> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = held.entries.get(key)?;
        if now < entry.exp {
            return Some(Arc::clone(&entry.verified));
        }
        held.remove(key);
        None
    }

    /// Holds `verified` under `key` until `exp`, unless `exp` has come, the
    /// key set has changed since it was verified, or it alone is larger
    /// than the byte bound.
    ///
    /// A full map first drops the verdicts whose `exp` has come, then the
    /// ones that expire soonest.
    pub(super) fn hold(&self, key: [u8; 32], verified: Verified, exp: i64, now: i64) {
        let bytes = weigh(&verified);
        if exp <= now || self.capacity == 0 || bytes > self.byte_capacity {
            return;
        }
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if verified.generation != held.generation {
            return;
        }
        held.remove(&key);
        let full = |held: &Held| {
            held.entries.len() >= self.capacity
                || held.bytes.saturating_add(bytes) > self.byte_capacity
        };
        if full(&held) {
            let ended: Vec<[u8; 32]> = held
                .entries
                .iter()
                .filter(|(_, entry)| entry.exp <= now)
                .map(|(key, _)| *key)
                .collect();
            for ended in &ended {
                held.remove(ended);
            }
        }
        while full(&held) {
            let Some(soonest) = held
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.exp)
                .map(|(key, _)| *key)
            else {
                break;
            };
            held.remove(&soonest);
        }
        held.bytes = held.bytes.saturating_add(bytes);
        held.entries.insert(
            key,
            Entry {
                exp,
                verified: Arc::new(verified),
                bytes,
            },
        );
    }

    /// Drops every verdict, the key set having changed to `generation`.
    pub(super) fn clear(&self, generation: u64) {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        held.generation = generation;
        held.entries.clear();
        held.bytes = 0;
    }

    /// Returns the cap, the entries and the estimated bytes of the map.
    pub(super) fn usage(&self) -> CacheUsage {
        let held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        CacheUsage::new(self.capacity, held.entries.len(), held.bytes)
    }
}

/// A sink that counts the bytes written to it and keeps none.
struct Counted(usize);

impl std::io::Write for Counted {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buffer.len());
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Returns the length of `claims` written as JSON, an estimate of the heap
/// they take.
pub(super) fn json_bytes(claims: &Map<String, Value>) -> usize {
    let mut members = Counted(0);
    // NOTE: no specification governs this: our own design; the sink takes every
    // write, and claims that came from JSON go back into it.
    let written = serde_json::to_writer(&mut members, claims);
    if written.is_ok() { members.0 } else { 0 }
}

/// Returns an estimate of the bytes a held `verified` takes under its
/// 32-byte key.
fn weigh(verified: &Verified) -> usize {
    size_of::<[u8; 32]>()
        .saturating_add(size_of::<Entry>())
        .saturating_add(size_of::<Verified>())
        .saturating_add(verified.kid.as_ref().map_or(0, String::len))
        .saturating_add(json_bytes(&verified.claims))
}

/// Returns the SHA-256 of `token`, the key its verdict is held under.
pub(super) fn digest(token: &str) -> [u8; 32] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, token.as_bytes());
    let mut key = [0_u8; 32];
    key.copy_from_slice(digest.as_ref());
    key
}

#[cfg(test)]
mod tests {
    use crate::jws::algorithm::Algorithm;
    use serde_json::Map;
    use serde_json::json;

    use super::Verdicts;
    use super::Verified;
    use super::digest;

    const NOW: i64 = 1_000_000;

    fn verified(generation: u64, padding: usize) -> Verified {
        let mut claims = Map::new();
        claims.insert(String::from("sub"), json!("s"));
        claims.insert(String::from("pad"), json!("x".repeat(padding)));
        Verified {
            claims,
            alg: Algorithm::Es256,
            kid: Some(String::from("k1")),
            generation,
        }
    }

    #[test]
    fn a_verdict_is_held_until_its_exp_and_never_past_it() {
        let verdicts = Verdicts::new(4, 1 << 20);
        let key = digest("token");
        verdicts.hold(key, verified(0, 0), NOW + 10, NOW);
        assert!(verdicts.get(&key, NOW + 9).is_some());
        assert!(verdicts.get(&key, NOW + 10).is_none(), "dropped at its exp");
        assert_eq!(0, verdicts.usage().entries);
        verdicts.hold(key, verified(0, 0), NOW, NOW);
        assert_eq!(0, verdicts.usage().entries, "an expired token is not held");
    }

    #[test]
    fn a_full_map_drops_the_verdict_that_expires_soonest() {
        let verdicts = Verdicts::new(2, 1 << 20);
        verdicts.hold(digest("a"), verified(0, 0), NOW + 30, NOW);
        verdicts.hold(digest("b"), verified(0, 0), NOW + 10, NOW);
        verdicts.hold(digest("c"), verified(0, 0), NOW + 20, NOW);
        assert_eq!(2, verdicts.usage().entries);
        assert!(verdicts.get(&digest("b"), NOW).is_none());
        assert!(verdicts.get(&digest("a"), NOW).is_some());
        assert!(verdicts.get(&digest("c"), NOW).is_some());
    }

    #[test]
    fn the_byte_bound_holds_and_an_oversized_verdict_is_not_held() {
        let verdicts = Verdicts::new(100, 2_000);
        verdicts.hold(digest("big"), verified(0, 4_000), NOW + 30, NOW);
        assert_eq!(0, verdicts.usage().entries);
        for name in ["a", "b", "c", "d"] {
            verdicts.hold(digest(name), verified(0, 600), NOW + 30, NOW);
            assert!(verdicts.usage().bytes <= 2_000, "{name}");
        }
        let usage = verdicts.usage();
        assert!(usage.entries < 4, "{usage:?}");
        assert!(usage.bytes > 600, "{usage:?}");
    }

    #[test]
    fn a_new_key_set_generation_drops_every_verdict_and_refuses_an_older_one() {
        let verdicts = Verdicts::new(4, 1 << 20);
        verdicts.hold(digest("a"), verified(0, 0), NOW + 30, NOW);
        verdicts.clear(1);
        assert_eq!(0, verdicts.usage().entries);
        assert_eq!(0, verdicts.usage().bytes);
        verdicts.hold(digest("b"), verified(0, 0), NOW + 30, NOW);
        assert_eq!(0, verdicts.usage().entries, "reached under the old set");
        verdicts.hold(digest("b"), verified(1, 0), NOW + 30, NOW);
        assert_eq!(1, verdicts.usage().entries);
    }
}
