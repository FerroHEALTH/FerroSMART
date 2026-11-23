// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A presentation of an SD-JWT VC: the Issuer-signed JWT, its Disclosures
//! and the Key Binding JWT (RFC 9901 §4, §7; draft-ietf-oauth-sd-jwt-vc-13
//! §3, §4; OpenID4VP 1.0 Appendix B.3.6).
//!
//! The check runs in two steps, with the I/O between them left to the
//! caller: [`Presentation::issuer_key`] names where the issuer's key comes
//! from, and [`Presentation::verify`] checks the rest against that key.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::{Jws, Refusal, sha256};

/// How far in the future a Key Binding JWT's `iat`, or a credential's
/// `nbf`, may lie, in seconds, for the clocks of wallet and verifier (no
/// specification sets the value: our own design).
pub const CLOCK_SKEW: i64 = 60;

/// How old a Key Binding JWT's `iat` may be, in seconds (RFC 9901 §7.3 step
/// 5 leaves the window to the verifier: our own design).
pub const MAX_BINDING_AGE: i64 = 300;

/// The hash the verifier checks Disclosures and `sd_hash` with, the
/// default and the one value it accepts for `_sd_alg` (RFC 9901 §4.1.1).
const SHA_256: &str = "sha-256";

/// Where the issuer's key comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerKey {
    /// The `x5c` chain of the header, DER, leaf first (HAIP 1.0 §6.1.1).
    Chain(Vec<Vec<u8>>),
    /// The `x5u` URL of the chain, with the `x5t#S256` thumbprint of its
    /// leaf when the header names one (Implementing Regulation (EU)
    /// 2024/2977 Annex as amended by 2026/1731, §4.2; RFC 7515 §4.1.5).
    Url {
        /// The URL.
        url: String,
        /// The leaf's SHA-256 thumbprint.
        thumbprint: Option<Vec<u8>>,
    },
}

/// What the request expects of a presentation.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    /// The request's `nonce`.
    pub nonce: &'a str,
    /// The audience the Key Binding JWT names: the verifier's client
    /// identifier.
    pub audience: &'a str,
    /// The credential types the request asked for.
    pub vct_values: &'a [String],
    /// The time, in seconds since the epoch.
    pub now: i64,
}

/// The reference to a Token Status List a credential carries
/// (draft-ietf-oauth-status-list-20 §6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReference {
    /// The URI of the Status List Token.
    pub uri: String,
    /// The credential's index in the list.
    pub idx: u64,
}

/// A presentation that verified, with the claims it discloses.
#[derive(Clone)]
pub struct Verified {
    /// The credential's claims, its Disclosures applied, with no `_sd`,
    /// `_sd_alg`, `cnf` or `status`.
    pub claims: Map<String, Value>,
    /// The status reference, when the credential carries one.
    pub status: Option<StatusReference>,
    /// The Key Binding JWT's `iat`: when the holder presented it.
    pub presented_at: i64,
}

impl std::fmt::Debug for Verified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verified")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// One presentation, read.
#[derive(Debug, Clone)]
pub struct Presentation<'a> {
    /// The Issuer-signed JWT.
    issuer_jwt: Jws<'a>,
    /// The Disclosures, base64url, in their order.
    disclosures: Vec<&'a str>,
    /// The Key Binding JWT, when there is one.
    binding: Option<&'a str>,
    /// What `sd_hash` covers: everything up to and including the last `~`.
    hashed: &'a str,
}

impl<'a> Presentation<'a> {
    /// Reads the compact presentation `text` (RFC 9901 §4).
    ///
    /// # Errors
    /// Returns [`Refusal::InvalidCredential`] for text of another shape or
    /// an Issuer-signed JWT whose `typ` is not an SD-JWT VC's.
    pub fn parse(text: &'a str) -> Result<Self, Refusal> {
        let last = text.rfind('~').ok_or(Refusal::InvalidCredential)?;
        let (hashed, binding) = text.split_at(last + 1);
        let mut parts = hashed.split('~');
        let issuer_jwt = parts
            .next()
            .and_then(Jws::parse)
            .ok_or(Refusal::InvalidCredential)?;
        let disclosures: Vec<&str> = parts.filter(|part| !part.is_empty()).collect();
        // NOTE: draft-ietf-oauth-sd-jwt-vc-13 §3.2.1, vc+sd-jwt is accepted beside
        // dc+sd-jwt for the transitional period the draft recommends.
        if !matches!(issuer_jwt.header_text("typ"), Some("dc+sd-jwt" | "vc+sd-jwt")) {
            return Err(Refusal::InvalidCredential);
        }
        Ok(Self {
            issuer_jwt,
            disclosures,
            binding: Some(binding).filter(|binding| !binding.is_empty()),
            hashed,
        })
    }

    /// Returns where the issuer's key comes from: the `x5c` chain, else the
    /// `x5u` URL.
    ///
    /// # Errors
    /// Returns [`Refusal::UntrustedIssuer`] when the header names neither, or
    /// a chain that does not read.
    pub fn issuer_key(&self) -> Result<IssuerKey, Refusal> {
        if let Some(chain) = self.issuer_jwt.header.get("x5c") {
            return chain_of(chain).map(IssuerKey::Chain);
        }
        let url = self
            .issuer_jwt
            .header_text("x5u")
            .ok_or(Refusal::UntrustedIssuer)?;
        let thumbprint = match self.issuer_jwt.header_text("x5t#S256") {
            Some(text) => Some(super::decode(text).map_err(|_unread| Refusal::UntrustedIssuer)?),
            None => None,
        };
        Ok(IssuerKey::Url {
            url: url.to_owned(),
            thumbprint,
        })
    }

    /// Checks the presentation against the issuer's P-256 key `issuer`, a
    /// key a trusted certificate path carries, and `expected`: the issuer's
    /// signature, the type, the validity, the Disclosures and the Key
    /// Binding JWT, in that order.
    ///
    /// # Errors
    /// Returns the [`Refusal`] of the first check that fails.
    pub fn verify(&self, issuer: &[u8], expected: &Expected<'_>) -> Result<Verified, Refusal> {
        if !self.issuer_jwt.verifies_with(issuer) {
            return Err(Refusal::InvalidCredential);
        }
        let vct = self.issuer_jwt.text("vct").ok_or(Refusal::InvalidCredential)?;
        if !expected.vct_values.iter().any(|wanted| wanted == vct) {
            return Err(Refusal::UnrequestedCredential);
        }
        valid_at(&self.issuer_jwt, expected.now)?;
        let mut claims = disclose(&self.issuer_jwt.claims, &self.disclosures)?;
        let holder = claims
            .get("cnf")
            .and_then(|cnf| cnf.get("jwk"))
            .and_then(super::p256_point)
            .ok_or(Refusal::BadHolderBinding)?;
        let presented_at = self.bound(&holder, expected)?;
        let status = match claims.remove("status") {
            Some(status) => Some(status_reference(&status).ok_or(Refusal::StatusUnavailable)?),
            None => None,
        };
        claims.remove("cnf");
        Ok(Verified {
            claims,
            status,
            presented_at,
        })
    }

    /// Checks the Key Binding JWT against the holder's key `holder` and
    /// returns its `iat` (RFC 9901 §7.3; OpenID4VP 1.0 Appendix B.3.6).
    fn bound(&self, holder: &[u8], expected: &Expected<'_>) -> Result<i64, Refusal> {
        let binding = self
            .binding
            .and_then(Jws::parse)
            .ok_or(Refusal::BadHolderBinding)?;
        let iat = binding.seconds("iat").ok_or(Refusal::BadHolderBinding)?;
        let sd_hash = super::encode(&sha256(self.hashed.as_bytes()));
        let holds = binding.header_text("typ") == Some("kb+jwt")
            && binding.verifies_with(holder)
            && binding.text("nonce") == Some(expected.nonce)
            && binding.text("aud") == Some(expected.audience)
            && binding.text("sd_hash") == Some(sd_hash.as_str())
            && iat <= expected.now + CLOCK_SKEW
            && iat >= expected.now - MAX_BINDING_AGE;
        if holds {
            Ok(iat)
        } else {
            Err(Refusal::BadHolderBinding)
        }
    }
}

/// Returns the DER certificates of the `x5c` value `chain` (RFC 7515
/// §4.1.6: standard base64, not base64url).
fn chain_of(chain: &Value) -> Result<Vec<Vec<u8>>, Refusal> {
    use base64::Engine as _;
    let entries = chain.as_array().ok_or(Refusal::UntrustedIssuer)?;
    if entries.is_empty() {
        return Err(Refusal::UntrustedIssuer);
    }
    entries
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .and_then(|text| base64::engine::general_purpose::STANDARD.decode(text).ok())
                .ok_or(Refusal::UntrustedIssuer)
        })
        .collect()
}

/// Checks the credential's `exp` and `nbf` at `now` (RFC 7519 §4.1.4,
/// §4.1.5; draft-ietf-oauth-status-list-20 §8.3: validity precedes status).
fn valid_at(credential: &Jws<'_>, now: i64) -> Result<(), Refusal> {
    let number = |name: &str| match credential.claims.get(name) {
        None => Ok(None),
        Some(value) => value.as_i64().map(Some).ok_or(Refusal::InvalidCredential),
    };
    if number("exp")?.is_some_and(|exp| now >= exp) {
        return Err(Refusal::Expired);
    }
    if number("nbf")?.is_some_and(|nbf| nbf > now + CLOCK_SKEW) {
        return Err(Refusal::Expired);
    }
    Ok(())
}

/// Returns the status reference of the `status` claim (HAIP 1.0 §6.1: a
/// present `status` carries `status_list`).
fn status_reference(status: &Value) -> Option<StatusReference> {
    let list = status.get("status_list")?;
    Some(StatusReference {
        uri: list.get("uri")?.as_str()?.to_owned(),
        idx: list.get("idx")?.as_u64()?,
    })
}

/// One Disclosure, decoded and matched by its digest.
struct Disclosure {
    /// The claim name, for an object property; none for an array element.
    name: Option<String>,
    /// The value.
    value: Value,
}

/// Returns the claims of `payload` with every Disclosure of `disclosures`
/// applied, refusing a digest met twice, a Disclosure of a reserved or
/// repeated name, and a Disclosure no digest references (RFC 9901 §7.1
/// steps 3 to 5).
fn disclose(payload: &Map<String, Value>, disclosures: &[&str]) -> Result<Map<String, Value>, Refusal> {
    match payload.get("_sd_alg") {
        None => {}
        Some(Value::String(alg)) if alg == SHA_256 => {}
        Some(_) => return Err(Refusal::InvalidCredential),
    }
    let mut by_digest: BTreeMap<String, Disclosure> = BTreeMap::new();
    for encoded in disclosures {
        let digest = super::encode(&sha256(encoded.as_bytes()));
        let decoded = decoded(encoded).ok_or(Refusal::InvalidCredential)?;
        if by_digest.insert(digest, decoded).is_some() {
            return Err(Refusal::InvalidCredential);
        }
    }
    let mut walk = Walk {
        disclosures: by_digest,
        seen: BTreeSet::new(),
    };
    let mut claims = walk.object(payload)?;
    if !walk.disclosures.is_empty() {
        return Err(Refusal::InvalidCredential);
    }
    claims.remove("_sd_alg");
    Ok(claims)
}

/// Returns the Disclosure the base64url text `encoded` holds: a JSON array
/// of a salt, a name and a value, or of a salt and a value (RFC 9901
/// §4.2.1, §4.2.2).
fn decoded(encoded: &str) -> Option<Disclosure> {
    let bytes = super::decode(encoded).ok()?;
    let Value::Array(parts) = serde_json::from_slice::<Value>(&bytes).ok()? else {
        return None;
    };
    match parts.as_slice() {
        [Value::String(_), Value::String(name), value] => {
            // NOTE: RFC 9901 §7.1 step 3.2.2, a Disclosure never names _sd or ...
            (name != "_sd" && name != "...").then(|| Disclosure {
                name: Some(name.clone()),
                value: value.clone(),
            })
        }
        [Value::String(_), value] => Some(Disclosure {
            name: None,
            value: value.clone(),
        }),
        _ => None,
    }
}

/// The recursive application of the Disclosures to the payload.
struct Walk {
    /// The Disclosures not yet applied, by digest.
    disclosures: BTreeMap<String, Disclosure>,
    /// The digests met so far.
    seen: BTreeSet<String>,
}

impl Walk {
    /// Records the digest `digest` as met, refusing one met before.
    fn meet(&mut self, digest: &str) -> Result<Option<Disclosure>, Refusal> {
        if !self.seen.insert(digest.to_owned()) {
            return Err(Refusal::InvalidCredential);
        }
        Ok(self.disclosures.remove(digest))
    }

    /// Returns `value` with the Disclosures applied.
    fn value(&mut self, value: &Value) -> Result<Value, Refusal> {
        match value {
            Value::Object(object) => self.object(object).map(Value::Object),
            Value::Array(items) => self.array(items).map(Value::Array),
            other => Ok(other.clone()),
        }
    }

    /// Returns `object` with the Disclosures its `_sd` digests reference
    /// inserted and `_sd` removed (RFC 9901 §7.1 step 3.2).
    fn object(&mut self, object: &Map<String, Value>) -> Result<Map<String, Value>, Refusal> {
        let mut out = Map::new();
        for (name, value) in object {
            if name != "_sd" {
                out.insert(name.clone(), self.value(value)?);
            }
        }
        let Some(digests) = object.get("_sd") else {
            return Ok(out);
        };
        let digests = digests.as_array().ok_or(Refusal::InvalidCredential)?;
        for digest in digests {
            let digest = digest.as_str().ok_or(Refusal::InvalidCredential)?;
            let Some(disclosure) = self.meet(digest)? else {
                continue;
            };
            let name = disclosure.name.ok_or(Refusal::InvalidCredential)?;
            if out.contains_key(&name) {
                return Err(Refusal::InvalidCredential);
            }
            let value = self.value(&disclosure.value)?;
            out.insert(name, value);
        }
        Ok(out)
    }

    /// Returns `items` with each `{"...": digest}` element replaced by its
    /// Disclosure's value, or left out when none was disclosed (RFC 9901
    /// §7.1 step 3.3).
    fn array(&mut self, items: &[Value]) -> Result<Vec<Value>, Refusal> {
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let reference = item
                .as_object()
                .filter(|object| object.len() == 1)
                .and_then(|object| object.get("..."));
            let Some(reference) = reference else {
                out.push(self.value(item)?);
                continue;
            };
            let digest = reference.as_str().ok_or(Refusal::InvalidCredential)?;
            if let Some(disclosure) = self.meet(digest)? {
                if disclosure.name.is_some() {
                    return Err(Refusal::InvalidCredential);
                }
                out.push(self.value(&disclosure.value)?);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn disclosure(parts: &Value) -> (String, String) {
        let encoded = super::super::encode(parts.to_string().as_bytes());
        let digest = super::super::encode(&sha256(encoded.as_bytes()));
        (encoded, digest)
    }

    #[test]
    fn disclosures_fill_objects_and_arrays_and_undisclosed_digests_stay_hidden() {
        let (name, name_digest) = disclosure(&json!(["s1", "family_name", "Jansen"]));
        let (_hidden, hidden_digest) = disclosure(&json!(["s2", "given_name", "Eva"]));
        let (element, element_digest) = disclosure(&json!(["s3", "NL"]));
        let payload = json!({
            "vct": "urn:eudi:pid:1",
            "_sd_alg": "sha-256",
            "_sd": [name_digest, hidden_digest],
            "nationalities": [{"...": element_digest}, "DE"],
        });
        let claims = disclose(payload.as_object().expect("an object"), &[&name, &element])
            .expect("the disclosures should apply");
        assert_eq!(claims["family_name"], "Jansen");
        assert!(claims.get("given_name").is_none());
        assert_eq!(claims["nationalities"], json!(["NL", "DE"]));
        assert!(claims.get("_sd").is_none() && claims.get("_sd_alg").is_none());
    }

    #[test]
    fn an_unreferenced_or_repeated_disclosure_is_refused() {
        let (name, name_digest) = disclosure(&json!(["s1", "family_name", "Jansen"]));
        let (stray, _) = disclosure(&json!(["s9", "given_name", "Eva"]));
        let payload = json!({"_sd": [name_digest]});
        let payload = payload.as_object().expect("an object");
        assert!(disclose(payload, &[&name, &stray]).is_err());
        assert!(disclose(payload, &[&name, &name]).is_err());
    }

    #[test]
    fn a_disclosure_of_a_reserved_or_present_name_is_refused() {
        let (reserved, reserved_digest) = disclosure(&json!(["s1", "_sd", "x"]));
        let payload = json!({"_sd": [reserved_digest]});
        assert!(disclose(payload.as_object().expect("an object"), &[&reserved]).is_err());
        let (clash, clash_digest) = disclosure(&json!(["s1", "vct", "x"]));
        let payload = json!({"vct": "urn:eudi:pid:1", "_sd": [clash_digest]});
        assert!(disclose(payload.as_object().expect("an object"), &[&clash]).is_err());
    }

    #[test]
    fn another_hash_algorithm_is_refused() {
        let payload = json!({"_sd_alg": "sha-512"});
        assert!(disclose(payload.as_object().expect("an object"), &[]).is_err());
    }

    #[test]
    fn a_digest_met_twice_is_refused() {
        let (name, digest) = disclosure(&json!(["s1", "family_name", "Jansen"]));
        let payload = json!({"_sd": [digest], "address": {"_sd": [digest]}});
        assert!(disclose(payload.as_object().expect("an object"), &[&name]).is_err());
    }

    #[test]
    fn a_status_claim_names_its_list_and_index() {
        let status = json!({"status_list": {"uri": "https://status.example/1", "idx": 7}});
        assert_eq!(
            status_reference(&status),
            Some(StatusReference {
                uri: String::from("https://status.example/1"),
                idx: 7
            })
        );
        assert_eq!(status_reference(&json!({"other": {}})), None);
    }

    #[test]
    fn a_presentation_without_a_tilde_or_of_another_type_does_not_read() {
        let header = super::super::encode(br#"{"alg":"ES256","typ":"JWT"}"#);
        let payload = super::super::encode(br#"{"vct":"x"}"#);
        assert!(Presentation::parse(&format!("{header}.{payload}.c2ln~")).is_err());
        assert!(Presentation::parse("no tilde").is_err());
    }
}
