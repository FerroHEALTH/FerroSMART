// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The check of one bearer access token.
//!
//! The header names an algorithm of the configured set and a key of the
//! issuer's set; the signature verifies with that key (RFC 7515 §5.2); `iss`
//! is the configured issuer and `aud` contains a configured audience
//! (RFC 9068 §4); `exp`, `nbf` and `iat` hold within the clock skew
//! (RFC 7519 §4.1.4, §4.1.5, §4.1.6). Every failure is the same
//! [`Rejection::Invalid`] on the wire; its [`Reason`] reaches only the log.
//!
//! The verdict of a token that holds is kept until its `exp`
//! ([`super::verdict`]), so the same token presented again is not verified
//! again while the key that verified it is still in the issuer's set; its
//! binding, its `iat` and its classification are checked on every request.

use std::sync::Arc;
use std::time::Duration;

use http::Extensions;
use jsonwebtoken::Validation;
use jsonwebtoken::errors::ErrorKind;
use serde_json::Map;
use serde_json::Value;

use crate::assurance::AssuranceSection;
use crate::federation::Context;
use crate::federation::FederationSection;
use crate::federation::person::AttributesSection;
use crate::kind::CallerKind;
use crate::kind::IssuerKind;
use crate::kind::Unclassified;
use crate::kind::classify;
use crate::profile::Profile;
use crate::refusal::Reason;
use crate::resource::Caller;
use crate::resource::Rejection;
use crate::resource::ResourceServer;
use crate::resource::ResourceTypes;
use crate::resource::verdict;
use crate::resource::verdict::Verified;
use crate::scope::Scopes;
use crate::sender::Binding;

/// Returns the caller `token` authenticates under `server`.
pub(super) async fn validate(
    server: &ResourceServer,
    token: &str,
    binding: &Binding,
) -> Result<Caller, Rejection> {
    let key = verdict::digest(token);
    if let Some(outcome) = held(server, &key, binding).await {
        return outcome;
    }
    verify(server, token, key, binding).await
}

/// Returns the caller of the token whose digest is `key` from its held
/// verdict, or `None` when `server` holds no verdict for it that still
/// stands.
///
/// The key that verified the token is looked up in the set as a fresh
/// check would, so a set past its maximum age is read again and a key it
/// no longer publishes refuses the token as [`Reason::UnknownKey`].
pub(super) async fn held(
    server: &ResourceServer,
    key: &[u8; 32],
    binding: &Binding,
) -> Option<Result<Caller, Rejection>> {
    let verified = server
        .keys
        .verdicts()
        .get(key, jiff::Timestamp::now().as_second())?;
    match server
        .keys
        .holds(verified.kid.as_deref(), verified.alg)
        .await
    {
        Err(source) => Some(Err(Rejection::Unavailable {
            source: Arc::new(source),
        })),
        Ok(None) => Some(Err(invalid(Reason::UnknownKey))),
        Ok(Some(generation)) if generation == verified.generation => {
            Some(finish(server, verified.claims.clone(), binding))
        }
        Ok(Some(_)) => None,
    }
}

/// Returns the caller `token`, whose digest is `key`, authenticates under
/// `server`, its signature, header and claims checked.
pub(super) async fn verify(
    server: &ResourceServer,
    token: &str,
    key: [u8; 32],
    binding: &Binding,
) -> Result<Caller, Rejection> {
    let settings = server.settings();
    let header =
        jsonwebtoken::decode_header(token).map_err(|_malformed| invalid(Reason::Malformed))?;
    if !settings.algorithms.contains(&header.alg) {
        return Err(invalid(Reason::Algorithm));
    }
    // NOTE: RFC 9068 §4 has the `typ` header checked, compared without regard
    // to case; a federation issuer's table may name its own values.
    if !settings.profile.accepts_type(header.typ.as_deref()) {
        return Err(invalid(Reason::Type));
    }
    let (decoding, generation) = server
        .keys
        .find(header.kid.as_deref(), header.alg)
        .await
        .map_err(|source| Rejection::Unavailable {
            source: Arc::new(source),
        })?
        .ok_or_else(|| invalid(Reason::UnknownKey))?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[settings.issuer.as_str()]);
    validation.set_audience(&settings.audience);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.validate_nbf = true;
    validation.leeway = settings.clock_skew.as_secs();
    server.count_signature();
    let data = jsonwebtoken::decode::<Map<String, Value>>(token, &decoding, &validation)
        .map_err(|error| invalid(reason(error.kind())))?;
    let claims = data.claims;
    if settings
        .profile
        .required_claims
        .iter()
        .any(|name| !claims.contains_key(name))
    {
        return Err(invalid(Reason::MissingClaim));
    }
    if let Some(exp) = claims.get("exp").and_then(Value::as_i64) {
        server.keys.verdicts().hold(
            key,
            Verified {
                claims: claims.clone(),
                alg: header.alg,
                kid: header.kid,
                generation,
            },
            exp,
            jiff::Timestamp::now().as_second(),
        );
    }
    finish(server, claims, binding)
}

/// Returns the caller the verified `claims` describe under `server`, the
/// steps that run on every request: the binding to what `binding` proves,
/// the subject and the admission.
fn finish(
    server: &ResourceServer,
    claims: Map<String, Value>,
    binding: &Binding,
) -> Result<Caller, Rejection> {
    let settings = server.settings();
    crate::sender::confirm(settings.sender_constraint, &claims, binding)
        .map_err(|check| invalid(Reason::Sender(check)))?;
    let subject = text(&claims, "sub").ok_or_else(|| invalid(Reason::Subject))?;
    admit(
        claims,
        subject,
        &Admission {
            issuer: &settings.issuer,
            kind: settings.kind,
            profile: &settings.profile,
            assurance: settings.assurance.as_ref(),
            federation: settings.federation.as_ref(),
            attributes: settings.attributes.as_ref(),
            audiences: &settings.audience,
            clock_skew: settings.clock_skew,
            role_claims: &settings.role_claims,
            resource_types: server.resource_types.as_ref(),
            extensions: &server.extensions,
        },
    )
}

/// What a verified token's claims are read under: the issuer that vouched
/// for them and the deployment's rules.
pub(super) struct Admission<'a> {
    /// The issuer the caller is attributed to.
    pub(super) issuer: &'a str,
    /// Whose tokens the issuer signs.
    pub(super) kind: IssuerKind,
    /// The issuer's profile the caller is classified and its scope read
    /// under.
    pub(super) profile: &'a Profile,
    /// The issuer's assurance mapping, when it has one.
    pub(super) assurance: Option<&'a AssuranceSection>,
    /// The `[auth.issuer.<name>.federation]` table of a `federation` issuer.
    pub(super) federation: Option<&'a FederationSection>,
    /// The `[auth.issuer.<name>.attributes]` table of a `persons` issuer.
    pub(super) attributes: Option<&'a AttributesSection>,
    /// This node's audiences, which an `authorization_details` entry names.
    pub(super) audiences: &'a [String],
    /// The clock skew `iat` is checked with.
    pub(super) clock_skew: Duration,
    /// The claims the roles are read from.
    pub(super) role_claims: &'a [String],
    /// The resource types a clinical scope may name, when the product holds
    /// a table.
    pub(super) resource_types: Option<&'a ResourceTypes>,
    /// The product's values copied onto the caller.
    pub(super) extensions: &'a Extensions,
}

/// Returns the caller the verified `claims` of `subject` describe, the step
/// the JWT check and the introspection check share: `iat` within the clock
/// skew, a subject that is not blank, the caller's kind by the issuer's
/// profile, and the scope, the client and the `patient` launch context
/// read the same way.
pub(super) fn admit(
    claims: Map<String, Value>,
    subject: String,
    admission: &Admission<'_>,
) -> Result<Caller, Rejection> {
    if let Some(issued) = claims.get("iat").and_then(Value::as_i64) {
        let latest = jiff::Timestamp::now()
            .as_second()
            .saturating_add(i64::try_from(admission.clock_skew.as_secs()).unwrap_or(i64::MAX));
        if issued > latest {
            return Err(invalid(Reason::IssuedInFuture));
        }
    }
    // NOTE: RFC 9068 §2.2 requires `sub`, and RFC 7519 §4.1.2 has it identify a
    // principal, which a blank value does not.
    if subject.trim().is_empty() {
        return Err(invalid(Reason::BlankSubject));
    }
    let assurance = admission
        .assurance
        .map(|section| section.assess(&claims))
        .unwrap_or_default();
    let federation = admission.federation.map(|section| Context {
        section,
        audiences: admission.audiences,
        level: assurance.level,
        levels: admission.assurance.map(|assurance| &assurance.levels),
    });
    let classified = classify(
        admission.kind,
        admission.profile,
        federation.as_ref(),
        &claims,
        admission.issuer,
    )
    .map_err(|reason| Rejection::Unclassified { reason })?;
    let professional = classified.kind.is_user()
        && !matches!(
            classified.kind,
            CallerKind::Patient | CallerKind::RelatedPerson
        );
    let attributes = match admission.attributes {
        Some(section) => Some(
            section
                .read(&claims, professional)
                .map_err(|reason| Rejection::Unclassified { reason })?,
        ),
        None => None,
    };
    let scope = Profile::scope(&claims).map_err(|_form| Rejection::Unclassified {
        reason: Unclassified::ScopeForm,
    })?;
    // NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, `launch/patient`: the
    // SMART authorization server sets the patient context; another party's does not.
    let patient = (admission.kind == IssuerKind::Smart)
        .then(|| text(&claims, "patient"))
        .flatten();
    let scopes = match admission.resource_types {
        Some(known) => Scopes::parse_known(&scope, |name| known(name)),
        None => Scopes::parse(&scope),
    };
    let roles = crate::roles::from_claims(&claims, admission.role_claims);
    let caller = Caller::new(subject, classified.client, &scope, patient, classified.kind)
        .with_scopes(scopes)
        .with_roles(roles)
        .with_assurance(assurance)
        .with_issuer(admission.issuer.to_owned())
        .with_claims(claims)
        .with_extensions(admission.extensions.clone());
    let caller = match classified.actor {
        Some(actor) => caller.with_actor(actor),
        None => caller,
    };
    Ok(match attributes {
        Some(attributes) => caller.with_attributes(attributes),
        None => caller,
    })
}

/// Returns the string claim `name` of `claims`.
pub(super) fn text(claims: &Map<String, Value>, name: &str) -> Option<String> {
    claims.get(name).and_then(Value::as_str).map(str::to_owned)
}

/// Returns the rejection of a token that does not hold for `reason`.
pub(super) const fn invalid(reason: Reason) -> Rejection {
    Rejection::Invalid { reason }
}

/// Returns the debug-log reason of a failed decode.
const fn reason(kind: &ErrorKind) -> Reason {
    match kind {
        ErrorKind::InvalidSignature => Reason::Signature,
        ErrorKind::ExpiredSignature => Reason::Expired,
        ErrorKind::ImmatureSignature => Reason::NotYetValid,
        ErrorKind::InvalidIssuer => Reason::Issuer,
        ErrorKind::InvalidAudience => Reason::Audience,
        ErrorKind::MissingRequiredClaim(_) => Reason::MissingClaim,
        ErrorKind::InvalidAlgorithm => Reason::Algorithm,
        _ => Reason::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
    use aws_lc_rs::signature::EcdsaKeyPair;
    use jsonwebtoken::Algorithm;
    use jsonwebtoken::EncodingKey;
    use jsonwebtoken::Header;
    use jsonwebtoken::jwk::Jwk;

    use crate::kind::IssuerKind;
    use crate::resource::ResourceServer;
    use crate::resource::Settings;

    const ISSUER: &str = "https://issuer.example";
    const AUDIENCE: &str = "https://ehr.example";

    /// A signing key generated for the case, with its public JWK.
    struct Key {
        kid: &'static str,
        encoding: EncodingKey,
        jwk: serde_json::Value,
    }

    fn key(kid: &'static str) -> Key {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .expect("a key pair");
        let encoding = EncodingKey::from_ec_der(pkcs8.as_ref());
        let mut jwk = serde_json::to_value(
            Jwk::from_encoding_key(&encoding, Algorithm::ES256).expect("a public JWK"),
        )
        .expect("the JWK serializes");
        if let Some(members) = jwk.as_object_mut() {
            members.insert(String::from("kid"), serde_json::json!(kid));
        }
        Key { kid, encoding, jwk }
    }

    fn publish(path: &std::path::Path, keys: &[&Key]) {
        let set: Vec<_> = keys.iter().map(|key| key.jwk.clone()).collect();
        std::fs::write(path, serde_json::json!({ "keys": set }).to_string())
            .expect("the key set file is written");
    }

    fn mint(key: &Key, jti: &str) -> String {
        let now = jiff::Timestamp::now().as_second();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(key.kid.to_owned());
        header.typ = Some(String::from("at+jwt"));
        let claims = serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "synthetic-sub",
            "client_id": "synthetic-client",
            "iat": now,
            "exp": now + 300,
            "jti": jti,
            "scope": "user/Observation.rs"
        });
        jsonwebtoken::encode(&header, &claims, &key.encoding).expect("the token signs")
    }

    async fn server(path: &std::path::Path, max_age: Duration) -> ResourceServer {
        let mut settings = Settings::new(ISSUER, AUDIENCE, IssuerKind::Smart);
        settings.jwks_file = Some(path.to_owned());
        settings.jwks_max_age = max_age;
        settings.jwks_refresh_interval = Duration::from_secs(3600);
        ResourceServer::discover(settings)
            .await
            .expect("the key set file is read")
    }

    #[tokio::test]
    async fn a_token_presented_again_is_not_verified_again() {
        let signer = key("k1");
        let file = tempfile::NamedTempFile::new().expect("a key set file");
        publish(file.path(), &[&signer]);
        let server = server(file.path(), Duration::from_secs(600)).await;
        let token = mint(&signer, "jti-1");
        let first = server.authenticate(&token).await.expect("the token holds");
        let second = server.authenticate(&token).await.expect("the token holds");
        assert_eq!(first, second, "the same caller both times");
        assert_eq!(
            1,
            server.signatures(),
            "one signature check for two requests"
        );
        server
            .authenticate(&mint(&signer, "jti-2"))
            .await
            .expect("the token holds");
        assert_eq!(2, server.signatures(), "another token is verified");
        assert_eq!(2, server.cache_usage().entries);
    }

    #[tokio::test]
    async fn a_key_set_read_again_unchanged_keeps_the_verdicts() {
        let signer = key("k1");
        let file = tempfile::NamedTempFile::new().expect("a key set file");
        publish(file.path(), &[&signer]);
        let server = server(file.path(), Duration::ZERO).await;
        let token = mint(&signer, "jti-1");
        for _ in 0..3 {
            server.authenticate(&token).await.expect("the token holds");
        }
        assert_eq!(1, server.signatures(), "the set read again is the same set");
    }

    #[tokio::test]
    async fn a_key_set_read_again_changed_drops_every_verdict() {
        let signer = key("k1");
        let added = key("k2");
        let file = tempfile::NamedTempFile::new().expect("a key set file");
        publish(file.path(), &[&signer]);
        let server = server(file.path(), Duration::ZERO).await;
        let token = mint(&signer, "jti-1");
        server.authenticate(&token).await.expect("the token holds");
        publish(file.path(), &[&signer, &added]);
        server.authenticate(&token).await.expect("the token holds");
        assert_eq!(2, server.signatures(), "the changed set verifies again");
        assert_eq!(1, server.cache_usage().entries);
    }
}
