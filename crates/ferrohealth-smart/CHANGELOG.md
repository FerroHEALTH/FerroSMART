<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.38.2] - 2026-11-28

### Fixed

- `client::outbound::OutboundClient` holds the TLS it was built from for its
  lifetime, so under `trust_roots_file` its endpoint stays cleared for
  revocation after `build` returns, and `send` clears the URL it calls before
  it connects. Every outbound client whose `tls` named `trust_roots_file`
  failed closed once its clearing ended (#1000).

## [0.38.1] - 2026-11-28

### Fixed

- Under `trust_roots_file`, every call the crate sends clears its endpoint for
  revocation before it connects, so a `jwks_uri`, an introspection endpoint or
  a token endpoint on another host under the same root connects as the issuer
  does, whether the configuration or the issuer's metadata names it. The
  endpoints handed to `config::ServerTls` are still cleared at once, and a
  first call waits for their first round. `client::PresentedTls` carries the
  new `client::Clearance` seam (`with_clearance`, `clear`) (#993).

## [0.38.0] - 2026-11-28

The move to `ferrohealth-server` 0.14 and `ferrohealth-config` 0.5: every
`trust_roots_file` endpoint is kept cleared for revocation.
`ferrohealth-authz` 0.31.0 and `ferrohealth-session` 0.35.0 follow it.

### Changed

- Breaking: the `server-tls` feature requires `ferrohealth-server` 0.14 and
  `ferrohealth-config` 0.5, which verify an outbound chain by its root: a
  chain to a root of `trust_roots_file` opens a connection only once a
  revocation check cleared its endpoint, failing closed when no CRL or OCSP
  source answers, and a root of the new `trust_roots_without_revocation_file`
  is trusted with no check and logged. `config::TlsBuilder::build` takes the
  endpoints a connection reaches, and `config::ServerTls` keeps them cleared
  with a `revocation::Clearing` held by the `client::PresentedTls` it builds,
  which names the unchecked roots in `PresentedTls::unchecked_roots`; a
  product's own builder takes the new `endpoints` parameter (#988).

## [0.37.0] - 2026-11-28

The move to `ferrohealth-server` 0.13, with ML-DSA certificates in TLS 1.3.
`ferrohealth-authz` 0.30.0 and `ferrohealth-session` 0.34.0 follow it.

### Changed

- Breaking: the `server-tls` feature requires `ferrohealth-server` 0.13 in
  place of 0.12, whose TLS 1.3 listener and clients present and verify
  ML-DSA certificates and whose revocation check verifies CRLs and OCSP
  answers an ML-DSA key signs (RFC 9881) (#981).

## [0.36.0] - 2026-11-27

The relying party's UserInfo request, ML-DSA DPoP keys and the shared
`post_quantum_only` switch. `ferrohealth-authz` 0.29.0 and
`ferrohealth-session` 0.33.0 follow it.

### Added

- `RelyingParty::userinfo`, the relying party's UserInfo request (OpenID
  Connect Core 1.0 §5.3): the access token as a bearer token with `GET`, a
  JSON answer or a signed one checked against the provider's keys, and its
  `sub` held to the ID Token's (§5.3.2), with `Provider::userinfo_endpoint`
  and the `OidcError` variants `UserInfo`, `UserInfoBody`,
  `UserInfoSignature` and `UserInfoSubject` (#933).
- `client::dpop::DpopKey::from_pem` reads an ML-DSA-44, ML-DSA-65 or
  ML-DSA-87 private key (RFC 9881 §6) beside the P-256 and P-384 keys, and
  signs its proofs with that parameter set, the `AKP` public key in the
  header `jwk` (RFC 9964, RFC 9449 §4.2) (#944).
- `[auth] post_quantum_only`: on, every JWT issuer's `algorithms` and
  `[auth.dpop] algorithms` left at their default become ML-DSA-44,
  ML-DSA-65 and ML-DSA-87 (RFC 9964 §5), an explicit ML-DSA list stays, and
  a list naming any other algorithm refuses the section with
  `ConfigError::ClassicalAlgorithm`, naming its key. `jws::algorithm::ML_DSA`
  holds the three parameter sets. A product that carries its own copy of
  this rule deletes it (#945).

### Changed

- Breaking: `ServerMetadata` carries `userinfo_endpoint` (OpenID Connect
  Discovery 1.0 §3); a product that builds the struct by its fields adds
  it or keeps `..ServerMetadata::default()` (#933).
- Breaking: `AuthSection` carries `post_quantum_only`; a product that
  builds the struct by its fields adds it or keeps
  `..AuthSection::default()` (#945).

## [0.35.0] - 2026-11-25

ML-DSA signatures (RFC 9964) and one JWS module in place of `jsonwebtoken`.
`ferrohealth-authz` 0.28.0 and `ferrohealth-session` 0.30.0 follow it.

### Added

- `jws`, the one module that signs and verifies every JWS (RFC 7515) over
  `aws-lc-rs`: RS256 to PS512, ES256, ES384, `EdDSA` (RFC 8037) and
  ML-DSA-44, ML-DSA-65 and ML-DSA-87 (RFC 9964), with the `AKP` JSON Web
  Key, the JWK thumbprint of every key type and the registered claim
  checks. A key verifies only the algorithm its type, curve or parameter
  set and its `alg`, `use` and `key_ops` admit (RFC 8725 §3.1). The
  resource server, the OpenID relying party and the `DPoP` proof check
  verify an ML-DSA token when the configured algorithms name it, and an
  assertion key read from an RFC 9881 ML-DSA private key signs with its
  parameter set and publishes its `AKP` key (#886).

### Changed

- Breaking: every signature algorithm is
  `jws::algorithm::Algorithm` (`Rs256` to `MlDsa87`) in place of
  `jsonwebtoken::Algorithm`, in `Settings::algorithms`, the `[auth]`
  tables, `ProofSettings`, `RelyingParty::with_algorithms`,
  `AssertionKey` and `DpopKey`; `DpopKey::public_jwk` returns a
  `jws::jwk::Jwk`, and the errors that carried a `jsonwebtoken` error
  carry the `jws` one. A symmetric algorithm or `none` has no value, so a
  configuration that names one fails to parse. The crate no longer
  depends on `jsonwebtoken`. A product moves its `Algorithm` imports to
  `ferrohealth_smart::jws::algorithm::Algorithm` (#886).

### Removed

- Breaking: `ResourceError::SymmetricAlgorithm`,
  `ProofSettingsError::SymmetricAlgorithm`, `AssertionError::Public` and
  `client::assertion::thumbprint`; the JWK's own `Jwk::thumbprint` takes
  the place of the last (#886).

## [0.34.0] - 2026-11-24

### Added

- `ProofCheck::check_token_request` checks the `DPoP` proof of a token
  request, which presents no access token and so carries no `ath` (RFC 9449
  §5) (#807).

### Changed

- Breaking: the caller is read from the token's standard claims the same
  way for every issuer. An issuer is a SMART App Launch 2.2 authorization
  server unless its table declares `kind = "federation"`, so a product
  trusts FerroSMART with an `[auth.issuer.<name>]` table naming only its
  `issuer`. `CallerKind` is `System`, a user by the type of their
  `fhirUser` (`Patient`, `Practitioner`, `PractitionerRole`,
  `RelatedPerson`, `Person`, or `User` with none), `ExternalPerson` or
  `ExternalOrganisation`; `Caller::actor` is the RFC 8693 actor,
  `Caller::fhir_user` the `fhirUser` and `Caller::represented` the patient
  a `RelatedPerson` acts for. A token's `typ` is `at+jwt` or
  `application/at+jwt` and its `scope` required (#805).

### Removed

- Breaking: the authorization server's registry is the one list of
  clients. A token from a trusted issuer whose `aud` names the resource
  server admits its client, and an RFC 8693 `act` is read as asserted
  (`Caller::actor` carries the actor). The profile keys
  `first_party_clients`, `delegates`, `audience_delegates` and
  `issuer_client_is_person`, the issuer key `scopeless_subjects`, the
  `kind::standing` module with `Standing` and `StandingSource`,
  `config::ProductStandingSection`, `Caller::scopeless`, the `scopeless`
  argument of `Caller::new`, and the `UnlistedClient`, `UnlistedActor` and
  `RepresentationThroughDelegate` refusals are removed; a configuration
  that sets one of the keys is refused as an unknown key (#804).
- Breaking: the `persons`, `patients` and `machines` issuer kinds, the
  `preset` and `profile_file` keys with the `rfc9068`, `entra`, `keycloak`,
  `okta` and `ferrosmart` presets, the `[auth.idp]` table with the
  `idp-entra` feature and the party adapters, the party table's `guests`
  key, and the profile keys `person_key`, `tenant_claim`, `client_claims`,
  `app_only`, `guest`, `impersonation_marker`, `expect`, `user_claims`,
  `person_equality`, `unstable_claims`, `representation`,
  `act_represents_patient`, `fhir_user_patient`, `patient_context`,
  `party_identifier_type`, `scope_claim`, `app_only_scope_claim` and
  `adapter` are removed, and a configuration that sets one is refused as an
  unknown key. `CallerKind::Delegated`, `Representative`,
  `PatientRepresentative` and `Guest`, `Caller::person_key` and
  `Caller::tenant` go with them (#805).

## [0.33.1] - 2026-11-22

### Changed

- The guard checks a Basic credential the verified-credential cache holds
  before its refresh point on the request's own task, with no hand-off to
  Tokio's blocking pool, which only a miss, a refresh or a wrong password
  still takes for the key derivation. A wrong password is refused as
  before, after the same derivation (#756).

## [0.33.0] - 2026-11-21

### Changed

- Breaking: with `server-tls`, requires `ferrohealth-server` 0.12.0 (caret
  `0.12.0`) in place of `0.11.0`, whose `tls_client::TlsClient`
  `config::TlsBuilder` carries. ferrohealth-server 0.12 can decode a gzip or
  Brotli request body under the body limit (`server.request_decompression`)
  (FerroHEALTH/FerroSYS#408). Upgrade: move `ferrohealth-server` to 0.12
  with this crate, so one copy links (#760).

## [0.32.0] - 2026-11-20

### Added

- The profile key `audience_delegates`: on a `persons` issuer under the
  `ferrosmart` preset, every client of a token whose `aud` names this
  resource server is a delegate, beside the clients `delegates` lists, so an
  app registered at FerroSMART with this product among its `resources`
  needs no entry here. It is refused under any other preset
  (`ProfileError::AudienceDelegates`), on another issuer kind, and beside a
  product's standing (`ProductStandingSection` does not know the key).
  `Profile` and `ProfileKeys` gain the field (#682).
- A product starts before its issuers are reachable: `IssuerSet::read_in_background`
  reads every issuer built with `ResourceServer::lazy` and not read yet, with
  a bounded back-off of one second doubling to one minute
  (`LazyResourceServer::read_until_read`), and `IssuerSet::is_ready` answers
  the product's readiness route, not ready until every issuer is read
  (`LazyResourceServer::is_read`). A configuration error still refuses the
  start (#734).
- The federation field `trc.care_role` (`Field::TrcCareRole`): the care
  role a treatment relationship attests for the professional, one coded
  value with its code system, mapped from a claim, a credential subject, an
  attested `authorization_details` member or a `{ constant, system }`
  source like the other `trc.*` fields and read through `External::field`.
  A string, a code without a system or more than one code refuses the token
  as `Unclassified::Attribute` naming the field, and a contact point's
  token that carries it carries `trc.id` and both TRC window bounds (#751).

### Changed

- Breaking: no federation field names a country. `federation::Field` loses
  `NlProfessionalNumber`, `NlRole`, `NlUra` and `NlOrganisationType`
  (`nl.professional_number`, `nl.role`, `nl.ura`, `nl.organisation_type`);
  their values arrive through the generic `professional.hp_identifier`,
  `professional.hp_professional_role`, `provider.healthcare_provider_identifier`
  and `provider.facility_type`, each with its code system. The new source
  `{ constant = "…", system = "…" }` (`Source::Coded`) configures a coded
  value with its system, and a value that arrives without a code system is
  kept unsystemed (`Code::system` `None`), so a consumer can refuse to match
  it. A deployment that read the `nl.*` fields reads the generic ones by
  their code systems; the book's Annex B example profile does (#492).
- Breaking: every refusal carries a stable reason code (`audience-mismatch`,
  `issuer-unknown`, `delegate-not-granted`, `refused-unbound` and the rest
  the book lists). The gate logs each refusal at info with the code, the
  token's issuer, client id and key id, never the token or a claim that
  names a person, and `Denied::challenge` sends the code as the
  `error_description` of the `401` or `403` (RFC 6750 §3); a missing
  credential and a Basic challenge carry none. `guard::Render::render` and
  `extract::HeaderOnly::respond` take a `refusal::Denied` in place of a
  `Refusal`, `Reason::as_str` returns the code, `Reason::Unclassified`
  carries the step's code (`kind::Unclassified::code`), and `Reason` gains
  `BasicIncomplete`, `ScopeNotGranted`, `RouteUnclassified`,
  `PartySourceUnavailable` and `Party`, the code a product refuses a party
  binding with (`party::Outcome::refusal_reason`). A product renders with
  `denied.challenge(realm)` and `denied.refusal().status()`, and refuses
  an unbound login with `Denied::new(Refusal::Forbidden,
  outcome.refusal_reason())` (#729).
- Breaking: issuers are a map by name, `[auth.issuer.<name>]`, in place of
  the `[[auth.issuer]]` array, and every other key names an issuer by its
  table's name: `described_issuer`, and a product's role lists through
  `Resolved::role_issuers` (in place of `check_role_issuers`, which took
  URLs) and `Resolved::issuer_named`. An unknown name is refused at load
  (`ConfigError::UnknownIssuer` lists the known names), a name outside the
  form (a lower-case letter, then lower-case letters, digits and `_`, at most
  64) is `ConfigError::IssuerName`, and the environment form addresses an
  issuer by name. The party, federation and attribute tables and the
  scopeless subjects sit under their issuer (`[auth.issuer.<name>.party]`,
  `.federation`, `.attributes`, `scopeless_subjects = ["sub"]`), and the
  section-level `[[auth.party]]`, `[[auth.federation]]`,
  `[[auth.attributes]]`, `scopeless_subjects` and `config::ScopelessSubject`
  are removed. Defaults derive: `AuthSection::resolve` and
  `ProductStandingSection::resolve` take the product's base URLs, the
  audience of an issuer that names none; `kind` is the preset's (`persons`
  under `ferrosmart`, `keycloak`, `entra` and `okta`, `Preset::kind`); a
  party table's `identifier_issuer` is the issuer's identifier and its
  `identifier_type` the new profile key `party_identifier_type` (`pairwise`
  under `ferrosmart`). The new profile key `patient_context` decides whether
  an issuer's `patient` claim is the launch context: on under `ferrosmart`,
  off otherwise. Under `ferrosmart` the new key `issuer_client_is_person`
  reads a token whose client is the issuer itself, FerroSMART's patient
  picker, as the person with no app grant, and its `client_id` still names
  FerroSMART. A product moves its issuer tables to named ones, refers to
  them by name, drops its own patient-issuer rule (FerroEHR's
  `patient_issuers`) and the picker's agent or self-delegate, and passes its
  base URLs to `resolve` (#730).
- Breaking: a profile loads from a file a deployment supplies, and the
  compiled presets are the standards-only one and the vendors' (`rfc9068`,
  `keycloak`, `entra`, `okta`, `ferrosmart`). An issuer table names its preset
  as `preset` (in place of `profile`), may name a `profile_file` in the form
  of a preset file (`profile::ProfileFile`: profile keys, `kind`, a
  `[federation]` table), and sets profile keys in its
  `[auth.issuer.<name>.profile]` table, which win over the file, which wins
  over the preset. The 31 profile keys that sat on the issuer table itself
  are removed from it (`IssuerEntry::profile` is now that table and
  `IssuerEntry::profile_keys` is removed), and the onward table follows:
  `[<lane>.credentials.onward]` takes `preset`, `profile_file` and a
  `profile` table in place of `profile` and `keys`. `Profile::with_keys`
  sets keys over a resolved profile. A product moves `profile = "…"` to
  `preset = "…"` and every profile key under the issuer's `profile` table (#732).
- Breaking: a token of an issuer whose metadata or key set has not been read
  since the start is refused as the new `Rejection::Unread`, `503` with the
  reason code `issuer-unread` (`Reason::IssuerUnread`), in place of
  `Rejection::Unavailable`. A product that matches `Rejection` exhaustively
  adds the variant (#734).

### Removed

- Breaking: the compiled `nl` preset (`Preset::Nl`, `profiles/nl.toml`) is
  removed: the products ship no country content. The book ships the same
  openEHR Federation Tier Annex B §B.4a mapping as an example a deployment
  loads with `profile_file` (#732).

## [0.31.0] - 2026-11-20

### Changed

- Breaking: the `ferrosmart` preset reads a patient's own token on a
  `persons` issuer as `CallerKind::Patient`, so `Caller::is_the_person`
  holds for it. The token must pass the client admission first (its client
  in `first_party_clients` or `delegates`, or a `Standing` answer of first
  party or delegate), carry no `act` and no representation claim, and hold
  all three: `fhirUser` is `Patient/<x>` (relative, or an absolute URL
  ending in `/Patient/<x>`), the `patient` claim is `x`, and its scopes
  carry a `patient/` grant with no `user/` or `system/` one. Any other
  FerroSMART token classifies as before, so a professional with `patient/`
  scopes stays a professional confined to the launch context. The reading
  is the new profile key `fhir_user_patient` (`Profile::fhir_user_patient`,
  `ProfileKeys::fhir_user_patient`, and the same key on `IssuerEntry`),
  which only the `ferrosmart` preset sets and an issuer table can turn off.
  A product that builds `Profile`, `ProfileKeys` or `IssuerEntry` with a
  struct literal adds the field, and a product that read a patient's own
  token through FerroSMART by its own rule (FerroEHR's `patient_issuers`)
  drops that rule and reads `Caller::is_the_person` (#681).

## [0.30.2] - 2026-11-19

### Added

- `xml`, behind the new `xml` feature: the bounded XML reader (`xml::prepare`
  holds a document to the caller's `xml::Limits`, a byte cap and a linear
  pre-scan of depth and namespace declarations, and translates its line
  ends; `xml::parse` refuses a DTD and holds a node cap) and
  `xml::c14n::canonicalize`, the Exclusive XML Canonicalization 1.0 the
  eHDSI assertion check verifies with, now public so FerroSMART's upstream
  SAML 2.0 login verifies with the same implementation (#688).
  `ehdsi-assertion` enables it; the eHDSI check's behaviour is unchanged.
- `uri::normalized` and `uri::normalize_percent`: the RFC 3986 §6.2.2
  syntax-based normalization the DPoP `htu` check applies, public so
  FerroSMART compares a registered launch URL the same way.
- `RelyingParty::refresh_for` sends a refresh request that names a
  `resource` (RFC 8707 §2.2), so a console gets a token for a second
  resource server on the same grant (#675).

## [0.30.1] - 2026-11-19

### Added

- `usage::CacheUsage` reports the cap, the entries and an estimate of the
  bytes of each in-memory cache that grows with traffic, for a product's
  memory metrics: `PasswordStore::cache_usage` (the verified-credential
  cache, at most 4096 entries), `Introspector::cache_usage` (the
  introspection responses, at most `cache_capacity`) and
  `MemoryReplayStore::cache_usage` (the DPoP proof records). The crate
  links no metrics library; a product copies the numbers into its own
  gauges (#630).
- `resource::ResourceServer` keeps the verdict of a verified access token
  until the token's `exp` (RFC 7519 §4.1.4), so the same token is verified
  once instead of on every request: its signature, header and claims are
  checked on the first request and held under the token's SHA-256, never
  the token. Before a held verdict answers, the token's key is looked up in
  the issuer's key set as a fresh check would, so a set past its maximum age
  is read again and a key the issuer no longer publishes refuses the token;
  a read that finds the set changed drops every held verdict. The binding,
  `iat` and the classification stay per request, and an introspected
  issuer is unchanged. At most 10,000 verdicts in at most 16 MiB are held,
  reported by `ResourceServer::cache_usage` and, summed over the issuers of
  a set, `IssuerSet::verdict_usage` (FerroHEALTH/FerroEHR#6049).

### Fixed

- `oidc::RelyingParty` refuses an ID Token without a numeric `iat`, which
  OpenID Connect Core 1.0 §2 makes REQUIRED, with `OidcError::IdToken`
  (#646).
- `oidc::RelyingParty` verifies an ID Token or a Logout Token that names
  no `kid` with the one key of the provider's set whose `use`, `key_ops`,
  `alg`, key type and curve fit the token's algorithm, where it took only
  a set of a single key; none or several such keys is `OidcError::Key`
  (RFC 7515 §4.1.4, OpenID Connect Core 1.0 §10.1; #648).

## [0.30.0] - 2026-11-17

### Changed

- Breaking: with `server-tls`, requires `ferrohealth-server` 0.11.0 (caret
  `0.11.0`) in place of `0.10.0`, whose `tls_client::TlsClient`
  `config::TlsBuilder` carries. ferrohealth-server 0.11 lets a request past
  the overload bound wait briefly for a slot before it is refused `503`
  (`server.admission_wait`, `server.max_waiting_requests`)
  (FerroHEALTH/FerroSYS#403). Upgrade: move `ferrohealth-server` to 0.11
  with this crate, so one copy links (#631).

## [0.29.2] - 2026-11-17

### Changed

- `oidc::RelyingParty` under `with_private_key_jwt` sends a client assertion
  whose `aud` is the provider's issuer identifier as its sole value and
  whose `typ` is `client-authentication+jwt`, as RFC 10070 §4 requires.
  Before, it sent the token endpoint URL typed `JWT`, which OpenID Connect
  Core 1.0 §9 recommends and which ZITADEL refuses. RFC 10070 §6 has such a
  client work with providers of either rule. The public API is unchanged,
  and `with_client_secret` stays for `ferrohealth-session`
  (FerroHEALTH/FerroSMART#619).
- The repository is FerroSMART again, at
  <https://github.com/FerroHEALTH/FerroSMART>, and the crate's `repository`
  and `homepage` point there (owner decision 2026-11-17). The FerroAUTH
  address redirects, and the crate name stays.

### Fixed

- The App Launch discovery document of `resource::configuration::document`
  names `token_endpoint_auth_signing_alg_values_supported`, the issuer's
  algorithms, whenever it lists `private_key_jwt`, as SMART App Launch
  2.2.0, Client Authentication: Asymmetric, Advertising server support
  requires of a server that supports the profile. Only the Backend Services
  document carried it before (FerroHEALTH/FerroSMART#600).

## [0.29.1] - 2026-11-17

### Added

- `oidc::RelyingParty::with_private_key_jwt` authenticates the relying party
  with a JWT its `AssertionKey` signs (`private_key_jwt`, OpenID Connect
  Core 1.0 §9): a fresh assertion per token or revocation request, `aud`
  the token endpoint URL, typed `JWT`, with the client id beside it (RFC
  7521 §4.2). `OidcError::Assertion` names a signature that failed.
  `AssertionKey::with_algorithm` signs with another algorithm of an RSA
  key's family, and `AssertionKey::with_certificate` (feature `oidc`) names
  the key's X.509 certificate by `x5t#S256` in every header (RFC 7515
  §4.1.8), refusing a certificate of another key with the new
  `AssertionError::Certificate` and `AssertionError::CertificateKey`. The
  `oidc` feature now pulls `x509-parser` (#569).

### Fixed

- `AuthSection::resolve` refuses two `[[auth.issuer]]` tables naming one
  issuer, JWT or introspected alike, with the new
  `ConfigError::DuplicateIssuer`, which names the key, both table indices and
  the issuer with any userinfo masked. Before, the later table silently
  replaced the earlier, so a FerroSMART deployment written as a `persons`
  table plus a `machines` table refused every person with `401`. Trust one
  issuer in one table: for FerroSMART, a single `persons` table under
  `profile = "ferrosmart"` with `delegates`, which also reads a Backend
  Services token as the system. The `ferrosmart` preset's comment and
  `docs/architecture.md` §13.21 now show that shape (#591).

## [0.29.0] - 2026-11-17

`Preset` gains `Ferrosmart`, and the configuration enums likely to grow are
now `#[non_exhaustive]`, so a later preset, onward grant or credential form
is an additive change. A `match` over one of them in a product takes a
wildcard arm.

### Added

- The `ferrosmart` issuer profile preset (`profile = "ferrosmart"`,
  `profiles/ferrosmart.toml`) reads the access tokens of FerroSMART, the
  family's SMART App Launch 2.x authorization server, as plain RFC 9068: every
  `rfc9068` default but `token_types = ["at+jwt"]` (RFC 9068 §2.1) and a
  `scope` among the required claims. A client credentials token reads as
  `System`, and a SMART app the resource server lists in `delegates` reads as
  `Delegated`. FerroSMART's own tests read the tokens it issues under it
  (#521).
- `oidc::RelyingParty::with_trusted_audiences` trusts named audiences beside
  the client in an ID Token's or a logout token's `aud`: OpenID Connect Core
  1.0 §3.1.3.7 item 3 refuses only "additional audiences not trusted by the
  Client", and ZITADEL names the project beside the client in every ID
  Token. A token with several audiences must then carry an `azp` naming the
  client (item 4). Without the call nothing changes: an audience beyond the
  client is refused as before (#523).
- A claim path reads a claim whose name contains a dot. OpenID Connect
  Core 1.0 §5.1.2 lets a claim name be any string, and Microsoft Entra ID
  writes a directory extension attribute into a JWT as `extn.<name>`
  (`optional-claims.md`, vendored under `docs/specs/entra-docs/`). At each
  level of the path the member named by the longest run of the remaining
  steps is taken first; a path that names no such member reads as before.
  This holds for `role_claims`, the assurance claim, the patient claim and
  every other claim path (#562).
- A role claim whose value is a JSON object carries each member name as a
  role, for an issuer that keys what it knows of each role by the role:
  ZITADEL writes `urn:zitadel:iam:org:project:{projectId}:roles` as
  `{"<role>": {"<orgId>": "<orgDomain>"}}` (its `retrieve-user-roles.mdx` at
  v4.20.3, vendored under `docs/specs/zitadel/`). Before, such a value
  carried no role. Name the claim in the issuer's `role_claims` (#523).
- `oidc::RelyingParty::logout_token` checks the Logout Token of OpenID
  Connect Back-Channel Logout 1.0 as §2.6 has a relying party check it: the
  provider's signature under an algorithm accepted for ID Tokens, `iss`,
  `aud` (this client alone), `iat` and `exp`, `sub` or `sid` or both, the
  back-channel logout event, and no `nonce`. It returns
  `oidc::logout::LogoutClaims` (issuer, subject, session, `jti`, `iat`,
  `exp`); the new `OidcError::LogoutToken` and `OidcError::LogoutClaims`
  name a failed check. The specification is vendored under
  `docs/specs/openid-connect-backchannel/` (#518).

### Changed

- Breaking: `profile::Preset`, `profile::Marker`, `profile::onward::OnwardGrant`,
  `profile::onward::OnwardIndicator`, `client::ClientAuth`,
  `config::AuthMode`, `config::credentials::Outbound`,
  `resource::introspection::IntrospectionAuth`, `sender::Scheme` and
  `sender::SenderConstraint` are `#[non_exhaustive]`; a `match` over one
  takes a wildcard arm (#521).

## [0.28.0] - 2026-11-16

### Changed

- Breaking: the `aud` and `typ` of a `private_key_jwt` client assertion
  follow the grant's security profile and are never configured: the token
  endpoint under `typ` `JWT` (SMART App Launch 2.2.0, Client
  Authentication: Asymmetric), and under `security_profile = "fapi2"` the
  issuer identifier as a string under `client-authentication+jwt` (FAPI 2.0
  §5.3.3.1, RFC 10070 §4). RFC 10070 §4 has every client name the issuer;
  SMART 2.2 governs a SMART client, so the plain grant keeps the token
  endpoint, a deviation recorded in `docs/architecture.md` §3.5 and
  reported in #528. `client::AssertionAudience`, the
  `ClientCredentials::assertion_audience` field and
  `client::fapi2::Fapi2Error::AssertionAudience` are removed;
  `client::CLIENT_AUTHENTICATION_TYP` is new. `AssertionKey::assertion`
  takes the audience and the `typ` (`assertion(client_id, audience, typ)`).
  Upgrade: delete `assertion_audience` from every
  `[<lane>.credentials.oauth]` table; a grant that needs the issuer as
  `aud` sets `security_profile = "fapi2"` (#529).

### Removed

- The `assertion_audience` key of `[<lane>.credentials.oauth]`. The table
  denies unknown fields, so a configuration that still sets it fails to
  load as an unknown key (#529).

## [0.27.0] - 2026-11-16

### Changed

- Breaking: `resource::described::describe` describes a deployment that
  trusts only `machines` issuers. When no trusted issuer signs user tokens
  (no `persons`, `patients` or `federation` issuer), the one `machines`
  issuer with metadata is described for SMART Backend Services; several are
  refused with the new `DescribeError::SeveralMachines`, naming them sorted.
  A named `described_issuer` of kind `machines` is described for Backend
  Services while no issuer is eligible for app launch, and still refused
  with `DescribeError::MachinesIssuer` beside one. `describe` returns a
  `Described` in place of the `Candidate`, with the same `issuer`, `kind`,
  `check` and `into_check` and a `purpose`. Upgrade: set
  `SmartOptions::purpose` to `Described::purpose` when building the
  document, and drop any refusal of a machines-only deployment (#507).

### Added

- `resource::configuration::Purpose`, the `SmartOptions::purpose` the
  discovery document is built under (`AppLaunch` by default), and
  `resource::configuration::backend_services`, the Backend Services
  document: `token_endpoint`, `private_key_jwt` with the issuer's signing
  algorithms, the `client_credentials` grant, the `system/` scopes of
  `scopes_supported` and `client-confidential-asymmetric` with the
  scope-syntax capabilities, and no `authorization_endpoint`, `issuer` or
  app-launch capability (SMART App Launch 2.2.0, Backend Services, Retrieve
  `.well-known/smart-configuration`) (#507).
- `Candidate::is_backend_eligible` (#507).

## [0.26.0] - 2026-11-15

### Changed

- Breaking: with `server-tls`, requires `ferrohealth-server` 0.10.0 (caret
  `0.10.0`) in place of `0.9.0`, whose `tls_client::TlsClient`
  `config::TlsBuilder` carries. ferrohealth-server 0.10 bounds the requests
  served at once by default (`server.max_concurrent_requests`, 256)
  (FerroHEALTH/FerroSYS#398). Upgrade: move `ferrohealth-server` to 0.10
  with this crate, so one copy links (#500).

### Fixed

- The verified-credential cache of `[auth.basic]` no longer lets one
  credential's expiry turn into a burst of Argon2id derivations.
  Concurrent misses for one credential share one derivation, a rejection
  included; each entry lives between nine tenths of `cache_ttl` and
  `cache_ttl`, by a jitter per credential, so entries derived together
  expire apart; and in the last tenth of its lifetime one request
  re-derives the credential while the others are still admitted. A
  re-derivation that fails drops the entry, and no entry admits past
  `cache_ttl` from the derivation that admitted it. `Verified::cached` is
  also set on a request admitted from a concurrent request's derivation
  (FerroHEALTH/FerroEHR#5742, #498).

## [0.25.0] - 2026-11-15

### Changed

- Breaking: with `server-tls`, requires `ferrohealth-server` 0.9.0 (caret
  `0.9.0`) in place of `0.8.0`, whose `tls_client::TlsClient`
  `config::TlsBuilder` carries. ferrohealth-server 0.9 builds on
  ferrohealth-telemetry 0.5, which installs its own `log` bridge beside the
  subscriber and no longer has `InitError::AlreadyInstalled`
  (FerroHEALTH/FerroSYS#389, #391). Upgrade: move `ferrohealth-server` and
  `ferrohealth-telemetry` to 0.9 and 0.5 with this crate, so one copy of
  each links (#493).

## [0.24.1] - 2026-11-13

### Fixed

- `config::ProductStandingSection` refuses an unknown key, at the `[auth]`
  level and in an `[[auth.issuer]]` entry, while the key is read, so the
  TOML error carries the key's own span and a product names its full path
  (`auth.isser`), as `AuthSection` does, where it named only the `auth`
  table (#489).

## [0.24.0] - 2026-11-13

### Added

- `kind::standing::Standing`, the product's answers to the three standing
  questions of the caller classification, asked on every request whose
  token needs one and never cached: `client` gives a `persons` token's
  client its `kind::standing::ClientStanding` (`FirstParty`, `Delegate` or
  `Unlisted`), `delegate` says whether the current RFC 8693 actor is a
  declared delegate, and `scopeless` whether a `CallerKind::System` caller
  of a `persons` or `machines` issuer is admitted without a scope. The
  answers classify as the lists do, with the same refusals
  (`UnlistedClient`, `UnlistedActor`, `RepresentationThroughDelegate`), and
  a token that carries a resource scope still reaches only its scopes. A
  `kind::standing::StandingError` refuses the token as
  `Rejection::Upstream` (`503`), never as an unlisted client (#484).
- `resource::Settings::standing` and
  `introspection::IntrospectionSettings::standing`, a
  `kind::standing::StandingSource`: `Lists` (the default) reads the
  profile's `first_party_clients` and `delegates` and the
  `scopeless_subjects`, `Product` asks the product's `Standing`. Beside
  `Product`, a set list is refused as
  `ResourceError::ListedBesideStanding`, so no list is read in two places
  (#484).
- `config::ProductStandingSection`, the `[auth]` section of a product whose
  standing answers the lists: `AuthSection` with `scopeless_subjects` and
  each `[[auth.issuer]]` table's `first_party_clients` and `delegates`
  unknown keys, refused as any unknown key is and absent from its schema.
  `ProductStandingSection::resolve` and `resolve_with_tls` hand every
  issuer the product's standing, and refuse a list set in code as
  `ConfigError::ListedBesideStanding` (#484).

### Changed

- Breaking: the caller classification asks the issuer's
  `StandingSource`, so `Settings` and `IntrospectionSettings` gain the
  public `standing` field, `ResourceError` gains `ListedBesideStanding`
  and `ConfigError` gains `ListedBesideStanding`. `Caller::scopeless` and
  the scope checks read the standing's answer (#484). Upgrade, per
  product:
  - FerroEHR: read `[auth]` as `config::ProductStandingSection` in place
    of `config::AuthSection`, delete `scopeless_subjects` and every
    issuer's `first_party_clients` and `delegates` from the shipped
    configuration and the reference, implement `kind::standing::Standing`
    over the in-memory copy of the CDR's client lists, and resolve with
    `section.resolve_with_tls(&tls, Arc::new(standing))?`.
  - FerroBRIDGE, FerroTERM, FerroPIX and FerroFED: no change; the lists
    stay in `[auth]` and answer as before. A test or a product that builds
    `Settings` or `IntrospectionSettings` with a struct literal adds
    `standing: StandingSource::Lists`.
- An introspected response held in the cache is classified again on each
  request it answers, so the standing answers every request (#484).
- `[auth] scopeless_subjects` is left out when an `AuthSection` is written
  with no entry (#484).

### Fixed

- An RFC 8693 actor, or a patient's representative, of an introspection
  response that names no `iss` is attributed to the configured issuer in
  place of an empty one (#484).

## [0.23.0] - 2026-11-13

### Added

- `Caller::with_granted_scope` and `Caller::with_granted_roles` add the
  scope tokens and roles a product grants a verified caller from its own
  data, beside the ones it holds, without rebuilding the caller. Every
  reader sees them: `scope()`, `has_scope()`, `scopes()` and the reach a
  scope grants, `openehr_scopes()`, `roles()` and `has_role()`. A token or
  a role already held is added once, and a Basic caller is granted no
  `system/` scope (#479).
- `config::BasicGrants`, a table of `config::BasicGrant` (`scopes`,
  `roles`) by user-id, for a product that keeps its Basic users' scopes
  and roles in its own configuration, and `PasswordStore::with_grants`,
  which grants them to the store's users and refuses a grant naming a user
  the store does not admit. `PasswordStore::with_scope` grants one user its
  scope, with the checks `with_user` ran before (#479).

### Changed

- Breaking: `[[auth.basic.users]]` holds the credential alone: `user`,
  `password_hash` and `password_hash_file`. A table that sets `roles` or
  `scopes` is refused as an unknown key, and `config::BasicUser` loses its
  `roles` and `scopes` fields. A Basic user's scope and roles are the
  product's to grant, so a product that keeps them as policy data drops
  both keys from its schema. `PasswordStore::with_user` takes the user-id
  and the hash alone, and a scope is granted with
  `PasswordStore::with_scope` (#479). Upgrade, per product:
  - FerroEHR: delete `roles` and `scopes` from every shipped
    `[[auth.basic.users]]` table, and add the `hold_roles` and
    `hold_scopes` grants of the user's party to the caller the gate admits
    with `caller.with_granted_scope(scopes).with_granted_roles(roles)` in
    place of rebuilding it with `Caller::basic(..).with_roles(..)
    .with_cached(..).with_party(..)`.
  - FerroBRIDGE, FerroTERM and FerroPIX: move each user's `roles` and
    `scopes` out of `[[auth.basic.users]]` into a `config::BasicGrants`
    table the product composes into its own configuration, keyed by
    user-id, and hand the store of `Resolved::basic` to the gate as
    `store.with_grants(&grants)?`.

## [0.22.0] - 2026-11-12

### Added

- `DpopSection::settings` returns the proof settings of a surface its
  clients address at the URL the product hands it, under the table's
  window and algorithms, and `DpopSection::validate` checks the window and
  the algorithms (#474).

### Changed

- Breaking: `[auth.dpop]` has no `external_url` key, and a table that sets
  it is refused as an unknown key. The base URL a proof's `htu` is compared
  with is the product's public URL, which the product names once and
  hands over in code, so a deployment never sets the same origin twice.
  `Resolved::dpop` is the checked `Option<DpopSection>` in place of
  `Option<ProofSettings>`, and `DpopSection` loses its public
  `external_url` field. A window or an algorithm that breaks a rule still
  refuses the resolution (`ConfigError::Dpop`); a URL that breaks the URL
  rule is refused by `ProofCheck::new` (`ProofSettingsError::ExternalUrl`).
  Upgrade: remove `external_url` from `[auth.dpop]` and build the check
  with `ProofCheck::new(dpop.settings(public_url), store)` (#474).

## [0.21.0] - 2026-11-12

### Added

- `resource::described`: the one rule for the issuer a SMART discovery
  document describes, shared by every product. `describe` takes a
  `Candidate` per trusted issuer (`Candidate::of_server`,
  `Candidate::of_introspector` or `Candidate::new`, each carrying the
  product's own check) and the named issuer, and returns the candidate to
  describe: the named one, else the one eligible issuer. Eligible is an
  issuer whose kind is not `machines` and whose metadata is available
  (SMART App Launch 2.2.0, Conformance, §Metadata: the
  `authorization_endpoint` is where every user launch starts, and this
  crate refuses every token of a `machines` issuer that is not app-only).
  `DescribeError` refuses a named issuer that is unknown
  (`UnknownIssuer`), `machines` (`MachinesIssuer`) or without metadata
  (`NoMetadata`), several eligible issuers without a name
  (`SeveralEligible`, naming them sorted) and none (`NoneEligible`). The
  order of the `[[auth.issuer]]` tables never decides. FerroBRIDGE,
  FerroTERM and FerroPIX can drop their first-in-table-order choice for it,
  and FerroEHR its own copy of the rule (#469).
- `ResourceServer::metadata_state`: whether the issuer's metadata is
  available, read from the issuer or supplied by `with_metadata` for a key
  set read from a `jwks_file` (#469).

### Changed

- Breaking: the `[auth]` section takes an optional `described_issuer`, the
  issuer the discovery document describes, carried to
  `Resolved::described_issuer` for `describe`. `AuthSection` and `Resolved`
  each gain the public field. Upgrade: a product that builds either with a
  struct literal adds `described_issuer: None`, or ends it with
  `..Default::default()` for `AuthSection` (#469).

## [0.20.0] - 2026-11-11

### Fixed

- Breaking: a product role list's refusal masks the issuer's userinfo, as
  every other refusal naming an issuer does since 0.19 (RFC 3986 §3.2.1).
  `config::Resolved::check_role_issuers` takes the issuers as
  `&[ferrohealth_secret::secret_url::SecretUrl]` in place of any
  `&[impl AsRef<str>]`, finds each by its exposed text, and
  `config::ConfigError::RoleIssuer::issuer` is a `SecretUrl` in place of a
  `String`, so an issuer written as `https://user:password@host/` reaches
  neither the refusal's `Display` nor its `Debug` with its password.
  Upgrade: hold the role list as `SecretUrl` (it deserializes from the same
  string) and pass it as it is, or wrap each entry with `SecretUrl::new`;
  read the refused issuer with `.expose()` (#464).

## [0.19.1] - 2026-11-11

### Fixed

- A `private_key_jwt` client assertion is valid for 60 seconds
  (`client::assertion::ASSERTION_LIFETIME_SECONDS`), down from 300, so an
  authorization server that caps the lifetime below SMART App Launch
  2.2.0's five-minute ceiling accepts it; mock-oauth2-server, which refuses
  an assertion that lives longer than 120 seconds, refused every token
  request and onward exchange signed with one (#461).

## [0.19.0] - 2026-11-11

### Changed

- Breaking: every configuration table that names an `[[auth.issuer]]`
  holds the issuer as a `ferrohealth_secret::secret_url::SecretUrl`, as the
  `[[auth.issuer]]` itself is since 0.18, so a password in its userinfo
  reaches no rendering of a product's configuration, serialized or
  `Debug`, nor a refusal (RFC 3986 §3.2.1):
  `federation::person::AttributesSection::issuer` (`[[auth.attributes]]`),
  `federation::FederationSection::issuer` (`[[auth.federation]]`),
  `party::config::PartySection::issuer` (`[[auth.party]]`) and
  `config::ScopelessSubject::issuer` (`auth.scopeless_subjects`). Upgrade:
  read the issuer with `.expose()` and build one with `SecretUrl::new`
  (#456).

## [0.18.0] - 2026-11-10

### Changed

- Breaking: every issuer identifier a configuration table names is a
  `ferrohealth_secret::secret_url::SecretUrl`, as every endpoint URL is
  since 0.17, so a password in its userinfo reaches no rendering of a
  product's configuration, serialized or `Debug`, even one rendered before
  validation runs (RFC 3986 §3.2.1): `config::IssuerEntry::issuer`,
  `config::onward::OnwardSection::issuer` and
  `config::credentials::OauthSection::issuer`, whose own masking serializer
  is gone. The start still refuses an issuer with userinfo, naming it
  masked. Upgrade: read the identifier with `.expose()` and build one with
  `SecretUrl::new` (#445).

### Fixed

- The router example of the README passes the `IssuerKind` that
  `Settings::new` takes, and the README's examples compile as doctests, so
  the crate page shows code that builds.

## [0.17.1] - 2026-11-10

### Added

- The purpose of use of every caller, not only a professional's: a
  `System` caller of a `persons` issuer with an `[[auth.attributes]]` table
  carries the purposes its token declares as `Caller::attributes`, with no
  professional field, and a `patients` or `machines` issuer may have a
  table too, which names no field but `purpose_of_use`, so the patient and
  the patient's representative carry theirs. A field other than
  `purpose_of_use` in such a table refuses the start
  (`FederationError::PurposeOnly`, `AttributesSection::validate_for`);
  a table on a `federation` issuer is still refused (#438).

### Fixed

- A FHIR Coding whose `code` is empty names no code, and an empty `system`
  no system (FHIR R4 datatypes.html: both have at least one character), so
  an IUA `purpose_of_use` of empty codes states no purpose of use instead of
  an empty one (#438).

## [0.17.0] - 2026-11-10

### Added

- `federation::Field::MessageId` (`message_id`): the UUID of the
  cross-border request message, its WS-Addressing `MessageID` (eHDSI NCPeH
  Components Specifications 10.0.0 §3.5), which a MyHealth@EU contact point
  relays. The `ehdsi` mapping reads it from `ehdsi.message_id`; it is
  optional, and held to the bounds of every field. `External::message_id`
  and `resource::Caller::message_id` return it as a `federation::MessageId`,
  whose `Debug` rendering never carries the value, so a product joins its
  access record to the contact point's audit entry (#432).

### Changed

- Breaking: every endpoint URL a configuration table names is a
  `ferrohealth_secret::secret_url::SecretUrl`, as `EndpointSection::url`
  is since 0.16, so a password in its userinfo reaches no rendering of a
  product's running configuration, serialized or `Debug`:
  `config::onward::OnwardSection::token_endpoint`,
  `config::IntrospectionSection::endpoint` and
  `config::credentials::OauthSection::token_endpoint`, whose own masking
  serializer is gone. An empty URL keeps its meaning (discover the endpoint
  from the issuer). `OauthSection::issuer` stays a `String`. Upgrade: read
  the URL with `.expose()` and build one with `SecretUrl::new` (#429).

### Fixed

- Breaking: an outbound client's TLS refusal names the key the operator
  wrote. `client::outbound::OutboundClient::build`, `build_sharing_tls` and
  `OutboundBuilder::build` hand the endpoint table's `tls` table to the
  product's `config::TlsBuilder` at `<key>.tls`, so an unreadable or empty
  `trust_roots_file` is named `cdr.tls.trust_roots_file` and an identity
  without a certificate `cdr.tls.client_identity`, where 0.16 named
  `cdr.trust_roots_file`. `config::ConfigError::TlsBuild::key` is a
  `String` in place of a `&'static str`, since the key is computed. Upgrade:
  a product that matches the field against a literal compares it instead
  (`TlsBuild { key, .. } if key == "auth.tls"`) (#427).

## [0.16.3] - 2026-11-10

### Added

- `client::outbound::OutboundClient::builder` starts an `OutboundBuilder`,
  the one way to build an outbound client with more than its endpoint
  table: `sharing_tls` takes the grant's TLS from the connection as
  `build_sharing_tls` does, `clock` has the client credentials token source
  read its tokens' expiry and renewal margin against a clock the product
  supplies (`client::cache::Clock`), so a test moves the clock to drive a
  renewal, and `authorizer` supplies an authorization of the product's own.
  `OutboundClient::build` and `build_sharing_tls` are unchanged and build
  through it (#422).
- `client::outbound::Authorizer` is that authorization, for a grant the
  endpoint table cannot name, such as a Nuts node token with a `DPoP` proof
  per request: `OutboundClient::send` asks it for the headers of every try
  from the request's method and URL, a retry included, tells it of every
  answer, and sends a `401` once more with new headers. It is held as the
  new `Authorization::Product`. A refusal reaches the caller as the new
  `SendError::Authorization`, whose `AuthorizerError` carries the product's
  error as its source, with nothing sent, and a table that names a
  credential beside it is refused with the new
  `OutboundError::CredentialBesideAuthorizer` (#423).

## [0.16.2] - 2026-11-10

### Added

- `client::outbound::OutboundClient::build_sharing_tls` builds an outbound
  client whose client credentials grant presents the connection's TLS when
  its `oauth.tls` names no material: the trust roots and the client
  certificate built from the endpoint table's `tls`. A mutual-TLS
  `client_auth` then authenticates with the certificate the connection
  presents (RFC 8705 §2), and a `certificate_bound` grant binds its tokens
  to it (RFC 8705 §3), so the operator writes the identity once. An
  `oauth.tls` that names material still wins, and a `certificate_bound`
  grant whose certificate is not the connection's is refused with the new
  `OutboundError::CertificateBinding`. `CredentialsSection::resolve_sharing_tls`
  and `OauthSection::resolve_sharing_tls` resolve a table the same way over a
  configuration the product built. `OutboundClient::build` is unchanged
  (#417).

## [0.16.1] - 2026-11-09

### Added

- The configuration sections implement `PartialEq` and `Eq`: `AuthSection`,
  `IssuerEntry`, `IntrospectionSection`, `BasicSection`, `BasicUser`,
  `credentials::CredentialsSection`, `credentials::OauthSection`,
  `endpoint::EndpointSection`, `idp::section::IdpSection` and
  `idp::entra::GraphSection`, so a product diffs a reloaded configuration
  against the running one without serializing either. A secret
  (`client_secret`, `password`, `password_hash`) compares by its value and
  stays out of every `Debug` and serialized rendering (#414).

## [0.16.0] - 2026-11-09

### Added

- `client::outbound::OutboundClient::build` builds the client of one
  outbound integration from its `config::endpoint::EndpointSection` and the
  product's `config::TlsBuilder`: the table validated, the HTTP engine with
  its `timeout`, its `connect_timeout`, no redirects and the TLS the
  builder makes, and `credentials` resolved into
  `client::outbound::Authorization` (Basic, or a `TokenSource` renewed once
  on a `401`). `OutboundClient::send` sends with that authorization and the
  table's `retry`: a call that did not reach the integration, timed out or
  met a `5xx` is tried again. `RetrySection::delays` gives the waits: the
  first `initial_backoff`, each later one doubled, capped at `max_backoff`.
  The `fetch` feature now enables the Tokio timer (#397).
- `[auth.idp]`: `AuthSection::idp` reads `[auth.idp.entra]`, the Graph
  table of the `idp-entra` adapter, which a build without `idp-entra`
  refuses as an unknown key. `Resolved::adapters` holds the adapters the
  tables build, and `party::binding::PartyBinding::with_resolved` registers
  them, so a product writes no deserializer and no `with_adapter` call of
  its own. A table the adapter refuses is `ConfigError::Adapter` (#398).

### Changed

- Breaking: `config::endpoint::EndpointSection::url` is a
  `ferrohealth_secret::secret_url::SecretUrl` in place of a `String`, so the
  URL masks its userinfo and query as a property of its type. Upgrade: read
  the URL with `url.expose()`, or take the parsed `Url` from
  `EndpointSection::validate`; build one with `SecretUrl::new` (#404).
- Breaking: `config::AuthSection` has the field `idp`, and
  `config::Resolved` the field `adapters`; a product that builds either
  with a struct literal adds them (`..Default::default()` for the section)
  (#398).

## [0.15.1] - 2026-11-09

### Security

- `config::endpoint::EndpointSection` renders its `url` with the userinfo
  and the query masked, in `Debug` and when serialized to TOML or JSON,
  through the family mask of `ferrohealth-secret` (`config::mask_userinfo`).
  Before 0.15.1 a credential in an endpoint URL rendered in full, so a
  product that logged or dumped its configuration could write it to its
  log. Affected: 0.14.0 and 0.15.0 (CWE-532, GHSA-vmx8-jr3x-394q). Upgrade
  step: move to 0.15.1; until then, put the endpoint credential in
  `[<x>.endpoint.credentials]` and keep it out of the URL (#403).

## [0.15.0] - 2026-11-09

### Removed

- Breaking: every named refusal of a retired key is deleted, under the
  owner's rule that a removal aid lives for the one release that retires
  it (#388). The strict load refuses each such key as unknown. Deleted:
  the fields that only held a retired key (`AuthSection`'s `audience`,
  `algorithms`, `token_profile`, `clock_skew_seconds`,
  `jwks_max_age_seconds`, `jwks_refresh_interval_seconds`, `jwks_file`,
  `timeout_ms`, `role_claims`, `mode`, `introspection`,
  `acting_for_claim`, `client_tokens` and `ca_file`; `IssuerEntry`'s
  `token_profile`, `acting_for_claim`, `client_tokens`,
  `clock_skew_seconds`, `jwks_max_age_seconds`,
  `jwks_refresh_interval_seconds` and `timeout_ms`;
  `IntrospectionSection::cache_max_age_seconds`;
  `BasicSection::cache_ttl_seconds`; `OauthSection`'s `ca_file`,
  `client_certificate_file`, `client_key_file`, `refresh_margin_ms`,
  `timeout_ms` and `previous_key_overlap_ms`; `DpopSection`'s
  `max_age_seconds` and `clock_skew_seconds`; the Entra table's
  `timeout_ms` and `max_response_bytes`; `PartySection::claim`),
  `OauthSection::removals`, `DpopSection::removals`,
  `ConfigError::Removed`, `ConfigError::RemovedKeys`,
  `PartyError::Claim`, and `IssuerKey`: `AuthSection::issuer` is a
  `Vec<IssuerEntry>`, so the flat `issuer = "…"` form is a type error.

### Changed

- Breaking: the crate builds on `ferrohealth-config` 0.4 and, behind
  `server-tls`, `ferrohealth-server` 0.8, the family's one breaking round
  of 2026-11-09: its sections name config 0.4's `Duration`, `ByteSize` and
  `TlsClientSection` (#396).
- `SECURITY.md` names `security@cadasto.com` as the email route for a
  vulnerability report, in place of `info@cadasto.com`, which stays the
  address for licensing and other business questions.
- Breaking: `ScopelessSubject` is a struct with `issuer` and `sub`; the
  string form of an entry is a type error (#388).

## [0.14.0] - 2026-11-09

A `persons` issuer reads the IHE IUA professional attributes and purposes
of use of its own professionals, and a `patients` token that names an
actor is the patient's representative or is refused. The settings, the
configuration and the profile gain public fields, so the line moves to
0.14.0.

The configuration moves onto the family types of `ferrohealth-config` 0.3
(FerroEHR #5259): one duration type, one outbound TLS table read by one
reader, one outbound endpoint table, and every retired key refused naming
its replacement. A product moves each key of its `[auth]` and
`[<lane>.credentials]` tables, in the same release.

### Added

- `[[auth.attributes]]` (`federation::person::AttributesSection`, the new
  `AuthSection::attributes`): one table per `persons` issuer maps the
  `federation::Field` set to claim and constant sources, `mapping = "iua"`
  reading the IHE IUA claims under `extensions.ihe_iua` (ITI TF-2
  §3.71.4.2.2.1.1), and `authorization_details_purposes = true` adds the
  `system|code` `purpose_of_use` of each RFC 9396 `authorization_details`
  entry. Every caller of the issuer but a `System` carries what its token
  states as `Caller::attributes` (`federation::person::Attributes`, with
  `field`, `fields`, `roles` and `purposes`, the purposes sorted and
  without duplicates). A claim of the wrong shape, a `subject_role` or
  `purpose_of_use` that is no array of codings, and a value with a control
  character or past its cap refuse the token as `Unclassified::Attribute`;
  an absent claim is an absent field. A table naming no trusted `persons`
  issuer, or naming one twice, refuses the start as the new
  `ConfigError::Attributes`, and an `authorization_details` or presentation
  source as `FederationError::Unattested` or `Presentations` (#376).
- `CallerKind::PatientRepresentative { actor }` and the profile key
  `act_represents_patient`: on a `patients` issuer that sets it, a token
  naming only the record subject and carrying an RFC 8693 §4.1 `act` is
  the patient's representative, the top-level actor's `iss` and `sub`
  read and a nested `act` left as informational. It is never
  `Caller::is_the_person`. The key on another kind of issuer refuses the
  issuer as `ProfileError::Kind` (#377).
- `config::endpoint::EndpointSection`, the shared table of an outbound
  integration: `url`, `timeout`, `connect_timeout`, `retry`
  (`config::endpoint::RetrySection`: `max_attempts`, `initial_backoff`,
  `max_backoff`), `tls` and `credentials`, with
  `EndpointSection::validate` (#379).
- `config::TlsBuilder`, the product's reader of an outbound `tls` table,
  and `config::ServerTls` (feature `server-tls`), which implements it over
  `ferrohealth-server`'s `tls_client::TlsClient`.
  `AuthSection::resolve_with_tls`, `CredentialsSection::resolve_with_tls`,
  `CredentialsSection::onward_with_tls` and `OauthSection::resolve_with_tls`
  resolve over it; `ConfigError::TlsNotBuilt` refuses a table that names
  material without it, and `ConfigError::TlsBuild` carries the builder's
  refusal (#379).
- Feature `schema`: `schemars::JsonSchema` on every configuration section,
  for a product that generates its configuration reference (#379).
- `ConfigError::RemovedKeys`, every retired key a section sets, named with
  its replacement, all at once, and `ConfigError::Endpoint` (#379).

### Changed

- A `patients` token that carries `act` on an issuer without
  `act_represents_patient` is refused as the new
  `Unclassified::PatientActor`, where it was classified `Patient`, the
  patient's own access. The onward check of a `patients` issuer's token
  keeps reading its `act` as the requesting client (#377).
- `resource::Settings`, `resource::introspection::IntrospectionSettings`
  and `config::AuthSection` gain the public field `attributes`, and
  `profile::Profile`, `profile::ProfileKeys` and `config::IssuerEntry` the
  public field `act_represents_patient`; a struct literal adds them or
  `..Default::default()` where the type has one (#376, #377).
- Breaking: every span of time is a `ferrohealth_config::units::Duration`
  (`"30s"`, `"10min"`) and its key names no unit: on `[[auth.issuer]]`
  `clock_skew`, `jwks_max_age`, `jwks_refresh_interval` and `timeout`;
  `introspection.cache_max_age`; `[auth.basic] cache_ttl`; `[auth.dpop]`
  `max_age` and `clock_skew`; on `[<lane>.credentials.oauth]`
  `refresh_margin`, `timeout` and `previous_key_overlap`; on the Graph table
  `timeout` and `max_response_size` (a `ByteSize`); and the profile key
  `max_onward_lifetime`, a bare number of seconds until now. Each old key is
  refused naming its replacement (#379).
- Breaking: `[auth] tls` and `[<lane>.credentials.oauth] tls`
  (`ferrohealth_config::tls::TlsClientSection`) replace `auth.ca_file` and
  the `oauth` table's `ca_file`, `client_certificate_file` and
  `client_key_file`, which are refused naming `tls.trust_roots_file` and
  `tls.client_identity_file`. The crate reads no TLS file: `client::Tls`
  holds the configuration the product built and the table's minimum
  version, which an engine with no built configuration negotiates at least.
  An introspection grant's calls use its own `tls` table, no longer merged
  with `auth.tls` (#379).
- Breaking: `client::Reach::with_min_tls_version` and `min_tls_version` take
  `ferrohealth_config::tls::TlsVersion` (#379).
- A section that sets several retired keys is refused once, naming every
  one, where it named only the first (#379).

### Removed

- Breaking: `config::Removed` (now `ferrohealth_config::removed::Removed`),
  `client::TlsVersion`, `ClientCredentials::with_mutual_tls` (a grant over a
  built configuration is `ClientCredentials::with_presented_tls`), the
  `root_certificates` and `identity` fields of `client::Tls`,
  `ConfigError::CaFile` and `ConfigError::Tls` (#379).

## [0.13.1] - 2026-11-09

A patch release that keeps a refused key set, introspection or metadata
body out of the errors that carried it.

### Security

- A refused key set, introspection or metadata answer kept its body, as
  received and up to 1 MiB, in the `body` field of
  `resource::ResourceError::KeySetStatus`,
  `resource::introspection::IntrospectionError::Status` and
  `metadata::DiscoveryError::Status`, and their `Debug` rendering printed
  it. A product that logged one of these errors with `{:?}` could write
  token, key or credential material an upstream or a proxy put in that body
  to its log. Affected: every release before 0.13.1 (CWE-532, CWE-209,
  GHSA-5qm7-v4fw-p2v9). `KeySetStatus` and `DiscoveryError::Status` now
  keep an empty `body`, since RFC 7517 and RFC 8414 define no error body,
  and `IntrospectionError::Status` keeps only the RFC 6749 §5.2 `error`
  code (RFC 7662 §2.3), cut to `client::MAX_ERROR_TEXT` characters and
  dropped when it leaves that section's character set, which its `Display`
  now names. The field types do not change. Upgrade step: move to 0.13.1;
  until then, log only the `Display` rendering of these errors (#373).

## [0.13.0] - 2026-11-09

A refusal of a JSON document the crate could not read no longer quotes the
document, and a grant can present the TLS identity a product already read.
The error type of the refusing variants and the fields of `client::Tls`
change, so the line moves to 0.13.0.

### Added

- `client::PresentedTls`, a rustls client configuration a product built
  from TLS material it read once (such as with `ferrohealth-server`'s
  `TlsClient`) with the end-entity certificate it presents.
  `ClientCredentials::with_presented_tls` authenticates over mutual TLS
  with it (RFC 8705 §2), and `OauthSection::resolve_with_tls` and
  `OauthSection::problems_with_tls` resolve and check the oauth table over
  it in place of `client_certificate_file`, `client_key_file` and
  `ca_file`, which the table then names none of. A `certificate_bound`
  grant compares the token's `x5t#S256` with the presented certificate
  (RFC 8705 §3). The crate reads no file and holds no key bytes for it
  (#357).
- `client::Tls::presented_certificate` and `Tls::presents_identity`, the
  certificate the connection presents from either source (#357).
- `Onward::invalidate(subject, actor, target, stale)`, the twin of
  `TokenSource::invalidate`: it drops the cached token `Onward::token`
  reads for the same arguments when it is the one `stale` renders, so the
  next call exchanges again after a resource server's `401`
  `invalid_token` (RFC 6750 §3.1). Other entries, and a token already
  renewed, stay (#364).

### Changed

- `client::Tls` gains the public field `presented`; a struct literal adds
  `presented: None` or `..Tls::default()`. `metadata::Http::with_tls` and
  `reaching` build the engine over a presented configuration, which keeps
  its own trust roots and protocol versions, and refuse PEM roots or a PEM
  identity beside it as the new `DiscoveryError::PresentedTlsTwice`. The
  introspection calls of a bearer source use the grant's presented
  configuration (#357).
- `OauthSection::resolve` reads `private_key_file`, with its previous and
  next keys, whatever the `client_auth`, so `[<lane>.credentials.onward]
  actor_assertion = true` names a mutual-TLS or client-secret client the
  actor with an assertion signed by that key (RFC 8693 §2.1). Under a
  method other than `private_key_jwt` the key signs the actor token alone
  and the request carries no `client_assertion`; under FAPI 2.0 it is held
  to §5.4.1's algorithms. A lane whose `private_key_file` signs nothing,
  under another method and without `actor_assertion`, is refused as the new
  `ConfigError::Unused`, and `previous_private_key_file` and
  `next_private_key_file` need `private_key_file` in place of
  `private_key_jwt` (#360).
- `client::TokenError::Refused` keeps the status and the RFC 6749 §5.2
  error, each member cut to the new `client::MAX_ERROR_TEXT` (256)
  characters, and no longer the raw body: its `body` field is removed, and
  neither its `Display` nor its `Debug` renders anything else of the
  answer. The onward refusal and `OnwardError::InteractionRequired` and
  `oidc::OidcError::Refused` bound their OAuth error the same way. The
  token endpoint's answer, of the client credentials grant and of the
  onward exchange, is read up to `metadata::MAX_DOCUMENT_BYTES` and a
  longer one is refused as `DiscoveryError::TooLarge`, which names the URL
  and quotes nothing (#361).
- The variants that refuse a JSON document carry `json::JsonError` in
  place of `serde_json::Error`: `resource::ResourceError::KeySet` and
  `KeySetRepeatedName`, `client::TokenError::Malformed`,
  `oidc::OidcError::Malformed` and `KeySetBody`,
  `metadata::DiscoveryError::Metadata` and `RepeatedName`,
  `resource::introspection::IntrospectionError::RepeatedName` and
  `Malformed`, `client::authorization_details::AuthorizationDetailsError::Json`
  and `Shape`, and `idp::entra::ReadError::Collection`.
  `metadata::repeats_no_name` returns a `JsonError`. A `JsonError` keeps the
  reader's `category()`, `line()` and `column()`, renders no part of the
  document and has no source. To upgrade, read `category()` where a product
  called `classify()` on the source (#351).

### Fixed

- A token endpoint that carries userinfo (RFC 9110 §4.2.4) or a fragment
  (RFC 6749 §3.2) is refused on the OAuth 2.0 path as the FAPI 2.0 path
  refused it: `OauthSection::resolve` and `problems` refuse a configured
  one as the new `ConfigError::TokenEndpoint`, and `ClientCredentials::validate`,
  `TokenSource` and the onward exchange refuse a programmatic or
  discovered one (`token_endpoint` or `mtls_endpoint_aliases.token_endpoint`)
  as the new `TokenError::TokenEndpointShape` before anything is sent.
  Neither quotes the URL. A query stays admitted (RFC 6749 §3.2) (#359).

### Security

Shipped with functional changes because: the fix is the change of the error type the Changed entry names, so the two cannot ship apart.

- A refusal of a JSON document the crate could not read carried
  `serde_json::Error` as its source, whose message quotes the value the
  reader stopped at. A product that logged the error chain could write a
  private or symmetric key from a `jwks_file` or `jwks_uri` key set, or an
  access, refresh or ID token from a malformed token endpoint response, to
  its log. Affected: every release before 0.13.0 (CWE-532, CWE-209,
  GHSA-mhv7-3975-6xq3). Upgrade step: move to 0.13.0; until then, log only
  the top-level display of these errors (#351).

## [0.12.0] - 2026-11-09

### Added

- The `[<lane>.credentials.onward]` table takes `actor_assertion`, `false`
  by default. `true` resolves the lane with
  `Onward::with_actor_assertion`, so every exchange sent without an actor
  token names the lane's client as its actor with an assertion signed by
  its `oauth` key ring (RFC 8693 §2.1, §3). A lane that cannot sign one,
  with no assertion key or under the JWT bearer grant, is refused as the
  new `ConfigError::OnwardActor` (#340).
- `client::assertion::AssertionKey::sign(typ, claims)` returns the compact
  JWS of a product's own claims, signed with the key's algorithm under its
  `kid` and the `typ` the product names (RFC 7515 §7.1, RFC 8725 §3.11), so
  `KeyRing::current()` signs the product's own tokens with the key its JWK
  Set publishes (#338). The client assertion is signed through it, as
  before with `typ` `JWT`.

### Changed

- **Breaking:** `config::onward::OnwardSection` gains the public field
  `actor_assertion` (#340). A struct literal that names every field no
  longer compiles: add the field, or write `..OnwardSection::default()`. A
  table read from TOML needs no change. Upgrade: pin
  `ferrohealth-smart = "=0.12.0"`. The `[workspace.dependencies]`
  requirement of `ferrohealth-smart` moves to 0.12.0.
- The config tables stay constructible with a struct literal: they are not
  `#[non_exhaustive]`, since products build them with
  `..Section::default()`, which `#[non_exhaustive]` forbids (#340).

### Fixed

- `AssertionKey::from_pem` without an algorithm signs an EC key with the
  algorithm of its curve: ES256 for P-256 and ES384 for P-384 (RFC 7518
  §3.4). A P-256 key was refused as `AssertionError::Public`, so an
  `[<lane>.credentials.oauth]` table with a P-256 `private_key_file` and no
  `assertion_alg` failed to resolve. An EC key on another curve is refused
  as the new `AssertionError::Curve` (#338).

## [0.11.0] - 2026-11-08

### Added

- The client half of sender-constrained tokens (#318).
  - `client::dpop::DpopKey` reads a P-256 (ES256) or P-384 (ES384) key and
    signs the RFC 9449 §4.2 proof of a request: `htm`, `htu` without query
    or fragment, `iat`, a fresh `jti`, and `ath` over the access token the
    request presents. It keeps the nonce each server sends per origin and
    per `Role`, so the token endpoint's nonce never reaches a resource (§9).
    `proof` and `remember` are public, which lets a product's own HTTP
    client prove its requests.
  - `ClientCredentials::with_dpop` binds a grant to a key. Every token
    request then carries a proof. A `400 use_dpop_nonce` is answered once,
    with a fresh client assertion (§8). Only a token of type `DPoP` is taken
    (§5), and it is sent as `Authorization: DPoP` (§7.1).
    `client::onward::exchange::Onward` does the same, and its cache key
    names the key, so a token bound to one key never serves a request proven
    with another.
  - `TokenSource::send` sends a call under the current token. Each `Attempt`
    carries the `Authorization` value and the attempt's proof. A resource's
    `401` naming `use_dpop_nonce` is answered once with a new proof (§9),
    and any other `401` renews the token once.
  - `ClientCredentials::with_certificate_binding` takes only a token whose
    stated `cnf."x5t#S256"`, in the token response or the JWT claim, names
    the certificate the grant presents (RFC 8705 §3.1, §3.2). The check runs
    before the token is cached or used. A token confirmed by another method
    is refused, and an opaque token that states no binding passes as sent.
  - The `[<lane>.credentials.oauth]` table takes `dpop_key_file` and
    `certificate_bound`, one or the other.
  - `client::binding::IssuedToken` holds the access token and its key for a
    product that composes its own `Authorization` field. `Token` and
    `OnwardToken` hand it out through `AsRef`.
- A rotating key ring, the FAPI 2.0 Security Profile and RFC 9396
  `authorization_details` on a client grant (#319).
  - `client::keys::KeyRing` signs with its current key and publishes its JWK
    Set (RFC 7517 §5), each key under its RFC 7638 thumbprint unless a `kid`
    is configured. The previous key stays published, never signing, for an
    overlap window or until the ring is rebuilt without it. The next key is
    published ahead of a rotation and never signs. The ring is shared as an
    `Arc` through `ClientCredentials::with_key_ring` and
    `ClientCredentials::assertion_keys`.
  - `client::fapi2` holds a grant whose `profile` is `SecurityProfile::Fapi2`
    to FAPI 2.0 §5.3.3.1 and §5.4.1 when it is built: a discovered issuer,
    `private_key_jwt` with the issuer as the one-string `aud` or mutual TLS,
    `PS256`, `ES256` or `EdDSA` keys, sender-constrained tokens, and a scope
    or `authorization_details`. Before the token endpoint is reached, its
    metadata must be `application/json` and list the client's method,
    algorithm, grant types and proof algorithm. The token endpoint must sit
    on the issuer's origin, or a mutual-TLS alias on a host the grant names
    (RFC 8705 §5), and `tls_client_certificate_bound_access_tokens` must be
    true for a certificate-bound grant (§3.3).
  - `client::authorization_details::AuthorizationDetails` holds the RFC 9396
    §2 shape. A grant sends its details on the client credentials request
    and the token exchange (§6), refuses a type the discovered metadata does
    not list (§10), and refuses a response that states no granted details,
    or ones not of §2 shape (§7). `IssuedToken::authorization_details`
    returns what was granted.
  - The `[<lane>.credentials.oauth]` table takes `security_profile`,
    `mtls_alias_hosts`, `previous_private_key_file`,
    `previous_key_overlap_ms`, `next_private_key_file` and
    `authorization_details`. It checks the resolved grant as
    `ClientCredentials::validate` does, so a FAPI 2.0 table that breaks a
    rule refuses the start.
  - `ServerMetadata` reads `token_endpoint_auth_signing_alg_values_supported`,
    `dpop_signing_alg_values_supported`,
    `authorization_details_types_supported` and
    `tls_client_certificate_bound_access_tokens`.
- `client::onward::exchange::Onward::with_actor_assertion` names the
  requesting client as the actor of a token exchange without an actor token
  (#321). The `actor_token` is an RFC 7523 assertion signed for each request
  with the current key of the grant's ring, with the claims and `aud` of its
  client assertion and a `jti` of its own, and the JWT type (RFC 8693 §2.1,
  §3). The cache key names the mode in place of a token hash.

### Changed

- **Breaking:** these changes ship with #318. To upgrade, pin
  `ferrohealth-smart = "=0.11.0"`.
  - `client::ClientCredentials` gains the public field `token_binding`, and
    `config::OauthSection` gains `dpop_key_file` and `certificate_bound`. A
    struct literal that names every field no longer compiles: add the new
    fields, or write `..Default::default()` on the section. A table read
    from TOML needs no change.
  - `client::TokenError::TokenType` gains the field `expected`, the type the
    grant asked for.
  - `client::cache::Answered` gains the required method `headers`, which the
    crate's `http::Response` and `reqwest::Response` implementations supply.
  - `client::CallError` gains `Unproven`, which `TokenSource::call` returns
    for a `DPoP`-bound source without sending anything, and `Proof`.
    `TokenSource::send` is the call path for such a source.
  - `client::ClientCredentials::assertion_key`, one `AssertionKey`, becomes
    `assertion_keys`, a shared `KeyRing`, and the struct gains
    `authorization_details` and `profile` (#319). `with_private_key_jwt`
    still takes one key. `ServerMetadata` and `config::OauthSection` gain
    public fields, and `config::OauthSection::resolve` now refuses a grant
    that `ClientCredentials::validate` refuses.
  - The `[workspace.dependencies]` requirement of `ferrohealth-smart` moves
    to 0.11.0.
- **Breaking:** `federation::assertion::Validator::new` takes a third
  argument, the `replay::ReplayGuard` every admitted exchange is recorded
  in, and `Validator::exchange(identity, treatment, now)`, async, replaces
  `Validator::identity` and `Validator::treatment` (#317). It checks the
  identity assertion alone, as the discovery phase presents it, or with
  one TRC, and returns an `Exchange` with `identity()`, `treatment()`,
  `ends()` and `claim()`. Upgrade: build the validator with
  `Arc::new(MemoryReplayGuard::default())` in one process, or with a
  `ReplayGuard` over a store every replica shares; call
  `exchange(&ida, trc.as_deref(), now)` in place of the two checks; cap
  the issued token's `exp` at `Exchange::ends()`; and answer
  `ExchangeError::Guard` as a server error (`code()` is
  `ERROR_SEC_GENERIC`). `IdentityAssertion` and `TreatmentAssertion`
  replace `not_before()` and `not_on_or_after()` with `window()`, a
  `Window` that also carries `session_not_on_or_after()` and `ends()`:
  write `assertion.window().not_on_or_after()`.
- `config::AuthSection::resolve` refuses three things a verifier must not
  start with (#320). It refuses an `[[auth.issuer]]` URL that carries
  userinfo as `ConfigError::IssuerUserinfo`, masked (OpenID Connect Core
  1.0 §1.2). It refuses a `jwks_file` holding a symmetric key or private
  key material as `ConfigError::JwksSymmetricKey` or `JwksPrivateKey`,
  naming the key's index, `kid` and member and never a value. It refuses a
  Basic user's Argon2id hash below the OWASP floor `m=19456,t=2,p=1` as
  `StoreError::Weak`, which `basic::Store::with_user` now applies too.
  Upgrade: rehash a weaker Basic password, and remove secret keys from a
  `jwks_file`.
- **Breaking:** `config::CredentialsSection`, `config::OauthSection` and
  `config::Outbound` move to `config::credentials`, the module that
  resolves them, so `config/mod.rs` stays under the 750-line split
  threshold (#329). The checks of one `[[auth.issuer]]` table move into
  `config::issuer` and stay private. Nothing else changes. Upgrade: import
  `ferrohealth_smart::config::credentials::{CredentialsSection,
  OauthSection, Outbound}`.

### Fixed

- `federation::assertion::Validator` translates every `\r\n` and every
  lone `\r` of an assertion to `\n` before parsing it, as XML 1.0 §2.11
  has a processor do (#316). `roxmltree` 0.21 left a literal carriage
  return directly before an entity or character reference untranslated, so
  the canonical form wrote `&#xD;` where a conformant signer wrote a line
  feed, and a correctly signed assertion was refused as `Integrity::Digest`.
  A carriage return written as `&#xD;` still canonicalizes to `&#xD;`
  (C14N 1.0 §2.3).
- A contact-point token that carries no TRC and no `patient.id`, the
  discovery-phase token `identity::ehdsi_claim(identity, None)` writes, is
  admitted and held to the identity assertion's window (#314). It was
  refused `ERROR_SEC_DATA_INTEGRITY_NOT_ENSURED`, although the TRC is issued
  only once the patient is identified (eHDSI SAML Profile 10.0.0 §4).
  `External::trc_patient` reads no patient from such a token, so a product
  still refuses patient data under it. A token that carries any TRC field
  or a `patient.id` must carry `trc.id` and both TRC window bounds.

### Security

Shipped with functional changes because: the replay fix (#317) changes the `federation::assertion::Validator` API, so the eHDSI security fixes ship on the 0.11.0 line, whose other breaking change (#318) the products take in the same move.

- `federation::assertion::Validator` bounds an assertion before it is
  parsed (#315). An input of 64 KiB with 2500 nested elements, each
  declaring a fresh namespace prefix, cost about 5.5 s of CPU in the parse
  before any check ran, and about 440 MB in the canonicalization when
  `ds:KeyInfo` named a trusted seal; it needed no valid signature (since
  0.10.0) (CWE-407, CWE-776, GHSA-6x8h-rrm4-6xp3). A linear pre-scan now
  refuses an input nested deeper than 32 elements or declaring more than
  128 namespaces as `Integrity::Malformed`, and the canonicalization keeps
  one namespace map with an undo log. The caps are our own design, well
  above an eHDSI assertion's 7 levels and about 50 declarations.
- `federation::assertion::Validator` holds an eHDSI assertion's instants
  to the clock and admits each exchange once (#317). It refused none of
  these: an `IssueInstant` in the future or at or after `NotOnOrAfter`, an
  `AuthnInstant` after the `IssueInstant`, or a `SessionNotOnOrAfter` in
  the past. The same IdA and TRC could also be exchanged again while their
  windows were open (since 0.10.0) (CWE-294, CWE-613, GHSA-vh6g-jqfw-g8pm).
  Each is now refused within the 60 s drift (SAML 2.0 Core §2.3.3,
  §2.7.2), as `Integrity::Issued`, `Authenticated`, `SessionEnded` and
  `Replayed`. `session_not_on_or_after()` returns the session end. The
  module docs state the caller's obligation: authenticate the presenting
  party as acting for the sender-vouches issuer (eHDSI Messaging Profile
  10.0.0 §5.5.2). An assertion whose `InclusiveNamespaces` lists `xs`, as
  OpenSAML signers often do, stays refused (Cryptographic Algorithms 9.0.0
  §4.1).

## [0.10.1] - 2026-11-08

### Added

- `federation::contact::TrcPatientId`, the one definition of the patient a
  Treatment Relationship Confirmation binds (#310). `from_cx` reads the
  TRC's `subject-id` in its CX form, `value^^^&<oid>&ISO` (eHDSI SAML
  Profile 10.0.0 §4.3), with the assigning authority as the system
  `urn:oid:<oid>`. `claim` and `from_claim` write and read the
  contact-point token's `patient.id` as one `system|value`, and its `Debug`
  carries no value. `External::trc_patient` reads a token's patient through
  it, and `TreatmentAssertion::patient` returns the TRC's. A resource
  server reads the TRC patient through this type in place of a parser of
  its own.

### Fixed

- `identity::ehdsi_claim` writes `patient.id` as `urn:oid:<oid>|<value>`,
  the `system|value` token FerroFED and FerroEHR read, in place of the TRC
  `subject-id` verbatim, which they refused (#310). A TRC whose
  `subject-id` is not a CX with an ISO OID assigning authority is refused
  `ERROR_SEC_DATA_INTEGRITY_NOT_ENSURED`, naming `patient.id`.
- The `keycloak` preset reads a Keycloak 26.8 impersonation as it is
  issued (#308): every token of an impersonation session carries an RFC
  8693 `act` claim naming the impersonator, with no `act.iss` (Keycloak
  26.8.0 release notes), so it is admitted as `Delegated` only when
  `delegates` lists the impersonator and refused as an unlisted actor
  otherwise. The preset no longer says an impersonation reaches no claim.
  To refuse every impersonation, add Keycloak's built-in IMPERSONATOR_ID
  and IMPERSONATOR_USERNAME mappers and set `impersonation_marker =
  "impersonator"`. The Keycloak release notes chapter and the two sources
  it rests on are vendored under `docs/specs/keycloak-docs/`.

## [0.10.0] - 2026-11-08

### Added

- A `[<lane>.credentials.onward]` table takes `cache` (#299). `cache =
  false` turns the lane's onward token cache off, so every call exchanges a
  token at the issuer and none is held, with a warning logged at load; it
  is a setting for a performance measurement's self-test
  (FerroHEALTH/FerroFED#1712), never for production, and the cache stays
  on by default. `client::onward::exchange::Onward::caches` reports the
  setting.
- `federation::assertion`, behind the new `ehdsi-assertion` feature,
  checks the eHDSI HP Identity Assertion and Treatment Relationship
  Confirmation for an authorization server acting for a MyHealth@EU
  contact point (#294). `Validator::identity` and `Validator::treatment`
  verify the enveloped XML signature (eHDSI Cryptographic Algorithms 9.0.0
  §4.1) by a `TrustedSigner` in one accepted shape, refusing an unsigned,
  wrongly signed or wrapped assertion; refuse an RSA key below 3000 bits, a
  hash below SHA-256 and an elliptic curve (SOG-IS ACM 1.3, Cryptographic
  Algorithms 9.0.0 §2); and check the issuer, the audience, the window with
  60 s of drift, sender-vouches, the attributes of SAML Profile 10.0.0 §2.3
  and the TRC's link to the IdA (§4.1). The values come back as typed
  `IdentityAssertion` and `TreatmentAssertion`, whose `Debug` carries no
  assertion content, and `identity::ehdsi_claim` writes them as the
  contact-point token's `ehdsi` claim. `AssertionError::code` names each
  refusal's MyHealth@EU Requirements Catalogue 10.0.0 §1.25 code. The
  feature adds `roxmltree` and `x509-parser`.
- The onward check holds a token issued for a MyHealth@EU contact-point
  caller within the caller's assertion windows (#295): its `exp` may not
  pass the HP Identity Assertion's `assertion.not_on_or_after` or the
  Treatment Relationship Confirmation's `trc.not_on_or_after`, each when
  the caller carries it, plus 60 s of drift (eHDSI SAML Profile 10.0.0
  §2.1, §4.1). A token past either is refused as
  `client::onward::Rejected::AssertionWindow`, whose
  `client::onward::AssertionWindow` names the window and its field; an
  unreadable window end is refused too. A caller without those fields is
  checked as before.

### Changed

- **Breaking:** `config::onward::OnwardSection` gains the public field
  `cache` (#299), so a struct literal that names every field no longer
  compiles. A product that builds an `OnwardSection` in code adds
  `cache: true`, or writes `..OnwardSection::default()`; a table read from
  TOML needs no change, since the key defaults to `true`. The
  `[workspace.dependencies]` requirement of `ferrohealth-smart` moves to
  0.10.0. To upgrade, pin `ferrohealth-smart = "=0.10.0"`.

## [0.9.4] - 2026-11-07

### Added

- The MyHealth@EU contact-point profile reads the format of the HP
  Identity Assertion's `NameID` as the field `assertion.name_id_format`
  (eHDSI SAML Profile 10.0.0 §2.1), mapped by `mapping = "ehdsi"` from
  `ehdsi.assertion.name_id_format`, and `Caller::name_id` returns the
  `NameID` (`professional.hp_identifier`) with its format as a
  `federation::contact::NameId`, so a product writes the professional's
  identifier with the format it was asserted under (#291).
  `federation::contact::NameIdFormat` names the three formats §2.1 allows
  and parses each from its URN. The format is one string: a coded value
  refuses the token as `Unclassified::Attribute` naming the field.

### Changed

- A contact-point token without `assertion.name_id_format`, or with a
  format other than the three of eHDSI SAML Profile 10.0.0 §2.1, is
  refused as `ERROR_HPI_INSUFFICIENT_INFORMATION` naming the field, as a
  missing `NameID` is (#291). A contact point's authorization server must
  now write the format into its tokens.

## [0.9.3] - 2026-11-07

### Added

- A `federation` issuer's table maps the field `consent.reference`, the
  reference of the consent decision the issuer rendered its authorization
  on (the Consent entity of the IHE BALP 1.1.4 3:5.7.6 consent decision
  record), and `Caller::consent_reference` returns it as a
  `federation::ConsentReference` for an external person or organisation
  whose token carries it, so a product reads it for a consent-conditioned
  federation read (#286). The reference is one string: a coded value
  refuses the token as `Unclassified::Attribute` naming the field. The
  onward check holds the token a `federation` issuer issues to the
  subject's reference, read under that issuer's own table, and refuses one
  that drops or changes it as `Rejected::Consent`. `CallerKind::external`
  returns what the token asserts for either external kind.
- A `federation` issuer's table maps the field `correlation_id`, the log
  correlation id of a chained organisation request, and
  `Caller::correlation_id` returns it as a `federation::CorrelationId` for
  an external person or organisation whose token carries it, read only from
  a claim of the verified token or an attested `authorization_details`
  member and never from a header (#287). A coded value refuses the token as
  `Unclassified::Attribute`. The onward check holds the token a
  `federation` issuer issues to the subject's id, read under that issuer's
  own table, and refuses one that drops or changes it as
  `Rejected::Correlation`.

### Changed

- A chained route (`Target::with_correlation_claim`) refuses a subject
  token without its correlation claim before anything is sent, as
  `OnwardError::NoCorrelation`, where the issued token was refused as
  `Rejected::Correlation` after the exchange (#287).

## [0.9.2] - 2026-11-06

### Added

- `refusal::Denied::ehdsi` returns the MyHealth@EU Requirements Catalogue
  10.0.0 §1.25 code the contact-point check refused a token with, so a
  product that answers a national contact point through the gate reads the
  code from the refusal (#281). `federation::contact::EhdsiCode::requirement`
  names the catalogue requirement each code answers. The code stays off the
  challenge, and a refusal before the contact-point check carries none.
- The onward client exchanges a patient's own token at a `patients` issuer,
  a deployment's separate patients realm or tenant, by token exchange
  (RFC 8693) or the JWT bearer grant (Entra ID's on-behalf-of flow), so a
  product reaches its upstream as the patient (#282).
  `[<lane>.credentials.onward]` accepts `kind = "patients"`. The issued
  token must read as a patient token of that issuer and carry the subject
  token's `patient`, `ehrId` and the deployment's `PatientClaim` with the
  same values, or it is refused as `Rejected::Patient` or
  `Rejected::PatientContext`. A caller that is not a patient is refused
  before anything is sent with `OnwardError::PatientRequired`, and a
  patient whose token names no patient context with
  `OnwardError::NoPatientContext`.

## [0.9.1] - 2026-11-06

### Added

- The `test-support` feature, for a downstream crate's tests only:
  `federation::External::new` builds the party that
  `CallerKind::ExternalPerson` and `ExternalOrganisation` carry, so a
  policy over the two external kinds can be tested without a `federation`
  token (#272). It runs none of the classification's checks, and a product
  never enables it outside its tests.

### Security

Shipped with functional changes because: the one other change, the `test-support` feature, is off by default and adds nothing to a build that does not enable it, so a product taking 0.9.1 gets the security fix alone.

- A Basic user never carries a `system/` scope (#274). An
  `[[auth.basic.users]]` entry granted one fails to load as
  `ConfigError::Basic` with `basic::StoreError::SystemScope`, naming the
  user and the scope, and `resource::Caller::basic` drops every `system/`
  scope it is handed. In 0.9.0 a Basic credential was a person, yet a
  `system/` scope still loaded and gave that person caller every resource
  of a type, the reach of a backend service (CWE-269, CWE-863,
  GHSA-jhg2-jwjp-hq74). Upgrade step: give each Basic user the `user/`
  scopes a person holds, and move each machine on Basic to a client of the
  authorization server under the client credentials grant (RFC 6749
  §4.4), of a `machines` or `persons` issuer.

## [0.9.0] - 2026-11-06

The caller classification (#215) and the party binding (#216). This
release breaks the public configuration and API: every product moves its
`[auth]` section to the issuer tables below and reads who called from
`Caller::kind`.

### Added

- `kind::CallerKind`, read through `Caller::kind`: who stands behind a
  credential, `Patient`, `System`, `Delegated` (with the RFC 8693 actor
  when there is one), `Representative` (the represented subject and the
  ground as asserted), `Person` or `Guest` wrapping the kind it would
  otherwise have. A valid token that matches no step for its issuer's kind
  is refused as `Rejection::Unclassified`, an `invalid_token` on the wire
  whose `kind::Unclassified` reason names the step. The audit line records
  the kind in its new `kind` field.
- `kind::IssuerKind` and the required `kind` key of every
  `[[auth.issuer]]`: `persons`, `patients`, `machines` or `federation`.
  A `federation` issuer needs its one `[[auth.federation]]` table
  (`ConfigError::Federation` otherwise).
- `federation`: what a `federation` issuer asserts about another party.
  `[[auth.federation]]` (`FederationSection`) maps each field, named after
  the 2026/2099 Annex Tables 1 and 2, to a claim path (`mapping = "iua"`
  for the IHE IUA claims), a constant, an attested RFC 9396
  `authorization_details` entry whose `locations` names this node, or a
  Nuts RFC021 presentation. `CallerKind::ExternalPerson` and
  `ExternalOrganisation` carry the `External` fields as asserted and the
  remote `sub`, never bound. A partial professional is refused naming the
  missing fields; the declared countries, issuing authorities and provider
  identifier prefixes bound every attribute; a control or bidi-control
  character, two disagreeing sources and a professional below level
  substantial are refused. Strings are compared exactly (RFC 9396 §12).
- `federation::contact`: the MyHealth@EU contact-point profile. A
  `contact_point = true` issuer (`mapping = "ehdsi"`) requires
  `sender_constraint = "required"` and fails to load without it
  (`ResourceError::ContactPointSender`, #220), takes no provider prefixes,
  and configures its country and issuing authority. Its tokens carry the
  eHDSI SAML Profile 10.0.0 §2.3 attributes, and each refusal carries its
  Requirements Catalogue 10.0.0 §1.25 code name (`EhdsiCode`,
  `Unclassified::ContactPoint`); `EhdsiCode::of` names any rejection, an
  unreadable key set or upstream as `ERROR_SEC_GENERIC` (requirement 11),
  since §1.25 gives that case no code of its own (#238). A
  token never outlives the identity assertion or the TRC window, any of
  the seven authentication classes is admitted and recorded, and nothing
  is refused on the description, the role or the point of care.
- `profile = "nl"` (#238): the harmonised BgZ and eOverdracht
  authentication of the openEHR Federation Tier specification 1.0.1 Annex
  B §B.4a, for a `federation` issuer that is one requesting care provider.
  Its `nl-gis-v1` `authorization_details` entry is attested and is the
  organisation's access statement; `purpose_of_use` and
  `nl.organisation_type` are read from it, and the deployment configures
  the issuer's `nl.ura`. The issuer requires `sender_constraint =
  "required"` and its own `token_types`, and a token missing the purpose,
  the organisation type or the URA is refused as
  `Unclassified::RequiredFields`. Every value cites its Annex B section.
- A preset file may carry `[[auth.federation]]` defaults
  (`Preset::federation`), which the issuer's own table is set over
  (`FederationSection::over`); an issuer of another kind refuses them. The
  federation table gains `required_fields`, the fields every token must
  carry, and `requires_sender_constraint`, which refuses the issuer without
  `sender_constraint = "required"` (`ResourceError::SenderConstraintRequired`).
- `profile`: each issuer's `Profile`, a `Preset` (`profile = "rfc9068"`,
  `"entra"`, `"keycloak"`, `"okta"` or `"nl"`, shipped as `profiles/*.toml` with
  each value labelled by its source) with any profile key set over it on
  the issuer table: `person_key`, `tenant_claim`, `client_claims`,
  `app_only`, `guest`, `impersonation_marker`, `expect`, `user_claims`,
  `person_equality`, `unstable_claims`, `first_party_clients`,
  `delegates`, `max_actor_chain`, `representation`, `token_types`,
  `required_claims`, `scope_claim`, `app_only_scope_claim` and `adapter`.
  A profile naming an adapter refuses its issuer, since this build
  compiles none. `email`, `phone_number`, `preferred_username` and `name`
  are never accepted as an identifier (OpenID Connect Core 1.0 §5.7).
- `Caller::person_key`, `Caller::tenant` and `Caller::assurance`.
- The `keycloak` preset documents how to mark an impersonation: map the
  `IMPERSONATOR_ID` session note into a claim with a User Session Note
  mapper and name that claim in `impersonation_marker`; the preset names
  none. The `okta` preset cites the page as re-pinned on 2026-11-05.
- `IssuerSet::with_introspector`: one set verifies JWT and introspected
  issuers together, routing a token with a readable `iss` to its issuer
  and an opaque token to the one introspected issuer.
- `config::Resolved::check_role_issuers`, which refuses a product's
  administrator, emergency or identifier-reader role list naming an
  issuer that is not a trusted `persons` issuer.
- `sender`: sender-constrained tokens (#220), bound to a DPoP key
  (RFC 9449) or to the client certificate of the mutual-TLS connection
  (RFC 8705 §3). Each `[[auth.issuer]]` takes `sender_constraint`,
  `"none"` by default or `"required"`, under which only a token whose
  `cnf` names a `jkt` or an `x5t#S256` is admitted. On every issuer a
  token that carries `cnf` is held to it and is never accepted as a plain
  bearer token, and a `cnf` naming any other method is refused. Each
  refusal is a `Rejection::Invalid` whose `Reason::Sender` names the
  failed `sender::Check`.
- `sender::proof::ProofCheck`, every check of RFC 9449 §4.3 over the
  `DPoP` header of a `DPoP` request, with the `htu` compared with the
  configured external base URL plus the request path. The `[auth.dpop]`
  table (`external_url`, `max_age_seconds` 60, `clock_skew_seconds` 10,
  `algorithms`) resolves to `Resolved::dpop`, and `Gate::with_dpop`
  admits the `DPoP` scheme. A refused proof answers
  `DPoP error="invalid_dpop_proof"`, a refused `DPoP` token
  `DPoP error="invalid_token"`, and a missing credential is challenged
  with `DPoP` beside `Bearer`.
- `sender::replay::ReplayStore`, the product's store of accepted proof
  `jti`s (RFC 9449 §11.1), and `MemoryReplayStore`, its in-memory
  default, which refuses a replay to the process that saw the proof
  alone. A product that runs more than one replica supplies a store they
  share. A store that fails answers `503`.
- `sender::ClientCertificate`, which a product puts in a request's
  extensions for the gate to hold a certificate-bound token to;
  `Verifier::verify_bound`, `ResourceServer::authenticate_bound`,
  `LazyResourceServer::authenticate_bound`,
  `Introspector::authenticate_bound` and `Gate::authenticate_request`.
- `client::onward`, the onward grants (#217): `exchange::Onward` obtains a
  token for another service on behalf of a verified caller, by RFC 8693
  token exchange (`subject_token`, an optional `actor_token`, the target as
  `resource` or `audience`) or the RFC 7523 JWT bearer grant (`assertion`
  and `scope`), as the issuer's profile names, authenticating as its
  `ClientCredentials` say. The issued token is refused unless its `iss` is
  the issuer asked, its `aud` lies inside the `Target`'s audiences, its
  `exp` is within `max_onward_lifetime` of its `iat`, it carries the
  profile's `expect`, it names the requesting client as its actor, and it
  names the caller's person: by `person_equality` on a `persons` issuer, by
  the attested `person_mapping` on a `federation` issuer. Every refusal is
  a typed `OnwardError`, an upstream refusal with its status and
  `interaction_required` with its claims challenge; a JWT bearer grant for
  a `System` caller is refused before sending (`UserPrincipalRequired`),
  `offline_access` is never sent and a refresh token never accepted. The
  token is cached by issuer, grant, subject and actor token, target, scope
  and extra parameters until a margin before the earlier of its own and the
  subject token's `exp`, and the check runs again on every hit.
- The profile keys `max_onward_lifetime`, `onward_grant`,
  `onward_indicator`, `onward_parameters`, `onward_client_id`,
  `onward_subject_audience` and `onward_preview` (`profile::onward`), on
  `[[auth.issuer]]` as on every preset: `entra` is the on-behalf-of flow,
  `keycloak` the standard token exchange with delegation refused as
  Preview. A parameter the client writes itself, a `requested_token_type`
  naming a refresh token and a lifetime of 0 refuse the issuer at load.
- `exchanges_from` and `person_mapping` on `[[auth.federation]]`, which a
  federation issuer of onward tokens requires.
- `[<lane>.credentials.onward]` (`config::onward::OnwardSection`, #246):
  the onward target of a lane, with the issuer of its onward tokens
  described in the table (`issuer`, `kind`, `profile`, `[onward.keys]`,
  `[onward.federation]`, `[onward.assurance]`), its `audiences`,
  `indicators`, `scope` and `correlation_claim`, and an optional
  `token_endpoint` and `client_id`. It authenticates with the lane's
  `oauth` table, so its secret or key comes through the same `_file`
  keys. `CredentialsSection::onward` resolves it into an
  `config::onward::OnwardLane` (the `Onward` client and its `Target`) and
  refuses at load a table missing `issuer`, `kind` or `audiences`, beside
  a Basic `user` or without `oauth`, a profile its issuer's rules refuse,
  an issuer the onward client refuses (`ConfigError::Onward`) and a target
  its grant cannot ask for. `Onward::check_target` runs the target checks
  on their own.

- `party`: the party a person's login belongs to (#216). One
  `[[auth.party]]` table (`party::config::PartySection`) per `persons`
  issuer names the `identifier_issuer` and `identifier_type` its logins are
  matched against, and the `group_claim` and `group_identifier_issuer` its
  groups are read under; it has no `claim` key, since the issuer profile's
  `person_key` is the key, and `guests = true` looks a guest up. The product
  implements `party::source::PartySource` over its own store, and
  `party::binding::PartyBinding::resolve` looks a `Person`, `Delegated` or
  `Representative` caller, or a Basic user by the key
  `PartyBinding::with_basic_user` maps it to, up on every request, with no
  cache, into one `party::Outcome`: `Party` (the reference, the identifier
  that matched, the markers, the groups the token names that the party
  belongs to, its representation relationships, provisional and guest),
  `WrongMarker`, `Unbound`, `Ambiguous`, `Inactive`, `Abandoned`,
  `Deprovisioned`, `KeyClaimMissing` or `GroupsUnavailable`. `Patient`,
  `System` and external callers are never looked up. A failing source is a
  `SourceError`, never `Unbound`. A key of the `guid` or `uuid` type is
  compared in lower case.
- `party::adapter::IdpAdapter`, the vendor adapter seam a profile's
  `adapter` names: on a groups overage marker (`_claim_names` naming the
  group claim, or `hasgroups = true`) the adapter registered with
  `PartyBinding::with_adapter` is called before the outcome is decided, and
  its failure is `GroupsUnavailable` carrying the upstream status and
  `Retry-After` (`party::adapter::AdapterError`).
- `Gate::with_party`: the guard looks every admitted caller up and leaves
  the outcome on it (`Caller::party`, `Access::party`); a failing source
  answers `503`. `Caller::with_party` attaches an outcome a product
  resolved itself, and `PasswordStore::users` lists the Basic users, which
  `PartyBinding::check_basic` holds to a key each.
- The audit line records what the login resolved to in its new `binding`
  field (`source_unavailable` when the source failed, `-` when not looked
  up) and the party reference in `party`, never a party attribute.
- `ConfigError::Party`, naming an `[[auth.party]]` table that sets `claim`
  (with the profile's `person_key`), names no trusted `persons` issuer,
  shares its issuer or its `identifier_issuer` with another table (naming
  both), or sets `group_claim` without `group_identifier_issuer`.
- The `idp-entra` feature and `idp::entra::GraphAdapter` (#221): an Entra
  ID groups overage (`_claim_names` naming `groups`, or `hasgroups`) is
  resolved through Microsoft Graph at
  `{base_url}/users/{oid}/getMemberObjects`, or
  `/servicePrincipals/{oid}/getMemberObjects` for an `idtyp` of `app`,
  built from the token's `oid` and `idtyp` and never from
  `_claim_sources`, under a client-credentials token. An issuer turns it on
  with `adapter = "idp-entra"`; the product builds it from an
  `idp::entra::GraphSection` (`base_url`, `timeout_ms` of 2000 by default,
  `max_response_bytes`, `security_enabled_only`, `credentials`) and
  registers it under `idp::entra::NAME`. Every Graph failure is
  `GroupsUnavailable` with the status and the `Retry-After` of a `429`,
  the timeout, or the unreadable cause; nothing is cached, and each
  request of a user above the overage limit costs one Graph round trip
  outside the product's lookup budget. `idp::COMPILED` lists the adapters
  a build compiles in, and a profile naming any other adapter fails to
  load, naming it (`ProfileError::Adapter`).
- `AdapterError::Claim`: the token lacks or misforms a claim the adapter
  reads, and nothing was called.
- `AdapterError::Status` carries `body`, a `party::adapter::BodyExcerpt` of
  the error body the identity provider answered with (#261), which its
  message ends with: at most 256 characters, control characters as spaces,
  and every string and number of the caller's token claims, the subject and
  every compact JWS replaced by `***`. The Graph adapter reads the body of
  every refusal up to `max_response_bytes`; a body it cannot read leaves
  the status and no excerpt. An adapter of a product's own builds the
  excerpt with `BodyExcerpt::new`.

### Changed

- Every issuer setting lives on its own `[[auth.issuer]]` table, with no
  section-level fallback: `audience`, `algorithms`, `clock_skew_seconds`,
  `jwks_max_age_seconds`, `jwks_refresh_interval_seconds`, `jwks_file`,
  `timeout_ms`, `mode`, `introspection` (now `[auth.issuer.introspection]`),
  `role_claims` and the new `assurance` table. Upgrade: move each key onto
  every issuer table it held for; a section-level key fails to load naming
  the table (`ConfigError::Removed`).
- `scopeless_subjects` entries are tables, `{ issuer, sub }`, and admit only
  a `System` caller of that issuer. Upgrade: rewrite each string, bare or
  `<issuer>#<sub>`, as a table; a string fails to load.
- A Basic credential is always a `CallerKind::Person`, never a `System`:
  a machine authenticates with the client credentials grant (RFC 6749
  §4.4). Upgrade: move each machine on Basic to a client credentials
  client of a `machines` or `persons` issuer.
- `Caller::is_the_person` holds for a `Patient` caller alone: a token of a
  `patients` issuer whose scopes are `patient/` with no `user/` or
  `system/` grant. A `persons` token whose only clinical scopes are
  `patient/` is a professional confined to its launch context. Upgrade:
  give patients and professionals separate issuers (a realm or tenant
  each), the patients' with `kind = "patients"`.
- A `persons` token is admitted only through a client the issuer lists in
  `first_party_clients` or `delegates`. Upgrade: list the deployment's own
  clients in `first_party_clients`.
- `Caller::client_id` is the client the profile's `client_claims` name
  (`client_id` by default, `azp` under `entra` and `keycloak`, `cid` under
  `okta`).
- `Caller::new` and `resource::Settings::new` take the kind, and
  `introspection::IntrospectionSettings::new` takes the kind after the
  authentication; `Resolved::introspection` is a list, one entry per
  introspected issuer; `assurance::AssuranceSection::assess` reads a
  token's claims, and `meets` the caller's assessment.
- An introspection response with `token_type = "DPoP"` is admitted when
  it names a `cnf.jkt`, and checked against the `DPoP` request's proof;
  one that names a `jkt` under `Bearer`, or `DPoP` without a `jkt`, is
  refused. A held response is checked against each request's binding.
- `refusal::Schemes` has a `dpop` field and `Refusal` the
  `InvalidDpopToken` and `InvalidDpopProof` variants. Upgrade: a product
  that builds `Schemes` sets `dpop: false`, and a product that matches
  `Refusal` exhaustively answers both with the challenge the crate
  renders. `Gate::authenticate` reads no request line, so it refuses a
  `DPoP` request and a certificate-bound token; the layer uses
  `Gate::authenticate_request`.
- The workspace requirement on `ferrohealth-smart` moves to 0.9.0.
- `audit::Actor::Caller` carries `binding` and `party`, and the audit line
  two fields more. Upgrade: a product that builds an `Actor::Caller` sets
  both (`"-"` and `None` for a caller not looked up); a log pipeline that
  holds the field set adds them.
- The `[auth.issuer.assurance] claim` path is held to the rule of
  `role_claims` and `resource::PatientClaim` (#234): a path carrying
  whitespace anywhere fails to load (`AssuranceError::Claim`), where only
  a blank step did. Upgrade: name the claim without whitespace.

### Removed

- The flat `[auth] issuer = "…"` form. Upgrade: write an
  `[[auth.issuer]]` table with its `kind`.
- `TokenProfile` and the `token_profile` key, section-level or per issuer.
  Upgrade: select a `profile`, or set `token_types`, `required_claims` and
  `scope_claim` on the issuer; the key fails to load naming them.
- `assurance::ProfessionalSection`, `ClientTokens`, `ActingMode` and
  `Actor`, with the `acting_for_claim` and `client_tokens` keys. Upgrade:
  issue the client a delegated token whose subject is the person, which
  `CallerKind::Delegated` classifies through the issuer's `delegates`; the
  keys fail to load naming it.
- `Caller::acts_for_the_person`. Upgrade: read `Caller::is_the_person` or
  `Caller::kind`.
- `ConfigError::Unqualified`, with the string forms of `scopeless_subjects`
  and `role_claims` it named.

### Fixed

- No `Debug` rendering carries a token claim beyond `sub`, `client_id` and
  `iss` (#229). `resource::Caller` renders the subject, the client, the
  issuer, the kind and the scheme alone, where it rendered every claim, the
  scope, the roles and the `patient` launch context;
  `assurance::Assessment` renders the level alone, and
  `resource::Compartment::Patient` and `resource::PersonContext` leave out
  the patient.

## [0.8.9] - 2026-11-05

### Security

- `[auth] scopeless_subjects` and `role_claims` hold per issuer. An entry
  written `<issuer>#<value>` holds for the tokens of the issuer it names
  alone; a bare entry holds only when the section trusts one issuer. A
  section with several `[[auth.issuer]]` entries refuses a bare entry as
  `ConfigError::Unqualified`, and every section refuses an entry naming an
  issuer it does not trust as `ConfigError::UnknownIssuer`. Before 0.8.9
  both lists applied to the tokens of every trusted issuer: a token from
  any of them whose `sub` was on the allowlist was granted system-wide
  access without a scope (since 0.1.0), and any of them could assert every
  role a product checks, its administrator and emergency roles included
  (since 0.7.0) (CWE-863, CWE-639, GHSA-pfgx-xq28-2629). A deployment with
  several issuers qualifies each entry, or sets `role_claims = []` to read
  no role from a token, before it upgrades: the default `role_claims` is
  bare and refused beside several issuers.

## [0.8.8] - 2026-11-03

### Added

- `client::Reach` names how a connection reaches its server beyond its TLS
  material (#196). It sets the lowest TLS version the connection negotiates
  (`client::TlsVersion`, written `"1.2"` or `"1.3"` in a configuration), and
  the hosts it reaches at a fixed address in place of resolving their names,
  for a server whose name resolves only inside a private network. The URL's
  port and the certificate check against the host name stay as the URL names
  them. `metadata::Http::reaching` builds the engine from a `Tls` and a
  `Reach`; `Http::with_tls` is `reaching` with the default reach, the TLS 1.2
  floor and no override.

## [0.8.7] - 2026-10-31

### Added

- Whether a request is the natural person's own access, for the EHDS
  person-access rights of Regulation (EU) 2025/327 Art. 3, 5 and 9, in two
  answers that fail safe in opposite directions (#171).
  `Caller::acts_for_the_person` is the broad answer, for the Art. 3(3)
  access delay: a bearer token that carries any `patient/` scope of the
  SMART on FHIR or SMART on openEHR grammar, or the deployment's patient
  claim, also beside `user/` or `system/` scopes. `Caller::is_the_person`
  is the strict answer, for Art. 5 authorship and the Art. 9 access record:
  a bearer token with a `patient/` scope and no `user/` or `system/` scope;
  the patient claim alone does not count. A Basic user is neither.
  `Caller::person` returns the `PersonContext` the request is bound to: the
  `patient` launch context, the `ehrId` and the patient claim's value.
- `resource::PatientClaim`, the dotted path of the claim a deployment names
  the patient in, attached to a resource server or introspector with
  `with_extension` so every caller it admits carries it.

## [0.8.6] - 2026-10-27

### Fixed

- `[auth] ca_file` is trusted under `mode = "introspection"` too: the
  metadata, introspection and token calls trust it beside the client or
  bearer grant's own `ca_file`, so an issuer behind a private certificate
  authority is reached with the setting that reaches it in JWT mode (#168).
  A bearer `IntrospectionAuth` now reads the metadata and calls the
  introspection endpoint trusting its grant's trust roots.

## [0.8.5] - 2026-10-27

### Added

- The `openehr-scopes` feature builds `openehr::smart_scopes`, the SMART on
  openEHR scope grammar, which depends on nothing. The crate builds for
  `wasm32-unknown-unknown`, where the grammar is all of it, so a browser
  client parses a scope string with the parser the resource server
  enforces it with (#158, #161).

### Changed

- `openehr::smart_scopes` is this crate's own module, moved from FerroEHR's
  `openehr-sdt` with the same path, types and behaviour, and the crate no
  longer depends on `openehr-sdt` (#158). A `0.0.x` requirement on that
  crate was exact, so each FerroEHR release left this crate behind and a
  product resolved two copies. A product that passes
  `openehr_sdt::smart_scopes` types to this crate names
  `ferrohealth_smart::openehr::smart_scopes` instead; cargo-semver-checks
  finds no other change to the public API.

## [0.8.4] - 2026-10-27

### Changed

- Requires `openehr-sdt` 0.0.109, the version FerroEHR publishes, so a
  product that also takes FerroEHR's openEHR crates resolves one
  `openehr-sdt` (#154). The `openehr` feature's re-exported scope types
  come from that version.

## [0.8.3] - 2026-10-27

### Changed

- `openehr-sdt` 0.0.102 in place of 0.0.98, the newest version on
  crates.io. The `openehr::smart_scopes` re-export names the 0.0.102 types,
  so a product with the `openehr` feature that depends on `openehr-sdt`
  itself moves to 0.0.102 with it (#148).

## [0.8.2] - 2026-10-27

### Fixed

- A misspelt key inside an `[[auth.issuer]]` entry is refused by its name.
  `config::IssuerKey` read the flat and list forms as an untagged enum,
  whose refusal ("data did not match any variant") dropped the entry's own
  error; it is now read by the value's shape, so the entry's
  `deny_unknown_fields` refusal reaches the operator (#145).

## [0.8.1] - 2026-10-27

### Fixed

- The documentation builds without a broken link under the default
  features and with no features, where it linked to the modules behind
  `openehr`, `axum` and `fetch` (#135). docs.rs builds every feature.

## [0.8.0] - 2026-10-26

### Added

- The `oidc` feature: `oidc::RelyingParty`, the OpenID Connect
  relying-party client every operator console signs in with (#131). It
  builds the authorization request with `state`, `nonce` and a PKCE `S256`
  challenge (OpenID Connect Core 1.0 §3.1.2.1, RFC 7636 §4), refuses a
  callback whose `state` is not the sign-in's before reading anything else
  (RFC 6749 §10.12), exchanges the code with the verifier, checks the ID
  Token's signature, `iss`, `aud`, `azp`, `exp` and `nonce` (OpenID Connect
  Core 1.0 §3.1.3.7), refreshes the access token (RFC 6749 §6), revokes a
  token (RFC 7009 §2.1), and returns the end-session URL (OpenID Connect
  RP-Initiated Logout 1.0 §2). Every failure is a typed `oidc::OidcError`
  carrying the provider's status and error code. Tokens are held in
  `ferrohealth_secret::secret::Secret` and none is rendered; the console
  keeps the session.
- `metadata::ServerMetadata::end_session_endpoint` (OpenID Connect
  RP-Initiated Logout 1.0 §2.1).

## [0.7.5] - 2026-10-26

### Changed

- It requires `ferrohealth-secret` 0.2 as a caret requirement (`0.2.0`), so a
  secret patch reaches a product without a smart release first.

## [0.7.4] - 2026-10-26

### Changed

- It builds on `ferrohealth-secret` 0.2.0, so a product can take the newest
  family mask beside it.
- `[auth.basic] cache_ttl_seconds` defaults to 300: a credential that verified
  is kept for five minutes, so a repeat request skips the Argon2id key
  derivation (#127). Each request otherwise costs about 10 ms of CPU, which
  capped a product's throughput. `cache_ttl_seconds = 0` keeps the old
  behaviour.

## [0.7.3] - 2026-10-26

### Changed

- Every secret and every masked URL renders through `ferrohealth-secret`,
  the family's one mask: `config::REDACTED` is its `***` in place of
  `[redacted]`, and `config::mask_userinfo` renders a URL through its
  `RedactedUrl`, so the query is masked as `?***` beside the userinfo. The
  `OauthSection` and `AuthSection` renderings follow. Text without `://` is
  still kept as written.

## [0.7.2] - 2026-10-26

### Added

- `[auth] ca_file`: a PEM file of trust roots added to the platform's for
  every issuer's discovery document and key set, so an issuer behind a
  private certificate authority can be reached without changing the trust
  of the whole process. `resource::Settings::trust_roots` carries it to
  `ResourceServer::discover`. A file that cannot be read, is no PEM or holds
  no certificate refuses the start as `ConfigError::CaFile`.

## [0.7.1] - 2026-10-26

### Added

- `config::mask_userinfo` and `config::REDACTED` are public, so a product
  renders every URL of its configuration with the one mask the shared
  sections use.

### Changed

- A masked URL keeps the rest of the URL as written: `[redacted]` stands in
  for the userinfo in place of a percent-encoded `%5Bredacted%5D`, and an
  explicit default port is no longer dropped.

- The changelog moves from the repository root to
  `crates/ferrohealth-smart/CHANGELOG.md`, beside `ferrohealth-authz`'s, and
  the published crate carries it.

### Security

Shipped with functional changes because: the fix is the public mask the Added entry names, so the two cannot ship apart.

- Every rendering of `OauthSection` masks the userinfo of its `issuer` and
  `token_endpoint`, a URL no parser accepts included. Before 0.7.1 a
  credential in those URLs could reach the rendering in full: through
  `Debug` since 0.1.0 and `Serialize` since 0.3.0, and in 0.7.0 still
  whenever the URL did not parse. A product that logged its configuration
  could write the credential to its log (CWE-532, GHSA-vphj-3f8c-5hpx).

## [0.7.0] - 2026-10-25

The granted subject: a caller's roles from the RFC 9068 claims or the Basic
user's configuration, with role requirements in the route table; the
assurance level and the natural person behind a token, with the RFC 9470
step-up; `OauthSection` checks named in the product's own keys and URLs
rendered without userinfo. The repository releases `ferrohealth-authz`
beside this crate, and each crate is now tagged with its name; this release
is `ferrohealth-smart-v0.7.0`. Products pin `=0.7.0`; the breaking change
below names what a product changes.

### Added

- The roles a caller holds (#101). `Caller::roles()` carries what the
  `roles`, `groups` and `entitlements` claims of RFC 9068 §2.2.3.1 hold, or
  the dotted paths `[auth] role_claims` names, from a JWT and from an
  introspection answer alike: each string array element, each SCIM complex
  element's `value` (RFC 7643 §2.4) and each word of a string, trimmed and
  once. A Basic user holds `[[auth.basic.users]] roles`
  (`PasswordStore::with_roles`). `Caller::has_role` matches without regard to
  ASCII case and `Caller::claim_text` reads a string at a dotted claim path.
- Role requirements in the route table: `Requirement::Role`,
  `Requirement::AnyRole`, `Requirement::WithoutRole` (a restriction that
  overrides a grant) and `Requirement::All`.
- RFC 7643 and RFC 9396 are vendored and pinned.
- `assurance` (#102): `AssuranceSection` maps the values of a token's
  authentication context class claim (`acr` by default) to the levels low,
  substantial and high, `assess` reads them, `meets` holds a caller to a
  minimum, and `step_up` gives the RFC 9470 §3 refusal naming the accepted
  `acr_values`. `ProfessionalSection` reads the natural person behind a
  token, telling a client token apart (`sub_is_client` by RFC 9068 §2.2, or
  `claim_absent`) and reading whom a client acts for. A Basic caller carries
  neither. Both sections validate at boot.
- `OauthSection::problems(table)` (#105): every problem of a grant without
  reading a file, each naming its key under the product's table, so a product
  reports a table it embeds at `terminology.server.oauth` in its own keys.

### Changed

- The repository releases a second crate, `ferrohealth-authz`, on its own
  version line (#103): its tag is `ferrohealth-authz-vX.Y.Z`, its changelog
  `crates/ferrohealth-authz/CHANGELOG.md`, and the release and publish lanes
  package, attest and publish the one crate a tag names. The release plan refuses a cut whose
  `[Unreleased]` link does not compare from the tag, and the link now
  compares from `v0.6.0`.

- Each crate is tagged with its name from this release on (owner decision
  of 2026-10-25): `ferrohealth-smart-vX.Y.Z` releases `ferrohealth-smart`,
  beside `ferrohealth-authz-vX.Y.Z`. The release lane, the release plan, the
  milestone check and the manual publish guard take the per-crate tags; the
  `v0.1.0` to `v0.6.0` tags stay and count as `ferrohealth-smart`'s earlier
  releases.

- An `OauthSection` renders `issuer` and `token_endpoint` with any userinfo
  masked, serialized and in `Debug` (#105); its `Debug` is written by hand.

- **Breaking:** `resource::Settings`, `resource::introspection::IntrospectionSettings`,
  `config::AuthSection`, `config::BasicUser` and `basic::Verified` gain a
  field (`role_claims` or `roles`); a struct literal adds it or ends with
  `..Default::default()` where the type has a default. `basic::StoreError`
  gains `Role` and `UnknownUser`.

- The repository is FerroAUTH, renamed from FerroSMART on 2026-10-25, at
  <https://github.com/FerroHEALTH/FerroSMART>; the old address redirects. It
  holds two crates: authentication, `ferrohealth-smart`, and the policy
  decision, `ferrohealth-authz`. The `repository` and `homepage` fields of
  the published manifest name the new address. The crate name and every
  `ferrohealth_smart` path stay as they are, so a product changes nothing.

## [0.6.0] - 2026-10-25

Token introspection (RFC 7662) for an authorization server that issues
opaque access tokens: `resource::introspection::Introspector` beside the
JWT check, under the product's client authentication or a bearer token, with
a cache bounded by each response's `exp`, and `[auth] mode =
"introspection"` to configure it. Products pin `=0.6.0`; the breaking change
below names what a product changes.

### Added

- `resource::introspection`, behind the `fetch` feature: `Introspector`, a
  `Verifier` that checks a bearer token by OAuth 2.0 Token Introspection
  (RFC 7662) for an authorization server whose tokens the resource server
  cannot read itself, with `IntrospectionSettings`, `IntrospectionAuth` and
  `IntrospectionError`. The call authenticates with the client
  authentication of the token endpoint or with a bearer token from the
  client credentials grant (SMART App Launch 2.2.0, Token Introspection).
  `active` other than `true` refuses the token with the new
  `Reason::Inactive`; `scope`, `client_id` and `exp` are required; `iss`
  and `aud` are checked when present; the claims are read by the step the
  JWT check uses. An active response is held until its `exp` and at most
  `cache_max_age`, in a bounded cache keyed by the token's SHA-256. An
  endpoint that fails answers `503` (FerroBRIDGE #533).
- `[auth] mode = "introspection"` with the `[auth.introspection]` table
  (`endpoint`, `cache_max_age_seconds`, `cache_capacity`, and one of
  `client` and `bearer`), resolved into `Resolved::introspection`;
  `config::AuthMode`, `config::IntrospectionSection`, and the
  `ConfigError` variants `Introspection` and `IntrospectionUnavailable`.

### Changed

- **Breaking:** `config::AuthSection` gains `mode` and `introspection`, and
  `config::Resolved` gains `introspection` (with the `fetch` feature); a
  struct literal adds them or ends with `..Default::default()`.
- `Caller::cached` is also `true` for a bearer caller admitted from a held
  introspection response.

## [0.5.1] - 2026-10-25

A patch release with no breaking API change: the repeated-name refusal of
0.5.0 now covers the key set, operator-supplied metadata is compared and
checked through the same functions discovery uses, its mutual-TLS token
alias included, and the manual crate publish runs only at a released tag.
A product pins `=0.5.1` in place of `=0.5.0` and changes nothing else.

### Fixed

- `ResourceServer::with_metadata` holds the `mtls_endpoint_aliases`
  token endpoint (RFC 8705 §5) of operator-supplied metadata to the `https`
  rule of RFC 8414 §2 like every other location, so a plain-`http` alias is
  refused with `ResourceError::Discovery`; the check reads the members
  `ServerMetadata::endpoints` lists (#93).

### Changed

- A key set in which any object, at any depth, repeats a member name is
  refused with the new `ResourceError::KeySetRepeatedName`, as the metadata
  document is since 0.5.0, whether it is read over the `jwks_uri` or from a
  `jwks_file` (RFC 8259 §4). A held set stays in use for the keys it holds
  when a read is refused (#88).
- `ResourceServer::with_metadata` compares the issuer of operator-supplied
  metadata through `metadata::check_issuer`, the RFC 8414 §3.3 comparison
  discovery uses; the refusal stays `ResourceError::MetadataIssuer` (#89).
- The manual `Publish crates` workflow publishes only when it runs at the
  tag `v<version>` of the manifest version and a published GitHub release
  exists for that tag; any other run is refused before the `crates-io`
  approval, naming what is missing. The dry run is unchanged. 0.4.1 reached
  crates.io with no tag and no release that way (#91).

## [0.5.0] - 2026-10-25

`openehr-sdt` 0.0.98, the version FerroEHR v5.4.1 publishes, so FerroEHR
builds one copy of the SMART on openEHR parser, and three checks on the
authorization server metadata FerroPIX's Nuts grant kept privately: the
issuer compared as exact text, a document that repeats a member name
refused, and an opt-in check that every endpoint sits on the issuer's
origin. Products pin `=0.5.0`; the breaking changes below name what a
product changes.

### Added

- `metadata::check_issuer`, the RFC 8414 §3.3 comparison of the issuer a
  metadata document names with the one its location was built from, as
  exact text with no normalization (RFC 8414 §4), and
  `metadata::canonical_issuer`, which also holds a configured issuer to the
  canonical form the URL parser writes, without userinfo, for a product that
  wants the text compared and the URL fetched to have one meaning (#67).
- `ServerMetadata::check_origin`, an opt-in check that every endpoint the
  metadata names (`jwks_uri`, the authorization, token, registration,
  introspection and revocation endpoints and the mutual-TLS token alias)
  shares the issuer's scheme, host and port (RFC 6454 §4, §5), with
  `metadata::same_origin` for one location and `ServerMetadata::endpoints`
  listing them; `DiscoveryError` gains `EndpointUrl` and `OtherOrigin`
  (#68).
- `metadata::repeats_no_name` and `metadata::parse_metadata`, the reader of
  a metadata body that refuses one whose objects repeat a member name
  (RFC 8259 §4) (#69).

### Changed

- Discovery refuses a metadata document in which any object, at any depth,
  repeats a member name, with the new `DiscoveryError::RepeatedName`, so a
  second `issuer` or `jwks_uri` another parser would take cannot hide in it
  (RFC 8259 §4). A repeated member the crate reads was refused before as
  `DiscoveryError::Metadata`; it is now `RepeatedName`, so a product that
  matches on `Metadata` for that case matches the new variant (#69).
- The release checks the family's Security changelog rules: every
  `### Security` entry names a GHSA advisory or an OpenVEX statement under
  `security/vex/`, and a Security section beside other changes opens with
  "Shipped with functional changes because:" and its reason (Regulation (EU)
  2024/2847 Annex I Part II(2), (4), (8)). CI checks `[Unreleased]`, and the
  release `plan` job the section it cuts, through `scripts/release/plan.sh`,
  which `scripts/release/preflight.sh` replays before the tag
  (`docs/release.md`). The release notes state the month the five years of
  security fixes end (Art 13(19)). CI fails an advisory exception in
  `deny.toml` that no longer names a finding. `SECURITY.md` names the
  `info@cadasto.com` reporting route and the advisory each fixed
  vulnerability is published as (#72).
- `SECURITY.md` states the response times every product of the Ferro family
  states: an acknowledgement within about 5 business days in place of seven
  days, an initial assessment within about 10 business days, both best
  effort, and a fixed release published within 7 days of the confirmed
  assessment for a Critical vulnerability, 30 days for High, 90 days for
  Medium and with the next release for Low.
- **Breaking:** `openehr-sdt` 0.0.98 in place of 0.0.90, the version
  FerroEHR v5.4.1 publishes, so FerroEHR builds one copy of the SMART on
  openEHR parser in place of two. The `openehr::smart_scopes` re-export
  names the 0.0.98 types, so a product with the `openehr` feature that
  depends on `openehr-sdt` itself moves to 0.0.98 with it (#83).

## [0.4.1] - 2026-10-21

A patch release with no API change: a product pins `=0.4.1` in place of
`=0.4.0` and changes nothing else.

### Changed

- The crate declares `rust-version = "1.98"` in place of 1.97, and the
  repository builds with Rust 1.99.1 in place of 1.98.1: the FerroHEALTH
  family builds with the latest stable toolchain and declares the release
  before it as its MSRV. A product on a toolchain older than 1.98 can no
  longer take the crate.

## [0.4.0] - 2026-10-20

The gaps FerroFED's migration and FerroEHR's move to 0.3.1 found, closed in
the crate: a lazy resource server and a `Send` discovery future, a named
credential header for an edge proxy, a typed upstream failure for a product
verifier, mutual TLS and a product HTTP client for the token client, a
configurable assertion audience, the RFC 9470 step-up challenge, a typed
extension on the caller, a Basic user list helper, and the cache-hit signal
of a Basic check. Products pin `=0.4.0`; the breaking changes below name
what a product changes.

### Added

- `ResourceServer::lazy` and `LazyResourceServer`: the settings are checked
  at once and the issuer's metadata and key set are read when the first
  token needs them; a read that fails answers `503` and is not repeated
  inside `jwks_refresh_interval_seconds`. `IssuerSet::with_lazy` routes to
  one (#55).
- `guard::CredentialHeader` and `Gate::with_credential_header`: a product
  behind an edge proxy names the header the credential travels in, schemed
  like `Authorization` or bare, under the same rules; the default stays
  `Authorization`. `Gate::credential` returns the credential text the gate
  read (#56).
- `resource::Rejection::Upstream` and `Rejection::upstream`: a product
  verifier reports an upstream failure (an RFC 7662 introspection
  endpoint) with its own error as the source; it answers `503` with
  `Reason::UpstreamUnavailable` (#57).
- Mutual TLS for the token client (RFC 8705): `ClientAuth::TlsClientAuth`
  and `ClientAuth::SelfSignedTlsClientAuth` (`tls_client_auth`,
  `self_signed_tls_client_auth`), `ClientCredentials::with_mutual_tls`,
  `client::Tls` with extra trust roots and the client certificate,
  `metadata::Http::with_tls` and `Http::from_client`,
  `TokenSource::with_http` for a product's own `reqwest::Client`, the
  `mtls_endpoint_aliases.token_endpoint` of RFC 8705 §5 used when a
  certificate is configured, and the `[<lane>.credentials.oauth]` keys
  `ca_file`, `client_certificate_file` and `client_key_file`, read and
  parsed at load (#58).
- `client::AssertionAudience` and `[<lane>.credentials.oauth]
  assertion_audience`: the `private_key_jwt` assertion names the token
  endpoint (the default, SMART's rule) or the issuer identifier (RFC 7523
  §3) (#59).
- The RFC 9470 step-up challenge: `refusal::StepUp` with `acr_values` and
  `max_age`, `Refusal::StepUp` answering `401` with
  `error="insufficient_user_authentication"`, `StepUp::satisfied_by`, and
  `Caller::acr` and `Caller::auth_time`. RFC 9470 joins the vendored set
  (#60).
- A typed extension on the caller: `ResourceServer::with_extension`,
  `LazyResourceServer::with_extension` and `Caller::with_extension` attach a
  product value, `Caller::extension` and `Access::extension` read it, so a
  product's per-issuer policy travels with the verified caller. Equality on
  `Caller` ignores extensions (#61).
- `Caller::basic_user_in`, `Access::basic_user_in` and
  `Requirement::basic_users`: whether a Basic caller is one of a list of
  user-ids; a bearer subject never matches (#62).
- `basic::Verified::cached` and `Caller::cached`: whether a Basic credential
  was admitted from the verified-credential cache, so a product records one
  fresh authentication per cache lifetime (#63).

### Security

- `rustls-webpki` 0.103.16 and `webpki-root-certs` 1.0.10 in the lock, past
  RUSTSEC-2026-0382 and RUSTSEC-2026-0383 (certificate paths through the
  distrusted emSign intermediates) (#66).

### Changed

- `ResourceServer::discover` returns a `Send` future, so a product calls
  it from a request without a blocking thread (#55).
- **Breaking:** `client::ClientCredentials` gains the public fields
  `assertion_audience` and `tls`, and `config::OauthSection` gains
  `assertion_audience`, `ca_file`, `client_certificate_file` and
  `client_key_file`; a struct literal adds them or uses a constructor or
  `..Default::default()` (#58, #59).
- **Breaking:** `client::ClientAuth` gains two variants, so an exhaustive
  `match` adds `TlsClientAuth` and `SelfSignedTlsClientAuth` (#58).
- **Breaking:** `metadata::ServerMetadata` gains
  `mtls_endpoint_aliases`; a struct literal adds it or ends with
  `..ServerMetadata::default()` (#58).
- **Breaking:** `basic::Verified` gains the public field `cached` (#63).

## [0.3.1] - 2026-10-20

`openehr-sdt` 0.0.90, the version FerroEHR publishes. No public API changes;
products pin `=0.3.1`.

### Changed

- `openehr-sdt` 0.0.90, the version FerroEHR publishes, so a product and
  the crate resolve one copy of the SMART on openEHR parser behind the
  `openehr::smart_scopes` re-export (#52).

## [0.3.0] - 2026-10-20

The gaps FerroEHR's migration found, closed in the crate: a blank `sub` is
refused, the configuration sections render with every secret redacted, a
Basic-only `[auth]` resolves, a `jwks_file` issuer takes operator-supplied
metadata, the SMART on openEHR requirement honours `scopeless_subjects`,
`Requirement::Client` admits named Basic principals, verified Basic
credentials are cached, a bearer value outside `b64token` is refused, the
product reads the reason of every refusal, and the SMART on openEHR grammar
is re-exported. Products pin `=0.3.0`; the breaking changes below name what
a product changes.

### Added

- `Serialize` on `config::AuthSection`, `IssuerKey`, `IssuerEntry`,
  `BasicSection`, `BasicUser`, `CredentialsSection` and `OauthSection`, so
  a product renders its running configuration. `password_hash`, `password`
  and `client_secret` are written as `[redacted]`, never their value; a
  `_file` path is written as configured (#42).
- A Basic-only surface: an enabled `[auth]` section with
  `[[auth.basic.users]]` and an empty flat `issuer` resolves to no issuer
  and the Basic store, so a product needs no `enabled = false` workaround
  (#43).
- `ResourceServer::with_metadata`: operator-supplied `ServerMetadata` for a
  `jwks_file` issuer, held to the configured issuer (RFC 8414 §3.3) and the
  `https` rule (RFC 8414 §2), so its SMART discovery document names a
  `token_endpoint`. `resource::configuration::document` is public (#44).
- `Caller::scopeless()`, whether the subject is on `[auth]
  scopeless_subjects` (#45).
- `[auth.basic] cache_ttl_seconds` and `PasswordStore::with_cache`: a
  verified Basic credential is kept for the TTL under an HMAC of the
  credential, so a repeat request skips the key derivation; 0 (the
  default) keeps none (#47).
- `refusal::Reason` and `refusal::Denied`: the check that refused a
  credential, for the product's own log. The wire answer stays the bare
  `invalid_token` of RFC 6750 §3 (#47).
- `openehr::smart_scopes`, the SMART on openEHR grammar module of
  `openehr-sdt` re-exported, so a product names `SmartScope`,
  `ResourceFamily` and `Permission` through the crate and links one copy of
  the parser (#48).

### Changed

- **Breaking:** `guard::Gate::authenticate` returns `Result<Access,
  Denied>`. `Denied::refusal()` is the refusal it returned before and
  `Denied::reason()` names the failed check; `Refusal::from(denied)` and
  `denied.into_refusal()` give the refusal alone (#47).
- **Breaking:** `config::BasicSection` gains the public field
  `cache_ttl_seconds`, so a struct literal adds it or ends with
  `..BasicSection::default()` (#47).
- **Breaking:** `resource::Rejection::Invalid { reason }` carries a
  `refusal::Reason` in place of a `&'static str`. A product's own
  `Verifier` names its reason as `Reason::Other("…")` (#47).
- **Breaking:** `guard::Requirement::Client` is a struct variant,
  `Client { client_ids, basic_users }`: a listed bearer `client_id` or a
  listed Basic user-id meets it, each list matched only against its own
  scheme. `Client(ids)` becomes `Client { client_ids: ids, basic_users:
  vec![] }` (#46).
- **Breaking:** `Requirement::OpenEhr` admits a caller on `[auth]
  scopeless_subjects` whose token carries no resource scope of either
  grammar. With the `openehr` feature a SMART on openEHR resource scope
  counts as a scope on a FHIR route too, so an allowlisted subject whose
  token carries only `system/composition-*.r` no longer reaches every FHIR
  resource (#45).
- A bearer value outside the RFC 6750 §2.1 `b64token` syntax is refused as
  `invalid_token` before the verifier reads it (#47).
- `openehr-sdt` stays at 0.0.89, the newest version on crates.io (#48).

### Fixed

- A token whose `sub` is empty or whitespace only is refused with the
  generic `invalid_token` (RFC 9068 §2.2, RFC 7519 §4.1.2), by the token
  check and by the gate over any `Verifier` (#41).
- An enabled `[auth]` section that admits no credential at all, such as
  `issuer = []` without Basic users, is refused at load with
  `ConfigError::Missing { key: "auth.issuer" }`; it resolved before and
  left the product an open gate (#43).
- `guard::Requirement::met_by` lints clean in the `axum` build without
  `openehr`, which CI now lints too.

## [0.2.0] - 2026-10-20

The gaps FerroTERM's migration found, closed in the crate: the SMART
discovery document claims only the permission capabilities a product
declares and writes `issuer` only with `sso-openid-connect`, a refusal's
renderer reads the request head so a product negotiates JSON or XML, and
the HTTP fetchers sit behind the default `fetch` feature. Products pin
`=0.2.0`; the breaking changes below name what a product changes.

### Added

- The `fetch` feature, on by default, carries the HTTP fetchers: the
  issuer's metadata, the key set over its `jwks_uri` and
  `client::cache::TokenSource`. A product built with
  `default-features = false` links no `reqwest` and reads its key set from a
  `jwks_file`; `ResourceServer::discover` then refuses settings without one
  with `ResourceError::KeySetFileRequired` (#38).
- `resource::configuration::PermissionCapability` and
  `SmartOptions::permissions`: the product declares the permission
  capabilities its route table enforces (#36).
- `resource::configuration::OpenIdConnect` and
  `SmartOptions::openid_connect`: whether the discovery document advertises
  `sso-openid-connect`, derived from an `openid` scope in the issuer's
  `scopes_supported` by default, declared, or withheld (#35).

### Changed

- **Breaking:** the SMART discovery document claims no permission
  capability unless the product declares it. `permission-v1`,
  `permission-patient` and `permission-user` were always written, and
  `SmartOptions::granular` is replaced by `PermissionCapability::V2` in
  `SmartOptions::permissions`. A product lists the capabilities its routes
  enforce (SMART App Launch 2.2.0, Conformance, Capabilities) (#36).
- **Breaking:** `issuer` is written only with `sso-openid-connect`, which
  SMART App Launch 2.2.0 (Conformance, Metadata) requires and which it
  otherwise omits. `sso-openid-connect` is written only when the issuer's
  metadata names a `jwks_uri`, which the capability also requires (#35).
- **Breaking:** `guard::Render::render` receives the refused request's head
  (`http::request::Parts`) beside the refusal, so a product answers in the
  format the request's `Accept` or `_format` negotiates. A renderer closure
  takes `(&Refusal, &Parts)`; `extract::HeaderOnly` ignores the head (#37).
- Without the `fetch` feature, `metadata::Http` and the
  `DiscoveryError::Build` and `DiscoveryError::Transport` variants are
  absent (#38).

## [0.1.1] - 2026-10-20

The gaps FerroBRIDGE's migration to 0.1.0 found, closed in the crate so no
product carries a copy: the Basic password readable as a secret, the audit
line's `addressed` field, the client credentials grant checked at load, a
product scope and validated capabilities in `[auth]`, and
`scopes_supported` in the SMART discovery document. Products pin
`=0.1.1`; the audit field rename and the new `[auth]` fields are the
changes a product makes.

### Added

- `basic::Credential::password` returns the password of an outgoing Basic
  credential as `&SecretString`, for an HTTP client that takes the user-id
  and the password itself; its `Debug` stays redacted (#27).
- `[auth] product_scope`: the product's own scope, a full URI or a string
  starting with `__` (SMART App Launch 2.2.0, Scopes and Launch Context,
  Extensibility), refused at load in any other form and resolved to
  `Resolved::product_scope` (#30).
- `scope::is_scope_token` (the RFC 6749 §3.3 scope-token rule) and
  `scope::is_extension_scope` are public, so a product checks its own
  scopes with the crate's rule instead of a copy (#30).
- `[auth] scopes_supported` and `Resolved::smart_options`: the scopes the
  product honours reach `scopes_supported` of the SMART discovery document,
  which "the server SHALL support" (SMART App Launch 2.2.0, Conformance,
  Metadata); each is checked as one scope token at load (#31).
- `resource::configuration::SMART_CAPABILITIES` and `is_capability`.

### Changed

- **Breaking for consumers of the audit log:** the audit line's `target`
  field is renamed `addressed`, and `audit::MAX_TARGET_LENGTH` is
  `MAX_ADDRESSED_LENGTH`. A JSON formatter that flattens the event fields
  wrote the field and the `tracing` target under one key, so a reader kept
  only one. A log query or dashboard that reads `target` for the addressed
  resource reads `addressed` (#28).
- `[auth] capabilities` refuses at load a value that SMART App Launch 2.2.0
  (Conformance, Capabilities) and the SMART on openEHR draft do not define
  and that is no full URI (#30).
- `[<lane>.credentials.oauth]` refuses at load an `issuer` outside the RFC
  8414 §2 URL rule, which was applied only at the first token request, and
  a `resource` with a fragment (RFC 8707 §2) (#29).
- `openehr-sdt` 0.0.89, the line FerroEHR v5.0.0 publishes (#22).
- `SECURITY.md`: only the newest release is supported. An earlier release
  receives no fix; upgrade to the newest release, which is free. Cadasto B.V.
  publishes security fixes for at least five years after each release (CRA
  Art 13(8)) and ships them only in the newest release (Art 13(10)).

## [0.1.0] - 2026-10-19

The first release: the shared SMART App Launch 2.x and OAuth 2.0
resource-server crate of the FerroHEALTH products, built to
`docs/architecture.md` from the FerroBRIDGE implementation, and the
repository setup. FerroSMART is a library, never an authorization server:
it issues no token and holds no key that signs one.

### Added

- `metadata`: the issuer's metadata read at the RFC 8414 §3 location, with
  the OpenID Connect Discovery 1.0 §4 location as the fallback on a `404`,
  the document's `issuer` required to match (RFC 8414 §3.3), the issuer and
  the `jwks_uri` held to `https` without a query or fragment (a loopback
  issuer may be plain `http`), and a 1 MiB ceiling on every document.
- `resource`: the resource server. The key set is read at boot, read again
  past its maximum age and once per interval on an unknown `kid`, a failed
  read keeps the held keys and is not repeated inside the interval, a
  member whose `use` is not `sig` or whose `key_ops` lack `verify` verifies
  nothing, and a token without a `kid` verifies only when the set holds one
  candidate. A token is checked under RFC 9068 (`typ` of `at+jwt`, the
  asymmetric algorithms of the configured list, `iss`, one of the
  configured audiences, `exp`, `nbf` and `iat` within a clock skew of at
  most 300 seconds, the required claims) or, by configuration, under a
  `jwt` profile for an issuer that mints no RFC 9068 token, where `scp` is
  read when `scope` is absent. A key set file replaces discovery for keys
  handed over out of band. `Verifier` is the seam a product plugs another
  check into, and `IssuerSet` routes each token to its trusted issuer. The
  SMART discovery document is built from the metadata with the options the
  product adds.
- `scope`: the SMART App Launch 2.2.0 scopes, `patient/`, `user/` and
  `system/` with the in-order `cruds` permissions, the v1 suffixes mapped
  as the specification has servers read them, the wildcard, the union rule,
  the patient compartment from the token's `patient` claim, the resource
  type held to the product's table, and the granular `?param=value`
  constraint carried on the grant and admitted only through a product
  evaluator.
- `openehr`, behind the `openehr` feature: the SMART on openEHR grammar
  beside the FHIR one, parsed by `openehr-sdt` and enforced here with the
  rules the draft leaves to the resource server: the permission letters in
  any order, `*` within a `::` segment and `**` across them, an operation
  naming no resource covered only by a bare wildcard, `system/aql-*` only
  for a listed backend client, a `patient/` grant only for a bound issuer
  and only on EHR data, no FHIR v1 suffixes, and both grammars in one
  `scope` claim; `Caller::ehr_id` and `Access::ehr_id` read the launch
  context's `ehrId`; the discovery document takes a platform's `services`
  map and the openEHR capabilities through `SmartOptions::with_openehr`.
- `basic`: HTTP Basic (RFC 7617) verified against a store of Argon2id PHC
  hashes with the enumeration decoy, each user carrying the scopes its
  configuration grants, and the outgoing credential that redacts itself.
- `client`: the OAuth 2.0 client credentials grant (RFC 6749 §4.4) with
  `client_secret_basic`, `client_secret_post` and `private_key_jwt` (the
  RFC 7523 assertion with the SMART asymmetric profile's header and claims,
  the `kid` configured or the RFC 7638 thumbprint, and the product's public
  JWK Set), the token endpoint configured or discovered, the cache with its
  refresh margin and shared fetch, and `call`, which sends a request once
  more under a new token when the upstream answers `401`.
- `audit`: one line per request under `ferrohealth_smart::audit` with the
  fixed fields `at`, `request_id`, `principal`, `client`, `via`, `issuer`,
  `method`, `route`, `target`, `interaction`, `status`, `duration_ms` and,
  on a batch entry, `entry`.
- `refusal`: the one `401` naming no claim (`invalid_token`), the `400` of
  two credentials or a malformed value (`invalid_request`), the `403`
  naming no scope (`insufficient_scope`), the `503` of an unreadable key
  set, and the Basic challenge with its realm and `charset="UTF-8"`.
- `config`: the `[auth]` section (the flat issuer or `[[auth.issuer]]`
  entries, the audiences, the algorithms, the profile, the skew and key
  set bounds, `jwks_file`, the realm, the scopeless subjects, the
  capabilities and the `[[auth.basic.users]]` with `password_hash` or
  `password_hash_file` and their scopes) and the `[<lane>.credentials]`
  table (`user` and `password` or `password_file`, or `oauth` with its
  `client_auth`, the secret or the `private_key_file`, `kid` and
  `assertion_alg`), every secret with its `_file` sibling of which exactly
  one is set, resolved at load.
- The `axum` feature: `guard`, the tower layer with the product's
  classifier (`Requirement::Public`, `Caller`, `Fhir`, `OpenEhr`, `Scope`,
  `Client`, `Either` or `Refused` on a `Target`), the credential check, the
  per-route permission check under the grammar the route declares with the
  product's `Honoured` flags, and the audit line, with the body of a
  refusal the product's; `extract`, the `Access` extractor and the
  header-only renderer.
- The repository setup as FerroUI's: the lint set, CI with the single
  required `conclusion` job, the vendored-specification guard, CodeQL,
  Scorecard, Dependabot, the release lane with signed tags and crates.io
  Trusted Publishing, the crate-version guard, the comment-style and
  `TODO(#N)` guards, the issue and pull request templates, the labels, the
  rulesets and the `crates-io` environment.

[Unreleased]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.38.2...HEAD
[0.38.2]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.38.1...ferrohealth-smart-v0.38.2
[0.38.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.38.0...ferrohealth-smart-v0.38.1
[0.38.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.37.0...ferrohealth-smart-v0.38.0
[0.37.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.36.0...ferrohealth-smart-v0.37.0
[0.36.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.35.0...ferrohealth-smart-v0.36.0
[0.35.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.34.0...ferrohealth-smart-v0.35.0
[0.34.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.33.1...ferrohealth-smart-v0.34.0
[0.33.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.33.0...ferrohealth-smart-v0.33.1
[0.33.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.32.0...ferrohealth-smart-v0.33.0
[0.32.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.31.0...ferrohealth-smart-v0.32.0
[0.31.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.30.2...ferrohealth-smart-v0.31.0
[0.30.2]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.30.1...ferrohealth-smart-v0.30.2
[0.30.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.30.0...ferrohealth-smart-v0.30.1
[0.30.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.29.2...ferrohealth-smart-v0.30.0
[0.29.2]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.29.1...ferrohealth-smart-v0.29.2
[0.29.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.29.0...ferrohealth-smart-v0.29.1
[0.29.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.28.0...ferrohealth-smart-v0.29.0
[0.28.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.27.0...ferrohealth-smart-v0.28.0
[0.27.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.26.0...ferrohealth-smart-v0.27.0
[0.26.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.25.0...ferrohealth-smart-v0.26.0
[0.25.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.24.1...ferrohealth-smart-v0.25.0
[0.24.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.24.0...ferrohealth-smart-v0.24.1
[0.24.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.23.0...ferrohealth-smart-v0.24.0
[0.23.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.22.0...ferrohealth-smart-v0.23.0
[0.22.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.21.0...ferrohealth-smart-v0.22.0
[0.21.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.20.0...ferrohealth-smart-v0.21.0
[0.20.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.19.1...ferrohealth-smart-v0.20.0
[0.19.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.19.0...ferrohealth-smart-v0.19.1
[0.19.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.18.0...ferrohealth-smart-v0.19.0
[0.18.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.17.1...ferrohealth-smart-v0.18.0
[0.17.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.17.0...ferrohealth-smart-v0.17.1
[0.17.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.16.3...ferrohealth-smart-v0.17.0
[0.16.3]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.16.2...ferrohealth-smart-v0.16.3
[0.16.2]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.16.1...ferrohealth-smart-v0.16.2
[0.16.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.16.0...ferrohealth-smart-v0.16.1
[0.16.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.15.1...ferrohealth-smart-v0.16.0
[0.15.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.15.0...ferrohealth-smart-v0.15.1
[0.15.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.14.0...ferrohealth-smart-v0.15.0
[0.14.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.13.1...ferrohealth-smart-v0.14.0
[0.13.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.13.0...ferrohealth-smart-v0.13.1
[0.13.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.12.0...ferrohealth-smart-v0.13.0
[0.12.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.11.0...ferrohealth-smart-v0.12.0
[0.11.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.10.1...ferrohealth-smart-v0.11.0
[0.10.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.10.0...ferrohealth-smart-v0.10.1
[0.10.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.9.4...ferrohealth-smart-v0.10.0
[0.9.4]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.9.3...ferrohealth-smart-v0.9.4
[0.9.3]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.9.2...ferrohealth-smart-v0.9.3
[0.9.2]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.9.1...ferrohealth-smart-v0.9.2
[0.9.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.9.0...ferrohealth-smart-v0.9.1
[0.9.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.8.9...ferrohealth-smart-v0.9.0
[0.8.9]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.8.8...ferrohealth-smart-v0.8.9
[0.8.8]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.8.7...ferrohealth-smart-v0.8.8
[0.8.7]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.8.6...ferrohealth-smart-v0.8.7
[0.8.6]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.8.5...ferrohealth-smart-v0.8.6
[0.8.5]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.8.4...ferrohealth-smart-v0.8.5
[0.8.4]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.8.3...ferrohealth-smart-v0.8.4
[0.8.3]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.8.2...ferrohealth-smart-v0.8.3
[0.8.2]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.8.1...ferrohealth-smart-v0.8.2
[0.8.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.8.0...ferrohealth-smart-v0.8.1
[0.8.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.7.5...ferrohealth-smart-v0.8.0
[0.7.5]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.7.4...ferrohealth-smart-v0.7.5
[0.7.4]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.7.3...ferrohealth-smart-v0.7.4
[0.7.3]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.7.2...ferrohealth-smart-v0.7.3
[0.7.2]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.7.1...ferrohealth-smart-v0.7.2
[0.7.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-smart-v0.7.0...ferrohealth-smart-v0.7.1
[0.7.0]: https://github.com/FerroHEALTH/FerroSMART/compare/v0.6.0...ferrohealth-smart-v0.7.0
[0.6.0]: https://github.com/FerroHEALTH/FerroSMART/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/FerroHEALTH/FerroSMART/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/FerroHEALTH/FerroSMART/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/FerroHEALTH/FerroSMART/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/FerroHEALTH/FerroSMART/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/FerroHEALTH/FerroSMART/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/FerroHEALTH/FerroSMART/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/FerroHEALTH/FerroSMART/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/FerroHEALTH/FerroSMART/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/FerroHEALTH/FerroSMART/releases/tag/v0.1.0
