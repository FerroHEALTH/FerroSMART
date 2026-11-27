<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Changelog
<!-- ANCHOR: book -->

All notable changes to FerroSMART are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - 2026-11-27

Documentation: the book is rewritten against the code and organised by task.
The server's behaviour does not change.

### Changed

- The book is rewritten against the code and organised by task, following the
  Diátaxis framework: a landing page for integrators, operators and compliance
  readers; a tutorial whose requests CI runs; how-to guides for integrating
  and for deploying, upgrading and running FerroSMART; reference pages, three
  of them generated from the code with a drift test (the command line, the
  admin API operations and the default configuration); and explanation pages
  on how FerroSMART decides a token, the EUDI Wallet login and the PID,
  signing keys and algorithms, and the crates every product uses. Every page
  states its audience, and pages that contradicted the code are corrected:
  the token and assertion algorithms include ML-DSA, several upstream
  providers are allowed, and the admin, audit, key and endpoint pages name
  what the server serves (#901).

## [0.8.0] - 2026-11-25

Post-quantum: ML-DSA tokens, client assertions and signed launches (RFC 9964),
and the X25519MLKEM768 key exchange on every TLS connection (RFC 10024).

### Added

- ML-DSA-65 token signing keys (RFC 9964) beside the RSA ones:
  `[ferrosmart.keys]` reads ML-DSA-65 private keys (RFC 9881) beside RSA
  keys, each algorithm rotating on its own, the JWK Set publishes each as
  an `AKP` key, and discovery lists `ML-DSA-65` in
  `id_token_signing_alg_values_supported`. A client's
  `id_token_signed_response_alg`, `RS256` or `ML-DSA-65`, picks the
  algorithm of its ID Tokens and access tokens; any other value, or one no
  key signs, is refused at registration (#887).
- The token endpoint accepts `private_key_jwt` client assertions, and the
  launch registration accepts signed launches, signed with ML-DSA-44,
  ML-DSA-65 or ML-DSA-87 (RFC 9964) by an `AKP` key of the client's
  registered JWK Set, beside RS384 and ES384; a key verifies only its own
  algorithm, so an assertion whose `alg` disagrees with the key is refused.
  `token_endpoint_auth_signing_alg_values_supported` and the introspection
  and revocation lists name the three ML-DSA algorithms (#888).
- The TLS 1.3 key exchange of the listener and of every client FerroSMART
  builds, the PostgreSQL connection among them, offers the post-quantum
  hybrid X25519MLKEM768 (RFC 10024) first, through `ferrohealth-server`
  0.12.4, and still reaches a classical-only peer over X25519.
  `docs/post-quantum.md` lists every cryptographic use and whether it is
  post-quantum safe, with `conformance/post-quantum.tsv` as its
  machine-readable copy and a README badge counted from it (#890).

### Changed

- Breaking: the `signing_key` and `client` tables of the baseline schema
  gain the `algorithm` and `id_token_signed_response_alg` columns, and a
  token key that is neither RSA nor ML-DSA-65 is refused at start, as is a
  pool without an RSA key. Requires `ferrohealth-smart` 0.35 (#887).

## [0.7.0] - 2026-11-25

FerroSMART 0.7.0 reads a launch patient for whom no grant exists yet as a
SMART Backend Services client of its own token endpoint, so a resource
server that exchanges user tokens onward, such as FerroBRIDGE, serves a
standalone patient launch. Every other read the picker makes runs under a
grant of the signed-in person. `[ferrosmart.backend]` is new and required
when people log in at a FHIR base. The EUDI Wallet login no longer asks
for, keeps or forwards the PID portrait.

### Changed

- FerroSMART reads a patient's own record during a standalone launch as a SMART Backend Services client (SMART App Launch 2.2.0, Backend Services): its own confidential client, registered under its issuer identifier from the new `[ferrosmart.backend]` table, obtains a `system/Patient.rs` client credentials token with a `private_key_jwt` assertion through its own token endpoint, so the token's `sub` is its `client_id` (IHE IUA §3.71.4.2.2.1) and the acquisition is the endpoint's `IHE.IUA.71` record. The same client reads the Patient of the paired-EHR lookup and of the token exchange, a wallet login's identifier search and the PIXm or PDQm patient index. A resource server that exchanges every user token onward reads these with its own credential. Each read is narrowed to the one matched `Patient`, one token per read, revoked once answered, and its access record is filed under the patient on whose behalf FerroSMART read; both are our own design (GDPR Art 5(1)(c), Art 25; Regulation (EU) 2025/327 Annex II 3.2(b) is silent on system access) (#873).
- `[ferrosmart.backend]` (`algorithm` `ES384` or `RS384`, and the `[ferrosmart.backend.keys]` ring, which shares no key with `[ferrosmart.keys]`) is required when people log in at a FHIR base. A configuration without it is refused at start (#873).
- The picker's searches and reads, a professional's EHR lookups and the `fhirUser` lookup run under a grant of the signed-in person to FerroSMART's own client, revoked with its token once the request is answered, so a resource server that exchanges the token onward finds the person's own grant (#873).
- The token exchange takes a professional's own token too (`user/` scopes alone, a `fhirUser` that names no `Patient`) and issues a token for the paired openEHR base with `user/composition-*.r` and `user/aql-*.s` at most, naming the professional and no patient (#873).
- The EUDI Wallet login never asks for, keeps or forwards the PID portrait,
  since FerroSMART identifies the person without it (Implementing Regulation
  (EU) 2024/2977 Art 3a(3); Regulation (EU) 2016/679 Art 5(1)(c)). A
  `[ferrosmart.upstream.openid4vp]` `claims` or `mdoc_claims` naming
  `picture` or `portrait` is refused at start, an mdoc carrying the portrait
  is `unrequested_credential`, and an SD-JWT VC that discloses it unasked has
  it dropped before the login reads its claims (#879).

### Removed

- The token FerroSMART issued itself for the signed-in person outside any grant (`user/Patient.rs` or `user/composition-*.r`), and the self-signed "system" token the patient index was asked with, are gone with no replacement setting (#873).

## [0.6.0] - 2026-11-25

FerroSMART 0.6.0 resolves the patient of an EUDI Wallet login at a patient
index such as FerroPIX, by PIXm or PDQm on the PID's administrative number,
and never from the wallet's values alone. It also passes the PID's names,
birth date, place of birth and nationalities into the ID Token under
`profile`.

### Added

- A wallet login's patient comes from a patient index such as FerroPIX:
  `[ferrosmart.upstream.openid4vp] identifier_systems` names each issuing
  country's identifier system, and a FHIR base's
  `[ferrosmart.resource.patient_index]` names the index, asked by PIXm
  ITI-83 or PDQm ITI-78 as FerroSMART with `system/Patient.rs`, and the
  system of the base's own patients. One patient becomes the `fhirUser`
  and the launch's `patient`. No patient, several, or a failed index
  refuses the launch. The ID Token carries the PID's `given_name`,
  `family_name`, `birthdate`, `place_of_birth` and `nationalities` under
  `profile`, and an upstream ID Token's `given_name`, `family_name` and
  `birthdate` the same way (#857).

## [0.5.0] - 2026-11-24

FerroSMART 0.5.0 lets a person log in with the PID in their EUDI Wallet as
an ISO mdoc as well as an SD-JWT VC. The wallet login asks for both formats
by default, and `credential_formats` narrows the request to one.

### Added

- The EUDI Wallet verifier accepts the PID as an ISO mdoc (`mso_mdoc`)
  beside the SD-JWT VC, over the redirect and the Digital Credentials API.
  The request offers both formats as one choice, and the wallet presents
  one. FerroSMART checks the issuer's signature under the same anchors and
  list of PID providers, each element's digest, the validity, the device
  signature over the OpenID4VP session transcript and, when the MSO names
  one, the Token Status List or identifier list in CWT format, with the
  same refusal reasons as the SD-JWT VC. The new keys of
  `[ferrosmart.upstream.openid4vp]` are `credential_formats` (both by
  default), `doctype` and `mdoc_claims`. The same person gets the same
  `sub` whichever format the wallet presents (#793).

## [0.4.0] - 2026-11-24

FerroSMART 0.4.0 registers clients by RFC 7591 and RFC 7592, with the client
document as RFC 7591 metadata, and adds pushed authorization requests,
sender-constrained tokens, the eIDAS level of assurance as `acr`, the EUDI
Wallet login by OpenID4VP and the Digital Credentials API, and the token
exchange of a patient's own token for an openEHR server. It runs on PostgreSQL
19 only, and its schema ships as one baseline per area, so a database of an
earlier release is created fresh. Several entries are breaking for a
deployment, and each says what its configuration changes.

### Added

- The patient picker offers, before a search, the patients the person
  chose at that server within `[ferrosmart.picker] recent_retention` (30
  days by default, `0s` keeps none), each read again as the person first,
  and at a FHIR server whose `[[ferrosmart.resource]]` names `assigned`
  (`care_team` or `encounter`) the patients of the professional's active
  care teams or encounters in progress, searched by `participant` as the
  person. The person forgets their recent patients on the management
  page, recorded as `recent-patients-forgotten` (#685).
- A person can log in with the person identification data (PID) in their
  EUDI Wallet: an `[[ferrosmart.upstream]]` entry with an
  `[ferrosmart.upstream.openid4vp]` table makes FerroSMART an OpenID4VP 1.0
  verifier under HAIP 1.0 and the EU wallet profile (Implementing
  Regulation (EU) 2024/2979 Annex II as amended by 2026/1731). It sends a
  request signed under its access certificate, takes the encrypted
  answer at `{issuer}/wallet/response` and completes the login in the
  browser that began it. The PID is checked against the configured
  anchors, its key binding, the request's nonce, its expiry and, when it
  carries one, its Token Status List. Its administrative number names the
  person and feeds the `fhirUser` lookup. Each refusal is a `400` and a
  login record that names its reason (#689).
- A client the app registered itself (RFC 7591), answered with
  `registered_by` `self`, is held to its own guards: it is never first
  party, the person always sees the consent page for it with a notice that
  it registered itself and no remember box, the page shows only its links on
  the redirect URI's scheme and host (RFC 7591 §5), and an error before the
  person's login was accepted is a page, never a redirect to it (RFC 9700
  §4.11.2) (#736).
- Breaking: every token issued on a person's login carries its eIDAS level
  of assurance as `acr` (`http://eidas.europa.eu/LoA/low`, `/substantial`
  or `/high`) beside `auth_time`, in the ID Token, the access token, every
  refresh and the introspection answer (RFC 9068 §2.2.1, RFC 9470 §6). Each
  `[[ferrosmart.upstream]]` entry maps its provider's values, an OpenID
  Connect `acr` or a SAML `AuthnContextClassRef`, to levels in
  `[ferrosmart.upstream.assurance] levels`, with an optional `minimum`.
  `[ferrosmart] assurance_minimum` is the deployment's floor, `substantial`
  by default after Implementing Regulation (EU) 2026/2099 Articles 4(2) and
  6(3), configurable to `high`, or `none` outside the eIDAS area; a
  provider whose values reach no floor is refused at load, so every
  deployment with an upstream maps its provider's values or sets
  `assurance_minimum`. A login below the floor or the provider's minimum is
  refused with `access_denied` and recorded. A client's
  `default_acr_values` and an app's `acr_values` naming an eIDAS URI are
  asked of the provider and refuse a lower login with
  `unmet_authentication_requirements` (RFC 9470 §5). Both discovery
  documents name `acr_values_supported` (#784).
- The token endpoint grants RFC 8693 token exchange
  (`urn:ietf:params:oauth:grant-type:token-exchange`) for one case: a
  confidential client whose `grant_types` lists the token exchange grant and
  whose `resources` lists a FHIR base and its paired openEHR base exchanges
  a patient's own access token at that FHIR base for a token at the openEHR
  base. The issued token keeps the patient's `sub`, `fhirUser`, `patient`,
  `acr` and `auth_time`, adds the `ehrId` looked up as the patient, names
  the exchanging client as `client_id` with no `act`, carries at most
  `patient/composition-*.r` and `patient/aql-*.s`, lives at most five
  minutes and never past the subject token, and is revoked with the
  subject's grant. A professional's, a machine's, an expired or a revoked
  subject token, an actor token, a wider scope and another target are
  refused (#785).
- The EUDI Wallet verifier reads the list of PID providers the Commission
  publishes under Implementing Regulation (EU) 2024/2980 Art 5, as ETSI TS
  119 602 V1.1.1 Annex D describes it: the JSON form under a compact JAdES
  signature. `[ferrosmart.upstream.openid4vp.pid_providers_list]` names the
  list's https `url` (or a `file`), the `signing_certificate_files` that
  verify it, and how often it is read again (`refresh`, `1h` by default).
  The providers it lists are trusted beside `issuer_anchor_files`. A list
  whose signature fails, or whose next update has passed, refuses every
  wallet login as `trusted_list_unavailable`. A read that fails keeps the
  last list that verified until that list's next update. `GET
  /admin/upstreams` shows each replica's last read (#794).
- Clients are registered and managed through RFC 7591 and RFC 7592:
  `POST {issuer}/register`, named `registration_endpoint` in the metadata,
  with an administrator's token as the initial access token, and `GET`,
  `PUT` and `DELETE {issuer}/register/{client_id}`. With
  `[ferrosmart.registration] open = true` an app registers itself, held to
  that section's `scope`, and manages itself with the registration access
  token its registration answered. Breaking: `POST /admin/clients`, `GET`
  and `PUT /admin/clients/{client_id}` are gone; `/admin/clients` keeps the
  list, disable and enable. A registration that omits
  `token_endpoint_auth_method` is `client_secret_basic`, and one that omits
  `grant_types` is `authorization_code` (RFC 7591 §2) (#802).
- Pushed authorization requests (RFC 9126): `POST {issuer}/par` takes an
  authenticated client's authorization request and answers a one-time
  `request_uri` that `/authorize` takes in its place. The metadata names
  `pushed_authorization_request_endpoint` and
  `require_pushed_authorization_requests`, which `[ferrosmart]
  require_pushed_authorization_requests` sets, and a client's own
  `require_pushed_authorization_requests` holds it to PAR (#806).
- Sender-constrained tokens at issuance: a token request with a `DPoP` proof
  gets a `DPoP` token whose `cnf.jkt` names the proof's key (RFC 9449), and a
  client registered with `tls_client_certificate_bound_access_tokens` gets a
  token whose `cnf` carries its client certificate's `x5t#S256` (RFC 8705).
  A public client's refresh token is bound to its `DPoP` key, a client
  registered with `dpop_bound_access_tokens` must send a proof, introspection
  answers the token's `cnf`, and the metadata names
  `dpop_signing_alg_values_supported` and
  `tls_client_certificate_bound_access_tokens` (#807).
- `GET {issuer}/admin/openapi.json` answers the OpenAPI 3.1 document of the
  registration endpoint, the admin API and the audit records, without a
  token and with the deployment's issuer as its server. A test holds the
  document to the router's operations and each answer to its schema (#824).
- `GET {issuer}/admin/upstreams` answers the state of each upstream
  provider behind the `system/admin` guard: the clients that name it, its
  OpenID Connect discovery document and key set read at once, or its SAML
  metadata as the replica last read it, each with its outcome, its error
  and its signing certificates' expiry (#830).
- The admin API finds a person and ends their access, as the person can on
  the management page: `GET {issuer}/admin/subjects?upstream=&sub=`
  answers their subject, `GET .../subjects/{sub}/grants` their live grants
  and remembered consents, and `DELETE .../grants/{grant_id}`,
  `.../consents/{client_id}` and `.../sessions` revoke one grant, withdraw
  one app's consent with its grants, or end their upstream sessions with
  the `online_access` grants in them, each with its audit record naming the
  admin client (#831).
- `GET {issuer}/audit` takes `client`, `event` and `outcome` beside
  `subject`, `since` and `until`, and pages: the searchset Bundle carries a
  `self` link and, while more records match, a `next` link to the next
  page. `POST {issuer}/admin/clients/{client_id}/secret` issues a
  confidential symmetric client a new secret, answered once with its audit
  record, through the same code as `ferrosmart client secret` (#832).
- The EUDI Wallet login offers the W3C Digital Credentials API beside the
  redirect, as Implementing Regulation (EU) 2024/2979 Annex II, amended by
  2026/1731, requires of a relying party. The browser first shows a page
  at `{issuer}/wallet`. Its "Open your wallet" link invokes the wallet by
  redirect. Where the browser has the API, the page's module asks for the
  PID with a request signed for the page's origin (`openid4vp-v1-signed`,
  `dc_api.jwt`) and posts the answer to `{issuer}/wallet/dc`. The answer
  is checked as in the redirect lane, bound to the page's origin.
  `[ferrosmart.upstream.openid4vp] digital_credentials_api = false` sends
  the browser straight to the wallet (#840).

### Changed

- Breaking: the token signing keys rotate on a schedule the replicas share
  through the database. `[ferrosmart.keys]` takes `private_key_files`, the
  key files in the order they take over, and `rotation_period` (`90d` by
  default) in place of `private_key_file`, `kid`,
  `next_private_key_file`, `previous_private_key_file` and
  `previous_key_overlap`. The next key is published for at least the JWK
  Set's cache lifetime before it signs, the previous key stays published
  until every token it signed has expired, and every key is published
  under its RFC 7638 thumbprint. `GET /admin/keys` no longer carries
  `published`, since every key it lists is published (#684).
- FerroSMART moves to `ferrohealth-server` 0.12: `[server] request_decompression`, off by default, decodes a request body sent in gzip or Brotli under the body limit (FerroHEALTH/FerroSYS#408, #760).
- FerroSMART runs on PostgreSQL 19 and refuses to start against an older
  server, naming the `server_version_num` it found and the 190000 it needs.
  The quickstart and the CI store run `postgres:19.0`. PostgreSQL 18 is no
  longer supported and there is no upgrade path: a quickstart volume holding
  an 18 cluster is removed and created again (#762).
- Breaking: the database schema ships as one baseline migration per area,
  which later releases change in place. The schema it creates is the same
  as before, but sqlx refuses a database migrated by an earlier release,
  because the files' checksums changed, so such a database is created fresh (#795).
- A client lives only in FerroSMART's database. `[[ferrosmart.client]]` is
  gone, and a configuration that holds it is refused as an unknown key; the
  start no longer seeds or removes clients. `ferrosmart client apply
  <file>...` writes each file's JSON client document, the admin API's, as
  the API does, creating the client or replacing the one with its
  `client_id`, each change with an `AuditEvent` that names the command as
  the requester. The admin API answers `registered_by` (`admin` or `self`)
  in place of `source`, and the document carries `jwks` by value. The
  quickstart, the examples and the test lanes apply their clients this way
  (#799).
- Breaking: the client document is RFC 7591 client metadata, which the admin
  API, `ferrosmart client apply` and the store share. `kind` becomes
  `token_endpoint_auth_method` (`none`, `client_secret_basic`,
  `client_secret_post`, `private_key_jwt`), and a client authenticates only
  by the method it registered; `name` becomes `client_name`; `scopes`
  becomes the space-separated `scope`; the `token_exchange` grant is
  `urn:ietf:params:oauth:grant-type:token-exchange`; a client's
  `assurance_minimum` becomes `default_acr_values`, which a request without
  `acr_values` asks for. FerroSMART issues a symmetric client's secret,
  answers it once as `client_secret` with `client_secret_expires_at` 0 and
  keeps only its Argon2id hash: `secret_hash` and `ferrosmart client
  hash-secret` are gone, and `ferrosmart client secret <client_id>` issues
  a new secret. The `client` columns follow in the clients baseline (#800).
- Breaking: whether a person sees the consent page follows from the type of
  their `fhirUser` and how the client was registered. A `Practitioner` or
  `PractitionerRole` sees no page for an app an administrator registered,
  the registration being the organisation's consent (OpenID Connect Core
  1.0 §3.1.2.4); a `Patient`, `RelatedPerson` or `Person` sees none only
  for an app marked `first_party`; a person of no stated type, and every
  app that registered itself, see the page. `organisation_approval` is gone
  with its columns, `DELETE /admin/clients/{client_id}/organisation_approval`
  and the `organisation-approval-withdrawn` record; `first_party` is a
  member of the client document only an administrator sets, and clearing it
  revokes the grants issued on it. Each code and grant records its basis,
  `page`, `remembered`, `administrative` or `first-party`, and the records
  of a skipped page are `consent-administrative` and `consent-first-party` (#801).
- The patient picker lists assigned patients for a professional alone, a
  `fhirUser` that names a `Practitioner` or `PractitionerRole`, as the
  consent page reads it (#801).
- Breaking: the deployment's name is one key, `[ferrosmart] name`, which
  every page carries and which the User Access Brand takes as its
  `Organization.name` when `[ferrosmart.brand]` names none.
  `[ferrosmart.branding] name` is gone; a configuration that sets it is
  refused as an unknown key (#803).
- The token exchange of a patient's own token may also issue
  `patient/aql-*.s`, running a query on the person's EHR (SMART on openEHR,
  Resource Scopes), beside `patient/composition-*.r`; a request naming no
  scope gets those of the two the client's ceiling admits (#809).

### Security

Shipped with functional changes because: the `url` fix is a lockfile move on `main`, where the server's releases are cut and the unreleased changes above already sit, so a security-only patch has no tree of its own to come from.

- The server takes `url` 2.5.9 in place of 2.5.8 (RUSTSEC-2026-0592,
  GHSA-hrj5-67jp-wqp9): every earlier `url` lets `Url::origin()` recurse
  without a bound on a nested `blob:` URL, so a crafted URL overflows the
  stack (#770).

## [0.3.0] - 2026-11-21

### Added

- Breaking: `[[ferrosmart.client]]` takes `resources`, the
  `[[ferrosmart.resource]]` bases the client's tokens may name in `aud`.
  An authorization request, a client credentials request, a refresh, a code
  redemption or a launch registration naming any other base is refused
  `invalid_target` (RFC 8707 §2), and a client credentials request without
  `resource` takes the one base the client lists alone. A client that lists
  none reaches no resource server, only FerroSMART's own endpoints, so every
  client table adds the bases it is for; a base no
  `[[ferrosmart.resource]]` table configures is refused at load. The admin
  API's client document carries `resources` too, and a base taken off a
  client's list is refused from its next request (#682).
- The admin API: `GET` and `POST /admin/clients`, `GET` and
  `PUT /admin/clients/{client_id}`, `POST .../disable`, `POST .../enable`
  and `DELETE .../organisation_approval` change the client registry while
  FerroSMART runs, and `GET /admin/keys` lists the signing keys with their
  states. Each request needs an access token FerroSMART issued for its own
  issuer with the new `system/admin` scope, confirmed against the store on
  every request, and each change commits with its audit record
  (`client-created`, `client-updated`, `client-disabled`,
  `client-enabled`). Withdrawing an organisation approval or disabling a
  client revokes its grants, refresh tokens and access tokens at once, at
  every replica, with no restart (#683).
- An OpenID Connect `[[ferrosmart.upstream]]` entry may name
  `preset = "keycloak"`, `"entra"`, `"okta"` or `"zitadel"`: the scopes,
  the `fhirUser` and role claims and the assertion algorithm of
  FerroSMART's tested setup with that provider, read from a data file
  under `app/ferrosmart/presets/` with the vendor's documentation cited
  beside each value. A key the entry's `[ferrosmart.upstream.oidc]` table
  sets wins over the preset, and the examples for the four providers use
  them (#733).
- `ferrosmart subject --upstream <name> --sub <sub>` prints the
  FerroSMART `sub` of a person from their subject at that provider, the
  pairwise identifier a resource server binds them by
  (`docs/architecture.md` §13.6 item 9), and the management page shows the
  signed-in person their own (#733).
- `ferrosmart upstream registration <name>` prints what the provider must
  be configured with: the redirect and logout URIs, the client
  authentication with its JWK Set URL or certificate, PKCE `S256`, the
  scopes, the claims and the roles, or for SAML 2.0 the entity IDs, the
  assertion consumer service and the attributes. Both commands read the
  configuration alone, with no key, secret or database (#733).

### Changed

- The `[[ferrosmart.client]]` tables seed the registry: a client the admin
  API created or changed keeps the store as its source, its table is no
  longer written at start, and start logs a warning naming it. A disabled
  client is found by no request, and its people's remembered consents are
  forgotten (#683).
- The management page lists every app holding live access to the person's
  data, organisation-approved and first-party apps included, each with a
  Disconnect button. Disconnect forgets the person's remembered consent and
  revokes the app's grants, refresh tokens and access tokens about them at
  once, and leaves the organisation approval standing; the
  `consent-withdrawn` record names the grants revoked (SMART App Launch
  2.2.0, `offline_access` and `management_endpoint`) (#725).
- A public client gets an authorization code with no consent page, on an
  organisation approval or a remembered consent, only when the request's
  redirect URI is a claimed `https` URI. A custom-scheme or loopback
  redirect shows the page, with a remembered choice ticked, and
  `ferrosmart config check` warns of a first-party public client with no
  claimed `https` redirect (RFC 8252 §8.6, §7.2; RFC 6749 §10.2).
  Confidential clients are unchanged (#726).
- A remembered consent is bound to the resource server it was given for:
  it answers only for the same client, the same `aud` and scopes it fully
  covers. The store migration drops the consents kept under the old key,
  so each person is asked once again (#727).
- Every `authorization-code` audit record names the basis of the code as
  its `basis` detail: `page`, `remembered`, `organisation` or
  `first-party` (#727).
- An organisation approval may list `patient/` scopes for staff, and it
  covers them in a professional's EHR launch with no consent page
  (OpenID Connect Core 1.0 §3.1.2.4). A standalone request for `patient/`
  scopes and every patient keep the page, unless the app is first party (#727).
- A client's ceiling and a role's scopes admit a requested `patient/`,
  `user/` or `system/` scope whose permission letters are a subset of a
  listed scope's, in the same context, on the same resource or under the
  wildcard `*`, and with the same query parameters, or any when the listed
  scope names none (SMART App Launch 2.2.0, SMART v2 scopes). A ceiling of
  `patient/Composition.crs` admits `patient/Composition.rs` and `.r`, so a
  deployment lists each resource once. A query-restricted ceiling still
  never admits the unrestricted scope (#731).
- Breaking: the `protocol` key of `[[ferrosmart.upstream]]` is removed, and
  the table present names the protocol: `[ferrosmart.upstream.oidc]` for
  OpenID Connect or `[ferrosmart.upstream.saml]` for SAML 2.0, exactly one
  per entry. A configuration that still sets `protocol` is refused as an
  unknown key; delete the line (and `FERROSMART__…__PROTOCOL` from the
  environment). `private_key_jwt` is taken when an entry names no client
  authentication table, so the empty
  `[ferrosmart.upstream.oidc.private_key_jwt]` header goes too and
  `[ferrosmart.upstream.oidc.private_key_jwt.keys]` alone is enough; an
  entry without the assertion key is refused for that missing key (#733).

### Fixed

- The RFC 8414 and OpenID Connect metadata list `refresh_token` in
  `grant_types_supported`, since the token endpoint serves that grant (RFC
  8414 §2). The token endpoint refuses every grant its metadata leaves out
  as `unsupported_grant_type`, so without a login the authorization code
  grant is refused (#735).

## [0.2.0] - 2026-11-20

### Added

- An openEHR `[[ferrosmart.resource]]` can name the platform's FHIR server
  as its `fhir_base`, with the `subject_system` of the `Patient.identifier`
  that names the EHR's subject. At such a base the patient picker searches
  the FHIR server and looks the chosen patient's EHR up at the openEHR
  server, each as the signed-in person, so a standalone launch with
  `launch/patient` gets both `patient` and `ehrId` (SMART on openEHR draft,
  Context Selection and Service Discovery). A patient without an EHR the
  person may see is told so and enters no context (#574).
- The introspection endpoint takes a confidential symmetric client's
  secret, by HTTP Basic or in the form, as the token endpoint does (RFC
  7662 §2.1, RFC 6749 §2.3.1), so a gateway that introspects with
  `client_secret_basic`, such as Apache APISIX, can sit in front of a
  resource server. The client's ceiling lists `system/introspect`; a wrong
  secret answers `401` `invalid_client` and a client without the scope
  `401` `unauthorized_client`, each challenged `Basic`. The metadata's
  `introspection_endpoint_auth_methods_supported` lists
  `client_secret_basic` and `client_secret_post` beside `private_key_jwt`
  (#639).
- An administrator can approve one of the organisation's own apps for its
  staff with `[ferrosmart.client.organisation_approval]` (scopes, who,
  when), so a professional who opens it sees no consent page (SMART App
  Launch 2.2.0, Obtain authorization code, Response). Only `user/` scopes
  with their launch, OpenID, refresh and extension scopes can be approved;
  a request with a `patient/` scope, a patient's own login and a request
  beyond the approval show the page. The granted scope never exceeds the
  person's roles. Each skipped page is audited with the approval as its
  basis, the management page lists the app as approved by the
  organisation, and clearing the approval revokes every token issued on it
  at the next start (#643).
- A `[[ferrosmart.role]]` may grant extension scopes, those that start with
  two underscores (SMART App Launch 2.2.0, Scopes and Launch Context,
  Extensibility), such as FerroEHR's `__ferroehr.platform`. A person is
  granted one when the request asks for it, the client's ceiling lists it
  and one of their roles grants it; the consent page names it in plain
  words, and `scopes_supported` lists every extension scope a role grants.
  Any other scope outside the SMART set is still never granted to a person
  (#647).
- The access token of a user flow carries the person's roles in a `roles`
  claim (RFC 9068 §2.2.3.1): the roles the identity provider's
  `role_claims` carry that a `[[ferrosmart.role]]` names, fixed at login
  and kept through every refresh. The introspection response carries them
  too. A Backend Services token carries none (#649).
- `.well-known/smart-configuration` and the RFC 8414 metadata name the EHR
  launch API as `launch_registration_endpoint` (`{issuer}/launch`) whenever
  the app launch is configured, so an EHR reads it from the documents
  instead of building the path (#657).
- A `[[ferrosmart.client]]` may register its app's `launch_uri`, and the
  EHR launch API takes `app_launch_uri` in place of `app_client_id`, so an
  EHR acting on a SMART `task-ehr-launch` Task, which names the app only by
  its launch URL, can register the launch. The URLs are compared after RFC
  3986 §6.2.2 normalization, and two clients may not register one (#659).
- The EHR launch API takes a Task's `appContext` (at most 8192 bytes), and
  the token response of that launch carries it unchanged as `appContext`
  (SMART App Launch 2.2.0, Task profile for requesting a SMART launch)
  (#660).
- The authorization endpoint meets what OpenID Connect Core 1.0 §15.1
  has every OpenID Provider implement, beside SMART App Launch 2.2.0's
  PKCE and `aud`, which stay required. `prompt=none` answers
  `login_required` with no page, and `none` beside another value is
  `invalid_request`. `prompt=login` and `select_account` reach the upstream
  login, and `prompt=consent` shows the consent page where a remembered
  consent or an organisation approval would answer. `max_age` reaches the
  upstream login: a login older than it, or one that names no
  `auth_time`, is begun again once with `prompt=login`, and one still
  older answers `login_required`. The ID Token's `auth_time` is the
  upstream login's. `ui_locales` reaches the upstream login and chooses
  the pages' language before `Accept-Language`. `display`,
  `claims_locales` and `acr_values` are taken. The OpenID Connect
  discovery document names `display_values_supported` and
  `ui_locales_supported` (#662).
- A refresh request may name a `resource` (RFC 8707 §2.2): the grant's
  own resource server or the FHIR base paired with its openEHR base, so an
  app signed in at the openEHR base gets a token for the platform's FHIR
  server on the same grant. The token's `aud` is that resource alone and
  its scope is the grant's, less the clinical scopes of the other kind;
  the scope never widens, and any other resource is `invalid_target`
  (#663).
- An administrator can mark an approved app as the organisation's own with
  `first_party = true` on its `[ferrosmart.client.organisation_approval]`.
  Its approval may then list `patient/` scopes, and a patient, related
  person or person who logs in to it sees no consent page while the
  approval covers every scope offered. An app without the mark keeps the
  page for every patient. Each skipped page is audited as
  `consent-first-party-approved`, the management page lists the app as the
  organisation's own, and setting or clearing the mark withdraws the old
  approval with every token issued on it (#666).
- The consent page draws identity, launch and refresh scopes (`openid`,
  `fhirUser`, `profile`, `email`, `launch`, `launch/*`, `offline_access`,
  `online_access`) as fixed lines with no box, granted with the app whatever
  the form posts, so a person can no longer untick a scope the app cannot
  work without; resource and extension scopes keep their boxes. A
  `[[ferrosmart.client]]` may register `client_uri`, `logo_uri`,
  `policy_uri` and `tos_uri` (RFC 7591 §2, absolute `https` URLs), which the
  consent page links and draws, with the logo's origin admitted by the
  page's `img-src` alone. The store gains a migration (#668).
- A standalone authorization request that asks a `patient/` scope without
  `launch/patient` is read as asking `launch/patient`, so the patient picker
  supplies the patient instead of the `patient/` scopes being dropped, and
  the granted `scope` names the inferred `launch/patient` (SMART App Launch
  2.2.0, Scopes and Launch Context, Standalone apps) (#669).
- An authorization request without `aud` (or `resource`) defaults to the
  resource server when the deployment configures exactly one, as the token
  endpoint already defaults `resource`; with two or more it is still refused,
  and a wrong `aud` is refused either way. Apps should still send `aud`, as
  SMART App Launch 2.2.0 requires (#670).
- When no requested scope can be granted to the person, FerroSMART shows a
  page that names the configured roles that would grant one (or says the
  app asks for access the server does not give it), and its button returns
  to the app with `access_denied`, the `state` and the `iss`, in place of
  sending `invalid_scope` back at once. The refusal is written as an
  `authorization.refused` audit line (#672).
- A patient whose `fhirUser` names their own `Patient` at the requested
  FHIR server, absolute or relative to its base, or at the FHIR server
  paired with the requested openEHR server, sees no patient picker: their
  record, read again as them, is the launch context, with their EHR at a
  paired base, and a record that cannot be read is a page that says so.
  They are offered the client's `patient/` scopes without a role. A
  professional still picks. `consent::offer` takes a `FhirUser` in place of
  the `has_fhir_user` flag (#673).
- When the identity provider sends no `fhirUser` claim, FerroSMART can
  find the person by an identifier: each
  `[[ferrosmart.resource.fhir_user_lookup]]` of a FHIR base names a
  `resource_type`, the upstream `claim` holding the identifier's value and
  the identifier's `system`, and FerroSMART searches
  `[base]/[type]?identifier=[system]|[value]` as the person. One match is
  the `fhirUser`; none, several or a refused search leave it out, the
  consent page says so, and a `fhir_user.lookup` audit line records the
  outcome without a value. A lookup on the FHIR base paired with an openEHR
  base serves that base too (#674).
- The `profile` and `email` scopes are offered within a client's ceiling,
  listed in `scopes_supported`, and, when granted, pass the upstream ID
  Token's `name` and `preferred_username` (`profile`) and `email` and
  `email_verified` (`email`) into FerroSMART's ID Token, never into an
  access token (OpenID Connect Core 1.0 §5.4). `claims_supported` lists the
  four. The store gains a migration (#676).
- FerroSMART takes OpenID Connect Front-Channel Logout 1.0 at
  `{issuer}/frontchannel-logout`: a provider that offers only front-channel
  logout, such as Microsoft Entra ID, renders it in an iframe with its
  `iss` and the login's `sid`, and the sessions of that `sid` end with their
  `online_access` grants. The page is never cached and only the provider's
  origins may frame it (#677).
- FerroSMART has an end-session endpoint (OpenID Connect RP-Initiated
  Logout 1.0), named as `end_session_endpoint` in discovery: it checks the
  `id_token_hint` it issued, the `client_id` and a `post_logout_redirect_uri`
  the client registers under the new `post_logout_redirect_uris` key, asks
  the person to confirm, ends their `online_access` grants, forwards to the
  provider's own end-session endpoint and returns the browser to the app
  with its `state`. Register `{issuer}/logout/return` at the provider as a
  post-logout redirect URI. Each logout is audited as `logged-out`, and the
  store gains a migration (#677).
- An upstream provider entry may authenticate with a client secret as HTTP
  Basic: `[ferrosmart.upstream.oidc.client_secret_basic]` with `secret_file`
  (or `secret`), in place of the default
  `[ferrosmart.upstream.oidc.private_key_jwt]`. Each entry names exactly one
  of the two, the secret never shows in a log or a debug rendering, and
  FerroSMART refuses to start when the provider's
  `token_endpoint_auth_methods_supported` does not list the method chosen (#679).
- A person can log in at a SAML 2.0 identity provider: a `protocol =
  "saml"` entry in `[[ferrosmart.upstream]]` with its
  `[ferrosmart.upstream.saml]` table, and FerroSMART as one service
  provider in `[ferrosmart.saml]`, its metadata at
  `{issuer}/saml/metadata`. The assertion consumer service
  `{issuer}/saml/acs` takes a response by HTTP-POST or an artifact,
  resolved over mutual TLS; the provider's metadata is read again on a
  timer; each assertion is admitted once, on every replica; the classes
  at or above the provider's minimum assurance are asked for and any
  other is refused; the `claims` table maps attributes to the claims of
  `fhirUser`, the roles and the `fhirUser` lookup; and every outcome is a
  `110122` Login record naming the check that failed. The chooser lists a
  SAML provider beside an OpenID Connect one. An entry without
  `[ferrosmart.saml]` or with an incomplete table is refused at load (#688).
- The patient picker's token carries the person's `roles`, and an openEHR
  `[[ferrosmart.resource]]` may list the purposes of use its server accepts
  (`[[ferrosmart.resource.purpose]]`, with `purpose_header`, default
  `x-purpose-of-use`). A professional chooses one on the picker page, the
  EHR lookup and the look-up-again of the choice declare it in that header,
  the request keeps it so the two cannot differ, and each lookup's access
  record names it (`purposeOfEvent`). A patient's own lookup declares none (#716).

### Changed

- A client presenting a rotated refresh token again within 10 seconds of
  its rotation, while the new refresh token is neither used nor revoked,
  gets that same new refresh token and a fresh access token instead of
  having the grant revoked, so a retry after a lost response or two
  requests racing (two tabs, two backend instances, two replicas) keep the
  grant. A repeat after the window, by another client, or once the new
  token was used still revokes the grant (RFC 9700 §2.2.2, §4.14.2; the
  window is FerroSMART's own design). Each repeat is recorded as
  `refresh-repeated`. The store gains a migration (#667).
- FerroSMART logs people in at several identity providers. `[ferrosmart.upstream]`
  becomes `[[ferrosmart.upstream]]`, one entry per provider with a `name`,
  an optional `label` and `protocol = "oidc"`, whose OpenID Connect keys
  (`issuer`, `client_id`, `scopes`, `fhir_user_claim`, `role_claims`,
  `trusted_audiences` and the `private_key_jwt` table) move into
  `[ferrosmart.upstream.oidc]`; an environment override is now
  `FERROSMART__FERROSMART__UPSTREAM__0__OIDC__ISSUER` and a `--set` is
  `ferrosmart.upstream.0.oidc.issuer`. A `[[ferrosmart.client]]` names its
  providers in `upstreams` (every provider when it names none): one sends
  the browser straight there, several show a chooser at `{issuer}/login`.
  Several Microsoft Entra ID tenants are several entries. Back-channel and
  front-channel logouts are matched to their provider by `iss`, and
  `{issuer}/upstream-jwks` publishes every provider's assertion keys. The
  store gains a migration (#678).

### Fixed

- The upstream login refuses an ID Token without `iat` (OpenID Connect
  Core 1.0 §2), and takes one without `kid` when a single key of the
  provider's set fits its algorithm. The OpenID Foundation conformance
  suite's relying party modules `oidcc-client-test-missing-iat` and
  `oidcc-client-test-kid-absent-single-jwks` found both (#646, #648).

## [0.1.0] - 2026-11-19

### Added

- The book shows every page a person meets during a launch, in the light
  and the dark theme: the consent page of a clinician app and of a patient
  app, the patient picker, the management page and the three error pages.
  The README and the landing page show the consent page (#623).
- `[ferrosmart.brand]` publishes the deployment's User Access Brands Bundle
  at `GET {issuer}/brands` (SMART App Launch 2.2.0, User Access Brands and
  Endpoints): a primary brand that references every FHIR endpoint, its
  portals and its affiliated brands, as `application/fhir+json` with CORS
  for any origin and a weak `ETag` an `If-None-Match` answers with `304`.
  `Bundle.timestamp` is the last change to the contents and each resource's
  `meta.lastUpdated` its own, which the store keeps across restarts and
  replicas. The Bundle is held to the guide's
  profiles with `ferrobridge-validator` over the package set
  `scripts/vendor/fhir-packages.sh` fetches (#602).
- The management page lists every app that holds a live `offline_access`
  or `online_access` grant of the person, remembered or not, says how long
  it stays connected, and withdraws it, as SMART App Launch 2.2.0, Best
  Practices asks a server to remind people which apps have offline access
  (#608).
- The consent and management pages put plain words before a FHIR resource
  type, "Measurements and test results (Observation)", for the common
  types (SMART App Launch 2.2.0, Best Practices, Considerations for Scope
  Consent) (#608).
- `ferrosmart client hash-secret` reads a confidential symmetric client's
  secret on standard input and prints its Argon2id hash at the OWASP floor
  (m=19456, t=2, p=1) with a fresh salt, the string `secret_hash_file`
  holds. The Inferno lane runs its EHR launch with a symmetric client made
  this way (#601).
- A standalone launch that asks for `launch/patient` and `launch/encounter`
  at a FHIR resource server gets an encounter step in the picker: the
  chosen patient's encounters, searched as the signed-in person with the
  scope `user/Encounter.rs`, latest first. The person picks one or goes on
  without, which drops `launch/encounter` from the offer. The chosen
  encounter is read again and enters the context only when its `subject` is
  that patient, and the token response and the access token carry it. The
  discovery document lists `context-standalone-encounter` when a resource
  server is a FHIR one (SMART App Launch 2.2.0, Scopes and Launch Context,
  Standalone apps) (#604).
- SMART v1 scopes (`patient/Observation.read`, `.write`, `.*`) are
  admitted by their v2 form against a client's ceiling and a person's roles
  and granted as asked, as SMART App Launch 2.2.0, Scopes and Launch
  Context has a server process them, and the discovery document lists
  `permission-v1` (#604).
- Confidential symmetric clients (SMART App Launch 2.2.0, Client
  Authentication: Symmetric): `kind = "confidential_symmetric"` with
  `secret_hash_file`, the Argon2id PHC hash of the client's secret at the
  OWASP floor, never the secret. The client authenticates at the token and
  revocation endpoints by `client_secret_basic` or `client_secret_post`
  (RFC 6749 §2.3.1); a failed Basic credential answers `401` with
  `WWW-Authenticate: Basic`, two methods in one request are refused, and
  the client credentials grant and a JWK Set are refused at load. The
  discovery documents list both methods and `client-confidential-symmetric`.
  Migration `0008` adds the hash to the client table (#601).
- The patient picker at an openEHR resource server: for a standalone launch
  with `launch/patient` at an openEHR base whose `[[ferrosmart.resource]]`
  table names a `subject_namespace`, the signed-in person enters the
  patient's identifier and FerroSMART looks the EHR up through ITS-REST
  (`GET [base]/ehr?subject_id=…&subject_namespace=…`) with a token of the
  person's own, living 30 seconds and revoked after use. The chosen EHR is
  looked up again before its `ehrId` enters the launch context, the token
  response and the access token, and every lookup writes the EHDS access
  record (#571).
- `[ferrosmart.upstream.private_key_jwt]`: FerroSMART authenticates at its
  upstream provider with a JWT (OpenID Connect Core 1.0 §9) signed by the
  current key of its own assertion ring,
  `[ferrosmart.upstream.private_key_jwt.keys]`, read as `[ferrosmart.keys]`
  is and published apart at `{issuer}/upstream-jwks`, so an assertion key
  never signs a token (RFC 8725 §3.12). It signs at the `algorithm` the
  provider's registration names (RS256 by default) and names the key's
  certificate by `x5t#S256` when `certificate_file` is set. A client secret
  beside it, an algorithm the key cannot sign, a certificate of another key
  and an assertion ring sharing a key with the token ring are refused at
  load. The Entra ID example uses it with a certificate
  credential and `PS256`, and its contract test verifies the assertion the
  stub receives (#569).
- Microsoft Entra ID and Okta as the upstream login, each with an example
  configuration under `examples/` and no provider code. Entra ID: a
  single-tenant app registration's v2.0 authority, the app roles in `roles`
  and the directory extension attribute `fhirUser` as the optional claim
  `extn.fhirUser`; the multitenant `/common` and `/organizations`
  authorities fail discovery, since their metadata names another issuer.
  Okta: the `default` custom authorization server, a `groups` claim and a
  custom `fhir_user` claim. Contract tests run each example through a
  standalone launch against a stub serving the provider's published
  discovery document, key set and token answer (#524, #525).
- ZITADEL as the upstream login (`compose.zitadel.yaml`, an override of the
  quickstart): `app/ferrosmart/examples/zitadel/bootstrap.sh` makes the
  project, its role, the application, the user and an Actions v2 target
  through ZITADEL's v2 APIs and writes FerroSMART's configuration, and the
  target, `tools/zitadel-fhir-user`, writes the user's `fhirUser` claim. CI
  drives a SMART standalone launch through it to a token with the mapped
  `fhirUser` and a role-granted scope (#523).
- `[ferrosmart.upstream] trusted_audiences`: the audiences an upstream ID
  Token may name beside FerroSMART's client id (OpenID Connect Core 1.0
  §3.1.3.7 item 3) (#523).
- The Inferno lane runs group 1, Standalone Launch: the person picks the
  lane's patient at the patient picker, which searches FerroBRIDGE's
  facade, so the launch carries `launch/patient`. All four groups of the
  kit's STU 2.2 suite run, and every test passes against FerroBRIDGE
  0.0.27, whose facade answers CORS for the kit's origin (#520).
- The Inferno lane runs its FHIR server on the family's own stack: FerroBRIDGE's
  facade, with FerroEHR as its CDR, serves the person's `fhirUser` as a
  Practitioner, and Keycloak is the upstream login. Group 4, Token
  Introspection, and group 2, EHR Launch, with the lane as the EHR, run beside
  group 3, and the discovery exception that waited on the authorization
  endpoint is gone (#520).
- `compose.keycloak.yaml`, an override of the quickstart that runs Keycloak
  with the example realm as the login of `compose.yaml`'s FerroSMART, in the
  same compose project (#522).
- A Keycloak example as the upstream login: a realm with fixed ids whose
  confidential client `ferrosmart` takes the authorization code flow with
  PKCE S256, and whose mappers write the user's `fhir_user` attribute and
  realm roles into the ID Token, and the `[ferrosmart.upstream]` and
  `[[ferrosmart.role]]` configuration that reads them, with no Keycloak code.
  CI drives a SMART standalone launch through it to a token with the mapped
  `fhirUser` (#522).
- The `ferrosmart` server: `serve`, `config check` and `healthcheck` on the
  family's stack, the `[ferrosmart]` configuration with its issuer and
  `RS256` signing key ring (current, previous and next key), the RFC 8414
  metadata, the SMART configuration and the JWK Set (#514).
- The PostgreSQL store with its embedded migrations, run under the
  advisory lock of `sqlx` at start, and its readiness indicator; the client
  registry of `[[ferrosmart.client]]` tables, each checked against SMART's
  registration rules (a JWK Set by URL or by value, with `kty`, `kid` and
  bare public members) and written to the store at every start (#514).
- The token endpoint with SMART Backend Services' client credentials grant.
  The `private_key_jwt` assertion is checked as SMART App Launch 2.2.0,
  Client Authentication: Asymmetric, has it: RS384 or ES384, `typ` `JWT` or
  `client-authentication+jwt`, one key by `kid` from the registered set or
  URL, a `jku` only as registered, an `aud` of one string naming the token
  endpoint or the issuer, an `exp` at most five minutes ahead, and a `jti`
  used once across replicas. The scope is narrowed to the client's ceiling,
  the audience is chosen by `resource` (RFC 8707) among
  `[[ferrosmart.resource]]`, and the RFC 9068 access token is signed under
  `RS256`, recorded in the store and answered with `no-store`. Each refusal
  is its RFC 6749 §5.2 error, and every issue and refusal writes an audit
  line (#514).
- The EHR launch API, FerroSMART's own design since SMART defines none
  (#517). An EHR client whose ceiling lists `system/launch.c` posts the
  launch context to `POST /launch`, authenticated with its
  `private_key_jwt` assertion as at the token endpoint, and receives a
  single-use `launch` value that lives five minutes, stored as its SHA-256
  and bound to the EHR, the app (`app_client_id`) and the resource server
  (`resource`). An EHR can instead sign a `launch+jwt` with a key of its
  registered JWK Set and hand it to the app as the `launch` value; its
  `iss`, sole `aud`, `exp` and `jti` are checked and a replay is refused.
  The context (`patient`, `encounter`, `fhirContext`, `intent`,
  `need_patient_banner`, `tenant`, and `ehrId` for an openEHR server) is
  checked against SMART's rules, and an unknown parameter or claim is
  refused. At `/authorize` a `launch` with the `launch` scope is redeemed
  for that app and `aud`, the consent page offers `launch`, its
  `launch/patient` and `launch/encounter` hints and the `patient/` scopes
  its patient allows, and the token response carries the context when the
  person keeps `launch`, with `patient`, `encounter` and `ehrId` in the
  access token too. The SMART configuration lists `launch-ehr`,
  `context-ehr-patient`, `context-ehr-encounter`, `context-banner` and
  `permission-patient`.
- The authorization code flow of SMART App Launch 2.2.0, standalone
  launch: the authorization endpoint by `GET` and `POST` (code with PKCE
  `S256` only, `aud` among the configured resource servers, the redirect URI
  matched exactly, an untrusted client or redirect shown and never
  redirected to), the login at any OpenID Connect provider through
  `[ferrosmart.upstream]`, the person's pairwise `sub`, `fhirUser` and roles
  from configured claims, the scopes narrowed by the client's ceiling and
  `[[ferrosmart.role]]` before the consent page, which FerroUI draws in the
  FerroSMART brand with no script and lets the person untick any scope,
  decline or remember the choice, the single-use code with `state` and
  `iss` (RFC 9207), and the code exchange for public and asymmetric clients
  with an RFC 9068 access token, an RS256 ID Token carrying `fhirUser` and
  the `smart_style_url` of `[ferrosmart.branding]`;
  a second use of a code revokes what the first issued. `GET /manage` lists
  the remembered choices and withdraws one, and the OpenID Connect
  discovery document and the App Launch SMART configuration describe the
  login once it is configured (#515).
- The introspection endpoint, `POST /introspect` (RFC 7662 with SMART App
  Launch 2.2.0, Token Introspection): a client whose ceiling lists
  `system/introspect` authenticates by its assertion or presents a bearer
  token FerroSMART issued for its own issuer with that scope, and may
  introspect any client's token. An active token answers `scope`,
  `client_id`, `exp`, `iat`, `sub`, `aud`, `iss`, the grant's launch
  context and `fhirUser`; an expired, revoked, forged or unknown token
  answers `{"active": false}` alone (#518).
- The revocation endpoint, `POST /revoke` (RFC 7009): a confidential client
  by its assertion, a public client by `client_id`, each only for its own
  tokens. Revoking a refresh token revokes its grant with every token under
  it; an unknown token answers `200` (#518).
- The refresh token grant at the token endpoint (SMART App Launch 2.2.0,
  Refresh access token): a public client by `client_id`, a confidential
  one by its assertion, each only with its own token. Every refresh
  rotates the token; a rotated token presented again revokes its grant
  with every token under it (RFC 9700 §4.14.2). A `scope` may narrow the
  grant and never widen it, the rotated token keeps the grant's scope, and
  the answer carries the launch context. `[ferrosmart] refresh_idle`
  (thirty days) and `online_idle` (eight hours) set how long an
  `offline_access` and an `online_access` refresh token last unused, and
  an `online_access` one ends with its upstream session. A client
  registers `refresh_token` only beside `authorization_code`. The code
  exchange opens the grant and answers its first refresh token when the
  person granted `offline_access` or `online_access`, which the consent page
  offers only to a client whose ceiling lists it and that registers
  `refresh_token`; each login at the upstream provider is recorded as the
  session an `online_access` grant ends with, and withdrawing a remembered
  consent revokes its grants (#518).
- `POST /backchannel-logout`, the back-channel logout URI to register at
  the upstream provider (OpenID Connect Back-Channel Logout 1.0): a Logout
  Token that checks ends the upstream sessions it names and revokes their
  `online_access` grants with every token under them, leaving
  `offline_access` grants; a token that does not check answers `400` with an
  OAuth 2.0 error body, every answer `no-store` (#518).
- Migration 0005: the grants, the refresh tokens stored as their SHA-256,
  the upstream sessions an `online_access` grant ends with, and the grant
  of each access token, so revocation reaches every replica at once. The
  RFC 8414 metadata names both endpoints and their client authentication
  methods (#518).
- The release lane: a `ferrosmart-vX.Y.Z` tag builds `x86_64` and `aarch64`
  tarballs for GNU and musl libc, each with its checksum, a CycloneDX and an
  SPDX SBOM and SLSA Build Level 3 provenance signed through Sigstore, and
  the image `ghcr.io/ferrohealth/ferrosmart` for `linux/amd64` and
  `linux/arm64` on distroless static, pushed by digest with its provenance
  and SBOMs as OCI referrers. Every finding of a full scan of the image and
  the tarballs needs an OpenVEX judgement before the release publishes, and
  the image is tagged only once it carries no fixable HIGH or CRITICAL
  finding, and a weekly scan of the published image files an issue for a
  new fixable one. `compose.yaml` is the quickstart beside PostgreSQL,
  attached to every release (#519).
- The audit records, kept in FerroSMART's own store (migration 0007): every
  token request, issued or refused, is the ITI-71 audit event in the form
  of BALP 1.1.4's `IHE.IUA.71`, and every login at the upstream provider a
  DICOM User Authentication event of type Login, each a FHIR R4
  `AuditEvent` written through `ihe-atna`. An issued token and its record
  commit in one transaction; a token request whose record cannot be
  committed is answered `503` with no token, and a login whose record
  cannot be committed goes no further. A record names the client, the
  person's pairwise subject and the token's `jti`, never a token, an
  assertion, a verifier or a secret. The optional `[ferrosmart.audit.feed]`
  forwards the records to an Audit Record Repository over the ITI-20 ATX:
  FHIR Feed, and `GET /audit` reads them by subject and time with a token
  carrying `system/AuditEvent.rs` (#534).
- The Inferno SMART App Launch test kit lane: the kit's STU 2.2 suite runs
  in CI against FerroSMART with FerroEHR as the resource server, every
  exchange over TLS, and fails on any result that differs from the expected
  results, which hold each test to `pass` outside a listed exception. Group
  3, Backend Services, runs; the groups whose steps have not landed are
  listed as pending in every run (#520).
- Every other write FerroSMART makes for a person or a client commits with
  its audit record in one transaction: a code issued, a consent remembered
  or withdrawn, a token or a grant revoked, a refresh token rotated or
  reused, a code reused, and an upstream session ended (DICOM Logout). Their
  codes are in `urn:ferrosmart:audit-event`, our own design where no IHE or
  BALP pattern exists, and a write whose record cannot be committed does
  not happen (#554).
- The EHR launch API writes audit records (#558): a registration commits
  with its launch row and a redemption with its use in one audited
  transaction (`launch-registered`, `launch-redeemed`), and a refused
  registration or redemption is a `launch-refused` record. A launch whose
  record cannot be kept is not kept. No record holds the launch value or a
  context value.
- The patient picker of a standalone launch: a client that may ask for
  `launch/patient` at a FHIR resource server is shown, after the login and
  before the consent, a page that searches `Patient` by name or identifier
  as the signed-in person, with a token of FerroSMART's own carrying their
  pairwise `sub` and `fhirUser`, scope `user/Patient.rs`, living 30 seconds
  and revoked after the request. The chosen patient is read again as them,
  enters the launch context, and reaches the token response and the access
  token as an EHR launch's does. Every search and read writes the access
  record of Regulation (EU) 2025/327 Annex II 3.2 through `ehds-logging`,
  and a failed search is an error page (#516).

### Changed

- The consent, picker, management and error pages draw FerroSMART's own
  mark, the shield with the keyhole, through FerroUI 0.6.11
  (`view::shell::ferrosmart_mark`), in the brand's yellow fill roles, where
  they drew a key glyph; the error pages now lead with the same lockup
  (#612).
- `access_token_lifetime` above one hour is refused at load, as SMART App
  Launch 2.2.0, App Launch has access tokens live no longer (#604).
- FerroSMART authenticates to every upstream identity provider with
  `private_key_jwt` alone (OpenID Connect Core 1.0 §9).
  `[ferrosmart.upstream.private_key_jwt]` is required, and the keys
  `client_secret` and `client_secret_file` are gone from
  `[ferrosmart.upstream]`, so a configuration that names one is refused at
  load, as is a public upstream client. Each assertion names the provider's
  issuer as its sole `aud` and is typed `client-authentication+jwt`
  (RFC 10070 §4). The Okta example moves to a public key on the
  integration, the ZITADEL bootstrap to Private Key JWT with the
  application key ZITADEL generates, held under its key id, and the README,
  the architecture and the book describe all four providers in one shape:
  login, client authentication, `fhirUser`, roles and how each is tested
  (#619).
- The Keycloak example authenticates FerroSMART with `private_key_jwt`: the
  realm's client takes the `client-jwt` authenticator and reads
  FerroSMART's `{issuer}/upstream-jwks`, so `compose.keycloak.yaml` and the
  CI lanes make an `upstream_assertion_key` in place of a
  `keycloak_client_secret` (#569).
- The audit lane takes `ihe-atna` and `ehds-logging` 0.23. Their FHIR Feed
  sends through FerroSMART's own outbound client as a `FeedClient`
  (`audit_feed`), so FerroSMART links one copy of `ferrohealth-smart` with no
  `[patch.crates-io]` in the workspace (#549).

### Fixed

- A Backend Services access token lives at most five minutes, whatever
  `access_token_lifetime` says, as SMART App Launch 2.2.0, Backend
  Services, Issue Access Token has `expires_in` not exceed 300 (#603).
- A client assertion sent with a `client_id` other than its `iss` is
  refused with `invalid_client`, as SMART App Launch 2.2.0, Client
  Authentication: Asymmetric, Signature Verification requires (#601).
- An expired client assertion whose signature holds is refused as
  `invalid_client` with the description "the client_assertion has
  expired", told apart from one that does not verify (RFC 7523 §3). The
  examples of SMART App Launch 2.2.0 §9 run as test vectors (#609).
- The SMART configuration lists every capability FerroSMART supports and
  nothing else (SMART App Launch 2.2.0, Conformance, Capabilities): it adds
  `authorize-post`, `permission-offline`, `permission-online`,
  `context-standalone-patient` when the patient picker can search a
  resource server, and `context-style` when `[ferrosmart.branding]
  smart_style_url` is set. It names
  `token_endpoint_auth_signing_alg_values_supported` beside
  `private_key_jwt`, and `scopes_supported` lists the identity, launch
  context and refresh scopes FerroSMART honours (#600).
- The token endpoint answers a request from one of the client's registered
  origins, the origins of its redirect URIs, with
  `Access-Control-Allow-Origin` and `Vary: Origin`, so a browser app can
  read its token response (SMART App Launch 2.2.0, Considerations for CORS
  support). Every other origin gets no CORS header (#560).

[Unreleased]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrosmart-v0.9.0...HEAD
[0.9.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrosmart-v0.8.0...ferrosmart-v0.9.0
[0.8.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrosmart-v0.7.0...ferrosmart-v0.8.0
[0.7.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrosmart-v0.6.0...ferrosmart-v0.7.0
[0.6.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrosmart-v0.5.0...ferrosmart-v0.6.0
[0.5.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrosmart-v0.4.0...ferrosmart-v0.5.0
[0.4.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrosmart-v0.3.0...ferrosmart-v0.4.0
[0.3.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrosmart-v0.2.0...ferrosmart-v0.3.0
[0.2.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrosmart-v0.1.0...ferrosmart-v0.2.0
[0.1.0]: https://github.com/FerroHEALTH/FerroSMART/releases/tag/ferrosmart-v0.1.0
