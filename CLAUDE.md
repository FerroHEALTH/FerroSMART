<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# CLAUDE.md

**FerroSMART** is SMART for the openEHR ecosystem, FHIR included, and a
FerroHEALTH product (owner decision 2026-11-17,
`.claude/memory/ferrosmart.md`): the family's SMART App Launch 2.x
authorization server in `app/ferrosmart`, which ships as its own OCI image
and release artefacts, and beside it the shared SMART App Launch 2.x and
OAuth 2.0 resource-server crates of the FerroHEALTH products, FerroBRIDGE,
FerroEHR, FerroFED, FerroPIX and FerroTERM. The repository is one Cargo
workspace with three library crates in `crates/`, all published to
crates.io: `ferrohealth-smart` (Rust path `ferrohealth_smart`),
authentication and the granted subject; `ferrohealth-authz` (Rust path
`ferrohealth_authz`), the policy decision (the NIST SP 800-162 request
model, a Cedar engine behind `cedar`, a remote PDP behind `remote`), which
the owner assigned here on 2026-10-25 (`.claude/memory/family-architecture.md`);
and `ferrohealth-session` (Rust path `ferrohealth_session`), the operator
consoles' OpenID Connect sign-in and session store over
`ferrohealth-smart`'s relying party, which the owner placed here on
2026-11-03. Each crate keeps its own version line and tag:
`ferrohealth-smart-vX.Y.Z` releases `ferrohealth-smart`,
`ferrohealth-authz-vX.Y.Z` releases `ferrohealth-authz` and
`ferrohealth-session-vX.Y.Z` releases `ferrohealth-session`, and
`ferrosmart-vX.Y.Z` releases the server (`docs/release.md`).

FerroSMART in prose and in the repository name (FerroHEALTH/FerroSMART; it
was FerroAUTH from 2026-10-25 to 2026-11-17), `ferrohealth-smart` and the
other `ferrohealth-*` names in identifiers. The crate name and its licence
are the owner's decision of 2026-10-19: `ferrohealth-smart`, under
BUSL-1.1, because it is hand-written code that implements a specification,
and in this family only generator-emitted code is Apache-2.0
(`.claude/memory/crate-name.md`, `.claude/memory/license-busl.md`).

## The libraries and the one authorization server

**The library crates are not an authorization server.** `ferrohealth-smart`,
`ferrohealth-authz` and `ferrohealth-session` are resource-server, policy and
session crates: they never issue a token and never hold a key that signs
one. Each deployment points them at its authorization server, FerroSMART or
any other standards-compliant one (Keycloak, Entra ID, any other). The one
private key the libraries can hold is the client credential of
`private_key_jwt`, which signs only the product's own client assertion to
the token endpoint (RFC 7523 §2.2), never an access token.

**FerroSMART is the one component that issues tokens and holds signing
keys** (owner decision 2026-11-16, `.claude/memory/ferrosmart.md`). It is the
family's SMART App Launch 2.x authorization server, built here because no
IdP the family supports issues real SMART tokens (scopes, `launch`, the
launch context, asymmetric clients). It uses any OpenID Connect IdP upstream
for login only, speaks only published standards on every interface (SMART
App Launch 2.2, OAuth 2.x, OpenID Connect, RFC 9068, 7662, 7009, 7523, 8414,
7591, 7636) with no Ferro-specific claim, and serves any FHIR or openEHR
server downstream. It lives in this repository permanently, licensed
BUSL-1.1, and ships as its own OCI image and release artefacts beside the
library crates. Its design is `docs/architecture.md` §13. A
change that would make a library crate issue a token or hold a signing key
is refused: that work belongs in FerroSMART.

**`ferrohealth-smart` is the library every product uses to:**

- act as an OAuth 2.0 and SMART App Launch 2.x resource server
  (`resource`, `metadata`): discover the issuer (RFC 8414, with OpenID
  Connect Discovery 1.0 as the fallback), fetch and cache its key set with
  rotation, and validate JWT access tokens under RFC 9068 (the signature with
  an asymmetric algorithm only, `iss`, `aud`, `exp` and `nbf` with a clock
  skew), answering one generic `401` that names no claim;
- parse and enforce the SMART on openEHR scopes (`openehr`, behind the
  `openehr` feature, parsed by `openehr::smart_scopes`, the grammar's one
  parser, dependency-free behind `openehr-scopes` and the whole crate for
  `wasm32-unknown-unknown`):
  the `template-`, `composition-` and `aql-` families with their patterns,
  the rules `docs/architecture.md` §3.9 fixes where the draft is silent,
  and the `ehrId` of the launch context; and the SMART on FHIR scopes
  (`scope`) beside them: `patient/`, `user/` and `system/` with `cruds`, the
  patient compartment from the token's launch context, granular constraints
  through a product evaluator. A product's route table declares which
  grammar each route is checked against (`Requirement::OpenEhr` or
  `Requirement::Fhir`), with a `403` that names no scope;
- authenticate machine-to-machine calls with the OAuth 2.0 client
  credentials grant (`client`: a token client with fetch, cache and one
  renewal on a `401`, authenticating with a secret or a `private_key_jwt`
  assertion), and a person's HTTP Basic credential (`basic`: verified
  against Argon2id hashes, sent outgoing), which carries no `system/`
  scope. Static or shared bearer tokens and API keys are not supported
  (owner decision 2026-10-19);
- obtain a token for another service on a caller's behalf (`client::onward`)
  by RFC 8693 token exchange or the RFC 7523 JWT bearer grant, as the
  issuer's profile names, refusing an issued token that fails the onward
  check of `docs/architecture.md` §3.16;
- write one audit line per request (`audit`) under the `tracing` target
  `ferrohealth_smart::audit`, with the fixed field set of
  `docs/architecture.md` §3.6 and never the token or any content.

`config` holds the `[auth]` and `[<lane>.credentials]` sections every
product embeds, the latter with the `onward` table of a lane that reaches
its upstream on a caller's behalf. The `axum` feature adds `guard` (the tower layer with the
credential check, the scope check and the audit line) and `extract` (the
`Access` extractor); the core stays framework-neutral.

## The design is recorded in `docs/architecture.md`

Read it first: the role, the pinned versions, each component with its
citations, the configuration model, how a product integrates, what the
library deliberately does not do, the threat model and the decision
register. The vendored specifications under `docs/specs/` are the oracle,
pinned in `docs/VERSIONS.md` and held to their provenance by
`scripts/checks/versions.sh`.

## Repo map

- `crates/ferrohealth-smart`: the library, with its own `CHANGELOG.md`. `src/` (`metadata`, `resource`
  with `jwks`, `token`, `configuration`, `described` (the issuer the
  discovery document describes) and `introspection`, `scope`, `basic`, `client` with
  `cache`, `endpoint`, `outbound` (the client of one outbound integration
  built from its endpoint table, with its retry), `assertion`, `dpop` (the client's DPoP proofs and
  nonces), `binding` (what a grant binds its tokens to, with the RFC 8705 §3
  certificate check), `keys` (the assertion key ring and its JWK Set),
  `fapi2` (the FAPI 2.0 Security Profile on a grant), `authorization_details`
  (RFC 9396) and `onward` (the token exchange and JWT bearer onward
  grants with their check and cache), `kind` (the caller
  classification), `profile` (the issuer profile with its `onward` keys), `federation`
  (what a `federation` issuer asserts, with `assertion`, the eHDSI IdA and
  TRC check behind `ehdsi-assertion`), `sender` (sender-constrained tokens,
  with `proof`, the DPoP proof check, and `replay`, the proof replay store),
  `party` (the login's party through a product `PartySource`, with
  `binding`, `source` and `config`), `assurance`,
  `audit`, `refusal`, `config`, `oidc` behind `oidc`, `xml` behind `xml` (the
  bounded XML reader and Exclusive XML Canonicalization the eHDSI check and
  FerroSMART's SAML login share), and `guard` and
  `extract` behind `axum`), `tests/it/` (one binary: the token check, the
  classification against each preset, the client credentials, Basic, the guard, every upstream a
  `wiremock` stub and every key generated when the case runs).
- `crates/ferrohealth-authz`: the policy decision, on its own version line
  with its own `CHANGELOG.md`. `src/` (`request`, `engine`, `cedar` behind
  `cedar`, `remote` behind `remote`), `tests/it/` (the Cedar engine over
  synthetic models and policies, the remote PDP against a `wiremock` point).
- `crates/ferrohealth-session`: the console sign-in and session, on its own
  version line with its own `CHANGELOG.md`. `src/` (`config`, `sessions`
  with its `memory` and `sealed` stores, `lifetime`, `refresh`, `record`,
  `cookies`, `return_path`, `paths`, and `routes` behind `axum`),
  `tests/it/` (the four routes of a synthetic console against a test OpenID
  Provider, a `wiremock` stub with a key generated when the case runs).
- `app/ferrosmart`: FerroSMART, the authorization server, released from
  0.1.0 (#512 carried the steps); `docs/architecture.md` §13 fixes its
  requirements, crate layout, storage, endpoints, configuration, keys and
  threat model; `src/saml/` is the SAML 2.0 service provider an upstream
  provider can log a person in through (13.26), and `src/wallet/` the
  OpenID4VP verifier a person logs in at with the PID in their EUDI Wallet
  (13.32).
- `tools/zitadel-fhir-user`: the Actions v2 target of FerroSMART's ZITADEL
  example (`compose.zitadel.yaml`, #523), which writes a user's `fhirUser`
  claim from its metadata; deployment content of the example, never
  published.
- `docs/`: `architecture.md`, `VERSIONS.md`, `release.md`, `specs/` (the
  vendored SMART App Launch, RFC, OAuth 2.1 draft, Inferno SMART App
  Launch test kit, OpenID Connect Discovery, Core,
  RP-Initiated Logout and Back-Channel Logout, FAPI 2.0 Security Profile, NIST SP 800-162 and Cedar language corpora, the
  OASIS SAML V2.0 standard with its Errata 05 and the W3C XML Signature,
  XML Encryption and canonicalization Recommendations, the
  IHE IUA supplement, the IHE BALP content page, Nuts RFC021, and the
  Microsoft Entra, SCIM workload identity and Keycloak documents the issuer
  profiles cite, the ZITADEL documentation and API definitions
  FerroSMART's ZITADEL example and the role claim reader cite, the eHDSI
  specifications the owner supplied with SOG-IS ACM 1.3 recorded by sha256
  and never copied, Implementing Regulation (EU)
  2026/2099 and 2015/1502, the GDPR and Commission Decision 2011/833/EU,
  Regulation (EU) 2024/1183 with the wallet implementing acts and their 2026
  amendments, OpenID4VC HAIP 1.0 and OpenID4VP 1.0 with the SD-JWT VC and
  Token Status List drafts, the ETSI wallet profiles recorded by sha256 and
  never copied, and the
  Federation Tier Annex B, and the openEHR RM Common chapter the party
  states cite, each with a `PROVENANCE.md`; `okta/` and `microsoft-graph/`
  hold only the provenance of cache-only pages, fetched into the ignored
  `.vendor-cache/`, and the MyHealth@EU Requirements Catalogue is recorded
  by sha256 and never copied).
- `changelog.d/`: the changelog fragments, one directory per package, which
  the release cut assembles into the package's changelog.
- `scripts/`: `vendor/` (the corpus fetchers), `checks/` (the committed
  guards), `release/` (the release plan, the changelog fragment tool
  `changelog.sh`, the crate publish, the Trivy
  install and the Chrome install of the screenshot capture), `gh/` (the tracker helpers).
- `.github/`: CI with a single required `conclusion` job, the vendored
  specification guard, CodeQL, Scorecard, Dependabot, the release lane with
  crates.io Trusted Publishing (`release.yml`, `release-crate.yml`,
  `publish-crates.yml`), and FerroSMART's release lane of attested tarballs
  and a GHCR image scanned before it is tagged (`release-ferrosmart.yml` with
  its `-build`, `-image` and `-scan` reusable workflows), and the weekly scan
  of the published image (`image-scan.yml`), and the OpenID4VP verifier
  plan of the OpenID Foundation suite (`oidf-verifier.yml`).
- `docker/ferrosmart/Dockerfile`, `compose.yaml`, `trivy.yaml`,
  `security/vex/`: FerroSMART's distroless image, its quickstart beside
  PostgreSQL, the image gate and the OpenVEX judgements its release reads.
- `.claude/`: the working discipline (rules, agents, skills, hooks, memory).

## IMPORTANT hard rules

- **Family rules carried in `.claude/memory/` (index `MEMORY.md`).** A removal
  aid (a named refusal of a removed or renamed config key, flag, env variable,
  route or format) lives exactly one release and the next release deletes it
  fully; no legacy support is ever kept (owner hard rule 2026-11-09,
  `no-compat-shims.md`). Build the proper solution even when it breaks an API
  and moves the minor version (owner 2026-11-08, `no-half-solutions.md`).
  Where the EHDS Regulation conflicts with an openEHR or other standard's
  text, the Regulation wins, and EHDS work is never reverted to pass a
  conformance row (owner 2026-11-09, `ehds-above-openehr.md`).
- **The specifications are the authority**: SMART App Launch 2.2.0, the
  SMART on openEHR draft (DEVELOPMENT, pinned by commit and read weekly
  upstream), RFC 6749, 6750, 7515, 7517, 7519, 7523, 7617, 7662, 8414, 8725,
  9068, 9700, 8707, 7638, 8705, 9449, 9470, 8259, 6454, 7636, 7009, 7521,
  7522, 8693 and 3986, OpenID Connect Discovery 1.0, Core 1.0, RP-Initiated
  Logout 1.0 and Back-Channel Logout 1.0, and for FerroSMART also RFC 6819, 7518, 7591, 8252, 9126,
  9207, 9864, 10070 and 9110 and the OAuth 2.1 draft (cited beside the RFCs it
  consolidates), the FAPI 2.0 Security Profile for a client grant held to it,
  and IHE IUA and Nuts RFC021 for federation tokens, as
  vendored under `docs/specs/`. Cite the section in every `// NOTE:`; never resolve a
  question from memory or from another implementation's behaviour. Where
  none governs a decision, say so: "no specification governs this: our own
  design" (`.claude/rules/spec-adherence.md`).
- **Asymmetric algorithms only** (no HMAC, no `none`); `typ` is `at+jwt`
  under the default profile; `aud` is required; a `401` with
  `error="invalid_token"` and the stable reason code as `error_description`,
  logged at info (#729); a `403` with `error="insufficient_scope"`, its code
  and no `scope` attribute; `503` when the key
  set cannot be read; the token is read from the `Authorization` header, or
  the one header a product names for its edge proxy, never a query or a
  form body. Every refusal is an asserted negative test.
- **No token, secret, key, password or claim beyond `sub`, `client_id` and
  `iss` reaches a log line, a `Debug` rendering or an error message.** Every
  credential type redacts itself.
- **Never send the user's email address to any service**, a `User-Agent`
  header included.
- **Comments follow RFC 505 and RFC 1574 with hard budgets**
  (`.claude/rules/comments.md`); prose follows
  `.claude/rules/writing-style.md`.
- **Branches use conventional types** (`feat/`, `fix/`, `chore/`, `docs/`,
  `refactor/`, `perf/`, `test/`, `ci/`, `build/`, `release/`); every commit is
  signed; `main` takes changes only through pull requests and the merge
  queue.
- **NEVER add AI or Claude attribution** to a commit, PR, issue, comment, or
  code comment. A `PreToolUse` hook blocks a commit or PR command carrying
  one.
- **The schema changes in place.** `app/ferrosmart/migrations/` is one
  baseline file per area; a schema change edits that file and never adds a
  numbered migration (owner 2026-11-23, `.claude/memory/migrations-in-place.md`).
- **Never weaken, skip, or delete a test** (`.claude/rules/testing.md`).
- **Keep the changelog** with a fragment, never an edit of `[Unreleased]`:
  a change a product sees adds
  `changelog.d/<package>/<issue>-<kebab-slug>.<section>.md` for the
  package it ships in (`ferrosmart`, `ferrohealth-smart`,
  `ferrohealth-authz`, `ferrohealth-session`), and the release cut
  assembles the fragments into that package's Keep a Changelog 1.1.0
  section (`.claude/rules/changelog.md`, `changelog.d/README.md`).

## Licence

Business Source License 1.1 (`LICENSE`, `NOTICE`), Licensor Cadasto B.V.,
Change License Apache 2.0 four years after each version; every first-party
file carries `SPDX-FileCopyrightText: Cadasto B.V.` and
`SPDX-License-Identifier: BUSL-1.1`. The vendored specifications keep their
upstream terms, recorded beside them.

## Working discipline (`.claude/`)

- Rules: `writing-style`, `rust-style`, `reliability`, `comments`, `testing`,
  `spec-adherence`, `vendored-inputs`, `ci-cd`, `crates-publishing`,
  `changelog`,
  `issue-workflow`, `issue-relationships`, `project-board`.
- Agents: `implementer`, `spec-researcher`. Skills: `next-task`,
  `phase-done`, `phase-status`.
- Memory: `.claude/memory/MEMORY.md` is the index; every learning is a
  tracked file there.
