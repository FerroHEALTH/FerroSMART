<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# CLAUDE.md

**FerroSMART** is SMART for the openEHR ecosystem, FHIR included: the
shared SMART App Launch 2.x and OAuth 2.0 resource-server crate of the
FerroHEALTH products, FerroBRIDGE, FerroFED, FerroEHR and FerroTERM. It is
one Cargo workspace with the library crate `ferrohealth-smart` (Rust path
`ferrohealth_smart`, published to crates.io), the way FerroUI is the
family's shared UI crate.

FerroSMART in prose, `ferrohealth-smart` in identifiers. The crate name and
its licence are the owner's decision of 2026-10-19: `ferrohealth-smart`,
under BUSL-1.1, because it is hand-written code that implements a
specification, and in this family only generator-emitted code is Apache-2.0
(`.claude/memory/crate-name.md`, `.claude/memory/license-busl.md`).

## What the library is, and is not

**FerroSMART is not an authorization server.** It never issues a token and
never holds a key that signs one. Each deployment points it at its own
standards-compliant authorization server (Keycloak, Entra ID, Cadasto's
smart-auth, any other). The one private key it can hold is the client
credential of `private_key_jwt`, which signs only the product's own client
assertion to the token endpoint (RFC 7523 §2.2), never an access token.

**FerroSMART is the library every product uses to:**

- act as an OAuth 2.0 and SMART App Launch 2.x resource server
  (`resource`, `metadata`): discover the issuer (RFC 8414, with OpenID
  Connect Discovery 1.0 as the fallback), fetch and cache its key set with
  rotation, and validate JWT access tokens under RFC 9068 (the signature with
  an asymmetric algorithm only, `iss`, `aud`, `exp` and `nbf` with a clock
  skew), answering one generic `401` that names no claim;
- parse and enforce the SMART on openEHR scopes (`openehr`, behind the
  `openehr` feature, parsed by `openehr-sdt` and never by a second parser):
  the `template-`, `composition-` and `aql-` families with their patterns,
  the rules `docs/architecture.md` §3.9 fixes where the draft is silent,
  and the `ehrId` of the launch context; and the SMART on FHIR scopes
  (`scope`) beside them: `patient/`, `user/` and `system/` with `cruds`, the
  patient compartment from the token's launch context, granular constraints
  through a product evaluator. A product's route table declares which
  grammar each route is checked against (`Requirement::OpenEhr` or
  `Requirement::Fhir`), with a `403` that names no scope;
- authenticate machine-to-machine callers and calls in exactly two modes
  (`basic`, `client`): HTTP Basic (verified against Argon2id hashes, sent
  outgoing) and the OAuth 2.0 client credentials grant (a token client with
  fetch, cache and one renewal on a `401`, authenticating with a secret or a
  `private_key_jwt` assertion). Static or shared bearer tokens and API keys
  are not supported (owner decision 2026-10-19);
- write one audit line per request (`audit`) under the `tracing` target
  `ferrohealth_smart::audit`, with the fixed field set of
  `docs/architecture.md` §3.6 and never the token or any content.

`config` holds the `[auth]` and `[<lane>.credentials]` sections every
product embeds. The `axum` feature adds `guard` (the tower layer with the
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

- `crates/ferrohealth-smart`: the library. `src/` (`metadata`, `resource`
  with `jwks`, `token` and `configuration`, `scope`, `basic`, `client` with
  `cache`, `endpoint` and `assertion`, `audit`, `refusal`, `config`, and
  `guard` and `extract` behind `axum`), `tests/it/` (one binary: the token
  check, the client credentials, Basic, the guard, every upstream a
  `wiremock` stub and every key generated when the case runs).
- `docs/`: `architecture.md`, `VERSIONS.md`, `specs/` (the vendored SMART App
  Launch, RFC and OpenID Connect Discovery corpora, each with a
  `PROVENANCE.md`).
- `scripts/`: `vendor/` (the corpus fetchers), `checks/` (the committed
  guards), `release/` (the crate publish), `gh/` (the tracker helpers).
- `.github/`: CI with a single required `conclusion` job, the vendored
  specification guard, CodeQL, Scorecard, Dependabot, the release lane with
  crates.io Trusted Publishing (`release.yml`, `release-crate.yml`,
  `publish-crates.yml`).
- `.claude/`: the working discipline (rules, agents, skills, hooks, memory).

## IMPORTANT hard rules

- **The specifications are the authority**: SMART App Launch 2.2.0, the
  SMART on openEHR draft (DEVELOPMENT, pinned by commit and read weekly
  upstream), RFC 6749, 6750, 7515, 7517, 7519, 7523, 7617, 7662, 8414, 8725,
  9068, 9700, 8707 and 7638, and OpenID Connect Discovery 1.0, as vendored
  under `docs/specs/`. Cite the section in every `// NOTE:`; never resolve a
  question from memory or from another implementation's behaviour. Where
  none governs a decision, say so: "no specification governs this: our own
  design" (`.claude/rules/spec-adherence.md`).
- **Asymmetric algorithms only** (no HMAC, no `none`); `typ` is `at+jwt`
  under the default profile; `aud` is required; one `401` with
  `error="invalid_token"` and no `error_description`; a `403` with
  `error="insufficient_scope"` and no `scope` attribute; `503` when the key
  set cannot be read; the token is read from the `Authorization` header
  alone. Every refusal is an asserted negative test.
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
- **Never weaken, skip, or delete a test** (`.claude/rules/testing.md`).
- **Keep the changelog** (`CHANGELOG.md`, Keep a Changelog 1.1.0).

## Licence

Business Source License 1.1 (`LICENSE`, `NOTICE`), Licensor Cadasto B.V.,
Change License Apache 2.0 four years after each version; every first-party
file carries `SPDX-FileCopyrightText: Cadasto B.V.` and
`SPDX-License-Identifier: BUSL-1.1`. The vendored specifications keep their
upstream terms, recorded beside them.

## Working discipline (`.claude/`)

- Rules: `writing-style`, `rust-style`, `reliability`, `comments`, `testing`,
  `spec-adherence`, `vendored-inputs`, `ci-cd`, `crates-publishing`,
  `issue-workflow`, `issue-relationships`, `project-board`.
- Agents: `implementer`, `spec-researcher`. Skills: `next-task`,
  `phase-done`, `phase-status`.
- Memory: `.claude/memory/MEMORY.md` is the index; every learning is a
  tracked file there.
