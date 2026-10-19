<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/FerroHEALTH/FerroSMART/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/FerroHEALTH/FerroSMART/releases/tag/v0.1.0
