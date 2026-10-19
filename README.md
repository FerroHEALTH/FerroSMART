<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->
# <img src="assets/brand/ferrosmart-icon.svg" alt="" width="40" height="40" align="top"> FerroSMART

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)

SMART for the openEHR ecosystem, FHIR included: the shared SMART App Launch
and OAuth 2.0 resource-server crate of the FerroHEALTH products, in pure
Rust, `ferrohealth-smart` on crates.io.

FerroSMART is a library, never an authorization server. It issues no token
and holds no key that signs one; each deployment points it at its own
standards-compliant authorization server (Keycloak, Entra ID, Cadasto's
smart-auth). What it does for every product:

- **The resource server.** The issuer's metadata is read at the RFC 8414
  location, with OpenID Connect Discovery 1.0 as the fallback, its key set is
  fetched and cached with rotation, and every JWT access token is validated
  under RFC 9068: the signature with an asymmetric algorithm only, `iss`,
  `aud`, `exp` and `nbf` within a clock skew. A refused token is one generic
  `401` that names no claim.
- **SMART on openEHR scopes**, through the `openehr` feature: the
  `template-`, `composition-` and `aql-` families with their `::` patterns
  under `patient/`, `user/` and `system/`, parsed by `openehr-sdt` (the one
  parser every product reads the grammar with) and enforced here: a
  `system/aql-*` grant only for a listed backend client, a `patient/` grant
  only for a bound issuer and only on the EHR of the launch context's
  `ehrId`, and the `services` map and openEHR capabilities of a platform's
  discovery document.
- **SMART on FHIR scopes**, beside them: `patient/`, `user/` and `system/`
  with the `cruds` permissions, the patient compartment from the token's
  launch context, and a `403` that names no scope. A product's route table
  declares which grammar each route is checked against, and both grammars
  coexist in one `scope` claim.
- **Machine authentication, in exactly two modes.** HTTP Basic, verified
  against Argon2id hashes and sent outgoing, and the OAuth 2.0 client
  credentials grant, a token client with a cache and one renewal on a `401`,
  authenticating with a client secret or a `private_key_jwt` assertion.
- **One audit line per request**, with a fixed field set and never the token
  or any content.

The `axum` feature adds a tower layer that runs the checks in front of every
route and an extractor of the caller it admitted; the core stays
framework-neutral.

FerroSMART is one of the [FerroHEALTH](https://ferrohealth.eu/) family. The
family page shows where it sits among the products and what calls what, and
this repository is where the design and the build happen; the tracker is the
record of both.

## Use it

```toml
[dependencies]
ferrohealth-smart = { version = "=0.1.0", features = ["axum", "openehr"] }
```

The crate documentation on docs.rs is the integration guide; the design, the
configuration model and the migration path of each product are in
[`docs/architecture.md`](docs/architecture.md). The specifications the crate
implements, SMART App Launch 2.2.0, the SMART on openEHR draft, the OAuth
2.0 and JOSE RFCs and OpenID Connect Discovery 1.0, are vendored under
[`docs/specs/`](docs/specs/) at the versions
[`docs/VERSIONS.md`](docs/VERSIONS.md) pins.

## Build and test

```
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --workspace --all-features --locked
```

Every upstream in the tests is a `wiremock` stub and every signing key is
generated when the case runs: no key, real or synthetic, is committed.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and
[SUPPORT.md](SUPPORT.md).

## Licence

FerroSMART is source-available under the Business Source License 1.1. The
parameters that apply, the Licensor, the Licensed Work, the Additional Use
Grant and the Change Date, are in [LICENSE](LICENSE): free for non-commercial
production use, a commercial licence for any other production use, and Apache
2.0 four years after each version is published. The crate is hand-written
code that implements the specifications above, which is why it is under the
family's own licence and not the Apache-2.0 of the family's generated crates.

A commercial licence is arranged with [Cadasto B.V.](https://www.cadasto.com),
the Licensor, which handles the business side of FerroSMART: write to
[info@cadasto.com](mailto:info@cadasto.com) or use
[cadasto.com/contact](https://www.cadasto.com/contact/). Technical questions go
to the maintainer named in [MAINTAINERS.md](MAINTAINERS.md).

The brand assets under `assets/brand/` are part of the Licensed Work. The
vendored specifications under `docs/specs/` keep their upstream terms,
recorded in the `PROVENANCE.md` beside each.

Contributions carry the terms in
[CONTRIBUTING.md](CONTRIBUTING.md#licensing-of-contributions): you keep your
copyright, and you grant the Licensor the relicensing right that keeps the work
one work under one licensor. There is no separate agreement to sign.
