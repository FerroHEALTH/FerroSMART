<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Rust style: idiomatic library code

Applies to every hand-written `.rs` file in the repository. **FerroSMART is
modern idiomatic Rust of our own design**, held to the specifications it
implements: SMART App Launch 2.2.0, the OAuth 2.0, JWT and Basic RFCs, and
OpenID Connect Discovery 1.0 (`spec-adherence.md`). The four FerroHEALTH
products' own auth modules are prior art: read them for how a problem was
solved, never port one blindly.

## Build idiomatic, compiling, tested code

- **Use proper crates; do not hand-roll** what the pinned set provides: the
  cryptography (`aws-lc-rs`), the password hashing (`argon2`), the HTTP
  engine (`reqwest`), the secrets (`secrecy`). Every JWS of
  `ferrohealth-smart` goes through its own `jws` module over `aws-lc-rs`
  (owner decision 2026-11-25, #886), since no `jsonwebtoken` release signs
  or verifies ML-DSA (RFC 9964). Add a dependency through
  the root `Cargo.toml [workspace.dependencies]` table (`dep.workspace =
  true`), and verify its version against crates.io or docs.rs the day it is
  added, never from memory. A new library dependency reaches every product,
  so it is justified against what it brings.
- **Every crate you touch compiles, is clippy-clean with and without the
  `axum` feature, and is tested before you move on.**
- **Read the governing specification first** for any check, challenge,
  claim, scope or grant behaviour (`spec-adherence.md`).

## File and module size

A hand-written Rust file is at most 1000 lines, and a file over 750 lines is
split into a module folder before it grows further. The shape of a split is
a folder `<name>/mod.rs` holding the module doc, the `mod` declarations and
the items every child shares, with one child file per concern. A split never
creates a test file under `src/`, adds no `pub use`, and moves code without
changing behaviour.

## Comments and documentation

The comment and doc-comment discipline lives in **`comments.md`** (RFC 505
plus RFC 1574): line comments only, `// TODO(#NNNN):` / `// NOTE:` as the only
markers, a NOTE as a citation plus one sentence (at most 3 lines), plain `//`
runs at most 8 lines, the summary-line convention for doc comments.

## Default values live in the struct's `Default` impl (RFC 3681 shape)

One `impl Default` per struct, every default value inline, and
container-level `#[serde(default, deny_unknown_fields)]` on a configuration
section. The per-field `#[serde(default = "path")]` form, a zero-argument
`fn default_x()`, and a single-reader `const DEFAULT_X` are all banned: each
puts a field's default somewhere other than its own struct. A `const` with
more than one consumer stays a constant (`MAX_CLOCK_SKEW` is read by the
settings check and its error).

## RFC-grounded conventions

| RFC | The rule | Enforcement |
|---|---|---|
| 0505 + 1574 | comment and doc conventions | `comments.md` + `too_long_first_doc_paragraph` |
| 3681 | a field's default lives inline in its `Default` impl | §Default values above |
| 3107 | `#[derive(Default)]` + `#[default]` where the default is a variant | `clippy::derivable_impls` (deny) |
| 0199 / 0344 / 0430 | `as_`/`to_`/`into_` cost conventions, naming | `clippy::wrong_self_convention` |
| 1940 | `#[must_use]` on functions whose result is the point | `clippy::must_use_candidate` (pedantic) |
| 2383 | every suppression carries `reason = "…"` | `clippy::allow_attributes_without_reason` (deny) |
| 1946 | intra-doc links over bare paths | `rustdoc::broken_intra_doc_links` (deny) |
| 0201 | an error carries its cause (`Error::source`) | `#[source]`/`#[from]` on every wrapping variant; review-enforced |

## Type and error conventions

- `thiserror` error enums, `#[non_exhaustive]` where the API will grow; no
  `unwrap`/`expect` outside `#[cfg(test)]`; `todo!()` and `unimplemented!()`
  are banned. An error a caller branches on is a variant, never a substring.
- A refusal on the wire is one of the `Refusal` variants and nothing else:
  a product renders the body, the library owns the status and the
  challenge.
- A secret is a `SecretString`, a header carrying a credential is marked
  sensitive, and every type that holds a credential or a key hand-writes a
  `Debug` that redacts it.
- Model closed sets as Rust `enum`s (`TokenProfile`, `ClientAuth`,
  `Permission`, `Context`, `Reach`, `Via`, `Requirement`).
- **No `use X as Y` import renaming.** Fix the name at its definition, or
  qualify one at the use site. (A trait import as `use Trait as _;` is not a
  rename.)
- `std::sync::LazyLock` for statics. Edition 2024, resolver 3, `cargo fmt`
  clean.
- Suppressions are `#[expect(lint, reason = "…")]` scoped to the smallest
  item (`reliability.md`).

## HTTP statuses are compared as types

An HTTP status is a `StatusCode`, and it is compared as one, never as a
number. Rendering the number (the audit line's `status` field) stays legal.

## Documentation (`missing_docs` is enforced workspace-wide)

Every public item carries a doc comment; intra-doc links resolve in the scope
of the module where the item is defined; literal square brackets are escaped.

## Edition-2024 standing guidance

- `if let` scrutinee temporaries drop before `else` (`reliability.md`).
- RPIT captures every in-scope lifetime and type parameter by default; say
  `use<…>` when a returned `impl Trait` must not.
- `Future` and `IntoFuture` are in the prelude.

## Naming

A name says what the thing is in its domain. Specification-defined things
keep the specification's names verbatim (`jwks_uri`, `client_assertion`,
`insufficient_scope`); a configuration key follows the family's shape
(`clock_skew_seconds`, `password_hash_file`). Modules are named for their
contents.

## No Python, anywhere

The tooling languages are bash and Rust. Python is banned in scripts and
embedded in shell; reach for `jq`, `awk`, `sed`, `grep`, or a Rust tool.

## What not to do

- Do not add a third machine-authentication mode: no static bearer token
  and no API key (owner decision 2026-10-19).
- Do not issue a token, hold a token-signing key, or read a token from a
  query string or a form body.
- Do not name a product in the library: a product scope, a resource table,
  a route table and a body are the product's, supplied through the seams.
