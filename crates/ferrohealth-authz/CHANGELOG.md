<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Changelog of ferrohealth-authz

All notable changes to `ferrohealth-authz` are documented in this file. It
keeps its own version line, released by the tag
`ferrohealth-authz-vX.Y.Z`; `ferrohealth-smart` keeps its own in
`crates/ferrohealth-smart/CHANGELOG.md`.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.29.0] - 2026-11-27

Releases beside `ferrohealth-smart` 0.36.0, whose types this crate carries in
its public API.

### Changed

- Breaking: requires `ferrohealth-smart` 0.36 in place of 0.35, whose
  `ServerMetadata` carries the UserInfo Endpoint (#933).

## [0.28.0] - 2026-11-25

Releases beside `ferrohealth-smart` 0.35.0, whose types this crate carries in
its public API.

### Changed

- Breaking: requires `ferrohealth-smart` 0.35 in place of 0.34, whose
  signature algorithms and JSON Web Keys are its own `jws` types, ML-DSA
  among them (#886).

## [0.27.0] - 2026-11-24

Releases beside `ferrohealth-smart` 0.34.0, whose types this crate carries in
its public API.

### Changed

- Breaking: requires `ferrohealth-smart` 0.34 in place of 0.33, whose
  resource server reads the caller from the token's standard claims and
  keeps no list of clients of its own (#804).

## [0.26.0] - 2026-11-21

Releases beside `ferrohealth-smart` 0.33.0, whose types this crate carries in
its public API.

### Changed

- Breaking: requires `ferrohealth-smart` 0.33.0 (caret `0.33.0`) in place of
  `0.32.0`. Upgrade: move `ferrohealth-smart` to 0.33.0 with this crate, so
  one copy links (#760).

## [0.25.0] - 2026-11-20

Releases beside `ferrohealth-smart` 0.32.0, whose changelog lists every
change a product meets when it moves to both.

### Changed

- Breaking: requires `ferrohealth-smart` 0.32 in place of 0.31, whose
  refusals carry a stable reason code and whose `guard::Render` takes a
  `refusal::Denied` (#729).

## [0.24.0] - 2026-11-20

### Changed

- Breaking: requires `ferrohealth-smart` 0.31 in place of 0.30. Its
  `ferrosmart` preset reads a patient's own token as `CallerKind::Patient`,
  and `Profile`, `ProfileKeys` and `IssuerEntry` gain
  `fhir_user_patient` (#681).

## [0.23.0] - 2026-11-17

Releases beside `ferrohealth-smart` 0.30.0, whose `resource::Caller`,
`client::cache::TokenSource` and `config::endpoint::RetrySection` this
crate carries in its public API.

### Changed

- The repository is FerroSMART again, at
  <https://github.com/FerroHEALTH/FerroSMART>, and the crate's `repository`
  and `homepage` point there (owner decision 2026-11-17). The FerroAUTH
  address redirects, and the crate name stays.
- Breaking: requires `ferrohealth-smart` 0.30.0 (caret `0.30.0`) in place of
  `0.29.0`. Upgrade: move `ferrohealth-smart` to 0.30.0 with this
  crate, so one copy links (#631).

## [0.22.0] - 2026-11-17

### Changed

- Breaking: requires `ferrohealth-smart` 0.29 in place of 0.28. Its
  configuration enums are now `#[non_exhaustive]` and `Preset` gains
  `Ferrosmart` (#521).

## [0.21.0] - 2026-11-16

Releases beside `ferrohealth-smart` 0.28.0, whose `resource::Caller`,
`client::cache::TokenSource` and `config::endpoint::RetrySection` this
crate carries in its public API.

### Changed

- Breaking: requires `ferrohealth-smart` 0.28.0 (caret `0.28.0`) in place of
  `0.27.0`. Upgrade: move `ferrohealth-smart` to 0.28.0 with this crate, so
  one copy links (#529).

## [0.20.0] - 2026-11-16

Releases beside `ferrohealth-smart` 0.27.0, whose `resource::Caller`,
`client::cache::TokenSource` and `config::endpoint::RetrySection` this
crate carries in its public API.

### Changed

- Breaking: requires `ferrohealth-smart` 0.27.0 (caret `0.27.0`) in place of
  `0.26.0`. Upgrade: move `ferrohealth-smart` to 0.27.0 with this crate, so
  one copy links (#507).

## [0.19.0] - 2026-11-16

Releases beside `ferrohealth-smart` 0.26.0, whose `resource::Caller`,
`client::cache::TokenSource` and `config::endpoint::RetrySection` this
crate carries in its public API.

### Changed

- Breaking: requires `ferrohealth-smart` 0.26.0 (caret `0.26.0`) in place of
  `0.25.0`. Upgrade: move `ferrohealth-smart` to 0.26.0 with this
  crate, so one copy links (#500).

## [0.18.0] - 2026-11-15

Releases beside `ferrohealth-smart` 0.25.0, whose `resource::Caller`,
`client::cache::TokenSource` and `config::endpoint::RetrySection` this
crate carries in its public API.

### Changed

- Breaking: requires `ferrohealth-smart` 0.25.0 (caret `0.25.0`) in place of
  `0.24.0`. Upgrade: move `ferrohealth-smart` to 0.25.0 with this
  crate, so one copy links (#493).

## [0.17.0] - 2026-11-13

Releases beside `ferrohealth-smart` 0.24.0, whose `resource::Caller`,
`client::cache::TokenSource` and `config::endpoint::RetrySection` this
crate carries in its public API.

### Changed

- Breaking: requires `ferrohealth-smart` 0.24.0 (caret `0.24.0`) in place of
  `0.23.0`. Upgrade: move `ferrohealth-smart` to 0.24.0 with this
  crate, so one copy links (#484).

## [0.16.0] - 2026-11-13

Releases beside `ferrohealth-smart` 0.23.0, whose `resource::Caller`,
`client::cache::TokenSource` and `config::endpoint::RetrySection` this
crate carries in its public API.

### Changed

- Breaking: requires `ferrohealth-smart` 0.23.0 (caret `0.23.0`) in place of
  `0.22.0`. Upgrade: move `ferrohealth-smart` to 0.23.0 with this
  crate, so one copy links (#479).

## [0.15.0] - 2026-11-12

Releases beside `ferrohealth-smart` 0.22.0, whose `resource::Caller`,
`client::cache::TokenSource` and `config::endpoint::RetrySection` this
crate carries in its public API.

### Changed

- Breaking: requires `ferrohealth-smart` 0.22.0 (caret `0.22.0`) in place of
  `0.21.0`. Upgrade: move `ferrohealth-smart` to 0.22.0 with this crate, so
  one copy links (#474).

## [0.14.0] - 2026-11-12

Releases beside `ferrohealth-smart` 0.21.0, whose `resource::Caller`,
`client::cache::TokenSource` and `config::endpoint::RetrySection` this
crate carries in its public API.

### Changed

- Breaking: requires `ferrohealth-smart` 0.21.0 (caret `0.21.0`) in place of
  `0.20.0`. Upgrade: move `ferrohealth-smart` to 0.21.0 with this crate, so
  one copy links (#469).

## [0.13.0] - 2026-11-11

Releases beside `ferrohealth-smart` 0.20.0, whose `resource::Caller`,
`client::cache::TokenSource` and `config::endpoint::RetrySection` this
crate carries in its public API.

### Changed

- Breaking: requires `ferrohealth-smart` 0.20.0 (caret `0.20.0`) in place of
  `0.19.0`. Upgrade: move `ferrohealth-smart` to 0.20.0 with this crate, so
  one copy links (#464).

## [0.12.0] - 2026-11-11

Releases beside `ferrohealth-smart` 0.19.0, whose `resource::Caller`,
`client::cache::TokenSource` and `config::endpoint::RetrySection` this
crate carries in its public API.

### Changed

- Breaking: requires `ferrohealth-smart` 0.19.0 (caret `0.19.0`) in place of
  `0.18.0`. Upgrade: move `ferrohealth-smart` to 0.19.0 with this crate, so
  one copy links (#456).

## [0.11.0] - 2026-11-10

Releases beside `ferrohealth-smart` 0.18.0, whose `resource::Caller`,
`client::cache::TokenSource` and `config::endpoint::RetrySection` this
crate carries in its public API.

### Changed

- Breaking: requires `ferrohealth-smart` 0.18.0 (caret `0.18.0`) in place of
  `0.17.0`. Upgrade: move `ferrohealth-smart` to 0.18.0 with this crate, so
  one copy links (#445).

## [0.10.0] - 2026-11-10

Releases beside `ferrohealth-smart` 0.17.0, whose `resource::Caller`,
`client::cache::TokenSource` and `config::endpoint::RetrySection` this
crate carries in its public API.

### Changed

- Breaking: requires `ferrohealth-smart` 0.17.0 (caret `0.17.0`) in place of
  `0.16.0`. Upgrade: move `ferrohealth-smart` to 0.17.0 with this crate, so
  one copy links (#427).

## [0.9.0] - 2026-11-09

Releases beside `ferrohealth-smart` 0.16.0, whose `resource::Caller`,
`client::cache::TokenSource` and `config::endpoint::RetrySection` this
crate carries in its public API.

### Added

- `remote::RemotePdp::from_outbound` builds the remote decision point from
  `ferrohealth-smart`'s `client::outbound::OutboundClient`: its URL, its HTTP
  engine with the endpoint's TLS and timeouts, its retry table, and its
  Basic credential or client credentials token (#407).

### Changed

- Breaking: requires `ferrohealth-smart` 0.16.0 (caret `0.16.0`) in place of
  `0.15.0`. Upgrade: move `ferrohealth-smart` to 0.16.0 with this crate, so
  one copy links (#407).

## [0.8.1] - 2026-11-09

### Added

- `remote::RemotePdp::with_client` builds the remote decision point over
  the product's own `reqwest::Client` and the `retry` table of
  `ferrohealth-smart`'s `config::endpoint::EndpointSection`, so the point
  of `[authz.abac.remote.endpoint]` is reached with that section's TLS and
  connect timeout. A call is tried again, up to `retry.max_attempts` tries
  with a backoff that doubles from `retry.initial_backoff` to
  `retry.max_backoff`, when the point could not be reached, the try timed
  out, or it answered a `5xx`; a `4xx`, a redirect and a refused token are
  tried once. `RemotePdp::new` is unchanged and tries each call once
  (#401).

## [0.8.0] - 2026-11-09

Releases beside `ferrohealth-smart` 0.15.0, whose `resource::Caller` and
`client::cache::TokenSource` this crate carries in its public API.

### Changed

- Breaking: the crate builds on `ferrohealth-smart` 0.15 and
  `ferrohealth-config` 0.4, the family's one breaking round of
  2026-11-09, so a product moves every family crate once (#396).

## [0.7.0] - 2026-11-09

Releases beside `ferrohealth-smart` 0.13.0, whose `resource::Caller` and
`client::cache::TokenSource` this crate carries in its public API (#353).

### Changed

- Requires `ferrohealth-smart` 0.13.0 (caret `0.13.0`) in place of
  `0.12.0`. `request::Subject::of` takes the 0.13.0 `resource::Caller` and
  the remote decision point the 0.13.0 `client::cache::TokenSource`, so a
  product on 0.12 that moves `ferrohealth-smart` to 0.13.0 alone builds two
  copies of it and fails on the type. Upgrade: move `ferrohealth-smart` to
  0.13.0 (its changelog lists what a product changes) and
  `ferrohealth-authz` to 0.7.0 in one change; nothing else this crate
  offers changes.

## [0.6.0] - 2026-11-09

Releases beside `ferrohealth-smart` 0.12.0, whose `resource::Caller` and
`client::cache::TokenSource` this crate carries in its public API (#341).

### Changed

- Requires `ferrohealth-smart` 0.12.0 (caret `0.12.0`) in place of
  `0.11.0`. `request::Subject::of` takes the 0.12.0 `resource::Caller` and
  the remote decision point the 0.12.0 `client::cache::TokenSource`, so a
  product on 0.11 that moves `ferrohealth-smart` to 0.12.0 alone builds two
  copies of it and fails on the type. Upgrade: move `ferrohealth-smart` to
  0.12.0 (its changelog lists what a product changes) and
  `ferrohealth-authz` to 0.6.0 in one change; nothing else this crate
  offers changes.

## [0.5.0] - 2026-11-08

Releases beside `ferrohealth-smart` 0.11.0, whose `resource::Caller` and
`client::cache::TokenSource` this crate carries in its public API (#332).

### Changed

- Requires `ferrohealth-smart` 0.11.0 (caret `0.11.0`) in place of
  `0.10.0`. `request::Subject::of` takes the 0.11.0 `resource::Caller` and
  the remote decision point the 0.11.0 `client::cache::TokenSource`, so a
  product on 0.10 that moves `ferrohealth-smart` to 0.11.0 alone builds two
  copies of it and fails on the type. Upgrade: move `ferrohealth-smart` to
  0.11.0 (its changelog lists what a product changes) and
  `ferrohealth-authz` to 0.5.0 in one change; nothing else this crate
  offers changes.

## [0.4.0] - 2026-11-08

A policy reads who stands behind the credential (#262). This release
breaks a Cedar model that declares a subject attribute named `kind`.

### Added

- `request::Subject` carries the caller kind: `Subject::of` reads it from
  `ferrohealth_smart::resource::Caller::kind`, `Subject::with_kind` sets
  it and `Subject::kind` returns it (`None` for a subject built with
  `Subject::new`). The subject's `Debug` names the kind by
  `CallerKind::as_str` alone.

### Changed

- The Cedar principal `User` declares `kind?: String`, holding the name
  `CallerKind::as_str` gives (`person`, `system`, `patient` and the rest
  the audit line records), so a policy reads `principal has kind &&
  principal.kind == "system"`. `cedar::Model` refuses a subject attribute
  named `kind`, as it refuses `roles` and `scopes` (`ModelError::Name`).
  Upgrade: rename a subject attribute `kind` the model declares, and its
  claim mapping, before moving to 0.4.0.
- A remote binding parameter named `kind` carries the subject's caller
  kind, read after the resource attributes and before a subject attribute
  of that name. Upgrade: a remote point that read a product attribute
  named `kind` reads it under another name.
- ferrohealth-authz builds on ferrohealth-smart 0.10.0 (#302), whose
  `resource::Caller` and `kind::CallerKind` its `request::Subject` takes.
  Upgrade: a product moves both crates together, pinning
  `ferrohealth-smart = "=0.10.0"` beside `ferrohealth-authz = "=0.4.0"`.

## [0.3.0] - 2026-11-06

Releases beside `ferrohealth-smart` 0.9.0, whose `resource::Caller` this
crate carries in its public API (#218).

### Changed

- Requires `ferrohealth-smart` 0.9.0 (caret `0.9.0`) in place of `0.8.2`.
  `request::Subject::of` takes the 0.9.0 `ferrohealth_smart::resource::Caller`,
  which carries its `kind::CallerKind`, and `remote::RemotePdp::new` its
  `client::cache::TokenSource`, so a product on 0.8 that moves
  `ferrohealth-smart` to 0.9.0 alone builds two copies of it and fails on
  the type. Upgrade: move `ferrohealth-smart` to 0.9.0 (its changelog lists
  the `[auth]` changes) and `ferrohealth-authz` to 0.3.0 in one change;
  nothing else this crate offers changes.

## [0.2.2] - 2026-10-27

### Changed

- Requires `ferrohealth-smart` as caret `0.8.2` in place of the exact
  `=0.8.1`, so a product takes a patch of ferrohealth-smart without waiting
  for a release of this crate, the family rule for shared crates.

## [0.2.1] - 2026-10-27

### Changed

- docs.rs builds every feature, so the `cedar` and `remote` modules are
  documented there (#135).
- It requires `ferrohealth-smart` 0.8.1 (`=0.8.1`).

## [0.2.0] - 2026-10-26

### Changed

- Takes `ferrohealth-smart` 0.8.0, the line it releases beside.
  `request::Subject::of` takes a `ferrohealth_smart::resource::Caller` and
  `remote::RemotePdp::new` a `ferrohealth_smart::client::cache::TokenSource`,
  so a product moves both crates together; nothing else it calls changes.

## [0.1.5] - 2026-10-26

### Changed

- Takes `ferrohealth-smart` 0.7.5, the line it releases beside.

## [0.1.4] - 2026-10-26

### Changed

- Takes `ferrohealth-smart` 0.7.4, the line it releases beside.

## [0.1.3] - 2026-10-26

### Changed

- Takes `ferrohealth-smart` 0.7.3, the line it releases beside.

## [0.1.2] - 2026-10-26

### Changed

- Takes `ferrohealth-smart` 0.7.2, the line it releases beside.

## [0.1.1] - 2026-10-26

### Changed

- Takes `ferrohealth-smart` 0.7.1, the line it releases beside.

## [0.1.0] - 2026-10-25

The first release: the policy decision of the FerroHEALTH products, the
NIST SP 800-162 request over the subject `ferrohealth-smart` 0.7.0
authenticates, with the Cedar engine behind `cedar` and the remote decision
point behind `remote`. Products pin `=0.1.0` beside `ferrohealth-smart`
`=0.7.0`.

### Added

- The policy decision of the FerroHEALTH products, moved out of FerroEHR and
  generalised so every product can use it (#103). `request::Subject` is read
  from the caller `ferrohealth-smart` admitted (its subject id, roles, scopes
  and chosen claims); `request::Request` names an action, a resource type,
  resource attributes (a set fans out, every combination must be permitted)
  and context attributes; `request::Decision` carries the policies that made
  it. `engine::PolicyEngine` is the trait every engine implements, and
  `engine::AuthzError` the answer of one that cannot decide, which a product
  never reads as a permit.
- `cedar` (feature `cedar`): the embedded engine over the Cedar policy
  language. The schema is written from the product's `cedar::Model`, the
  operator's policies are validated strictly at load and at every reload, a
  reload that does not validate keeps the set in force, and a policy that
  errors during evaluation makes the evaluation an error instead of being
  skipped.
- `remote` (feature `remote`): a remote policy decision point over HTTP, one
  call per combination with the bound attributes as a flat JSON object,
  `200` a permit, a `4xx` a deny and every other answer no decision,
  authorized with the client credentials token of `ferrohealth-smart`.

[Unreleased]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.29.0...HEAD
[0.29.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.28.0...ferrohealth-authz-v0.29.0
[0.28.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.27.0...ferrohealth-authz-v0.28.0
[0.27.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.26.0...ferrohealth-authz-v0.27.0
[0.26.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.25.0...ferrohealth-authz-v0.26.0
[0.25.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.24.0...ferrohealth-authz-v0.25.0
[0.24.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.23.0...ferrohealth-authz-v0.24.0
[0.23.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.22.0...ferrohealth-authz-v0.23.0
[0.22.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.21.0...ferrohealth-authz-v0.22.0
[0.21.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.20.0...ferrohealth-authz-v0.21.0
[0.20.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.19.0...ferrohealth-authz-v0.20.0
[0.19.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.18.0...ferrohealth-authz-v0.19.0
[0.18.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.17.0...ferrohealth-authz-v0.18.0
[0.17.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.16.0...ferrohealth-authz-v0.17.0
[0.16.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.15.0...ferrohealth-authz-v0.16.0
[0.15.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.14.0...ferrohealth-authz-v0.15.0
[0.14.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.13.0...ferrohealth-authz-v0.14.0
[0.13.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.12.0...ferrohealth-authz-v0.13.0
[0.12.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.11.0...ferrohealth-authz-v0.12.0
[0.11.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.10.0...ferrohealth-authz-v0.11.0
[0.10.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.9.0...ferrohealth-authz-v0.10.0
[0.9.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.8.1...ferrohealth-authz-v0.9.0
[0.8.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.8.0...ferrohealth-authz-v0.8.1
[0.8.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.7.0...ferrohealth-authz-v0.8.0
[0.7.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.6.0...ferrohealth-authz-v0.7.0
[0.6.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.5.0...ferrohealth-authz-v0.6.0
[0.5.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.4.0...ferrohealth-authz-v0.5.0
[0.4.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.3.0...ferrohealth-authz-v0.4.0
[0.3.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.2.2...ferrohealth-authz-v0.3.0
[0.2.2]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.2.1...ferrohealth-authz-v0.2.2
[0.2.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.2.0...ferrohealth-authz-v0.2.1
[0.2.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.1.5...ferrohealth-authz-v0.2.0
[0.1.5]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.1.4...ferrohealth-authz-v0.1.5
[0.1.4]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.1.3...ferrohealth-authz-v0.1.4
[0.1.3]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.1.2...ferrohealth-authz-v0.1.3
[0.1.2]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.1.1...ferrohealth-authz-v0.1.2
[0.1.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-authz-v0.1.0...ferrohealth-authz-v0.1.1
[0.1.0]: https://github.com/FerroHEALTH/FerroSMART/releases/tag/ferrohealth-authz-v0.1.0
