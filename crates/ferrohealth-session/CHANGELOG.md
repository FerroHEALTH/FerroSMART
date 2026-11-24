<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Changelog of ferrohealth-session

All notable changes to `ferrohealth-session` are documented in this file. It
keeps its own version line, released by the tag
`ferrohealth-session-vX.Y.Z`; `ferrohealth-smart` and `ferrohealth-authz`
keep their own.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.29.0] - 2026-11-24

Releases beside `ferrohealth-smart` 0.34.0, whose types this crate carries in
its public API.

### Changed

- Breaking: requires `ferrohealth-smart` 0.34 in place of 0.33, whose
  resource server reads the caller from the token's standard claims and
  keeps no list of clients of its own (#804).

## [0.28.1] - 2026-11-23

A security patch: the crate requires the `cookie` release that fixes
RUSTSEC-2026-0594.

### Security

- Requires `cookie` 0.18.3 (caret `0.18.3`) in place of `0.18.2`
  (RUSTSEC-2026-0594, GHSA-8wcq-xq25-7fhm): in 0.14.0 up to 0.18.2 a private
  cookie the sealed store adds in more than one process after a `fork()`
  could reuse an AES-GCM nonce. A product's lockfile can no longer keep an
  affected `cookie` (#782).

## [0.28.0] - 2026-11-21

Releases beside `ferrohealth-smart` 0.33.0, on `ferrohealth-server` 0.12.

### Changed

- Breaking: requires `ferrohealth-smart` 0.33.0 (caret `0.33.0`) in place of
  `0.32.0`, whose `oidc` and `config::TlsBuilder` types this crate carries
  in its public API. Upgrade: move `ferrohealth-smart` to 0.33.0 with this
  crate, so one copy links (#760).

## [0.27.0] - 2026-11-20

Releases beside `ferrohealth-smart` 0.32.0, whose changelog lists every
change a product meets when it moves to both.

### Changed

- Breaking: requires `ferrohealth-smart` 0.32 in place of 0.31, whose
  refusals carry a stable reason code and whose `guard::Render` takes a
  `refusal::Denied` (#729).

## [0.26.0] - 2026-11-20

### Changed

- Breaking: requires `ferrohealth-smart` 0.31 in place of 0.30. Its
  `ferrosmart` preset reads a patient's own token as `CallerKind::Patient`,
  and `Profile`, `ProfileKeys` and `IssuerEntry` gain
  `fhir_user_patient` (#681).

## [0.25.1] - 2026-11-19

### Added

- `Sessions::token_for` returns an access token for a second resource
  server on the session's grant: kept with the memory-store session until
  it is due, else one refresh naming the resource (RFC 8707 §2.2), with
  the rotated refresh token kept. `invalid_grant` ends the session; any
  other refusal is returned as `ForResource::Refused` and the session stays
  (#675).

## [0.25.0] - 2026-11-17

### Changed

- The repository is FerroSMART again, at
  <https://github.com/FerroHEALTH/FerroSMART>, and the crate's `repository`
  and `homepage` point there (owner decision 2026-11-17). The FerroAUTH
  address redirects, and the crate name stays.
- Breaking: requires `ferrohealth-smart` 0.30.0 (caret `0.30.0`) in place of
  `0.29.0`, whose `oidc` and `config::TlsBuilder` types this crate carries
  in its public API. Upgrade: move `ferrohealth-smart` to 0.30.0 with this
  crate, so one copy links (#631).

## [0.24.0] - 2026-11-17

### Changed

- Breaking: requires `ferrohealth-smart` 0.29 in place of 0.28. Its
  configuration enums are now `#[non_exhaustive]` and `Preset` gains
  `Ferrosmart` (#521).

## [0.23.0] - 2026-11-16

### Changed

- Breaking: requires `ferrohealth-smart` 0.28.0 (caret `0.28.0`) in place of
  `0.27.0`, whose `oidc` and `config::TlsBuilder` types this crate carries
  in its public API. Upgrade: move `ferrohealth-smart` to 0.28.0 with this
  crate, so one copy links (#529).

## [0.22.0] - 2026-11-16

### Changed

- Breaking: requires `ferrohealth-smart` 0.27.0 (caret `0.27.0`) in place of
  `0.26.0`, whose `oidc` and `config::TlsBuilder` types this crate carries
  in its public API. Upgrade: move `ferrohealth-smart` to 0.27.0 with this
  crate, so one copy links (#507).

## [0.21.0] - 2026-11-16

### Changed

- Breaking: requires `ferrohealth-smart` 0.26.0 (caret `0.26.0`) in place of
  `0.25.0`, whose `oidc` and `config::TlsBuilder` types this crate carries
  in its public API. Upgrade: move `ferrohealth-smart` to 0.26.0 with this
  crate, so one copy links (#500).

## [0.20.0] - 2026-11-15

### Changed

- Breaking: requires `ferrohealth-smart` 0.25.0 (caret `0.25.0`) in place of
  `0.24.0`, whose `oidc` and `config::TlsBuilder` types this crate carries
  in its public API. Upgrade: move `ferrohealth-smart` to 0.25.0 with this
  crate, so one copy links (#493).

## [0.19.0] - 2026-11-13

### Changed

- Breaking: requires `ferrohealth-smart` 0.24.0 (caret `0.24.0`) in place of
  `0.23.0`, whose `oidc` and `config::TlsBuilder` types this crate carries
  in its public API. Upgrade: move `ferrohealth-smart` to 0.24.0 with this
  crate, so one copy links (#484).

## [0.18.0] - 2026-11-13

### Changed

- Breaking: requires `ferrohealth-smart` 0.23.0 (caret `0.23.0`) in place of
  `0.22.0`, whose `oidc` and `config::TlsBuilder` types this crate carries
  in its public API. Upgrade: move `ferrohealth-smart` to 0.23.0 with this
  crate, so one copy links (#479).

## [0.17.0] - 2026-11-12

### Changed

- Breaking: requires `ferrohealth-smart` 0.22.0 (caret `0.22.0`) in place of
  `0.21.0`, whose `oidc` and `config::TlsBuilder` types this crate carries
  in its public API. Upgrade: move `ferrohealth-smart` to 0.22.0 with this
  crate, so one copy links (#474).

## [0.16.0] - 2026-11-12

### Changed

- Breaking: requires `ferrohealth-smart` 0.21.0 (caret `0.21.0`) in place of
  `0.20.0`, whose `oidc` and `config::TlsBuilder` types this crate carries
  in its public API. Upgrade: move `ferrohealth-smart` to 0.21.0 with this
  crate, so one copy links (#469).

## [0.15.0] - 2026-11-11

### Changed

- Breaking: requires `ferrohealth-smart` 0.20.0 (caret `0.20.0`) in place of
  `0.19.0`, whose `oidc` and `config::TlsBuilder` types this crate carries
  in its public API. Upgrade: move `ferrohealth-smart` to 0.20.0 with this
  crate, so one copy links (#464).

## [0.14.0] - 2026-11-11

### Changed

- Breaking: requires `ferrohealth-smart` 0.19.0 (caret `0.19.0`) in place of
  `0.18.0`, whose `oidc` and `config::TlsBuilder` types this crate carries
  in its public API. Upgrade: move `ferrohealth-smart` to 0.19.0 with this
  crate, so one copy links (#456).

## [0.13.0] - 2026-11-11

### Changed

- Breaking: `config::OidcSection::issuer`, `redirect_uri` and
  `post_logout_redirect_uri` are `ferrohealth_secret::secret_url::SecretUrl`,
  as the five endpoints are since 0.11, so a password in their userinfo
  reaches no rendering of a console's configuration, serialized or `Debug`,
  even one rendered before the check runs (RFC 3986 §3.2.1). The check
  still refuses a userinfo in each, naming the key. Upgrade: read a value
  with `.expose()` and build one with `SecretUrl::new` (#451).

## [0.12.0] - 2026-11-10

### Changed

- Breaking: requires `ferrohealth-smart` 0.18.0 (caret `0.18.0`) in place of
  `0.17.0`, whose `oidc` and `config::TlsBuilder` types this crate carries
  in its public API. Upgrade: move `ferrohealth-smart` to 0.18.0 with this
  crate, so one copy links (#445).

## [0.11.0] - 2026-11-10

### Changed

- Breaking: the five endpoint fields of `config::OidcSection`,
  `authorization_endpoint`, `token_endpoint`, `jwks_uri`,
  `end_session_endpoint` and `revocation_endpoint`, are
  `Option<ferrohealth_secret::secret_url::SecretUrl>` in place of
  `Option<String>`, so a password in a URL's userinfo reaches no rendering
  of a console's running configuration, serialized or `Debug`; the host and
  path stay. `issuer`, `redirect_uri` and `post_logout_redirect_uri` stay
  `String`s. Upgrade: read an endpoint with `.expose()` and build one with
  `SecretUrl::new` (#430).
- Breaking: requires `ferrohealth-smart` 0.17.0 (caret `0.17.0`) in place of
  `0.16.0`, whose `oidc` and `config::TlsBuilder` types this crate carries
  in its public API. Upgrade: move `ferrohealth-smart` to 0.17.0 with this
  crate, so one copy links (#427).

## [0.10.0] - 2026-11-09

### Changed

- Breaking: requires `ferrohealth-smart` 0.16.0 (caret `0.16.0`) in place of
  `0.15.0`, whose `oidc` and `config::TlsBuilder` types this crate carries
  in its public API. Upgrade: move `ferrohealth-smart` to 0.16.0 with this
  crate, so one copy links (#408).

## [0.9.0] - 2026-11-09

### Changed

- Breaking: the crate builds on `ferrohealth-smart` 0.15 and
  `ferrohealth-config` 0.4, the family's one breaking round of 2026-11-09
  (#396).

### Removed

- Breaking: the named refusals of the keys 0.8.0 retired are deleted,
  under the owner's rule that a removal aid lives for the one release
  that retires it (#388). `oidc.ca_file`, `oidc.timeout_s`,
  `session.sign_in_timeout_s`, `idle_timeout_s`, `absolute_timeout_s` and
  `[oidc.tls] client_certificate`, `client_key` and `client_key_file` are
  refused as unknown keys when the section loads. The fields
  `OidcSection::ca_file`, `timeout_s` and `SessionSection::sign_in_timeout_s`,
  `idle_timeout_s`, `absolute_timeout_s` and the variant
  `ConfigError::Removed` are gone. A console moves to `ferrohealth-smart`
  0.15 in the same change.

## [0.8.0] - 2026-11-09

### Changed

- Breaking: `[oidc] tls` is `ferrohealth_config::tls::TlsClientSection`
  (`trust_roots_file`, `client_identity` or `client_identity_file`,
  `min_version`, by default `"1.3"`), and the crate reads no TLS file: a
  console checks a section that names TLS material with the new
  `OidcSection::check_with_tls`, handing it its `TlsBuilder` (such as
  `ferrohealth-smart`'s `config::ServerTls`); `OidcSection::check` refuses
  it as `ConfigError::TlsNotBuilt`. `oidc.ca_file` is refused naming
  `oidc.tls.trust_roots_file`. `[oidc.tls] client_certificate`,
  `client_key` and `client_key_file` are refused when the section loads,
  all of them at once, each naming `oidc.tls.client_identity_file` or
  `oidc.tls.client_identity`, the one PEM that holds the chain and the
  key (#382).
- Breaking: `oidc.timeout`, `session.sign_in_timeout`, `idle_timeout` and
  `absolute_timeout` are `ferrohealth_config::units::Duration`s (`"30min"`),
  and `oidc.timeout_s`, `session.sign_in_timeout_s`, `idle_timeout_s` and
  `absolute_timeout_s` are refused naming their replacement
  (`ConfigError::Removed`) (#382).

### Added

- Feature `schema`: `schemars::JsonSchema` on the `[oidc]` and `[session]`
  sections (#382).
- `ConfigError::TlsBuild`, the console's TLS builder refusing `oidc.tls`
  (#382).

### Removed

- Breaking: `OidcTlsSection`, `ConfigError::CaFile`,
  `ConfigError::ClientIdentityHalf` and `ConfigError::ClientCertificate`
  (#382).

## [0.7.0] - 2026-11-09

Releases beside `ferrohealth-smart` 0.13.0, whose `oidc` types this crate
carries in its public API (#354).

### Changed

- Requires `ferrohealth-smart` 0.13.0 (caret `0.13.0`) in place of
  `0.12.0`. `record::SignedIn::from_oidc` takes the 0.13.0
  `ferrohealth_smart::oidc::SignedIn`, and
  `config::OidcSettings::relying_party` and `routes` hand out its
  `oidc::RelyingParty`, so a console on 0.12 that moves
  `ferrohealth-smart` to 0.13.0 alone builds two copies of it and fails on
  the type. Upgrade: move `ferrohealth-smart` to 0.13.0 (its changelog
  lists what a product changes) and `ferrohealth-session` to 0.7.0 in one
  change; nothing else this crate offers changes.

## [0.6.0] - 2026-11-09

Releases beside `ferrohealth-smart` 0.12.0, whose `oidc` types this crate
carries in its public API (#342).

### Changed

- Requires `ferrohealth-smart` 0.12.0 (caret `0.12.0`) in place of
  `0.11.0`. `record::SignedIn::from_oidc` takes the 0.12.0
  `ferrohealth_smart::oidc::SignedIn`, and
  `config::OidcSettings::relying_party` and `routes` hand out its
  `oidc::RelyingParty`, so a console on 0.11 that moves
  `ferrohealth-smart` to 0.12.0 alone builds two copies of it and fails on
  the type. Upgrade: move `ferrohealth-smart` to 0.12.0 (its changelog
  lists what a product changes) and `ferrohealth-session` to 0.6.0 in one
  change; nothing else this crate offers changes.

## [0.5.0] - 2026-11-08

Releases beside `ferrohealth-smart` 0.11.0, whose `oidc` types this crate
carries in its public API (#333).

### Changed

- Requires `ferrohealth-smart` 0.11.0 (caret `0.11.0`) in place of
  `0.10.0`. `record::SignedIn::from_oidc` takes the 0.11.0
  `ferrohealth_smart::oidc::SignedIn`, and
  `config::OidcSettings::relying_party` and `routes` hand out its
  `oidc::RelyingParty`, so a console on 0.10 that moves
  `ferrohealth-smart` to 0.11.0 alone builds two copies of it and fails on
  the type. Upgrade: move `ferrohealth-smart` to 0.11.0 (its changelog
  lists what a product changes) and `ferrohealth-session` to 0.5.0 in one
  change; nothing else this crate offers changes.

## [0.4.0] - 2026-11-08

Releases beside `ferrohealth-smart` 0.10.0, whose `oidc` types this crate
carries in its public API (#303).

### Changed

- Requires `ferrohealth-smart` 0.10.0 (caret `0.10.0`) in place of `0.9.0`.
  `record::SignedIn::from_oidc` takes the 0.10.0
  `ferrohealth_smart::oidc::SignedIn`, and
  `config::OidcSettings::relying_party` and `routes` hand out its
  `oidc::RelyingParty`, so a console on 0.9 that moves
  `ferrohealth-smart` to 0.10.0 alone builds two copies of it and fails on
  the type. Upgrade: move `ferrohealth-smart` to 0.10.0 (its changelog
  lists the `[<lane>.credentials.onward]` change) and
  `ferrohealth-session` to 0.4.0 in one change; nothing else this crate
  offers changes.

## [0.3.1] - 2026-11-06

### Added

- `clock::ManualClock` moves in milliseconds as well as seconds
  (`now_millis`, `set_millis`, `advance_millis`), so a console's test
  reaches either side of a second boundary (#268).

### Fixed

- The sign-in timeout, the idle and the absolute lifetime last at least
  their configured length. They were counted in whole seconds, so one
  begun late in a second could end up to a second early. The memory store
  now counts them in milliseconds of the wall clock. The sealed cookie
  keeps its format of whole seconds, read by every earlier release, and
  rounds the sign-in and the last activity up, so its lifetimes last
  between their length and one second more. `Session::signed_in_at` reads
  the sign-in time rounded up (#268).
- A refreshed access token is not due again until it is within
  `refresh::MARGIN` of its expiry, or past half its lifetime when that is
  shorter; it could fall due within a second of its refresh (#268).

## [0.3.0] - 2026-11-06

Releases beside `ferrohealth-smart` 0.9.0, whose `oidc::SignedIn` this
crate carries in its public API (#219).

### Changed

- Requires `ferrohealth-smart` 0.9.0 (caret `0.9.0`) in place of `0.8.8`.
  `record::SignedIn::from_oidc` takes the 0.9.0
  `ferrohealth_smart::oidc::SignedIn`, and
  `config::OidcSettings::relying_party` and `routes` hand out its
  `oidc::RelyingParty`, so a console on 0.8 that moves
  `ferrohealth-smart` to 0.9.0 alone builds two copies of it and fails on
  the type. Upgrade:
  move `ferrohealth-smart` to 0.9.0 (its changelog lists the `[auth]`
  changes) and `ferrohealth-session` to 0.3.0 in one change; nothing else
  this crate offers changes.

## [0.2.3] - 2026-11-04

### Changed

- `ferrohealth-session` requires `ferrohealth-ui` 0.6.6, the FerroUI
  release the consoles pin, in place of 0.6.0. A console on an older
  FerroUI 0.6 moves its pin to 0.6.6 with this release (#208).

## [0.2.2] - 2026-11-04

### Added

- `clock::Clock` is public, the time every lifetime is counted on, and
  `sessions::Sessions::with_clock` builds a store on one; `Sessions::new`
  stays on the wall clock (#206).
- `clock::ManualClock`, behind the new `test-clock` feature, is a time a
  console's tests set and move (`new`, `clock`, `now`, `set`, `advance`), so
  a session test reaches an idle or absolute timeout without waiting for the
  wall clock (#206).

## [0.2.1] - 2026-11-03

### Fixed

- `POST /logout` sends the operator to the provider's end-session endpoint
  only when the ended session holds an ID Token (OpenID Connect RP-Initiated
  Logout 1.0 §2), and otherwise redirects to `Pages::signed_out` (#201).
  A Basic sign-out on a console that also has a provider configured went to
  the provider, which held no session of the operator's to end. Revocation
  is unchanged.

## [0.2.0] - 2026-11-03

### Added

- `[oidc] resolve` reaches provider hosts at a fixed address in place of
  resolving their names, for a provider whose name resolves only inside a
  private network (#196). Each entry is `host=ip:port`, and an entry that is
  not refuses the section with the new `ConfigError::Resolve`. The URL's port
  and the certificate check against the host name stay as the URL names them.
  The override reaches the provider client only.
- `[oidc.tls]`: the client certificate the console presents to its provider
  (RFC 8705 §2), as `client_certificate` with `client_key` or
  `client_key_file`, and `min_version`, the lowest TLS version of the
  provider connection (`"1.2"`, the default, or `"1.3"`). A certificate
  without its key, or a key without its certificate, is refused with
  `ConfigError::ClientIdentityHalf`, and a certificate file that cannot be
  read with `ConfigError::ClientCertificate`. The key is read as a secret.

### Changed

- `config::OidcSection` carries the two new fields `resolve` and `tls`
  (`config::OidcTlsSection`). A console that builds the section with a struct
  literal naming every field adds them, or ends the literal with
  `..OidcSection::default()`. `ferrohealth-session` requires
  `ferrohealth-smart` 0.8.8, whose `client::Reach` the provider client is
  built with.

## [0.1.1] - 2026-11-03

### Added

- `config::OidcSection::check` refuses a section a console cannot sign in
  with safely: the issuer or a written endpoint that is not `https` off a
  loopback host (RFC 6749 §3.1), a `redirect_uri` that is no `http` or
  `https` URL with a host and no userinfo or that carries a fragment
  (RFC 6749 §3.1.2), `scopes` without `openid` (OpenID Connect Core 1.0
  §3.1.2.1), and `scopes` that list `offline_access`, which
  `offline_access = true` asks for (§11). The refusals are the new
  `ConfigError::UrlShape`, `NoOpenId` and `OfflineAccessScope` (#181).
- The session watch answers a gone session with an RFC 9457 problem
  (`application/problem+json`, `about:blank`, status `401`) whose `detail`
  the console words through the new `routes::Pages::session_gone`, which
  has an English default (#183).
- `sessions::Sessions::session_preference` writes a preference cookie with
  no `Max-Age`, which the browser keeps until its session ends
  (RFC 6265 §4.1.2.2), beside `preference` and its `Max-Age` (#184).

### Fixed

- `return_path::ReturnPath::parse` refuses every page under the sign-in
  page, such as `/sign-in/expired`, as well as the sign-in page itself, so a
  completed sign-in never lands on the page that says the session ended
  (#180).

## [0.1.0] - 2026-11-03

The first release: the OpenID Connect sign-in and the session of the
FerroHEALTH operator consoles, over the relying party of `ferrohealth-smart`
0.8. Consoles pin `=0.1.0` with the `axum` feature.

### Added

- The sign-in and the session of the FerroHEALTH operator consoles, one
  crate in place of the copy each console carried (#177). `config` reads the
  `[oidc]` and `[session]` sections with `deny_unknown_fields` and every
  secret through `ferrohealth-secret`; with `issuer` alone the endpoints are
  discovered. `sessions::Sessions` keeps the pending sign-ins and the
  sessions in a `memory` store (bounded pools, an opaque id in the cookie)
  or a `sealed` one (one AES-256-GCM cookie that every instance holding the
  key opens). A sealed store without a key, or with `offline_access`, is
  refused when the configuration loads.
- The idle and the absolute lifetime, counted from times the session
  carries, the absolute one from the sign-in time; an access token no
  refresh token can replace ends the session when it expires. `Sessions::left`
  answers FerroUI's session-watch wire (`{"idle": s, "absolute": s}`): a read
  never counts as activity, an extension starts the idle lifetime again.
- `Sessions::keep_fresh` renews an access token before it expires through
  `ferrohealth-smart`'s relying party, one refresh per session at a time; a
  refusal ends the session, and a provider that cannot be reached is a
  `refresh::Freshness::Unreached`, never a silent success.
- `routes` (feature `axum`): `GET /login` with a `?return=` path held to the
  console's own pages, `GET /auth/callback`, `POST /logout` with RFC 7009
  revocation and RP-initiated logout, and `GET`/`POST /session`, the same
  four routes on every console, with the middleware that hands every page
  its request's `record::Held` and the `routes::Pages` trait a console draws
  a stopped sign-in through.

[Unreleased]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.29.0...HEAD
[0.29.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.28.1...ferrohealth-session-v0.29.0
[0.28.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.28.0...ferrohealth-session-v0.28.1
[0.28.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.27.0...ferrohealth-session-v0.28.0
[0.27.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.26.0...ferrohealth-session-v0.27.0
[0.26.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.25.1...ferrohealth-session-v0.26.0
[0.25.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.25.0...ferrohealth-session-v0.25.1
[0.25.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.24.0...ferrohealth-session-v0.25.0
[0.24.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.23.0...ferrohealth-session-v0.24.0
[0.23.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.22.0...ferrohealth-session-v0.23.0
[0.22.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.21.0...ferrohealth-session-v0.22.0
[0.21.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.20.0...ferrohealth-session-v0.21.0
[0.20.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.19.0...ferrohealth-session-v0.20.0
[0.19.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.18.0...ferrohealth-session-v0.19.0
[0.18.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.17.0...ferrohealth-session-v0.18.0
[0.17.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.16.0...ferrohealth-session-v0.17.0
[0.16.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.15.0...ferrohealth-session-v0.16.0
[0.15.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.14.0...ferrohealth-session-v0.15.0
[0.14.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.13.0...ferrohealth-session-v0.14.0
[0.13.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.12.0...ferrohealth-session-v0.13.0
[0.12.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.11.0...ferrohealth-session-v0.12.0
[0.11.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.10.0...ferrohealth-session-v0.11.0
[0.10.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.9.0...ferrohealth-session-v0.10.0
[0.9.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.8.0...ferrohealth-session-v0.9.0
[0.8.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.7.0...ferrohealth-session-v0.8.0
[0.7.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.6.0...ferrohealth-session-v0.7.0
[0.6.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.5.0...ferrohealth-session-v0.6.0
[0.5.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.4.0...ferrohealth-session-v0.5.0
[0.4.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.3.1...ferrohealth-session-v0.4.0
[0.3.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.3.0...ferrohealth-session-v0.3.1
[0.3.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.2.3...ferrohealth-session-v0.3.0
[0.2.3]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.2.2...ferrohealth-session-v0.2.3
[0.2.2]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.2.1...ferrohealth-session-v0.2.2
[0.2.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.2.0...ferrohealth-session-v0.2.1
[0.2.0]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.1.1...ferrohealth-session-v0.2.0
[0.1.1]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrohealth-session-v0.1.0...ferrohealth-session-v0.1.1
[0.1.0]: https://github.com/FerroHEALTH/FerroSMART/releases/tag/ferrohealth-session-v0.1.0
