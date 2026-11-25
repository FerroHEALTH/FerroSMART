<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Published crate discipline (crates.io)

Three crates are published on crates.io so the FerroHEALTH products can
depend on them: `crates/ferrohealth-smart` as `ferrohealth-smart`,
`crates/ferrohealth-authz` as `ferrohealth-authz` and
`crates/ferrohealth-session` as `ferrohealth-session`. All are BUSL-1.1.
Published versions are immutable, so version hygiene is a hard rule.

## Three version lines

The workspace `version` in the root `Cargo.toml` is `ferrohealth-smart`'s
version, and its release tag is `ferrohealth-smart-vX.Y.Z` (0.1.0 to 0.6.0
were tagged `vX.Y.Z`; those tags stay). The crate inherits it
(`version.workspace = true`), and its changelog is
`crates/ferrohealth-smart/CHANGELOG.md`. `ferrohealth-authz` and
`ferrohealth-session` each keep their own `[package] version`, released by
the tags `ferrohealth-authz-vX.Y.Z` and `ferrohealth-session-vX.Y.Z`, with
their own `crates/<crate>/CHANGELOG.md`. For each crate, the tag, the crate
and the changelog section always agree
(`scripts/checks/crate-version-guard.sh`, `scripts/release/plan.sh`).

## The bump rule

- **A version, its changelog section and the lock move together**
  (`cargo update -w`): in the release pull request, or, for the first
  breaking change after a release, in the pull request that breaks, which
  opens the pending section `## [X.Y.Z] - Unreleased` that the release pull
  request dates (`docs/release.md`, When the version moves). A
  release that moves the `ferrohealth-smart` requirement of
  `[workspace.dependencies]` releases `ferrohealth-authz` with it.
- A **product** pins the crate exactly (`=X.Y.Z`) and moves its pin
  deliberately, in lockstep with the other products. A **shared crate** that
  builds on it takes a caret requirement on the newest release it needs
  (`ferrohealth-secret = "0.2.0"`), which Cargo reads as compatible across the patches of that
  `0.x` line (<https://doc.rust-lang.org/cargo/reference/semver.html>), so a
  patch reaches every product through its lockfile without a release of
  every shared crate in between (owner decision, 2026-10-26). That is safe
  only because a patch release never breaks the public API.
- A pull request that breaks a public API says so in its body and its
  CHANGELOG entry, naming what a product changes; while the line is `0.x`,
  such a release moves the minor version. The Cargo Book, "SemVer
  Compatibility", is the authority on what breaks
  (<https://doc.rust-lang.org/cargo/reference/semver.html>): for `0.y.z` it
  counts a change of `y` as major and of `z` as minor, since only the
  left-most non-zero component is incompatible.
- A public dependency moved to another compatibility line is a breaking
  change: the types the crate exposes from it change with it (The Cargo
  Book, "SemVer Compatibility"). A public dependency is a `ferrohealth-*`
  crate or a member of this workspace
  (`scripts/checks/lib/public-deps.sh`); the `ferrohealth-smart`
  requirement of `ferrohealth-authz` and `ferrohealth-session` is one.
  `cargo-semver-checks` cannot see such a move, since its README lists
  breaking type changes, "for example in the type of a field or function
  parameter", as not yet detected, so `crate-version-guard.sh` and
  `semver.sh` compare the caret line of each such requirement themselves
  and require the dependant's version to leave its line.
- `ferrohealth-authz` takes `ferrohealth-smart` by a caret requirement on
  the newest release it needs, like any shared crate on another (since
  `ferrohealth-authz` 0.2.2), so a `ferrohealth-smart` patch needs no
  `ferrohealth-authz` release. The requirement moves only when
  `ferrohealth-authz` needs a newer `ferrohealth-smart`, and that move is a
  `ferrohealth-authz` release of its own.

## Every release is checked for compatibility

A caret on these crates is only safe while a patch never breaks the API.
`cargo-semver-checks`
(<https://github.com/obi1kenobi/cargo-semver-checks>) holds that by machine:
it builds the rustdoc of each crate and of its newest version on crates.io
and refuses a break the manifest version does not allow (Cargo's SemVer
rules count `0.x.y` to `0.x.(y+1)` as compatible, so a break on a `0.x`
line moves the minor version). An unchanged version is checked as a patch.
`scripts/checks/semver.sh` runs it at the version pinned in
`docs/VERSIONS.md`:

- on every pull request whose change reaches a crate, over the workspace
  (the `cargo-semver-checks` job of `ci.yml`, `semver.sh --changed`
  against the base), so a breaking change carries its minor bump in the
  pull request that breaks. A change that reaches no crate leaves every
  API as its base has it, and is not judged: judging it would judge only
  the base, against whatever crates.io holds when the run starts;
- in the release plan (`scripts/release/plan.sh`, which
  `scripts/release/preflight.sh` and the `plan` job of `release.yml` both
  run), over the crate the tag releases.

Both runs judge all three crates and skip none; a crate with no release on
crates.io yet is named as not judged and passes. Each crate's public
dependencies are compared with the requirements of its newest release, and a
judge that cannot build a crate is named apart from a judged break.

A failure is answered with the minor bump and a changelog entry naming what
a product changes, or by keeping the API; never by skipping the check.

## The publish lane is resumable and verified

`scripts/release/publish-crates.sh` (`publish <crate>` / `verify <crate>` /
`version` / `crate <tag>` / `guard`) uploads the one crate a tag releases,
counts "already exists" as done, and reads the registry back before reporting
success. Two lanes call it: the `crates` leg of `release.yml` on a `ferrohealth-smart-v*`
or `ferrohealth-authz-v*` tag (the primary path, paused by the `crates-io`
environment's required reviewer) and `publish-crates.yml` on a manual
dispatch (a dry run by default; `publish = true` is the recovery path for
an existing release, refused by its `guard` job unless the run is at the
release tag of a crate at its manifest version and that tag has a published
GitHub release). Both
authenticate with crates.io Trusted Publishing (OIDC through
`rust-lang/crates-io-auth-action`); no long-lived crates.io token exists in
the repository. Neither lane restores a build cache (`ci-cd.md`).

`cargo publish --workspace --dry-run --locked` runs on every pull request as
the `publish-dry-run` job; Cargo packages the members together, so
`ferrohealth-authz` verifies against the `ferrohealth-smart` beside it before
that version is on crates.io.

## Owner steps (done once)

1. The name was reserved at `0.0.0` by the owner's crates.io login on
   2026-10-19, since a first version cannot use Trusted Publishing.
2. On crates.io, the crate's Trusted Publishing carries two GitHub entries:
   repository owner `FerroHEALTH`, repository `FerroSMART`, workflows
   `release.yml` and `publish-crates.yml`, environment `crates-io`.
   `ferrohealth-authz`, the policy decision crate reserved at `0.0.0`, has
   Trusted Publishing for the same repository.
3. The `crates-io` GitHub environment carries the owner as required reviewer
   and admits `main`, `ferrohealth-smart-v*` tags and `ferrohealth-authz-v*`
   tags (and `v*`, until the per-crate tags have shipped).

## Official documentation (durable citations)

- Trusted Publishing on crates.io: <https://crates.io/docs/trusted-publishing>
- `cargo publish`: <https://doc.rust-lang.org/cargo/commands/cargo-publish.html>
- Caret requirements: <https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#caret-requirements>
- SemVer compatibility: <https://doc.rust-lang.org/cargo/reference/semver.html>
- cargo-semver-checks: <https://github.com/obi1kenobi/cargo-semver-checks>
