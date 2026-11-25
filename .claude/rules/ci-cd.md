---
paths:
  - ".github/**"
  - "scripts/**"
---

<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# CI/CD and supply-chain discipline

No specification governs this: our own design, grounded in the OWASP GitHub
Actions Security Cheat Sheet, SLSA v1.0, OpenSSF Scorecard, and Sigstore.

## What runs

- `.github/workflows/ci.yml`: the gate on every pull request, merge-group run
  and push to `main`. The workflow tier (zizmor, actionlint, shellcheck, the
  comment-style guard, the caller kind guard
  (`scripts/checks/caller-kinds.sh`, the kinds the docs list against
  `CallerKind::as_str`), the `TODO(#N)` guard, the conflict-marker guard,
  which the `conflict_markers_guard.sh` hook also runs on every commit's
  staged files, the duplication ratchet
  (`scripts/checks/duplication.sh`: jscpd from its pinned image over the
  hand-written Rust, the duplicated lines held to
  `scripts/checks/duplication.count`, a rise failing and naming both places
  of each new block, a fall passing with a note)) and the Rust tier
  (`cargo fmt --all --check`; `cargo clippy
  --workspace --all-targets --locked -- -D warnings` with and without
  `--all-features`; `cargo nextest run --workspace --locked` with and without
  `--all-features`, plus `cargo test --doc`; `cargo doc` with
  `RUSTDOCFLAGS=-D warnings`; `cargo deny check`; `cargo publish -p
  ferrohealth-smart --dry-run --locked`; the crate-version guard and
  `dependency-review-action` on pull requests; the live Keycloak case
  against the pinned image, as the last steps of the nextest job, on a pull
  request that touches the profiles or the resource server, and on every push
  to `main`, which saves the build cache the pull request runs restore). The
  `conclusion` job is the single required status check on `main`.

  These run as four jobs that all start at once, `guards` (every guard and
  the publish dry run, no build cache), `lint`, `nextest (core and axum)` and,
  on a pull request, `cargo-semver-checks`, beside `conclusion`. The hosted
  runner pool is shared across the organisation, so every job pays a wait
  for a runner however short its work, and a job that waits on another pays
  it twice: twenty jobs in three waves made a run take 48 to 58 minutes for
  about 11 runner-minutes of work (#392). Add a step to one of the four
  before adding a job, and give a guard step `if: ${{ !cancelled() }}` so a
  run still reports every finding.

  A merge-group run is light (owner, 2026-11-25), since the pull request
  ran the full suite on the same change: the guards without the publish dry
  run, rustfmt, cargo-deny and the advisory-exception check without clippy
  and rustdoc, and every test target compiled with every feature with only
  the unit tests (`--lib --bins`) run and no lane, since two pull requests
  that each passed alone can break a test binary together. `cargo-semver-checks` and `quickstart` do not run there.
  `conclusion` reads a skipped job as a pass.
- `.github/workflows/ratchet-tighten.yml`: once a day on `main`, runs
  `scripts/checks/duplication.sh --update` and, when the count fell, pushes
  `chore/ratchet-tighten` with only the ratchet files, committed through the
  Git Data API so GitHub signs it; a maintainer opens its pull request. A
  pull request that lowers the count never touches the files itself.
- `.github/workflows/specs.yml`: the vendored-specification guard,
  `scripts/checks/versions.sh`, offline, on the same events.
- `.github/workflows/codeql.yml`: CodeQL over the `actions` language and Rust,
  advisory, on a push to `main`, weekly, and on a pull request that changes a
  Rust source, a Cargo file or `.github/`; never on a merge group, and a
  newer push cancels a running analysis (owner decision, 2026-11-25).
- `.github/workflows/scorecard.yml`: OpenSSF Scorecard, published to the
  OpenSSF API and to code scanning.
- `.github/workflows/release.yml`: dormant until a `v*` tag is pushed. It
  validates the tag against the workspace version, takes the notes from the
  matching section of the tagged crate's `crates/<crate>/CHANGELOG.md`, creates the release as a draft, calls
  `release-crate.yml` (a reusable workflow, so the signing identity stays out
  of reach of caller steps) to package the `.crate`, attest it and attach it,
  publishes the release, and then its `crates` leg uploads the crate through
  Trusted Publishing behind the `crates-io` environment
  (`crates-publishing.md`).
  Its `plan` job refuses a tag when no milestone is titled exactly as the tag
  or that milestone still holds an open issue or pull request, naming each
  one, and its last job, `milestone`, closes that milestone once every leg,
  crates included, has succeeded; a failed leg leaves it open and the job log
  names the leg. Both call `scripts/release/milestone.sh`.
- `.github/workflows/release-ferrosmart.yml`: dormant until a
  `ferrosmart-v*` tag is pushed. It runs the same `plan.sh` list for the
  server, creates the draft with `compose.yaml` attached, and calls three
  reusable workflows: `release-ferrosmart-build.yml` builds, packages and
  attests the binary per target, `release-ferrosmart-image.yml` verifies the
  musl tarballs against that signer and pushes the distroless image to GHCR
  by digest with its attestations, and `release-ferrosmart-scan.yml` gates
  the digest on fixable HIGH and CRITICAL findings before it applies the
  tags. Between them its `vulnerability-record` job refuses the release while
  a finding of a full scan lacks an OpenVEX judgement under `security/vex/`
  (`scripts/checks/vex-coverage.sh`). It publishes the release last and closes
  the milestone as `release.yml` does (`docs/release.md`).
- `.github/workflows/image-scan.yml`: the weekly Trivy scan of the published
  FerroSMART image at `latest`, with every OpenVEX document under
  `security/vex/` applied. A finding files or comments on one tracking
  issue; the run is red only when the scan itself fails.
- `.github/workflows/pin-freshness.yml`: each Monday and on dispatch,
  `scripts/checks/pin-freshness.sh` reads every `ghcr.io/ferrohealth/*`
  image of another product pinned in `docs/VERSIONS.md` against that
  product's latest stable release and image index digest, and opens or
  rewrites one issue per image behind through `scripts/gh/fields.sh new`.
  A pull request that changes the lane or the pin table runs it as a dry
  run that files nothing; it fails only when a release or a digest could not
  be read. The `guards` job runs its `--self-test`.
- `.github/workflows/publish-crates.yml`: the manual crates.io lane, a dry
  run unless `publish` is set, sharing `scripts/release/publish-crates.sh`
  with the release lane. A real publish runs only at the tag of the
  manifest version that has a published GitHub release: its `guard` job
  refuses any other ref before the approval (`docs/release.md`).

## Workflow security (every workflow, no exceptions)

- **Every `uses:` is pinned to a full commit SHA** with a trailing `# vX.Y.Z`
  comment; Dependabot (`github-actions`) bumps them.
- **`permissions: {}` at workflow level**, with the minimum granted per job.
- **`persist-credentials: false`** on every `actions/checkout`.
- **No `${{ }}` context interpolation inside `run:`:** pass context through
  `env:`.
- **A publishing lane restores no build cache.**

Run `zizmor --min-severity=low .github/`, `actionlint` and `shellcheck
--severity=style` by hand before pushing a workflow or script change. A
finding is fixed, or carries a `# zizmor: ignore[audit]` or `# shellcheck
disable=SCnnnn` with its reason on the line it names; no `.shellcheckrc`
exists.

## Supply chain

- **A release is assembled as a draft and published last.** The fix for a bad
  cut is a new patch version, never a retag: immutable releases freeze a
  published release, and the `release-tags` ruleset stops a tag being moved
  or deleted.
- **Every tag is signed**, on the merge commit on `main`.
- **Always `--locked`**, and `Cargo.lock` is committed.
- **The crate publishes through Trusted Publishing** (OIDC, no long-lived
  token), with a dry run on every pull request.

## Never

- Never unpin a `uses:`, widen a job's permissions without cause, interpolate
  context into `run:`, or restore a cache in a publishing lane.
- Never weaken a gate to go green (`testing.md`); fix the cause.
- **Never add AI or Claude attribution** to any commit, PR, or release text.

## Official documentation (durable citations)

- OWASP GitHub Actions Security Cheat Sheet:
  <https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html>
- SLSA v1.0: <https://slsa.dev/spec/v1.0/>
- OpenSSF Scorecard: <https://github.com/ossf/scorecard-action>
- Trusted Publishing on crates.io: <https://crates.io/docs/trusted-publishing>
