<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: SMART on openEHR (ITS-REST, status DEVELOPMENT)

**Status: DEVELOPMENT.** The specification declares `:spec_status: DEVELOPMENT`
in its `manifest_vars.adoc`; its amendment record's latest entry is
1.1.0, dated 20 May 2025. It is a draft the openEHR ITS-REST release
does not stabilise: it is pinned to a commit and tracked, never assumed
stable. `scripts/vendor/smart-on-openehr.sh --upstream` reads the newest
commit touching the tree on the repository's default branch and fails when
the pin is behind it; a move of the pin is recorded as a decision in
docs/architecture.md with what changed.

Vendored verbatim by `scripts/vendor/smart-on-openehr.sh`. Never edit a file
here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/openEHR/specifications-ITS-REST>, the tree `docs/smart_app_launch` (the
  "SMART on openEHR (SMART)" document) with the repository's `LICENSE`
- Pin: commit `9d25ea783f790512e05f908ef743626b4f7e8d2c` (2026-10-16T11:27:25Z), the default branch's head when
  vendored
- Last change: commit `5183c1f9274ed84096b29ea2b3977bc2e2b26247`, the newest commit touching `docs/smart_app_launch`
  at the pin, which `--upstream` compares with the default branch
- Fetched: 2026-10-19
- Upstream licence: Apache License 2.0, the repository's `LICENSE` file,
  vendored beside this file
- Layout: the upstream paths, unchanged
- Files: 18, of which 10 are the numbered section sources
  `docs/smart_app_launch/master0N-*.adoc`
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `e2c77e8668a3ee332b4dc81d75c6b163297827e65059e95e8abf5da18a75c4d6`

## What is here

`docs/smart_app_launch/master.adoc` is the document root and includes the sections in
order: the amendment record, preface, overview, registration, service
discovery (the `.well-known/smart-configuration` additions: `services`
and the openEHR capabilities), application types, authentication,
authorization (the launch flows and the context selection with `ehrId`),
scopes (the `<compartment>/<resource>.<permissions>` grammar over the
`template-`, `composition-` and `aql-` families) and the experimental
features (the base64 `launch` parameter and the episode context).
`diagrams/` holds the figures the sections embed. The document includes
boilerplate from the repository's `docs/boilerplate/` by reference, which
is not vendored: it is layout, not specification text.
