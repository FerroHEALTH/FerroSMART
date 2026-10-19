#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/smart-on-openehr.sh
#
# Vendors the SMART on openEHR specification source into
# docs/specs/smart-on-openehr/: the docs/smart_app_launch/ tree of the openEHR
# ITS-REST specification repository, with the repository's LICENSE, at the
# commit the "SMART on openEHR source" row of docs/VERSIONS.md pins. The
# specification declares itself DEVELOPMENT in its manifest_vars.adoc; the
# script reads that status, refuses a tree that declares another, and writes
# it at the top of the PROVENANCE.md, because a development specification is
# pinned and tracked, never assumed stable.
#
# Usage:
#   scripts/vendor/smart-on-openehr.sh             fetch and stamp
#   scripts/vendor/smart-on-openehr.sh --upstream  read the newest commit that
#                                                  touches the tree on the
#                                                  default branch and fail
#                                                  when the pin is behind it
#
# Requires: curl, tar, shasum, jq.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"

corpus_require curl tar shasum jq

dest="docs/specs/smart-on-openehr"
path="docs/smart_app_launch"

pin="$(corpus_pin_cell "SMART on openEHR source")"
repo="$(corpus_pin_repo "$pin")"
commit="$(corpus_pin_commit "$pin")"
last_change="$(corpus_pin_field change "$pin")"
grep -qE '^[0-9a-f]{40}$' <<< "$last_change" || die "the pin names no 'change' commit"

# The newest commit of the default branch that touches the tree.
upstream_change() {
  local branch
  branch="$(corpus_api "https://api.github.com/repos/$repo" | jq -r '.default_branch // empty')"
  [ -n "$branch" ] || die "cannot read the default branch of $repo"
  corpus_api "https://api.github.com/repos/$repo/commits?path=$path&sha=$branch&per_page=1" |
    jq -r '.[0].sha // empty'
}

if [ "${1:-}" = "--upstream" ]; then
  newest="$(upstream_change)"
  [ -n "$newest" ] || die "cannot read the newest commit touching $path"
  if [ "$newest" = "$last_change" ]; then
    say "upstream unchanged: $path last changed at $last_change"
    exit 0
  fi
  die "upstream moved: $path last changed at $newest, the pin records $last_change; re-pin, re-vendor and record the change as a decision in docs/architecture.md"
fi
[ -z "${1:-}" ] || die "usage: scripts/vendor/smart-on-openehr.sh [--upstream]"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "$repo at $commit"
newest="$(upstream_change)"
[ "$newest" = "$last_change" ] ||
  die "the newest commit touching $path is $newest, the pin records $last_change; move both pins together"
committed="$(corpus_commit_date "$repo" "$commit")"
[ -n "$committed" ] || die "cannot read the date of $commit"
tree_root="$(corpus_fetch "$repo" "$commit" "$tmp")"
[ -f "$tree_root/LICENSE" ] || die "the archive has no LICENSE"
[ -d "$tree_root/$path" ] || die "the archive has no $path"

manifest="$tree_root/$path/manifest_vars.adoc"
[ -f "$manifest" ] || die "$path has no manifest_vars.adoc"
status="$(sed -n 's/^:spec_status: *//p' "$manifest" | head -n1 | tr -d '[:space:]')"
[ "$status" = "DEVELOPMENT" ] ||
  die "manifest_vars.adoc declares spec_status '$status', the design pins a DEVELOPMENT specification; re-read the design before moving the pin"
title="$(sed -n 's/^:spec_title: *//p' "$manifest" | head -n1)"
latest_issue="$(grep -oE '\[\[latest_issue\]\][^|]*' "$tree_root/$path/master00-amendment_record.adoc" | head -n1 | sed 's/\[\[latest_issue\]\]//' | tr -d '[:space:]')"
latest_date="$(grep -oE '\[\[latest_issue_date\]\][^|]*' "$tree_root/$path/master00-amendment_record.adoc" | head -n1 | sed 's/\[\[latest_issue_date\]\]//' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
[ -n "$latest_issue" ] && [ -n "$latest_date" ] || die "the amendment record names no latest issue"

rm -rf "$dest"
mkdir -p "$dest"
corpus_take "$tree_root" "$dest" "$path" LICENSE

sections="$(find "$dest/$path" -maxdepth 1 -type f -name 'master0*.adoc' | wc -l | tr -d '[:space:]')"
files="$(corpus_file_count "$dest")"
digest="$(corpus_tree_digest "$dest")"
fetched="$(corpus_fetched)"

cat > "$dest/PROVENANCE.md" << PROV
<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: SMART on openEHR (ITS-REST, status $status)

**Status: $status.** The specification declares \`:spec_status: $status\`
in its \`manifest_vars.adoc\`; its amendment record's latest entry is
$latest_issue, dated $latest_date. It is a draft the openEHR ITS-REST release
does not stabilise: it is pinned to a commit and tracked, never assumed
stable. \`scripts/vendor/smart-on-openehr.sh --upstream\` reads the newest
commit touching the tree on the repository's default branch and fails when
the pin is behind it; a move of the pin is recorded as a decision in
docs/architecture.md with what changed.

Vendored verbatim by \`scripts/vendor/smart-on-openehr.sh\`. Never edit a file
here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/$repo>, the tree \`$path\` (the
  "$title" document) with the repository's \`LICENSE\`
- Pin: commit \`$commit\` ($committed), the default branch's head when
  vendored
- Last change: commit \`$last_change\`, the newest commit touching \`$path\`
  at the pin, which \`--upstream\` compares with the default branch
- Fetched: $fetched
- Upstream licence: Apache License 2.0, the repository's \`LICENSE\` file,
  vendored beside this file
- Layout: the upstream paths, unchanged
- Files: $files, of which $sections are the numbered section sources
  \`$path/master0N-*.adoc\`
- Tree digest (sha256 over the sorted per-file \`sha256  path\` listing,
  \`PROVENANCE.md\` excluded): \`$digest\`

## What is here

\`$path/master.adoc\` is the document root and includes the sections in
order: the amendment record, preface, overview, registration, service
discovery (the \`.well-known/smart-configuration\` additions: \`services\`
and the openEHR capabilities), application types, authentication,
authorization (the launch flows and the context selection with \`ehrId\`),
scopes (the \`<compartment>/<resource>.<permissions>\` grammar over the
\`template-\`, \`composition-\` and \`aql-\` families) and the experimental
features (the base64 \`launch\` parameter and the episode context).
\`diagrams/\` holds the figures the sections embed. The document includes
boilerplate from the repository's \`docs/boilerplate/\` by reference, which
is not vendored: it is layout, not specification text.
PROV

say "$files files ($sections sections), status $status, latest issue $latest_issue ($latest_date), tree digest $digest"
say "done"
