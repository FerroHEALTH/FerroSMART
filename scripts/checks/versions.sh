#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/checks/versions.sh
#
# Version-drift guard: docs/VERSIONS.md is the single source of truth, and
# every file that repeats a pin must agree with it. The guard runs offline.
#
#   1. SMART App Launch  the PROVENANCE.md names the pinned version and
#                        commit, and the package and repository trees still
#                        hash to the digests it records.
#   1b. SMART on openEHR the PROVENANCE.md names the pinned commit, declares
#                        the DEVELOPMENT status the design assumes, and the
#                        tree still hashes to the digest it records.
#   2. the RFCs          every `RFC NNNN` row's sha256 is the sha256 of the
#                        vendored text, which the PROVENANCE.md repeats.
#   3. OpenID Connect    the vendored Discovery document hashes to the row's
#                        sha256, which its PROVENANCE.md repeats.
#   4. the design        the pin table of docs/architecture.md names the
#                        same SMART App Launch version as the matrix.
#   5. the licence       no first-party file claims a licence other than
#                        BUSL-1.1 in its SPDX header; the vendored trees are
#                        third-party material and are left out.
#
# Usage:
#   scripts/checks/versions.sh
#
# Requires: shasum, git.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"

corpus_require shasum git

failures=0
fail() {
  printf 'versions: %s\n' "$*" >&2
  failures=$((failures + 1))
}
ok() { printf 'versions: ok: %s\n' "$*"; }

# The value after `- <Label>:` in a PROVENANCE.md, backticks removed. A
# label whose value wraps to the next line (the digests) is read as the
# first backticked token on the following line.
provenance_line() {
  local file="$1" label="$2" value
  value="$(awk -v label="- $label:" '
    index($0, label) == 1 {
      v = substr($0, length(label) + 1)
      gsub(/`/, "", v); gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
      print v; exit
    }' "$file")"
  printf '%s\n' "$value"
}

provenance_digest() {
  local file="$1" label="$2"
  awk -v label="- $label" '
    found { if (match($0, /`[0-9a-f]{64}`/)) { print substr($0, RSTART + 1, 64); exit } }
    index($0, label) == 1 { found = 1; if (match($0, /`[0-9a-f]{64}`/)) { print substr($0, RSTART + 1, 64); exit } }
  ' "$file"
}

# ---- 1. SMART App Launch ----------------------------------------------------
smart="docs/specs/smart-app-launch"
if [ -f "$smart/PROVENANCE.md" ]; then
  pin="$(corpus_pin_cell "SMART App Launch package")"
  version="$(awk '{ print $1; exit }' <<< "$pin")"
  commit="$(corpus_pin_commit "$(corpus_pin_cell "SMART App Launch source")")"
  got_version="$(provenance_line "$smart/PROVENANCE.md" Version)"
  [ "$got_version" = "$version" ] ||
    fail "$smart/PROVENANCE.md names version '$got_version', docs/VERSIONS.md pins $version"
  got_commit="$(provenance_line "$smart/PROVENANCE.md" Pin)"
  [ "$got_commit" = "commit $commit" ] ||
    fail "$smart/PROVENANCE.md names '$got_commit', docs/VERSIONS.md pins commit $commit"
  declared="$(sed -n 's/^  "version" : "\(.*\)",$/\1/p' "$smart/package/package.json")"
  [ "$declared" = "$version" ] ||
    fail "$smart/package/package.json declares version '$declared', docs/VERSIONS.md pins $version"
  for tree in "package:Package tree digest" "repository:Repository tree digest"; do
    want="$(provenance_digest "$smart/PROVENANCE.md" "${tree#*:}")"
    got="$(corpus_tree_digest "$smart/${tree%%:*}")"
    [ "$got" = "$want" ] ||
      fail "$smart/${tree%%:*} hashes to $got, its PROVENANCE.md records ${want:-nothing}"
  done
  ok "SMART App Launch $version at $commit, both trees at their digests"
else
  fail "$smart/PROVENANCE.md is missing"
fi

# ---- 1b. SMART on openEHR ---------------------------------------------------
soe="docs/specs/smart-on-openehr"
if [ -f "$soe/PROVENANCE.md" ]; then
  commit="$(corpus_pin_commit "$(corpus_pin_cell "SMART on openEHR source")")"
  status="$(awk '{ print $1; exit }' <<< "$(corpus_pin_cell "SMART on openEHR")")"
  got_commit="$(provenance_line "$soe/PROVENANCE.md" Pin)"
  [ "${got_commit%% (*}" = "commit $commit" ] ||
    fail "$soe/PROVENANCE.md names '$got_commit', docs/VERSIONS.md pins commit $commit"
  declared="$(sed -n 's/^:spec_status: *//p' "$soe/docs/smart_app_launch/manifest_vars.adoc" | head -n1 | tr -d '[:space:]')"
  [ "$declared" = "$status" ] ||
    fail "$soe declares spec_status '$declared', docs/VERSIONS.md records $status; the design assumes a development draft"
  grep -qF "**Status: $status.**" "$soe/PROVENANCE.md" ||
    fail "$soe/PROVENANCE.md does not state the $status status"
  want="$(provenance_digest "$soe/PROVENANCE.md" "Tree digest")"
  got="$(corpus_tree_digest "$soe")"
  [ "$got" = "$want" ] || fail "$soe hashes to $got, its PROVENANCE.md records ${want:-nothing}"
  ok "SMART on openEHR at $commit, status $status, tree at its digest"
else
  fail "$soe/PROVENANCE.md is missing"
fi

# ---- 2. the RFCs ------------------------------------------------------------
rfc="docs/specs/rfc"
count=0
while IFS= read -r item; do
  number="${item#RFC }"
  want="$(corpus_pin_field sha256 "$(corpus_pin_cell "$item")")"
  if [ ! -f "$rfc/rfc$number.txt" ]; then
    fail "$rfc/rfc$number.txt is missing"
    continue
  fi
  got="$(corpus_sha256 "$rfc/rfc$number.txt")"
  [ "$got" = "$want" ] || fail "$rfc/rfc$number.txt hashes to $got, docs/VERSIONS.md pins $want"
  if ! grep -F "| RFC $number |" "$rfc/PROVENANCE.md" | grep -qF "\`$want\`"; then
    fail "$rfc/PROVENANCE.md does not record RFC $number at $want"
  fi
  count=$((count + 1))
done < <(corpus_pin_items "RFC ")
vendored="$(find "$rfc" -maxdepth 1 -name 'rfc*.txt' | wc -l | tr -d '[:space:]')"
[ "$vendored" = "$count" ] || fail "$rfc holds $vendored RFC texts, docs/VERSIONS.md pins $count"
ok "$count RFCs at their checksums"

# ---- 3. OpenID Connect Discovery --------------------------------------------
oidc="docs/specs/openid-connect-discovery"
pin="$(corpus_pin_cell "OpenID Connect Discovery 1.0 document")"
file="$(awk '{ print $1; exit }' <<< "$pin")"
want="$(corpus_pin_field sha256 "$pin")"
if [ -f "$oidc/$file" ]; then
  got="$(corpus_sha256 "$oidc/$file")"
  [ "$got" = "$want" ] || fail "$oidc/$file hashes to $got, docs/VERSIONS.md pins $want"
  recorded="$(provenance_line "$oidc/PROVENANCE.md" sha256)"
  [ "$recorded" = "$want" ] || fail "$oidc/PROVENANCE.md records sha256 '$recorded', docs/VERSIONS.md pins $want"
  ok "OpenID Connect Discovery 1.0 ($file) at its checksum"
else
  fail "$oidc/$file is missing"
fi

# ---- 4. the design ----------------------------------------------------------
architecture="docs/architecture.md"
if [ -f "$architecture" ]; then
  matrix="$(awk '{ print $1; exit }' <<< "$(corpus_pin_cell "SMART App Launch")")"
  design="$(awk -F'|' '
    NF >= 3 {
      k = $2; v = $3
      gsub(/`/, "", k); gsub(/`/, "", v)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", k)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
      if (k == "SMART App Launch") { split(v, t, " "); print t[1]; exit }
    }' "$architecture")"
  [ "$design" = "$matrix" ] ||
    fail "$architecture pins SMART App Launch '$design', docs/VERSIONS.md $matrix"
  ok "$architecture agrees on SMART App Launch $matrix"
else
  fail "$architecture is missing"
fi

# ---- 5. the licence ---------------------------------------------------------
licence="$(awk '{ print $1; exit }' <<< "$(corpus_pin_cell "Project licence")")"
while IFS= read -r path; do
  claimed="$(grep -m1 -oE 'SPDX-License-Identifier: [A-Za-z0-9.+-]+' "$path" | cut -d' ' -f2 || true)"
  [ -z "$claimed" ] || [ "$claimed" = "$licence" ] ||
    fail "$path claims $claimed, the project licence is $licence"
done < <(git ls-files -z | tr '\0' '\n' | grep -v '^docs/specs/' | grep -v '^LICENSE$')
ok "every first-party SPDX header names $licence"

if [ "$failures" -gt 0 ]; then
  printf 'versions: %d failure(s)\n' "$failures" >&2
  exit 1
fi
printf 'versions: every pin agrees with docs/VERSIONS.md\n'
