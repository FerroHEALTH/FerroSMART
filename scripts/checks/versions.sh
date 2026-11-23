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
#   3. OpenID Connect    the vendored Discovery, Core, RP-Initiated Logout,
#                        Front-Channel and Back-Channel Logout documents each hash to
#                        their row's sha256, which their PROVENANCE.md
#                        repeats.
#   3a. FAPI 2.0         the vendored Security Profile hashes to its row's
#                        sha256, which its PROVENANCE.md repeats.
#   3b. NIST SP 800-162  the vendored PDF hashes to the row's sha256, which
#                        its PROVENANCE.md repeats.
#   3c. Cedar docs       the PROVENANCE.md names the pinned commit and the
#                        tree still hashes to the digest it records.
#   3d. the party        the IHE IUA, Nuts RFC021, Microsoft Entra, SCIM
#       binding sources  workload identity, Keycloak and Federation Tier
#       and the Inferno  Annex B trees and the Inferno SMART App Launch
#       test kit         test kit: each PROVENANCE.md names its row's
#                        commit and the tree still hashes to the digest it
#                        records.
#   3e. cache only       the Okta, Microsoft Graph and SOG-IS ACM PROVENANCE.md files
#                        each record their row's pin-set digest and each
#                        directory holds no other file; no
#                        file under .vendor-cache/ is tracked.
#   3f. pinned by sha256 the eHDSI specifications, the EU legal acts, the
#                        IHE BALP content page and the OAuth 2.1 draft:
#                        each PROVENANCE.md records its row's pin-set
#                        digest, the tree hashes to the digest it records,
#                        and the script's --check finds every committed file
#                        at its pin and no withheld or unpinned file.
#   3g. FHIR packages    the Brands Bundle check's packages: each
#                        PROVENANCE.md names its row's sha1 and sha256, a
#                        fetched tarball is at its pin, and the closure of
#                        the SMART package is complete
#                        (scripts/vendor/fhir-packages.sh --check).
#   4. the design        the pin table of docs/architecture.md names the
#                        same SMART App Launch version as the matrix.
#   4e. Inferno lane     the FerroBRIDGE image the lane runs is pinned by
#                        digest at the release its party mappings pin.
#   4f. the screenshots  scripts/release/journey-tools.sh carries the Chrome
#                        for Testing release and the four zip digests of
#                        the matrix, and Cargo.toml the thirtyfour version.
#   4g. third-party lane the HAPI FHIR, Envoy and APISIX images the lane
#                        runs are pinned by digest, and the lane reads each
#                        row.
#   4h. OIDF lane        the conformance suite, its TLS front and MongoDB
#                        are pinned by digest, and the lane reads the rows.
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
  before="$failures"
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
  [ "$failures" -ne "$before" ] || ok "SMART App Launch $version at $commit, both trees at their digests"
else
  fail "$smart/PROVENANCE.md is missing"
fi

# ---- 1b. SMART on openEHR ---------------------------------------------------
soe="docs/specs/smart-on-openehr"
if [ -f "$soe/PROVENANCE.md" ]; then
  before="$failures"
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
  [ "$failures" -ne "$before" ] || ok "SMART on openEHR at $commit, status $status, tree at its digest"
else
  fail "$soe/PROVENANCE.md is missing"
fi

# ---- 2. the RFCs ------------------------------------------------------------
rfc="docs/specs/rfc"
count=0
before="$failures"
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
[ "$failures" -ne "$before" ] || ok "$count RFCs at their checksums"

# ---- 3. the OpenID Connect specifications ----------------------------------
for spec in discovery:"OpenID Connect Discovery 1.0" core:"OpenID Connect Core 1.0" \
  rpinitiated:"OpenID Connect RP-Initiated Logout 1.0" \
  frontchannel:"OpenID Connect Front-Channel Logout 1.0" \
  backchannel:"OpenID Connect Back-Channel Logout 1.0"; do
  oidc="docs/specs/openid-connect-${spec%%:*}"
  name="${spec#*:}"
  pin="$(corpus_pin_cell "$name document")"
  file="$(awk '{ print $1; exit }' <<< "$pin")"
  want="$(corpus_pin_field sha256 "$pin")"
  if [ -f "$oidc/$file" ]; then
    before="$failures"
    got="$(corpus_sha256 "$oidc/$file")"
    [ "$got" = "$want" ] || fail "$oidc/$file hashes to $got, docs/VERSIONS.md pins $want"
    recorded="$(provenance_line "$oidc/PROVENANCE.md" sha256)"
    [ "$recorded" = "$want" ] || fail "$oidc/PROVENANCE.md records sha256 '$recorded', docs/VERSIONS.md pins $want"
    [ "$failures" -ne "$before" ] || ok "$name ($file) at its checksum"
  else
    fail "$oidc/$file is missing"
  fi
done

# ---- 3a. the FAPI 2.0 Security Profile -------------------------------------
fapi="docs/specs/fapi-security-profile"
pin="$(corpus_pin_cell "FAPI 2.0 Security Profile document")"
file="$(awk '{ print $1; exit }' <<< "$pin")"
want="$(corpus_pin_field sha256 "$pin")"
if [ -f "$fapi/$file" ]; then
  before="$failures"
  got="$(corpus_sha256 "$fapi/$file")"
  [ "$got" = "$want" ] || fail "$fapi/$file hashes to $got, docs/VERSIONS.md pins $want"
  recorded="$(provenance_line "$fapi/PROVENANCE.md" sha256)"
  [ "$recorded" = "$want" ] || fail "$fapi/PROVENANCE.md records sha256 '$recorded', docs/VERSIONS.md pins $want"
  [ "$failures" -ne "$before" ] || ok "FAPI 2.0 Security Profile ($file) at its checksum"
else
  fail "$fapi/$file is missing"
fi

# ---- 3b. NIST SP 800-162 ----------------------------------------------------
nist="docs/specs/nist-sp-800-162"
pin="$(corpus_pin_cell "NIST SP 800-162 document")"
file="$(awk '{ print $1; exit }' <<< "$pin")"
want="$(corpus_pin_field sha256 "$pin")"
if [ -f "$nist/$file" ]; then
  before="$failures"
  got="$(corpus_sha256 "$nist/$file")"
  [ "$got" = "$want" ] || fail "$nist/$file hashes to $got, docs/VERSIONS.md pins $want"
  recorded="$(provenance_line "$nist/PROVENANCE.md" sha256)"
  [ "$recorded" = "$want" ] || fail "$nist/PROVENANCE.md records sha256 '$recorded', docs/VERSIONS.md pins $want"
  [ "$failures" -ne "$before" ] || ok "NIST SP 800-162 ($file) at its checksum"
else
  fail "$nist/$file is missing"
fi

# ---- 3c. the Cedar language documentation -----------------------------------
cedar="docs/specs/cedar-docs"
if [ -f "$cedar/PROVENANCE.md" ]; then
  before="$failures"
  commit="$(corpus_pin_commit "$(corpus_pin_cell "Cedar language documentation")")"
  got_commit="$(provenance_line "$cedar/PROVENANCE.md" Pin)"
  case "$got_commit" in
    "commit $commit"*) ;;
    *) fail "$cedar/PROVENANCE.md names '$got_commit', docs/VERSIONS.md pins commit $commit" ;;
  esac
  want="$(provenance_digest "$cedar/PROVENANCE.md" "Tree digest")"
  got="$(corpus_tree_digest "$cedar")"
  [ "$got" = "$want" ] || fail "$cedar hashes to $got, its PROVENANCE.md records ${want:-nothing}"
  [ "$failures" -ne "$before" ] || ok "the Cedar language documentation at $commit"
else
  fail "$cedar/PROVENANCE.md is missing"
fi

# ---- 3d. the party binding sources ------------------------------------------
for tree in "ihe-iua:IHE IUA supplement" "nuts-rfc:Nuts RFC021" \
  "entra-docs:Microsoft Entra documentation" \
  "scim-workload-identity:SCIM workload identity federation guide" \
  "keycloak-docs:Keycloak documentation" \
  "zitadel:ZITADEL documentation" \
  "ferrobridge-party:FerroBRIDGE party mappings" \
  "inferno-smart-test-kit:Inferno SMART App Launch test kit" \
  "openehr-rm/development:openEHR RM Common (development)" \
  "federation-spec:Federation Tier with AQL specification"; do
  dir="docs/specs/${tree%%:*}"
  item="${tree#*:}"
  if [ -f "$dir/PROVENANCE.md" ]; then
    before="$failures"
    commit="$(corpus_pin_commit "$(corpus_pin_cell "$item")")"
    got_commit="$(provenance_line "$dir/PROVENANCE.md" Pin)"
    case "$got_commit" in
      *"commit $commit"*) ;;
      *) fail "$dir/PROVENANCE.md names '$got_commit', docs/VERSIONS.md pins commit $commit" ;;
    esac
    want="$(provenance_digest "$dir/PROVENANCE.md" "Tree digest")"
    got="$(corpus_tree_digest "$dir")"
    [ "$got" = "$want" ] || fail "$dir hashes to $got, its PROVENANCE.md records ${want:-nothing}"
    [ "$failures" -ne "$before" ] || ok "$item at $commit"
  else
    fail "$dir/PROVENANCE.md is missing"
  fi
done

# ---- 3e. the cache-only and copy-free sources ------------------------------
for tree in "okta:Okta OpenID Connect and OAuth 2.0 API" \
  "microsoft-graph:Microsoft Graph documentation" \
  "sogis-acm:SOG-IS Agreed Cryptographic Mechanisms" \
  "etsi-eudi:ETSI EUDI wallet specifications"; do
  dir="docs/specs/${tree%%:*}"
  item="${tree#*:}"
  if [ -f "$dir/PROVENANCE.md" ]; then
    before="$failures"
    want="$(grep -oE '[0-9a-f]{64}' <<< "$(corpus_pin_cell "$item")" | head -n1)"
    got="$(provenance_digest "$dir/PROVENANCE.md" "Pin-set digest")"
    [ "$got" = "$want" ] || fail "$dir/PROVENANCE.md records pin-set digest ${got:-nothing}, docs/VERSIONS.md $want"
    extra="$(corpus_file_count "$dir")"
    [ "$extra" = "0" ] || fail "$dir holds $extra file(s) besides PROVENANCE.md; its source is cache only"
    [ "$failures" -ne "$before" ] || ok "$item pinned at $want, cache only"
  else
    fail "$dir/PROVENANCE.md is missing"
  fi
done
tracked="$(git ls-files .vendor-cache | head -n1)"
[ -z "$tracked" ] || fail ".vendor-cache/ is never committed, and $tracked is tracked"

# ---- 3f. the corpora pinned file by file by sha256 --------------------------
for tree in "ehdsi-specifications:eHDSI specifications" "eu-law:EU legal acts" \
  "openid4vc:OpenID for Verifiable Credentials texts" \
  "ihe-balp-pages:IHE BALP narrative pages" \
  "oasis-saml:OASIS SAML V2.0 standard" \
  "w3c-xmlsec:W3C XML security Recommendations" \
  "oauth-v2-1:OAuth 2.1 Authorization Framework draft"; do
  dir="docs/specs/${tree%%:*}"
  item="${tree#*:}"
  if [ -f "$dir/PROVENANCE.md" ]; then
    before="$failures"
    want="$(grep -oE '[0-9a-f]{64}' <<< "$(corpus_pin_cell "$item")" | head -n1)"
    got="$(provenance_digest "$dir/PROVENANCE.md" "Pin-set digest")"
    [ "$got" = "$want" ] || fail "$dir/PROVENANCE.md records pin-set digest ${got:-nothing}, docs/VERSIONS.md $want"
    want="$(provenance_digest "$dir/PROVENANCE.md" "Tree digest")"
    got="$(corpus_tree_digest "$dir")"
    [ "$got" = "$want" ] || fail "$dir hashes to $got, its PROVENANCE.md records ${want:-nothing}"
    bash "scripts/vendor/${tree%%:*}.sh" --check > /dev/null ||
      fail "$dir does not match the pins of scripts/vendor/${tree%%:*}.sh"
    [ "$failures" -ne "$before" ] || ok "$item, every file at its pinned sha256"
  else
    fail "$dir/PROVENANCE.md is missing"
  fi
done

# ---- 3g. the FHIR packages of the Brands Bundle check ----------------------
if checked="$(bash scripts/vendor/fhir-packages.sh --check 2>&1)"; then
  ok "FHIR packages: ${checked##*: }"
else
  fail "FHIR packages: $checked"
fi

# ---- 4. the design ----------------------------------------------------------
architecture="docs/architecture.md"
if [ -f "$architecture" ]; then
  before="$failures"
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
  [ "$failures" -ne "$before" ] || ok "$architecture agrees on SMART App Launch $matrix"
else
  fail "$architecture is missing"
fi

# ---- 4b. the Keycloak test image -------------------------------------------
keycloak_live="crates/ferrohealth-smart/tests/it/keycloak_live.rs"
before="$failures"
want="$(grep -oE 'sha256:[0-9a-f]{64}' <<< "$(corpus_pin_cell "Keycloak test image")" | head -n1)"
[ -n "$want" ] || fail "docs/VERSIONS.md pins no Keycloak test image digest"
grep -qF "@$want" "$keycloak_live" ||
  fail "$keycloak_live does not run the Keycloak image $want"
[ "$failures" -ne "$before" ] || ok "the live Keycloak case runs the image $want"

# ---- 4c. the PostgreSQL test image -----------------------------------------
ci="./.github/workflows/ci.yml"
before="$failures"
want="$(grep -oE 'sha256:[0-9a-f]{64}' <<< "$(corpus_pin_cell "PostgreSQL test image")" | head -n1)"
[ -n "$want" ] || fail "docs/VERSIONS.md pins no PostgreSQL test image digest"
grep -qF "@$want" "$ci" ||
  fail "$ci does not run the PostgreSQL image $want"
[ "$failures" -ne "$before" ] || ok "the store cases run the PostgreSQL image $want"

# ---- 4d. the FerroSMART release lane ----------------------------------------
before="$failures"
want="$(grep -oE 'sha256:[0-9a-f]{64}' <<< "$(corpus_pin_cell "PostgreSQL test image")" | head -n1)"
grep -qF "@$want" compose.yaml ||
  fail "compose.yaml does not run the PostgreSQL image $want"
want="$(grep -oE 'sha256:[0-9a-f]{64}' <<< "$(corpus_pin_cell "Keycloak test image")" | head -n1)"
grep -qF "@$want" compose.keycloak.yaml ||
  fail "compose.keycloak.yaml does not run the Keycloak image $want"
for item in "ZITADEL image" "ZITADEL Login image" "curl image" "Rust build image" "PostgreSQL test image"; do
  want="$(grep -oE 'sha256:[0-9a-f]{64}' <<< "$(corpus_pin_cell "$item")" | head -n1)"
  [ -n "$want" ] || fail "docs/VERSIONS.md pins no digest for the $item"
  grep -qF "@$want" compose.zitadel.yaml ||
    fail "compose.zitadel.yaml does not run the $item $want"
done
want="$(grep -oE 'sha256:[0-9a-f]{64}' <<< "$(corpus_pin_cell "FerroSMART image base")" | head -n1)"
[ -n "$want" ] || fail "docs/VERSIONS.md pins no FerroSMART image base digest"
grep -qF "@$want" docker/ferrosmart/Dockerfile ||
  fail "docker/ferrosmart/Dockerfile is not built on the base $want"
want="$(awk '{ print $1; exit }' <<< "$(corpus_pin_cell "Trivy")")"
for workflow in .github/workflows/release-ferrosmart.yml .github/workflows/release-ferrosmart-scan.yml .github/workflows/image-scan.yml; do
  grep -qF "TRIVY_VERSION: \"$want\"" "$workflow" ||
    fail "$workflow does not run Trivy $want"
done
bash scripts/release/install-trivy.sh --sha256 "$want" > /dev/null ||
  fail "scripts/release/install-trivy.sh pins no sha256 for Trivy $want"
[ "$failures" -ne "$before" ] || ok "the FerroSMART release lane runs the pinned base, database and Trivy"

# ---- 4e. the Inferno lane's FerroBRIDGE ------------------------------------
before="$failures"
image="$(corpus_pin_cell "FerroBRIDGE FHIR server image")"
tag="$(corpus_pin_tag "$(corpus_pin_cell "FerroBRIDGE party mappings")")"
grep -qE "^ghcr\.io/ferrohealth/ferrobridge:${tag#v}@sha256:[0-9a-f]{64}," <<< "$image" ||
  fail "the FerroBRIDGE FHIR server image is not release ${tag#v} by digest, the release the party mappings pin"
[ "$failures" -ne "$before" ] || ok "the Inferno lane runs FerroBRIDGE ${tag#v}, the release of its party mappings"

# ---- 4f. the screenshot capture's browser ----------------------------------
before="$failures"
tools="scripts/release/journey-tools.sh"
while IFS='=' read -r variable item; do
  pin="$(corpus_pin_cell "$item")"
  grep -qxF "$variable=\"$pin\"" "$tools" ||
    fail "$tools does not set $variable to $pin, the pin of '$item'"
done << 'ROWS'
chrome_version=Chrome for Testing (Chrome and chromedriver)
chrome_linux64_sha256=Chrome for Testing, chrome-linux64.zip SHA-256
chrome_mac_arm64_sha256=Chrome for Testing, chrome-mac-arm64.zip SHA-256
chromedriver_linux64_sha256=Chrome for Testing, chromedriver-linux64.zip SHA-256
chromedriver_mac_arm64_sha256=Chrome for Testing, chromedriver-mac-arm64.zip SHA-256
ROWS
pin="$(corpus_pin_cell "thirtyfour")"
grep -qE "^thirtyfour = \{ version = \"${pin//./\\.}\"," Cargo.toml ||
  fail "Cargo.toml does not pin thirtyfour at $pin"
[ "$failures" -ne "$before" ] || ok "the screenshot capture's browser and client are at their pins"

# ---- 4g. the third-party lane's images --------------------------------------
before="$failures"
third_party="scripts/idp/third-party-fhir.sh"
for item in "HAPI FHIR server image" "Envoy token validator image" "APISIX introspecting gateway image"; do
  grep -qE '^[^ ]+@sha256:[0-9a-f]{64},' <<< "$(corpus_pin_cell "$item")" ||
    fail "docs/VERSIONS.md does not pin the $item by tag and digest"
  grep -qF "pinned_image '$item'" "$third_party" ||
    fail "$third_party does not run the $item of docs/VERSIONS.md"
done
[ "$failures" -ne "$before" ] || ok "the third-party lane runs its FHIR server and validator at their pins"

# ---- 4h. the OpenID Foundation lane's images -------------------------------
before="$failures"
oidf_lane="scripts/oidf/lane.sh"
for item in "OpenID Foundation conformance suite image" \
  "OpenID Foundation conformance suite TLS front image" "MongoDB test image"; do
  grep -qE '^[^ ]+@sha256:[0-9a-f]{64},' <<< "$(corpus_pin_cell "$item")" ||
    fail "docs/VERSIONS.md does not pin the $item by tag and digest"
  grep -qF "pinned_image '$item'" "$oidf_lane" ||
    fail "$oidf_lane does not run the $item of docs/VERSIONS.md"
done
[ "$failures" -ne "$before" ] || ok "the OpenID Foundation lane runs the suite at its pins"

# ---- 5. the licence ---------------------------------------------------------
licence="$(awk '{ print $1; exit }' <<< "$(corpus_pin_cell "Project licence")")"
before="$failures"
while IFS= read -r path; do
  claimed="$(grep -m1 -oE 'SPDX-License-Identifier: [A-Za-z0-9.+-]+' "$path" | cut -d' ' -f2 || true)"
  [ -z "$claimed" ] || [ "$claimed" = "$licence" ] ||
    fail "$path claims $claimed, the project licence is $licence"
done < <(git ls-files -z | tr '\0' '\n' | grep -v '^docs/specs/' | grep -v '^LICENSE$')
[ "$failures" -ne "$before" ] || ok "every first-party SPDX header names $licence"

if [ "$failures" -gt 0 ]; then
  printf 'versions: %d failure(s)\n' "$failures" >&2
  exit 1
fi
printf 'versions: every pin agrees with docs/VERSIONS.md\n'
