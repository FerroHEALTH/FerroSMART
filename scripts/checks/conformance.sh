#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# The README conformance badges (#859): one shields.io endpoint badge
# (https://shields.io/badges/endpoint-badge) per self-tested specification,
# written under conformance/badges/ from the files the tests hold FerroSMART
# to. No specification governs the badges: our own design.
#
#   pid-rulebook.json      conformance/pid-attributes.tsv, which the PID
#                          mapping test holds to the mapping: the attributes
#                          handled (mapped, or not retained as the law
#                          requires) whose named test exists under app/, of
#                          those listed
#   openid4vp.json         app/ferrosmart/oidf/expected.tsv: of the verifier
#                          plans' negative modules (the login refused), those
#                          the suite passes
#   smart-app-launch.json  app/ferrosmart/inferno/smart_stu2_2_expected.json:
#                          the Inferno tests that pass, of all run
#
# Each label names the exact version it was tested against, and no label
# claims more than a self-test: "certified", "compliant" and "conformant"
# are refused, in a badge and in the README's badge text. Every badge, and
# every static badge in the README, carries a logo from badge-logos/.
#
#   scripts/checks/conformance.sh             rewrite the badges
#   scripts/checks/conformance.sh --check     fail when a badge or a label
#                                             disagrees (CI)
#   scripts/checks/conformance.sh --self-test
#
# Needs jq. Exit 0 when clean, 1 on drift or a refused label, 2 on a usage
# error.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly root
# shellcheck source=scripts/checks/badge-logos/logo.sh
source "$root/scripts/checks/badge-logos/logo.sh"
readonly REFUSED='certified|compliant|conformant'

# The rows of a table, without its comments.
rows() {
  grep -vE '^(#|$)' "$1"
}

# Prints the endpoint JSON of label $1 with the message $2/$3 $4 and logo $5.
badge() {
  local color=brightgreen logo
  [[ "$2" -eq "$3" ]] || color=yellow
  logo="$(badge_logo_fields "$5")"
  jq -cn --arg label "$1" --arg message "$2/$3 $4" --arg color "$color" --argjson logo "$logo" \
    '{schemaVersion: 1, label: $label, message: $message, color: $color} + $logo'
}

# The SMART App Launch version docs/VERSIONS.md pins.
smart_version() {
  awk -F'|' '$2 ~ /^ SMART App Launch $/ { print $3 }' "$1/docs/VERSIONS.md" |
    grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

# Counts the rows of the PID table of the tree $1 that name a handling and a
# test function defined under its app/.
handled() {
  local tree="$1" count=0 handling test
  while IFS=$'\t' read -r _ _ _ _ handling test; do
    [[ -n "$handling" && "$handling" != "-" && -n "$test" ]] || continue
    grep -rqE "fn ${test}\(" "$tree/app" && count=$((count + 1))
  done < <(rows "$tree/conformance/pid-attributes.tsv")
  echo "$count"
}

# Writes the three badges of the tree $1 into the directory $2.
render() {
  local tree="$1" out="$2" mapped listed refused negative passed tests version
  mapped=$(handled "$tree")
  listed=$(rows "$tree/conformance/pid-attributes.tsv" | wc -l | tr -d ' ')
  badge "EUDI PID Rulebook 1.6" "$mapped" "$listed" "attributes handled" eu > "$out/pid-rulebook.json"
  negative=$(rows "$tree/app/ferrosmart/oidf/expected.tsv" |
    awk -F'\t' '$1 ~ /^oid4vp-/ && $4 == "refused"' | wc -l | tr -d ' ')
  refused=$(rows "$tree/app/ferrosmart/oidf/expected.tsv" |
    awk -F'\t' '$1 ~ /^oid4vp-/ && $4 == "refused" && $3 == "PASSED"' | wc -l | tr -d ' ')
  badge "OpenID4VP 1.0" "$refused" "$negative" "negative tests" openid > "$out/openid4vp.json"
  local results="$tree/app/ferrosmart/inferno/smart_stu2_2_expected.json"
  tests=$(jq '[.[] | select(.test_id)] | length' "$results")
  passed=$(jq '[.[] | select(.test_id and .result == "pass")] | length' "$results")
  version=$(smart_version "$tree")
  [[ -n "$version" ]] || { echo "conformance: docs/VERSIONS.md pins no SMART App Launch version" >&2; return 2; }
  badge "SMART App Launch $version" "$passed" "$tests" "Inferno tests" key > "$out/smart-app-launch.json"
}

# Fails when a badge under $1/conformance/badges, or the README's badge
# text, uses a refused word, a badge label names no version, or a badge
# carries no logo.
labels() {
  local tree="$1" failures=0 file label
  for file in "$tree"/conformance/badges/*.json; do
    label=$(jq -r .label "$file")
    if grep -qiE "$REFUSED" <<< "$label"; then
      echo "conformance: $(basename "$file") claims more than a self-test: $label" >&2
      failures=$((failures + 1))
    fi
    if ! grep -qE '[0-9]+\.[0-9]+' <<< "$label"; then
      echo "conformance: $(basename "$file") names no version: $label" >&2
      failures=$((failures + 1))
    fi
  done
  if grep -E 'conformance/badges/' "$tree/README.md" | grep -qiE "$REFUSED"; then
    echo "conformance: a README badge claims more than a self-test" >&2
    failures=$((failures + 1))
  fi
  badge_logo_check "$tree"/conformance/badges/*.json || failures=$((failures + 1))
  badge_logo_readme "$tree/README.md" || failures=$((failures + 1))
  [[ "$failures" -eq 0 ]]
}

# Rewrites the badges of the tree $1, or with $2 = check compares them.
run() {
  local tree="$1" mode="$2" fresh drift=0
  fresh="$(mktemp -d)"
  render "$tree" "$fresh"
  if [[ "$mode" == check ]]; then
    if ! diff -r "$fresh" "$tree/conformance/badges" > /dev/null 2>&1; then
      echo "conformance: conformance/badges/ differs from what the tests count:" >&2
      diff -r "$fresh" "$tree/conformance/badges" >&2 || true
      echo "run scripts/checks/conformance.sh and commit the badges." >&2
      drift=1
    fi
  else
    mkdir -p "$tree/conformance/badges"
    cp "$fresh"/*.json "$tree/conformance/badges/"
  fi
  rm -f "$fresh"/*.json
  rmdir "$fresh"
  [[ "$drift" -eq 0 ]] || return 1
  labels "$tree"
  echo "conformance: OK, $(cd "$tree/conformance/badges" && jq -r '"\(.label) \(.message)"' ./*.json | paste -sd ';' -)"
}

# Removes the self-test's tree under $1, file by file.
clean() {
  local work="$1" tree="$1/repo"
  rm -f "$work/badge" "$tree"/conformance/badges/*.json "$tree/conformance/pid-attributes.tsv" "$tree/app/ferrosmart/pid.rs" \
    "$tree/app/ferrosmart/oidf/expected.tsv" "$tree/app/ferrosmart/inferno/smart_stu2_2_expected.json" \
    "$tree/docs/VERSIONS.md" "$tree/README.md"
  rmdir "$tree/conformance/badges" "$tree/conformance" "$tree/app/ferrosmart/oidf" \
    "$tree/app/ferrosmart/inferno" "$tree/app/ferrosmart" "$tree/app" "$tree/docs" "$tree" "$work"
}

self_test() {
  local work tree
  work="$(mktemp -d)"
  fail() {
    echo "conformance: self-test FAILED: $*" >&2
    exit 1
  }
  tree="$work/repo"
  mkdir -p "$tree/conformance" "$tree/app/ferrosmart/oidf" "$tree/app/ferrosmart/inferno" "$tree/docs"
  printf '# c\nfamily_name\tyes\tfamily_name\tfamily_name\tfamily_name\tmaps\nportrait\tyes\tpicture\tportrait\tnot retained (x)\tdrops\n' \
    > "$tree/conformance/pid-attributes.tsv"
  printf '#[test]\nfn maps() {}\n' > "$tree/app/ferrosmart/pid.rs"
  printf '# c\noid4vp-p\tm1\tPASSED\trefused\t-\t\noid4vp-p\tm2\tFAILED\trefused\t#1\tx\noid4vp-p\tm3\tREVIEW\taccepted\t-\t\noidcc-p\tm4\tPASSED\trefused\t-\t\n' \
    > "$tree/app/ferrosmart/oidf/expected.tsv"
  printf '[{"test_id":"a","result":"pass"},{"test_id":"b","result":"omit"},{"test_group_id":"g","result":"pass"}]' \
    > "$tree/app/ferrosmart/inferno/smart_stu2_2_expected.json"
  printf '| Item | Pin |\n|---|---|\n| SMART App Launch | 2.2.0 (STU 2.2) |\n' > "$tree/docs/VERSIONS.md"
  printf '[![x](https://img.shields.io/endpoint?url=conformance/badges/pid-rulebook.json)](x)\n' > "$tree/README.md"
  run "$tree" update > /dev/null || fail "a clean tree is refused"
  [[ "$(jq -r .message "$tree/conformance/badges/pid-rulebook.json")" == "1/2 attributes handled" ]] ||
    fail "a row whose test does not exist counted"
  printf 'fn drops() {}\n' >> "$tree/app/ferrosmart/pid.rs"
  run "$tree" update > /dev/null || fail "the rewrite with both tests is refused"
  [[ "$(jq -r .message "$tree/conformance/badges/pid-rulebook.json")" == "2/2 attributes handled" ]] ||
    fail "a not-retained row with its test left out"
  [[ "$(jq -r .message "$tree/conformance/badges/openid4vp.json")" == "1/2 negative tests" ]] ||
    fail "the negative-test count"
  [[ "$(jq -r .label "$tree/conformance/badges/smart-app-launch.json")" == "SMART App Launch 2.2.0" ]] ||
    fail "the SMART label"
  [[ "$(jq -r .message "$tree/conformance/badges/smart-app-launch.json")" == "1/2 Inferno tests" ]] ||
    fail "the Inferno count"
  run "$tree" check > /dev/null || fail "fresh badges are refused"
  printf 'given_name\tyes\tgiven_name\tgiven_name\t-\tmaps\n' >> "$tree/conformance/pid-attributes.tsv"
  if run "$tree" check > /dev/null 2>&1; then fail "a stale badge passes"; fi
  run "$tree" update > /dev/null || fail "the rewrite is refused"
  local word
  for word in certified Compliant conformant; do
    jq -c --arg word "$word" '.label = "OpenID4VP 1.0 \($word)"' "$tree/conformance/badges/openid4vp.json" > "$work/badge"
    cp "$work/badge" "$tree/conformance/badges/extra.json"
    if labels "$tree" 2> /dev/null; then fail "a badge labelled $word passes"; fi
  done
  rm "$tree/conformance/badges/extra.json"
  jq -c '.label = "OpenID4VP"' "$tree/conformance/badges/openid4vp.json" > "$work/badge"
  cp "$work/badge" "$tree/conformance/badges/extra.json"
  if labels "$tree" 2> /dev/null; then fail "a label with no version passes"; fi
  rm "$tree/conformance/badges/extra.json"
  [[ "$(jq -r .namedLogo "$tree/conformance/badges/pid-rulebook.json")" == europeanunion ]] ||
    fail "the PID badge's EU emblem"
  [[ "$(jq -r .logoSvg "$tree/conformance/badges/smart-app-launch.json")" == "<svg "* ]] ||
    fail "the SMART badge's pictogram"
  jq -c 'del(.namedLogo)' "$tree/conformance/badges/openid4vp.json" > "$work/badge"
  cp "$work/badge" "$tree/conformance/badges/extra.json"
  if labels "$tree" 2> /dev/null; then fail "a badge without a logo passes"; fi
  jq -c 'del(.labelColor)' "$tree/conformance/badges/pid-rulebook.json" > "$work/badge"
  cp "$work/badge" "$tree/conformance/badges/extra.json"
  if labels "$tree" 2> /dev/null; then fail "an EU emblem without the EU blue label passes"; fi
  rm "$tree/conformance/badges/extra.json"
  cp "$tree/README.md" "$work/badge"
  printf '[![x](https://img.shields.io/badge/x-y-blue)](x)\n' >> "$tree/README.md"
  if labels "$tree" 2> /dev/null; then fail "a static badge without a logo passes"; fi
  cp "$work/badge" "$tree/README.md"
  printf '[![SMART certified](https://img.shields.io/endpoint?url=conformance/badges/x.json)](x)\n' >> "$tree/README.md"
  if labels "$tree" 2> /dev/null; then fail "a README badge text claiming certification passes"; fi
  clean "$work"
  echo "conformance: self-test OK"
}

case "${1:-}" in
  "") run "$root" update ;;
  --check) run "$root" check ;;
  --self-test) self_test ;;
  *)
    echo "usage: scripts/checks/conformance.sh [--check | --self-test]" >&2
    exit 2
    ;;
esac
