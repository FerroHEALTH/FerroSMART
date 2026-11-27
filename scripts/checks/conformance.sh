#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# The README conformance badges (#859, #946, #950): one shields.io endpoint badge
# (https://shields.io/badges/endpoint-badge) per self-tested specification,
# written under conformance/badges/ from the files the tests hold FerroSMART
# to. No specification governs the badges: our own design.
#
#   pid-rulebook.json      conformance/pid-attributes.tsv, which the PID
#                          mapping test holds to the mapping: of every data
#                          identifier of the Rulebook docs/VERSIONS.md pins,
#                          those handled (mapped, not retained as the law
#                          requires, or not asked for a stated reason) whose
#                          named test exists under app/
#   openid4vp.json         app/ferrosmart/oidf/expected.tsv: of the verifier
#                          plans' negative modules (the login refused), those
#                          the suite passes
#   openid4vp-accepted.json
#                          the same file: of the verifier plans' positive
#                          modules (a valid presentation), those FerroSMART
#                          accepted and the suite did not fail (PASSED, or
#                          REVIEW, which the suite gives a module with an
#                          image for its reviewers)
#   openid-connect-op.json app/ferrosmart/oidf/expected.tsv: of the modules
#                          of the two OpenID Provider plans, those the
#                          suite passes (PASSED or WARNING)
#   openid-connect-rp.json the same, of the two relying party plans
#   fapi2-op.json          the same, of the FAPI 2.0 Security Profile plan
#   smart-app-launch.json  app/ferrosmart/inferno/smart_stu2_2_expected.json:
#                          the Inferno tests that pass, of all run and not
#                          omitted, as Inferno scores them
#   post-quantum.json      conformance/post-quantum.tsv, through the shared
#                          helper's badge_post_quantum: the post-quantum
#                          safe uses of all (#890); the same rows are the
#                          table of docs/post-quantum.md, and each file a
#                          row's location names exists
#
# A badge shows only its count, in the family's length limits; docs/conformance.md,
# written from the same files, breaks every count down: each result of
# the OpenID Foundation plans, the REVIEW modules and the issues the rows
# name (owner decision, 2026-11-27).
#
# Each label names the exact version it was tested against, and no label
# claims more than a self-test: "certified", "compliant" and "conformant"
# are refused, in a badge and in the README's badge text. Every badge, and
# every static badge in the README, carries a logo from badge-logos/, and
# the small caption under the README's conformance heading says once what the
# badges count (owner decision, 2026-11-25). A badge's colour follows its
# count: green when all pass, yellow when some do, red when none do.
#
#   scripts/checks/conformance.sh             rewrite the badges and the page
#   scripts/checks/conformance.sh --check     fail when a badge, the page or a label
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
  local color logo
  color="$(badge_count_color "$2" "$3")"
  logo="$(badge_logo_fields "$5")"
  jq -cn --arg label "$1" --arg message "$2/$3 $4" --arg color "$color" --argjson logo "$logo" \
    '{schemaVersion: 1, label: $label, message: $message, color: $color} + $logo'
}

# The SMART App Launch version docs/VERSIONS.md pins.
smart_version() {
  awk -F'|' '$2 ~ /^ SMART App Launch $/ { print $3 }' "$1/docs/VERSIONS.md" |
    grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

# The EUDI PID Rulebook version docs/VERSIONS.md of the tree $1 pins.
pid_version() {
  grep -oE 'EUDI PID Rulebook [0-9]+\.[0-9]+' "$1/docs/VERSIONS.md" | head -1 | grep -oE '[0-9]+\.[0-9]+$' || true
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

# Prints the markdown table of the post-quantum inventory $1.
pq_table() {
  printf '| Use | Algorithm | Safe | Post-quantum standard | Location |\n|---|---|---|---|---|\n'
  rows "$1" | tail -n +2 | awk -F'\t' '{ printf "| %s | %s | %s | %s | `%s` |\n", $1, $2, $3, $4, $5 }'
}

# Prints the docs/post-quantum.md of the tree $1 with its table rewritten
# from the inventory, between the two table markers.
pq_page() {
  local tree="$1" table
  table="$(pq_table "$tree/conformance/post-quantum.tsv")"
  PQ_TABLE="$table" awk '
    /^<!-- post-quantum table -->$/ { print; print ENVIRON["PQ_TABLE"]; skip = 1; next }
    /^<!-- end of the post-quantum table -->$/ { skip = 0 }
    !skip { print }
  ' "$tree/docs/post-quantum.md"
}

# Fails for each file a row of the post-quantum inventory of the tree $1
# names in its location that the tree does not hold.
pq_locations() {
  local tree="$1" failures=0 location item path items
  while IFS=$'\t' read -r _ _ _ _ location; do
    IFS=',' read -ra items <<< "$location"
    for item in "${items[@]}"; do
      path="$(awk '{ print $1 }' <<< "$item")"
      [[ "$path" == */* ]] || continue
      if [[ ! -e "$tree/$path" ]]; then
        echo "conformance: the post-quantum inventory names $path, which the tree does not hold" >&2
        failures=$((failures + 1))
      fi
    done
  done < <(rows "$tree/conformance/post-quantum.tsv" | tail -n +2)
  [[ "$failures" -eq 0 ]]
}

# Prints, for the modules of expected.tsv $1 whose plan matches the regular
# expression $2, the line "<passed> <total>" (passed: PASSED, or WARNING,
# which the suite passes with a remark), then one "<result> <count>" line
# per result in the suite's order, then "issues" and the issues the rows
# that did not pass name, ascending.
oidf_counts() {
  rows "$1" | awk -F'\t' -v plans="$2" '
    $1 ~ plans {
      total++
      # A module whose outcome races the suite counts as its first outcome.
      r = $3
      sub(/\|.*/, "", r)
      if (r == "PASSED" || r == "WARNING") passed++
      result[r]++
      if (r != "PASSED" && r != "WARNING") {
        m = split($5, named, /[ ,]+/)
        for (i = 1; i <= m; i++) if (named[i] ~ /^#?[0-9]+$/) { sub(/^#/, "", named[i]); issue[named[i]] = 1 }
      }
    }
    END {
      if (total == 0) exit 1
      print passed + 0, total
      split("PASSED WARNING FAILED REVIEW INTERRUPTED SKIPPED NOT-RUN", order, " ")
      for (i = 1; i <= 7; i++) if (order[i] in result) { print order[i], result[order[i]]; delete result[order[i]] }
      n = 0
      for (r in result) extra[++n] = r
      for (i = 1; i <= n; i++) for (j = i + 1; j <= n; j++) if (extra[j] < extra[i]) { t = extra[i]; extra[i] = extra[j]; extra[j] = t }
      for (i = 1; i <= n; i++) print extra[i], result[extra[i]]
      n = 0
      for (k in issue) ids[++n] = k
      for (i = 1; i <= n; i++) for (j = i + 1; j <= n; j++) if (ids[j] + 0 < ids[i] + 0) { t = ids[i]; ids[i] = ids[j]; ids[j] = t }
      line = "issues"
      for (i = 1; i <= n; i++) line = line " " ids[i]
      print line
    }
  '
}

# Prints the markdown breakdown of the oidf_counts output $1.
oidf_section() {
  local result count issues id first=1
  printf '| Result | Modules |\n|---|---|\n'
  while read -r result count; do
    [[ "$result" == issues ]] || printf '| %s | %s |\n' "$result" "$count"
  done < <(tail -n +2 <<< "$1")
  issues="$(tail -n 1 <<< "$1")"
  issues="${issues#issues}"
  [[ -n "${issues// /}" ]] || return 0
  printf '\nOpen issues:'
  for id in $issues; do
    [[ "$first" -eq 1 ]] || printf ','
    printf ' [#%s](https://github.com/FerroHEALTH/FerroSMART/issues/%s)' "$id" "$id"
    first=0
  done
  printf '.\n'
}

# Prints the endpoint JSON of label $1 with the message $2, coloured by the
# count it opens with, and logo $3.
message_badge() {
  local color logo passed total
  passed="${2%%/*}"
  total="${2#*/}"
  total="${total%% *}"
  color="$(badge_count_color "$passed" "$total")"
  logo="$(badge_logo_fields "$3")"
  jq -cn --arg label "$1" --arg message "$2" --arg color "$color" --argjson logo "$logo" \
    '{schemaVersion: 1, label: $label, message: $message, color: $color} + $logo'
}

# Writes the badges of the tree $1 into the directory $2, with the page
# that breaks their counts down as $2/conformance.md.
render() {
  local tree="$1" out="$2" mapped listed refused negative passed tests pid smart
  local expected="$tree/app/ferrosmart/oidf/expected.tsv"
  mapped=$(handled "$tree")
  listed=$(rows "$tree/conformance/pid-attributes.tsv" | wc -l | tr -d ' ')
  pid=$(pid_version "$tree")
  [[ -n "$pid" ]] || { echo "conformance: docs/VERSIONS.md pins no EUDI PID Rulebook version" >&2; return 2; }
  badge "EUDI PID Rulebook $pid" "$mapped" "$listed" handled eu > "$out/pid-rulebook.json"
  negative=$(rows "$expected" | awk -F'\t' '$1 ~ /^oid4vp-/ && $4 == "refused"' | wc -l | tr -d ' ')
  refused=$(rows "$expected" | awk -F'\t' '$1 ~ /^oid4vp-/ && $4 == "refused" && $3 == "PASSED"' | wc -l | tr -d ' ')
  badge "OpenID4VP 1.0 negative tests" "$refused" "$negative" passed openid > "$out/openid4vp.json"
  local positive accepted review
  read -r positive accepted review < <(rows "$expected" | awk -F'\t' '
    $1 ~ /^oid4vp-/ && $4 != "refused" {
      n++
      if ($4 == "accepted" && ($3 == "PASSED" || $3 == "REVIEW")) a++
      if ($4 == "accepted" && $3 == "REVIEW") r++
    }
    END { print n + 0, a + 0, r + 0 }
  ')
  badge "OpenID4VP 1.0 positive tests" "$accepted" "$positive" accepted openid > "$out/openid4vp-accepted.json"
  local op rp count
  op="$(oidf_counts "$expected" '^oidcc-(basic|config)-certification-test-plan$')" ||
    { echo "conformance: expected.tsv holds no OpenID Provider module" >&2; return 2; }
  read -r -a count <<< "$(head -n 1 <<< "$op")"
  badge "OIDC Core 1.0 OIDF OP" "${count[0]}" "${count[1]}" passed openid > "$out/openid-connect-op.json"
  rp="$(oidf_counts "$expected" '^oidcc-client-(basic-certification-)?test-plan$')" ||
    { echo "conformance: expected.tsv holds no relying party module" >&2; return 2; }
  read -r -a count <<< "$(head -n 1 <<< "$rp")"
  badge "OIDC Core 1.0 OIDF RP" "${count[0]}" "${count[1]}" passed openid > "$out/openid-connect-rp.json"
  local fapi
  fapi="$(oidf_counts "$expected" '^fapi2-security-profile-final-test-plan$')" ||
    { echo "conformance: expected.tsv holds no FAPI 2.0 module" >&2; return 2; }
  read -r -a count <<< "$(head -n 1 <<< "$fapi")"
  badge "FAPI 2.0 OIDF OP" "${count[0]}" "${count[1]}" passed openid > "$out/fapi2-op.json"
  local results="$tree/app/ferrosmart/inferno/smart_stu2_2_expected.json"
  # NOTE: inferno_core 1.4.3 result.rb:50, result_summarizer.rb and HelpModal.tsx:76: an omit
  # "does not affect passed or failed scores", and a group of passes and omits scores `pass`.
  tests=$(jq '[.[] | select(.test_id and .result != "omit")] | length' "$results")
  passed=$(jq '[.[] | select(.test_id and .result == "pass")] | length' "$results")
  smart=$(smart_version "$tree")
  [[ -n "$smart" ]] || { echo "conformance: docs/VERSIONS.md pins no SMART App Launch version" >&2; return 2; }
  badge "SMART App Launch $smart" "$passed" "$tests" "Inferno tests" key > "$out/smart-app-launch.json"
  if [[ -f "$tree/conformance/post-quantum.tsv" ]]; then
    badge_post_quantum "$tree/conformance/post-quantum.tsv" > "$out/post-quantum.json"
  fi
  {
    printf '<!-- SPDX-FileCopyrightText: Cadasto B.V. -->\n<!-- SPDX-License-Identifier: BUSL-1.1 -->\n\n'
    printf '# Conformance\n\n'
    printf 'Each README conformance badge shows one count; this page breaks each count\n'
    printf "down. \`scripts/checks/conformance.sh\` writes the badges and this page from\\n"
    printf 'the same files, and CI fails when either disagrees with them. The counts\n'
    printf 'are self-tested; none is a certification.\n\n'
    printf '## EUDI PID Rulebook %s\n\n' "$pid"
    printf "%s of the %s data identifiers in \`conformance/pid-attributes.tsv\` are\\n" "$mapped" "$listed"
    printf 'handled (mapped, not retained as the law requires, or not asked for a\n'
    printf "stated reason) by a named test under \`app/\`.\\n\\n"
    printf '## OpenID4VP 1.0\n\n'
    printf "From \`app/ferrosmart/oidf/expected.tsv\`, the verifier plans of the OpenID\\n"
    printf 'Foundation suite.\n\n'
    printf '| Modules | Count |\n|---|---|\n'
    printf '| Negative (the login refused), passed | %s of %s |\n' "$refused" "$negative"
    printf '| Positive (a valid presentation), accepted | %s of %s |\n' "$accepted" "$positive"
    printf '| Accepted, awaiting the suite'"'"'s image review (REVIEW) | %s |\n\n' "$review"
    printf '## OpenID Connect Core 1.0: OpenID Provider plans\n\n'
    printf "The basic and config certification plans in\\n\`app/ferrosmart/oidf/expected.tsv\`. A WARNING passes with a remark.\\n\\n"
    oidf_section "$op"
    printf '\n## OpenID Connect Core 1.0: relying party plans\n\n'
    printf "The client and client basic certification plans in\\n\`app/ferrosmart/oidf/expected.tsv\`.\\n\\n"
    oidf_section "$rp"
    printf '\n## FAPI 2.0 Security Profile: authorization server plan\n\n'
    printf "The FAPI 2.0 Security Profile Final plan in \`app/ferrosmart/oidf/expected.tsv\`,\\n"
    printf 'with private_key_jwt, DPoP and OpenID Connect; its authorization requests\n'
    printf 'carry the S256 PKCE challenge SMART App Launch 2.2.0 requires.\n\n'
    oidf_section "$fapi"
    printf '\n## SMART App Launch %s\n\n' "$smart"
    printf "%s of the %s Inferno tests in\\n\`app/ferrosmart/inferno/smart_stu2_2_expected.json\` pass; an omitted test\\nis not counted.\\n" "$passed" "$tests"
    if [[ -f "$tree/conformance/post-quantum.tsv" ]]; then
      printf '\n## Post-quantum\n\nThe inventory and its table are [the post-quantum page](post-quantum.md).\n'
    fi
  } > "$out/conformance.md"
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
    if [[ "$label" != post-quantum ]] && ! grep -qE '[0-9]+\.[0-9]+' <<< "$label"; then
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
  badge_caption_check "$tree/README.md" || failures=$((failures + 1))
  badge_color_check "$tree"/conformance/badges/*.json || failures=$((failures + 1))
  if [[ -f "$tree/conformance/post-quantum.tsv" ]]; then
    pq_locations "$tree" || failures=$((failures + 1))
  fi
  [[ "$failures" -eq 0 ]]
}

# Rewrites the badges and docs/conformance.md of the tree $1, or with
# $2 = check compares them. A badge whose label or message runs long fails
# before anything is written.
run() {
  local tree="$1" mode="$2" fresh drift=0
  fresh="$(mktemp -d)"
  render "$tree" "$fresh"
  if [[ -f "$tree/conformance/post-quantum.tsv" ]]; then
    pq_page "$tree" > "$fresh/post-quantum.md"
  fi
  if ! badge_length_check "$fresh"/*.json; then
    rm -f "$fresh"/*.json "$fresh"/*.md
    rmdir "$fresh"
    return 1
  fi
  if [[ "$mode" == check ]]; then
    if [[ -f "$fresh/post-quantum.md" ]] && ! diff "$fresh/post-quantum.md" "$tree/docs/post-quantum.md" > /dev/null; then
      echo "conformance: the table of docs/post-quantum.md differs from conformance/post-quantum.tsv;" >&2
      echo "run scripts/checks/conformance.sh and commit the page." >&2
      drift=1
    fi
    if ! diff "$fresh/conformance.md" "$tree/docs/conformance.md" > /dev/null 2>&1; then
      echo "conformance: docs/conformance.md differs from what the tests count;" >&2
      echo "run scripts/checks/conformance.sh and commit the page." >&2
      drift=1
    fi
    if ! diff -r "$fresh" "$tree/conformance/badges" -x '*.md' > /dev/null 2>&1; then
      echo "conformance: conformance/badges/ differs from what the tests count:" >&2
      diff -r "$fresh" "$tree/conformance/badges" -x '*.md' >&2 || true
      echo "run scripts/checks/conformance.sh and commit the badges." >&2
      drift=1
    fi
  else
    mkdir -p "$tree/conformance/badges"
    cp "$fresh"/*.json "$tree/conformance/badges/"
    cp "$fresh/conformance.md" "$tree/docs/conformance.md"
    if [[ -f "$fresh/post-quantum.md" ]]; then
      cp "$fresh/post-quantum.md" "$tree/docs/post-quantum.md"
    fi
  fi
  rm -f "$fresh"/*.json "$fresh"/*.md
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
    "$tree/docs/VERSIONS.md" "$tree/README.md" "$tree/conformance/post-quantum.tsv" "$tree/docs/post-quantum.md" \
    "$tree/docs/conformance.md"
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
  {
    printf '# c\noid4vp-p\tm1\tPASSED\trefused\t-\t\noid4vp-p\tm2\tFAILED\trefused\t#1\tx\noid4vp-p\tm3\tREVIEW\taccepted\t-\t\noidcc-p\tm4\tPASSED\trefused\t-\t\n'
    printf 'oidcc-basic-certification-test-plan\tm5\tFAILED\t-\t650\tx\noidcc-config-certification-test-plan\tm6\tWARNING\t-\t#650\tx\noidcc-basic-certification-test-plan\tm7\tSKIPPED\t-\t#9\tx\n'
    printf 'oidcc-client-test-plan\tm8\tPASSED\trefused\t-\t\noidcc-client-basic-certification-test-plan\tm9\tPASSED\trefused\t-\t\n'
    printf 'fapi2-security-profile-final-test-plan\tm11\tPASSED\t-\t-\t\nfapi2-security-profile-final-test-plan\tm12\tFAILED\t-\t966\tx\n'
  } > "$tree/app/ferrosmart/oidf/expected.tsv"
  printf '[{"test_id":"a","result":"pass"},{"test_id":"b","result":"omit"},{"test_group_id":"g","result":"pass"}]' \
    > "$tree/app/ferrosmart/inferno/smart_stu2_2_expected.json"
  printf '| Item | Pin |\n|---|---|\n| SMART App Launch | 2.2.0 (STU 2.2) |\n| mdoc sources | the EUDI PID Rulebook 1.7 at commit x |\n' \
    > "$tree/docs/VERSIONS.md"
  printf '**Conformance**<br>\n%s<br>\n[![x](https://img.shields.io/endpoint?url=conformance/badges/pid-rulebook.json)](x)\n' \
    "$badge_caption" > "$tree/README.md"
  run "$tree" update > /dev/null || fail "a clean tree is refused"
  [[ "$(jq -r .message "$tree/conformance/badges/pid-rulebook.json")" == "1/2 handled" ]] ||
    fail "a row whose test does not exist counted"
  printf 'fn drops() {}\n' >> "$tree/app/ferrosmart/pid.rs"
  run "$tree" update > /dev/null || fail "the rewrite with both tests is refused"
  [[ "$(jq -r .message "$tree/conformance/badges/pid-rulebook.json")" == "2/2 handled" ]] ||
    fail "a not-retained row with its test left out"
  [[ "$(jq -r .label "$tree/conformance/badges/pid-rulebook.json")" == "EUDI PID Rulebook 1.7" ]] ||
    fail "the PID label names the pinned Rulebook"
  [[ "$(jq -r .message "$tree/conformance/badges/openid4vp.json")" == "1/2 passed" ]] ||
    fail "the negative-test count"
  [[ "$(jq -r .message "$tree/conformance/badges/openid4vp-accepted.json")" == "1/1 accepted" ]] ||
    fail "the valid-presentation count: $(jq -r .message "$tree/conformance/badges/openid4vp-accepted.json")"
  [[ "$(jq -r .message "$tree/conformance/badges/openid-connect-op.json")" == "1/3 passed" ]] ||
    fail "the OpenID Provider count: $(jq -r .message "$tree/conformance/badges/openid-connect-op.json")"
  grep -qxF '| FAILED | 1 |' "$tree/docs/conformance.md" || fail "the OpenID Provider breakdown names no failed module"
  grep -qF 'Open issues: [#9](https://github.com/FerroHEALTH/FerroSMART/issues/9), [#650](' "$tree/docs/conformance.md" ||
    fail "the OpenID Provider breakdown names no open issue"
  grep -qxF "| Accepted, awaiting the suite's image review (REVIEW) | 1 |" "$tree/docs/conformance.md" ||
    fail "the page names no presentation awaiting review"
  [[ "$(jq -r .color "$tree/conformance/badges/openid-connect-op.json")" == yellow ]] ||
    fail "the OpenID Provider colour"
  [[ "$(jq -r .message "$tree/conformance/badges/openid-connect-rp.json")" == "2/2 passed" ]] ||
    fail "the relying party count"
  [[ "$(jq -r .color "$tree/conformance/badges/openid-connect-rp.json")" == brightgreen ]] ||
    fail "the relying party colour"
  [[ "$(jq -r .message "$tree/conformance/badges/fapi2-op.json")" == "1/2 passed" ]] ||
    fail "the FAPI 2.0 count"
  cp "$tree/app/ferrosmart/oidf/expected.tsv" "$work/badge"
  printf 'oidcc-client-test-plan\tm10\tFAILED|PASSED\trefused|accepted\t933\tx\n' >> "$tree/app/ferrosmart/oidf/expected.tsv"
  run "$tree" update > /dev/null || fail "a tree with a racing module is refused"
  [[ "$(jq -r .message "$tree/conformance/badges/openid-connect-rp.json")" == "2/3 passed" ]] ||
    fail "a racing module counted as other than its first outcome"
  cp "$work/badge" "$tree/app/ferrosmart/oidf/expected.tsv"
  run "$tree" update > /dev/null || fail "the rewrite after the racing module is refused"
  [[ "$(jq -r .label "$tree/conformance/badges/smart-app-launch.json")" == "SMART App Launch 2.2.0" ]] ||
    fail "the SMART label"
  [[ "$(jq -r .message "$tree/conformance/badges/smart-app-launch.json")" == "1/1 Inferno tests" ]] ||
    fail "an omitted test counted"
  run "$tree" check > /dev/null || fail "fresh badges are refused"
  cp "$tree/app/ferrosmart/inferno/smart_stu2_2_expected.json" "$work/badge"
  jq -c '. + [{"test_id":"c","result":"fail"}]' "$work/badge" > "$tree/app/ferrosmart/inferno/smart_stu2_2_expected.json"
  run "$tree" update > /dev/null || fail "a tree with a failed test is refused"
  [[ "$(jq -r .message "$tree/conformance/badges/smart-app-launch.json")" == "1/2 Inferno tests" ]] ||
    fail "a failed test left out of the count"
  [[ "$(jq -r .color "$tree/conformance/badges/smart-app-launch.json")" == yellow ]] ||
    fail "a failed test leaves the badge green"
  jq -c 'map(if .test_id then .result = "fail" else . end)' "$work/badge" > "$tree/app/ferrosmart/inferno/smart_stu2_2_expected.json"
  run "$tree" update > /dev/null || fail "a tree with every test failed is refused"
  [[ "$(jq -r .color "$tree/conformance/badges/smart-app-launch.json")" == red ]] ||
    fail "a badge with nothing passing is not red"
  cp "$work/badge" "$tree/app/ferrosmart/inferno/smart_stu2_2_expected.json"
  run "$tree" update > /dev/null || fail "the rewrite after a fail is refused"
  [[ "$(jq -r .color "$tree/conformance/badges/smart-app-launch.json")" == brightgreen ]] ||
    fail "a badge with every test passing is not green"
  jq -c '.color = "blue"' "$tree/conformance/badges/smart-app-launch.json" > "$tree/conformance/badges/extra.json"
  if labels "$tree" 2> /dev/null; then fail "a counted badge in blue passes"; fi
  rm "$tree/conformance/badges/extra.json"
  printf 'given_name\tyes\tgiven_name\tgiven_name\t-\tmaps\n' >> "$tree/conformance/pid-attributes.tsv"
  if run "$tree" check > /dev/null 2>&1; then fail "a stale badge passes"; fi
  run "$tree" update > /dev/null || fail "the rewrite is refused"
  printf 'x\n' >> "$tree/docs/conformance.md"
  if run "$tree" check > /dev/null 2>&1; then fail "a stale conformance page passes"; fi
  run "$tree" update > /dev/null || fail "the rewrite of the page is refused"
  badge_length_check "$tree"/conformance/badges/*.json || fail "a rendered badge runs long"
  jq -c '.message = "1/1 passed, 2 skipped; open: #9"' "$tree/conformance/badges/smart-app-launch.json" > "$tree/conformance/badges/extra.json"
  if badge_length_check "$tree/conformance/badges/extra.json" 2> /dev/null; then fail "a long message passes"; fi
  rm "$tree/conformance/badges/extra.json"
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
  grep -vF "$badge_caption" "$work/badge" > "$tree/README.md"
  if labels "$tree" 2> /dev/null; then fail "a README without the conformance caption passes"; fi
  cp "$work/badge" "$tree/README.md"
  printf '[![SMART certified](https://img.shields.io/endpoint?url=conformance/badges/x.json)](x)\n' >> "$tree/README.md"
  if labels "$tree" 2> /dev/null; then fail "a README badge text claiming certification passes"; fi
  cp "$work/badge" "$tree/README.md"
  printf '%s\n' "$badge_post_quantum_header" \
    $'tls\tX25519MLKEM768\tyes\tRFC 10024\tapp/ferrosmart/pid.rs' \
    $'tokens\tRS256\tno\tRFC 9964\tapp/ferrosmart/pid.rs, ferrohealth-smart jws' > "$tree/conformance/post-quantum.tsv"
  printf '# x\n<!-- post-quantum table -->\n<!-- end of the post-quantum table -->\n' > "$tree/docs/post-quantum.md"
  run "$tree" update > /dev/null || fail "a tree with an inventory is refused"
  [[ "$(jq -r .message "$tree/conformance/badges/post-quantum.json")" == "1/2" ]] ||
    fail "the post-quantum count"
  grep -q '^| tokens | RS256 | no |' "$tree/docs/post-quantum.md" || fail "the inventory table is not written"
  printf '%s\n' $'saml\tRSA\tno\tno standard yet\tapp/ferrosmart/gone.rs' >> "$tree/conformance/post-quantum.tsv"
  if run "$tree" check > /dev/null 2>&1; then fail "a stale inventory table passes"; fi
  run "$tree" update > /dev/null 2>&1 || true
  if labels "$tree" 2> /dev/null; then fail "a location the tree does not hold passes"; fi
  clean "$work"
  badge_post_quantum_self_test || exit 1
  badge_length_self_test || exit 1
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
