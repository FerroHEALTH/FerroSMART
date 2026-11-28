#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# Whether a change to Cargo.lock reaches what the conformance lanes measure:
# a registry or git package added, removed or changed, or a workspace
# member's entry changed beyond its own version. A release pull request
# moves only a member's version, which no lane measures, so its lock change
# reaches none. No specification governs this: our own design.
#
#   scripts/checks/lock-reaches.sh <base> <head>   print each package that reaches;
#                                                  exit 0 when one does or a lock
#                                                  cannot be read, 1 when none
#   scripts/checks/lock-reaches.sh --self-test
set -euo pipefail

# Prints one sorted record per [[package]] of the lock on stdin, its lines
# joined; a workspace member, the package with no source, leaves out its
# version.
records() {
  awk '
    function flush() {
      if (name != "") print name "|" (sourced ? version : "") body
      name = ""; body = ""; sourced = 0; version = ""
    }
    /^\[\[package\]\]$/ { flush(); inpkg = 1; next }
    /^\[/ { flush(); inpkg = 0; next }
    !inpkg || /^$/ { next }
    /^name = / { name = $0; next }
    /^version = / { version = $0; next }
    /^source = / { sourced = 1 }
    { body = body "|" $0 }
    END { flush() }
  ' | sort
}

# Prints the name of each package whose record differs between the locks
# in the files $1 and $2.
reaching() {
  comm -3 <(records < "$1") <(records < "$2") |
    awk -F'|' '{ sub(/^[[:space:]]+/, "", $1); sub(/^name = /, "", $1); gsub(/"/, "", $1); print $1 }' | sort -u
}

self_test() {
  local work
  work="$(mktemp -d)"
  fail() {
    echo "lock-reaches: self-test FAILED: $*" >&2
    exit 1
  }
  lock() {
    printf 'version = 4\n\n[[package]]\nname = "ferrohealth-smart"\nversion = "%s"\ndependencies = [\n%s]\n\n[[package]]\nname = "serde"\nversion = "%s"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "%s"\n' "$@"
  }
  lock 0.38.1 ' "serde",\n' 1.0.0 aa > "$work/base"
  lock 0.38.2 ' "serde",\n' 1.0.0 aa > "$work/member"
  lock 0.38.2 ' "serde",\n' 1.0.1 bb > "$work/registry"
  lock 0.38.2 ' "serde",\n "url",\n' 1.0.1 bb > "$work/dependency"
  [[ -z "$(reaching "$work/base" "$work/member")" ]] ||
    fail "a member's version move reaches: $(reaching "$work/base" "$work/member")"
  [[ "$(reaching "$work/member" "$work/registry")" == serde ]] || fail "a registry package's move does not reach"
  [[ "$(reaching "$work/registry" "$work/dependency")" == ferrohealth-smart ]] ||
    fail "a member's new dependency does not reach"
  rm -f "$work/base" "$work/member" "$work/registry" "$work/dependency"
  rmdir "$work"
  echo "lock-reaches: self-test OK"
}

case "${1:-}" in
  --self-test) self_test ;;
  *)
    [[ "$#" -eq 2 ]] || {
      echo "usage: scripts/checks/lock-reaches.sh <base> <head> | --self-test" >&2
      exit 2
    }
    for revision in "$1" "$2"; do
      if ! git cat-file -e "$revision:Cargo.lock" 2> /dev/null; then
        echo "Cargo.lock: unreadable at $revision, so it reaches every lane"
        exit 0
      fi
    done
    found="$(reaching <(git show "$1:Cargo.lock") <(git show "$2:Cargo.lock"))"
    [[ -n "$found" ]] || exit 1
    while IFS= read -r name; do echo "Cargo.lock: $name"; done <<< "$found"
    ;;
esac
