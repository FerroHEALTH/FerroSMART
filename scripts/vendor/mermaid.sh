#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/mermaid.sh
#
# Fetches the mermaid browser bundle the book draws its diagrams with into
# website/book/vendor/mermaid/, verbatim and checked by sha256. The book
# serves the file itself, so its Content-Security-Policy keeps
# script-src 'self'. The bundle is the mermaid 11.6.0 build that
# mdbook-mermaid 0.17.1 ships, the bytes every FerroHEALTH book serves.
#
# Usage:
#   scripts/vendor/mermaid.sh
#
# Re-run after changing a pin below, then commit the result and update
# website/book/vendor/mermaid/PROVENANCE.md and the mermaid row of
# docs/VERSIONS.md.
#
# Requires: curl, shasum.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="$root/website/book/vendor/mermaid"

readonly MDBOOK_MERMAID_COMMIT=99e2393a739f3c36fde30c59317d4daa355eefaf
readonly MERMAID_COMMIT=7b2083926dbe3b6280f42376a0d4195b2c72fb8e

# One "URL destination sha256" record per line.
readonly FILES="\
https://raw.githubusercontent.com/badboy/mdbook-mermaid/$MDBOOK_MERMAID_COMMIT/src/bin/assets/mermaid.min.js mermaid.min.js eefea253bed9655e838eb874ff955c46872f982a8e26290c1dd2982ddc0a4703
https://raw.githubusercontent.com/mermaid-js/mermaid/$MERMAID_COMMIT/LICENSE LICENSE ec9fb67dcb25eccc416ed56e1aab819222c805a2a4bfe4cb19e7556bf2ffde80"

mkdir -p "$out"
while read -r url name want; do
  [[ -n "$url" ]] || continue
  tmp="$(mktemp)"
  curl --fail --silent --show-error --location --output "$tmp" "$url"
  got="$(shasum -a 256 "$tmp" | cut -d' ' -f1)"
  if [[ "$got" != "$want" ]]; then
    rm -f "$tmp"
    echo "vendor: $name changed upstream (want $want, got $got)" >&2
    exit 1
  fi
  mv "$tmp" "$out/$name"
  chmod 644 "$out/$name"
  echo "vendor: $name ok"
done <<< "$FILES"
