#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
#
# Installs the pinned cloudflared on a Linux x86_64 runner from its GitHub
# release asset, verified against the sha256 below, into BINDIR. The
# certification job of oidf-verifier.yml opens a quick tunnel with it, so the
# OpenID Foundation's hosted suite reaches FerroSMART (#817).
#
#   scripts/oidf/install-cloudflared.sh <version> <bindir>
#
# A version with no row below is refused: a bump adds its row, read from the
# release notes, which list each asset's sha256. No specification governs
# this: our own design.
set -euo pipefail

# One "version<TAB>sha256 of cloudflared-linux-amd64" row per line.
readonly CHECKSUMS="\
2026.10.7	1f99fb518b83dec2ba8d870a7cc991d82a77e6196295a3d2754ba17ab9f91872"

die() {
  printf 'install-cloudflared: %s\n' "$1" >&2
  exit 1
}

[[ $# -eq 2 ]] || die "usage: $0 <version> <bindir>"
version="$1"
bindir="$2"
want="$(awk -F'\t' -v want="$version" '$1 == want { print $2; found = 1 } END { exit !found }' <<< "$CHECKSUMS")" \
  || die "no sha256 is pinned for cloudflared $version"
[[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]] \
  || die "only the Linux x86_64 binary is pinned, and this is $(uname -s) $(uname -m)"

mkdir -p "$bindir"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --retry 3 \
  --output "$bindir/cloudflared" \
  "https://github.com/cloudflare/cloudflared/releases/download/${version}/cloudflared-linux-amd64"
got="$(sha256sum "$bindir/cloudflared" | cut -d' ' -f1)"
[[ "$got" == "$want" ]] || {
  rm -f "$bindir/cloudflared"
  die "cloudflared-linux-amd64 has sha256 $got, and $want is pinned"
}
chmod +x "$bindir/cloudflared"
"$bindir/cloudflared" --version
