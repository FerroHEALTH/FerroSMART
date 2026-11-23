#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/etsi-eudi.sh
#
# Pins the ETSI Technical Specifications the EUDI wallet verifier (#689)
# reads: ETSI TS 119 472-2 V1.2.1, whose clauses 4.1, 4.2, 5 and 6
# Implementing Regulation (EU) 2026/1731 Annex XII applies as the
# presentation profiles of the wallet, and ETSI TS 119 475 V1.2.1, the
# wallet-relying party access and registration certificate profile that
# Annex XII requirement OIDFVP-HAIP-COMMON-REQ-RO-23 names.
#
# Redistribution: each document reads "No part may be reproduced or utilized
# in any form or by any means, electronic or mechanical, including
# photocopying and microfilm except as authorized by written permission of
# ETSI", so each is pinned `withheld` (scripts/vendor/lib/pinned.sh): its
# URL and sha256 are recorded, nothing is copied into the repository or the
# cache, and the script writes only docs/specs/etsi-eudi/PROVENANCE.md.
#
# Usage:
#   scripts/vendor/etsi-eudi.sh           write docs/specs/etsi-eudi/PROVENANCE.md
#   scripts/vendor/etsi-eudi.sh --check   check the committed tree
#
# Requires: shasum, awk.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

case "${1:-}" in
  --check) export PINNED_CHECK=1 ;;
  '') ;;
  *)
    echo "usage: $0 [--check]" >&2
    exit 2
    ;;
esac
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"
# shellcheck source=scripts/vendor/lib/pinned.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/pinned.sh"

corpus_require shasum awk
pinned_begin

etsi='ETSI copyright, "No part may be reproduced or utilized in any form or by any means, electronic or mechanical, including photocopying and microfilm except as authorized by written permission of ETSI." (the document'"'"'s Copyright Notification); free to download from the ETSI deliver site and read'

pin withheld ts_11947202v010201p.pdf \
  'ETSI TS 119 472-2 V1.2.1 (2026-03), Electronic Signatures and Trust Infrastructures (ESI); Profiles for Electronic Attestation of Attributes; Part 2: Profiles for EAA/PID Presentations to Relying Party' \
  'https://www.etsi.org/deliver/etsi_ts/119400_119499/11947202/01.02.01_60/ts_11947202v010201p.pdf' \
  128c51ed497a82ee01a709070669e53bef4f38a0da3ec8792542f659f86e3b1f "$etsi" \
  'Fetched on 2026-11-23 and read for #689. Implementing Regulation (EU) 2026/1731 Annex XII applies its clauses 4.1, 4.2, 5 and 6, with the adaptations the Annex lists; the wallet verifier implements its clause 6, the OpenID4VC-HAIP profile.'
pin withheld ts_119475v010201p.pdf \
  'ETSI TS 119 475 V1.2.1 (2026-03), Electronic Signatures and Trust Infrastructures (ESI); Relying party attributes supporting EUDI Wallet user'"'"'s authorization decisions' \
  'https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf' \
  77bf8e71715c495494113da23ccba89c0af8bf6b457fe2da38b5a12738ace55f "$etsi" \
  'Fetched on 2026-11-23 and read for #689: the wallet-relying party access certificate whose hash is the x509_hash client identifier, and the registration certificate the request carries in verifier_info.'
pinned_corpus etsi-eudi "ETSI EUDI wallet specifications" \
  "the ETSI specifications the wallet verifier reads" \
  "ETSI TS 119 472-2 V1.2.1 and ETSI TS 119 475 V1.2.1, the presentation
profiles and the relying party certificate profile that Implementing
Regulation (EU) 2026/1731 Annex XII makes the technical specifications of
the European Digital Identity Wallet's presentations.

ETSI permits no reproduction without its written permission, so each
document is recorded here by URL, version and sha256, and no copy of it
enters the repository or the cache. Its content is cited by clause only." none \
  "the EUDI wallet verifier (#689)"

say "done"
