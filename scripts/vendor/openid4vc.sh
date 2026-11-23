#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/openid4vc.sh
#
# Vendors the OpenID for Verifiable Credentials texts the EUDI wallet
# verifier (#689) cites into docs/specs/openid4vc/: OpenID4VC High Assurance
# Interoperability Profile 1.0 and OpenID for Verifiable Presentations 1.0,
# the profile Implementing Regulation (EU) 2026/1731 Annex XII makes a
# presentation profile of the wallet, and the IETF drafts HAIP 1.0 §9.4 pins
# (SD-JWT VC -13, Token Status List -14) with the Token Status List -20 that
# 2026/1731 Annex IV names. Each is pinned by URL and sha256
# (scripts/vendor/lib/pinned.sh).
#
# Usage:
#   scripts/vendor/openid4vc.sh           fetch and write the tree
#   scripts/vendor/openid4vc.sh --check   check the committed tree, offline
#
# Requires: curl, shasum, awk.

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

corpus_require curl shasum awk
pinned_begin

oidf='The specification'"'"'s Notices: "Copyright (c) 2025 The OpenID Foundation. The OpenID Foundation (OIDF) grants to any Contributor, developer, implementer, or other interested party a non-exclusive, royalty free, worldwide copyright license to reproduce, prepare derivative works from, distribute, perform and display, this Implementers Draft, Final Specification, or Final Specification Incorporating Errata Corrections solely for the purposes of (i) developing specifications, and (ii) implementing Implementers Drafts, Final Specifications, and Final Specification Incorporating Errata Corrections based on such documents, provided that attribution be made to the OIDF as the source of the material"'
ietf='An Internet-Draft, "Copyright (c) <year> IETF Trust and the persons identified as the document authors. All rights reserved.", subject to BCP 78 and the IETF Trust Legal Provisions Relating to IETF Documents (https://trustee.ietf.org/license-info), which allow it to be copied and distributed unmodified'

pin commit openid4vc-high-assurance-interoperability-profile-1_0-final.html "OpenID4VC High Assurance Interoperability Profile 1.0, Final, 24 December 2025" \
  https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html \
  3996e0479d06b72d6d68668b8ae3cd39fddfc29ae9220c0c3fead7dc060ec4fb "$oidf" \
  'The profile of OpenID4VP the wallet verifier implements: §5 (signed requests with the x509_hash prefix, DCQL, direct_post.jwt), §5.1 (redirects), §5.2 (the W3C Digital Credentials API), §6.1 (SD-JWT VC), §7 and §8.'
pin commit openid-4-verifiable-presentations-1_0-final.html "OpenID for Verifiable Presentations 1.0, Final" \
  https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html \
  08e635ea3563b192309c627382c281c81de176e94cdb5ffb11b13ac624f7e12e "$oidf" \
  'The presentation protocol HAIP profiles: the request object, DCQL, response encryption, the Digital Credentials API appendix and the credential format appendices.'
pin commit draft-ietf-oauth-sd-jwt-vc-13.txt "draft-ietf-oauth-sd-jwt-vc-13, 6 November 2025" \
  https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-13.txt \
  c1cb38fde3c41f32a7915bebbff2c76b121da9712a07ecb2a25a9802e428b38d "$ietf" \
  'SD-JWT-based Verifiable Credentials, the revision HAIP 1.0 §9.4 pins; the PID format dc+sd-jwt.'
pin commit draft-ietf-oauth-status-list-14.txt "draft-ietf-oauth-status-list-14, 10 December 2025" \
  https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-14.txt \
  7f47502ad2f076879a06880a4e1f864991ae1bfc21f86f6ffa1d73cd4a930352 "$ietf" \
  'Token Status List, the revision HAIP 1.0 §9.4 pins.'
pin commit draft-ietf-oauth-status-list-20.txt "draft-ietf-oauth-status-list-20, 20 April 2026" \
  https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-20.txt \
  bf4ef5827af4374b83db8df538489d21023bfd2953a938fbd8e5a6c807d94369 "$ietf" \
  'Token Status List, the revision Implementing Regulation (EU) 2026/1731 names for the status of an attestation.'
pinned_corpus openid4vc "OpenID for Verifiable Credentials texts" \
  "the OpenID for Verifiable Credentials texts the wallet verifier cites" \
  "OpenID4VC High Assurance Interoperability Profile 1.0 and OpenID for
Verifiable Presentations 1.0, Final Specifications of the OpenID
Foundation's Digital Credentials Protocols working group, and the IETF
Internet-Drafts SD-JWT VC and Token Status List at the revisions HAIP 1.0
and Implementing Regulation (EU) 2026/1731 name." "" \
  "the EUDI wallet verifier (#689)"

say "done"
