#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/eu-law.sh
#
# Vendors the EU legal acts the caller classification (#215) and the level
# of assurance in FerroSMART's tokens (#784) cite into docs/specs/eu-law/:
# Commission Implementing Regulation (EU) 2026/2099 on the cross-border
# identification and authentication mechanism, Commission Implementing
# Regulation (EU) 2015/1502 on the eIDAS assurance levels, the General
# Data Protection Regulation (Regulation (EU) 2016/679), and Commission
# Decision 2011/833/EU on the reuse of Commission documents, which is their
# reuse terms. Each is the English XHTML of the Official Journal, pinned at
# the Publications Office (Cellar) manifestation its CELEX resource resolves
# to, by URL and sha256 (scripts/vendor/lib/pinned.sh). The EUR-Lex copy of
# the same text adds a script tag with per-request ids, so its bytes differ
# on every fetch. 2026/2099 and 2011/833/EU are the bytes
# FerroHEALTH/FerroFED vendors under docs/specs/eu-ehds/.
#
# Usage:
#   scripts/vendor/eu-law.sh           fetch and write the tree
#   scripts/vendor/eu-law.sh --check   check the committed tree, offline
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

eu_act='An official EU legal act published in the Official Journal; reuse under Commission Decision 2011/833/EU of 12 December 2011 on the reuse of Commission documents (dec-eu-2011-833-en.xhtml, here), whose Article 6(1) reads "Documents shall be made available for reuse without application unless otherwise specified and without restrictions or, where appropriate, an open licence or disclaimer setting out conditions explaining the rights of reusers.", and whose Article 6(2)(a) allows "the obligation for the reuser to acknowledge the source of the documents"'

pin commit impl-reg-eu-2026-2099-en.xhtml "OJ L, 2026/2099, 22.9.2026 (CELEX 32026R2099), English" \
  https://publications.europa.eu/resource/cellar/dff777d4-b61d-11f1-81de-01aa75ed71a1.0006.03/DOC_1 \
  6389d047750ed8fca879d53ebeda22af444d1f1619ed3bf6f13560097aa887d0 "$eu_act" \
  'Commission Implementing Regulation (EU) 2026/2099 of 21 September 2026 on the cross-border identification and authentication mechanism, adopted under Article 16(2) of Regulation (EU) 2025/327; applies from 26 March 2027, its Article 3(3) and Article 5(2) from 26 March 2029 (its Article 9). The caller classification reads Article 6(3) and Annex Tables 1 and 2.'
pin commit reg-eu-2016-679-en.xhtml "OJ L 119, 4.5.2016, p. 1 (CELEX 32016R0679), English" \
  https://publications.europa.eu/resource/cellar/3e485e15-11bd-11e6-ba9a-01aa75ed71a1.0006.03/DOC_1 \
  962539af03738bf552319ff4ce42d69e5f95a576307c4dfed7bf87e81b646b9d "$eu_act" \
  'Regulation (EU) 2016/679 of 27 April 2016 (the General Data Protection Regulation), the text as published, with no corrigendum applied. The caller classification reads Article 9(3) and Article 29 for a guest who acts under the controller.'
pin commit impl-reg-eu-2015-1502-en.xhtml "OJ L 235, 9.9.2015, p. 7 (CELEX 32015R1502), English" \
  https://publications.europa.eu/resource/cellar/4735575a-56b7-11e5-afbf-01aa75ed71a1.0006.03/DOC_1 \
  5697550d734fa0368f002f0f5b7183eeb87704d1349b5450d2f98ecd89ffb373 "$eu_act" \
  'Commission Implementing Regulation (EU) 2015/1502 of 8 September 2015 on the minimum technical specifications and procedures for the assurance levels low, substantial and high of electronic identification means under Article 8(3) of Regulation (EU) No 910/2014. FerroSMART reads its Annex for the three levels a token carries as acr.'
pin commit dec-eu-2011-833-en.xhtml "OJ L 330, 14.12.2011, p. 39 (CELEX 32011D0833), English" \
  https://publications.europa.eu/resource/cellar/cb76d4a0-c886-40bd-99d7-8db018a723d0.0010.03/DOC_1 \
  2d5bc877b9a5aad948af21c680aca1d3409f41df5dd0dcc57ef9b1b225f60982 "$eu_act" \
  'Commission Decision 2011/833/EU of 12 December 2011 on the reuse of Commission documents, the reuse terms of the acts here (its Articles 2 and 6), kept as their licence evidence.'
pinned_corpus eu-law "EU legal acts" \
  "the EU legal acts the caller classification and the level of assurance cite" \
  "Commission Implementing Regulation (EU) 2026/2099 on the cross-border
identification and authentication mechanism, adopted under Article 16(2) of
Regulation (EU) 2025/327, Commission Implementing Regulation (EU) 2015/1502
on the assurance levels of electronic identification means, the General
Data Protection Regulation (Regulation (EU) 2016/679), and Commission
Decision 2011/833/EU of 12 December 2011 on the reuse of Commission
documents, which governs the reuse of the others.
Each is an official EU legal act published in the Official Journal, here as
the English XHTML the Publications Office serves, verbatim and with no
later amendment applied. The source is acknowledged by this file: the
Official Journal of the European Union, through the Publications Office." "" \
  "the caller classification (#215: the contact-point fields of 2026/2099
  Annex Tables 1 and 2 and its Article 6(3), and GDPR Article 9(3) and
  Article 29 for guests), vendored by #224; FerroSMART's level of assurance
  (#784: the 2015/1502 Annex levels and the floor of 2026/2099 Articles 4(2)
  and 6(3))"

say "done"
