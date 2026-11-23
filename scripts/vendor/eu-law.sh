#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/eu-law.sh
#
# Vendors the EU legal acts the caller classification (#215), the level of
# assurance in FerroSMART's tokens (#784) and the EUDI wallet verifier
# (#689: Regulation (EU) 2024/1183 and the wallet implementing acts with
# their 2025 and 2026 amendments) cite into docs/specs/eu-law/:
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
pin commit reg-eu-2024-1183-en.xhtml "OJ L, 2024/1183, 30.4.2024 (CELEX 32024R1183), English" \
  https://publications.europa.eu/resource/cellar/459993a1-068e-11ef-a251-01aa75ed71a1.0006.03/DOC_1 \
  1e0f838b7fdb1a07ddbc359c836796cb8fe5ba44f812ae4c4884cc4319add8cf "$eu_act" \
  'Regulation (EU) 2024/1183 of 11 April 2024 amending Regulation (EU) No 910/2014 as regards establishing the European Digital Identity Framework (eIDAS 2.0). The wallet verifier (#689) reads the new Articles 5a(11) (the wallet at assurance level high), 5b (wallet-relying parties) and 5f(2) (private relying parties accepting the wallet).'
pin commit impl-reg-eu-2024-2977-en.xhtml "OJ L, 2024/2977, 4.12.2024 (CELEX 32024R2977), English" \
  https://publications.europa.eu/resource/cellar/acccd446-b1e0-11ef-acb1-01aa75ed71a1.0006.03/DOC_1 \
  e6823fd65f11dc56c803daac4e5e5fde5c6404b0fad6924f80bd54264bcb3e94 "$eu_act" \
  'Commission Implementing Regulation (EU) 2024/2977 of 28 November 2024 on person identification data and electronic attestations of attributes issued to European Digital Identity Wallets, as published; read with its amendment by 2026/1731. The wallet verifier reads Article 3 and the Annex (the PID attributes and their trust infrastructure).'
pin commit impl-reg-eu-2024-2979-en.xhtml "OJ L, 2024/2979, 4.12.2024 (CELEX 32024R2979), English" \
  https://publications.europa.eu/resource/cellar/a7576de1-b1e0-11ef-acb1-01aa75ed71a1.0006.03/DOC_1 \
  ac7e5fff2a72a3bb4ad6fa442745e59ee59ad3e65dc578f6acdd6575040b8b5a "$eu_act" \
  'Commission Implementing Regulation (EU) 2024/2979 of 28 November 2024 on the integrity and core functionalities of European Digital Identity Wallets, as published; read with its amendment by 2026/1731, which replaces its Annex II (the attestation formats).'
pin commit impl-reg-eu-2024-2980-en.xhtml "OJ L, 2024/2980, 4.12.2024 (CELEX 32024R2980), English" \
  https://publications.europa.eu/resource/cellar/e331b1f3-b1e0-11ef-acb1-01aa75ed71a1.0006.03/DOC_1 \
  f9d82eb35f4b5b8f7bdf209936306593b965925e8aef2dccad62bdcfc20e1345 "$eu_act" \
  'Commission Implementing Regulation (EU) 2024/2980 of 28 November 2024 on notifications to the Commission concerning the European Digital Identity Wallet ecosystem, as published; read with its amendment by 2026/1731. The list of PID providers it makes available is the trust anchor of a presented PID.'
pin commit impl-reg-eu-2024-2982-en.xhtml "OJ L, 2024/2982, 4.12.2024 (CELEX 32024R2982), English" \
  https://publications.europa.eu/resource/cellar/0c2d7c7b-b1e1-11ef-acb1-01aa75ed71a1.0006.03/DOC_1 \
  6dcd6d801df70c72976faf396166d82990cd6b3b152a10828be5eda3e7b8c213 "$eu_act" \
  'Commission Implementing Regulation (EU) 2024/2982 of 28 November 2024 on the protocols and interfaces of the European Digital Identity Framework, as published; read with its amendment by 2026/1731, which rewrites Articles 3 and 5 and replaces its Annex with Annexes I and II (the presentation profiles).'
pin commit impl-reg-eu-2025-848-en.xhtml "OJ L, 2025/848, 7.5.2025 (CELEX 32025R0848), English" \
  https://publications.europa.eu/resource/cellar/a6ba31dd-2adb-11f0-8a44-01aa75ed71a1.0006.03/DOC_1 \
  ad3e50c59821596b3e829d6fdf08125d1da8255c9d0613648b79e0013a88226e "$eu_act" \
  'Commission Implementing Regulation (EU) 2025/848 of 6 May 2025 on the registration of wallet-relying parties, as published; read with its amendment by 2026/1730. The wallet verifier reads Article 7 (access certificates) and Article 8 (registration certificates).'
pin commit impl-reg-eu-2026-1730-en.xhtml "OJ L, 2026/1730, 22.7.2026 (CELEX 32026R1730), English" \
  https://publications.europa.eu/resource/cellar/933ea5f2-856a-11f1-bf5e-01aa75ed71a1.0006.03/DOC_1 \
  2d939d209aeb176ac76a05062e05fad7f630251c95afa8f0874f815c8421269f "$eu_act" \
  'Commission Implementing Regulation (EU) 2026/1730 of 15 July 2026 amending Implementing Regulation (EU) 2025/848, among others Article 8 on wallet-relying party registration certificates.'
pin commit impl-reg-eu-2026-1731-en.xhtml "OJ L, 2026/1731, 22.7.2026 (CELEX 32026R1731), English" \
  https://publications.europa.eu/resource/cellar/802ddc72-856b-11f1-bf5e-01aa75ed71a1.0006.03/DOC_1 \
  716f17c983e24d60d54e577a696e691518bc082330920298c6f7fe64c24d0f73 "$eu_act" \
  'Commission Implementing Regulation (EU) 2026/1731 of 15 July 2026 amending Implementing Regulations (EU) 2024/2977, 2024/2979, 2024/2980 and 2024/2982 as regards applicable standards and specifications. Its Annex XII is the new Annex II of 2024/2982: the ISO/IEC-mdoc and OpenID4VC-HAIP presentation profiles over ETSI TS 119 472-2 V1.2.1, which the wallet verifier implements.'
pinned_corpus eu-law "EU legal acts" \
  "the EU legal acts the caller classification, the level of assurance and the wallet verifier cite" \
  "Commission Implementing Regulation (EU) 2026/2099 on the cross-border
identification and authentication mechanism, adopted under Article 16(2) of
Regulation (EU) 2025/327, Commission Implementing Regulation (EU) 2015/1502
on the assurance levels of electronic identification means, the General
Data Protection Regulation (Regulation (EU) 2016/679), and Commission
Decision 2011/833/EU of 12 December 2011 on the reuse of Commission
documents, which governs the reuse of the others; and for the European
Digital Identity Wallet, Regulation (EU) 2024/1183, Commission Implementing
Regulations (EU) 2024/2977, 2024/2979, 2024/2980, 2024/2982 and 2025/848,
and their amending Implementing Regulations (EU) 2026/1730 and 2026/1731.
Each is an official EU legal act published in the Official Journal, here as
the English XHTML the Publications Office serves, verbatim and with no
later amendment applied. The source is acknowledged by this file: the
Official Journal of the European Union, through the Publications Office." "" \
  "the caller classification (#215: the contact-point fields of 2026/2099
  Annex Tables 1 and 2 and its Article 6(3), and GDPR Article 9(3) and
  Article 29 for guests), vendored by #224; FerroSMART's level of assurance
  (#784: the 2015/1502 Annex levels and the floor of 2026/2099 Articles 4(2)
  and 6(3)); the EUDI wallet verifier (#689: 2024/1183 Articles 5a(11), 5b
  and 5f(2), the PID of 2024/2977, the presentation profiles of 2024/2982 as
  2026/1731 rewrites them, and the certificates of 2025/848)"

say "done"
