#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/mdoc-references.sh
#
# Pins the sources the EUDI wallet verifier's mdoc PID (#793) was built
# from where ISO/IEC 18013-5 alone defines a structure. The ISO text is
# sold and was not available, so the verifier reads OpenID4VP 1.0 Appendix
# B.2, the RFCs and draft-ietf-oauth-status-list-20 first, and cross-checks
# each mdoc structure against two independent implementations: the EU's
# Apache-2.0 reference libraries for iOS and multipaz, the mdoc library the
# EU's Kotlin wallet core (eudi-lib-android-wallet-core) pins at 0.101.0.
# The EUDI PID Rulebook gives the namespace and the data elements, and the
# OpenID Foundation suite's mdoc builders are the conformance lane's wallet.
#
# Redistribution: the owner's decision on #793 vendors nothing from these
# sources, so each is pinned `cache` (scripts/vendor/lib/pinned.sh): its URL,
# commit and sha256 are recorded, the script fetches it into the
# git-ignored .vendor-cache/ to verify those bytes, and only
# docs/specs/mdoc-references/PROVENANCE.md is committed.
#
# Usage:
#   scripts/vendor/mdoc-references.sh           fetch, verify and write the provenance
#   scripts/vendor/mdoc-references.sh --check   check the committed tree
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

apache_eu='Apache License 2.0, "Copyright (c) 2026 European Commission" (the file header); read as secondary evidence and not redistributed, by the owner'"'"'s decision on #793'
apache_multipaz='Apache License 2.0 (the repository'"'"'s LICENSE); read as secondary evidence and not redistributed, by the owner'"'"'s decision on #793'
no_licence='The repository states no licence; read and not redistributed'
mit_suite='MIT: the repository'"'"'s LICENSE.txt, "This software is licensed under the MIT License: Copyright (c) 2019-2020 OpenID Foundation"; read as the conformance lane'"'"'s wallet and not redistributed'

pin cache eudi-ios-data-model-MobileSecurityObject.swift \
  'eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model at commit 1bcbbdefa5f82b5c5822e5220b24683b2e7834ef' \
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model/1bcbbdefa5f82b5c5822e5220b24683b2e7834ef/Sources/MdocDataModel18013/IssuerAuth/MobileSecurityObject.swift' \
  72cd710a4f5b4bde404f53993f9553be475f366785d8c131dff53cc215f79af0 "$apache_eu"
pin cache eudi-ios-data-model-StatusList.swift \
  'eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model at commit 1bcbbdefa5f82b5c5822e5220b24683b2e7834ef' \
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model/1bcbbdefa5f82b5c5822e5220b24683b2e7834ef/Sources/MdocDataModel18013/IssuerAuth/StatusList.swift' \
  6e497dcae674b9119d3520242df9ce9006060580cfc2b8cca1dd5c74974da444 "$apache_eu"
pin cache eudi-ios-data-model-ValidityInfo.swift \
  'eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model at commit 1bcbbdefa5f82b5c5822e5220b24683b2e7834ef' \
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model/1bcbbdefa5f82b5c5822e5220b24683b2e7834ef/Sources/MdocDataModel18013/IssuerAuth/ValidityInfo.swift' \
  8f143508d9ed4d0ab86d4a33bcd46290c028035c07209a72ae4986e929cd11d5 "$apache_eu"
pin cache eudi-ios-data-model-DeviceKeyInfo.swift \
  'eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model at commit 1bcbbdefa5f82b5c5822e5220b24683b2e7834ef' \
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model/1bcbbdefa5f82b5c5822e5220b24683b2e7834ef/Sources/MdocDataModel18013/IssuerAuth/DeviceKeyInfo.swift' \
  126074350a178d0db083f27c204d85bda60e9704d1815d55d659e525c3f42da4 "$apache_eu"
pin cache eudi-ios-data-model-IssuerAuth.swift \
  'eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model at commit 1bcbbdefa5f82b5c5822e5220b24683b2e7834ef' \
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model/1bcbbdefa5f82b5c5822e5220b24683b2e7834ef/Sources/MdocDataModel18013/IssuerAuth/IssuerAuth.swift' \
  0e0bf2b50d6664390c68001c2ad6eee6b31176b1b3798c344644ee42b50fc338 "$apache_eu"
pin cache eudi-ios-data-model-IssuerSignedItem.swift \
  'eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model at commit 1bcbbdefa5f82b5c5822e5220b24683b2e7834ef' \
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model/1bcbbdefa5f82b5c5822e5220b24683b2e7834ef/Sources/MdocDataModel18013/MdocResponse/IssuerSignedItem.swift' \
  1dbda169275ddae31fe230b223dac9c92f3351a30476fac8357452e298152e00 "$apache_eu"
pin cache eudi-ios-data-model-IssuerSigned.swift \
  'eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model at commit 1bcbbdefa5f82b5c5822e5220b24683b2e7834ef' \
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model/1bcbbdefa5f82b5c5822e5220b24683b2e7834ef/Sources/MdocDataModel18013/MdocResponse/IssuerSigned.swift' \
  77c6166c8428ca8029c200bdd53ff69504a90d764ceb40381466d619c8e3534d "$apache_eu"
pin cache eudi-ios-data-model-IssuerNameSpaces.swift \
  'eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model at commit 1bcbbdefa5f82b5c5822e5220b24683b2e7834ef' \
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model/1bcbbdefa5f82b5c5822e5220b24683b2e7834ef/Sources/MdocDataModel18013/MdocResponse/IssuerNameSpaces.swift' \
  04ec726e50fe1db3c8fbdb8dd14db533b1e3985db3b48d0fb17aca896cbb852b "$apache_eu"
pin cache eudi-ios-data-model-DeviceResponse.swift \
  'eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model at commit 1bcbbdefa5f82b5c5822e5220b24683b2e7834ef' \
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model/1bcbbdefa5f82b5c5822e5220b24683b2e7834ef/Sources/MdocDataModel18013/MdocResponse/DeviceResponse.swift' \
  c27433db382b524b426141d571a800b031318e9c6893480c757b50d9b997bce3 "$apache_eu"
pin cache eudi-ios-data-model-Document.swift \
  'eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model at commit 1bcbbdefa5f82b5c5822e5220b24683b2e7834ef' \
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model/1bcbbdefa5f82b5c5822e5220b24683b2e7834ef/Sources/MdocDataModel18013/MdocResponse/Document.swift' \
  122389973a4ef39e40663d75ca6f9b41a4199576492898fbfe97a76d7cabd834 "$apache_eu"
pin cache eudi-ios-data-model-DeviceSigned.swift \
  'eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model at commit 1bcbbdefa5f82b5c5822e5220b24683b2e7834ef' \
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model/1bcbbdefa5f82b5c5822e5220b24683b2e7834ef/Sources/MdocDataModel18013/MdocResponse/DeviceSigned.swift' \
  2d6064e6aee025aa494ffd47fde1ce8b5af095e1fb43a9013580fb2b4e6003a8 "$apache_eu"
pin cache eudi-ios-data-model-DeviceAuth.swift \
  'eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model at commit 1bcbbdefa5f82b5c5822e5220b24683b2e7834ef' \
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model/1bcbbdefa5f82b5c5822e5220b24683b2e7834ef/Sources/MdocDataModel18013/MdocResponse/DeviceAuth.swift' \
  d58f16c355888083fb4e5336172e14440f0d1546d62c7ca773dc7de1b05f9d37 "$apache_eu"
pin cache eudi-ios-security-DigestCalculations.swift \
  'eu-digital-identity-wallet/eudi-lib-ios-iso18013-security at commit 548a4bceba60a8d02a95b6bebe411678b5b81d9b' \
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-security/548a4bceba60a8d02a95b6bebe411678b5b81d9b/Sources/MdocSecurity18013/IssuerAuthentication/DigestCalculations.swift' \
  5c76e946ecd9ec3b57bf02babfecc7587ef41c034e2eb710f4eaa0986453e709 "$apache_eu"
pin cache eudi-ios-security-MsoValidation.swift \
  'eu-digital-identity-wallet/eudi-lib-ios-iso18013-security at commit 548a4bceba60a8d02a95b6bebe411678b5b81d9b' \
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-security/548a4bceba60a8d02a95b6bebe411678b5b81d9b/Sources/MdocSecurity18013/IssuerAuthentication/MsoValidation.swift' \
  3b95ce666fee3ba3a1d7e0a18a3a0a51d399a4e2800c7767dbe6a35eb51d5d0a "$apache_eu"
pin cache eudi-ios-security-DeviceAuthentication.swift \
  'eu-digital-identity-wallet/eudi-lib-ios-iso18013-security at commit 548a4bceba60a8d02a95b6bebe411678b5b81d9b' \
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-security/548a4bceba60a8d02a95b6bebe411678b5b81d9b/Sources/MdocSecurity18013/MdocAuthentication/DeviceAuthentication.swift' \
  58da5eb3579c13687e23aad76c95d971a34ea53bec9af70932945c350d0b6952 "$apache_eu"
pin cache eudi-ios-security-MdocAuthentication.swift \
  'eu-digital-identity-wallet/eudi-lib-ios-iso18013-security at commit 548a4bceba60a8d02a95b6bebe411678b5b81d9b' \
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-security/548a4bceba60a8d02a95b6bebe411678b5b81d9b/Sources/MdocSecurity18013/MdocAuthentication/MdocAuthentication.swift' \
  71191fa887940c3d46e2441d5e7e1edf611676bb2bf61bb938eaab6a628e6cd6 "$apache_eu"
pin cache eudi-ios-security-CoseSignature.swift \
  'eu-digital-identity-wallet/eudi-lib-ios-iso18013-security at commit 548a4bceba60a8d02a95b6bebe411678b5b81d9b' \
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-security/548a4bceba60a8d02a95b6bebe411678b5b81d9b/Sources/MdocSecurity18013/MdocAuthentication/CoseSignature.swift' \
  4a833fb7dafe0ca007286923298393c61663fb14aa0cead65de7e83746f29321 "$apache_eu"
pin cache eudi-ios-security-SessionTranscript.swift \
  'eu-digital-identity-wallet/eudi-lib-ios-iso18013-security at commit 548a4bceba60a8d02a95b6bebe411678b5b81d9b' \
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-security/548a4bceba60a8d02a95b6bebe411678b5b81d9b/Sources/MdocSecurity18013/SessionEncryption/SessionTranscript.swift' \
  f776d57ad1ac28ea3d818f36477f6aa22ffc878db5309e10c94cd5c2a9b35413 "$apache_eu"
pin cache eudi-pid-rulebook.md \
  'ARF Annex 3.01, PID Rulebook, version 1.7 (17 Jul 2026), eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog at commit 36f8adcf914ac06cac18d685add04e0a8a06d685' \
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/36f8adcf914ac06cac18d685add04e0a8a06d685/rulebooks/pid/pid-rulebook.md' \
  6251416f6f67fb6f9e5db1cddf5947d09d7bd46e4abf248d31f9f34f466b2c04 "$no_licence"
pin cache multipaz-MobileSecurityObject.kt \
  'openwallet-foundation-labs/identity-credential (multipaz) 0.101.0, commit 5fed4566c48f8e1c55379d36a4c10f33179428c8, the release eudi-lib-android-wallet-core pins' \
  'https://raw.githubusercontent.com/openwallet-foundation-labs/identity-credential/5fed4566c48f8e1c55379d36a4c10f33179428c8/multipaz/src/commonMain/kotlin/org/multipaz/mdoc/mso/MobileSecurityObject.kt' \
  f0117d7111c1083141fb7660df3038bf5ef6ab68ee0a7884d594f7bf13b1bb3d "$apache_multipaz"
pin cache multipaz-MdocDocument.kt \
  'openwallet-foundation-labs/identity-credential (multipaz) 0.101.0, commit 5fed4566c48f8e1c55379d36a4c10f33179428c8, the release eudi-lib-android-wallet-core pins' \
  'https://raw.githubusercontent.com/openwallet-foundation-labs/identity-credential/5fed4566c48f8e1c55379d36a4c10f33179428c8/multipaz/src/commonMain/kotlin/org/multipaz/mdoc/response/MdocDocument.kt' \
  c8216b282069ae760498ec530f7837f51a9a366b3f78cabb3b47827b65b17b44 "$apache_multipaz"
pin cache multipaz-RevocationStatus.kt \
  'openwallet-foundation-labs/identity-credential (multipaz) 0.101.0, commit 5fed4566c48f8e1c55379d36a4c10f33179428c8, the release eudi-lib-android-wallet-core pins' \
  'https://raw.githubusercontent.com/openwallet-foundation-labs/identity-credential/5fed4566c48f8e1c55379d36a4c10f33179428c8/multipaz/src/commonMain/kotlin/org/multipaz/revocation/RevocationStatus.kt' \
  baa45f844082894efdad520f0affb99405944d57c19ab16cca93e4f6c86628c9 "$apache_multipaz"
pin cache multipaz-IdentifierList.kt \
  'openwallet-foundation-labs/identity-credential (multipaz) 0.101.0, commit 5fed4566c48f8e1c55379d36a4c10f33179428c8, the release eudi-lib-android-wallet-core pins' \
  'https://raw.githubusercontent.com/openwallet-foundation-labs/identity-credential/5fed4566c48f8e1c55379d36a4c10f33179428c8/multipaz/src/commonMain/kotlin/org/multipaz/revocation/IdentifierList.kt' \
  fce159c16ef801787bd3fb0cef30013ff321cfd548f4d186b1d148ceea53691a "$apache_multipaz"
pin cache multipaz-StatusList.kt \
  'openwallet-foundation-labs/identity-credential (multipaz) 0.101.0, commit 5fed4566c48f8e1c55379d36a4c10f33179428c8, the release eudi-lib-android-wallet-core pins' \
  'https://raw.githubusercontent.com/openwallet-foundation-labs/identity-credential/5fed4566c48f8e1c55379d36a4c10f33179428c8/multipaz/src/commonMain/kotlin/org/multipaz/revocation/StatusList.kt' \
  225fee6a22c28646a3570c795aa08ca3c218499ebbda79faf9e45f17b2e4fc05 "$apache_multipaz"
pin cache oidf-suite-CreateMdocCredential.java \
  'openid/conformance-suite release-v5.3.4, commit 23353b36957d6466010de767c812d2c91ed37638' \
  'https://gitlab.com/openid/conformance-suite/-/raw/23353b36957d6466010de767c812d2c91ed37638/src/main/java/net/openid/conformance/condition/as/CreateMdocCredential.java' \
  5354aa1f4099b644b665128af2e1b23c997de504c8fceab79fa094edbb94683b "$mit_suite"
pin cache oidf-suite-CwtIdentifierListTokenBuilder.java \
  'openid/conformance-suite release-v5.3.4, commit 23353b36957d6466010de767c812d2c91ed37638' \
  'https://gitlab.com/openid/conformance-suite/-/raw/23353b36957d6466010de767c812d2c91ed37638/src/main/java/net/openid/conformance/oauth/statuslists/CwtIdentifierListTokenBuilder.java' \
  a6eeea510ee3b9caaed1649f1c9e11857d7a44fcb9821afe26ce6ad90e61872a "$mit_suite"
pin cache oidf-suite-CwtStatusListTokenBuilder.java \
  'openid/conformance-suite release-v5.3.4, commit 23353b36957d6466010de767c812d2c91ed37638' \
  'https://gitlab.com/openid/conformance-suite/-/raw/23353b36957d6466010de767c812d2c91ed37638/src/main/java/net/openid/conformance/oauth/statuslists/CwtStatusListTokenBuilder.java' \
  2bf240718accc5734001a40011738f7a39ba9bd3c3e936aee62f583abf986f21 "$mit_suite"
pin cache oidf-suite-StatusListCwt.java \
  'openid/conformance-suite release-v5.3.4, commit 23353b36957d6466010de767c812d2c91ed37638' \
  'https://gitlab.com/openid/conformance-suite/-/raw/23353b36957d6466010de767c812d2c91ed37638/src/main/java/net/openid/conformance/oauth/statuslists/StatusListCwt.java' \
  f91bb3b7432006e02cd8080b511920dfeaa08eb9ac763bdff57a74be7b3a8e92 "$mit_suite"
pin cache oidf-suite-VciMdocUtils.kt \
  'openid/conformance-suite release-v5.3.4, commit 23353b36957d6466010de767c812d2c91ed37638' \
  'https://gitlab.com/openid/conformance-suite/-/raw/23353b36957d6466010de767c812d2c91ed37638/src/main/kotlin/org/multipaz/testapp/VciMdocUtils.kt' \
  cd9852a033863f51a75c59d6fd83dca4ee5e222d0235b20c4143f9420bcc599b "$mit_suite"
pin cache oidf-suite-TestAppUtils.kt \
  'openid/conformance-suite release-v5.3.4, commit 23353b36957d6466010de767c812d2c91ed37638' \
  'https://gitlab.com/openid/conformance-suite/-/raw/23353b36957d6466010de767c812d2c91ed37638/src/main/kotlin/com/android/identity/testapp/TestAppUtils.kt' \
  6b42511cd9d3b152b2ce413780d9a8c7aec3303edb0881b90bda52920d3c3be8 "$mit_suite"
pin cache oidf-suite-VP1FinalVerifierPresentCredentialOnIdentifierList.java \
  'openid/conformance-suite release-v5.3.4, commit 23353b36957d6466010de767c812d2c91ed37638' \
  'https://gitlab.com/openid/conformance-suite/-/raw/23353b36957d6466010de767c812d2c91ed37638/src/main/java/net/openid/conformance/vp1finalverifier/VP1FinalVerifierPresentCredentialOnIdentifierList.java' \
  69bec195867936f9c8c63418dd72f1ba8796642b2993782c6c7d3e222c0dba95 "$mit_suite"
pinned_corpus mdoc-references "mdoc reference sources" \
  "the sources the mdoc PID verifier was cross-checked against" \
  "The files read while building the EUDI wallet verifier's mdoc PID
(FerroHEALTH/FerroSMART#793). ISO/IEC 18013-5 defines the mdoc structures,
and its text was not available. The verifier follows OpenID4VP 1.0 Appendix
B.2, RFC 8949, RFC 9052, RFC 9053, RFC 9360 and
draft-ietf-oauth-status-list-20 §5.2 and §6.3 where they describe a
structure, and checked every structure they leave to the ISO text against
two independent implementations: the EU's reference libraries for iOS
(eudi-lib-ios-iso18013-data-model and -security) and multipaz 0.101.0, the
mdoc library the EU's Kotlin wallet core pins. The identifier list rests on
multipaz and the OpenID Foundation suite alone. The EUDI PID
Rulebook names the namespace and the data elements.

Nothing here is redistributed: each file is recorded by URL, commit and
sha256, fetched only into the git-ignored .vendor-cache/ to verify its
bytes, and cited by path." "" \
  "the EUDI wallet verifier's mdoc PID (#793)"

say "done"
