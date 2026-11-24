<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Pinned version matrix

This file is the single source of truth for every version pin in FerroSMART.
When it and a file that repeats a pin disagree, that is drift. Fix the
disagreement; never let either side silently win. `scripts/checks/versions.sh`
reads every vendored `PROVENANCE.md` and every vendored file back against the
rows below.

No specification governs this file; it is FerroSMART's own design.

## Specifications

The ground for each pin is the pin table in `docs/architecture.md` §2, which
records why the value is what it is.

| Item | Pin | Repeated in |
|---|---|---|
| SMART App Launch | 2.2.0 (STU 2.2, on FHIR R4 4.0.1) | `docs/architecture.md` §2, `docs/specs/smart-app-launch/PROVENANCE.md` |
| IETF RFCs | the RFCs of the table below | `docs/architecture.md` §2, `docs/specs/rfc/PROVENANCE.md` |
| OpenID Connect Discovery 1.0 | incorporating errata set 2 (2023-12-15) | `docs/architecture.md` §2, `docs/specs/openid-connect-discovery/PROVENANCE.md` |
| FAPI 2.0 Security Profile | Final Specification (2025-02-22) | `docs/architecture.md` §2, `docs/specs/fapi-security-profile/PROVENANCE.md` |
| OpenID Connect Core 1.0 | incorporating errata set 2 (2023-12-15) | `docs/architecture.md` §2, `docs/specs/openid-connect-core/PROVENANCE.md` |
| OpenID Connect RP-Initiated Logout 1.0 | final (2022-09-12) | `docs/architecture.md` §2, `docs/specs/openid-connect-rpinitiated/PROVENANCE.md` |
| OpenID Connect Front-Channel Logout 1.0 | final (2022-09-12) | `docs/architecture.md` §2, `docs/specs/openid-connect-frontchannel/PROVENANCE.md` |
| OpenID Connect Back-Channel Logout 1.0 | incorporating errata set 1 (2023-12-15) | `docs/architecture.md` §2, `docs/specs/openid-connect-backchannel/PROVENANCE.md` |
| OAuth 2.1 Authorization Framework | draft-ietf-oauth-v2-1-17 (2026-10-31, an Internet-Draft, cited beside RFC 6749, 6750 and 9700 and never in their place) | `docs/architecture.md` §2 and §13, `docs/specs/oauth-v2-1/PROVENANCE.md` |
| SMART on openEHR | DEVELOPMENT (the ITS-REST draft at its amendment record 1.1.0, 2025-05-20, pinned by commit below; never a release) | `docs/architecture.md` §2 and §3.9, `docs/specs/smart-on-openehr/PROVENANCE.md` |

## Corpora and machine-readable inputs

A corpus is pinned by commit, immutable publication or checksum, never by a
moving tag or a `latest` URL, and vendored by a committed `scripts/vendor/*.sh`
with a `PROVENANCE.md`. Each script reads its pin from this table, and
`scripts/checks/versions.sh` reads each vendored `PROVENANCE.md` back and
hashes the vendored bytes again, failing when either disagrees with its row.

| Item | Pin | Repeated in |
|---|---|---|
| SMART App Launch package | 2.2.0 registry sha1 `2e5b7caacf87523082507f6af2efdf25c24ad3d8` (`hl7.fhir.uv.smart-app-launch` from packages.fhir.org, FHIR 4.0.1, CC-BY-4.0) | `scripts/vendor/smart-app-launch.sh`, `docs/specs/smart-app-launch/PROVENANCE.md` |
| SMART App Launch source | `HL7/smart-app-launch` tag `2.2.0` commit `13449f93ba52d401d29ca9e72e8a4cbced8d6424` (the page sources the STU 2.2 publication renders) | `scripts/vendor/smart-app-launch.sh`, `docs/specs/smart-app-launch/PROVENANCE.md` |
| SMART on openEHR source | `openEHR/specifications-ITS-REST` commit `9d25ea783f790512e05f908ef743626b4f7e8d2c` (the default branch head on 2026-10-16) path `docs/smart_app_launch` last change `5183c1f9274ed84096b29ea2b3977bc2e2b26247` (status DEVELOPMENT; `scripts/vendor/smart-on-openehr.sh --upstream` fails when the default branch has a newer commit touching the path) | `scripts/vendor/smart-on-openehr.sh`, `docs/specs/smart-on-openehr/PROVENANCE.md`, the `smart-on-openehr-upstream` job of `.github/workflows/specs.yml` |
| OpenID Connect Discovery 1.0 document | `openid-connect-discovery-1_0-errata2.html` sha256 `0401a07b35de50e914e195aa2c3c64cc4f6542464381c885d24a2623fbf75ec2` (the edition `openid-connect-discovery-1_0.html` serves) | `scripts/vendor/openid-connect-discovery.sh`, `docs/specs/openid-connect-discovery/PROVENANCE.md` |
| FAPI 2.0 Security Profile document | `fapi-security-profile-2_0-final.html` sha256 `26a49ad19b1f2b19ecc1cd9b825b4d5012f5e03a5dc8cb0dbd26462d39da465c` | `scripts/vendor/fapi-security-profile.sh`, `docs/specs/fapi-security-profile/PROVENANCE.md` |
| OpenID Connect Core 1.0 document | `openid-connect-core-1_0-errata2.html` sha256 `4d016752a645e8a3c259baa4173b5a90cb6c82898ce868fc8444adde262a5aed` (the edition `openid-connect-core-1_0.html` serves) | `scripts/vendor/openid-connect-core.sh`, `docs/specs/openid-connect-core/PROVENANCE.md` |
| OpenID Connect RP-Initiated Logout 1.0 document | `openid-connect-rpinitiated-1_0-final.html` sha256 `246432dafaa5556d896fa9b9ae4284b213ff6921b33478ed3b46bd6bd4aab804` (the edition `openid-connect-rpinitiated-1_0.html` serves) | `scripts/vendor/openid-connect-rpinitiated.sh`, `docs/specs/openid-connect-rpinitiated/PROVENANCE.md` |
| OpenID Connect Front-Channel Logout 1.0 document | `openid-connect-frontchannel-1_0-final.html` sha256 `8b89f9f5a9386474b424a20dd24994763137d14d5f13915a9dd4e6cb71f9061b` (the edition `openid-connect-frontchannel-1_0.html` serves) | `scripts/vendor/openid-connect-frontchannel.sh`, `docs/specs/openid-connect-frontchannel/PROVENANCE.md` |
| OpenID Connect Back-Channel Logout 1.0 document | `openid-connect-backchannel-1_0-errata1.html` sha256 `3b5c933d5269047b39a65166d5c4d8ff6852b06451f54ed2531b8f97299fdc50` (the edition `openid-connect-backchannel-1_0.html` serves) | `scripts/vendor/openid-connect-backchannel.sh`, `docs/specs/openid-connect-backchannel/PROVENANCE.md` |
| NIST SP 800-162 document | `NIST.SP.800-162.pdf` sha256 `ea90ee967a7011c8de5cfaffe0820d157167edefdea5fc2a84af730af4295cd7` (January 2014, with the updates of 2019-08-02) | `scripts/vendor/nist-sp-800-162.sh`, `docs/specs/nist-sp-800-162/PROVENANCE.md` |
| Cedar language documentation | `cedar-policy/cedar-docs` commit `5d8a02fda9ddf629b9989b0e0e2fb16215d394e4` (the default branch head on 2026-10-25) paths `docs/collections/_policies`, `_auth` and `_schema` | `scripts/vendor/cedar-docs.sh`, `docs/specs/cedar-docs/PROVENANCE.md` |
| IHE IUA supplement | `IHE/ITI.IUA` tag `2.5` commit `a8e20c92928b7560ee07a410922187757248c8b9`, the Revision 2.5 Trial Implementation supplement text (ITI-71, ITI-72, ITI-102, ITI-103) and its figures, the edition FerroHEALTH/FerroFED vendors (CC-BY-4.0) | `scripts/vendor/ihe-iua.sh`, `docs/specs/ihe-iua/PROVENANCE.md` |
| IHE BALP narrative pages | pin-set digest `3fd80aafc7ddc31d12ca5c4a3d1a2cee9ee863b42da5731d07de146eff70c8b4` over the Volume 3 content page (3:5.7) of Basic Audit Log Patterns 1.1.4, pinned by URL and sha256 as profiles.ihe.net renders it, the bytes FerroHEALTH/FerroFED vendors (CC-BY-4.0) | `scripts/vendor/ihe-balp-pages.sh`, `docs/specs/ihe-balp-pages/PROVENANCE.md` |
| OASIS SAML V2.0 standard | pin-set digest `e0068404c33afe1c8e31c345696a326750548adfb8da2e3dd0142424d4f6f9ae` over the Core, Bindings, Profiles and Metadata documents of the OASIS Standard of 15 March 2005 (`saml-*-2.0-os.pdf`) and the Errata 05 composite of 1 May 2012, each pinned by its docs.oasis-open.org URL and sha256 (the OASIS notice each carries) | `scripts/vendor/oasis-saml.sh`, `docs/specs/oasis-saml/PROVENANCE.md` |
| W3C XML security Recommendations | pin-set digest `e84f3413c80317b5b4475e06a378cb7c0ee9dc2d982dd82c9aa58d35685f5b65` over XML Signature 1.1 and XML Encryption 1.1 (Recommendations of 11 April 2013), Exclusive XML Canonicalization 1.0 (18 July 2002) and Canonical XML 1.0 (15 March 2001), each pinned by its dated www.w3.org/TR URL and sha256 (the W3C Document License) | `scripts/vendor/w3c-xmlsec.sh`, `docs/specs/w3c-xmlsec/PROVENANCE.md` |
| OAuth 2.1 Authorization Framework draft | pin-set digest `ceae881690dd894a6e6565186ef7e0e8496da39445293565188449f523163429` over `draft-ietf-oauth-v2-1-17.txt`, pinned by its IETF archive URL and sha256 `5762f86fef656f4d5afd1d2fbd3bb79cbd25bbcba8c856dc7e0ad4851437b2a7` (BCP 78, the IETF Trust Legal Provisions) | `scripts/vendor/oauth-v2-1.sh`, `docs/specs/oauth-v2-1/PROVENANCE.md` |
| Inferno SMART App Launch test kit | `inferno-framework/smart-app-launch-test-kit` tag `v1.0.3` commit `980e54e4ed632b28267d797013399a8588772174` (the latest release on 2026-11-16, gem version 1.0.3 on `inferno_core` 1.4.3), the STU 2.2 server suite, its test groups and the kit's requirement extraction for SMART App Launch 2.2.0 (Apache-2.0) | `scripts/vendor/inferno-smart-test-kit.sh`, `docs/specs/inferno-smart-test-kit/PROVENANCE.md`, the kit checkout of `.github/workflows/ci.yml` (the Inferno lane, #520) |
| Nuts RFC021 | `nuts-foundation/nuts-specification` commit `7c0de533b8cce537812b6647542e5719c93433a8`, RFC021 (VP Token Grant Type), the commit FerroHEALTH/FerroFED vendors (CC-BY-SA-4.0, per the document's Copyright Notice) | `scripts/vendor/nuts-rfc.sh`, `docs/specs/nuts-rfc/PROVENANCE.md` |
| Microsoft Entra documentation | `MicrosoftDocs/entra-docs` commit `219d8d57b01779e72e6d5449dc9341334c1fb906` (the default branch head on 2026-11-05), the access token claims reference, the optional claims reference and the on-behalf-of flow, and for FerroSMART's login the ID token claims reference, OpenID Connect, the authorization code flow and the app registration, redirect URI, credential, certificate credential, app role, optional claim, directory extension and multitenant pages (CC-BY-4.0 per the README, MIT per the LICENSE file) | `scripts/vendor/entra-docs.sh`, `docs/specs/entra-docs/PROVENANCE.md` |
| SCIM workload identity federation guide | `AzureAD/SCIMReferenceCode` commit `21b92c8f28383e30f8c304908b126682af2370d7` (the default branch head on 2026-11-05), `Workload-Identity-Federation-for-SCIM-Provisioning.md` and its figures (MIT) | `scripts/vendor/scim-workload-identity.sh`, `docs/specs/scim-workload-identity/PROVENANCE.md` |
| openEHR RM Common (development) | `openEHR/specifications-RM` commit `09e481e9f2ed9e3f9d5b9257bd68c0679d80c7cc` on `master`, the development RM FerroHEALTH/FerroEHR generates from, the Common chapter "Change Control Package" (`docs/common/master06-change_control_package.adoc`) the party states cite (CC-BY-SA-3.0) | `scripts/vendor/openehr-rm.sh`, `docs/specs/openehr-rm/development/PROVENANCE.md` |
| Keycloak documentation | `keycloak/keycloak` tag `26.8.2` commit `e514445f9dcdabc5bdcf67cab56c1e49655de067`, the token exchange chapter, the server administration guide's service account, protocol mapper, audience, user profile and identity brokering sections, the server guide's container chapter, the audience mapper's two source files, the default user profile, the client attribute keys and signed JWT client authenticator sources, and the truststore guide (Apache-2.0) | `scripts/vendor/keycloak-docs.sh`, `docs/specs/keycloak-docs/PROVENANCE.md` |
| FerroBRIDGE party mappings | `FerroHEALTH/FerroBRIDGE` tag `v0.0.28` commit `c22bc44b571ff6076c744d133086e5f4ae0fcb4f`, the ADL 1.4 PERSON template of FerroBRIDGE's demographic suite and its Practitioner and Patient party contexts and model mappings, the release whose image the Inferno lane runs (BUSL-1.1) | `scripts/vendor/ferrobridge-party.sh`, `docs/specs/ferrobridge-party/PROVENANCE.md` |
| OpenID Foundation conformance suite runner | pin-set digest `ac1b6b6a753a914418ddc08c0faa8c841e4a107aebdcc3471deb13280032c40a` over `run-test-plan.py`, `conformance.py`, `test_plan_parser.py` and `LICENSE.txt` of `openid/conformance-suite` on GitLab at the tag `release-v5.3.4`, commit `23353b36957d6466010de767c812d2c91ed37638`, each pinned by the commit's URL and its sha256 (MIT) | `scripts/vendor/oidf-conformance-suite.sh`, `docs/specs/oidf-conformance-suite/PROVENANCE.md` |
| ZITADEL documentation | `zitadel/zitadel` tag `v4.20.3` commit `a8b256c94b6d8615f12c05c54289600a06ca1912` (the release FerroHEALTH/FerroEHR vendors and runs), the OpenID Connect claims, scopes, endpoints and grant types, the role claim guide, the login UI guides, Actions v2 with its target signature, the self-hosting pages, the setup steps and defaults, the official compose file and the v2 API definitions of the bootstrap (`apps/docs/` and `proto/` Apache-2.0 per `LICENSING.md`; the setup steps, the defaults, the signing source and the compose file AGPL-3.0-only, copied for citation) | `scripts/vendor/zitadel-docs.sh`, `docs/specs/zitadel/PROVENANCE.md` |
| Okta OpenID Connect and OAuth 2.0 API | pin-set digest `c4c7b0a45106479bcdaea3c284f05455cbe9a812bdd05b537126f5d9c5ae42b7` over the seven pages the script pins by URL and sha256 (the API reference overview, client authentication, the custom authorization server, and the authorization server, custom claim, groups claim and authorization code guides); cache only, never committed ("All rights reserved") | `scripts/vendor/okta.sh`, `docs/specs/okta/PROVENANCE.md` |
| Microsoft Graph documentation | pin-set digest `e57d83b8670cc8285f92127af8f5717c49268af10083dadb1ce138fd7278b91c` over five files of `microsoftgraph/microsoft-graph-docs-contrib` commit `bb35043c742d4406d73ccae904c05fbfca7c7428` (the default branch head on 2026-11-05), pinned by URL and sha256: `directoryObject: getMemberObjects`, `directoryObject: getMemberGroups`, the throttling guidance and the two licence files; cache only, never committed (`LICENSE.md` states CC BY-NC-ND 3.0 US, `LICENSE` holds CC BY 4.0) | `scripts/vendor/microsoft-graph.sh`, `docs/specs/microsoft-graph/PROVENANCE.md` |
| eHDSI specifications | pin-set digest `85e062f853f90a98c993ee5aa349bf19392d021deefc5505e1e5eebad9783839`: the SAML Profile 10.0.0, Section II Security Services 10.0.0, the Service Location and Capability Lookup Profile 10.0.0, the NCPeH Components Specifications 10.0.0, the Messaging Profile 10.0.0, the Cryptographic Algorithms 9.0.0, the X.509 Certificates Profile 7.0.0 and the Interoperability Specifications 8.0.1, supplied by the owner from the eHDSI wiki (EU Login) and committed (each cover: PU, reuse authorised with the source acknowledged), the files and sha256 values FerroHEALTH/FerroFED vendors; the MyHealth@EU Requirements Catalogue 10.0.0 read and not committed (no reuse statement) | `scripts/vendor/ehdsi-specifications.sh`, `docs/specs/ehdsi-specifications/PROVENANCE.md` |
| SOG-IS Agreed Cryptographic Mechanisms | pin-set digest `195a4255de680cff0fa08587b79e42f27960a912c110d7fc053390b55dc6800a`: SOG-IS Crypto Evaluation Scheme Agreed Cryptographic Mechanisms 1.3 (February 2023), `SOGIS-Agreed-Cryptographic-Mechanisms-1.3.pdf` sha256 `5560ab5c86de3e62d63304c433691f5ad01116b88aceaea52a8e4b8887e0afb3`, the floor eHDSI Cryptographic Algorithms 9.0.0 §2 sets; no licence is stated, so it is read and not redistributed, with no copy in the repository or the cache | `scripts/vendor/sogis-acm.sh`, `docs/specs/sogis-acm/PROVENANCE.md` |
| ETSI EUDI wallet specifications | pin-set digest `7b97114447adbf127274e5d633f95614628a877fb6f13d695566f0e683b147c3`: ETSI TS 119 602 V1.1.1 (2025-11) `ts_119602v010101p.pdf` sha256 `27a00765a20661ecd04076a406b26a5be1123228a2f44a2dc74caeb3041155ec`, its Annex A.1 JSON schema `1960201_json_schema.json` sha256 `f16d60477359b936cefe0c74d5f1c598e3346daf84a6bad1846c712381ca36b4` (BSD 3-Clause), ETSI TS 119 472-2 V1.2.1 (2026-03) `ts_11947202v010201p.pdf` sha256 `128c51ed497a82ee01a709070669e53bef4f38a0da3ec8792542f659f86e3b1f` and ETSI TS 119 475 V1.2.1 (2026-03) `ts_119475v010201p.pdf` sha256 `77bf8e71715c495494113da23ccba89c0af8bf6b457fe2da38b5a12738ace55f`; ETSI permits no reproduction, so they are read and not redistributed, with no copy in the repository or the cache | `scripts/vendor/etsi-eudi.sh`, `docs/specs/etsi-eudi/PROVENANCE.md` |
| mdoc reference sources | pin-set digest `74a60721cb0d4991bf522643d83b27cb4d9eac3ca6c9cf0a8d4e340708b1401e`: the files of eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model at commit `1bcbbdefa5f82b5c5822e5220b24683b2e7834ef` and eudi-lib-ios-iso18013-security at commit `548a4bceba60a8d02a95b6bebe411678b5b81d9b` (Apache-2.0), multipaz 0.101.0 at commit `5fed4566c48f8e1c55379d36a4c10f33179428c8` (Apache-2.0), the EUDI PID Rulebook 1.7 at commit `36f8adcf914ac06cac18d685add04e0a8a06d685`, and the OpenID Foundation suite's mdoc builders at `release-v5.3.4` (MIT), each by URL and sha256; the mdoc PID verifier (#793) read them where ISO/IEC 18013-5, not available, alone defines a structure, and none is redistributed | `scripts/vendor/mdoc-references.sh`, `docs/specs/mdoc-references/PROVENANCE.md` |
| EU legal acts | pin-set digest `26a0768d1a7a8cd0e504c3c0c6477aabdb4e1d236abf58ef51559edf3126f8e4`: Implementing Regulation (EU) 2026/2099, Implementing Regulation (EU) 2015/1502, Regulation (EU) 2016/679 (the GDPR), Commission Decision 2011/833/EU, Regulation (EU) 2024/1183, Implementing Regulations (EU) 2024/2977, 2024/2979, 2024/2980, 2024/2982 and 2025/848, and their amendments 2026/1730 and 2026/1731, the English Official Journal XHTML at its Cellar manifestation, reused under that Decision | `scripts/vendor/eu-law.sh`, `docs/specs/eu-law/PROVENANCE.md` |
| OpenID for Verifiable Credentials texts | pin-set digest `04f0423f15693ef4865f6714f12e2941b6d56b563c1f68a0846b4acc2b35983a`: OpenID4VC High Assurance Interoperability Profile 1.0 (Final, 24 December 2025), OpenID for Verifiable Presentations 1.0 (Final), draft-ietf-oauth-sd-jwt-vc-13 and draft-ietf-oauth-status-list-14 and -20 | `scripts/vendor/openid4vc.sh`, `docs/specs/openid4vc/PROVENANCE.md` |
| Federation Tier with AQL specification | `syntaric/openehr-federation-spec` commit `b4242c291b08990df718bbfaa1188e4865478e5a`, untagged (declares 1.0.1), the commit FerroHEALTH/FerroFED vendors; Annex B (the Dutch Generic Functions), `antora.yml` and `LICENSE` (CC0-1.0) | `scripts/vendor/federation-spec.sh`, `docs/specs/federation-spec/PROVENANCE.md` |

### The RFCs

Each row pins the RFC Editor's text form (`https://www.rfc-editor.org/rfc/rfcNNNN.txt`)
by its sha256; an RFC is immutable once published, so the checksum is the
pin. `scripts/vendor/rfcs.sh` reads every `RFC` row here, refuses an RFC the
RFC Editor reports obsoleted, and records what updates it.

| Item | Pin | Repeated in |
|---|---|---|
| RFC 6749 | The OAuth 2.0 Authorization Framework, sha256 `f204fc8661d6c92d2ec6e0b54808f961a9ad26e792f57f312d9528335519bd71` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 6750 | The OAuth 2.0 Authorization Framework: Bearer Token Usage, sha256 `9dc385cf4ecdd85024e5a95e447ede9230e11700bf35251906b25b37557d604b` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7515 | JSON Web Signature (JWS), sha256 `ecbf84674118e62526511c1237e1deaa86aada86d25b247623a2a7e04ae62e40` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7517 | JSON Web Key (JWK), sha256 `681c19b92a85068716b7e89c5815aa821bd3f11c755ff1c641b40ae9851bb33c` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7519 | JSON Web Token (JWT), sha256 `fecd930e9ccf2276b95c0017c6c4ff5d09352e4bc3c7629946447894e0f97248` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7523 | JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants, sha256 `ae24f77a8fc4338903c805c6ace38def1f23d40194aea87b123b13c5b3d2d915` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7617 | The 'Basic' HTTP Authentication Scheme, sha256 `bc941321da9912fbb1bc92ad1820848ddfd3283dbfbc30f26ea2800bdaf541db` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7662 | OAuth 2.0 Token Introspection, sha256 `2b7d688cb849f093e860557ac97e6cddac2556d69a4386561b22cdf97bf13657` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 8414 | OAuth 2.0 Authorization Server Metadata, sha256 `16c816e4e0fdbffb7e910ff3017867bf39debe9cb7f52f5cbc508a052ed660e8` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 8725 | JSON Web Token Best Current Practices, sha256 `737b7013a2495dcfd5481cf4c57c87e2455d537c4cec1140c9096a71fcef0812` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 9068 | JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens, sha256 `68d3ff3910c0f2340fd7b93b430e00053da845b6eebe095ebef0c8bfda5e14c5` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 9700 | Best Current Practice for OAuth 2.0 Security, sha256 `9919d061d40a97886ca866b51c69389b6c81c65cd4b979056c14fdbebfcf622a` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 8707 | Resource Indicators for OAuth 2.0, sha256 `3b89844a938b9219571931b664ed4a7b380555a4dda1df4e9445a2f72188e76b` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7638 | JSON Web Key (JWK) Thumbprint, sha256 `98b29ab9652070e6a5fec748d43e221bbedc66b6b22e05903fb5366c04ef3110` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 9449 | OAuth 2.0 Demonstrating Proof of Possession (DPoP), for reference, sha256 `3842c58e1f6043389416023b9bb8d765048266024982fbbd90640e05943f4e13` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 9901 | Selective Disclosure for JSON Web Tokens (SD-JWT), the format of the EUDI wallet's PID (#689), sha256 `fd4cb79184162fa7ef95f4f63abab8ee6d03c9a04c19b8f83758946464b284eb` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 8705 | OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens, sha256 `6e45a1ee94c6a6a177a4cb077fe67d74bd70c1218c9362f2db2f153239612414` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 9470 | OAuth 2.0 Step Up Authentication Challenge Protocol, sha256 `02d742f49cc0a03fb09197563c436b6f38928a71b0d8e41cde9cfe0362363e56` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 8259 | The JavaScript Object Notation (JSON) Data Interchange Format, sha256 `61a5378f4255c720beb2a4b4a63b29540147c140f36988bf086291989b4cd2d7` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 6454 | The Web Origin Concept, sha256 `6a42d01bf407e87255e3bd8d870fda0f473e09f3272592ba438b57c983bc5399` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7643 | System for Cross-domain Identity Management: Core Schema, sha256 `df799c112a3fa5be3c0fe054c08b1f4eb5d07590c4c8343a014c4537bf638ae3` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 9396 | OAuth 2.0 Rich Authorization Requests, sha256 `d6a8f032d8a585daae1c33a8c7b6e539d199f886ec8cc1c7898436f7f2eed29c` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7636 | Proof Key for Code Exchange by OAuth Public Clients, sha256 `1972e5d81cbaba7066cfd46374207bc2b4546b085ed5dd9b034e79e023e0ca31` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7009 | OAuth 2.0 Token Revocation, sha256 `b2f346d5a87ba9d7f09047901257a65f7ac0b26352095969c25821afab447829` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7521 | Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants, sha256 `d5d97b3e691c9bbc495c277cc2cd79316b82486991468fc346a96ab59ba4b3c8` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7522 | Security Assertion Markup Language (SAML) 2.0 Profile for OAuth 2.0 Client Authentication and Authorization Grants, sha256 `87656a015c74b2cce4ed74fdf785ea2cf824e8d13cc53860d40fac3e57569afd` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 8693 | OAuth 2.0 Token Exchange, sha256 `358d658014738bf4dc56c8aae2094ce716ede23b6d5a80488a7dc8e8d72da609` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 3986 | Uniform Resource Identifier (URI): Generic Syntax, sha256 `3102dae4b68cebe40337730312fcb612297b8928547267e8b3d1ee6002b2d683` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 6819 | OAuth 2.0 Threat Model and Security Considerations, sha256 `7130b62c2861e8f8a7a28aa1af9d12b6dd49e9f1353f51a84314026fbcf9dd08` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7518 | JSON Web Algorithms (JWA), sha256 `9a9ae524b09ea700ad3f189bac115df95ba69af84b26ffdbe3cdfb8d2152b1fc` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7591 | OAuth 2.0 Dynamic Client Registration Protocol, sha256 `f9cd8b8eefdb2d1b1bd5734310f246926db0abb4ec1b2f933f358d58327964e3` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 8252 | OAuth 2.0 for Native Apps, sha256 `4233c0650ec7e7918c20e0fde2dc565f85e2aa2d4c18123e3cd834295c2f68d0` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 9126 | OAuth 2.0 Pushed Authorization Requests, sha256 `a79d0e30fcc24a22b79c8e18aa82362f6e63a7b8a5d58b480e746360e97388db` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 9207 | OAuth 2.0 Authorization Server Issuer Identification, sha256 `c9c17b9824315aca9bda5c0b5e3627cb24aa28d54324292f3761006209b705fd` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 9864 | Fully-Specified Algorithms for JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE), sha256 `0f9b6dd26b3285fd9fe7f7e0a82e684d06512dee642703d51c6f88a7b0edaa2b` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 10070 | Updates to OAuth 2.0 JSON Web Token (JWT) Client Authentication and Assertion-Based Authorization Grants, sha256 `bca193c44b10f864396706e29192a091256d9c15a66c1549b01e75866165e163` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 8949 | Concise Binary Object Representation (CBOR), the encoding of the EUDI wallet's mdoc PID (#793), sha256 `f1164a5b31a39350ad46abe29b83575eb933ca6c45366989c118b6b1058a214a` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 8943 | Concise Binary Object Representation (CBOR) Tags for Date, the `full-date` of the mdoc PID's dates (#793), sha256 `bb3a62834af19f6d5d15e5a7faca922e2eab58541050f5bddf9cf477af3b7850` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 9052 | CBOR Object Signing and Encryption (COSE): Structures and Process, the `COSE_Sign1` of the mdoc's issuer and device signatures and of a status list in CWT format (#793), sha256 `01eecd7f646537600e7aad665b1fa581ce6ec33dae4ef4add0997aaf38cd0a45` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 9053 | CBOR Object Signing and Encryption (COSE): Initial Algorithms, ES256 and the EC2 key of the mdoc's device (#793), sha256 `3d470615875620375f8453ba25b8dce7e4d0271e76b0b79a46df34ccb2d56ab0` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 9360 | CBOR Object Signing and Encryption (COSE): Header Parameters for Carrying and Referencing X.509 Certificates, the `x5chain` of the mdoc's issuer (#793), sha256 `3dbe546adf08e309b429c8e71b2ee8384292fb8767338d3eb17d1c4e5adefc23` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 8392 | CBOR Web Token (CWT), the claims of a status list in CWT format (#793), sha256 `9021ff7c4d274cf34873fe4f4fb17c4fe323247dd0f96bfcab54909bfcdc5f13` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 9596 | CBOR Object Signing and Encryption (COSE) "typ" (type) Header Parameter, the type of a status list in CWT format (#793), sha256 `4beb37fe8cb3eec78cec2445c65dcf2db4866ba99a72e7b1e54e23e5bfa69b5e` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 9110 | HTTP Semantics, for the conditional GET of the Brands Bundle (If-None-Match, weak entity tags), sha256 `21c1cdce6ab0e5509b04d84a28000836c7a087cf786efe6f04877ebfff47232a` | `docs/specs/rfc/PROVENANCE.md` |

## FHIR packages (the Brands Bundle check, build time, never committed)

The test that holds FerroSMART's User Access Brands Bundle to the profiles
of SMART App Launch 2.2.0 (#602) reads the SMART package vendored under
`docs/specs/smart-app-launch/` and the packages below with
`ferrobridge-validator`, offline. `scripts/vendor/fhir-packages.sh` fetches
each from the FHIR package registry at build time into the ignored
`docs/specs/fhir-packages/<package>#<version>/package.tgz`, checks the
registry's sha1 and the sha256 pinned here, and commits only each
`PROVENANCE.md`; its `--check` asserts the dependency closure offline.

The closure is the SMART package's `dependencies` and theirs. A package
whose `fhirVersions` name another FHIR release than R4 is held without its
own dependencies, since an R4 validator never reads it, and its R4 edition,
the same package with the `.r4` suffix at the same version, is pinned
beside it so its definitions resolve: SMART App Launch 2.2.0 depends on
`hl7.fhir.uv.extensions` 5.1.0-snapshot1, an R5 package, which carries
`organization-brand`, `organization-portal` and `endpoint-fhir-version`, and
`hl7.fhir.uv.extensions.r4` 5.1.0-snapshot1 is their R4 form. No
specification governs the substitution: our own design.

| Item | Pin | Repeated in |
|---|---|---|
| `hl7.fhir.r4.core#4.0.1` | sha1 `0e4b8d99f7918587557682c8b47df605424547a5` sha256 `ebd7731df7d36b5b7d39d5fb6c9d77b44bb7fe5742f1a2e87f164738c3289d44` (CC0-1.0) | `scripts/vendor/fhir-packages.sh`, `docs/specs/fhir-packages/hl7.fhir.r4.core#4.0.1/PROVENANCE.md` |
| `hl7.fhir.uv.extensions#5.1.0-snapshot1` | sha1 `c9b500af54cea20afb742c9773a57ba422557376` sha256 `8a1f92c1e77535cb2ae21b69028de81a21ea27bd24d0a76c43c7224b8f46b35c` (CC0-1.0, FHIR 5.0.0, held) | `scripts/vendor/fhir-packages.sh`, `docs/specs/fhir-packages/hl7.fhir.uv.extensions#5.1.0-snapshot1/PROVENANCE.md` |
| `hl7.fhir.uv.extensions.r4#5.1.0-snapshot1` | sha1 `439ac5c744b7b66b841d682f1926331719db5042` sha256 `00c6d967fb4afc9fa8dd7852a95ea8806fc838a5651589011c3a056649326eb1` (CC0-1.0, the R4 edition of the row above) | `scripts/vendor/fhir-packages.sh`, `docs/specs/fhir-packages/hl7.fhir.uv.extensions.r4#5.1.0-snapshot1/PROVENANCE.md` |
| `hl7.terminology#5.5.0` | sha1 `db33c3b3204dd21e5c9d392aaa3e6c16e2d90ac1` sha256 `6d0947f9be882c06c29c693b784b751e8bd8700acdc0cf042bf4ce48d6b16698` (CC0-1.0) | `scripts/vendor/fhir-packages.sh`, `docs/specs/fhir-packages/hl7.terminology#5.5.0/PROVENANCE.md` |
| `hl7.fhir.uv.extensions.r4#1.0.0` | sha1 `d4f95213cd55173fb5bce87c02eba3ecdace3cb2` sha256 `b270eb5b0ea3d015398a5af6c86cab2718070cbb850e366ef050ce6d6eb4a9d3` (CC0-1.0, a dependency of `hl7.terminology` 5.5.0) | `scripts/vendor/fhir-packages.sh`, `docs/specs/fhir-packages/hl7.fhir.uv.extensions.r4#1.0.0/PROVENANCE.md` |

## Licence

| Item | Pin | Repeated in |
|---|---|---|
| Project licence | BUSL-1.1 | `LICENSE`, `NOTICE`, the SPDX header of every first-party file, the `license` field of the `ferrohealth-smart` manifest once the workspace lands |

`LICENSE` names Apache License 2.0 as a licence of its own, as the Change
License four years after each version. `ferrohealth-smart` is hand-written code
that implements the specifications above, so it is under BUSL-1.1 like the
rest of the family's own code; only generator-emitted code is published under
Apache-2.0 elsewhere in the family (`docs/architecture.md` §9).
`scripts/checks/versions.sh` fails on an Apache-2.0 or MIT claim in a
first-party file.

Vendored material keeps its upstream terms, recorded beside each vendored tree
in its `PROVENANCE.md`: CC BY 4.0 for the SMART App Launch package and page
sources, the IETF Trust Legal Provisions for the RFCs, Apache License 2.0
for the SMART on openEHR source and the Cedar language documentation, the
OpenID Foundation's notice for the three OpenID Connect specifications, the
public domain of a United States Government work for NIST SP 800-162, CC BY
4.0 for the IHE IUA supplement and the IHE BALP content page, CC BY-SA 4.0
for Nuts RFC021, the README's CC BY 4.0 grant and the LICENSE file's MIT
text for the Microsoft Entra documents, MIT for the SCIM workload identity
federation guide, Apache License 2.0 for the Keycloak documentation
and the Inferno SMART App Launch test kit, the IETF Trust Legal
Provisions for the OAuth 2.1 draft,
and CC BY-SA 3.0 Unported for the openEHR RM Common chapter. The Okta API
reference and guides state
"All rights reserved" and grant no licence, so `scripts/vendor/okta.sh`
fetches them into the git-ignored `.vendor-cache/okta/` and only their
`PROVENANCE.md` is committed. The Microsoft Graph reference pages carry
two licence statements that disagree, CC BY-NC-ND 3.0 United States in
`LICENSE.md` and the CC BY 4.0 text in `LICENSE`, so
`scripts/vendor/microsoft-graph.sh` keeps them in
`.vendor-cache/microsoft-graph/` the same way. The eHDSI documents are reused as each cover
allows ("Reuse is authorised, provided the source is acknowledged"), with
the source line of the cover as the acknowledgement; the MyHealth@EU
Requirements Catalogue states no reuse terms, so only its sha256 and
version are recorded and no copy is committed or cached. The EU legal acts
are reused under Commission Decision 2011/833/EU, vendored beside them, and
the Federation Tier Annex B is under CC0 1.0.

## The toolchain and the crate

| Item | Pin | Repeated in |
|---|---|---|
| Rust toolchain | 1.99.1, profile `minimal`, components `rustfmt` and `clippy` | `rust-toolchain.toml` |
| Rust edition | 2024 | `Cargo.toml` `[workspace.package] edition`, `rustfmt.toml` |
| MSRV | 1.98 | `Cargo.toml` `[workspace.package] rust-version` |
| `ferrohealth-smart` | the workspace version (read it in the manifest; a release moves it), with the release tag `ferrohealth-smart-vX.Y.Z` and the section of its own `CHANGELOG.md` | `Cargo.toml` `[workspace.package] version`, `Cargo.lock`, `crates/ferrohealth-smart/CHANGELOG.md` (held together by `scripts/checks/crate-version-guard.sh`) |
| `ferrohealth-authz` | its own version line (read it in the manifest; a release moves it), with the release tag `ferrohealth-authz-vX.Y.Z` and the section of its own `CHANGELOG.md` | `crates/ferrohealth-authz/Cargo.toml` `[package] version`, `Cargo.lock`, `crates/ferrohealth-authz/CHANGELOG.md` (held together by `scripts/checks/crate-version-guard.sh`) |
| `ferrohealth-session` | its own version line (read it in the manifest; a release moves it), with the release tag `ferrohealth-session-vX.Y.Z` and the section of its own `CHANGELOG.md` | `crates/ferrohealth-session/Cargo.toml` `[package] version`, `Cargo.lock`, `crates/ferrohealth-session/CHANGELOG.md` (held together by `scripts/checks/crate-version-guard.sh`) |
| Third-party crates | the `[workspace.dependencies]` table, each version checked against crates.io on 2026-10-19 | `Cargo.toml`, `Cargo.lock` |

## Documentation toolchain

The tools that build and check the site under `website/`.
`scripts/site/toolchain.sh` reads these rows, the Docs workflow and the CI
link check install exactly these versions, and `scripts/site/assemble.sh`
refuses another mdBook. They are the versions the FerroHEALTH family book
pins, so every book in the family builds with the same tools.

| Item | Pin | Repeated in |
|---|---|---|
| mdBook | `0.5.4` | `scripts/site/toolchain.sh` reads it |
| mdbook-lint | `0.14.4` | `scripts/site/toolchain.sh` reads it |
| lychee | `0.24.2` | `scripts/site/toolchain.sh` reads it |
| mermaid | `11.6.0` | `scripts/vendor/mermaid.sh` pins its sha256, recorded in `website/book/vendor/mermaid/PROVENANCE.md` |

## The screenshot capture

The book's screenshots of FerroSMART's pages (`app/ferrosmart/tests/it/screenshots/`,
#623) are taken in headless Chrome over WebDriver, through chromedriver,
with the `thirtyfour` client, a test-only dependency of the server. The
capture runs on a developer's machine behind `FERROSMART_SCREENSHOTS=1`,
never in CI, which runs only the guard over the committed images.
`scripts/release/journey-tools.sh target/journey-tools` installs Chrome and
chromedriver as one Chrome for Testing release, so the browser and its
driver always match. It takes each download URL from the Chrome for Testing
JSON API and checks each zip against the SHA-256 below before it unpacks
it. Chrome for Testing publishes no SHA-256; the four digests are the ones
FerroHEALTH/FerroPIX pins for the same release, taken on 2026-11-03 of
downloads whose MD5 equals the `x-goog-hash` the storage bucket serves, and
the two macOS ones were checked again here on 2026-11-19.

| Item | Pin | Repeated in |
|---|---|---|
| thirtyfour | `0.38.1` | `Cargo.toml` |
| Chrome for Testing (Chrome and chromedriver) | `157.0.8103.38` | `scripts/release/journey-tools.sh` |
| Chrome for Testing, `chrome-linux64.zip` SHA-256 | `8cdeb344e9b2cefe59f4aea8d1d93d5d93054c03cde217665c16fc1f62e72a66` | `scripts/release/journey-tools.sh` |
| Chrome for Testing, `chrome-mac-arm64.zip` SHA-256 | `3406b38b52b7d341d74450eb7b369be038c9fec9894c8b8a9e9e9f97333caf2f` | `scripts/release/journey-tools.sh` |
| Chrome for Testing, `chromedriver-linux64.zip` SHA-256 | `329525fa0bf02be19794de1e9475772ef64695e0456f142888bd70df3147dc1e` | `scripts/release/journey-tools.sh` |
| Chrome for Testing, `chromedriver-mac-arm64.zip` SHA-256 | `e59394fda6a05067362c225678e185e46e473cebea1593025deb2b2641b75688` | `scripts/release/journey-tools.sh` |

## The CI tools

The FerroEHR and FerroBRIDGE image rows are read each Monday against each
product's latest release and the digest of its image index by
`scripts/checks/pin-freshness.sh`, which opens one issue per image behind.

| Item | Pin | Repeated in |
|---|---|---|
| zizmor | 1.31.1 | `.github/workflows/ci.yml` |
| actionlint | 1.7.12, image digest `sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667` | `.github/workflows/ci.yml` |
| shellcheck | 0.11.0 | `.github/workflows/ci.yml` |
| hadolint | 2.15.1, image digest `sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d` | `.github/workflows/ci.yml` |
| cargo-semver-checks | 0.51.0, installed through `taiki-e/install-action`, which verifies the archive against its manifest checksum | read from this row by `scripts/checks/semver.sh --pin` for `.github/workflows/ci.yml` and `.github/workflows/release.yml` |
| `jscpd` | `5.4.2` (release v5.4.2 of github.com/kucherenko/jscpd, 2026-10-20) | `scripts/checks/duplication.sh` |
| `jscpd image` | `ghcr.io/kucherenko/jscpd:5.4.2@sha256:112bc771493f25ec412ebf61bef738dc1fbe80d3793090e6a5eeac827ef0ee79` | `scripts/checks/duplication.sh` (docker, podman) |
| `jscpd darwin-arm64` | `b51d22d7c7610d27d8fd022577021ff3266a10f13295a2e545a8b8e126133a88` (`jscpd-darwin-arm64.tar.gz`) | `scripts/checks/duplication.sh --install` |
| `jscpd darwin-x64` | `ae8d24aba2719df7682b1bb2c5021ab096116b8240c45fdae88654fc1ff36b17` (`jscpd-darwin-x64.tar.gz`) | `scripts/checks/duplication.sh --install` |
| `jscpd linux-x64` | `5f18a6b70b4210782fc3c401c780ba994a2777249cd44d97d6fa460f6fff4570` (`jscpd-linux-x64-musl.tar.gz`) | `scripts/checks/duplication.sh --install` |
| `jscpd linux-arm64` | `3635d652ae08ae10bfbc6821bfa8ac14080101f317fb5f45f4b590d5d32b9339` (`jscpd-linux-arm64-musl.tar.gz`) | `scripts/checks/duplication.sh --install` |
| cargo-nextest, cargo-deny | the newest release `taiki-e/install-action` resolves at run time | `.github/workflows/ci.yml` |
| Keycloak test image | `quay.io/keycloak/keycloak:26.8.2`, index digest `sha256:3879c623248408de29a5303178b5816c77e8dfef3890c361f8c0bbeaa979ba3b`, the release the Keycloak documentation pin names, FerroSMART's upstream login in the example lanes | `scripts/idp/keycloak-launch.sh` (read from this row), `scripts/inferno/lane.sh` (read from this row), `compose.keycloak.yaml` (run by `scripts/idp/compose-launch.sh` in CI's `quickstart` job) |
| PostgreSQL test image | `postgres:19.0`, index digest `sha256:bb6e70add742cd868fb62cb3b2f67d1dd2bdd2b65a521e778420748753687c60`, the oldest PostgreSQL FerroSMART runs on (the server refuses an older one at start), the service of CI's `nextest (core and axum)` job that FerroSMART's store cases reach through `FERROSMART_TEST_PG_URL`, and the database of the FerroSMART quickstart | `.github/workflows/ci.yml`, `compose.yaml` |
| Redis test image | `redis:8.2.3-alpine@sha256:08ad0b1d280850169a790dba1393ff7a90aef951fc19632cf4d3ce4f78e679ba`, the queue of the Inferno test kit's web and worker processes in the Inferno lane (#520) | read from this row by `scripts/inferno/lane.sh` |
| FerroEHR resource server image | `ghcr.io/ferrohealth/ferroehr:5.7.0@sha256:44c9268cb8a154df118a10ffe84329633f22923ea2cc54261ff0cea57a2ee7e7`, the FerroHEALTH/FerroEHR release that is the CDR behind FerroBRIDGE in the Inferno lane (#520), holding the PERSON the facade serves as the person's Practitioner | read from this row by `scripts/inferno/lane.sh`, `app/ferrosmart/inferno/ferroehr.toml` |
| FerroBRIDGE FHIR server image | `ghcr.io/ferrohealth/ferrobridge:0.0.28@sha256:7bae02e93c9be9e5752b492799908e758b9c0593c75b045ba8b36554891807ee`, the FerroHEALTH/FerroBRIDGE release whose FHIR R4 facade is the `url` the Inferno lane gives the kit (#520): its SMART document describes FerroSMART and it serves the person's Practitioner | read from this row by `scripts/inferno/lane.sh`, `app/ferrosmart/inferno/ferrobridge.toml` |
| Inferno runtime | `ruby:3.3.6-bookworm@sha256:347edd0c70ee08d87de9f01b99de2f14a64cedb5d1bfb38457dfe8cd0bf113c5`, the Ruby of the kit's own `.ruby-version` at the commit the test kit row pins, running the gems its `Gemfile.lock` locks (`inferno_core` 1.4.3, `tls_test_kit` 1.0.2) | read from this row by `scripts/inferno/lane.sh` |
| HAPI FHIR server image | `hapiproject/hapi:v8.12.0-2@sha256:0ff86aac4c7bd13a1ee226444a70263bb46ed1c28ef543c30a44f865b80ca04e`, the HAPI FHIR JPA server starter (Apache-2.0), run unmodified as the FHIR server that is no FerroHEALTH product in the third-party lane (#598) | read from this row by `scripts/idp/third-party-fhir.sh` |
| Envoy token validator image | `envoyproxy/envoy:distroless-v1.40.2@sha256:09ca6f2140a61ad8df11779a4a30d52b48433d444466328494f9188c9c35eded`, Envoy (Apache-2.0), run unmodified with its JWT authentication filter as the token validator in front of that server (#598) | read from this row by `scripts/idp/third-party-fhir.sh`, configured by `app/ferrosmart/third-party/envoy.yaml` |
| APISIX introspecting gateway image | `apache/apisix:3.20.0-debian@sha256:013de62a9dfba7d8e6006b3e85b524c28c9f1c3549fca3b91d5b258b0b9e759a`, Apache APISIX (Apache-2.0), run unmodified in standalone mode with its `openid-connect` plugin as the gateway that introspects every token at FerroSMART by HTTP Basic in front of that server (#639) | read from this row by `scripts/idp/third-party-fhir.sh`, configured by `app/ferrosmart/third-party/apisix-config.yaml` and `app/ferrosmart/third-party/apisix.yaml` |
| OpenID Foundation conformance suite image | `registry.gitlab.com/openid/conformance-suite:release-v5.3.4@sha256:dcc4bd1fb7e9c00f048a67373fe2bec5ecf9feb45a6b5d55e237e5c30e5312c6`, the suite's published server image (MIT) at the release the runner row pins, run unmodified in the conformance lane (#621) | read from this row by `scripts/oidf/lane.sh` |
| OpenID Foundation conformance suite TLS front image | `registry.gitlab.com/openid/conformance-suite/nginx:release-v5.3.4@sha256:9a7850826fcc8690cd43373528f50e9551ba33bf8e4a40b67b13267b0aca3675`, the suite's published nginx image of the same release, run unmodified in front of the suite with the certificate the lane makes (#621) | read from this row by `scripts/oidf/lane.sh` |
| MongoDB test image | `mongo:6.0.13@sha256:b415b12f638e2685d06c58ab7fb5943577c50fadec6d9340ef67d21aeac72070`, the MongoDB the suite's own `docker-compose-prebuilt.yml` names at that release, the suite's database in the conformance lane (#621) | read from this row by `scripts/oidf/lane.sh` |
| OpenID Foundation conformance suite runner packages | `httpx` 0.28.1 and `pyparsing` 3.3.3, the two packages the runner's `scripts/requirements.txt` names, with `anyio` 4.16.0, `certifi` 2026.10.23, `h11` 0.16.0, `httpcore` 1.0.9, `idna` 3.20 and `typing_extensions` 4.16.0, which they depend on, each locked to the sha256 of its wheel | `app/ferrosmart/oidf/requirements.txt`, installed by `.github/workflows/ci.yml` |
| FerroSMART image base | `gcr.io/distroless/static-debian13:nonroot`, index digest `sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5`, bumped by Dependabot | `docker/ferrosmart/Dockerfile` |
| Trivy | 0.73.0 (the Linux x86_64 release tarball, checked by the sha256 `scripts/release/install-trivy.sh` pins) | `.github/workflows/release-ferrosmart.yml`, `.github/workflows/release-ferrosmart-scan.yml`, `.github/workflows/image-scan.yml`, `scripts/release/install-trivy.sh` |
| cloudflared | 2026.10.7 (the Linux x86_64 release binary, checked by the sha256 `scripts/oidf/install-cloudflared.sh` pins), the quick tunnel through which the OpenID Foundation's hosted suite reaches FerroSMART | `.github/workflows/oidf-verifier.yml` |
| syft | 1.51.1, installed through `taiki-e/install-action` | `.github/workflows/release-ferrosmart-build.yml`, `.github/workflows/release-ferrosmart-image.yml` |
| cargo-auditable | 0.7.5, installed through `taiki-e/install-action` | `.github/workflows/release-ferrosmart-build.yml` |
| cargo-cyclonedx | 0.5.9, installed through `taiki-e/install-action` | `.github/workflows/release-ferrosmart-build.yml` |
| ZITADEL image | `ghcr.io/zitadel/zitadel:v4.20.3@sha256:1b30fea7ed88826dc0a98dacee4e2f2c8b05201fd26f5e4cb5386615b29f7638`, the release the ZITADEL documentation pin names and FerroHEALTH/FerroEHR runs, run unmodified (AGPL-3.0-only) by FerroSMART's ZITADEL example and its CI launch (#523) | `compose.zitadel.yaml`, `scripts/idp/zitadel-launch.sh` (read from this row) |
| ZITADEL Login image | `ghcr.io/zitadel/zitadel-login:v4.20.3@sha256:8f730428dfd65cd8979d07ef4e34a59d44978e956692b7dbbc3bba4e4abb4f92`, ZITADEL's Login v2 UI at the same release (MIT), for a person signing in through the example (#523) | `compose.zitadel.yaml` |
| curl image | `curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777`, the image FerroHEALTH/FerroEHR pins, which runs the ZITADEL example's bootstrap once (#523) | `compose.zitadel.yaml` |
| Rust build image | `rust:1.99.1-trixie@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07`, the pinned toolchain, which builds and runs the ZITADEL example's Actions v2 target from the checkout (#523) | `compose.zitadel.yaml` |
| GitHub Actions | every `uses:` pinned to a full commit SHA with its version in a trailing comment, bumped by Dependabot | `.github/workflows/*.yml`, `.github/actions/setup-rust/action.yml` |
