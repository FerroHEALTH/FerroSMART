<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the OpenID for Verifiable Credentials texts the wallet verifier cites

Vendored by `scripts/vendor/openid4vc.sh`, each artefact pinned by its
URL and the sha256 of its bytes. Never edit a file here: change the pins in
the script and the pin-set digest in docs/VERSIONS.md, and re-run the script.

- Pin-set digest (sha256 over the sorted `mode  file  url  sha256` lines of
  the pins): `04f0423f15693ef4865f6714f12e2941b6d56b563c1f68a0846b4acc2b35983a`
- Fetched: 2026-11-23, with the User-Agent `ferrohealth-smart-vendor (scripts/vendor)`
- Artefacts: 5 committed, 0 cache only, 0 needing
  manual retrieval
- Files in this directory: 5 besides this one, each verbatim as the
  publisher serves it
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `db02837b7948ebe12a6e4d1d2c478d9c502145c6b2ac02d3c70a3507d64ada96`
- Read by: the EUDI wallet verifier (#689)

OpenID4VC High Assurance Interoperability Profile 1.0 and OpenID for
Verifiable Presentations 1.0, Final Specifications of the OpenID
Foundation's Digital Credentials Protocols working group, and the IETF
Internet-Drafts SD-JWT VC and Token Status List at the revisions HAIP 1.0
and Implementing Regulation (EU) 2026/1731 name.

## Artefacts

### `openid4vc-high-assurance-interoperability-profile-1_0-final.html` (committed)

- Source: <https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html>
- Version: OpenID4VC High Assurance Interoperability Profile 1.0, Final, 24 December 2025
- sha256: `3996e0479d06b72d6d68668b8ae3cd39fddfc29ae9220c0c3fead7dc060ec4fb`
- Licence: The specification's Notices: "Copyright (c) 2025 The OpenID Foundation. The OpenID Foundation (OIDF) grants to any Contributor, developer, implementer, or other interested party a non-exclusive, royalty free, worldwide copyright license to reproduce, prepare derivative works from, distribute, perform and display, this Implementers Draft, Final Specification, or Final Specification Incorporating Errata Corrections solely for the purposes of (i) developing specifications, and (ii) implementing Implementers Drafts, Final Specifications, and Final Specification Incorporating Errata Corrections based on such documents, provided that attribution be made to the OIDF as the source of the material"
- Note: The profile of OpenID4VP the wallet verifier implements: §5 (signed requests with the x509_hash prefix, DCQL, direct_post.jwt), §5.1 (redirects), §5.2 (the W3C Digital Credentials API), §6.1 (SD-JWT VC), §7 and §8.

### `openid-4-verifiable-presentations-1_0-final.html` (committed)

- Source: <https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html>
- Version: OpenID for Verifiable Presentations 1.0, Final
- sha256: `08e635ea3563b192309c627382c281c81de176e94cdb5ffb11b13ac624f7e12e`
- Licence: The specification's Notices: "Copyright (c) 2025 The OpenID Foundation. The OpenID Foundation (OIDF) grants to any Contributor, developer, implementer, or other interested party a non-exclusive, royalty free, worldwide copyright license to reproduce, prepare derivative works from, distribute, perform and display, this Implementers Draft, Final Specification, or Final Specification Incorporating Errata Corrections solely for the purposes of (i) developing specifications, and (ii) implementing Implementers Drafts, Final Specifications, and Final Specification Incorporating Errata Corrections based on such documents, provided that attribution be made to the OIDF as the source of the material"
- Note: The presentation protocol HAIP profiles: the request object, DCQL, response encryption, the Digital Credentials API appendix and the credential format appendices.

### `draft-ietf-oauth-sd-jwt-vc-13.txt` (committed)

- Source: <https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-13.txt>
- Version: draft-ietf-oauth-sd-jwt-vc-13, 6 November 2025
- sha256: `c1cb38fde3c41f32a7915bebbff2c76b121da9712a07ecb2a25a9802e428b38d`
- Licence: An Internet-Draft, "Copyright (c) <year> IETF Trust and the persons identified as the document authors. All rights reserved.", subject to BCP 78 and the IETF Trust Legal Provisions Relating to IETF Documents (https://trustee.ietf.org/license-info), which allow it to be copied and distributed unmodified
- Note: SD-JWT-based Verifiable Credentials, the revision HAIP 1.0 §9.4 pins; the PID format dc+sd-jwt.

### `draft-ietf-oauth-status-list-14.txt` (committed)

- Source: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-14.txt>
- Version: draft-ietf-oauth-status-list-14, 10 December 2025
- sha256: `7f47502ad2f076879a06880a4e1f864991ae1bfc21f86f6ffa1d73cd4a930352`
- Licence: An Internet-Draft, "Copyright (c) <year> IETF Trust and the persons identified as the document authors. All rights reserved.", subject to BCP 78 and the IETF Trust Legal Provisions Relating to IETF Documents (https://trustee.ietf.org/license-info), which allow it to be copied and distributed unmodified
- Note: Token Status List, the revision HAIP 1.0 §9.4 pins.

### `draft-ietf-oauth-status-list-20.txt` (committed)

- Source: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-20.txt>
- Version: draft-ietf-oauth-status-list-20, 20 April 2026
- sha256: `bf4ef5827af4374b83db8df538489d21023bfd2953a938fbd8e5a6c807d94369`
- Licence: An Internet-Draft, "Copyright (c) <year> IETF Trust and the persons identified as the document authors. All rights reserved.", subject to BCP 78 and the IETF Trust Legal Provisions Relating to IETF Documents (https://trustee.ietf.org/license-info), which allow it to be copied and distributed unmodified
- Note: Token Status List, the revision Implementing Regulation (EU) 2026/1731 names for the status of an attestation.
