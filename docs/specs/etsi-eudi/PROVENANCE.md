<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the ETSI specifications the wallet verifier reads

Vendored by `scripts/vendor/etsi-eudi.sh`, each artefact pinned by its
URL and the sha256 of its bytes. Never edit a file here: change the pins in
the script and the pin-set digest in docs/VERSIONS.md, and re-run the script.

- Pin-set digest (sha256 over the sorted `mode  file  url  sha256` lines of
  the pins): `7b97114447adbf127274e5d633f95614628a877fb6f13d695566f0e683b147c3`
- Fetched: 2026-11-23, from the owner's local copies; nothing is downloaded
- Artefacts: 0 committed, 0 cache only, 0 needing
  manual retrieval, 4 read and not redistributed
- Files in this directory: 0 besides this one, each verbatim as the
  owner supplied it
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- Read by: the EUDI wallet verifier (#689) and its list of PID providers (#794)

ETSI TS 119 472-2 V1.2.1 and ETSI TS 119 475 V1.2.1, the presentation
profiles and the relying party certificate profile that Implementing
Regulation (EU) 2026/1731 Annex XII makes the technical specifications of
the European Digital Identity Wallet's presentations, and ETSI TS 119 602
V1.1.1 with its Annex A.1 JSON schema, the model of the list of PID
providers the ARF points to; no published act names that structure yet.

ETSI permits no reproduction without its written permission, so each
document is recorded here by URL, version and sha256, and no copy of it
enters the repository or the cache. Its content is cited by clause only.

## Artefacts

### `ts_11947202v010201p.pdf` (read, not redistributed)

- Source: <https://www.etsi.org/deliver/etsi_ts/119400_119499/11947202/01.02.01_60/ts_11947202v010201p.pdf>
- Version: ETSI TS 119 472-2 V1.2.1 (2026-03), Electronic Signatures and Trust Infrastructures (ESI); Profiles for Electronic Attestation of Attributes; Part 2: Profiles for EAA/PID Presentations to Relying Party
- sha256: `128c51ed497a82ee01a709070669e53bef4f38a0da3ec8792542f659f86e3b1f`
- Licence: ETSI copyright, "No part may be reproduced or utilized in any form or by any means, electronic or mechanical, including photocopying and microfilm except as authorized by written permission of ETSI." (the document's Copyright Notification); free to download from the ETSI deliver site and read
- Not redistributed: the owner read the file and its sha256 is recorded;
  the script copies it nowhere, and this repository carries none of its
  content.
- Note: Fetched on 2026-11-23 and read for #689. Implementing Regulation (EU) 2026/1731 Annex XII applies its clauses 4.1, 4.2, 5 and 6, with the adaptations the Annex lists; the wallet verifier implements its clause 6, the OpenID4VC-HAIP profile.

### `ts_119475v010201p.pdf` (read, not redistributed)

- Source: <https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf>
- Version: ETSI TS 119 475 V1.2.1 (2026-03), Electronic Signatures and Trust Infrastructures (ESI); Relying party attributes supporting EUDI Wallet user's authorization decisions
- sha256: `77bf8e71715c495494113da23ccba89c0af8bf6b457fe2da38b5a12738ace55f`
- Licence: ETSI copyright, "No part may be reproduced or utilized in any form or by any means, electronic or mechanical, including photocopying and microfilm except as authorized by written permission of ETSI." (the document's Copyright Notification); free to download from the ETSI deliver site and read
- Not redistributed: the owner read the file and its sha256 is recorded;
  the script copies it nowhere, and this repository carries none of its
  content.
- Note: Fetched on 2026-11-23 and read for #689: the wallet-relying party access certificate whose hash is the x509_hash client identifier, and the registration certificate the request carries in verifier_info.

### `ts_119602v010101p.pdf` (read, not redistributed)

- Source: <https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf>
- Version: ETSI TS 119 602 V1.1.1 (2025-11), Electronic Signatures and Trust Infrastructures (ESI); Lists of trusted entities; Data model
- sha256: `27a00765a20661ecd04076a406b26a5be1123228a2f44a2dc74caeb3041155ec`
- Licence: ETSI copyright, "No part may be reproduced or utilized in any form or by any means, electronic or mechanical, including photocopying and microfilm except as authorized by written permission of ETSI." (the document's Copyright Notification); free to download from the ETSI deliver site and read
- Not redistributed: the owner read the file and its sha256 is recorded;
  the script copies it nowhere, and this repository carries none of its
  content.
- Note: Fetched on 2026-11-23 and read for #794: Annex D, the profile of the list of PID providers the Commission publishes under Implementing Regulation (EU) 2024/2980 Art 5(2), the JSON binding signed as a compact JAdES baseline B signature.

### `1960201_json_schema.json` (read, not redistributed)

- Source: <https://forge.etsi.org/rep/esi/x19_60201_lists_of_trusted_entities/-/raw/e84f427f0cde99513b574ef4b5a155ac4a38eab6/1960201_json_schema/1960201_json_schema.json>
- Version: The JSON binding of ETSI TS 119 602 V1.1.1 Annex A.1, the scheme-explicit LoTE schema, at commit e84f427f0cde99513b574ef4b5a155ac4a38eab6 of the ETSI forge repository
- sha256: `f16d60477359b936cefe0c74d5f1c598e3346daf84a6bad1846c712381ca36b4`
- Licence: BSD 3-Clause, "Copyright 2025 ETSI" (the repository's LICENSE); recorded by sha256 beside the document it binds
- Not redistributed: the owner read the file and its sha256 is recorded;
  the script copies it nowhere, and this repository carries none of its
  content.
- Note: The member names of the PID providers list (#794).
