<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the ETSI specifications the wallet verifier reads

Vendored by `scripts/vendor/etsi-eudi.sh`, each artefact pinned by its
URL and the sha256 of its bytes. Never edit a file here: change the pins in
the script and the pin-set digest in docs/VERSIONS.md, and re-run the script.

- Pin-set digest (sha256 over the sorted `mode  file  url  sha256` lines of
  the pins): `5f512fb7e31aaa42f110dc15cd1ef8137a263b4de9fc1e182f7c82bf7845c25e`
- Fetched: 2026-11-23, from the owner's local copies; nothing is downloaded
- Artefacts: 0 committed, 0 cache only, 0 needing
  manual retrieval, 2 read and not redistributed
- Files in this directory: 0 besides this one, each verbatim as the
  owner supplied it
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- Read by: the EUDI wallet verifier (#689)

ETSI TS 119 472-2 V1.2.1 and ETSI TS 119 475 V1.2.1, the presentation
profiles and the relying party certificate profile that Implementing
Regulation (EU) 2026/1731 Annex XII makes the technical specifications of
the European Digital Identity Wallet's presentations.

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
