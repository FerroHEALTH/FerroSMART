- FerroSMART builds on `ferrohealth-server` 0.13: its TLS 1.3 listener and
  clients present and verify ML-DSA certificates, and the revocation check
  verifies CRLs and OCSP answers an ML-DSA key signs (RFC 9881).
