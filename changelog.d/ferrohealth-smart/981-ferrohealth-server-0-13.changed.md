- Breaking: the `server-tls` feature requires `ferrohealth-server` 0.13 in
  place of 0.12, whose TLS 1.3 listener and clients present and verify
  ML-DSA certificates and whose revocation check verifies CRLs and OCSP
  answers an ML-DSA key signs (RFC 9881).
