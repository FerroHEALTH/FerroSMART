- `ferrosmart key generate --out <file>` writes a fresh ML-DSA private key
  (`--algorithm` `ML-DSA-44`, `ML-DSA-65` by default, or `ML-DSA-87`) as
  PKCS#8 PEM (RFC 9881 §6) to a new file readable by its owner alone, so no
  OpenSSL with ML-DSA key generation is needed.
