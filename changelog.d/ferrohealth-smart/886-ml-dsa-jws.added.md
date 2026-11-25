- `jws`, the one module that signs and verifies every JWS (RFC 7515) over
  `aws-lc-rs`: RS256 to PS512, ES256, ES384, `EdDSA` (RFC 8037) and
  ML-DSA-44, ML-DSA-65 and ML-DSA-87 (RFC 9964), with the `AKP` JSON Web
  Key, the JWK thumbprint of every key type and the registered claim
  checks. A key verifies only the algorithm its type, curve or parameter
  set and its `alg`, `use` and `key_ops` admit (RFC 8725 §3.1). The
  resource server, the OpenID relying party and the `DPoP` proof check
  verify an ML-DSA token when the configured algorithms name it, and an
  assertion key read from an RFC 9881 ML-DSA private key signs with its
  parameter set and publishes its `AKP` key.
