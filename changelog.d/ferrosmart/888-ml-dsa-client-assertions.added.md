- The token endpoint accepts `private_key_jwt` client assertions, and the
  launch registration accepts signed launches, signed with ML-DSA-44,
  ML-DSA-65 or ML-DSA-87 (RFC 9964) by an `AKP` key of the client's
  registered JWK Set, beside RS384 and ES384; a key verifies only its own
  algorithm, so an assertion whose `alg` disagrees with the key is refused.
  `token_endpoint_auth_signing_alg_values_supported` and the introspection
  and revocation lists name the three ML-DSA algorithms.
