- `private_key_jwt` client assertions and signed launches signed PS256,
  ES256 or `EdDSA` (FAPI 2.0 Security Profile §5.4.1; RFC 7518, RFC 8037),
  beside RS384, ES384 and ML-DSA, listed in
  `token_endpoint_auth_signing_alg_values_supported`. A client's JWK Set
  may hold an Ed25519 `OKP` key.
- `[ferrosmart.keys]` signs `ES256` with a P-256 key, `EdDSA` with an
  Ed25519 key and `PS256` with the RSA keys `ps256_private_key_files`
  names; a client's `id_token_signed_response_alg` may name each, and a
  resource server's `access_token_signing_alg` too.
