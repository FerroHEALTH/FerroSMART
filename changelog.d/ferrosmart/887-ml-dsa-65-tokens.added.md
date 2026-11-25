- ML-DSA-65 token signing keys (RFC 9964) beside the RSA ones:
  `[ferrosmart.keys]` reads ML-DSA-65 private keys (RFC 9881) beside RSA
  keys, each algorithm rotating on its own, the JWK Set publishes each as
  an `AKP` key, and discovery lists `ML-DSA-65` in
  `id_token_signing_alg_values_supported`. A client's
  `id_token_signed_response_alg`, `RS256` or `ML-DSA-65`, picks the
  algorithm of its ID Tokens and access tokens; any other value, or one no
  key signs, is refused at registration.
