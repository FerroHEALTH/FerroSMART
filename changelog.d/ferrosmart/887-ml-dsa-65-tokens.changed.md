- Breaking: the `signing_key` and `client` tables of the baseline schema
  gain the `algorithm` and `id_token_signed_response_alg` columns, and a
  token key that is neither RSA nor ML-DSA-65 is refused at start, as is a
  pool without an RSA key. Requires `ferrohealth-smart` 0.35.
