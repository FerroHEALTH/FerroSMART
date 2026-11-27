- A client's `id_token_signed_response_alg` chooses the algorithm of its
  ID Tokens alone; its access tokens follow the resource server's
  `access_token_signing_alg`. A client registered for `ML-DSA-65` gets
  `RS256` access tokens for a resource server that names none.
- An upstream `private_key_jwt` entry whose algorithm the provider's
  `token_endpoint_auth_signing_alg_values_supported` leaves out is refused
  at start (RFC 8414 §2).
