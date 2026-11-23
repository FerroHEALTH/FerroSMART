- Sender-constrained tokens at issuance: a token request with a `DPoP` proof
  gets a `DPoP` token whose `cnf.jkt` names the proof's key (RFC 9449), and a
  client registered with `tls_client_certificate_bound_access_tokens` gets a
  token whose `cnf` carries its client certificate's `x5t#S256` (RFC 8705).
  A public client's refresh token is bound to its `DPoP` key, a client
  registered with `dpop_bound_access_tokens` must send a proof, introspection
  answers the token's `cnf`, and the metadata names
  `dpop_signing_alg_values_supported` and
  `tls_client_certificate_bound_access_tokens`.
