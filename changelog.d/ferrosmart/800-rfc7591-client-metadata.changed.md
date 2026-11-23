- Breaking: the client document is RFC 7591 client metadata, which the admin
  API, `ferrosmart client apply` and the store share. `kind` becomes
  `token_endpoint_auth_method` (`none`, `client_secret_basic`,
  `client_secret_post`, `private_key_jwt`), and a client authenticates only
  by the method it registered; `name` becomes `client_name`; `scopes`
  becomes the space-separated `scope`; the `token_exchange` grant is
  `urn:ietf:params:oauth:grant-type:token-exchange`; a client's
  `assurance_minimum` becomes `default_acr_values`, which a request without
  `acr_values` asks for. FerroSMART issues a symmetric client's secret,
  answers it once as `client_secret` with `client_secret_expires_at` 0 and
  keeps only its Argon2id hash: `secret_hash` and `ferrosmart client
  hash-secret` are gone, and `ferrosmart client secret <client_id>` issues
  a new secret. The `client` columns follow in the clients baseline.
