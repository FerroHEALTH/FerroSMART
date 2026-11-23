- Clients are registered and managed through RFC 7591 and RFC 7592:
  `POST {issuer}/register`, named `registration_endpoint` in the metadata,
  with an administrator's token as the initial access token, and `GET`,
  `PUT` and `DELETE {issuer}/register/{client_id}`. With
  `[ferrosmart.registration] open = true` an app registers itself, held to
  that section's `scope`, and manages itself with the registration access
  token its registration answered. Breaking: `POST /admin/clients`, `GET`
  and `PUT /admin/clients/{client_id}` are gone; `/admin/clients` keeps the
  list, disable and enable. A registration that omits
  `token_endpoint_auth_method` is `client_secret_basic`, and one that omits
  `grant_types` is `authorization_code` (RFC 7591 §2).
