- `GET {issuer}/admin/upstreams` answers the state of each upstream
  provider behind the `system/admin` guard: the clients that name it, its
  OpenID Connect discovery document and key set read at once, or its SAML
  metadata as the replica last read it, each with its outcome, its error
  and its signing certificates' expiry.
