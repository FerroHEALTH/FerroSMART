- Pushed authorization requests (RFC 9126): `POST {issuer}/par` takes an
  authenticated client's authorization request and answers a one-time
  `request_uri` that `/authorize` takes in its place. The metadata names
  `pushed_authorization_request_endpoint` and
  `require_pushed_authorization_requests`, which `[ferrosmart]
  require_pushed_authorization_requests` sets, and a client's own
  `require_pushed_authorization_requests` holds it to PAR.
