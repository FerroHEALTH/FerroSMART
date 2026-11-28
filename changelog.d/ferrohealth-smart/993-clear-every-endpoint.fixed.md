- Under `trust_roots_file`, every call the crate sends clears its endpoint for
  revocation before it connects, so a `jwks_uri`, an introspection endpoint or
  a token endpoint on another host under the same root connects as the issuer
  does, whether the configuration or the issuer's metadata names it. The
  endpoints handed to `config::ServerTls` are still cleared at once, and a
  first call waits for their first round. `client::PresentedTls` carries the
  new `client::Clearance` seam (`with_clearance`, `clear`).
