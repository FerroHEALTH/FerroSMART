- `client::outbound::OutboundClient` holds the TLS it was built from for its
  lifetime, so under `trust_roots_file` its endpoint stays cleared for
  revocation after `build` returns, and `send` clears the URL it calls before
  it connects. Every outbound client whose `tls` named `trust_roots_file`
  failed closed once its clearing ended.
