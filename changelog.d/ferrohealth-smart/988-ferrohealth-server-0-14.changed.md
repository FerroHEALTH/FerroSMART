- Breaking: the `server-tls` feature requires `ferrohealth-server` 0.14 and
  `ferrohealth-config` 0.5, which verify an outbound chain by its root: a
  chain to a root of `trust_roots_file` opens a connection only once a
  revocation check cleared its endpoint, failing closed when no CRL or OCSP
  source answers, and a root of the new `trust_roots_without_revocation_file`
  is trusted with no check and logged. `config::TlsBuilder::build` takes the
  endpoints a connection reaches, and `config::ServerTls` keeps them cleared
  with a `revocation::Clearing` held by the `client::PresentedTls` it builds,
  which names the unchecked roots in `PresentedTls::unchecked_roots`; a
  product's own builder takes the new `endpoints` parameter.
