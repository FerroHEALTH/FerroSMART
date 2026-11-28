- Mutual-TLS client authentication (RFC 8705 §2): a client registers
  `tls_client_auth` with one certificate subject
  (`tls_client_auth_subject_dn`, `tls_client_auth_san_dns`,
  `tls_client_auth_san_uri`, `tls_client_auth_san_ip` or
  `tls_client_auth_san_email`), or `self_signed_tls_client_auth` with its
  certificate in its JWK Set, and the token, PAR, introspection and
  revocation endpoints authenticate it by the connection's certificate. The
  metadata lists both methods when `[server.tls]` asks for a client
  certificate.
