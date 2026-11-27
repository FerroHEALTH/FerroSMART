- `[ferrosmart.backend] algorithm` defaults to `ML-DSA-65` (RFC 9964), which
  FerroSMART's own token endpoint takes; a deployment that keeps a P-384 or
  RSA backend key sets `algorithm = "ES384"` or `"RS384"`.
