- `client::dpop::DpopKey::from_pem` reads an ML-DSA-44, ML-DSA-65 or
  ML-DSA-87 private key (RFC 9881 §6) beside the P-256 and P-384 keys, and
  signs its proofs with that parameter set, the `AKP` public key in the
  header `jwk` (RFC 9964, RFC 9449 §4.2).
