- `[[ferrosmart.resource]] access_token_signing_alg`: the access tokens for
  a resource server are signed with the algorithm it verifies, `RS256` by
  default and `ML-DSA-65` for one on `ferrohealth-smart` (RFC 9964); a
  value no key of `[ferrosmart.keys]` signs is refused at start.
- `DPoP` proofs signed with ML-DSA-44, ML-DSA-65 or ML-DSA-87 by their
  `AKP` key are accepted and listed in `dpop_signing_alg_values_supported`
  (RFC 9449 §5.1).
- `[ferrosmart.backend] algorithm` takes `ML-DSA-44`, `ML-DSA-65` and
  `ML-DSA-87`, which FerroSMART's own token endpoint lists.
