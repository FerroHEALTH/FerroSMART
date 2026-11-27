- `[auth] post_quantum_only`: on, every JWT issuer's `algorithms` and
  `[auth.dpop] algorithms` left at their default become ML-DSA-44,
  ML-DSA-65 and ML-DSA-87 (RFC 9964 §5), an explicit ML-DSA list stays, and
  a list naming any other algorithm refuses the section with
  `ConfigError::ClassicalAlgorithm`, naming its key. `jws::algorithm::ML_DSA`
  holds the three parameter sets. A product that carries its own copy of
  this rule deletes it.
