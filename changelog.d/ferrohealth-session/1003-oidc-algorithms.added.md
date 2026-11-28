- `[oidc] algorithms` lists the signature algorithms a console accepts on an
  ID Token, ML-DSA-44, ML-DSA-65 and ML-DSA-87 among them (RFC 9964 §5);
  unset, the relying party's own list applies, and an empty list is refused.
  Breaking: `OidcSection` has the new public field `algorithms`, so a console
  that builds the section with a struct literal adds it or `..Default::default()`.
