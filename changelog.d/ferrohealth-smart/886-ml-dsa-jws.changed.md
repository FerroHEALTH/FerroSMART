- Breaking: every signature algorithm is
  `jws::algorithm::Algorithm` (`Rs256` to `MlDsa87`) in place of
  `jsonwebtoken::Algorithm`, in `Settings::algorithms`, the `[auth]`
  tables, `ProofSettings`, `RelyingParty::with_algorithms`,
  `AssertionKey` and `DpopKey`; `DpopKey::public_jwk` returns a
  `jws::jwk::Jwk`, and the errors that carried a `jsonwebtoken` error
  carry the `jws` one. A symmetric algorithm or `none` has no value, so a
  configuration that names one fails to parse. The crate no longer
  depends on `jsonwebtoken`. A product moves its `Algorithm` imports to
  `ferrohealth_smart::jws::algorithm::Algorithm`.
