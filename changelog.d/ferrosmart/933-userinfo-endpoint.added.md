- The UserInfo Endpoint, `GET` and `POST {issuer}/userinfo`, listed as
  `userinfo_endpoint` in both discovery documents (OpenID Connect Core 1.0
  §5.3, Discovery 1.0 §3): an access token issued under a person's grant
  with `openid`, as `Bearer` or, when bound, under `DPoP` with its proof
  and over its certificate, answers `sub`, `fhirUser` and the standard
  claims its scope passes on, the claims of the ID Token issued with it. A
  refusal is the RFC 6750 §3 challenge.
- After an upstream login, FerroSMART asks the provider's UserInfo
  Endpoint when its metadata names one, refuses the login when the answer's
  `sub` is not the ID Token's (§5.3.2), and lets its claims complete the ID
  Token's.
