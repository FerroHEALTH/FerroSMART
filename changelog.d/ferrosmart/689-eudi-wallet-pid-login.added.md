- A person can log in with the person identification data (PID) in their
  EUDI Wallet: an `[[ferrosmart.upstream]]` entry with an
  `[ferrosmart.upstream.openid4vp]` table makes FerroSMART an OpenID4VP 1.0
  verifier under HAIP 1.0 and the EU wallet profile (Implementing
  Regulation (EU) 2024/2979 Annex II as amended by 2026/1731). It sends a
  request signed under its access certificate, takes the encrypted
  answer at `{issuer}/wallet/response` and completes the login in the
  browser that began it. The PID is checked against the configured
  anchors, its key binding, the request's nonce, its expiry and, when it
  carries one, its Token Status List. Its administrative number names the
  person and feeds the `fhirUser` lookup. Each refusal is a `400` and a
  login record that names its reason.
