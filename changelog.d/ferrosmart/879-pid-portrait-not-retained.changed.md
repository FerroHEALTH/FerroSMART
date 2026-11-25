- The EUDI Wallet login never asks for, keeps or forwards the PID portrait,
  since FerroSMART identifies the person without it (Implementing Regulation
  (EU) 2024/2977 Art 3a(3); Regulation (EU) 2016/679 Art 5(1)(c)). A
  `[ferrosmart.upstream.openid4vp]` `claims` or `mdoc_claims` naming
  `picture` or `portrait` is refused at start, an mdoc carrying the portrait
  is `unrequested_credential`, and an SD-JWT VC that discloses it unasked has
  it dropped before the login reads its claims.
