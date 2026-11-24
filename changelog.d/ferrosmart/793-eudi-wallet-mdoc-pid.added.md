- The EUDI Wallet verifier accepts the PID as an ISO mdoc (`mso_mdoc`)
  beside the SD-JWT VC, over the redirect and the Digital Credentials API.
  The request offers both formats as one choice, and the wallet presents
  one. FerroSMART checks the issuer's signature under the same anchors and
  list of PID providers, each element's digest, the validity, the device
  signature over the OpenID4VP session transcript and, when the MSO names
  one, the Token Status List or identifier list in CWT format, with the
  same refusal reasons as the SD-JWT VC. The new keys of
  `[ferrosmart.upstream.openid4vp]` are `credential_formats` (both by
  default), `doctype` and `mdoc_claims`. The same person gets the same
  `sub` whichever format the wallet presents.
