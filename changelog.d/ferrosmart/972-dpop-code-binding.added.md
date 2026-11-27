- The authorization code is bound to a DPoP key (RFC 9449 §10): by the
  `dpop_jkt` authorization request parameter, or by a DPoP header on the
  pushed authorization request, whose `dpop_jkt` must then name the same
  key. A bound code is redeemed only with a DPoP proof of that key.
