<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Signing keys and algorithms

**For:** integrators who verify FerroSMART's tokens or sign assertions to
it, and compliance readers who track where FerroSMART is safe against a
quantum computer. Rotating the keys is on [rotate keys](../operate/keys.md).

Every signature FerroSMART makes or accepts on a token is a JWS (RFC 7515)
with an asymmetric algorithm. Neither `none` nor an HMAC algorithm can be
named by any setting, header or key (RFC 8725 §3.1, §3.2): such a name
fails to parse.

## What FerroSMART signs

| What | Algorithm | Key |
|---|---|---|
| Access tokens | `RS256`, or `ML-DSA-65` for a resource server whose `access_token_signing_alg` names it | The token keys, `[ferrosmart.keys]`, published at `{issuer}/jwks` |
| ID Tokens | `RS256`, or `ML-DSA-65` for a client whose `id_token_signed_response_alg` names it | The token keys |
| Client assertions to an upstream OpenID Provider | `RS256` by default, as the provider's registration names; ML-DSA where the provider lists it | The assertion keys, published at `{issuer}/upstream-jwks` |
| Client assertions of FerroSMART's own Backend Services client | `ES384`, `RS384`, or ML-DSA-44, ML-DSA-65 or ML-DSA-87 | The backend keys |
| SAML `AuthnRequest` and `ArtifactResolve` | RSA, or ECDSA on P-256 or P-384 | `[ferrosmart.saml] signing_key_file` |
| OpenID4VP request objects | `ES256` | The wallet-relying party access key |

`RS256` signs every token by default, since RFC 9068 §2.1 and OpenID
Connect Discovery 1.0 §3 have every authorization server support it. An
access token is signed for the resource server that verifies it: set
`access_token_signing_alg = "ML-DSA-65"` on a `[[ferrosmart.resource]]`
that verifies ML-DSA (RFC 9964), as a FerroHEALTH product on
`ferrohealth-smart` does. A client that can verify ML-DSA registers
`"id_token_signed_response_alg": "ML-DSA-65"` (OpenID Connect Dynamic
Client Registration 1.0 §2) for its ID Tokens. Either needs an ML-DSA-65
key in `[ferrosmart.keys]`. One ring per algorithm signs both kinds of
token; their `typ` (`at+jwt` against `JWT`) keeps an ID Token from passing
as an access token.

## What FerroSMART accepts

| What | Algorithms |
|---|---|
| Client assertions (`private_key_jwt`) and signed EHR launches | `RS384`, `ES384`, and `ML-DSA-44`, `ML-DSA-65` or `ML-DSA-87` by an `AKP` key (RFC 9964) |
| DPoP proofs at the token endpoint | `RS256`, `RS384`, `PS256`, `PS384`, `ES256`, `ES384` |
| Upstream ID Tokens | `RS256` to `PS512`, `ES256`, `ES384`, `EdDSA` |

`RS384` and `ES384` are the two algorithms SMART App Launch 2.2.0 requires
for asymmetric client authentication (Client Authentication: Asymmetric),
and the discovery documents list every accepted assertion algorithm in
`token_endpoint_auth_signing_alg_values_supported`.

## ML-DSA and JWS

ML-DSA is the module-lattice signature of FIPS 204. RFC 9964 defines it for
JOSE: the algorithm names `ML-DSA-44`, `ML-DSA-65` and `ML-DSA-87`, and the
key type `AKP`, whose public JWK carries `alg` and `pub`. An ML-DSA key file
is PKCS#8 PEM as RFC 9881 describes it; OpenSSL 3.5 or later makes one with
`openssl genpkey -algorithm ML-DSA-65`.

A resource server that reads ML-DSA-65 tokens fetches the `AKP` key from
`{issuer}/jwks` like any other, by its RFC 7638 thumbprint as `kid`.
`ferrohealth-smart` verifies ML-DSA tokens, so every FerroHEALTH product
does.

## Where FerroSMART is post-quantum safe

NIST IR 8547 deprecates RSA and ECDSA signatures after 2030 and disallows
them after 2035, and the EU's coordinated roadmap has high-risk uses, health
data among them, complete the move by the end of 2030. Today:

- **Safe:** the TLS 1.3 key exchange of the listener and of every client
  FerroSMART builds (the hybrid X25519MLKEM768 first), ML-DSA-65 tokens,
  ML-DSA client assertions, and the symmetric primitives.
- **Classical:** `RS256` tokens of clients that did not register ML-DSA,
  `RS384` and `ES384` assertions, DPoP proofs, upstream ID Tokens, the SAML
  and wallet mechanisms, and TLS certificates. Their post-quantum forms are
  either unstandardised or depend on the other party moving.

The repository's
[post-quantum inventory](https://github.com/FerroHEALTH/FerroSMART/blob/main/docs/post-quantum.md)
lists every cryptographic use with its algorithm and location, and CI holds
it to the tree.
