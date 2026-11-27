<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Post-quantum inventory

This page lists every cryptographic use in FerroSMART, its crates and its
release workflows, the algorithm each uses, and whether it resists a
cryptographically relevant quantum computer. The machine-readable copy is
`conformance/post-quantum.tsv`: after its `#` comment lines, a header and
one row per use with five tab-separated columns: `use`, `algorithm`,
`safe` (`yes` or `no`), `pq_standard` (the standard that defines the
post-quantum form, `no standard yet`, or, for a use whose algorithm another
party fixes, whose choice it is and the text that fixes it) and `location`. Every change that
adds, removes or changes a cryptographic use updates the file in the same
pull request, and `scripts/checks/conformance.sh` rewrites the table below
and the README badge from it through the family's shared badge helper. CI
fails when the table, the badge or a file a location names disagrees with
the tree.

## The sources

- **NIST IR 8547 (final):** ECDSA, EdDSA and RSA signatures (§4.1.1) and
  ECDH, DH and RSA key establishment (§4.1.2) are deprecated after 2030 and
  disallowed after 2035. Symmetric primitives with at least 128 bits of
  classical security, AES-128 and up, SHA-256 and HMAC-SHA-256 among them,
  stay (§4.1.3). FIPS 203, 204 and 205 define ML-KEM, ML-DSA and SLH-DSA.
- **The EU coordinated implementation roadmap (NIS Cooperation Group,
  v1.1):** a use case is high-risk when its confidentiality must hold for
  10 years or more, which health data needs, and high-risk use cases
  complete the transition by 31.12.2030 (§4.2). After 2030 they use no
  quantum-vulnerable public-key mechanism stand-alone, and standardised
  hybrid solutions are recommended (§4.1).
- **RFC 10024:** the TLS 1.3 hybrid group X25519MLKEM768 (codepoint
  0x11EC), within the hybrid design of RFC 9954.
- **RFC 9964:** ML-DSA for JOSE and COSE. **RFC 9881:** ML-DSA in X.509.

A row is `safe` when every key it depends on is established or verified by
a post-quantum or hybrid mechanism, or when it is a symmetric primitive at
128 bits or more. A row whose post-quantum form has no standard yet counts
as not safe, and the badge counts the safe rows of all rows.

## What FerroSMART does

The listener comes from `ferrohealth-server` 0.12.4, which offers
X25519MLKEM768 first in the TLS 1.3 key exchange, then X25519, P-256 and
P-384 for a peer that lacks the hybrid group. It enables rustls's
`prefer-post-quantum` feature, so every other rustls user in FerroSMART
takes the same order from the default provider: the clients FerroSMART
builds itself, the clients built through `ferrohealth-smart`, and the
PostgreSQL connection of `sqlx`. Tests (`app/ferrosmart/tests/it/post_quantum.rs`)
show the listener and each of those clients agreeing on X25519MLKEM768 with
a peer that offers it, and on X25519 with a peer that offers only that.

FerroSMART signs an access token with ML-DSA-65 when its resource server's
`access_token_signing_alg` names it, and an ID Token when the client's
registration does. It accepts client assertions, signed launches and DPoP
proofs signed with ML-DSA by an `AKP` key, signs its own Backend Services
assertions with ML-DSA-65 by default (`ferrosmart key generate` writes the
key), and
signs an upstream client assertion with ML-DSA when the provider lists it
(RFC 9964). RS256 stays beside
it, since RFC 9068 §2.1 has an authorization server support it, and RS384
and ES384 stay for client assertions, which SMART App Launch 2.2.0
requires. The certificate signatures that authenticate a TLS peer, the
SAML and OpenID4VP mechanisms and the release signatures stay classical
until their post-quantum forms are standardised or the parties FerroSMART
works with move.

## The uses FerroSMART does not choose

Five unsafe rows keep their algorithm because a specification or another
party fixes it, and the row's `pq_standard` names whose choice it is:

- **TLS 1.2 key exchange.** The eHDSI trust model requires "at least TLS
  1.2" (eHDSI Cryptographic Algorithms 9.0.0 §3), so `min_version` can
  lower the minimum for a MyHealth@EU peer, and RFC 10024 defines its
  hybrid key agreement for TLS 1.3 alone. TLS 1.3 stays the default.
- **Client assertions by an RSA or EC key.** SMART App Launch 2.2.0,
  Client Authentication: Asymmetric, has every client support RS384 and
  ES384 and the server validate at least one of them. FerroSMART keeps
  both and serves a client with an `AKP` key by ML-DSA (RFC 9964).
- **Upstream ID tokens.** The provider signs with the algorithm the
  registration names, RS256 by default (OpenID Connect Core 1.0 §3.1.3.7
  items 6 and 7). FerroSMART verifies ML-DSA once a provider signs it.
- **crates.io publishing.** GitHub issues the Trusted Publishing token,
  signed RS256 (GitHub Actions documentation, OpenID Connect,
  Understanding the OIDC token).
- **Release attestations.** Sigstore's signer makes an ephemeral ECDSA
  P-256 key for each attestation (`sigstore-js`,
  `packages/sign/src/signer/fulcio/ephemeral.ts`).

The TLS certificate authentication row belongs to `ferrohealth-server`
(FerroHEALTH/FerroSYS#449).

## The inventory

<!-- post-quantum table -->
| Use | Algorithm | Safe | Post-quantum standard | Location |
|---|---|---|---|---|
| TLS 1.3 key exchange of the listener | X25519MLKEM768 first; X25519, P-256, P-384 for a peer without it | yes | RFC 10024 | `ferrohealth-server tls, app/ferrosmart/src/command.rs, app/ferrosmart/tests/it/post_quantum.rs` |
| TLS 1.3 key exchange of the clients FerroSMART builds: client JWK Sets, the FHIR server, the wallet's trusted list, the upstream OpenID Providers, the SAML artifact resolution and the audit feed | X25519MLKEM768 first (rustls prefer-post-quantum); X25519, P-256, P-384 for a peer without it | yes | RFC 10024 | `app/ferrosmart/src/server.rs, app/ferrosmart/src/upstream/wallet.rs, app/ferrosmart/src/upstream/mod.rs, app/ferrosmart/src/upstream/saml.rs, app/ferrosmart/src/config/settings.rs, app/ferrosmart/tests/it/post_quantum.rs` |
| TLS 1.3 key exchange of the PostgreSQL connection | X25519MLKEM768 first (rustls prefer-post-quantum) | yes | RFC 10024 | `Cargo.toml (sqlx tls-rustls-aws-lc-rs), app/ferrosmart/tests/it/post_quantum.rs` |
| TLS 1.2 key exchange where min_version lowers the minimum | ECDHE over X25519, P-256 or P-384 | no | the eHDSI trust model's: Cryptographic Algorithms 9.0.0 §3 requires at least TLS 1.2, and RFC 10024 defines the hybrid groups for TLS 1.3 alone | `ferrohealth-server tls (protocol_versions)` |
| TLS server and client certificate authentication | ECDSA, RSA or Ed25519, as the operator's certificates hold | no | no standard yet | `ferrohealth-server tls, ferrohealth-server tls_client` |
| TLS record protection | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 | yes | NIST IR 8547 4.1.3 | `ferrohealth-server tls` |
| Access tokens for a resource server set to ML-DSA-65, and their key in the JWK Set | ML-DSA-65 | yes | RFC 9964 | `app/ferrosmart/src/config/settings.rs, app/ferrosmart/src/token/mint.rs` |
| ID tokens of a client registered for ML-DSA-65 | ML-DSA-65 | yes | RFC 9964 | `app/ferrosmart/src/signing.rs, app/ferrosmart/src/token/mint.rs` |
| Access tokens for every other resource server, and their keys in the JWK Set | RS256 | no | the deployment's: the resource server's access_token_signing_alg, RS256 by default, which RFC 9068 §2.1 has every resource server verify | `app/ferrosmart/src/config/settings.rs, app/ferrosmart/src/token/mint.rs` |
| ID tokens of every other client | RS256 | no | the client's: its id_token_signed_response_alg, RS256 by default (OpenID Connect Dynamic Client Registration 1.0 §2) | `app/ferrosmart/src/signing.rs, app/ferrosmart/src/token/mint.rs` |
| Client assertions and signed launches FerroSMART accepts by an AKP key | ML-DSA-44, ML-DSA-65, ML-DSA-87 | yes | RFC 9964 | `app/ferrosmart/src/token/assertion.rs, app/ferrosmart/src/launch/signed.rs` |
| Client assertions and signed launches FerroSMART accepts by an RSA or EC key | RS384, ES384 | no | SMART App Launch 2.2.0's: Client Authentication: Asymmetric has the server validate RS384 or ES384, which every client supports; RFC 9964 serves a client with an AKP key | `app/ferrosmart/src/token/assertion.rs, app/ferrosmart/src/launch/signed.rs` |
| DPoP proof verification by an AKP key | ML-DSA-44, ML-DSA-65, ML-DSA-87 | yes | RFC 9964 | `app/ferrosmart/src/token/sender.rs, app/ferrosmart/src/userinfo.rs, crates/ferrohealth-smart/src/sender/proof.rs` |
| DPoP proof verification by an RSA or EC key | RS256, RS384, PS256, PS384, ES256, ES384 | no | the client's: it signs with its own key (RFC 9449 §4.2) | `app/ferrosmart/src/token/sender.rs, app/ferrosmart/src/userinfo.rs, crates/ferrohealth-smart/src/sender/proof.rs` |
| Backend Services assertions FerroSMART signs with an ML-DSA key | ML-DSA-44, ML-DSA-65 or ML-DSA-87 | yes | RFC 9964 | `app/ferrosmart/src/config/settings.rs` |
| Backend Services assertions FerroSMART signs with an RSA or EC key | ES384 or RS384 | no | the deployment's: [ferrosmart.backend] algorithm set to ES384 or RS384 in place of the default ML-DSA-65 | `app/ferrosmart/src/config/settings.rs` |
| Upstream OpenID Provider client assertions by an ML-DSA key the provider lists | ML-DSA-44, ML-DSA-65 or ML-DSA-87 | yes | RFC 9964 | `app/ferrosmart/src/upstream/mod.rs, app/ferrosmart/src/config/settings.rs` |
| Upstream OpenID Provider client assertions by an RSA or EC key | RS256 by default, as the provider's registration names | no | the provider's: the algorithm its registration names, held to its token_endpoint_auth_signing_alg_values_supported (RFC 8414 §2) | `app/ferrosmart/src/upstream/mod.rs` |
| Upstream ID token verification | RS256 to PS512, ES256, ES384, EdDSA | no | the upstream provider's: OpenID Connect Core 1.0 §3.1.3.7 items 6 and 7, the alg it signs with, RS256 by default; RFC 9964 once it signs ML-DSA | `crates/ferrohealth-smart/src/oidc.rs` |
| SAML assertion and metadata signatures (XML Signature) | RSA, ECDSA P-256, ECDSA P-384 | no | no standard yet | `app/ferrosmart/src/saml/keys.rs, app/ferrosmart/src/saml/dsig.rs, crates/ferrohealth-smart/src/federation/assertion/dsig.rs` |
| SAML encrypted assertion key transport (XML Encryption) | RSA-OAEP | no | no standard yet | `app/ferrosmart/src/saml/xenc.rs` |
| SAML encrypted assertion content | AES-128-GCM, AES-256-GCM, AES-CBC under a verified signature | yes | NIST IR 8547 4.1.3 | `app/ferrosmart/src/saml/xenc.rs` |
| OpenID4VP response encryption key agreement | ECDH-ES over P-256 | no | no standard yet | `app/ferrosmart/src/wallet/jwe.rs` |
| OpenID4VP response content encryption | A128GCM, A256GCM | yes | NIST IR 8547 4.1.3 | `app/ferrosmart/src/wallet/jwe.rs` |
| OpenID4VP request objects FerroSMART signs | ES256 | no | RFC 9964 | `app/ferrosmart/src/wallet/request.rs` |
| SD-JWT VC and key binding verification | ES256 | no | RFC 9964 | `app/ferrosmart/src/wallet/mod.rs, app/ferrosmart/src/wallet/sdjwt.rs` |
| mdoc and status list COSE signature verification | ES256 | no | RFC 9964 | `app/ferrosmart/src/wallet/cose.rs, app/ferrosmart/src/wallet/status.rs` |
| Trusted list (LoTE) signature verification | ES256, ES384, RS256 to PS512 | no | RFC 9964 | `app/ferrosmart/src/wallet/lote.rs` |
| Client secret and Basic password hashing | Argon2id | yes | NIST IR 8547 4.1.3 | `app/ferrosmart/src/clients.rs, crates/ferrohealth-smart/src/basic.rs` |
| Basic credential cache key | HMAC-SHA-256 | yes | NIST IR 8547 4.1.3 | `crates/ferrohealth-smart/src/basic/cache.rs` |
| crates.io publishing | Trusted Publishing (OIDC token from GitHub, RS256) | no | GitHub's: its OIDC token is RS256 (GitHub Actions, OpenID Connect, Understanding the OIDC token) | `.github/workflows/release.yml, .github/workflows/publish-crates.yml` |
| Release provenance and SBOM attestations | Sigstore attestation (ECDSA P-256) | no | Sigstore's: its signer makes an ephemeral ECDSA P-256 key (sigstore-js, packages/sign/src/signer/fulcio/ephemeral.ts) | `.github/workflows/release-crate.yml, .github/workflows/release-ferrosmart-build.yml, .github/workflows/release-ferrosmart-image.yml` |
<!-- end of the post-quantum table -->
