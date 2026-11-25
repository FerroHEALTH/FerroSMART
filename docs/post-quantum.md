<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Post-quantum inventory

This page lists every cryptographic use in FerroSMART, its crates and its
release workflows, the algorithm each uses, and whether it resists a
cryptographically relevant quantum computer. The machine-readable copy is
`conformance/post-quantum.tsv`: after its `#` comment lines, a header and
one row per use with five tab-separated columns: `use`, `algorithm`,
`safe` (`yes` or `no`), `pq_standard` (the standard that defines the
post-quantum form, or `no standard yet`) and `location`. Every change that
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

FerroSMART signs a client's access and ID tokens with ML-DSA-65 when the
client's registration names it, and accepts client assertions and signed
launches signed with ML-DSA by an `AKP` key (RFC 9964). RS256 stays beside
it, since RFC 9068 §2.1 has an authorization server support it, and RS384
and ES384 stay for client assertions, which SMART App Launch 2.2.0
requires. The certificate signatures that authenticate a TLS peer, the
SAML and OpenID4VP mechanisms and the release signatures stay classical
until their post-quantum forms are standardised or the parties FerroSMART
works with move.

## The inventory

<!-- post-quantum table -->
| Use | Algorithm | Safe | Post-quantum standard | Location |
|---|---|---|---|---|
| TLS 1.3 key exchange of the listener | X25519MLKEM768 first; X25519, P-256, P-384 for a peer without it | yes | RFC 10024 | `ferrohealth-server tls, app/ferrosmart/src/command.rs, app/ferrosmart/tests/it/post_quantum.rs` |
| TLS 1.3 key exchange of the clients FerroSMART builds: client JWK Sets, the FHIR server, the wallet's trusted list, the upstream OpenID Providers, the SAML artifact resolution and the audit feed | X25519MLKEM768 first (rustls prefer-post-quantum); X25519, P-256, P-384 for a peer without it | yes | RFC 10024 | `app/ferrosmart/src/server.rs, app/ferrosmart/src/upstream/wallet.rs, app/ferrosmart/src/upstream/mod.rs, app/ferrosmart/src/upstream/saml.rs, app/ferrosmart/src/config/settings.rs, app/ferrosmart/tests/it/post_quantum.rs` |
| TLS 1.3 key exchange of the PostgreSQL connection | X25519MLKEM768 first (rustls prefer-post-quantum) | yes | RFC 10024 | `Cargo.toml (sqlx tls-rustls-aws-lc-rs), app/ferrosmart/tests/it/post_quantum.rs` |
| TLS 1.2 key exchange where min_version lowers the minimum | ECDHE over X25519, P-256 or P-384 | no | no standard yet | `ferrohealth-server tls (protocol_versions)` |
| TLS server and client certificate authentication | ECDSA, RSA or Ed25519, as the operator's certificates hold | no | no standard yet | `ferrohealth-server tls, ferrohealth-server tls_client` |
| TLS record protection | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 | yes | NIST IR 8547 4.1.3 | `ferrohealth-server tls` |
| Access and ID tokens of a client registered for ML-DSA-65, and their keys in the JWK Set | ML-DSA-65 | yes | RFC 9964 | `app/ferrosmart/src/signing.rs, app/ferrosmart/src/token/mint.rs` |
| Access and ID tokens of every other client, and their keys in the JWK Set | RS256 | no | RFC 9964 | `app/ferrosmart/src/signing.rs, app/ferrosmart/src/token/mint.rs` |
| Client assertions and signed launches FerroSMART accepts by an AKP key | ML-DSA-44, ML-DSA-65, ML-DSA-87 | yes | RFC 9964 | `app/ferrosmart/src/token/assertion.rs, app/ferrosmart/src/launch/signed.rs` |
| Client assertions and signed launches FerroSMART accepts by an RSA or EC key | RS384, ES384 | no | RFC 9964 | `app/ferrosmart/src/token/assertion.rs, app/ferrosmart/src/launch/signed.rs` |
| DPoP proof verification at the token endpoint | RS256, RS384, PS256, PS384, ES256, ES384 | no | RFC 9964 | `app/ferrosmart/src/token/sender.rs, crates/ferrohealth-smart/src/sender/proof.rs` |
| Backend Services assertions FerroSMART signs | ES384 or RS384 | no | RFC 9964 | `app/ferrosmart/src/config/settings.rs` |
| Upstream OpenID Provider client assertions | RS256 by default, as the provider's registration names | no | RFC 9964 | `app/ferrosmart/src/upstream/mod.rs` |
| Upstream ID token verification | RS256 to PS512, ES256, ES384, EdDSA | no | RFC 9964 | `crates/ferrohealth-smart/src/oidc.rs` |
| SAML assertion and metadata signatures (XML Signature) | RSA, ECDSA P-256, ECDSA P-384 | no | no standard yet | `app/ferrosmart/src/saml/keys.rs, app/ferrosmart/src/saml/dsig.rs, crates/ferrohealth-smart/src/federation/assertion/dsig.rs` |
| SAML encrypted assertion key transport (XML Encryption) | RSA-OAEP | no | no standard yet | `app/ferrosmart/src/saml/xenc.rs` |
| SAML encrypted assertion content | AES-128-GCM, AES-256-GCM, AES-CBC under a verified signature | yes | NIST IR 8547 4.1.3 | `app/ferrosmart/src/saml/xenc.rs` |
| OpenID4VP response encryption key agreement | ECDH-ES over P-256 | no | no standard yet | `app/ferrosmart/src/wallet/jwe.rs` |
| OpenID4VP response content encryption | A128GCM, A256GCM | yes | NIST IR 8547 4.1.3 | `app/ferrosmart/src/wallet/jwe.rs` |
| OpenID4VP request objects FerroSMART signs | ES256 | no | RFC 9964 | `app/ferrosmart/src/wallet/request.rs` |
| SD-JWT VC and key binding verification | ES256 | no | RFC 9964 | `app/ferrosmart/src/wallet/mod.rs, app/ferrosmart/src/wallet/sdjwt.rs` |
| mdoc and status list COSE signature verification | ES256 | no | RFC 9964 | `app/ferrosmart/src/wallet/cose.rs, app/ferrosmart/src/wallet/status.rs` |
| Trusted list (LoTE) signature verification | ES256, ES384, RS256 to PS512 | no | RFC 9964 | `app/ferrosmart/src/wallet/lote.rs` |
| Console session sealed cookie | AES-256-GCM | yes | NIST IR 8547 4.1.3 | `crates/ferrohealth-session/src/sessions` |
| Client secret and Basic password hashing | Argon2id | yes | NIST IR 8547 4.1.3 | `app/ferrosmart/src/clients.rs, crates/ferrohealth-smart/src/basic.rs` |
| Basic credential cache key | HMAC-SHA-256 | yes | NIST IR 8547 4.1.3 | `crates/ferrohealth-smart/src/basic/cache.rs` |
| crates.io publishing | Trusted Publishing (OIDC token from GitHub, RS256) | no | no standard yet | `.github/workflows/release.yml, .github/workflows/publish-crates.yml` |
| Release provenance and SBOM attestations | Sigstore attestation (ECDSA P-256) | no | no standard yet | `.github/workflows/release-crate.yml, .github/workflows/release-ferrosmart-build.yml, .github/workflows/release-ferrosmart-image.yml` |
<!-- end of the post-quantum table -->
