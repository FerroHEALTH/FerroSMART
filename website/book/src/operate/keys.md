<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Keys and rotation

FerroSMART holds three rings of keys, each for one purpose, so a key of one
kind signs nothing the other is trusted for (RFC 8725 §3.12):

| Ring | Configured in | Published at | Signs |
|---|---|---|---|
| The token keys | `[ferrosmart.keys]` | `{issuer}/jwks`, which every discovery document names | Access tokens and ID Tokens |
| The assertion keys | `[ferrosmart.upstream.oidc.private_key_jwt.keys]` | `{issuer}/upstream-jwks`, which no discovery document names | FerroSMART's own client assertions to the identity provider |
| The backend keys | `[ferrosmart.backend.keys]` | Its own client registration, by value | The client assertions of FerroSMART's own SMART Backend Services client to its token endpoint |

The token keys share no key with either assertion ring; FerroSMART refuses
to start when they do.
Each key is a PEM file from a mounted secret. The private key never enters
the database.

## The token keys

Tokens are signed `RS256`, the algorithm RFC 9068 §2.1 and OpenID Connect
Discovery 1.0 §3 have every authorization server support and SMART signs
ID Tokens with, or `ML-DSA-65` (RFC 9964) for a client whose
`id_token_signed_response_alg` names it. `none` and HMAC never sign. Each
algorithm has one ring, which signs both access tokens and ID Tokens; their
`typ` (`at+jwt` against `JWT`) keeps an ID Token from passing as an access
token.

Make an RSA key, and an ML-DSA-65 key beside it, with OpenSSL 3.5 or
later:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out rs256.pem
openssl genpkey -algorithm ML-DSA-65 -out ml-dsa-65.pem
```

Each key is published under its RFC 7638 thumbprint as its `kid`.
`{issuer}/jwks` answers with `Cache-Control: public, max-age=3600`, so a
resource server may hold the key set for an hour, and a resource server
refetches it when a token names a `kid` it has not seen.

## Rotating the token keys

The token keys rotate on a schedule. List the key files in the order they
take over, and set how long each one signs:

```toml
[ferrosmart.keys]
private_key_files = ["/run/secrets/rs256-1.pem", "/run/secrets/rs256-2.pem"]
rotation_period = "90d"
```

The replicas share where each key stands through the database, so every
replica signs with the same key, and each replica reads it every minute.
A key moves through four states:

1. **`next`.** The first start signs with the first key and publishes the
   second as `next` at once. Later, whenever no key is `next`, the first
   key of the list the database has never seen becomes it. A next key is
   published at `{issuer}/jwks` and signs nothing.
2. **`active`.** After `rotation_period`, the next key takes over, once it
   has been published for at least an hour and a minute (the key set's
   cache lifetime and the refresh interval), so every resource server has
   seen it.
3. **`retiring`.** The old key stays published for the longest-lived token
   it signed plus that hour and a minute: with the default
   `access_token_lifetime` of five minutes, an hour and six minutes.
   A `rotation_period` shorter than that is refused at start.
4. **`retired`.** The key is no longer published and never signs again,
   even while its file stays in the list.

To keep the rotation going, add a fresh key file to the end of the list
on every replica before the current next key takes over, and remove a
retired key's file when you like. With no unused key left, the active key
keeps signing past its period. Every replica must run the same key files:
a replica whose files lack the next key never makes it sign, and a replica
whose files lack the active key keeps the ring it had and logs an error.
`GET {issuer}/admin/keys` shows the replica's ring: every public key it
publishes with its state ([the admin API](../configure/admin-api.md)).

## The assertion keys

When FerroSMART authenticates to its identity provider with
`private_key_jwt`, the current assertion key signs a fresh assertion for
every request: `iss` and `sub` the client id, `aud` the provider's token
endpoint, a unique `jti`, `exp` 60 seconds ahead, `typ` `JWT`. The
algorithm is the one the provider's registration names (`algorithm`,
`RS256` by default), and `certificate_file` names the current key's X.509
certificate for a provider that knows the key that way.

The assertion ring rotates by its files, with a restart at each step:

1. **Publish the next key.** Set `next_private_key_file` to the new key and
   restart. The next key is published at `{issuer}/upstream-jwks` and signs
   nothing. A provider that reads that set, as Keycloak does, sees it there;
   a provider that stores a certificate, as Microsoft Entra ID does, needs
   the next key's certificate uploaded now.
2. **Make it current.** Move the new key to `private_key_file`, the old one
   to `previous_private_key_file`, remove `next_private_key_file`, and
   restart. The new key signs; the old one is still published.
3. **Retire the old key.** `previous_key_overlap` removes the previous key
   by itself after that long; at `0s` it stays until you remove
   `previous_private_key_file` and restart. Remove an old certificate from
   the provider after this step.

## The backend keys

FerroSMART's own SMART Backend Services client (`[ferrosmart.backend]`)
signs an assertion for each token it requests from its own token endpoint:
`iss` and `sub` its client id, `aud` the token endpoint, a unique `jti`,
`exp` 60 seconds ahead, `typ` `JWT`, under `ES384` or `RS384`. Before each
request FerroSMART checks its client registration against the ring and
writes the ring's published keys into it when they differ, so the ring
rotates by its files as the assertion ring does, each step a restart, with
nothing to upload.
