<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Your first system client

**For:** integrators who write a system that calls a FHIR or openEHR server
with no person present: a nightly export, an integration engine, a
resource server checking tokens. You need the [quickstart](../install/quickstart.md)
running on your machine.

In this tutorial you register a SMART Backend Services client, get an
access token with a signed assertion, check the token as a resource server
would, revoke it, and meet the refusal you get when you ask for too much.
Every request on this page runs in FerroSMART's CI against a fresh server,
so the answers shown are the answers you get.

## 1. Read the SMART configuration

An app finds the token endpoint in the server's SMART configuration
(SMART App Launch 2.2.0, Conformance):

<!-- book-request: discover status=200 expect=/token_endpoint="http://localhost:8080/token" -->

```http
GET /.well-known/smart-configuration HTTP/1.1
Host: localhost:8080
```

With no identity provider configured, this is the Backend Services
document: only systems get tokens.

## 2. Make a key and register the client

A system authenticates with a signed assertion, never a password (SMART
App Launch 2.2.0, Client Authentication: Asymmetric). Make a P-384 key and
write its public half as a JWK with the `kid` `my-key-1`; any JOSE library
does this, and `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384`
makes the key.

Write the client document as `config/first-system.json`, with your public
key in `jwks`:

<!-- book-client -->

```json
{
  "client_id": "first-system",
  "client_name": "My first system",
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks": {"keys": [{"kty": "EC", "crv": "P-384", "kid": "my-key-1", "x": "…", "y": "…"}]},
  "resources": ["http://localhost:8090/fhir"],
  "scope": "system/Observation.rs system/introspect",
  "grant_types": ["client_credentials"]
}
```

Apply it:

```sh
docker compose run --rm ferrosmart client apply /etc/ferrosmart/first-system.json
```

The `scope` is the client's ceiling: it can never be granted more.
`system/introspect` lets it check tokens in step 4; a real resource server
gets its own client for that.

## 3. Get a token

Sign a client assertion with your key: a JWT with header
`{"alg": "ES384", "typ": "JWT", "kid": "my-key-1"}` and the claims `iss`
and `sub` set to `first-system`, `aud` set to
`http://localhost:8080/token`, `exp` at most five minutes ahead and a
fresh `jti`. Below, `$ASSERTION` stands for it; sign a new one for every
request, since each `jti` is accepted once.

<!-- book-request: token status=200 capture=TOKEN:/access_token expect=/token_type="bearer" expect=/scope="system/Observation.rs" -->

```http
POST /token HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&scope=system%2FObservation.rs
&resource=http%3A%2F%2Flocalhost%3A8090%2Ffhir
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=$ASSERTION
```

The answer carries `access_token`, `token_type` `bearer`, `expires_in` and
the granted `scope`. Compare `token_type` without regard to case, as RFC
6749 §5.1 has it: a person's tokens answer `Bearer`. The token is a JWT whose `aud` is the FHIR server
named in `resource` (RFC 8707) and whose `sub` is your `client_id`. Below,
`$TOKEN` stands for it. Send it to the FHIR server as
`Authorization: Bearer $TOKEN`.

## 4. Check the token

A resource server checks the JWT against FerroSMART's keys at
`/jwks`, or asks the introspection endpoint (RFC 7662):

<!-- book-request: introspect status=200 expect=/active=true expect=/client_id="first-system" -->

```http
POST /introspect HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded

token=$TOKEN
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=$ASSERTION
```

## 5. Revoke it

When the system is done, it revokes the token (RFC 7009):

<!-- book-request: revoke status=200 -->

```http
POST /revoke HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded

token=$TOKEN
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=$ASSERTION
```

Introspection now answers the token inactive:

<!-- book-request: introspect-revoked status=200 expect=/active=false -->

```http
POST /introspect HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded

token=$TOKEN
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=$ASSERTION
```

A resource server that checks the JWT itself, without introspection, still
accepts it until it expires, at most five minutes for a Backend Services
token.

## 6. Ask for too much

A scope outside the ceiling is never granted. When nothing asked for lies
within it, the token endpoint refuses (RFC 6749 §5.2):

<!-- book-request: beyond-ceiling status=400 expect=/error="invalid_scope" -->

```http
POST /token HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&scope=system%2FPatient.rs
&resource=http%3A%2F%2Flocalhost%3A8090%2Ffhir
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=$ASSERTION
```

## Where to go next

- To launch an app a person uses: [launch an app](../integrate/flows.md).
- To accept FerroSMART's tokens at your server: [put a server behind FerroSMART](../integrate/resource-server.md).
- To see why FerroSMART grants what it grants: [how FerroSMART decides a token](../explanation/token-decision.md).
