<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Architecture

FerroSMART is the shared library, `ferrohealth-smart`, with which every
FerroHEALTH product (FerroBRIDGE, FerroEHR, FerroFED and FerroTERM) acts as an
OAuth 2.0 and SMART App Launch 2.x resource server, verifies and sends
machine-to-machine credentials, and writes one audit line per request. It is
the owner's decision of 2026-10-19, and this document is the design of
record. Every decision below names its ground in a vendored specification
(`docs/specs/`, pinned in `docs/VERSIONS.md`), and where no specification
governs a decision the text says so: "no specification governs this: our own
design". The product code the design replaces was read on each product's
`main` on 2026-10-19 and is named in section 5, so the migration is a list
of moves.

Citation style: `rfc6749 §4.4` is `docs/specs/rfc/rfc6749.txt` section 4.4;
`smart conformance` is `docs/specs/smart-app-launch/repository/input/pages/conformance.md`
(rendered as `conformance.html` under the STU 2.2 publication); `discovery
§4.3` is section 4.3 of `docs/specs/openid-connect-discovery/`; `soe
master08` is `docs/specs/smart-on-openehr/docs/smart_app_launch/master08-scopes.adoc`.

## 0. The picture

```text
                 inbound                                   outbound
  client ──Bearer/Basic──▶ product listener            product ──▶ upstream
                            │                                 ▲
                      AuthLayer (tower)                 BasicSender
                      ├─ Verifier (JWT)                 ClientCredentials
                      │    ├─ discovery (RFC 8414 / OIDC)   ├─ client_secret_basic
                      │    ├─ KeySet cache (RFC 7517)        ├─ client_secret_post
                      │    └─ token checks (RFC 9068)        └─ private_key_jwt
                      ├─ BasicVerifier (RFC 7617, Argon2id)       (RFC 7523)
                      ├─ Scopes (SMART App Launch 2.2)
                      └─ Audit (one line per request)
                            │
                       Access extension ──▶ product handlers (axum extractor)
```

One crate, four consumers. The library owns everything in the middle column:
it decides who the caller is and what the caller's grant reaches, and it
obtains and presents the product's own credential upstream. The product owns
the two edges: which route needs what (its route table and its interaction
model), what the refusal body looks like (an `OperationOutcome`, an ITS-REST
error body, a JSON document), and every policy beyond the SMART grant
(FerroEHR's roles and attributes, FerroFED's purpose of use and trust list).

## 1. The role: a resource server, never an authorization server

OAuth 2.0 names four roles: the resource owner, the resource server, the
client and the authorization server (`rfc6749 §1.1`). SMART App Launch has an
EHR system "operate as both resource servers and authorization servers"
(`smart conformance`, Actors). FerroSMART takes exactly one of those roles for
every product: the resource server, which "SHALL validate the access token
and ensure that it has not expired and that its scope covers the requested
resource" (`smart app-launch`, Access FHIR API, Response; `smart
backend-services`, Access FHIR API, Response), plus the two client-side
credentials a product needs to call another server.

It never issues a token, never runs a login, and never holds a key that
signs an access token. The authorization server is the deployment's own, any
standards-compliant one, named by its issuer identifier; the product reads
its metadata and its key set and trusts what that server signed. The one
private key the library can hold is a client credential: the key behind
`private_key_jwt` signs the product's own client assertion to its
authorization server (`rfc7523 §2.2`), which is the asymmetric form of a
client secret and signs nothing a resource server would accept.

Why one library: the four products each carry their own copy of the same
checks today (section 7), with differences that are accidents of history
(which `typ` values pass, whether `nbf` is checked, whether the reason for a
refusal reaches the wire, how a refetch of the key set is bounded). A
security check that differs between products is a defect in at least one of
them. One crate, reviewed once, closes that.

## 2. Pinned versions

The single source of truth is `docs/VERSIONS.md`; this table carries the
grounds. `scripts/checks/versions.sh` compares the first token of each row
with the matrix.

| Item | Pin | Ground |
|---|---|---|
| SMART App Launch | 2.2.0 (STU 2.2, on FHIR R4 4.0.1) | The registry's `latest` on 2026-10-19 and the current 2.x publication; the 2.x line is where the `cruds` scope grammar, the `.well-known/smart-configuration` document and the asymmetric client profile live. Vendored as the package `hl7.fhir.uv.smart-app-launch` 2.2.0 and the page sources at the release tag. |
| OAuth 2.0 and JOSE | RFC 6749, 6750, 7515, 7517, 7519, 7523, 7617, 7662, 8414, 8725, 9068, 9700, 8707, 7638, 9449, 8705 | None is obsoleted (the vendor script refuses an obsoleted pin). RFC 9700 updates 6749 and 6750 and RFC 8725 updates 7519, so each is read with its update. RFC 8707 is the `resource` parameter the client credentials client sends and RFC 7638 the thumbprint that names the product's own JWK. Three are in the set for reference: RFC 7662, because section 6 says why introspection is not the default, and RFC 9449 (DPoP) and RFC 8705 (mutual TLS), the sender-constraining mechanisms that stay product-specific (section 9). |
| OpenID Connect Discovery 1.0 | incorporating errata set 2 (2023-12-15) | The edition the unversioned URL serves; RFC 9068 §4 names it as the alternative to RFC 8414 for publishing keys and the issuer. |
| SMART on openEHR | DEVELOPMENT (the ITS-REST draft, `openEHR/specifications-ITS-REST` at commit `9d25ea78…`, its tree last changed at `5183c1f9…`, amendment record 1.1.0 of 2025-05-20) | The one specification of openEHR scopes, which FerroEHR, FerroFED and FerroBRIDGE reach. It is a draft the ITS-REST release does not stabilise, so it is pinned by commit, its status is checked on every vendor run, and a weekly job fails when upstream moves (3.9). |

What is deliberately outside the pinned set: RFC 9396 (authorization
details, which SMART marks experimental). This document makes no claim
about its content.

## 3. The components

### 3.1 Issuer discovery

The issuer identifier is configured. The library reads the authorization
server metadata at the RFC 8414 location first, formed by inserting
`/.well-known/oauth-authorization-server` between the host and the path after
removing a terminating `/` (`rfc8414 §3.1`), and on a `404` there at the
OpenID Connect location, formed by appending
`/.well-known/openid-configuration` to the issuer (`discovery §4.1`). Any
other status at the first location is final. The order and the fallback are
no specification's: our own design, the one FerroBRIDGE runs, chosen so an
authorization server that publishes only one of the two documents works
without a switch. RFC 9068 §4 requires the two documents to be consistent
where both exist, so the first that answers is read and the other is never
consulted.

The document must name the configured issuer exactly: "The `issuer` value
returned MUST be identical to the authorization server's issuer identifier
value into which the well-known URI string was inserted" (`rfc8414 §3.3`;
`discovery §4.3` has every operation that depends on failed validation
aborted). A mismatch refuses the start.

The issuer is an `https` URL with no query and no fragment (`rfc8414 §2`,
`discovery §3` `issuer`), and the `jwks_uri` "MUST use the https scheme"
(`discovery §3`). One exception, no specification's: a loopback issuer
(`localhost`, `127.0.0.1`, `::1`) may be plain HTTP, because a test issuer is
one and its transport cannot be observed. FerroTERM runs this rule today;
FerroEHR's `allow_insecure_issuer` switch is replaced by it.

Discovery runs once at boot and refuses the start when the metadata or the
key set cannot be read: a server that cannot check a token must not serve a
surface it declares protected. The members read are `issuer`, `jwks_uri`,
`token_endpoint`, `authorization_endpoint`, `registration_endpoint`,
`introspection_endpoint`, `revocation_endpoint`, `grant_types_supported`,
`scopes_supported`, `response_types_supported`,
`token_endpoint_auth_methods_supported` and
`code_challenge_methods_supported` (`rfc8414 §2`; `discovery §3`). An omitted
`grant_types_supported` means `["authorization_code", "implicit"]` and an
omitted `token_endpoint_auth_methods_supported` means
`["client_secret_basic"]`, the documented defaults (`rfc8414 §2`, `discovery
§3`), never an empty capability.

### 3.2 The key set cache

The key set is the JWK Set at `jwks_uri` (`rfc7517 §5`): a JSON object with a
`keys` array; a member "that use[s] `kty` values that are not understood,
that [is] missing required members, or for which values are out of the
supported ranges" is ignored, as §5 says to, so such a member is legitimately
absent and no defect. A key is usable for verification when its `use`, if
present, is `sig` (`rfc7517 §4.2`), its `key_ops`, if present, holds `verify`
(`§4.3`), its `alg`, if present, equals the token's (`§4.4`), and its `kty`
belongs to the token's algorithm family. A symmetric key (`kty` of `oct`)
verifies nothing, whatever it says: see 3.3 on algorithms.

Key selection follows the token's `kid` header (`rfc7515 §4.1.4`, "used to
match a JWK `kid` parameter value"; `rfc7517 §4.5`). A token without a `kid`
verifies with the one usable key of its family when the set holds exactly
one; two or more candidates refuse the token, because taking the first would
let a rotation decide which key verifies a request. FerroTERM, FerroEHR and
FerroBRIDGE all refuse the ambiguous case today.

Rotation and freshness, no specification governs these: our own design.

- The set is read at boot, and read again when it is older than
  `jwks_max_age_seconds` (default 600), so a key the issuer withdraws stops
  verifying within that window without any token forcing a read.
- A token naming a `kid` the set does not hold reads the set again at most
  once per `jwks_refresh_interval_seconds` (default 60), because an unknown
  `kid` is how a rotation reaches the resource server; a stream of forged
  `kid`s cannot turn the product into a load on the authorization server.
  RFC 8725 §3.10 has the `kid` treated as untrusted input: it is compared
  as a string and never used to form a path or a query.
- Concurrent misses share one read; the write lock is held across the fetch.
- A read that fails keeps the previous set in use for the keys it holds and
  is not repeated inside the interval. A token that needs a key the held set
  lacks while the set cannot be read is answered `503`, never `401` and never
  admitted: the token was not checked, and the caller must be told to retry
  later, with the same token. This is fail closed: nothing is admitted
  on a failed read, and nothing is refused as invalid that was not examined.
- A `jku` or `x5u` header on a token is ignored: the keys come from the
  issuer's `jwks_uri` alone (`rfc9068 §4`, "MUST use the keys provided by the
  authorization server"; `rfc8725 §3.10` on following such URLs).

A key set may also come from a file (`jwks_file`) for keys handed over out of
band, FerroFED's need; such a set is re-read on the same schedule and is
never combined with a fetched one.

### 3.3 Token validation

A bearer token arrives in the `Authorization` header with the `Bearer` scheme
(`rfc6750 §2.1`), the scheme compared case-insensitively. The form-encoded
body parameter and the URI query parameter of `rfc6750 §2.2` and `§2.3` are
not read: a token in a query string reaches logs and browser history
(`rfc9700 §4.3.2`), and nothing in SMART needs either form. A request that
carries two credentials is `invalid_request` (`rfc6750 §3.1`).

The checks, in order, each a refusal when it fails:

1. **Structure.** The token parses as a JWS in compact serialization
   (`rfc7515 §5.2` steps 1 to 7; `rfc7519 §7.2`). A JWE is refused: no
   product negotiated encryption at registration, and `rfc9068 §4` has an
   encrypted token decrypted only with keys the resource server registered.
2. **Algorithm.** The header's `alg` is on the configured list, and the key
   that verifies it belongs to that algorithm (`rfc8725 §3.1`: "Libraries
   MUST enable the caller to specify a supported set of algorithms and MUST
   NOT use any other algorithms"; "each key MUST be used with exactly one
   algorithm"). The list holds asymmetric algorithms only. `none` is refused
   (`rfc9068 §2.1`, `§4`), and so is every HMAC algorithm, because a key the
   issuer publishes for verification would then also sign (`rfc8725 §2.1`,
   `§3.2`; the algorithm confusion of section 8). The default list is
   `RS256`, `RS384`, `PS256`, `PS384`, `ES256`, `ES384`: RS256 because
   "Authorization servers and resource servers conforming to this
   specification MUST include RS256 among their supported signature
   algorithms" (`rfc9068 §2.1`), RS384 and ES384 because SMART's asymmetric
   client profile names them (`smart client-confidential-asymmetric`,
   Registering a client), and the PS and ES256 forms because they are the
   current algorithms a deployment's authorization server is likely to
   mint. `EdDSA` is accepted when configured. A deployment narrows the list;
   it cannot add `none` or an HMAC.
3. **Type.** Under the default `rfc9068` profile the `typ` header is
   `at+jwt` or `application/at+jwt`, compared case-insensitively, and any
   other value is refused (`rfc9068 §4`, "MUST verify that the `typ` header
   value is `at+jwt` or `application/at+jwt` and reject tokens carrying any
   other value"). This is what keeps an ID token, a client assertion or a
   logout token from being spent as an access token (`rfc8725 §3.11`,
   `§3.12`). Under the `jwt` profile, for an authorization server that does
   not mint RFC 9068 tokens, `typ` may be absent or `JWT`; a value naming
   another kind is still refused, and the audience check below is what then
   keeps an ID token out, because an ID token's audience is the client, never
   the resource server. The profile is configuration, default `rfc9068`.
4. **Key and signature.** The key is selected as in 3.2 and the signature
   verified over the signing input (`rfc7515 §5.2` step 8).
5. **Issuer.** `iss` equals the configured issuer exactly (`rfc9068 §4`,
   "MUST exactly match"; `rfc8725 §3.8`), compared as a string with no
   normalization, because the metadata's `issuer` was already required to be
   identical to it.
6. **Audience.** `aud` contains one of the configured audiences, whether it
   is a string or an array (`rfc7519 §4.1.3`; `rfc9068 §4`, "MUST validate
   that the `aud` claim contains a resource indicator value corresponding to
   an identifier the resource server expects for itself"). A token without
   `aud` is refused (`rfc8725 §3.9`: "if the audience value is not present
   or not associated with the recipient, it MUST reject the JWT"). There is
   no unconfigured case: `audience` is required, and FerroTERM's "no
   audience configured, so `aud` is not checked" tolerance is not carried
   over.
7. **Time.** The current time is before `exp` and at or after `nbf`, each
   with the configured skew (`rfc7519 §4.1.4`, `§4.1.5`, "some small leeway,
   usually no more than a few minutes"; `rfc9068 §4`). `nbf` is checked when
   present, which is the opt-in the JWT crate needs. `iat`, when present, is
   not later than now plus the skew: no specification governs that check;
   our own design, because a token issued in the future is a clock the
   caller controls. The skew is `clock_skew_seconds`, default 60, at most
   300, the bound FerroFED fixes from the "few minutes" of RFC 7519.
8. **Required claims.** Under `rfc9068`: `iss`, `exp`, `aud`, `sub`,
   `client_id`, `iat` and `jti` are present (`rfc9068 §2.2`). Under `jwt`:
   `iss`, `exp`, `aud` and `sub`. A claim required by the profile but absent
   is a refusal, and a refusal names no claim on the wire (3.7).

What the library then reads from a valid token: `sub`, `client_id`, `scope`
(the space-delimited string of `rfc6749 §3.3`, which `rfc9068 §2.2.3` carries
as the `scope` claim of RFC 8693), and `patient`. Two of these need a note:

- `scp`: some authorization servers mint the scopes as an array under `scp`.
  No vendored specification names it. FerroTERM reads it today. The library
  reads `scp` only when `scope` is absent, as an array of strings, and
  records that this is our own tolerance; section 9 asks the owner whether
  to keep it.
- `patient`: SMART places the patient of the launch context in the token
  response ("Launch context parameters come alongside the access token",
  `smart scopes-and-launch-context`, Launch context arrives with your
  `access_token`) and in the introspection response (`smart
  token-introspection`, Conditional fields), never in the access token
  itself, whose format SMART leaves to the issuer. A `patient` claim inside
  the token is therefore the issuer's own convention. The library reads it
  when present; a `patient/` grant without it reaches nothing (3.4). No
  specification governs the claim: our own design, which FerroBRIDGE runs
  today and FerroFED runs under the name `ehrId` for SMART on openEHR.

`jti` is read and carried but not tracked: see the replay entry of section 8.
Every other claim is passed over; a product that needs one (FerroEHR's `acr`,
FerroFED's IUA extension) reads it from the raw claims the `Access` carries,
under its own rules.

### 3.4 The SMART v2 scope grammar and its enforcement

The grammar is `smart scopes-and-launch-context`, FHIR Resource Scope
Syntax: `(patient|user|system)/(<FHIR Resource Type>|*).<permissions>`
with an optional `?param=value&…` suffix, and the permissions "a subset of
the in-order string `.cruds`". Each letter maps to interactions the same page
fixes:

| Letter | Interactions |
|---|---|
| `c` | type-level `create` |
| `r` | instance-level `read`, `vread`, `history` |
| `u` | instance-level `update` (an upsert included) and `patch` |
| `d` | instance-level `delete` |
| `s` | type-level `search` and `history`, system-level `search` and `history` |

The v1 suffixes are read as the page says servers SHOULD read them: `.read`
as `.rs`, `.write` as `.cud`, `.*` as `.cruds`. "Scope requests with
undefined or out of order interactions MAY be ignored": a permission string
out of order, repeated, empty or with an unknown letter grants nothing, and
so does a context other than the three, or a resource that the product's
type set does not name. Granting nothing is the safe reading: a scope the
grammar does not define can only refuse more than the issuer meant, never
admit more. The resource type vocabulary is the product's (FerroBRIDGE's R4
table, FerroTERM's R4B and R5 tables), supplied as a predicate; the library
pins no FHIR version.

Batch and transaction Bundles carry no scope of their own: "batch and
transaction requests should be validated based on the actual requests within
them" (Batches and Transactions). The library checks per entry, and the
product's handler calls it per entry.

**Granular scopes** (the `?param=value` suffix, the `permission-v2`
capability) are parsed and carried on the grant as a constraint, and the
library's own check admits such a grant only when the product supplies an
evaluator for the constraint. Without one, a constrained grant grants
nothing, which again refuses more and never less. The page marks modifiers,
chaining and `_filter` in the suffix experimental; the library parses the
`param=value` pairs and nothing more.

**Reach.** A `user/` or `system/` grant reaches every resource of the type
the product serves to that caller: "these scopes convey 'full access'
relative to the user's underlying permissions" (SMART's scopes are used to
delegate access), and the underlying permissions are the product's, applied
after the library (FerroEHR's roles, FerroFED's purpose of use). A `patient/`
grant reaches the compartment of the patient in the launch context, the
`patient` claim of 3.3: "If the app has any patient-level scopes, they will
be scoped to Patient 123" (Launch context arrives with your `access_token`).
A `patient/` grant on a token that names no patient reaches nothing. What a
patient's compartment is on an openEHR-backed server (the EHR the subject
maps to) is the product's own mapping; FerroBRIDGE keeps it in its
`compartment` module. When both a `patient/` and a `user/` or `system/`
grant cover a permission, the wider one wins, because scopes "can be combined
to represent a union of access" (Scope Equivalence).

**Other scope tokens.** `openid`, `fhirUser`, `launch`, `launch/*`,
`online_access` and `offline_access` grant no FHIR access and are passed
over. A product scope (FerroBRIDGE's `ferrobridge.operator`, FerroTERM's
`ferroterm/admin`) is a scope token the product names, and the library
answers "does this token carry scope *x*" so the product can gate a surface
no SMART scope covers; the page's Extensibility section is the licence for
such a scope ("use any string starting with `__`" or a full URI), and
section 9 asks the owner whether the two products' existing names move to one
of those forms.

**The scopeless-subject allowlist.** A token that carries no FHIR scope at
all is admitted system-wide when its `sub` is on the deployment's allowlist,
and nowhere otherwise. No specification governs this: our own design, the
one FerroBRIDGE runs for an authorization server that cannot mint SMART
scopes for a service account. The allowlist is a list of exact subjects, and
a subject on it that does carry scopes gets only its scopes.

**A Basic principal** carries the scope string its configuration grants it
(4.1), so the same check serves a Basic caller and a bearer caller, and a
handler never asks which it was. No specification governs this: our own
design.

### 3.5 Machine authentication

Machine-to-machine traffic has exactly two forms: HTTP Basic and the OAuth
2.0 client credentials grant. No static bearer token and no API key exists
in the family (owner decision 2026-10-19).

**Basic, verifying.** The credential is `Basic` followed by the base64 of
`user-id:password` (`rfc7617 §2`). The user-id "MUST NOT contain any control
characters" and a user-id "containing a colon character is invalid"; the
octets are decoded as UTF-8, the encoding the challenge advertises with
`charset="UTF-8"` (`rfc7617 §2.1`). A user is configured with the Argon2id
PHC string of its password (`password_hash` or `password_hash_file`) and the
scopes it holds; the cleartext is never stored and never logged. No
specification in the pinned set governs the hash: our own design, on the
OWASP Password Storage Cheat Sheet's Argon2id parameters
(<https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>),
which FerroEHR runs today with the `argon2` crate. An unknown user-id is
verified against a decoy hash of the same parameters, so the time a refusal
takes does not say whether the user exists (FerroEHR's enumeration defence,
carried over). Verification runs on a blocking thread, never on the async
runtime.

**Basic, sending.** The outbound `[<lane>.credentials]` with `user` and
`password` renders the same header (`rfc7617 §2`), UTF-8 then base64, and
the credential type redacts itself in every `Debug` rendering.

**The client credentials grant.** The product obtains its own token with
`grant_type=client_credentials` posted form-encoded to the token endpoint
(`rfc6749 §4.4.2`, with the UTF-8 form encoding of Appendix B), with `scope`
when configured (`§3.3`). The token endpoint is configured outright or
discovered from the issuer as in 3.1. A configured `resource` is sent as
the resource indicator of `rfc8707 §2`, "an absolute URI" that names the
upstream the token is for, so the authorization server can restrict the
token's audience to it (`rfc9700 §4.10.2`); an `audience` parameter has no
specification and is sent only when configured, for an authorization server
that reads one in its place. The client authenticates one of three
ways, configured, never guessed from the server's metadata:

- `client_secret_basic`: HTTP Basic over the form-encoded client id and
  secret, "the HTTP Basic authentication scheme for authenticating clients
  that were issued a client password", which every authorization server
  MUST support (`rfc6749 §2.3.1`). The default.
- `client_secret_post`: `client_id` and `client_secret` in the body, which
  the same section calls NOT RECOMMENDED and limits to clients unable to use
  Basic. Supported for an authorization server that accepts nothing else;
  the parameters "MUST NOT be included in the request URI", and are not.
- `private_key_jwt`: `client_assertion_type` of
  `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` with a single
  JWT in `client_assertion` (`rfc7523 §2.2`), the form RFC 9700 §2.5
  recommends ("It is RECOMMENDED to use asymmetric cryptography for client
  authentication") and SMART Backend Services requires (`smart
  backend-services`, Obtain access token). The assertion is the one `smart
  client-confidential-asymmetric` fixes: header `alg` (RS384 or ES384 by
  default, the two the profile mandates a client support), `kid` (required,
  unique in the client's set) and `typ` of `JWT`; claims `iss` and `sub` both
  the `client_id`, `aud` the token endpoint URL, `exp` "no more than five
  minutes in the future" and a unique `jti`; one assertion per request,
  never reused (`rfc7523 §3` items 1 to 7). The private key comes from
  `private_key_file`; the product serves the matching public JWK Set at a
  route of its own, which the library renders (`rfc7517 §5`, bare `n`/`e` or
  `crv`/`x`/`y` as the SMART profile requires), holding the current and the
  successor key during a rotation, the page's own advice. The `kid` of the
  product's own key is configured, or, when it is not, the SHA-256 JWK
  thumbprint of the key (`rfc7638 §3`), which names the key without a
  registry and changes with the key; the default is our own design, the
  thumbprint is the RFC's.

The response is read under `rfc6749 §5.1`: `access_token`, `token_type`
(`bearer`, compared case-insensitively, the one type the products send;
`rfc6750`), `expires_in` and `scope`. SMART Backend Services makes
`expires_in` required and short ("SHOULD NOT exceed 300"), so the cache below
is sized for five-minute tokens. A non-`200` is read as the `rfc6749 §5.2`
error body (`error`, `error_description`, `error_uri`) when it is one, and
the refusal carries the status, the parsed error and the raw body: a token
the product could not obtain is a typed error, never a missing credential.

**The cache**, no specification governs it: our own design, FerroBRIDGE's.
One token per configured grant, fetched on first use, reused until
`refresh_margin` before `expires_in` (the margin capped at half the
lifetime), concurrent callers sharing one fetch, a token without
`expires_in` reused until the upstream refuses it. **One renewal on a
`401`:** when the upstream answers `401` to a request carrying the cached
token, the product invalidates that token, fetches once, and retries once;
a second `401` stands and reaches the caller as the upstream's refusal. A
token another caller already renewed is not fetched again.

**Never forwarded.** A caller's bearer token is never passed upstream. An
access token names the resource server it is for (`rfc9068 §4`, the `aud`
check that resource server runs), and "the resource server MUST treat access
tokens like other sensitive secrets and not store or transfer them in
plaintext" (`rfc9700 §4.9.3`). The product reaches its upstream under its
own credential, for the upstream's audience.

### 3.6 The audit line

One line per request that passes through the layer, written once the
response is ready, under the `tracing` target `ferrohealth_smart::audit` so
a deployment routes it apart from the application log. No specification
governs the line: our own design, shaped so it can serve as the access record
the products keep under Regulation (EU) 2025/327 Annex II 3.2(b), which asks
for "the specific natural person or persons having accessed" the data. The
field set is fixed; a product adds nothing to the line and removes nothing
from it, so the four products' records read the same:

| Field | Value |
|---|---|
| `at` | the arrival time, RFC 3339 in UTC |
| `request_id` | the request id the product minted or echoed, `-` when none |
| `principal` | the token's `sub`, the Basic user-id, `-` for an open route, `unauthenticated` for a refused credential |
| `client` | the token's `client_id`, `-` when none |
| `via` | `bearer`, `basic`, `open` or `none` |
| `issuer` | the issuer that signed the token, `-` otherwise |
| `method` | the HTTP method |
| `route` | the matched route template, never the raw path |
| `target` | the product's name for what was addressed (`Condition/c-1`, `ehr/…/composition`), at most 64 characters, `-` when none |
| `interaction` | the product's name for the interaction (`read`, `search-type`, an ITS-REST operation id) |
| `status` | the response status |
| `duration_ms` | the time to the response |
| `entry` | the position of a batch or transaction entry, absent on a request line |

Never on the line: the token or any part of it, a claim beyond `sub`,
`client_id` and `iss`, a scope string, a query string, a header, a body, a
password, a client secret or a key. The `Debug` of every credential type
redacts itself, so a line cannot carry one by accident. A product that keeps
a further record (FerroEHR's ATNA audit, FerroFED's security log with its
HMAC references) keeps it beside this line.

### 3.7 The error model

The library returns a typed `Refusal`, and the product renders the body:
an `OperationOutcome` on a FHIR surface, the ITS-REST error body on an openEHR
surface, a JSON document on an admin listener. The status and the
`WWW-Authenticate` challenge are the library's and never differ by product.

- **No credential:** `401` with `WWW-Authenticate: Bearer realm="<realm>"`,
  and, when Basic is enabled on that surface, a second challenge
  `Basic realm="<realm>", charset="UTF-8"` (`rfc6750 §3`; `rfc7617 §2`,
  `§2.1`). No `error` attribute: "If the request lacks any authentication
  information …, the resource server SHOULD NOT include an error code or
  other error information" (`rfc6750 §3.1`).
- **A credential that does not hold:** one `401` for every cause, with
  `error="invalid_token"` for a bearer token, which `rfc9068 §4` makes a
  MUST "in case of any failure in the validation checks", and with no
  `error_description`. The reason (which check failed) reaches the debug log
  and nothing else: a refusal that names the failed claim teaches a forger
  which claim to fix next. No specification requires the omission: our own
  design. FerroTERM's `error_description` with the reason and FerroEHR's
  per-cause variants collapse into this one answer. A Basic credential that
  does not verify gets the same `401` and the same two challenges.
- **A credential that holds and does not permit:** `403` with
  `error="insufficient_scope"` and no `scope` attribute (`rfc6750 §3.1`
  makes the attribute a MAY). The body names no scope either, so a refusal
  teaches a caller nothing about the grants it lacks; no specification
  requires the omission: our own design, FerroBRIDGE's.
- **Two credentials, or a malformed `Authorization` value:** `400` with
  `error="invalid_request"` (`rfc6750 §3.1`).
- **The key set or the metadata cannot be read when a token needs it:**
  `503`, never `401` (3.2). No specification governs this status: our own
  design.
- **A route the product's classifier does not know:** `403` on a guarded
  deployment, so a route mounted without a classification fails closed. Our
  own design, FerroBRIDGE's.

Every challenge value stays inside the character set `rfc6750 §3` fixes for
`error` and `error_description`, and a realm is a configured string.

### 3.8 The `.well-known/smart-configuration` document

"FHIR endpoints requiring authorization SHALL serve a JSON document at the
location formed by appending `/.well-known/smart-configuration` to their
base URL", answered as `application/json` "regardless of `Accept` headers"
(`smart conformance`, Using well-known). The library builds the document from
the issuer's metadata and the capabilities the product enforces; the product
mounts it. The rules the builder keeps:

- `token_endpoint`, `grant_types_supported`, `capabilities` and
  `code_challenge_methods_supported` are required; `issuer` and `jwks_uri`
  are required only with `sso-openid-connect`; the rest is copied from the
  metadata when present (`smart conformance`, Metadata).
- `code_challenge_methods_supported` carries `S256` and never `plain`: "The
  `S256` method SHALL be included in this list, and the `plain` method SHALL
  NOT be included".
- `grant_types_supported` lists only `authorization_code` and
  `client_credentials`, and `token_endpoint_auth_methods_supported` only
  `client_secret_post`, `client_secret_basic` and `private_key_jwt`, each
  value kept only when the issuer advertises it, because those are "the
  options" the page defines and the document is the product's own assertion
  about itself.
- `scopes_supported` lists only scopes the product serves: "The server SHALL
  support all scopes listed here".
- `capabilities` holds what the library enforces for every product
  (`permission-v1`, `permission-patient`, `permission-user`; `permission-v2`
  only when the product supplies a constraint evaluator), the client types
  and launch modes the issuer's metadata supports, and what the product adds
  by configuration.

The route stays public: a client reads it before it holds a token. For an
openEHR surface the builder adds the `services` map and the openEHR
capabilities of 3.9, from the product's declaration of its base URLs.

### 3.9 The SMART on openEHR grammar

FerroEHR, FerroFED and FerroBRIDGE all reach openEHR resources: the first two
serve the ITS-REST surface, and FerroBRIDGE requests openEHR scopes for its
own CDR token. The crate therefore parses and enforces the SMART on openEHR
scope grammar beside the FHIR grammar of 3.4. The source is the ITS-REST
"SMART on openEHR" document, status DEVELOPMENT, vendored at
`docs/specs/smart-on-openehr/docs/smart_app_launch/` and cited here as
`soe master08` for `master08-scopes.adoc` and so on.

**The grammar** (`soe master08`, Resource Scopes): `<compartment>/<resource>.<permissions>`,
the compartment one of `patient`, `user` and `system` with the same meaning
as in 3.4, the resource one of three families with a pattern,
`template-<templateId>`, `composition-<templateId>` and `aql-<queryName>`,
and the permissions the letters `c`, `r`, `u`, `d` and `s`, with `s` "Search
or execute (e.g., for AQL queries)". A pattern is an exact id, `*::Name.v0`
(one name in any namespace), `Namespace::*` (any id in one namespace), or
`*` for "All available templates or queries"; `*` and `**` are both named
as wildcards. **The launch context** (`soe master07`, Context Selection):
`launch/patient` asks for "both FHIR `Patient` resource and corresponding
openEHR `EHR` instance", and the token response then carries `ehrId`, "the
unique identifier of the openEHR `EHR` instance"; `launch/episode` and
`episodeId` are experimental (`soe master09`). **The discovery document**
(`soe master04`): served relative to the platform base URL, with the FHIR
members unchanged, a `services` map keyed by reverse domain name in which
`org.openehr.rest` with its `baseUrl` is required and `org.fhir.rest`
recommended, and the capabilities `context-openehr-ehr`,
`openehr-permission-v1`, `launch-base64-json` and, experimentally,
`context-openehr-episode`.

**The parser is `openehr-sdt`'s.** The published `openehr-sdt` crate
carries `smart_scopes`, a total parser of this grammar (`SmartScope`,
`ResourceScope`, `Compartment`, `ResourceFamily`, `Pattern`, `Permissions`),
which FerroFED consumes today. The crate consumes it behind an `openehr`
feature and models nothing of the grammar itself: a second copy of a
published parser would fork the grammar between the products, which is the
drift one crate exists to close. What the crate adds is the enforcement: a `Requirement::OpenEhr {
family, permission, resource }` the product's classifier names per route,
checked against the token's parsed scopes.

**Where the draft is silent, these rules are ours**, carried over from
FerroFED's `auth/permission/grant.rs`, which moves into the crate with
FerroFED's migration:

- The permission letters are read in any order: the draft lists the five
  letters and fixes no order, unlike SMART App Launch, so `.rs` and `.sr`
  are one grant. A letter outside the five grants nothing.
- `*` matches within one `::`-delimited segment and `**` across segments;
  a bare `*` or `**` matches every id. The draft's table shows the four
  forms and no more, so this is the one reading under which every row of
  the table holds.
- A resource with no family of its own (the `EHR`, its `EHR_STATUS`, its
  `DIRECTORY`, a `CONTRIBUTION`) is held to the `composition-` family with
  the operation's permission over every template, because they are the EHR's
  data and the draft names no other family for them. The DEMOGRAPHIC API has
  no family either and no scope covers it: only a client the product lists
  by `client_id` reaches it.
- Where the product cannot see which resource a request addresses (an ad hoc
  AQL query, a composition whose template only the node knows, an upload
  whose template is in its body), only a pattern covering every resource,
  `*` or `**`, covers it; a specific pattern cannot be shown to match.
- `system/aql-*` counts only for a client the product lists as a backend
  client, because the draft's own note says it "would grant access to all
  registered and ad-hoc AQL queries system-wide".
- A `patient/` grant reaches only the EHR of the launch context: the `ehrId`
  the draft places in the token response, read from an `ehrId` claim in the
  token when the issuer carries it there (the same convention as `patient`
  in 3.3, our own design), and it "means nothing outside the platform that
  issued it", so a product honours it only for an issuer it binds to its own
  EHR space. It reaches EHR data alone: a `composition-` grant or an `aql-`
  search, never a `template-` grant.
- The FHIR v1 suffixes (`.read`, `.write`) are not applied to this grammar;
  the draft defines none.
- The two grammars coexist in one `scope` claim: each parser reads the
  whole claim and keeps its own grants, and a token may carry both
  `system/Observation.rs` and `system/composition-*.rs`. A scope string that
  parses in neither grammar grants nothing in either.

**Which grammar applies to which route is the product's declaration**, not
the listener's: the classifier of section 5 names a `Requirement` per route, and the
requirement carries the grammar. `Requirement::Fhir { permission,
resource_type }` is checked against the 3.4 grants and
`Requirement::OpenEhr { family, permission, resource }` against this
section's, so a product that serves both surfaces under one listener
(FerroFED's facade beside a FHIR endpoint, FerroEHR's ITS-REST beside its own
FHIR surface) mixes them route by route, and a product that serves one
grammar declares one. Neither grammar is a configuration switch; the route
table is the declaration, and a route with no requirement is refused (3.7).

**The development status is handled by pinning and tracking.** The draft is
vendored at a commit, `scripts/vendor/smart-on-openehr.sh` refuses a tree
whose `manifest_vars.adoc` no longer declares DEVELOPMENT, and its
`--upstream` mode, run weekly by the `smart-on-openehr-upstream` job of
`.github/workflows/specs.yml`, fails when the repository's default branch
has a newer commit touching the tree. A change upstream is then re-vendored
and recorded as a decision in section 9, naming what changed and what the
crate does about it; nothing in the crate follows the draft silently, and a
rule above that the draft later settles differently is changed with its
tests and its decision row, never by drift. The crate's tests cite the
section names of the vendored draft, so a re-vendor that moves a section
fails a citation before it fails a behaviour.

## 4. The configuration model

Every product embeds the same `[auth]` section, deserialized with
`deny_unknown_fields`, with every default inline in the section's `Default`
impl, and every secret with a `_file` sibling of which exactly one is set.
Environment overrides use the product's own prefix and the family's
double-underscore path (`FERROBRIDGE__AUTH__ISSUER`, `FERROEHR__AUTH__…`),
applied by the product's loader over the library's section types. No
specification governs this: our own design.

```toml
[auth]
enabled = true                       # a product may refuse `false`
issuer = "https://as.example.org/realms/ferro"
audience = ["https://bridge.example.org/fhir"]   # at least one; `aud` must contain one
algorithms = ["RS256", "RS384", "PS256", "PS384", "ES256", "ES384"]
token_profile = "rfc9068"            # or "jwt"
clock_skew_seconds = 60              # at most 300
jwks_max_age_seconds = 600
jwks_refresh_interval_seconds = 60
jwks_file = ""                       # a key set handed over out of band, instead of jwks_uri
timeout_ms = 10000                   # one call to the authorization server
realm = "ferrobridge"                # the product's default
scopeless_subjects = []              # exact `sub` values granted system-wide access without a scope
capabilities = []                    # SMART capabilities the discovery document adds

[[auth.basic.users]]                 # absent: no Basic on this surface
user = "etl"
password_hash_file = "/run/secrets/etl.phc"   # or password_hash = "$argon2id$…"
scopes = ["system/*.rs"]
```

A product that trusts several issuers (FerroFED) writes `[[auth.issuer]]`
tables, each carrying the fields of the flat form from `issuer` to
`jwks_file`, and the flat form is read as a one-entry list; the library's
type is a list, and every verifier runs the same checks per entry. The
product-specific fields of an issuer entry (FerroFED's backend clients,
patient binding, contact-point claims) stay in the product's own wrapper
around the entry.

Outgoing credentials are one shape for every lane of every product:

```toml
[cdr.credentials]                    # the lane names the table; the shape is the library's
user = "bridge"
password_file = "/run/secrets/cdr-password"

[terminology.credentials.oauth]      # or the client credentials grant
issuer = "https://as.example.org/realms/ferro"   # or token_endpoint = "https://…/token"
client_id = "ferrobridge"
client_auth = "client_secret_basic"  # client_secret_post | private_key_jwt
client_secret_file = "/run/secrets/terminology-client-secret"
# private_key_jwt instead:
# private_key_file = "/run/secrets/terminology-client.pem"
# kid = "2026-10"
# assertion_alg = "ES384"
scope = "system/CodeSystem.rs"
refresh_margin_ms = 30000
```

`user`/`password` and `oauth` are exclusive; a lane that obtains no token of
its own refuses an `oauth` table at load (FerroBRIDGE's `NoGrant` shape). The
`resource` key is the `rfc8707 §2` resource indicator and `audience` the
parameter without a specification, both sent only when set (3.5).

Validation at load, refusing the start: the issuer URL rule of 3.1, at least
one audience, at least one algorithm and none symmetric, the skew bound, every
Basic user with a parseable Argon2id PHC string and a non-empty user-id
without a colon, every scope token inside the `rfc6749 §3.3` character set,
and exactly one of each secret and its `_file`.

## 5. How a product integrates

The library offers three seams, and nothing in it names a product.

- **A tower `Layer`.** `AuthLayer::new(verifier, classifier)` wraps a router.
  The classifier is the product's: a function from the matched route
  template, the method and the path to a `Target` (whether the route is
  public, which `Requirement` it carries: a SMART permission on a resource
  type, a named scope, or nothing beyond authentication, and the `target`
  and `interaction` names for the audit line). The layer authenticates,
  checks the requirement at the type level, inserts an `Access` into the
  request's extensions, runs the inner service, and writes the audit line
  from the response. A route the classifier does not know is refused (3.7).
- **An axum extractor.** `Access` implements `FromRequestParts`; a handler
  that takes it gets the caller, and one that finds none is outside the
  layer, which is a `500`, never an open door. `Access::reach(permission,
  resource_type)` answers `Any`, `Patient(id)` or `None`; `Access::has_scope`
  answers for a product scope; `Access::claims()` hands the raw claims to a
  product rule that needs more.
- **The outbound side.** `BasicSender` renders the header; `ClientCredentials`
  implements the credentials-provider trait the product's upstream client
  takes (the generated ITS-REST client's for FerroBRIDGE and FerroFED, the
  FHIR terminology client's for FerroBRIDGE and FerroEHR), with `invalidate`
  for the one renewal on a `401`.

The crate is `axum`-independent at its core (the verifier, the scopes, the
credentials, the audit record) and carries the `Layer` and the extractor
behind an `axum` feature, so a product that fronts a different server keeps
the core.

### 5.1 What each product keeps

| Product | Moves into `ferrohealth-smart` | Stays product-specific |
|---|---|---|
| FerroBRIDGE | `src/auth/{discovery,jwks,token,scope}.rs`, the token and scope halves of `guard.rs`, the audit line, `smart.rs` (the discovery document), `src/cdr/oauth/` whole | `compartment.rs` (the patient-to-EHR mapping), the route table `CLASSIFIED`, the `OperationOutcome` bodies, the operator scope and the operations it admits, the `[auth]` loader over the shared section |
| FerroTERM | `src/smart/{discovery,jwks}.rs`, the token checks and the challenge rendering of `mod.rs`, the scope parser of `scopes.rs`, the discovery document | the write-route classification, the admin listener's requirement, the per-version audience list, the `CapabilityStatement` security block, the `OperationOutcome` bodies |
| FerroEHR | `authn/jwt.rs` (the remote key source, the claim checks), `authn/basic.rs` (Argon2id and the enumeration defence), the challenge rendering, `service/terminology/oauth2.rs` (the client credentials client) | the RBAC and ABAC gate (`authz/`, Cedar), the assurance gate (`acr`, step-up challenge), the professional and acting-for claims, the ATNA audit, the committer identity |
| FerroFED | `auth/keys.rs`, `auth/fetch.rs`, the RFC 9068 checks of `auth/mod.rs`, the challenge rendering of `auth/refusal.rs`, the openEHR grant rules of `auth/permission/grant.rs` (3.9) | the trust list and per-issuer policy, RFC 7662 introspection for opaque tokens, the edge mode, the IUA and contact-point claims, purpose of use, the ITS-REST operation table (the classifier, `auth/permission/table.rs`) with its demographic and backend client lists, the FAPI 2.0, mTLS, DPoP and token-exchange onward grants, the HMAC references of the security log |

Two of FerroFED's verifiers do not fit the library's one verifier and plug in
beside it: the introspecting verifier for a token that is not a JWS
(`rfc7662 §2.2`), and the edge-assertion verifier. The library exposes the
`Verifier` trait both implement, so the layer, the `Access` and the audit
line are shared and only the way a token is checked differs.

### 5.2 The migration path

Each product moves in one pull request per product, in this order, each
green on its own gates before the next starts:

1. **FerroBRIDGE** first: its `auth/` and `cdr/oauth/` are the closest to the
   design, so the move is a deletion plus a classifier. Its `[auth]` keys
   rename where the shared section differs (`audience` becomes a list,
   `jwks_refresh_interval_ms` becomes `jwks_refresh_interval_seconds`,
   `jwks_max_age_seconds` appears), with the old keys refused by
   `deny_unknown_fields` and named in the changelog.
2. **FerroTERM**: the environment variables `FERROTERM_OIDC_ISSUER`,
   `FERROTERM_OIDC_AUDIENCE` and `FERROTERM_OIDC_ADMIN_SCOPE` become the
   `[auth]` section (or its environment form); `audience` becomes required,
   which is a breaking change for a deployment that set none; the
   `error_description` on a refusal disappears; the `typ` of `JWT` stays
   accepted only under `token_profile = "jwt"`.
3. **FerroEHR**: the `hmac_secret` key source is removed (section 3.3,
   algorithm), `jwks_json` becomes `jwks_file`, `allow_insecure_issuer`
   becomes the loopback rule, `audiences` keeps its list shape, `basic.users`
   gains `scopes` and keeps `roles` for the RBAC gate. The RBAC and ABAC
   gate runs on the `Access` the layer leaves, reading the roles from the
   claims as it does today.
4. **FerroFED** last: its trust list wraps the library's issuer entries, its
   introspecting and edge verifiers implement the `Verifier` trait, its
   permission table stays, and its onward grants keep their own engine; the
   library's `ClientCredentials` replaces only the plain client-credentials
   case.

Each move keeps every existing test and adds none that weakens one: the
status tables and the challenge strings the products pin today are the
contract the library must meet, and a difference between a product's pinned
behaviour and this design is settled on the tracker before the move, never
by editing the test.

## 6. What FerroSMART deliberately does not do

- **Issue tokens.** That is the authorization server (`rfc6749 §1.1`), and
  the family takes one off the shelf per deployment. A token-issuing library
  would hold a signing key in every product, which is the one key whose
  leak forges every caller.
- **Log a user in, show a consent screen, or hold an app registry.** All
  three are the authorization server's (SMART App Launch's authorize
  endpoint and registration, `smart app-launch`), and each is a product in
  itself with its own threat surface.
- **Introspect by default.** RFC 7662 trades a signature check for a network
  call per request, so a resource server that introspects by default
  inherits the authorization server's availability and latency on every
  request, and SMART only has an EHR "SHOULD support" the endpoint (`smart
  token-introspection`). Self-contained RFC 9068 tokens checked against a
  cached key set are the default; introspection is FerroFED's plug-in for
  opaque tokens from an issuer that mints no JWS.
- **Evaluate the product's own authorization policy.** Roles, attributes,
  purpose of use and consent are "a lower-level responsibility in the access
  control stack" the scopes do not model (`smart scopes-and-launch-context`,
  SMART's scopes are used to delegate access), so they stay in the product.
- **Sender-constrain tokens.** RFC 9700 §2.2.1 has resource servers "SHOULD
  use mechanisms for sender-constraining access tokens" (mutual TLS,
  `rfc8705`; DPoP, `rfc9449`). Both RFCs are vendored for reference, and
  only FerroFED needs one today, so DPoP stays product-specific in FerroFED
  for now (owner decision 2026-10-19; section 9).
- **Read a token from a query string or a form body** (3.3).

## 7. Reference: what the products run today and the design changes

The product code was read on `main` on 2026-10-19. The design keeps what the
four agree on and settles each difference:

| Behaviour | FerroBRIDGE | FerroTERM | FerroEHR | FerroFED | Design |
|---|---|---|---|---|---|
| Metadata location | RFC 8414, then OIDC | OIDC only | OIDC (`openidconnect`) | key set URL or file, introspection | RFC 8414, then OIDC (3.1) |
| Algorithms | RS256, ES256 (configurable, no HMAC) | nine asymmetric, fixed | configurable, HMAC allowed | ES256, ES384, PS256, RS256, fixed | asymmetric only, configurable, default six (3.3) |
| `typ` | `at+jwt` under `rfc9068`, any under `jwt` | `at+jwt` or `JWT`, absent allowed | `at+jwt` when `require_at_jwt` | `at+jwt` | `at+jwt` by default; `jwt` profile by configuration (3.3) |
| `aud` | one configured, required | version bases, optional | list, required | one, required | list, required (3.3) |
| Unknown `kid` | one refetch per interval | one refetch per cooldown | TTL cache | one refetch per interval, max age | both bounds (3.2) |
| No `kid` | single key of the family | single usable key | single usable key | single usable key | single candidate, else refuse (3.2) |
| Refusal reason on the wire | no | `error_description` | one challenge, a body per cause | a stable code per cause in the body | never (3.7) |
| `403` names the scope | no | `scope=` when one | no | no | never (3.7) |
| Key set unreadable | `503` | `401` | `503` | `503` | `503` (3.2) |
| Basic | no | no | Argon2id, decoy | no | Argon2id, decoy, scopes (3.5) |
| Client credentials out | Basic or post, cache, one renewal | none | the `oauth2` crate, cache | FAPI 2.0 engine | Basic, post, `private_key_jwt`, cache, one renewal (3.5) |

## 8. The threat model, in brief

- **Key rotation.** A new key appears in the issuer's set before it signs;
  the unknown-`kid` refetch picks it up within one request, bounded by the
  refresh interval; a withdrawn key stops verifying within the max age. A
  flood of unknown `kid`s costs one read per interval. A failed read admits
  nothing and refuses nothing as invalid (3.2).
- **Algorithm confusion.** `none` is refused outright, every HMAC algorithm
  is refused outright, and a key verifies only the algorithm it belongs to,
  so a public key from the issuer's set can never become the secret of a
  symmetric signature (`rfc8725 §2.1`, `§3.1`, `§3.2`; `rfc9068 §4`).
- **Token substitution.** `typ` must be `at+jwt` and the audience must name
  this product, so an ID token, a client assertion or another resource
  server's token is refused twice over (`rfc8725 §3.9`, `§3.11`, `§3.12`;
  `rfc9068 §4`; `rfc9700 §4.10.2`).
- **Token replay.** A bearer token is a bearer token (`rfc6750 §5.1`): the
  library bounds the damage with the audience check, a short `exp` the
  issuer sets (SMART Backend Services asks for five minutes), TLS on every
  hop, and the rule that a caller's token is never forwarded. `jti` is not
  tracked: a replay inside the lifetime at the same resource server is
  indistinguishable from the client's own retry, and the countermeasure RFC
  9700 §4.9.3 names is sender-constraining, which stays FerroFED's (section 9).
- **Clock skew.** `exp` and `nbf` take the configured leeway, at most five
  minutes; a token issued in the future beyond the leeway is refused; the
  skew never widens by configuration beyond the bound (3.3).
- **Credential leakage through the product.** The audit line carries no
  token, no secret and no claim beyond three; every credential type redacts
  its `Debug`; a refusal names no claim and no scope; a token is read from
  the header only (3.3, 3.6, 3.7; `rfc9700 §4.9.3`).
- **The reverse proxy.** A deployment that terminates TLS in front of a
  product must sanitize inbound headers and protect the link to the product
  (`rfc9700 §4.13`); the library reads no `X-Forwarded-*` header and treats
  the `Authorization` header as the only credential, so a proxy cannot
  inject a caller by header unless the product's edge mode (FerroFED) was
  configured to accept a signed assertion.
- **The issuer itself.** The issuer is trusted entirely: a compromised
  authorization server mints valid tokens for every product that trusts it.
  That is the OAuth model, and the mitigation is operational (one issuer per
  deployment, its keys rotated, its audit read), not the library's.

## 9. Decision register

| Decision | Ground | Owner items |
|---|---|---|
| FerroSMART is a library, `ferrohealth-smart`, a resource server and a credential client, never an authorization server | owner decision 2026-10-19 | the repository's `README.md` still describes a SMART on openEHR server that issues tokens and launch context; it needs the new statement |
| The crate is licensed BUSL-1.1 | It is hand-written code that implements the specifications above, which is the family's rule for its own code; only generator-emitted code (`fhir-types`, `hl7v2-types` in FerroBRIDGE) is published under Apache-2.0, because it is emitted from CC0 inputs and three servers depend on it. `ferrohealth-smart` emits nothing and is consumed by the family's own products (owner decision 2026-10-19). `docs/VERSIONS.md` records the licence row and `scripts/checks/versions.sh` fails on any other claim. | none |
| Machine-to-machine traffic is HTTP Basic or the client credentials grant, nothing else | owner decision 2026-10-19 | none |
| The `private_key_jwt` key is a client credential, held under `[<lane>.credentials.oauth]`, and is the one private key the library can hold; "never holds a signing key" means never a key that signs an access token, and this key signs only the product's own client assertion (owner decision 2026-10-19) | `rfc7523 §2.2`; the assertion authenticates the client to the token endpoint and no resource server accepts it as an access token (`rfc9068 §4`, the `typ` and `aud` checks) | none |
| Asymmetric algorithms only; HMAC and `none` refused; FerroEHR's `hmac_secret` source removed | `rfc8725 §3.1`, `§3.2`; `rfc9068 §2.1`, `§4` | a FerroEHR deployment on an HMAC secret must move its authorization server to published keys before the FerroEHR migration |
| `audience` is required, as a list | `rfc9068 §4`; `rfc8725 §3.9` | a FerroTERM deployment that set no audience must set one |
| One `401` for every invalid credential, naming nothing; `403` naming no scope | `rfc6750 §3.1`; `rfc9068 §4`; the omissions are our own design | none |
| `503` when the key set cannot be read | our own design | none |
| The `patient` claim is read from the access token when present | our own design (SMART places the context in the token response and the introspection response) | none |
| Under the `rfc9068` profile only `scope` counts; under the `jwt` profile `scp` is read as a fallback when `scope` is absent, for an issuer such as Entra ID that mints the array form | `rfc9068 §2.2.3` names `scope`; `scp` is no specification's, so it is admitted only outside the profile (owner decision 2026-10-19) | none |
| Product scopes (`ferrobridge.operator`, `ferroterm/admin`) are renamed to a form SMART's Extensibility section admits, a `__` prefix or a full URI, during each product's migration | `smart scopes-and-launch-context`, Extensibility (owner decision 2026-10-19) | each product's migration names the new scope and the deployments that must update their authorization server |
| Granular scopes grant nothing without a product evaluator | the safe reading of "MAY be ignored" | none |
| `jti` is read, not tracked; DPoP (`rfc9449`) and mutual TLS (`rfc8705`) stay product-specific, in FerroFED, for now | `rfc9700 §4.9.3` names sender-constraining as the countermeasure; both RFCs are vendored for reference (owner decision 2026-10-19) | none |
| `resource` is the RFC 8707 resource indicator, sent when configured; `audience` has no specification and is sent only when configured | `rfc8707 §2`; FerroBRIDGE sends both today | none |
| The `kid` of the product's own JWK is configured, or defaults to the RFC 7638 SHA-256 thumbprint | `rfc7638 §3`; the default is our own design | none |
| The crate parses (through `openehr-sdt`) and enforces the SMART on openEHR grammar beside the FHIR grammar; the product's route table declares which applies per route | owner decision 2026-10-19; `soe master07`, `master08`; the rules the draft leaves open are listed in 3.9 as our own design | none |
| SMART on openEHR is DEVELOPMENT: pinned by commit, its status checked on every vendor run, upstream read weekly, and every upstream change re-vendored and recorded here as a decision naming what changed | the draft's `manifest_vars.adoc`; no release stabilises it | none yet: the draft last changed on 2026-07-19 (amendment record 1.1.0) |
| The `ehrId` of the launch context is read from an `ehrId` claim when the issuer carries it in the token | our own design, as `patient` in 3.3; the draft places it in the token response (`soe master07`, Context Selection) | none |

## 10. Verification

Every rule above is a test the crate carries before a product moves:

- the discovery order and the issuer mismatch, over `wiremock`;
- the key set: `use`, `key_ops`, `alg` and `kty` filtering, the `kid`
  match, the ambiguous no-`kid` case, the unknown-`kid` refetch and its
  interval, the max-age refetch, the failed read answering `503`;
- the token: each check of 3.3 as its own refusal with its own test, for a
  token minted under RS256, PS256, ES256, ES384 and EdDSA, and the `none`
  and HMAC refusals pinned as asserted negative tests;
- the scopes: the grammar, the v1 mapping, the out-of-order and unknown
  cases, the wildcard, the patient compartment, the union rule, the granular
  constraint without an evaluator;
- Basic: the colon and control-character rules, the UTF-8 decoding, the
  decoy timing, the scopes a user carries;
- the client credentials client: the three authentication methods, the
  assertion's claims and lifetime, the cache and its margin, the shared
  fetch, the one renewal on a `401`, the `rfc6749 §5.2` error body;
- the audit line: the field set, byte for byte, and the absence of every
  forbidden value under a token, a Basic credential and a refusal;
- the error model: every status and challenge string of 3.7, pinned as the
  contract the products' existing tests already hold.

The vendored specifications are read by the design and by the tests that
cite them; `scripts/checks/versions.sh` holds the trees to their provenance,
so the corpus cannot drift under the citations.
