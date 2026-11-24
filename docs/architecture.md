<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Architecture

FerroSMART is the family's SMART App Launch 2.x authorization server
(section 13, owner decision 2026-11-16), a FerroHEALTH product whose name
this repository carries (owner decision 2026-11-17). Beside the server it
holds three crates: authentication, `ferrohealth-smart`, the policy
decision, `ferrohealth-authz` (section 11), and the console sign-in and
session, `ferrohealth-session` (section 12). Sections 0 to 10 design
`ferrohealth-smart`, the shared library with which every
FerroHEALTH product (FerroBRIDGE, FerroEHR, FerroFED, FerroPIX and FerroTERM) acts as an
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
master08` is `docs/specs/smart-on-openehr/docs/smart_app_launch/master08-scopes.adoc`;
`rm-common master06` is
`docs/specs/openehr-rm/development/docs/common/master06-change_control_package.adoc`.

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

This section is the role of the library crates. The family's one
authorization server is FerroSMART (section 13), a separate component of
this repository that no product links.

OAuth 2.0 names four roles: the resource owner, the resource server, the
client and the authorization server (`rfc6749 §1.1`). SMART App Launch has an
EHR system "operate as both resource servers and authorization servers"
(`smart conformance`, Actors). `ferrohealth-smart` takes exactly one of those
roles for every product: the resource server, which "SHALL validate the access token
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
| IETF RFCs | RFC 6749, 6750, 7515, 7517, 7519, 7523, 7617, 7662, 8414, 8725, 9068, 9700, 8707, 7638, 9449, 8705, 9470, 8259, 6454, 7636, 7009, 7643, 9396, 7521, 7522, 8693, 3986, 6819, 7518, 7591, 8252, 9126, 9207, 9864, 10070, 9110 | None is obsoleted (the vendor script refuses an obsoleted pin). RFC 9700 updates 6749 and 6750 and RFC 8725 updates 7519, so each is read with its update. RFC 8707 is the `resource` parameter the client credentials client sends and RFC 7638 the thumbprint that names the product's own JWK. RFC 8705 §2 and §5 are the mutual-TLS client authentication of the token client (3.5), and §3 the certificate-bound tokens of 3.15. RFC 9470 is the step-up challenge of 3.7. RFC 8259 §4 is the repeated member name a metadata document is refused for, and RFC 6454 §4 and §5 the origin the opt-in endpoint check of 3.1 compares. RFC 7636 (PKCE) and RFC 7009 (token revocation) are the code exchange and the revocation of the `oidc` relying party. RFC 9449 (DPoP) is the proof-bound tokens of 3.15. RFC 7662 is in the set because section 6 says why introspection is not the default. RFC 7643 §2.4 and §4.1.2 are the SCIM `roles` and `entitlements` forms the role claims of 3.11 read. RFC 9396 (rich authorization requests, which SMART marks experimental) is the `authorization_details` a client grant sends and reads back (3.5); the resource server reads no `authorization_details` claim (3.11). RFC 8693 (token exchange, `act` in §4.1) and RFC 7521, the assertion framework that RFC 7523 profiles for the JWT bearer grant, with RFC 7522 its SAML 2.0 profile beside it, are the onward grants and the delegation of the caller classification (FerroHEALTH/FerroSMART#215, #217). RFC 3986 §6.2.2 and §6.2.3 are the normalizations RFC 9449 §4.3 has a server apply before it compares the `htu` (3.15), and §4.2 the network-path reference the session's return path refuses (FerroHEALTH/FerroSMART#235). RFC 6819, 7518, 7591, 8252, 9126, 9207, 9864 and 10070 are what FerroSMART, the authorization server of section 13, cites beyond the resource server's set: the threat model, the algorithms and their fully-specified names, dynamic registration, native apps, pushed authorization requests, the `iss` authorization response parameter, and RFC 10070's audience rule for client assertions, which updates RFC 7521, 7522, 7523 and 9126 and conflicts with SMART 2.2 (13.6). RFC 9110 §8.8.3 and §13.1.2 are the weak entity tag and the conditional GET of the Brands Bundle (13.23, §8). |
| OpenID Connect Discovery 1.0 | incorporating errata set 2 (2023-12-15) | The edition the unversioned URL serves; RFC 9068 §4 names it as the alternative to RFC 8414 for publishing keys and the issuer. |
| OpenID Connect Core 1.0 | incorporating errata set 2 (2023-12-15) | The edition the unversioned URL serves; the authorization code flow (§3.1) and the ID Token check (§3.1.3.7) of the `oidc` relying party. |
| OpenID Connect RP-Initiated Logout 1.0 | final (2022-09-12) | The edition the unversioned URL serves; the end-session request (§2) and the `end_session_endpoint` metadata (§2.1) of the `oidc` relying party. |
| OpenID Connect Front-Channel Logout 1.0 | final (2022-09-12) | The edition the unversioned URL serves; the logout URI an upstream renders in an iframe (§2), which ends FerroSMART's `online_access` grants for providers that offer no back-channel logout, such as Microsoft Entra ID (#677). |
| OpenID Connect Back-Channel Logout 1.0 | incorporating errata set 1 (2023-12-15) | The edition the unversioned URL serves; the Logout Token check (§2.6) of the `oidc` relying party, which ends FerroSMART's `online_access` grants at upstream logout (13.6 item 7). |
| OAuth 2.1 Authorization Framework | draft-ietf-oauth-v2-1-17 (2026-10-31) | The current revision of the Working Group draft that consolidates RFC 6749, 6750 and the security best current practice. FerroSMART cites it beside those RFCs (13.5) and never in their place, because an Internet-Draft is a work in progress. |
| Inferno SMART App Launch test kit | 1.0.3 (`inferno-framework/smart-app-launch-test-kit` tag `v1.0.3`) | The latest release on 2026-11-16 and the conformance lane FerroSMART runs (13.13). Its requirement extraction for SMART App Launch 2.2.0 is a cross-check of the checklist, never a citation. |
| FAPI 2.0 Security Profile | Final Specification (2025-02-22) | The profile a client grant can be held to (3.5): the authorization servers of the Dutch BgZ and eOverdracht track FerroFED reaches follow it. §5.3.3.1 sets the client's sender constraint, client authentication, assertion `aud` and metadata use, and §5.4.1 the admitted algorithms. |
| Party binding references | IHE IUA Revision 2.5 (`IHE/ITI.IUA` tag `2.5`) and Nuts RFC021 (`nuts-foundation/nuts-specification` at `7c0de533…`) | The access token of a federation issuer (IUA ITI-71, Nuts RFC021) that the caller model reads (FerroHEALTH/FerroSMART#215). IUA and RFC021 are the editions FerroHEALTH/FerroFED vendors. |
| Contact-point references | The eHDSI SAML Profile, Section II Security Services, Service Location and Capability Lookup Profile, NCPeH Components Specifications and Messaging Profile 10.0.0, the Cryptographic Algorithms 9.0.0, the X.509 Certificates Profile 7.0.0 and the Interoperability Specifications 8.0.1 (supplied by the owner); SOG-IS Agreed Cryptographic Mechanisms 1.3 (read, recorded by sha256, never copied); the MyHealth@EU Requirements Catalogue 10.0.0 (read, recorded by sha256, never copied); Implementing Regulation (EU) 2026/2099 and Regulation (EU) 2016/679 (the Official Journal XHTML); the Federation Tier with AQL specification 1.0.1 Annex B (`syntaric/openehr-federation-spec` at `b4242c29…`) | The contact-point issuer profile of the caller classification (FerroHEALTH/FerroSMART#215): the IdA issuer, attributes, authentication classes, lifetimes and refusal names from the eHDSI documents, the fields of 2026/2099 Annex Tables 1 and 2, GDPR Art. 9(3) and Art. 29 for guests, and the Dutch `authorization_details` of Annex B §B.4a. The eHDSI files and Annex B are the ones FerroHEALTH/FerroFED vendors. The Requirements Catalogue states no reuse terms, so it is cited by section only. |
| Consent decision record | IHE Basic Audit Log Patterns (BALP) 1.1.4, the Volume 3 content page (3:5.7) as profiles.ihe.net renders it | The consent decision reference a `federation` token carries in `consent.reference` is the Consent entity of the 3:5.7.6 consent decision record (FerroHEALTH/FerroSMART#286). The page is the one FerroHEALTH/FerroFED vendors. |
| SMART on openEHR | DEVELOPMENT (the ITS-REST draft, `openEHR/specifications-ITS-REST` at commit `9d25ea78…`, its tree last changed at `5183c1f9…`, amendment record 1.1.0 of 2025-05-20) | The one specification of openEHR scopes, which FerroEHR, FerroFED and FerroBRIDGE reach. It is a draft the ITS-REST release does not stabilise, so it is pinned by commit, its status is checked on every vendor run, and a weekly job fails when upstream moves (3.9). |

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
aborted). A mismatch refuses the start. The comparison is exact text, code
point by code point once the JSON escaping is removed, with no
normalization (`rfc8414 §4`), so a different case, a default port written
out or a terminating `/` is another issuer (`metadata::check_issuer`). A
product that also holds the configured issuer to the canonical form the URL
parser writes, without userinfo, so the text compared and the URL fetched
have one meaning, reads it with `metadata::canonical_issuer`; that form is
no specification's: our own design, FerroPIX's (#67).

A document in which any object repeats a member name is refused before it is
read (`DiscoveryError::RepeatedName`): "The names within an object SHOULD be
unique" (`rfc8259 §4`), and the meaning of a repeated one is each parser's,
so a second `issuer` or `jwks_uri` could be the one another reader takes.
The refusal is our own design (#69).

A product that sends a credential only to its issuer's origin opts into
`ServerMetadata::check_origin`, which refuses metadata naming an endpoint
(`jwks_uri`, the authorization, token, registration, introspection and
revocation endpoints, the mutual-TLS token alias) whose scheme, host and
port differ from the issuer's (`rfc6454 §4`, `§5`). RFC 8414 places no
endpoint, and an authorization server may publish its key set or an alias on
another host, so the check is off unless the product calls it: our own
design (#68).

The issuer is an `https` URL with no query and no fragment (`rfc8414 §2`,
`discovery §3` `issuer`), and the `jwks_uri` "MUST use the https scheme"
(`discovery §3`). One exception, no specification's: a loopback issuer
(`localhost`, `127.0.0.1`, `::1`) may be plain HTTP, because a test issuer is
one and its transport cannot be observed. FerroTERM runs this rule today;
FerroEHR's `allow_insecure_issuer` switch is replaced by it.

Discovery runs once at boot and refuses the start when the metadata or the
key set cannot be read: a server that cannot check a token must not serve a
surface it declares protected. A product that would rather start and answer
an unreachable issuer per request builds the server with
`ResourceServer::lazy`: the settings are checked at once, the metadata and
key set are read when the first token needs them, and a read that fails
answers that token `503` (3.7) and is not repeated inside
`jwks_refresh_interval`, the bound 3.2 sets on key set reads. No
specification governs when the key set is first read: our own design,
FerroFED's, moved into the crate (#55). So a product never depends on
start order (#734): it builds every issuer with `ResourceServer::lazy`,
calls `IssuerSet::read_in_background` once at start, which reads each
unread issuer with a bounded back-off (one second, doubling to one
minute), and answers its readiness route with `IssuerSet::is_ready`, not
ready until every issuer is read. A token of an unread issuer is refused
`503` with the reason code `issuer-unread` (`Rejection::Unread`). A
configuration error (a malformed or plain-HTTP issuer, an unknown key, a
symmetric algorithm) still refuses the start, because `lazy` checks the
settings at once. Both constructors return `Send`
futures, so a product calls them from a request. The members read are `issuer`, `jwks_uri`,
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
  `jwks_max_age` (default `10min`), so a key the issuer withdraws stops
  verifying within that window without any token forcing a read.
- A token naming a `kid` the set does not hold reads the set again at most
  once per `jwks_refresh_interval` (default `60s`), because an unknown
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
(`rfc6750 §2.1`), the scheme compared case-insensitively. A product behind
an edge proxy that forwards the credential in a header of its own names that
header (`Gate::with_credential_header`), either schemed like `Authorization`
or bare, its whole value a bearer token; the default stays `Authorization`,
and the rules below hold in whichever header is read (#56). Basic is read
from a schemed header only. The form-encoded
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
   caller controls. The skew is `clock_skew`, default `60s`, at most
   300, the bound FerroFED fixes from the "few minutes" of RFC 7519.
8. **Required claims.** Under `rfc9068`: `iss`, `exp`, `aud`, `sub`,
   `client_id`, `iat` and `jti` are present (`rfc9068 §2.2`). Under `jwt`:
   `iss`, `exp`, `aud` and `sub`. A claim required by the profile but absent
   is a refusal, and a refusal names no claim on the wire (3.7). A `sub`
   that is empty or whitespace only is refused too: `rfc9068 §2.2` requires
   the claim, and `rfc7519 §4.1.2` has it identify a principal "locally
   unique in the context of the issuer", which a blank value does not. The
   gate holds the same rule over a caller any `Verifier` returns.

Steps 1 to 8 are a verdict on the token alone, so the resource server keeps
it: the claims of a token that passed are held under the SHA-256 of the
token, never the token itself, and the same token presented again is not
verified again. A held verdict ends at the token's `exp` and never later
(`rfc7519 §4.1.4`), without the skew; after it the token takes the full
check, which refuses it as today. Before a held verdict answers, the key
that verified the token is looked up in the set exactly as step 4 does, so
a set past its maximum age is read again and a token whose key the issuer
no longer publishes is refused. A read that finds the set changed drops
every held verdict. The steps that read the request or the deployment run
on every request, a held verdict included: the binding (3.15), `iat`, the
subject and the classification. At most 10 000 verdicts in at most 16 MiB
are held, a full map dropping the expired ones and then those that expire
soonest, reported by `ResourceServer::cache_usage` and summed over a set by
`IssuerSet::verdict_usage`. An introspected issuer (3.10) keeps its own
cache and its own per-request rules. No specification asks for a signature
to be recomputed per request: our own design (FerroHEALTH/FerroEHR#6049).

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

An access token's `jti` is read and carried but not tracked: see the replay
entry of section 8. A DPoP proof's `jti` is tracked (3.15).
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

**A Basic principal** carries the scope the product grants it, so the same
check serves a Basic caller and a bearer caller, and a handler never asks
which it was. No specification governs this: our own design. The
`[[auth.basic.users]]` entry holds the credential alone (4); the scope and
the roles are policy, which the product grants from its own configuration
(`config::BasicGrants`, handed to `PasswordStore::with_grants`) or from its
own data (`Caller::with_granted_scope` and `Caller::with_granted_roles` on
the caller the gate admits, which every scope and role reader sees), so a
product that keeps them in its record store drops the keys from its schema
(#479). A Basic principal is a person, so it is granted no `system/` scope,
a backend service's grant (`smart scopes-and-launch-context`): a grant
holding one fails to load naming the user and the scope, and
`Caller::basic` and `Caller::with_granted_scope` drop any they are handed
(#274).

### 3.5 Machine authentication

Machine-to-machine traffic has one form of its own, the OAuth 2.0 client
credentials grant, beside the onward grants a product uses on a caller's
behalf (3.16) and the tokens a `federation` issuer asserts (3.14). No
static bearer token and no API key exists in the family (owner decision
2026-10-19). HTTP Basic, verified and sent below, is a person's credential:
a Basic caller is classified `Person` (3.14), and a Basic user carries no
`system/` scope (3.4, #274; owner ruling 2026-11-05).

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

A verified credential may be kept for at most `[auth.basic] cache_ttl`
(default `5min`, `0s` keeps none), so a repeat request skips the key
derivation. The entry is named by an HMAC-SHA-256 of `user-id:password`
under a key drawn when the store is built, never the password itself; only
a credential that verified is kept, so a wrong password always pays the
derivation; the cache holds at most 4096 entries. Concurrent misses for one
credential share one derivation: the first request runs it and the others
wait for its outcome, a rejection included. Each entry lives between nine
tenths of `cache_ttl` and `cache_ttl`, by a jitter read from its keyed name,
so entries derived together expire apart, and in its last tenth one request
re-derives the credential while the others are still admitted from it. A
re-derivation that fails drops the entry, and no entry admits past
`cache_ttl` from the derivation that admitted it (#498). No specification
governs the cache: our own design, FerroEHR's, moved into the crate.

Four caches of the crate grow with traffic: this one, the verdicts of
verified tokens (3.3, at most 10 000), the introspection response cache
(3.10, at most `cache_capacity` responses) and the records of
`MemoryReplayStore` (3.15, at most 100 000 unless the product sets another
cap). Each reports its cap, its entries and an estimate of their bytes as a
`usage::CacheUsage` (`PasswordStore::cache_usage`,
`ResourceServer::cache_usage`, `Introspector::cache_usage`,
`MemoryReplayStore::cache_usage`), which a
product copies into its own gauges; the crate links no metrics library
(FerroHEALTH/FerroSMART#630). The estimate counts each key and value with
the heap it owns and leaves out the collection's own nodes. No
specification governs the report: our own design.

The outcome says whether a credential was admitted from the cache
(`Verified::cached`, `Caller::cached`), so a product that records each fresh
authentication records one per cache lifetime (#63).

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
- `tls_client_auth` and `self_signed_tls_client_auth`: a client
  certificate in the TLS handshake, checked by the authorization server
  against its PKI or the client's registered keys (`rfc8705 §2.1`, `§2.2`),
  with `client_id` in the body, which "the client MUST include" (`§2`), and
  no secret. When the endpoint is discovered and a certificate is
  configured, the client posts to `mtls_endpoint_aliases.token_endpoint`
  when the metadata names it (`rfc8705 §5`, a MUST). A certificate may also
  be presented under the other methods, for an authorization server that
  binds the token to it. Extra trust roots for a token endpoint behind a
  private certificate authority are added to the built-in ones; a product
  may instead hand the client its own `reqwest::Client`, which is used as
  built, its redirect policy then the product's (#58).
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
  minutes in the future" (the library signs it valid for 60 seconds, since
  it is sent at once and some authorization servers cap the lifetime below
  five minutes: our own design) and a unique `jti`; one assertion per request,
  never reused (`rfc7523 §3` items 1 to 7). The `aud` and the `typ` are
  fixed by the grant's security profile, never configured: the token
  endpoint URL under `JWT` for every grant ("The FHIR authorization
  server's 'token URL'", `typ` "Fixed value: JWT", `smart
  client-confidential-asymmetric`, Request), and under `security_profile =
  "fapi2"` the issuer identifier as a string under
  `client-authentication+jwt` (a client "shall use the authorization
  server's issuer identifier value ... in the aud claim ... as a string not
  as an item in an array", FAPI 2.0 §5.3.3.1; RFC 10070 §4 types it). RFC
  10070 §4 has every client use the issuer; SMART 2.2 governs a SMART
  client and requires the token URL, so the plain grant deviates from RFC
  10070 there, the conflict FerroHEALTH/FerroSMART#528 reports (#529; the
  `assertion_audience` key of #59 is removed in 0.28.0 and refused as
  an unknown key). The private key comes from
  `private_key_file`; the product serves the matching public JWK Set at a
  route of its own, which the library renders (`rfc7517 §5`, bare `n`/`e` or
  `crv`/`x`/`y` as the SMART profile requires), holding the current and the
  successor key during a rotation, the page's own advice. The `kid` of the
  product's own key is configured, or, when it is not, the SHA-256 JWK
  thumbprint of the key (`rfc7638 §3`), which names the key without a
  registry and changes with the key; the default is our own design, the
  thumbprint is the RFC's.

The response is read under `rfc6749 §5.1`: `access_token`, `token_type`
(`bearer`, compared case-insensitively; `rfc6750`; or `DPoP` for a grant
bound to a DPoP key, 3.15), `expires_in` and `scope`. SMART Backend Services makes
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

**The key ring.** A `private_key_jwt` grant signs with the current key of a
`client::keys::KeyRing`, shared as an `Arc` with whatever else signs or
publishes with it. The ring renders its JWK Set (`rfc7517 §5`) in a fixed
order: the current key first, then the previous key while it stays
published (for an overlap window, or until the ring is rebuilt without it),
then the next key. Only the current key signs. Each key is published under
its configured `kid` or, by default, its `rfc7638 §3` thumbprint. A previous
key equal to the current key is refused, and so is a next key equal to
either. No specification governs the rotation: our own design, FerroFED's,
moved into the crate (FerroHEALTH/FerroSMART#319).

**`authorization_details`.** A grant may send RFC 9396 `authorization_details`
on its client credentials request and its token exchange (`rfc9396 §6`).
The text goes out as written once it passes the `§2` shape check: a
non-empty array of objects, each with a non-empty string `type`, the `§2.2`
common fields in their stated types, and no repeated member name. When the
endpoint is discovered, every `type` must be listed in
`authorization_details_types_supported` (`§10`). A token response to a grant
that asked for details must state the details it granted, in the `§2` shape
(`§7`), and `IssuedToken::authorization_details` hands them to the product.

**The FAPI 2.0 Security Profile.** A grant whose `profile` is `Fapi2` is
held to the client rules of FAPI 2.0 §5.3.3.1 and §5.4.1 when it is built:

- an issuer it discovers from;
- `private_key_jwt` with the issuer as the one-string `aud`, or mutual TLS;
- every ring key and the DPoP key signing `PS256`, `ES256` or `EdDSA`;
- tokens bound by DPoP or the certificate;
- a `scope` or `authorization_details`, so the authorization server never
  chooses the token's reach (our own design);
- mutual-TLS alias hosts only on a grant that uses mutual TLS.

The metadata is held to the profile before anything reaches the token
endpoint:

- an `application/json` answer (`rfc8414 §3.2`);
- a token endpoint on the issuer's origin, or a mutual-TLS alias on a host
  the grant names (`rfc8705 §5`; the host list is our own design);
- the client's method and assertion algorithm listed (`rfc8414 §2`);
- `tls_client_certificate_bound_access_tokens` true for a certificate-bound
  grant (`rfc8705 §3.3`);
- each grant type it sends listed;
- the proof algorithm listed when `dpop_signing_alg_values_supported` is
  present (`rfc9449 §5.1`).

The authorization-endpoint rules of §5.3.2.2 need a user agent, and no
client grant has one.

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
| `kind` | the caller kind (3.14): `system`, `patient`, `practitioner`, `practitioner_role`, `related_person`, `person`, `user`, `external_person` or `external_organisation`, `-` for an open route or a refused credential; `scripts/checks/caller-kinds.sh` holds this list to `CallerKind::as_str` |
| `via` | `bearer`, `basic`, `open` or `none` |
| `issuer` | the issuer that signed the token, `-` otherwise |
| `binding` | what the login resolved to (3.17): `party`, `wrong_marker`, `unbound`, `ambiguous`, `inactive`, `abandoned`, `deprovisioned`, `key_claim_missing` or `groups_unavailable`, `source_unavailable` when the party source failed, `-` when no party binding looked the caller up |
| `party` | the party the outcome names, as `<namespace>/<type>/<id>`, `-` when it names none; never a name or another attribute of the party |
| `method` | the HTTP method |
| `route` | the matched route template, never the raw path |
| `addressed` | the product's name for what was addressed (`Condition/c-1`, `ehr/…/composition`), at most 64 characters, `-` when none |
| `interaction` | the product's name for the interaction (`read`, `search-type`, an ITS-REST operation id) |
| `status` | the response status |
| `duration_ms` | the time to the response |
| `entry` | the position of a batch or transaction entry, absent on a request line |

No field is named `target`, `level` or after another key a `tracing`
formatter writes from the event's metadata, so a JSON log that flattens the
event fields beside the metadata keeps all sixteen; the field was `target`
in 0.1.0 and is `addressed` from 0.1.1.

Never on the line: the token or any part of it, a claim beyond `sub`,
`client_id` and `iss`, a scope string, a query string, a header, a body, a
password, a client secret or a key. The `Debug` of every credential type
redacts itself, so a line cannot carry one by accident. A product that keeps
a further record (FerroEHR's ATNA audit, FerroFED's security log with its
HMAC references) keeps it beside this line.

### 3.7 The error model

The library returns a typed `Refusal`, and the product renders the body:
an `OperationOutcome` on a FHIR surface, the ITS-REST error body on an openEHR
surface, a JSON document on an admin listener. The renderer reads the
refused request's head (`http::request::Parts`), so a product answers in
the format the request negotiates (the `Accept` header, a FHIR `_format`). The status and the
`WWW-Authenticate` challenge are the library's and never differ by product.

- **No credential:** `401` with `WWW-Authenticate: Bearer realm="<realm>"`,
  and, when Basic is enabled on that surface, a second challenge
  `Basic realm="<realm>", charset="UTF-8"` (`rfc6750 §3`; `rfc7617 §2`,
  `§2.1`). No `error` attribute: "If the request lacks any authentication
  information …, the resource server SHOULD NOT include an error code or
  other error information" (`rfc6750 §3.1`).
- **A credential that does not hold:** `401` with `error="invalid_token"`
  for a bearer token, which `rfc9068 §4` makes a MUST "in case of any
  failure in the validation checks", and with the stable reason code of the
  failed check as `error_description` (`rfc6750 §3`, #729). A bearer value
  outside the `b64token` syntax of `rfc6750 §2.1` is one such token,
  "malformed" in the words of `rfc6750 §3.1`, with the code
  `not-b64token`. The gate logs every refusal at info with the code, the
  token's `iss`, its client (`client_id`, else `azp`) and its header's
  `kid`, read without checking anything and left out unless visible ASCII
  of a bounded length; never the token or a claim that names a person. The
  owner's decision of 2026-11-20 (#729) weighs an operator's need to see
  why a token was refused above hiding the failed check from a forger: the
  code names a check, never a claim value, and a forger learns no key or
  secret from it. A Basic credential that does not verify gets the same
  `401` and the Basic challenge, which carries no `error_description`
  (`rfc7617 §2` defines no such parameter). The book lists every code
  (`A server behind FerroSMART`).
- **A credential that holds and does not permit:** `403` with
  `error="insufficient_scope"`, the code `scope-not-granted` (or the
  product's party code, `refused-unbound`) as `error_description`, and no
  `scope` attribute (`rfc6750 §3.1` makes the attribute a MAY). The body
  names no scope either, so a refusal
  teaches a caller nothing about the grants it lacks; no specification
  requires the omission: our own design, FerroBRIDGE's.
- **A `DPoP` request that does not hold** (3.15): `401` under the `DPoP`
  scheme, `error="invalid_dpop_proof"` for a proof that fails `rfc9449
  §4.3`, and `error="invalid_token"` for a token or a key binding that fails
  (`rfc9449 §7.1`, Figure 16), with the reason code as
  `error_description`. A surface that
  admits `DPoP` adds a `DPoP realm="<realm>"` challenge to the no-credential
  answer, after the `Bearer` one (`rfc9449 §7.2`, Figure 17).
- **Two credentials, or a malformed `Authorization` value:** `400` with
  `error="invalid_request"` (`rfc6750 §3.1`).
- **The key set or the metadata cannot be read when a token needs it:**
  `503`, never `401` (3.2). A product's own verifier whose upstream fails
  (an RFC 7662 introspection endpoint) reports it as `Rejection::Upstream`,
  which answers the same `503` (#57). No specification governs this status:
  our own design.
- **A credential that holds, from an authentication event the resource
  does not accept:** `401` with `error="insufficient_user_authentication"`
  and, when the product names them, `acr_values` and `max_age` (`rfc9470
  §3`), and the code as `error_description`. What a resource requires is the
  product's ("out of scope", `rfc9470 §3`); `StepUp::satisfied_by` checks it
  against the token's `acr` and `auth_time` (`rfc9470 §6`, `rfc9068 §2.2.1`)
  and `Refusal::StepUp` renders it (#60).
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
  are required only with `sso-openid-connect`, and `issuer` is "otherwise,
  omitted"; the rest is copied from the metadata when present (`smart
  conformance`, Metadata).
- `sso-openid-connect`, and with it `issuer`, is written when the issuer's
  metadata lists the `openid` scope in `scopes_supported` (an OpenID
  Connect issuer "MUST support the `openid` scope value", OpenID Connect
  Discovery 1.0 §3) or the product declares it, and never when the product
  withholds it (`SmartOptions::openid_connect`). It is written only when the
  metadata names a `jwks_uri`, which the capability also requires, so a key
  set read from a file never advertises it.
- `code_challenge_methods_supported` carries `S256` and never `plain`: "The
  `S256` method SHALL be included in this list, and the `plain` method SHALL
  NOT be included".
- `grant_types_supported` lists only `authorization_code` and
  `client_credentials`, and `token_endpoint_auth_methods_supported` only
  `client_secret_post`, `client_secret_basic` and `private_key_jwt`, each
  value kept only when the issuer advertises it, because those are "the
  options" the page defines and the document is the product's own assertion
  about itself.
- `scopes_supported` lists only scopes the product honours: "The server SHALL
  support all scopes listed here". It is RECOMMENDED, so the product fills
  it from `[auth] scopes_supported` (`Resolved::smart_options`), and the
  builder never copies the issuer's own list, which names scopes the
  issuer grants and the resource server may not enforce.
- `capabilities` holds the permission capabilities the product declares
  for its route table (`SmartOptions::permissions`, none by default, because
  a capability is one "that the server supports"; `permission-v2` only with
  a constraint evaluator), the client types and launch modes the issuer's
  metadata supports, `sso-openid-connect` as above, and what the product
  adds by configuration. A configured capability is one the page lists, one the
  SMART on openEHR draft lists (`soe master04`, Capabilities), or a full
  URI: "Simple, non-URI capability strings are reserved for definition in
  SMART App Launch", and other capabilities are "represented with full
  URIs" (`smart conformance`, Capabilities).

A resource server whose key set comes from a `jwks_file` reads no metadata,
so the operator supplies it (`ResourceServer::with_metadata`): it must name
the configured issuer, as `rfc8414 §3.3` holds a fetched document to, every
location it names follows the `https` rule of 3.1, and metadata read from the
issuer is never replaced. The builder is public
(`resource::configuration::document`) for a product that holds its metadata
elsewhere.

A product that trusts several issuers serves one document, so it describes
one of them: the `authorization_endpoint` is "Required if server supports the
launch-ehr or launch-standalone capability" (`smart conformance`, Metadata),
and every user launch starts there; the `token_endpoint` is required always,
and a Backend Services client discovers it from the same document (`smart
backend-services`, Retrieve `.well-known/smart-configuration`). SMART does
not say which of several issuers, so the rule is our own design, one for
every product (`resource::described::describe`), and its answer carries the
`Purpose` the document is built under:

- **Named:** `[auth] described_issuer`, when set, is described once it is a
  trusted issuer with metadata; an unknown or metadata-less issuer is
  refused.
- **The one SMART issuer:** otherwise, the one SMART issuer whose metadata
  is available (read from it, introspected, or supplied by `with_metadata`)
  is described for SMART App Launch; several are refused, naming them
  sorted and the key, and none is refused. A `federation` issuer is another
  party's, so it is described only when named. A `jwks_file` issuer without
  supplied metadata names no `authorization_endpoint`.
- **None:** otherwise the document describes no issuer, and is refused.

The order of the `[auth.issuer.<name>]` tables never decides, so an environment
overlay that adds an issuer cannot change the described issuer.

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

**The parser is this crate's.** `ferrohealth_smart::openehr::smart_scopes`
is a total parser of this grammar (`SmartScope`, `ResourceScope`,
`Compartment`, `ResourceFamily`, `Pattern`, `Permissions`), the one every
product reads the grammar with: a second copy would fork the grammar
between the products, which is the drift one crate exists to close. It
moved here from FerroEHR's `openehr-sdt` with the same path and API
(owner decision 2026-10-27): a `0.0.x` requirement on that crate is exact,
so each of FerroEHR's lockstep releases left this crate behind and a
product resolved two copies. It depends on nothing beyond `std`, behind
the `openehr-scopes` feature, and for the browser (`wasm32-unknown-unknown`)
it is the whole crate, so a browser client (the FerroEHR viewer's scope
previewer) parses with the code the resource server enforces with (5). What the `openehr` feature adds is the enforcement: a `Requirement::OpenEhr {
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
  by `client_id`, or a Basic principal it lists by user-id, reaches it
  (`Requirement::Client`, each list matched only against its own scheme).
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

### 3.10 Token introspection

An authorization server that issues tokens a resource server cannot read
itself is checked by OAuth 2.0 Token Introspection (`rfc7662`), behind
`[auth] mode = "introspection"` and the `fetch` feature
(`resource::introspection::Introspector`, a `Verifier` like the JWT check).
The issuer's metadata is read once at boot, as 3.1 reads it, and names the
`introspection_endpoint` unless the section does; the endpoint is held to the
`https` rule of 3.1, since the token travels in the request (`rfc7662 §4`
requires TLS).

The token is posted as `token` with `token_type_hint=access_token`
(`rfc7662 §2.1`) under the product's own credential, which §2.1 requires:
either the client authentication of the token endpoint (`rfc6749 §2.3.1`,
`rfc7523 §2.2`, `rfc8705 §2`, the same code the token client of 3.5 runs;
§4 names it as a common credential), or a bearer token the product obtains
with the client credentials grant, the form SMART has an EHR accept
(`smart token-introspection`, Authorization to perform Token
Introspection), renewed once on a `401`. A `private_key_jwt` assertion
names the introspection endpoint as its `aud`, or the issuer when the grant
asks for it (`rfc7523 §3` item 3 admits a value that identifies the
authorization server; the choice is our own design).

The response is read under these rules, each refusal the generic `401` of
3.7 with its own `Reason`:

- A body that repeats a member name (`rfc8259 §4`, as 3.1 refuses a
  metadata document), is no JSON object, or has no boolean `active`, and a
  status other than `200` (`rfc7662 §2.3`), are an upstream failure: `503`
  through `Rejection::Upstream`, never a refusal of the caller.
- `active` other than `true` refuses the token (`Reason::Inactive`,
  `rfc7662 §2.2`).
- `scope`, `client_id` and `exp` must be present (`smart
  token-introspection`, Required fields: "SHALL be included").
- `exp` and `nbf` are checked within the clock skew, though the
  authorization server already did (`rfc7662 §4`); the check costs nothing
  and a stale cache entry cannot outlive it.
- `iss`, when present, must be the configured issuer as exact text (3.1),
  and `aud`, when present, must name a configured audience. Both are
  optional in `rfc7662 §2.2`, and §4 has the authorization server determine
  whether the token "can be used at the resource server making the
  introspection call", so an absent one is admitted.
- A `token_type` is `DPoP` exactly when the response names a `cnf.jkt`,
  and otherwise absent or `Bearer` (`rfc6750`; `rfc9449 §6.2`); any other
  value refuses the token. The response's `cnf` is then held to the
  request's binding on every request, a held response included (3.15).
- A response without `sub` is the client's: "the value of sub SHOULD
  correspond to an identifier the authorization server uses to indicate
  the client application" when no resource owner is involved (`rfc9068
  §2.2`), so the subject is `client_id`; a blank `sub` is refused as 3.3
  refuses it.

The claims then go through the step the JWT check of 3.3 ends with (`iat`
within the skew, the subject, the scope parsed under the product's resource
table, `client_id`, the `patient` launch context, the whole response kept as
the caller's claims), so a product's handlers and the audit line read an
introspected caller as they read a JWT one.

An active response is held, keyed by the SHA-256 of the token so no token
stays in memory, until its `exp` and never longer than
`cache_max_age` (default `60s`): "the response MUST NOT be cached
beyond the time indicated" by `exp` (`rfc7662 §4`), and the age bounds the
window in which a revoked token still passes, the trade-off §4 leaves to the
deployment. Zero caches nothing. At most `cache_capacity` responses are held;
a full cache drops its expired entries, then the one that expires first. An
inactive response is never held, so a token activated later is not refused
from the cache. A caller admitted from the cache reports `cached()`, and
a held response is classified again on each request (3.14). The cache
bounds are no
specification's: our own design (FerroBRIDGE #533, #484).

### 3.11 Roles and role requirements

RFC 9068 §2.2.3.1 has an authorization server that puts authorization
attributes in a JWT access token use the `groups`, `roles` and
`entitlements` attributes of the SCIM `User` resource (`rfc7643 §4.1.2`) as
claim types. `Caller::roles()` holds what the configured claims carry
(each `[auth.issuer.<name>]` names its own `role_claims`, by default those
three; a dotted path such as `realm_access.roles` reaches into a JSON object
for an issuer that nests them), so a claim is read from that issuer's
tokens alone, and a `federation` issuer contributes no role. A value is an array element that is a string, an element that is an
object with a string `value` sub-attribute (a SCIM multi-valued attribute,
`rfc7643 §2.4`), each member name of an object (an issuer that keys what it
knows of each role by the role, as ZITADEL writes
`urn:zitadel:iam:org:project:{projectId}:roles`,
`docs/specs/zitadel/apps/docs/content/guides/integrate/retrieve-user-roles.mdx`), or each whitespace-separated word of a string.
A role keeps
the issuer's spelling, trimmed, and appears once. An introspection answer is
read the same way (`rfc7662 §2.2` lets it carry further members). A Basic
user's roles are the ones the product grants it (3.4), each one word.
`Caller::claim_text` reads a string at a dotted claim path for a product's
own attribute.

A route table states its role rules beside its scope rules:
`Requirement::Role` (the caller holds the role), `Requirement::AnyRole`,
`Requirement::WithoutRole` (a restriction, such as a read-only role on a
write, that overrides every grant combined with it) and `Requirement::All`,
beside the existing `Either`. Neither RFC gives roles a vocabulary or a
comparison rule, so a role is matched without regard to ASCII case: no
specification governs role semantics, our own design. RFC 9396 (rich
authorization requests) is vendored as the reference for the
`authorization_details` claim a later release may read; this one does not.

### 3.12 Assurance

RFC 9470 §3 lets a resource server refuse a token whose authentication does
not meet its requirement, with `401`, `insufficient_user_authentication` and
the accepted `acr_values`, and leaves the logic that decides it out of scope.
`assurance::AssuranceSection` holds that logic for every product, on each
`[auth.issuer.<name>]` table, since each issuer writes its own values: the claim
the class is read from (`acr` by default, OpenID Connect Core 1.0 §2), the
level each value stands for (low, substantial, high), and the minimum. The
issuer assesses each token when it admits it (`Caller::assurance`), and
`step_up` builds the `Refusal::StepUp` naming the values that meet the
minimum. Which routes a product holds to them stays the product's. The level
mapping is the deployment's: no specification governs it, our own design.
A token FerroSMART issues names the level as its eIDAS URI
(`http://eidas.europa.eu/LoA/substantial` and the like, 13.28), so a
product behind it maps those three values.

### 3.13 The natural person's own access

The EHDS person-access rights (Regulation (EU) 2025/327 Art. 5 and 9) need
every product to tell the same way whether a request is the natural
person's own access. SMART names *what* a `patient/` scope reaches and not
*who* asks (`smart scopes-and-launch-context`, Patient-specific scopes), so
the answer is read from the token's `fhirUser` (3.14): `Caller::is_the_person`
holds for a `CallerKind::Patient` caller whose `fhirUser` is `Patient/<x>`
(relative, or an absolute URL ending in `/Patient/<x>`; SMART App Launch
2.2.0, Scopes for requesting identity data), whose `patient` launch context
is `x`, and whose token names no actor. A professional's `fhirUser` is never
a `Patient`, so a professional's token whose only clinical scopes are
`patient/` is a professional confined to its launch context; a
`RelatedPerson` acts for the patient (Art 4(2)) and an RFC 8693 actor acts
beside them, so neither is the person's own access, and a token of a
`federation` issuer never is. Who asks under a `patient/` scope is our own
design (owner decision 2026-11-19), since SMART names only what the scope
reaches. A product reads `Caller::is_the_person` and keeps no reading of its
own. A Basic caller is never the person. `Caller::person` returns the
patient the request is bound to: the `patient` launch context, the `ehrId`
and the patient claim's value. The deployment names its patient claim as a
`resource::PatientClaim`, a dotted path, attached to each resource server
with `with_extension`, the one extension the crate reads.

### 3.14 The caller classification

Every product needs one answer to who stands behind a token, and
`ferrohealth-smart` reads it from the token's standard claims the same way
for every issuer (#805). An issuer is a SMART App Launch 2.2 authorization
server, FerroSMART among them, unless its `[auth.issuer.<name>]` table
declares `kind = "federation"`, the one kind with rules of its own
(Regulation (EU) 2025/327 Art 23, Implementing Regulation (EU) 2026/2099).
A token of a SMART issuer is read by RFC 9068: `typ` `at+jwt` or
`application/at+jwt` (`rfc9068 §4`), the claims of §2.2 with `scope`
(SMART App Launch 2.2.0, Obtain access token, Response) required, `scope`
as one string (§2.2.3), and `client_id` the client. Its caller is
(`kind::CallerKind`):

1. `System`: no user. A client credentials token's `sub` is its
   `client_id` (`rfc9068 §2.2`, §5; SMART Backend Services).
2. A user, named by the resource type of their `fhirUser` (SMART App
   Launch 2.2.0, Scopes and Launch Context): `Patient`, `Practitioner`,
   `PractitionerRole`, `RelatedPerson` or `Person`, the reference relative
   or an absolute URL ending in `<type>/<id>`. A user without `fhirUser` is
   `User`, a user of no stated type, and a `fhirUser` of any other form is
   refused as `Unclassified::FhirUser`.

`patient` is the launch context (`launch/patient`), read from a SMART
issuer alone. A `RelatedPerson` with a patient in context is that patient's
representative (Regulation (EU) 2025/327 Art 4(2); `Caller::represented`).
An RFC 8693 §4.1 `act` names the current actor beside the user
(`Caller::actor`, `act.iss` with `act.sub`, the token's own issuer when it
names none), read as the issuer asserts it; prior actors are
"informational only", and a chain deeper than `max_actor_chain` (1 by
default) is refused. A user's token with no `client_id` is refused, and
the client is always recorded (`Caller::client_id`). The authorization
server's registry is the one list of clients: a token whose `aud` names
this resource server was issued for it (`rfc9068 §4`, `rfc8707`), so the
resource server keeps no list of clients or actors, and a product's policy
may still decide on the recorded client and actor. A Basic credential is a
user's and always `User`, never a `System` (owner ruling of 2026-11-05): a
machine authenticates with the client credentials grant (RFC 6749 §4.4).
The audit line records the kind (3.6). A token that reads as none is
refused as `Rejection::Unclassified`, an `invalid_token` on the wire whose
`kind::Unclassified` reason names why.

The `[auth.issuer.<name>.profile]` table holds the keys a deployment may
set over those defaults: `max_actor_chain`, `token_types` and
`required_claims` (a federation issuer's own token shape, 4), and the
onward keys (3.16). No product module names a vendor, and an integration
test scans the crate's modules for a vendor's name.

**A SMART issuer's professional attributes.** One `[auth.issuer.<name>.attributes]`
table per SMART issuer (`federation::person::AttributesSection`) maps
the same fields the `federation` kind reads to their sources, a claim path
or a constant; `mapping = "iua"` reads the IHE IUA §3.71.4.2.2.1.1 claims
under `extensions.ihe_iua` (`subject_name`, `subject_role`,
`national_provider_identifier`, `subject_organization_id`,
`subject_organization` and `purpose_of_use`, never `person_id`), and
`authorization_details_purposes = true` adds the `purpose_of_use` of each
RFC 9396 `authorization_details` entry, written `system|code`. A
professional user of the issuer (every user but a `Patient` and a
`RelatedPerson`) carries what its token states as `Caller::attributes`: the
fields, the roles and the purposes of use as codings, the purposes sorted
and without duplicates. The purpose of use is a property of the request,
so every other caller carries its purposes alone (#438). A coding
whose `code` is empty names no code and an empty `system` no system (FHIR
R4 datatypes.html: `code` and `uri` have at least one character), so a
`purpose_of_use` of empty codes states none. An absent claim is an
absent field; a claim of no attribute shape, a `subject_role` or
`purpose_of_use` that is no array of codings (IUA: "shall be formatted as
array of FHIR Coding"), and a value with a control or bidi-control
character or past its cap refuse the token as `Unclassified::Attribute`,
naming the field. A table on a `federation` issuer, two tables of one
issuer, and an `authorization_details` or presentation source refuse the
start. Which claims are read is our own design over IUA and RFC 9396.

**The `federation` kind.** A `federation` issuer's tokens name another
party's professional or organisation, and its one `[auth.issuer.<name>.federation]`
table (`federation::FederationSection`) maps each field, named after the
Commission Implementing Regulation (EU) 2026/2099 Annex Tables 1 and 2, to
its sources: a claim path (`mapping = "iua"` reads the IHE IUA
§3.71.4.2.2.1.1 claims under `extensions.ihe_iua`, and never `person_id`,
the patient's), a constant, a path in the RFC 9396 `authorization_details`
entry of the declared type, which counts only from an issuer declared to
attest it and only when its `locations` names this node, or a credential
subject path in the Verifiable Presentations of a Nuts RFC021 §6
introspection response. Strings are compared exactly, with "no additional
transformation or normalization" (RFC 9396 §12), and two sources that
disagree refuse the token. A token that names a professional (a
professional field, or `sub` other than the client) is a
`CallerKind::ExternalPerson` only with every Table 1 field, the name as one
string or as family and given names, and is refused as
`ExternalIncomplete` naming each missing field otherwise. One that names
none is an `ExternalOrganisation` only with an attested organisation
statement, and a Nuts token is one unless a presentation holds a credential
type the deployment declares user-authenticated (Nuts RFC021 §8). A
domestic issuer (`contact_point = false`, a required key) declares the
countries, issuing authorities and provider identifier prefixes it may
assert, and an attribute outside them, or holding a C0, C1 or bidi-control
character, or over its length cap, is refused naming the field. A
professional below level substantial, or below level high from 26 March
2032 (2026/2099 Art. 6(3)), is refused. The `sub` is recorded with its
issuer (`External::remote_subject`) and never bound to a local party, and a
`federation` issuer contributes no role. The field `consent.reference`
carries the reference of the consent decision the issuer rendered its
authorization on, the Consent entity of the IHE BALP 1.1.4 3:5.7.6 consent
decision record: one string, a coded value refused naming the field, read
onto the caller as `Caller::consent_reference` when the table maps it. The
field `correlation_id` carries the log correlation id of a chained
organisation request, which the requester sets and each hop carries on,
only from the source the table maps (a claim of the verified token or an
attested `authorization_details` member, never a request header): one
string, read onto the caller as `Caller::correlation_id`. The field
`trc.care_role` carries the care role a treatment relationship attests for
the professional (#751): one code with its code system, a string, an
unsystemed code or two codes refused naming the field, read through
`External::field`; the value set is the deployment's access policy's, never
a product's, and a contact point's token carrying it carries the whole TRC.

**The contact-point profile** (`federation::contact`). A
`contact_point = true` issuer is NCPeH-A's authorization server, and its
token carries what that server read from the validated HP Identity
Assertion and Treatment Relationship Confirmation, under `ehdsi`
(`mapping = "ehdsi"`; the claim names are our own design). It requires
`sender_constraint = "required"` (3.15) and fails to load without it,
naming the key, since the assertion lives up to 4 h. It declares the
participating `countries` and no provider prefixes, and configures the
country and the issuing authority, which the assertion does not carry.
The mandatory attributes are eHDSI SAML Profile 10.0.0 §2.3's, with the
§2.1 assertion window. A refusal carries its MyHealth@EU Requirements
Catalogue 10.0.0 §1.25 code name (`contact::EhdsiCode`, `Unclassified::ContactPoint`):

- no professional: `ERROR_HPI_NO_INFORMATION`;
- a missing NameID or NameID format, a format outside the three of §2.1,
  a missing name or role, `on_behalf_of` missing for role 44, or a purpose
  of use other than `TREATMENT` or `EMERGENCY`:
  `ERROR_HPI_INSUFFICIENT_INFORMATION`, with the missing fields (the
  format outside the three and the purpose are our own design, as §1.25 has
  no code for them);
- no `organization-id`: `ERROR_HPI_HAI_NO_INFORMATION`;
- no point of care, facility type or `homeCommunityId`:
  `ERROR_HPI_POC_NO_INFORMATION`;
- an authentication class outside the seven of §2.1:
  `ERROR_HPI_AUTHENTICATION_NOT_RECEIVED` (requirement 01.01);
- a missing assertion attribute, or a token that outlives the IdA (4 h) or
  the TRC (2 h) window, with 60 s of drift:
  `ERROR_SEC_DATA_INTEGRITY_NOT_ENSURED` (requirement 11.01.02).

A discovery-phase token carries no TRC field and no `patient.id`: the TRC
is issued once the patient is identified (eHDSI SAML Profile 10.0.0 §4),
so the professional's patient identification presents the IdA alone. It is
admitted, held to the IdA window, and `External::trc_patient` reads no
patient from it, so a product refuses every patient-data request under it
(FerroFED and FerroEHR answer `trc-missing`). A token that carries any TRC
field or a `patient.id` carries `trc.id` and both TRC window bounds, or is
refused `ERROR_SEC_DATA_INTEGRITY_NOT_ENSURED` naming the missing ones
(FerroHEALTH/FerroSMART#314).

`EhdsiCode::of` names any other invalid token, and an unreadable key set or
upstream, `ERROR_SEC_GENERIC` (requirement 11): §1.25 has no code for an
unreadable key set, and its `ERROR_REGISTRY_NOT_AVAILABLE` belongs to
requirement 05, the Patient Summary. Nothing is refused on
the description of the HP, the role or the point of care (requirements 01
and 01.02), and no level is judged (Interoperability Specifications 8.0.1
§2.4.3): the class is recorded as received. A contact point never admits
an organisation. Whether a request is a patient-data request, which needs
`patient.id`, is the product's to check.

The IdA's `NameID` is `professional.hp_identifier` and its `@Format` is
`assertion.name_id_format` (one string, a coded value refused naming the
field), each `@Format` one of the three URNs of eHDSI SAML Profile 10.0.0
§2.1. Both are mandatory there, and one string under two formats names two
identifiers, so a product reads them as one pair, `Caller::name_id`, a
`contact::NameId` with its `contact::NameIdFormat`, beside
`assertion.issuer` (FerroHEALTH/FerroSMART#291).

The contact point may relay the UUID of the cross-border request message,
the WS-Addressing `MessageID` of the request (eHDSI NCPeH Components
Specifications 10.0.0 §3.5), as the field `message_id`, read by the `ehdsi`
mapping from `ehdsi.message_id`. It is optional: a token without it is
admitted. It is one string held to the bounds of every field (no control or
bidirectional control character, at most 256 characters), a `urn:uuid:`
form taken as relayed, and a product reads it as `Caller::message_id`, a
`federation::MessageId` whose `Debug` rendering never carries the value, to
join its access record to the contact point's audit entry
(FerroHEALTH/FerroSMART#432).

**FerroSMART behind a product.** FerroSMART (§13) issues plain RFC 9068
access tokens with no Ferro-specific claim, read by the defaults above; the
launch context claims (`patient`, `encounter`, `fhirUser`, `ehrId`, §13.6
item 2) need no key. A product trusts FerroSMART in one issuer table that
names only its issuer, which also reads a client credentials token as
`System`. FerroSMART grants one token exchange, of a patient's own token for
the openEHR base paired with its FHIR base (13.29); the issued token names
the exchanging client as `client_id` and no `act`, so a product reads it as
the patient. FerroSMART's own tests read the tokens it issues the same way.

**A national binding as a federation table.** The products ship no country
content (owner rule, #732). The harmonised BgZ and eOverdracht
authentication of the openEHR Federation Tier specification 1.0.1 Annex B
§B.4a is the book's example issuer table
(`website/book/src/integrate/profiles/nl-annex-b.toml`): a requesting care
provider signs its own client-credentials access token (§B.4a.2), and the
healthcare attributes travel in an `authorization_details` entry of type
`nl-gis-v1` (§B.4a.3). The example declares the issuer a `federation`
issuer, domestic in `NL`, with the CIBG as the issuing authority (§B.3),
the URA prefix `urn:oid:2.16.528.1.1007.3.3.` (the §B.4a.3 example), the
attested entry as the organisation's access statement (§B.4a.1 verifies
only the organisation), the purpose of use and organisation type read from
the entry, and `required_fields` (§B.4a.4: for the query use case
"Organization type must travel"). The URA is the signing organisation's
own, so the deployment configures it as a constant. `sender_constraint =
"required"` holds the issuer to sender-constrained tokens (§B.4a.2), and
with no `typ` in §B.4a.2 the issuer fails to load until the deployment sets
`token_types`. The crate's tests load the book's table, so the example
cannot drift from what the crate reads.

### 3.15 Sender-constrained tokens

A token may be bound to a key its client proves with a DPoP proof
(`rfc9449`) or to the client certificate of the mutual-TLS connection
(`rfc8705 §3`). The token says so in its `cnf` claim, or in the `cnf`
member of its introspection response: `jkt`, the RFC 7638 SHA-256
thumbprint of the DPoP key (`rfc9449 §6.1`, `§6.2`), or `x5t#S256`, the
SHA-256 of the certificate's DER encoding (`rfc8705 §3.1`, `§3.2`). The
module is `sender` (FerroHEALTH/FerroSMART#220).

**Per issuer, `sender_constraint`**, `none` (the default) or `required` on
each `[auth.issuer.<name>]`. Under `required` a token without `cnf` is refused.
Whatever the setting, a token that carries `cnf` is held to it on every
verifier of the crate, and the gate holds every caller a product's own
verifier returns to it too:

- a `jkt` needs a `DPoP` request whose proof's key has that thumbprint; the
  same token under the `Bearer` scheme is refused (`rfc9449 §7.2`);
- an `x5t#S256` needs the certificate it names; a token without one, or
  with another, is refused with `invalid_token` (`rfc8705 §3`);
- a `cnf` that is no object, is empty, or names any other member is
  refused, since nothing here can confirm it (our own design);
- a `DPoP` request whose token names no `jkt` is refused (`rfc9449 §7.1`).

An introspection response's `token_type` is `DPoP` exactly when it names a
`jkt` and otherwise absent or `Bearer` (`rfc9449 §6.2`), and a held
response is checked against the request's binding again on every request.

**The DPoP proof** arrives in the `DPoP` header beside `Authorization: DPoP
<token>`, and `[auth.dpop]` turns the scheme on: without the table the
scheme is not admitted. `sender::proof::ProofCheck` runs every check of
`rfc9449 §4.3`, each refusal its own `sender::Check`: one header (check 1),
a single well-formed JWT in `token68` (2), `jti`, `htm`, `htu`, `iat` and
`ath` present (3), `typ` `dpop+jwt`, compared as a media type
(`rfc7515 §4.1.9`) (4), an asymmetric algorithm of the configured list,
default the token list of 3.3 (5), the signature verified with the `jwk`
header (6), a `jwk` of type EC, RSA or OKP with no private member (7),
`htm` the request's method, case-sensitive (8), `htu` the request's URI
(9), `iat` within the window (11), and `ath` the hash of the token and the
`jkt` the token's (12). No resource-server nonce is issued (`rfc9449 §9`
makes it optional), so check 10 has nothing to compare.

**The `htu` is compared with the product's external URL**, never with the
URI the server sees: behind a TLS-terminating proxy the client addressed
the proxy (`rfc9449 §4.3` check 9, "the HTTP request in which the JWT was
received"). The external URL is the surface's base URL as its clients
address it, and the expected `htu` is that URL with the request path
appended. It is no key of `[auth.dpop]`: a product names its public URL
once, for every document and check that needs it, and hands it to
`DpopSection::settings` (no specification governs the configuration model:
our own design, FerroHEALTH/FerroSMART#474). Both sides are normalized first (`rfc3986 §6.2.2`,
`§6.2.3`, which `rfc9449 §4.3` has a server apply): scheme and host
lowercased, the default port dropped, dot segments resolved, an
unreserved percent-encoding decoded and every other one in upper case, the
query and fragment ignored.

**The window**: a proof is accepted for `max_age` after its `iat`,
default 60, at most 300, and an `iat` up to `clock_skew` ahead,
default 10 (`rfc9449 §11.1`, "on the order of seconds or minutes"; the
values are our own design).

**Replay.** The `jti` of every accepted proof is recorded for its window,
and a proof whose `jti` was recorded is refused (`rfc9449 §11.1`). The
record is the SHA-256 of the `jti` (`sender::replay::ProofId`), a `jti`
over 256 bytes is refused, and the record is written after every other
check, so a refused request spends nothing. The store is the product's,
`sender::replay::ReplayStore`, supplied as a product supplies a `Verifier`:
one atomic call that records a proof and answers whether it was unseen. A
store that fails answers `503` (`Rejection::Upstream`) and never admits a
proof. The crate ships `MemoryReplayStore`, whose refusal holds **within one
process only**: a replay to another replica is admitted there, the case
`rfc9449 §11.1` names ("may not always be feasible in practice, e.g., when
multiple servers behind a single endpoint have no shared state"). A product
that runs more than one replica supplies a store all of them share
(FerroFED's PostgreSQL table, FerroHEALTH/FerroFED#1637). A full in-memory
store refuses a new proof with `503` rather than forgetting one inside its
window. Only DPoP proofs are recorded, never a bearer access token, which
is presented on many requests within its life (`rfc6750 §1.2`).

**The client certificate** is the product's to read from its TLS layer
(`rfc8705 §3`), as `sender::ClientCertificate` in the request's extensions,
where the gate reads it; its trust chain is not checked (`rfc8705 §6.2`),
and behind a TLS-terminating proxy how it reaches the product is the
deployment's (`rfc8705 §6.5`). A certificate-bound token uses the `Bearer`
scheme.

**The wire.** A proof that fails is `401` with `DPoP error="invalid_dpop_proof"`,
a `DPoP` request whose token or binding fails `401` with `DPoP
error="invalid_token"` (`rfc9449 §7.1`, Figure 16), and a missing credential
is challenged with `Bearer` and `DPoP` beside each other (Figure 17). The
reason code is the `error_description` (3.7), and the `algs` parameter, a SHOULD, is
left out. Outside the gate, `ResourceServer::authenticate_bound`,
`Introspector::authenticate_bound` and `Verifier::verify_bound` take the
`sender::Binding` a request proves, and `ProofCheck::authenticate` runs the
whole `DPoP` request; a product verifier that does not implement
`verify_bound` refuses every `DPoP` request (`Check::Unsupported`).

**The client half.** A client grant binds the tokens it is issued, as its
`token_binding` says (FerroHEALTH/FerroSMART#318):

- **to a DPoP key** (`client::dpop::DpopKey`, P-256 signing ES256 or P-384
  signing ES384, `rfc7518 §3.4`). Every token request carries a proof whose
  header has `typ` `dpop+jwt` and the public `jwk`, and whose claims are
  `htm`, `htu` (the URL with no query or fragment), `iat` and a fresh `jti`
  (`rfc9449 §4.2`). A request that presents the token adds `ath`, the
  base64url SHA-256 of the token, and sends `Authorization: DPoP` (`§7.1`).
  Only a token of type `DPoP` is taken (`§5`). A `400 use_dpop_nonce` from
  the token endpoint (`§8`), or a `401` whose `DPoP` challenge names
  `use_dpop_nonce` from a resource (`§9`), is answered once with a new
  proof carrying the nonce. The resend signs a new client assertion, since
  `rfc7523 §3` makes each one single-use. Nonces are kept per origin and per
  role, so an authorization server's nonce and a resource server's are never
  confused (`§9`). `DpopKey::proof` and `DpopKey::remember` are the seam a
  product's own HTTP client calls. `TokenSource::send` is the crate's own
  call path: each `Attempt` carries the `Authorization` value and that
  attempt's proof, and `TokenSource::call` refuses a DPoP-bound source
  without sending anything, since a call handed the `Authorization` value
  alone cannot prove the key;
- **to the client certificate** of its TLS identity. Every token that states
  a binding must name that certificate: a `cnf` member of the token
  response, in the form `rfc8705 §3.2` gives introspection, or the `cnf`
  claim of a JWT access token (`§3.1`). A binding to another certificate or
  another confirmation method is refused before the token is cached or used.
  An opaque token that states nothing passes as sent, since an access token
  is opaque to its client (`rfc6749 §1.4`). The thumbprint comes from the
  identity the grant presents, never from a separate setting, so the check
  can never compare against a certificate the connection does not present.

`Onward` carries both bindings, and its cache key names the key or the
certificate, so a token bound to one never serves a request proven with
another. The `[<lane>.credentials.oauth]` table takes `dpop_key_file` or
`certificate_bound`, and never both.

### 3.16 The onward grants

A product that calls another service on behalf of its caller obtains an
onward token for that service with `client::onward::exchange::Onward`,
behind the default `fetch` feature (FerroHEALTH/FerroSMART#217). The
caller's token travels to the token endpoint only, never to the service,
as 3.5 requires.

A lane declares its onward target in `[<lane>.credentials.onward]` (4),
which `CredentialsSection::onward` resolves into the client and its
`Target`.

**The two grants**, chosen by the issuer's `onward_grant` profile key:

- `token_exchange` (`rfc8693 §2.1`), the default: the caller's token as
  `subject_token` with its `subject_token_type`, an optional `actor_token`
  (an access token of the actor's own, with `actor_token_type`, or, under
  `Onward::with_actor_assertion`, which the onward table's
  `actor_assertion = true` asks for (FerroHEALTH/FerroSMART#340), an RFC 7523 assertion of the requesting
  client signed for each request, with the claims and `aud` of its client
  assertion, a `jti` of its own and the JWT type of `rfc8693 §3`, whose
  issued token is held to the client as its actor, FerroHEALTH/FerroSMART#321), `scope`
  when the target names one, and the target as `resource` (`rfc8707 §2`,
  an absolute URI without a fragment) or `audience`, as `onward_indicator`
  declares. The response must name `issued_token_type`
  (`rfc8693 §2.2.1`) as an access token or a JWT.
- `jwt_bearer` (`rfc7523 §2.1`): the caller's token as `assertion` and
  `scope` naming the target, with no actor token and no `resource` or
  `audience`. A subject the classification calls `System` or
  `ExternalOrganisation` is refused before anything is sent
  (`OnwardError::UserPrincipalRequired`).

The client authenticates as its `ClientCredentials` say, `private_key_jwt`
(`rfc7523 §2.2`) the form `rfc9700 §2.5` recommends. The profile adds what
differs between authorization servers: `onward_parameters` (extra request
parameters, never one the client writes itself and never a
`requested_token_type` naming a refresh token), `onward_client_id`
(`client_id` beside a client assertion, which `rfc7523 §3` leaves
optional), `onward_subject_audience` (the subject token's `aud` must name
the requesting client before it is sent) and `onward_preview` (variants
the authorization server labels preview, refused). No source states
`max_onward_lifetime`; a deployment sets it, and an issuer without it
refuses to build a client. `offline_access` is never sent.

**Fail closed.** A refused or unreadable answer is `OnwardError::Token`
with the upstream status; `interaction_required` is
`OnwardError::InteractionRequired` with the `claims` challenge the body
carries, which the product answers with its own `401`; a response carrying
a refresh token is refused. The client never falls back to its own
credentials, and a caller with no verified token (a Basic caller, or one an
edge asserts with no issuer and no claims) is refused before anything is
sent. `rfc6749 §5.2` does not list `interaction_required` for the token
endpoint; the client reads it where an issuer answers it.

**The onward check**, run on the token as issued and again on every cache
hit. The token is decoded, not verified: it came from the token endpoint
over the connection the client opened. It is refused unless:

- its `iss` is the issuer asked;
- its `aud` is present and every value lies in the target's audiences,
  configured on the `Target` and never derived from a scope;
- its `iat` and `exp` are present, `exp` is no later than `iat` plus
  `max_onward_lifetime`, and neither it nor the subject token has expired;
- for a MyHealth@EU contact-point caller, its `exp` is no later than the
  caller's `assertion.not_on_or_after` or `trc.not_on_or_after`, each when
  carried, plus 60 s of drift (eHDSI SAML Profile 10.0.0 §2.1, §4.1),
  refused as `Rejected::AssertionWindow` naming the window; an unreadable
  end is refused (our own design, FerroHEALTH/FerroSMART#295);
- it names the requesting client as its actor: `act` (`rfc8693 §4.1`,
  `iss` and `sub`) equal to the actor token's actor, or to the issuer and
  the client id when none was sent, or, with no `act` and no actor token,
  its `client_id`;
- on a SMART issuer, `iss` and `sub` are equal in the subject and the
  issued token (OpenID Connect Core 1.0 §5.7);
- for a patient's own token, the issued token's `fhirUser` is a `Patient`
  (`Rejected::Patient`) and every claim of the subject token's patient
  context is equal in it: `patient`, `ehrId` and the deployment's
  `PatientClaim` (3.13), each when the subject token carries it;
- on a `federation` issuer, the subject token's issuer is in its
  `[auth.issuer.<name>.federation]` table's `exchanges_from`, the token reads under
  that table as 3.14 reads a federation token, a professional's
  `professional.hp_identifier` equals the subject claim `person_mapping`
  names, a person's exchange never yields an organisation's token, the
  subject's consent decision reference (3.14), when it carries one, is
  carried over with the same value (`Rejected::Consent`), so is its
  correlation id (`Rejected::Correlation`), and on a chained route
  (`Target::with_correlation_claim`) the correlation claim is carried over.
  A chained route refuses a subject token without that claim before
  anything is sent (`OnwardError::NoCorrelation`).

A patient's own token is exchanged for the patient in its launch context
alone: before anything is sent the client refuses a `CallerKind::Patient`
caller whose token names no patient context
(`OnwardError::NoPatientContext`). No specification governs the patient's
route: our own design over `rfc8693 §2.1` and `rfc7523 §2.1`.

**The cache** is keyed by a SHA-256 over the issuer, the grant, the hash of
the subject token and of the actor token, the target's audiences and
indicators, the scope and the profile's extra parameters, so one subject
token sent to two targets is two exchanges and a token issued for one
target never reaches another (`rfc8707 §2`). An entry lives until
`refresh_margin` (capped at half the time left) before the earliest of the
issued token's `exp`, the subject token's `exp` and `expires_in`, and holds
at most 4096 entries. No token reaches a log line or a `Debug` rendering.

The check, the cache and the profile keys are our own design over
`rfc8693`, `rfc7523` and `rfc8707`.

### 3.17 The party binding

Every product attributes a request to the token's issuer and subject, and
FerroEHR binds every request of a professional or a representative to their
own demographic `PERSON`. The rules of that lookup live in `party`, beside
the classification (3.14), and each product supplies only its store, a
`party::source::PartySource` it implements over an indexed table of its
own. The library never issues a token and never provisions a party. No
specification governs resolving a login to a party: our own design, over
the sources cited here.

**Who is looked up.** A user other than a `Patient` of a SMART issuer that
has an `[auth.issuer.<name>.party]` table, and a Basic user, whose
credential is always a user's (3.14). A `RelatedPerson` is looked up by
their own login, never by the patient they represent. `Patient`, `System`,
`ExternalPerson` and `ExternalOrganisation` callers are never looked up: a
`federation` token's `sub` names a user in another issuer's namespace
(`rfc7519 §4.1.2`, "locally unique in the context of the issuer"). A caller
of an issuer with no table is `Unbound`.

**The match.** The token's `sub` (OpenID Connect Core 1.0 §5.7) is put
in the canonical form the table's `identifier_type` declares (`guid` and
`uuid` in lower case, any other type exactly) and handed to the source with
the table's `identifier_issuer`, which compares it exactly. A Basic user is
looked up by the key the product maps it to
(`PartyBinding::with_basic_user`), and `PartyBinding::check_basic` refuses a
store with an unmapped user. The source reports every party carrying the
value (with its state, its `professional` and `representative` markers, its
memberships and its representation relationships) or the tombstone of a
deleted one, and never chooses between two.

**The outcomes.** `party::Outcome`, left on the caller (`Caller::party`):

- `Party`: one party, with the marker the caller's kind needs (`professional`
  for a `Practitioner`, a `PractitionerRole`, a `Person` or a `User`,
  `representative` for a `RelatedPerson`; a party with both binds either),
  the identifier that matched, the groups the token names that the party
  belongs to, its representation relationships (whether one covers the
  request is the product's check), and whether its record is incomplete
  (`provisional`);
- `WrongMarker`: one party without the marker, with its reference;
- `Unbound`, `Ambiguous` (two or more parties, never resolved to either),
  `Deprovisioned` (the tombstone);
- `Inactive` and `Abandoned`: the state the product reports (openEHR
  `800|inactive|` and `801|abandoned|`, `rm-common master06` §Abandoned
  and Inactive States), with the reference;
- `KeyClaimMissing`: the token's `sub` is blank, or a Basic user maps to
  no key;
- `GroupsUnavailable`: a group claim the token carries in another source
  (`_claim_names` naming it, OpenID Connect Core 1.0 §5.6.2), or a group
  claim that is no array of strings. An absent group claim is the empty
  set.

The groups are the source's memberships intersected with the token's group
claim on each request, so a person in two groups has two. A source that
fails is a `party::source::SourceError`, never `Unbound`; behind the guard
(`Gate::with_party`) it answers `503`, and every other outcome reaches the
handler, which decides what it means. The library calls the source once
per request and holds no cache, no expiry and no invalidation hook (owner
ruling 2026-11-05): a source meets its product's latency budget by indexed
reads, and a cache is proposed only with measurements and an owner ruling.

**The configuration.** One `[auth.issuer.<name>.party]` table per bound
SMART issuer, with `deny_unknown_fields`, checked when the section
resolves:

```toml
[auth.issuer.smart.party]                          # under a SMART issuer
identifier_issuer = "urn:example:ferroehr:login"   # never shared by two tables; unset: the issuer's identifier
identifier_type = "pairwise"                       # declares the canonical form; unset: pairwise, FerroSMART's sub
group_claim = "groups"                             # empty: no group is read
group_identifier_issuer = "urn:example:ferroehr:groups"   # set with group_claim
```

A table has no `claim` key: the token's `sub` is the key, and `claim` is
refused as an unknown key. A table on a `federation` issuer, two tables
naming one issuer or sharing an `identifier_issuer` (two subject spaces
would merge, naming both), and a `group_claim` without its
`group_identifier_issuer` fail too, as `ConfigError::Party`. `PartyBinding::with_resolved` builds the binding from
`Resolved`. The audit line records the outcome and the party reference
(3.6), and no `Debug` rendering carries the key value, a group or a
represented subject.

### 3.18 The eHDSI assertion check

`federation::assertion`, behind `ehdsi-assertion`, is the check an
authorization server acting for NCPeH-A runs on the HP Identity Assertion
and the Treatment Relationship Confirmation before it issues the
contact-point token of 3.14 (FerroHEALTH/FerroSMART#294). The library still
issues nothing: it reads two signed SAML 2.0 assertions and returns typed
values, and `identity::ehdsi_claim` writes them as the `ehdsi` claim the
contact-point profile reads.

- **The signature.** The assertion is the document element, signed by an
  enveloped `ds:Signature` (eHDSI Cryptographic Algorithms 9.0.0 §4.1;
  SAML Profile 10.0.0 §2.2, §4.2). One shape is accepted, which is what
  rules out signature wrapping: one `ds:Signature` in the document, a child
  of the document element; no nested `saml:Assertion`; one `ds:Reference`
  whose URI names the document element's `ID`, carried by no other
  attribute named `ID`, `Id` or `id`; the enveloped transform then
  exclusive canonicalization; `KeyInfo` naming the signer by its
  certificate or its subject key identifier. Every value is read from that
  element by child path, never by ID lookup. Exclusive canonicalization
  (W3C Exc-C14N 1.0) is our own implementation over `roxmltree`, which
  refuses a DTD, under a 64 KiB and 4096-node cap (our own design). A
  linear pre-scan holds the element depth to 32 and the namespace
  declarations to 128 before `roxmltree` parses (our own design), since its
  namespace copies cost time quadratic in nested declarations, and the
  canonicalization keeps one rendered-namespace map with an undo log
  (FerroHEALTH/FerroSMART#315). The line ends are translated before parsing
  (XML 1.0 §2.11), since `roxmltree` 0.21 leaves a carriage return before a
  reference untranslated (FerroHEALTH/FerroSMART#316).
- **The floor.** SOG-IS ACM 1.3 at "Legacy valid beyond 2025"
  (Cryptographic Algorithms 9.0.0 §2): an RSA modulus of at least 3000 bits
  (§4.1, Note 27), PKCS#1 v1.5 or PSS with SHA-256, SHA-384 or SHA-512
  (§5.2). SHA-1 and SHA-224 are refused as `Floor::Hash`, an ECDSA method
  or key as `Floor::EllipticCurve` ("if agreed by all countries").
- **The signer.** A `TrustedSigner` pairs the `saml:Issuer` URI with the
  seal certificate the SMP publishes for it (SMP Profile 10.0.0 §3.1.3,
  §3.1.6). It is refused at registration below the floor, on an elliptic
  curve, or outside the X.509 Certificates Profile 7.0.0 §3.1 seal profile
  (`KeyUsage` critical with `digitalSignature` and `keyEncipherment` alone,
  no `ExtendedKeyUsage`, `BasicConstraints` naming no CA, a
  `SubjectKeyIdentifier`); its validity is checked at each assertion
  (§2.4). Revocation is the deployment's: it removes a revoked
  certificate from the set (our own design).
- **The assertion.** `@Version` 2.0; `@ID` a UUID, as `urn:uuid:` (SAML
  Profile 10.0.0 §2.1) or behind the `_` that makes it an `xs:ID` (SAML 2.0
  Core §2.3.3), since the profile's URN is no `NCName`; `IssueInstant`,
  `NotBefore`, `NotOnOrAfter` and `AuthnInstant` in UTC; a window of at most
  4 h (IdA) or 2 h (TRC), with 60 s of drift at each boundary; an `Audience`
  the validator accepts; `sender-vouches`; and for the IdA no
  `SubjectConfirmationData` (§2.1).
- **The attributes.** The IdA's in the order of 3.14, so an assertion and
  its token are refused with the same §1.25 code; the `Role` and
  `PurposeOfUse` values are the HL7 v3 elements §2.3 requires. The TRC
  carries `PreviousSession`, names the IdA in `Advice/AssertionIDRef` with
  the same `NameID` and format (§4.1; Messaging Profile 10.0.0 §5.5.1), and
  its patient `subject-id`, whose absence answers
  `ERROR_SEC_DATA_INTEGRITY_NOT_ENSURED` (the owner's decision on
  FerroHEALTH/FerroFED#1620); the §4.4 EUDI Wallet attributes are held to
  their pairing.

- **The instants.** `IssueInstant` no more than 60 s ahead and before
  `NotOnOrAfter` (SAML 2.0 Core §2.3.3), `AuthnInstant` no more than 60 s
  after the `IssueInstant` or now (§2.7.2), and `SessionNotOnOrAfter`, when
  present, no more than 60 s behind (§2.7.2; SAML Profile 10.0.0 §2.1,
  §4.1). The session end is returned, and `Exchange::ends` is the earliest
  window or session end, the latest `exp` a token issued on it may carry.
- **The exchange and its replay.** `Validator::exchange` checks the IdA
  alone (the discovery phase) or the IdA with one TRC, and admits that
  exchange once: the `ReplayGuard` `Validator::new` requires records it,
  keyed by the issuer and `ID` of each assertion, until the earliest end
  plus the drift (RFC 7522 §3, item 6). The key is the exchange, not the
  IdA alone, since the IdA "always takes the role of a Supporting Token"
  (Messaging Profile 10.0.0 §5.5.1) and comes again with each TRC of its
  session (SAML Profile 10.0.0 §6, non-normative). The crate ships a
  `MemoryReplayGuard` for one process; a product on several replicas
  supplies a shared store. A guard that cannot answer admits nothing
  (`ERROR_SEC_GENERIC`).
- **The caller's obligation.** Sender-vouches names no presenter, so the
  caller authenticates the presenting party as acting for the issuer:
  NCPeH-A verifies NCP-B's message signature over the Body and the
  assertions (Messaging Profile 10.0.0 §5.5.2), and an authorization
  server acting for NCPeH-A authenticates its national connector, for
  instance by its client certificate (RFC 8705 §2).
- **Interoperability.** An `InclusiveNamespaces PrefixList` naming a
  prefix outside SAML Profile 10.0.0 §1.4.2 is refused as
  `Integrity::Canonicalization` (Cryptographic Algorithms 9.0.0 §4.1:
  "other prefixes than the ones defined in [SAML Profile] MUST NOT be
  used"). Signers built on OpenSAML often list `xs`, so their assertions
  are refused until the issuer fixes its signer.

Every refusal is an `AssertionError`, whose `code()` is its §1.25 code
name: each `Integrity` refusal answers
`ERROR_SEC_DATA_INTEGRITY_NOT_ENSURED`, the attribute refusals the codes of
3.14.

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
realm = "ferrobridge"                # the product's default
capabilities = []                    # SMART capabilities the discovery document adds
scopes_supported = []                # the scopes the product honours, listed in the discovery document
# described_issuer = "sso"           # the name of the issuer the discovery document describes; unset for the one eligible issuer (3.8)
product_scope = ""                   # the product's own scope: `__name` or a full URI

[auth.issuer.sso]                    # one table per issuer, by name; none with Basic users: a Basic-only surface
issuer = "https://smart.example.org"
# kind = "federation"                # another party's issuer (3.14); unset: a SMART authorization server
audience = ["https://bridge.example.org/fhir"]   # `aud` must contain one; unset: the product's own base URLs
algorithms = ["RS256", "RS384", "PS256", "PS384", "ES256", "ES384"]
clock_skew = "60s"                   # at most 300s
jwks_max_age = "10min"
jwks_refresh_interval = "60s"
jwks_file = ""                       # a key set handed over out of band, instead of jwks_uri
timeout = "10s"                      # one call to the authorization server
role_claims = ["roles", "groups", "entitlements"]   # this issuer's role paths (3.11); none on federation
mode = "jwt"                         # or "introspection" (3.10), with the table below
sender_constraint = "none"           # or "required": a DPoP- or certificate-bound token alone (3.15)

[auth.issuer.sso.profile]            # the profile keys, over the defaults
max_actor_chain = 1                  # the deepest RFC 8693 act chain admitted

[auth.issuer.sso.assurance]          # the level this issuer's tokens carry (3.12)
claim = "acr"
levels = { "urn:example:acr:high" = "high" }

[auth.issuer.sso.introspection]      # only under mode = "introspection"
endpoint = ""                        # empty: the metadata's introspection_endpoint
cache_max_age = "60s"                # "0s" caches nothing; never past the response's exp
cache_capacity = 10000

[auth.issuer.sso.introspection.client]   # or .bearer: a grant whose token authorizes the call
client_id = "ferrobridge-rs"         # the fields of [<lane>.credentials.oauth]; the issuer stands in
client_secret_file = "/run/secrets/introspection-secret"

[auth.dpop]                          # absent: the DPoP scheme is not admitted (3.15)
max_age = "60s"                      # a proof is accepted this long after its iat; at most 300s
clock_skew = "10s"                   # an iat this far ahead is accepted; at most 300s
algorithms = ["RS256", "RS384", "PS256", "PS384", "ES256", "ES384"]

[auth.basic]
cache_ttl = "0s"                     # how long a verified credential is kept; "0s" keeps none

[[auth.basic.users]]                 # a person's credential; absent: no Basic on this surface
user = "operator"
password_hash_file = "/run/secrets/operator.phc"   # or password_hash = "$argon2id$…"
```

The entry holds the credential alone, and a table that sets `scopes` or
`roles` is refused as an unknown key. A product that keeps its Basic users'
scopes and roles in its configuration composes `config::BasicGrants` into
its own section, one table per user-id (3.4):

```toml
[operator]                           # a user-id of [[auth.basic.users]]
scopes = ["user/*.rs"]               # never a system/ scope
roles = ["auditor"]                  # one word each (3.11)
```

Every setting of an issuer lives on its own table: no section-level value
stands in for one an issuer leaves out, and a section-level issuer setting
is an unknown key. A named refusal of a retired key lives for the one
release that retires it (owner rule, 2026-11-09); after it the strict load
refuses the key as unknown. Issuers are a map by name (owner decision
2026-11-20, #730): every other key, a product's role lists included, names
an issuer by its table's name, an unknown name is refused at load with the
known names listed, and the environment form addresses an issuer by name
(`FERROEHR__AUTH__ISSUER__SSO__AUDIENCE`), never by a position that shifts
when an issuer is added. A name is a lower-case letter, then lower-case
letters, digits and `_`, at most 64. The party, federation and attribute
tables of an issuer sit under it (`[auth.issuer.<name>.party]`), so none
names its issuer. Defaults derive where one value is the only sensible
one: the audience is the base URLs the product resolves the section for
(`AuthSection::resolve(bases)`), a party table's `identifier_issuer` is
the issuer's own identifier and its `identifier_type` `pairwise`; an
explicit value wins. `Resolved` holds each
JWT issuer's `Settings`, each introspected issuer's settings, every
issuer's kind and its identifier by name; `Resolved::issuer_named` reads a
product key that names an issuer, and `Resolved::role_issuers` holds a
product's administrator, emergency or identifier-reader role list to
SMART issuers. An
`IssuerSet` routes a token to the issuer its readable `iss` names, JWT or
introspected, and an opaque token to the one introspected issuer. The
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
refresh_margin = "30s"
# mutual TLS (RFC 8705 §2) instead, or a certificate beside another method:
# client_auth = "tls_client_auth"    # or "self_signed_tls_client_auth"
# dpop_key_file = "/run/secrets/dpop.pem"  # bind tokens to a P-256/P-384 key (RFC 9449)
# certificate_bound = true                 # or to the client certificate (RFC 8705 §3)
# security_profile = "fapi2"               # FAPI 2.0: issuer, private_key_jwt or mTLS, bound tokens
# mtls_alias_hosts = ["mtls.example.org"]  # hosts a FAPI 2.0 mTLS alias may be on
# previous_private_key_file = "/run/secrets/client-previous.pem"  # published, never signs
# previous_key_overlap = "0s"             # "0s": published while the key is set
# next_private_key_file = "/run/secrets/client-next.pem"          # published ahead of a rotation
# authorization_details = '[{"type": "nl-gis-v1"}]'               # RFC 9396, sent as written
# [terminology.credentials.oauth.tls]   # read by the product's TLS reader (ferrohealth-server TlsClient)
# client_identity_file = "/run/secrets/client.pem"   # the chain and the key in one PEM
# trust_roots_file = "/run/secrets/private-ca.pem" # roots beside the platform's
```

`user`/`password` and `oauth` are exclusive; a lane that obtains no token of
its own refuses an `oauth` table at load (FerroBRIDGE's `NoGrant` shape). The
`resource` key is the `rfc8707 §2` resource indicator and `audience` the
parameter without a specification, both sent only when set (3.5).

Every outbound TLS table of the crate (`auth.tls`, the `tls` of an `oauth`
table) is `ferrohealth_config::tls::TlsClientSection`, and the crate reads no
TLS file. A table that names material resolves through the product's
`config::TlsBuilder` (`resolve_with_tls`), which feature `server-tls`
implements as `config::ServerTls` over `ferrohealth-server`'s
`tls_client::TlsClient`, so the family has one reader of TLS material and
the table's minimum version holds; `resolve` refuses such a table
(`ConfigError::TlsNotBuilt`). Every span of time is a
`ferrohealth_config::units::Duration` (`"30s"`). No specification governs the seam: our own
design.

An outbound integration is one table, `config::endpoint::EndpointSection`:
`url`, `timeout`, `connect_timeout`, `retry` (`max_attempts`,
`initial_backoff`, `max_backoff`), `tls` and `credentials`, so an operator
writes every product's integrations with the same keys. `url` is a
`SecretUrl`, so its userinfo and query render masked, and so is every
issuer identifier a table names (`[auth.issuer.<name>] issuer`, the onward and
the `oauth` issuer, and the issuer `[auth.issuer.<name>.attributes]`,
`[auth.issuer.<name>.federation]` and `[auth.issuer.<name>.party]` name), which renders masked even
before the start refuses an issuer with userinfo (RFC 3986 §3.2.1; #445,
#456). One call,
`client::outbound::OutboundClient::build`, turns the table into the HTTP
engine (its timeouts, no redirects, the TLS the product's `TlsBuilder`
builds) and the authorization (Basic, or a `TokenSource`), and
`OutboundClient::send` applies both with the retry: a call that did not
reach the integration, timed out or met a `5xx` is tried again after a wait
that doubles from `initial_backoff` up to `max_backoff`. Any other answer
is the caller's. No specification governs the retry rule: our own design.
`OutboundClient::build` builds the grant's TLS from its own `oauth.tls`
only. `OutboundClient::build_sharing_tls` is the opt-in for a grant that
presents the connection's identity: when `oauth.tls` names no material, the
grant takes the configuration built from the table's `tls`, so a
mutual-TLS `client_auth` authenticates with the certificate the connection
presents (`rfc8705 §2`) and a `certificate_bound` grant binds its tokens to
the certificate the integration checks them against (`rfc8705 §3`). An
`oauth.tls` that names material still wins, and a `certificate_bound` grant
whose certificate is not the connection's is refused at build
(`OutboundError::CertificateBinding`), since the integration would refuse
every token it is issued.

A lane that reaches its upstream on a caller's behalf declares its onward
target beside its `oauth` table, which the onward client authenticates
with (3.16):

```toml
[cdr.credentials.onward]             # resolved by CredentialsSection::onward
issuer = "https://smart.example.org" # issues the onward tokens
# kind = "federation"                # another party's issuer; unset: a SMART authorization server
# token_endpoint = "https://…/token" # empty: discovered from issuer
# client_id = "…"                    # empty: the oauth table's client id
audiences = ["https://ehr.example.org/openehr/v1"]   # what an onward token's aud may name
# scope = "…"                        # the scope the request names
indicators = ["https://ehr.example.org/openehr/v1"]  # resource or audience, as the profile names
# correlation_claim = "txn"          # a chained federation route
# cache = false                      # default true; false exchanges on every call,
#                                    # for a performance self-test, never production
# actor_assertion = true             # default false; name the client the actor of
#                                    # each exchange with an assertion (rfc8693 §2.1)

[cdr.credentials.onward.profile]     # any profile key over the defaults
max_onward_lifetime = "90min"        # required: no source states one

# [cdr.credentials.onward.federation]  # a federation issuer: exchanges_from and
# [cdr.credentials.onward.assurance]   # person_mapping required
```

The issuer is described in the table, never borrowed from `[auth.issuer.<name>]`,
because the issuer of onward tokens is not always one whose tokens the
surface admits. The table refuses the start when `issuer` or `audiences`
is unset, beside a Basic `user`, without the lane's `oauth` table, for a
profile or federation table its issuer's rules refuse, for an issuer the
onward client refuses (`ConfigError::Onward`: no `max_onward_lifetime`, a federation table without `exchanges_from` or
`person_mapping`), and for a target its grant cannot ask for
(`Onward::check_target`: no audience, `offline_access`, a JWT bearer target
without `scope` or with an indicator, a `resource` that is not an absolute
URI without a fragment).

Validation at load, refusing the start: an enabled section that admits no
credential (no issuer and no Basic user), the issuer URL rule of 3.1, at
least one audience, at least one algorithm and none symmetric, the skew bound, every
Basic user with a parseable Argon2id PHC string and a non-empty user-id
without a colon, every scope token inside the `rfc6749 §3.3` character set
(`scope::is_scope_token`, public so a product checks its own scopes with
the same rule), every capability as 3.8 describes, a product scope in one
of the two extension forms of `smart scopes-and-launch-context`
(Extensibility: "a full URI that you control" or "any string starting with
`__`", `scope::is_extension_scope`), and exactly one of each secret and its
`_file`. An outgoing `oauth` table is held to the same issuer URL rule at
load, and its `resource` to `rfc8707 §2` ("The URI MUST NOT include a
fragment component"), so a bad grant refuses the start rather than the
first token request. The TLS files are read and parsed at load too: a
certificate file without its key file or the reverse, a mutual-TLS method
without a certificate, and roots that hold no certificate each refuse the
start.

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
  product rule that needs more; `Access::basic_user_in` answers whether a
  Basic caller is one of a list of user-ids (#62); and
  `Access::extension::<T>()` hands back the product's own value of type `T`,
  which the issuer's resource server (`ResourceServer::with_extension`) or
  the product's verifier (`Caller::with_extension`) attached, so a
  product's per-issuer policy travels with the verified caller and is not
  looked up again by issuer string (#61).
- **The outbound side.** `BasicSender` renders the header; `ClientCredentials`
  implements the credentials-provider trait the product's upstream client
  takes (the generated ITS-REST client's for FerroBRIDGE and FerroFED, the
  FHIR terminology client's for FerroBRIDGE and FerroEHR), with `invalidate`
  for the one renewal on a `401`.

The crate is `axum`-independent at its core (the verifier, the scopes, the
credentials, the audit record) and carries the `Layer` and the extractor
behind an `axum` feature, so a product that fronts a different server keeps
the core. The HTTP fetchers (the issuer's metadata, the key set over its
`jwks_uri`, the client credentials token client) sit behind the default
`fetch` feature; a product built without it links no HTTP client and reads
its key set from a `jwks_file`. A browser runs none of it, so for
`wasm32-unknown-unknown` the manifest leaves these dependencies out and a
build script's `resource_server` cfg leaves out every module but the SMART
on openEHR grammar (3.9); a feature would have broken every product built
with `default-features = false` (no specification governs this: our own
design).

### 5.1 What each product keeps

| Product | Moves into `ferrohealth-smart` | Stays product-specific |
|---|---|---|
| FerroBRIDGE | `src/auth/{discovery,jwks,token,scope}.rs`, the token and scope halves of `guard.rs`, the audit line, `smart.rs` (the discovery document), `src/cdr/oauth/` whole | `compartment.rs` (the patient-to-EHR mapping), the route table `CLASSIFIED`, the `OperationOutcome` bodies, the operator scope and the operations it admits, the `[auth]` loader over the shared section |
| FerroTERM | `src/smart/{discovery,jwks}.rs`, the token checks and the challenge rendering of `mod.rs`, the scope parser of `scopes.rs`, the discovery document | the write-route classification, the admin listener's requirement, the per-version audience list, the `CapabilityStatement` security block, the `OperationOutcome` bodies |
| FerroEHR | `authn/jwt.rs` (the remote key source, the claim checks), `authn/basic.rs` (Argon2id and the enumeration defence), the challenge rendering, `service/terminology/oauth2.rs` (the client credentials client) | the RBAC and ABAC gate (`authz/`, Cedar), which moves to `ferrohealth-authz` (owner decision 2026-10-25), the choice of which routes carry patient data (the assurance and professional reading itself is `assurance`, 3.12), the ATNA audit, the committer identity |
| FerroFED | `auth/keys.rs`, `auth/fetch.rs`, the RFC 9068 checks of `auth/mod.rs`, the challenge rendering of `auth/refusal.rs`, the openEHR grant rules of `auth/permission/grant.rs` (3.9) | the trust list and per-issuer policy, RFC 7662 introspection for opaque tokens, the edge mode, the IUA and contact-point claims, purpose of use, the ITS-REST operation table (the classifier, `auth/permission/table.rs`) with its demographic and backend client lists, the FAPI 2.0, mTLS, DPoP and token-exchange onward grants, the HMAC references of the security log |

FerroFED's edge-assertion verifier does not fit the library's verifiers and
plugs in beside them through the `Verifier` trait, so the layer, the
`Access` and the audit line are shared and only the way a token is checked
differs. Its introspecting verifier for a token that is not a JWS
(`rfc7662 §2.2`) can move onto the library's `Introspector` (3.10).

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
   `error_description` on a refusal disappears; the `typ` of `JWT` is
   accepted when the issuer's profile lists it in `token_types`.
3. **FerroEHR**: the `hmac_secret` key source is removed (section 3.3,
   algorithm), `jwks_json` becomes `jwks_file`, `allow_insecure_issuer`
   becomes the loopback rule, `audiences` keeps its list shape, `basic.users`
   gains `scopes` and keeps `roles` for the RBAC gate. The RBAC and ABAC
   gate runs on the `Access` the layer leaves, reading the roles from the
   claims as it does today, and then moves with its Cedar policy to
   `ferrohealth-authz` (owner decision 2026-10-25).
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

## 6. What `ferrohealth-smart` deliberately does not do

- **Issue tokens.** That is the authorization server (`rfc6749 §1.1`):
  FerroSMART (section 13) or any other standards-compliant one a deployment
  names. A token-issuing library would hold a signing key in every product,
  which is the one key whose leak forges every caller, so the signing keys
  live in FerroSMART alone.
- **Log a user in, show a consent screen, or hold an app registry.** All
  three are the authorization server's (SMART App Launch's authorize
  endpoint and registration, `smart app-launch`), and each has its own
  threat surface, which FerroSMART carries as its own component.
- **Introspect by default.** RFC 7662 trades a signature check for a network
  call per request, so a resource server that introspects by default
  inherits the authorization server's availability and latency on every
  request, and SMART only has an EHR "SHOULD support" the endpoint (`smart
  token-introspection`). Self-contained RFC 9068 tokens checked against a
  cached key set are the default; introspection (3.10) is a deployment's
  opt-in, `mode = "introspection"`, for opaque tokens from an issuer that
  mints no JWS, with a bounded cache in front of the endpoint.
- **Evaluate an authorization policy.** Roles, attributes, purpose of use
  and consent are "a lower-level responsibility in the access control
  stack" the scopes do not model (`smart scopes-and-launch-context`, SMART's
  scopes are used to delegate access), so `ferrohealth-smart` hands the
  verified `Access` on and decides nothing more. The policy decision (RBAC
  and ABAC, Cedar, a remote PDP) belongs to `ferrohealth-authz`, the second
  crate of this repository, and FerroEHR's `authz/` moves there (owner
  decision 2026-10-25).
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
| Refusal reason on the wire | no | `error_description` | one challenge, a body per cause | a stable code per cause in the body | a stable code as `error_description` (3.7) |
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
  9700 §4.9.3 names is sender-constraining, which an issuer turns on with
  `sender_constraint = "required"` (3.15). A DPoP proof is single-use within
  its window, across replicas only when the product supplies a shared
  replay store.
- **Clock skew.** `exp` and `nbf` take the configured leeway, at most five
  minutes; a token issued in the future beyond the leeway is refused; the
  skew never widens by configuration beyond the bound (3.3).
- **Credential leakage through the product.** The audit line carries no
  token, no secret and no claim beyond three; every credential type redacts
  its `Debug`; a refusal names no claim and no scope; a token is read from
  the header only (3.3, 3.6, 3.7; `rfc9700 §4.9.3`).
- **The reverse proxy.** A deployment that terminates TLS in front of a
  product must sanitize inbound headers and protect the link to the product
  (`rfc9700 §4.13`); the library reads no `X-Forwarded-*` header and reads
  the credential from one header, `Authorization` unless the product names
  another for its edge proxy (3.3). A product that names one owes the
  sanitizing of that header at the proxy, because whatever arrives in it is
  checked as the caller's credential.
- **The issuer itself.** The issuer is trusted entirely: a compromised
  authorization server mints valid tokens for every product that trusts it.
  That is the OAuth model, and the mitigation is operational (one issuer per
  deployment, its keys rotated, its audit read), not the library's.
- **Several issuers.** A section that trusts several issuers trusts each
  only for its own tokens: the claims roles are read from hold for the
  issuer whose table names them, so one issuer cannot mint the role another
  was trusted for (`rfc7519 §4.1.2`; 3.11; GHSA-pfgx-xq28-2629).

## 9. Decision register

| Decision | Ground | Owner items |
|---|---|---|
| `ferrohealth-smart` is a library, a resource server and a credential client, never an authorization server | owner decision 2026-10-19, kept for the three library crates by the owner decision of 2026-11-16 | none |
| The repository is FerroSMART again, a FerroHEALTH product: the server in `app/ferrosmart`, the three libraries in `crates/` under their `ferrohealth-*` names, and the product's own yellow brand | owner decision 2026-11-17, replacing the rename to FerroAUTH of 2026-10-25 | none |
| Cedar and the remote PDP stay features of `ferrohealth-authz` with no change in behaviour, and their future is decided after FerroEHR v6 | owner decision 2026-11-17 | the owner decides after FerroEHR v6 |
| FerroSMART, a SMART App Launch 2.x authorization server, is built in this repository, licensed BUSL-1.1 and shipped as its own OCI image; it is the one component that issues tokens and holds signing keys, and any OpenID Connect IdP upstream serves login only | owner decision 2026-11-16: no IdP the family supports issues real SMART tokens (FerroHEALTH/FerroEHR#5827) | a deployment that wants SMART launch points its products' issuer at FerroSMART (section 13) |
| The crate is licensed BUSL-1.1 | It is hand-written code that implements the specifications above, which is the family's rule for its own code; only generator-emitted code (`fhir-types`, `hl7v2-types` in FerroBRIDGE) is published under Apache-2.0, because it is emitted from CC0 inputs and three servers depend on it. `ferrohealth-smart` emits nothing and is consumed by the family's own products (owner decision 2026-10-19). `docs/VERSIONS.md` records the licence row and `scripts/checks/versions.sh` fails on any other claim. | none |
| Machine-to-machine traffic is the client credentials grant, beside the onward grants and federation tokens; HTTP Basic is a person's credential and carries no `system/` scope; no static bearer token and no API key | owner decision 2026-10-19; owner ruling 2026-11-05 on Basic (#215, #274) | none |
| The `private_key_jwt` key is a client credential, held under `[<lane>.credentials.oauth]`, and is the one private key the library can hold; "never holds a signing key" means never a key that signs an access token, and this key signs only the product's own client assertion (owner decision 2026-10-19) | `rfc7523 §2.2`; the assertion authenticates the client to the token endpoint and no resource server accepts it as an access token (`rfc9068 §4`, the `typ` and `aud` checks) | none |
| Asymmetric algorithms only; HMAC and `none` refused; FerroEHR's `hmac_secret` source removed | `rfc8725 §3.1`, `§3.2`; `rfc9068 §2.1`, `§4` | a FerroEHR deployment on an HMAC secret must move its authorization server to published keys before the FerroEHR migration |
| `audience` is required, as a list | `rfc9068 §4`; `rfc8725 §3.9` | a FerroTERM deployment that set no audience must set one |
| One `401` for every invalid credential, naming nothing; `403` naming no scope | `rfc6750 §3.1`; `rfc9068 §4`; the omissions are our own design | none |
| `503` when the key set cannot be read | our own design | none |
| FerroSMART authenticates to an upstream provider by `private_key_jwt` by default, and by `client_secret_basic` where the administrator chooses it per provider (13.22) | owner decision 2026-11-19 (FerroHEALTH/FerroSMART#679), reversing the `private_key_jwt`-alone decision of 2026-11-17 (#619); `oidc core §9` | a deployment that chooses the secret keeps it in a `_file` |
| FerroSMART speaks standard SAML 2.0 upstream beside OpenID Connect, the Web Browser SSO profile with the HTTP-Redirect, HTTP-POST and HTTP-Artifact bindings, and ships no national profile (13.26) | owner decision 2026-11-19 (FerroHEALTH/FerroSMART#687, #688) | none |
| The `patient` claim is read from the access token when present | our own design (SMART places the context in the token response and the introspection response) | none |
| Only `scope` counts, as one string | `rfc9068 §2.2.3` names `scope`; `scp` is no specification's (owner decision 2026-10-19, #805) | none |
| Product scopes (`ferrobridge.operator`, `ferroterm/admin`) are renamed to a form SMART's Extensibility section admits, a `__` prefix or a full URI, during each product's migration | `smart scopes-and-launch-context`, Extensibility (owner decision 2026-10-19) | each product's migration names the new scope and the deployments that must update their authorization server |
| Granular scopes grant nothing without a product evaluator | the safe reading of "MAY be ignored" | none |
| An access token's `jti` is read, not tracked; DPoP-bound (`rfc9449`) and certificate-bound (`rfc8705 §3`) tokens are verified per issuer, `sender_constraint = "required"` admits a bound token alone, a `cnf` token is never a plain bearer token, the `htu` is compared with the external URL the product names, and the proof `jti` is recorded in a product-supplied `ReplayStore` whose in-memory default holds per replica (3.15) | `rfc9700 §4.9.3`; `rfc9449 §4.3`, `§6`, `§7`, `§11.1`; `rfc8705 §3`; the store, the window values and the refusal of an unknown `cnf` method are our own design (FerroHEALTH/FerroSMART#220, which replaces the owner decision of 2026-10-19 that kept both in FerroFED) | a product with more than one replica supplies a shared `ReplayStore` (FerroHEALTH/FerroFED#1637); a surface admitting `DPoP` sets `[auth.dpop] external_url` |
| `resource` is the RFC 8707 resource indicator, sent when configured; `audience` has no specification and is sent only when configured | `rfc8707 §2`; FerroBRIDGE sends both today | none |
| The `kid` of the product's own JWK is configured, or defaults to the RFC 7638 SHA-256 thumbprint | `rfc7638 §3`; the default is our own design | none |
| A caller's roles are read from the RFC 9068 §2.2.3.1 claims, or the paths a deployment names, and a Basic user's from the product's grant; a route table states role requirements beside scope requirements, matched without regard to ASCII case | `rfc9068 §2.2.3.1`, `rfc7643 §2.4`, `§4.1.2`; the matching and the requirement forms are our own design (owner decision 2026-10-25: authentication and the granted subject belong in this crate) | a product that read roles itself (FerroEHR's claim paths and Basic role table) moves them to `[auth] role_claims` and its Basic grants (3.4) |
| The crate parses (with its own `openehr::smart_scopes`, which moved here from `openehr-sdt` and builds dependency-free behind `openehr-scopes`, for the browser too) and enforces the SMART on openEHR grammar beside the FHIR grammar; the product's route table declares which applies per route | owner decision 2026-10-19, the move 2026-10-27; `soe master07`, `master08`; the rules the draft leaves open are listed in 3.9 as our own design | a product that named `openehr_sdt::smart_scopes` names `ferrohealth_smart::openehr::smart_scopes` |
| SMART on openEHR is DEVELOPMENT: pinned by commit, its status checked on every vendor run, upstream read weekly, and every upstream change re-vendored and recorded here as a decision naming what changed | the draft's `manifest_vars.adoc`; no release stabilises it | none yet: the draft last changed on 2026-07-19 (amendment record 1.1.0) |
| A request is the natural person's own access only for a `Patient` caller whose `fhirUser` is the `Patient` its `patient` launch context names, with no actor; a Basic user is never the person (3.13) | Regulation (EU) 2025/327 Art 5, 9 and 4(2); `smart scopes-and-launch-context` (Patient-specific scopes leave *who* open; Scopes for requesting identity data); our own design (#215, owner decision 2026-11-19, #805) | a product reads `Caller::is_the_person` and keeps no reading of its own |
| The `ehrId` of the launch context is read from an `ehrId` claim when the issuer carries it in the token | our own design, as `patient` in 3.3; the draft places it in the token response (`soe master07`, Context Selection) | none |
| An enabled `[auth]` with Basic users and no issuer is a Basic-only surface; an enabled section that admits no credential is refused at load | our own design, fail closed; asked by the FerroEHR migration (#43) | none |
| A blank `sub` is refused, by the token check and by the gate over every verifier | `rfc9068 §2.2`; `rfc7519 §4.1.2` (#41) | none |
| A bearer value outside `b64token` is `invalid_token`; the reason of every refusal reaches the product as a typed `Reason`, never the wire | `rfc6750 §2.1`, `§3.1`; the omission is our own design (#47) | none |
| Verified Basic credentials may be cached for a configured TTL under an HMAC of the credential | our own design, FerroEHR's (#47) | none |
| `[auth]` and `[[auth.basic.users]]` take no product extension fields; policy configuration belongs to `ferrohealth-authz`, where FerroEHR's `[authz]` moves | `deny_unknown_fields` refuses a mistyped or retired key (4); policy stays out of `ferrohealth-smart` (6) (#49, not planned; owner decision 2026-10-25 on `ferrohealth-authz`) | none |
| A plain-`http` issuer on a host that is no loopback stays refused, with no development switch; a development authorization server gets TLS | `rfc8414 §2`; `discovery §3` (orchestrator decision 2026-10-20 on the FerroEHR migration) | none |
| `ResourceServer::lazy` reads the issuer on its first token, a failed read answering `503` and not repeated inside the refresh interval; `discover` stays the eager default and both return `Send` futures | our own design, FerroFED's (#55) | none |
| A product may name the header the credential travels in, schemed or bare; the default stays `Authorization` and the rules of 3.3 hold in any header | `rfc6750 §2.1`, `§3.1`; `rfc9700 §4.13` puts the sanitizing on the proxy (#56) | a deployment that names a header sanitizes it at its proxy |
| A product verifier reports an upstream failure as `Rejection::Upstream`, answered `503` like an unreadable key set | our own design (#57) | none |
| The token client authenticates with mutual TLS (`tls_client_auth`, `self_signed_tls_client_auth`), uses the mTLS alias of a discovered token endpoint, adds configured trust roots, and takes a product `reqwest::Client` | `rfc8705 §2`, `§5` (#58); certificate-bound access tokens at the resource server stay product-specific | none |
| The assertion `aud` and `typ` follow the security profile and are never configured: the token endpoint under `JWT`, and under FAPI 2.0 the issuer as a string under `client-authentication+jwt`; the plain grant deviates from RFC 10070 §4 | SMART App Launch 2.2.0, Client Authentication: Asymmetric, Request; FAPI 2.0 §5.3.3.1; `rfc10070 §4`; SMART 2.2 governs a SMART client (owner, 2026-11-16, #529, #528) | a product that set `assertion_audience` deletes it; a FAPI 2.0 grant needs no change |
| The RFC 9470 step-up challenge is a crate refusal, with `acr_values` and `max_age`, and the crate checks `acr` and `auth_time` against the product's requirement | `rfc9470 §3`, `§6`; what a resource requires is the product's (#60) | none |
| `Caller` carries a typed extension map a resource server or a product verifier fills; the configuration sections still take no product field (#49) | our own design: the verifier that routed the token already knows the issuer's policy, and the crate reads no extension (#61) | none |
| `Caller::basic_user_in` and `Requirement::basic_users` answer whether a Basic caller is one of a list | our own design (#62) | none |
| `[[auth.basic.users]]` holds the credential alone; a Basic user's scopes and roles are the product's to grant, from its configuration through `config::BasicGrants` or from its data through `Caller::with_granted_scope` and `Caller::with_granted_roles` | our own design: policy stays out of the shared credential table, so a product that keeps it as data drops the keys (#479, FerroEHR #5438) | FerroEHR drops `roles` and `scopes` and grants them to the admitted caller; FerroBRIDGE, FerroTERM and FerroPIX move them into a `BasicGrants` table of their own configuration and call `PasswordStore::with_grants` |
| The authorization server's registry is the one list of clients: a token from a trusted issuer whose `aud` names this resource server admits its client, an RFC 8693 actor is read as asserted, and a caller reaches only what its scopes grant; `first_party_clients`, `delegates`, `audience_delegates`, `scopeless_subjects` and `issuer_client_is_person` are unknown keys (3.14) | `rfc9068 §4`; `rfc8707`; `rfc8693 §4.1` (#804) | a product deletes the five keys; FerroEHR reads `[auth]` as `AuthSection` and drops its `Standing` |
| The outcome of a Basic check says whether the verified-credential cache admitted it | our own design (#63) | none |
| Concurrent Basic cache misses for one credential share one derivation; each entry's lifetime is jittered down by up to a tenth of `cache_ttl`, and one request refreshes it in its last tenth | our own design: FerroEHR measured the expiry burst as its capacity knee (FerroEHR #5742, #498) | none |
| The metadata `issuer` is compared as exact text; a product may also hold the configured issuer to its canonical URL form | `rfc8414 §3.3`, `§4`; the canonical form is our own design (#67) | none |
| A metadata document whose objects repeat a member name is refused | `rfc8259 §4` leaves the meaning to each parser; the refusal is our own design (#69) | none |
| A product may refuse metadata whose endpoints are off the issuer's origin; the check is opt-in | `rfc6454 §4`, `§5` define the origin; RFC 8414 places no endpoint, so the policy is our own design (#68) | none |
| Token introspection is a deployment's opt-in (`mode = "introspection"`), under client authentication or a grant's bearer token, with `scope`, `client_id` and `exp` required, `iss` and `aud` checked when present, and a response without `sub` read as the client's | `rfc7662 §2.1`, `§2.2`, `§4`; `smart token-introspection`; `rfc9068 §2.2` | none |
| `role_claims` sit on each issuer table; the string forms, bare or `<issuer>#<value>`, are refused at load | `rfc7519 §4.1.2`; our own design (#215, after GHSA-pfgx-xq28-2629) | a deployment moves `role_claims` onto its issuer tables |
| Every issuer is a SMART authorization server unless its table declares `kind = "federation"`; a SMART issuer's token is read from its standard claims as `System` (`sub` its `client_id`) or a user named by the type of their `fhirUser` (`Patient`, `Practitioner`, `PractitionerRole`, `RelatedPerson`, `Person`, or `User` with none), with `patient` the launch context and an RFC 8693 `act` the actor beside them; presets, profile files, vendor keys and the `persons`, `patients` and `machines` kinds are gone; a Basic credential is always a `User` (3.14) | `rfc9068 §2.2`, `§4`, `§5`; `rfc8693 §4.1`; `smart scopes-and-launch-context`, `fhirUser`; Regulation (EU) 2025/327 Art 4(2), 23; owner decision 2026-11-23 (#805) | a product trusts FerroSMART with an `[auth.issuer.<name>]` table naming only its issuer, drops `kind`, `preset`, `profile_file`, `[auth.idp]` and every vendor profile key, and matches the new `CallerKind` |
| A SMART issuer's login is resolved to its party through a `PartySource` the product supplies, once per request with no cache, keyed by the token's `sub` in the canonical form of its `identifier_type`, against the identifiers of one `[auth.issuer.<name>.party]` table's `identifier_issuer`; two matches are `Ambiguous`, a source failure is an error and never `Unbound`, and the outcome is the product's to answer (3.17) | `oidc-core §5.6.2`, `§5.7`; `rfc7519 §4.1.2`; the binding is our own design (#216, owner ruling 2026-11-05 on the cache) | a product binds its SMART issuer with an `[auth.issuer.<name>.party]` table, implements `PartySource`, maps each Basic user to a key, and answers each outcome |
| A SMART issuer's `[auth.issuer.<name>.attributes]` table reads the IHE IUA professional attributes and purposes of use, from claims or constants and, with `authorization_details_purposes`, the `system\|code` of each `authorization_details` entry, onto every professional user as `Caller::attributes`, and the purposes of use alone onto every other caller; a claim of the wrong shape refuses the token, and a coding with an empty code names none (3.14) | IHE IUA §3.71.4.2.2.1.1; `rfc9396 §2`; FHIR R4 datatypes.html; our own design over them (#376, #438) | a product reads the professional, the organisation and the purposes from `Caller::attributes` and drops its own IUA claim parser |
| The discovery document describes the issuer `[auth] described_issuer` names, which must be trusted and have metadata; else the one SMART issuer with metadata; several without a name, or none, are refused; the table order never decides (3.8) | `smart conformance`, Metadata (`authorization_endpoint` is where a user launch starts); the choice among several is our own design, settled in FerroEHR (FerroHEALTH/FerroEHR#5426), moved here (#469) | a product offers each issuer as a `Candidate` and serves the document of the one `describe` returns |
| An active introspection response is held until its `exp` and at most `cache_max_age`, keyed by the token's SHA-256, in a bounded cache; an inactive one is never held | `rfc7662 §4` ("MUST NOT be cached beyond" `exp`); the bounds are our own design (FerroBRIDGE #533) | none |
| Onward tokens are obtained by token exchange or the JWT bearer grant as the issuer's profile names, refused unless they pass the onward check of 3.16, cached by issuer, grant, subject and actor token, target, scope and extra parameters until the earlier `exp` (unless the onward table sets `cache = false`, which exchanges on every call for a performance self-test and never in production, #299), and never refreshed; a patient's own token is exchanged for a token that keeps its patient context | `rfc8693 §2.1`, `§2.2`, `§4.1`; `rfc7523 §2.1`, `§2.2`; `rfc8707 §2`; the check, the cache and the profile keys are our own design (#217) | a deployment sets `max_onward_lifetime` on each onward issuer, and `exchanges_from` and `person_mapping` on a federation issuer's table |
| The eHDSI IdA and TRC are checked in this crate behind `ehdsi-assertion`, by our own exclusive canonicalization over `roxmltree` and `x509-parser` with `aws-lc-rs` verifying, in one accepted signature shape against wrapping; a trusted signer is an issuer URI with its seal certificate, revocation is the deployment's, and an inclusive prefix outside SAML Profile 10.0.0 §1.4.2 or a canonicalization other than Exc-C14N is refused (3.18) | eHDSI Cryptographic Algorithms 9.0.0 §2, §4.1; SAML Profile 10.0.0 §2, §4; X.509 Certificates Profile 7.0.0 §2.4, §3.1; SOG-IS ACM 1.3 §4.1, §5.2; the shape, the caps and the trust set are our own design (#294) | an authorization server acting for NCPeH-A compiles `ehdsi-assertion` and supplies the SMP-published seal certificates |
| An `@ID` is accepted as `urn:uuid:` or `_` followed by a UUID | SAML Profile 10.0.0 §2.1 writes a URN-encoded UUID, which SAML 2.0 Core §2.3.3's `xs:ID` cannot hold; accepting both is our own design (#294) | none |
| An eHDSI exchange is admitted once: the `ReplayGuard` keys it by the issuer and `ID` of the IdA and, past the discovery phase, of the TRC, and keeps it until the earliest window or session end plus 60 s; a guard is required to build a `Validator`, and one that cannot answer admits nothing | RFC 7522 §3, item 6; eHDSI Messaging Profile 10.0.0 §5.5.1 (the IdA is a supporting token) and SAML Profile 10.0.0 §6 (non-normative, the IdA's session); keying by the exchange is our own design | the authorization server acting for NCPeH-A supplies a store its replicas share (FerroHEALTH/FerroSMART#317) |
| An eHDSI assertion whose `InclusiveNamespaces PrefixList` names a prefix outside SAML Profile 10.0.0 §1.4.2, such as the `xs` OpenSAML signers often list, is refused | eHDSI Cryptographic Algorithms 9.0.0 §4.1: "other prefixes than the ones defined in [SAML Profile] MUST NOT be used" | an NCP-B whose signer lists `xs` fixes its signer |

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
- sender-constrained tokens: the RFC 9449 Figure 2, 4, 9, 13 and 14 and
  RFC 8705 Figure 2 and Appendix A examples, each check of `rfc9449 §4.3`
  as its own refusal, the replay refusal over a shared and an in-memory
  store, the certificate binding, and the `cnf` token under `Bearer` (3.15);
- the onward grants: RFC 8693 §2.3 Figures 2 and 3 and Appendix A Figures
  10 to 18, RFC 7523 §4 with the §2.2 client assertion, then every check of
  3.16 as its own refusal under token exchange and the JWT bearer grant
  against a harness token endpoint, the federation route, and the cache
  (3.16);
- **The request.** `request::Subject` is read from the caller
  `ferrohealth-smart` admitted: its subject id, its caller kind (3.14), roles
  (3.11), scopes, and the claims a product names as subject attributes. `request::Request` names an
  action, a resource type, resource attributes and context attributes. A
  resource attribute may be a set, when one operation touches several objects;
  the engine decides every combination of one value per set and permits only
  when every combination is permitted, the first deny ending the evaluation.
  An empty set is refused when the request is built, since it would leave
  nothing to decide. No specification governs the fan-out: our own design.
- **The decision.** `request::Decision` is `Permit` or `Deny`, each with the
  policies that made it. An engine that cannot decide answers
  `engine::AuthzError`, never a decision, and a product answers that as a
  fault of its own (a `500`): the PDP decides (`nist-sp-800-162 §3.2.1`), and
  failing closed when it cannot is our own design.
- **Cedar** (feature `cedar`). Policies are in the Cedar language
  (`cedar-docs`, the language reference): deny by default, a `forbid`
  overriding every `permit`. The schema is written from the product's
  `cedar::Model` (the subject attributes, each resource type with its
  attributes, each action with the resource types it applies to, the context
  attributes), so a policy can name only what the product sends; the principal
  is `User` with `roles`, `scopes` and the caller `kind` by the name the audit
  line records, which the model may not redeclare. Policies are validated strictly at load
  and at every reload; a reload that does not validate keeps the set in force.
  Cedar skips a policy that errors during evaluation and reports it in the
  diagnostics; the engine answers such an evaluation with an error, since a
  skipped `forbid` would otherwise stop forbidding. Entity ids are built with
  the API, never by formatting a policy string, so no subject can forge
  another principal.
- **A remote PDP** (feature `remote`). One `POST {server}{policy}` per
  combination with a flat JSON object of the attributes the resource type's
  binding names; `200` permits, a `4xx` denies, and every other answer, a
  redirect included, is no decision. Under a client credentials grant the
  call carries `ferrohealth-smart`'s token and is sent once more under a new
  token on a `401`. `RemotePdp::with_client` takes the product's HTTP
  client, built from the integration's endpoint table with its TLS, and that
  table's `retry`: a call that did not reach the point, timed out or met a
  `5xx` is tried again with a doubling, bounded backoff, and a `4xx`, a
  redirect or a refused token is not. The wire contract and the retry rule
  are our own design.
- **Their future.** The Cedar engine and the remote PDP stay as they are,
  features of this crate with no change in behaviour. The owner decides
  their future after FerroEHR v6 (owner decision 2026-11-17).
- **Dependencies.** Without a feature the crate holds the request model and
  the trait alone. `cedar` adds `cedar-policy`, `arc-swap` and the Tokio
  timer of the reload; `remote` adds the HTTP client through
  `ferrohealth-smart`'s `fetch` and the Tokio timer of the retry backoff.
- **Releases.** The crate keeps its own version line and changelog,
  released by the tag `ferrohealth-authz-vX.Y.Z` through the same release and
  publish lanes as `ferrohealth-smart` (`docs/release.md`).

| Decision | Ground | Owner items |
|---|---|---|
| The policy decision is its own crate in this repository, `ferrohealth-authz`, on its own version line, reading `ferrohealth-smart`'s subject | owner decision 2026-10-25; `nist-sp-800-162 §2`, §3 | FerroEHR moves its `authz/` here and deletes its copy |
| A request with a set attribute is permitted only when every combination is; an engine that cannot decide answers an error the PEP fails closed on | our own design | none |

## 12. `ferrohealth-session`: the console sign-in and session

Every operator console of the family signs its operator in at an OpenID
Provider and keeps a session the browser holds a cookie to. The relying
party itself is `ferrohealth_smart::oidc` (#131), which keeps no state
between calls; `ferrohealth-session` keeps that state, in one crate in place
of the five copies the consoles of FerroBRIDGE, FerroFED, FerroPIX and
FerroTERM and the FerroEHR viewer carried (owner decision 2026-11-03, #177).
The relying party also checks a Logout Token a provider posts
(`RelyingParty::logout_token`, Back-Channel Logout 1.0 §2.6), which
FerroSMART uses to end the `online_access` grants of an upstream login
(13.6 item 7); the optional `jti` and session checks of §2.6 are the
caller's, which holds the sessions.

- **The flow.** `GET /login` mints the `state`, the `nonce` and the PKCE
  verifier through the relying party and keeps them as a pending sign-in
  with the page `?return=` names, held to one of the console's own
  (`rfc3986 §4.2`); `GET /auth/callback` takes it once, and the relying party
  holds the returned `state` to it (`rfc6749 §10.12`), exchanges the code
  with the verifier (`rfc7636 §4.5`) and checks the ID Token (OpenID Connect
  Core 1.0 §3.1.3.7). `POST /logout` ends the session, revokes its refresh
  token, or its access token when there is none (`rfc7009 §2.1`), and sends
  the operator to the end-session endpoint with the session's ID Token as
  `id_token_hint` (RP-Initiated Logout 1.0 §2); a session that holds no ID
  Token was never signed in at the provider and lands on the console's
  signed-out page. The four paths are the same on every console.
- **The stores.** `memory` keeps two bounded pools in the process: a full
  pending pool drops its oldest sign-in, and a full session pool refuses a
  new session and keeps every live one. `sealed` keeps the whole record in
  one cookie sealed with AES-256-GCM (the `cookie` crate's private jar), so
  a console that runs as several instances with no shared store opens it
  anywhere; a cookie that does not open is no session, and one larger than
  the 4096 bytes a browser keeps (`rfc6265 §6.1`) is refused when it is
  sealed. Every cookie is `HttpOnly`, `SameSite=Lax` and, unless turned off,
  `Secure` with the `__Host-` prefix (RFC 6265bis §4.1.3.2, §5.4.7).
- **The lifetimes.** The absolute lifetime runs from the sign-in time the
  session carries and nothing moves it; the idle lifetime runs from the last
  request that counted as activity and never past the absolute end; an
  access token no refresh token can replace ends the session when it
  expires. The session watch (`GET`/`POST /session`) answers FerroUI's wire
  `{"idle": s, "absolute": s}`: a `GET` never counts as activity, a `POST`
  does, and `401` says the session is gone.
- **The refresh.** A memory session that holds a refresh token renews its
  access token within 60 seconds of its expiry, at most half its lifetime
  (`rfc6749 §6`), one refresh per session at a time so a rotated refresh
  token is spent once; a refusal ends the session, and a provider that is
  not reached is reported, never read as a success.

| Decision | Ground | Owner items |
|---|---|---|
| The console sign-in and session is its own crate in this repository, `ferrohealth-session`, on its own version line, over `ferrohealth-smart`'s relying party | owner decision 2026-11-03 | each console moves onto it and deletes its copy |
| A sealed store refuses `offline_access` when the configuration loads | `rfc6749 §10.4`: a refresh token sealed into a browser cookie outlives a sign-out that cannot reach it (owner decision 2026-11-03) | a console that wants refresh tokens uses the memory store |
| A sealed store without a key is refused when the configuration loads; there is no per-process key | our own design, fail closed (owner decision 2026-11-03) | the FerroEHR viewer's deployments set `session.key` |
| One route set, `/login`, `/auth/callback`, `/logout` and `/session`, on every console | our own design (owner decision 2026-11-03) | FerroTERM and the FerroEHR viewer change the redirect URI registered at their provider |
| The store, the lifetimes and the watch route | no specification governs them: our own design, held to the OWASP Session Management Cheat Sheet | none |

## 13. FerroSMART: the SMART authorization server

FerroSMART is the family's SMART App Launch 2.x authorization server
(`smart conformance`, Actors; `rfc6749 §1.1`). The owner decided on
2026-11-16 to build it, for these reasons and on these terms.

### 13.1 Why the family builds one

The products need tokens that carry SMART: the `launch` and `launch/patient`
scopes, the patient and encounter context in the token response, v2 scopes
chosen per request, and asymmetric client authentication. No identity
provider the family supports issues those. ZITADEL drops the SMART scopes
and `launch`, puts no `scope` claim in its access tokens and refuses a
client that authenticates in the asymmetric form `smart client-confidential-asymmetric`
describes (FerroHEALTH/FerroEHR#5827). Keycloak, as the family configures
it, gives each client a fixed scope set and has no launch context. SMART
has to work whichever identity provider a hospital runs, so the family
supplies the authorization server and leaves login to the identity
provider.

FerroSMART is required for FerroEHR v6.0.0: v6.0.0-rc1 waits for it,
because v6.0.0 must be the full, proper setup (owner decision 2026-11-16,
FerroHEALTH/FerroEHR#5844). Keycloak, ZITADEL, Microsoft Entra ID and Okta
each run upstream of FerroSMART, with cited configuration and a test:
compose examples for the first two, contract tests against the published
discovery and token shapes for the two SaaS providers.

### 13.2 What it is, and what it is not

- **The one component that issues tokens and holds signing keys.** The
  library crates (sections 0 to 12) stay resource-server, policy and
  session crates and never issue a token; FerroSMART uses them, and no
  product links FerroSMART.
- **An authorization server, never an identity provider.** A person logs in
  at an upstream OpenID Connect provider, any one, named by configuration
  (its discovery URL, the client FerroSMART is registered as, and the
  mapping of its claims to the user and to `fhirUser`). FerroSMART keeps no
  password.
- **Standards only on every interface.** SMART App Launch 2.2, OAuth 2.0
  (RFC 6749 with the OAuth 2.1 consolidation and RFC 9700), OpenID Connect
  Core and Discovery, RFC 9068, 7662, 7009, 7523, 8414, 7591, 7636, 9126
  (PAR) and 8693; DPoP (RFC 9449) and FAPI 2.0 follow.
  No interface requires a Ferro-specific claim or parameter.
- **Vendor neutral on both sides.** Any OpenID Connect provider upstream;
  any FHIR or openEHR server downstream, which reads FerroSMART's tokens as
  RFC 9068 JWTs whose `aud` is its base URL, or by RFC 7662 introspection.
- **Policy is content.** The role-to-scope mapping, the client registry, the
  consent text and the branding are configuration or database rows, never
  code.
- **Stateless replicas.** Authorization codes, refresh tokens, launch
  contexts and consents live in PostgreSQL, so any replica answers any
  request; signing keys rotate, with a KMS or HSM as an option.
- **Its own audit.** Every login and every token request is an audit
  record, a FHIR R4 `AuditEvent` written through `ihe-atna` into
  FerroSMART's own PostgreSQL store (#534). A token request is the ITI-71
  audit event in the form of BALP 1.1.4's profile `IHE.IUA.71`: type
  `110114`, subtype `ITI-71`, the client (`110150`) and the authorization
  server (`AuthzOauthService`) as agents, the person as `agent:user` when
  one logged in, and the one `token-request` entity holding the HTTP
  request with the values of `code_verifier`, `code`, `refresh_token`,
  `client_secret` and `client_assertion` left out. A login at the upstream
  provider is a DICOM User Authentication event of type `110122` Login
  (DICOM PS3.15 A.5.3.12), whose `AuditEvent` form is our own design. An
  issued token and its record commit in one transaction; a refusal or a
  login commits its record alone, and a request whose record cannot be
  committed fails: the token endpoint answers `503` with no token. With
  `[ferrosmart.audit.feed]` the store is the outbox the `ihe-atna`
  forwarder delivers from to an Audit Record Repository over the ITI-20
  ATX: FHIR Feed; a record the repository refuses is kept and stamped for
  an operator. `GET {issuer}/audit` reads the records by `subject`,
  `client`, `event`, `outcome`, `since` and `until` as a FHIR `searchset`
  Bundle a page at a time, its `next` link carrying a keyset cursor
  (FHIR R4 Bundle.link), with a bearer token
  FerroSMART issued for its own issuer with `system/AuditEvent.rs`
  (Regulation (EU) 2025/327 Art 9 has the logs accessible; the parameters
  are our own design).

  The other writes FerroSMART makes for a person or a client each commit
  with a record of their own in one transaction, through the store's
  `Transaction`, whose commit refuses a write with no record (#554). An
  upstream session ended by a back-channel logout is DICOM User
  Authentication with `110123` Logout (DICOM PS3.15 A.5.3.12). The rest
  have no IHE or BALP pattern (BALP's `IHE.BasicAudit.AuthZconsent` needs
  a patient and the requesting organisation, which an app's authorization
  consent does not have), so their form is our own design: DICOM `110114`
  User Authentication or `110113` Security Alert, with a subtype from
  FerroSMART's code system `urn:ferrosmart:audit-event`:

  | Write | `type` | subtypes | `action` |
  |---|---|---|---|
  | a code issued, with its basis: `page`, `remembered`, `administrative` or `first-party` | `110114` | `authorization-code` | `C` |
  | a consent remembered | `110113` | `110137`, `consent-remembered` | `C` |
  | an app disconnected at the management page, with the remembered consent and the grants it ended | `110113` | `110137`, `consent-withdrawn` | `D` |
  | a code issued to a professional with no page, on the administrator's registration (13.6 item 6) | `110113` | `110137`, `consent-administrative` | `C` |
  | a code issued with no page for a first-party app (13.6 item 6) | `110113` | `110137`, `consent-first-party` | `C` |
  | an access token revoked (RFC 7009) | `110113` | `token-revoked` | `D` |
  | a grant revoked by its refresh token (RFC 7009 §2.1) | `110113` | `grant-revoked` | `D` |
  | a refresh token rotated | `110114` | `refresh-rotated` | `E` |
  | a rotated refresh token repeated by its client within the window, answered with the same successor | `110114` | `refresh-repeated` | `E` |
  | a rotated refresh token reused, its grant revoked | `110113` | `refresh-reused` | `E` |
  | a code redeemed again, its tokens revoked | `110113` | `code-reused` | `E` |
  | an upstream session ended, by a back-channel or front-channel logout | `110114` | `110123` Logout, `session-ended` | `E` |
  | a person logged out at the end-session endpoint, with the online grants it ended | `110114` | `110123` Logout, `logged-out` | `E` |
  | the patient picker's own token issued (13.6 item 4) | `110114` | `picker-token` | `C` |
  | a client registered through the admin API (13.27) | `110113` | `110137`, `client-created` | `C` |
  | a client changed through the admin API | `110113` | `110137`, `client-updated` | `U` |
  | a client disabled, with every grant and token it held | `110113` | `110137`, `client-disabled` | `D` |
  | a disabled client enabled | `110113` | `110137`, `client-enabled` | `U` |

  None of these events is an access to personal electronic health data,
  so none is an access record of Annex II 3.2; the patient
  picker (#516), which reads Patient resources, writes that record through
  `ehds-logging`.
- **The family stack.** It is built on `ferrohealth-server`,
  `ferrohealth-telemetry`, `ferrohealth-config` and `ferrohealth-health`,
  and reuses `ferrohealth-smart` (the scope grammar, token and assertion
  checks) and `ferrohealth-session` (the upstream OpenID Connect login with
  PKCE).
- **Conformance oracle.** The SMART App Launch specification, with the
  Inferno SMART App Launch test kit run as a CI lane.

### 13.3 Where it lives, and its licence

FerroSMART lives in this repository permanently: the owner chose fewer
repositories over a new one. It ships as its own OCI image and the family's
release artefacts (signed, with SLSA provenance and an SBOM), on its own
version line beside the library crates: the tag `ferrosmart-vX.Y.Z`, the
image `ghcr.io/ferrohealth/ferrosmart` on distroless static, and the
`compose.yaml` quickstart beside PostgreSQL (`docs/release.md`, The
FerroSMART release). It is licensed BUSL-1.1, like the
rest of the family's hand-written code. The repository carries the
product's name: it was FerroSMART until the owner renamed it FerroAUTH on
2026-10-25, and the owner made it FerroSMART again on 2026-11-17, a product
and no longer only a library repository.

### 13.4 The sources

The step-1 research (FerroHEALTH/FerroSMART#513) read the vendored corpora
and added what FerroSMART cites and the tree lacked: RFC 6819, 7518, 7591,
8252, 9126, 9207, 9864 and 10070 beside the RFCs of section 2, the OAuth 2.1
Authorization Framework draft (`docs/specs/oauth-v2-1/`, revision 17) and
the Inferno SMART App Launch test kit at release 1.0.3
(`docs/specs/inferno-smart-test-kit/`). Citation keys follow the document's
convention, plus: `oauth21 §4.1.3` is section 4.1.3 of the draft, which is a
work in progress and is cited beside RFC 6749, 6750 and 9700, never in
their place; `oidc core §3.1.2.1` is OpenID Connect Core 1.0; `backchannel §2.6` is
OpenID Connect Back-Channel Logout 1.0; `smart
app-launch`, `smart scopes-and-launch-context`, `smart backend-services`,
`smart client-confidential-asymmetric`, `smart token-introspection` and
`smart conformance` are the page sources under
`docs/specs/smart-app-launch/repository/input/pages/`, cited with the page's
own heading.

The Inferno kit carries its own extraction of SMART App Launch 2.2.0 into
265 server-side requirement rows
(`lib/smart_app_launch/requirements/smart_app_launch_test_kit_requirements.csv`),
of which its STU 2.2 suite checks 53
(`requirements/generated/smart_stu2_2_requirements_coverage.csv`). The
checklist below was built from the specification pages and cross-checked
against that extraction; every row cites the specification, never the
kit. The 210 rows the kit does not check are FerroSMART's own tests.

### 13.5 The requirements checklist

Level is the specification's keyword. Step is the FerroSMART sub-issue
that delivers the row: 2 core and Backend Services (#514), 3 the
authorization code flow (#515), 4 the patient picker (#516), 5 the EHR
launch API (#517), 6 refresh, introspection and revocation (#518). The
User Access Brands rows (`smart brands`) are in 13.23: FerroSMART
publishes the deployment's Brand Bundle at `{issuer}/brands` (#602), and
the `user_access_brand_*` metadata belongs in each FHIR server's own
document (13.8).

**Discovery and metadata**

| Requirement | Level | Citation | Step |
|---|---|---|---|
| RFC 8414 metadata at `/.well-known/oauth-authorization-server` (inserted between host and path), with `issuer`, `authorization_endpoint`, `token_endpoint` and `response_types_supported`; `issuer` equals the issuer identifier | MUST | `rfc8414 §2`, `§3`, `§3.3` | 2 |
| OpenID Connect discovery at `/.well-known/openid-configuration` with `jwks_uri`, `subject_types_supported` and `id_token_signing_alg_values_supported`, which includes `RS256` | REQUIRED | `discovery §3`, `§4` | 2 |
| A SMART configuration document at FerroSMART's own `/.well-known/smart-configuration`, as `application/json` whatever the `Accept` header, every endpoint URL absolute | SHALL | `smart conformance`, Using well-known | 2 |
| The document carries `token_endpoint`, `grant_types_supported`, `capabilities` and `code_challenge_methods_supported` with `S256` and never `plain`; `authorization_endpoint` with a launch capability; `issuer` and `jwks_uri` with `sso-openid-connect` | REQUIRED, CONDITIONAL | `smart conformance`, Metadata | 2 |
| `introspection_endpoint`, `revocation_endpoint`, `scopes_supported`, `response_types_supported`, `management_endpoint` | RECOMMENDED | `smart conformance`, Metadata | 2, 6 |
| `launch_registration_endpoint`, the EHR launch API of 13.17, with the app launch | our own design (additional metadata) | `smart conformance`, Metadata; `rfc8414 §2` | 3 |
| Every scope in `scopes_supported` is supported | SHALL | `smart conformance`, Metadata | 3 |
| With `client-confidential-asymmetric`: `token_endpoint`, `scopes_supported`, `token_endpoint_auth_methods_supported` with `private_key_jwt`, `token_endpoint_auth_signing_alg_values_supported` with `RS384` or `ES384` | SHALL | `smart client-confidential-asymmetric`, Advertising server support | 2 |
| `authorization_response_iss_parameter_supported` is `true` and every authorization response carries `iss` | MUST (when advertised) | `rfc9207 §2`, `§3` | 3 |
| Each listed capability is supported: `launch-ehr`, `launch-standalone`, `authorize-post`, `client-public`, `client-confidential-symmetric`, `client-confidential-asymmetric`, `sso-openid-connect`, `context-banner`, `context-style`, `context-ehr-patient`, `context-ehr-encounter`, `context-standalone-patient`, `context-standalone-encounter`, `permission-offline`, `permission-online`, `permission-patient`, `permission-user`, `permission-v1`, `permission-v2` | SHALL (per listed capability) | `smart conformance`, Capabilities | 2 to 6 |
| The four capability sets (patient and clinician, standalone and EHR launch) | SHOULD support one or more | `smart conformance`, Capability Sets | 3, 5 |
| CORS on the discovery documents for any origin, and on the token endpoint for a client's registered origins | SHALL (browser apps) | `smart app-launch`, Considerations for CORS support; `rfc7009 §2.3` | 2, 3 (13.6 item 12) |

**Client registration and authentication**

| Requirement | Level | Citation | Step |
|---|---|---|---|
| Every app's complete redirect URIs are registered, and the server communicates a `client_id` | SHALL | `smart app-launch`, Register App with EHR | 2 |
| Redirect URIs compared by exact string match, except the port of a native app's loopback URI | MUST | `rfc9700 §2.1`; `rfc8252 §7.3` | 3 |
| Public clients (no authentication), confidential symmetric (`client_secret_basic`, `client_secret_post`) and confidential asymmetric (`private_key_jwt`) | SHALL (per capability) | `smart conformance`, Client Types; `smart client-confidential-symmetric`; `rfc6749 §2.3.1` | 2 |
| Client JWK Sets registered both by URL (`jwks_uri`) and by value (`jwks`); a JWK Set held by value is protected from corruption | SHALL | `smart client-confidential-asymmetric`, Registering a client | 2 |
| Each registered JWK carries `kty` and `kid` and bare key members (`n`, `e`; `crv`, `x`, `y`) | SHALL | same | 2 |
| Signatures validated with at least one of `RS384` and `ES384` (FerroSMART takes both) | SHALL | same | 2 |
| The client assertion is validated by `rfc7523 §3`: signature, `iss` = `sub` = a known `client_id`, `aud`, `exp` at most five minutes ahead, `jti` not seen for that `iss` within the assertion lifetime | SHALL | `smart client-confidential-asymmetric`, Signature Verification; `rfc7523 §3`, `§3.2` | 2 |
| Key resolution: a `jku` header must equal the registered JWK Set URL, otherwise the registered keys; exactly one key matching `kid` and the `kty` of `alg` | SHALL | same | 2 |
| A client's JWK Set is cached no longer than its `Cache-Control` allows | SHALL NOT exceed; SHOULD cache | same | 2 |
| Any authentication failure answers `invalid_client` | SHALL | same; `rfc6749 §5.2` | 2 |
| The assertion's `aud` is a single string equal to the token endpoint URL or the issuer identifier; `typ` is `JWT` or `client-authentication+jwt` (13.6 item 1, a recorded deviation from `rfc10070 §4`) | SHALL (SMART); MUST (RFC 10070) | `smart client-confidential-asymmetric`, Request and Signature Verification; `rfc7523 §3`; `rfc10070 §4` | 2 |
| The symmetric profile is not used for Backend Services | SHALL NOT | `smart client-confidential-symmetric`, Profile audience and scope | 2 |
| Dynamic client registration is encouraged, not required | MAY | `smart app-launch`, Register App with EHR; `rfc7591 §3` | after 9 |

**The authorization endpoint**

| Requirement | Level | Citation | Step |
|---|---|---|---|
| `GET` and `POST` (form) at the authorization endpoint | SHALL | `smart app-launch`, Obtain authorization code; `oidc core §3.1.2.1` | 3 |
| `response_type=code` only; the implicit and password grants are absent | SHOULD NOT (implicit); MUST NOT (password) | `rfc9700 §2.1.2`, `§2.4`; `oauth21 §10` | 3 |
| PKCE with `S256`; `plain` refused; a token request with `code_verifier` is accepted only if the request carried a `code_challenge` | SHALL, SHALL NOT, MUST | `smart app-launch`, Considerations for PKCE Support; `rfc7636 §4.6`; `rfc9700 §2.1.1`, `§4.8.2` | 3 |
| `aud` supported and checked against the FHIR (or openEHR) bases FerroSMART serves; `resource` MAY be a synonym | SHALL; MAY | `smart app-launch`, Obtain authorization code | 3 |
| An invalid `client_id` or `redirect_uri` is shown to the user and never redirected | MUST NOT redirect | `rfc6749 §4.1.2.1`; `rfc9700 §4.11` | 3 |
| `state` returned exactly as received | REQUIRED | `smart app-launch`, Obtain authorization code, Response; `rfc6749 §4.1.2` | 3 |
| The code expires shortly after issue (FerroSMART: 60 seconds), is single-use, and a second valid use is denied and revokes what it issued | SHOULD; MUST deny, SHOULD revoke | `smart app-launch`, Response; `rfc6749 §4.1.2`; `oauth21 §4.1.3`, `§7.5.3` | 3 |
| The decision to grant or deny is the server's, by local policy and optionally the user's input (FerroSMART asks the user unless the administrator's registration answers for a professional, or a first-party app's for any person it represents, 13.6 item 6); a denial is an `access_denied` error response | SHALL | `smart app-launch`, Response; `rfc6749 §4.1.2.1` | 3 |
| The granted scope may differ from the request and is reported | MAY, SHALL report | `smart app-launch`, Obtain access token, Response; `rfc6749 §3.3` | 3 |
| v1 scopes (`.read`, `.write`, `.*`) are processed as `.rs`, `.cud`, `.cruds`, and returned as v1 when granted as v1 | SHOULD | `smart scopes-and-launch-context`, Scopes for requesting FHIR Resources | 3 |
| Undefined or out-of-order interactions may be ignored, replaced or refused | MAY | same | 3 |
| The server's own policies and permissions hold even when a scope would grant more | SHALL | `smart scopes-and-launch-context`, SMART's scopes are used to delegate access | 3 |
| Requested scopes are limited to the minimum, and tokens are audience-restricted | SHOULD | `rfc9700 §2.3` | 3 |
| Clickjacking: the authorization and consent pages refuse framing | MUST (where framing matters) | `rfc9700 §4.16`; `rfc6749 §10.13` | 3 |

**Launch context**

| Requirement | Level | Citation | Step |
|---|---|---|---|
| EHR launch: the `launch` value the EHR passed binds the request to the EHR's context; `launch/` scopes are hints the server MAY ignore | must match; MAY | `smart app-launch`, Launch App: EHR Launch; `smart scopes-and-launch-context`, Apps that launch from the EHR | 5 |
| A granted `patient/` scope establishes a patient in context; a request with `patient/` and no `launch` or `launch/patient` MAY be refused or MAY infer `launch/patient` | SHALL; MAY | same, and Standalone apps | 3, 4 |
| A standalone app's `launch/patient` and `launch/encounter` are provided | SHOULD | `smart scopes-and-launch-context`, Standalone apps | 4 |
| The context arrives as token response parameters: `patient`, `encounter`, `fhirContext` (each item with at least one of `reference`, `canonical`, `identifier`; a `role` never empty; non-SMART roles absolute URIs), `need_patient_banner`, `intent`, `smart_style_url`, `tenant` | SHALL (when in context) | `smart scopes-and-launch-context`, Launch context arrives with your access_token, `fhirContext` | 3, 5 |
| An unsupported `?role=` returns any context for the type | SHOULD | `smart scopes-and-launch-context`, Scopes for requesting context data | 5 |
| SMART on openEHR: `launch/patient` also yields `ehrId`; `launch/episode` yields `episodeId` (experimental) | may be included | `soe master07`, Context Selection; `soe master04`, Capabilities | 4, 5 |
| `authorization_details` of type `smart_on_fhir` for a token valid at more than one base | MAY (experimental) | `smart app-launch`, Authorization Details for Multiple Servers; `rfc9396` | later |

**The token endpoint and the token response**

| Requirement | Level | Citation | Step |
|---|---|---|---|
| `application/x-www-form-urlencoded` POST; `code`, `redirect_uri` (equal to the request's), `code_verifier`; `client_id` for public clients | required | `smart app-launch`, Obtain access token, Request; `rfc6749 §4.1.3`; `rfc7636 §4.5`, `§4.6` | 3 |
| The response carries `access_token`, `token_type` `Bearer`, `scope`, `expires_in` (recommended), optional `id_token` and `refresh_token`, and the context parameters, in the body of `rfc6749 §5.1` | SHALL | `smart app-launch`, Obtain access token, Response | 3 |
| `Cache-Control: no-store` and `Pragma: no-cache` on every token response | SHALL | same; `rfc6749 §5.1` | 2 |
| Access tokens live no longer than one hour (FerroSMART default 300 seconds for every grant) | SHOULD | `smart app-launch`, Obtain access token, Response | 2 |
| Errors are the `rfc6749 §5.2` JSON body | SHALL | `smart backend-services`, Issue Access Token; `rfc6749 §5.2` | 2 |
| Access tokens are RFC 9068 JWTs: signed, never `none`, `typ` `at+jwt`, with `iss`, `exp`, `aud`, `sub`, `client_id`, `iat` and `jti`, and `scope` when one was requested; `RS256` is supported | MUST, SHOULD | `rfc9068 §2.1`, `§2.2`, `§2.2.3` | 2 |
| `sub` of a client credentials token identifies the client and cannot collide with a person's `sub` | SHOULD | `rfc9068 §2.2`, `§5` | 2 |
| The `aud` of the access token is the base the request named, distinct per resource | MUST (distinct `aud`) | `rfc9068 §3`, `§5`; `rfc8707 §2` | 3 |

**OpenID Connect**

| Requirement | Level | Citation | Step |
|---|---|---|---|
| The authorization code flow with SMART's parameters | SHALL | `smart scopes-and-launch-context`, Scopes for requesting identity data | 3 |
| Public keys published as bare JWKs | SHALL | same | 2 |
| `fhirUser` in the `id_token` whenever `openid` and `fhirUser` are granted; a `Patient`, `Practitioner`, `PractitionerRole`, `RelatedPerson` or `Person` URL, absolute or relative to `aud` | SHALL | same | 3 |
| ID Tokens signed with `RS256` | SHALL | same; `discovery §3` | 2 |
| ID Token claims `iss`, `sub`, `aud`, `exp`, `iat`, `nonce` when sent, `auth_time` when `max_age` is requested | REQUIRED | `oidc core §2`, `§3.1.2.1` | 3 |
| `profile` and `email` request `name`, `preferred_username`, `email` and `email_verified`; FerroSMART passes the upstream ID Token's values into its own ID Token when granted, never into an access token, and leaves out what the upstream did not send (owner, 2026-11-19, #676) | MAY (an OP may decline) | `oidc core §5.1`, `§5.4` | 3 |
| `claims`, request objects and UserInfo | MAY | `smart scopes-and-launch-context`, Scopes for requesting identity data | not built: no UserInfo Endpoint, which `oidc core §15.2` requires only of a Dynamic OP (owner decision of 2026-11-19, #650) |
| What every OpenID Provider implements (`oidc core §15.1`) | MUST | `oidc core §15.1` | met, 13.25 |

**Refresh tokens**

| Requirement | Level | Citation | Step |
|---|---|---|---|
| `online_access` refresh lasts while the user remains online; `offline_access` without the user | SHALL (with the capability) | `smart app-launch`, Refresh access token; `smart scopes-and-launch-context`, Scopes for requesting a refresh token | 6 |
| The server decides which client types get offline access | MAY | `smart app-launch`, Refresh access token | 6 |
| A refresh token is bound to its `client_id` and carries the same or fewer grants | SHALL | same | 6 |
| A refresh request's `scope` is a strict subset, or absent for the original scope; the response carries `access_token`, `token_type`, `expires_in`, `scope` (the original's) and the context | SHALL | `smart app-launch`, Refresh access token, Request and Response | 6 |
| A refresh request's `resource` names the token's target, limited by policy to what the grant reaches; an unacceptable one is `invalid_target` and the token is audience-restricted to the one named | SHOULD (audience restriction) | `rfc8707 §2`, `§2.2` | 6 |
| Public clients' refresh tokens are rotated or sender-constrained | MUST | `rfc9700 §2.2.2`, `§4.14` | 6 |
| A rotated refresh token keeps the grant's scope; idle refresh tokens expire | MUST; SHOULD | `oauth21 §4.3.3` | 6 |
| Backend Services issues no refresh token | SHOULD NOT | `smart backend-services`, Enforce Authorization | 2 |

**Backend Services**

| Requirement | Level | Citation | Step |
|---|---|---|---|
| `grant_type=client_credentials` with `private_key_jwt` | required | `smart backend-services`, Obtain access token | 2 |
| The requested scope is mediated to stay within what the client is pre-authorized for | SHALL | `smart backend-services`, Evaluate Requested Access | 2 |
| `expires_in` is required and SHOULD NOT exceed 300; tokens are short-lived | SHALL, SHOULD NOT | `smart backend-services`, Issue Access Token | 2 |
| `scope` reports what was granted; each token covers only what was requested | SHALL; SHOULD | same | 2 |
| An error carries `error_description` or `error_uri` | SHOULD | same | 2 |
| TLS 1.2 or newer on every exchange | SHALL | `smart backend-services`, Obtain access token; `smart client-confidential-asymmetric`, Authenticating to the Token endpoint | 7 |

**Introspection and revocation**

| Requirement | Level | Citation | Step |
|---|---|---|---|
| An introspection endpoint by RFC 7662 | SHOULD | `smart token-introspection`; `rfc7662 §2` | 6 |
| The response carries `active`, and for an active token `scope`, `client_id` and `exp` (consistent with `expires_in`), every launch context parameter of the original response, and `iss` and `sub` (`fhirUser` SHOULD) of an ID Token that was issued | SHALL, SHOULD | `smart token-introspection`, Required and Conditional fields | 6 |
| The endpoint requires authorization; when it does, a SMART bearer token with the introspection scope is accepted and may introspect any client's token | MUST (`rfc7662`); SHALL (SMART, if access-controlled) | `rfc7662 §2.1`, `§4`; `smart token-introspection`, Authorization to perform Token Introspection | 6 |
| An inactive, expired, revoked or unknown token answers `{"active": false}` only | MUST | `rfc7662 §2.2` | 6 |
| A revocation endpoint by RFC 7009: confidential clients authenticate, the token must belong to the client, an unknown token answers `200`, revoking a refresh token revokes its grant's access tokens | MUST, SHOULD | `rfc7009 §2.1`, `§2.2` | 6 |

### 13.6 Where the specifications conflict or are silent

Each item names the decision. "Our own design" marks where no
specification governs.

1. **The client assertion's `aud`: one fixed behaviour.** The texts:
   - SMART 2.2, `smart client-confidential-asymmetric`, Request: the
     client's `aud` is "required: The FHIR authorization server's 'token
     URL' (the same URL to which this authentication JWT will be posted)",
     and `typ` is "required: Fixed value: JWT". Signature Verification: the
     server "SHALL validate the JWT according to the processing
     requirements defined in Section 3 of RFC7523".
   - `rfc7523 §3` item 3, the text SMART 2.2 cites: "The JWT MUST contain an
     'aud' (audience) claim containing a value that identifies the
     authorization server as an intended audience. The token endpoint URL
     of the authorization server MAY be used ... The authorization server
     MUST reject any JWT that does not contain its own identity as the
     intended audience", compared by "Simple String Comparison".
   - `rfc10070 §4` replaces that item for client authentication: "the 'aud'
     (audience) claim value MUST use the issuer identifier [RFC8414] of the
     authorization server as its sole value ... the token endpoint URL of
     the authorization server MUST NOT be used as an audience value. The
     authorization server MUST reject any JWT that does not contain its
     issuer identifier as its sole audience value", and has client
     authentication JWTs "SHOULD be explicitly typed" as
     `client-authentication+jwt`, while "it is NOT RECOMMENDED for servers
     to reject JWTs that do not have explicit types".

   No one behaviour meets both: a SMART 2.2 client must send the token URL,
   and an RFC 10070 server must reject it. SMART 2.2 governs a SMART
   authorization server (owner, 2026-11-16). FerroSMART therefore accepts an
   `aud` that is a single string equal to its token endpoint URL (SMART 2.2,
   and `rfc7523 §3` item 3 as SMART cites it) or to its issuer identifier
   (`rfc7523 §3` item 3, "a value that identifies the authorization server";
   `rfc10070 §4`), each compared by simple string comparison, and refuses an
   array and every other value (`rfc10070 §4`, "sole value"). It accepts
   `typ` `JWT` (SMART 2.2) and `client-authentication+jwt` (`rfc10070 §4`)
   and refuses an assertion with no `typ` or another one. This is fixed
   behaviour with no setting. Accepting the token URL deviates from
   `rfc10070 §4`'s server MUST; FerroHEALTH/FerroSMART#528 is the upstream
   report. `ferrohealth-smart`'s own client follows the same reading
   (3.5, #529): the token URL under `JWT`, and under FAPI 2.0 the issuer
   (FAPI 2.0 §5.3.3.1).
2. **The launch context in the access token.** SMART puts the context in
   the token response and the introspection response only. A resource
   server reading a JWT needs it in the token, and `ferrohealth-smart` reads
   a `patient` claim when present (section 9). FerroSMART writes `patient`,
   `encounter`, `fhirUser` and, for an openEHR `aud`, `ehrId` as access
   token claims beside the RFC 9068 set, names `rfc9068 §2.2.2` ("arbitrary
   attributes") as the ground, and keeps the claims to what the token
   response carried. Our own design. In a user flow the token also carries
   the person's `roles` (`rfc9068 §2.2.3.1`: an authorization server that
   includes such attributes "SHOULD use the "groups", "roles", and
   "entitlements" attributes" of `rfc7643 §4.1.2`), and so does the
   introspection response: the roles the upstream ID Token's
   `role_claims` carry that a `[[ferrosmart.role]]` names, sorted, fixed at
   login and kept through every refresh, never a value the client asks
   for. A role no table names stays at the provider. Backend Services
   tokens carry none. SMART "leaves access token formats out of scope"
   (`smart scopes-and-launch-context`), so the claim set is ours; whether a
   resource server trusts FerroSMART for roles is its own decision (owner,
   2026-11-19, #649).
3. **The EHR launch API.** In an EHR launch "an opaque handle to the EHR
   context is passed along to the app" and "The server will provide the
   application with EHR context based on this handle" (`smart app-launch`,
   SMART authorization & FHIR access: overview), but SMART defines no way
   for an EHR to give the authorization server that context. Our own
   design (#517), in two forms; 13.17 is the EHR's side.
   - **The EHR client.** A registered `confidential_asymmetric` client
     whose ceiling lists `system/launch.c`, a SMART v2 `system/` scope with
     the `c` permission over a launch, our own name (`smart
     scopes-and-launch-context`, Extensibility, admits it). Any other
     client is refused.
   - **`POST /launch`**, shaped as a pushed authorization request (`rfc9126
     §2`): an `application/x-www-form-urlencoded` body in which the EHR
     authenticates with its `private_key_jwt` assertion exactly as at the
     token endpoint (`client_assertion_type`, `client_assertion`; 13.6 item
     1), and names the registered app of the authorization code grant it
     launches by exactly one of `app_client_id` and `app_launch_uri` (both
     or neither is `invalid_request`), `resource` (the base the app
     receives as `iss`, `rfc8707 §2`) and the context: `patient`,
     `encounter`, `fhirContext` (the JSON array of the token response, as
     `rfc9396 §3` carries a JSON parameter in a form), `intent`,
     `need_patient_banner` (`true` or `false`), `tenant`, `appContext` and,
     for an openEHR base only, `ehrId`. A SMART Task names the app it asks
     for only by its launch URL (`smart task-launch`,
     `smartonfhir-application`), so a client may register `launch_uri`, an
     absolute `https` URL, which `app_launch_uri` names: both are compared
     after `rfc3986 §6.2.2` syntax-based normalization, two clients may not
     register one (the configuration is refused), and a URL no client
     registered is `invalid_request` naming `app_launch_uri`. The key
     follows OpenID Connect Dynamic Client Registration 1.0 §2's
     `initiate_login_uri`; both are our own design (#659). `appContext` is
     a Task's `smartonfhir-appcontext`, "to be included in the token
     response" (`smart task-launch`): a string of at most 8192 bytes, passed
     on unchanged and never logged, which the token response, a refresh and
     the introspection response carry as `appContext` like the other
     launch context parameters. SMART's table of launch context parameters
     does not list it, so carrying it as one is our own design (#660). `smart_style_url` is not a launch
     parameter: it is the deployment's, from `[ferrosmart.branding]`. Any other parameter
     is refused, so a misspelt context parameter never vanishes. The
     context is checked against `smart scopes-and-launch-context`,
     `fhirContext`: each item names a `reference`, `canonical` or
     `identifier`; a `role` is never empty and is `launch` or an absolute
     URI; Patient and Encounter appear there only under another role. The
     answer is `201` with `{ "launch": "<opaque>", "expires_in": 300 }`
     and `Cache-Control: no-store` (`rfc9126 §2.2`); a refusal is the
     `rfc6749 §5.2` body (`rfc9126 §2.3`): `invalid_client`,
     `unauthorized_client` for a client that may not launch,
     `invalid_target` for a base FerroSMART does not serve, and
     `invalid_request` otherwise. The value is 256 random bits, stored as
     its SHA-256.
   - **The launch JWT**, for an EHR that calls FerroSMART for nothing: a
     JWS (`rfc7515`) the EHR signs with a key of its registered JWK Set
     (`RS384` or `ES384`) and hands the app as `launch`. Its header carries
     `typ` `launch+jwt` (explicit typing, `rfc8725 §3.11`) and `kid`; its
     claims are `iss` (the EHR's `client_id`), `aud` (FerroSMART's issuer,
     one string), `exp` (at most five minutes ahead), `jti`, `client_id`
     (the app, `rfc8693 §4.3`), `resource` (the base) and the context
     parameters above under their own names; `iat` and `nbf` may be
     present. Any other claim is refused. FerroSMART checks it as it
     checks a client assertion (signature by `kid`, a `jku` only as
     registered, sole `aud`, `exp`, `jti` once per `iss` in `seen_jti`).
   - **Redemption.** Both forms are single use, live at most 300 seconds
     (the bound SMART sets a client assertion) and are bound to the EHR,
     the app and the base: at `/authorize` the `launch` value resolves
     only for the `client_id` and the `aud` the launch names, and a
     resolution for another app or base is refused and leaves the launch
     unused. The `fhirUser` of the token never comes from a launch; it
     comes from the person's own login (item 9).
   - **At `/authorize`.** A `launch` without the `launch` scope is
     refused (`invalid_scope`), since the app "requests the scope `launch`
     and provides an additional URL parameter of `launch`" (`smart
     scopes-and-launch-context`, Apps that launch from the EHR); an
     unknown, used, lapsed or foreign launch is `invalid_request`. The
     launch is redeemed before the upstream login. The consent page then
     offers `launch`, the `launch/patient` and `launch/encounter` hints
     its context answers, and the `patient/` scopes the client's ceiling
     and the person's roles allow once the launch put a patient in
     context. The context reaches the code and the token response only
     when the person keeps `launch`; without it the `patient/` and
     `launch/` scopes are dropped too, because a granted `patient/` scope
     "SHALL establish a patient in context" (same section). The SMART
     configuration lists `launch-ehr`, `context-ehr-patient`,
     `context-ehr-encounter`, `context-banner` and `permission-patient`.
   - **Records.** A registration commits with its `launch` row and a
     redemption with its `used_at` (or the launch JWT's `seen_jti` row) in
     one audited transaction, as `launch-registered` and `launch-redeemed`
     records; a refused registration or redemption is a `launch-refused`
     record of its own, with a minor-failure outcome. A write whose record
     cannot be kept is not kept, and the request fails. Each record names
     the EHR, the app, the base and the form (`registered` or `signed`), or
     the OAuth error and the rule broken, never the launch value, the
     assertion or a context value. No IHE profile names an EHR-launch
     event (ITI-71 covers the token request), so the codes, in
     FerroSMART's own `urn:ferrosmart:audit-event` system, are our own
     design.
4. **The patient picker.** SMART places the choice inside the
   authorization server's own flow: for `launch/patient` "The EHR's
   'authorize' endpoint will take care of acquiring the context it needs
   ... the EHR may provide the end-user with a patient selection widget"
   (`smart app-launch`, Obtain authorization code). SMART defines no
   protocol for handing the choice to a picker elsewhere and back, so an
   external picker URL would be a hand-off of our own invention with its
   own threat surface. FerroSMART draws the picker itself (#516), between
   the login and the consent, for a standalone launch whose client may ask
   for `launch/patient` at a FHIR resource server. A standalone request
   that asks a `patient/` scope without `launch/patient` is read as asking
   it, and the granted scope names it (`smart scopes-and-launch-context`,
   Standalone apps: the server MAY infer `launch/patient`; owner,
   2026-11-19, #669). A person whose
   `fhirUser` names a `Patient` at that server (absolute, or relative to
   the request's base, `smart scopes-and-launch-context`, `fhirUser`), or
   at the FHIR base paired with the openEHR base asked, sees no picker:
   FerroSMART reads that record again as them and puts it in context, with
   their EHR at a paired base, and a record it cannot read is a page that
   says so, never the picker. Such a person is offered the `patient/`
   scopes the client's ceiling allows with no role, since they reach their
   own record alone (owner, 2026-11-19, #673). The picker is a
   server-rendered form
   over a FHIR R4 search (`GET [base]/Patient?name=…&identifier=…`). The
   search runs as the signed-in person, never as a system: FerroSMART
   issues itself a token whose `sub` is the person's pairwise subject and
   whose `fhirUser` is theirs, `aud` the one base, scope `user/Patient.rs`
   alone, living 30 seconds and revoked once the request is answered, each
   step committed with its record (13.2). The FHIR server's own access
   rules for that person decide which patients they see: a `user/` scope
   is "relative to the user's underlying permissions. If the underlying
   user has limited permissions, the client will face these same
   limitations" (`smart scopes-and-launch-context`). The chosen id is read again as them before it enters
   the launch context, so a patient they may not see is never chosen. The
   choice travels as an EHR launch's does: in the code's launch context,
   the grant's context map, the token response's `patient` and the access
   token's claim. At a FHIR server a request that also asks for
   `launch/encounter` gets a second step (#604): the chosen patient's
   encounters (`GET [base]/Encounter?patient=…`, as the person, scope
   `user/Encounter.rs`), one of which the person picks or goes on without;
   the chosen one is read again and enters the context only when its
   `subject` is that patient (13.23). Every search and read is an access record of Regulation
   (EU) 2025/327 Annex II 3.2 through `ehds-logging`. A failed search is an
   error page, never an empty context. The search call and the page are our
   own design.

   At an openEHR resource server `launch/patient` asks for "both FHIR
   `Patient` resource and corresponding openEHR `EHR` instance", and "For
   Standalone Launch, the user should be prompted to select the openEHR
   `EHR`" (`soe master07`, Context Selection). The same picker does that
   (#571) for an openEHR base whose `[[ferrosmart.resource]]` table names
   its `subject_namespace`, the namespace its EHRs name their subjects in;
   a base without one offers no `launch/patient`. The person enters the
   patient's identifier, and FerroSMART looks the EHR up with `GET
   [base]/ehr?subject_id=…&subject_namespace=…` (openEHR ITS-REST 1.1.0,
   `ehr_get_by_subject`), under the same guard: a token of the person's own
   for the one base, living 30 seconds, revoked after the one request, with
   the scope `user/composition-*.r`, since the EHR has no scope family and
   is held to the `composition-` family over every template (3.9). A `404`
   is "no EHR you may see"; any other failure is an error page. The chosen
   EHR is looked up again as the person before its `ehrId` enters the
   launch context, and each lookup is an access record naming the patient
   by the identifier and namespace and the EHR it reached, with the
   operation id in the `urn:openehr:its-rest:operation` system. No FHIR
   `Patient` id is known at an openEHR base on its own, so the context
   carries `ehrId` and no `patient`. The form and the single namespace per
   base are our own design.

   A platform names its FHIR server as the `org.fhir.rest` service beside
   the required `org.openehr.rest` one (`soe master04`, Services), and
   `ehrId` is "the openEHR `EHR` instance associated with the selected
   FHIR `Patient` resource" (`soe master07`, Context Selection). An openEHR
   base whose `[[ferrosmart.resource]]` table names that server as its
   `fhir_base`, one of the configured FHIR bases, is paired with it (#574).
   At a paired base the picker is the FHIR one: the person searches the
   FHIR server and chooses a patient, the choice is read again as them
   there, and FerroSMART looks the EHR up at the openEHR base by the value
   of the patient's `Patient.identifier` whose `system` is the table's
   `subject_system`, in the `subject_namespace`. Each request keeps the
   guard above with a token for the one server it goes to: `aud` the FHIR
   base and `user/Patient.rs` for the search and the read, `aud` the
   openEHR base and `user/composition-*.r` for the lookup. The context then
   carries both `patient` and `ehrId`. An identifier whose `use` is `old`
   names no current subject (FHIR R4, `Identifier.use`); a patient with no
   identifier of the system, or whose EHR the person may not see, gets the
   picker again with words that say so and enters no context; two current
   identifiers of the system with different values, or a failed lookup,
   are an error page. The draft does not say how a `Patient` names its
   EHR's subject, so the identifier system per base is our own design.

   Every picker token carries the person's mapped `roles`, the list the
   access token of the same sign-in carries (RFC 9068 §2.2.3.1, #649), so
   an openEHR server such as FerroEHR decides a professional's lookup by
   their roles as it decides their other reads (#716). Such a server also
   reads a declared purpose of use from a header, so an openEHR base's
   table may list the purposes it accepts as
   `[[ferrosmart.resource.purpose]]` entries (a `code`, its `system` and
   the `display` the page shows) with the header in `purpose_header`
   (default `x-purpose-of-use`). A code is a header value, visible ASCII
   with no comma (RFC 9110 §5.5), checked at load. With purposes listed,
   the professional chooses one on the picker page, preselected when only
   one is listed: in the identifier form at an unpaired base, beside the
   patient choice at a paired one. The EHR lookup and the look-up-again of
   the choice send its code in the header. The pending request keeps the
   first lookup's code (`pending_authorization.purpose_of_use`), so the look-up-again, and any
   later search, declares the same one; a request naming another code, a
   code the base does not list, or none while several are listed is a
   `400` page and asks nothing. A patient's lookup of their own record
   declares no purpose. Each lookup's access record names the purpose
   with its system, which the BALP record carries as `purposeOfEvent` and
   in `agent[user].purposeOfUse`, and names the person's roles. FerroSMART
   puts no purpose claim in the token, which would bind it to one purpose
   before the person chose, and does not read the accepted purposes from
   the server, since no published standard names such a route. No
   specification governs a picker's purpose: our own design.

   Before a search the picker offers two lists (#685), each read again as
   the person before the page shows it. The recent list holds the patients
   the person chose at the base asked: at a FHIR base (or the FHIR base
   paired with an openEHR one) one search `GET [base]/Patient?_id=…` as
   the person, the `_id` parameter with comma-separated values, which FHIR
   R4 search reads as any of them, so a patient they may no longer see
   is left out; at an unpaired openEHR base the EHR of each subject id is
   looked up again, with the kept or the only listed purpose of use, and
   not before one is chosen where several are listed. The `recent_patient`
   table keeps a person's ten latest choices per base for
   `[ferrosmart.picker] recent_retention` (30 days by default, `0s` keeps
   none), the sweep deletes the older ones, and the person erases the list
   on the management page beside their apps' access, with a
   `recent-patients-forgotten` record. The assigned list, where a FHIR
   base's table names `assigned`, is the professional's patients by the
   FHIR R4 `participant` search parameter of `CareTeam`
   (`CareTeam.participant.member`, with `status=active`) or `Encounter`
   (`Encounter.participant.individual`, with `status=in-progress`), the
   patients included by FHIR R4 search's `_include` of the `patient`
   reference, for a professional, a `fhirUser` that names a `Practitioner`
   or `PractitionerRole` at that base, as the consent page reads it (item
   6); its token carries
   `user/CareTeam.rs user/Patient.rs` or `user/Encounter.rs
   user/Patient.rs`. A choice from either list is read again as any
   other. SMART App Launch 2.2 leaves the widget to the server, so both
   lists are our own design.
5. **Scope narrowing.** The granted scope is the intersection of the
   request, the client's registered ceiling, the user's roles mapped to
   scopes by configuration, and the consent the user gave; SMART allows the
   result to differ from the request (`smart app-launch`, Obtain access
   token, Response) and requires the server's policy to win (`smart
   scopes-and-launch-context`, SMART's scopes are used to delegate access).
   The mapping is content, never code. When the intersection leaves no
   scope at all, FerroSMART draws a page that names the configured roles
   that would grant a requested scope the ceiling admits (or says the app
   asks for access the server does not give it), never a claim value, and
   its one way on returns to the app with `access_denied`, the `state` and
   the `iss` (`rfc6749 §4.1.2.1`, `rfc9207 §2`; owner, 2026-11-19, #672; the
   page first is our own design). A role maps to `user/` and
   `patient/` scopes and to extension scopes, "any string starting with
   `__` (two underscores)" that a resource server defines for its own API
   (`smart scopes-and-launch-context`, Extensibility): such a scope is
   offered when the request asks for it, the ceiling lists it and a held
   role grants it, never on the request alone, and `scopes_supported`
   advertises every one a role lists ("The server could advertise this
   scope in its developer-facing documentation"). Any other scope outside
   the SMART set is never granted to a person (owner, 2026-11-19, #647).
6. **Consent.** (Built in #515: the consent page's "Remember this choice"
   box, off by default and explained to app developers on the book's
   flows page, writes the `consent` row; a later request whose offered scopes the
   row covers goes back with a code at once; `GET /manage` logs the person
   in at the provider and lists the rows, each withdrawn by a post that also
   revokes the client's live access tokens about them.) SMART leaves the user's part open: "The authorization
   decision is up to the EHR authorization server which may request
   authorization from the end-user. The EHR authorization server will
   enforce access rules based on local policies and optionally direct
   end-user input" (`smart app-launch`, Obtain authorization code,
   Response), and the granted scope "can be different from the scopes
   requested by the app" (Obtain access token, Response). FerroSMART takes
   the end-user input in every user flow, standalone and EHR launch (owner,
   2026-11-16): policy first narrows the request to what the client's
   ceiling and the user's roles allow (item 5), then the consent page shows
   the remaining scopes and the user approves them, narrows them by
   unticking any resource scope, or denies (an `access_denied` error
   response, `rfc6749 §4.1.2.1`). Identity, launch and refresh scopes
   (`openid`, `fhirUser`, `profile`, `email`, `launch`, `launch/*`,
   `offline_access`, `online_access`) are fixed lines with no box, granted
   with the app whatever the form posts, since they give the app no data
   the boxes do not, SMART issues a refresh token only "if granted"
   (`smart app-launch`, Refresh access token) so an app copes without one,
   and the person ends lasting access at the `management_endpoint` (#728);
   `patient/`, `user/` and extension scopes keep
   their boxes (owner, 2026-11-19, #668; `smart app-launch` §7 Best
   Practices, non-normative, asks for plain descriptions; the split is our
   own design). The page also shows what the client registers about the app
   (`rfc7591 §2`): `client_uri` linked as the app's home page, `logo_uri`
   drawn, `policy_uri` and `tos_uri` linked. Whether the person sees the
   page follows from who they are, read from the type of their `fhirUser`
   (`smart scopes`, `fhirUser`), and how the client was registered, in one
   function (`authorize::consent::without_page`):

   | Person (`fhirUser`) | Admin-registered | Admin-registered, `first_party` | Self-registered |
   |---|---|---|---|
   | `Practitioner`, `PractitionerRole` | no page | no page | page |
   | `Patient`, `RelatedPerson`, `Person` | page | no page | page |
   | none, or another type | page | page | page |

   An administrator's registration is the organisation's consent for its
   professionals: the server may obtain the decision "by asking the
   resource owner or by establishing approval via other means" (`rfc6749
   §4.1.1`), consent may be "previous administrative consent" (`oidc-core
   §3.1.2.4`), and SMART's Best Practices (Considerations for Scope
   Consent) ask the user's consent where the client and the resource
   server are not from the same organization. A patient, or the related
   person who speaks for them, decides which other party's app reads their
   data (Regulation (EU) 2025/327 Art 3, 4(2), 7(1)), so they skip the page
   only for an app marked `first_party`: the controller's own app, or one
   acting for it, which only an administrator sets. An app that registered
   itself asserts its own metadata (`rfc7591 §5`) and always shows the
   page. No page is skipped for a scope beyond the registration's ceiling;
   the granted scope stays the intersection of the request, the ceiling,
   the roles and the patient context, and the resource server's policy
   still decides every request. Each code records its basis, `page`,
   `remembered`, `administrative` or `first-party`, on the code and its
   grant, and a skipped page commits a `consent-administrative` or
   `consent-first-party` record. Clearing a client's `first_party` revokes
   every grant issued on it with its tokens, in the same transaction.
   Backend Services has no user and no consent step (`smart
   backend-services`, Scopes: "The client is pre-authorized by the
   server"). `prompt=consent` shows the page whatever the table says
   (`oidc-core §3.1.2.1`). A consent is remembered only when the user ticks
   to remember it, for that client, that resource server (the request's
   `aud`) and that scope set, and it answers only on the page path; a
   request that asks for more, or for another resource server, shows the
   page again (our own design). The management page (`management_endpoint`,
   `smart conformance`, Metadata) lists every app holding live access with
   a Disconnect form: it forgets the remembered consent and revokes every
   grant and token of the app about the person, with a `consent-withdrawn`
   record, and leaves the registration standing; `offline_access` lasts "as
   long as the authorization server and end-user will allow" (`smart
   scopes`), so no app holds lasting access the person cannot end. Neither
   the registration nor a remembered consent answers for a public client
   unless the request's redirect URI is a claimed `https` URI (`rfc8252
   §8.6`, `§7.2`; `rfc6749 §10.2`): a custom-scheme or loopback redirect
   shows the page, and `ferrosmart client apply` warns of an
   administrator's public client with no claimed `https` redirect.
7. **`online_access`.** "As long as the end-user remains online" has no
   mechanism in SMART. FerroSMART ties an online refresh token to the
   upstream login session: it ends at upstream logout and after the
   configured idle time (`online_idle`). The callback records each login as
   an `upstream_session` with the provider's `sid`; a Logout Token posted to
   `/backchannel-logout` (Back-Channel Logout 1.0 §2.6) ends the session it
   names, or every session of its `sub` without a `sid`, and revokes the
   `online_access` grants in them ("SHOULD be revoked", §2.7), never an
   `offline_access` one ("SHOULD NOT"). Logging out is idempotent, so the
   optional `jti` check of §2.6 is not made. The upstream ID Token's `exp`
   is the token's lifetime, not the session's (`oidc core §2`), so it ends
   nothing. A provider that offers only Front-Channel Logout 1.0, such as
   Microsoft Entra ID, renders `/frontchannel-logout` in an iframe with its
   `iss` and the login's `sid` (§2; registered with
   `frontchannel_logout_session_required`, since FerroSMART keeps no browser
   session of its own to clear), which ends the sessions of that `sid` as
   the back-channel path does; a request without both, or from another
   issuer, ends nothing. The end-session endpoint (`rpinitiated §2`) ends
   the `online_access` grants of the person its `id_token_hint` names, and
   forwards to the upstream's end-session endpoint; FerroSMART notifies no
   app of the logout, whose revoked refresh token fails at its next use. Our
   own design.
8. **Introspection access.** `smart token-introspection` lets the endpoint
   take a SMART bearer token and leaves any other access rule "out of scope
   for the SMART App Launch IG"; `rfc7662 §2.1` admits "client
   authentication as described in OAuth 2.0 [RFC6749] or a separate OAuth
   2.0 access token". FerroSMART takes both: a confidential client
   authenticated as at the token endpoint, by its `private_key_jwt`
   assertion or, for a confidential symmetric client, its secret by HTTP
   Basic or in the form (`rfc6749 §2.3.1`), or a bearer token FerroSMART
   issued carrying the scope `system/introspect`. A public client cannot
   authenticate (`rfc6749 §2.1`) and is refused. Every resource server that
   introspects is a registered client whose scope ceiling lists
   `system/introspect`. The secret is taken because an off-the-shelf
   gateway that introspects (Apache APISIX's `openid-connect` plugin, for
   one) authenticates with `client_secret_basic` by default, cannot renew a
   bearer token by itself, and names the introspection endpoint as its
   assertion's `aud`, which item 1 refuses; the third-party lane holds it
   (13.21). The metadata lists the three methods in
   `introspection_endpoint_auth_methods_supported` (`rfc8414 §2`). A bearer
   token must name FerroSMART's issuer as its `aud` (`rfc9068 §4`), which
   the client credentials grant gives when `resource` names the issuer. A
   failed bearer answers `401` with an RFC 6750 challenge, a failed client
   `401` with `invalid_client` or `unauthorized_client` (`rfc7662 §2.3`),
   challenged `Basic` when the client used that scheme (`rfc6749 §5.2`); a
   request with two client authentication methods is `invalid_request`
   (`rfc6749 §2.3`). The scope name is fixed, never a setting. Our own
   design.
9. **Upstream identity.** The user's FerroSMART `sub` is a pairwise-stable
   identifier derived from the upstream issuer and the upstream `sub`
   (SHA-256 of both, base64url), so two IdPs never collide and the upstream
   identifier never reaches a resource server. `fhirUser` comes from the
   configured claim of the upstream ID token first; without it, from the
   `[[ferrosmart.resource.fhir_user_lookup]]` tables of the FHIR base the
   request reads (the request's own, or the one paired with its openEHR
   base): each names a resource type, the upstream claim whose text is an
   identifier's value and the identifier's system, and FerroSMART searches
   `[base]/[type]?identifier=[system]|[value]` (FHIR R4 search, token
   parameters) as the person, with the one scope of that type. Exactly one
   match across the tables is the `fhirUser`, relative to the request's
   base or absolute at a paired one (`smart scopes-and-launch-context`,
   `fhirUser`); none, several or a failed search leave it out, the consent
   page says so, and an audit line records the outcome without a value
   (owner, 2026-11-19, #674). The system and the claim are deployment
   configuration with no default. Our own design.
10. **Revocation's reach.** Revoking a refresh token revokes its grant
    with every refresh and access token under it (`rfc7009 §2.1`, SHOULD);
    revoking an access token revokes that token alone (the MAY to revoke
    the refresh token too is not taken). A token issued to another client
    is refused with `unauthorized_client` (`rfc7009 §2.1`: "the request is
    refused"; the RFC names no code, so the choice is our own design). The
    endpoint ignores `token_type_hint` (`rfc7009 §2.1`, MAY) and tells the
    two kinds apart by the value: an access token is an RFC 9068 JWT one
    of FerroSMART's keys verifies, anything else is looked up by its
    SHA-256 as a refresh token.
11. **Refresh rotation for every client.** `rfc9700 §4.14.2` requires
    rotation or sender-constraining for public clients; FerroSMART rotates
    every client's refresh token, one fixed behaviour, so reuse detection
    covers confidential clients too (`oauth21 §4.3.2`, MAY issue a new
    refresh token). A rotated token presented again revokes the grant with
    every token under it (`oauth21 §4.3.1`), with one exception (owner,
    2026-11-19, #667): the same client presenting it again within 10
    seconds, while its successor is neither used nor revoked, gets the same
    successor and a new access token, so a retry after a lost response or
    two requests racing (two tabs, two backend instances) is not read as a
    replay. `rfc9700 §2.2.2` makes rotation a MUST for public clients only
    and `rfc9700 §4.14.2` gives reuse detection no grace rule; the window is
    our own design. The successor is the SHA-256 of the presented token and
    a salt the store keeps beside the presented token's hash, so only a
    holder of the rotated token can derive it again, and the store still
    holds no refresh token. The new token keeps the grant's whole
    scope (`oauth21 §4.3.3`) and lapses after `refresh_idle`
    (`offline_access`) or `online_idle` (`online_access`) unused. A
    refresh request's `scope` may equal the grant's (owner, 2026-11-16).
    `smart app-launch`, Refresh access token, Request, asks for "a strict
    sub-set of the scopes granted in the original launch (no new
    permissions can be obtained at refresh time)". `rfc6749 §6`, which
    SMART profiles, has "The requested scope MUST NOT include any scope not
    originally granted by the resource owner" (and `oauth21 §4.3.1` the
    same). A request equal to the original adds no permission, which is the
    intent SMART's parenthetical states. FerroHEALTH/FerroSMART#550 is the
    upstream report. A client receives a refresh token when its
    ceiling lists `offline_access` or `online_access` and it registers the
    `refresh_token` grant; only then does the consent page offer either
    (`smart app-launch`, Refresh access token: "A server can decide which
    client types ... are eligible"). With both granted, `offline_access`
    decides. Redeeming a code opens the grant every token of the launch is
    issued under, with the launch context and the upstream session the
    person logged in under; withdrawing a remembered consent revokes the
    grants it covered with every token under them. A refresh request may
    name a `resource` (`rfc8707 §2.2`: "for all grant types", with the
    acceptable resources "at its sole discretion" and limited "to those
    that were originally granted"). FerroSMART takes the grant's own
    audience or the `fhir_base` paired with it (#574), so one grant at an
    openEHR base reaches the platform's FHIR server, and refuses any other
    with `invalid_target` (`rfc8707 §2`). The token's `aud` is that
    resource alone (`rfc8707 §2`, SHOULD audience-restrict; `rfc9068 §3`;
    `rfc9700 §4.10.2`), and its scope is the grant's, narrowed by the
    request's `scope`, less the clinical scopes of the other kind's
    grammar: a `template-`, `composition-` or `aql-` scope is openEHR's
    (`soe master08`, Resource Scopes), any other clinical scope FHIR's.
    The identity, launch and access scopes stay. The scope is never wider
    than the grant's, and a scope left empty is `invalid_scope`. The
    rotated refresh token keeps the grant's audience and whole scope
    (`rfc8707 §2.2`, "bound to the full original grant"), and a refresh
    without `resource` keeps the grant's audience. Which resource a grant
    reaches through a pairing is our own design (FerroHEALTH/FerroSMART#663).
12. **A client's registered origins.** `smart app-launch`, Considerations
    for CORS support, has the token endpoint readable "for requests from a
    client's registered origin(s)" and says nothing of how an origin is
    registered. A client's registered origins are the origins (`rfc6454
    §4`) of its registered redirect URIs, where a browser app receives its
    code. A token response to a request whose `Origin` is one of them
    carries `Access-Control-Allow-Origin` with it and `Vary: Origin`; any
    other origin, `null` included, gets no CORS header. Our own design
    (#560).
13. **A client's resource servers.** The owner's decision of 2026-11-19
    (#682): a client's `resources` lists the `[[ferrosmart.resource]]`
    bases its tokens may name in `aud`, and an authorization request, a
    client credentials request, a refresh, a code redemption or a launch
    registration naming any other base is refused `invalid_target`
    (`rfc8707 §2`: "The requested resource is invalid, missing, unknown,
    or malformed"). FerroSMART's own issuer stays a target of its own
    `system/` scopes for every client (item 8, 13.27). The list is read
    from the store on every request, so a base the admin API takes off it
    is refused from the next request. A client that lists none reaches no
    resource server, and a client credentials request without `resource`
    takes the one base its client lists alone (`rfc9068 §3`). A token's
    `aud` therefore says the client was admitted for that server, so a
    product admits every client FerroSMART issued a token for its audience
    and keeps no list of its own (3.14, 13.21); RFC 9068 §4 has a resource
    server check `aud`, and SMART 2.2 leaves the rest to the server's own
    policy. Which clients reach which server is our own design.
14. **A client that registered itself.** RFC 7591 §5 has the server "treat
    all client metadata as self-asserted", so a client the app registered
    itself (`registered_by` `self` in the `client` table) is its own type,
    `Registration::Dynamic`, which is never first party; the store refuses
    a row of one that holds the mark.
    The person always sees the consent page for it, with a notice that the
    app registered itself and no remember box, and a remembered consent or
    an assured redirect never skips the page (§5: the server "can also
    present warning messages to end-users about dynamically registered
    clients in all cases"). Of its `client_uri`, `logo_uri`, `policy_uri`
    and `tos_uri`, the page shows only those with the scheme and host of
    the request's redirect URI (§5, "SHOULD check"). An error found before
    the person's login was accepted (a malformed request, a decline or
    failure at the provider, a login older than `max_age` or below the
    level of assurance) is a page and never a redirect to it: RFC 9700
    §4.11.2 has the server authenticate the person before it redirects to
    a URI an attacker could have registered. The configuration never
    writes over its row, as with a client the admin API changed (13.27).

### 13.7 The crate layout

FerroSMART is one binary crate, `app/ferrosmart` (package `ferrosmart`,
`publish = false`), beside the library crates under `crates/`, with the
workspace's members widened to `app/*`. It depends on the published family
crates and on `ferrohealth-smart` and `ferrohealth-session` by path, so it
always builds against the libraries of the same commit. Its modules:

| Module | Holds |
|---|---|
| `config` | the `[ferrosmart]` tree, read by `ferrohealth-config` with `deny_unknown_fields` |
| `discovery` | the RFC 8414, OpenID Connect and SMART documents, and the JWKS |
| `keys` | the signing key ring, the `Signer` trait with the file and KMS signers, rotation |
| `clients` | the registry, client authentication (secret, `private_key_jwt`, the client JWK Set fetch and cache) |
| `admin` | the admin API over the registry and the key ring, with its guard (13.27) |
| `authorize` | the authorization endpoint, the pending request, the scope narrowing |
| `upstream` | the login at an upstream provider: OpenID Connect through `ferrohealth_smart::oidc`, SAML 2.0 through `saml` (13.26), and the claim mapping; `preset`, the vendor defaults read from `presets/`, and `registration`, the subject and registration the operator commands print (#733) |
| `consent` | the consent page and the consent records |
| `picker` | the patient picker over FHIR and ITS-REST |
| `launch` | the EHR launch API and the signed launch JWT |
| `token` | the token endpoint and its grants (`authorization_code`, `refresh_token`, `client_credentials`) |
| `mint` | the RFC 9068 access token and the ID Token |
| `introspect`, `revoke` | RFC 7662 and RFC 7009 |
| `store` | the PostgreSQL store (`sqlx` 0.9, the family's driver) and its migrations |
| `audit` | the BALP and EHDS records through `ihe-atna` and `ehds-logging` |
| `pages` | the consent, picker and error pages, server-drawn with FerroUI (13.15) |

The server stack is `ferrohealth-server` (request id, timeout, body
ceiling, TLS listener, drain), `ferrohealth-telemetry` and
`ferrohealth-health` (the database and the upstream discovery as
indicators). Scope parsing is `ferrohealth_smart::scope` and
`ferrohealth_smart::openehr::smart_scopes`, the parsers the resource
servers enforce with, so FerroSMART never grants a scope a product parses
differently.

### 13.8 The endpoints

| Method and path | Purpose | Ground |
|---|---|---|
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata | `rfc8414 §3` |
| `GET /.well-known/openid-configuration` | OpenID Connect discovery | `discovery §4` |
| `GET /.well-known/smart-configuration` | FerroSMART's SMART document, which each product's own document describes through the described-issuer rule (3.8) | `smart conformance` |
| `GET /jwks` | the public signing keys, bare JWKs | `rfc7517 §5`; `smart scopes-and-launch-context` |
| `GET`, `POST /authorize` | the authorization endpoint; a `request_uri` the PAR endpoint issued stands for the request, taken once | `smart app-launch`; `rfc6749 §3.1`; `rfc9126 §4` |
| `POST /par` | the pushed authorization request endpoint (13.30) | `rfc9126 §2` |
| `GET /callback` | the upstream provider's redirect back, completed with the settings of the provider the request went to | `oidc core §3.1.2.5` |
| `GET /saml/metadata` | FerroSMART's SAML 2.0 service provider metadata (`application/samlmetadata+xml`), when `[ferrosmart.saml]` is set | `saml-metadata §2.4.4`, `§4.1.1` |
| `GET`, `POST /saml/acs` | the assertion consumer service: a `SAMLResponse` posted, or a `SAMLart` posted or redirected and resolved over mutual TLS, with the `RelayState` that names the pending request (13.26) | `saml-bindings §3.5`, `§3.6`; `saml-profiles §4.1.4` |
| `GET`, `POST /wallet/request/{state}` | the signed request object of an EUDI Wallet login, served as often as the wallet asks, echoing a posted `wallet_nonce` (13.32) | `openid4vp §5.10`; `rfc9101 §5.2` |
| `POST /wallet/response` | the wallet's encrypted answer: a refusal is a `400` naming its reason, an accepted answer a `redirect_uri` with a fresh response code (13.32) | `openid4vp §8.2`, `§8.3.1` |
| `GET /wallet/complete` | the response code brought back by the browser that began the request, where the login completes (13.32) | `openid4vp §14.2`; `haip §5.1` |
| `GET`, `POST /login` | the chooser of a request whose client may use more than one `[[ferrosmart.upstream]]` provider: one button per provider, whose post sends the browser to that provider's login | our own design (#678) |
| `POST /backchannel-logout` | the back-channel logout URI registered at the upstream provider, which ends the `online_access` grants of a login | `backchannel §2.5` to `§2.8` |
| `GET /frontchannel-logout` | the front-channel logout URI registered at the upstream provider: with its `iss` and `sid`, it ends the sessions of that `sid` and their `online_access` grants; never cached, framed only by the provider's origins | `frontchannel §2` |
| `GET`, `POST /logout` | the end-session endpoint: checks the `id_token_hint` FerroSMART issued (accepted past its `exp`), the `client_id` against its `aud` and the `post_logout_redirect_uri` against the client's registration, then asks the person to confirm (`POST /logout/confirm`), ends their `online_access` grants and forwards to the upstream's end-session endpoint, whose redirect back (`GET /logout/return`) sends the browser to the app with its `state`; a refusal is a page | `rpinitiated §2`, `§3` |
| `GET`, `POST /consent`, `/picker` | the consent and picker pages | our own design |
| `POST /token` | the token endpoint | `rfc6749 §3.2` |
| `POST /introspect` | RFC 7662 | `rfc7662 §2` |
| `POST /revoke` | RFC 7009 | `rfc7009 §2` |
| `POST /launch` | the EHR launch API | our own design (13.6) |
| `GET /manage` | the apps holding the user's consent or live access, each with Disconnect (`management_endpoint`) | `smart conformance`, Metadata |
| `GET /brands` | the deployment's User Access Brands Bundle, when `[ferrosmart.brand]` is set | `smart brands`, Conformance Overview |
| `POST /register` | client registration (`registration_endpoint`): an administrator's token as the initial access token, or an app's own registration when `[ferrosmart.registration] open` (13.27) | `rfc7591 §3` |
| `GET`, `PUT`, `DELETE /register/{client_id}` | the client's configuration endpoint, with its registration access token or an administrator's token (13.27) | `rfc7592 §2` |
| `GET /admin/clients`; `POST /admin/clients/{client_id}/disable`, `.../enable`, `.../secret` | the registry over the store, behind a `ferrohealth-smart` guard with the `system/admin` scope, every change audited (13.27); `secret` issues a confidential symmetric client a new secret, answered once | `rfc7591 §3.2.1`; our own design |
| `GET /admin/keys` | the signing key ring's public keys with their states, behind the same guard | our own design |
| `GET /admin/openapi.json` | the OpenAPI 3.1 document of the registration, admin and audit operations, answered without a token for the deployment's issuer; each admin router is built from the operation table the document is tested against, and each answer is tested against its schema | the OpenAPI Specification 3.1.0; our own design (#824) |
| `GET /admin/upstreams` | each upstream provider with the clients that name it, its OpenID Connect discovery document and key set read when the request is answered, or its SAML metadata as the replica last read it, each with its outcome and its signing certificates' expiry, behind the same guard | our own design (#830) |
| `GET /admin/subjects`; `GET /admin/subjects/{sub}/grants`; `DELETE .../grants/{grant_id}`, `.../consents/{client_id}`, `.../sessions` | a person's pairwise subject by provider and upstream `sub`, their live grants and remembered consents, and the revocation of one grant, one app's consent and grants, or their upstream sessions with the `online_access` grants in them, each committed with its record naming the admin client, behind the same guard | GDPR Art 7(3); our own design (#831) |
| `/healthz`, `/readyz` | `ferrohealth-health` | the family |

Each FHIR or openEHR server keeps serving its own
`/.well-known/smart-configuration` at its base, as SMART requires of "FHIR
endpoints requiring authorization", and names FerroSMART's endpoints in it.

### 13.9 The storage schema

PostgreSQL holds every piece of state, so any replica answers any request.
A secret is never stored: codes, refresh tokens and launch values are
stored as their SHA-256, client secrets as Argon2id hashes.

| Table | Key | Holds |
|---|---|---|
| `client` | `client_id` | the RFC 7591 §2 metadata (`client_name`, `token_endpoint_auth_method`, `scope`, `grant_types`, `jwks` or `jwks_uri`, `redirect_uris`, `post_logout_redirect_uris`, `default_acr_values`, `require_pushed_authorization_requests`, the app's URLs), the secret's Argon2id hash, the upstream providers it may use, the resource servers its tokens may name (13.6 item 13), launch URI, `first_party`, `registered_by` (`admin` (13.27) or `self` (13.6 item 14)), disabled time |
| `signing_key` | `kid` | state (`next`, `active`, `retiring`, `retired`) and the time it reached each one; the key itself stays in the files of `[ferrosmart.keys]` (13.11) |
| `pending_authorization` | random id | the validated request (client, redirect URI, scope, `state`, `nonce`, PKCE challenge, `aud`, launch, and the OpenID Connect `prompt`, `max_age` and `ui_locales` of 13.25), the upstream provider chosen, its `state`, `nonce` and PKCE verifier, expiry |
| `authorization_code` | code hash | the grant it opens, the PKCE challenge, the redirect URI, expiry, redemption time, the basis of its consent (13.6 item 6) |
| `authorization_grant` | grant id | client, subject, `fhirUser`, `aud`, scope, launch context, `auth_time`, upstream session, access (`offline`, `online`, none), the basis of its consent, the `DPoP` key a public client's refresh token is bound to (13.31), creation and revocation times (`grant` is an SQL keyword, so the table takes RFC 6749 §1.3's full name) |
| `refresh_token` | token hash | grant, predecessor, idle expiry, use time (set when rotated, kept for reuse detection), revocation |
| `access_token` | `jti` | grant or client, `aud`, scope, `exp`, revocation, so introspection and revocation answer for a JWT |
| `launch` | launch hash | EHR client, the app's `client_id`, `aud`, context, expiry, use time |
| `pushed_request` | `request_uri` hash | the pushed authorization request without its client authentication, the client that pushed it, expiry; deleted when taken (13.30) |
| `consent` | subject, client | the scope set the user chose to remember, times, revocation |
| `upstream_session` | id | upstream issuer, upstream `sid` and `sub`, last seen, end |
| `seen_jti` | issuer, `jti` | client assertions and launch JWTs, until their `exp` |
| `seen_saml_assertion` | identity provider, assertion `ID` | the SAML assertions a login was admitted with, until the bearer confirmation's `NotOnOrAfter` (`saml-profiles §4.1.4.5`) |
| `wallet_answer` | the request's nonce | an EUDI Wallet's accepted presentation: the pending request, the SHA-256 of the response code, the person the PID names, when the browser took it, expiry; kept until expiry, so a nonce is answered once (13.32) |
| `pending_logout` | random id (the logout cookie) | a logout waiting for the person's answer: the client, the hint's `sub`, the registered post-logout redirect and its `state`, the form token, the `state` sent upstream, expiry |
| `brand_bundle` | one row for the contents and one per resource, by `Type/id` | the digest a replica last started with, and when it became so: the Bundle's `timestamp` and each resource's `meta.lastUpdated` |

Expired rows are deleted by a sweep on each replica under a PostgreSQL
advisory lock. The migrations ship in the binary and run at start under
the same lock. They are one baseline file per area of the schema, each
table in its final shape, and a schema change edits its area's file in
place; nothing runs in production, so a database from before a change is
created fresh, since sqlx refuses a file whose checksum changed.

### 13.10 The configuration

```toml
[ferrosmart]
name = "Example Hospital"                     # the deployment's name on every page, and the brand's by default
issuer = "https://smart.example.org"          # the issuer identifier, https, no query or fragment
access_token_lifetime = "5min"                # at most one hour (smart app-launch, Response); the book's flows page tells apps to refresh
refresh_idle = "30d"
online_idle = "8h"
assurance_minimum = "substantial"            # the eIDAS level every login reaches: none, low, substantial or high (13.28)

[ferrosmart.database]
url_file = "/run/secrets/ferrosmart-db-url"
max_connections = 16

[ferrosmart.keys]                             # the RS256 keys, signing in turn (13.11)
private_key_files = [                         # in the order they take over; each kid its RFC 7638 thumbprint
    "/run/secrets/rs256-1.pem",
    "/run/secrets/rs256-2.pem",
]
rotation_period = "90d"                       # how long a key signs before the next takes over

[[ferrosmart.resource]]                       # each base an `aud` may name; at least one
base = "https://ehr.example.org/fhir"
kind = "fhir"                                 # or "openehr"
# subject_namespace = "examples"              # openEHR only: the EHR subjects' namespace the picker looks up in
# fhir_base = "https://ehr.example.org/fhir"  # openEHR only: the platform's FHIR base the picker finds the patient at
# subject_system = "urn:example:mrn"          # with fhir_base: the Patient.identifier system that names the EHR's subject
# purpose_header = "x-purpose-of-use"         # openEHR only, with purpose: the header a picker lookup declares it in
# [[ferrosmart.resource.purpose]]             # openEHR only: a purpose of use a professional's picker lookup may declare
# code = "TREAT"                              # the header's value, visible ASCII with no comma
# system = "http://terminology.hl7.org/CodeSystem/v3-ActReason"
# display = "Treatment"                       # the words the picker page shows
# [[ferrosmart.resource.fhir_user_lookup]]    # FHIR only: find fhirUser when the provider sends none (13.6 item 9)
# resource_type = "Practitioner"              # or PractitionerRole, Patient, RelatedPerson, Person
# claim = "staff_id"                          # the upstream ID Token claim holding the identifier's value
# system = "urn:example:staff"                # the identifier's system

[[ferrosmart.upstream]]                       # one entry per provider people log in at, each discovered at start
name = "idp"                                   # the provider's name, which a client's `upstreams` names
preset = "keycloak"                           # optional: "keycloak", "entra", "okta" or "zitadel", the defaults below

[ferrosmart.upstream.oidc]                    # OpenID Connect; [ferrosmart.upstream.saml] instead for SAML 2.0 (13.26), [ferrosmart.upstream.openid4vp] for the EUDI Wallet (13.32)
issuer = "https://idp.example.org/realms/hospital"
client_id = "ferrosmart"
# scopes = ["openid"]                         # the preset's, else ["openid"]
# fhir_user_claim = "fhir_user"               # the ID Token claim holding fhirUser; the preset's, else none
# role_claims = ["roles"]                     # the dotted claims holding the roles; the preset's, else RFC 9068's three
# trusted_audiences = []                      # the preset's, else none

[ferrosmart.upstream.assurance]               # the eIDAS level of each of the provider's values (13.28)
levels = { "urn:idp:loa:substantial" = "substantial", "urn:idp:loa:high" = "high" }   # an OIDC acr, a SAML AuthnContextClassRef
# minimum = "high"                            # the provider's own minimum, above the floor

# [ferrosmart.upstream.oidc.client_secret_basic]   # instead of private_key_jwt, for a provider without it (13.22)
# secret_file = "/run/secrets/upstream-secret"

# [ferrosmart.upstream.oidc.private_key_jwt]       # private_key_jwt, taken when no table names another (13.22)
# algorithm = "RS256"                         # the one the provider's registration names; the preset's, else RS256
# certificate_file = "/run/secrets/upstream-assertion.crt"   # for a provider that knows the key by its certificate

[ferrosmart.upstream.oidc.private_key_jwt.keys]    # the assertion ring, apart from the token keys
private_key_file = "/run/secrets/upstream-assertion.pem"
# kid = "..."                                 # the id the provider knows the key by; its thumbprint when unset

# [ferrosmart.saml]                           # FerroSMART as one SAML 2.0 service provider (13.26)
# entity_id = "https://smart.example.org/saml/metadata"   # the default: {issuer}/saml/metadata
# signing_key_file = "/run/secrets/saml-signing.pem"      # signs every AuthnRequest and ArtifactResolve
# signing_certificate_file = "/run/secrets/saml-signing.crt"
# [[ferrosmart.saml.decryption]]              # a key an identity provider encrypts for
# key_file = "/run/secrets/saml-decryption.pem"
# certificate_file = "/run/secrets/saml-decryption.crt"
# [ferrosmart.saml.tls]                       # the client identity of artifact resolution, extra trust roots
# client_identity_file = "/run/secrets/saml-tls.pem"

# [[ferrosmart.upstream]]
# name = "saml-idp"
# [ferrosmart.upstream.saml]
# entity_id = "https://idp.example.org/saml"  # the identity provider's entity ID
# metadata_url = "https://idp.example.org/saml/metadata"   # or metadata_file
# metadata_signing_certificate_files = []     # the keys that must sign the metadata; empty trusts it as read
# metadata_refresh = "24h"                    # read again, so a rolled-over key is trusted
# request_binding = "redirect"                # or "post"
# response_binding = "post"                   # or "artifact", resolved over mutual TLS
# force_authn = false
# name_id_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
# authn_contexts = ["<a class at or above the provider's minimum>"]   # asked for exactly; any other refused
# clock_skew = "3min"
# subject_attribute = ""                      # the attribute holding the identifier; empty takes the NameID
# fhir_user_claim = "fhir_user"               # a claim of the table below
# role_claims = ["roles"]
# [ferrosmart.upstream.saml.claims]           # claim name = attribute Name
# name = "<attribute of the display name>"
# roles = "<attribute of the roles>"
# fhir_user = "<attribute of the fhirUser>"

# [[ferrosmart.upstream]]
# name = "wallet"
# label = "EUDI Wallet"
# [ferrosmart.upstream.openid4vp]             # the PID from an EUDI Wallet, by OpenID4VP under HAIP (13.32)
# access_certificate_file = "/run/secrets/wrp-access.pem"   # the access certificate and its path, the anchor left out
# access_key_file = "/run/secrets/wrp-access-key.pem"       # its PKCS#8 P-256 key, which signs every request object
# registration_certificate_file = "/run/secrets/wrp-registration.jwt"   # as the registrar issued it
# issuer_anchor_files = ["/run/secrets/pid-providers.pem"]  # the PID providers' trust anchors
# wallet_endpoint = "eu-eaap://"
# vct_values = ["urn:eudi:pid:1"]
# claims = ["family_name", "given_name", "birthdate", "personal_administrative_number", "issuing_country"]
# identifier_claim = "personal_administrative_number"       # the claim the fhirUser lookup reads

[[ferrosmart.role]]                           # policy as content: what a role may be granted
name = "clinician"
scopes = ["user/Observation.rs", "user/Patient.rs"]    # user/ and patient/ scopes only

[ferrosmart.branding]                          # content, never code (13.15)
smart_style_url = "https://ehr.example.org/smart-style.json"  # an app's token response carries it
consent_text = "We log every access in your record's audit trail."  # the deployment's own words

[ferrosmart.brand]                             # optional: the User Access Brands Bundle at {issuer}/brands (13.23, §8)
# name = "Example Hospital"                   # Organization.name; [ferrosmart] name when absent
website = "https://example.org"               # Organization.telecom, the brand's own website
identifier = [{ system = "urn:ietf:rfc:3986", value = "https://example.org" }]   # unique across the brands
category = ["prov"]                           # codes of ValueSet/user-access-category
logo = "https://example.org/logo.svg"         # https or data; logo_license beside it
# alias = [...], address = [{ line, city, state, postal_code, country }]

[[ferrosmart.brand.portal]]                    # organization-portal, as many as the brand offers
name = "Patient Portal"
url = "https://portal.example.org"
endpoints = ["https://ehr.example.org/fhir"]   # bases of [[ferrosmart.brand.endpoint]]

[[ferrosmart.brand.endpoint]]                  # one Endpoint per FHIR [[ferrosmart.resource]] base it names
base = "https://ehr.example.org/fhir"
fhir_version = ["4.0.1"]
contact = ["https://developer.example.org"]   # where developers configure access

# [[ferrosmart.brand.affiliate]]               # an affiliated brand, partOf the primary one, with its own portals

[ferrosmart.audit]                             # every login and token request (13.2), kept in the store
source_id = "smart.example.org"               # AuditEvent.source.observer; empty: the issuer's host
site = "Example Hospital"

[ferrosmart.audit.feed]                        # optional: forward to an Audit Record Repository, ITI-20 ATX: FHIR Feed
url = "https://audit.example.org/fhir"         # https only: a record names people
credentials = { user = "ferrosmart", password_file = "/run/secrets/audit-password" }   # or [ferrosmart.audit.feed.credentials.oauth]
```

Every secret is a `_file` key read through `ferrohealth-secret`; the
`FERROSMART__` environment and `--set` override as in every product.

**Several upstream providers** (owner, 2026-11-19, #678). Each
`[[ferrosmart.upstream]]` entry is a provider by `name`, with one
protocol's table, `oidc`, `saml` (13.26) or `openid4vp` (13.32), whose
presence names the protocol (#733); the claim names
(`fhir_user_claim`, `role_claims`) sit in that table, since each protocol
names what its login carries in its own terms. Nothing in
SMART App Launch 2.2.0 limits a server to one provider. Each entry has an
issuer of its own (`oidc discovery §4.3` holds each to its metadata), so a
person's pairwise `sub` (13.6 item 9) is per provider. A client's
`upstreams` names the providers its people may use, every one when empty;
one sends the browser straight there, several draw the chooser at
`/login`, and an unknown name refuses the configuration at load. The
pending request records the provider chosen, and the callback completes
the login with that provider's relying party and claim names alone, so an
ID Token another provider issued fails its `iss` check (`oidc core
§3.1.3.7` item 2). A Logout Token or a front-channel request is routed by
its `iss` to the provider whose keys check it, and the end-session
endpoint forwards to the provider the person last logged in at. The
management page may use every provider. The upstream login sits behind
one seam in `upstream`: the `Protocol` and `Login` enums and the
provider registry, which SAML 2.0 (#688) joins with a variant, a table
and the routes of 13.26. What the login says reaches the steps after it
as one protocol-neutral identity: the issuer, the person's identifier,
the claims, the session and the time of the authentication. No
specification governs the chooser: our own design.

**Upstream presets and the operator commands** (#733). An OpenID Connect
entry may name `preset = "keycloak" | "entra" | "okta" | "zitadel"`: a
data file under `app/ferrosmart/presets/`, compiled in, holding the
scopes, the `fhirUser` and role claims and the assertion algorithm of the
tested setup of 13.16 and 13.18 to 13.20, each value with its vendor
citation. A key the entry's table sets wins over the preset, which wins
over the built-in default; a preset never holds an issuer, a client or a
key, and never country content. `private_key_jwt` is taken when the entry
names no client authentication table, so its keys table alone is enough.
Two commands read the configuration tree alone, with no key, secret or
database: `ferrosmart subject --upstream <name> --sub <sub>` prints the
pairwise `sub` of item 9 under the issuer exactly as configured (an
operator otherwise hashed it by hand, and a trailing slash gave another
subject), and `ferrosmart upstream registration <name>` prints what the
provider is configured with: the redirect and logout URIs, the client
authentication with its JWK Set URL or certificate, PKCE `S256`, the
scopes, the claims and the roles, or, for SAML 2.0, the entity IDs, the
assertion consumer service and the attributes. The management page shows
the person their own pairwise `sub`. No specification governs the
presets or the commands: our own design.

### 13.11 Key handling

- **Algorithms.** `RS256` is always available, because RFC 9068 §2.1 and
  OpenID Connect Discovery §3 require it and SMART signs ID Tokens with it;
  `ES256`, `ES384` and `PS256` can sign beside it. Names follow RFC 9864's
  fully-specified registrations; `none` and HMAC never sign.
- **Rotation.** `[ferrosmart.keys]` names a pool of key files, and the
  `signing_key` table (13.9) holds where each key stands, so every replica
  signs with the same one. A key is `next` from the moment it is
  published, `active` while it signs, `retiring` after, and `retired` for
  good. The first key of the pool signs at the first start, and the next
  unseen key of the pool is published as `next` at once. The active key
  hands over after `rotation_period` (90 days by default), once the next
  key has been published for the JWK Set's cache lifetime
  (`Cache-Control: max-age`, one hour) plus the refresh interval, which
  the resource servers' refetch on an unknown `kid` (3.2) relies on. The
  old key stays published as `retiring` for that same time plus
  `access_token_lifetime`, the longest lifetime of a token it signed; a
  shorter `rotation_period` is refused at load. Each replica moves the
  keys on and reads the table every minute under the table's own lock,
  and a replica whose files lack the next key never makes it sign. With
  no unseen key left the active key keeps signing; adding a key file to
  every replica is the operator's part of a rotation. RFC 7517 §5 and
  OpenID Connect Core 1.0 §10.1.1 describe publishing a key before it
  signs; the schedule is our own design. The private material never
  enters the database.
- **Signers.** The ring each replica signs with is `ferrohealth-smart`'s
  `client::keys::KeyRing` over PEM files from mounted secrets, the same
  ring a product's `private_key_jwt` key lives in. A
  KMS or PKCS#11 HSM signer, which keeps the private key in hardware, joins
  as a second source of the ring's keys.
- **Separation.** One key ring signs access tokens and ID Tokens; RFC 9068
  §5 says resource servers cannot rely on separate keys, and the `typ`
  values (`at+jwt` against `JWT`) are what keeps an ID Token from passing
  as an access token (`rfc9068 §2.1`).

### 13.12 The threat model

| Threat | Mitigation | Ground |
|---|---|---|
| A stolen or injected authorization code | PKCE `S256` on every client, single use with revocation on a second valid use, 60-second lifetime, bound to client and redirect URI | `rfc9700 §4.5`; `oauth21 §7.5.3` |
| Open redirection and code leakage | exact redirect URI match, no redirect on an invalid client or URI, `Referrer-Policy: no-referrer` on every page | `rfc9700 §4.1`, `§4.2`, `§4.11` |
| Mix-up between authorization servers | `iss` in every authorization response | `rfc9207 §2`; `rfc9700 §4.4` |
| CSRF and clickjacking on the consent and picker pages | a per-request form token bound to the pending authorization, `frame-ancestors 'none'`, the CSP of 13.15; an app embedded in an EHR iframe opens the authorization in a new window (the book's flows page) | `rfc9700 §4.7`, `§4.16`; `rfc6749 §10.12`, `§10.13` |
| Client assertion replay and audience injection | the `jti` store, a single `aud` value (13.6 item 1) | `rfc7523 §3`; `rfc10070 §1`, `§4` |
| SSRF through a client's `jwks_uri` | `https` only, taken from the registry and never from a request; no private or loopback address; time and size bounds | `smart client-confidential-asymmetric`, Registering a client (TLS-protected URL); the address rule is our own design |
| A stolen access token | 300-second lifetime, `aud` restricted to one base, DPoP when step DPoP lands | `rfc9700 §2.2.1`, `§2.3` |
| A stolen refresh token | rotation for public clients with reuse detection that revokes the grant, binding to the client, idle expiry | `rfc9700 §2.2.2`, `§4.14` |
| A signing key leak | keys in a KMS or HSM, rotation, a retiring key published only as long as needed | `rfc6819 §5.1.4` |
| A database leak | codes, refresh tokens and launch values stored hashed; client secrets as Argon2id | `rfc6819 §5.1.4.1.3` |
| Scope escalation | narrowing on every grant, refresh never widens, policy as content checked at load | `smart app-launch`, Refresh access token |
| A forged, replayed or stolen EHR launch | a launch value bound to an authenticated EHR client, the app and the `aud`, single use and five minutes long, stored hashed; or a launch JWT checked like a client assertion, its `jti` used once | our own design (13.6 item 3) |
| An upstream IdP that is compromised or misconfigured | one configured issuer per upstream, its ID Token checked by `oidc core §3.1.3.7`, claims mapped explicitly, nothing taken from unlisted claims | `oidc core §3.1.3.7` |
| Patient data on the picker page | the search, or at an openEHR server the EHR lookup, runs with the user's own delegated access; the page shows only display fields and the one EHR id | our own design |
| Credential leakage in logs | no token, code, secret or assertion in a log line or `Debug`, as the library crates already hold | `CLAUDE.md` hard rule |
| Request flooding | per-client and per-address rate limits on `/token` and `/authorize`, the body ceiling of `ferrohealth-server` | `rfc6819 §4.4.1.11` |

### 13.13 The Inferno test groups

The STU 2.2 server suite (`smart_stu2_2`, kit 1.0.3) runs four groups.
The CI lane (#520) runs FerroSMART with a test OpenID Connect provider
upstream and a FHIR server downstream, because the discovery tests read
the FHIR base's `/.well-known/smart-configuration` and the `fhirUser`
test reads the user's resource from it.

| Group | Children | Step that makes it pass |
|---|---|---|
| 1 Standalone Launch (`smart_full_standalone_launch`) | SMART on FHIR Discovery (`smart_discovery_stu2_2`, with the CORS checks), SMART Standalone Launch (`smart_standalone_launch_stu2_2`: TLS, redirect, code, token exchange, response body and headers, CORS), OpenID Connect (`smart_openid_connect_stu2_2`: ID Token decode, configuration, JWKS, header, payload, `fhirUser`), Token Refresh without and with scopes (`smart_token_refresh_stu2`) | 2, 3, 4, 6 |
| 2 EHR Launch (`smart_full_ehr_launch`) | Discovery, SMART EHR Launch (`smart_ehr_launch_stu2_2`: launch received, redirect, code, token exchange, response), OpenID Connect, Token Refresh without and with scopes | 5, 6 |
| 3 Backend Services (`smart_backend_services`) | Discovery, SMART Backend Services Authorization (`backend_services_authorization`: TLS, invalid grant type, invalid client assertion, invalid JWT, success, response body) | 2 |
| 4 Token Introspection (`smart_token_introspection_stu2_2`) | Request a new access token, issue introspection requests for an active and an invalid token, validate both responses | 6 |

The suite drives a browser through the authorization page, so the lane
runs the test provider with a scripted login.

The lane is steps of CI's `nextest (core and axum)` job, so its result is
part of the `conclusion` check; `scripts/inferno/lane.sh` runs it. Every
party is the family's own, at the release `docs/VERSIONS.md` pins, on the
runner's host network, with a development CA made for the run that signs
`smart.localhost` and `bridge.localhost`, so every exchange the kit makes
is TLS:

- FerroSMART, with Keycloak as its upstream login (the realm of 13.16).
  It trusts the lane's CA beside the system roots (`SSL_CERT_FILE`) for the
  picker's search at FerroBRIDGE.
- FerroBRIDGE's FHIR R4 facade as the FHIR server, the kit's `url`. Its
  SMART document describes FerroSMART as a `persons` issuer, it checks
  FerroSMART's tokens through `ferrohealth-smart` under the `ferrosmart`
  preset, as 13.21 deploys a product, and it serves the
  person's `fhirUser` as a `Practitioner`, mapped onto a `PERSON` by the
  party context its own release ships (vendored under
  `docs/specs/ferrobridge-party/`). The lane stores that `PERSON` in
  FerroEHR before Keycloak starts, so the realm's `fhirUser` names a
  resource the facade really serves.
- FerroEHR as FerroBRIDGE's CDR, answering it alone on the loopback
  interface.
- The kit at its pinned commit, on the Ruby and gems that commit locks.
  Where the kit waits for a browser, the execution script runs
  `scripts/idp/authorize.sh`, which logs in at Keycloak and approves every
  scope on FerroSMART's consent page, as a person would.

`inferno execute_script` runs `app/ferrosmart/inferno/smart_stu2_2.yaml`
and fails unless every result matches `smart_stu2_2_expected.json`, with
the values each run makes anew (the `state`, the PKCE challenge)
normalized. The lane's own files hold the rest, and the lane refuses a
change that lets one drift:

- `groups.tsv` marks each group `run` or `pending` with the issues it waits
  on. Every run lists the pending groups in the log and the job summary,
  and warns once their issues are closed. All four groups run. In group 1
  the person searches the lane's patient by name at FerroSMART's patient
  picker (13.6 item 4, #516) and picks it, so the launch carries
  `launch/patient`; FerroBRIDGE serves that `Patient` from FerroEHR as it
  serves the `Practitioner`, and its party search finds it by name over the
  CDR's AQL demographic extension. Group 2's EHR
  is the lane itself: `scripts/inferno/ehr-launch.sh` registers each launch
  at `POST /launch` as the lane's client (13.6 item 3) and opens the kit's
  launch URI with `iss` and `launch`. The app it launches is the kit as a
  confidential symmetric client (`inferno-ehr`, `auth_type: symmetric`),
  so every client type runs: public in groups 1 and 4, symmetric in group
  2, asymmetric in group 3. The kit's clients are the documents under
  `app/ferrosmart/inferno/clients/`, which the lane applies with
  `ferrosmart client apply` after adding their keys and the Argon2id hash
  of the kit's synthetic secret.
- `exceptions.tsv` lists each test of a run group that the expected results
  do not hold to `pass`, with its reason; any other test expected to be
  anything but `pass` fails the run. It holds one row: group 2's
  `smart_cors_token_exchange`, which the kit omits for the symmetric
  client, since CORS is asked for browser-based apps; groups 1 and 4 run
  it with the public client. FerroBRIDGE answers
  CORS (`smart app-launch`, Considerations for CORS support): its SMART
  document and CapabilityStatement for any origin (item 1), and its REST
  routes for the kit's origin `http://localhost:4567`, which the lane
  lists in `[facade.cors] allowed_origins` (item 2), so
  `smart_cors_well_known_endpoint`, `smart_cors_metadata_request` and
  `smart_cors_openid_fhir_user_claim` pass in every group that runs them.
- Each result is recorded in the job summary against the SMART App Launch
  2.2.0 requirements the kit's coverage map ties its test to.

Group 4 introspects with a bearer token of the lane's own client, which
holds `system/introspect` (13.6 item 8) and asks for FerroSMART's issuer as
its audience. Every test of the suite passes:
SMART Backend Services Authorization (TLS 1.2 or newer, the invalid grant
type, the invalid client assertion and the invalid JWT refused, the success
response and its body); the standalone launch of group 4 (TLS on the
authorization and token endpoints, the redirect, the code, the token
exchange with its response body and headers, CORS on the token endpoint
(13.6 item 12)); the introspection of an active and an invalid token with
both responses; and the standalone launch of group 1 with its patient
and the EHR launch of group 2, each with the same exchange, OpenID
Connect (the ID Token, the configuration, the key set and the `fhirUser`
claim, whose `Practitioner` FerroBRIDGE serves) and the refresh with and
without `scope`.

### 13.14 The build order

Step 1 (#513) is this section. Steps 2 to 9 are the sub-issues of #512 in
their blocked-by order: the core first (#514), then the authorization code
flow (#515), which the picker (#516), the EHR launch API (#517), refresh
and introspection (#518), the Inferno lane (#520) and the four upstream
providers (#522 to #525) wait on; the image (#519) and the issuer preset
with the family adoption (#521) follow the core.

### 13.15 The screens

FerroSMART has no frontend project: no single-page app and no JavaScript
application. Login belongs to the upstream identity provider. The screens
SMART needs from the authorization server itself are the consent page
(13.6 item 6), the patient picker (13.6 item 4), the management page of
remembered consents and the error page. The Rust server draws each as a
whole HTML document of plain forms.

They are drawn with FerroUI (`ferrohealth-ui`, pinned exactly in
`[workspace.dependencies]`; owner, 2026-11-16), so they look and behave
like the family's consoles: askama templates compiled into the binary,
fluent locales for the deployment's languages, the light and dark themes,
and FerroUI's axum asset router serving its CSS, script modules and fonts
from FerroSMART's own origin. FerroSMART follows FerroUI's consumer guide
(`docs/consoles.md`) and component rules (`.claude/rules/console-ui.md`) at
the git tag of the pin, the way FerroBRIDGE's console does. The pages work
without script wherever FerroUI allows it: every action is a form post the
server answers with the next page. The CSP is `default-src 'none';
script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self';
form-action 'self'; frame-ancestors 'none'; base-uri 'none'` (`rfc9700
§4.16`), and the consent page adds to `form-action` the origin of that
request's registered redirect URI alone, since CSP Level 3 §6.4.2 applies
`form-action` to the redirect that follows the post, and to `img-src` the
origin of the client's registered `logo_uri` alone (#668).

A component, pattern or locale the screens need and FerroUI lacks is
added in FerroUI as a general component, through FerroUI's own tracker and
release, and FerroSMART takes the release; it is never copied into this
repository (owner, 2026-11-16). FerroUI 0.6.8 ships a sign-in card, a
picker, search, a refusal and an error page; it has no design under
`design/consoles/` for FerroSMART's pages and no scope-approval form, which
#515 adds to FerroUI. Branding is content: the deployment's name, logo,
locales and consent wording come from `[ferrosmart.branding]`, never a code
edit.

### 13.16 Upstream providers: Keycloak

Keycloak 26.8.2 (the release the Keycloak documentation pin names) runs
upstream of FerroSMART for login only (#522). The realm is
`app/ferrosmart/examples/keycloak/ferrosmart-realm.json`, FerroSMART's side
is `ferrosmart.toml` beside it, and `scripts/idp/keycloak-launch.sh` runs both
in CI: a SMART standalone launch through Keycloak's login form and
FerroSMART's consent page, to a token response whose ID Token and access
token carry the person's mapped `fhirUser`. The quickstart takes the same
path in CI (#519): the `quickstart` job builds the image from a static
binary with `docker/ferrosmart/Dockerfile`, brings up `compose.yaml` with
`compose.keycloak.yaml` on it with secrets made as their comments make them,
and runs the same launch through them (`scripts/idp/compose-launch.sh`).
The realm's ids are fixed in the
file, so an import is reproducible; its secrets are placeholders the
environment fills at import, so none is in the tree. Citations are to
`docs/specs/keycloak-docs/`, server administration guide `topics/` unless
named otherwise.

| Setting | Value | Ground |
|---|---|---|
| Realm import | `--import-realm`, with `${...}` placeholders for FerroSMART's JWK Set URL, the redirect URI, the user's password and `fhirUser` | server guide `importExport.adoc`, Importing a Realm during Startup, Using Environment Variables within the Realm Configuration Files |
| Client `ferrosmart` | `publicClient: false`, `clientAuthenticatorType: client-jwt`, `use.jwks.url: true`, `jwks.url` FerroSMART's `{issuer}/upstream-jwks`, `token.endpoint.auth.signing.alg: RS256`: a confidential client that authenticates with a JWT FerroSMART's current assertion key signs, which Keycloak verifies against the published key set and re-reads after a rotation | `clients/oidc/con-basic-settings.adoc`, Client authentication; `clients/oidc/con-confidential-client-credentials.adoc`, Signed JWT issued by the client, Using a JWKS URL; `OIDCConfigAttributes.java`, `JWTClientAuthenticator.java`, `JWTClientValidator.java`; `oidc core §9` |
| Flows | `standardFlowEnabled: true`, implicit and direct access grants off | `con-basic-settings.adoc`, Standard Flow, Direct Access Grants; `rfc9700 §2.4` |
| PKCE | `pkce.code.challenge.method: S256` | `con-basic-settings.adoc`, Proof Key for Code Exchange Code Challenge Method; `rfc7636 §4.2` |
| Redirect URI | FerroSMART's `{issuer}/callback`, one exact URI | `con-basic-settings.adoc`, Valid Redirect URIs; `rfc9700 §2.1` |
| `fhir_user` claim | a user attribute mapper (`oidc-usermodel-attribute-mapper`, `user.attribute` `fhir_user`) into the ID Token only | `clients/con-protocol-mappers.adoc`; `UserAttributeMapper.java`, `ProtocolMapperUtils.java`, `OIDCAttributeMapperHelper.java` (`claim.name`, `id.token.claim`) |
| `roles` claim | a realm role mapper (`oidc-usermodel-realm-role-mapper`, `multivalued`) into the ID Token only | `clients/con-protocol-mappers.adoc`; `UserRealmRoleMappingMapper.java` |
| Realm role | `clinician`, which `[[ferrosmart.role]]` maps to `user/` scopes | `roles-groups/proc-creating-realm-roles.adoc`; 13.6 item 5 |

`compose.keycloak.yaml` runs the same realm beside the quickstart of
`compose.yaml`, as an override in the same project: FerroSMART shares
Keycloak's network namespace, so both issuers are one `localhost` URL for
the browser and for each other, and the configuration below arrives as
`FERROSMART__` environment.

On FerroSMART's side, `[[ferrosmart.upstream]]` names the realm's issuer and
the client, `[ferrosmart.upstream.oidc.private_key_jwt.keys]` its client authentication
(#569), and `preset = "keycloak"` brings `fhir_user_claim = "fhir_user"` and `role_claims = ["roles"]`
(the generic dotted claim reader of `ferrohealth_smart::roles`). No code
knows Keycloak. The example serves every party on the loopback interface
over plain `http`, which `ferrohealth_smart::metadata::issuer_url` admits
there. A deployment serves both over TLS.

### 13.17 Launching an app from an EHR

This is what an EHR, FerroEHR's sandbox or any other, does to launch an app
through FerroSMART. SMART fixes only the last step, the app's launch URL;
the rest is FerroSMART's own API of 13.6 item 3.

1. **Register once.** The EHR is a client of kind
   `confidential_asymmetric` with its JWK Set (`jwks_uri` or `jwks`) and
   `system/launch.c` in its `scopes`; each app it launches is a client of
   the `authorization_code` grant with its redirect URIs (13.27):

   ```json
   {
     "client_id": "ehr",
     "client_name": "Example EHR",
     "token_endpoint_auth_method": "private_key_jwt",
     "jwks_uri": "https://ehr.example.org/.well-known/jwks.json",
     "scope": "system/launch.c",
     "grant_types": ["client_credentials"]
   }
   ```

2. **On each launch, get a `launch` value**, one per click and never
   reused, in one of two ways.
   - Register the context at FerroSMART, at the URL its discovery
     documents name `launch_registration_endpoint` (`{issuer}/launch`),
     in `.well-known/smart-configuration` and in the RFC 8414 metadata
     whenever the app launch is configured. SMART defines no member for
     it; SMART App Launch 2.2.0, Conformance, Metadata lets a server add
     metadata, and `rfc8414 §2` says "Additional authorization server
     metadata parameters MAY also be used". The name is our own design
     (#657). The client assertion is the one
     the EHR would send to the token endpoint: `iss` and `sub` its
     `client_id`, `aud` FerroSMART's token URL or issuer, `exp` at most
     five minutes ahead, a fresh `jti`, signed `RS384` or `ES384`, `typ`
     `JWT`.

     ```http
     POST /launch HTTP/1.1
     Host: smart.example.org
     Content-Type: application/x-www-form-urlencoded

     client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
     &client_assertion=eyJ...
     &app_client_id=growth-chart
     &resource=https%3A%2F%2Fehr.example.org%2Ffhir
     &patient=123&encounter=456&need_patient_banner=false
     &fhirContext=%5B%7B%22reference%22%3A%22DiagnosticReport%2F7%22%7D%5D
     ```

     FerroSMART answers `201` with `{"launch": "<43 characters>",
     "expires_in": 300}`.
   - Or sign a launch JWT with the same key, and send FerroSMART nothing:

     ```json
     {"alg": "ES384", "typ": "launch+jwt", "kid": "ehr-1"}
     {"iss": "ehr", "aud": "https://smart.example.org", "exp": 1794856312,
      "jti": "b1f0...", "client_id": "growth-chart",
      "resource": "https://ehr.example.org/fhir",
      "patient": "123", "encounter": "456", "need_patient_banner": false}
     ```

     The compact JWS is the `launch` value.

3. **Open the app's launch URL** with `iss`, the FHIR or openEHR base, and
   `launch` (`smart app-launch`, Launch App: EHR Launch, Request):
   `https://app.example.org/launch?iss=https%3A%2F%2Fehr.example.org%2Ffhir&launch=<value>`.
   The `iss` is the `resource` of the launch, since the app's `aud` at the
   authorization endpoint "is the same as the launch's `iss` value"
   (`smart app-launch`, Obtain authorization code).

4. **The app takes it from there.** It reads the base's
   `.well-known/smart-configuration`, which names FerroSMART, and sends
   the person to `/authorize` with the `launch` scope and the `launch`
   value. The person logs in at the upstream provider and consents
   (13.6 item 6), and the token response carries the context the EHR
   registered. A launch the app does not redeem within five minutes, or
   redeems for another app or base, fails, and the EHR launches again.

### 13.18 Upstream providers: Microsoft Entra ID

Entra ID runs upstream of FerroSMART for login only (#524). It is a hosted
service, so no example runs it: `app/ferrosmart/examples/entra/ferrosmart.toml`
is FerroSMART's side, and the contract tests of
`app/ferrosmart/tests/it/upstream_vendors.rs` run that file against a stub
serving the discovery document, key set and token answer Entra ID publishes,
at its own paths, through a standalone launch to a token whose ID Token
carries the mapped `fhirUser`. Citations are to `docs/specs/entra-docs/`,
`docs/identity-platform/`.

| Setting | Value | Ground |
|---|---|---|
| App registration | Supported account types: single tenant only | `quickstart-register-app.md`, Register an application |
| Authority | `https://login.microsoftonline.com/{tenant id}/v2.0`, FerroSMART's `upstream.issuer`; its metadata is at `/.well-known/openid-configuration` under it | `v2-protocols-oidc.md`, Find your app's OpenID configuration document URI; `oidc discovery §4` |
| Platform and redirect URI | Web, FerroSMART's `{issuer}/callback`, `https` | `how-to-add-redirect-uri.md`, Add a redirect URI; `reply-url.md`, What are the restrictions of redirect URIs; `rfc9700 §2.1` |
| Client credential | a certificate of FerroSMART's current assertion key (`[ferrosmart.upstream.oidc.private_key_jwt.keys]`, never a token key), uploaded to the registration; FerroSMART signs a client assertion with that key under `PS256`, naming the certificate by `x5t#S256`, `iss` and `sub` the client id, `aud` the authority's issuer identifier and `typ` `client-authentication+jwt` (13.22; `certificate-credentials.md` names the token endpoint as `aud`, and #620 checks the issuer on a live tenant) | `how-to-add-credentials.md`, Add a certificate; `certificate-credentials.md`, Assertion format, Register your certificate with Microsoft identity platform; `oidc core §9`; `rfc10070 §4`, `§6`; `rfc7515 §4.1.8` |
| PKCE | `S256` on every request, which the code flow takes | `v2-oauth2-auth-code-flow.md`, Request an authorization code (`code_challenge_method`); `rfc7636 §4.2` |
| Scopes | `openid profile`; `profile` brings `name`, `preferred_username` and `oid` | `id-token-claims-reference.md`, Payload claims |
| App role | `clinician`: allowed member types Users/Groups, value `clinician`, assigned to people under Enterprise applications; the ID Token carries it in `roles` | `howto-add-app-roles-in-apps.md`, Declare roles for an application, Usage scenario of app roles |
| `fhirUser` | a directory extension attribute `fhirUser` registered on the application through Microsoft Graph, set per user, and the ID Token optional claim `extension_<appid>_fhirUser`, which Entra ID emits as `extn.fhirUser` | `schema-extensions.md`, Register and use directory extensions, Emit claims using Graph or PowerShell; `optional-claims.md`, Configure directory extension optional claims, Directory extension formatting |

On FerroSMART's side, `[[ferrosmart.upstream]]` names the tenant authority and
the Application (client) ID, `[ferrosmart.upstream.oidc.private_key_jwt]` its
client authentication, and `preset = "entra"` brings `fhir_user_claim = "extn.fhirUser"`,
`role_claims = ["roles"]` and `PS256`. A claim name holding a dot is read whole before a
dotted path steps into an object (`ferrohealth_smart::roles`, #562), which is
what reads `extn.fhirUser`; no code knows Entra ID. Three readings of the
vendored text are decisions:

1. **The person is keyed by `sub`.** Entra ID's `sub` is immutable and
   pairwise per application, and `oid` is the same person across the
   tenant's applications (`id-token-claims-reference.md`, Use claims to
   reliably identify a user). FerroSMART derives its pairwise `sub` from the
   issuer and `sub` (13.6 item 9); `oid` and `tid` are not read, and the
   tenant is fixed by the authority, so `tid` adds nothing.
2. **Roles come from app roles, never groups.** A person in more groups than
   the token holds gets the `_claim_names` and `_claim_sources` overage
   instead of `groups` (`id-token-claims-reference.md`, Groups overage
   claim), which points at Microsoft Graph and which FerroSMART does not
   follow. App roles belong to the application, so their values hold in
   every tenant where group ids and names differ
   (`howto-add-app-roles-in-apps.md`, App roles vs. groups), and a group
   assigned to an app role gives its members that role in `roles`. The
   book's identity provider page says what an administrator does about it,
   and that the licence a group assignment needs is not in the vendored
   pages (`website/book/src/install/upstream.md`).
3. **The multitenant authorities are refused.** `/common` and
   `/organizations` are no issuer: the issuer in a token is the person's
   tenant (`howto-convert-app-to-be-multi-tenant.md`, Update your code to
   send requests to `/common`), so their metadata names an issuer other than
   the URL it was read under, which `oidc discovery §4.3` has a relying party
   refuse. FerroSMART fails discovery with `IssuerMismatch` and serves no
   login. Several tenants are several `[[ferrosmart.upstream]]` entries,
   each with its tenant's authority as its issuer (13.10, #678), so one
   FerroSMART logs in the people of each, with a pairwise `sub` per tenant.
4. **Logout is front-channel.** Entra ID sends its single sign-out as an
   HTTP GET to each app's front-channel logout URL
   (`v2-protocols-oidc.md`, Single sign-out) and documents no back-channel
   logout, so the registration names `{issuer}/frontchannel-logout`. That
   URI acts only on a request that carries `iss` and `sid`
   (`frontchannel §2`), and the login's `sid` comes from the ID Token; the
   vendored page states neither, so a deployment checks that Entra ID's
   discovery document says `frontchannel_logout_session_supported` and that
   the ID Token carries `sid` before relying on it. FerroSMART's
   end-session endpoint forwards to Entra ID's `end_session_endpoint`,
   whose `post_logout_redirect_uri` "must match one of the redirect URIs
   registered" (Send a sign-out request), so `{issuer}/logout/return` is
   registered beside `{issuer}/callback`.

Entra ID advises a certificate over a client secret in production
(`how-to-add-credentials.md`, Add a client secret), and FerroSMART takes no
client secret at all (13.22). The key is FerroSMART's assertion key, with
its ring's rotation: upload the next key's certificate before the ring makes
it current, and remove the old one after.

### 13.19 Upstream providers: Okta

Okta runs upstream of FerroSMART for login only (#525). It is a hosted
service, so no example runs it: `app/ferrosmart/examples/okta/ferrosmart.toml`
is FerroSMART's side, run by the same contract tests against a stub of the
discovery documents, key set and token answer Okta publishes. Okta's pages
are "All rights reserved", so `scripts/vendor/okta.sh` pins them by URL and
sha256 into the git-ignored `.vendor-cache/okta/` and the table cites them by
page and section; none of their text is in the tree
(`docs/specs/okta/PROVENANCE.md`).

| Setting | Value | Ground |
|---|---|---|
| Authorization server | the custom authorization server `default`, issuer `https://{Okta domain}/oauth2/default`; its RFC 8414 metadata is at `/.well-known/oauth-authorization-server/oauth2/default` | Authorization servers: Issuer - custom authorization server, Discovery endpoints - default custom authorization server; Custom Authorization Servers, Retrieve the OAuth 2.0 metadata; `rfc8414 §3` |
| App integration | a Web Application: the Authorization Code grant, which a web app always has | Implement the Authorization Code grant (Set up your app) |
| Redirect URI | FerroSMART's `{issuer}/callback` as the one Sign-in redirect URI | Implement the Authorization Code grant (Sign-in redirect URIs); `rfc9700 §2.1` |
| Client authentication | Public key / Private key: the integration's public keys hold the JWK FerroSMART publishes at `{issuer}/upstream-jwks`, and FerroSMART signs each client assertion with the current assertion key under `RS256`, `iss` and `sub` the client id, `aud` the authorization server's issuer identifier and `typ` `client-authentication+jwt` (13.22; the guide names the token endpoint as `aud`, and #620 checks the issuer on a live org) | OpenID Connect & OAuth 2.0 API, Client authentication, JWT with private key; `oidc core §9`; `rfc10070 §4`, `§6` |
| PKCE | `S256` on every request; the metadata names `S256` in `code_challenge_methods_supported` | Custom Authorization Servers, Retrieve the OAuth 2.0 metadata; `rfc7636 §4.2` |
| `fhir_user` claim | a custom claim on the authorization server: include in the ID Token, Always, value type Expression reading the person's `fhirUser` profile attribute | Customize tokens returned from Okta, Add a custom claim to a token |
| `groups` claim | a groups claim on the authorization server: include in the ID Token, Always, a Groups filter matching FerroSMART's role groups | Customize tokens with a groups claim, Add a groups claim for a custom authorization server |
| Group | `clinician`, assigned to the app integration, which `[[ferrosmart.role]]` maps to `user/` scopes | Overview, Subtle behavior (a user is assigned to the client); 13.6 item 5 |

On FerroSMART's side, `[[ferrosmart.upstream]]` names the authorization server
and the client, `[ferrosmart.upstream.oidc.private_key_jwt.keys]` its client
authentication, and `preset = "okta"` brings `fhir_user_claim = "fhir_user"` and `role_claims =
["groups"]`. No code knows Okta. Three readings are decisions:

1. **The custom authorization server, never the org one.** Okta's pages
   disagree on whether the org authorization server takes a custom claim in
   the ID Token: Authorization servers (Which authorization server should
   you use) says it does, Customize tokens returned from Okta (Add a custom
   claim to a token) says only a custom authorization server does. The
   procedure that is written down is the custom one, so FerroSMART's setup
   uses it.
2. **The groups filter is narrow.** The groups claim holds at most 100
   groups, and a request matching more fails (Overview, ID token claims), so
   the filter names FerroSMART's role groups, never every group.
3. **`nonce` is in the ID Token.** The sample ID Token payload of the
   Overview carries none, while the custom claim guide's carries the one
   its request sent. OpenID Connect Core 1.0 §2 has a provider include the
   `nonce` the request sent; FerroSMART sends one on every request and
   refuses an ID Token without it (`oidc core §3.1.3.7` item 11), so the
   stub follows the specification.

### 13.20 Upstream providers: ZITADEL

ZITADEL v4.20.3 (the release the ZITADEL documentation pin names, run
unmodified) runs upstream of FerroSMART for login only (#523). The example
is `compose.zitadel.yaml`, an override of the quickstart, and
`scripts/idp/zitadel-launch.sh` runs the same pieces in CI: a SMART
standalone launch through ZITADEL to a token response whose ID Token and
access token carry the person's `fhirUser`, with a `user/` scope a ZITADEL
role grants. Citations are to `docs/specs/zitadel/`, ZITADEL's
`apps/docs/content/` unless named otherwise.

`app/ferrosmart/examples/zitadel/bootstrap.sh` makes everything through
ZITADEL's v2 APIs, with the IAM_OWNER token the first instance writes
(`cmd/setup/steps.yaml`, FirstInstance). Every id it can choose is fixed;
ZITADEL generates the OIDC client id, the application's private key with
its key id, and the target's signing key, so the script writes them out
with the FerroSMART configuration that names them.

| Setting | Value | Ground |
|---|---|---|
| Project | `ferrosmart`, role assertion on, the role `clinician` | `proto/zitadel/project/v2/project_service.proto` (CreateProject, AddProjectRole); `guides/integrate/retrieve-user-roles.mdx` |
| Application | `ferrosmart-login`: an OIDC web app, the code flow, one redirect URI `{issuer}/callback`, roles and userinfo asserted into the ID Token | `proto/zitadel/application/v2/application_service.proto` (CreateApplication, CreateOIDCApplicationRequest); `rfc9700 §2.1` |
| Client authentication | Private Key JWT (`OIDC_AUTH_METHOD_TYPE_PRIVATE_KEY_JWT`) with an application key ZITADEL generates (CreateApplicationKey); FerroSMART's assertion ring holds that key under ZITADEL's key id as `kid`, and each assertion names ZITADEL's issuer as its sole `aud`, which ZITADEL requires (zitadel/oidc v3.47.5, `JWTProfileVerifier`) | `proto/zitadel/application/v2/oidc.proto`, `application_service.proto` (CreateApplicationKeyResponse.key_details); `oidc core §9`; `rfc10070 §4` |
| PKCE | `S256` on every request FerroSMART sends; ZITADEL applies it to a web app that sends it | `rfc7636 §4.2`; `apis/openidoauth/endpoints.mdx` |
| User | `clinician`, its role granted, the metadata `fhir_user` | `proto/zitadel/user/v2/user_service.proto` (AddHumanUser, SetUserMetadata); `proto/zitadel/authorization/v2/authorization_service.proto` |
| `fhirUser` | an Actions v2 execution on the `preuserinfo` function calls the example's target, `tools/zitadel-fhir-user`, which checks the `ZITADEL-Signature` and answers `append_claims` with `fhirUser` from the metadata | `guides/integrate/actions/usage.mdx` (PreUserinfo, Content Signing); `pkg/actions/signing.go`; `proto/zitadel/action/v2/` |
| Target address | ZITADEL refuses a target on a private address by default; the example lifts `localhost`, `127.0.0.0/8` and `::1/128` from the deny list, where its target listens beside ZITADEL, and keeps the rest | `cmd/defaults.yaml`, HTTPClient.DenyList |
| Roles | `urn:zitadel:iam:org:project:ferrosmart:roles`, an object whose member names are the roles, read by `ferrohealth_smart::roles` (3.4, #543) | `guides/integrate/retrieve-user-roles.mdx` |
| Audience | ZITADEL names the project beside the client in every ID Token's `aud`, so `trusted_audiences = ["ferrosmart"]` | `oidc core §3.1.3.7` items 3 and 4 |

On FerroSMART's side `[[ferrosmart.upstream]]` names ZITADEL's issuer and
the generated client, `[ferrosmart.upstream.oidc.private_key_jwt.keys]` the
application key, `preset = "zitadel"` brings `fhir_user_claim = "fhirUser"`, and the
entry names the project's role claim and the trusted audience over the
preset's project-neutral `urn:zitadel:iam:org:project:roles`. No code knows ZITADEL: `trusted_audiences` is
`ferrohealth_smart::oidc::RelyingParty::with_trusted_audiences`, the item 3
rule ("additional audiences not trusted by the Client") for any provider,
and an ID Token with several audiences must then carry an `azp` naming the
client (item 4).

The role claim's shape was checked against a live v4.20.3: the server
writes the object `retrieve-user-roles.mdx` shows
(`{"clinician": {"<orgId>": "<orgDomain>"}}`), and the array
`apis/openidoauth/claims.mdx` shows does not occur. FerroHEALTH/FerroSMART#565
is the upstream report.

ZITADEL has no password grant (`apis/openidoauth/grant-types.mdx`), so the
CI launch logs in with ZITADEL's custom login flow
(`guides/integrate/login-ui/oidc-standard.mdx`): a session with a password
check, then the callback of the auth request, with the login client's
token (`scripts/idp/authorize.sh`). A person uses the Login v2 UI the
example runs at `http://localhost:3000/ui/v2/login`.

### 13.21 A product behind FerroSMART

A FerroHEALTH product runs behind FerroSMART as a resource server, and an
OpenID Connect provider runs upstream for login only. The person never
signs in to the product. Any IdP works upstream: 13.16 and 13.18 to 13.20
name Keycloak, Microsoft Entra ID, Okta and ZITADEL. The resource server
can be FerroEHR, FerroBRIDGE, FerroTERM, FerroPIX or FerroFED. Each product's
adoption issue tracks its own side (#521).

```
 browser                SMART app             FerroSMART               IdP (login only)
    |   1. launch          |                       |                          |
    |--------------------->|  2. /authorize        |                          |
    |                      |  aud = product base   |                          |
    |<---------------------------------------------|  3. OIDC login           |
    |------------------------------------------------------------------------>|
    |<------------------------------------------------------------------------|
    |  4. patient picker and consent (13.6 items 4 and 6)                      |
    |--------------------------------------------->|                          |
    |                      |<-- 5. code, /token -->|                          |
    |                      |   RFC 9068 access token, launch context          |
    |                      |                                                   |
    |                      |  6. API call, Bearer token                        |
    |                      |-------------------------> product (resource server)
    |                      |                          reads the token under the
    |                      |                          `ferrosmart` preset, keys
    |                      |                          from FerroSMART's jwks_uri
```

1. **FerroSMART names the product's base** as a resource, so a launch can
   use it as `aud` (13.10):

   ```toml
   [[ferrosmart.resource]]
   base = "https://ehr.example.org/openehr/v1"   # or the FHIR base
   kind = "openehr"                               # or "fhir"
   subject_namespace = "examples"                # openEHR only: the picker's EHR lookup (13.6 item 4)
   ```

2. **The product trusts FerroSMART** in one `persons` issuer table under
   the `ferrosmart` preset (3.3, the profile section). The preset keeps
   every `rfc9068` default except three: `typ` is `at+jwt` alone, `scope`
   is required, and `fhir_user_patient` reads a patient's own token as the
   person (3.13). A token FerroSMART issued for the product's base names it
   in `aud`, since FerroSMART issues a client's tokens only for the bases
   its `resources` lists (13.6 item 13), so the product admits every app
   registered at FerroSMART and keeps no list of its own (`rfc9068 §4`,
   `rfc8707`). It reads the person's own access with
   `Caller::is_the_person`; one table serves professionals and patients, so
   a deployment needs no second FerroSMART for patients. Its own access
   policy still decides each request. The same table reads a Backend
   Services token as `System`,
   because its `sub` is its `client_id` (`rfc9068 §2.2`), and a `persons`
   issuer reads the app-only tokens of its machines too. One issuer takes one
   table: `AuthSection::resolve` refuses a second table naming it (#591).

   ```toml
   [auth.issuer.smart]
   issuer = "https://smart.example.org"
   ```

3. **The product's discovery document describes FerroSMART.** The
   product's `.well-known/smart-configuration` names FerroSMART's
   `authorization_endpoint` and `token_endpoint` through the described-issuer
   rule of 3.8, so an app that starts at the product's base finds
   FerroSMART.

4. **FerroSMART logs the person in at the IdP.** Its `[[ferrosmart.upstream]]`
   section names the IdP, the claim that carries `fhirUser` and the role
   claims. The roles map to the scopes the person may be granted
   (`[[ferrosmart.role]]`). The product never sees the IdP's tokens: the
   person's `sub` is FerroSMART's pairwise identifier (13.6 item 9).

The launch context (`patient`, `encounter`, `fhirUser`, and `ehrId` at an
openEHR base) reaches the product in the access token (13.6 item 2), where
`Caller::patient` and `Caller::ehr_id` read it. The product's own rules
still apply on top of the token's scopes. No specification governs this
deployment shape: our own design, built only from the specifications 13.4
names.

**A server that is no FerroHEALTH product.** A resource server needs none
of the family's crates to take FerroSMART's tokens: an RFC 9068 access
token is validated with the issuer, the JWK Set and the audience alone
(`rfc9068 §4`: the signature, `iss`, `aud` and `exp`). A CI lane holds that
(#598, `scripts/idp/third-party-fhir.sh`): HAPI FHIR, a third-party FHIR
server, runs behind Envoy's JWT authentication filter, which is given
FerroSMART's issuer, `{issuer}/jwks` and the FHIR base as its audience and
nothing else (`app/ferrosmart/third-party/envoy.yaml`), both images pinned
by digest in `docs/VERSIONS.md`. Through the validator a Backend Services
token and a person's token from a standalone launch through Keycloak each
read a `Patient`; a request without a token, a token for another audience
and a token past its `exp` are refused. Envoy validates locally and never
introspects, so it takes a revoked token until its `exp`, at most the
access token's lifetime later. The lane therefore revokes a
token and reads `{issuer}/introspect` as a resource server that introspects
would, with a bearer token carrying `system/introspect` (13.6 item 8), and
the answer is `{"active": false}` (`rfc7662 §2.2`). Beside Envoy, Apache
APISIX in standalone mode guards the same server with its `openid-connect`
plugin (#639, `app/ferrosmart/third-party/apisix.yaml`, pinned by digest in
`docs/VERSIONS.md`), which introspects every token at FerroSMART as the
confidential symmetric client `third-party-gateway` by HTTP Basic (13.6
item 8): a request without a token is refused, an active token reads the
`Patient`, and a token revoked before the gateway first saw it is refused.
The plugin holds an active answer until the token's `exp`, so a token
revoked after it passed is taken until then, and it checks no `aud`. The
filter does not
verify the `typ` header, which `rfc9068 §4` also requires of a resource
server, and enforces no scope: HAPI FHIR serves whatever passes it, so the
lane shows token validation and no scope enforcement. The choice of server
and validator is our own design.

### 13.22 Client authentication at the upstream provider

FerroSMART authenticates at a provider's token and revocation endpoints
with `private_key_jwt` by default, or with `client_secret_basic` (`rfc6749
§2.3.1`) where the administrator chooses it for that provider (`oidc core
§9` defines both and makes neither mandatory for a relying party; owner
decision of 2026-11-19, #679, which reverses the `private_key_jwt`-alone
rule of 2026-11-17, #619). Each `[ferrosmart.upstream.oidc]` table names
at most one: `[ferrosmart.upstream.oidc.private_key_jwt]`, taken when it
names neither (#733), or `[ferrosmart.upstream.oidc.client_secret_basic]`
with `secret` or `secret_file`, read through `ferrohealth-secret` and
redacted in every rendering. A table naming both is refused at load, and
a secret anywhere else is an unknown key. At start FerroSMART reads the
provider's `token_endpoint_auth_methods_supported` (`rfc8414 §2`,
`client_secret_basic` when absent) and refuses a provider that does not
list the method. Choose the secret only for a provider that offers no
`private_key_jwt` for a web client: OAuth 2.1 and FAPI 2.0 prefer
asymmetric client authentication, a secret can leak from a configuration
file, and FerroSMART holds keys already.

Every provider is set up the same way, in one shape:

| Provider | Login | Client authentication | `fhirUser` | Roles | Tested by |
|---|---|---|---|---|---|
| Keycloak (13.16) | the realm's login form, the code flow with PKCE `S256` | the client authenticator "Signed JWT" (`client-jwt`), reading `{issuer}/upstream-jwks` | a user attribute mapper, `fhir_user` | a realm role mapper, `roles` | the CI Keycloak lane and the compose quickstart lane, a live launch |
| ZITADEL (13.20) | the Login v2 UI, the code flow with PKCE `S256` | Private Key JWT with an application key ZITADEL generates, held under its key id | the Actions v2 `preuserinfo` target, `fhirUser` from user metadata | the project role claim `urn:zitadel:iam:org:project:ferrosmart:roles` | the CI ZITADEL lane, a live launch |
| Microsoft Entra ID (13.18) | the tenant's sign-in, the code flow with PKCE `S256` | certificate credentials: the certificate of the current assertion key, named by `x5t#S256` | a directory extension attribute, `extn.fhirUser` | app roles, `roles` | the contract test against a stub of Entra ID's documents |
| Okta (13.19) | the org's sign-in through the `default` custom authorization server, the code flow with PKCE `S256` | Public key / Private key, the JWK of `{issuer}/upstream-jwks` | a custom claim, `fhir_user` | a groups claim, `groups` | the contract test against a stub of Okta's documents |

Under `[ferrosmart.upstream.oidc.private_key_jwt]` the current key of the
assertion ring signs a fresh assertion for every request: `iss` and `sub`
the client id, `aud` the provider's issuer identifier as its sole value, a
unique `jti`, `exp` 60 seconds ahead, typed `client-authentication+jwt`
(`rfc10070 §4`, which updates `rfc7523 §3`). RFC 10070 supersedes the
token endpoint URL `oidc core §9` recommends ("SHOULD") for
`private_key_jwt`, and §6 has a client that follows it interoperate with
servers of either rule. One rule holds for every provider (owner decision
of 2026-11-17); a revocation request carries the same assertion shape. The
providers stand on it differently:

- Keycloak accepts the issuer as a single `aud` (`JWTClientValidator.java`,
  the issuer among the expected audiences) and refuses an array by default.
- ZITADEL requires its issuer in `aud` (zitadel/oidc v3.47.5,
  `JWTProfileVerifier` with `CheckAudience` against the issuer).
- Entra ID (`certificate-credentials.md`, Assertion format) and Okta
  (Client authentication, JWT with private key) document the token endpoint
  URL and do not mention RFC 10070. Both rest on RFC 10070 §6 until a test
  on a real tenant confirms them; FerroHEALTH/FerroSMART#620 is that test
  plan, and a refusal becomes an upstream report for the owner to decide.

`algorithm` is the one the provider's registration names (`rfc7518 §3.1`;
the preset's, else RS256), and the ring's keys are read to sign with it. `kid`
under the keys table is the id a provider knows the key by (ZITADEL's key
id), the RFC 7638 thumbprint when empty. `certificate_file` is the X.509
certificate of the current assertion key, for a provider that knows the key
by its certificate; each assertion then names it by `x5t#S256`
(`rfc7515 §4.1.8`), and a certificate of another key is refused at load.

**One key per purpose.** The assertion ring is
`[ferrosmart.upstream.oidc.private_key_jwt.keys]` (a current key, the previous
one for its overlap and the next one) and never holding a key of `[ferrosmart.keys]`:
a ring that shares a key with the token ring is refused at load. RFC 8725
§3.12 has JWTs of different kinds validated by mutually exclusive rules, and
separate keys give that by construction: an assertion key, leaked or
misused, signs nothing a resource server of FerroSMART's accepts. The ring
is published at its own `{issuer}/upstream-jwks` (`discovery::UPSTREAM_JWKS_ROUTE`),
apart from the token key set at `{issuer}/jwks`, so a provider that reads it,
as Keycloak does, trusts the assertion keys alone and a resource server
never sees them. The route answers `404` when no upstream provider is
configured, and no metadata document names it, since it is FerroSMART's key
as a client, not as an authorization server.

The assertion ring rotates as 13.11 describes for the token ring: the next
key is published at `{issuer}/upstream-jwks` before it signs, so a provider
that reads that URL holds it in time; a provider that stores a certificate
is given the next key's certificate before the rotation. No specification
governs the rotation or the route: our own design.

### 13.23 Conformance to SMART App Launch 2.2.0

The audit of FerroSMART against the whole SMART App Launch 2.2.0
implementation guide (vendored under `docs/specs/smart-app-launch/`, the
`hl7.fhir.uv.smart-app-launch` 2.2.0 package and the page sources) runs
section by section, each with its own issue under #512.

**Capabilities** (`smart conformance`, Capabilities). The App Launch
document lists exactly the supported rows; `the_document_lists_exactly_the_capabilities_the_server_supports`
holds the list to this table and to the case each row names, and
`what_the_document_leaves_out_the_server_refuses` holds the rows marked
absent.

| Capability | Status | Test |
|---|---|---|
| `launch-ehr` | supported | `ehr_launch::an_ehr_launch_carries_its_context_to_the_token_response` |
| `launch-standalone` | supported | `authorize::a_standalone_launch_logs_in_upstream_asks_consent_and_issues_tokens` |
| `authorize-post` | supported | `authorize::an_authorization_request_by_post_is_the_get_s_twin` |
| `client-public` | supported | `authorize::a_standalone_launch_logs_in_upstream_asks_consent_and_issues_tokens` |
| `client-confidential-symmetric` | supported: `client_secret_basic` and `client_secret_post` against an Argon2id hash, never for Backend Services | `symmetric::a_symmetric_client_authenticates_by_http_basic` |
| `client-confidential-asymmetric` | supported | `token::a_backend_services_client_gets_an_rfc_9068_token` |
| `sso-openid-connect` | supported | `authorize::a_standalone_launch_logs_in_upstream_asks_consent_and_issues_tokens` |
| `context-banner` | supported | `ehr_launch::an_ehr_launch_carries_its_context_to_the_token_response` |
| `context-style` | supported when `[ferrosmart.branding] smart_style_url` is set | `authorize::a_standalone_launch_logs_in_upstream_asks_consent_and_issues_tokens` |
| `context-ehr-patient` | supported | `ehr_launch::an_ehr_launch_carries_its_context_to_the_token_response` |
| `context-ehr-encounter` | supported | `ehr_launch::an_ehr_launch_carries_its_context_to_the_token_response` |
| `context-standalone-patient` | supported when the picker can search a resource server (any FHIR base; an openEHR base with a `subject_namespace`) | `authorize::a_standalone_launch_picks_a_patient_the_person_may_see` |
| `context-standalone-encounter` | supported when a resource server is a FHIR one: the picker offers the chosen patient's encounters; never at an openEHR base, which has no Encounter resource to choose from | `authorize::encounter_picker::a_standalone_launch_picks_an_encounter_of_the_chosen_patient` |
| `permission-offline` | supported | `authorize::an_offline_access_launch_issues_a_refresh_token_that_rotates` |
| `permission-online` | supported | `authorize::an_online_access_launch_ends_with_its_upstream_login` |
| `permission-patient` | supported | `authorize::a_standalone_launch_picks_a_patient_the_person_may_see` |
| `permission-user` | supported | `authorize::a_standalone_launch_logs_in_upstream_asks_consent_and_issues_tokens` |
| `permission-v1` | supported: a v1 scope is matched by its v2 form (`read` as `rs`, `write` as `cud`, `*` as `cruds`) and granted as asked | `authorize::a_v1_scope_is_offered_by_its_v2_form_and_granted_as_asked` |
| `permission-v2` | supported | `authorize::a_standalone_launch_logs_in_upstream_asks_consent_and_issues_tokens` |
| `smart-app-state` | never: the `$smart-app-state` operations are FHIR operations on stored `Basic` resources, so the resource server serves them (`smart app-state`) | `authorize::what_the_document_leaves_out_the_server_refuses` |

**Discovery metadata** (`smart conformance`, Metadata). The App Launch
document carries `issuer` and `jwks_uri` (with `sso-openid-connect`),
`authorization_endpoint`, `token_endpoint`,
`token_endpoint_auth_methods_supported` (`private_key_jwt`,
`client_secret_basic`, `client_secret_post`, `none`) with
`token_endpoint_auth_signing_alg_values_supported` (`RS384`, `ES384`, as
`smart client-confidential-asymmetric`, Advertising server support
requires), `grant_types_supported` (`authorization_code`,
`client_credentials`, the two options of `smart conformance`, Metadata;
the RFC 8414 and OpenID Connect metadata list `refresh_token` beside them,
with or without a login, since RFC 8414 §2 lists every grant the token
endpoint serves, and the token endpoint refuses any grant its metadata
leaves out, #735), `scopes_supported` (the identity, launch context and
refresh scopes FerroSMART honours whatever a client registers; the resource
scopes depend on each client's ceiling and are left out, since "The server
SHALL support all scopes listed here"), `response_types_supported`
(`code`), `management_endpoint`, `introspection_endpoint`,
`revocation_endpoint`, `capabilities` and `code_challenge_methods_supported`
(`S256` alone). `registration_endpoint` and `associated_endpoints` are
absent, since FerroSMART has neither, and `user_access_brand_bundle` and
`user_access_brand_identifier` belong in each FHIR server's document
(13.5), which may name FerroSMART's `{issuer}/brands`.

**§2.1 App Launch and §2.2 Scopes and Launch Context** (`smart
app-launch`, `smart scopes-and-launch-context`). One row per SHALL and
SHOULD. A requirement on the app, the resource server or the EHR names
who holds it; FerroSMART's own rows name the case that holds them.

| Requirement | Level | Holder and status | Test |
|---|---|---|---|
| Apps protect sensitive data in transit, generate and check an unpredictable `state`, run no untrusted input, forward nothing from the redirect, keep tokens out of cookies and in app storage (App Launch, Security and Privacy Considerations; Validate the state value) | SHALL, SHOULD | the app's; FerroSMART refuses an empty `state` and returns the one it got | `authorize::a_request_that_breaks_the_profile_is_sent_back_with_its_error` |
| Every app supports PKCE; the server supports `S256` and not `plain` (Considerations for PKCE Support) | SHALL | met: `S256` alone, `plain` refused | `authorize::a_request_that_breaks_the_profile_is_sent_back_with_its_error` |
| The server checks that `code_verifier` is present and valid at the code exchange (Obtain access token, Note on PKCE Support) | SHALL | met | `authorize::a_code_exchange_that_does_not_hold_is_refused_and_burns_nothing` |
| CORS on the discovery endpoints for any origin, on the token endpoint for a client's registered origins (Considerations for CORS support) | SHALL | met; the FHIR REST API's CORS is the resource server's | `authorize::a_token_response_is_readable_from_the_app_s_origin_alone`, `discovery::the_smart_configuration_is_json_whatever_the_accept_header` |
| Every app registers fixed, fully specified redirect URIs and launch URLs (Register App with EHR) | SHALL | met for redirect URIs: an authorization code client registers absolute ones, matched exactly; a launch URL is the EHR's | `clients::an_authorization_code_client_registers_absolute_redirect_uris` |
| The `state` parameter is used against CSRF and session fixation (Obtain authorization code) | SHALL | the app's; FerroSMART requires it and echoes it | `authorize::a_request_that_breaks_the_profile_is_sent_back_with_its_error` |
| The server supports the `aud` parameter (Obtain authorization code) | SHALL | met: `aud` names a configured resource server, else the request is refused; with exactly one configured, a request without `aud` defaults to it, as the token endpoint defaults `resource` (owner, 2026-11-19, #670; our own design) | `authorize::a_request_that_breaks_the_profile_is_sent_back_with_its_error`, `authorize::a_request_without_aud_defaults_to_the_one_configured_base`, `authorize::a_request_without_aud_is_refused_with_two_bases` |
| The app limits its scopes to the minimum (Obtain authorization code) | SHOULD | the app's; the consent page lets the person untick any resource scope | `authorize::the_consent_page_offers_what_the_ceiling_and_the_roles_allow` |
| The authorization endpoint supports GET and POST (Obtain authorization code) | SHALL | met | `authorize::an_authorization_request_by_post_is_the_get_s_twin` |
| Confidential clients use asymmetric authentication if available (Obtain access token) | SHOULD | the client's; both profiles are offered (§4.1, §4.2) | `token::a_backend_services_client_gets_an_rfc_9068_token` |
| The token response is JSON with `access_token`, `token_type`, `expires_in`, `scope` and the granted context (Obtain access token, Response) | SHALL | met | `authorize::a_standalone_launch_logs_in_upstream_asks_consent_and_issues_tokens` |
| The token response carries `Cache-Control: no-store` and `Pragma: no-cache` (Obtain access token, Response) | SHALL | met | `authorize::a_standalone_launch_logs_in_upstream_asks_consent_and_issues_tokens`, `token::a_backend_services_client_gets_an_rfc_9068_token` |
| Access tokens live no longer than one hour (Obtain access token, Response) | SHOULD | met: `access_token_lifetime` is five minutes by default and refused above one hour | `config::a_token_lifetime_over_one_hour_is_refused` |
| A token past `expires_in` is not accepted (Obtain access token, Response); the resource server validates the token and its scope (Access FHIR API) | SHALL | the resource server's; FerroSMART's introspection answers an expired token inactive | `introspection::an_expired_token_is_inactive` |
| The app does not follow a reference to another server with its token (Access FHIR API) | SHOULD | the app's | none |
| A refresh token is bound to its `client_id` and carries the same or fewer claims (Refresh access token) | SHALL | met | `refresh::a_refresh_token_is_bound_to_its_client`, `refresh::a_refresh_may_narrow_the_scope_and_never_widen_it` |
| v1 scopes: advertise `permission-v1`, process `.read`, `.write`, `.*` as `.rs`, `.cud`, `.cruds`, return v1 when v1 was granted (Scopes for requesting FHIR Resources) | SHOULD | met | `authorize::a_v1_scope_is_offered_by_its_v2_form_and_granted_as_asked` |
| A server that links Patients through `Patient.link` documents its authorization behaviour (Patient-specific scopes) | SHALL | the resource server's; FerroSMART reads no `Patient.link` | none |
| An unsupported `?role=` gets any launch context of the resource type (Scopes for requesting context data) | SHOULD | met for an EHR launch: the EHR's `fhirContext` items return under `launch` whatever role was asked; a standalone launch offers no `launch/` scope beyond `launch/patient` and `launch/encounter` | `ehr_launch::an_ehr_launch_carries_its_context_to_the_token_response` |
| A granted `patient/` scope has a patient in context (Apps that launch from the EHR; Standalone apps) | SHALL | met: `patient/` scopes are offered only with a patient from the EHR launch or the picker, and the launch scopes that carry the context are fixed lines the form cannot drop | `ehr_launch::a_launch_needs_the_launch_scope_and_a_form_cannot_drop_the_context`, `authorize::a_standalone_launch_picks_a_patient_the_person_may_see` |
| A standalone app's `launch/patient` and `launch/encounter` are provided (Standalone apps) | SHOULD | met: the picker chooses the patient at a FHIR base and at an openEHR base with a `subject_namespace` (with a `fhir_base`, the FHIR `Patient` and their EHR together), and one of the patient's encounters at a FHIR base; the person may go on without an encounter, which drops `launch/encounter` from the offer. At an openEHR base no encounter is chosen: openEHR has no Encounter resource, and the SMART on openEHR draft's context is the `ehrId` (Context Selection) | `authorize::encounter_picker::a_standalone_launch_picks_an_encounter_of_the_chosen_patient`, `authorize::encounter_picker::a_person_may_go_on_without_an_encounter`, `authorize::ehr_picker::a_standalone_launch_at_an_openehr_server_picks_the_ehr_the_person_may_see`, `authorize::paired_picker::a_standalone_launch_at_a_paired_openehr_base_picks_the_patient_and_their_ehr` |
| Each `fhirContext` item has `reference`, `canonical` or `identifier`; a `role` is never empty (Launch context arrives with your access_token, fhirContext) | SHALL | met: an EHR's launch registration breaking either is refused | `launch::a_launch_registration_breaking_a_rule_is_refused` |
| The app shows a default UI without a style; the style URL serves a SMART Style object; a changed style gets a new URL (Styling) | SHOULD, SHALL | the app's and the deployment's: `smart_style_url` is configuration, `https` only, and a new style document is published at a new URL | `config::a_style_url_other_than_https_is_refused` |
| OpenID Connect: the Authorization Code Flow (Scopes for requesting identity data) | SHALL | met: `code` alone | `authorize::a_request_that_breaks_the_profile_is_sent_back_with_its_error` |
| Public keys published as bare JWKs | SHALL | met | `discovery::the_jwk_set_publishes_bare_rs256_keys_and_may_be_cached` |
| `fhirUser` in the ID Token when `openid` and `fhirUser` are granted | SHALL | met | `authorize::a_standalone_launch_logs_in_upstream_asks_consent_and_issues_tokens` |
| ID Tokens signed with RSA SHA-256 | SHALL | met: RS256 | `authorize::the_documents_describe_the_login_once_it_is_configured` |
| An app passes no `auth_time` or `max_age` to a server that does not take them | SHALL NOT | the app's | none |
| Scopes as URIs carry the SMART or OpenID prefix (Scopes represented as URIs) | SHALL | not applicable: FerroSMART exchanges no scope as a URI | none |

The encounter step is our own design where the specification is silent:
the picker chooses an encounter only after a patient, so a request for
`launch/encounter` without `launch/patient` is not offered it; it searches
`Encounter?patient=` as the person with a token whose one scope is
`user/Encounter.rs`, shows the latest start first, leaves out an entry of
another patient, and reads the chosen encounter again, accepting it only
when its `subject` is the chosen patient.

**§4.1 Client Authentication: Asymmetric and §4.2 Symmetric**
(`smart client-confidential-asymmetric`, `smart
client-confidential-symmetric`). One row per SHALL and SHOULD; §4.2 has no
keyword of its own, so its rows are the profile's statements.

| Requirement | Level | Holder and status | Test |
|---|---|---|---|
| The client generates a key pair and registers its public key set, by URL or by value, as a JWK Set (Registering a client) | SHALL | the client's; FerroSMART refuses a confidential asymmetric client without exactly one set | `clients::a_confidential_asymmetric_client_registers_exactly_one_jwk_set` |
| The server supports both registrations, a JWK Set URL and a JWK Set by value | SHALL | met: `jwks_uri` and `jwks` | `clients::a_backend_services_client_registers_its_jwk_set_by_url`, `clients::a_jwk_set_by_value_holds_bare_public_keys_with_kty_and_kid` |
| The JWK Set URL is reachable over TLS without authentication; the client returns `Cache-Control` | SHALL, SHOULD | the client's; FerroSMART requires `https` outside loopback and honours the header | `token::a_jwk_set_url_is_read_and_cached_as_the_client_allows` |
| The server protects a JWK Set given by value from corruption, and reminds the client to update it | SHALL, SHOULD | the deployment's: the set is a configuration file the operator owns, read at start, or a value the admin API stores (13.27), which an administrator replaces; FerroSMART has no channel to the client to send a reminder over | none |
| The client signs with RS384 and ES384; the server validates at least one | SHALL | met: both, and nothing else | `token::a_backend_services_client_gets_an_rfc_9068_token`, `token::an_rs384_assertion_typed_by_rfc_10070_naming_the_issuer_is_admitted` |
| Each JWK is an asymmetric key with `kty` and `kid`, bare `n` and `e` or `crv`, `x` and `y` | SHALL | met: a set breaking it is refused at load, a private member too | `clients::a_jwk_set_by_value_holds_bare_public_keys_with_kty_and_kid` |
| The client uses its `client_id`, and TLS 1.2 or later (Requesting an access token) | SHALL | met for TLS by `ferrohealth-server`'s listener, which offers TLS 1.2 and 1.3 alone; the lane's kit checks it | Inferno lane `standalone_auth_tls`, `backend_services_authorization` TLS |
| The authentication JWT carries `alg`, `kid`, `typ` `JWT`, `iss` and `sub` the client, `aud` the token URL, `exp` at most five minutes ahead, a `jti`; `jku` when present is the registered URL | SHALL | met: `typ` `JWT` or `client-authentication+jwt`, `aud` the token URL or the issuer (13.6 item 1) | `token::an_assertion_breaking_the_profile_is_refused`, `token::the_assertion_s_audience_is_one_string_naming_this_server`, `token::a_replayed_or_long_lived_or_unsigned_assertion_is_refused` |
| The server validates the JWT by RFC 7523 §3 and its signature | SHALL | met | `token::a_replayed_or_long_lived_or_unsigned_assertion_is_refused` |
| A `jti` seen before for the `iss` within the JWT's lifetime is refused | SHALL | met, across replicas through the store | `token::a_replayed_or_long_lived_or_unsigned_assertion_is_refused` |
| The `client_id` provided is known and matches the JWT's `iss` | SHALL | met: a form `client_id` other than the `iss` is refused (#601) | `token::an_assertion_whose_client_or_key_does_not_resolve_is_refused` |
| Key resolution: a `jku` not registered fails; without one, the registered set; exactly one key by `kid` with a `kty` fitting the algorithm | SHALL, SHOULD | met | `token::a_jwk_set_url_is_read_and_cached_as_the_client_allows`, `token::an_assertion_whose_client_or_key_does_not_resolve_is_refused` |
| An authentication error answers `invalid_client` | SHALL | met | `token::an_assertion_breaking_the_profile_is_refused`, `symmetric::a_wrong_secret_is_invalid_client` |
| A JWK Set is cached no longer than the client's `Cache-Control` allows, and cached as it allows | SHALL NOT, SHOULD | met | `token::a_jwk_set_url_is_read_and_cached_as_the_client_allows` |
| A symmetric client sends its `client_secret` by HTTP Basic (Authentication using a `client_secret`) | profile | met, with `client_secret_post` beside it (RFC 6749 §2.3.1), never both | `symmetric::a_symmetric_client_authenticates_by_http_basic`, `symmetric::a_symmetric_client_authenticates_in_the_form`, `symmetric::two_authentication_methods_at_once_are_refused` |
| The symmetric profile is for App Launch clients and not for Backend Services (Profile Audience and Scope) | profile | met: the client credentials grant and a JWK Set are refused to a symmetric client | `symmetric::a_symmetric_client_is_refused_the_client_credentials_grant_and_a_jwk_set` |
| The server knows the secret (Authentication using a `client_secret`) | profile | met: FerroSMART issues it once and keeps its Argon2id hash at the OWASP floor (`rfc7591 §3.2.1`; 13.27) | `symmetric::an_issued_secret_is_hashed_at_the_floor_with_a_fresh_salt`, `admin::a_symmetric_client_is_issued_its_secret_once_and_keeps_its_hash` |

The Inferno lane runs a symmetric client in group 2 (13.13).

**§3 Backend Services** (`smart backend-services`). One row per SHALL and
SHOULD.

| Requirement | Level | Holder and status | Test |
|---|---|---|---|
| The client registers with the server before it runs, as a confidential client with its JWK Set (Register Client) | SHALL | the client's; FerroSMART takes a Backend Services client only as `confidential_asymmetric` with one JWK Set | `clients::a_backend_services_client_registers_its_jwk_set_by_url`, `clients::a_public_client_neither_registers_keys_nor_uses_client_credentials` |
| TLS 1.2 or later on the exchange | SHALL | met by `ferrohealth-server`'s listener | Inferno lane `backend_services_authorization` TLS |
| A request for data the client is not allowed, or the server does not support, fails at the start | SHOULD | met for scopes beyond the client's ceiling (`invalid_scope`); what a resource server supports is the resource server's | `token::a_request_outside_the_grant_is_refused_with_its_own_error` |
| No refresh token is issued | SHOULD NOT | met: the client credentials grant answers without one | `token::a_backend_services_token_lives_five_minutes_at_most` |
| The requested scope is within the client's pre-authorized scope (Evaluate Requested Access) | SHALL | met: the ceiling | `token::a_request_outside_the_grant_is_refused_with_its_own_error` |
| An error answers by RFC 6749 §5.2, with an `error_description` | SHALL, SHOULD | met | `token::an_assertion_breaking_the_profile_is_refused` |
| A valid request gets a JSON token response with `access_token`, `token_type` `bearer`, `expires_in` and `scope` (Issue Access Token) | SHALL | met | `token::a_backend_services_client_gets_an_rfc_9068_token` |
| The token's scope is limited to what was requested; tokens are short-lived, `expires_in` at most 300 | SHOULD, SHALL | met: the scope granted is the requested scope within the ceiling, and a Backend Services token lives at most five minutes whatever `access_token_lifetime` says (#603) | `token::a_backend_services_token_lives_five_minutes_at_most` |
| The resource server validates the token; the client does not follow references elsewhere with its token (Access FHIR API) | SHALL, SHOULD | the resource server's and the client's | none |

**§5 Token Introspection** (`smart token-introspection`). One row per
SHALL and SHOULD.

| Requirement | Level | Holder and status | Test |
|---|---|---|---|
| The server supports Token Introspection, by RFC 7662 | SHOULD | met: `POST {issuer}/introspect`, listed as `introspection_endpoint` | `introspection::an_active_backend_services_token_answers_what_smart_requires` |
| An active token's answer carries `active`, `scope`, `client_id` and `exp` consistent with `expires_in` (Required fields) | SHALL | met | `introspection::an_active_backend_services_token_answers_what_smart_requires` |
| The launch context of the token response is in the answer (Conditional fields) | SHALL | met | `introspection::a_token_issued_under_a_grant_carries_its_launch_context` |
| With an `id_token` in the response, the answer carries its `iss` and `sub`, and `fhirUser` | SHALL, SHOULD | met | `introspection::a_token_issued_under_a_grant_carries_its_launch_context` |
| With access control, a client authorized to introspect may do so with an appropriately scoped bearer token (Authorization to perform Token Introspection) | SHALL | met: a token holding `system/introspect` for FerroSMART's own issuer, beside the client's own authentication | `introspection::a_bearer_token_with_the_introspection_scope_may_introspect`, `introspection::a_bearer_token_without_the_right_is_refused_with_a_401` |
| An inactive, expired, revoked or unknown token answers `{"active": false}` alone (RFC 7662 §2.2) | MUST | met | `introspection::an_unknown_or_forged_token_is_inactive`, `introspection::an_expired_token_is_inactive`, `introspection::a_revoked_grant_s_tokens_are_inactive` |

**§7 Best Practices** (`smart best-practices`). The page is
non-normative; each practice for a server is applied or the reason is
given. The practices for app developers are the apps'.

| Practice | Status | Test |
|---|---|---|
| Remind users which apps have offline access | applied: the management page lists every app holding a live `offline_access` or `online_access` grant, remembered or not, says how long it stays connected, and withdraws it (#608) | `authorize::the_management_page_lists_an_app_with_offline_access_and_withdraws_it` |
| Mitigate the threat of compromised refresh tokens | applied: refresh tokens rotate on every use, idle out (`refresh_idle`, `online_idle`), and are stored hashed | `refresh::a_refresh_issues_a_new_access_token_and_rotates_the_refresh_token`, `config::the_refresh_idle_times_default_and_refuse_zero` |
| Expire an app's authorization when a refresh token is used twice | applied: the second use revokes the whole grant | `refresh::a_rotated_refresh_token_presented_again_revokes_the_grant` |
| Offer binding refresh tokens to asymmetric secrets held in hardware (per-device registration, DPoP) | applied for confidential clients, whose refresh needs the client's own authentication, by its private key for an asymmetric client; not offered to public clients: SMART App Launch 2.2.0 defines no DPoP or per-device registration, and FerroSMART has no dynamic registration (13.5) | `refresh::a_confidential_client_authenticates_to_refresh` |
| A short and a long plain-language description per requested scope, in the browser's language | applied for the short one: FerroUI's scope grant reads each scope in words, with plain words for the common FHIR resource types, in the language `Accept-Language` prefers among the catalogs (English today); the long description needs FerroUI's scope grant to carry one (FerroHEALTH/FerroUI#695) | `authorize::the_management_page_lists_an_app_with_offline_access_and_withdraws_it` |
| Publish consent design documentation for client developers | applied: the book's [clients, roles and consent](https://ferrosmart.eu/docs/configure/clients.html) page says which scopes the consent page offers and why | none |
| Avoid jargon such as "Encounters" | applied: the consent and management pages put plain words before the resource type (`resource-*` messages of the catalog), the type kept for the clinician who knows it | `authorize::the_management_page_lists_an_app_with_offline_access_and_withdraws_it` |
| Explain experimental query-based scopes plainly | applied: a query-constrained scope is granted only when a client's ceiling and a role cover it: the same context and resource (or `*`), a subset of the permission letters, and the same query parameters, or none on the listed scope (#731), and the consent page shows its constraint in words (FerroUI's scope grant, "Only where") | none |

**§8 User-access Brands and Endpoints** (`smart brands`, Conformance
Overview, and the profiles `UserAccessBrandsBundle`, `UserAccessBrand`
and `UserAccessEndpoint`). FerroSMART is the deployment's Brand Bundle
Publisher when `[ferrosmart.brand]` is set: it serves the Bundle at
`GET {issuer}/brands` as `application/fhir+json`, built from that table
(13.10). One row per SHALL and SHOULD; a requirement on the Health Data
Provider, the SMART on FHIR server or the app names who holds it. The
Bundle is held to the guide's profiles by `ferrobridge-validator` over the
package set `scripts/vendor/fhir-packages.sh` fetches (`docs/VERSIONS.md`,
FHIR packages), and the guide's four example bundles are read the same way
as test vectors.

| Requirement | Level | Holder and status | Test |
|---|---|---|---|
| An Organization identifier with `system` `urn:ietf:rfc:3986` and the brand's HTTPS web presence as `value` (Health Data Provider) | RECOMMENDED | the provider's: `identifier` takes any customer-supplied `system` and `value` | `brands::the_national_lab_example_is_written_by_configuration` |
| A primary brand that references each FHIR endpoint in the Bundle (Brand Bundle Publisher) | SHALL | met: the primary brand's `endpoint` lists every `[[ferrosmart.brand.endpoint]]` | `brands::the_primary_brand_references_every_endpoint_and_the_affiliate_is_part_of_it` |
| A more detailed brand hierarchy | SHOULD | met: each `[[ferrosmart.brand.affiliate]]` is an Organization `partOf` the primary brand, with its own portals and the endpoints they offer | `brands::the_primary_brand_references_every_endpoint_and_the_affiliate_is_part_of_it` |
| `Bundle.timestamp` advertises the last change to the contents | SHALL | met: the store records the contents' digest and the instant it last moved (`brand_bundle`, 13.9), so a restart with the same contents keeps the instant and every replica serves the same one; a removed resource moves it too; `Bundle.meta.lastUpdated`, which the profile requires, carries it too | `brands::the_last_change_moves_only_for_what_changed`, `brands::the_primary_brand_references_every_endpoint_and_the_affiliate_is_part_of_it` |
| `Bundle.entry.resource.meta.lastUpdated` per resource | SHOULD | met: the store records a digest and an instant per resource beside the contents' (`brand_bundle`, 13.9), so a change of configuration moves only the resources it changed, and each is served with its own instant | `brands::the_last_change_moves_only_for_what_changed`, `brands::each_resource_is_served_with_its_own_last_change` |
| CORS for every GET of the artifacts | SHALL | met: `Access-Control-Allow-Origin: *`, with `ETag` exposed to a browser app | `brands::the_bundle_is_served_as_fhir_json_to_any_origin_with_a_weak_etag` |
| A weak `ETag` on every Brand Bundle response | SHOULD | met: `W/` and half the SHA-256 of the body, on the `200` and the `304`; an `If-None-Match` naming it, weakly compared (RFC 9110 §13.1.2), answers `304` | `brands::the_bundle_is_served_as_fhir_json_to_any_origin_with_a_weak_etag`, `brands::a_request_naming_the_etag_is_answered_not_modified` |
| Every Must-Support element of `UserAccessBrand` and `UserAccessEndpoint` can be managed | SHALL | met: a key per element (name, website, identifier, alias, category, logo and its licence, address, portals with name, description, URL, logo, licence and endpoints, `partOf` through `affiliate`, endpoint address, FHIR versions and contacts); status, connection type and payload type are fixed by the profile or active | `brands::the_bundle_built_from_configuration_holds_to_the_smart_profiles` |
| Customer-supplied Organization identifiers, `system` and `value` | SHALL | met; an identifier given to two brands is refused, since a server's brand identifier must match exactly one | `brands::a_brand_breaking_a_rule_is_refused` |
| Data Absent Reasons only `asked-declined` or `asked-unknown` | MAY, SHALL NOT | met: FerroSMART writes no Data Absent Reason; the website, the one 1..1 element a provider may lack, is required | `brands::a_brand_breaking_a_rule_is_refused` |
| `user_access_brand_bundle` and `user_access_brand_identifier` in the SMART configuration, the identifier with a `value` and a `system`, matching exactly one Organization identifier (SMART on FHIR Server) | SHOULD, SHALL | each FHIR server's: its own document may name `{issuer}/brands` and one of the configured identifiers; FerroSMART's document describes no FHIR endpoint and names neither | none |
| The app sends `If-None-Match`, caches by ETag, and prefers the resources its server's document links (App) | SHOULD, SHALL | the app's | none |

The fullUrl of each entry is `{issuer}/brands/<type>/<id>`, a RESTful URL
the relative references of the Bundle resolve against (FHIR R4,
Bundle, Resolving references in Bundles); FerroSMART serves no resource at it, which the
specification allows of a `fullUrl`. The ids are `brand`, `affiliate-N`
and `endpoint-N` in the order of the configuration: our own design.

**Sections**

| Section | Status |
|---|---|
| §1 Conformance (capabilities, discovery) | this section |
| §2.1 App Launch, §2.2 Scopes and Launch Context | below |
| §2.3 Persisting App State (experimental) | the resource server's; FerroSMART never advertises it (below) |
| §2.4 Task profile for requesting a launch (experimental) | the EHR's; FerroSMART serves the EHR launch API it uses (below) |
| §3 Backend Services | in audit |
| §4.1 Client Authentication: Asymmetric, §4.2 Symmetric | below |
| §5 Token Introspection | in audit |
| §7 Best Practices | in audit |

| §3 Backend Services | below |
| §4.1 Client Authentication: Asymmetric, §4.2 Symmetric | symmetric built; in audit |
| §5 Token Introspection | below |
| §7 Best Practices | below |
| §8 User-access Brands and Endpoints | below |
| §9 Examples | test vectors in `app/ferrosmart/tests/it/ig_examples.rs`: the worked RS384 and ES384 assertions and the app launch and Backend Services ES384 assertions verify against their published keys through the token endpoint (each refused only as expired), the symmetric example's Basic credentials authenticate, and the worked ID Token verifies with the page's key and reads as shown; the sandbox's HS256 codes and tokens and the logins are not replayable, and the file says why (#609) |

**App State** (`smart app-state`, Discovery). An EHR advertises
`smart-app-state` "in the capabilities array of their FHIR server's
`.well-known/smart-configuration`", and the `$smart-app-state-query` and
`$smart-app-state-modify` operations read and write `Basic` resources at
that FHIR server or at an `associated_endpoints` entry it names. FerroSMART
is the authorization server and stores no FHIR resource, so the operations
belong to the resource server, FerroBRIDGE's facade, and FerroSMART's own
document never lists the capability
(`authorize::what_the_document_leaves_out_the_server_refuses`). Its part is
the access token: "Every App State request SHALL include an Authorization
header with an access token issued by the EHR's authorization server"
(`smart app-state`, Access Control), with scopes such as `user/Basic.cuds`
or `patient/Basic.cuds` granted as any other resource scope, by a client's
ceiling and a person's roles.

**Task launch** (`smart task-launch`). A `Task` of the `task-ehr-launch`
or `task-standalone-launch` profile asks staff to launch an app, with its
URL and optional `appContext`, `for` and `encounter`. Creating it, showing
it and acting on it is the EHR's work: FerroEHR's viewer and FerroBRIDGE's
facade. An EHR acting on a `task-ehr-launch` Task registers the launch at
FerroSMART's `POST {issuer}/launch` (13.17) with the Task's patient,
encounter and `appContext` as the launch context, and opens the app with
the `launch` value it gets back; a `task-standalone-launch` Task needs
nothing of FerroSMART beyond the standalone launch.

### 13.24 The OpenID Foundation conformance suite lane

A CI lane (#621, `scripts/oidf/lane.sh`) runs the OpenID Foundation
conformance suite against a FerroSMART built from the commit, in both of
its OpenID Connect roles. The suite is its published image at
`release-v5.3.4`, with its nginx TLS front and MongoDB, each pinned by
digest in `docs/VERSIONS.md`, and its own `scripts/run-test-plan.py`,
vendored under `docs/specs/oidf-conformance-suite/`, runs each plan.
`app/ferrosmart/oidf/expected.tsv` holds every module to its result, and
any difference fails the lane: a module that got worse is a regression,
and one that got better is recorded. No specification governs the lane:
our own design.

| Plan | Role | Variants | Modules |
|---|---|---|---|
| `oidcc-client-test-plan` | relying party, FerroSMART's upstream login with `private_key_jwt`; its client-secret module with `client_secret_basic` | `private_key_jwt`, `code`, static client | 28 |
| `oidcc-client-basic-certification-test-plan` | relying party, FerroSMART's upstream login with `client_secret_basic` | the plan fixes `client_secret_basic` | 14 |
| `oidcc-config-certification-test-plan` | OpenID Provider, FerroSMART's own ID Tokens | discovery | 1 |
| `oidcc-basic-certification-test-plan` | OpenID Provider | discovery, static client; the plan fixes `client_secret_basic` | 35 |

**As the relying party**, FerroSMART's upstream provider is the suite.
`scripts/oidf/rp-client.sh` is the client the runner starts for each
module: it starts FerroSMART against the module's provider, sends an app's
authorization request, follows the browser to the provider and back to
`{issuer}/callback`, and records what FerroSMART made of the provider's
answer: `accepted` (the login reached the consent page), `refused` (the
app got an error, `rfc6749 §4.1.2.1`), `no-start` (FerroSMART refused the
provider's metadata) or `started`. The suite's verdict on a negative
module cannot see the relying party refuse, so the login column carries
the check: the lane knows what each module asks of the login, from the
module's own summary in the suite, and a login the module does not ask
for names its issue. A happy-path module finishes at the suite only after
a UserInfo request (`oidc core §5.3`), which FerroSMART never makes: it
reads the person from the ID Token. The driver therefore stops such a
module once the login is accepted, and the suite records it
`INTERRUPTED`. One configuration, `app/ferrosmart/oidf/ferrosmart-rp.toml`,
names no client authentication, and the driver adds the one the module
fixes (13.22): `client_secret_basic` with the secret
`app/ferrosmart/oidf/rp.json` registers, from a file, for the Basic
relying party plan and the client-secret module, and `private_key_jwt`
for every other module. The suite's runner never runs the two key-rotation
modules (its own `ignored_modules`), and the lane records them as not run.

**As the OpenID Provider**, the suite is the static client `oidf-suite`, a
confidential symmetric client, and Keycloak is FerroSMART's upstream.
FerroSMART has no UserInfo Endpoint, so every module of the Basic plan
stops before its authorization request and the configuration module
warns. The owner decided on 2026-11-19 (#650) that FerroSMART builds none:
`oidc core §15.1` does not list it, `§15.2` requires it only of a Dynamic
OP, and SMART App Launch 2.2.0 makes it a MAY. The modules would stop at
the authorization request even with one, since they send neither the PKCE
challenge nor the `aud` SMART App Launch 2.2.0 requires, so the Basic OP
plan does not apply to a SMART authorization server and its 36 modules
stay held as failures under #650. What `§15.1` requires of every OP is
tested through the endpoints instead (13.25).

What the lane found: the relying party accepted an ID Token without
`iat` (#646) and refused one without `kid` whose key set holds a single
matching key (#648), both fixed and now held as passes. The
client-secret module and the Basic relying party plan failed while
FerroSMART authenticated upstream with `private_key_jwt` alone (#619); a
provider entry may now choose `client_secret_basic` (13.22, #679), and
the lane runs them with a `client_secret_basic` upstream (#706). The FAPI 2.0 plans, the only OpenID Foundation plans that enforce
RFC 10070's audience rule, need PAR and DPoP and are the lane's next
target.

### 13.25 What every OpenID Provider implements

OpenID Connect Core 1.0 §15.1 lists what every OpenID Provider implements,
and FerroSMART is one toward its apps. Each requirement holds beside SMART
App Launch 2.2.0's own rules: an authorization request without the S256
PKCE challenge or the `aud` is refused before any of these is read
(13.6). FerroSMART keeps no session of its own: every authorization
request logs the person in at the upstream provider, so the parameters
that ask about the login go there (`app/ferrosmart/src/authorize/oidc.rs`).
The tests are in `app/ferrosmart/tests/it/authorize/core_op.rs`.

| Requirement | What FerroSMART does | Citation | Test |
|---|---|---|---|
| Signing ID Tokens with RS256 | every ID Token is signed RS256 with the current key of `[ferrosmart.keys]`, and the discovery document names `RS256` | `oidc core §15.1`, `§2`; `discovery §3` | `the_id_token_is_rs256_and_carries_the_upstream_login_s_auth_time`, `the_document_names_rs256_the_display_values_and_the_page_languages` |
| `prompt`, with `none` and `login` | `none` answers `login_required` to the app with no page and no login, as FerroSMART holds no session in which the person is already authenticated; `none` beside another value is `invalid_request`; `login` and `select_account` go to the upstream login; `consent` shows the consent page where a remembered consent or the registration would answer (13.6 item 6); another value is taken and ignored, which no specification governs: our own design | `oidc core §15.1`, `§3.1.2.1`, `§3.1.2.6` | `prompt_none_answers_login_required_without_a_page`, `prompt_login_and_select_account_reach_the_upstream_login`, `prompt_consent_shows_the_page_an_approval_would_skip` |
| `display` | `page`, `popup`, `touch` and `wap` are taken, and the same page answers at any size; `display_values_supported` names the four | `oidc core §15.1`, `§3.1.2.1`; `discovery §3` | `display_locales_and_acr_values_are_taken`, `the_document_names_rs256_the_display_values_and_the_page_languages` |
| `ui_locales` and `claims_locales` | `ui_locales` goes to the upstream login, and the pages take its first language the catalog holds before the browser's `Accept-Language`; `ui_locales_supported` names the catalog's languages. `claims_locales` is taken; no claim FerroSMART returns depends on a language, so the document names no `claims_locales_supported` | `oidc core §15.1`, `§3.1.2.1`, `§5.2`; `discovery §3` | `display_locales_and_acr_values_are_taken` |
| `auth_time` | every ID Token carries `auth_time`, the upstream ID Token's own, or the time the upstream login returned when it names none; a refresh keeps it | `oidc core §15.1`, `§2` | `the_id_token_is_rs256_and_carries_the_upstream_login_s_auth_time` |
| `max_age` | goes to the upstream login; an upstream `auth_time` older than `max_age`, or none, begins the upstream login again with `prompt=login`, once, and a login still older answers `login_required`; `max_age=0` is `prompt=login`; a value that is no number of seconds is `invalid_request` | `oidc core §15.1`, `§3.1.2.1`, `§3.1.2.6` | `an_upstream_login_older_than_max_age_is_begun_again_with_prompt_login` |
| `acr_values` | an eIDAS URI it names is the level the login must reach, a miss answered `unmet_authentication_requirements`; the provider is asked for its values at that level; any other value is taken and ignored; the ID Token and the access token carry `acr`, and the documents name `acr_values_supported` (13.28) | `oidc core §15.1`, `§3.1.2.1`; `rfc9470 §5`, `§7` | `acr_values_naming_an_eidas_level_holds_the_login_to_it`, `display_locales_and_acr_values_are_taken` |

### 13.26 Upstream providers: SAML 2.0

A person can log in at an upstream identity provider that speaks SAML 2.0
rather than OpenID Connect: FerroSMART is then a service provider of the
OASIS SAML 2.0 Web Browser SSO profile (`saml-profiles-2.0-os §4.1`, as
the Errata 05 composite amends it), with the standard bindings and nothing
national (owner decision 2026-11-19 on FerroHEALTH/FerroSMART#687 and
#688). A country or a deployment configures its provider with the standard
settings; which attribute or name identifier becomes the person's
identifier is deployment configuration (#674). The protocol machinery is
`app/ferrosmart/src/saml/`; it holds no configuration and does no I/O. The
protocol-neutral provider entry of #678 drives it (#688), from
`app/ferrosmart/src/upstream/saml.rs` (the tables, the metadata read and
read again, the artifact resolution) and `app/ferrosmart/src/authorize/saml.rs`
(the routes). Citation keys: `saml-core`,
`saml-bindings`, `saml-profiles` and `saml-metadata` are the 2005 OASIS
Standard documents and `errata E26` an entry of SAML V2.0 Errata 05, all
under `docs/specs/oasis-saml/`; `xmldsig-core1`, `xmlenc-core1` and
`Exc-C14N` are the W3C Recommendations under `docs/specs/w3c-xmlsec/`.

**The configuration.** FerroSMART is one service provider for every
SAML provider: `[ferrosmart.saml]` names its entity ID (by default its
metadata URL, `{issuer}/saml/metadata`), the key that signs every request,
the keys an identity provider encrypts for, and under `tls` the client
identity artifact resolution presents. One entity for every partner is our
own design: the metadata and the assertion consumer service then have one
address each. Each SAML entry's `[ferrosmart.upstream.saml]`
names the identity provider's entity ID, its metadata by `https` URL or
file with the certificates that must sign it, the two bindings, `ForceAuthn`,
the name identifier format, and `authn_contexts`, the classes at or above
the provider's minimum assurance in its own vocabulary. A minimum is a
generic setting: SAML defines no order of classes, so the deployment lists
the classes it accepts. The `claims` table maps attribute `Name`s to the
claims the steps after the login read (`name`, `preferred_username`,
`email`, the claims of `fhir_user_claim` and `role_claims`, and any claim a
`fhirUser` lookup names), and `subject_attribute` names the attribute of
the person's identifier, the `NameID` when empty. The configuration is
refused at load when an entry has no `[ferrosmart.saml]`, no metadata or
two, a claim name the table does not map, a non-`https` metadata URL, or the
artifact binding without a TLS client identity. At start the metadata is
read and must name a single sign-on service for the request binding; it is
read again every `metadata_refresh`, and a failed read keeps the last good
copy until its `validUntil`.

**The login.** The request's `RelayState` is 256 random bits, which find
the pending authorization; its `ID` is stored with it, so the response
must answer it. The browser is bound to the request by a cookie of its own
on the assertion consumer service's path, `SameSite=None`, since the
identity provider's post is cross-site and a `Lax` cookie is not sent with
it; the assertion consumer service refuses a response from another browser
as the OpenID Connect callback does (`rfc9700 §4.7`). `prompt=login` and a
login older than `max_age` ask the provider again with `ForceAuthn`. The
identifier is the subject attribute's one value or the `NameID`; a
transient `NameID` (`saml-core §8.3.8`) with no subject attribute is
refused, since no grant or consent could find the person again. A response
posted to a provider asked for an artifact, or the reverse, is refused.
Each outcome is a DICOM `110122` Login record (13.2), a refusal naming its
check, and a provider status other than success sends the app
`access_denied`, any other failure `server_error`.

**What FerroSMART does.**

- **The request.** An `AuthnRequest` (`saml-core §3.4.1`) with
  `AssertionConsumerServiceURL` and `ProtocolBinding` (HTTP-POST or
  HTTP-Artifact), `ForceAuthn` when the provider sets it, a `NameIDPolicy`
  when the provider names a format, and the provider's minimum assurance
  as `RequestedAuthnContext Comparison="exact"` listing the accepted
  `AuthnContextClassRef` values (`saml-core §3.3.2.2.1`). It is always
  signed: the query string of the HTTP-Redirect binding
  (`saml-bindings §3.4.4.1`) or an enveloped signature for HTTP-POST
  (`§3.5.4`). `RelayState` is at most 80 bytes (`§3.4.3`).
- **The response.** Delivered by HTTP-POST (`saml-bindings §3.5`) or by
  an artifact (`§3.6`), whose `ArtifactResolve` FerroSMART signs and sends
  over the SOAP binding (`§3.2`) with its TLS client certificate, the
  mutual authentication `saml-profiles §4.1.4.4` requires. HTTP-Redirect
  never carries a response (`saml-profiles §4.1.2`).
- **The checks**, each its own `Refusal`: `Version` 2.0;
  `InResponseTo` naming the request, so an unsolicited response is refused
  (`§4.1.5`); `Destination` where the response arrived, required on a
  signed posted response (`saml-bindings §3.5.5.2`); the `Issuer` the
  provider's entity ID in the entity format; status success; one bearer
  `SubjectConfirmationData` with the assertion consumer service as
  `Recipient`, the request as `InResponseTo`, no `NotBefore` and a
  `NotOnOrAfter` not passed (`saml-profiles §4.1.4.2`, `§4.1.4.3`,
  errata E26); `NotBefore` and `NotOnOrAfter` of the conditions; an
  `AudienceRestriction` naming FerroSMART, and every one present naming it
  (`saml-core §2.5.1.4`, errata E46); `OneTimeUse` and `ProxyRestriction`
  understood, any other condition refused (`§2.5.1.1`); an instant ahead
  of now refused; the `AuthnContextClassRef` one of the accepted values;
  the clock skew configurable (errata E92 suggests 3 to 5 minutes).
- **Replay.** The assertion `ID` is admitted once, remembered until the
  bearer confirmation's `NotOnOrAfter` (`saml-profiles §4.1.4.5`); the
  artifact itself is single use at the provider (`saml-bindings
  §3.6.5.2`), and the request it answers is consumed with the pending
  authorization.

**The rules beyond the profile**, our own design, each held by a test:

- Exactly one assertion, plain or encrypted, and no `saml:Advice`: there
  is one assertion to read and no nested one to confuse it with.
- The assertion is covered by a verified signature whatever the binding:
  its own, the `Response`'s, or the `ArtifactResponse`'s that carried it.
  `saml-profiles §4.1.4.5` (as errata E26 words it) requires this for
  HTTP-POST; FerroSMART holds HTTP-Artifact to it too, so the transport
  is never the only protection.
- Exactly one `AuthnStatement`, with an `AuthnContextClassRef`.
- An attribute value is text, or one `saml:NameID`; anything else is
  refused.

**Signature wrapping.** The signature check is handed the element the
caller then reads, never an ID to look up. The `ds:Signature` must be a
child of that element in its schema place, its one `ds:Reference` must
name that element's `ID` (`saml-core §5.4.2`), the digest is taken over
that element as parsed, and every value is read from it by child path. A
document in which any attribute named `ID`, `Id` or `id` carries a value
twice is refused before any check, and so is a `ds:Signature` anywhere but
as the child of the `ArtifactResponse`, the `Response` or the assertion,
each of which is verified when it carries one. The corpus under
`app/ferrosmart/tests/it/saml/attacks.rs` holds the eight XSW shapes of
Somorovsky et al. (USENIX Security 2012), a signature by a key the
metadata does not publish, a reference to another ID, a second signature,
a `ds:Object` (`saml-core §5.4` as errata E91 extends it), an unsigned
assertion added to or swapped into a signed response, and a comment
splitting the `NameID`: a value is read only from an element holding text
alone, since the canonical form without comments drops a comment that a
reader would split the text at.

**Algorithms** (`xmldsig-core1 §6.1`, `xmlenc-core1 §5.1`; our own
choice within them):

| Role | Accepted | Refused |
|---|---|---|
| Canonicalization | Exclusive XML Canonicalization 1.0 without comments, with an `InclusiveNamespaces PrefixList` | inclusive C14N, `#WithComments` |
| Transforms | the enveloped signature transform, then exclusive canonicalization | any other list |
| Digest | SHA-256, SHA-384, SHA-512 | SHA-1, SHA-224 |
| Signature | RSASSA-PKCS1-v1_5 with SHA-256, -384 or -512 on RSA keys of 2048 bits or more; ECDSA with SHA-256 on P-256, SHA-384 on P-384, SHA-512 on P-521 | SHA-1 (`xmldsig-core1` discourages it; it is broken), DSA, every HMAC (a MAC keyed by a public key is an algorithm confusion) |
| Key transport | RSA-OAEP, `rsa-oaep-mgf1p` or `xmlenc11#rsa-oaep`, digest and MGF1 both SHA-1, -256, -384 or -512, with an `OAEPparams` label | RSA-v1.5 (Bleichenbacher), key agreement, key wrap, mixed digest and MGF1 |
| Data | AES-128, -192 and -256 in GCM; in CBC only when a verified signature covers the encrypted element (`saml-core §6.2` as errata E93 replaces it), checked before anything is decrypted | Triple DES, CBC without a covering signature |

SHA-1 is refused although `xmldsig-core1 §6.1` lists RSA with SHA-1 as
recommended for verification: an identity provider that still signs with
it is refused until it moves to SHA-256. The keys are the provider's
metadata's `use="signing"` (or unmarked) `KeyDescriptor`s; `ds:KeyInfo`
in a message is never read. A certificate in metadata is a key carrier:
its dates and issuer are not checked, since the metadata is the trust. A
decryption failure is one refusal whatever step failed, so it tells an
attacker nothing.

**Metadata.** The provider's `md:EntityDescriptor` is read, alone or
inside `md:EntitiesDescriptor` aggregates (`saml-metadata §2.3`): its
`IDPSSODescriptor` supporting SAML 2.0, its signing keys, its
`SingleSignOnService` and `ArtifactResolutionService` endpoints (each an
`https` URL), `WantAuthnRequestsSigned`, and the earliest `validUntil`,
past which the metadata is refused (`§2.2.1`, `§4.3`). With the
deployment's metadata signing certificates configured, the descriptor or
an aggregate above it carries a signature they verify (`§3`), checked as
every SAML signature is. FerroSMART publishes its own
`md:EntityDescriptor` with an `SPSSODescriptor`
(`AuthnRequestsSigned="true"`, `WantAssertionsSigned="true"`), its signing
certificate, one encryption certificate per decryption key with the
algorithms it accepts, the requested name identifier formats, and the
assertion consumer service under HTTP-POST (index 0, the default) and
HTTP-Artifact (index 1).

**Not built.** Single Logout (`saml-profiles §4.4`) is its own profile,
which the Web Browser SSO profile does not require; FerroSMART's grants of
a SAML login end with their own lifetimes. IdP-initiated (unsolicited)
login is refused, since FerroSMART logs a person in only for a pending
authorization. No national profile, default or example is shipped.

**The library choice.** The XML parser is `roxmltree` 0.21, pure Rust
and read-only, already in the workspace for the eHDSI assertion check: it
refuses a document type declaration by default, so neither an external
entity nor entity expansion can be expressed, and it keeps every node's
source range, which the canonical form needs to keep the signer's
prefixes. The exclusive canonicalization is `ferrohealth_smart::xml`, the
eHDSI check's implementation (3.18) moved into its own module behind the
`xml` feature so both checks share one copy, with its linear pre-scan of
depth and namespace declarations, its line-end translation and its tests
against `xmllint --exc-c14n`; FerroSMART reads SAML messages under caps of
256 KiB, 16 384 nodes, depth 32 and 256 namespace declarations. The
cryptography is `aws-lc-rs`, the provider `jsonwebtoken` and `rustls`
already link: RSA and ECDSA verification and signing, RSA-OAEP
decryption, AES-GCM and AES-CBC. `x509-parser` reads the certificates,
and `flate2` (pure Rust behind `rust_backend`) writes the raw DEFLATE of
the HTTP-Redirect binding. The alternatives were weighed: `samael`, the
one SAML crate for Rust, verifies signatures only through `xmlsec` and
`libxml2` over C bindings, resolves references by ID inside libxmlsec,
which is the wrapping surface this design closes by construction, and
would add two C libraries to the static distroless image; the `xmlsec`
crate is the same C library alone. No pure-Rust XML Signature or XML
Encryption crate exists at a maturity worth trusting over a check shaped
for SAML's one signature form, so the check is our own, over primitives
that are each established, and the case
`app/ferrosmart/tests/it/saml/interop.rs` holds it against a response
canonicalized by libxml2 and signed by OpenSSL.

### 13.27 The admin API and `client apply`

A client lives only in the store every replica reads. RFC 6749 §2 leaves
the means of registration to the server, and SMART App Launch 2.2.0
(Register App with EHR) asks only what a registration holds, so the admin
API and `ferrosmart client apply` are our own design. Both take one client
document, check it by one validator and write it with one store path, each
change audited.

- **The guard.** Every admin route sits behind the `ferrohealth-smart`
  layer with `Requirement::Scope("system/admin")`, and the layer writes its
  audit line for each request. The bearer token is an access token
  FerroSMART issued for its own issuer (`resource` the issuer, as for
  introspection, 13.6 item 8), to a Backend Services client whose ceiling
  lists `system/admin`; no role grants a `system/` scope, so no person
  holds it. The verifier confirms each token against the store on every
  request: its `access_token` row active, its `aud` the issuer, its client
  registered and enabled. Nothing is cached between requests, so a revoked
  token or a disabled admin client is refused on the next request at every
  replica.
- **Registration (`rfc7591`, `rfc7592`).** `POST {issuer}/register` is
  the registration endpoint SMART App Launch 2.2.0 recommends (Register App
  with EHR), named `registration_endpoint` in the RFC 8414 metadata and the
  OpenID Provider configuration. An administrator's FerroSMART access token
  holding `system/admin` is the initial access token (`rfc7591 §3`), which
  sets every member, `client_id` included. Without one, the endpoint
  answers only when `[ferrosmart.registration] open` is set: the server
  issues the `client_id`, the client is `registered_by` `self`, its `scope`
  is held to `[ferrosmart.registration] scope` (all of it when it asks
  none; patient-facing, since no `user/` or `system/` scope is taken there),
  its `resources` are every configured resource server (our own design),
  and `resources`, `launch_uri`, `upstreams` or `first_party` refuse it with
  `invalid_client_metadata`. The answer is `201` with the metadata, the
  issued secret once, and for an app that registered itself its
  `registration_access_token`, kept as its SHA-256, with its
  `registration_client_uri` and `client_id_issued_at` (`rfc7591 §3.2.1`).
  A member the endpoint does not read is ignored (`rfc7591 §2`); an omitted
  `token_endpoint_auth_method` is `client_secret_basic` and omitted
  `grant_types` are `authorization_code`. `GET`, `PUT` and `DELETE
  {issuer}/register/{client_id}` take the client's registration access token
  or an administrator's token (`rfc7592 §2`): a `PUT` names the client and,
  when it carries `client_secret`, the secret the client holds; an app that
  registered itself keeps its ceiling; `DELETE` revokes everything the
  client held and deletes it (`204`). An unknown client or a token that does
  not hold is `401 invalid_token` (`rfc7592 §2.1`).
- **The admin routes.** `GET /admin/clients` lists every client, disabled
  ones included; `POST .../disable` and `POST .../enable` disable and
  enable one, which RFC 7592 has no operation for.
- **The document.** One document, RFC 7591 §2 client metadata
  (`client_name`, `token_endpoint_auth_method`, `scope`, `grant_types`,
  `jwks_uri` or `jwks`, `redirect_uris`, `default_acr_values` of OpenID
  Connect Dynamic Client Registration 1.0 §2, and the URLs of the app),
  with FerroSMART's own `resources`, `launch_uri`, `upstreams` and
  `first_party` (13.6 item 6). FerroSMART issues a `client_secret_basic` or
  `client_secret_post` client its secret, answers it once with
  `client_secret_expires_at` 0 and keeps its Argon2id hash (`rfc7591
  §3.2.1`); no document or answer carries the hash, an update keeps the
  stored secret, and `ferrosmart client secret` issues a new one. A client
  authenticates only by its registered method.
- **`ferrosmart client apply <file>...`.** Each file is one client
  document, read strictly, with an unknown member refused, applied as an
  administrator's `PUT` replaces a client, or as its registration when no
  client has its `client_id`, with the same checks and records,
  naming `ferrosmart client apply` from the host as the requester. It
  migrates the store first and runs only when the operator runs it, so it
  creates the first administrator client, and a deployment that keeps its
  clients as files applies them the same way.
- **Typed refusals.** A rule broken answers `400` with the RFC 7591
  §3.2.2 code (`invalid_redirect_uri`, `invalid_client_metadata`); a body
  is read only as `application/json` of at most 64 KiB into the closed
  document object (`415`, `413`, `400` for no JSON, `422` for an array, a
  wrong type or an unknown member, each `invalid_request`), and a
  `client_id` other than the path's is `400 invalid_request`; an unknown client `404 not_found`; a
  repeated id `409 client_exists`; a launch URL another client registers
  `409 launch_uri_taken`; a change to the state the client is in already
  `409 unchanged`. A refusal of the guard is `401 invalid_token` or `403
  insufficient_scope` (RFC 6750 §3.1) with its challenge.
- **The record.** Every change commits in one transaction with its
  `AuditEvent` (`client-created`, `client-updated`, `client-disabled`,
  `client-enabled`), naming the admin client, or `ferrosmart client
  apply`, as the requester and the client changed, never a key or a hash.
- **Revocation at once.** A change that clears `first_party` revokes, in
  its own transaction, every grant issued with no page on the mark with
  its refresh and access tokens, and drops its unredeemed codes; the
  record names the mark cleared and the grants revoked. Disabling a client
  revokes every grant and access token it holds with their refresh tokens,
  drops its codes, launches, pending requests and remembered consents, and
  every lookup of a client reads `disabled_at IS NULL`, so its next
  request at any replica is refused. Introspection answers each revoked
  token inactive at once; a resource server that checks the JWT alone
  honours the revocation when the token expires, at most
  `access_token_lifetime` later (3.2).
- **The key ring.** `GET /admin/keys` lists the public JWK of each key the
  replica publishes with its state: `active`, `next` or `retiring` (13.11).
  The private keys stay in the files of `[ferrosmart.keys]`; the API never
  carries private material.

### 13.28 The level of assurance of a login

EHDS Article 16(1) lets a natural person identify with any electronic
identification means recognised under the eIDAS Regulation, and
Implementing Regulation (EU) 2026/2099 holds a natural person (Article
4(2)) and a health professional (Article 6(3)) to the assurance level
substantial at least (`docs/specs/eu-law/`). The three levels, low,
substantial and high, are those of Regulation (EU) No 910/2014 Article
8(2), specified in the Annex of Implementing Regulation (EU) 2015/1502. A
resource server reads the level from the token (3.12), so FerroSMART
carries it from the upstream login into every token (owner decision on
FerroHEALTH/FerroEHR#6419, #784).

- **The levels of a provider.** Each `[[ferrosmart.upstream]]` entry maps
  its own values to levels in `[ferrosmart.upstream.assurance] levels`: an
  OpenID Connect provider's `acr` (`oidc core §2`), a SAML provider's
  `AuthnContextClassRef` (`saml-core §2.7.2.2`). A value the map does not
  name carries no level. Which value stands for which level is the
  deployment's, since only it knows how its provider proofs and
  authenticates a person: no specification governs the map, our own design.
- **The minimum.** `[ferrosmart] assurance_minimum` is the deployment's
  floor, `substantial` by default after 2026/2099, `high` for a deployment
  that asks it, `none` for one outside the eIDAS area. A provider's
  `minimum` raises it. A provider whose
  map reaches neither the floor nor its own minimum is refused at load.
- **The request.** An app's `acr_values` naming an eIDAS URI asks for the
  lowest level it names, since any listed value answers it (`oidc core
  §3.1.2.1`); a request without `acr_values` asks for the client's
  `default_acr_values` (OpenID Connect Dynamic Client Registration 1.0
  §2). The upstream OpenID Connect
  request carries as `acr_values` the provider's values at or above the
  higher of that level and the provider's minimum, lowest first. A SAML
  request keeps its configured `authn_contexts` (13.26).
- **The check.** After the login, its level is held to the provider's
  minimum (with the floor) and to the request's level. A login below the
  provider's minimum, or naming no mapped value, sends the app
  `access_denied` (`rfc6749 §4.1.2.1`); one below the request's level
  `unmet_authentication_requirements` (`rfc9470 §5`). Each refusal is a
  failed DICOM `110122` Login record naming its check, and the management
  page shows its own refusal page.
- **The tokens.** The level travels with the pending request, the code and
  the grant. The ID Token and the access token carry `acr` as the level's
  eIDAS URI, `http://eidas.europa.eu/LoA/low`, `/substantial` or `/high`,
  and `auth_time` (`rfc9068 §2.2.1`, `oidc core §2`); a refresh repeats
  both (`rfc9470 §6.1`), and introspection answers them (`§6.2`). No
  specification FerroSMART vendors fixes the `acr` value of an eIDAS
  level; the URIs are those the eIDAS nodes exchange, our own choice.
- **The documents.** The authorization server metadata and the OpenID
  Provider configuration name `acr_values_supported`, the URIs of the
  levels the providers map, lowest first (`rfc9470 §7`, `discovery §3`).

The tests are `app/ferrosmart/tests/it/authorize/assurance.rs` and the SAML
case `a_class_is_held_to_its_eidas_level_and_the_client_s_minimum`.

### 13.29 The token exchange of a patient's own token

A product that serves a person at a FHIR base, such as FerroBRIDGE's
patient summary, reads the person's own EHR at the openEHR base paired
with it. With its own credential the CDR would see a system caller, so it
could not apply the person's own-access rules (EHDS Article 3) or name the
person in its access record. FerroSMART therefore grants RFC 8693 token
exchange for this one case (owner decision on FerroHEALTH/FerroEHR#6419,
#785); no other subject is exchanged. Where the specification leaves the
choice to the server, the rules below are our own design.

- **The client.** A confidential client whose `grant_types` lists
  `urn:ietf:params:oauth:grant-type:token-exchange` (`rfc8693 §2.1`), authenticated as at every grant; a public client is
  refused the grant at load and at the endpoint (`unauthorized_client`).
  Its `resources` lists the FHIR base it serves and the paired openEHR
  base, so the exchange admits only the product of that FHIR base.
- **The request.** `subject_token` with `subject_token_type`
  `urn:ietf:params:oauth:token-type:access_token`; no `actor_token`, since
  the product acts for the person and an actor would make the exchange a
  delegation (`rfc8693 §1.1`); a `requested_token_type`, when named, of an
  access token; `resource` or `audience`, when named, the paired openEHR
  base, any other `invalid_target`; `scope` within `patient/composition-*.r`
  and `patient/aql-*.s` (reading the person's compositions and running a
  query on their EHR, `master08 §Resource Scopes`) and the client's
  ceiling, `invalid_scope` beyond it, and those of the two the client's
  ceiling admits when named none. SMART on openEHR has no scope for a
  demographic read, so the exchange issues none.
- **The subject token.** An access token FerroSMART issued, its signature
  verified with its own keys, its record active (unexpired, neither it nor
  its grant revoked), under a grant that is the person's own access
  (3.13): `fhirUser` naming `Patient/<x>` at the token's FHIR base,
  `patient` naming `<x>`, `patient/` scopes alone with a read among them.
  Any other subject, a professional's or a machine's among them, is
  `invalid_request` (`rfc8693 §2.2.2`). Every request, refused or answered,
  is the token endpoint's `IHE.IUA.71` record (13.2).
- **The patient's EHR.** The openEHR base is the one whose `fhir_base`
  pairs it with the subject token's audience (13.6 item 4). The patient is
  read at the FHIR base and their EHR looked up by the identifier
  `subject_system` names, each as the person with a token for that lookup
  alone and its access record, as the paired picker does; a patient with
  no EHR there is `invalid_target`.
- **The issued token.** An RFC 9068 access token with the subject token's
  `sub`, `aud` the openEHR base, `client_id` the exchanging client and no
  `act`, `fhirUser` as the absolute URL of the patient at the FHIR base,
  `patient` and `ehrId`, the subject's `acr` and `auth_time` (13.28) and
  its roles, the scope granted, and a lifetime of at most five minutes,
  never past the subject token's `exp`. It is recorded under the subject
  token's grant, so revoking the grant revokes it. The response names
  `issued_token_type` as an access token (`rfc8693 §2.2.1`), and an audit
  line names the client and both tokens' `jti`, never a value.
- **What a product reads.** Under the `ferrosmart` preset the issued
  token reads as
  `CallerKind::Patient` and `is_the_person` (3.13, 3.14).

The tests are `app/ferrosmart/tests/it/authorize/token_exchange.rs`.

### 13.30 Pushed authorization requests

FerroSMART accepts pushed authorization requests (RFC 9126), which FAPI
2.0 Security Profile §5.3.2.2 requires of an authorization server.
`POST {issuer}/par` authenticates the client as the token endpoint does
(`rfc9126 §2.1`; a client assertion's `aud` may also be the PAR endpoint's
URL, §2), refuses a `request_uri` parameter, and checks the request as the
authorization endpoint would: the client's grant, its registered redirect
URI, `response_type`, `state`, the S256 challenge, the `aud` and the
client's reach (13.6 item 13), `scope` and the OpenID Connect parameters.
A refusal is the token endpoint's error body (`rfc9126 §2.3`). An accepted
request is kept without its client authentication under the SHA-256 of a
`request_uri` of the form `urn:ietf:params:oauth:request_uri:<random>`,
bound to the client, and answered `201` with `expires_in` of 60 seconds,
never cached (`rfc9126 §2.2`).

At the authorization endpoint a `request_uri` with its `client_id` stands
for the request: it is taken in one statement, so it is used once and
never by another client, and a taken, lapsed, unknown or another client's
`request_uri` is the page that says the request lapsed (`rfc9126 §4`). The
pushed request is then checked again in full. `[ferrosmart]
require_pushed_authorization_requests = true` refuses every request that
names no `request_uri`, and a client's own
`require_pushed_authorization_requests` (`rfc9126 §6`) refuses its own, as
`invalid_request` (`rfc9126 §4`). The RFC 8414 metadata and the OpenID
Connect discovery document name `pushed_authorization_request_endpoint` and
`require_pushed_authorization_requests` once people log in (`rfc9126 §5`).
The lifetime is our own design within §2.2's range.

### 13.31 Sender-constrained tokens

FerroSMART binds a token to its sender when the token request proves a key
or presents a certificate, as FAPI 2.0 Security Profile §5.3.2.1 requires
of an authorization server. A `DPoP` header at `POST {issuer}/token` is
checked as RFC 9449 §4.3 says, against `POST` and the token endpoint's URL
and with no `ath`, since the request presents no access token (`rfc9449
§5`); its `jti` is recorded once in `seen_jti` under its own issuer column,
so every replica refuses a replay (`rfc9449 §11.1`). A proof that does not
hold is `invalid_dpop_proof`. The token then carries `cnf.jkt`, the RFC
7638 thumbprint of the proof's key (`rfc9449 §6.1`), and the response's
`token_type` is `DPoP` (`rfc9449 §5`). A public client's refresh token is
bound to that key in its grant, and a refresh without a proof of it is
`invalid_grant`, checked before the token is used up; a confidential
client's refresh token is bound to its authentication instead (`rfc9449
§5`). A client registered with `dpop_bound_access_tokens` that sends no
proof is `invalid_request` (`rfc9449 §5.2`).

Under `[server.tls]` with a `client_auth` the listener reads the client's
certificate. A client registered with
`tls_client_certificate_bound_access_tokens` gets a token whose `cnf`
carries `x5t#S256`, the SHA-256 of the leaf certificate's DER encoding
(`rfc8705 §3.1`); its request over a connection that presented none is
`invalid_request`, which RFC 8705 §3.4 leaves to the server. Introspection
answers the token's `cnf` (`rfc9449 §6.2`, `rfc8705 §3.2`). The metadata
names `dpop_signing_alg_values_supported`, the proof algorithms the check
admits (`rfc9449 §5.1`), and `tls_client_certificate_bound_access_tokens`,
`true` when the listener asks for a certificate (`rfc8705 §3.3`).

### 13.32 Upstream providers: the EUDI Wallet

A person can log in by presenting their person identification data (PID)
from a European Digital Identity Wallet. A relying party in the health
sector that requires strong user authentication accepts the wallet at the
person's request (Regulation (EU) 2024/1183, new Art 5f(2)), and FerroSMART
is where a care provider puts that acceptance. The wallet is an
`[[ferrosmart.upstream]]` entry with an `[ferrosmart.upstream.openid4vp]`
table, beside OpenID Connect and SAML 2.0 (13.26). The protocol machinery
is `app/ferrosmart/src/wallet/`, which holds no configuration and does no
I/O; `app/ferrosmart/src/upstream/wallet.rs` reads the files and fetches
what a presentation points at, and `app/ferrosmart/src/authorize/wallet.rs`
holds the routes. Citation keys: `openid4vp` is OpenID for Verifiable
Presentations 1.0 (Final), `haip` the OpenID4VC High Assurance
Interoperability Profile 1.0 (Final), `sd-jwt-vc` draft-ietf-oauth-sd-jwt-vc-13,
`tsl` draft-ietf-oauth-status-list-20 (the revision Implementing Regulation
(EU) 2026/1731 names; `haip` pins -14, which agrees on every rule read
here), all under `docs/specs/openid4vc/`; `rfc9901` is SD-JWT; `etsi 472-2`
is ETSI TS 119 472-2 V1.2.1, recorded by sha256 under
`docs/specs/etsi-eudi/`; the EU acts are under `docs/specs/eu-law/`.

**The protocol.** Implementing Regulation (EU) 2024/2979 Annex II, as
amended by 2026/1731 (Annex XII), applies `etsi 472-2` clauses 4.1, 4.2, 5
and 6: an ISO/IEC mdoc profile and the OpenID4VP profile under `haip`. A
relying party "shall" meet clause 6.5, the Digital Credentials API
(OIDFVP-HAIP-SUPPORT-05), which FerroHEALTH/FerroSMART#840 builds. The
redirect mechanism of clause 6.4 is built here and is what the OpenID
Foundation's verifier plan tests. The ISO/IEC 18013-7 Annex C mdoc API is
an RP "should" (ISO/IEC 18013-SUPPORT-04) and is not built. The PID is
accepted as an SD-JWT VC (`dc+sd-jwt`, `haip §5.3.2`) of type
`urn:eudi:pid:1` (Implementing Regulation (EU) 2024/2977 Annex as amended,
§4.2); the mdoc PID is FerroHEALTH/FerroSMART#793.

**The request.** The browser is sent to the wallet endpoint, `eu-eaap://`
by default (`etsi 472-2` OIDFVP-HAIP-REDIRECTS-03), with the `client_id`,
the `request_uri` and `request_uri_method=post`. The `client_id` is
`x509_hash:` and the base64url SHA-256 of the wallet-relying party access
certificate (`openid4vp §5.9.3`; `haip §5`; OIDFVP-HAIP-COMMON-REQ-RO-23).
`GET` or `POST {issuer}/wallet/request/{state}` answers the request object
as often as a wallet asks, since only the nonce is single-use
(`openid4vp §5.10`), and a posted `wallet_nonce` is echoed in it. The object
is a JWS of type `oauth-authz-req+jwt` (`openid4vp §5`), signed ES256 with
the access key, whose protected header carries `x5c` (the access
certificate and its path, the anchor left out) and `iat`
(OIDFVP-HAIP-REDIRECTS_RO-01 to -03). Its claims are `aud`
`https://self-issued.me/v2` (`openid4vp §5.8`), `response_type`
`vp_token`, `response_mode` `direct_post.jwt` with the `response_uri`
(`haip §5.1`), a fresh `nonce` and `state` (`openid4vp §5.2`), `iat` and
`exp`, `client_metadata` with the request's own ECDH-ES P-256 key named by
the `state`, `A128GCM` and `A256GCM`, and ES256 for the SD-JWT and the Key
Binding JWT (`haip §5`, `§7`; `openid4vp §8.3`, Appendix B.3.4),
`verifier_info` with the registration certificate as `registration_cert`
(OIDFVP-HAIP-COMMON-REQ-RO-13 to -16), and one DCQL credential query `pid`
naming the accepted types, the claims asked for and an `aki` trusted
authorities query over the configured anchors (`openid4vp §6`, `§6.1.1.1`;
`haip §5`). The `etsi_tl` query of RO-17 waits on the trusted lists of
FerroHEALTH/FerroSMART#794.

**The answer.** The wallet posts `response`, a JWE under ECDH-ES to the
request's key (`openid4vp §8.3.1`), to `POST {issuer}/wallet/response`.
FerroSMART finds the request by the JWE's `kid`, opens it, checks its
`state`, and reads one presentation for `pid`. A wallet's error, sealed or
in the clear, sends the browser back with `error` and the request's
`state`, which must name the cookie's request, and the app gets
`access_denied` (`openid4vp §8.5`; `rfc6749 §4.1.2.1`). An error takes no
nonce, so one posted against the public `state` blocks no presentation. A
VP Token posted in the clear is refused (`haip §5.1`). The presentation is
then checked in this order, and the first check that fails is the
refusal:

| Reason | The check |
|---|---|
| `malformed_response` | the JWE opens under the request's key, names its `state`, and carries one presentation for `pid` (`openid4vp §8.1`, `§8.6`) |
| `unencrypted_response` | the VP Token comes inside an encrypted `response` (`haip §5.1`) |
| `invalid_credential` | the SD-JWT reads, its `typ` is `dc+sd-jwt` (or `vc+sd-jwt`, `sd-jwt-vc §3.2.1`), its ES256 signature verifies, and its Disclosures apply (`rfc9901 §7.1`) |
| `untrusted_issuer` | the issuer's chain, from `x5c` (`haip §6.1.1`) or from `x5u` over https matching `x5t#S256` (2977 Annex §4.2 as amended; `rfc7515 §4.1.5`), ends at a configured anchor, every certificate valid, every signer a certificate authority, the leaf not self-signed |
| `unrequested_credential` | the `vct` is one the request asked for (`openid4vp §8.6`, Appendix B.3.5) |
| `expired` | now is before `exp` and at or after `nbf` less 60 seconds |
| `bad_holder_binding` | a Key Binding JWT of type `kb+jwt`, ES256 under `cnf.jwk`, with the request's `nonce`, the `client_id` as `aud`, the `sd_hash` of the presentation, and an `iat` at most 300 seconds old and 60 ahead (`rfc9901 §7.3`; `openid4vp` Appendix B.3.6; the window is our own design) |
| `revoked` | the Token Status List gives the credential's index the value valid (`tsl §7.1`) |
| `status_unavailable` | the Status List Token reads, is of type `statuslist+jwt`, is signed under a chain to the same anchors (`haip §6.1`), names the credential's `uri` as `sub`, is not expired, and holds the index (`tsl §8.3`) |
| `replayed_nonce` | the request's nonce was not answered before (`openid4vp §14.1.2`) |
| `no_administrative_number` | the identifier claim is disclosed |
| `missing_claim` | every other claim asked for is disclosed (`openid4vp §8.6`) |

The status list is read only when the credential carries `status`
(`sd-jwt-vc §3.4`); a credential without one is accepted, as a credential
valid for 24 hours or less needs no revocation (2979 EAA-4.2.13-03). A
refusal is recorded as a failed `110122` Login naming the reason and
answered with a `400` whose `error_description` is the reason, so the
wallet sees it. The request stays open until it lapses or a valid answer
completes it, so an answer forged against a public `state` cannot end a
person's login (our own design).

**The way back.** An accepted answer is kept in `wallet_answer` under the
request's nonce, so a nonce is answered once, and under the SHA-256 of a
fresh response code. The response URI answers `200` with a `redirect_uri`,
`{issuer}/wallet/complete?response_code=…` (`openid4vp §8.2`). The browser
that began the request brings it back, its cookie naming the request, and
the login completes there; an answer brought back in another session is
refused (`haip §5.1`; `openid4vp §14.2`). The answer is taken once and its
row stays until the request lapses.

**The person.** The PID's `issuing_country` and identifier claim name the
person. The FerroSMART `sub` is pairwise (13.6 item 9) over the entry's
first credential type and `{issuing_country}:{identifier}`, which
`ferrosmart subject <entry> NL:999990019` prints. The identifier claim is
`personal_administrative_number` by default (2977 Annex, Table 8), or a
domestic claim a jurisdiction configures, and the `fhirUser` lookup reads
it through `[[ferrosmart.resource.fhir_user_lookup]]` with the jurisdiction's
identifier system (13.6 item 9). A PID without it is refused as
`no_administrative_number`, and no demographic matching is attempted. The
login's `acr` is `http://eidas.europa.eu/LoA/high`, the level the wallet is
provided at (Regulation (EU) 2024/1183 Art 5a(11); 2977 Art 3(7)), so a
wallet entry takes no `assurance.levels`, only a `minimum`. Its
`auth_time` is the Key Binding JWT's `iat`.

**The configuration.** `access_certificate_file` (the access certificate
and its path), `access_key_file` (its PKCS#8 P-256 key), and
`registration_certificate_file` are read at start, the key checked against
the certificate and the certificate refused when self-signed.
`issuer_anchor_files` hold the PID providers' anchors as PEM certificates.
`wallet_endpoint`, `vct_values`, `claims` (dotted for a nested claim, the
identifier claim and `issuing_country` among them) and `identifier_claim`
have the defaults above. `ferrosmart upstream registration <entry>` prints
the request URI, the response URI, the redirect URI, the types and the
attributes the registrar records (Implementing Regulation (EU) 2025/848
Art 5, Annex I).
