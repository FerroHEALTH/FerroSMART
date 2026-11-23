<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Capabilities and conformance

FerroSMART implements
[SMART App Launch 2.2.0](https://hl7.org/fhir/smart-app-launch/STU2.2/) on
OAuth 2.0 and OpenID Connect, and is held to it by the
[Inferno SMART App Launch test kit](https://github.com/inferno-framework/smart-app-launch-test-kit)
in CI. The specifications are vendored in the repository under
[`docs/specs/`](https://github.com/FerroHEALTH/FerroSMART/tree/main/docs/specs)
at the versions
[`docs/VERSIONS.md`](https://github.com/FerroHEALTH/FerroSMART/blob/main/docs/VERSIONS.md)
pins.

## The discovery documents

FerroSMART serves three documents under its issuer, each with absolute
endpoint URLs:

| Document | Path | Specification |
|---|---|---|
| Authorization server metadata | `/.well-known/oauth-authorization-server`, inserted between the host and the issuer's path | RFC 8414 §3 |
| OpenID Connect discovery | `{issuer}/.well-known/openid-configuration` | OpenID Connect Discovery 1.0 §4 |
| SMART configuration | `{issuer}/.well-known/smart-configuration` | SMART App Launch 2.2.0, Conformance |

Which document it serves depends on whether people log in. With an
[identity provider](../install/upstream.md) configured, the SMART document
is the App Launch document. Without one, FerroSMART answers Backend
Services alone and the document says so.

## The capabilities it advertises

The SMART App Launch 2.2.0 Conformance page lists capabilities a server
supports. FerroSMART's App Launch document lists these:

| Capability | What it means here |
|---|---|
| `launch-standalone` | The authorization endpoint takes an app that starts on its own |
| `launch-ehr` | An app launched by an EHR with a `launch` value ([EHR launch API](../integrate/ehr-launch.md)) |
| `authorize-post` | The authorization endpoint takes the request by `GET` and by `POST` |
| `client-public` | A public client authenticates with PKCE alone |
| `client-confidential-symmetric` | A confidential client authenticates with its secret, `client_secret_basic` or `client_secret_post` |
| `client-confidential-asymmetric` | A confidential client authenticates with a `private_key_jwt` assertion signed `RS384` or `ES384` |
| `sso-openid-connect` | `openid` and `fhirUser` give the app an ID Token signed `RS256` with the person's `fhirUser` |
| `context-ehr-patient`, `context-ehr-encounter` | The patient and encounter of an EHR launch reach the token response |
| `context-standalone-patient` | The patient picker chooses the patient of a standalone launch, when a resource server can be searched |
| `context-standalone-encounter` | The picker chooses one of that patient's encounters, at a FHIR server |
| `context-banner` | `need_patient_banner` reaches the token response |
| `context-style` | The token response carries `smart_style_url`, when one is configured |
| `permission-offline`, `permission-online` | Refresh tokens under `offline_access` and `online_access` |
| `permission-patient`, `permission-user` | `patient/` and `user/` scopes |
| `permission-v1` | SMART v1 scopes (`.read`, `.write`, `.*`), matched by their v2 form and granted as asked |
| `permission-v2` | SMART v2 scopes (`.cruds`) |

The Backend Services document lists `client-confidential-asymmetric`.

Both documents advertise `code_challenge_methods_supported: ["S256"]` and
never `plain`, `token_endpoint_auth_signing_alg_values_supported:
["RS384", "ES384"]`, the introspection and revocation endpoints, and, with
login, `management_endpoint`, where a person sees the apps they allowed
and every app holding live access to their data, and disconnects any of
them.

## The endpoints

| Method and path | What it is | Ground |
|---|---|---|
| `GET {issuer}/jwks` | The public keys that sign tokens, as bare JWKs | RFC 7517 §5 |
| `GET`, `POST {issuer}/authorize` | The authorization endpoint | SMART App Launch 2.2.0; RFC 6749 §3.1 |
| `GET {issuer}/callback` | The identity provider's redirect back | OpenID Connect Core 1.0 §3.1.2.5 |
| `GET`, `POST {issuer}/picker` | The patient picker | our own design |
| `GET`, `POST {issuer}/consent` | The consent page | our own design |
| `GET`, `POST {issuer}/manage` | The person's remembered consents and every app holding live access, organisation-approved apps included, each with Disconnect | SMART App Launch 2.2.0, `management_endpoint` |
| `POST {issuer}/token` | The token endpoint | RFC 6749 §3.2 |
| `POST {issuer}/introspect` | Token introspection | RFC 7662 §2 |
| `POST {issuer}/revoke` | Token revocation | RFC 7009 §2 |
| `POST {issuer}/launch` | The EHR launch API | our own design |
| `POST {issuer}/backchannel-logout` | The identity provider's logout notice | OpenID Connect Back-Channel Logout 1.0 |
| `GET {issuer}/frontchannel-logout` | The identity provider's logout notice, in its iframe | OpenID Connect Front-Channel Logout 1.0 |
| `GET`, `POST {issuer}/logout` | The end-session endpoint, with its confirmation at `{issuer}/logout/confirm` and the provider's return at `{issuer}/logout/return` | OpenID Connect RP-Initiated Logout 1.0 |
| `GET {issuer}/audit` | FerroSMART's own audit records | our own design |
| `GET {issuer}/upstream-jwks` | The keys FerroSMART signs its own client assertions to the identity provider with | our own design |
| `GET {issuer}/health`, `/health/liveness`, `/health/readiness`, `/health/info` | Health | the FerroHEALTH family |

## OpenID Connect parameters

FerroSMART is an OpenID Provider toward its apps and takes the parameters
OpenID Connect Core 1.0 §15.1 has every provider support, beside SMART's
PKCE and `aud`, which stay required. FerroSMART keeps no session of its
own, so every request logs the person in at the identity provider, and
the parameters about that login go there:

| Parameter | What FerroSMART does |
|---|---|
| `prompt=none` | Answers `login_required` to the app at once, with no page |
| `prompt=login`, `prompt=select_account` | Passed to the identity provider's login |
| `prompt=consent` | Shows the consent page even when a remembered consent or an approval would answer |
| `max_age` | Passed to the identity provider; a login older than it is begun again once with `prompt=login`, and one still older answers `login_required` |
| `ui_locales` | Passed to the identity provider, and chooses the pages' language before the browser's |
| `acr_values` | An eIDAS level URI is the level the login must reach, asked of the identity provider; a login below it answers `unmet_authentication_requirements` (RFC 9470 §5). Any other value is taken and ignored |
| `display`, `claims_locales` | Taken without changing the flow |

Every ID Token is signed `RS256` and carries `auth_time`, the time the
person authenticated at the identity provider, and `acr`, the eIDAS level
of that login. FerroSMART has no UserInfo
endpoint: the ID Token and its `fhirUser` claim identify the person.

## What SMART leaves open, and how FerroSMART decides

Where the specifications are silent, FerroSMART makes one fixed decision
and the architecture records it as its own design:

- **The launch context in the access token.** SMART puts `patient`,
  `encounter` and `fhirUser` in the token response. FerroSMART writes them,
  and `ehrId` for an openEHR server, into the access token as well, so a
  resource server that reads the JWT has them (RFC 9068 §2.2.2).
- **Scopes.** The granted scope is what the request asks for, narrowed to
  the client's registered ceiling, the scopes the person's roles allow and
  what the person approves ([clients, roles and consent](../configure/clients.md)).
- **Consent where it protects the person.** A user flow shows the consent
  page unless the person remembered that choice for that client and
  resource server, or an administrator approved the client and the
  request stays within that approval: for the organisation's
  professionals (with `patient/` scopes only in an EHR launch), and for
  the organisation's own app (`first_party`) its patients too, lasting
  access included (OpenID Connect Core 1.0 §3.1.2.4, "previous
  administrative consent"). An app of another party always shows a
  patient the page (SMART App Launch 2.2.0, Best Practices). A public
  client without a claimed `https` redirect, and an app's
  `prompt=consent`, always show the page (RFC 8252 §8.6; OpenID Connect
  Core 1.0 §3.1.2.1). Every app holding live access can be disconnected on
  the management page. [The consent rules](../configure/consent.md) lists
  every case.
- **`online_access`.** An online refresh token ends when the person's login
  at the identity provider ends, signalled by back-channel or front-channel
  logout, when the person logs out at the end-session endpoint, or after
  `online_idle` unused.
- **The person's `sub`.** A pairwise identifier derived from the identity
  provider's issuer and `sub`, so the provider's identifier never reaches a
  resource server.
- **Refresh rotation for every client.** Each refresh rotates the token, and
  a rotated token presented again revokes the whole grant, unless its own
  client repeats it within 10 seconds while the new token is unused: a retry
  or a race then gets the same new token.
- **Introspection.** A confidential client authenticated as at the token
  endpoint (its assertion or its secret), or a bearer token FerroSMART
  issued, each holding the scope `system/introspect` (RFC 7662 §2.1).

## The test kit in CI

The CI lane runs the four groups of the kit's STU 2.2 server suite
(`smart_stu2_2`): the standalone launch, the EHR launch, Backend Services
and token introspection. FerroSMART runs with Keycloak upstream and
FerroBRIDGE's FHIR R4 facade as the FHIR server, all over TLS, and every
test of the suite passes. The lane fails when a result changes, and the
list of tests it may expect anything other than a pass is empty.

## The OpenID Foundation conformance suite in CI

A second CI lane runs four plans of the OpenID Foundation conformance
suite against FerroSMART. Each module is held to the result recorded in
[`app/ferrosmart/oidf/expected.tsv`](https://github.com/FerroHEALTH/FerroSMART/blob/main/app/ferrosmart/oidf/expected.tsv),
and an expected failure names its issue.

| Plan | FerroSMART's role | Its client authentication at the suite |
|---|---|---|
| `oidcc-client-test-plan` | Relying party, logging in at the suite | `private_key_jwt`, and `client_secret_basic` for the module `oidcc-client-test-client-secret-basic` |
| `oidcc-client-basic-certification-test-plan` | Relying party | `client_secret_basic`, with the secret read from a file |
| `oidcc-config-certification-test-plan` | OpenID Provider | Not applicable: the suite reads the discovery document |
| `oidcc-basic-certification-test-plan` | OpenID Provider | Not applicable: the suite is a confidential client of FerroSMART |

As the relying party, FerroSMART runs from one configuration that names no
client authentication, and the lane adds the method each module fixes, as
an administrator sets it for a provider (see
[Identity providers](../install/upstream.md)).
