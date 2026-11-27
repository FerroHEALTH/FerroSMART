<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Register clients and roles

**For:** operators and administrators who register apps and map roles to scopes.

Who may ask for what is content, never code. Three things decide the scope
an app gets, and the narrowest wins
([how FerroSMART decides a token](../explanation/token-decision.md) explains
the whole decision):

1. the client's **ceiling**, the scopes its client document lists;
2. the **roles** the person holds at the identity provider, each mapped by a
   `[[ferrosmart.role]]` table to the `user/` and `patient/` scopes it allows;
3. the **consent** the person gives on FerroSMART's consent page.

SMART lets the granted scope differ from the request and has the server's
policy win (SMART App Launch 2.2.0, Obtain access token, Response; Scopes
and Launch Context, SMART's scopes are used to delegate access). The token
response's `scope` always says what was granted. The resource server still
applies its own rules on top.

## The client registry

A client lives in one place: FerroSMART's database, which every replica
reads. RFC 6749 §2 leaves the means of registration to the server, and
SMART App Launch 2.2.0 (Register App with EHR) asks only for what a
registration holds. An administrator registers a client with a client
document, a JSON object, through the [admin API](admin-api.md) or from a
file:

```sh
ferrosmart client apply growth-chart.json portal.json
```

`client apply` reads each file's document, checks it as the admin API does,
and creates the client or replaces the one with its `client_id`, each change
committed with its `AuditEvent`, which names `ferrosmart client apply` as
the requester. It runs when you run it, never at start, and migrates the
database first, so it can create the first client, the administrator, before
FerroSMART first serves.

The document is RFC 7591 §2 client metadata, the names an app that
registers itself sends too. `resources`, `launch_uri`, `upstreams` and
`first_party` are FerroSMART's own.

| Member | What it is |
|---|---|
| `client_id` | The client's id, as the app sends it |
| `client_name` | The name the consent page shows the person |
| `token_endpoint_auth_method` | `none`, `client_secret_basic`, `client_secret_post` or `private_key_jwt` |
| `jwks_uri` | A `private_key_jwt` client's JWK Set URL, `https`; exclusive with `jwks` |
| `jwks` | The client's JWK Set by value |
| `redirect_uris` | The client's complete redirect URIs, compared by exact string |
| `post_logout_redirect_uris` | Where the end-session endpoint may send the browser back (RP-Initiated Logout 1.0 §3.1) |
| `resources` | The `[[ferrosmart.resource]]` bases its tokens may name in `aud`; a request for any other base is refused `invalid_target`, and a client that lists none reaches no resource server |
| `upstreams` | The identity providers its people log in at; every provider when absent |
| `default_acr_values` | The eIDAS level-of-assurance URIs a request without `acr_values` asks for (OpenID Connect Dynamic Client Registration 1.0 §2) |
| `require_pushed_authorization_requests` | `true` when the app may start an authorization request only by pushing it to `POST {issuer}/par` (RFC 9126 §6); `false` by default |
| `id_token_signed_response_alg` | `RS256` (the default) or `ML-DSA-65`: the algorithm the client's ID Tokens are signed with; its access tokens follow the resource server's `access_token_signing_alg` (OpenID Connect Dynamic Client Registration 1.0 §2); `ML-DSA-65` needs an ML-DSA-65 key in `[ferrosmart.keys]` |
| `dpop_bound_access_tokens` | `true` when every token request of the client carries a `DPoP` proof (RFC 9449 §5.2); `false` by default |
| `tls_client_certificate_bound_access_tokens` | `true` when the client's tokens are bound to the certificate of its mutual-TLS connection, which every token request then presents (RFC 8705 §3.4); `false` by default |
| `launch_uri` | Optional: the app's launch URL, absolute `https`, by which an EHR's [launch registration](../integrate/ehr-launch.md) may name the app (`app_launch_uri`), as a SMART Task does; compared after RFC 3986 normalization, one client per URL |
| `client_uri` | Optional: the app's home page, absolute `https`, linked from the consent page |
| `logo_uri` | Optional: the app's logo, absolute `https`, drawn on the consent page; the page's CSP admits that origin for images alone |
| `policy_uri` | Optional: the app's privacy policy, absolute `https`, linked from the consent page |
| `tos_uri` | Optional: the app's terms of service, absolute `https`, linked from the consent page |
| `first_party` | `true` for the organisation's own app, or one that acts for it, whose patients then see no consent page ([the consent rules](consent.md#who-sees-the-page)); only an administrator sets it, and it needs `authorization_code`. `false` by default |
| `scope` | The ceiling, space-separated: every scope the client may ever be granted |
| `grant_types` | Any of `authorization_code`, `client_credentials`, `refresh_token` and `urn:ietf:params:oauth:grant-type:token-exchange`. The token exchange lets a confidential client that serves a FHIR base exchange a patient's own token there for a token at the paired openEHR base (RFC 8693), and needs both bases in `resources` |

FerroSMART refuses a document that breaks one of these rules, with the
RFC 7591 §3.2.2 error `invalid_redirect_uri` or `invalid_client_metadata`:

- a client lists at least one grant type;
- a `none` client registers no JWK Set and cannot use
  `client_credentials` or the token exchange, since both grants
  authenticate the client;
- a `private_key_jwt` client registers exactly one of `jwks_uri` and
  `jwks`, and every key in the set carries `kty` and `kid` and the bare
  public members (`n` and `e`, `crv`, `x` and `y`, or for an ML-DSA `AKP`
  key `alg` and `pub`), and no private part;
- a `client_secret_basic` or `client_secret_post` client registers no JWK
  Set and never `client_credentials`, which SMART keeps for asymmetric
  clients;
- `refresh_token`, `launch_uri` and `first_party` come with
  `authorization_code`;
- `authorization_code` comes with at least one redirect URI;
- each of `default_acr_values` is an eIDAS level of assurance.

### Client authentication

| `token_endpoint_auth_method` | SMART capability | How it authenticates |
|---|---|---|
| `none` | `client-public` | PKCE alone; a browser or native app that keeps no secret |
| `client_secret_basic` | `client-confidential-symmetric` | Its client secret by HTTP Basic |
| `client_secret_post` | `client-confidential-symmetric` | Its client secret in the form |
| `private_key_jwt` | `client-confidential-asymmetric` | A client assertion signed `RS384`, `ES384`, `ML-DSA-44`, `ML-DSA-65` or `ML-DSA-87` (RFC 9964, an `AKP` key) with a key of its registered JWK Set |

A client authenticates only by the method it registered. SMART prefers
asymmetric authentication for a client that can hold a key pair; a secret
is for an app that can keep one and nothing more. FerroSMART issues the
secret when it registers the client and answers it once, as
`client_secret` with `client_secret_expires_at` 0 (RFC 7591 §3.2.1); it
keeps only the secret's Argon2id hash. `client apply` prints the secret it
issued, and `ferrosmart client secret <client_id>` issues a new one, which
it prints once. The admin API's `POST /admin/clients/{client_id}/secret`
does the same and answers the client with the secret, once
([the admin API](admin-api.md#a-clients-new-secret)):

```sh
ferrosmart client secret portal
```

The client assertion follows SMART App Launch 2.2.0, Client Authentication:
Asymmetric: `iss` and `sub` the `client_id`, `aud` the token endpoint URL
or the issuer, `exp` at most five minutes ahead, a `jti` used once, `typ`
`JWT`. A `client_id` sent beside it must be the `iss`, a `jku` header must
equal the registered JWK Set URL, and exactly one key of the set must match
the `kid` and the algorithm's key type. A JWK Set fetched by URL is cached
no longer than its `Cache-Control` allows. Any failure answers
`invalid_client`.

### Examples

A SMART app a person launches, which may stay signed in:

```json
{
  "client_id": "growth-chart",
  "client_name": "Growth chart",
  "token_endpoint_auth_method": "none",
  "resources": ["https://ehr.example.org/fhir"],
  "redirect_uris": ["https://growth-chart.example.org/callback"],
  "scope": "openid fhirUser launch launch/patient patient/Observation.rs online_access",
  "grant_types": ["authorization_code", "refresh_token"]
}
```

A web app with a server that keeps a secret:

```json
{
  "client_id": "portal",
  "client_name": "Patient portal",
  "token_endpoint_auth_method": "client_secret_basic",
  "resources": ["https://ehr.example.org/fhir"],
  "redirect_uris": ["https://portal.example.org/callback"],
  "scope": "openid fhirUser launch/patient patient/Observation.rs",
  "grant_types": ["authorization_code", "refresh_token"]
}
```

A system with no person, SMART Backend Services:

```json
{
  "client_id": "bulk-export",
  "client_name": "Bulk export",
  "token_endpoint_auth_method": "private_key_jwt",
  "resources": ["https://ehr.example.org/fhir"],
  "jwks_uri": "https://export.example.org/jwks.json",
  "scope": "system/Patient.rs system/Observation.rs",
  "grant_types": ["client_credentials"]
}
```

Four scopes are FerroSMART's own `system/` scopes, which a client's ceiling
lists to reach an endpoint of FerroSMART itself:

| Scope | What it opens |
|---|---|
| `system/introspect` | `POST /introspect`, for a resource server that introspects ([the flows](../integrate/flows.md#refresh-introspection-and-revocation)) |
| `system/launch.c` | `POST /launch` and the signed launch JWT, for an EHR ([the EHR launch API](../integrate/ehr-launch.md)) |
| `system/AuditEvent.rs` | `GET /audit`, for an operator's client ([audit records](../operate/audit.md#reading-the-records)) |
| `system/admin` | `/register` and every `/admin/` route, for an administrator's client ([the admin API](admin-api.md)) |

## Roles

A `[[ferrosmart.role]]` table names a role as the identity provider's role
claims carry it, and the scopes a person holding it may be granted:

```toml
[[ferrosmart.role]]
name = "clinician"
scopes = ["user/Patient.rs", "user/Observation.rs", "patient/Observation.rs"]
```

When none of the scopes an app asks for can be granted to the person,
FerroSMART shows a page that names the roles that would grant one (or says
the app asks for access this server does not give it), and its button
returns to the app with `access_denied`. Give the person one of the named
roles at the identity provider.

A role grants only `user/` and `patient/` scopes and extension scopes,
has a name with no space, and is named once. An extension scope is any
scope that starts with two underscores, such as FerroEHR's
`__ferroehr.platform` (SMART App Launch 2.2.0, Scopes and Launch Context,
Extensibility): a resource server defines it for an API of its own. A
person is granted one only when the request asks for it, the client's
ceiling lists it and one of the person's roles grants it; a request alone
never grants it. The discovery document lists every extension scope a
role grants in `scopes_supported`, and the consent page names it in plain
words beside the SMART scopes:

```toml
[[ferrosmart.role]]
name = "administrator"
scopes = ["user/Patient.rs", "__ferroehr.platform"]
```

Any other scope outside the SMART set is never granted to a person. `[ferrosmart.upstream.oidc] role_claims` says where in the ID
Token the roles are ([identity providers](../install/upstream.md)).

## Which scopes a person is offered

FerroSMART offers a requested scope only when the client's ceiling lists
it, and, for a `user/`, `patient/` or extension scope, when one of the
person's roles grants it; [how FerroSMART decides a
token](../explanation/token-decision.md#the-scopes-request-ceiling-roles-context)
has the whole table. "Lists it" and "grants it" read a scope by its parts
(SMART App Launch 2.2.0, Scopes and Launch Context), so write a ceiling or
a role with these in mind:

- `patient/Composition.crs` admits `patient/Composition.rs` and
  `patient/Composition.r`;
- `user/*.rs` admits `user/Observation.r`;
- `patient/Observation.rs?category=vital-signs` never admits the
  unrestricted `patient/Observation.r`;
- a v1 scope (`.read`, `.write`, `.*`) reads as its v2 letters, and every
  other scope matches as written.

With both refresh scopes granted, `offline_access` decides.

## Consent

[The consent rules](consent.md) say who sees the consent page and why. Two
members of the client document change the outcome: `first_party`, for the
organisation's own app, and the redirect URIs of a public client.

### Native and browser apps without a secret

A public client (`token_endpoint_auth_method` `none`) has no secret, so a
request carrying its `client_id` could come from any app on the device.
FerroSMART skips the consent page for a public client only when the
request's redirect URI is a claimed `https` URI: an `https` URL whose host
is not `localhost` or a loopback address, which the operating system hands
only to the app that proved it owns the domain (RFC 8252 §7.2). With a
custom-scheme redirect such as `com.example.app:/callback`, or a loopback
one such as `http://127.0.0.1:8400/callback`, the person sees the page on
every sign-in (RFC 8252 §8.6).

Register the organisation's own mobile app with a claimed `https` redirect,
an iOS Universal Link or an Android App Link, so its patients see no page.
`ferrosmart client apply` prints a warning for a public client an
administrator registers whose redirect URIs are all custom-scheme or
loopback ones:

```text
ferrosmart: warning: client "portal-app" is a public app with no claimed https redirect URI, so every sign-in shows the consent page (RFC 8252 §8.6): register an https redirect the app claims, such as a Universal Link or an App Link
```
