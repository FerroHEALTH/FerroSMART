<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# The admin API

The admin API and the registration endpoint change the client registry
while FerroSMART runs, so a new app, a changed redirect URI or a disabled
client needs no restart. They write the PostgreSQL store every replica
reads, and every change takes effect on the next request at every replica.
Clients are registered and managed through RFC 7591 and RFC 7592, the
process SMART App Launch 2.2.0 recommends (Register App with EHR); the
admin routes keep what RFC 7592 has no operation for.

## Access

Register a Backend Services client for your administration tool, with
`system/admin` in its ceiling. The first one has no API to go through, so
apply its document with `ferrosmart client apply registry-admin.json`
([the client registry](clients.md#the-client-registry)):

```json
{
  "client_id": "registry-admin",
  "client_name": "Registry administration",
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks_uri": "https://admin.example.org/jwks.json",
  "scope": "system/admin",
  "grant_types": ["client_credentials"]
}
```

The tool asks the token endpoint for `system/admin` with FerroSMART's own
issuer as the `resource`, and sends the token as a bearer token:

```sh
curl -s https://smart.example.org/token \
  -d grant_type=client_credentials -d scope=system/admin \
  -d resource=https://smart.example.org \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion="$assertion"
```

No role grants a `system/` scope, so no person's token carries it.
FerroSMART checks every admin request against its store: the token not
revoked or expired, issued for its own issuer, and its client still
registered and enabled. A request without a token answers `401
invalid_token`, a token without `system/admin` `403 insufficient_scope`.

## The OpenAPI document

`GET {issuer}/admin/openapi.json` answers, without a token, the OpenAPI
3.1 document of the registration endpoint, the admin routes and the audit
records, with their request and answer schemas, their scopes and their
refusals. Its server is your issuer, so a console or a client generator
can read it straight from the deployment:

```sh
curl -s https://smart.example.org/admin/openapi.json
```

The standard endpoints (`/authorize`, `/token`, `/introspect`, `/revoke`
and the discovery documents) are described by their RFCs and are not in
it.

## The routes

| Request | What it does |
|---|---|
| `POST /register` | Registers a client (RFC 7591 §3), the admin token as the initial access token; answers `201` |
| `GET /register/{client_id}` | Reads one client (RFC 7592 §2.1) |
| `PUT /register/{client_id}` | Replaces a client with the document sent, which names its `client_id` (RFC 7592 §2.2) |
| `DELETE /register/{client_id}` | Deletes a client and ends everything it held; answers `204` (RFC 7592 §2.3) |
| `GET /admin/clients` | Lists every client, disabled ones included |
| `POST /admin/clients/{client_id}/disable` | Disables a client and ends everything it holds |
| `POST /admin/clients/{client_id}/enable` | Enables a disabled client |
| `GET /admin/keys` | Lists the token signing keys, each public key with its state |

Every answer is JSON with `Cache-Control: no-store`.

## The client document

The registration endpoint takes the document `ferrosmart client apply`
reads ([the client registry](clients.md#the-client-registry)) and ignores a
member it does not read (RFC 7591 §2). An omitted
`token_endpoint_auth_method` is `client_secret_basic` and omitted
`grant_types` are `authorization_code`. An administrator's registration
may name its `client_id`; without one FerroSMART issues it. For a client that
authenticates with a secret, the answer that registers it carries the
secret FerroSMART issued, once, as `client_secret` with
`client_secret_expires_at` 0 (RFC 7591 §3.2.1); a `PUT` keeps the stored
secret, and no answer repeats it.

```json
{
  "client_id": "growth-chart",
  "client_name": "Growth chart",
  "token_endpoint_auth_method": "none",
  "redirect_uris": ["https://growth-chart.example.org/callback"],
  "resources": ["https://ehr.example.org/fhir"],
  "scope": "openid fhirUser launch user/Observation.rs",
  "grant_types": ["authorization_code"],
  "first_party": false
}
```

An answer adds `registered_by`, `admin` or `self`
for an app that registered itself (RFC 7591 §5), and `disabled_at` for a
disabled client.

## Refusals

| Status | `error` | When |
|---|---|---|
| `415` | `invalid_request` | The body is not `application/json` |
| `413` | `invalid_request` | The body is over 64 KiB |
| `400` | `invalid_request` | The body is not JSON, or names another `client_id` than the path |
| `422` | `invalid_request` | The JSON is not a client document object, or holds a member the document does not have |
| `400` | `invalid_redirect_uri` | A redirect URI is not an absolute URL without a fragment (RFC 7591 §3.2.2) |
| `400` | `invalid_client_metadata` | Any other rule of the registry is broken, or the client names an identity provider that is not configured (RFC 7591 §3.2.2) |
| `404` | `not_found` | No client is registered under the id |
| `409` | `client_exists` | A client is registered under the id already |
| `409` | `launch_uri_taken` | Another client registers the launch URL |
| `409` | `unchanged` | The client is in that state already: disabled or enabled |

A refusal with a status below 500 carries an `error_description` that names
the rule broken.

## Apps that register themselves

With `[ferrosmart.registration] open = true`, `POST /register` also
answers a request with no token: the app registers itself. FerroSMART
issues its `client_id`, holds its `scope` to `[ferrosmart.registration]
scope` (all of it when the app asks none), lets its tokens name every
configured resource server, and refuses `resources`, `launch_uri`,
`upstreams` and `first_party` with `invalid_client_metadata`. The answer
carries a `registration_access_token` and the `registration_client_uri`
where the app reads, changes and deletes its own registration with it
(RFC 7592). The person always sees the consent page for such an app
([the consent rules](consent.md)).

```toml
[ferrosmart.registration]
open = true
scope = "openid fhirUser launch/patient patient/Observation.rs offline_access"
```

The scope takes no `user/` or `system/` scope: an administrator registers
professional and backend apps.

## Clearing `first_party` and disabling

A `PUT` that clears `first_party` revokes, in the same transaction, every
grant issued on it with no page, with its refresh and access tokens, and
drops its unredeemed codes. The person's next refresh fails, and
introspection answers every revoked token inactive at once.

Disabling a client ends everything it holds: every grant and access token
is revoked with its refresh tokens, its codes, launches and pending
requests are dropped, and the people's remembered consents for it are
forgotten. No request finds the client again until it is enabled, and an
enabled client starts with nothing: its people see the consent page again.

A resource server that checks each JWT itself, without introspection,
still accepts a revoked access token until it expires, at most
`access_token_lifetime` later (five minutes by default).

## Records

Every change commits with an audit record that names the administration
client, or `ferrosmart client apply`, as the requester and the client
changed: `client-created`,
`client-updated`, `client-disabled` with how many grants, access tokens
and consents it ended, and `client-enabled`; a `client-updated` that
cleared `first_party` names the grants it revoked ([audit records](../operate/audit.md)). Every admin request also writes the
`ferrohealth_smart::audit` log line with the client and the route.

## The keys

`GET /admin/keys` lists the token signing ring the replica publishes: the
public JWK of each key with its state, `active` (signs), `next` (published
ahead of the rotation that makes it sign) and `retiring` (published until
the tokens it signed have expired). The private keys stay in the files
`[ferrosmart.keys]` names ([keys and rotation](../operate/keys.md)).

## The upstream providers

`GET /admin/upstreams` shows whether each provider people log in at can
still be read, in configuration order, without reading the logs. Each
entry carries the provider's `name`, `label`, `protocol` (`oidc` or
`saml`), its `issuer` (the issuer identifier or the SAML entity ID), the
`clients` that name it in their `upstreams` (a client that names none may
use every provider), and its `documents`:

- an OpenID Connect provider's `openid_configuration` and `jwks`, read
  when the request is answered, since the key set is read at each login
  and FerroSMART holds no copy of it;
- a SAML provider's `saml_metadata` as this replica last read it, with
  `last_good_read_at` (the copy in use) and the metadata's `valid_until`.

Each document has `read_at`, `ok` and, for a failed read, `error`. A key
set or metadata also lists `certificates_expire_at`, the `notAfter` of
each signing certificate it carries. A failed SAML read leaves the last
good copy in use until its `validUntil`. The providers' configuration and
secrets stay in the file and are never answered.

```json
{
  "upstreams": [
    {
      "name": "national",
      "label": "National login",
      "protocol": "saml",
      "issuer": "https://idp.example.org/saml",
      "clients": ["clinic"],
      "documents": [
        {
          "document": "saml_metadata",
          "read_at": "2026-11-23T10:00:00Z",
          "ok": false,
          "error": "the identity provider's metadata cannot be fetched",
          "last_good_read_at": "2026-11-22T10:00:00Z",
          "certificates_expire_at": ["2027-06-01T00:00:00Z"]
        }
      ]
    }
  ]
}
```
## A client's new secret

`POST /admin/clients/{client_id}/secret` issues a confidential symmetric
client a new secret, the same job as `ferrosmart client secret`. The
answer is the client with `client_secret`, once, and
`client_secret_expires_at` 0 (RFC 7591 §3.2.1); the old secret no longer
authenticates, and the record of the change never holds the secret. A
public or `private_key_jwt` client answers `400` with `invalid_request`.
