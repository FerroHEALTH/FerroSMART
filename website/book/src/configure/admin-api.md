<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# The admin API

The admin API changes the client registry while FerroSMART runs, so a new
app, a changed redirect URI or a withdrawn approval needs no restart. It
writes the PostgreSQL store every replica reads, and every change takes
effect on the next request at every replica. SMART App Launch 2.2.0 leaves
registration to the server (Register App with EHR), so the API is
FerroSMART's own design.

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

## The routes

| Request | What it does |
|---|---|
| `GET /admin/clients` | Lists every client, disabled ones included |
| `GET /admin/clients/{client_id}` | Reads one client |
| `POST /admin/clients` | Registers a client; answers `201` with its `Location` |
| `PUT /admin/clients/{client_id}` | Replaces a client with the document sent |
| `POST /admin/clients/{client_id}/disable` | Disables a client and ends everything it holds |
| `POST /admin/clients/{client_id}/enable` | Enables a disabled client |
| `DELETE /admin/clients/{client_id}/organisation_approval` | Withdraws the client's organisation approval |
| `GET /admin/keys` | Lists the token signing keys, each public key with its state |

Every answer is JSON with `Cache-Control: no-store`.

## The client document

The API takes the document `ferrosmart client apply` reads
([the client registry](clients.md#the-client-registry)). For a client that
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
  "organisation_approval": {
    "scopes": ["openid", "launch", "user/Observation.rs"],
    "approved_by": "J. de Vries, information security"
  }
}
```

An approval without `approved_at` keeps the stored approval's time when its
scopes, approver and `first_party` mark are unchanged, and takes the time of
the request otherwise. An answer adds `registered_by`, `admin` or `self`
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
| `409` | `unchanged` | The client is in that state already: disabled, enabled, or without an approval |

A refusal with a status below 500 carries an `error_description` that names
the rule broken.

## Withdrawing and disabling

A `PUT` whose approval differs from the stored one, or leaves it out, and a
`DELETE` of the approval, withdraw the approval in the same transaction as
the change: every grant issued on it is revoked with its refresh and access
tokens, and its unredeemed codes are dropped. The person's next refresh
fails, and introspection answers every revoked token inactive at once.

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
and consents it ended, `client-enabled`, and
`organisation-approval-withdrawn` with how many grants it revoked
([audit records](../operate/audit.md)). Every admin request also writes the
`ferrohealth_smart::audit` log line with the client and the route.

## The keys

`GET /admin/keys` lists the token signing ring the replica publishes: the
public JWK of each key with its state, `active` (signs), `next` (published
ahead of the rotation that makes it sign) and `retiring` (published until
the tokens it signed have expired). The private keys stay in the files
`[ferrosmart.keys]` names ([keys and rotation](../operate/keys.md)).
