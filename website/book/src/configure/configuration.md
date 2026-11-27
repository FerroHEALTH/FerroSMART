<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Configuration

**For:** operators. Every configuration key, its default and what it does.

FerroSMART reads one configuration tree, in this order, the later winning:

1. the TOML file `--config` names, or `FERROSMART_CONFIG` does;
2. the environment, every key as `FERROSMART__<SECTION>__<KEY>`, with an
   index for an element of an array of tables
   (`FERROSMART__FERROSMART__RESOURCE__0__BASE`);
3. `--set key=value` pairs on the command line.

Every table refuses a key it does not know, so a typing error fails the
start instead of being ignored. Every secret has a `_file` form that names a
file holding it, such as `url_file` beside `url`; use the file form, so a
secret stays out of the environment. `ferrosmart config check` prints the
tree as FerroSMART reads it, every secret masked, and exits non-zero naming
the first key it cannot run with.

A duration is written as `"5min"`, `"8h"` or `"30d"`.

## `[server]`

The listener and the request stack every FerroHEALTH server shares.

| Key | Default | What it is |
|---|---|---|
| `listen` | `127.0.0.1:8080` (the image sets `0.0.0.0:8080`) | The address the listener binds |
| `base_path` | empty | The path every route is served under; it must equal the issuer's path |
| `request_timeout` | `30s` | How long one request may take before a `408` |
| `header_read_timeout` | `30s` | How long a client may take to send its request head |
| `idle_timeout` | `2min` | How long an idle connection is kept |
| `body_limit` | 1 MiB | The largest request body read before a `413` |
| `drain_delay` | `0s` | How long readiness stays withdrawn before the listener closes |
| `shutdown_timeout` | `10s` | How long requests in flight may take once the listener closed |
| `max_concurrent_requests` | 256 | Requests served at once before a `503` with `Retry-After` |
| `trusted_proxies` | none | The reverse proxies whose forwarded client address is believed |
| `caller_rate` | none | A request rate per caller, refused past it |
| `compression` | `true` | Whether responses are compressed for a client that accepts it |
| `[server.tls]` | none | TLS on the listener: `certificate_file`, `key_file`, `min_version`, and client certificates; unset, the listener speaks plain HTTP behind a proxy that terminates TLS |

The table is the `ferrohealth-server` crate's, documented on
[docs.rs](https://docs.rs/ferrohealth-server).

## `[telemetry]`

The console log. `format` is `auto` (readable on a terminal, JSON
otherwise), `pretty` or `json`; `filter` is a `RUST_LOG` filter such as
`info`, and `RUST_LOG` sets it too. No line carries a token, a code, a
secret or an assertion.

## `[ferrosmart]`

| Key | Default | What it is |
|---|---|---|
| `name` | `FerroSMART` | The deployment's name, such as the hospital's: every page carries it, and the User Access Brand's name when `[ferrosmart.brand]` names none |
| `issuer` | required | The issuer identifier (RFC 8414 §2): an `https` URL with no query or fragment, or `http` on a loopback host. Its path is `[server] base_path`. Every document repeats it exactly |
| `access_token_lifetime` | `5min` | How long an access token lives, for every grant; at most one hour (SMART App Launch 2.2.0, App Launch) |
| `refresh_idle` | `30d` | How long an `offline_access` refresh token lasts unused; each refresh starts it again |
| `online_idle` | `8h` | How long an `online_access` refresh token lasts unused, and never past the person's login at the identity provider |
| `assurance_minimum` | `substantial` | The eIDAS level of assurance every person's login reaches: `none`, `low`, `substantial` or `high`. `substantial` is the least Implementing Regulation (EU) 2026/2099 admits; a deployment outside the eIDAS area sets `none`. Each provider's `[ferrosmart.upstream.assurance]` must map a value that reaches it |
| `require_pushed_authorization_requests` | `false` | Whether every authorization request arrives pushed to `POST {issuer}/par` (RFC 9126 §4); `false` still holds a client whose own `require_pushed_authorization_requests` is `true` to it |

None of the three lifetimes may be zero.

## `[ferrosmart.database]`

| Key | Default | What it is |
|---|---|---|
| `url_file` | | A file holding the PostgreSQL connection URL |
| `url` | | The URL itself; set one of the two |
| `max_connections` | 16 | The most connections one replica holds |

FerroSMART needs PostgreSQL 19 or newer and refuses an older server at
start. Every piece of state is in the database, so any number of replicas
share one. Migrations ship in the binary and run at start
([upgrade FerroSMART](../operate/upgrades.md)).

## `[ferrosmart.keys]`

The keys that sign every access token and ID Token, each in turn
([keys and rotation](../operate/keys.md)): RSA keys under `RS256`, which
are required, and ML-DSA-65 keys (RFC 9964) beside them. The keys of each
algorithm rotate on their own. A resource server's
`access_token_signing_alg` decides which signs its access tokens, and a
client's `id_token_signed_response_alg` which signs its ID Tokens.

| Key | Default | What it is |
|---|---|---|
| `private_key_files` | required | The PEM files of the keys, in the order they take over: RSA (PKCS#8 or PKCS#1) signing `RS256`, at least one; P-256 signing `ES256`; Ed25519 signing `EdDSA`; ML-DSA-65 (PKCS#8, RFC 9881) signing `ML-DSA-65`. Each is published under its RFC 7638 thumbprint |
| `ps256_private_key_files` | none | The PEM files of RSA keys that sign `PS256`, none of them among `private_key_files` |
| `rotation_period` | `90d` | How long a key signs before the next one takes over; at least `access_token_lifetime` plus an hour and a minute |

## `[ferrosmart.backend]`

FerroSMART's own SMART Backend Services client. During a standalone launch
it reads a patient's own record, the patient of a paired EHR lookup, a
wallet login's patient and the patient index with a client credentials
token of this client (`system/Patient.rs`, `sub` and `client_id` the
issuer), which a resource server that exchanges user tokens onward reads
with its own credential. FerroSMART keeps the client's registration
itself. A deployment that logs people in at a FHIR server needs this table.

| Key | Default | What it is |
|---|---|---|
| `algorithm` | `ML-DSA-65` | The JWS algorithm of its client assertions: `ML-DSA-65`, `ML-DSA-44` or `ML-DSA-87` (RFC 9964), which FerroSMART's own token endpoint takes, or `ES384` or `RS384`. `ferrosmart key generate --out <file>` writes an ML-DSA-65 key |
| `[ferrosmart.backend.keys]` | required | The assertion ring: `private_key_file` (a P-384 key for `ES384`, an RSA key for `RS384`, an ML-DSA key of that parameter set for ML-DSA), `kid`, `next_private_key_file`, `previous_private_key_file` and `previous_key_overlap`, as the upstream assertion ring has them. It may share no key with the token keys |

## `[[ferrosmart.resource]]`

Each FHIR or openEHR server a token may be for. Its base URL is the `aud`
of the tokens issued for it. At least one is required, and no base twice.

| Key | What it is |
|---|---|
| `base` | The server's base URL as its clients name it: `https`, or `http` on a loopback host, no query or fragment |
| `kind` | `fhir` or `openehr` |
| `access_token_signing_alg` | The algorithm its access tokens are signed with: `RS256` (the default) or `ML-DSA-65` for a server that verifies ML-DSA (RFC 9964); a key of `[ferrosmart.keys]` must sign it |
| `subject_namespace` | openEHR only: the namespace the server's EHRs name their subjects in, which the patient picker looks an EHR up by. Unset, the picker is not offered at that base |
| `fhir_base` | openEHR only: the base of the same platform's FHIR server, one of the FHIR bases configured here. The patient picker then searches that server for the patient and looks their EHR up, so the app gets both `patient` and `ehrId`. Needs `subject_namespace` and `subject_system` |
| `subject_system` | With `fhir_base`: the `system` of the `Patient.identifier` whose value is the subject id of the patient's EHR in `subject_namespace` |
| `fhir_user_lookup` | FHIR only, a list of tables: how to find a person's `fhirUser` when the identity provider sends none (below) |
| `patient_index` | FHIR only, a table: the patient index a wallet login's administrative number is resolved at, with its FHIR `base`, its `transaction` (`pixm`, the default, for ITI-83, or `pdqm` for ITI-78) and the `system` of this server's own patients in it. FerroSMART asks the index as itself with `system/Patient.rs`, then searches this server for the person's identifier in that system. One patient is the `fhirUser`; none or several refuse the launch. Unset, a wallet login takes `fhir_user_lookup` |
| `purpose` | openEHR only, a list of tables: the purposes of use the server accepts, one of which a professional chooses on the patient picker (below). Empty, a lookup declares none |
| `purpose_header` | openEHR only, with `purpose`: the header a picker lookup declares the purpose in. Default `x-purpose-of-use`, FerroEHR's default `[audit] purpose_header` |
| `assigned` | FHIR only: the search the patient picker lists a professional's assigned patients by, `care_team` (their active care teams) or `encounter` (their encounters in progress), each by the FHIR R4 `participant` search parameter and the person's `fhirUser`, for a `fhirUser` that names a `Practitioner` or `PractitionerRole`. Unset, the picker lists none |

When the identity provider sends no `fhirUser` claim, FerroSMART can find
the person at a FHIR server by an identifier. Each
`[[ferrosmart.resource.fhir_user_lookup]]` names a `resource_type`
(`Practitioner`, `PractitionerRole`, `Patient`, `RelatedPerson` or
`Person`), the upstream ID Token `claim` whose text is the identifier's
value, and the identifier's `system`. FerroSMART searches
`[base]/[resource_type]?identifier=[system]|[value]` as the person. One
match across the tables is the person's `fhirUser`; none, several or a
refused search leave it out, and the consent page tells the person their
account is linked to no single record. A lookup on the FHIR base paired
with an openEHR base also serves requests to that openEHR base.

```toml
[[ferrosmart.resource]]
base = "https://ehr.example.org/fhir"

[[ferrosmart.resource.fhir_user_lookup]]
resource_type = "Practitioner"
claim = "staff_id"
system = "urn:example:staff"
```

An openEHR server such as FerroEHR decides a professional's request by
their roles and by the purpose of use the request declares in a header.
The patient picker's token carries the person's roles, and each
`[[ferrosmart.resource.purpose]]` names a purpose the server accepts: the
`code` sent as the header's value (visible ASCII, no comma, one of the
server's accepted codes, FerroEHR's `[audit] purpose_codes`), its code
`system` (an absolute URI) and the `display` the picker page shows. The
professional chooses one on the picker page (it is preselected when only
one is listed), and the EHR lookup and the look-up-again of the choice
both send it. The choice is kept for the rest of the request, so the two
always declare the same purpose. A patient looking up their own record
declares none. FerroSMART's access record of each lookup names the
purpose.

```toml
[[ferrosmart.resource]]
base = "https://ehr.example.org/openehr/v1"
kind = "openehr"
subject_namespace = "examples"
purpose_header = "x-purpose-of-use"

[[ferrosmart.resource.purpose]]
code = "TREAT"
system = "http://terminology.hl7.org/CodeSystem/v3-ActReason"
display = "Treatment"

[[ferrosmart.resource.purpose]]
code = "ETREAT"
system = "http://terminology.hl7.org/CodeSystem/v3-ActReason"
display = "Emergency treatment"
```

## `[[ferrosmart.upstream]]`

The identity providers people log in at. Their keys are on
[upstream configuration](upstream-keys.md#ferrosmartupstream).

## `[ferrosmart.saml]`

FerroSMART as a SAML 2.0 service provider. Its keys are on
[upstream configuration](upstream-keys.md#ferrosmartsaml).

## `[[ferrosmart.role]]`

The policy: what each role may be granted. The clients live in the
database, never in the configuration. [Clients, roles and consent](clients.md)
describes both.

## `[ferrosmart.registration]`

Whether an app may register itself at `POST {issuer}/register` with no
initial access token (RFC 7591 §3), and the most it may hold.

| Key | What it is |
|---|---|
| `open` | `true` lets an app register itself; `false` by default, when only an administrator registers |
| `scope` | The ceiling of an app that registered itself, space-separated; no `user/` or `system/` scope. Required when `open` |

[The admin API](admin-api.md#apps-that-register-themselves) describes the
registration.

## `[ferrosmart.branding]`

The deployment's own words on the pages. Content, never code.

| Key | What it is |
|---|---|
| `consent_text` | The deployment's words on the consent page, such as what it does with the access a person gives |
| `smart_style_url` | The `smart_style_url` every token response carries: an `https` URL of the deployment's SMART style document; empty for none |

## `[ferrosmart.brand]`

The deployment's User Access Brands Bundle (SMART App Launch 2.2.0, User
Access Brands and Endpoints): the cards an app shows so a person can find
the hospital and connect to it. With this table FerroSMART serves the
Bundle at `GET {issuer}/brands` as `application/fhir+json`, readable from
any origin, with a weak `ETag` that a request's `If-None-Match` answers with
`304`. Without it the route is absent.

The table is the primary brand. Every FHIR server it publishes is a
`[[ferrosmart.brand.endpoint]]`, which the primary brand references.

| Key | What it is |
|---|---|
| `name` | The name people recognize the brand by; `[ferrosmart] name` when absent. An affiliate names its own |
| `website` | The brand's own `https` website, apart from any portal. Required |
| `identifier` | The identifiers apps merge brands by, each `{ system, value }`; SMART recommends `system = "urn:ietf:rfc:3986"` with the website's origin, without `www.`, as `value`. An identifier belongs to one brand |
| `alias` | Other names people may search by, such as a former name |
| `category` | Codes of SMART's `user-access-category`: `prov`, `ins`, `laboratory`, `imaging`, `pharmacy`, `health-information-network`, `health-data-aggregator` |
| `logo`, `logo_license` | The brand's logo, an `https` or `data` URL, and the `https` page of its terms of use |
| `address` | The places of the brand, each `{ line, city, state, postal_code, country }` |
| `[[ferrosmart.brand.portal]]` | A portal people manage their account in: `name`, `description` (Markdown), `url`, `logo`, `logo_license`, and `endpoints`, the bases of the endpoints it offers |
| `[[ferrosmart.brand.endpoint]]` | A FHIR server of the Bundle: `base`, one of the FHIR `[[ferrosmart.resource]]` bases; `name`; `fhir_version`, such as `["4.0.1"]`, at least one; and `contact`, at least one `https` page where developers configure access |
| `[[ferrosmart.brand.affiliate]]` | An affiliated brand, part of the primary one, with the same keys but `endpoint` and `affiliate`, and portals of its own |

`Bundle.timestamp` is the moment the contents last changed, and each
resource's `meta.lastUpdated` the moment that brand or endpoint last
changed: FerroSMART keeps a digest of the contents and of each resource in
its database, so a restart with the same table keeps every moment and every
replica serves the same Bundle. Each FHIR
server names the Bundle in its own `.well-known/smart-configuration` as
`user_access_brand_bundle`, with one of the brand's identifiers as
`user_access_brand_identifier` when the Bundle holds more than one brand.

```toml
[ferrosmart.brand]
name = "Example Hospital"
website = "https://example.org"
identifier = [{ system = "urn:ietf:rfc:3986", value = "https://example.org" }]
category = ["prov"]
logo = "https://example.org/logo.svg"

[[ferrosmart.brand.portal]]
name = "Patient Portal"
url = "https://portal.example.org"
endpoints = ["https://ehr.example.org/fhir"]

[[ferrosmart.brand.endpoint]]
base = "https://ehr.example.org/fhir"
fhir_version = ["4.0.1"]
contact = ["https://developer.example.org"]
```

## `[ferrosmart.picker]`

| Key | Default | What it is |
|---|---|---|
| `recent_retention` | `30d` | How long a patient a person chose stays on their recent list, which the picker offers again; `0s` keeps no list. FerroSMART keeps a person's ten latest choices at each server, and the person forgets them on the management page |

## `[ferrosmart.audit]`

How FerroSMART names itself in its [audit records](../operate/audit.md), and
where it forwards them.

| Key | What it is |
|---|---|
| `source_id` | FerroSMART as the recording system, `AuditEvent.source.observer`; empty takes the issuer's host |
| `site` | The site FerroSMART runs at, `AuditEvent.source.site` |
| `[ferrosmart.audit.feed]` | An Audit Record Repository: `url`, an `https` FHIR base the records are created under as `[base]/AuditEvent`, with `timeout`, `connect_timeout`, `retry`, `tls` and `credentials` (Basic, or an OAuth 2.0 client credentials grant under `credentials.oauth`). Unset, the records stay in FerroSMART's own store |

## A whole file

```toml
[ferrosmart]
name = "Example Hospital"
issuer = "https://smart.example.org"

[ferrosmart.database]
url_file = "/run/secrets/ferrosmart-db-url"

[ferrosmart.keys]
private_key_files = ["/run/secrets/rs256-1.pem", "/run/secrets/rs256-2.pem"]

[ferrosmart.backend.keys]
private_key_file = "/run/secrets/backend-assertion.pem"

[[ferrosmart.resource]]
base = "https://ehr.example.org/fhir"
kind = "fhir"

[[ferrosmart.upstream]]
name = "idp"
preset = "keycloak"

[ferrosmart.upstream.oidc]
issuer = "https://idp.example.org/realms/hospital"
client_id = "ferrosmart"

[ferrosmart.upstream.oidc.private_key_jwt.keys]
private_key_file = "/run/secrets/upstream-assertion.pem"

[[ferrosmart.role]]
name = "clinician"
scopes = ["user/Patient.rs", "user/Observation.rs"]

[ferrosmart.audit]
site = "Example Hospital"
```
