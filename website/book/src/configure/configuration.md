<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Configuration

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

Every piece of state is in the database, so any number of replicas share
one. Migrations ship in the binary and run at start.

## `[ferrosmart.keys]`

The RSA keys that sign every access token and ID Token under `RS256`, each
in turn ([keys and rotation](../operate/keys.md)).

| Key | Default | What it is |
|---|---|---|
| `private_key_files` | required | The PEM files of the keys, in the order they take over; each is published under its RFC 7638 thumbprint |
| `rotation_period` | `90d` | How long a key signs before the next one takes over; at least `access_token_lifetime` plus an hour and a minute |

## `[[ferrosmart.resource]]`

Each FHIR or openEHR server a token may be for. Its base URL is the `aud`
of the tokens issued for it. At least one is required, and no base twice.

| Key | What it is |
|---|---|
| `base` | The server's base URL as its clients name it: `https`, or `http` on a loopback host, no query or fragment |
| `kind` | `fhir` or `openehr` |
| `subject_namespace` | openEHR only: the namespace the server's EHRs name their subjects in, which the patient picker looks an EHR up by. Unset, the picker is not offered at that base |
| `fhir_base` | openEHR only: the base of the same platform's FHIR server, one of the FHIR bases configured here. The patient picker then searches that server for the patient and looks their EHR up, so the app gets both `patient` and `ehrId`. Needs `subject_namespace` and `subject_system` |
| `subject_system` | With `fhir_base`: the `system` of the `Patient.identifier` whose value is the subject id of the patient's EHR in `subject_namespace` |
| `fhir_user_lookup` | FHIR only, a list of tables: how to find a person's `fhirUser` when the identity provider sends none (below) |
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

The identity providers people log in at
([identity providers](../install/upstream.md)), one entry each. Without an
entry, nobody logs in and FerroSMART answers Backend Services alone.

| Key | What it is |
|---|---|
| `name` | The provider's name, of letters, digits and `-`, unique among the entries; a client's `upstreams` names it |
| `label` | The words the chooser page shows for the provider; its `name` when empty |
| `preset` | `keycloak`, `entra`, `okta` or `zitadel`: the defaults of FerroSMART's tested setup with that provider, for an OpenID Connect entry; none by default |

The table present names the protocol: `[ferrosmart.upstream.oidc]` for
OpenID Connect, `[ferrosmart.upstream.saml]` for SAML 2.0 or
`[ferrosmart.upstream.openid4vp]` for the EUDI Wallet, exactly one per
entry.

`[ferrosmart.upstream.assurance]` says what the provider's logins are
worth. A login below the minimum is refused with `access_denied`, and every
token issued on a login carries its level as `acr`, the eIDAS URI
`http://eidas.europa.eu/LoA/low`, `/substantial` or `/high`, beside
`auth_time`.

| Key | What it is |
|---|---|
| `levels` | A table of the provider's value to its eIDAS level (`low`, `substantial`, `high`): an OpenID Connect provider's `acr`, a SAML provider's `AuthnContextClassRef`. A value it does not name carries no level |
| `minimum` | The level every login at this provider reaches, above `assurance_minimum`; none by default |

Each entry has its own issuer, and two entries never share one. A client
lists the providers its people may log in at in `upstreams`; with none
listed it may use every provider. With one provider the browser goes
straight to it; with several, FerroSMART shows a chooser at
`{issuer}/login`. Several Microsoft Entra ID tenants are several entries,
one per tenant authority.

`[ferrosmart.upstream.oidc]`. A key the table leaves out takes the
preset's value, then the default below; a key the table sets wins over
the preset.

| Key | What it is |
|---|---|
| `issuer` | The provider's issuer, whose discovery document FerroSMART reads at start |
| `client_id` | The client FerroSMART is registered as at the provider |
| `scopes` | The scopes FerroSMART asks for, `openid` among them; `["openid"]` by default |
| `fhir_user_claim` | The ID Token claim holding the person's `fhirUser`; empty for none, the default |
| `role_claims` | The ID Token claims holding the person's roles, each a dotted path; a claim name with a dot is read whole first. `roles`, `groups` and `entitlements` by default |
| `trusted_audiences` | Audiences an ID Token may carry beside the client id, such as a project the provider adds; empty trusts none, the default |

| Preset | `scopes` | `fhir_user_claim` | `role_claims` | `algorithm` |
|---|---|---|---|---|
| `keycloak` | `openid` | `fhir_user` | `roles` | `RS256` |
| `entra` | `openid profile` | `extn.fhirUser` | `roles` | `PS256` |
| `okta` | `openid profile` | `fhir_user` | `groups` | `RS256` |
| `zitadel` | `openid profile` | `fhirUser` | `urn:zitadel:iam:org:project:roles` | `RS256` |

Each preset is a data file under `app/ferrosmart/presets/` with the
provider's documentation cited beside each value
([identity providers](../install/upstream.md)).

FerroSMART authenticates at the provider with `private_key_jwt` unless
the entry names `[ferrosmart.upstream.oidc.client_secret_basic]`; the
assertion keys go in `[ferrosmart.upstream.oidc.private_key_jwt.keys]`,
and the `private_key_jwt` table itself is needed only for a key below.
An entry never names both, and FerroSMART refuses a provider whose
discovery document does not list the method.

| Key of `client_secret_basic` | What it is |
|---|---|
| `secret_file` | The file holding the client secret the provider issued, sent as HTTP Basic (RFC 6749 §2.3.1); `secret` sets it inline |

The `private_key_jwt` table:

| Key | What it is |
|---|---|
| `algorithm` | The JWS algorithm the provider's registration names; the preset's, else `RS256` |
| `certificate_file` | The X.509 certificate of the current assertion key, for a provider that knows the key by its certificate; each assertion then names it by `x5t#S256` |
| `[ferrosmart.upstream.oidc.private_key_jwt.keys]` | The assertion ring: `private_key_file` (the key that signs), `kid` (the id the provider knows it by, such as ZITADEL's key id; its RFC 7638 thumbprint when empty), `next_private_key_file`, `previous_private_key_file` and `previous_key_overlap` (`0s` keeps the previous key published while it is configured). It may share no key with the token keys |

`[ferrosmart.upstream.saml]`, for a SAML 2.0 identity provider
([SAML 2.0 providers](../install/upstream.md#saml-20)):

| Key | What it is |
|---|---|
| `entity_id` | The identity provider's entity ID, an absolute URI |
| `metadata_url` | The `https` URL its metadata is read from; exclusive with `metadata_file` |
| `metadata_file` | The file its metadata is read from |
| `metadata_signing_certificate_files` | The PEM certificates whose keys must sign the metadata; empty trusts it as read |
| `metadata_refresh` | How often the metadata is read again; `24h` by default. A failed read keeps the last good copy until its `validUntil` |
| `request_binding` | `redirect` (the default) or `post`: how the browser carries the signed `AuthnRequest` |
| `response_binding` | `post` (the default) or `artifact`: how the provider answers. An artifact is resolved over mutual TLS with the identity of `[ferrosmart.saml.tls]` |
| `force_authn` | Whether every request asks the provider to authenticate the person afresh; `prompt=login` and `max_age` ask it per request |
| `name_id_format` | The name identifier format asked for; empty asks for none |
| `authn_contexts` | The authentication context classes at or above the provider's minimum assurance, in its own vocabulary. FerroSMART asks for them as an exact match and refuses a login of any other class; empty accepts any |
| `clock_skew` | The clock skew admitted at each time bound; `3min` by default, at most one hour |
| `subject_attribute` | The attribute whose one value is the person's identifier; empty takes the `NameID`, which must not be transient |
| `claims` | A table of claim name to attribute `Name`: the claims the login yields, a string for one value and an array for more. `name`, `preferred_username` and `email` are read as the ID Token claims of those names are |
| `fhir_user_claim` | The claim of `claims` holding the person's `fhirUser`; empty for none |
| `role_claims` | The claims of `claims` holding the person's roles |

`[ferrosmart.upstream.openid4vp]`, for the EUDI Wallet
([the EUDI Wallet](../install/upstream.md#the-eudi-wallet)). A wallet login
is at level `high`, so the entry's `[ferrosmart.upstream.assurance]` sets
only a `minimum`.

| Key | What it is |
|---|---|
| `access_certificate_file` | The PEM wallet-relying party access certificate first, then its path up to, but not including, the anchor. It must not be self-signed |
| `access_key_file` | The access certificate's PKCS#8 PEM P-256 key, which signs every request object |
| `registration_certificate_file` | The registration certificate as the registrar issued it; every request object carries it |
| `issuer_anchor_files` | The PEM certificates of the PID providers' trust anchors. A PID's issuer and its status list must chain to one of these or to the list below |
| `wallet_endpoint` | Where the wallet is invoked; `eu-eaap://` by default |
| `vct_values` | The credential types accepted; `["urn:eudi:pid:1"]` by default. The first names the person's pairwise `sub` |
| `claims` | The PID claims asked for, dotted for a nested claim, with `identifier_claim` and `issuing_country` among them; the PID's names and the administrative number by default |
| `identifier_claim` | The claim whose value names the person and that a [`fhirUser` lookup](#ferrosmartresource) reads; `personal_administrative_number` by default |
| `digital_credentials_api` | Whether the wallet page offers the W3C Digital Credentials API beside its link; `true` by default. With `false` the browser goes straight to `wallet_endpoint` |

`[ferrosmart.upstream.openid4vp.pid_providers_list]` is the list of PID
providers the Commission publishes, signed, under Implementing Regulation
(EU) 2024/2980 Art 5. FerroSMART reads it as ETSI TS 119 602 Annex D, the
JSON form under a JAdES signature. A list that does not verify, or whose
next update has passed, refuses every wallet login, and the last list that
verified stays in use until its own next update.

| Key | What it is |
|---|---|
| `url` | The https URL the list is read from; exclusive with `file` |
| `file` | A file holding a copy of the list |
| `signing_certificate_files` | The PEM certificates the Commission publishes to verify the list's signature |
| `refresh` | How often the list is read again; `1h` by default. It is read again at its next update too |

## `[ferrosmart.saml]`

FerroSMART as one SAML 2.0 service provider, which every `protocol =
"saml"` entry needs. FerroSMART serves its metadata at
`{issuer}/saml/metadata` and takes the provider's answer at
`{issuer}/saml/acs`.

| Key | What it is |
|---|---|
| `entity_id` | FerroSMART's entity ID; `{issuer}/saml/metadata` by default |
| `signing_key_file` | The PKCS#8 PEM key that signs every `AuthnRequest` and `ArtifactResolve`: RSA of 2048 bits or more, or ECDSA on P-256 or P-384 |
| `signing_certificate_file` | The PEM certificate of that key, which the metadata publishes |
| `[[ferrosmart.saml.decryption]]` | `key_file` and `certificate_file` of an RSA key a provider encrypts assertions, identifiers and attributes for |
| `[ferrosmart.saml.tls]` | `client_identity_file`, the certificate and key artifact resolution presents, and `trust_roots_file`, roots beside the platform's for every call to a provider |

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
