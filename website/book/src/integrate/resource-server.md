<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# A server behind FerroSMART

A FHIR or openEHR server sits behind FerroSMART as a resource server: it
reads the tokens FerroSMART issues and never sees the person log in. The
identity provider runs upstream for login only.

```text
 browser            SMART app           FerroSMART           identity provider
    |  1. launch        |                    |                       |
    |------------------>| 2. /authorize      |                       |
    |                   |    aud = the base  |                       |
    |<---------------------------------------|  3. login             |
    |--------------------------------------------------------------->|
    |<---------------------------------------------------------------|
    |  4. picker and consent                 |                       |
    |--------------------------------------->|                       |
    |                   |<- 5. code, token ->|                       |
    |                   |  6. API call with the access token         |
    |                   |------------------------------> the server
```

## On FerroSMART's side

Name the server's base as a resource, so a launch can use it as `aud`:

```toml
[[ferrosmart.resource]]
base = "https://ehr.example.org/openehr/v1"   # or the FHIR base
kind = "openehr"                               # or "fhir"
subject_namespace = "examples"                 # openEHR only: the picker's EHR lookup
```

When the platform also serves FHIR, pair the two bases. The picker then
finds the patient at the FHIR server and their EHR at the openEHR server,
and the app gets both `patient` and `ehrId`:

```toml
[[ferrosmart.resource]]
base = "https://ehr.example.org/fhir"

[[ferrosmart.resource]]
base = "https://ehr.example.org/openehr/v1"
kind = "openehr"
subject_namespace = "examples"
fhir_base = "https://ehr.example.org/fhir"     # the platform's FHIR base, configured above
subject_system = "urn:example:mrn"             # the Patient.identifier that names the EHR's subject
```

## On the server's side

The server checks each token as an RFC 9068 JWT:

- the signature with a key from FerroSMART's `jwks_uri`, refetched on an
  unknown `kid`, so a [rotated key](../operate/keys.md) is found;
- `typ` `at+jwt`, `iss` FerroSMART's issuer, `aud` its own base, `exp`;
- the `scope` claim against what the request needs, and the context
  claims `patient`, `encounter`, `fhirUser` and `ehrId` for whose data it
  is;
- the `roles` claim (RFC 9068 §2.2.3.1), when the server takes roles from
  its issuer: the person's roles at the identity provider that a
  `[[ferrosmart.role]]` names, carried by every token of a user flow and
  never by a Backend Services token. The server decides itself whether it
  trusts FerroSMART for roles (FerroEHR's `role_issuers`), and a privileged
  role such as an emergency access role needs its own `[[ferrosmart.role]]`
  table to reach it.
  The patient picker's own short-lived token carries the same `roles`,
  and at an openEHR server that lists purposes of use its lookups declare
  the professional's chosen purpose in the server's purpose header
  ([configuration](../configure/configuration.md#ferrosmartresource)).

A server that cannot read JWTs introspects instead
([the flows](flows.md#refresh-introspection-and-revocation)), as a
registered client whose ceiling lists `system/introspect`.

The server serves its own `.well-known/smart-configuration`, as SMART asks
of every FHIR endpoint that requires authorization, and names FerroSMART's
`authorization_endpoint` and `token_endpoint` in it, so an app that starts
at the server finds FerroSMART.

## A FerroHEALTH product

Every FerroHEALTH product does this through `ferrohealth-smart`, the crate
the FerroSMART repository publishes. It trusts FerroSMART in one named
issuer table under the `ferrosmart` preset. The preset makes the issuer a
`persons` issuer and keeps every RFC 9068 default except these: `typ` is
`at+jwt` alone, `scope` is required, a patient's own token is read as the
patient, the `patient` claim is the launch context (`patient_context`), and
a token from FerroSMART's own patient picker, whose client is the issuer
itself, is the signed-in person with no app. The audience is the product's
own base URL unless the table names another. `delegates` lists the SMART
apps the product admits for a person, a patient's apps among them:

```toml
[auth.issuer.smart]
issuer = "https://smart.example.org"
preset = "ferrosmart"

[auth.issuer.smart.profile]
delegates = [{ client = "growth-chart" }]
```

An app can instead be registered once, at FerroSMART. Give each client
document the bases its tokens may name in `resources`
([clients](../configure/clients.md#the-client-registry)); FerroSMART then
refuses a token for any other base with `invalid_target`. A product's table
can admit every app whose token names the product in `aud`, in place of
listing each one:

```toml
[auth.issuer.smart.profile]
audience_delegates = true
```

Each table makes its own choice: `delegates` keeps the product's own list,
`audience_delegates` reads every app of a FerroSMART token for the product
as a delegate, the listed ones included. The key is refused on an issuer
under any other preset, because only FerroSMART is known to issue an app's
tokens just for the bases it lists. A product whose own data decides which
apps it admits, such as FerroEHR with its CDR grant, takes neither key, and
its own access policy still decides every request.

The same table reads a Backend Services token as a system caller, because
its `sub` is its `client_id`. A token through a listed app is the patient's
own access when its `fhirUser` is `Patient/<x>`, its `patient` is `x`, and
its scopes are `patient/` with no `user/` or `system/` scope; any other
person's token, a professional's with `patient/` scopes included, is read as
the professional's. The product's own SMART document describes
FerroSMART, and its own rules still apply on top of the token's scopes.
Every other key names the issuer by its table's name (`smart` here), and
the environment form does too: `FERROEHR__AUTH__ISSUER__SMART__PROFILE__DELEGATES`.
An unknown name is refused at start, with the known names listed.
Each product's book has the details of its `[auth]` section.

### Issuer profiles

An issuer table names a `preset`: `rfc9068` (the standards alone, the
default), `keycloak`, `entra`, `okta` or `ferrosmart`. A deployment whose
issuer needs more than a preset carries, such as a national binding or an
IdP of its own, writes the profile in a file of the same form and names it
with `profile_file`. Keys in the issuer's `[auth.issuer.<name>.profile]`
table win over both:

```toml
[auth.issuer.provider_a]
issuer = "https://care-provider-a.example.org"
profile_file = "/etc/ferro/profiles/nl-annex-b.toml"
audience = ["https://fhir.example.org/fhir"]
sender_constraint = "required"

[auth.issuer.provider_a.profile]
token_types = ["at+jwt"]

[auth.issuer.provider_a.federation.fields]
"provider.healthcare_provider_identifier" = [{ constant = "87654321", system = "urn:oid:2.16.528.1.1007.3.3" }]
```

The products ship no country content. This example file maps the Dutch
harmonised authentication of the openEHR Federation Tier specification
1.0.1 Annex B §B.4a, each value with its source:

```toml
{{#include profiles/nl-annex-b.toml}}
```

#### The treatment relationship fields

A federation table maps these fields of a treatment relationship
confirmation, each from a claim, a credential subject path, an attested
`authorization_details` member or a constant, as it maps the professional
and provider fields:

| Field | Value |
|---|---|
| `trc.id` | The confirmation's identifier, one string |
| `trc.not_before` | The start of its window, in seconds since the epoch |
| `trc.not_on_or_after` | The end of its window, in seconds since the epoch |
| `trc.care_role` | The care role it attests for the professional: one coded value with its code system, as a FHIR Coding `[{ "system": "…", "code": "…" }]` or a configured `{ constant = "…", system = "…" }`; a string, a code without a system or two codes refuse the token (`attribute-refused`) |

The products name no care role value set: the deployment's access policy
names the one it reads. A contact point's token that carries any of these
fields carries `trc.id` and both window bounds.

### Why a token was refused

A product refuses a token with `401` and `error="invalid_token"`, or a
request its token does not permit with `403` and
`error="insufficient_scope"`. The `WWW-Authenticate` header carries a
stable reason code as `error_description` (RFC 6750 §3), and the product
logs the same code at info with the token's issuer, client id and key id:

```text
WWW-Authenticate: Bearer realm="ehr", error="invalid_token", error_description="audience-mismatch"
INFO a request was refused reason="audience-mismatch" status=401 issuer="https://smart.example.org" client_id="growth-chart" kid="k-2026-11"
```

A missing credential carries no code (RFC 6750 §3.1 asks for none), and a
Basic challenge carries none either. The codes:

| Code | The check that refused |
|---|---|
| `credential-missing` | no credential of a scheme the server admits (log only) |
| `two-credentials` | two `Authorization` header fields |
| `malformed-header` | an `Authorization` value that is no scheme and credential |
| `not-b64token` | a bearer value outside the RFC 6750 §2.1 syntax |
| `malformed-token` | not a JWS in compact serialization |
| `algorithm-refused` | an algorithm outside the configured set |
| `type-mismatch` | a `typ` that names another kind of token (RFC 9068 §4) |
| `key-unknown` | no key of the issuer's set |
| `signature-invalid` | the signature does not verify |
| `expired`, `not-yet-valid`, `issued-in-future` | `exp`, `nbf`, `iat` |
| `issuer-mismatch` | `iss` is not the issuer the key set belongs to |
| `issuer-unknown` | `iss` names no issuer the server trusts |
| `audience-mismatch` | `aud` names none of the server's audiences |
| `claim-missing` | a claim the issuer's profile requires is absent |
| `subject-not-string`, `subject-blank` | `sub` is not a string, or blank |
| `token-inactive` | introspection answered `active: false` (RFC 7662 §2.2) |
| `key-set-unavailable`, `upstream-unavailable` | the key set or another upstream could not be read (`503`, log only) |
| `basic-malformed`, `basic-rejected`, `basic-incomplete` | the Basic credential (log only) |
| `scope-not-granted` | the token holds and grants nothing for the request (`403`) |
| `route-unclassified` | the route is one the server does not classify (`403`) |
| `party-source-unavailable` | the party source could not answer (`503`, log only) |
| `claim-unexpected`, `user-claim-missing` | a claim the profile expects holds another value, or a user claim is absent |
| `impersonation`, `app-only-markers-disagree`, `scope-form` | the profile's impersonation marker, app-only markers or scope form |
| `not-patient-context`, `patient-actor-refused` | a patients token that does not name only its subject, or names an actor |
| `not-app-only`, `client-missing` | a machines token that is not app-only, a persons token with no client |
| `delegate-not-granted`, `actor-not-granted` | the client, or the `act` actor, is neither first party nor a delegate |
| `actor-chain-refused`, `representation-with-act`, `representation-through-delegate` | the `act` chain, or a representation claim beside it |
| `professional-incomplete`, `required-fields-missing`, `attribute-out-of-bounds`, `attribute-refused`, `sources-disagree` | a federation token's attributes |
| `authorization-details-refused`, `organisation-statement-missing`, `assurance-too-low`, `presentations-unreadable`, `contact-point-refused` | a federation token's grants and assertions |
| `kind-unclassified` | no step classifies a token of the issuer's kind |
| `refused-unbound`, `refused-wrong-marker`, `refused-ambiguous`, `refused-inactive`, `refused-abandoned`, `refused-deprovisioned`, `refused-key-claim-missing`, `refused-groups-unavailable` | the product refuses the login's party binding (`403`) |
| `dpop-…`, `certificate-…`, `confirmation-unknown`, `sender-constraint-required` | a `DPoP` proof or a sender-constrained token (RFC 9449, RFC 8705) |

A code names a check, never a claim value, and keeps its meaning once
published.

A product starts whether or not FerroSMART is up: it reads FerroSMART's
metadata in the background, retrying with a back-off of one second doubling
to one minute, and reports not ready on its readiness route until the read
succeeds. Until then it refuses FerroSMART's tokens with `503` and the code
`issuer-unread`, so the two can start in any order.

For a server of your own in Rust, add the crate with its axum layer:

```sh
cargo add ferrohealth-smart -F axum
```

Its documentation is on [docs.rs](https://docs.rs/ferrohealth-smart).
