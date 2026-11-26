<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Refusal codes

**For:** integrators and operators of a resource server that uses
`ferrohealth-smart`, reading why a token was refused.

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
| `scope-form`, `client-missing` | `scope` is not one string, or a user's token names no client |
| `fhir-user-refused` | `fhirUser` names no `Patient`, `Practitioner`, `PractitionerRole`, `RelatedPerson` or `Person` |
| `actor-chain-refused` | the `act` chain is deeper than admitted or malformed |
| `professional-incomplete`, `required-fields-missing`, `attribute-out-of-bounds`, `attribute-refused`, `sources-disagree` | a federation token's attributes |
| `authorization-details-refused`, `organisation-statement-missing`, `assurance-too-low`, `presentations-unreadable`, `contact-point-refused` | a federation token's grants and assertions |
| `kind-unclassified` | a federation issuer has no federation table to read its token under |
| `refused-unbound`, `refused-wrong-marker`, `refused-ambiguous`, `refused-inactive`, `refused-abandoned`, `refused-deprovisioned`, `refused-key-claim-missing`, `refused-groups-unavailable` | the product refuses the login's party binding (`403`) |
| `dpop-…`, `certificate-…`, `confirmation-unknown`, `sender-constraint-required` | a `DPoP` proof or a sender-constrained token (RFC 9449, RFC 8705) |

A code names a check, never a claim value, and keeps its meaning once
published.
