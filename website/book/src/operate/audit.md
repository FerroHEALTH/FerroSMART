<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Audit records

FerroSMART records every login and every token request as a FHIR R4
`AuditEvent`, in its own PostgreSQL store. An issued token and its record
commit in one transaction; a refusal or a login commits its record alone.
When a record cannot be committed, the request fails: the token endpoint
answers `503` and issues no token.

## What is recorded

| Event | Form |
|---|---|
| A token request, granted or refused | The ITI-71 audit event of IHE Basic Audit Log Patterns 1.1.4, profile `IHE.IUA.71`: type `110114`, subtype `ITI-71`, the client and the authorization server as agents, the person as `agent:user` when one logged in, and the HTTP request as the `token-request` entity, with the values of `code_verifier`, `code`, `refresh_token`, `client_secret` and `client_assertion` left out |
| A login at the identity provider | DICOM User Authentication, type `110122` Login |
| A session ended by back-channel or front-channel logout | DICOM User Authentication, `110123` Logout |
| A logout at the end-session endpoint | DICOM User Authentication, `110123` Logout, subtype `logged-out` |

Every other write FerroSMART makes for a person or a client commits with a
record of its own, in a form of FerroSMART's design, since no IHE or BALP
pattern covers it. The subtype comes from FerroSMART's code system
`urn:ferrosmart:audit-event`:

| Write | `type` | Subtypes | `action` |
|---|---|---|---|
| A code issued, with its basis as the `basis` detail: `page` (the person approved on the consent page), `remembered` (a remembered consent), `administrative` (a professional, on the administrator's registration) or `first-party` (a first-party app) | `110114` | `authorization-code` | `C` |
| A consent remembered | `110113` | `110137`, `consent-remembered` | `C` |
| An app disconnected at the management page, with whether a remembered consent was forgotten and how many grants were revoked | `110113` | `110137`, `consent-withdrawn` | `D` |
| A person's recent patients forgotten at the management page, with how many | `110113` | `recent-patients-forgotten` | `D` |
| A code issued to a professional on the administrator's registration, with no consent page | `110113` | `110137`, `consent-administrative` | `C` |
| A code issued for a first-party app, with no consent page | `110113` | `110137`, `consent-first-party` | `C` |
| An access token revoked | `110113` | `token-revoked` | `D` |
| A grant revoked by its refresh token | `110113` | `grant-revoked` | `D` |
| A refresh token rotated | `110114` | `refresh-rotated` | `E` |
| A rotated refresh token repeated by its client within 10 seconds, answered with the same successor | `110114` | `refresh-repeated` | `E` |
| A rotated refresh token reused, its grant revoked | `110113` | `refresh-reused` | `E` |
| A code redeemed again, its tokens revoked | `110113` | `code-reused` | `E` |
| An upstream session ended | `110114` | `110123`, `session-ended` | `E` |
| The patient picker's own token issued | `110114` | `picker-token` | `C` |
| A launch an EHR registered at `POST /launch` | `110114` | `launch-registered` | `C` |
| A launch an app redeemed at the authorization endpoint | `110114` | `launch-redeemed` | `E` |
| A launch registration or redemption refused, with outcome `4` | `110113` | `launch-refused` | `E` |
| A client registered through the [admin API](../configure/admin-api.md) | `110113` | `110137`, `client-created` | `C` |
| A client changed through the admin API | `110113` | `110137`, `client-updated` | `U` |
| A client disabled, with the grants, access tokens and consents it ended | `110113` | `110137`, `client-disabled` | `D` |
| A disabled client enabled | `110113` | `110137`, `client-enabled` | `U` |
| A client deleted at `DELETE /register/{client_id}` | `110113` | `110137`, `client-deleted` | `D` |

None of these is an access to a person's electronic health data. The
patient picker, which does read Patient resources and EHRs, writes the
access record of Regulation (EU) 2025/327 Annex II 3.2 for each search and
read.

`[ferrosmart.audit] source_id` and `site` name FerroSMART as the recording
system in each record ([configuration](../configure/configuration.md#ferrosmartaudit)).

## Reading the records

`GET {issuer}/audit` answers a FHIR `searchset` Bundle of `AuditEvent`
resources, newest first. The caller presents a bearer token FerroSMART
issued for its own issuer with the scope `system/AuditEvent.rs`: a
Backend Services client whose ceiling lists that scope, asking with
`resource` set to the issuer.

| Parameter | What it selects |
|---|---|
| `subject` | The records of one person, by their FerroSMART `sub` |
| `client` | The records of one client, by its `client_id`; for an administrator's change, the admin client |
| `event` | The records of one event, such as `token`, `login` or `grant-revoked` |
| `outcome` | The records of one `AuditEvent.outcome` code: `0`, `4`, `8` or `12` |
| `since`, `until` | An RFC 3339 instant each, bounding the time |
| `_count` | How many records a page holds, from 1 to 1000; 100 by default |
| `cursor` | Where a page starts, as the `next` link names it |

Each parameter may appear once, and any other is refused. The Bundle's
`self` link names the page read, and while more records match, its `next`
link reads the next page with the same parameters (FHIR R4 Bundle.link). Regulation (EU)
2025/327 Art 9 gives a person access to who accessed their data; the
endpoint lets an operator answer that without a database client.

## Forwarding to an Audit Record Repository

With `[ferrosmart.audit.feed]`, the store is also an outbox: the
`ihe-atna` forwarder delivers each record to the repository's FHIR base
over the ITI-20 ATX: FHIR Feed, as a create of `[base]/AuditEvent`, `https`
only, with the retry and credentials the table names. A record the
repository refuses stays in the store, stamped for an operator to look at.
