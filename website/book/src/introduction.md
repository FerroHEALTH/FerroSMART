<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# FerroSMART

FerroSMART is a SMART App Launch 2.2 authorization server. A health app
sends a person to FerroSMART to ask for access to a FHIR or openEHR server.
FerroSMART sends them to the login your organisation already runs, shows
them what the app asks for, and gives the app an access token the server
checks. The person's password never reaches FerroSMART.

The newest release is v{{version:ferrosmart}}. Every page describes what
the code on `main` does, and the [release notes](changelog.md) list each
change.

## Start here

| You are | You want to | Start with | Then |
|---|---|---|---|
| An integrator of a system with no person | Get and check a Backend Services token | [Your first system client](tutorial/first-system-client.md) | [How FerroSMART decides a token](explanation/token-decision.md), [refusal codes](integrate/refusals.md) |
| An integrator of a SMART app | Launch an app and get a token | [The flows](integrate/flows.md) | [Launch from an EHR](integrate/ehr-launch.md), [how FerroSMART decides a token](explanation/token-decision.md) |
| An integrator of a FHIR or openEHR server | Accept FerroSMART's tokens | [A server behind FerroSMART](integrate/resource-server.md) | [Refusal codes](integrate/refusals.md), [how FerroSMART decides a token](explanation/token-decision.md) |
| An operator | Run FerroSMART | [Quickstart](install/quickstart.md) | [Identity providers](install/upstream.md), [clients, roles and consent](configure/clients.md), [deploy for production](operate/deploy.md), [upgrade FerroSMART](operate/upgrades.md), [configuration](configure/configuration.md) |
| A compliance reader | Decide whether FerroSMART meets your obligations | [What FerroSMART is](evaluate/what-ferrosmart-is.md) | [How FerroSMART decides a token](explanation/token-decision.md), [the consent rules](configure/consent.md), [security and the CRA](operate/security.md), [Xt-EHR system authorization](evaluate/xt-ehr-authorization.md) |

## How the book is organised

The book follows the [Diátaxis](https://diataxis.fr/) framework:

- **Tutorials:** the quickstart, one run from nothing to a working server,
  and your first system client, whose requests run in CI.
- **How-to guides:** one task each, for integrators and for operators.
- **Reference:** the configuration, the APIs, the endpoints, the refusal
  codes and the audit records, to look things up.
- **Explanation:** why FerroSMART decides as it does.
- **Compliance:** security, the Cyber Resilience Act, Xt-EHR and the
  licence.

The design of record, with the specification section behind every
decision, is
[`docs/architecture.md`](https://github.com/FerroHEALTH/FerroSMART/blob/main/docs/architecture.md)
§13 in the repository. FerroSMART is one of the
[FerroHEALTH](https://ferrohealth.eu/) products; the pages that hold for
every product (the manufacturer, the security policy, the Cyber Resilience
Act and the EHDS) are in the [family book](https://ferrohealth.eu/docs/).
