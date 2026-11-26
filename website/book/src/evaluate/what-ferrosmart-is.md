<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# What FerroSMART is

**For:** anyone deciding whether FerroSMART fits: decision makers, compliance readers and architects.

FerroSMART is the authorization server of the
[SMART App Launch 2.2](https://hl7.org/fhir/smart-app-launch/STU2.2/)
specification, with OAuth 2.0 and OpenID Connect underneath. It issues the
tokens that let a health app reach a FHIR or openEHR server, and nothing
else.

## Why it exists

SMART needs more from an authorization server than login. An app asks for
`launch` and `launch/patient`, chooses its scopes per request, expects the
patient and encounter in the token response, and may authenticate with a
signed assertion instead of a secret. The identity providers hospitals run
do not do this: ZITADEL drops the SMART scopes and `launch` and puts no
`scope` in its access tokens, and Keycloak, as it is commonly configured,
gives each client a fixed scope set and has no launch context.

FerroSMART fills that gap and leaves login where it is. The person logs in
at your identity provider, and FerroSMART issues the SMART tokens.

## What it does

- **The SMART flows.** The standalone launch and the EHR launch through the
  authorization code flow with PKCE `S256`, Backend Services through the
  client credentials grant, refresh tokens, token introspection (RFC 7662)
  and revocation (RFC 7009). The [flows](../integrate/flows.md) page walks
  through each.
- **Consent and the patient picker.** The person approves the scopes an app
  asks for, narrows them or refuses, and can remember the choice. In a
  standalone launch the person picks the patient on a page FerroSMART draws,
  searching the FHIR or openEHR server as themselves.
- **The EHR launch API.** An EHR hands FerroSMART the launch context, or
  signs it, before it opens the app ([the EHR launch API](../integrate/ehr-launch.md)).
- **Signed tokens.** Access tokens are RFC 9068 JWTs whose `aud` is the one
  server they are for, and ID Tokens carry `fhirUser`. A resource server
  checks them offline against FerroSMART's published keys, or asks the
  introspection endpoint.
- **Its own audit trail.** Every login and every token request is a FHIR
  `AuditEvent`, committed together with the token
  ([audit records](../operate/audit.md)).

## What it is not

- **Not an identity provider.** FerroSMART keeps no password and draws no
  login form. A person logs in at a provider you configure: an OpenID
  Connect provider, a SAML 2.0 identity provider or their EUDI Wallet, and
  you may configure several. FerroSMART reads only the claims you map: the
  person, their roles and their `fhirUser`. Keycloak, ZITADEL, Microsoft
  Entra ID and Okta each have a tested setup
  ([identity providers](../install/upstream.md)).
- **Not a clinical data store.** FerroSMART holds clients, grants, codes,
  token records, consents and its audit records in PostgreSQL. It reads
  patient data only in the picker, as the signed-in person, and keeps none
  of it.
- **Not a policy engine for the data.** The token says what the person
  approved and what their roles allow. The FHIR or openEHR server still
  applies its own rules on top of the scopes.
- **Not tied to FerroHEALTH.** Every interface is a published standard with
  no claim or parameter of FerroSMART's own, so any FHIR server that reads
  SMART tokens can sit behind it, and any OpenID Connect provider in front.

## Where it fits in the family

FerroHEALTH is a family of servers that reach each other only over
published protocols: FerroEHR keeps the openEHR record, FerroBRIDGE carries
it to FHIR and OMOP, FerroFED federates it, FerroPIX says who the patient
is, and FerroTERM serves the code systems. Each of them is a SMART resource
server through `ferrohealth-smart`, a crate the FerroSMART repository
publishes, and trusts FerroSMART as an issuer in one configuration table
([a server behind FerroSMART](../integrate/resource-server.md)).

The repository also publishes `ferrohealth-authz`, the policy decision,
and `ferrohealth-session`, the operator consoles' sign-in. They are libraries
for the products and never issue a token; their documentation is on
[docs.rs](https://docs.rs/ferrohealth-smart).
