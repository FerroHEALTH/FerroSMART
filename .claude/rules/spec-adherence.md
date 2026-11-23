<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Spec adherence (the published specifications are the oracle)

FerroSMART answers to these sources, never to memory and never to how
another implementation behaves. Each is vendored under `docs/specs/` at the
version `docs/VERSIONS.md` pins, and the design of record,
`docs/architecture.md`, cites them section by section:

1. **SMART App Launch 2.2.0** (<https://hl7.org/fhir/smart-app-launch/>):
   the scopes and launch context, the conformance document, the client
   authentication profiles, backend services and token introspection.
2. **The IETF RFCs**: RFC 6749 (the framework), 6750 (bearer
   tokens), 7515 (JWS), 7517 (JWK), 7519 (JWT), 7523 (the JWT client
   assertion), 7617 (Basic), 7662 (introspection), 8414 (server metadata),
   8725 (JWT best practices), 9068 (the JWT access token profile), 9700
   (the security best practice), 8707 (resource indicators), 7638 (the
   JWK thumbprint), 8705 (mutual TLS client authentication, §2 and §5,
   and certificate-bound tokens, §3), 9449 (DPoP-bound tokens) and
   9470 (the step-up challenge), 8259 (JSON, §4 on repeated member names)
   and 6454 (the web origin, §4 and §5), 7636 (PKCE) and 7009 (token
   revocation), the last two for the `oidc` relying party; 7521 (the
   assertion framework), 7522 (its SAML 2.0 profile) and 8693 (token
   exchange) for the onward grants and delegation; 3986 (URI syntax, §6.2.2
   and §6.2.3 for the DPoP `htu` comparison, §4.2 for the console's return
   path).
3. **OpenID Connect Discovery 1.0** (incorporating errata set 2): the
   fallback metadata location and the `issuer` and `jwks_uri` rules. For
   the `oidc` relying party, **OpenID Connect Core 1.0** (incorporating
   errata set 2), the authorization code flow and the ID Token check,
   **OpenID Connect RP-Initiated Logout 1.0**, the end-session request,
   **OpenID Connect Back-Channel Logout 1.0** (incorporating errata set 1),
   the Logout Token check, and **OpenID Connect Front-Channel Logout 1.0**,
   the logout URI an upstream renders in an iframe.
4. **IHE IUA** (ITI-71) and **Nuts RFC021** for the access token of a
   federation issuer, and **IHE BALP** 1.1.4 (3:5.7.6, the consent decision
   record) for the consent decision reference it carries. The Microsoft
   Entra, Keycloak and Okta documents are evidence for the values of a
   vendor's issuer profile, never the source of a core rule.
5. **The eHDSI specifications** (the SAML Profile, Section II Security
   Services, the Service Location and Capability Lookup Profile and the
   NCPeH Components Specifications 10.0.0, the Interoperability
   Specifications 8.0.1, and the MyHealth@EU Requirements Catalogue 10.0.0,
   cited by section and never copied), **Implementing Regulation (EU)
   2026/2099** and **the GDPR** for a MyHealth@EU contact point,
   **Implementing Regulation (EU) 2015/1502** with 2026/2099 Articles 4(2)
   and 6(3) for the eIDAS level of assurance in FerroSMART's tokens, and the
   **Federation Tier with AQL specification** 1.0.1 Annex B for the Dutch
   `authorization_details`.
6. **The docs.rs pages of the pinned crates** (`jsonwebtoken`, `argon2`,
   `reqwest`, `secrecy`, `axum`, `tower`), the Rust book and reference, for
   every question about the tools.

## Hard rules

- **Read the governing section before implementing or reviewing** a check,
  a challenge, a claim, a scope rule or a grant, and cite it (document and
  section) in the `// NOTE:` or the pull request.
- **NEVER LAX. Strictness is a hard rule.** The library accepts exactly what
  the governing specification admits. Everything a specification refuses, we
  refuse, and every refusal is an asserted negative test, so a silently
  loosened check is a failing build rather than quiet drift. A tolerance
  outside the specification (the `jwt` profile, the `scp` claim under it,
  the loopback `http` issuer) is recorded in `docs/architecture.md` §9 with
  the owner's decision, flagged "no specification governs this: our own
  design", and never widened without a new decision.
- **Cite only durable references**: the sources above or official external
  documentation. Never cite an internal markdown file as a design authority.
  Where no specification governs a decision (the key set cache, the audit
  line, the configuration model), flag it: "no specification governs this:
  our own design".
- **The four FerroHEALTH products' auth modules are prior art**, never the
  oracle. Where a product's behaviour and a specification disagree, the
  specification wins, and the difference is settled on the tracker before
  the product's migration, never by editing a test.
- **Never claim a property no test or citation shows.** A refusal exists by
  evidence: a negative test that pins its status and its challenge.
- **A defect in a published specification is recorded as an
  `upstream-report` issue**, with what the specification says, what this
  implementation does and the resolution an upstream would need. The issue
  is the record and stays here.
