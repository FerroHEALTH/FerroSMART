<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Security and the CRA

**For:** compliance readers and operators: reporting a vulnerability, supported versions, and how the tokens are protected.

This page says how to report a vulnerability, which releases receive
fixes, what each release proves, and how FerroSMART protects the tokens it
issues.

## Reporting a vulnerability

Do not open a public issue. Report it privately, through either route:

- [GitHub private vulnerability reporting](https://github.com/FerroHEALTH/FerroSMART/security/advisories/new),
  which needs a GitHub account; or
- email to [security@cadasto.com](mailto:security@cadasto.com), the
  security address of Cadasto B.V., the manufacturer, with "FerroSMART
  vulnerability" in the subject.

The repository's
[security policy](https://github.com/FerroHEALTH/FerroSMART/blob/main/SECURITY.md)
gives the response times, and the
[family security page](https://ferrohealth.eu/docs/security.html) the
procedure every FerroHEALTH product shares.

## Supported versions and updates

Only the newest release is supported, and a fix ships in a new release.
Under the Cyber Resilience Act (Regulation (EU) 2024/2847), Cadasto B.V.
keeps publishing security fixes for at least five years after each release
(Art 13(8)), and each release's notes state the month its five years end.
Where it is technically feasible, a security fix ships as a patch release
with the fix alone (Annex I Part II(2)). A published release and its image
are never deleted.

The manufacturer is Cadasto B.V., Comeniusstraat 2d, 1817 MS Alkmaar, The
Netherlands. The family book holds the
[manufacturer](https://ferrohealth.eu/docs/manufacturer.html),
[post-market](https://ferrohealth.eu/docs/post-market.html) and
[CRA](https://ferrohealth.eu/docs/cra.html) pages.

## What each release proves

- **Provenance and SBOMs.** Every tarball and the image carry SLSA build
  provenance and SBOMs, attested through Sigstore by the workflow that
  built them ([verify before you run](../install/image.md#verify-before-you-run)).
- **A vulnerability record.** Trivy scans the image and the tarballs at
  every severity, and the release is refused while a finding has no OpenVEX
  judgement under `security/vex/` (Annex I Part I(2)(a)). The record is
  attached to the release.
- **A scan gate.** The image is tagged only after a scan finds no fixable
  HIGH or CRITICAL finding, and the published image is scanned again every
  week.

## How FerroSMART protects the tokens

| Threat | What FerroSMART does |
|---|---|
| A stolen or injected code | PKCE `S256` on every client, a 60-second single-use code bound to the client and redirect URI, and a second use revokes what the first issued |
| Open redirection | Exact redirect URI match, no redirect on an unknown client or URI, `Referrer-Policy: no-referrer` |
| Mix-up between authorization servers | `iss` in every authorization response (RFC 9207) |
| Cross-site request forgery and clickjacking | A per-request form token on the consent and picker pages, and a Content-Security-Policy with `frame-ancestors 'none'` |
| A replayed client assertion or launch JWT | Each `jti` is accepted once until it expires |
| A stolen access token | Five minutes of life and one `aud` |
| A stolen refresh token | Rotation on every use, a reused token revoking its grant, binding to the client, idle expiry |
| A database leak | Codes, refresh tokens and launch values stored as their SHA-256 |
| Scope escalation | The client's ceiling, the roles and the consent narrow every grant; a refresh never widens it |
| An identity provider that misbehaves | Each provider has its own issuer, and a person's `sub` is derived under it; an ID Token is checked by OpenID Connect Core 1.0 §3.1.3.7, a SAML response by its signature, audience and `InResponseTo`, a wallet presentation by its issuer chain, status and key binding; only the mapped claims are read |
| Credentials in logs | No token, code, secret or assertion in a log line or an error |

The architecture's threat model, with the specification behind each row, is
[`docs/architecture.md`](https://github.com/FerroHEALTH/FerroSMART/blob/main/docs/architecture.md)
§13.12.
