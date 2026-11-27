<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Conformance

Each README conformance badge shows one count; this page breaks each count
down. `scripts/checks/conformance.sh` writes the badges and this page from
the same files, and CI fails when either disagrees with them. The counts
are self-tested; none is a certification.

## EUDI PID Rulebook 1.7

27 of the 27 data identifiers in `conformance/pid-attributes.tsv` are
handled (mapped, not retained as the law requires, or not asked for a
stated reason) by a named test under `app/`.

## OpenID4VP 1.0

From `app/ferrosmart/oidf/expected.tsv`, the verifier plans of the OpenID
Foundation suite.

| Modules | Count |
|---|---|
| Negative (the login refused), passed | 12 of 12 |
| Positive (a valid presentation), accepted | 9 of 9 |
| Accepted, awaiting the suite's image review (REVIEW) | 9 |

## OpenID Connect Core 1.0: OpenID Provider plans

The basic and config certification plans in
`app/ferrosmart/oidf/expected.tsv`. A WARNING passes with a remark, and a
REVIEW, which holds the screenshot of FerroSMART's page that the lane uploads
and checks, passes too.

| Result | Modules |
|---|---|
| PASSED | 3 |
| FAILED | 28 |
| REVIEW | 2 |
| SKIPPED | 3 |

Open issues: [#933](https://github.com/FerroHEALTH/FerroSMART/issues/933).

Deviations, each a module whose outcome a specification FerroSMART follows asks for:

| Module | Why |
|---|---|
| `oidcc-server` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-userinfo-get` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-userinfo-post-header` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-userinfo-post-body` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-ensure-request-without-nonce-succeeds-for-code-flow` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-scope-profile` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-scope-email` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-alternate-happy-flow` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-display-page` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-display-popup` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-prompt-login` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-prompt-none-not-logged-in` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-prompt-none-logged-in` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-max-age-1` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-max-age-10000` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-ensure-request-with-unknown-parameter-succeeds` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-id-token-hint` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-login-hint` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-ui-locales` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-claims-locales` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-ensure-request-with-acr-values-succeeds` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-codereuse` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-codereuse-30seconds` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-ensure-post-request-succeeds` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-claims-essential` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |
| `oidcc-refresh-token` | the suite sends no S256 code_challenge, which SMART App Launch 2.2.0 (Considerations for PKCE Support) requires of every app, so FerroSMART refuses the authorization request with invalid_request |

## OpenID Connect Core 1.0: relying party plans

The client and client basic certification plans in
`app/ferrosmart/oidf/expected.tsv`.

| Result | Modules |
|---|---|
| PASSED | 35 |
| FAILED | 2 |
| INTERRUPTED | 1 |
| SKIPPED | 2 |
| NOT-RUN | 2 |

Open issues: [#933](https://github.com/FerroHEALTH/FerroSMART/issues/933).

## FAPI 2.0 Security Profile: authorization server plan

The FAPI 2.0 Security Profile Final plan in `app/ferrosmart/oidf/expected.tsv`,
with private_key_jwt, DPoP and OpenID Connect; its authorization requests
carry the S256 PKCE challenge SMART App Launch 2.2.0 requires.

| Result | Modules |
|---|---|
| PASSED | 42 |
| FAILED | 5 |
| REVIEW | 3 |
| SKIPPED | 2 |

Open issues: [#966](https://github.com/FerroHEALTH/FerroSMART/issues/966).

Deviations, each a module whose outcome a specification FerroSMART follows asks for:

| Module | Why |
|---|---|
| `fapi2-security-profile-final-ensure-authorization-request-without-state-success` | SMART App Launch 2.2.0 (Obtain authorization code) requires state, which the module leaves out of the pushed request, so FerroSMART refuses it with invalid_request |
| `fapi2-security-profile-final-state-only-outside-request-object-not-used` | SMART App Launch 2.2.0 (Obtain authorization code) requires state, which the module leaves out of the pushed request, so FerroSMART refuses it with invalid_request |
| `fapi2-security-profile-final-refresh-token` | FerroSMART rotates every client's refresh token, so the module's second refresh with the first token is refused as a reuse (OAuth 2.1 draft 17 §4.3.1); FAPI 2.0 Security Profile §5.3.2.1 has a server not rotate except in extraordinary circumstances, with the old token retryable (Note 1), and the decision is the owner's |
| `fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` | FerroSMART takes each request_uri once (RFC 9126 §4: one-time use SHOULD be enforced, a repeat MAY be allowed), so the second use before the login completes is refused |
| `fapi2-security-profile-final-ensure-pkce-code-verifier-required` | FerroSMART answers a token request with no code_verifier invalid_request, the error OAuth 2.1 draft 17 §3.2.4 gives a request "missing a required parameter"; the suite expects invalid_grant |

## SMART App Launch 2.2.0

79 of the 79 Inferno tests in
`app/ferrosmart/inferno/smart_stu2_2_expected.json` pass; an omitted test
is not counted.

## Post-quantum

The inventory and its table are [the post-quantum page](post-quantum.md).
