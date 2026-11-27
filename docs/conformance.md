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
`app/ferrosmart/oidf/expected.tsv`. A WARNING passes with a remark.

| Result | Modules |
|---|---|
| PASSED | 3 |
| FAILED | 30 |
| SKIPPED | 3 |

Open issues: [#933](https://github.com/FerroHEALTH/FerroSMART/issues/933).

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
| PASSED | 37 |
| FAILED | 13 |
| SKIPPED | 2 |

Open issues: [#966](https://github.com/FerroHEALTH/FerroSMART/issues/966), [#972](https://github.com/FerroHEALTH/FerroSMART/issues/972).

## SMART App Launch 2.2.0

79 of the 79 Inferno tests in
`app/ferrosmart/inferno/smart_stu2_2_expected.json` pass; an omitted test
is not counted.

## Post-quantum

The inventory and its table are [the post-quantum page](post-quantum.md).
