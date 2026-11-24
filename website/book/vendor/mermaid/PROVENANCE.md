<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Provenance: the mermaid browser bundle

`scripts/vendor/mermaid.sh` fetches these files verbatim and checks each
sha256; they are never hand-edited (`.claude/rules/vendored-inputs.md`). They
keep their upstream terms and are not covered by the project's licence.

The book loads `mermaid.min.js` through `additional-js` in `book.toml`, and
`theme/mermaid-init.js` draws every ```` ```mermaid ```` fence with it. The
book serves the file itself, so its Content-Security-Policy keeps
`script-src 'self'`.

| File | Upstream | Pin | sha256 | Terms |
|---|---|---|---|---|
| `mermaid.min.js` | <https://github.com/badboy/mdbook-mermaid> `src/bin/assets/mermaid.min.js`, the mermaid 11.6.0 browser bundle | commit `99e2393a739f3c36fde30c59317d4daa355eefaf` (tag `v0.17.1`) | `eefea253bed9655e838eb874ff955c46872f982a8e26290c1dd2982ddc0a4703` | MIT, in `LICENSE` |
| `LICENSE` | <https://github.com/mermaid-js/mermaid> `LICENSE` | commit `7b2083926dbe3b6280f42376a0d4195b2c72fb8e` (tag `mermaid@11.6.0`) | `ec9fb67dcb25eccc416ed56e1aab819222c805a2a4bfe4cb19e7556bf2ffde80` | MIT |

Fetched on 2026-11-24. FerroBRIDGE, FerroEHR, FerroFED, FerroPIX and FerroTERM serve
the same bytes.

## Refreshing

Change the pins at the top of `scripts/vendor/mermaid.sh`, run it, and commit
the result with this file and the mermaid row of `docs/VERSIONS.md` updated.
The script prints the new checksum when an upstream byte changes.
