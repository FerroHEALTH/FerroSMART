<!-- This file describes vendored material; the bytes beside it are copied
     verbatim and keep the licence their headers and LICENSE name. -->

# Provenance: the FerroBRIDGE party mappings

Vendored verbatim by `scripts/vendor/ferrobridge-party.sh`. Never
edit a file here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/FerroHEALTH/FerroBRIDGE>
- Pin: tag `v0.0.28`, which resolves to commit `c22bc44b571ff6076c744d133086e5f4ae0fcb4f` (2026-11-22T19:20:35Z), the
  release whose image the Inferno lane runs
- Fetched: 2026-11-24, each file from raw.githubusercontent.com at the commit
  and checked against the git blob id the commit records
- Licence: the Business Source License 1.1 (`LICENSE`), the Licensor of
  this repository; the files are unmodified
- Layout: the upstream paths, unchanged
- Files: 6
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `cb54fb2fbfbc8dfead690fb1debfc4faf7eba7c4d35ff99c061b63f730bdafc6`
- Read by: the Inferno lane (#520), which loads the template into FerroEHR
  and the two mappings into FerroBRIDGE so the facade serves the person's
  `fhirUser` as a `Practitioner` and the patient the picker finds as a
  `Patient`

## What is taken

- `tools/ferrobridge-testkit/fixtures/opt/person.opt`: the ADL 1.4 PERSON
  template `ferrobridge.person.v1`.
- `app/ferrobridge-server/tests/it/fixtures_demographic/ferrobridge_demographic_practitioner.context.yml` and
  `ferrobridge_demographic_practitioner.yml`: the FHIRconnect party
  context and model mapping of the base `Practitioner` onto it.
- `app/ferrobridge-server/tests/it/fixtures_demographic/ferrobridge_demographic_patient.context.yml` and
  `ferrobridge_demographic_patient.yml`: the same of the base `Patient`.

| File | sha256 | git blob id |
|---|---|---|
| `LICENSE` | `5327e1b1ac2378e89ceb7806be6efc7902a006c2ba7a28f7877da782f58d4ee3` | `e253ea3679f587b196727e6ab260ffb279fbea74` |
| `app/ferrobridge-server/tests/it/fixtures_demographic/ferrobridge_demographic_patient.context.yml` | `c2af6ef50b5ca981b4850fc0633ab88494b1791ebda47dc11acc4704734c6796` | `b415eaf806421a83b5784b241ae67be6820153bd` |
| `app/ferrobridge-server/tests/it/fixtures_demographic/ferrobridge_demographic_patient.yml` | `6c6544626cc6f099e05f63de0fb2f73c99cfeb538832c65d5b6871f5f0f705d0` | `d1ef01a64ae41bc13c55641587e1ba56f9a214b3` |
| `app/ferrobridge-server/tests/it/fixtures_demographic/ferrobridge_demographic_practitioner.context.yml` | `371b4d658cb6e70c0c83c16e1edc1d328ca167d0b506fdf7383094e8fad71dc3` | `e2cd61f249b12187fb3552d13bd7e32cf6e145c5` |
| `app/ferrobridge-server/tests/it/fixtures_demographic/ferrobridge_demographic_practitioner.yml` | `267f493efd351981c9a6748701f75b7940a4f84b38d275bac94c50bb544776df` | `80257101b4864163dece6e1e97a9f58502edacd6` |
| `tools/ferrobridge-testkit/fixtures/opt/person.opt` | `5ac0a4142a71c1fcfb504d6c351a10e87c4ab6babcf39b32bb65f7f49ac36214` | `10187b239057ab2c5a03fd9d32e0f09ba8e424da` |
