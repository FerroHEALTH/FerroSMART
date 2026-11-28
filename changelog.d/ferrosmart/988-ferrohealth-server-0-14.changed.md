- FerroSMART builds on `ferrohealth-server` 0.14, `ferrohealth-config` 0.5
  and `ferrohealth-telemetry` 0.6. Every outbound TLS table verifies by root:
  a chain to a root of `trust_roots_file` connects only once a revocation
  check cleared its endpoint, which FerroSMART keeps cleared from its start,
  and fails closed when no CRL or OCSP source answers; the new
  `trust_roots_without_revocation_file` names a private PKI's roots, trusted
  with no check and logged.
