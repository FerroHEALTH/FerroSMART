- The EUDI Wallet verifier reads the list of PID providers the Commission
  publishes under Implementing Regulation (EU) 2024/2980 Art 5, as ETSI TS
  119 602 V1.1.1 Annex D describes it: the JSON form under a compact JAdES
  signature. `[ferrosmart.upstream.openid4vp.pid_providers_list]` names the
  list's https `url` (or a `file`), the `signing_certificate_files` that
  verify it, and how often it is read again (`refresh`, `1h` by default).
  The providers it lists are trusted beside `issuer_anchor_files`. A list
  whose signature fails, or whose next update has passed, refuses every
  wallet login as `trusted_list_unavailable`. A read that fails keeps the
  last list that verified until that list's next update. `GET
  /admin/upstreams` shows each replica's last read.
