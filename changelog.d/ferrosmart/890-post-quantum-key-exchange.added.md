- The TLS 1.3 key exchange of the listener and of every client FerroSMART
  builds, the PostgreSQL connection among them, offers the post-quantum
  hybrid X25519MLKEM768 (RFC 10024) first, through `ferrohealth-server`
  0.12.4, and still reaches a classical-only peer over X25519.
  `docs/post-quantum.md` lists every cryptographic use and whether it is
  post-quantum safe, with `conformance/post-quantum.tsv` as its
  machine-readable copy and a README badge counted from it.
