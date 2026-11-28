- `RemotePdp::from_outbound` holds the outbound client it was built from, so
  under `trust_roots_file` the decision point's endpoint stays cleared for
  revocation while the point lives. It needs `ferrohealth-smart` 0.38.2.
