- The token endpoint grants RFC 8693 token exchange
  (`urn:ietf:params:oauth:grant-type:token-exchange`) for one case: a
  confidential client whose `grant_types` lists `token_exchange` and whose
  `resources` lists a FHIR base and its paired openEHR base exchanges a
  patient's own access token at that FHIR base for a token at the openEHR
  base. The issued token keeps the patient's `sub`, `fhirUser`, `patient`,
  `acr` and `auth_time`, adds the `ehrId` looked up as the patient, names
  the exchanging client as `client_id` with no `act`, carries at most
  `patient/composition-*.r`, lives at most five minutes and never past the
  subject token, and is revoked with the subject's grant. A professional's,
  a machine's, an expired or a revoked subject token, an actor token, a
  wider scope and another target are refused.
