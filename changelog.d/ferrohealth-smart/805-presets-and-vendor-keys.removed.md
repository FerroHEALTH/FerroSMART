- Breaking: the `persons`, `patients` and `machines` issuer kinds, the
  `preset` and `profile_file` keys with the `rfc9068`, `entra`, `keycloak`,
  `okta` and `ferrosmart` presets, the `[auth.idp]` table with the
  `idp-entra` feature and the party adapters, the party table's `guests`
  key, and the profile keys `person_key`, `tenant_claim`, `client_claims`,
  `app_only`, `guest`, `impersonation_marker`, `expect`, `user_claims`,
  `person_equality`, `unstable_claims`, `representation`,
  `act_represents_patient`, `fhir_user_patient`, `patient_context`,
  `party_identifier_type`, `scope_claim`, `app_only_scope_claim` and
  `adapter` are removed, and a configuration that sets one is refused as an
  unknown key. `CallerKind::Delegated`, `Representative`,
  `PatientRepresentative` and `Guest`, `Caller::person_key` and
  `Caller::tenant` go with them.
