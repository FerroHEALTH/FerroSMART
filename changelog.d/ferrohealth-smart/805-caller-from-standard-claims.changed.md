- Breaking: the caller is read from the token's standard claims the same
  way for every issuer. An issuer is a SMART App Launch 2.2 authorization
  server unless its table declares `kind = "federation"`, so a product
  trusts FerroSMART with an `[auth.issuer.<name>]` table naming only its
  `issuer`. `CallerKind` is `System`, a user by the type of their
  `fhirUser` (`Patient`, `Practitioner`, `PractitionerRole`,
  `RelatedPerson`, `Person`, or `User` with none), `ExternalPerson` or
  `ExternalOrganisation`; `Caller::actor` is the RFC 8693 actor,
  `Caller::fhir_user` the `fhirUser` and `Caller::represented` the patient
  a `RelatedPerson` acts for. A token's `typ` is `at+jwt` or
  `application/at+jwt` and its `scope` required.
