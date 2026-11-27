- The PID mapping holds every data identifier of the PID Rulebook 1.7,
  the version `docs/VERSIONS.md` pins (#932): `email_address` reaches the
  ID Token's `email` from either format, `birth_date` reaches `birthdate`
  only as a full date `YYYY-MM-DD`, `issuing_country` names the
  identifier's system, and every other identifier, the mandatory
  `issuing_authority` among them, is not asked for, with its reason in
  `conformance/pid-attributes.tsv`. The README badge counts the data
  identifiers handled over all 27 of the Rulebook.
