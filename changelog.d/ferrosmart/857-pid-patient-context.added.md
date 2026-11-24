- A wallet login's patient comes from a patient index such as FerroPIX:
  `[ferrosmart.upstream.openid4vp] identifier_systems` names each issuing
  country's identifier system, and a FHIR base's
  `[ferrosmart.resource.patient_index]` names the index, asked by PIXm
  ITI-83 or PDQm ITI-78 as FerroSMART with `system/Patient.rs`, and the
  system of the base's own patients. One patient becomes the `fhirUser`
  and the launch's `patient`. No patient, several, or a failed index
  refuses the launch. The ID Token carries the PID's `given_name`,
  `family_name`, `birthdate`, `place_of_birth` and `nationalities` under
  `profile`, and an upstream ID Token's `given_name`, `family_name` and
  `birthdate` the same way.
