- Breaking: whether a person sees the consent page follows from the type of
  their `fhirUser` and how the client was registered. A `Practitioner` or
  `PractitionerRole` sees no page for an app an administrator registered,
  the registration being the organisation's consent (OpenID Connect Core
  1.0 §3.1.2.4); a `Patient`, `RelatedPerson` or `Person` sees none only
  for an app marked `first_party`; a person of no stated type, and every
  app that registered itself, see the page. `organisation_approval` is gone
  with its columns, `DELETE /admin/clients/{client_id}/organisation_approval`
  and the `organisation-approval-withdrawn` record; `first_party` is a
  member of the client document only an administrator sets, and clearing it
  revokes the grants issued on it. Each code and grant records its basis,
  `page`, `remembered`, `administrative` or `first-party`, and the records
  of a skipped page are `consent-administrative` and `consent-first-party`.
