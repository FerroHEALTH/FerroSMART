- The patient picker offers, before a search, the patients the person
  chose at that server within `[ferrosmart.picker] recent_retention` (30
  days by default, `0s` keeps none), each read again as the person first,
  and at a FHIR server whose `[[ferrosmart.resource]]` names `assigned`
  (`care_team` or `encounter`) the patients of the professional's active
  care teams or encounters in progress, searched by `participant` as the
  person. The person forgets their recent patients on the management
  page, recorded as `recent-patients-forgotten`.
