- A client lives only in FerroSMART's database. `[[ferrosmart.client]]` is
  gone, and a configuration that holds it is refused as an unknown key; the
  start no longer seeds or removes clients. `ferrosmart client apply
  <file>...` writes each file's JSON client document, the admin API's, as
  the API does, creating the client or replacing the one with its
  `client_id`, each change with an `AuditEvent` that names the command as
  the requester. The admin API answers `registered_by` (`admin` or `self`)
  in place of `source`, and the document carries `jwks` and `secret_hash`
  by value. The quickstart, the examples and the test lanes apply their
  clients this way.
