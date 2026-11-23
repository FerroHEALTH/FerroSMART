- Breaking: the authorization server's registry is the one list of
  clients. A token from a trusted issuer whose `aud` names the resource
  server admits its client, and an RFC 8693 `act` is read as asserted
  (`CallerKind::Delegated` carries its actor). The profile keys
  `first_party_clients`, `delegates`, `audience_delegates` and
  `issuer_client_is_person`, the issuer key `scopeless_subjects`, the
  `kind::standing` module with `Standing` and `StandingSource`,
  `config::ProductStandingSection`, `Caller::scopeless`, the `scopeless`
  argument of `Caller::new`, and the `UnlistedClient`, `UnlistedActor` and
  `RepresentationThroughDelegate` refusals are removed; a configuration
  that sets one of the keys is refused as an unknown key.
