- Breaking: every token issued on a person's login carries its eIDAS level
  of assurance as `acr` (`http://eidas.europa.eu/LoA/low`, `/substantial`
  or `/high`) beside `auth_time`, in the ID Token, the access token, every
  refresh and the introspection answer (RFC 9068 §2.2.1, RFC 9470 §6). Each
  `[[ferrosmart.upstream]]` entry maps its provider's values, an OpenID
  Connect `acr` or a SAML `AuthnContextClassRef`, to levels in
  `[ferrosmart.upstream.assurance] levels`, with an optional `minimum`.
  `[ferrosmart] assurance_minimum` is the deployment's floor, `substantial`
  by default after Implementing Regulation (EU) 2026/2099 Articles 4(2) and
  6(3), configurable to `high`, or `none` outside the eIDAS area; a
  provider whose values reach no floor is refused at load, so every
  deployment with an upstream maps its provider's values or sets
  `assurance_minimum`. A login below the floor or the provider's minimum is
  refused with `access_denied` and recorded. A client's
  `assurance_minimum` and an app's `acr_values` naming an eIDAS URI are
  asked of the provider and refuse a lower login with
  `unmet_authentication_requirements` (RFC 9470 §5). Both discovery
  documents name `acr_values_supported`.
