- `RelyingParty::userinfo`, the relying party's UserInfo request (OpenID
  Connect Core 1.0 §5.3): the access token as a bearer token with `GET`, a
  JSON answer or a signed one checked against the provider's keys, and its
  `sub` held to the ID Token's (§5.3.2), with `Provider::userinfo_endpoint`
  and the `OidcError` variants `UserInfo`, `UserInfoBody`,
  `UserInfoSignature` and `UserInfoSubject`.
