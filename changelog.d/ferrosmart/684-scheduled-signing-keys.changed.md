- Breaking: the token signing keys rotate on a schedule the replicas share
  through the database. `[ferrosmart.keys]` takes `private_key_files`, the
  key files in the order they take over, and `rotation_period` (`90d` by
  default) in place of `private_key_file`, `kid`,
  `next_private_key_file`, `previous_private_key_file` and
  `previous_key_overlap`. The next key is published for at least the JWK
  Set's cache lifetime before it signs, the previous key stays published
  until every token it signed has expired, and every key is published
  under its RFC 7638 thumbprint. `GET /admin/keys` no longer carries
  `published`, since every key it lists is published.
