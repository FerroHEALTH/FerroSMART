- `GET {issuer}/audit` takes `client`, `event` and `outcome` beside
  `subject`, `since` and `until`, and pages: the searchset Bundle carries a
  `self` link and, while more records match, a `next` link to the next
  page. `POST {issuer}/admin/clients/{client_id}/secret` issues a
  confidential symmetric client a new secret, answered once with its audit
  record, through the same code as `ferrosmart client secret`.
