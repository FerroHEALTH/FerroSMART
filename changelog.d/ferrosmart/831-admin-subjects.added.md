- The admin API finds a person and ends their access, as the person can on
  the management page: `GET {issuer}/admin/subjects?upstream=&sub=`
  answers their subject, `GET .../subjects/{sub}/grants` their live grants
  and remembered consents, and `DELETE .../grants/{grant_id}`,
  `.../consents/{client_id}` and `.../sessions` revoke one grant, withdraw
  one app's consent with its grants, or end their upstream sessions with
  the `online_access` grants in them, each with its audit record naming the
  admin client.
