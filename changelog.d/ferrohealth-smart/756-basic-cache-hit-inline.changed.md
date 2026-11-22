- The guard checks a Basic credential the verified-credential cache holds
  before its refresh point on the request's own task, with no hand-off to
  Tokio's blocking pool, which only a miss, a refresh or a wrong password
  still takes for the key derivation. A wrong password is refused as
  before, after the same derivation.
