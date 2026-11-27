- A `private_key_jwt` client assertion with no `typ` authenticates, since RFC
  10070 §3.2 does not recommend refusing an untyped client authentication
  JWT; a `typ` other than `JWT` or `client-authentication+jwt` is still
  refused.
