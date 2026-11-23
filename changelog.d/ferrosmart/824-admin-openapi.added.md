- `GET {issuer}/admin/openapi.json` answers the OpenAPI 3.1 document of the
  registration endpoint, the admin API and the audit records, without a
  token and with the deployment's issuer as its server. A test holds the
  document to the router's operations and each answer to its schema.
