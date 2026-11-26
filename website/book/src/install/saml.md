<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Log in at a SAML 2.0 provider

**For:** operators who log people in at a SAML 2.0 identity provider.

FerroSMART is a service provider of the OASIS SAML 2.0 Web Browser SSO
profile, with the standard bindings and no national profile. Configure
FerroSMART once as a service provider in `[ferrosmart.saml]`, then one
entry with a `[ferrosmart.upstream.saml]` table per identity provider
([the keys](../configure/upstream-keys.md#ferrosmartsaml)).

At the identity provider, register FerroSMART by its metadata at
`{issuer}/saml/metadata` (`ferrosmart upstream registration <name>` prints
it with the entity IDs, the assertion consumer service and the attributes
the entry reads). It names:

- FerroSMART's entity ID and its signing certificate: every
  `AuthnRequest` is signed;
- one encryption certificate per decryption key, for an encrypted
  assertion, identifier or attribute;
- the assertion consumer service `{issuer}/saml/acs` under HTTP-POST and
  HTTP-Artifact.

At the provider, release:

- a persistent name identifier, or an attribute with the person's
  identifier named by `subject_attribute`; a transient name identifier is
  refused, since it names the person for one login only;
- the attributes the `claims` table maps, such as the display name, the
  roles that [`[[ferrosmart.role]]`](../configure/clients.md#roles) maps to
  scopes, and the person's `fhirUser` or an identifier a
  [`fhirUser` lookup](../configure/configuration.md#ferrosmartresource) searches by;
- an authentication context class among `authn_contexts`, which lists the
  classes at or above the minimum assurance you accept.

```toml
[ferrosmart.saml]
signing_key_file = "/run/secrets/saml-signing.pem"
signing_certificate_file = "/run/secrets/saml-signing.crt"

[[ferrosmart.saml.decryption]]
key_file = "/run/secrets/saml-decryption.pem"
certificate_file = "/run/secrets/saml-decryption.crt"

[[ferrosmart.upstream]]
name = "saml-idp"
label = "Your organisation's login"

[ferrosmart.upstream.saml]
entity_id = "https://idp.example.org/saml"
metadata_url = "https://idp.example.org/saml/metadata"
name_id_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
authn_contexts = ["urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"]
fhir_user_claim = "fhir_user"
role_claims = ["roles"]

[ferrosmart.upstream.saml.claims]
name = "urn:oid:2.16.840.1.113730.3.1.241"
roles = "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
fhir_user = "fhirUser"
```

FerroSMART refuses a response that is not signed by a key of the
provider's metadata, that answers no request it sent or another one, that
names another audience, or whose authentication context is not one you
accept, and it admits each assertion once. Each outcome is a login record
in the [audit](../operate/audit.md) that names the check that failed. For
the HTTP-Artifact binding, set `response_binding = "artifact"` and give
FerroSMART a TLS client identity in `[ferrosmart.saml.tls]`: it resolves
the artifact at the provider's artifact resolution service over mutual
TLS. Single Logout is not taken: a SAML login's grants end with their own
lifetimes.
