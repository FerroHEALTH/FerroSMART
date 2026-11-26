<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Upstream configuration

**For:** operators. The keys of `[[ferrosmart.upstream]]`, the providers
people log in at, and of `[ferrosmart.saml]`, FerroSMART as a SAML service
provider. The rest of the tree is on [configuration](configuration.md); the
how-to pages are [OpenID Connect providers](../install/upstream.md),
[SAML 2.0 providers](../install/saml.md) and
[the EUDI Wallet](../install/wallet.md).

## `[[ferrosmart.upstream]]`

The identity providers people log in at
([identity providers](../install/upstream.md)), one entry each. Without an
entry, nobody logs in and FerroSMART answers Backend Services alone.

| Key | What it is |
|---|---|
| `name` | The provider's name, of letters, digits and `-`, unique among the entries; a client's `upstreams` names it |
| `label` | The words the chooser page shows for the provider; its `name` when empty |
| `preset` | `keycloak`, `entra`, `okta` or `zitadel`: the defaults of FerroSMART's tested setup with that provider, for an OpenID Connect entry; none by default |

The table present names the protocol: `[ferrosmart.upstream.oidc]` for
OpenID Connect, `[ferrosmart.upstream.saml]` for SAML 2.0 or
`[ferrosmart.upstream.openid4vp]` for the EUDI Wallet, exactly one per
entry.

`[ferrosmart.upstream.assurance]` says what the provider's logins are
worth. A login below the minimum is refused with `access_denied`, and every
token issued on a login carries its level as `acr`, the eIDAS URI
`http://eidas.europa.eu/LoA/low`, `/substantial` or `/high`, beside
`auth_time`.

| Key | What it is |
|---|---|
| `levels` | A table of the provider's value to its eIDAS level (`low`, `substantial`, `high`): an OpenID Connect provider's `acr`, a SAML provider's `AuthnContextClassRef`. A value it does not name carries no level |
| `minimum` | The level every login at this provider reaches, above `assurance_minimum`; none by default |

Each entry has its own issuer, and two entries never share one. A client
lists the providers its people may log in at in `upstreams`; with none
listed it may use every provider. With one provider the browser goes
straight to it; with several, FerroSMART shows a chooser at
`{issuer}/login`. Several Microsoft Entra ID tenants are several entries,
one per tenant authority.

`[ferrosmart.upstream.oidc]`. A key the table leaves out takes the
preset's value, then the default below; a key the table sets wins over
the preset.

| Key | What it is |
|---|---|
| `issuer` | The provider's issuer, whose discovery document FerroSMART reads at start |
| `client_id` | The client FerroSMART is registered as at the provider |
| `scopes` | The scopes FerroSMART asks for, `openid` among them; `["openid"]` by default |
| `fhir_user_claim` | The ID Token claim holding the person's `fhirUser`; empty for none, the default |
| `role_claims` | The ID Token claims holding the person's roles, each a dotted path; a claim name with a dot is read whole first. `roles`, `groups` and `entitlements` by default |
| `trusted_audiences` | Audiences an ID Token may carry beside the client id, such as a project the provider adds; empty trusts none, the default |

| Preset | `scopes` | `fhir_user_claim` | `role_claims` | `algorithm` |
|---|---|---|---|---|
| `keycloak` | `openid` | `fhir_user` | `roles` | `RS256` |
| `entra` | `openid profile` | `extn.fhirUser` | `roles` | `PS256` |
| `okta` | `openid profile` | `fhir_user` | `groups` | `RS256` |
| `zitadel` | `openid profile` | `fhirUser` | `urn:zitadel:iam:org:project:roles` | `RS256` |

Each preset is a data file under `app/ferrosmart/presets/` with the
provider's documentation cited beside each value
([identity providers](../install/upstream.md)).

FerroSMART authenticates at the provider with `private_key_jwt` unless
the entry names `[ferrosmart.upstream.oidc.client_secret_basic]`; the
assertion keys go in `[ferrosmart.upstream.oidc.private_key_jwt.keys]`,
and the `private_key_jwt` table itself is needed only for a key below.
An entry never names both, and FerroSMART refuses a provider whose
discovery document does not list the method.

| Key of `client_secret_basic` | What it is |
|---|---|
| `secret_file` | The file holding the client secret the provider issued, sent as HTTP Basic (RFC 6749 §2.3.1); `secret` sets it inline |

The `private_key_jwt` table:

| Key | What it is |
|---|---|
| `algorithm` | The JWS algorithm the provider's registration names; the preset's, else `RS256` |
| `certificate_file` | The X.509 certificate of the current assertion key, for a provider that knows the key by its certificate; each assertion then names it by `x5t#S256` |
| `[ferrosmart.upstream.oidc.private_key_jwt.keys]` | The assertion ring: `private_key_file` (the key that signs), `kid` (the id the provider knows it by, such as ZITADEL's key id; its RFC 7638 thumbprint when empty), `next_private_key_file`, `previous_private_key_file` and `previous_key_overlap` (`0s` keeps the previous key published while it is configured). It may share no key with the token keys |

`[ferrosmart.upstream.saml]`, for a SAML 2.0 identity provider
([SAML 2.0 providers](../install/saml.md)):

| Key | What it is |
|---|---|
| `entity_id` | The identity provider's entity ID, an absolute URI |
| `metadata_url` | The `https` URL its metadata is read from; exclusive with `metadata_file` |
| `metadata_file` | The file its metadata is read from |
| `metadata_signing_certificate_files` | The PEM certificates whose keys must sign the metadata; empty trusts it as read |
| `metadata_refresh` | How often the metadata is read again; `24h` by default. A failed read keeps the last good copy until its `validUntil` |
| `request_binding` | `redirect` (the default) or `post`: how the browser carries the signed `AuthnRequest` |
| `response_binding` | `post` (the default) or `artifact`: how the provider answers. An artifact is resolved over mutual TLS with the identity of `[ferrosmart.saml.tls]` |
| `force_authn` | Whether every request asks the provider to authenticate the person afresh; `prompt=login` and `max_age` ask it per request |
| `name_id_format` | The name identifier format asked for; empty asks for none |
| `authn_contexts` | The authentication context classes at or above the provider's minimum assurance, in its own vocabulary. FerroSMART asks for them as an exact match and refuses a login of any other class; empty accepts any |
| `clock_skew` | The clock skew admitted at each time bound; `3min` by default, at most one hour |
| `subject_attribute` | The attribute whose one value is the person's identifier; empty takes the `NameID`, which must not be transient |
| `claims` | A table of claim name to attribute `Name`: the claims the login yields, a string for one value and an array for more. `name`, `preferred_username` and `email` are read as the ID Token claims of those names are |
| `fhir_user_claim` | The claim of `claims` holding the person's `fhirUser`; empty for none |
| `role_claims` | The claims of `claims` holding the person's roles |

`[ferrosmart.upstream.openid4vp]`, for the EUDI Wallet
([the EUDI Wallet](../install/wallet.md)). A wallet login
is at level `high`, so the entry's `[ferrosmart.upstream.assurance]` sets
only a `minimum`.

| Key | What it is |
|---|---|
| `access_certificate_file` | The PEM wallet-relying party access certificate first, then its path up to, but not including, the anchor. It must not be self-signed |
| `access_key_file` | The access certificate's PKCS#8 PEM P-256 key, which signs every request object |
| `registration_certificate_file` | The registration certificate as the registrar issued it; every request object carries it |
| `issuer_anchor_files` | The PEM certificates of the PID providers' trust anchors. A PID's issuer and its status list must chain to one of these or to the list below |
| `wallet_endpoint` | Where the wallet is invoked; `eu-eaap://` by default |
| `credential_formats` | The formats the PID is asked for in, of which the wallet presents one: `["dc+sd-jwt", "mso_mdoc"]` by default |
| `vct_values` | The credential types accepted as an SD-JWT VC; `["urn:eudi:pid:1"]` by default. The first names the person's pairwise `sub`, whichever format the wallet presents |
| `claims` | The PID claims asked for of an SD-JWT VC, dotted for a nested claim, with `identifier_claim` and `issuing_country` among them and never the portrait `picture`, which FerroSMART does not retain (Implementing Regulation (EU) 2024/2977 Art 3a(3)); the PID's names and the administrative number by default |
| `doctype` | The document type accepted as an mdoc, which is also the namespace of its elements; `eu.europa.ec.eudi.pid.1` by default |
| `mdoc_claims` | The data elements asked for of an mdoc, with `identifier_claim` and `issuing_country` among them and never `portrait`; the PID's names, `birth_date` and the administrative number by default |
| `identifier_claim` | The claim or element whose value names the person and that a [`fhirUser` lookup](configuration.md#ferrosmartresource) reads; `personal_administrative_number` by default |
| `identifier_systems` | A table from each issuing country's ISO 3166-1 alpha-2 code to the identifier system of its administrative numbers, which a `patient_index` is asked in; empty by default. A country it leaves out refuses a launch that needs the index |
| `identifier_type` | The HL7 v2 table 0203 code of that identifier's type; `NI` by default |
| `digital_credentials_api` | Whether the wallet page offers the W3C Digital Credentials API beside its link; `true` by default. With `false` the browser goes straight to `wallet_endpoint` |

`[ferrosmart.upstream.openid4vp.pid_providers_list]` is the list of PID
providers the Commission publishes, signed, under Implementing Regulation
(EU) 2024/2980 Art 5. FerroSMART reads it as ETSI TS 119 602 Annex D, the
JSON form under a JAdES signature. A list that does not verify, or whose
next update has passed, refuses every wallet login, and the last list that
verified stays in use until its own next update.

| Key | What it is |
|---|---|
| `url` | The HTTPS URL the list is read from; exclusive with `file` |
| `file` | A file holding a copy of the list |
| `signing_certificate_files` | The PEM certificates the Commission publishes to verify the list's signature |
| `refresh` | How often the list is read again; `1h` by default. It is read again at its next update too |

## `[ferrosmart.saml]`

FerroSMART as one SAML 2.0 service provider, which every entry with a
`[ferrosmart.upstream.saml]` table needs. FerroSMART serves its metadata at
`{issuer}/saml/metadata` and takes the provider's answer at
`{issuer}/saml/acs`.

| Key | What it is |
|---|---|
| `entity_id` | FerroSMART's entity ID; `{issuer}/saml/metadata` by default |
| `signing_key_file` | The PKCS#8 PEM key that signs every `AuthnRequest` and `ArtifactResolve`: RSA of 2048 bits or more, or ECDSA on P-256 or P-384 |
| `signing_certificate_file` | The PEM certificate of that key, which the metadata publishes |
| `[[ferrosmart.saml.decryption]]` | `key_file` and `certificate_file` of an RSA key a provider encrypts assertions, identifiers and attributes for |
| `[ferrosmart.saml.tls]` | `client_identity_file`, the certificate and key artifact resolution presents, and `trust_roots_file`, roots beside the platform's for every call to a provider |
