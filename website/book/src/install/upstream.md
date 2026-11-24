<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Identity providers

A person logs in at an identity provider upstream of FerroSMART: an
OpenID Connect provider, of which FerroSMART is a client, or a SAML 2.0
identity provider, of which FerroSMART is a service provider. Any OpenID
Connect provider that publishes a discovery document works, and any SAML
2.0 provider of the Web Browser SSO profile; no code in FerroSMART knows a
vendor or a country. Four OpenID Connect providers have a tested setup,
and each section below says what to configure at the provider and in
`[[ferrosmart.upstream]]`. [SAML 2.0](#saml-20) and [the EUDI Wallet](#the-eudi-wallet)
close the page.

## What every provider needs

At the provider, register FerroSMART as a confidential web client:

- the authorization code flow, with PKCE `S256` (FerroSMART sends a
  challenge on every request);
- one redirect URI, FerroSMART's `{issuer}/callback`, matched exactly;
- an ID Token claim with the person's `fhirUser`, such as
  `Practitioner/123` or an absolute URL, when apps ask for `fhirUser`;
- an ID Token claim with the person's roles, which
  [`[[ferrosmart.role]]`](../configure/clients.md#roles) maps to scopes;
- optionally FerroSMART's `{issuer}/backchannel-logout` as the back-channel
  logout URI, or, at a provider that offers only front-channel logout such
  as Microsoft Entra ID, `{issuer}/frontchannel-logout` as the front-channel
  logout URI with `frontchannel_logout_session_required` (the provider
  sends `iss` and `sid`), so a logout at the provider ends the person's
  `online_access` grants;
- optionally FerroSMART's `{issuer}/logout/return` as a post-logout
  redirect URI, so a logout an app starts at FerroSMART's end-session
  endpoint also logs the person out at the provider and comes back.

`ferrosmart upstream registration <name>` prints this list for the entry
`<name>`, with FerroSMART's URIs, the client authentication, the scopes,
the claims and the roles filled in from the configuration:

```text
$ ferrosmart --config ferrosmart.toml upstream registration keycloak
Register FerroSMART at the provider `keycloak` (OpenID Connect) with:
  issuer                    http://localhost:8180/realms/ferrosmart
  client id                 ferrosmart
  client type               confidential web client
  grant                     authorization code, PKCE S256
  redirect URI              http://localhost:8080/callback
  post-logout redirect URI  http://localhost:8080/logout/return
  back-channel logout URI   http://localhost:8080/backchannel-logout
  front-channel logout URI  http://localhost:8080/frontchannel-logout, with iss and sid, where the provider has no back-channel logout
  client authentication     private_key_jwt, signed RS256
  JWK Set URL               http://localhost:8080/upstream-jwks
  scopes                    openid
  fhirUser claim            fhir_user, in the ID Token
  role claims               roles, in the ID Token
  roles                     clinician
```

An entry names the vendor it is set up for as `preset`, and the preset
brings that setup's scopes, claims and assertion algorithm; each provider
below lists what its preset holds. A key set in the entry's
`[ferrosmart.upstream.oidc]` table wins over the preset
([the keys](../configure/configuration.md#ferrosmartupstream)).

FerroSMART authenticates to a provider with `private_key_jwt` (OpenID
Connect Core 1.0 §9) by default: a JWT signed by its assertion key,
configured under `[ferrosmart.upstream.oidc.private_key_jwt.keys]`. For a
provider that offers no `private_key_jwt` to a web client, name
`[ferrosmart.upstream.oidc.client_secret_basic]` with `secret_file`
instead: FerroSMART then sends the client secret as HTTP Basic (RFC 6749
§2.3.1). Each provider names exactly one of the two, and FerroSMART
refuses to start when the provider's discovery document does not list the
method in `token_endpoint_auth_methods_supported`. Prefer the key: a
secret can leak from a configuration file. The assertion key is a key of its own,
never a token signing key, and FerroSMART publishes it at
`{issuer}/upstream-jwks` for a provider that reads a key set
([keys and rotation](../operate/keys.md#the-assertion-keys)).

Each assertion names the provider's issuer as its only audience (`aud`)
and has the type `client-authentication+jwt`, as RFC 10070 §4 requires.
Keycloak and ZITADEL accept this by their source code. Entra ID and Okta
document the token endpoint URL as `aud`; RFC 10070 §6 says a client that
follows the update works with them too. Verify it on your tenant before
production.

Every provider below is described in the same shape: login, client
authentication, `fhirUser`, roles, and how the setup is tested.

| Provider | Login | Client authentication | `fhirUser` | Roles | Tested by |
|---|---|---|---|---|---|
| Keycloak | the realm's login form | Signed JWT, reading `{issuer}/upstream-jwks` | a user attribute mapper | a realm role mapper, `roles` | a live launch in CI, and the compose quickstart |
| ZITADEL | the Login v2 UI | Private Key JWT, with a key ZITADEL generates | an Actions v2 target, from user metadata | the project role claim | a live launch in CI |
| Microsoft Entra ID | the tenant's sign-in | a certificate of the assertion key | a directory extension attribute | app roles, `roles` | a contract test against Entra ID's documents |
| Okta | the org's sign-in, `default` authorization server | Public key / Private key, the JWK of `{issuer}/upstream-jwks` | a custom claim | a groups claim, `groups` | a contract test against Okta's documents |

FerroSMART checks the provider's ID Token by OpenID Connect Core 1.0
§3.1.3.7, refuses one without the `nonce` it sent, and reads only the
claims you name. The person's `sub` at FerroSMART is derived from the
provider's issuer and `sub`, so the provider's `sub` never reaches a
resource server. To bind a person at a resource server, take their
FerroSMART `sub` from `ferrosmart subject --upstream <name> --sub <their
sub at the provider>`, or let them read it on the management page at
`{issuer}/manage`.

## Keycloak

Keycloak runs upstream in a compose overlay of the quickstart. From a
checkout, with the two extra secret files the overlay's header lists:

```sh
docker compose -f compose.yaml -f compose.keycloak.yaml up
```

Sign in as `clinician` with the password in
`secrets/keycloak_user_password`. The realm is
`app/ferrosmart/examples/keycloak/ferrosmart-realm.json`, and FerroSMART's
side is `ferrosmart.toml` beside it. The overlay runs Keycloak in
development mode and both servers on plain `http` on `localhost`; a
deployment serves both over TLS on their own names.

| At Keycloak | Value |
|---|---|
| Login | the client `ferrosmart`, the standard flow with PKCE `S256`, implicit and direct access grants off, redirect URI `{issuer}/callback` |
| Client authentication | confidential, client authenticator `client-jwt` with a JWKS URL: FerroSMART's `{issuer}/upstream-jwks`, signed `RS256` |
| `fhirUser` | a user attribute mapper writes the attribute `fhir_user` into the ID Token |
| Roles | a realm role mapper, multivalued, writes `roles` into the ID Token; the realm role `clinician` |
| Tested by | a standalone launch in CI through Keycloak's login form, and the compose quickstart lane |

The `keycloak` preset holds the scope `openid`, the claims `fhir_user`
and `roles`, and `RS256`.

```toml
[[ferrosmart.upstream]]
name = "idp"
preset = "keycloak"

[ferrosmart.upstream.oidc]
issuer = "https://keycloak.example.org/realms/ferrosmart"
client_id = "ferrosmart"

[ferrosmart.upstream.oidc.private_key_jwt.keys]
private_key_file = "/run/secrets/upstream_assertion_key"
```

## ZITADEL

ZITADEL runs upstream in a compose overlay too, with its Login v2 UI and
its own PostgreSQL. From a checkout, with the three extra secret files the
overlay's header lists:

```sh
docker compose -f compose.yaml -f compose.zitadel.yaml up
```

A bootstrap container runs `app/ferrosmart/examples/zitadel/bootstrap.sh`
once: it makes the project with its role, the application, the user and
the action that writes `fhirUser`, and writes FerroSMART's configuration
with the client id ZITADEL generated. Log in at
`http://localhost:3000/ui/v2/login`.

| At ZITADEL | Value |
|---|---|
| Login | the OIDC web app `ferrosmart-login`, the code flow with PKCE `S256`, one redirect URI `{issuer}/callback`, roles and user info in the ID Token |
| Client authentication | Private Key JWT, with an application key ZITADEL generates; FerroSMART signs with it under ZITADEL's key id |
| `fhirUser` | an Actions v2 execution on `preuserinfo` that adds `fhirUser` from the user's metadata |
| Roles | the project `ferrosmart` with role assertion on and the role `clinician`, in the claim `urn:zitadel:iam:org:project:ferrosmart:roles`, an object whose member names are the roles |
| Tested by | a standalone launch in CI through ZITADEL |
| Audience | ZITADEL adds the project to the ID Token's `aud`, so FerroSMART trusts it |

The `zitadel` preset holds the scopes `openid profile`, the claim
`fhirUser`, the roles of the application's own project in
`urn:zitadel:iam:org:project:roles`, and `RS256`. The example reads the
roles of the project `ferrosmart` by its id instead, which ZITADEL
recommends, and trusts that project as an audience:

```toml
[[ferrosmart.upstream]]
name = "idp"
preset = "zitadel"

[ferrosmart.upstream.oidc]
issuer = "https://zitadel.example.org"
client_id = "<the generated client id>"
role_claims = ["urn:zitadel:iam:org:project:ferrosmart:roles"]
trusted_audiences = ["ferrosmart"]

[ferrosmart.upstream.oidc.private_key_jwt.keys]
private_key_file = "/run/secrets/zitadel-application-key.pem"
kid = "<the key id ZITADEL gave the key>"
```

`trusted_audiences` names the audiences beside FerroSMART's client id that
an ID Token may carry; an ID Token with several audiences must then name
the client in `azp`.

## Microsoft Entra ID

Entra ID is a hosted service, so no example runs it; the contract tests run
FerroSMART's side, `app/ferrosmart/examples/entra/ferrosmart.toml`, against
the discovery document, key set and token answer Entra ID publishes.

| At Entra ID | Value |
|---|---|
| Login | a single-tenant app registration, the authority `https://login.microsoftonline.com/<tenant id>/v2.0` as the `issuer`, platform Web with the redirect URI `{issuer}/callback`, the code flow with PKCE `S256` |
| Client authentication | a certificate of FerroSMART's current assertion key, uploaded to the registration; each assertion names it by `x5t#S256`, signed `PS256` |
| `fhirUser` | a directory extension attribute `fhirUser`, set per user, as an ID Token optional claim, which Entra ID emits as `extn.fhirUser` |
| Roles | the app role `clinician`, assigned to people or to groups under Enterprise applications; the ID Token carries it in `roles` |
| Logout | the front-channel logout URL `{issuer}/frontchannel-logout`, and `{issuer}/logout/return` as a second redirect URI for the end-session endpoint's return. FerroSMART ends a session only from a request with `iss` and `sid`: check that the tenant's discovery document says `frontchannel_logout_session_supported` and that the ID Token carries `sid` |
| Tested by | a contract test that runs the example against Entra ID's discovery document, key set and token answer |

FerroSMART reads roles from app roles alone, never from the `groups`
claim: a person in more groups than the token holds gets an overage
reference to Microsoft Graph in place of `groups`, which FerroSMART does
not follow, and app roles hold the same values in every tenant
(`howto-add-app-roles-in-apps.md`, App roles vs. groups). Assigning a group
to an app role gives every member that role in `roles`. Whether assigning a
group, rather than each person, needs a paid Microsoft Entra ID licence
(P1 or higher) is not stated in the Microsoft pages FerroSMART vendors, so
check your tenant's licence before you plan on group assignment.

The `entra` preset holds the scopes `openid profile`, the claims
`extn.fhirUser` and `roles`, and `PS256`.

```toml
[[ferrosmart.upstream]]
name = "idp"
preset = "entra"

[ferrosmart.upstream.oidc]
issuer = "https://login.microsoftonline.com/<tenant id>/v2.0"
client_id = "<the application (client) id>"

[ferrosmart.upstream.oidc.private_key_jwt]
certificate_file = "/run/secrets/upstream-assertion.crt"

[ferrosmart.upstream.oidc.private_key_jwt.keys]
private_key_file = "/run/secrets/upstream-assertion.pem"
```

Three choices hold here. Roles come from app roles, never groups, because a
person in many groups gets an overage pointer instead of the groups. The
multitenant authorities `/common` and `/organizations` are refused, since
their metadata names an issuer other than the one it was read under: one
FerroSMART logs in the people of one tenant. To rotate, upload the next
key's certificate before the ring makes it current.

## Okta

Okta is a hosted service as well; the contract tests run
`app/ferrosmart/examples/okta/ferrosmart.toml` against the documents Okta
publishes.

| At Okta | Value |
|---|---|
| Login | a Web Application integration with the authorization code grant and PKCE `S256`, `{issuer}/callback` as the one sign-in redirect URI, at the custom authorization server `default`, issuer `https://<your Okta domain>/oauth2/default` |
| Client authentication | Public key / Private key: add the JWK FerroSMART publishes at `{issuer}/upstream-jwks` to the integration's public keys; assertions are signed `RS256` |
| `fhirUser` | a custom claim `fhir_user` in the ID Token, always, reading the person's `fhirUser` profile attribute |
| Roles | a groups claim `groups` in the ID Token, always, filtered to FerroSMART's role groups; the group `clinician`, assigned to the app integration |
| Tested by | a contract test that runs the example against the documents Okta publishes |

The `okta` preset holds the scopes `openid profile`, the claims
`fhir_user` and `groups`, and `RS256`.

```toml
[[ferrosmart.upstream]]
name = "idp"
preset = "okta"

[ferrosmart.upstream.oidc]
issuer = "https://example.okta.com/oauth2/default"
client_id = "<the client id>"

[ferrosmart.upstream.oidc.private_key_jwt.keys]
private_key_file = "/run/secrets/upstream-assertion.pem"
```

Use the custom authorization server, since only that one takes a custom
claim in the ID Token by Okta's written procedure, and keep the groups
filter narrow: a groups claim holds at most 100 groups. To rotate, add the
next key's JWK to the integration before the ring makes it current.

## SAML 2.0

FerroSMART is a service provider of the OASIS SAML 2.0 Web Browser SSO
profile, with the standard bindings and no national profile. Configure
FerroSMART once as a service provider in `[ferrosmart.saml]`, then one
entry with a `[ferrosmart.upstream.saml]` table per identity provider
([the keys](../configure/configuration.md#ferrosmartsaml)).

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

## The EUDI Wallet

A person can log in by presenting the person identification data (PID) in
their European Digital Identity Wallet. FerroSMART is the verifier, under
the OpenID4VC High Assurance Interoperability Profile and the EU wallet
profile: it sends the browser to the wallet with a signed request, the
wallet posts the person's PID back encrypted, and the browser that began
the login brings the answer back. The entry has an
`[ferrosmart.upstream.openid4vp]` table
([the keys](../configure/configuration.md#ferrosmartupstream)).

Before the first login you need, from your Member State's registrar of
wallet-relying parties:

- a wallet-relying party access certificate with its P-256 key, which signs
  every request;
- a registration certificate naming the attributes you may ask for;
- the trust anchors of the PID providers you accept.

`ferrosmart upstream registration <name>` prints what the registrar
records: the request URI, the response URI `{issuer}/wallet/response`, the
redirect URI `{issuer}/wallet/complete`, the credential formats, and for
each format the credential or document type and the attributes.

The request asks for the PID as an SD-JWT VC or as an ISO mdoc, and the
wallet presents the one it holds. Both name the same person, so the login
is the same either way. Set `credential_formats` to ask for one format
only.

The browser first shows a page with an "Open your wallet" link. Where the
browser has the W3C Digital Credentials API, a press asks the browser for
the PID, which offers a wallet on the device or on a phone nearby; any
other browser follows the link to the wallet app. Set
`digital_credentials_api = false` to send the browser straight to the
wallet.

```toml
[[ferrosmart.upstream]]
name = "wallet"
label = "EUDI Wallet"

[ferrosmart.upstream.openid4vp]
access_certificate_file = "/run/secrets/wrp-access.pem"
access_key_file = "/run/secrets/wrp-access-key.pem"
registration_certificate_file = "/run/secrets/wrp-registration.jwt"
issuer_anchor_files = ["/run/secrets/pid-providers.pem"]

[[ferrosmart.resource]]
base = "https://ehr.example.org/fhir"

[[ferrosmart.resource.fhir_user_lookup]]
resource_type = "Patient"
claim = "personal_administrative_number"
system = "http://fhir.nl/fhir/NamingSystem/bsn"
```

The PID's administrative number names the person, and the `fhirUser`
lookup finds their record by it. A PID without one is refused, since
FerroSMART does not match people by name and birth date. FerroSMART
refuses a presentation whose issuer does not chain to an anchor, whose
type was not asked for, that has expired or been revoked, whose key
binding does not hold, whose nonce was answered before, or that leaves out
a claim asked for. Each refusal is a login record in the
[audit](../operate/audit.md) that names the reason.
