<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# The EHR launch API

In an EHR launch the EHR hands the app "an opaque handle to the EHR
context", which the app passes back as `launch`, and "the server will
provide the application with EHR context based on this handle" (SMART App
Launch 2.2.0, SMART authorization & FHIR access: overview). SMART does not
say how the EHR gives the authorization server that context. FerroSMART
offers two ways, both its own design: register the context and get a
`launch` value, or sign the context and use the JWT as the value. Either
way the launch is bound to the EHR, the app and the server, lives at most
five minutes and is redeemed once.

## Register the EHR

The EHR is a confidential client with its JWK Set, and its ceiling lists
`system/launch.c`. Each app it launches is a client of the
`authorization_code` grant whose ceiling lists `launch`. Apply its
document with `ferrosmart client apply`:

```json
{
  "client_id": "ehr",
  "client_name": "Example EHR",
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks_uri": "https://ehr.example.org/.well-known/jwks.json",
  "scope": "system/launch.c",
  "grant_types": ["client_credentials"]
}
```

## Way 1: register the launch

On each launch, the EHR posts the context to `{issuer}/launch`, the URL
FerroSMART's `.well-known/smart-configuration` and RFC 8414 metadata name
`launch_registration_endpoint` (a member of FerroSMART's own; SMART defines
none), authenticated with the client assertion it would send to the token
endpoint: `iss` and `sub` its `client_id`, `aud` FerroSMART's token URL or
issuer, `exp` at most five minutes ahead, a fresh `jti`, signed `RS384`,
`ES384` or ML-DSA (RFC 9964), `typ` `JWT`.

```http
POST /launch HTTP/1.1
Host: smart.example.org
Content-Type: application/x-www-form-urlencoded

client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJ...
&app_client_id=growth-chart
&resource=https%3A%2F%2Fehr.example.org%2Ffhir
&patient=123&encounter=456&need_patient_banner=false
&fhirContext=%5B%7B%22reference%22%3A%22DiagnosticReport%2F7%22%7D%5D
```

| Parameter | What it is |
|---|---|
| `app_client_id` or `app_launch_uri` | The app the launch is for, by its `client_id` or by the `launch_uri` it registers; exactly one |
| `resource` | The base URL of the server, one of `[[ferrosmart.resource]]` and one the app's `resources` lists (`invalid_target` otherwise) |
| `patient`, `encounter` | The FHIR ids in context |
| `fhirContext` | A JSON array of context items, each with a `reference`, `canonical` or `identifier` |
| `intent`, `need_patient_banner`, `tenant` | The SMART launch context parameters of the same names |
| `ehrId` | The openEHR EHR in context, for an openEHR server |
| `appContext` | A SMART Task's application context, at most 8192 bytes, which the token response carries unchanged as `appContext` |

FerroSMART answers `201 Created`:

```json
{"launch": "<43 characters>", "expires_in": 300}
```

The value is 256 random bits, stored only as its SHA-256.

## Way 2: sign the launch

The EHR signs the same context as a JWT with a key of its registered JWK
Set and uses the compact JWS as the `launch` value. FerroSMART is not
called first, so the EHR and FerroSMART share nothing but the key set.

```json
{"alg": "ES384", "typ": "launch+jwt", "kid": "ehr-1"}
{"iss": "ehr", "aud": "https://smart.example.org", "exp": 1794856312,
 "jti": "b1f0...", "client_id": "growth-chart",
 "resource": "https://ehr.example.org/fhir",
 "patient": "123", "encounter": "456", "need_patient_banner": false}
```

FerroSMART checks it the way it checks a client assertion: `typ`
`launch+jwt`, signed `RS384`, `ES384` or ML-DSA (RFC 9964), `aud` FerroSMART's issuer as its
one value, `exp` at most five minutes ahead, and a `jti` used once.
`client_id` is the app and `resource` the server.

## Open the app

Open the app's launch URL with `iss`, the server's base, and `launch`:

```text
https://app.example.org/launch?iss=https%3A%2F%2Fehr.example.org%2Ffhir&launch=<value>
```

The `iss` is the launch's `resource`, since the app's `aud` at the
authorization endpoint "is the same as the launch's `iss` value" (SMART App
Launch 2.2.0, Obtain authorization code). The app reads the server's
`.well-known/smart-configuration`, which names FerroSMART, and sends the
person to `/authorize` with the `launch` scope and value. The person logs
in and consents, and the token response carries the context the EHR gave.
[The flows](flows.md#the-standalone-launch) show the consent page.

A launch that the app does not redeem within five minutes, or redeems for
another app or server, fails; the EHR launches again.
