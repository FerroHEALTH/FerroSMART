<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Log in with the EUDI Wallet

**For:** operators who let people log in with the person identification
data in their European Digital Identity Wallet.

A person can log in by presenting the person identification data (PID) in
their European Digital Identity Wallet. FerroSMART is the verifier, under
the OpenID4VC High Assurance Interoperability Profile and the EU wallet
profile: it sends the browser to the wallet with a signed request, the
wallet posts the person's PID back encrypted, and the browser that began
the login brings the answer back. The entry has an
`[ferrosmart.upstream.openid4vp]` table
([the keys](../configure/upstream-keys.md#ferrosmartupstream)).

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
FerroSMART does not match people by name and birth date.

With a patient index such as FerroPIX, the index resolves the person
instead. `identifier_systems` names the identifier system of each issuing
country's administrative numbers, and the FHIR server's `patient_index`
names the index and the system of the server's own patients there.
FerroSMART asks the index by PIXm ITI-83 (or PDQm ITI-78 with
`transaction = "pdqm"`) for the person's identifier in that system, as
itself with the scope `system/Patient.rs`, and then searches the FHIR
server for it as the person. Exactly one patient at each step is the
person's `fhirUser` and the app's `patient`; no patient or several refuse
the launch, and the app gets `access_denied`.

```toml
[ferrosmart.upstream.openid4vp]
# ...
identifier_systems = { NL = "http://fhir.nl/fhir/NamingSystem/bsn" }

[[ferrosmart.resource]]
base = "https://ehr.example.org/fhir"

[ferrosmart.resource.patient_index]
base = "https://pix.example.org/fhir"
system = "urn:oid:2.16.840.1.113883.2.4.6.3.1"
```

FerroSMART
refuses a presentation whose issuer does not chain to an anchor, whose
type was not asked for, that has expired or been revoked, whose key
binding does not hold, whose nonce was answered before, or that leaves out
a claim asked for. Each refusal is a login record in the
[audit](../operate/audit.md) that names the reason.
