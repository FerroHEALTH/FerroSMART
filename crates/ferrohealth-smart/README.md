<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# ferrohealth-smart

SMART for the openEHR ecosystem, FHIR included: the shared SMART App Launch
2.x and OAuth 2.0 resource-server crate of the FerroHEALTH products. It is a
library, never an authorization server: it issues no token and holds no key
that signs one. Each deployment points it at its own standards-compliant
authorization server.

```toml
[dependencies]
ferrohealth-smart = { version = "=0.34.0", features = ["axum", "openehr"] }
```

## What it does

- **`resource`**: the resource server. `ResourceServer::discover` reads the
  issuer's metadata (RFC 8414, OpenID Connect Discovery 1.0 as the fallback)
  and its key set, and `authenticate` checks a JWT access token under
  RFC 9068: the signature with an asymmetric algorithm (RSA, ECDSA, `EdDSA`
  or ML-DSA of RFC 9964, through the `jws` module), `iss`, `aud`, `exp`
  and `nbf` within a clock skew, the `at+jwt` type and the required claims.
  The `Caller` it returns carries the subject, the client, the scopes, the
  `patient` launch context and the raw claims. `IssuerSet` routes tokens of
  several issuers; `Verifier` is the seam for another kind of check.
  `introspection::Introspector` checks an opaque token by RFC 7662 token
  introspection, under the product's client authentication or a bearer
  token, with a cache bounded by each response's `exp`.
- **`openehr`** (feature `openehr`): the SMART on openEHR scopes, parsed by
  `openehr::smart_scopes` and enforced with `openehr::granted` over the `template-`,
  `composition-` and `aql-` families, the product's `Honoured` flags per
  issuer or client, and `Caller::ehr_id` for the launch context's EHR.
- **`scope`**: the SMART on FHIR scopes, `patient/`, `user/` and `system/`
  with `cruds`, and `Caller::reach`, which answers `Compartment::Any`,
  `Compartment::Patient(id)` or `None` for a permission on a resource type.
  Both grammars coexist in one `scope` claim; the route table declares
  which one a route is checked against.
- **`roles`**: the roles a caller holds, `Caller::roles()`, read from the
  `roles`, `groups` and `entitlements` claims of RFC 9068 §2.2.3.1 or the
  paths each `[auth.issuer.<name>] role_claims` names, or granted to a Basic
  user by the product (`config::BasicGrants` with
  `PasswordStore::with_grants`, or `Caller::with_granted_roles` and
  `Caller::with_granted_scope` from its own data); the route
  table checks them with `Requirement::Role`, `AnyRole`, `WithoutRole` and
  `All`.
- **`kind`** and **`profile`**: who stands behind a token, read from its
  standard claims the same way for every issuer. An `[auth.issuer.<name>]`
  is a SMART authorization server unless it declares
  `kind = "federation"`; a product trusts FerroSMART with a table naming
  only its `issuer`. `Caller::kind` answers `System`, `Patient`,
  `Practitioner`, `PractitionerRole`, `RelatedPerson`, `Person`, `User`,
  `ExternalPerson` or `ExternalOrganisation`, and the last two arise only
  on a federation issuer. A user is named by the type of their `fhirUser`,
  `User` when the token names none. `Caller::actor` is the RFC 8693 actor beside the user,
  `Caller::patient` the launch context, and `Caller::represented` the
  patient a `RelatedPerson` acts for. A token that reads as none is refused
  as `Rejection::Unclassified`. A Basic credential is a user's, never a
  system's, and carries no `system/` scope: a Basic grant holding one fails
  to load.
- **One list of clients**: the authorization server's registry. A token
  from a trusted issuer whose `aud` names the resource server admits its
  client (RFC 9068 §4, RFC 8707), recorded as `Caller::client_id` for the
  product's own policy, and an RFC 8693 `act` is read as the issuer
  asserts it.
- **`party`**: the party a person's login belongs to. One `[auth.issuer.<name>.party]`
  table per SMART issuer names the identifiers its logins are matched
  against; the product implements `PartySource` over its own store, and
  `PartyBinding::resolve` (or `Gate::with_party` behind the guard) looks the
  token's `sub` up on every request, with no cache, into one
  `Outcome`: `Party`, `WrongMarker`, `Unbound`, `Ambiguous`, `Inactive`,
  `Abandoned`, `Deprovisioned`, `KeyClaimMissing` or `GroupsUnavailable`. A
  source failure is a `SourceError`, never no match.
- **`xml`** (feature `xml`): the bounded XML reader (a byte cap, a linear
  pre-scan of depth and namespace declarations, no DTD, a node cap) and the
  Exclusive XML Canonicalization an XML signature check reads its document
  through; `ehdsi-assertion` enables it.
- **`federation::assertion`** (feature `ehdsi-assertion`): the check an
  authorization server acting for a MyHealth@EU contact point runs on the
  eHDSI HP Identity Assertion and Treatment Relationship Confirmation. A
  `Validator` over `TrustedSigner`s (an issuer URI with its seal
  certificate) verifies the enveloped XML signature in one accepted shape,
  holds the signer and the signature to the SOG-IS ACM 1.3 floor, and checks
  the window, the audience, sender-vouches and the attributes of eHDSI SAML
  Profile 10.0.0 §2 and §4, with every instant held to the clock.
  `Validator::exchange` checks the identity assertion alone or with its
  TRC, and admits that exchange once through the `ReplayGuard` the product
  supplies (`MemoryReplayGuard` for one process). It returns an `Exchange`
  of an `IdentityAssertion` and a `TreatmentAssertion`, whose `Debug`
  carries no assertion content, with `ends()` capping the token's `exp`
  and `claim()` writing the contact-point token's `ehdsi` claim. Every
  refusal's `code()` is its §1.25 code name. The caller authenticates the
  presenting party as acting for the issuer, since sender-vouches names no
  presenter (eHDSI Messaging Profile 10.0.0 §5.5.2).
- **Feature `test-support`**, for a downstream crate's tests only:
  `federation::External::new` builds the party the two external caller
  kinds carry, which otherwise only a `federation` token yields.
- **The person's own access**: `Caller::is_the_person`, a `Patient` caller
  whose `fhirUser` is the patient in its launch context, with no actor, with `Caller::person` naming the patient the request is bound to and a
  deployment's patient claim attached as a `resource::PatientClaim`.
- **`assurance`**: the assurance level behind a token (`AssuranceSection`
  on each issuer, its claim mapped to low, substantial or high, a minimum
  and the RFC 9470 step-up refusal), read as `Caller::assurance`.
- **`basic`** and **`client`**: HTTP Basic against Argon2id hashes and sent
  outgoing, and the client credentials grant (`TokenSource`) with a cache,
  `client_secret_basic`, `client_secret_post` or `private_key_jwt`, and
  `call`, which renews the token once when the upstream answers `401`.
- **`audit`**: one line per request under the `tracing` target
  `ferrohealth_smart::audit`, with a fixed field set and never the token;
  what a request addressed is the `addressed` field, so a JSON log that
  flattens the fields keeps the `tracing` target beside it.
- **`resource::configuration`**: the SMART discovery document. The product
  declares the permission capabilities its route table enforces in
  `SmartOptions::permissions` (none is claimed by default), and
  `sso-openid-connect` with `issuer` is written only for an OpenID Connect
  issuer or on the product's declaration (`SmartOptions::openid_connect`).
- **`refusal`**: the status and `WWW-Authenticate` challenge of every
  refusal; the body is the product's, rendered from the refused request's
  head so it can follow the request's `Accept` or `_format`.
- **`config`**: the `[auth]` and `[<lane>.credentials]` sections a product
  embeds in its own configuration.
- **`oidc`** (feature `oidc`): the OpenID Connect relying-party client an
  operator console signs in with. `oidc::RelyingParty` builds the
  authorization request with `state`, `nonce` and a PKCE `S256` challenge,
  exchanges the code and checks the ID Token (OpenID Connect Core 1.0
  §3.1.3.7), refreshes the access token, revokes a token, and returns the
  end-session URL of RP-Initiated Logout. It keeps no state: the console
  stores the `PendingSignIn` and the tokens of the `SignedIn` it returns.

The HTTP fetchers (the issuer's metadata, the key set over its `jwks_uri`
and `client::cache::TokenSource`) sit behind the default `fetch` feature.
A product built with `default-features = false` links no HTTP client and
reads its key set from a `jwks_file`.

The `openehr-scopes` feature builds `openehr::smart_scopes`, the SMART on
openEHR scope grammar, which depends on nothing. Built for the browser
(`wasm32-unknown-unknown`), the grammar is the whole crate: the resource
server and its dependencies are left out, so a browser client parses a
scope string with the parser the resource server enforces it with:

```toml
ferrohealth-smart = { version = "=0.34.0", default-features = false, features = ["openehr-scopes"] }
```

With the `axum` feature, **`guard::AuthLayer`** runs the credential check,
the type-level scope check and the audit line in front of every route the
product's classifier describes, and **`extract`** hands a handler the
`Access` the layer admitted.

## Guarding a router

```rust,no_run
# #![allow(dead_code)]
use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use ferrohealth_smart::guard::{AuthLayer, Gate, Requirement, Target};
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::resource::{Access, ResourceServer, Settings, Verifier};
use ferrohealth_smart::scope::Permission;
use http::{Extensions, Method, Uri};

async fn read(access: Access) -> String {
    access
        .caller()
        .map_or(String::from("open"), |caller| caller.subject().to_owned())
}

fn classify(_method: &Method, uri: &Uri, _extensions: &Extensions) -> Option<Target> {
    let resource_type = uri.path().trim_start_matches("/fhir/").split('/').next()?;
    let requirement = Requirement::Fhir {
        permission: Permission::Read,
        resource_type: resource_type.to_owned(),
    };
    Some(
        Target::new("read", requirement)
            .route("/fhir/{resource_type}/{id}")
            .target(uri.path().trim_start_matches("/fhir/")),
    )
}

# async fn build() -> Result<Router, Box<dyn std::error::Error>> {
let settings = Settings::new(
    "https://as.example.org/realms/ferro",
    "https://bridge.example.org/fhir",
    IssuerKind::Smart,
);
let verifier: Arc<dyn Verifier> = Arc::new(ResourceServer::discover(settings).await?);
let gate = Gate::open().with_bearer(verifier).with_realm("ferrobridge");
let app = Router::new()
    .route("/fhir/{resource_type}/{id}", get(read))
    .layer(AuthLayer::new(gate, classify));
# Ok(app)
# }
```

An openEHR route declares `Requirement::OpenEhr { family, permission,
resource }` instead, checked against the SMART on openEHR grants with the
`Honoured` flags `Gate::with_honoured` reads for the caller. A handler holds
a `patient/` token to its patient with `Compartment::admits`, or to its EHR
with `Access::ehr_id`; a product scope neither grammar covers is read with
`Access::has_scope`; a product rule that needs more reads `Access::claims`.

## Calling an upstream

```rust,no_run
# #![allow(dead_code)]
use ferrohealth_smart::client::{ClientCredentials, Endpoint};
use ferrohealth_smart::client::cache::TokenSource;
use secrecy::SecretString;

# async fn call() -> Result<(), Box<dyn std::error::Error>> {
let grant = ClientCredentials::new(
    Endpoint::Issuer(String::from("https://as.example.org/realms/ferro")),
    String::from("ferrobridge"),
    SecretString::from("the-secret-from-a-file"),
);
let source = TokenSource::new(grant)?;
let response = source
    .call(|header| async move {
        reqwest::Client::new()
            .get("https://cdr.example.org/v1/ehr")
            .header(http::header::AUTHORIZATION, header)
            .send()
            .await
    })
    .await?;
# let _ = response;
# Ok(())
# }
```

The design of record, with every check cited to its specification section,
is `docs/architecture.md` in the repository.

## Licence

Business Source License 1.1, Licensor Cadasto B.V., converting to Apache 2.0
four years after each version.
