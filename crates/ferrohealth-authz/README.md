<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# ferrohealth-authz

The policy decision of the FerroHEALTH products. `ferrohealth-smart`
authenticates a caller and says who it is; `ferrohealth-authz` decides what
that subject may do with an object, in the vocabulary of NIST SP 800-162
(attribute-based access control: subject, object and environment attributes,
a policy decision point and the enforcement point that consults it).

| Module | Feature | What it holds |
|---|---|---|
| `request` | always | `Subject` (from `ferrohealth-smart`'s caller), `Request` with resource attributes that fan out, `Decision` with the policies that made it |
| `engine` | always | `PolicyEngine`, the trait every engine implements, and `AuthzError`, the answer of an engine that cannot decide |
| `cedar` | `cedar` | the embedded engine over the Cedar policy language, its schema written from the product's `Model` and its policies validated strictly before they run |
| `remote` | `remote` | a remote decision point over HTTP, authorized with `ferrohealth-smart`'s client credentials token |

```toml
[dependencies]
ferrohealth-authz = { version = "=0.28.0", features = ["cedar"] }
```

Without a feature the crate holds the request model and the trait alone,
with no policy engine and no HTTP client.

```rust,ignore
use ferrohealth_authz::cedar::{CedarEngine, Model};
use ferrohealth_authz::engine::PolicyEngine;
use ferrohealth_authz::request::{Attr, Request, Subject};

let model = Model::new()
    .subject_attribute("organization")
    .resource("Composition", ["patient", "template"])
    .action("composition.read", ["Composition"])
    .context("operation");
let engine = CedarEngine::from_directory(model, "/etc/policies".as_ref(), None)?;
let subject = Subject::of(&caller, &[("organization", "org_id")]);
let request = Request::new(&subject, "composition.read", "Composition")
    .with_attribute("patient", Attr::One(patient))?
    .with_context("operation", "composition_get");
if !engine.decide(&request).await?.is_permit() {
    // answer 403
}
```

An engine that cannot decide answers `AuthzError`; a product answers that as
a fault of its own (a `500`), never as a permit and never as a `403`.

## Licence

Business Source License 1.1 (`LICENSE` in the repository): free for every
non-production use and for non-commercial production use; a commercial
licence for other production use; Apache License 2.0 four years after each
version. The crate is hand-written code that implements the specifications
it cites, which is the family's rule for its own code.
