<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# ferrohealth-session

The sign-in and the session of a FerroHEALTH operator console. The operator
signs in at the deployment's OpenID Provider with the authorization code
flow and PKCE, through the relying party of `ferrohealth-smart`, which keeps
no state; this crate keeps the pending sign-in between the redirect and the
callback, and the session once the sign-in completes.

| Module | Feature | What it holds |
|---|---|---|
| `config` | always | the `[oidc]` and `[session]` sections, `deny_unknown_fields`, every secret through `ferrohealth-secret`'s `<key>` / `<key>_file` rule |
| `sessions` | always | `Sessions`, the store: `memory` (bounded pools in the process, an opaque id in the cookie) or `sealed` (the whole record in one AES-256-GCM cookie, for a console that runs as several instances) |
| `clock` | always | `Clock`, what every lifetime is counted on (the wall clock by default), and `ManualClock` behind `test-clock`, a time a console's tests set and move and hand to `Sessions::with_clock` |
| `lifetime` | always | the idle and the absolute lifetime, the absolute one counted from the sign-in time, and what is left as FerroUI's session watch reads it |
| `refresh` | always | the renewal of an access token before it expires, one at a time per session |
| `record` | always | `SignedIn` (from an OpenID Connect sign-in or a Basic one the console checked), `Held`, `Session`, `Ended` |
| `routes` | `axum` | `GET /login`, `GET /auth/callback`, `POST /logout`, `GET`/`POST /session`, and the middleware every page sits behind |

```toml
[dependencies]
ferrohealth-session = { version = "=0.30.1", features = ["axum"] }

[dev-dependencies]
ferrohealth-session = { version = "=0.30.1", features = ["axum", "test-clock"] }
```

```toml
[oidc]
issuer = "https://idp.example.org/realms/console"
client_id = "console"
client_secret_file = "/run/secrets/oidc-client"
redirect_uri = "https://console.example.org/auth/callback"
# resolve = ["idp.internal=10.0.0.12:443"]     # a host reached at a fixed address
# timeout = "10s"                              # one call to the provider

# [oidc.tls]                                   # built by the console's TLS reader
# trust_roots_file = "/run/secrets/private-ca.pem"   # roots beside the platform's
# client_identity_file = "/run/secrets/console.pem"  # mutual TLS (RFC 8705 §2): chain and key
# min_version = "1.2"                          # the default is "1.3"

[session]
store = "memory"
idle_timeout = "30min"
absolute_timeout = "12h"
```

`[oidc] tls` is the family's outbound TLS table, and the crate reads no TLS
file: a console checks a section that names TLS material with
`OidcSection::check_with_tls`, handing it `ferrohealth-smart`'s
`config::ServerTls` (feature `server-tls`). Every duration is a whole
number and a unit (`"30min"`), and an unknown key is refused.

A `sealed` store needs `key` or `key_file` (base64 of at least 64 bytes, the
same on every instance) and refuses `offline_access`, so a refresh token is
never put in a browser cookie; both are refused when the configuration
loads.

```rust,ignore
use ferrohealth_session::cookies::CookieNames;
use ferrohealth_session::routes::{SignIn, keep_session, router};
use ferrohealth_session::sessions::Sessions;

let oidc = config.oidc.check()?;
let sessions = Sessions::new(config.session.check(&oidc)?, CookieNames::for_console("ferrobridge_console"));
let sign_in = SignIn::new(sessions, Some(oidc.relying_party().await?), ConsolePages);
let app = pages
    .layer(axum::middleware::from_fn_with_state(sign_in.clone(), keep_session::<ConsolePages>))
    .merge(router(sign_in));
```

Every page then reads the request's `record::Held` from its extensions.
`POST /logout` ends the session and removes its cookie whatever the
provider: a session signed in at the provider is sent to its end-session
endpoint with its ID Token as the hint. A session with no ID Token (a Basic
sign-in), a provider with no end-session endpoint, or no provider configured
at all redirects to the console's `Pages::signed_out`. A sign-out never answers `503`. The
console implements `routes::Pages` to draw a stopped sign-in in its own
locale, and keeps its stack's same-origin check in front of the two `POST`
routes.

## Licence

Business Source License 1.1 (`LICENSE` in the repository): free for every
non-production use and for non-commercial production use; a commercial
licence for other production use; Apache License 2.0 four years after each
version. The crate is hand-written code that implements the specifications
it cites, which is the family's rule for its own code.
