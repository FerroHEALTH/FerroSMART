// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The grants of the token endpoint.
//!
//! SMART Backend Services' client credentials grant and the authorization
//! code grant (RFC 6749 §4.1.3, §4.4), with the client they identify and the
//! scope and audience they grant.

use serde_json::Map;

use crate::audit::{self};
use crate::clients::{Client, ClientKind, GrantType};
use crate::discovery::TOKEN_ROUTE;
use crate::form::Params;
use crate::server::AppState;

use super::assertion::authenticate;
use super::mint::{Authentication, Grant, Identity, mint};
use super::sender::{Confirmation, Presented};
use super::{Issued, Refusal, server_error};

/// The longest a Backend Services access token lives: five minutes, the
/// most SMART App Launch 2.2.0, Backend Services, Issue Access Token allows.
pub const BACKEND_LIFETIME: std::time::Duration = std::time::Duration::from_secs(300);

/// The client credentials grant (RFC 6749 §4.4; SMART App Launch 2.2.0,
/// Backend Services).
pub(super) async fn client_credentials(
    state: &AppState,
    form: &Params,
    presented: &Presented,
) -> Result<Issued, Refusal> {
    let client = authenticate(state, form).await?;
    let confirmation = presented.bind(&client)?;
    may_use(&client, GrantType::ClientCredentials)?;
    let scope = granted_scope(&client, form.get("scope"))?;
    let audience = audience(state, &client, form.get("resource"))?;
    mint(
        state,
        &client,
        Grant {
            subject: &client.client_id,
            audience: &audience,
            scope: &scope,
            fhir_user: None,
            code_hash: None,
            token_type: "bearer",
            // NOTE: SMART App Launch 2.2.0, Backend Services, Issue Access Token, the
            // `expires_in` value SHOULD NOT exceed 300.
            longest: Some(BACKEND_LIFETIME),
            identity: None,
            under: None,
            context: &Map::new(),
            // NOTE: RFC 9068 §2.2.3.1, roles are a person's; Backend Services has none.
            roles: &[],
            login: None,
            confirmation: &confirmation,
        },
    )
}

/// The authorization code grant (RFC 6749 §4.1.3; SMART App Launch 2.2.0,
/// Obtain access token): the client authenticated by its assertion, or a
/// public client named by `client_id`; the code its own, unexpired and
/// unused, for the same redirect URI, its PKCE verifier matching (RFC 7636
/// §4.6). A second use of a code is refused and revokes the tokens the
/// first issued, once the rest of the request holds (OAuth 2.1 draft
/// §4.1.3, §7.5.3).
pub(super) async fn authorization_code(
    from: std::net::IpAddr,
    state: &AppState,
    headers: &http::HeaderMap,
    form: &Params,
    presented: &Presented,
) -> Result<Issued, Refusal> {
    let (client, confirmation) = admitted(
        state,
        headers,
        form,
        presented,
        GrantType::AuthorizationCode,
    )
    .await?;
    let invalid = |description| Refusal {
        error: "invalid_grant",
        description,
    };
    let code = form
        .get("code")
        .ok_or(Refusal::request("the request carries no code"))?;
    let verifier = form
        .get("code_verifier")
        .ok_or(Refusal::request("the request carries no code_verifier"))?;
    let hash = crate::authorize::sha256(code);
    let (grant, redeemed) = state
        .store()
        .code(&hash)
        .await
        .map_err(|error| server_error("the code cannot be read", &error))?
        .ok_or(invalid("the code is unknown or expired"))?;
    issued_for(&client, &grant, form)?;
    // NOTE: RFC 7636 §4.1 and §4.6, a verifier of 43 to 128 unreserved characters
    // whose S256 is the challenge.
    let well_formed = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte));
    if !well_formed || ferrohealth_smart::oidc::challenge(verifier) != grant.code_challenge {
        return Err(invalid("the code_verifier does not match"));
    }
    let first = !redeemed
        && state
            .store()
            .redeem(&hash)
            .await
            .map_err(|error| server_error("the code cannot be redeemed", &error))?;
    if !first {
        let mut tx = state
            .store()
            .begin()
            .await
            .map_err(|error| server_error("the code's tokens cannot be revoked", &error))?;
        let revoked = tx
            .revoke_code(&hash)
            .await
            .map_err(|error| server_error("the code's tokens cannot be revoked", &error))?;
        let endpoint = state.settings().endpoint_url(TOKEN_ROUTE);
        state
            .audit()
            .commit_happening(
                tx,
                &audit::Happening {
                    event: audit::Event::CodeReused,
                    issuer: &state.settings().issuer,
                    client_id: Some(&client.client_id),
                    subject: Some(&grant.subject),
                    from,
                    endpoint: &endpoint,
                    details: vec![("revoked", revoked.to_string())],
                },
            )
            .await
            .map_err(|error| server_error("the code's tokens cannot be revoked", &error))?;
        return Err(invalid("the code was used before"));
    }
    let openid = grant.scope.split(' ').any(|scope| scope == "openid");
    let fhir_user = grant
        .fhir_user
        .as_deref()
        .filter(|_| grant.scope.split(' ').any(|scope| scope == "fhirUser"));
    let launch = crate::refresh::open(state, &client, &grant, presented).await?;
    let mut issued = mint(
        state,
        &client,
        Grant {
            subject: &grant.subject,
            audience: &grant.audience,
            scope: &grant.scope,
            fhir_user,
            code_hash: Some(&hash),
            token_type: "Bearer",
            longest: None,
            identity: openid.then(|| identity(&grant)),
            under: Some(&launch.grant_id),
            context: &launch.context,
            roles: &grant.roles,
            login: Some(Authentication {
                auth_time: Some(grant.auth_time),
                acr: grant.acr,
            }),
            confirmation: &confirmation,
        },
    )?;
    issued.response.refresh_token = launch.refresh_token;
    Ok(issued)
}

/// Checks that the code `grant` was issued to `client`, for the redirect URI
/// `form` carries, at a resource server the client's `resources` still
/// lists.
fn issued_for(client: &Client, grant: &crate::store::Code, form: &Params) -> Result<(), Refusal> {
    let invalid = |description| Refusal {
        error: "invalid_grant",
        description,
    };
    if grant.client_id != client.client_id {
        return Err(invalid("the code was issued to another client"));
    }
    // NOTE: RFC 8707 §2, the client's `resources` is read again, so a base taken
    // off its list is refused from the next request on.
    if !client.reaches(&grant.audience) {
        return Err(Refusal {
            error: "invalid_target",
            description: "the client may no longer name the code's resource server",
        });
    }
    // NOTE: RFC 6749 §4.1.3, the redirect URI is the one the request carried.
    if form.get("redirect_uri") != Some(grant.redirect_uri.as_str()) {
        return Err(invalid("the redirect_uri is not the request's"));
    }
    Ok(())
}

/// Returns what the ID Token of the code `grant` carries of the login.
fn identity(grant: &crate::store::Code) -> Identity<'_> {
    Identity {
        nonce: grant.nonce.as_deref(),
        auth_time: grant.auth_time,
        person: &grant.person_claims,
    }
}

/// Returns the refusal of a client that may not use the grant it asked for
/// (RFC 6749 §5.2).
pub(crate) const fn unauthorized_client() -> Refusal {
    Refusal {
        error: "unauthorized_client",
        description: "the client may not use this grant",
    }
}

/// Returns the client a token request for `grant` identifies, once it is
/// registered with the grant, and the `cnf` its token is bound to.
pub(crate) async fn admitted(
    state: &AppState,
    headers: &http::HeaderMap,
    form: &Params,
    presented: &Presented,
    grant: GrantType,
) -> Result<(Client, Confirmation), Refusal> {
    let client = identify(state, headers, form).await?;
    may_use(&client, grant)?;
    let confirmation = presented.bind(&client)?;
    Ok((client, confirmation))
}

/// Refuses `client` the grant `grant` unless it is registered with it.
pub(crate) fn may_use(client: &Client, grant: GrantType) -> Result<(), Refusal> {
    if client.grant_types.contains(&grant) {
        Ok(())
    } else {
        Err(unauthorized_client())
    }
}

/// Returns the client of `headers` and `form`: authenticated by its secret
/// (RFC 6749 §2.3.1) or its assertion, or a registered public client named
/// by `client_id`, which cannot
/// authenticate (RFC 6749 §2.1, §3.2.1; SMART App Launch 2.2.0, Refresh
/// access token, Request).
pub(crate) async fn identify(
    state: &AppState,
    headers: &http::HeaderMap,
    form: &Params,
) -> Result<Client, Refusal> {
    if let Some(presented) = super::secret::presented(headers, form)? {
        return super::secret::authenticate(state, presented).await;
    }
    if form.get("client_assertion").is_some() || form.get("client_assertion_type").is_some() {
        return authenticate(state, form).await;
    }
    let client_id = form
        .get("client_id")
        .ok_or(Refusal::client("the request names no client"))?;
    match state.store().client(client_id).await {
        Ok(Some(client)) if client.kind() == ClientKind::Public => Ok(client),
        Ok(_) => Err(Refusal::client(
            "the client is not a registered public client",
        )),
        Err(error) => Err(server_error("the client registry cannot be read", &error)),
    }
}

/// Returns the scope the client is granted: each requested scope its
/// registered ceiling lists, in the order requested, "to assure that the
/// scope requested is within the scope pre-authorized to the client" (SMART
/// App Launch 2.2.0, Backend Services, Evaluate Requested Access). A
/// request with no scope, or none within the ceiling, is refused
/// (`invalid_scope`, RFC 6749 §3.3, §5.2). A v1 scope is matched by its v2
/// form and granted as requested ([`crate::scopes`]).
fn granted_scope(client: &Client, requested: Option<&str>) -> Result<String, Refusal> {
    let invalid = |description| Refusal {
        error: "invalid_scope",
        description,
    };
    let requested = requested.ok_or(invalid("the request names no scope"))?;
    let mut granted: Vec<&str> = Vec::new();
    for scope in requested.split(' ').filter(|scope| !scope.is_empty()) {
        if crate::scopes::admits(&client.scopes, scope) && !granted.contains(&scope) {
            granted.push(scope);
        }
    }
    if granted.is_empty() {
        return Err(invalid("no requested scope is granted to the client"));
    }
    Ok(granted.join(" "))
}

/// Returns the token's audience: the resource server, or the patient index
/// of one (§13.32), the request names in `resource` (RFC 8707 §2), or the
/// one the client's `resources` lists when it lists one alone (RFC 9068
/// §3, a default audience). The issuer is a resource too, the introspection
/// endpoint's (`docs/architecture.md` §13.6 item 8); any other base the
/// client's `resources` does not list is `invalid_target` (§13.6 item 12).
fn audience(state: &AppState, client: &Client, resource: Option<&str>) -> Result<String, Refusal> {
    let settings = state.settings();
    let target = |description| Refusal {
        error: "invalid_target",
        description,
    };
    match (resource, client.resources.as_slice()) {
        (Some(named), _) if named == settings.issuer => Ok(settings.issuer.clone()),
        (Some(named), _) if !settings.serves(named) => {
            Err(target("the resource is not served by this issuer"))
        }
        (Some(named), _) if client.reaches(named) => Ok(named.to_owned()),
        (Some(_), _) => Err(target("the client may not name this resource server")),
        (None, [only]) => Ok(only.clone()),
        (None, _) => Err(target("the request names no resource")),
    }
}
