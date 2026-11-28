// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The sender constraint of an issued access token.
//!
//! The key of a `DPoP` proof (RFC 9449 §5) and the certificate of a
//! mutual-TLS connection (RFC 8705 §3) are written into the token's `cnf`
//! (RFC 9449 §6.1, RFC 8705 §3.1).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;

use ferrohealth_server::tls::PeerCertificates;
use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrohealth_smart::resource::Rejection;
use ferrohealth_smart::sender::ClientCertificate;
use ferrohealth_smart::sender::proof::{DPOP, ProofCheck, ProofSettings};
use ferrohealth_smart::sender::replay::{ProofId, ReplayStore, ReplayStoreError};
use http::{HeaderMap, Method};
use serde::Serialize;

use crate::clients::{Client, ClientKind};
use crate::discovery::TOKEN_ROUTE;
use crate::server::AppState;
use crate::store::Store;

use super::{Refusal, server_error};

/// The issuer column the `jti` of a `DPoP` proof is recorded under in
/// `seen_jti`, apart from every client's assertions.
const DPOP_ISSUER: &str = "urn:ferrosmart:dpop";

/// The `DPoP` proofs and the client certificate a token request presents.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Presented {
    /// The JWK SHA-256 thumbprint of the `DPoP` proof's key, when the
    /// request carried a valid proof.
    pub(crate) jkt: Option<String>,
    /// The SHA-256 thumbprint of the connection's client certificate, when
    /// the connection presented one.
    pub(crate) certificate: Option<String>,
    /// The DER of that certificate, which mutual-TLS client authentication
    /// reads (RFC 8705 §2).
    pub(crate) leaf: Option<Vec<u8>>,
}

/// The `cnf` claim of an access token (RFC 7800 §3.1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Confirmation {
    /// The `DPoP` key's thumbprint (RFC 9449 §6.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) jkt: Option<String>,
    /// The client certificate's thumbprint (RFC 8705 §3.1).
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub(crate) certificate: Option<String>,
}

impl Confirmation {
    /// Returns whether the token is bound to nothing.
    pub(crate) const fn is_empty(&self) -> bool {
        self.jkt.is_none() && self.certificate.is_none()
    }
}

/// The `invalid_dpop_proof` refusal (RFC 9449 §5).
pub(crate) const fn invalid_proof() -> Refusal {
    Refusal {
        error: "invalid_dpop_proof",
        description: "the DPoP proof is invalid",
    }
}

/// Returns what the token request with `headers` over a connection that
/// presented `certificates` proves: its `DPoP` proof checked against the
/// token endpoint and its `jti` recorded once (RFC 9449 §4.3, §11.1), and
/// the leaf certificate's thumbprint.
pub(crate) async fn presented(
    state: &AppState,
    headers: &HeaderMap,
    certificates: Option<&PeerCertificates>,
) -> Result<Presented, Refusal> {
    let jkt = proof_key(state, headers, TOKEN_ROUTE).await?;
    let leaf = leaf_of(certificates);
    let certificate = leaf
        .as_deref()
        .map(|der| ClientCertificate::from_der(der).thumbprint().to_owned());
    Ok(Presented {
        jkt,
        certificate,
        leaf,
    })
}

/// Returns the DER of the leaf of the connection's `certificates`.
fn leaf_of(certificates: Option<&PeerCertificates>) -> Option<Vec<u8>> {
    certificates
        .and_then(|chain| chain.0.first())
        .map(|leaf| leaf.as_ref().to_vec())
}

/// Returns the DER of the leaf of the client certificates a handler's
/// extractor read from the request, which mutual-TLS client authentication
/// reads (RFC 8705 §2).
pub(crate) fn leaf(certificates: Option<axum::Extension<PeerCertificates>>) -> Option<Vec<u8>> {
    certificates.and_then(|axum::Extension(chain)| leaf_of(Some(&chain)))
}

/// Returns the JWK SHA-256 thumbprint of the key of the `DPoP` proof in
/// `headers`, checked as a `POST` to `route` with its `jti` recorded once
/// (RFC 9449 §4.3, §11.1), or none when the request carries no proof.
pub(crate) async fn proof_key(
    state: &AppState,
    headers: &HeaderMap,
    route: &str,
) -> Result<Option<String>, Refusal> {
    if !headers.contains_key(DPOP) {
        return Ok(None);
    }
    let check = ProofCheck::new(proof_settings(state.settings()), replays(state))
        .map_err(|error| server_error("the DPoP proof check cannot be built", &error))?;
    let proof = check
        .check_token_request(&Method::POST, route, headers)
        .map_err(|_refused| invalid_proof())?;
    check
        .consume(&proof)
        .await
        .map_err(|refused| match refused {
            Rejection::Upstream { source, .. } => {
                server_error("the DPoP proof cannot be recorded", &*source)
            }
            _ => invalid_proof(),
        })?;
    Ok(Some(proof.key().jkt().to_owned()))
}

impl Presented {
    /// Returns the `cnf` of a token issued to `client`: the `DPoP` key the
    /// request proved, and the client certificate when `client` asks for
    /// certificate-bound tokens.
    ///
    /// A client registered with `dpop_bound_access_tokens` that sent no
    /// proof is refused (RFC 9449 §5.2), and so is one registered with
    /// `tls_client_certificate_bound_access_tokens` whose connection
    /// presented no certificate, which RFC 8705 §3.4 leaves to the server.
    pub(crate) fn bind(&self, client: &Client) -> Result<Confirmation, Refusal> {
        if client.dpop_bound_access_tokens && self.jkt.is_none() {
            return Err(Refusal::request(
                "the client sends a DPoP proof with every token request",
            ));
        }
        let certificate = if client.tls_client_certificate_bound_access_tokens {
            Some(self.certificate.clone().ok_or(Refusal::request(
                "the client's tokens are bound to a certificate the connection did not present",
            ))?)
        } else {
            None
        };
        Ok(Confirmation {
            jkt: self.jkt.clone(),
            certificate,
        })
    }

    /// Returns the `DPoP` key a refresh token issued to `client` is bound
    /// to: the proof's key for a public client (RFC 9449 §5), none for a
    /// confidential one, which authenticates instead.
    pub(crate) fn refresh_key(&self, client: &Client) -> Option<String> {
        (client.kind() == ClientKind::Public)
            .then(|| self.jkt.clone())
            .flatten()
    }
}

/// Returns what FerroSMART checks a `DPoP` proof against.
///
/// Its issuer, and the algorithms of `ferrohealth-smart`'s defaults with
/// ML-DSA-44, ML-DSA-65 and ML-DSA-87 (RFC 9964) beside them, which RFC
/// 9449 §5.1 lets the server choose.
#[must_use]
pub fn proof_settings(settings: &crate::config::settings::Settings) -> ProofSettings {
    let mut proof = ProofSettings::new(settings.issuer_url.clone());
    proof
        .algorithms
        .extend([Algorithm::MlDsa44, Algorithm::MlDsa65, Algorithm::MlDsa87]);
    proof
}

/// Returns the record of the `DPoP` proofs seen, which every endpoint that
/// takes a proof shares.
pub(crate) fn replays(state: &AppState) -> Arc<dyn ReplayStore> {
    Arc::new(Replays(state.store().clone()))
}

/// The `DPoP` proofs seen, in the store every replica shares.
struct Replays(Store);

impl ReplayStore for Replays {
    fn first_use<'a>(
        &'a self,
        proof: &'a ProofId,
        until: SystemTime,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ReplayStoreError>> + Send + 'a>> {
        Box::pin(async move {
            let until = until
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
                .unwrap_or_default();
            self.0
                .first_use(DPOP_ISSUER, proof.as_str(), until)
                .await
                .map_err(ReplayStoreError::new)
        })
    }
}
