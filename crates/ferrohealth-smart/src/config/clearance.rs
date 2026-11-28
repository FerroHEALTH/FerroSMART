// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The [`Clearance`] of a `trust_roots_file` table: one
//! `revocation::Clearing` per origin the configuration connects to, started
//! for each configured endpoint when the table is built and for any other
//! endpoint, such as a `jwks_uri` read from metadata, before the first
//! connection to it. No specification governs the clearance: our own design.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::Duration;

use ferrohealth_server::revocation::Clearing;
use ferrohealth_server::revocation::RevocationCheck;
use tokio::sync::OnceCell;

use crate::client::Clearance;

/// How long one endpoint's revocation check may take, as
/// `ferrohealth-server`'s telemetry clears its collector (no specification
/// governs the bound: our own design).
const CLEAR_WITHIN: Duration = Duration::from_secs(10);

/// The clearing of every origin a configuration connects to, by origin.
#[derive(Debug)]
pub(super) struct Origins {
    check: RevocationCheck,
    cleared: Mutex<BTreeMap<String, Arc<OnceCell<Clearing>>>>,
}

impl Origins {
    /// Returns the clearance over `check`, starting the clearing of each of
    /// `endpoints` on `runtime` at once.
    pub(super) fn new(
        check: RevocationCheck,
        runtime: Option<&tokio::runtime::Handle>,
        endpoints: &[url::Url],
    ) -> Arc<Self> {
        let origins = Arc::new(Self {
            check,
            cleared: Mutex::new(BTreeMap::new()),
        });
        if let Some(runtime) = runtime {
            for endpoint in endpoints {
                if let Some(cell) = origins.cell(endpoint) {
                    let check = origins.check.clone();
                    let endpoint = endpoint.clone();
                    runtime.spawn(async move {
                        cell.get_or_init(|| start(check, endpoint)).await;
                    });
                }
            }
        }
        origins
    }

    /// Returns the clearing cell of `endpoint`'s origin, or `None` for an
    /// endpoint no TLS handshake reaches.
    fn cell(&self, endpoint: &url::Url) -> Option<Arc<OnceCell<Clearing>>> {
        if endpoint.scheme() != "https" {
            return None;
        }
        let origin = endpoint.origin().ascii_serialization();
        let mut cleared = self.cleared.lock().unwrap_or_else(PoisonError::into_inner);
        Some(Arc::clone(cleared.entry(origin).or_default()))
    }
}

impl Clearance for Origins {
    fn clear<'a>(
        &'a self,
        endpoint: &'a url::Url,
    ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            if let Some(cell) = self.cell(endpoint) {
                cell.get_or_init(|| start(self.check.clone(), endpoint.clone()))
                    .await;
            }
        })
    }
}

/// Starts the clearing of `endpoint`, logging a first round that does not
/// clear it.
async fn start(check: RevocationCheck, endpoint: url::Url) -> Clearing {
    let (clearing, first) = Clearing::start(check, vec![endpoint], CLEAR_WITHIN).await;
    for (endpoint, outcome) in first {
        if let Err(error) = outcome {
            tracing::warn!(
                host = endpoint.host_str().unwrap_or_default(),
                port = endpoint.port_or_known_default(),
                error = %error,
                "an endpoint was not cleared for revocation, so its connections fail until it is"
            );
        }
    }
    clearing
}
