//! Announcing the zones to the secondaries once DNS is served.
//!
//! The authority speaks for the fleet: the master, or a single process. A
//! secondary answers NOTIFY by connecting for the transfer at once, and a
//! refused connection makes it back off for hours, so the announcement waits
//! until a socket accepts. Sockets are bound in `DnsServer::run` — never in
//! boot — so readiness comes from there: a worker that has bound its sockets
//! says so with a fleet event, and the master announces on the first one. A
//! single process announces itself right after binding.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use claviron::orbit::{FleetEventCodec, FleetEventRegistry};
use claviron::runtime::AppState;
use claviron::runtime::registry::Result;

use crate::providers::DnsProvider;

/// A worker's DNS sockets are bound and accepting.
#[derive(Clone, Debug)]
pub(crate) struct DnsListening {
    worker: u8,
}

impl claviron::runtime::Event for DnsListening {}

impl FleetEventCodec for DnsListening {
    const TOPIC: &'static str = "claviron.dns.listening.v1";

    fn encode_orbit(&self) -> Vec<u8> {
        vec![self.worker]
    }

    fn decode_orbit(bytes: &[u8]) -> std::result::Result<Self, String> {
        match bytes {
            [worker] => Ok(Self { worker: *worker }),
            _ => Err(format!(
                "dns listening payload: expected 1 byte, got {}",
                bytes.len()
            )),
        }
    }
}

/// Registration only — no task starts here. In a fleet the event crosses
/// Orbit from the workers to the master; the master announces once, on the
/// first worker that listens.
pub(crate) fn install(state: &AppState) -> Result<()> {
    if state.is_standalone() {
        return Ok(());
    }
    let events = state.registry_ref().resolve::<FleetEventRegistry>().ok_or_else(|| {
        claviron::runtime::registry::Error::msg(
            "claviron-dns in a fleet needs the Orbit FleetEventRegistry registered first"
        )
    })?;
    events.register_bridge::<DnsListening>(state)?;
    if state.is_master() {
        let announced = Arc::new(AtomicBool::new(false));
        state.events().listen::<DnsListening, _>(move |state, event| {
            let announced = announced.clone();
            async move {
                if !announced.swap(true, Ordering::SeqCst) {
                    tracing::debug!(
                        worker = event.worker,
                        "DNS served; announcing zones"
                    );
                    announce(&state).await;
                }
                Ok(())
            }
        })?;
    }
    Ok(())
}

/// Called by `DnsServer::run` once its sockets are bound.
pub(crate) async fn listening(state: &AppState) {
    match state.worker_id() {
        Some(worker) => state.events().emit(DnsListening { worker }),
        None if state.is_standalone() => announce(state).await,
        None => {}
    }
}

/// NOTIFY every zone to the secondaries.
async fn announce(state: &AppState) {
    let Some(provider) = state.registry_ref().resolve::<DnsProvider>() else {
        return;
    };
    let config = provider.config_snapshot();
    if let (true, Some(snapshot)) = (config.enabled, provider.snapshot()) {
        super::xfr::notify_changed(&config, None, &snapshot).await;
    }
}
