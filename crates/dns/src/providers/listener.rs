//! Reload the DNS snapshot when roma says a zone changed.
//!
//! roma's triggers send `dns_zone_changed` on every change to `dns.dns_zones`
//! or `dns.dns_records`, and move the zone's SOA serial in the same
//! transaction. Each process that serves DNS listens and reloads its own
//! snapshot; the master (or a single process) also sends NOTIFY, as a reload
//! always does. Workers never talk to the secondaries.
//!
//! The connection comes from the application's Postgres pool through
//! `claviron::db::ChannelListener`, like every Claviron listener: a dropped
//! connection is replaced, a gap is answered with a reload, and a database
//! that does not answer is waited for, never retried on a clock.

use std::sync::Arc;

use async_trait::async_trait;
use claviron::db::{ChannelListener, Notice};
use claviron::runtime::registry::{
    Component, Error as RegistryError, Runnable, priority,
};
use claviron::runtime::{AppState, RunContext};
use tracing::{debug, info, warn};

use super::dns::DnsProvider;

/// The channel roma's DNS triggers notify on.
const CHANNEL: &str = "dns_zone_changed";

#[derive(Default)]
pub struct DnsZoneListener;

#[async_trait]
impl Component<AppState> for DnsZoneListener {
    type Deps = (Arc<DnsProvider>, Option<Arc<claviron::db::DbService>>);

    fn name(&self) -> &'static str {
        "DnsZoneListener"
    }

    fn run_priority(&self) -> Option<u8> {
        Some(priority::LATE)
    }

    fn as_runnable(
        self: Arc<Self>
    ) -> Option<Arc<dyn Runnable<AppState, Self::Deps>>> {
        Some(self)
    }
}

#[async_trait]
impl Runnable<AppState, <Self as Component<AppState>>::Deps>
    for DnsZoneListener
{
    async fn run(
        self: Arc<Self>,
        (provider, db): <Self as Component<AppState>>::Deps,
        state: AppState,
        context: RunContext,
    ) -> Result<(), RegistryError> {
        if !provider.config_snapshot().enabled {
            return Ok(());
        }
        let pool = db.and_then(|db| db.postgres()).ok_or_else(|| {
            RegistryError::msg("DnsZoneListener: postgres pool unavailable")
        })?;

        let mut channel = tokio::select! {
            _ = context.cancelled() => return Ok(()),
            channel = ChannelListener::open(&state, &pool, &[CHANNEL]) => channel
        };
        info!("👂 DNS listening on '{CHANNEL}'");

        loop {
            let notice = tokio::select! {
                _ = context.cancelled() => break,
                notice = channel.next() => notice
            };
            // A reload reads every zone, so a change and a gap are handled
            // alike; several notifications that arrived together are one.
            match notice {
                Notice::Changed(notifications) => {
                    debug!(count = notifications.len(), "DNS zone change")
                }
                Notice::Resync => info!("DNS resync after a listener gap"),
            }
            if let Err(error) = provider.reload_from_database(&state).await {
                warn!("DNS reload failed: {error}");
                channel.missed();
            }
        }
        Ok(())
    }
}
