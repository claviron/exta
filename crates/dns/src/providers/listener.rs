//! Follow the hosting profile: PostgreSQL NOTIFY or SQLite fleet events.
//! Every process rebuilds its serving snapshot, including the writer.

use std::sync::Arc;

use async_trait::async_trait;
#[cfg(feature = "postgres")]
use claviron::db::{ChannelListener, Notice};
use claviron::runtime::registry::{Component, Error, Runnable, priority};
use claviron::runtime::{AppState, RunContext};
use tracing::info;

use super::dns::DnsProvider;
use crate::models::actions::Pool;

#[cfg(feature = "postgres")]
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
        (provider, _db): <Self as Component<AppState>>::Deps,
        state: AppState,
        context: RunContext,
    ) -> Result<(), Error> {
        if !provider.config_snapshot().enabled {
            return Ok(());
        }
        let store = provider.store()?;
        match store.pool {
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(_) => {
                use tokio::sync::broadcast::error::RecvError;
                let mut events =
                    state.events().subscribe::<super::event::DnsChanged>();
                // Subscribe before reading: close the gap between boot's
                // initial snapshot and the listener becoming runnable.
                provider.reload_from_database(&state).await?;
                info!("DNS listening for committed fleet changes");
                loop {
                    let received = tokio::select! {
                        _ = context.cancelled() => return Ok(()),
                        received = events.recv() => received,
                    };
                    match received {
                        Ok(_) | Err(RecvError::Lagged(_)) => {
                            provider.reload_from_database(&state).await.map_err(|error| {
                                Error::recoverable(format!("DNS fleet snapshot reload failed: {error}"))
                            })?;
                        }
                        Err(RecvError::Closed) => return Ok(()),
                    }
                }
            }
            #[cfg(feature = "postgres")]
            Pool::Postgres(pool) => {
                let mut channel = tokio::select! {
                    _ = context.cancelled() => return Ok(()),
                    channel = ChannelListener::open(&state, &pool, &[CHANNEL]) => channel,
                };
                info!("DNS listening on '{CHANNEL}'");
                loop {
                    let notice = tokio::select! {
                        _ = context.cancelled() => return Ok(()),
                        notice = channel.next() => notice,
                    };
                    match notice {
                        Notice::Changed(notifications) => tracing::debug!(
                            count = notifications.len(),
                            "DNS zone change"
                        ),
                        Notice::Resync => {
                            info!("DNS resync after a listener gap")
                        }
                    }
                    if let Err(error) =
                        provider.reload_from_database(&state).await
                    {
                        tracing::warn!("DNS reload failed: {error}");
                        channel.missed();
                    }
                }
            }
            #[cfg(not(feature = "postgres"))]
            Pool::Postgres(_) => Err(Error::msg(
                "DNS PostgreSQL listener requires the postgres feature",
            )),
        }
    }
}
