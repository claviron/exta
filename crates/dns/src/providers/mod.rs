//! DNS state provider — config + DB-derived snapshot + handler.
//!
//! Consumed by both the UDP listener (`crate::server::DnsServer`)
//! and the dedicated-host DoH binding. Doesn't bind any
//! socket; that's the server's job.

mod config;
mod dns;
mod handler;
#[cfg(feature = "postgres")]
mod listener;
mod resolver;
mod snapshot;

#[cfg(feature = "doh")]
pub use config::DohConfig;
pub use config::{CONFIG_FILE, DnsConfig, DnsConfigProvider};
pub use dns::DnsProvider;
pub use handler::DnsHandler;
#[cfg(feature = "postgres")]
pub use listener::DnsZoneListener;
pub use resolver::{DnsResolver, DnsResolverFactory};
pub(crate) use snapshot::convert_db_record_to_hickory;
pub use snapshot::{DnsSnapshot, Zone};
