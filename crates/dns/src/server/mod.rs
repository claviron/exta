//! DNS server — UDP/53 binding instance that drives the listener
//! using the `DnsProvider` snapshot from the registry. Doesn't own
//! any state; the provider does. Activated by the `server` feature.

pub(crate) mod announce;
mod dns;
mod tcp;
mod udp;
pub(crate) mod xfr;

pub use dns::DnsServer;
pub use tcp::start_dns_tcp_server;
pub use udp::start_dns_server;
