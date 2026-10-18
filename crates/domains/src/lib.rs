//! claviron-domains
//!
//! Registrar-held domains for a Claviron edge: the hosting store's domain
//! tables, the registrars `domains.yaml` configures, and the operations that
//! join them. [`Domains`] is the one entry point; gRPC, the CLI and the
//! scheduled tasks call it and nothing beneath it.
//!
//! Each registrar talks through its own Orbit client pool
//! ([`transport::Transport`]), whose envelope `domains.yaml` declares: how
//! many requests run at once, how long a request may take, and how long
//! admission pauses after a rate-limit answer. Nothing here invents a
//! duration or a limit.

use claviron::runtime::AppState;

pub mod config;
pub mod dns;
pub mod domains;
pub mod registrar;
pub mod store;
pub mod templates;
pub mod transport;

#[cfg(feature = "godaddy")]
pub mod godaddy;
#[cfg(feature = "namecheap")]
pub mod namecheap;
#[cfg(feature = "tasks")]
pub mod tasks;

pub use domains::{
    Domains, Error, RegistrarEntry, Result, SyncReport, TemplateRecord,
    registrar_id, registrar_name,
};
pub use store::{PROV_CLAVIRON, PROV_CLOUDFLARE, PROV_GODADDY, PROV_NAMECHEAP};

/// Register the owner of `domains.yaml`. The applied configuration builds
/// the registrar set every process reads; a missing file leaves every
/// registrar "not configured".
///
/// With the `tasks` feature this call also keeps the crate linked, so the
/// `#[task]` registrations stay discoverable through `inventory`.
pub fn register(state: &AppState) -> claviron::runtime::registry::Result<()> {
    use claviron::runtime::Register;
    config::DomainsConfigProvider::register(state)
}
