//! claviron-dns — DNS protocol + DB-propagate. Three flavours via
//! features:
//!
//! * (no features) — DNS protocol/data types only.
//! * `service` — adds the `provider` module (`DnsProvider`,
//!   `DnsConfigProvider`, `DnsHandler`, `DnsSnapshot`). DoH bridges
//!   need only this.
//! * `server` — adds the `server` module (`DnsServer`, UDP/53
//!   accept loop). Implies `service`.

pub(crate) mod models;

#[cfg(feature = "service")]
pub mod management;

#[cfg(feature = "service")]
pub mod providers;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "doh")]
pub mod doh;

#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub use providers::DnsZoneListener;
#[cfg(feature = "doh")]
pub use providers::DohConfig;
#[cfg(feature = "service")]
pub use providers::{
    DnsConfig, DnsConfigProvider, DnsHandler, DnsProvider, DnsResolver,
    DnsResolverFactory, DnsSnapshot,
};
#[cfg(feature = "server")]
pub use server::DnsServer;

/// Register DNS providers without I/O. The listener shares the registered
/// configuration owner; it does not load a second configuration.
///
/// Registers, in every process:
/// * `DnsConfigProvider` (always when `service` is on) — owns `dns.yaml`
///   through Congif.
/// * `DnsProvider` (always when `service` is on) — shared snapshot +
///   handler API consumed by both UDP and DoH.
/// * `DnsServer` (only when `server` is on) — Runnable that drives the
///   UDP/TCP accept loops; scope and dispatch come from `dns.yaml`.
#[cfg(feature = "service")]
pub fn register(
    state: &claviron::runtime::AppState
) -> claviron::runtime::registry::Result<()> {
    use claviron::runtime::Register;
    let registry = state.registry_ref();

    DnsConfigProvider::register(state)?;
    DnsProvider::register(state)?;

    #[cfg(feature = "upstream")]
    {
        use claviron::resolver::ResolverFactory;
        use std::sync::Arc;
        let dns = registry
            .resolve::<DnsProvider>()
            .expect("DNS provider registered above");
        registry.insert(Arc::new(DnsResolverFactory::new(
            dns.as_ref().clone(),
            None,
        )))?;
        registry.bind_dyn::<dyn ResolverFactory, DnsResolverFactory>(
            |factory| factory,
        )?;
    }

    // Every serving process follows the selected DB's notifications or fleet
    // events; see `providers::listener`.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    registry.register(std::sync::Arc::new(DnsZoneListener))?;
    #[cfg(not(any(feature = "postgres", feature = "sqlite")))]
    let _ = registry;

    #[cfg(feature = "server")]
    {
        let config =
            registry.resolve::<DnsConfigProvider>().ok_or_else(|| {
                claviron::runtime::registry::Error::msg(
                    "DnsServer requires its registered DnsConfigProvider",
                )
            })?;
        registry.register(std::sync::Arc::new(DnsServer::new(config)))?;
        server::announce::install(state)?;
    }

    Ok(())
}
