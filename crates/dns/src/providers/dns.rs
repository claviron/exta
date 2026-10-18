use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use claviron::runtime::registry::{
    Bootable, Component, Error as RegistryError, Reloadable,
};
use claviron::runtime::{AppState, Register};
use tracing::info;

use super::config::{DnsConfig, DnsConfigProvider};
use super::handler::DnsHandler;
use super::snapshot::DnsSnapshot;

/// DNS state provider.
///
/// Lifecycle: `Register` inserts an `empty()` instance holding the
/// `DnsConfigProvider` registered before it — only the in-process snapshot
/// slots are allocated. `Bootable::boot()` gates on `enabled`, then
/// uses the supplied `DbService`, builds the initial `DnsSnapshot` and the per-query
/// handler. Reload re-reads the snapshot from the DB; config refresh comes
/// via `DnsConfigProvider`'s own Congif source.
///
/// Doesn't bind any socket — `crate::server::DnsServer` does that
/// and resolves this provider through the registry.
#[derive(Clone)]
pub struct DnsProvider {
    state: AppState,
    config_provider: Arc<OnceLock<Arc<DnsConfigProvider>>>,
    snapshot: Arc<ArcSwapOption<DnsSnapshot>>,
    handler: Arc<ArcSwapOption<DnsHandler>>,
}

impl DnsProvider {
    pub fn empty(state: AppState) -> Self {
        Self {
            state,
            config_provider: Arc::default(),
            snapshot: Arc::default(),
            handler: Arc::default(),
        }
    }

    pub fn state(&self) -> &AppState {
        &self.state
    }

    /// Open the management store from the current runtime pool, never a
    /// second database connection configuration owned by the transport.
    pub fn store(
        &self
    ) -> claviron::runtime::registry::Result<crate::management::DnsStore> {
        if !self.config_snapshot().enabled {
            return Err(RegistryError::msg("DNS is disabled"));
        }
        Self::postgres_pool(&self.state).map(crate::management::DnsStore::new)
    }

    fn postgres_pool(
        state: &AppState
    ) -> claviron::runtime::registry::Result<sqlx::PgPool> {
        Self::pool_from(
            state.registry_ref().resolve::<claviron::db::DbService>(),
        )
    }

    fn pool_from(
        db: Option<Arc<claviron::db::DbService>>
    ) -> claviron::runtime::registry::Result<sqlx::PgPool> {
        #[cfg(feature = "postgres")]
        {
            db.and_then(|db| db.postgres()).ok_or_else(|| {
                RegistryError::msg("DNS postgres pool unavailable")
            })
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = db;
            Err(RegistryError::msg(
                "DNS persistence requires the `postgres` feature; SQLite DNS is not implemented",
            ))
        }
    }

    fn cfg_provider(&self) -> &DnsConfigProvider {
        self.config_provider
            .get()
            .expect("DnsProvider is registered with its DnsConfigProvider")
    }

    pub fn config_snapshot(&self) -> Arc<DnsConfig> {
        self.cfg_provider().current()
    }

    pub fn snapshot(&self) -> Option<Arc<DnsSnapshot>> {
        self.snapshot.load_full()
    }

    /// Get the current handler. Errors if `Bootable::boot()` hasn't
    /// populated the snapshot — `?`-friendly so callers can chain.
    pub fn handler(&self) -> claviron::runtime::registry::Result<DnsHandler> {
        self.handler.load_full().map(|h| (*h).clone()).ok_or_else(|| {
            RegistryError::msg("DnsProvider handler not initialised")
        })
    }

    /// Give the provider a configuration without a `dns.yaml`; the transfer
    /// tests name their secondary and key this way.
    #[cfg(test)]
    pub(crate) fn install_config_for_test(
        &self,
        config: DnsConfig,
    ) {
        let provider = DnsConfigProvider::empty(std::path::PathBuf::new());
        provider.replace_for_test(config);
        let _ = self.config_provider.set(Arc::new(provider));
    }

    /// Install a snapshot without a database; the resolver tests build zones
    /// by hand.
    #[cfg(test)]
    pub(crate) fn install_snapshot_for_test(
        &self,
        snapshot: DnsSnapshot,
    ) {
        let _ = self.install_snapshot(snapshot);
    }

    /// Install `snapshot`; returns the one it replaced and the new one.
    fn install_snapshot(
        &self,
        snapshot: DnsSnapshot,
    ) -> (Option<Arc<DnsSnapshot>>, Arc<DnsSnapshot>) {
        let domains = snapshot.domain_count();
        let record_sets = snapshot.record_set_count();
        let snap_arc = Arc::new(snapshot);
        let new_handler = DnsHandler::new(snap_arc.clone());
        let previous = self.snapshot.swap(Some(snap_arc.clone()));
        self.handler.store(Some(Arc::new(new_handler)));
        info!(
            "✅ DNS snapshot installed domains={} record_sets={}",
            domains, record_sets
        );
        (previous, snap_arc)
    }

    /// Tell the secondaries about zones whose serial moved on a reload. Once
    /// per fleet: the master (or a single process) sends, its workers do not.
    async fn notify_secondaries(
        &self,
        state: &AppState,
        installed: (Option<Arc<DnsSnapshot>>, Arc<DnsSnapshot>),
    ) {
        #[cfg(feature = "server")]
        if !state.is_worker() {
            let (before, after) = installed;
            crate::server::xfr::notify_changed(
                &self.config_snapshot(),
                before.as_deref(),
                &after,
            )
            .await;
        }
        #[cfg(not(feature = "server"))]
        let _ = (state, installed);
    }
}

/// Registers the provider in every process, after `DnsConfigProvider`, as
/// the DoH host binding when that feature is on.
impl Register<AppState> for DnsProvider {
    fn register(state: &AppState) -> claviron::runtime::registry::Result<()> {
        let registry = state.registry_ref();
        let cfg_provider =
            registry.resolve::<DnsConfigProvider>().ok_or_else(|| {
                RegistryError::msg(
                    "DnsProvider needs DnsConfigProvider: register it first",
                )
            })?;
        let provider = Arc::new(Self::empty(state.clone()));
        let _ = provider.config_provider.set(cfg_provider);
        #[cfg(feature = "doh")]
        claviron::edge::register_host_binding_provider(state, provider)?;
        #[cfg(not(feature = "doh"))]
        registry.register(provider)?;
        Ok(())
    }
}

#[async_trait]
impl Component<AppState> for DnsProvider {
    // A disabled declaration does not require a database registration.
    type Deps = (Option<Arc<claviron::db::DbService>>,);

    fn name(&self) -> &'static str {
        "DnsProvider"
    }

    fn as_bootable(&self) -> Option<&dyn Bootable<AppState, Self::Deps>> {
        Some(self)
    }

    fn validate(
        &self,
        state: &AppState,
    ) -> claviron::runtime::registry::Result<()> {
        #[cfg(feature = "doh")]
        {
            let config = self.config_snapshot();
            if config.enabled
                && let Some(doh) = config.doh.as_ref()
            {
                use claviron::edge::VhostResolver;
                use claviron::tls::CertResolver;

                let vhosts = state
                    .registry_ref()
                    .resolve::<VhostResolver>()
                    .ok_or_else(|| {
                        RegistryError::msg(
                            "DoH validation: VhostResolver unavailable",
                        )
                    })?;
                let snapshot = vhosts.snapshot();
                if snapshot.canonical_config(&doh.vhost).is_none() {
                    return Err(RegistryError::msg(format!(
                        "DoH vhost '{}' is not a configured canonical vhost key",
                        doh.vhost
                    )));
                }

                let certs = state
                    .registry_ref()
                    .resolve::<CertResolver>()
                    .ok_or_else(|| {
                        RegistryError::msg(
                            "DoH validation: CertResolver unavailable",
                        )
                    })?;
                let has_certificate = certs.contains(&doh.vhost.to_string())
                    || snapshot.alias_entries().any(|(hostname, canonical)| {
                        canonical == &doh.vhost
                            && certs.contains(&hostname.to_string())
                    });
                if !has_certificate {
                    return Err(RegistryError::msg(format!(
                        "DoH vhost '{}' has no loaded certificate for its hostnames",
                        doh.vhost
                    )));
                }
            }
        }

        #[cfg(not(feature = "doh"))]
        let _ = state;

        Ok(())
    }

    fn as_reloadable(&self) -> Option<&dyn Reloadable<AppState>> {
        Some(self)
    }
}

#[async_trait]
impl Bootable<AppState, <Self as Component<AppState>>::Deps> for DnsProvider {
    /// Reads the zones the database holds; nothing is bound here.
    async fn boot(
        &self,
        (db,): <Self as Component<AppState>>::Deps,
        _state: &AppState,
    ) -> claviron::runtime::registry::Result<()> {
        if !self.config_snapshot().enabled {
            return Ok(());
        }
        let pool = Self::pool_from(db)?;
        let store = crate::models::actions::DnsStore::new(pool);
        let snapshot = DnsSnapshot::from_store(&store).await?;
        // No NOTIFY here: at boot the listeners are not up yet. The server
        // announces the zones once its TCP listener is bound.
        let _ = self.install_snapshot(snapshot);
        info!("📦 DnsProvider booted");
        Ok(())
    }
}

#[cfg(feature = "doh")]
impl claviron::edge::HostBindingProvider for DnsProvider {
    fn match_host(
        &self,
        key: &claviron::edge::Host,
        _host: &claviron::edge::HostConfig,
    ) -> bool {
        let config = self.config_snapshot();
        config.enabled
            && config.doh.as_ref().is_some_and(|doh| &doh.vhost == key)
    }

    fn binding(
        &self,
        _key: &claviron::edge::Host,
        _host: Arc<claviron::edge::HostConfig>,
    ) -> claviron::runtime::registry::Result<Option<claviron::edge::RouteBinding>>
    {
        use axum::routing::any;
        use axum::{Extension, Router};
        use claviron::edge::RouteBinding;

        let provider = Arc::new(self.clone());
        Ok(Some(RouteBinding::Standalone(Arc::new(move |_state: AppState| {
            Router::new()
                .route("/dns-query", any(crate::doh::handle_doh_request))
                .layer(Extension(provider.clone()))
        }))))
    }
}

#[async_trait]
impl Reloadable<AppState> for DnsProvider {
    async fn reload(
        &self,
        state: &AppState,
    ) -> claviron::runtime::registry::Result<()> {
        self.reload_from_database(state).await
    }
}

impl DnsProvider {
    /// Re-read every zone, install the snapshot and, in the master or a
    /// single process, NOTIFY the secondaries of zones whose serial moved.
    /// A reload of the service and a change announced by the database both
    /// come here.
    pub(crate) async fn reload_from_database(
        &self,
        state: &AppState,
    ) -> claviron::runtime::registry::Result<()> {
        let cfg = self.cfg_provider().current();
        if !cfg.enabled {
            return Ok(());
        }

        info!("🔄 Reloading DNS records from database...");
        let pool = Self::postgres_pool(state)?;
        let store = crate::models::actions::DnsStore::new(pool);
        let snapshot = DnsSnapshot::from_store(&store).await?;
        let installed = self.install_snapshot(snapshot);
        self.notify_secondaries(state, installed).await;

        Ok(())
    }
}
