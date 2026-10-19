//! AcmeService — the owner of `acme.yaml`.
//!
//! Holds an [`ArcSwapOption`] snapshot of [`crate::config::AcmeConfig`];
//! consumers (renewal task, cleanup task, gRPC ACME endpoint) resolve this
//! from the registry and pull the snapshot on demand. Congif reads the file:
//! it is prepared before boot and in the reload batch, applied here through
//! `configure`, and followed through `ConfigObserver` when the source is
//! watched. An absent file is the "ACME off" declaration: the snapshot is
//! `None` and the HTTP-01 directory publishes nothing.

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use claviron::http::acme::Http01ChallengeDirectory;
use claviron::runtime::congif::{
    self, ConfigFile, ConfigObserver, Configurable,
};
use claviron::runtime::registry::{Component, Reloadable, priority};
use claviron::runtime::{AppState, Register};
use tracing::info;

use crate::config::AcmeConfig;

/// What the ACME configuration file is called in the config directory.
pub const CONFIG_FILE: &str = "acme.yaml";

pub struct AcmeProvider {
    config_path: PathBuf,
    snapshot: ArcSwapOption<AcmeConfig>,
    http01_directory: Arc<Http01ChallengeDirectory>,
    worker: bool,
}

impl AcmeProvider {
    pub fn empty(
        config_path: PathBuf,
        http01_directory: Arc<Http01ChallengeDirectory>,
    ) -> Self {
        Self {
            config_path,
            snapshot: ArcSwapOption::empty(),
            http01_directory,
            worker: false,
        }
    }

    pub fn snapshot(&self) -> Option<Arc<AcmeConfig>> {
        self.snapshot.load_full()
    }

    fn apply(
        &self,
        config: &Option<AcmeConfig>,
    ) {
        match config {
            Some(cfg) => {
                self.http01_directory
                    .publish(Some(cfg.challenges_dir().clone()));
                self.snapshot.store(Some(Arc::new(cfg.clone())));
                if self.worker {
                    tracing::debug!(
                        "📦 AcmeService applied {}",
                        self.config_path.display()
                    );
                } else {
                    info!(
                        "📦 AcmeService applied {}",
                        self.config_path.display()
                    );
                }
            }
            None => {
                self.snapshot.store(None);
                self.http01_directory.publish(None);
                tracing::debug!(
                    path = %self.config_path.display(),
                    "acme.yaml not found; AcmeService running empty"
                );
            }
        }
    }
}

/// Registers the HTTP-01 challenge directory and the provider that
/// publishes into it, in every process.
impl Register<AppState> for AcmeProvider {
    fn register(state: &AppState) -> claviron::runtime::registry::Result<()> {
        let registry = state.registry_ref();
        state.bind_config_environment::<Self>()?;
        let http01_directory = Arc::new(Http01ChallengeDirectory::default());
        registry.insert(http01_directory.clone())?;
        registry.register(Arc::new(AcmeProvider {
            worker: state.is_worker(),
            ..AcmeProvider::empty(
                state.config_dir().join(CONFIG_FILE),
                http01_directory,
            )
        }))?;
        Ok(())
    }
}

#[async_trait]
impl Component<AppState> for AcmeProvider {
    type Deps = ();

    fn name(&self) -> &'static str {
        "AcmeService"
    }

    fn as_configurable(&self) -> Option<&dyn congif::ConfigRegistration> {
        Some(self)
    }

    fn as_reloadable(&self) -> Option<&dyn Reloadable<AppState>> {
        Some(self)
    }
}

#[async_trait]
impl Configurable for AcmeProvider {
    /// The document, or `None` for no document: ACME is opt-in by file.
    type Config = Option<AcmeConfig>;

    fn source(&self) -> ConfigFile {
        ConfigFile::yaml(&self.config_path)
    }

    fn absent_source(&self) -> Option<Option<AcmeConfig>> {
        Some(None)
    }

    async fn configure(
        &self,
        config: &Option<AcmeConfig>,
    ) -> congif::Result<()> {
        self.apply(config);
        Ok(())
    }

    fn as_config_observer(
        &self
    ) -> Option<&dyn ConfigObserver<Config = Self::Config>> {
        Some(self)
    }
}

#[async_trait]
impl ConfigObserver for AcmeProvider {
    async fn config_changed(
        &self,
        config: &Option<AcmeConfig>,
    ) -> congif::Result<()> {
        self.apply(config);
        Ok(())
    }
}

#[async_trait]
impl Reloadable<AppState> for AcmeProvider {
    fn priority(&self) -> Option<u8> {
        Some(priority::EARLY)
    }

    async fn reload(
        &self,
        state: &AppState,
    ) -> claviron::runtime::registry::Result<()> {
        let config = state.config_reader().snapshot::<Self>()?;
        self.apply(&config);
        Ok(())
    }
}

pub fn register(state: &AppState) -> claviron::runtime::registry::Result<()> {
    <AcmeProvider as Register<AppState>>::register(state)
}
