//! `domains.yaml`: registrar credentials and each registrar's outbound
//! envelope, read by Congif.
//!
//! `DomainsConfigProvider` owns the file: prepared before boot and in the
//! reload batch, followed through `ConfigObserver` when the source is
//! watched. `${ENV_KEY}` expands from the environment the runtime binds to
//! the owner, so no credential is read from the process environment at
//! request time. A missing file is an empty configuration: every registrar
//! is "not configured".
//!
//! ```yaml
//! godaddy:
//!   api_key: ${GODADDY_API_KEY}
//!   api_secret: ${GODADDY_API_SECRET}
//!   http:
//!     connect_timeout: 2s
//!     request_timeout: 30s
//!     rate_limit_pause: 60s
//!     pool: { min_idle: 0, max_idle: 2, max_live: 4, max_concurrency: 4, max_waiting: 64 }
//! namecheap:
//!   api_key: ${NAMECHEAP_API_KEY}
//!   username: ${NAMECHEAP_USERNAME}
//!   client_ip: ${NAMECHEAP_CLIENT_IP}
//!   http:
//!     connect_timeout: 2s
//!     request_timeout: 30s
//!     rate_limit_pause: 60s
//!     pool: { min_idle: 0, max_idle: 1, max_live: 1, max_concurrency: 1, max_waiting: 256 }
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use claviron::clients::PoolOptions;
use claviron::runtime::congif::{
    self, ConfigFile, ConfigObserver, Configurable,
};
use claviron::runtime::registry::{Component, Reloadable};
use claviron::runtime::{AppState, Register};
use serde::Deserialize;

use crate::Domains;

/// What the configuration file is called in the config directory.
pub const CONFIG_FILE: &str = "domains.yaml";

#[derive(Debug, Default, Deserialize, Clone, PartialEq)]
pub struct DomainsConfig {
    #[cfg(feature = "godaddy")]
    #[serde(default)]
    pub godaddy: Option<GodaddyConfig>,
    #[cfg(feature = "namecheap")]
    #[serde(default)]
    pub namecheap: Option<NamecheapConfig>,
}

impl DomainsConfig {
    pub fn validate(&self) -> Result<(), String> {
        #[cfg(feature = "godaddy")]
        if let Some(godaddy) = &self.godaddy {
            godaddy.http.validate("godaddy.http")?;
        }
        #[cfg(feature = "namecheap")]
        if let Some(namecheap) = &self.namecheap {
            namecheap.http.validate("namecheap.http")?;
        }
        Ok(())
    }
}

#[cfg(feature = "godaddy")]
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct GodaddyConfig {
    #[serde(default = "default_godaddy_url")]
    pub api_url: String,
    pub api_key: String,
    pub api_secret: String,
    pub http: HttpConfig,
}

#[cfg(feature = "godaddy")]
fn default_godaddy_url() -> String {
    "https://api.godaddy.com".to_string()
}

#[cfg(feature = "namecheap")]
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct NamecheapConfig {
    #[serde(default = "default_namecheap_url")]
    pub api_url: String,
    pub api_key: String,
    pub username: String,
    pub client_ip: String,
    pub http: HttpConfig,
}

#[cfg(feature = "namecheap")]
fn default_namecheap_url() -> String {
    "https://api.namecheap.com/xml.response".to_string()
}

/// One registrar's outbound envelope. Every duration is declared here; the
/// transport invents none.
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct HttpConfig {
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
    /// How long admission pauses after a rate-limit answer that names no
    /// `Retry-After`. Absent: no pause, the next caller sees the answer.
    #[serde(default, with = "humantime_serde")]
    pub rate_limit_pause: Option<Duration>,
    pub pool: Pool,
}

impl HttpConfig {
    fn validate(
        &self,
        block: &str,
    ) -> Result<(), String> {
        if self.connect_timeout.is_zero() || self.request_timeout.is_zero() {
            return Err(format!(
                "{block}: connect_timeout and request_timeout must be greater than zero"
            ));
        }
        self.pool.validate(&format!("{block}.pool"))
    }
}

/// An Orbit client pool's bounds, as a `pool:` block.
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct Pool {
    pub min_idle: usize,
    pub max_idle: usize,
    pub max_live: usize,
    pub max_concurrency: usize,
    pub max_waiting: usize,
    #[serde(default, with = "humantime_serde")]
    pub acquire_timeout: Option<Duration>,
    #[serde(default, with = "humantime_serde")]
    pub idle_timeout: Option<Duration>,
    #[serde(default, with = "humantime_serde")]
    pub max_lifetime: Option<Duration>,
}

impl Pool {
    pub fn validate(
        &self,
        block: &str,
    ) -> Result<(), String> {
        if self.max_live == 0 || self.max_concurrency == 0 {
            return Err(format!(
                "{block}: max_live and max_concurrency must be greater than zero"
            ));
        }
        if self.min_idle > self.max_idle || self.max_idle > self.max_live {
            return Err(format!(
                "{block}: min_idle <= max_idle <= max_live must hold"
            ));
        }
        Ok(())
    }

    pub fn options(&self) -> PoolOptions {
        PoolOptions::new(
            self.min_idle,
            self.max_idle,
            self.max_live,
            self.max_concurrency,
            self.max_waiting,
        )
        .acquire_timeout(self.acquire_timeout)
        .idle_timeout(self.idle_timeout)
        .max_lifetime(self.max_lifetime)
    }
}

/// The owner of `domains.yaml`. Every applied configuration becomes a new
/// registrar set in [`Domains`]; the previous set's pools drain.
pub struct DomainsConfigProvider {
    config_path: PathBuf,
}

impl DomainsConfigProvider {
    pub fn new(state: &AppState) -> Self {
        Self { config_path: state.config_dir().join(CONFIG_FILE) }
    }
}

impl Register<AppState> for DomainsConfigProvider {
    fn register(state: &AppState) -> claviron::runtime::registry::Result<()> {
        state.bind_config_environment::<Self>()?;
        state.registry_ref().register(Arc::new(Self::new(state)))?;
        Ok(())
    }
}

#[async_trait]
impl Component<AppState> for DomainsConfigProvider {
    type Deps = ();

    fn name(&self) -> &'static str {
        "DomainsConfigProvider"
    }

    fn as_configurable(&self) -> Option<&dyn congif::ConfigRegistration> {
        Some(self)
    }

    fn as_reloadable(&self) -> Option<&dyn Reloadable<AppState>> {
        Some(self)
    }
}

#[async_trait]
impl Configurable for DomainsConfigProvider {
    type Config = DomainsConfig;

    fn source(&self) -> ConfigFile {
        ConfigFile::yaml(&self.config_path)
    }

    /// No file: no registrar is configured.
    fn absent_source(&self) -> Option<DomainsConfig> {
        Some(DomainsConfig::default())
    }

    fn validate_config(
        &self,
        config: &DomainsConfig,
    ) -> congif::Result<()> {
        config.validate().map_err(congif::Error::invalid)
    }

    async fn configure(
        &self,
        config: &DomainsConfig,
    ) -> congif::Result<()> {
        Domains::apply(config).map_err(congif::Error::invalid)
    }

    fn as_config_observer(
        &self
    ) -> Option<&dyn ConfigObserver<Config = Self::Config>> {
        Some(self)
    }
}

#[async_trait]
impl ConfigObserver for DomainsConfigProvider {
    async fn config_changed(
        &self,
        config: &DomainsConfig,
    ) -> congif::Result<()> {
        Domains::apply(config).map_err(congif::Error::invalid)
    }
}

#[async_trait]
impl Reloadable<AppState> for DomainsConfigProvider {
    async fn reload(
        &self,
        state: &AppState,
    ) -> claviron::runtime::registry::Result<()> {
        let config = state.config_reader().snapshot::<Self>()?;
        Domains::apply(&config)
            .map_err(claviron::runtime::registry::Error::msg)?;
        Ok(())
    }
}
