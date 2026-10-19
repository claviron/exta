use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
#[cfg(feature = "doh")]
use claviron::edge::Host;
use claviron::helpers::de::deserialize_bind_address;
use claviron::orbit::placement::{Dispatch, DispatchPolicy, Scope};
use claviron::runtime::congif::{
    self, ConfigFile, ConfigObserver, Configurable,
};
use claviron::runtime::registry::{
    Component, Error as RegistryError, Reloadable, priority,
};
use claviron::runtime::{AppState, Register};
use hickory_proto::rr::TSigner;
use serde::Deserialize;
use tracing::info;

/// What the DNS configuration file is called in the config directory.
pub const CONFIG_FILE: &str = "dns.yaml";

/// Single owner of `dns.yaml`, read by Congif: prepared before boot and in
/// the reload batch, applied here through `configure`, and followed through
/// `ConfigObserver` when the source is watched. `${NAME}` resolves against
/// the environment the runtime bound for it, never the live one: a TSIG
/// secret lives in the service's environment file, not in `dns.yaml`. The DNS
/// runtime reads the snapshot via `current()`; nobody else does file I/O.
#[derive(Debug)]
pub struct DnsConfigProvider {
    config_path: PathBuf,
    snapshot: ArcSwap<DnsConfig>,
}

impl DnsConfigProvider {
    pub fn new(state: &AppState) -> Self {
        Self::empty(state.config_dir().join(CONFIG_FILE))
    }

    pub fn empty(config_path: PathBuf) -> Self {
        Self {
            config_path,
            snapshot: ArcSwap::from_pointee(DnsConfig::default()),
        }
    }

    #[cfg(test)]
    pub(crate) fn replace_for_test(
        &self,
        config: DnsConfig,
    ) {
        self.snapshot.store(Arc::new(config));
    }

    /// Current dns config snapshot. Always returns — Congif applies the
    /// file before boot, or the defaults if `dns.yaml` is absent.
    pub fn current(&self) -> Arc<DnsConfig> {
        self.snapshot.load_full()
    }

    fn apply(
        &self,
        config: &DnsConfig,
    ) {
        self.snapshot.store(Arc::new(config.clone()));
        info!("📦 DnsConfigProvider applied {}", self.config_path.display());
    }
}

impl Register<AppState> for DnsConfigProvider {
    fn register(state: &AppState) -> claviron::runtime::registry::Result<()> {
        state.bind_config_environment::<Self>()?;
        state.registry_ref().register(Arc::new(Self::new(state)))?;
        Ok(())
    }
}

#[async_trait]
impl Component<AppState> for DnsConfigProvider {
    type Deps = ();

    fn name(&self) -> &'static str {
        "DnsConfigProvider"
    }

    fn as_reloadable(&self) -> Option<&dyn Reloadable<AppState>> {
        Some(self)
    }

    fn as_configurable(&self) -> Option<&dyn congif::ConfigRegistration> {
        Some(self)
    }
}

#[async_trait]
impl Configurable for DnsConfigProvider {
    type Config = DnsConfig;

    fn source(&self) -> ConfigFile {
        ConfigFile::yaml(&self.config_path)
    }

    /// Without the file DNS is off; `enabled: true` is how it is opted in.
    fn absent_source(&self) -> Option<DnsConfig> {
        Some(DnsConfig::default())
    }

    fn validate_config(
        &self,
        config: &DnsConfig,
    ) -> congif::Result<()> {
        if config.enabled {
            config
                .dispatch
                .validate_policy(config.dispatch_policy)
                .map_err(congif::Error::invalid)?;
        }
        config
            .check_secondaries()
            .map_err(|error| congif::Error::msg(error.to_string()))
    }

    async fn configure(
        &self,
        config: &DnsConfig,
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
impl ConfigObserver for DnsConfigProvider {
    async fn config_changed(
        &self,
        config: &DnsConfig,
    ) -> congif::Result<()> {
        self.apply(config);
        Ok(())
    }
}

#[async_trait]
impl Reloadable<AppState> for DnsConfigProvider {
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

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DnsConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Process placement of the UDP/TCP listener, not the DNS snapshot or DoH.
    #[serde(default)]
    pub scope: Scope,
    /// Fleet selection of the listener. One/Pool require a dispatcher and the
    /// listener-owned lease policy below.
    #[serde(default)]
    pub dispatch: Dispatch,
    #[serde(default)]
    pub dispatch_policy: Option<DispatchPolicy>,
    #[serde(
        default = "default_bind_address",
        deserialize_with = "deserialize_bind_address"
    )]
    pub address: SocketAddr,
    /// Optional HTTPS endpoint. Presence enables DoH for exactly one
    /// canonical vhost; the host must exist and have an SNI certificate.
    #[cfg(feature = "doh")]
    #[serde(default)]
    pub doh: Option<DohConfig>,
    /// TSIG keys by name, the name being what both ends call the key.
    #[serde(default)]
    pub tsig_keys: BTreeMap<String, TsigKeyConfig>,
    /// Secondary servers: who may transfer a zone (AXFR, and IXFR answered
    /// with the whole zone) and who is told when one changes (NOTIFY).
    #[serde(default)]
    pub secondaries: Vec<SecondaryConfig>,
}

/// One TSIG key, as a secondary's configuration names it.
#[derive(Clone, PartialEq, Deserialize)]
pub struct TsigKeyConfig {
    /// `hmac-sha256`, `hmac-sha384` or `hmac-sha512`.
    pub algorithm: String,
    /// Base64, as `tsig-keygen` and nsd write it.
    pub secret: String,
    /// Seconds a signature's time may differ from ours. RFC 8945 §10
    /// recommends 300, which is the default.
    #[serde(default = "default_tsig_fudge")]
    pub fudge: u16,
}

impl std::fmt::Debug for TsigKeyConfig {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("TsigKeyConfig")
            .field("algorithm", &self.algorithm)
            .field("secret", &"<redacted>")
            .field("fudge", &self.fudge)
            .finish()
    }
}

/// A secondary server: allowed to transfer with `key`, and sent NOTIFY
/// when `notify` is set.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SecondaryConfig {
    pub address: IpAddr,
    pub key: String,
    #[serde(default)]
    pub notify: bool,
    /// The zones this secondary serves, without the trailing dot. Empty is
    /// every zone; otherwise it is sent NOTIFY and may transfer only these.
    #[serde(default)]
    pub zones: Vec<String>,
}

impl SecondaryConfig {
    pub fn serves(
        &self,
        zone: &hickory_proto::rr::Name,
    ) -> bool {
        let zone = zone.to_ascii();
        let zone = zone.trim_end_matches('.');
        self.zones.is_empty()
            || self.zones.iter().any(|name| {
                name.trim_end_matches('.').eq_ignore_ascii_case(zone)
            })
    }
}

impl DnsConfig {
    /// The secondary at `address`, with its key ready to sign and verify.
    pub fn secondary(
        &self,
        address: IpAddr,
    ) -> Option<(&SecondaryConfig, claviron::runtime::registry::Result<TSigner>)>
    {
        let secondary = self
            .secondaries
            .iter()
            .find(|secondary| secondary.address == address)?;
        Some((secondary, self.signer(&secondary.key)))
    }

    /// Build the signer for a configured key.
    pub fn signer(
        &self,
        name: &str,
    ) -> claviron::runtime::registry::Result<TSigner> {
        use base64ct::{Base64, Encoding};
        use hickory_proto::rr::Name;
        use hickory_proto::rr::rdata::tsig::TsigAlgorithm;

        let key = self.tsig_keys.get(name).ok_or_else(|| {
            RegistryError::msg(format!("TSIG key '{name}' is not configured"))
        })?;
        let algorithm = match key.algorithm.to_ascii_lowercase().as_str() {
            "hmac-sha256" => TsigAlgorithm::HmacSha256,
            "hmac-sha384" => TsigAlgorithm::HmacSha384,
            "hmac-sha512" => TsigAlgorithm::HmacSha512,
            other => {
                return Err(RegistryError::msg(format!(
                    "TSIG key '{name}': unsupported algorithm '{other}'"
                )));
            }
        };
        let secret = Base64::decode_vec(key.secret.trim()).map_err(|_| {
            RegistryError::msg(format!(
                "TSIG key '{name}': secret is not base64"
            ))
        })?;
        let signer_name = Name::from_utf8(name).map_err(|e| {
            RegistryError::msg(format!("TSIG key name '{name}': {e}"))
        })?;
        TSigner::new(secret, algorithm, signer_name, key.fudge)
            .map_err(|e| RegistryError::msg(format!("TSIG key '{name}': {e}")))
    }

    /// Every secondary names a configured, usable key.
    fn check_secondaries(&self) -> claviron::runtime::registry::Result<()> {
        for secondary in &self.secondaries {
            self.signer(&secondary.key).map_err(|e| {
                RegistryError::msg(format!(
                    "secondary {}: {e}",
                    secondary.address
                ))
            })?;
        }
        Ok(())
    }
}

#[cfg(feature = "doh")]
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DohConfig {
    /// Canonical edge vhost key, not a request hostname or TLS SNI name.
    pub vhost: Host,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scope: Scope::Worker,
            dispatch: Dispatch::Each,
            dispatch_policy: None,
            address: default_bind_address(),
            #[cfg(feature = "doh")]
            doh: None,
            tsig_keys: BTreeMap::new(),
            secondaries: Vec::new(),
        }
    }
}

fn default_tsig_fudge() -> u16 {
    300
}

fn default_bind_address() -> SocketAddr {
    "0.0.0.0:53".parse().unwrap()
}

#[cfg(all(test, feature = "doh"))]
mod tests {
    use super::DnsConfig;

    #[test]
    fn parses_dedicated_doh_vhost() {
        let config: DnsConfig = serde_yaml::from_str(
            r#"
enabled: true
address: 127.0.0.1:5454
doh:
  vhost: dns
"#,
        )
        .expect("valid DNS config");

        assert!(config.enabled);
        assert_eq!(config.doh.expect("DoH config").vhost.to_string(), "dns");
    }

    #[test]
    fn doh_is_opt_in_at_runtime() {
        let config: DnsConfig = serde_yaml::from_str("enabled: true\n")
            .expect("valid DNS config without DoH");

        assert!(config.doh.is_none());
    }
}
