//! The domain service: the store, the configured registrars, and the
//! operations that join them. gRPC, the CLI and the scheduled tasks call
//! this and nothing below it.
//!
//! One process has one applied `domains.yaml`, so one registrar set lives
//! here; applying a configuration builds the next set and drains the pools
//! of the previous one. Reading the store never calls a registrar, and a
//! registrar call writes the store only in an operation whose name says so.

use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use claviron::db::DbService;
use claviron::runtime::AppState;
use futures_util::stream::{self, StreamExt};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

use crate::config::DomainsConfig;
use crate::registrar::{self, DomainInfo, Registrar, RegistrarRecord};
use crate::store::{
    self, Domain, DomainStatus, DomainStore, DomainTemplate, DomainWrite,
    Nameserver, PROV_CLAVIRON, PROV_CLOUDFLARE, PROV_GODADDY, PROV_NAMECHEAP,
};
use crate::templates::DomainTemplateData;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unknown registrar `{0}`")]
    UnknownRegistrar(String),
    #[error("registrar `{0}` is not configured")]
    NotConfigured(String),
    #[error("{0}")]
    Invalid(String),
    #[error("{0} is not in the store")]
    NotFound(String),
    #[error("{0}")]
    InUse(String),
    #[error(transparent)]
    Registrar(#[from] registrar::Error),
    #[error("store: {0}")]
    Database(#[from] sqlx::Error),
    #[error("the PostgreSQL pool for the hosting schema is unavailable")]
    StoreUnavailable,
}

pub type Result<T> = std::result::Result<T, Error>;

/// One registrar section of `domains.yaml` as the service sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrarEntry {
    pub name: &'static str,
    pub configured: bool,
    pub supports_registration: bool,
    pub supports_dns: bool,
    pub supports_glue: bool,
}

/// A registration template with its data decoded.
#[derive(Debug, Clone)]
pub struct TemplateRecord {
    pub id: i32,
    pub name: String,
    pub data: DomainTemplateData,
    pub updated_at: OffsetDateTime,
}

/// What one synchronization run did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub found: usize,
    pub skipped: usize,
    pub created: Vec<String>,
    pub updated: Vec<String>,
    pub failed: Vec<(String, String)>,
}

impl SyncReport {
    fn absorb(
        &mut self,
        other: SyncReport,
    ) {
        self.found += other.found;
        self.skipped += other.skipped;
        self.created.extend(other.created);
        self.updated.extend(other.updated);
        self.failed.extend(other.failed);
    }
}

/// The registrars one applied configuration built, with the token that
/// ends their pools.
struct RegistrarSet {
    by_name: BTreeMap<&'static str, Arc<dyn Registrar>>,
    cancel: CancellationToken,
}

impl Drop for RegistrarSet {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

static SET: std::sync::LazyLock<ArcSwap<RegistrarSet>> =
    std::sync::LazyLock::new(|| {
        ArcSwap::from_pointee(RegistrarSet {
            by_name: BTreeMap::new(),
            cancel: CancellationToken::new(),
        })
    });

/// Every registrar this build knows, in `domains.yaml` order.
const KNOWN: &[(&str, RegistrarEntry)] = &[
    #[cfg(feature = "godaddy")]
    (
        "godaddy",
        RegistrarEntry {
            name: "godaddy",
            configured: false,
            supports_registration: false,
            supports_dns: true,
            supports_glue: false,
        },
    ),
    #[cfg(feature = "namecheap")]
    (
        "namecheap",
        RegistrarEntry {
            name: "namecheap",
            configured: false,
            supports_registration: true,
            supports_dns: true,
            supports_glue: true,
        },
    ),
];

/// The store and the registrars, for one process.
pub struct Domains {
    store: DomainStore,
}

impl Domains {
    /// Build the next registrar set from an applied configuration. Pools of
    /// the previous set drain once the last holder lets go of it.
    pub fn apply(config: &DomainsConfig) -> std::result::Result<(), String> {
        let cancel = CancellationToken::new();
        let mut by_name: BTreeMap<&'static str, Arc<dyn Registrar>> =
            BTreeMap::new();
        #[cfg(feature = "godaddy")]
        if let Some(section) = &config.godaddy {
            let registrar = crate::godaddy::Godaddy::new(section)?;
            spawn_pool(registrar.transport(), cancel.child_token());
            by_name.insert("godaddy", Arc::new(registrar));
        }
        #[cfg(feature = "namecheap")]
        if let Some(section) = &config.namecheap {
            let registrar = crate::namecheap::Namecheap::new(section)?;
            spawn_pool(registrar.transport(), cancel.child_token());
            by_name.insert("namecheap", Arc::new(registrar));
        }
        SET.store(Arc::new(RegistrarSet { by_name, cancel }));
        Ok(())
    }

    /// The service over the hosting store the runtime's PostgreSQL pool
    /// reaches.
    pub fn from_state(state: &AppState) -> Result<Self> {
        let pool = state
            .registry_ref()
            .resolve::<DbService>()
            .and_then(|db| db.claviron_pool())
            .ok_or(Error::StoreUnavailable)?;
        Ok(Self { store: DomainStore::new(pool) })
    }

    pub fn with_store(store: DomainStore) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &DomainStore {
        &self.store
    }

    // ── registrars ────────────────────────────────────────────────────

    /// The registrars this build knows, configured or not.
    pub fn registrars() -> Vec<RegistrarEntry> {
        let set = SET.load();
        KNOWN
            .iter()
            .map(|(name, entry)| RegistrarEntry {
                configured: set.by_name.contains_key(name),
                ..entry.clone()
            })
            .collect()
    }

    pub fn registrar(name: &str) -> Result<Arc<dyn Registrar>> {
        let set = SET.load();
        if let Some(registrar) = set.by_name.get(name) {
            return Ok(registrar.clone());
        }
        if KNOWN.iter().any(|(known, _)| *known == name) {
            Err(Error::NotConfigured(name.to_owned()))
        } else {
            Err(Error::UnknownRegistrar(name.to_owned()))
        }
    }

    /// Every registrar that is configured right now.
    pub fn configured() -> Vec<Arc<dyn Registrar>> {
        SET.load().by_name.values().cloned().collect()
    }

    /// The registrar a stored domain names.
    fn registrar_of(
        &self,
        domain: &Domain,
    ) -> Result<Arc<dyn Registrar>> {
        let name = registrar_name(domain.registrar_id);
        if name.is_empty() {
            return Err(Error::Invalid(format!(
                "{} names registrar id {} which this build does not know",
                domain.name, domain.registrar_id
            )));
        }
        Self::registrar(name)
    }

    // ── store view ────────────────────────────────────────────────────

    pub async fn list(
        &self,
        registrar: Option<&str>,
        status: Option<DomainStatus>,
        expiring_within_days: Option<u32>,
    ) -> Result<Vec<Domain>> {
        let registrar_id = match registrar {
            None => None,
            Some(name) => Some(
                registrar_id(name)
                    .ok_or_else(|| Error::UnknownRegistrar(name.to_owned()))?,
            ),
        };
        let expires_before = expiring_within_days.map(|days| {
            OffsetDateTime::now_utc() + time::Duration::days(i64::from(days))
        });
        Ok(self
            .store
            .list_domains(registrar_id, status, expires_before)
            .await?)
    }

    pub async fn get(
        &self,
        name: &str,
    ) -> Result<Domain> {
        self.store
            .domain_by_name(name)
            .await?
            .ok_or_else(|| Error::NotFound(name.to_owned()))
    }

    // ── registrar view ────────────────────────────────────────────────

    pub async fn info(
        &self,
        registrar: &str,
        name: &str,
    ) -> Result<DomainInfo> {
        Ok(Self::registrar(registrar)?.domain(name).await?)
    }

    pub async fn contacts(
        &self,
        registrar: &str,
        name: &str,
    ) -> Result<crate::templates::Contacts> {
        Ok(Self::registrar(registrar)?.contacts(name).await?)
    }

    /// Record a domain the registrar already holds: its own dates,
    /// reference and status, never invented ones.
    pub async fn record(
        &self,
        registrar: &str,
        name: &str,
    ) -> Result<Domain> {
        let registrar = Self::registrar(registrar)?;
        let info = registrar.domain(name).await?;
        self.write(registrar.as_ref(), info).await
    }

    /// Re-read a stored domain from the registrar its row names and replace
    /// the row; how a renewal made at the registrar's panel reaches here.
    pub async fn refresh(
        &self,
        name: &str,
    ) -> Result<Domain> {
        let existing = self.get(name).await?;
        let registrar = self.registrar_of(&existing)?;
        let info = registrar.domain(&existing.name).await?;
        self.write(registrar.as_ref(), info).await
    }

    /// Renew at the registrar the row names, then record what it reports.
    pub async fn renew(
        &self,
        name: &str,
        years: u8,
    ) -> Result<Domain> {
        if !(1..=10).contains(&years) {
            return Err(Error::Invalid(
                "years must be between 1 and 10".into(),
            ));
        }
        let existing = self.get(name).await?;
        let registrar = self.registrar_of(&existing)?;
        let info = registrar.renew(&existing.name, years).await?;
        self.write(registrar.as_ref(), info).await
    }

    /// Register a new domain at a registrar from a stored template.
    pub async fn register(
        &self,
        registrar: &str,
        name: &str,
        template: &str,
        years: u8,
    ) -> Result<Domain> {
        if !(1..=10).contains(&years) {
            return Err(Error::Invalid(
                "years must be between 1 and 10".into(),
            ));
        }
        let registrar = Self::registrar(registrar)?;
        let template = self
            .store
            .template_by_name(template)
            .await?
            .ok_or_else(|| Error::NotFound(format!("template `{template}`")))
            .and_then(decode_template)?;
        let info = registrar.register(name, &template.data, years).await?;
        self.write(registrar.as_ref(), info).await
    }

    /// Turn a registrar's report into a store row.
    async fn write(
        &self,
        registrar: &dyn Registrar,
        info: DomainInfo,
    ) -> Result<Domain> {
        let name = registrar.name();
        let registered_at = info.registered_at.ok_or_else(|| {
            Error::Invalid(format!(
                "{name} did not report a registration date for {}",
                info.name
            ))
        })?;
        let expires_at = info.expires_at.ok_or_else(|| {
            Error::Invalid(format!(
                "{name} did not report an expiry date for {}",
                info.name
            ))
        })?;
        let reference = info.reference.ok_or_else(|| {
            Error::Invalid(format!(
                "{name} did not report a registration reference for {}",
                info.name
            ))
        })?;
        let status = domain_status(&info.status).ok_or_else(|| {
            Error::Invalid(format!(
                "{name} reports {} as `{}`, which the store cannot hold",
                info.name, info.status
            ))
        })?;
        let existing = self.store.domain_by_name(&info.name).await?;
        let dns_provider_id = self
            .infer_dns_provider(registrar, &info)
            .await?
            .or(existing.as_ref().and_then(|d| d.dns_provider_id));
        Ok(self
            .store
            .upsert_domain(DomainWrite {
                name: info.name,
                registrar_id: registrar.id(),
                register_ref: reference,
                dns_provider_id,
                status,
                registered_at,
                expires_at,
                auto_renew: info
                    .auto_renew
                    .or(existing.as_ref().map(|d| d.auto_renew))
                    .unwrap_or(true),
                whois_privacy: info
                    .whois_privacy
                    .or(existing.as_ref().map(|d| d.whois_privacy))
                    .unwrap_or(true),
            })
            .await?)
    }

    /// Which DNS provider a report points at: the registrar's own DNS when
    /// it says so, else the nameservers it listed.
    async fn infer_dns_provider(
        &self,
        registrar: &dyn Registrar,
        info: &DomainInfo,
    ) -> Result<Option<i32>> {
        if info.registrar_dns == Some(true) {
            return Ok(Some(registrar.id()));
        }
        let Some(servers) = info.nameservers.as_deref() else {
            return Ok(None);
        };
        let claviron =
            self.store.nameservers_for_provider(PROV_CLAVIRON).await?;
        Ok(infer_dns_provider(servers, &claviron))
    }

    // ── delegation ────────────────────────────────────────────────────

    pub async fn nameservers(
        &self,
        registrar: &str,
        name: &str,
    ) -> Result<Vec<String>> {
        Ok(Self::registrar(registrar)?.nameservers(name).await?)
    }

    /// Replace the delegation set; a stored domain's DNS provider follows.
    pub async fn set_nameservers(
        &self,
        registrar: &str,
        name: &str,
        nameservers: &[String],
    ) -> Result<Vec<String>> {
        if nameservers.is_empty() {
            return Err(Error::Invalid(
                "at least one nameserver is required".into(),
            ));
        }
        let registrar = Self::registrar(registrar)?;
        registrar.set_nameservers(name, nameservers).await?;
        let current = registrar.nameservers(name).await?;
        if let Some(existing) = self.store.domain_by_name(name).await? {
            let claviron =
                self.store.nameservers_for_provider(PROV_CLAVIRON).await?;
            self.store
                .set_dns_provider(
                    existing.id,
                    infer_dns_provider(&current, &claviron),
                )
                .await?;
        }
        Ok(current)
    }

    /// Delegate to the glue hosts `hosting.nameservers` lists for Claviron.
    pub async fn use_claviron_nameservers(
        &self,
        registrar: &str,
        name: &str,
    ) -> Result<Vec<String>> {
        let hosts: Vec<String> = self
            .store
            .nameservers_for_provider(PROV_CLAVIRON)
            .await?
            .into_iter()
            .map(|server| server.hostname)
            .collect();
        if hosts.is_empty() {
            return Err(Error::Invalid(
                "no Claviron nameserver is registered in hosting.nameservers"
                    .into(),
            ));
        }
        self.set_nameservers(registrar, name, &hosts).await
    }

    pub async fn create_glue(
        &self,
        registrar: &str,
        name: &str,
        host: &str,
        ip: &str,
    ) -> Result<()> {
        Ok(Self::registrar(registrar)?.create_glue(name, host, ip).await?)
    }

    pub async fn update_glue(
        &self,
        registrar: &str,
        name: &str,
        host: &str,
        ip: &str,
        old_ip: Option<&str>,
    ) -> Result<()> {
        Ok(Self::registrar(registrar)?
            .update_glue(name, host, ip, old_ip)
            .await?)
    }

    // ── registrar-hosted DNS ──────────────────────────────────────────

    pub async fn records(
        &self,
        registrar: &str,
        name: &str,
        record_type: &str,
    ) -> Result<Vec<RegistrarRecord>> {
        let mut records = Self::registrar(registrar)?.records(name).await?;
        if !record_type.is_empty() {
            records.retain(|record| {
                record.record_type.eq_ignore_ascii_case(record_type)
            });
        }
        Ok(records)
    }

    pub async fn replace_records(
        &self,
        registrar: &str,
        name: &str,
        records: &[RegistrarRecord],
    ) -> Result<Vec<RegistrarRecord>> {
        validate_records(records)?;
        let registrar = Self::registrar(registrar)?;
        registrar.replace_records(name, records).await?;
        Ok(registrar.records(name).await?)
    }

    pub async fn upsert_records(
        &self,
        registrar: &str,
        name: &str,
        records: &[RegistrarRecord],
    ) -> Result<Vec<RegistrarRecord>> {
        validate_records(records)?;
        if records.is_empty() {
            return Err(Error::Invalid("no records to upsert".into()));
        }
        let registrar = Self::registrar(registrar)?;
        registrar.upsert_records(name, records).await?;
        Ok(registrar.records(name).await?)
    }

    pub async fn remove_records(
        &self,
        registrar: &str,
        name: &str,
        record_type: &str,
        owner: &str,
    ) -> Result<Vec<RegistrarRecord>> {
        if record_type.is_empty() || owner.is_empty() {
            return Err(Error::Invalid(
                "record type and name are required".into(),
            ));
        }
        let registrar = Self::registrar(registrar)?;
        registrar.remove_records(name, record_type, owner).await?;
        Ok(registrar.records(name).await?)
    }

    // ── synchronization ───────────────────────────────────────────────

    /// Pull one registrar's domain list into the store, or every
    /// configured registrar's when `registrar` is `None`.
    pub async fn sync_domains(
        &self,
        registrar: Option<&str>,
    ) -> Result<SyncReport> {
        let registrars = match registrar {
            Some(name) => vec![Self::registrar(name)?],
            None => Self::configured(),
        };
        if registrars.is_empty() {
            return Err(Error::Invalid("no registrar is configured".into()));
        }
        let mut report = SyncReport::default();
        for registrar in registrars {
            report.absorb(self.sync_registrar(registrar.as_ref()).await?);
        }
        Ok(report)
    }

    async fn sync_registrar(
        &self,
        registrar: &dyn Registrar,
    ) -> Result<SyncReport> {
        let listed = registrar.domains().await?;
        let mut report =
            SyncReport { found: listed.len(), ..Default::default() };
        for info in listed {
            let name = info.name.clone();
            let before = self.store.domain_by_name(&name).await?;
            match self.write(registrar, info).await {
                Ok(saved) => match before {
                    None => report.created.push(name),
                    Some(previous)
                        if saved.updated_at > previous.updated_at =>
                    {
                        report.updated.push(name)
                    }
                    Some(_) => report.skipped += 1,
                },
                Err(error) => report.failed.push((name, error.to_string())),
            }
        }
        Ok(report)
    }

    /// Pull registrar-hosted records into the store: for one domain, or for
    /// every unexpired domain whose DNS provider is a configured registrar.
    /// Concurrency is each registrar's pool admission.
    pub async fn sync_records(
        &self,
        only: Option<&str>,
    ) -> Result<SyncReport> {
        if let Some(name) = only {
            let domain = self.get(name).await?;
            let provider = domain
                .dns_provider_id
                .map(registrar_name)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    Error::Invalid(format!(
                        "{name} has no registrar-hosted DNS provider recorded"
                    ))
                })?;
            let registrar = Self::registrar(provider)?;
            let mut report = SyncReport { found: 1, ..Default::default() };
            match self.sync_one_record_set(registrar.as_ref(), &domain).await {
                Ok(()) => report.updated.push(domain.name),
                Err(error) => {
                    report.failed.push((domain.name, error.to_string()))
                }
            }
            return Ok(report);
        }
        let mut report = SyncReport::default();
        for registrar in Self::configured() {
            let domains = self
                .store
                .domains_by_dns_provider(
                    registrar.id(),
                    OffsetDateTime::now_utc(),
                )
                .await?;
            report.found += domains.len();
            let registrar = registrar.as_ref();
            let results: Vec<(String, Result<()>)> = stream::iter(domains)
                .map(|domain| async move {
                    let outcome =
                        self.sync_one_record_set(registrar, &domain).await;
                    (domain.name, outcome)
                })
                .buffer_unordered(registrar.concurrency().max(1))
                .collect()
                .await;
            for (name, outcome) in results {
                match outcome {
                    Ok(()) => report.updated.push(name),
                    Err(error) => report.failed.push((name, error.to_string())),
                }
            }
        }
        Ok(report)
    }

    /// Infer the DNS provider of every stored domain that has none, from
    /// the delegation its registrar reports. Nothing else on the row moves.
    pub async fn sync_providers(&self) -> Result<SyncReport> {
        let domains = self.store.domains_without_dns_provider().await?;
        let claviron =
            self.store.nameservers_for_provider(PROV_CLAVIRON).await?;
        let mut report =
            SyncReport { found: domains.len(), ..Default::default() };
        let mut by_registrar: BTreeMap<&'static str, Vec<Domain>> =
            BTreeMap::new();
        for domain in domains {
            let name = registrar_name(domain.registrar_id);
            if name.is_empty() {
                report.failed.push((
                    domain.name,
                    format!("registrar id {} is unknown", domain.registrar_id),
                ));
                continue;
            }
            by_registrar.entry(name).or_default().push(domain);
        }
        for (name, domains) in by_registrar {
            let registrar = match Self::registrar(name) {
                Ok(registrar) => registrar,
                Err(error) => {
                    let message = error.to_string();
                    report.failed.extend(
                        domains.into_iter().map(|d| (d.name, message.clone())),
                    );
                    continue;
                }
            };
            let registrar = registrar.as_ref();
            let claviron = &claviron;
            let results: Vec<(String, Result<bool>)> = stream::iter(domains)
                .map(|domain| async move {
                    let outcome = async {
                        let servers =
                            registrar.nameservers(&domain.name).await?;
                        match infer_dns_provider(&servers, claviron) {
                            Some(provider) => {
                                self.store
                                    .set_dns_provider(domain.id, Some(provider))
                                    .await?;
                                Ok(true)
                            }
                            None => Ok(false),
                        }
                    }
                    .await;
                    (domain.name, outcome)
                })
                .buffer_unordered(registrar.concurrency().max(1))
                .collect()
                .await;
            for (domain, outcome) in results {
                match outcome {
                    Ok(true) => report.updated.push(domain),
                    Ok(false) => report.skipped += 1,
                    Err(error) => {
                        report.failed.push((domain, error.to_string()))
                    }
                }
            }
        }
        Ok(report)
    }

    async fn sync_one_record_set(
        &self,
        registrar: &dyn Registrar,
        domain: &Domain,
    ) -> Result<()> {
        let records = registrar.records(&domain.name).await?;
        let rows: Vec<_> = records.iter().map(store_row).collect();
        self.store.replace_dns_records(domain.id, &rows).await?;
        Ok(())
    }

    // ── templates ─────────────────────────────────────────────────────

    pub async fn templates(&self) -> Result<Vec<TemplateRecord>> {
        self.store.templates().await?.into_iter().map(decode_template).collect()
    }

    /// Insert or replace the template under `name`. A record list the
    /// stored template holds survives a write that carries none.
    pub async fn put_template(
        &self,
        name: &str,
        data: &DomainTemplateData,
    ) -> Result<TemplateRecord> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::Invalid("template name is required".into()));
        }
        let mut data = data.clone();
        if data.dns_records.is_none()
            && let Some(existing) = self.store.template_by_name(name).await?
            && let Ok(previous) = decode_template(existing)
        {
            data.dns_records = previous.data.dns_records;
        }
        let value = serde_json::to_value(&data)
            .map_err(|error| Error::Invalid(error.to_string()))?;
        decode_template(self.store.upsert_template(name, &value).await?)
    }

    pub async fn remove_template(
        &self,
        name: &str,
    ) -> Result<bool> {
        self.store.remove_template(name).await.map_err(|error| {
            if error
                .as_database_error()
                .is_some_and(|db| db.is_foreign_key_violation())
            {
                Error::InUse(format!(
                    "template `{name}` is still assigned to a registrar or domain"
                ))
            } else {
                Error::Database(error)
            }
        })
    }
}

fn spawn_pool(
    transport: crate::transport::SharedTransport,
    cancel: CancellationToken,
) {
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::spawn(async move { transport.run(cancel).await });
    }
}

/// The registrar name a `hosting.registrars` id stands for.
pub fn registrar_name(id: i32) -> &'static str {
    match id {
        PROV_GODADDY => "godaddy",
        PROV_NAMECHEAP => "namecheap",
        PROV_CLOUDFLARE => "cloudflare",
        PROV_CLAVIRON => "claviron",
        _ => "",
    }
}

/// The `hosting.registrars` id for a name, if the name is known.
pub fn registrar_id(name: &str) -> Option<i32> {
    match name {
        "godaddy" => Some(PROV_GODADDY),
        "namecheap" => Some(PROV_NAMECHEAP),
        "cloudflare" => Some(PROV_CLOUDFLARE),
        "claviron" => Some(PROV_CLAVIRON),
        _ => None,
    }
}

/// The store status a registrar's status word stands for.
fn domain_status(word: &str) -> Option<DomainStatus> {
    let word = word.trim().to_ascii_uppercase();
    match word.as_str() {
        "ACTIVE" | "OK" | "REGISTERED" => Some(DomainStatus::Active),
        "EXPIRED" => Some(DomainStatus::Expired),
        "SUSPENDED" | "LOCKED" | "HELD" => Some(DomainStatus::Suspended),
        "CANCELLED" | "FAILED" => Some(DomainStatus::Failed),
        _ if word.starts_with("PENDING") => Some(DomainStatus::Pending),
        _ if word.starts_with("TRANSFER") => Some(DomainStatus::Transferring),
        _ => None,
    }
}

/// Which DNS provider a delegation set points at, from the hostnames alone.
fn infer_dns_provider(
    nameservers: &[String],
    claviron: &[Nameserver],
) -> Option<i32> {
    if nameservers.is_empty() {
        return None;
    }
    let lower: Vec<String> = nameservers
        .iter()
        .map(|server| server.trim_end_matches('.').to_ascii_lowercase())
        .collect();
    let all = |predicate: &dyn Fn(&str) -> bool| {
        lower.iter().all(|server| predicate(server))
    };
    if !claviron.is_empty()
        && all(&|server| {
            claviron
                .iter()
                .any(|known| known.hostname.eq_ignore_ascii_case(server))
        })
    {
        return Some(PROV_CLAVIRON);
    }
    if all(&|server| server.ends_with(".domaincontrol.com")) {
        return Some(PROV_GODADDY);
    }
    if all(&|server| server.ends_with(".registrar-servers.com")) {
        return Some(PROV_NAMECHEAP);
    }
    if all(&|server| server.ends_with(".ns.cloudflare.com")) {
        return Some(PROV_CLOUDFLARE);
    }
    None
}

fn validate_records(records: &[RegistrarRecord]) -> Result<()> {
    for record in records {
        if record.record_type.is_empty() || record.name.is_empty() {
            return Err(Error::Invalid(
                "every record needs a type and a name".into(),
            ));
        }
        if record.value.is_empty() {
            return Err(Error::Invalid(format!(
                "record {} {} has no value",
                record.record_type, record.name
            )));
        }
    }
    Ok(())
}

fn store_row(record: &RegistrarRecord) -> store::DnsRecordWrite {
    let signed = |value: Option<u32>| value.and_then(|v| i32::try_from(v).ok());
    store::DnsRecordWrite {
        name: record.name.clone(),
        record_type: store::normalized_record_type(&record.record_type),
        ttl: i32::try_from(record.ttl).unwrap_or(i32::MAX),
        value: Some(record.value.clone()),
        priority: signed(record.priority),
        weight: signed(record.weight),
        port: signed(record.port),
        rdata: None,
    }
}

fn decode_template(template: DomainTemplate) -> Result<TemplateRecord> {
    let data = serde_json::from_value(template.data).map_err(|error| {
        Error::Invalid(format!(
            "template `{}` holds data this build cannot read: {error}",
            template.name
        ))
    })?;
    Ok(TemplateRecord {
        id: template.id,
        name: template.name,
        data,
        updated_at: template.updated_at,
    })
}
