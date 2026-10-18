//! The registrar contract: what every registrar integration answers, in
//! domains, nameservers, contacts and records, never in its own wire shapes.
//!
//! A registrar knows nothing about Claviron's store. It reports what it
//! holds; [`crate::Domains`] decides what to record. Fields a registrar does
//! not report stay `None` rather than defaulted.

use async_trait::async_trait;
use time::OffsetDateTime;

use crate::templates::{Contacts, DomainTemplateData};

/// A registrar's own record of one domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainInfo {
    pub name: String,
    /// The registrar's numeric reference for the registration.
    pub reference: Option<i64>,
    /// The registrar's own status word (`ACTIVE`, `Expired`, ...).
    pub status: String,
    pub registered_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub auto_renew: Option<bool>,
    pub whois_privacy: Option<bool>,
    pub nameservers: Option<Vec<String>>,
    /// The registrar says its own DNS serves the domain. Some list calls
    /// report this without listing the nameservers.
    pub registrar_dns: Option<bool>,
}

/// One record as the registrar's own DNS holds it; `name` is relative to
/// the domain, `@` at the apex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrarRecord {
    pub record_type: String,
    pub name: String,
    pub value: String,
    pub ttl: u32,
    pub priority: Option<u32>,
    pub weight: Option<u32>,
    pub port: Option<u32>,
}

impl RegistrarRecord {
    /// Two records address the same set when type and owner match.
    pub fn same_set(
        &self,
        other: &Self,
    ) -> bool {
        self.record_type.eq_ignore_ascii_case(&other.record_type)
            && self.name == other.name
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The registrar answered with its own error code.
    #[error("{registrar} {code}: {message}")]
    Api { registrar: &'static str, code: String, message: String },
    /// The registrar refused for rate; `retry_after` is what it declared.
    #[error("{registrar} rate limit reached")]
    RateLimited {
        registrar: &'static str,
        retry_after: Option<std::time::Duration>,
    },
    #[error("{registrar} HTTP {status}: {body}")]
    HttpStatus { registrar: &'static str, status: u16, body: String },
    #[error("{registrar} transport: {message}")]
    Transport { registrar: &'static str, message: String },
    #[error(
        "{registrar} returned a response this build cannot read: {message}"
    )]
    Decode { registrar: &'static str, message: String },
    #[error("{0}")]
    Invalid(String),
    #[error("{registrar} does not support {operation}")]
    Unsupported { registrar: &'static str, operation: &'static str },
    #[error("cancelled")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, Error>;

/// One registrar integration. Every method is a live call.
#[async_trait]
pub trait Registrar: Send + Sync {
    /// The key the registrar has in `domains.yaml` and `hosting.registrars`.
    fn name(&self) -> &'static str;

    /// The `hosting.registrars` / `hosting.dns_providers` id.
    fn id(&self) -> i32;

    /// How many requests the registrar admits at once, from its pool.
    fn concurrency(&self) -> usize;

    /// Every domain the account holds, as much detail as the list call gives.
    async fn domains(&self) -> Result<Vec<DomainInfo>>;

    async fn domain(
        &self,
        name: &str,
    ) -> Result<DomainInfo>;

    async fn contacts(
        &self,
        name: &str,
    ) -> Result<Contacts>;

    /// Register a new domain from a template. The default refuses.
    async fn register(
        &self,
        name: &str,
        _template: &DomainTemplateData,
        _years: u8,
    ) -> Result<DomainInfo> {
        let _ = name;
        Err(Error::Unsupported {
            registrar: self.name(),
            operation: "registration",
        })
    }

    /// Renew and report the domain as the registrar now holds it.
    async fn renew(
        &self,
        name: &str,
        years: u8,
    ) -> Result<DomainInfo>;

    async fn nameservers(
        &self,
        name: &str,
    ) -> Result<Vec<String>>;

    /// Full replacement of the delegation set.
    async fn set_nameservers(
        &self,
        name: &str,
        nameservers: &[String],
    ) -> Result<()>;

    /// A glue host under the domain. The default refuses.
    async fn create_glue(
        &self,
        name: &str,
        host: &str,
        ip: &str,
    ) -> Result<()> {
        let _ = (name, host, ip);
        Err(Error::Unsupported {
            registrar: self.name(),
            operation: "glue records",
        })
    }

    async fn update_glue(
        &self,
        name: &str,
        host: &str,
        ip: &str,
        old_ip: Option<&str>,
    ) -> Result<()> {
        let _ = (name, host, ip, old_ip);
        Err(Error::Unsupported {
            registrar: self.name(),
            operation: "glue records",
        })
    }

    /// The registrar's own record set for the domain.
    async fn records(
        &self,
        name: &str,
    ) -> Result<Vec<RegistrarRecord>>;

    /// Full replacement of the record set.
    async fn replace_records(
        &self,
        name: &str,
        records: &[RegistrarRecord],
    ) -> Result<()>;

    /// Replace the sets the request names; every other record stays. The
    /// default reads, merges and replaces, which is what registrars without
    /// a partial write offer.
    async fn upsert_records(
        &self,
        name: &str,
        records: &[RegistrarRecord],
    ) -> Result<()> {
        let mut current = self.records(name).await?;
        current.retain(|existing| {
            !records.iter().any(|record| record.same_set(existing))
        });
        current.extend(records.iter().cloned());
        self.replace_records(name, &current).await
    }

    /// Remove every record of one type and owner. The default reads,
    /// filters and replaces.
    async fn remove_records(
        &self,
        name: &str,
        record_type: &str,
        owner: &str,
    ) -> Result<()> {
        let current = self.records(name).await?;
        let kept: Vec<_> = current
            .iter()
            .filter(|record| {
                !(record.record_type.eq_ignore_ascii_case(record_type)
                    && record.name == owner)
            })
            .cloned()
            .collect();
        if kept.len() == current.len() {
            return Err(Error::Invalid(format!(
                "{name} has no {record_type} record named {owner}"
            )));
        }
        self.replace_records(name, &kept).await
    }
}

/// `@` for the apex, otherwise the owner without a trailing dot.
pub fn normalize_owner(name: &str) -> String {
    let trimmed = name.trim().trim_end_matches('.');
    if trimmed.is_empty() { "@".to_owned() } else { trimmed.to_owned() }
}

/// `example.com` → (`example`, `com`); registrars that key by SLD/TLD need it.
pub fn split_sld_tld(domain: &str) -> Result<(&str, &str)> {
    match domain.rsplit_once('.') {
        Some((sld, tld)) if !sld.is_empty() && !tld.is_empty() => {
            Ok((sld, tld))
        }
        _ => Err(Error::Invalid(format!(
            "`{domain}` is not a second-level domain"
        ))),
    }
}
