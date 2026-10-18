//! The hosting schema's domain tables, as the one place that writes SQL for
//! them: `hosting.domains`, `hosting.dns_records`, `hosting.nameservers` and
//! `hosting.domain_templates`.

use sqlx::{FromRow, PgPool};
use time::OffsetDateTime;

/// Seed ids of `hosting.registrars` and `hosting.dns_providers`; the names
/// are the keys `domains.yaml` uses.
pub const PROV_CLAVIRON: i32 = 2000;
pub const PROV_NAMECHEAP: i32 = 2001;
pub const PROV_CLOUDFLARE: i32 = 2002;
pub const PROV_GODADDY: i32 = 2003;

/// The `hosting.dns_record_type` value a registrar's type word maps to.
pub fn normalized_record_type(value: &str) -> String {
    match value.to_ascii_uppercase().as_str() {
        "A" | "AAAA" | "CNAME" | "MX" | "TXT" | "SRV" | "NS" | "CAA"
        | "HTTPS" | "SVCB" | "PTR" => value.to_ascii_uppercase(),
        _ => "UNKNOWN".to_owned(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainStatus {
    Pending,
    Active,
    Expired,
    Suspended,
    Transferring,
    Failed,
}

impl DomainStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Suspended => "suspended",
            Self::Transferring => "transferring",
            Self::Failed => "failed",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value {
            "pending" => Self::Pending,
            "expired" => Self::Expired,
            "suspended" => Self::Suspended,
            "transferring" => Self::Transferring,
            "failed" => Self::Failed,
            _ => Self::Active,
        }
    }
}

/// The store's error type, so adapters need not name the query library.
pub type Error = sqlx::Error;

#[derive(Clone, Debug)]
pub struct Domain {
    pub id: i32,
    pub name: String,
    pub registrar_id: i32,
    pub register_ref: i64,
    pub dns_provider_id: Option<i32>,
    pub template_id: Option<i32>,
    pub status: DomainStatus,
    pub registered_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub auto_renew: bool,
    pub renew_before_days: i32,
    pub whois_privacy: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Debug)]
pub struct DomainWrite {
    pub name: String,
    pub registrar_id: i32,
    pub register_ref: i64,
    pub dns_provider_id: Option<i32>,
    pub status: DomainStatus,
    pub registered_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub auto_renew: bool,
    pub whois_privacy: bool,
}

/// One row of `hosting.domain_templates`: the contacts, nameservers and
/// records a registration starts from, kept as the JSON the operator wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainTemplate {
    pub id: i32,
    pub name: String,
    pub data: serde_json::Value,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// One row of `hosting.nameservers`: a glue host a DNS provider answers on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nameserver {
    pub hostname: String,
    pub ip_address: String,
    pub provider_id: i32,
    pub is_master: bool,
}

#[derive(Clone, Debug)]
pub struct DnsRecordWrite {
    pub name: String,
    pub record_type: String,
    pub ttl: i32,
    pub value: Option<String>,
    pub priority: Option<i32>,
    pub weight: Option<i32>,
    pub port: Option<i32>,
    pub rdata: Option<serde_json::Value>,
}

#[derive(Clone)]
pub struct DomainStore {
    pool: PgPool,
}

impl DomainStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn domain_by_name(
        &self,
        name: &str,
    ) -> Result<Option<Domain>, sqlx::Error> {
        domain_query_by_name(&self.pool, name).await
    }

    /// Domains as the store records them, narrowed by registrar, status and
    /// an expiry bound; `None` leaves that dimension open.
    pub async fn list_domains(
        &self,
        registrar_id: Option<i32>,
        status: Option<DomainStatus>,
        expires_before: Option<OffsetDateTime>,
    ) -> Result<Vec<Domain>, sqlx::Error> {
        let rows = sqlx::query_as::<_, DomainRow>(
            "SELECT id, name, registrar_id, register_ref, dns_provider_id,
                    template_id, status::TEXT AS status, registered_at, expires_at,
                    auto_renew, renew_before_days, whois_privacy, created_at, updated_at
               FROM hosting.domains
              WHERE ($1::INT IS NULL OR registrar_id = $1)
                AND ($2::TEXT IS NULL OR status::TEXT = $2)
                AND ($3::TIMESTAMPTZ IS NULL OR expires_at <= $3)
              ORDER BY name"
        )
        .bind(registrar_id)
        .bind(status.map(DomainStatus::as_str))
        .bind(expires_before)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn templates(&self) -> Result<Vec<DomainTemplate>, sqlx::Error> {
        let rows = sqlx::query_as::<_, TemplateRow>(
            "SELECT id, name, data, created_at, updated_at
               FROM hosting.domain_templates ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn template_by_name(
        &self,
        name: &str,
    ) -> Result<Option<DomainTemplate>, sqlx::Error> {
        sqlx::query_as::<_, TemplateRow>(
            "SELECT id, name, data, created_at, updated_at
               FROM hosting.domain_templates WHERE name = $1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map(|row| row.map(Into::into))
    }

    /// Insert or replace a template's data under its name.
    pub async fn upsert_template(
        &self,
        name: &str,
        data: &serde_json::Value,
    ) -> Result<DomainTemplate, sqlx::Error> {
        sqlx::query_as::<_, TemplateRow>(
            "INSERT INTO hosting.domain_templates (name, data)
             VALUES ($1, $2)
             ON CONFLICT (name) DO UPDATE
                SET data = EXCLUDED.data, updated_at = NOW()
             RETURNING id, name, data, created_at, updated_at",
        )
        .bind(name)
        .bind(data)
        .fetch_one(&self.pool)
        .await
        .map(Into::into)
    }

    /// Remove a template; a registrar or domain still referencing it makes
    /// the database refuse, which the caller reports as such.
    pub async fn remove_template(
        &self,
        name: &str,
    ) -> Result<bool, sqlx::Error> {
        let result =
            sqlx::query("DELETE FROM hosting.domain_templates WHERE name = $1")
                .bind(name)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// The nameservers registered for one DNS provider, master first.
    pub async fn nameservers_for_provider(
        &self,
        provider_id: i32,
    ) -> Result<Vec<Nameserver>, sqlx::Error> {
        let rows = sqlx::query_as::<_, (String, String, i32, String)>(
            "SELECT hostname, ip_address, provider_id, role::TEXT
               FROM hosting.nameservers
              WHERE provider_id = $1
              ORDER BY (role = 'master') DESC, hostname",
        )
        .bind(provider_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(hostname, ip_address, provider_id, role)| Nameserver {
                hostname,
                ip_address,
                provider_id,
                is_master: role == "master",
            })
            .collect())
    }

    pub async fn domains_by_dns_provider(
        &self,
        provider_id: i32,
        expires_after: OffsetDateTime,
    ) -> Result<Vec<Domain>, sqlx::Error> {
        let rows = sqlx::query_as::<_, DomainRow>(
            "SELECT id, name, registrar_id, register_ref, dns_provider_id,
                    template_id, status::TEXT AS status, registered_at, expires_at,
                    auto_renew, renew_before_days, whois_privacy, created_at, updated_at
               FROM hosting.domains
              WHERE dns_provider_id = $1 AND expires_at > $2
              ORDER BY name"
        )
        .bind(provider_id)
        .bind(expires_after)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn domains_without_dns_provider(
        &self
    ) -> Result<Vec<Domain>, sqlx::Error> {
        let rows = sqlx::query_as::<_, DomainRow>(
            "SELECT id, name, registrar_id, register_ref, dns_provider_id,
                    template_id, status::TEXT AS status, registered_at, expires_at,
                    auto_renew, renew_before_days, whois_privacy, created_at, updated_at
               FROM hosting.domains
              WHERE dns_provider_id IS NULL
              ORDER BY name"
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn upsert_domain(
        &self,
        value: DomainWrite,
    ) -> Result<Domain, sqlx::Error> {
        sqlx::query_as::<_, DomainRow>(
            "INSERT INTO hosting.domains
                (name, registrar_id, dns_provider_id, register_ref, status,
                 registered_at, expires_at, auto_renew, whois_privacy)
             VALUES ($1, $2, $3, $4, $5::hosting.domain_status, $6, $7, $8, $9)
             ON CONFLICT (name) DO UPDATE SET
                 registrar_id = EXCLUDED.registrar_id,
                 dns_provider_id = EXCLUDED.dns_provider_id,
                 register_ref = EXCLUDED.register_ref,
                 status = EXCLUDED.status,
                 registered_at = EXCLUDED.registered_at,
                 expires_at = EXCLUDED.expires_at,
                 auto_renew = EXCLUDED.auto_renew,
                 whois_privacy = EXCLUDED.whois_privacy
             RETURNING id, name, registrar_id, register_ref, dns_provider_id,
                       template_id, status::TEXT AS status, registered_at, expires_at,
                       auto_renew, renew_before_days, whois_privacy, created_at, updated_at"
        )
        .bind(value.name)
        .bind(value.registrar_id)
        .bind(value.dns_provider_id)
        .bind(value.register_ref)
        .bind(value.status.as_str())
        .bind(value.registered_at)
        .bind(value.expires_at)
        .bind(value.auto_renew)
        .bind(value.whois_privacy)
        .fetch_one(&self.pool)
        .await
        .map(Into::into)
    }

    pub async fn update_expiry(
        &self,
        name: &str,
        expires_at: OffsetDateTime,
    ) -> Result<Option<Domain>, sqlx::Error> {
        sqlx::query_as::<_, DomainRow>(
            "UPDATE hosting.domains SET expires_at = $2
              WHERE name = $1
          RETURNING id, name, registrar_id, register_ref, dns_provider_id,
                    template_id, status::TEXT AS status, registered_at, expires_at,
                    auto_renew, renew_before_days, whois_privacy, created_at, updated_at"
        )
        .bind(name)
        .bind(expires_at)
        .fetch_optional(&self.pool)
        .await
        .map(|row| row.map(Into::into))
    }

    pub async fn set_dns_provider(
        &self,
        domain_id: i32,
        provider_id: Option<i32>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE hosting.domains SET dns_provider_id = $2 WHERE id = $1",
        )
        .bind(domain_id)
        .bind(provider_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn replace_dns_records(
        &self,
        domain_id: i32,
        records: &[DnsRecordWrite],
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM hosting.dns_records WHERE domain_id = $1")
            .bind(domain_id)
            .execute(&mut *tx)
            .await?;
        for record in records {
            sqlx::query(
                "INSERT INTO hosting.dns_records
                    (domain_id, name, type, ttl, value, priority, weight, port,
                     rdata, enabled, created_at, updated_at)
                 VALUES ($1, $2, $3::hosting.dns_record_type, $4, $5, $6, $7, $8,
                         $9, TRUE, NOW(), NOW())"
            )
            .bind(domain_id)
            .bind(&record.name)
            .bind(&record.record_type)
            .bind(record.ttl)
            .bind(&record.value)
            .bind(record.priority)
            .bind(record.weight)
            .bind(record.port)
            .bind(&record.rdata)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await
    }
}

#[derive(FromRow)]
struct TemplateRow {
    id: i32,
    name: String,
    data: serde_json::Value,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl From<TemplateRow> for DomainTemplate {
    fn from(row: TemplateRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            data: row.data,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(FromRow)]
struct DomainRow {
    id: i32,
    name: String,
    registrar_id: i32,
    register_ref: i64,
    dns_provider_id: Option<i32>,
    template_id: Option<i32>,
    status: String,
    registered_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    auto_renew: bool,
    renew_before_days: i32,
    whois_privacy: bool,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl From<DomainRow> for Domain {
    fn from(row: DomainRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            registrar_id: row.registrar_id,
            register_ref: row.register_ref,
            dns_provider_id: row.dns_provider_id,
            template_id: row.template_id,
            status: DomainStatus::parse(&row.status),
            registered_at: row.registered_at,
            expires_at: row.expires_at,
            auto_renew: row.auto_renew,
            renew_before_days: row.renew_before_days,
            whois_privacy: row.whois_privacy,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

async fn domain_query_by_name(
    pool: &PgPool,
    name: &str,
) -> Result<Option<Domain>, sqlx::Error> {
    sqlx::query_as::<_, DomainRow>(
        "SELECT id, name, registrar_id, register_ref, dns_provider_id,
                template_id, status::TEXT AS status, registered_at, expires_at,
                auto_renew, renew_before_days, whois_privacy, created_at, updated_at
           FROM hosting.domains WHERE name = $1"
    )
    .bind(name)
    .fetch_optional(pool)
    .await
    .map(|row| row.map(Into::into))
}
