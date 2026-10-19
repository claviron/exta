//! SQLx-backed snapshot loader for authoritative DNS data.

use sqlx::{FromRow, PgPool};

use super::records::DnsRecord;
use super::zones::{DnsSoa, DnsZone};

#[cfg(all(test, feature = "sqlite"))]
#[path = "../../tests/store_sqlite.rs"]
mod sqlite_tests;

/// Persistence handle for DNS snapshot reads and management mutations.
///
/// SQLx row shapes remain private; callers receive plain DNS values.
#[derive(Clone)]
pub struct DnsStore {
    pub(crate) pool: Pool,
    announce: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

#[derive(Clone)]
pub(crate) enum Pool {
    Postgres(PgPool),
    #[cfg(feature = "sqlite")]
    Sqlite(sqlx::SqlitePool),
}

pub(crate) enum Tx {
    Postgres(sqlx::Transaction<'static, sqlx::Postgres>),
    #[cfg(feature = "sqlite")]
    Sqlite(sqlx::Transaction<'static, sqlx::Sqlite>),
}

impl Tx {
    pub(crate) async fn commit(self) -> Result<(), sqlx::Error> {
        match self {
            Self::Postgres(tx) => tx.commit().await,
            #[cfg(feature = "sqlite")]
            Self::Sqlite(tx) => tx.commit().await,
        }
    }
}

#[cfg(feature = "sqlite")]
pub(crate) fn sqlite(sql: &'static str) -> String {
    sql.replace("dns.dns_", "dns_")
        .replace(" FOR UPDATE OF z", "")
        .replace(" FOR UPDATE", "")
        .replace("now()", "strftime('%Y-%m-%dT%H:%M:%SZ', 'now')")
}

// All SQL comes from this crate's static statements; values remain bound.
macro_rules! run {
    ($store:expr, $query:ident, $sql:expr, [$($bind:expr),* $(,)?], $fetch:ident) => {
        match &$store.pool {
            $crate::models::actions::Pool::Postgres(pool) =>
                sqlx::$query(sqlx::AssertSqlSafe($sql))$(.bind($bind))*.$fetch(pool).await,
            #[cfg(feature = "sqlite")]
            $crate::models::actions::Pool::Sqlite(pool) =>
                sqlx::$query(sqlx::AssertSqlSafe($crate::models::actions::sqlite($sql)))$(.bind($bind))*.$fetch(pool).await,
        }
    };
}
pub(crate) use run;

macro_rules! run_tx {
    ($tx:expr, $query:ident, $sql:expr, [$($bind:expr),* $(,)?], $fetch:ident) => {
        match &mut $tx {
            $crate::models::actions::Tx::Postgres(tx) =>
                sqlx::$query(sqlx::AssertSqlSafe($sql))$(.bind($bind))*.$fetch(&mut **tx).await,
            #[cfg(feature = "sqlite")]
            $crate::models::actions::Tx::Sqlite(tx) =>
                sqlx::$query(sqlx::AssertSqlSafe($crate::models::actions::sqlite($sql)))$(.bind($bind))*.$fetch(&mut **tx).await,
        }
    };
}
pub(crate) use run_tx;

impl DnsStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool: Pool::Postgres(pool), announce: None }
    }

    #[cfg(feature = "sqlite")]
    pub fn sqlite(pool: sqlx::SqlitePool) -> Self {
        Self { pool: Pool::Sqlite(pool), announce: None }
    }

    /// Use the same named database profile as hosting; never a default fallback.
    #[cfg(feature = "service")]
    pub fn open(
        db: &claviron::db::DbService
    ) -> claviron::runtime::registry::Result<Self> {
        use claviron::runtime::registry::Error;
        let profile = db.hosting_profile();
        match db.profile(&profile).map_err(Error::msg)? {
            #[cfg(feature = "postgres")]
            claviron::db::Pool::Postgres(pool) => Ok(Self::new(pool)),
            #[cfg(feature = "sqlite")]
            claviron::db::Pool::Sqlite(pool) => Ok(Self::sqlite(pool)),
            #[allow(unreachable_patterns)]
            _ => Err(Error::msg(format!(
                "DNS hosting profile `{profile}` requires the matching postgres or sqlite feature"
            ))),
        }
    }

    #[cfg(feature = "sqlite")]
    pub(crate) fn announcing(
        mut self,
        announce: std::sync::Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        self.announce = Some(announce);
        self
    }

    pub(crate) fn changed(&self) {
        if let Some(announce) = &self.announce {
            announce();
        }
    }

    pub(crate) async fn begin(&self) -> Result<Tx, sqlx::Error> {
        Ok(match &self.pool {
            Pool::Postgres(pool) => Tx::Postgres(pool.begin().await?),
            // Reserve the writer before CNAME/conflict reads; no deferred
            // read-to-write upgrade can race another management writer.
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(pool) => {
                Tx::Sqlite(pool.begin_with("BEGIN IMMEDIATE").await?)
            }
        })
    }

    pub async fn load_zones(
        &self
    ) -> claviron::runtime::registry::Result<Vec<DnsZone>> {
        let rows: Vec<ZoneRecordRow> = run!(
            self,
            query_as,
            "SELECT z.domain,
                    z.soa_serial, z.soa_refresh, z.soa_retry, z.soa_expire,
                    z.soa_minimum, z.soa_mname, z.soa_rname,
                    r.name AS record_name,
                    r.type AS record_type,
                    r.value AS record_value,
                    r.ttl AS record_ttl,
                    r.priority AS record_priority,
                    r.weight AS record_weight,
                    r.port AS record_port
               FROM dns.dns_zones AS z
          LEFT JOIN dns.dns_records AS r
                 ON r.zone_id = z.id
                AND r.enabled = TRUE
              WHERE z.enabled = TRUE
              ORDER BY z.domain, r.id",
            [],
            fetch_all
        )
        .map_err(|error| {
            claviron::runtime::registry::Error::msg(format!(
                "failed to load DNS snapshot: {error}"
            ))
        })?;

        let mut zones = Vec::<DnsZone>::new();
        for row in rows {
            let needs_zone =
                zones.last().is_none_or(|zone| zone.domain != row.domain);
            if needs_zone {
                zones.push(DnsZone {
                    domain: row.domain.clone(),
                    soa: row.soa(),
                    records: Vec::new(),
                });
            }
            if let Some(record) = row.into_record() {
                zones
                    .last_mut()
                    .expect("zone inserted above")
                    .records
                    .push(record);
            }
        }
        Ok(zones)
    }
}

#[derive(FromRow)]
struct ZoneRecordRow {
    domain: String,
    soa_serial: i64,
    soa_refresh: i32,
    soa_retry: i32,
    soa_expire: i32,
    soa_minimum: i32,
    soa_mname: String,
    soa_rname: String,
    record_name: Option<String>,
    record_type: Option<String>,
    record_value: Option<String>,
    record_ttl: Option<i32>,
    record_priority: Option<i32>,
    record_weight: Option<i32>,
    record_port: Option<i32>,
}

impl ZoneRecordRow {
    fn soa(&self) -> DnsSoa {
        DnsSoa {
            serial: self.soa_serial,
            refresh: self.soa_refresh,
            retry: self.soa_retry,
            expire: self.soa_expire,
            minimum: self.soa_minimum,
            mname: self.soa_mname.clone(),
            rname: self.soa_rname.clone(),
        }
    }

    fn into_record(self) -> Option<DnsRecord> {
        Some(DnsRecord {
            name: self.record_name?,
            record_type: self.record_type?,
            value: self.record_value?,
            ttl: self.record_ttl?,
            priority: self.record_priority,
            weight: self.record_weight,
            port: self.record_port,
        })
    }
}
