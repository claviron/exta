//! SQLx-backed snapshot loader for authoritative DNS data.

use sqlx::{FromRow, PgPool};

use super::records::DnsRecord;
use super::zones::{DnsSoa, DnsZone};

/// Narrow persistence handle for boot/reload snapshot reads.
///
/// SQLx row shapes remain private; callers receive plain DNS values.
#[derive(Clone)]
pub struct DnsStore {
    pub(crate) pool: PgPool,
}

impl DnsStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn load_zones(
        &self
    ) -> claviron::runtime::registry::Result<Vec<DnsZone>> {
        let rows = sqlx::query_as::<_, ZoneRecordRow>(
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
        )
        .fetch_all(&self.pool)
        .await
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
