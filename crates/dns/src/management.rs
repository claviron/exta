//! Operator mutations of the existing `dns.*` schema. Queries never run on
//! the DNS request path. Database triggers own SOA serials and notifications.

use hickory_proto::rr::Name;
use sqlx::FromRow;

pub use crate::models::actions::DnsStore;
use crate::models::records::DnsRecord;

#[derive(Debug, thiserror::Error)]
pub enum ManagementError {
    #[error("{0}")]
    Invalid(String),
    #[error("DNS entry not found")]
    NotFound,
    #[error("zone contains records; explicit cascade is required")]
    NonemptyZone,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}
pub type Result<T> = std::result::Result<T, ManagementError>;

#[cfg(test)]
#[path = "../tests/management.rs"]
mod tests;

#[derive(Debug, Clone, FromRow)]
pub struct Zone {
    pub id: i32,
    pub domain: String,
    pub soa_serial: i64,
    pub soa_refresh: i32,
    pub soa_retry: i32,
    pub soa_expire: i32,
    pub soa_minimum: i32,
    pub soa_mname: String,
    pub soa_rname: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, FromRow)]
pub struct Record {
    pub id: i32,
    pub zone_id: i32,
    pub name: String,
    #[sqlx(rename = "type")]
    pub record_type: String,
    pub value: String,
    pub ttl: i32,
    pub priority: Option<i32>,
    pub weight: Option<i32>,
    pub port: Option<i32>,
    pub enabled: bool,
}

fn invalid(message: impl ToString) -> ManagementError {
    ManagementError::Invalid(message.to_string())
}

fn domain(raw: &str) -> Result<String> {
    let name = Name::from_utf8(raw).map_err(invalid)?;
    if name.is_root() || name.is_wildcard() {
        return Err(invalid("zone/SOA name cannot be root or wildcard"));
    }
    Ok(name.to_ascii().trim_end_matches('.').to_ascii_lowercase())
}

impl Zone {
    pub fn validate(&mut self) -> Result<()> {
        self.domain = domain(&self.domain)?;
        self.soa_mname = domain(&self.soa_mname)?;
        self.soa_rname = domain(&self.soa_rname)?;
        if [self.soa_refresh, self.soa_retry, self.soa_expire, self.soa_minimum]
            .into_iter()
            .any(|n| n < 0)
        {
            return Err(invalid("SOA durations must be nonnegative"));
        }
        Ok(())
    }
}

impl Record {
    pub fn validate(
        &mut self,
        zone: &str,
    ) -> Result<()> {
        self.record_type = self.record_type.to_ascii_uppercase();
        if self.name.is_empty() || self.name.ends_with('.') {
            return Err(invalid(
                "record name must be @ or a zone-relative name",
            ));
        }
        if self.record_type == "MX" && self.priority.is_none() {
            return Err(invalid("MX priority is required"));
        }
        for n in [self.priority, self.weight, self.port].into_iter().flatten() {
            u16::try_from(n)
                .map_err(|_| invalid("record metadata must fit u16"))?;
        }
        if (self.record_type != "MX"
            && self.record_type != "SRV"
            && self.priority.is_some())
            || (self.record_type != "SRV"
                && (self.weight.is_some() || self.port.is_some()))
        {
            return Err(invalid(
                "metadata does not belong to this record type",
            ));
        }
        if self.record_type == "TXT" && self.value.len() > 255 {
            return Err(invalid(
                "TXT value exceeds the supported single-string limit",
            ));
        }
        let zone =
            Name::from_utf8(format!("{}.", domain(zone)?)).map_err(invalid)?;
        crate::providers::convert_db_record_to_hickory(
            &DnsRecord {
                name: self.name.clone(),
                record_type: self.record_type.clone(),
                value: self.value.clone(),
                ttl: self.ttl,
                priority: self.priority,
                weight: self.weight,
                port: self.port,
            },
            &zone,
        )
        .map_err(invalid)?;
        self.name = self.name.to_ascii_lowercase();
        Ok(())
    }
}

impl DnsStore {
    /// Ask existing database notification listeners to rebuild snapshots.
    /// This confirms publication, not listener/fleet completion.
    pub async fn request_reload(&self) -> Result<()> {
        sqlx::query("SELECT pg_notify('dns_zone_changed', '{}')")
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn list_zones(
        &self,
        enabled_only: bool,
    ) -> Result<Vec<Zone>> {
        Ok(sqlx::query_as("SELECT * FROM dns.dns_zones WHERE NOT $1 OR enabled ORDER BY domain")
            .bind(enabled_only).fetch_all(&self.pool).await?)
    }

    pub async fn get_zone(
        &self,
        name: &str,
    ) -> Result<Zone> {
        sqlx::query_as("SELECT * FROM dns.dns_zones WHERE domain=$1")
            .bind(domain(name)?)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(ManagementError::NotFound)
    }

    pub async fn save_zone(
        &self,
        mut zone: Zone,
        updating: bool,
    ) -> Result<Zone> {
        zone.validate()?;
        let sql = if updating {
            "UPDATE dns.dns_zones SET domain=$1,soa_refresh=$2,soa_retry=$3,soa_expire=$4,soa_minimum=$5,soa_mname=$6,soa_rname=$7,enabled=$8,updated_at=now() WHERE id=$9 RETURNING *"
        } else {
            "INSERT INTO dns.dns_zones (domain,soa_refresh,soa_retry,soa_expire,soa_minimum,soa_mname,soa_rname,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *"
        };
        let query = sqlx::query_as(sql)
            .bind(zone.domain)
            .bind(zone.soa_refresh)
            .bind(zone.soa_retry)
            .bind(zone.soa_expire)
            .bind(zone.soa_minimum)
            .bind(zone.soa_mname)
            .bind(zone.soa_rname)
            .bind(zone.enabled);
        let query = if updating { query.bind(zone.id) } else { query };
        query.fetch_optional(&self.pool).await?.ok_or(ManagementError::NotFound)
    }

    pub async fn remove_zone(
        &self,
        id: i32,
        cascade: bool,
    ) -> Result<String> {
        let mut tx = self.pool.begin().await?;
        // Parent lock excludes concurrent FK inserts until deletion commits.
        let zone: Zone = sqlx::query_as(
            "SELECT * FROM dns.dns_zones WHERE id=$1 FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ManagementError::NotFound)?;
        let nonempty: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM dns.dns_records WHERE zone_id=$1)",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        if nonempty && !cascade {
            return Err(ManagementError::NonemptyZone);
        }
        sqlx::query("DELETE FROM dns.dns_zones WHERE id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(zone.domain)
    }

    pub async fn list_records(
        &self,
        zone: &str,
        enabled_only: bool,
    ) -> Result<Vec<Record>> {
        let zone = self.get_zone(zone).await?;
        Ok(sqlx::query_as("SELECT * FROM dns.dns_records WHERE zone_id=$1 AND (NOT $2 OR enabled) ORDER BY name,type,id")
            .bind(zone.id).bind(enabled_only).fetch_all(&self.pool).await?)
    }

    pub async fn save_record(
        &self,
        zone: Option<&str>,
        mut record: Record,
    ) -> Result<(Record, Zone)> {
        let mut tx = self.pool.begin().await?;
        let updating = zone.is_none();
        let zone: Zone = if let Some(name) = zone {
            sqlx::query_as(
                "SELECT * FROM dns.dns_zones WHERE domain=$1 FOR UPDATE",
            )
            .bind(domain(name)?)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ManagementError::NotFound)?
        } else {
            sqlx::query_as("SELECT z.* FROM dns.dns_zones z JOIN dns.dns_records r ON r.zone_id=z.id WHERE r.id=$1 FOR UPDATE OF z")
                .bind(record.id).fetch_optional(&mut *tx).await?.ok_or(ManagementError::NotFound)?
        };
        record.validate(&zone.domain)?;
        // A CNAME must not coexist with another RRset (including zone-apex SOA).
        if record.enabled {
            if record.name == "@" && record.record_type == "CNAME" {
                return Err(invalid("zone apex cannot be CNAME"));
            }
            let conflict: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM dns.dns_records WHERE zone_id=$1 AND name=$2 AND enabled AND id<>$3 AND (type='CNAME' OR $4='CNAME'))")
                .bind(zone.id).bind(&record.name).bind(if updating { record.id } else { 0 }).bind(&record.record_type)
                .fetch_one(&mut *tx).await?;
            if conflict {
                return Err(invalid("CNAME conflicts with existing records"));
            }
        }
        let sql = if updating {
            "UPDATE dns.dns_records SET zone_id=$1,name=$2,type=$3,value=$4,ttl=$5,priority=$6,weight=$7,port=$8,enabled=$9,updated_at=now() WHERE id=$10 RETURNING *"
        } else {
            "INSERT INTO dns.dns_records(zone_id,name,type,value,ttl,priority,weight,port,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *"
        };
        let query = sqlx::query_as(sql)
            .bind(zone.id)
            .bind(record.name)
            .bind(record.record_type)
            .bind(record.value)
            .bind(record.ttl)
            .bind(record.priority)
            .bind(record.weight)
            .bind(record.port)
            .bind(record.enabled);
        let query = if updating { query.bind(record.id) } else { query };
        let record = query
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ManagementError::NotFound)?;
        let zone = sqlx::query_as("SELECT * FROM dns.dns_zones WHERE id=$1")
            .bind(zone.id)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok((record, zone))
    }

    pub async fn remove_record(
        &self,
        id: i32,
    ) -> Result<Zone> {
        let mut tx = self.pool.begin().await?;
        let zone: Zone = sqlx::query_as("SELECT z.* FROM dns.dns_zones z JOIN dns.dns_records r ON r.zone_id=z.id WHERE r.id=$1 FOR UPDATE OF z")
            .bind(id).fetch_optional(&mut *tx).await?.ok_or(ManagementError::NotFound)?;
        let removed = sqlx::query("DELETE FROM dns.dns_records WHERE id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        if removed.rows_affected() == 0 {
            return Err(ManagementError::NotFound);
        }
        let zone = sqlx::query_as("SELECT * FROM dns.dns_zones WHERE id=$1")
            .bind(zone.id)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(zone)
    }
}
