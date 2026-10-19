//! Operator mutations on the hosting DB's DNS tables, never the request path.
//! Triggers own SOA serials. PostgreSQL triggers publish NOTIFY; SQLite stores
//! announce fleet changes only after commit.

use hickory_proto::rr::Name;
use sqlx::FromRow;

pub use crate::models::actions::DnsStore;
use crate::models::actions::{Pool, run, run_tx};
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
    /// Ask database/fleet change listeners to rebuild snapshots.
    /// This confirms publication, not listener/fleet completion.
    pub async fn request_reload(&self) -> Result<()> {
        match &self.pool {
            Pool::Postgres(pool) => {
                sqlx::query("SELECT pg_notify('dns_zone_changed', '{}')")
                    .execute(pool)
                    .await?;
            }
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(_) => self.changed(),
        }
        Ok(())
    }
    pub async fn list_zones(
        &self,
        enabled_only: bool,
    ) -> Result<Vec<Zone>> {
        Ok(run!(
            self,
            query_as,
            "SELECT * FROM dns.dns_zones WHERE NOT $1 OR enabled ORDER BY domain",
            [enabled_only],
            fetch_all
        )?)
    }

    pub async fn get_zone(
        &self,
        name: &str,
    ) -> Result<Zone> {
        run!(
            self,
            query_as,
            "SELECT * FROM dns.dns_zones WHERE domain=$1",
            [domain(name)?],
            fetch_optional
        )?
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
        let mut tx = self.begin().await?;
        let saved: Option<Zone> = if updating {
            run_tx!(
                tx,
                query_as,
                sql,
                [
                    &zone.domain,
                    zone.soa_refresh,
                    zone.soa_retry,
                    zone.soa_expire,
                    zone.soa_minimum,
                    &zone.soa_mname,
                    &zone.soa_rname,
                    zone.enabled,
                    zone.id
                ],
                fetch_optional
            )?
        } else {
            run_tx!(
                tx,
                query_as,
                sql,
                [
                    &zone.domain,
                    zone.soa_refresh,
                    zone.soa_retry,
                    zone.soa_expire,
                    zone.soa_minimum,
                    &zone.soa_mname,
                    &zone.soa_rname,
                    zone.enabled
                ],
                fetch_optional
            )?
        };
        let saved = saved.ok_or(ManagementError::NotFound)?;
        // SQLite RETURNING precedes AFTER triggers, so read the committed
        // mutation's serial inside the same transaction before returning it.
        let saved = run_tx!(
            tx,
            query_as,
            "SELECT * FROM dns.dns_zones WHERE id=$1",
            [saved.id],
            fetch_one
        )?;
        tx.commit().await?;
        self.changed();
        Ok(saved)
    }

    pub async fn remove_zone(
        &self,
        id: i32,
        cascade: bool,
    ) -> Result<String> {
        let mut tx = self.begin().await?;
        // Parent lock excludes concurrent FK inserts until deletion commits.
        let zone: Zone = run_tx!(
            tx,
            query_as,
            "SELECT * FROM dns.dns_zones WHERE id=$1 FOR UPDATE",
            [id],
            fetch_optional
        )?
        .ok_or(ManagementError::NotFound)?;
        let nonempty: bool = run_tx!(
            tx,
            query_scalar,
            "SELECT EXISTS(SELECT 1 FROM dns.dns_records WHERE zone_id=$1)",
            [id],
            fetch_one
        )?;
        if nonempty && !cascade {
            return Err(ManagementError::NonemptyZone);
        }
        let _: Option<i32> = run_tx!(
            tx,
            query_scalar,
            "DELETE FROM dns.dns_zones WHERE id=$1 RETURNING id",
            [id],
            fetch_optional
        )?;
        tx.commit().await?;
        self.changed();
        Ok(zone.domain)
    }

    pub async fn list_records(
        &self,
        zone: &str,
        enabled_only: bool,
    ) -> Result<Vec<Record>> {
        let zone = self.get_zone(zone).await?;
        Ok(run!(
            self,
            query_as,
            "SELECT * FROM dns.dns_records WHERE zone_id=$1 AND (NOT $2 OR enabled) ORDER BY name,type,id",
            [zone.id, enabled_only],
            fetch_all
        )?)
    }

    pub async fn save_record(
        &self,
        zone: Option<&str>,
        mut record: Record,
    ) -> Result<(Record, Zone)> {
        let mut tx = self.begin().await?;
        let updating = zone.is_none();
        let zone: Zone = if let Some(name) = zone {
            run_tx!(
                tx,
                query_as,
                "SELECT * FROM dns.dns_zones WHERE domain=$1 FOR UPDATE",
                [domain(name)?],
                fetch_optional
            )?
            .ok_or(ManagementError::NotFound)?
        } else {
            run_tx!(tx, query_as, "SELECT z.* FROM dns.dns_zones z JOIN dns.dns_records r ON r.zone_id=z.id WHERE r.id=$1 FOR UPDATE OF z", [record.id], fetch_optional)?.ok_or(ManagementError::NotFound)?
        };
        record.validate(&zone.domain)?;
        // A CNAME must not coexist with another RRset (including zone-apex SOA).
        if record.enabled {
            if record.name == "@" && record.record_type == "CNAME" {
                return Err(invalid("zone apex cannot be CNAME"));
            }
            let conflict: bool = run_tx!(
                tx,
                query_scalar,
                "SELECT EXISTS(SELECT 1 FROM dns.dns_records WHERE zone_id=$1 AND name=$2 AND enabled AND id<>$3 AND (type='CNAME' OR $4='CNAME'))",
                [
                    zone.id,
                    &record.name,
                    if updating { record.id } else { 0 },
                    &record.record_type
                ],
                fetch_one
            )?;
            if conflict {
                return Err(invalid("CNAME conflicts with existing records"));
            }
        }
        let sql = if updating {
            "UPDATE dns.dns_records SET zone_id=$1,name=$2,type=$3,value=$4,ttl=$5,priority=$6,weight=$7,port=$8,enabled=$9,updated_at=now() WHERE id=$10 RETURNING *"
        } else {
            "INSERT INTO dns.dns_records(zone_id,name,type,value,ttl,priority,weight,port,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *"
        };
        let saved: Option<Record> = if updating {
            run_tx!(
                tx,
                query_as,
                sql,
                [
                    zone.id,
                    &record.name,
                    &record.record_type,
                    &record.value,
                    record.ttl,
                    record.priority,
                    record.weight,
                    record.port,
                    record.enabled,
                    record.id
                ],
                fetch_optional
            )?
        } else {
            run_tx!(
                tx,
                query_as,
                sql,
                [
                    zone.id,
                    &record.name,
                    &record.record_type,
                    &record.value,
                    record.ttl,
                    record.priority,
                    record.weight,
                    record.port,
                    record.enabled
                ],
                fetch_optional
            )?
        };
        let record = saved.ok_or(ManagementError::NotFound)?;
        let zone = run_tx!(
            tx,
            query_as,
            "SELECT * FROM dns.dns_zones WHERE id=$1",
            [zone.id],
            fetch_one
        )?;
        tx.commit().await?;
        self.changed();
        Ok((record, zone))
    }

    pub async fn remove_record(
        &self,
        id: i32,
    ) -> Result<Zone> {
        let mut tx = self.begin().await?;
        let zone: Zone = run_tx!(tx, query_as, "SELECT z.* FROM dns.dns_zones z JOIN dns.dns_records r ON r.zone_id=z.id WHERE r.id=$1 FOR UPDATE OF z", [id], fetch_optional)?.ok_or(ManagementError::NotFound)?;
        let removed: Option<i32> = run_tx!(
            tx,
            query_scalar,
            "DELETE FROM dns.dns_records WHERE id=$1 RETURNING id",
            [id],
            fetch_optional
        )?;
        if removed.is_none() {
            return Err(ManagementError::NotFound);
        }
        let zone = run_tx!(
            tx,
            query_as,
            "SELECT * FROM dns.dns_zones WHERE id=$1",
            [zone.id],
            fetch_one
        )?;
        tx.commit().await?;
        self.changed();
        Ok(zone)
    }
}
