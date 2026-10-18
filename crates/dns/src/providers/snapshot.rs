use std::collections::{HashMap, HashSet};

use claviron::runtime::registry::{Error, Result};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tracing::{debug, trace};

use crate::models::actions::DnsStore;
use crate::models::records::DnsRecord;
use crate::models::zones::DnsSoa;

/// DNS records snapshot loaded from database
/// Similar to TLS CertSnapshot pattern
pub struct DnsSnapshot {
    /// Zones indexed by domain name
    zones: HashMap<String, Zone>,
    /// Fast lookup for records
    records_cache: HashMap<(Name, RecordType), Vec<Record>>,
    /// Owner names and empty nonterminals, indexed once at snapshot build.
    names: HashSet<Name>,
}

/// One authoritative zone; public so an embedding application or test can
/// build a snapshot without a database.
#[derive(Clone)]
pub struct Zone {
    pub name: Name,
    pub records: Vec<Record>,
}

impl Zone {
    /// The apex SOA record, when the zone carries one.
    pub fn soa(&self) -> Option<&Record> {
        self.records.iter().find(|record| {
            record.record_type() == RecordType::SOA && record.name == self.name
        })
    }

    pub fn serial(&self) -> Option<u32> {
        match &self.soa()?.data {
            RData::SOA(soa) => Some(soa.serial),
            _ => None,
        }
    }
}

impl DnsSnapshot {
    pub fn new() -> Self {
        Self {
            zones: HashMap::new(),
            records_cache: HashMap::new(),
            names: HashSet::new(),
        }
    }

    /// Load DNS zones and records from database
    pub async fn from_store(store: &DnsStore) -> Result<Self> {
        let mut snapshot = Self::new();

        // Load all zones with their records
        let zones_data = store.load_zones().await?;

        // Convert storage-neutral rows to hickory types
        for zone_data in zones_data {
            let domain = zone_data.domain;
            // Create FQDN with trailing dot for proper DNS lookup
            let zone_name = Name::from_utf8(format!("{}.", domain))
                .map_err(|e| Error::msg(format!("Invalid zone name: {}", e)))?;

            // The apex SOA leads the zone: SOA queries, negative answers and
            // zone transfers all read it from here.
            let mut zone_records =
                vec![soa_record(&zone_data.soa, &zone_name)?];

            // Convert each record
            for rec in zone_data.records {
                match convert_db_record_to_hickory(&rec, &zone_name) {
                    Ok(record) => zone_records.push(record),
                    Err(e) => {
                        tracing::warn!(
                            "Failed to convert record {} for {}: {}",
                            rec.name,
                            domain,
                            e
                        );
                    }
                }
            }

            let zone = Zone { name: zone_name, records: zone_records };

            snapshot.add_zone(zone);
        }

        let zones_count = snapshot.zones.len();
        debug!("📋 DNS snapshot loaded: {} zones)", zones_count,);
        Ok(snapshot)
    }

    #[allow(unused)]
    /// Get zone by name
    pub fn get_zone(
        &self,
        name: &Name,
    ) -> Option<&Zone> {
        self.zones.get(name.to_string().as_str())
    }

    /// The zone that holds `name`: the deepest one when zones nest.
    pub fn zone_for(
        &self,
        name: &Name,
    ) -> Option<&Zone> {
        self.zones
            .values()
            .filter(|zone| zone.name.zone_of(name))
            .max_by_key(|zone| zone.name.num_labels())
    }

    /// The zone whose apex is exactly `name`.
    pub fn zone_at(
        &self,
        name: &Name,
    ) -> Option<&Zone> {
        self.zones.values().find(|zone| &zone.name == name)
    }

    /// Every zone with its SOA serial; what NOTIFY compares across reloads.
    pub fn serials(&self) -> Vec<(Name, u32)> {
        self.zones
            .values()
            .filter_map(|zone| Some((zone.name.clone(), zone.serial()?)))
            .collect()
    }

    /// Whether this service is authoritative for the question name.
    pub fn is_authoritative(
        &self,
        name: &Name,
    ) -> bool {
        self.zones.values().any(|zone| zone.name.zone_of(name))
    }

    /// Exact name or RFC 4592 closest-encloser wildcard source.
    /// An existing owner/empty nonterminal blocks wildcard synthesis even
    /// when it has no records of the requested type.
    fn source_name(
        &self,
        name: &Name,
    ) -> Option<Name> {
        if self.names.contains(name) {
            return Some(name.clone());
        }
        let zone = self
            .zones
            .values()
            .filter(|zone| zone.name.zone_of(name))
            .max_by_key(|zone| zone.name.num_labels())?;
        let mut ancestor = name.base_name();
        while zone.name.zone_of(&ancestor) {
            if self.names.contains(&ancestor) {
                let wildcard = Name::from_utf8(format!("*.{ancestor}")).ok()?;
                return self.names.contains(&wildcard).then_some(wildcard);
            }
            ancestor = ancestor.base_name();
        }
        None
    }

    /// Name existence is independent of query type (RFC 2308 NODATA).
    pub fn name_exists(
        &self,
        name: &Name,
    ) -> bool {
        self.source_name(name).is_some()
    }

    /// Lookup exact/wildcard records; CNAME redirects retain their type.
    pub fn lookup(
        &self,
        name: &Name,
        record_type: RecordType,
    ) -> Option<&[Record]> {
        let source = self.source_name(name)?;
        self.records_cache
            .get(&(source.clone(), record_type))
            .or_else(|| self.records_cache.get(&(source, RecordType::CNAME)))
            .map(Vec::as_slice)
    }

    /// Add a zone to the snapshot
    pub fn add_zone(
        &mut self,
        zone: Zone,
    ) {
        // Cache all records for fast lookup. hickory 0.26: `name`/`ttl`
        // are public fields on `Record` (no longer accessor methods).
        self.names.insert(zone.name.clone());
        for record in &zone.records {
            let mut owner = record.name.clone();
            while zone.name.zone_of(&owner) {
                self.names.insert(owner.clone());
                if owner == zone.name {
                    break;
                }
                owner = owner.base_name();
            }
            let key = (record.name.clone(), record.record_type());
            trace!(
                "Caching record: {} {} (ttl={})",
                record.name,
                record.record_type(),
                record.ttl
            );
            self.records_cache.entry(key).or_default().push(record.clone());
        }

        self.zones.insert(zone.name.to_string(), zone);
    }

    pub fn domain_count(&self) -> usize {
        self.zones.len()
    }

    pub fn record_set_count(&self) -> usize {
        self.records_cache.len()
    }
}

impl Default for DnsSnapshot {
    fn default() -> Self {
        Self::new()
    }
}

/// The zone row's SOA as a record at the apex. Names stored without a
/// trailing dot get one, as record targets do. Its TTL is the negative-caching
/// minimum, which RFC 2308 caps a negative answer's lifetime at anyway.
fn soa_record(
    soa: &DnsSoa,
    zone_name: &Name,
) -> Result<Record> {
    let fqdn = |value: &str, what: &str| {
        let value = if value.ends_with('.') {
            value.to_owned()
        } else {
            format!("{value}.")
        };
        Name::from_utf8(&value)
            .map_err(|e| Error::msg(format!("Invalid SOA {what}: {e}")))
    };
    let serial = u32::try_from(soa.serial).map_err(|_| {
        Error::msg(format!("SOA serial {} does not fit 32 bits", soa.serial))
    })?;
    let minimum = u32::try_from(soa.minimum)
        .map_err(|_| Error::msg("SOA minimum must be nonnegative"))?;
    let rdata = RData::SOA(hickory_proto::rr::rdata::SOA::new(
        fqdn(&soa.mname, "mname")?,
        fqdn(&soa.rname, "rname")?,
        serial,
        soa.refresh,
        soa.retry,
        soa.expire,
        minimum,
    ));
    Ok(Record::from_rdata(zone_name.clone(), minimum, rdata))
}

/// Convert DB record model to hickory Record
pub(crate) fn convert_db_record_to_hickory(
    rec: &DnsRecord,
    zone_name: &Name,
) -> Result<Record> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    // Build full record name (zone_name already has trailing dot)
    let record_name = if rec.name == "@" {
        zone_name.clone()
    } else if rec.name == "*" {
        // Wildcard record - zone_name already has trailing dot, just strip it and re-add
        let zone_str = zone_name.to_string();
        let zone_without_dot = zone_str.trim_end_matches('.');
        Name::from_utf8(format!("*.{}.", zone_without_dot)).map_err(|e| {
            Error::msg(format!("Invalid wildcard record name: {}", e))
        })?
    } else {
        // Regular subdomain - zone_name already has trailing dot, strip and rebuild
        let zone_str = zone_name.to_string();
        let zone_without_dot = zone_str.trim_end_matches('.');
        Name::from_utf8(format!("{}.{}.", rec.name, zone_without_dot))
            .map_err(|e| Error::msg(format!("Invalid record name: {}", e)))?
    };

    // Parse record type
    let record_type = RecordType::from_str(&rec.record_type.to_uppercase())
        .map_err(|_| {
            Error::msg(format!("Invalid record type: {}", rec.record_type))
        })?;

    // Parse RData based on type
    let rdata = match record_type {
        RecordType::A => {
            let ip = Ipv4Addr::from_str(&rec.value).map_err(|_| {
                Error::msg(format!("Invalid IPv4: {}", rec.value))
            })?;
            RData::A(ip.into())
        }
        RecordType::AAAA => {
            let ip = Ipv6Addr::from_str(&rec.value).map_err(|_| {
                Error::msg(format!("Invalid IPv6: {}", rec.value))
            })?;
            RData::AAAA(ip.into())
        }
        RecordType::CNAME => {
            // Ensure CNAME target has trailing dot
            let target_str = if rec.value.ends_with('.') {
                rec.value.clone()
            } else {
                format!("{}.", rec.value)
            };
            let target = Name::from_utf8(&target_str)
                .map_err(|e| Error::msg(format!("Invalid CNAME: {}", e)))?;
            RData::CNAME(hickory_proto::rr::rdata::CNAME(target))
        }
        RecordType::TXT => {
            RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![
                rec.value.clone(),
            ]))
        }
        RecordType::NS => {
            // Ensure NS has trailing dot
            let ns_str = if rec.value.ends_with('.') {
                rec.value.clone()
            } else {
                format!("{}.", rec.value)
            };
            let ns = Name::from_utf8(&ns_str)
                .map_err(|e| Error::msg(format!("Invalid NS: {}", e)))?;
            RData::NS(hickory_proto::rr::rdata::NS(ns))
        }
        RecordType::MX => {
            let preference = u16::try_from(rec.priority.unwrap_or(10))
                .map_err(|_| Error::msg("MX priority must fit u16"))?;
            // Ensure MX exchange has trailing dot
            let exchange_str = if rec.value.ends_with('.') {
                rec.value.clone()
            } else {
                format!("{}.", rec.value)
            };
            let exchange = Name::from_utf8(&exchange_str)
                .map_err(|e| Error::msg(format!("Invalid MX: {}", e)))?;
            RData::MX(hickory_proto::rr::rdata::MX::new(preference, exchange))
        }
        RecordType::SRV => {
            let field = |value: Option<i32>, name: &str| -> Result<u16> {
                let value = value.ok_or_else(|| {
                    Error::msg(format!("SRV {name} is required"))
                })?;
                u16::try_from(value)
                    .map_err(|_| Error::msg(format!("SRV {name} must fit u16")))
            };
            let target = Name::from_utf8(if rec.value.ends_with('.') {
                rec.value.clone()
            } else {
                format!("{}.", rec.value)
            })
            .map_err(|e| Error::msg(format!("Invalid SRV target: {e}")))?;
            RData::SRV(hickory_proto::rr::rdata::SRV::new(
                field(rec.priority, "priority")?,
                field(rec.weight, "weight")?,
                field(rec.port, "port")?,
                target,
            ))
        }
        _ => {
            return Err(Error::msg(format!(
                "Unsupported record type: {}",
                rec.record_type
            )));
        }
    };

    // Build Record using from_rdata
    let ttl = u32::try_from(rec.ttl)
        .map_err(|_| Error::msg("DNS TTL must be nonnegative"))?;
    let record = Record::from_rdata(record_name, ttl, rdata);

    Ok(record)
}

#[cfg(test)]
mod tests;
