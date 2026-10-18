//! Structured DNS record data a registration template may carry.
//!
//! Registrar-hosted records travel as [`crate::registrar::RegistrarRecord`];
//! this is the typed shape a template stores for records a registration
//! should start with.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::rr::RecordType;
use serde::{Deserialize, Serialize};

#[allow(clippy::upper_case_acronyms)]
/// Structured RDATA per RR type. Unknown stays as raw bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "UPPERCASE")]
pub enum DnsRData {
    A {
        addr: Ipv4Addr,
    },
    AAAA {
        addr: Ipv6Addr,
    },
    CNAME {
        target: String,
    },
    MX {
        preference: u16,
        exchange: String,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    TXT {
        strings: Vec<String>,
    },
    NS {
        host: String,
    },
    PTR {
        host: String,
    },
    CAA {
        flags: u8,
        tag: String,
        value: String,
    },

    /// RFC 9460 service-binding records. Keep params as k/v for portability.
    HTTPS {
        priority: u16,
        target: String,
        params: HashMap<String, String>,
    },
    SVCB {
        priority: u16,
        target: String,
        params: HashMap<String, String>,
    },

    /// Catch-all – unknown/new RR types by number with raw wire data.
    Unknown {
        rrtype: u16,
        data: Vec<u8>,
    },
}

/// One DNS record entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String, // relative or FQDN (your choice—be consistent)
    pub ttl: u32,
    #[serde(rename = "type")]
    pub r#type: RecordType,
    pub data: DnsRData,
}
