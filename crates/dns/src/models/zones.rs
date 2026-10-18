use super::records::DnsRecord;

/// Enabled authoritative zone and the enabled records loaded with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsZone {
    pub domain: String,
    pub soa: DnsSoa,
    pub records: Vec<DnsRecord>,
}

/// The zone's start of authority, from its row in `dns.dns_zones`. The
/// serial is what a secondary compares to decide whether to transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsSoa {
    pub serial: i64,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum: i32,
    pub mname: String,
    pub rname: String,
}
