/// Storage-neutral DNS record used while building a runtime snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: i32,
    pub priority: Option<i32>,
    pub weight: Option<i32>,
    pub port: Option<i32>,
}
