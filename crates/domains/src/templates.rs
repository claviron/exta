use serde::{Deserialize, Serialize};

use crate::dns::DnsRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainTemplateData {
    /// Required contact groups
    pub contacts: Contacts,
    pub nameservers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_records: Option<Vec<DnsRecord>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contacts {
    pub registrant: Contact,
    pub admin: Option<Contact>,
    pub tech: Option<Contact>,
    pub billing: Option<Contact>,
}

/// Contact data for each role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub first_name: String,
    pub last_name: String,
    pub address1: String,
    pub address2: Option<String>, // optional
    pub city: String,
    pub state_province: String,
    pub postal_code: String,
    pub country: String,
    pub phone: String, // format +NNN.NNNNNNNNNN
    pub email: String,
}
