use serde::{Deserialize, Serialize};

//=============================================================================
// Domain Types
//=============================================================================

/// Response from GoDaddy /v1/domains endpoint (list domains)
#[derive(Debug, Deserialize)]
pub(crate) struct GdDomainSummary {
    #[serde(rename = "domainId")]
    pub(crate) domain_id: i64,
    pub(crate) domain: String,
    pub(crate) status: String,
    #[serde(rename = "createdAt")]
    pub(crate) created_at: Option<String>, // ISO 8601 format
    pub(crate) expires: Option<String>, // ISO 8601 format
    #[serde(rename = "renewAuto")]
    pub(crate) renew_auto: Option<bool>,
    #[serde(rename = "privacy")]
    pub(crate) privacy: Option<bool>,
    #[serde(rename = "nameServers")]
    pub(crate) name_servers: Option<Vec<String>>,
}

/// Response from GoDaddy /v1/domains/{domain} endpoint (get domain details)
#[derive(Debug, Deserialize)]
pub(crate) struct GdDomainDetail {
    #[serde(rename = "domainId")]
    pub(crate) domain_id: i64,
    pub(crate) domain: String,
    pub(crate) status: String,
    #[serde(rename = "createdAt")]
    pub(crate) created_at: Option<String>,
    pub(crate) expires: Option<String>,
    #[serde(rename = "renewAuto")]
    pub(crate) renew_auto: Option<bool>,
    #[serde(rename = "privacy")]
    pub(crate) privacy: Option<bool>,
    #[serde(rename = "nameServers")]
    pub(crate) name_servers: Option<Vec<String>>,
}

/// Response from GoDaddy /v1/domains/{domain}/contacts endpoint
#[derive(Debug, Deserialize)]
pub(crate) struct GdContactsResponse {
    #[serde(rename = "contactRegistrant")]
    pub(crate) registrant: GdContact,
    #[serde(rename = "contactAdmin")]
    pub(crate) admin: GdContact,
    #[serde(rename = "contactTech")]
    pub(crate) tech: GdContact,
    #[serde(rename = "contactBilling")]
    pub(crate) billing: GdContact,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct GdContact {
    #[serde(rename = "nameFirst")]
    pub(crate) first_name: String,
    #[serde(rename = "nameLast")]
    pub(crate) last_name: String,
    #[serde(rename = "addressMailing")]
    pub(crate) address: GdAddress,
    pub(crate) phone: String,
    pub(crate) email: String,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct GdAddress {
    pub(crate) address1: String,
    #[serde(default)]
    pub(crate) address2: Option<String>,
    pub(crate) city: String,
    pub(crate) state: String,
    #[serde(rename = "postalCode")]
    pub(crate) postal_code: String,
    pub(crate) country: String,
}

/// Request body for domain renewal
#[derive(Debug, Serialize)]
pub(crate) struct GdRenewRequest {
    pub(crate) period: i32, // years
}

/// Request body for updating nameservers
#[derive(Debug, Serialize)]
pub(crate) struct GdNameserversRequest {
    #[serde(rename = "nameServers")]
    pub(crate) nameservers: Vec<String>,
}

/// GoDaddy API error response
#[derive(Debug, Deserialize)]
pub(crate) struct GdErrorResponse {
    pub(crate) code: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) fields: Option<Vec<GdErrorField>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GdErrorField {
    pub(crate) path: Option<String>,
    pub(crate) code: Option<String>,
    pub(crate) message: Option<String>,
}

//=============================================================================
// DNS Types
//=============================================================================

/// DNS Record from GoDaddy API
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GdDnsRecord {
    #[serde(rename = "type")]
    pub record_type: String, // A, AAAA, CNAME, MX, TXT, SRV, NS, etc.
    pub name: String, // @ for root, or subdomain
    pub data: String, // IP, hostname, or text value
    #[serde(default = "default_ttl")]
    pub ttl: i32, // Time to live in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>, // For MX and SRV records
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<i32>, // For SRV records
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<i32>, // For SRV records
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>, // For SRV records
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>, // For SRV records
}

fn default_ttl() -> i32 {
    600 // GoDaddy default TTL
}
