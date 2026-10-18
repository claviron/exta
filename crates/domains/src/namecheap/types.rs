use serde::{Deserialize, Serialize};

//=============================================================================
// Common API Response Types
//=============================================================================

#[derive(Deserialize)]
pub(crate) struct ApiResponse {
    #[serde(rename = "@Status")]
    pub(crate) status: String,
    #[serde(rename = "Errors")]
    #[serde(default)]
    pub(crate) errors: Option<ErrorsList>,
}

#[derive(Deserialize)]
pub(crate) struct ErrorsList {
    // <Errors /> may have no <Error> children; default to empty vec
    #[serde(rename = "Error", default)]
    pub(crate) items: Vec<ApiErrorItem>,
}

#[derive(Deserialize)]
pub(crate) struct ApiErrorItem {
    #[serde(rename = "@Number")]
    pub(crate) number: String,
    #[serde(rename = "$text")]
    pub(crate) message: String,
}

#[derive(Deserialize)]
pub(crate) struct GetListApiResponse {
    #[serde(rename = "@Status")]
    status: String,
    #[serde(rename = "CommandResponse")]
    pub(crate) command_response: NcCommandResponse,
}

#[derive(Deserialize)]
pub(crate) struct NcCommandResponse {
    #[serde(rename = "DomainGetListResult")]
    pub(crate) result: DomainGetListResult,
}

#[derive(Deserialize)]
pub(crate) struct DomainGetListResult {
    #[serde(rename = "Domain")]
    pub(crate) domains: Vec<NcDomainItem>,
}

#[derive(Deserialize)]
pub(crate) struct NcDomainItem {
    #[serde(rename = "@id", alias = "@ID")]
    pub(crate) id: i64,
    #[serde(rename = "@Name")]
    pub(crate) name: String,
    #[serde(rename = "@Created")]
    pub(crate) created: Option<String>,
    #[serde(rename = "@Expires")]
    pub(crate) expires: Option<String>,
    #[serde(rename = "@AutoRenew")]
    pub(crate) auto_renew: Option<String>,
    #[serde(rename = "@WhoisGuard")]
    pub(crate) whois_guard: Option<String>,
    #[serde(rename = "@IsOurDNS")]
    pub(crate) is_our_dns: Option<String>,
    #[serde(rename = "@IsExpired")]
    pub(crate) is_expired: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct RenewApiResponse {
    #[serde(rename = "@Status")]
    status: String,
    #[serde(rename = "CommandResponse")]
    pub(crate) cmd: RenewCommandResponse,
}

#[derive(Deserialize)]
pub(crate) struct RenewCommandResponse {
    #[serde(rename = "DomainRenewResult")]
    pub(crate) result: DomainRenewResult,
}

#[derive(Deserialize)]
pub(crate) struct DomainRenewResult {
    #[serde(rename = "@DomainName")]
    pub(crate) domain_name: String,
    #[serde(rename = "@DomainID")]
    domain_id: Option<i64>,
    #[serde(rename = "@Expiration")]
    pub(crate) expiration: Option<String>, // some responses also include ChargedAmount, OrderID, etc., which we ignore for now
}

// Structs for parsing create response
#[derive(Deserialize)]
pub(crate) struct CreateApiResponse {
    #[serde(rename = "@Status")]
    status: String,
    #[serde(rename = "CommandResponse")]
    pub(crate) cmd: CreateCommandResponse,
}

#[derive(Deserialize)]
pub(crate) struct CreateCommandResponse {
    #[serde(rename = "DomainCreateResult")]
    pub(crate) result: DomainCreateResult,
}

#[derive(Deserialize)]
pub(crate) struct DomainCreateResult {
    #[serde(rename = "@Domain")]
    pub(crate) domain: String,
    #[serde(rename = "@DomainID")]
    pub(crate) domain_id: Option<i64>,
    #[serde(rename = "@Registered")]
    pub(crate) registered: Option<String>,
    #[serde(rename = "@Expiration")]
    pub(crate) expiration: Option<String>,
}

// Structs for parsing getInfo response
#[derive(Deserialize)]
pub(crate) struct GetInfoApiResponse {
    #[serde(rename = "@Status")]
    status: String,
    #[serde(rename = "CommandResponse")]
    pub(crate) cmd: GetInfoCommandResponse,
}

#[derive(Deserialize)]
pub(crate) struct GetInfoCommandResponse {
    #[serde(rename = "DomainGetInfoResult")]
    pub(crate) result: DomainGetInfoResult,
}

#[derive(Deserialize)]
pub(crate) struct DomainGetInfoResult {
    #[serde(rename = "@DomainName")]
    pub(crate) domain_name: String,
    #[serde(rename = "@ID")]
    pub(crate) id: Option<i64>,
    #[serde(rename = "@Status")]
    pub(crate) status: Option<String>,
    #[serde(rename = "DomainDetails")]
    pub(crate) details: DomainDetails,
}

#[derive(Deserialize)]
pub(crate) struct DomainDetails {
    #[serde(rename = "CreatedDate")]
    pub(crate) created_date: Option<String>,
    #[serde(rename = "ExpiredDate")]
    pub(crate) expired_date: Option<String>,
    #[serde(rename = "Nameservers", default)]
    pub(crate) nameservers: Vec<String>,
}

// Structs for parsing getContacts response
#[derive(Deserialize)]
pub(crate) struct GetContactsApiResponse {
    #[serde(rename = "@Status")]
    status: String,
    #[serde(rename = "CommandResponse")]
    pub(crate) cmd: GetContactsCommandResponse,
}

#[derive(Deserialize)]
pub(crate) struct GetContactsCommandResponse {
    #[serde(rename = "DomainContactsResult")]
    pub(crate) result: DomainContactsResult,
}

#[derive(Deserialize)]
pub(crate) struct DomainContactsResult {
    #[serde(rename = "@Domain")]
    pub(crate) domain: String,
    #[serde(rename = "Registrant")]
    pub(crate) registrant: NcContact,
    #[serde(rename = "Admin")]
    pub(crate) admin: NcContact,
    #[serde(rename = "Tech")]
    pub(crate) tech: NcContact,
    #[serde(rename = "AuxBilling")]
    pub(crate) billing: NcContact,
}

#[derive(Deserialize, Clone)]
pub(crate) struct NcContact {
    #[serde(rename = "FirstName")]
    pub(crate) first_name: String,
    #[serde(rename = "LastName")]
    pub(crate) last_name: String,
    #[serde(rename = "Address1")]
    pub(crate) address1: String,
    #[serde(rename = "Address2", default)]
    pub(crate) address2: Option<String>,
    #[serde(rename = "City")]
    pub(crate) city: String,
    #[serde(rename = "StateProvince")]
    pub(crate) state_province: String,
    #[serde(rename = "PostalCode")]
    pub(crate) postal_code: String,
    #[serde(rename = "Country")]
    pub(crate) country: String,
    #[serde(rename = "Phone")]
    pub(crate) phone: String,
    #[serde(rename = "EmailAddress")]
    pub(crate) email: String,
}

//=============================================================================
// DNS Types
//=============================================================================

/// Response from namecheap.domains.dns.getHosts
#[derive(Debug, Deserialize)]
pub(crate) struct GetHostsApiResponse {
    #[serde(rename = "@Status")]
    status: String,
    #[serde(rename = "CommandResponse")]
    pub(crate) command_response: GetHostsCommandResponse,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GetHostsCommandResponse {
    #[serde(rename = "DomainDNSGetHostsResult")]
    pub(crate) result: DomainDNSGetHostsResult,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DomainDNSGetHostsResult {
    #[serde(rename = "@Domain")]
    pub(crate) domain: String,
    #[serde(rename = "@IsUsingOurDNS")]
    pub(crate) is_using_our_dns: Option<String>,
    #[serde(rename = "host", default)]
    pub(crate) hosts: Vec<NcDnsHost>,
}

/// Single DNS host record from Namecheap
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NcDnsHost {
    #[serde(rename = "@HostId")]
    pub host_id: Option<String>,

    #[serde(rename = "@Name")]
    pub name: String, // subdomain or @ for root

    #[serde(rename = "@Type")]
    pub record_type: String, // A, AAAA, CNAME, MX, TXT, NS, etc.

    #[serde(rename = "@Address")]
    pub address: String, // IP, hostname, or text value

    #[serde(rename = "@MXPref")]
    #[serde(default)]
    pub mx_pref: Option<String>, // Priority for MX records

    #[serde(rename = "@TTL")]
    #[serde(default = "default_nc_ttl")]
    pub ttl: String, // TTL in seconds as string
}

fn default_nc_ttl() -> String {
    "1800".to_string() // Namecheap default TTL
}

/// Response from namecheap.domains.dns.setHosts
#[derive(Debug, Deserialize)]
pub(crate) struct SetHostsApiResponse {
    #[serde(rename = "@Status")]
    status: String,
    #[serde(rename = "CommandResponse")]
    pub(crate) command_response: SetHostsCommandResponse,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SetHostsCommandResponse {
    #[serde(rename = "DomainDNSSetHostsResult")]
    pub(crate) result: DomainDNSSetHostsResult,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DomainDNSSetHostsResult {
    #[serde(rename = "@Domain")]
    pub(crate) domain: String,
    #[serde(rename = "@IsSuccess")]
    pub(crate) is_success: String, // "true" or "false"
}
