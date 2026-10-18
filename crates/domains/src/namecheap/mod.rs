//! Namecheap's XML API, over the pooled transport. Authentication rides the
//! query string, every command answers `<ApiResponse Status=...>`, and the
//! host list is only ever written whole.

use std::sync::Arc;

use async_trait::async_trait;
use quick_xml::de::from_str;
use serde::Deserialize;
use time::OffsetDateTime;
use tracing::info;

use crate::config::NamecheapConfig;
use crate::registrar::{
    DomainInfo, Error, Registrar, RegistrarRecord, Result, normalize_owner,
    split_sld_tld,
};
use crate::store::PROV_NAMECHEAP;
use crate::templates::{Contact, Contacts, DomainTemplateData};
use crate::transport::{SharedTransport, Transport};

#[allow(unused)]
pub(crate) mod types;

use types::{
    ApiResponse, CreateApiResponse, GetContactsApiResponse,
    GetHostsApiResponse, GetInfoApiResponse, GetListApiResponse, NcContact,
    NcDnsHost, RenewApiResponse, SetHostsApiResponse,
};

const NAME: &str = "namecheap";

/// Namecheap's own "too many requests" error numbers start with this.
const RATE_LIMIT_ERROR_PREFIX: &str = "2030";

pub struct Namecheap {
    api_url: String,
    api_key: String,
    username: String,
    client_ip: String,
    transport: SharedTransport,
}

impl Namecheap {
    pub fn new(config: &NamecheapConfig) -> std::result::Result<Self, String> {
        let transport = Transport::new(
            NAME,
            "claviron-namecheap/1.0",
            "text/xml, application/xml;q=0.9, */*;q=0.8",
            &config.http,
        )?;
        Ok(Self {
            api_url: config.api_url.clone(),
            api_key: config.api_key.clone(),
            username: config.username.clone(),
            client_ip: config.client_ip.clone(),
            transport: Arc::new(transport),
        })
    }

    pub(crate) fn transport(&self) -> SharedTransport {
        self.transport.clone()
    }

    fn params<'a>(
        &'a self,
        command: &'a str,
        extra: &[(&'a str, &'a str)],
    ) -> Vec<(&'a str, &'a str)> {
        let mut all = vec![
            ("ApiUser", self.username.as_str()),
            ("ApiKey", self.api_key.as_str()),
            ("UserName", self.username.as_str()),
            ("ClientIp", self.client_ip.as_str()),
            ("Command", command),
        ];
        all.extend_from_slice(extra);
        all
    }

    /// `GET` for the ordinary commands.
    async fn call(
        &self,
        command: &str,
        extra: &[(&str, &str)],
    ) -> Result<String> {
        let params = self.params(command, extra);
        let url = reqwest::Url::parse_with_params(&self.api_url, &params)
            .map_err(|error| Error::Invalid(error.to_string()))?;
        let response = self
            .transport
            .send(|client| {
                client.get(url.clone()).header("X-Request-Source", "claviron")
            })
            .await?;
        self.check(response).await
    }

    /// `POST` form for the commands that carry many parameters.
    async fn post(
        &self,
        command: &str,
        extra: &[(&str, &str)],
    ) -> Result<String> {
        let params = self.params(command, extra);
        let response = self
            .transport
            .send(|client| {
                client
                    .post(&self.api_url)
                    .header("X-Request-Source", "claviron")
                    .form(&params)
            })
            .await?;
        self.check(response).await
    }

    /// The XML of an `OK` answer, or the registrar's first error.
    async fn check(
        &self,
        response: reqwest::Response,
    ) -> Result<String> {
        let status = response.status();
        let rate = self.transport.rate_outcome(&response);
        let body = response.text().await.map_err(|error| Error::Transport {
            registrar: NAME,
            message: error.to_string(),
        })?;
        if rate.limited {
            return Err(Error::RateLimited {
                registrar: NAME,
                retry_after: rate.retry_after,
            });
        }
        if body.trim_start().starts_with("<!DOCTYPE html")
            || body.contains("<html")
        {
            return Err(Error::Decode {
                registrar: NAME,
                message: "expected XML, received HTML".into(),
            });
        }
        if !status.is_success() {
            return Err(Error::HttpStatus {
                registrar: NAME,
                status: status.as_u16(),
                body,
            });
        }
        let top: ApiResponse = from_str(&body).map_err(|error| {
            Error::Decode { registrar: NAME, message: error.to_string() }
        })?;
        if top.status != "OK" {
            let first =
                top.errors.and_then(|errors| errors.items.into_iter().next());
            return Err(match first {
                Some(item)
                    if item.number.starts_with(RATE_LIMIT_ERROR_PREFIX) =>
                {
                    self.transport.note_application_limit();
                    Error::RateLimited { registrar: NAME, retry_after: None }
                }
                Some(item) => Error::Api {
                    registrar: NAME,
                    code: item.number,
                    message: item.message,
                },
                None => Error::Api {
                    registrar: NAME,
                    code: top.status,
                    message: "error without details".into(),
                },
            });
        }
        Ok(body)
    }

    fn decode<T: for<'de> Deserialize<'de>>(
        xml: &str,
        what: &str,
    ) -> Result<T> {
        from_str(xml).map_err(|error| Error::Decode {
            registrar: NAME,
            message: format!("{what}: {error}"),
        })
    }

    async fn hosts(
        &self,
        name: &str,
    ) -> Result<Vec<NcDnsHost>> {
        let (sld, tld) = split_sld_tld(name)?;
        let xml = self
            .call(
                "namecheap.domains.dns.getHosts",
                &[("SLD", sld), ("TLD", tld)],
            )
            .await?;
        let parsed: GetHostsApiResponse = Self::decode(&xml, "dns.getHosts")?;
        Ok(parsed.command_response.result.hosts)
    }

    async fn set_hosts(
        &self,
        name: &str,
        hosts: &[NcDnsHost],
    ) -> Result<()> {
        let (sld, tld) = split_sld_tld(name)?;
        let mut owned: Vec<(String, String)> =
            vec![("SLD".into(), sld.into()), ("TLD".into(), tld.into())];
        for (index, host) in hosts.iter().enumerate() {
            let n = index + 1;
            owned.push((format!("HostName{n}"), host.name.clone()));
            owned.push((format!("RecordType{n}"), host.record_type.clone()));
            owned.push((format!("Address{n}"), host.address.clone()));
            owned.push((format!("TTL{n}"), host.ttl.clone()));
            if host.record_type.eq_ignore_ascii_case("MX") {
                owned.push((
                    format!("MXPref{n}"),
                    host.mx_pref.clone().unwrap_or_else(|| "10".into()),
                ));
            }
        }
        let extra: Vec<(&str, &str)> =
            owned.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let xml = self.post("namecheap.domains.dns.setHosts", &extra).await?;
        let parsed: SetHostsApiResponse = Self::decode(&xml, "dns.setHosts")?;
        if parsed.command_response.result.is_success != "true" {
            return Err(Error::Api {
                registrar: NAME,
                code: "setHosts".into(),
                message: "IsSuccess=false".into(),
            });
        }
        Ok(())
    }
}

#[async_trait]
impl Registrar for Namecheap {
    fn name(&self) -> &'static str {
        NAME
    }

    fn id(&self) -> i32 {
        PROV_NAMECHEAP
    }

    fn concurrency(&self) -> usize {
        self.transport.concurrency()
    }

    async fn domains(&self) -> Result<Vec<DomainInfo>> {
        let xml = self
            .call(
                "namecheap.domains.getList",
                &[("ListType", "ALL"), ("PageSize", "100"), ("SortBy", "NAME")],
            )
            .await?;
        let parsed: GetListApiResponse = Self::decode(&xml, "getList")?;
        Ok(parsed
            .command_response
            .result
            .domains
            .into_iter()
            .filter(|item| !item.name.is_empty())
            .map(|item| DomainInfo {
                name: item.name,
                reference: Some(item.id),
                status: if item.is_expired.as_deref() == Some("true") {
                    "Expired".into()
                } else {
                    "Active".into()
                },
                registered_at: item.created.as_deref().and_then(parse_date),
                expires_at: item.expires.as_deref().and_then(parse_date),
                auto_renew: item.auto_renew.as_deref().map(truthy),
                whois_privacy: item
                    .whois_guard
                    .as_deref()
                    .map(|value| value.eq_ignore_ascii_case("ENABLED")),
                nameservers: None,
                registrar_dns: item.is_our_dns.as_deref().map(truthy),
            })
            .collect())
    }

    async fn domain(
        &self,
        name: &str,
    ) -> Result<DomainInfo> {
        let xml = self
            .call("namecheap.domains.getInfo", &[("DomainName", name)])
            .await?;
        let parsed: GetInfoApiResponse = Self::decode(&xml, "getInfo")?;
        let result = parsed.cmd.result;
        let details = result.details;
        Ok(DomainInfo {
            name: result.domain_name,
            reference: result.id,
            status: result.status.unwrap_or_else(|| "UNKNOWN".into()),
            registered_at: details.created_date.as_deref().and_then(parse_date),
            expires_at: details.expired_date.as_deref().and_then(parse_date),
            auto_renew: None,
            whois_privacy: None,
            nameservers: (!details.nameservers.is_empty())
                .then_some(details.nameservers),
            registrar_dns: None,
        })
    }

    async fn contacts(
        &self,
        name: &str,
    ) -> Result<Contacts> {
        let xml = self
            .call("namecheap.domains.getContacts", &[("DomainName", name)])
            .await?;
        let parsed: GetContactsApiResponse = Self::decode(&xml, "getContacts")?;
        let result = parsed.cmd.result;
        Ok(Contacts {
            registrant: contact(result.registrant),
            admin: Some(contact(result.admin)),
            tech: Some(contact(result.tech)),
            billing: Some(contact(result.billing)),
        })
    }

    async fn register(
        &self,
        name: &str,
        template: &DomainTemplateData,
        years: u8,
    ) -> Result<DomainInfo> {
        let years = years.to_string();
        let mut owned: Vec<(String, String)> =
            vec![("DomainName".into(), name.into()), ("Years".into(), years)];
        let contacts = &template.contacts;
        let registrant = &contacts.registrant;
        for (role, contact) in [
            ("Registrant", registrant),
            ("Admin", contacts.admin.as_ref().unwrap_or(registrant)),
            ("Tech", contacts.tech.as_ref().unwrap_or(registrant)),
            ("AuxBilling", contacts.billing.as_ref().unwrap_or(registrant)),
        ] {
            owned
                .push((format!("{role}FirstName"), contact.first_name.clone()));
            owned.push((format!("{role}LastName"), contact.last_name.clone()));
            owned.push((format!("{role}Address1"), contact.address1.clone()));
            if let Some(address2) = &contact.address2 {
                owned.push((format!("{role}Address2"), address2.clone()));
            }
            owned.push((format!("{role}City"), contact.city.clone()));
            owned.push((
                format!("{role}StateProvince"),
                contact.state_province.clone(),
            ));
            owned.push((
                format!("{role}PostalCode"),
                contact.postal_code.clone(),
            ));
            owned.push((format!("{role}Country"), contact.country.clone()));
            owned.push((format!("{role}Phone"), contact.phone.clone()));
            owned.push((format!("{role}EmailAddress"), contact.email.clone()));
        }
        if let Some(servers) = &template.nameservers
            && !servers.is_empty()
        {
            owned.push(("Nameservers".into(), servers.join(",")));
        }
        let extra: Vec<(&str, &str)> =
            owned.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let xml = self.post("namecheap.domains.create", &extra).await?;
        let parsed: CreateApiResponse = Self::decode(&xml, "create")?;
        let result = parsed.cmd.result;
        info!(domain = name, "[namecheap] registered");
        Ok(DomainInfo {
            name: result.domain,
            reference: result.domain_id,
            status: "Active".into(),
            registered_at: result.registered.as_deref().and_then(parse_date),
            expires_at: result.expiration.as_deref().and_then(parse_date),
            auto_renew: None,
            whois_privacy: None,
            nameservers: template.nameservers.clone(),
            registrar_dns: None,
        })
    }

    async fn renew(
        &self,
        name: &str,
        years: u8,
    ) -> Result<DomainInfo> {
        let years = years.to_string();
        let xml = self
            .call(
                "namecheap.domains.renew",
                &[("DomainName", name), ("Years", &years)],
            )
            .await?;
        let parsed: RenewApiResponse = Self::decode(&xml, "renew")?;
        info!(domain = name, expiration = ?parsed.cmd.result.expiration, "[namecheap] renewed");
        self.domain(name).await
    }

    async fn nameservers(
        &self,
        name: &str,
    ) -> Result<Vec<String>> {
        let (sld, tld) = split_sld_tld(name)?;
        let xml = self
            .call(
                "namecheap.domains.dns.getList",
                &[("SLD", sld), ("TLD", tld)],
            )
            .await?;
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "CommandResponse")]
            cmd: Command,
        }
        #[derive(Deserialize)]
        struct Command {
            #[serde(rename = "DomainDNSGetListResult")]
            result: ListResult,
        }
        #[derive(Deserialize)]
        struct ListResult {
            #[serde(rename = "Nameserver", default)]
            nameserver: Vec<String>,
        }
        let parsed: Response = Self::decode(&xml, "dns.getList")?;
        Ok(parsed
            .cmd
            .result
            .nameserver
            .into_iter()
            .map(|server| server.trim().to_owned())
            .filter(|server| !server.is_empty())
            .collect())
    }

    async fn set_nameservers(
        &self,
        name: &str,
        nameservers: &[String],
    ) -> Result<()> {
        let (sld, tld) = split_sld_tld(name)?;
        let joined = nameservers.join(",");
        self.call(
            "namecheap.domains.dns.setCustom",
            &[("SLD", sld), ("TLD", tld), ("NameServers", &joined)],
        )
        .await
        .map(|_| ())
    }

    async fn create_glue(
        &self,
        name: &str,
        host: &str,
        ip: &str,
    ) -> Result<()> {
        let (sld, tld) = split_sld_tld(name)?;
        self.call(
            "namecheap.domains.ns.create",
            &[("SLD", sld), ("TLD", tld), ("Nameserver", host), ("IP", ip)],
        )
        .await
        .map(|_| ())
    }

    async fn update_glue(
        &self,
        name: &str,
        host: &str,
        ip: &str,
        old_ip: Option<&str>,
    ) -> Result<()> {
        let old_ip = old_ip.ok_or_else(|| {
            Error::Invalid(
                "Namecheap keys a glue update by the previous address; old_ip is required"
                    .into(),
            )
        })?;
        let (sld, tld) = split_sld_tld(name)?;
        self.call(
            "namecheap.domains.ns.update",
            &[
                ("SLD", sld),
                ("TLD", tld),
                ("Nameserver", host),
                ("IP", ip),
                ("OldIP", old_ip),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn records(
        &self,
        name: &str,
    ) -> Result<Vec<RegistrarRecord>> {
        Ok(self.hosts(name).await?.into_iter().map(record_from).collect())
    }

    async fn replace_records(
        &self,
        name: &str,
        records: &[RegistrarRecord],
    ) -> Result<()> {
        let hosts: Vec<NcDnsHost> = records.iter().map(record_to).collect();
        self.set_hosts(name, &hosts).await
    }
}

fn parse_date(value: &str) -> Option<OffsetDateTime> {
    use time::macros::format_description;
    let format = format_description!("[month]/[day]/[year]");
    time::Date::parse(value, &format)
        .ok()
        .map(|date| date.midnight().assume_utc())
}

fn truthy(value: &str) -> bool {
    value.eq_ignore_ascii_case("true")
}

fn contact(contact: NcContact) -> Contact {
    Contact {
        first_name: contact.first_name,
        last_name: contact.last_name,
        address1: contact.address1,
        address2: contact.address2,
        city: contact.city,
        state_province: contact.state_province,
        postal_code: contact.postal_code,
        country: contact.country,
        phone: contact.phone,
        email: contact.email,
    }
}

fn record_from(host: NcDnsHost) -> RegistrarRecord {
    let record_type = host.record_type.to_ascii_uppercase();
    let priority = if record_type == "MX" {
        host.mx_pref.as_deref().and_then(|value| value.parse().ok())
    } else {
        None
    };
    RegistrarRecord {
        record_type,
        name: host.name,
        value: host.address,
        ttl: host.ttl.parse().unwrap_or_default(),
        priority,
        weight: None,
        port: None,
    }
}

fn record_to(record: &RegistrarRecord) -> NcDnsHost {
    NcDnsHost {
        host_id: None,
        name: normalize_owner(&record.name),
        record_type: record.record_type.to_ascii_uppercase(),
        address: record.value.clone(),
        mx_pref: record.priority.map(|value| value.to_string()),
        ttl: record.ttl.to_string(),
    }
}
