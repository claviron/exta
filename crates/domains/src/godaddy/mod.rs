//! GoDaddy's domains API (`/v1/domains`), JSON over the pooled transport.
//!
//! Registration is not offered: a purchase needs contacts and payment
//! consent the API expects in a shape this crate does not model. Glue
//! hosts have no endpoint in the public API.

use std::sync::Arc;

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use time::OffsetDateTime;
use tracing::info;

use crate::config::GodaddyConfig;
use crate::registrar::{
    DomainInfo, Error, Registrar, RegistrarRecord, Result, normalize_owner,
};
use crate::store::PROV_GODADDY;
use crate::templates::{Contact, Contacts};
use crate::transport::{SharedTransport, Transport};

#[allow(unused)]
pub(crate) mod types;

use types::{
    GdContact, GdContactsResponse, GdDnsRecord, GdDomainDetail,
    GdDomainSummary, GdErrorResponse, GdNameserversRequest, GdRenewRequest,
};

const NAME: &str = "godaddy";

pub struct Godaddy {
    api_url: String,
    authorization: String,
    transport: SharedTransport,
}

impl Godaddy {
    pub fn new(config: &GodaddyConfig) -> std::result::Result<Self, String> {
        let transport = Transport::new(
            NAME,
            "claviron-godaddy/1.0",
            "application/json",
            &config.http,
        )?;
        Ok(Self {
            api_url: config.api_url.trim_end_matches('/').to_owned(),
            authorization: format!(
                "sso-key {}:{}",
                config.api_key, config.api_secret
            ),
            transport: Arc::new(transport),
        })
    }

    pub(crate) fn transport(&self) -> SharedTransport {
        self.transport.clone()
    }

    fn url(
        &self,
        path: &str,
    ) -> String {
        format!("{}{path}", self.api_url)
    }

    async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T> {
        let url = self.url(path);
        let response = self
            .transport
            .send(|client| {
                client.get(&url).header("Authorization", &self.authorization)
            })
            .await?;
        self.decode(response).await
    }

    async fn write<B: serde::Serialize + Sync>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: &B,
    ) -> Result<()> {
        let url = self.url(path);
        let response = self
            .transport
            .send(|client| {
                client
                    .request(method.clone(), &url)
                    .header("Authorization", &self.authorization)
                    .json(body)
            })
            .await?;
        self.check(response).await.map(|_| ())
    }

    async fn post<B: serde::Serialize + Sync, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let url = self.url(path);
        let response = self
            .transport
            .send(|client| {
                client
                    .post(&url)
                    .header("Authorization", &self.authorization)
                    .json(body)
            })
            .await?;
        self.decode(response).await
    }

    /// The body of a successful answer, or the registrar's error.
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
        if status.is_success() {
            return Ok(body);
        }
        if let Ok(error) = serde_json::from_str::<GdErrorResponse>(&body) {
            return Err(Error::Api {
                registrar: NAME,
                code: error.code.unwrap_or_else(|| status.to_string()),
                message: error
                    .message
                    .unwrap_or_else(|| "unknown error".into()),
            });
        }
        Err(Error::HttpStatus {
            registrar: NAME,
            status: status.as_u16(),
            body,
        })
    }

    async fn decode<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T> {
        let body = self.check(response).await?;
        serde_json::from_str(&body).map_err(|error| Error::Decode {
            registrar: NAME,
            message: error.to_string(),
        })
    }

    async fn detail(
        &self,
        name: &str,
    ) -> Result<GdDomainDetail> {
        self.get(&format!("/v1/domains/{name}")).await
    }
}

#[async_trait]
impl Registrar for Godaddy {
    fn name(&self) -> &'static str {
        NAME
    }

    fn id(&self) -> i32 {
        PROV_GODADDY
    }

    fn concurrency(&self) -> usize {
        self.transport.concurrency()
    }

    async fn domains(&self) -> Result<Vec<DomainInfo>> {
        let listed: Vec<GdDomainSummary> =
            self.get("/v1/domains?includes=nameServers").await?;
        Ok(listed
            .into_iter()
            .filter(|summary| !summary.domain.is_empty())
            .map(|summary| DomainInfo {
                name: summary.domain,
                reference: Some(summary.domain_id),
                status: summary.status,
                registered_at: summary
                    .created_at
                    .as_deref()
                    .and_then(parse_date),
                expires_at: summary.expires.as_deref().and_then(parse_date),
                auto_renew: summary.renew_auto,
                whois_privacy: summary.privacy,
                nameservers: summary.name_servers,
                registrar_dns: None,
            })
            .collect())
    }

    async fn domain(
        &self,
        name: &str,
    ) -> Result<DomainInfo> {
        let detail = self.detail(name).await?;
        Ok(DomainInfo {
            name: detail.domain,
            reference: Some(detail.domain_id),
            status: detail.status,
            registered_at: detail.created_at.as_deref().and_then(parse_date),
            expires_at: detail.expires.as_deref().and_then(parse_date),
            auto_renew: detail.renew_auto,
            whois_privacy: detail.privacy,
            nameservers: detail.name_servers,
            registrar_dns: None,
        })
    }

    async fn contacts(
        &self,
        name: &str,
    ) -> Result<Contacts> {
        let contacts: GdContactsResponse =
            self.get(&format!("/v1/domains/{name}/contacts")).await?;
        Ok(Contacts {
            registrant: contact(contacts.registrant),
            admin: Some(contact(contacts.admin)),
            tech: Some(contact(contacts.tech)),
            billing: Some(contact(contacts.billing)),
        })
    }

    async fn renew(
        &self,
        name: &str,
        years: u8,
    ) -> Result<DomainInfo> {
        let _: serde_json::Value = self
            .post(
                &format!("/v1/domains/{name}/renew"),
                &GdRenewRequest { period: i32::from(years) },
            )
            .await?;
        info!(domain = name, years, "[godaddy] renewed");
        self.domain(name).await
    }

    async fn nameservers(
        &self,
        name: &str,
    ) -> Result<Vec<String>> {
        Ok(self.detail(name).await?.name_servers.unwrap_or_default())
    }

    async fn set_nameservers(
        &self,
        name: &str,
        nameservers: &[String],
    ) -> Result<()> {
        self.write(
            reqwest::Method::PATCH,
            &format!("/v1/domains/{name}"),
            &GdNameserversRequest { nameservers: nameservers.to_vec() },
        )
        .await
    }

    async fn records(
        &self,
        name: &str,
    ) -> Result<Vec<RegistrarRecord>> {
        let records: Vec<GdDnsRecord> =
            self.get(&format!("/v1/domains/{name}/records")).await?;
        Ok(records.into_iter().map(record_from).collect())
    }

    async fn replace_records(
        &self,
        name: &str,
        records: &[RegistrarRecord],
    ) -> Result<()> {
        let body: Vec<GdDnsRecord> = records.iter().map(record_to).collect();
        self.write(
            reqwest::Method::PUT,
            &format!("/v1/domains/{name}/records"),
            &body,
        )
        .await
    }

    /// GoDaddy replaces one type/owner set per `PUT`, so an upsert is one
    /// call per set rather than a read-merge-write of the whole zone.
    async fn upsert_records(
        &self,
        name: &str,
        records: &[RegistrarRecord],
    ) -> Result<()> {
        let mut sets: Vec<(&RegistrarRecord, Vec<GdDnsRecord>)> = Vec::new();
        for record in records {
            match sets.iter_mut().find(|(head, _)| head.same_set(record)) {
                Some((_, members)) => members.push(record_to(record)),
                None => sets.push((record, vec![record_to(record)])),
            }
        }
        for (head, members) in sets {
            let path = format!(
                "/v1/domains/{name}/records/{}/{}",
                head.record_type.to_ascii_uppercase(),
                normalize_owner(&head.name)
            );
            self.write(reqwest::Method::PUT, &path, &members).await?;
        }
        Ok(())
    }

    async fn remove_records(
        &self,
        name: &str,
        record_type: &str,
        owner: &str,
    ) -> Result<()> {
        let path = format!(
            "/v1/domains/{name}/records/{}/{}",
            record_type.to_ascii_uppercase(),
            normalize_owner(owner)
        );
        let url = self.url(&path);
        let response = self
            .transport
            .send(|client| {
                client.delete(&url).header("Authorization", &self.authorization)
            })
            .await?;
        self.check(response).await.map(|_| ())
    }
}

fn parse_date(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .ok()
}

fn contact(contact: GdContact) -> Contact {
    Contact {
        first_name: contact.first_name,
        last_name: contact.last_name,
        address1: contact.address.address1,
        address2: contact.address.address2,
        city: contact.address.city,
        state_province: contact.address.state,
        postal_code: contact.address.postal_code,
        country: contact.address.country,
        phone: contact.phone,
        email: contact.email,
    }
}

fn record_from(record: GdDnsRecord) -> RegistrarRecord {
    let unsigned =
        |value: Option<i32>| value.and_then(|v| u32::try_from(v).ok());
    RegistrarRecord {
        record_type: record.record_type.to_ascii_uppercase(),
        name: record.name,
        value: record.data,
        ttl: u32::try_from(record.ttl).unwrap_or_default(),
        priority: unsigned(record.priority),
        weight: unsigned(record.weight),
        port: unsigned(record.port),
    }
}

fn record_to(record: &RegistrarRecord) -> GdDnsRecord {
    let signed = |value: Option<u32>| value.and_then(|v| i32::try_from(v).ok());
    GdDnsRecord {
        record_type: record.record_type.to_ascii_uppercase(),
        name: normalize_owner(&record.name),
        data: record.value.clone(),
        ttl: i32::try_from(record.ttl).unwrap_or(i32::MAX),
        priority: signed(record.priority),
        weight: signed(record.weight),
        port: signed(record.port),
        service: None,
        protocol: None,
    }
}
