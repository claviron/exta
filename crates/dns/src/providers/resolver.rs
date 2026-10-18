//! In-process resolver over the authoritative snapshot.
//!
//! `claviron-upstream` asks the application for a `dyn ResolverFactory`; an
//! application that also runs this DNS service can bind [`DnsResolverFactory`]
//! so hostname origins inside its own zones are answered from the same
//! `DnsSnapshot` the UDP listener serves, with no socket, no query and no
//! cache: the snapshot is the truth and a reload swaps it. Names outside the
//! authoritative zones go to the fallthrough resolver the application
//! supplied, or fail with `NxDomain` when it supplied none. That choice is
//! the application's, made where the factory is bound.

use std::sync::Arc;
use std::time::{Duration, Instant};

use claviron::resolver::{
    Answer, Query, Record, RecordType, ResolveError, ResolveErrorKind,
    ResolveFuture, Resolver, ResolverConfig, ResolverFactory,
};
use hickory_proto::rr::{Name, RData, RecordType as WireType};

use super::dns::DnsProvider;

/// Opens one [`DnsResolver`] per consumer configuration.
pub struct DnsResolverFactory {
    provider: DnsProvider,
    fallthrough: Option<Arc<dyn ResolverFactory>>,
}

impl DnsResolverFactory {
    /// `fallthrough` answers names this service is not authoritative for.
    pub fn new(
        provider: DnsProvider,
        fallthrough: Option<Arc<dyn ResolverFactory>>,
    ) -> Self {
        Self { provider, fallthrough }
    }
}

impl ResolverFactory for DnsResolverFactory {
    fn open(
        &self,
        config: &ResolverConfig,
    ) -> Result<Arc<dyn Resolver>, ResolveError> {
        config.validate()?;
        let fallthrough = self
            .fallthrough
            .as_ref()
            .map(|factory| factory.open(config))
            .transpose()?;
        Ok(Arc::new(DnsResolver {
            provider: self.provider.clone(),
            ttl: (config.min_ttl, config.max_ttl),
            fallthrough,
        }))
    }
}

/// Answers from the live snapshot; the record TTL, clamped by the consumer's
/// `min_ttl`/`max_ttl`, becomes the answer's remaining validity.
pub struct DnsResolver {
    provider: DnsProvider,
    ttl: (Duration, Duration),
    fallthrough: Option<Arc<dyn Resolver>>,
}

impl DnsResolver {
    fn local(
        &self,
        query: Query<'_>,
    ) -> Option<Result<Answer, ResolveError>> {
        let snapshot = self.provider.snapshot()?;
        // Consumers hand over names as written in config, usually without the
        // trailing dot; the snapshot indexes fully qualified names and hickory
        // hashes the FQDN flag, so an unqualified name would never match.
        let mut name = match Name::from_utf8(query.name) {
            Ok(name) => name,
            Err(error) => {
                return Some(Err(ResolveError::new(
                    ResolveErrorKind::InvalidName,
                    error.to_string(),
                )));
            }
        };
        name.set_fqdn(true);
        if !snapshot.is_authoritative(&name) {
            return None;
        }
        let wire = match query.record_type {
            RecordType::A => WireType::A,
            RecordType::Aaaa => WireType::AAAA,
            RecordType::Srv => WireType::SRV,
            RecordType::Txt => WireType::TXT,
            _ => {
                return Some(Err(ResolveError::new(
                    ResolveErrorKind::Config,
                    "record type is not served by the in-process DNS snapshot",
                )));
            }
        };
        let Some(records) = snapshot.lookup(&name, wire) else {
            let kind = if snapshot.name_exists(&name) {
                ResolveErrorKind::NoRecords
            } else {
                ResolveErrorKind::NxDomain
            };
            return Some(Err(ResolveError::new(kind, query.name.to_string())));
        };
        let mut ttl = u32::MAX;
        let answers = records
            .iter()
            .filter_map(|record| {
                let converted = match (&record.data, query.record_type) {
                    (RData::A(addr), RecordType::A) => Record::A(addr.0),
                    (RData::AAAA(addr), RecordType::Aaaa) => {
                        Record::Aaaa(addr.0)
                    }
                    (RData::SRV(srv), RecordType::Srv) => Record::Srv {
                        priority: srv.priority,
                        weight: srv.weight,
                        port: srv.port,
                        target: srv.target.to_utf8(),
                    },
                    (RData::TXT(txt), RecordType::Txt) => Record::Txt(
                        txt.txt_data.iter().map(|part| part.to_vec()).collect(),
                    ),
                    _ => return None,
                };
                ttl = ttl.min(record.ttl);
                Some(converted)
            })
            .collect::<Vec<_>>();
        if answers.is_empty() {
            return Some(Err(ResolveError::new(
                ResolveErrorKind::NoRecords,
                query.name.to_string(),
            )));
        }
        let ttl =
            Duration::from_secs(u64::from(ttl)).clamp(self.ttl.0, self.ttl.1);
        Some(Ok(Answer { records: answers, valid_until: Instant::now() + ttl }))
    }
}

impl Resolver for DnsResolver {
    fn lookup<'a>(
        &'a self,
        query: Query<'a>,
    ) -> ResolveFuture<'a> {
        Box::pin(async move {
            if let Some(answer) = self.local(query) {
                return answer;
            }
            match &self.fallthrough {
                Some(resolver) => resolver.lookup(query).await,
                None => Err(ResolveError::new(
                    ResolveErrorKind::NxDomain,
                    format!(
                        "{} is outside the zones this DNS service is authoritative for and no fallthrough resolver is bound",
                        query.name
                    ),
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use hickory_proto::rr::Record as WireRecord;
    use hickory_proto::rr::rdata::A;

    use super::*;
    use crate::providers::{DnsSnapshot, Zone};

    struct Scripted(Ipv4Addr);
    impl Resolver for Scripted {
        fn lookup<'a>(
            &'a self,
            _: Query<'a>,
        ) -> ResolveFuture<'a> {
            Box::pin(async move {
                Ok(Answer {
                    records: vec![Record::A(self.0)],
                    valid_until: Instant::now() + Duration::from_secs(1),
                })
            })
        }
    }
    struct ScriptedFactory(Ipv4Addr);
    impl ResolverFactory for ScriptedFactory {
        fn open(
            &self,
            _: &ResolverConfig,
        ) -> Result<Arc<dyn Resolver>, ResolveError> {
            Ok(Arc::new(Scripted(self.0)))
        }
    }

    fn provider_with_zone() -> DnsProvider {
        let state =
            claviron::runtime::AppState::standalone("dns-resolver", ".");
        let provider = DnsProvider::empty(state);
        let zone_name = Name::from_utf8("upstream.internal.").unwrap();
        let mut record = WireRecord::from_rdata(
            Name::from_utf8("wallet.upstream.internal.").unwrap(),
            30,
            RData::A(A(Ipv4Addr::new(127, 0, 0, 9))),
        );
        record.ttl = 30;
        let mut snapshot = DnsSnapshot::new();
        snapshot.add_zone(Zone { name: zone_name, records: vec![record] });
        provider.install_snapshot_for_test(snapshot);
        provider
    }

    #[tokio::test]
    async fn answers_authoritative_names_from_the_snapshot_with_record_ttl() {
        let factory = DnsResolverFactory::new(provider_with_zone(), None);
        let config = ResolverConfig {
            min_ttl: Duration::from_secs(5),
            max_ttl: Duration::from_secs(300),
            ..ResolverConfig::default()
        };
        let resolver = factory.open(&config).unwrap();
        let answer = resolver
            .lookup(Query::new("wallet.upstream.internal.", RecordType::A))
            .await
            .unwrap();
        assert_eq!(
            answer.records,
            vec![Record::A(Ipv4Addr::new(127, 0, 0, 9))]
        );
        let remaining =
            answer.valid_until.saturating_duration_since(Instant::now());
        assert!(
            remaining <= Duration::from_secs(30)
                && remaining > Duration::from_secs(29)
        );
    }

    #[tokio::test]
    async fn answers_unqualified_names_as_written_in_config() {
        let factory = DnsResolverFactory::new(provider_with_zone(), None);
        let resolver = factory.open(&ResolverConfig::default()).unwrap();
        let answer = resolver
            .lookup(Query::new("wallet.upstream.internal", RecordType::A))
            .await
            .unwrap();
        assert_eq!(
            answer.records,
            vec![Record::A(Ipv4Addr::new(127, 0, 0, 9))]
        );
    }

    #[tokio::test]
    async fn clamps_ttl_to_the_consumer_bounds() {
        let factory = DnsResolverFactory::new(provider_with_zone(), None);
        let config = ResolverConfig {
            min_ttl: Duration::from_secs(60),
            max_ttl: Duration::from_secs(120),
            ..ResolverConfig::default()
        };
        let resolver = factory.open(&config).unwrap();
        let answer = resolver
            .lookup(Query::new("wallet.upstream.internal.", RecordType::A))
            .await
            .unwrap();
        assert!(
            answer.valid_until.saturating_duration_since(Instant::now())
                > Duration::from_secs(59)
        );
    }

    #[tokio::test]
    async fn missing_name_inside_the_zone_is_nxdomain_not_fallthrough() {
        let factory = DnsResolverFactory::new(
            provider_with_zone(),
            Some(Arc::new(ScriptedFactory(Ipv4Addr::new(10, 0, 0, 1)))),
        );
        let resolver = factory.open(&ResolverConfig::default()).unwrap();
        let error = resolver
            .lookup(Query::new("missing.upstream.internal.", RecordType::A))
            .await
            .unwrap_err();
        assert_eq!(error.kind, ResolveErrorKind::NxDomain);
        let error = resolver
            .lookup(Query::new("wallet.upstream.internal.", RecordType::Aaaa))
            .await
            .unwrap_err();
        assert_eq!(error.kind, ResolveErrorKind::NoRecords);
    }

    #[tokio::test]
    async fn names_outside_the_zones_use_the_fallthrough_or_fail() {
        let bound = DnsResolverFactory::new(
            provider_with_zone(),
            Some(Arc::new(ScriptedFactory(Ipv4Addr::new(10, 0, 0, 1)))),
        )
        .open(&ResolverConfig::default())
        .unwrap();
        let answer = bound
            .lookup(Query::new("api.example.test.", RecordType::A))
            .await
            .unwrap();
        assert_eq!(answer.records, vec![Record::A(Ipv4Addr::new(10, 0, 0, 1))]);

        let unbound = DnsResolverFactory::new(provider_with_zone(), None)
            .open(&ResolverConfig::default())
            .unwrap();
        let error = unbound
            .lookup(Query::new("api.example.test.", RecordType::A))
            .await
            .unwrap_err();
        assert_eq!(error.kind, ResolveErrorKind::NxDomain);
    }
}
