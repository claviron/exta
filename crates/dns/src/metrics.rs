//! Bounded authoritative DNS counters and their fleet snapshot owner.
use std::fmt::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use claviron::metrics::{MetricsFamily, MetricsProvider};
use claviron::orbit::{FleetProvider, OrbitStateExt};
use claviron::orbitive::metrics::{
    METRIC_SNAPSHOT_RING_CAPACITY, OrbitMetricCollector, OrbitMetricPublisher,
    OrbitMetricSnapshot, OrbitTyped, RingSpec,
};
use claviron::runtime::registry::{Component, Runnable};
use claviron::runtime::{AppState, RunContext, registry};
use hickory_proto::op::{Message, ResponseCode};
use serde::Deserialize;
use tokio::sync::watch;

use crate::DnsConfigProvider;
use crate::observation::{Failure, Transport};

/// DNS publication policy. Durations have no implicit fallback.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    pub enabled: bool,
    #[serde(deserialize_with = "claviron::helpers::de::deserialize_duration")]
    pub publish_interval: Duration,
    #[serde(deserialize_with = "claviron::helpers::de::deserialize_duration")]
    pub max_age: Duration,
}

impl MetricsConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.publish_interval.is_zero()
            || self.max_age < self.publish_interval
            || self.max_age.as_secs() == 0
            || self.max_age.subsec_nanos() != 0
        {
            return Err("DNS metrics require a positive publish_interval and whole-second max_age >= publish_interval".into());
        }
        Ok(())
    }
}

// Fixed schema dimensions, not operator capacities: adding a field changes
// the wire ABI and requires a new physical kind.
const TRANSPORTS: [&str; 3] = ["udp", "tcp", "doh"];
const QTYPES: [&str; 15] = [
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV", "CAA",
    "AXFR", "IXFR", "ANY", "OTHER", "NONE",
];
const RCODES: [&str; 7] = [
    "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "OTHER",
];
const FAILURES: [&str; 9] = [
    "malformed",
    "response_packet",
    "unavailable",
    "processing",
    "encode",
    "write",
    "read",
    "cancelled",
    "method",
];
const QUERY: usize = 1;
const RESPONSE: usize = QUERY + QTYPES.len();
const ERROR: usize = RESPONSE + RCODES.len();
const COUNT: usize = ERROR + FAILURES.len();
const MICROS: usize = COUNT + 1;
const WIDTH: usize = MICROS + 1;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Snapshot([[u64; WIDTH]; TRANSPORTS.len()]);
impl Default for Snapshot {
    fn default() -> Self {
        Self([[0; WIDTH]; TRANSPORTS.len()])
    }
}
impl Snapshot {
    fn merge(
        &mut self,
        other: &Self,
    ) {
        for (a, b) in self.0.iter_mut().flatten().zip(other.0.iter().flatten())
        {
            *a = a.saturating_add(*b);
        }
    }
    fn render(
        &self,
        out: &mut String,
    ) -> std::fmt::Result {
        for (name, help, kind) in [
            (
                "requests_total",
                "Admitted DNS transport requests including invalid input.",
                "counter",
            ),
            (
                "queries_total",
                "Decoded DNS questions, classified by the first question type.",
                "counter",
            ),
            (
                "responses_total",
                "DNS responses handed successfully to the transport.",
                "counter",
            ),
            (
                "failures_total",
                "Requests ending without a successful DNS response handoff.",
                "counter",
            ),
            (
                "request_duration_seconds",
                "Time from transport admission to response handoff or failure.",
                "summary",
            ),
        ] {
            writeln!(
                out,
                "# HELP claviron_dns_{name} {help}\n# TYPE claviron_dns_{name} {kind}"
            )?;
        }
        for (transport, row) in TRANSPORTS.iter().zip(&self.0) {
            writeln!(
                out,
                "claviron_dns_requests_total{{transport=\"{transport}\"}} {}",
                row[0]
            )?;
            for (offset, labels, name, label) in [
                (QUERY, QTYPES.as_slice(), "queries_total", "qtype"),
                (RESPONSE, RCODES.as_slice(), "responses_total", "rcode"),
                (ERROR, FAILURES.as_slice(), "failures_total", "reason"),
            ] {
                for (i, value) in labels.iter().enumerate() {
                    writeln!(
                        out,
                        "claviron_dns_{name}{{transport=\"{transport}\",{label}=\"{value}\"}} {}",
                        row[offset + i]
                    )?;
                }
            }
            writeln!(
                out,
                "claviron_dns_request_duration_seconds_count{{transport=\"{transport}\"}} {}",
                row[COUNT]
            )?;
            writeln!(
                out,
                "claviron_dns_request_duration_seconds_sum{{transport=\"{transport}\"}} {:.6}",
                row[MICROS] as f64 / 1_000_000.0
            )?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct Store {
    values: Mutex<Snapshot>,
    policy: watch::Sender<Option<MetricsConfig>>,
}
impl Default for Store {
    fn default() -> Self {
        Self {
            values: Mutex::new(Snapshot::default()),
            policy: watch::channel(None).0,
        }
    }
}
impl Store {
    pub(crate) fn configure(
        &self,
        dns_enabled: bool,
        policy: Option<MetricsConfig>,
    ) {
        let policy = policy.filter(|p| dns_enabled && p.enabled);
        self.policy.send_if_modified(|old| {
            if *old == policy {
                false
            } else {
                *old = policy;
                true
            }
        });
    }
    pub(crate) fn begin(
        self: &Arc<Self>,
        transport: Transport,
    ) -> Option<Request> {
        self.policy.borrow().as_ref()?;
        let transport = match transport {
            Transport::Udp => 0,
            Transport::Tcp => 1,
            Transport::Doh => 2,
        };
        self.values.lock().unwrap().0[transport][0] += 1;
        Some(Request {
            store: self.clone(),
            transport,
            started: Instant::now(),
            finished: false,
        })
    }
    fn snapshot(&self) -> Snapshot {
        self.values.lock().unwrap().clone()
    }
}

pub(crate) struct Request {
    store: Arc<Store>,
    transport: usize,
    started: Instant,
    finished: bool,
}
impl Request {
    pub(crate) fn query(
        &mut self,
        query: &Message,
    ) {
        use hickory_proto::rr::RecordType::*;
        let index = match query.queries.first().map(|q| q.query_type()) {
            Some(A) => 0,
            Some(AAAA) => 1,
            Some(CNAME) => 2,
            Some(MX) => 3,
            Some(NS) => 4,
            Some(TXT) => 5,
            Some(SOA) => 6,
            Some(PTR) => 7,
            Some(SRV) => 8,
            Some(CAA) => 9,
            Some(AXFR) => 10,
            Some(IXFR) => 11,
            Some(ANY) => 12,
            Some(_) => 13,
            None => 14,
        };
        self.store.values.lock().unwrap().0[self.transport][QUERY + index] += 1;
    }
    fn complete(
        &mut self,
        outcome: Result<ResponseCode, Failure>,
    ) {
        if self.finished {
            return;
        }
        self.finished = true;
        let mut values = self.store.values.lock().unwrap();
        let row = &mut values.0[self.transport];
        let index = match outcome {
            Ok(code) => {
                RESPONSE
                    + match code {
                        ResponseCode::NoError => 0,
                        ResponseCode::FormErr => 1,
                        ResponseCode::ServFail => 2,
                        ResponseCode::NXDomain => 3,
                        ResponseCode::NotImp => 4,
                        ResponseCode::Refused => 5,
                        _ => 6,
                    }
            }
            Err(failure) => {
                ERROR
                    + match failure {
                        Failure::Malformed => 0,
                        Failure::ResponsePacket => 1,
                        Failure::Unavailable => 2,
                        Failure::Processing => 3,
                        Failure::Encode => 4,
                        Failure::Write => 5,
                        Failure::Read => 6,
                        Failure::Cancelled => 7,
                        Failure::Method => 8,
                    }
            }
        };
        row[index] += 1;
        row[COUNT] += 1;
        row[MICROS] = row[MICROS].saturating_add(
            self.started.elapsed().as_micros().min(u64::MAX as u128) as u64,
        );
    }
    pub(crate) fn finish(
        mut self,
        outcome: Result<ResponseCode, Failure>,
    ) {
        self.complete(outcome);
    }
}
impl Drop for Request {
    fn drop(&mut self) {
        self.complete(Err(Failure::Cancelled));
    }
}

// node u16 + timestamp u64 + enabled u8 + the fixed scalar matrix.
const WIRE_LEN: usize = 11 + TRANSPORTS.len() * WIDTH * 8;
#[derive(Clone, Debug, PartialEq, Eq)]
struct Record {
    node: u16,
    at: u64,
    enabled: bool,
    snapshot: Snapshot,
}
impl OrbitTyped for Record {
    const KIND: u8 = 190;
    const RING_SPEC: RingSpec =
        RingSpec::new(METRIC_SNAPSHOT_RING_CAPACITY, WIRE_LEN);
}
impl OrbitMetricSnapshot for Record {
    const FAMILY: &'static str = "claviron_dns_metrics";
    fn node_id(&self) -> u16 {
        self.node
    }
    fn captured_at_unix_secs(&self) -> u64 {
        self.at
    }
    fn encode(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::with_capacity(WIRE_LEN);
        bytes.extend_from_slice(&self.node.to_le_bytes());
        bytes.extend_from_slice(&self.at.to_le_bytes());
        bytes.push(u8::from(self.enabled));
        for value in self.snapshot.0.iter().flatten() {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != WIRE_LEN || bytes[10] > 1 {
            return Err("Invalid DNS metrics snapshot".into());
        }
        let node = u16::from_le_bytes(bytes[..2].try_into().unwrap());
        let at = u64::from_le_bytes(bytes[2..10].try_into().unwrap());
        let mut snapshot = Snapshot::default();
        for (slot, raw) in
            snapshot.0.iter_mut().flatten().zip(bytes[11..].as_chunks::<8>().0)
        {
            *slot = u64::from_le_bytes(*raw);
        }
        Ok(Self { node, at, enabled: bytes[10] == 1, snapshot })
    }
}
fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|e| e.to_string())
}

struct Family(Arc<Store>);
impl MetricsFamily for Family {
    fn name(&self) -> &'static str {
        "claviron.dns"
    }
    fn write_prometheus(
        &self,
        state: &AppState,
        out: &mut String,
    ) -> Result<(), String> {
        let Some(policy) = self.0.policy.borrow().clone() else {
            return Ok(());
        };
        let snapshot = if state.is_standalone() {
            self.0.snapshot()
        } else {
            let fleet = state
                .fleet()
                .ok_or("Orbit fleet unavailable for DNS metrics")?;
            let collector = OrbitMetricCollector::<Record>::new(fleet);
            let mut sum = Snapshot::default();
            for sample in collector
                .fresh_by_node(now()?, policy.max_age.as_secs())
                .into_values()
            {
                if sample.snapshot.enabled {
                    sum.merge(&sample.snapshot.snapshot);
                }
            }
            sum
        };
        snapshot.render(out).map_err(|e| e.to_string())
    }
}

struct Publisher(Arc<Store>);
impl Component<AppState> for Publisher {
    type Deps = (Arc<FleetProvider>,);
    fn name(&self) -> &'static str {
        "DnsMetricsPublisher"
    }
    fn as_runnable(
        self: Arc<Self>
    ) -> Option<Arc<dyn Runnable<AppState, Self::Deps>>> {
        Some(self)
    }
}
#[async_trait]
impl Runnable<AppState, (Arc<FleetProvider>,)> for Publisher {
    async fn run(
        self: Arc<Self>,
        (fleet,): (Arc<FleetProvider>,),
        state: AppState,
        context: RunContext,
    ) -> registry::Result<()> {
        let publisher =
            OrbitMetricPublisher::<Record>::new(fleet.handle().ok_or_else(
                || registry::Error::msg("DNS metrics require Orbit"),
            )?);
        let mut changes = self.0.policy.subscribe();
        loop {
            let policy = changes.borrow_and_update().clone();
            let record = Record {
                node: state.fleet_node_id().raw(),
                at: now().map_err(registry::Error::msg)?,
                enabled: policy.is_some(),
                snapshot: self.0.snapshot(),
            };
            publisher.publish(&record).map_err(registry::Error::msg)?;
            match policy {
                Some(policy) => tokio::select! {
                    _ = context.cancelled() => break,
                    result = changes.changed() => { if result.is_err() { break; } },
                    _ = tokio::time::sleep(policy.publish_interval) => {},
                },
                None => tokio::select! {
                    _ = context.cancelled() => break,
                    result = changes.changed() => { if result.is_err() { break; } },
                },
            }
        }
        publisher
            .publish(&Record {
                node: state.fleet_node_id().raw(),
                at: now().map_err(registry::Error::msg)?,
                enabled: false,
                snapshot: Snapshot::default(),
            })
            .map_err(registry::Error::msg)?;
        Ok(())
    }
}

pub(crate) fn register(state: &AppState) -> registry::Result<()> {
    let registry = state.registry_ref();
    if registry.resolve::<MetricsProvider>().is_none() {
        claviron::metrics::register(state)?;
    }
    let config = registry
        .resolve::<DnsConfigProvider>()
        .ok_or_else(|| registry::Error::msg("DNS config is not registered"))?;
    registry
        .resolve::<MetricsProvider>()
        .unwrap()
        .register(Arc::new(Family(config.metrics.clone())));
    if !state.is_standalone() {
        claviron::orbit::shm::register_reusable_ring::<Record>(
            state,
            "DnsMetricsShm",
            "dns-metrics-ring",
        )?;
        registry.register(Arc::new(Publisher(config.metrics.clone())))?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/metrics.rs"]
mod tests;
