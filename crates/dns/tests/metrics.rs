use super::*;
use crate::providers::Zone;
use crate::providers::{DnsHandler, DnsSnapshot};
use hickory_proto::op::{MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, Record as DnsRecord, RecordType};

fn store() -> Arc<Store> {
    let store = Arc::new(Store::default());
    store.configure(
        true,
        Some(MetricsConfig {
            enabled: true,
            publish_interval: Duration::from_secs(1),
            max_age: Duration::from_secs(5),
        }),
    );
    store
}
fn query(name: &str) -> Message {
    let mut message = Message::new(1, MessageType::Query, OpCode::Query);
    message
        .add_query(Query::query(Name::from_utf8(name).unwrap(), RecordType::A));
    message
}

#[tokio::test]
async fn dns_metrics_counts_answers_and_failures_once() {
    let mut snapshot = DnsSnapshot::new();
    snapshot.add_zone(Zone {
        name: Name::from_utf8("example.test.").unwrap(),
        records: vec![DnsRecord::from_rdata(
            Name::from_utf8("www.example.test.").unwrap(),
            60,
            RData::A(std::net::Ipv4Addr::new(192, 0, 2, 1).into()),
        )],
    });
    let handler = DnsHandler::new(Arc::new(snapshot));
    let store = store();
    let mut unsupported = query("www.example.test.");
    unsupported.metadata.op_code = OpCode::Status;
    for (message, expected) in [
        (query("www.example.test."), ResponseCode::NoError),
        (query("missing.example.test."), ResponseCode::NXDomain),
        (unsupported, ResponseCode::NotImp),
        (
            Message::new(1, MessageType::Query, OpCode::Query),
            ResponseCode::FormErr,
        ),
    ] {
        let mut request = store.begin(Transport::Udp).unwrap();
        request.query(&message);
        let response = handler.handle_query(message).await.unwrap();
        assert_eq!(response.metadata.response_code, expected);
        request.finish(Ok(response.metadata.response_code));
    }
    assert!(Message::from_vec(&[0]).is_err());
    store.begin(Transport::Udp).unwrap().finish(Err(Failure::Malformed));
    store.begin(Transport::Udp).unwrap().finish(Err(Failure::Processing));
    store.begin(Transport::Udp).unwrap().finish(Err(Failure::Write));
    drop(store.begin(Transport::Udp).unwrap());
    let values = store.snapshot();
    let row = &values.0[0];
    assert_eq!(row[0], 8);
    assert_eq!(row[COUNT], 8);
    assert_eq!(row[QUERY..RESPONSE].iter().sum::<u64>(), 4);
    assert_eq!(row[RESPONSE..ERROR].iter().sum::<u64>(), 4);
    assert_eq!(row[ERROR..COUNT].iter().sum::<u64>(), 4);
    let mut text = String::new();
    values.render(&mut text).unwrap();
    assert!(text.contains(
        "claviron_dns_responses_total{transport=\"udp\",rcode=\"NXDOMAIN\"} 1"
    ));
    assert!(!text.contains("example.test"));
}

#[test]
fn dns_metrics_disabled_collection_and_policy_changes_are_event_driven() {
    let store = store();
    let mut changes = store.policy.subscribe();
    store.configure(false, None);
    assert!(changes.has_changed().unwrap());
    changes.borrow_and_update();
    assert!(store.begin(Transport::Tcp).is_none());
    store.configure(false, None);
    assert!(!changes.has_changed().unwrap());
    assert_eq!(store.snapshot(), Snapshot::default());
}

#[test]
fn dns_metrics_rejects_unusable_publication_and_freshness_policy() {
    for text in [
        "enabled: true\npublish_interval: 0s\nmax_age: 5s",
        "enabled: true\npublish_interval: 6s\nmax_age: 5s",
        "enabled: true\npublish_interval: 1s\nmax_age: 1500ms",
    ] {
        let policy: MetricsConfig = serde_yaml::from_str(text).unwrap();
        assert!(policy.validate().is_err());
    }
}

#[cfg(feature = "doh")]
#[tokio::test]
async fn dns_metrics_doh_handler_accounts_http_rejections_and_dns_handoff() {
    use crate::{DnsConfig, DnsProvider};
    use axum::{
        body::Body,
        extract::Extension,
        http::{Request, StatusCode},
    };
    let provider =
        Arc::new(DnsProvider::empty(AppState::standalone("dns-metrics", ".")));
    provider.install_config_for_test(DnsConfig::default());
    let store = &provider.cfg_provider().metrics;
    store.configure(
        true,
        Some(MetricsConfig {
            enabled: true,
            publish_interval: Duration::from_secs(1),
            max_age: Duration::from_secs(5),
        }),
    );
    let good = query("www.example.test.").to_vec().unwrap();
    let call = |method, body: Vec<u8>| {
        crate::doh::handle_doh_request(
            Extension(provider.clone()),
            Request::builder()
                .method(method)
                .uri("/dns-query")
                .body(Body::from(body))
                .unwrap(),
        )
    };
    assert_eq!(
        call("POST", good.clone()).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    provider.install_snapshot_for_test(DnsSnapshot::new());
    assert_eq!(call("POST", good.clone()).await.status(), StatusCode::OK);
    assert_eq!(call("POST", vec![0]).await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(call("GET", vec![]).await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        call("DELETE", vec![]).await.status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    let mut reply = query("www.example.test.");
    reply.metadata.message_type = MessageType::Response;
    assert_eq!(
        call("POST", reply.to_vec().unwrap()).await.status(),
        StatusCode::BAD_REQUEST
    );
    let before = store.snapshot();
    assert_eq!(before.0[2][0], 6);
    assert_eq!(before.0[2][RESPONSE + 5], 1);
    assert_eq!(before.0[2][ERROR], 2);
    assert_eq!(before.0[2][ERROR + 1], 1);
    assert_eq!(before.0[2][ERROR + 2], 1);
    assert_eq!(before.0[2][ERROR + 8], 1);
    assert_eq!(before.0[2][COUNT], 6);
    store.configure(false, None);
    assert_eq!(call("POST", good).await.status(), StatusCode::OK);
    assert_eq!(store.snapshot(), before);
}

#[test]
fn dns_metrics_wire_and_fleet_replace_stale_and_restarted_nodes() {
    use claviron::orbitive::Fleet;
    let fleet = Arc::new(Fleet::join("dns-test", 3).unwrap());
    let publisher = OrbitMetricPublisher::<Record>::new(fleet.clone());
    let collector = OrbitMetricCollector::<Record>::new(fleet);
    let record = |node, at, value, enabled| {
        let mut snapshot = Snapshot::default();
        snapshot.0[0][0] = value;
        Record { node, at, enabled, snapshot }
    };
    for sample in [
        record(1, 100, 10, true),
        record(2, 100, 20, true),
        record(1, 101, 11, true),
    ] {
        let bytes = sample.encode().unwrap();
        assert_eq!(bytes.len(), WIRE_LEN);
        assert_eq!(Record::decode(&bytes).unwrap(), sample);
        publisher.publish(&sample).unwrap();
    }
    let aggregate = |now| {
        let mut sum = Snapshot::default();
        for sample in collector.fresh_by_node(now, 5).into_values() {
            if sample.snapshot.enabled {
                sum.merge(&sample.snapshot.snapshot);
            }
        }
        sum.0[0][0]
    };
    assert_eq!(aggregate(101), 31); // newest per node, not 10 + 11 + 20
    publisher.publish(&record(1, 102, 1, true)).unwrap();
    assert_eq!(aggregate(102), 21); // restarted node replaces its old lifetime
    publisher.publish(&record(2, 103, 0, false)).unwrap();
    assert_eq!(aggregate(103), 1); // tombstone hides retained contribution
    assert_eq!(aggregate(108), 0); // crashed publishers expire without a timer in the reader
    assert!(Record::decode(&[0]).is_err());
}
