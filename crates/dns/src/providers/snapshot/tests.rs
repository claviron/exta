use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use super::{DnsRecord, DnsSnapshot, Zone, convert_db_record_to_hickory};
use crate::providers::DnsHandler;

fn name(value: &str) -> Name {
    Name::from_utf8(value).unwrap()
}

fn handler() -> DnsHandler {
    let mut snapshot = DnsSnapshot::new();
    snapshot.add_zone(Zone {
        name: name("upstream.internal."),
        records: ["api", "*.wild", "known.wild", "leaf.branch.wild"]
            .into_iter()
            .map(|owner| {
                Record::from_rdata(
                    name(&format!("{owner}.upstream.internal.")),
                    10,
                    RData::A(
                        "127.0.0.1"
                            .parse::<std::net::Ipv4Addr>()
                            .unwrap()
                            .into(),
                    ),
                )
            })
            .chain(std::iter::once(Record::from_rdata(
                name("*.wild.upstream.internal."),
                10,
                RData::AAAA(std::net::Ipv6Addr::LOCALHOST.into()),
            )))
            .chain(std::iter::once(Record::from_rdata(
                name("alias.upstream.internal."),
                10,
                RData::CNAME(hickory_proto::rr::rdata::CNAME(name(
                    "api.upstream.internal.",
                ))),
            )))
            .collect(),
    });
    DnsHandler::new(Arc::new(snapshot))
}

async fn query(
    handler: &DnsHandler,
    owner: &str,
    kind: RecordType,
) -> Message {
    let mut message = Message::new(73, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.metadata.recursion_available = true;
    message.metadata.authentic_data = true;
    message.add_query(Query::query(name(owner), kind));
    // Exercise the same protocol bytes consumed by UDP and DoH callers.
    let answer = handler
        .handle_query(Message::from_vec(&message.to_vec().unwrap()).unwrap())
        .await
        .unwrap();
    Message::from_vec(&answer.to_vec().unwrap()).unwrap()
}

#[tokio::test]
async fn missing_family_is_nodata_and_unknown_name_is_nxdomain() {
    let handler = handler();
    let positive =
        query(&handler, "api.upstream.internal.", RecordType::A).await;
    assert_eq!(positive.answers.len(), 1);
    for owner in [
        "api.upstream.internal.",
        "upstream.internal.",
        "branch.wild.upstream.internal.",
    ] {
        let answer = query(&handler, owner, RecordType::AAAA).await;
        assert_eq!(
            answer.metadata.response_code,
            ResponseCode::NoError,
            "{owner}"
        );
        assert!(answer.answers.is_empty());
        assert!(answer.metadata.authoritative);
        assert!(answer.metadata.recursion_desired);
        assert!(!answer.metadata.recursion_available);
        assert!(!answer.metadata.authentic_data);
    }
    let unknown =
        query(&handler, "absent.upstream.internal.", RecordType::A).await;
    assert_eq!(unknown.metadata.response_code, ResponseCode::NXDomain);
    assert!(unknown.metadata.authoritative);
    assert!(unknown.metadata.recursion_desired);
    let outside = query(&handler, "unowned.internal.", RecordType::A).await;
    assert_eq!(outside.metadata.response_code, ResponseCode::Refused);
    assert!(!outside.metadata.authoritative);
}

#[tokio::test]
async fn wildcard_uses_closest_encloser_and_synthesizes_question_owner() {
    let handler = handler();
    for owner in
        ["new.wild.upstream.internal.", "deep.new.wild.upstream.internal."]
    {
        let answer = query(&handler, owner, RecordType::A).await;
        assert_eq!(answer.answers.len(), 1);
        assert_eq!(answer.answers[0].name, name(owner));
        let nodata = query(&handler, owner, RecordType::TXT).await;
        assert_eq!(nodata.metadata.response_code, ResponseCode::NoError);
        assert!(nodata.answers.is_empty());
    }
    // An exact owner with another type must not fall back to the wildcard.
    let exact =
        query(&handler, "known.wild.upstream.internal.", RecordType::AAAA)
            .await;
    assert_eq!(exact.metadata.response_code, ResponseCode::NoError);
    assert!(exact.answers.is_empty());
    // The empty nonterminal branch blocks synthesis from *.wild.
    let blocked =
        query(&handler, "new.branch.wild.upstream.internal.", RecordType::A)
            .await;
    assert_eq!(blocked.metadata.response_code, ResponseCode::NXDomain);
}

#[tokio::test]
async fn address_query_preserves_cname_redirect() {
    let answer =
        query(&handler(), "alias.upstream.internal.", RecordType::AAAA).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
    assert_eq!(answer.answers.len(), 1);
    assert_eq!(answer.answers[0].record_type(), RecordType::CNAME);
}

fn srv() -> DnsRecord {
    DnsRecord {
        name: "_wallet._tcp".into(),
        record_type: "SRV".into(),
        value: "api.upstream.internal.".into(),
        ttl: 10,
        priority: Some(20),
        weight: Some(0),
        port: Some(3040),
    }
}

#[test]
fn srv_wire_preserves_target_port_priority_zero_weight_and_zero_ttl() {
    for ttl in [0, 10] {
        let mut stored = srv();
        stored.ttl = ttl;
        let record =
            convert_db_record_to_hickory(&stored, &name("upstream.internal."))
                .unwrap();
        let mut response =
            Message::new(73, MessageType::Response, OpCode::Query);
        response.add_answer(record);
        let decoded = Message::from_vec(&response.to_vec().unwrap()).unwrap();
        assert_eq!(decoded.answers[0].ttl, ttl as u32);
        let RData::SRV(data) = &decoded.answers[0].data else {
            panic!("SRV lost")
        };
        assert_eq!(data.priority, 20);
        assert_eq!(data.weight, 0);
        assert_eq!(data.port, 3040);
        assert_eq!(data.target, name("api.upstream.internal."));
    }
}

#[test]
fn invalid_storage_fields_do_not_wrap_or_default_srv_metadata() {
    let zone = name("upstream.internal.");
    for field in ["priority", "weight", "port"] {
        for invalid in [None, Some(-1), Some(65536)] {
            let mut record = srv();
            match field {
                "priority" => record.priority = invalid,
                "weight" => record.weight = invalid,
                "port" => record.port = invalid,
                _ => unreachable!(),
            }
            assert!(
                convert_db_record_to_hickory(&record, &zone).is_err(),
                "{field}: {invalid:?}"
            );
        }
    }
    let mut record = srv();
    record.ttl = -1;
    assert!(convert_db_record_to_hickory(&record, &zone).is_err());
    record.ttl = 10;
    record.record_type = "MX".into();
    record.priority = Some(65536);
    assert!(convert_db_record_to_hickory(&record, &zone).is_err());
}
