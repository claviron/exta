//! The TSIG exchange a secondary depends on: a signed AXFR from the
//! configured address is answered with the zone between two SOAs, signed so
//! the requester can verify it; anything else is refused.

use std::net::IpAddr;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::tsig::TsigAlgorithm;
use hickory_proto::rr::{Name, RData, Record, RecordType, TSigner};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

use super::{answer, now};
use crate::providers::{DnsConfig, DnsProvider, DnsSnapshot, Zone};

const SECONDARY: &str = "192.0.2.53";
const SECRET: &str = "c2VjcmV0LXNoYXJlZC1ieS1ib3RoLWVuZHMtb2YtdGhlLXRyYW5zZmVy";

fn provider() -> DnsProvider {
    let zone = Name::from_utf8("example.test.").unwrap();
    let soa = Record::from_rdata(
        zone.clone(),
        300,
        RData::SOA(hickory_proto::rr::rdata::SOA::new(
            Name::from_utf8("ns1.example.test.").unwrap(),
            Name::from_utf8("hostmaster.example.test.").unwrap(),
            2026092601,
            3600,
            600,
            604800,
            300,
        )),
    );
    let www = Record::from_rdata(
        Name::from_utf8("www.example.test.").unwrap(),
        300,
        RData::A("192.0.2.10".parse::<std::net::Ipv4Addr>().unwrap().into()),
    );
    let mut snapshot = DnsSnapshot::new();
    snapshot.add_zone(Zone { name: zone, records: vec![soa, www] });

    let config: DnsConfig = serde_yaml::from_str(&format!(
        r#"
enabled: true
tsig_keys:
  axfr-key: {{ algorithm: hmac-sha256, secret: {SECRET} }}
secondaries:
  - {{ address: {SECONDARY}, key: axfr-key }}
"#
    ))
    .unwrap();

    let provider = DnsProvider::empty(claviron::runtime::AppState::standalone(
        "dns-xfr", ".",
    ));
    provider.install_config_for_test(config);
    provider.install_snapshot_for_test(snapshot);
    provider
}

fn signer() -> TSigner {
    use base64ct::{Base64, Encoding};
    TSigner::new(
        Base64::decode_vec(SECRET).unwrap(),
        TsigAlgorithm::HmacSha256,
        Name::from_utf8("axfr-key").unwrap(),
        300,
    )
    .unwrap()
}

fn axfr() -> Message {
    let mut request = Message::new(4242, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(
        Name::from_utf8("example.test.").unwrap(),
        RecordType::AXFR,
    ));
    request
}

#[test]
fn a_signed_axfr_from_the_secondary_gets_the_zone_signed() {
    let provider = provider();
    let mut request = axfr();
    let (tsig, verifier) = signer().sign_message(&request, now()).unwrap();
    request.set_signature(tsig);
    let raw = request.to_bytes().unwrap();

    let reply = answer(
        &provider,
        &raw,
        &Message::from_bytes(&raw).unwrap(),
        SECONDARY.parse().unwrap(),
    );
    let response = Message::from_bytes(&reply).unwrap();

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    let types: Vec<_> =
        response.answers.iter().map(Record::record_type).collect();
    assert_eq!(types, [RecordType::SOA, RecordType::A, RecordType::SOA]);
    // The requester can check the answer with the MAC of its own request.
    verifier.unwrap().verify(&reply).expect("response TSIG verifies");
}

#[test]
fn an_unsigned_axfr_is_refused() {
    let raw = axfr().to_bytes().unwrap();
    let reply = answer(
        &provider(),
        &raw,
        &Message::from_bytes(&raw).unwrap(),
        SECONDARY.parse().unwrap(),
    );
    let response = Message::from_bytes(&reply).unwrap();
    assert_eq!(response.metadata.response_code, ResponseCode::Refused);
    assert!(response.answers.is_empty());
}

#[test]
fn an_axfr_from_another_address_is_refused() {
    let mut request = axfr();
    let (tsig, _) = signer().sign_message(&request, now()).unwrap();
    request.set_signature(tsig);
    let raw = request.to_bytes().unwrap();
    let stranger: IpAddr = "198.51.100.7".parse().unwrap();
    let reply = answer(
        &provider(),
        &raw,
        &Message::from_bytes(&raw).unwrap(),
        stranger,
    );
    assert_eq!(
        Message::from_bytes(&reply).unwrap().metadata.response_code,
        ResponseCode::Refused
    );
}
