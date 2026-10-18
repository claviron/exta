use super::*;

fn record(record_type: &str) -> Record {
    Record {
        id: 0,
        zone_id: 0,
        name: "www".into(),
        record_type: record_type.into(),
        value: "192.0.2.1".into(),
        ttl: 0,
        priority: None,
        weight: None,
        port: None,
        enabled: true,
    }
}

#[test]
fn mutations_reject_values_the_snapshot_cannot_serve() {
    let mut r = record("A");
    r.validate("EXAMPLE.test.").unwrap();
    r.value = "not-an-ip".into();
    assert!(r.validate("example.test").is_err());
    let mut r = record("CAA");
    assert!(r.validate("example.test").is_err());
    let mut r = record("TXT");
    r.value = "x".repeat(256);
    assert!(r.validate("example.test").is_err());
    let mut r = record("A");
    r.port = Some(0);
    assert!(r.validate("example.test").is_err());
}

#[test]
fn srv_preserves_zero_metadata_and_mx_requires_priority() {
    let mut r = record("SRV");
    r.name = "_service._tcp".into();
    r.value = "target.example.test".into();
    assert!(r.validate("example.test").is_err());
    r.priority = Some(0);
    r.weight = Some(0);
    r.port = Some(0);
    r.validate("example.test").unwrap();
    r.port = Some(65536);
    assert!(r.validate("example.test").is_err());
    let mut r = record("MX");
    r.value = "mail.example.test".into();
    assert!(r.validate("example.test").is_err());
    r.priority = Some(0);
    r.validate("example.test").unwrap();
}

#[test]
fn zone_keys_normalize_but_root_and_wildcard_are_not_zones() {
    assert_eq!(domain("EXAMPLE.test.").unwrap(), "example.test");
    assert!(domain(".").is_err());
    assert!(domain("*.example.test").is_err());
}
