use super::*;
use crate::management::{ManagementError, Record, Zone};
use crate::providers::event::DnsChanged;
use claviron::orbit::FleetEventCodec;
use claviron::runtime::events::ProcessEventBus;
use std::sync::Arc;
use tokio::sync::broadcast::error::TryRecvError;

fn zone() -> Zone {
    Zone {
        id: 0,
        domain: "EXAMPLE.test.".into(),
        soa_serial: 0,
        soa_refresh: 3600,
        soa_retry: 600,
        soa_expire: 604800,
        soa_minimum: 300,
        soa_mname: "ns.example.test".into(),
        soa_rname: "hostmaster.example.test".into(),
        enabled: true,
    }
}

fn record() -> Record {
    Record {
        id: 0,
        zone_id: 0,
        name: "www".into(),
        record_type: "A".into(),
        value: "192.0.2.1".into(),
        ttl: 0,
        priority: None,
        weight: None,
        port: None,
        enabled: true,
    }
}

#[tokio::test]
async fn dns_sqlite_mutations_commit_before_events_and_roll_back_failures() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("fixtures/store.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let bus = ProcessEventBus::default();
    let mut events = bus.subscribe::<DnsChanged>();
    let store =
        DnsStore::sqlite(pool.clone()).announcing(Arc::new(move || {
            bus.emit(DnsChanged);
        }));
    let zone = store.save_zone(zone(), false).await.unwrap();
    events.try_recv().unwrap();
    assert_eq!(zone.domain, "example.test");
    let (mut record, changed) =
        store.save_record(Some(&zone.domain), record()).await.unwrap();
    events.try_recv().unwrap();
    assert!(changed.soa_serial > zone.soa_serial);
    let snapshot = store.load_zones().await.unwrap();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].records[0].ttl, 0);
    assert_eq!(snapshot[0].soa.serial, changed.soa_serial);
    let mut conflict = record.clone();
    conflict.record_type = "CNAME".into();
    conflict.value = "target.example.test".into();
    assert!(matches!(
        store.save_record(Some(&zone.domain), conflict).await,
        Err(ManagementError::Invalid(_))
    ));
    assert!(matches!(
        store.remove_zone(zone.id, false).await,
        Err(ManagementError::NonemptyZone)
    ));
    assert!(
        store.save_record(Some(&zone.domain), record.clone()).await.is_err()
    );
    let mut deferred = record.clone();
    deferred.name = "deferred".into();
    assert!(store.save_record(Some(&zone.domain), deferred).await.is_err());
    assert!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
    assert_eq!(
        store.get_zone(&zone.domain).await.unwrap().soa_serial,
        changed.soa_serial
    );
    assert_eq!(store.list_records(&zone.domain, false).await.unwrap().len(), 1);
    record.value = "192.0.2.2".into();
    let (record, updated) = store.save_record(None, record).await.unwrap();
    events.try_recv().unwrap();
    assert!(updated.soa_serial > changed.soa_serial);
    let removed = store.remove_record(record.id).await.unwrap();
    events.try_recv().unwrap();
    assert!(removed.soa_serial > updated.soa_serial);
    let mut disabled = removed;
    disabled.enabled = false;
    let disabled = store.save_zone(disabled, true).await.unwrap();
    events.try_recv().unwrap();
    assert!(disabled.soa_serial > updated.soa_serial);
    assert!(store.list_zones(true).await.unwrap().is_empty());
    assert!(store.load_zones().await.unwrap().is_empty());
    let (record, _) =
        store.save_record(Some(&zone.domain), record).await.unwrap();
    events.try_recv().unwrap();
    assert!(
        store
            .list_records(&zone.domain, true)
            .await
            .unwrap()
            .iter()
            .any(|r| r.id == record.id)
    );
    store.remove_zone(zone.id, true).await.unwrap();
    events.try_recv().unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM dns_records")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    assert!(matches!(
        store.get_zone(&zone.domain).await,
        Err(ManagementError::NotFound)
    ));
    store.request_reload().await.unwrap();
    events.try_recv().unwrap();
    pool.close().await;
}

#[test]
fn dns_change_codec_round_trips_without_accepting_invalid_payloads() {
    assert!(DnsChanged::decode_orbit(&DnsChanged.encode_orbit()).is_ok());
    assert!(DnsChanged::decode_orbit(&[]).is_err());
    assert!(DnsChanged::decode_orbit(&[2]).is_err());
}
