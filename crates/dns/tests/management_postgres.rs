//! Explicit live-store test. Run only against a disposable PostgreSQL database
//! with the DNS table, notification and serial migrations already installed.
use claviron_dns::management::{DnsStore, ManagementError, Record, Zone};

#[tokio::test]
#[ignore = "requires CLAVIRON_DNS_TEST_DATABASE_URL for a disposable DNS database"]
async fn domain_and_record_mutations_commit_and_enforce_deletion_intent() {
    let url = std::env::var("CLAVIRON_DNS_TEST_DATABASE_URL")
        .expect("explicit test database");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let empty: bool =
        sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM dns.dns_zones)")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(empty, "test requires an empty disposable DNS store");
    let store = DnsStore::new(pool.clone());
    let zone = store
        .save_zone(
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
            },
            false,
        )
        .await
        .unwrap();
    assert_eq!(zone.domain, "example.test");
    assert_eq!(store.list_zones(false).await.unwrap().len(), 1);
    let (mut record, changed) = store
        .save_record(
            Some(&zone.domain),
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
            },
        )
        .await
        .unwrap();
    assert!(changed.soa_serial > zone.soa_serial);
    assert_eq!(
        store.list_records("EXAMPLE.test.", true).await.unwrap().len(),
        1
    );
    assert!(matches!(
        store.remove_zone(zone.id, false).await,
        Err(ManagementError::NonemptyZone)
    ));
    let mut conflict = record.clone();
    conflict.record_type = "CNAME".into();
    conflict.value = "target.example.test".into();
    assert!(matches!(
        store.save_record(Some(&zone.domain), conflict).await,
        Err(ManagementError::Invalid(_))
    ));
    record.value = "192.0.2.2".into();
    let (record, replaced) = store.save_record(None, record).await.unwrap();
    assert!(replaced.soa_serial > changed.soa_serial);
    let removed = store.remove_record(record.id).await.unwrap();
    assert!(removed.soa_serial > replaced.soa_serial);
    assert!(store.list_records(&zone.domain, false).await.unwrap().is_empty());
    let mut updated = removed;
    updated.enabled = false;
    store.save_zone(updated, true).await.unwrap();
    assert!(store.list_zones(true).await.unwrap().is_empty());
    store.remove_zone(zone.id, false).await.unwrap();
    assert!(matches!(
        store.get_zone(&zone.domain).await,
        Err(ManagementError::NotFound)
    ));
    let restored = store.save_zone(zone, false).await.unwrap();
    store.save_record(Some(&restored.domain), record).await.unwrap();
    store.remove_zone(restored.id, true).await.unwrap();
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM dns.dns_records")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0);
    pool.close().await;
}
