use super::*;

#[test]
fn issuance_input_requires_explicit_validity_and_exact_client_names() {
    let request = |name: &str, days| CreateCertificateRequest {
        issuer: None,
        ca_path_len: None,
        kind: crate::proto::mtls::CertificateKind::Client as i32,
        common_name: name.into(),
        aliases: vec![
            "client.test".into(),
            "alias.test".into(),
            "alias.test".into(),
        ],
        validity_days: days,
    };
    assert!(input(request("client.test", 0)).is_err());
    assert!(input(request("client.test", u32::MAX)).is_err());
    assert!(input(request("*.test", 1)).is_err());
    let IssuanceRequest { name, aliases, .. } =
        input(request("client.test", 1)).unwrap();
    assert_eq!(name, "client.test");
    assert_eq!(aliases, ["client.test", "alias.test"]);
}

#[tokio::test]
async fn ca_server_and_client_material_stays_in_database() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("fixtures/certificates.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let store = HostingStore::sqlite(pool.clone());
    let manager = MtlsManager::new(store.clone(), Some(1), None);
    let root = manager
        .create_root_ca(CreateRootCaRequest {
            common_name: "root.test".into(),
            validity_days: 30,
            organization: None,
            country: None,
        })
        .await
        .unwrap();
    assert_eq!(root.issuer_id, None);
    let issuer = store.issuer_by_name("root.test").await.unwrap().unwrap();
    let authority =
        CertAuthority::from_issuer(&store, "root.test").await.unwrap();
    let configured = MtlsManager::new(
        store.clone(),
        Some(1),
        Some(Arc::new(authority.clone())),
    );
    let default_client = configured
        .create_certificate(CreateCertificateRequest {
            issuer: None,
            common_name: "default-client.test".into(),
            aliases: vec![],
            validity_days: 1,
            kind: crate::proto::mtls::CertificateKind::Client as i32,
            ca_path_len: None,
        })
        .await
        .unwrap();
    assert_eq!(default_client.issuer_id, Some(issuer.id));
    for (kind, name, server) in [
        (CertificateKind::Client, "client.test", None),
        (CertificateKind::Server, "server.test", Some(1)),
        (CertificateKind::Ca, "intermediate.test", None),
    ] {
        let info = manager
            .create_certificate(CreateCertificateRequest {
                issuer: Some("root.test".into()),
                common_name: name.into(),
                aliases: if kind == CertificateKind::Ca {
                    vec![]
                } else {
                    vec!["alternate.test".into()]
                },
                validity_days: 1,
                kind: match kind {
                    CertificateKind::Server => {
                        crate::proto::mtls::CertificateKind::Server as i32
                    }
                    CertificateKind::Client => {
                        crate::proto::mtls::CertificateKind::Client as i32
                    }
                    CertificateKind::Ca => {
                        crate::proto::mtls::CertificateKind::Ca as i32
                    }
                },
                ca_path_len: (kind == CertificateKind::Ca).then_some(0),
            })
            .await
            .unwrap();
        assert_eq!(info.issuer_id, Some(issuer.id));
        assert_eq!(
            info.aliases,
            if kind == CertificateKind::Ca {
                vec![]
            } else {
                vec!["alternate.test"]
            }
        );
        let saved = store.certificate_by_id(info.id).await.unwrap().unwrap();
        assert!(!saved.key_der.is_empty());
        assert_eq!(saved.kind, kind);
        let renewed = manager
            .renew_certificate(RenewCertificateRequest {
                common_name: name.into(),
                validity_days: 2,
            })
            .await
            .unwrap();
        assert_eq!(renewed.id, info.id);
        assert_eq!(renewed.aliases, info.aliases);
        assert_eq!(renewed.issuer_id, info.issuer_id);
        let updated = store.certificate_by_id(info.id).await.unwrap().unwrap();
        assert_eq!(updated.key_der, saved.key_der);
        assert_ne!(updated.certs_der, saved.certs_der);
        let before = take_first_cert_from_der(&saved.certs_der).unwrap();
        let after = take_first_cert_from_der(&updated.certs_der).unwrap();
        assert_eq!(before.subject().as_raw(), after.subject().as_raw());
        assert_eq!(before.extensions(), after.extensions());
        let root_material =
            store.certificate_by_id(root.id).await.unwrap().unwrap();
        let signer =
            take_first_cert_from_der(&root_material.certs_der).unwrap();
        assert!(after.verify_signature(Some(signer.public_key())).is_ok());
        assert_eq!(
            store.servers_for_certificate(name).await.unwrap().len(),
            usize::from(server.is_some())
        );
    }
    let root_before = store.certificate_by_id(root.id).await.unwrap().unwrap();
    let renewed = manager
        .renew_certificate(RenewCertificateRequest {
            common_name: "root.test".into(),
            validity_days: 30,
        })
        .await
        .unwrap();
    assert_eq!(renewed.id, root.id);
    let root_after = store.certificate_by_id(root.id).await.unwrap().unwrap();
    assert_eq!(root_before.key_der, root_after.key_der);
    assert!(matches!(
        store
            .renew_certificate_material(
                &root_before,
                root_before.certs_der.clone(),
                root_before.issued_at,
                root_before.expires_at
            )
            .await,
        Err(HostingError::Conflict(_))
    ));
    assert!(store.issuer_by_name("intermediate.test").await.unwrap().is_some());
    assert_eq!(store.acme_certificates(true, None).await.unwrap().len(), 0);
    let other = store.ensure_acme_issuer(1).await.unwrap();
    assert!(CertAuthority::from_issuer(&store, &other.name).await.is_err());
    store.set_certificate_enabled("root.test", false).await.unwrap();
    assert!(CertAuthority::from_issuer(&store, "root.test").await.is_err());
    assert!(authority.validate_issuer(&store).await.is_err());
}
