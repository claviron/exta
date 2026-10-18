use super::{GrpcConfig, binds_overlap};
use claviron::orbit::placement::{Dispatch, Scope};

const LISTENER: &str = "listener:\n  hosts: [management.example.test]\n  listen: [127.0.0.1:9443, 127.0.0.1:9444]\n  scope: workers\n  dispatch: one\n  dispatch_policy: {capacity: 1, lease_ttl: 20s, renewal_interval: 5s}\n  max_connections: 4\n  acl: {policy: deny, allowed: [127.0.0.0/8]}\n";

#[test]
fn absence_binds_nothing_and_retired_auth_switches_are_rejected() {
    let config = GrpcConfig::default();
    assert!(config.vhosts().is_empty());
    assert!(config.listener.is_none());
    config.validate().unwrap();
    for retired in [
        "enabled: true",
        "host: management",
        "hosts: management",
        "mode: both",
        "require_client_auth: false",
        "dedicated: {}",
    ] {
        assert!(serde_yaml::from_str::<GrpcConfig>(retired).is_err());
    }
}

#[test]
fn vhosts_and_reserved_listener_are_independent() {
    for selector in ["", "vhosts: [management]\n"] {
        let config: GrpcConfig =
            serde_yaml::from_str(&format!("{selector}{LISTENER}")).unwrap();
        config.validate().unwrap();
        let listener = config.listener.unwrap();
        assert_eq!(listener.listen.len(), 2);
        assert_eq!(listener.scope, Scope::Worker);
        assert_eq!(listener.dispatch, Dispatch::One);
        assert!(listener.graceful_timeout.is_none());
        assert!(
            serde_yaml::from_str::<GrpcConfig>(&LISTENER.replace(
                "  acl: {policy: deny, allowed: [127.0.0.0/8]}\n",
                ""
            ))
            .is_err()
        );
        assert!(
            serde_yaml::from_str::<GrpcConfig>(&format!(
                "{LISTENER}  ca_bundle: ca.pem\n"
            ))
            .is_err()
        );
    }
    let config: GrpcConfig = serde_yaml::from_str("vhost: management").unwrap();
    assert_eq!(config.vhosts().len(), 1);
    assert!(config.listener.is_none());
}

#[test]
fn tcp_bind_conflicts_include_wildcards_but_not_other_ports() {
    let overlap = |a: &str, b: &str| {
        binds_overlap(a.parse().unwrap(), b.parse().unwrap())
    };
    assert!(overlap("127.0.0.1:9443", "127.0.0.1:9443"));
    assert!(overlap("0.0.0.0:9443", "127.0.0.1:9443"));
    assert!(overlap("[::]:9443", "127.0.0.1:9443"));
    assert!(overlap("[::ffff:127.0.0.1]:9443", "127.0.0.1:9443"));
    assert!(!overlap("127.0.0.1:9443", "127.0.0.1:9444"));
    assert!(!overlap("127.0.0.1:9443", "127.0.0.2:9443"));
    assert!(!overlap("0.0.0.0:0", "127.0.0.1:0"));
}
