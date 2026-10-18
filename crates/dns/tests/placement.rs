use std::path::PathBuf;
use std::sync::Arc;

use claviron::orbit::placement::{Dispatch, Dispatched, Scope, Scoped};

use super::DnsServer;
use crate::providers::{DnsConfig, DnsConfigProvider};

#[test]
fn absent_placement_preserves_every_worker() {
    let config: DnsConfig = serde_yaml::from_str("enabled: true").unwrap();
    assert_eq!(config.scope, Scope::Worker);
    assert_eq!(config.dispatch, Dispatch::Each);
}

#[test]
fn listener_uses_the_prepared_config_for_worker_selection() {
    let owner = Arc::new(DnsConfigProvider::empty(PathBuf::from("dns.yaml")));
    let listener = DnsServer::new(owner.clone());
    let config =
        serde_yaml::from_str("enabled: true\nscope: workers\ndispatch: one\ndispatch_policy: {capacity: 1, lease_ttl: 20s, renewal_interval: 5s}\n")
            .unwrap();
    owner.replace_for_test(config);

    assert_eq!(listener.scope(), Scope::Worker);
    assert_eq!(listener.dispatch(), Dispatch::One);
    listener.dispatch().validate_policy(listener.dispatch_policy()).unwrap();
}

#[test]
fn invalid_listener_dispatch_is_rejected() {
    assert!(serde_yaml::from_str::<DnsConfig>("dispatch: first").is_err());
}
