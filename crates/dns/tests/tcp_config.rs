use super::*;

#[test]
fn tcp_backlog_matches_the_socket_apis_positive_signed_range() {
    assert!(serde_yaml::from_str::<DnsConfig>("tcp_backlog: 0").is_err());
    let provider = DnsConfigProvider::empty(PathBuf::from("dns.yaml"));
    let oversized: DnsConfig =
        serde_yaml::from_str("tcp_backlog: 2147483648").unwrap();
    assert!(provider.validate_config(&oversized).is_err());
    let valid: DnsConfig = serde_yaml::from_str("tcp_backlog: 2048").unwrap();
    assert!(provider.validate_config(&valid).is_ok());
}
