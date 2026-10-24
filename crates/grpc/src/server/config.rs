use std::net::SocketAddr;
use std::time::Duration;

use claviron::edge::Host;
use claviron::helpers::de::{deserialize_duration, one_or_many};
use claviron::http::config::acl::AccessLimiter;
use claviron::http::config::{H2Config, TcpConfig};
use claviron::orbit::placement::{Dispatch, DispatchPolicy, Scope};
use serde::Deserialize;

/// What the management service's configuration file is called in the config
/// directory.
pub const CONFIG_FILE: &str = "grpc.yaml";

/// `grpc.yaml`: which resolved vhost keys carry the management service and
/// how it bounds its requests. Prepared by Congif; see `GrpcServiceProvider`.
#[derive(Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GrpcConfig {
    #[cfg(any(feature = "users", feature = "authorization"))]
    #[serde(default)]
    pub user_management: Option<super::management::Limits>,
    #[serde(default)]
    pub listener: Option<ListenerConfig>,
    #[serde(default, deserialize_with = "one_or_many", alias = "vhost")]
    vhosts: Vec<Host>,
    #[serde(
        default = "default_request_timeout",
        deserialize_with = "deserialize_duration"
    )]
    pub request_timeout: Duration,
    #[serde(default = "default_max_requests")]
    pub max_requests: usize,
}

impl GrpcConfig {
    pub fn vhosts(&self) -> &[Host] {
        &self.vhosts
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.max_requests == 0 {
            return Err("grpc.max_requests must be greater than zero".into());
        }
        if let Some(listener) = &self.listener {
            listener
                .dispatch
                .validate_policy(listener.dispatch_policy)
                .map_err(|error| format!("grpc.listener: {error}"))?;
            if listener.hosts.is_empty()
                || listener
                    .hosts
                    .iter()
                    .any(|host| host.is_ip() || host.to_string().contains('*'))
            {
                return Err(
                    "grpc.listener.hosts requires concrete TLS server names"
                        .into(),
                );
            }
            if listener.listen.is_empty() {
                return Err(
                    "grpc.listener.listen must contain a bind address".into()
                );
            }
            for (index, hostname) in listener.hosts.iter().enumerate() {
                if listener.hosts[..index].contains(hostname) {
                    return Err(
                        "grpc.listener.hosts contains a duplicate server name"
                            .into(),
                    );
                }
            }
            for (index, address) in listener.listen.iter().enumerate() {
                if listener.listen[..index]
                    .iter()
                    .any(|other| binds_overlap(*other, *address))
                {
                    return Err("grpc.listener.listen contains overlapping bind addresses".into());
                }
            }
            if listener.max_connections == 0 {
                return Err(
                    "grpc.listener.max_connections must be greater than zero"
                        .into(),
                );
            }
            let h2 = &listener.h2;
            if h2.max_concurrent_streams == 0
                || h2.max_send_buf_size == 0
                || h2.max_header_list_size == 0
                || !(16_384..=16_777_215).contains(&h2.max_frame_size)
                || h2.max_send_buf_size > u32::MAX as usize
            {
                return Err("grpc.listener.h2 limits are invalid".into());
            }
            let retry = &listener.tcp.accept_retry;
            if retry.initial.is_zero() || retry.max < retry.initial {
                return Err("grpc.listener.tcp.accept_retry requires positive initial <= max".into());
            }
            if listener.handshake_timeout.is_some_and(|bound| bound.is_zero()) {
                return Err("grpc.listener.handshake_timeout must be positive when declared".into());
            }
            if h2.keep_alive_interval.is_some_and(|bound| bound.is_zero())
                || h2.keep_alive_timeout.is_zero()
            {
                return Err(
                    "grpc.listener.h2 heartbeat bounds must be positive".into(),
                );
            }
        }
        Ok(())
    }
}

/// Explicit listener policy. No handshake or drain deadline is invented.
#[derive(Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    /// Placement belongs to the reserved runnable, never the vhost bindings.
    #[serde(default)]
    pub scope: Scope,
    #[serde(default)]
    pub dispatch: Dispatch,
    #[serde(default)]
    pub dispatch_policy: Option<DispatchPolicy>,
    /// Actual SSL server names, resolved only to prepare TLS policy, not routes.
    #[serde(deserialize_with = "one_or_many", alias = "host")]
    pub hosts: Vec<Host>,
    #[serde(deserialize_with = "one_or_many")]
    pub listen: Vec<SocketAddr>,
    pub max_connections: usize,
    /// Dedicated admission only. Vhost ACL remains owned by Edge.
    pub acl: AccessLimiter,
    #[serde(default, with = "humantime_serde")]
    pub handshake_timeout: Option<Duration>,
    #[serde(default, with = "humantime_serde")]
    pub graceful_timeout: Option<Duration>,
    #[serde(default)]
    pub tcp: TcpConfig,
    #[serde(default)]
    pub h2: H2Config,
}

/// No file: the service is declared but bound to no vhost.
impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            #[cfg(any(feature = "users", feature = "authorization"))]
            user_management: None,
            listener: None,
            vhosts: Vec::new(),
            request_timeout: default_request_timeout(),
            max_requests: default_max_requests(),
        }
    }
}

fn default_request_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_max_requests() -> usize {
    100
}

/// Conservative socket overlap, including wildcard and dual-stack IPv6 binds.
/// Port zero asks the kernel for a distinct ephemeral port; UDP is checked by
/// its own owner, never against this reserved TCP listener.
pub(crate) fn binds_overlap(
    left: SocketAddr,
    right: SocketAddr,
) -> bool {
    use std::net::IpAddr;
    if left.port() == 0 || right.port() == 0 || left.port() != right.port() {
        return false;
    }
    match (left.ip(), right.ip()) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            a == b || a.is_unspecified() || b.is_unspecified()
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            a == b || a.is_unspecified() || b.is_unspecified()
        }
        (IpAddr::V6(v6), IpAddr::V4(v4)) | (IpAddr::V4(v4), IpAddr::V6(v6)) => {
            v6.is_unspecified()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped == v4 || v4.is_unspecified())
        }
    }
}

#[cfg(test)]
#[path = "../../tests/ingress_config.rs"]
mod tests;
