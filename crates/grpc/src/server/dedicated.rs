//! Dedicated management transport; the management service and edge binding
//! remain independent. TLS identity comes only from the terminating session.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::poll_fn;
use std::sync::Arc;
use std::task::Poll;

use async_trait::async_trait;
use claviron::edge::transport::VhostTable;
use claviron::edge::{BypassHandler, Host, HttpConfigProvider, VhostResolver};
use claviron::http::ext::{
    ClientAuthStatus, ConnCtx, TlsClientCertInfo, TlsInfo,
};
use claviron::http::listener::ListenerTransport;
use claviron::http::{ListenerId, boxed_body};
use claviron::orbit::placement::{
    Dispatch, DispatchPolicy, Dispatched, Scope, Scoped,
};
use claviron::runtime::registry::{
    Component, ComponentOrder, Error, Result, Runnable,
};
use claviron::runtime::{AppState, RunContext, RunMode, ServiceStartPolicy};
use claviron::sys::net::{
    AcceptErrorClass, PortSharing, classify_accept_error, create_tcp_listener,
};
use claviron::tls::auth::create_tcp_auth_config;
use claviron::tls::auth::verifier::PolicyConfig;
use claviron::tls::{CertResolver, CertResolverProvider, Proto};
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::ServerConfig;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::LazyConfigAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::bypass::ManagementGrpcHandler;
use super::config::{GrpcConfig, ListenerConfig, binds_overlap};
use super::provider::GrpcServiceProvider;
use super::services::ManagementTransport;

pub(crate) const LISTENER_SERVICE: &str = "GrpcListener";

/// Registered with the service; runnable only when a dedicated ingress was
/// explicitly declared. Its stop/restart never owns the web listener.
pub struct GrpcListener {
    service: Arc<GrpcServiceProvider>,
}

impl GrpcListener {
    pub(crate) fn new(service: Arc<GrpcServiceProvider>) -> Self {
        Self { service }
    }
}

impl Scoped for GrpcListener {
    fn scope(&self) -> Scope {
        self.service
            .config()
            .listener
            .as_ref()
            .map(|listener| listener.scope)
            .unwrap_or_default()
    }
}

impl Dispatched for GrpcListener {
    fn dispatch(&self) -> Dispatch {
        self.service
            .config()
            .listener
            .as_ref()
            .map(|listener| listener.dispatch)
            .unwrap_or_default()
    }

    fn dispatch_policy(&self) -> Option<DispatchPolicy> {
        self.service
            .config()
            .listener
            .as_ref()
            .and_then(|listener| listener.dispatch_policy)
    }
}

#[async_trait]
impl Component<AppState> for GrpcListener {
    // Vhost-only management needs no dedicated TLS resolver.
    type Deps = (
        Arc<GrpcServiceProvider>,
        Option<Arc<CertResolver>>,
        Option<Arc<VhostResolver>>,
    );

    fn name(&self) -> &'static str {
        LISTENER_SERVICE
    }
    fn as_scoped(&self) -> Option<&dyn Scoped> {
        Some(self)
    }
    fn as_dispatched(&self) -> Option<&dyn Dispatched> {
        Some(self)
    }
    fn order(&self) -> ComponentOrder {
        ComponentOrder::new().after::<CertResolverProvider>()
    }
    fn validate(
        &self,
        state: &AppState,
    ) -> Result<()> {
        if let Some(listener) = self.service.config().listener.as_ref() {
            validate_bindings(listener, state)?;
        }
        Ok(())
    }
    fn as_runnable(
        self: Arc<Self>
    ) -> Option<Arc<dyn Runnable<AppState, Self::Deps>>> {
        Some(self)
    }
}

#[async_trait]
impl Runnable<AppState, <Self as Component<AppState>>::Deps> for GrpcListener {
    fn start_policy(
        &self,
        _state: &AppState,
    ) -> ServiceStartPolicy {
        if self.service.config().listener.is_some() {
            ServiceStartPolicy::Automatic
        } else {
            ServiceStartPolicy::Unavailable
        }
    }

    async fn run(
        self: Arc<Self>,
        (service, certs, vhosts): <Self as Component<AppState>>::Deps,
        state: AppState,
        context: RunContext,
    ) -> Result<()> {
        let config = service.config();
        config.validate().map_err(Error::msg)?;
        let policy = config.listener.as_ref().ok_or_else(|| {
            Error::msg("gRPC dedicated ingress is not configured")
        })?;
        validate_bindings(policy, &state)?;
        let shared = certs.ok_or_else(|| {
            Error::msg("gRPC certificate resolver is not registered")
        })?;
        let names = vhosts
            .ok_or_else(|| {
                Error::msg("gRPC TLS hostname policy is not registered")
            })?
            .snapshot();
        let tls_policy = policy.clone();
        // Prepare the existing client-auth policy off the executor: its CA
        // may be file-backed. No request performs this work or resolves a vhost.
        let tls_configs = Arc::new(
            tokio::task::spawn_blocking(move || {
                prepare_tls(&tls_policy, shared, &names)
            })
            .await
            .map_err(|error| {
                Error::msg(format!("gRPC TLS preparation: {error}"))
            })??,
        );
        let handler = Arc::new(service.handler(
            state.clone(),
            &config,
            "dedicated management".into(),
        )?);
        let sharing = match state.run_mode() {
            RunMode::Worker(_) | RunMode::Master => PortSharing::Shared,
            RunMode::Standalone => PortSharing::Exclusive,
        };
        let mut listeners = Vec::with_capacity(policy.listen.len());
        for address in &policy.listen {
            listeners.push(
                create_tcp_listener(*address, sharing).await.map_err(
                    |error| {
                        Error::msg(format!(
                            "gRPC dedicated bind {address}: {error}"
                        ))
                    },
                )?,
            );
        }
        let permits = Arc::new(Semaphore::new(policy.max_connections));
        let cancellation = context.cancellation_token().child_token();
        let mut connections = JoinSet::new();
        let mut next_listener = 0;
        let mut retry_delay = policy.tcp.accept_retry.initial;
        info!(listen = ?policy.listen, "gRPC dedicated listener started");
        let result = loop {
            // One generation, with fair wake-driven accept across every bind.
            let accepted = poll_fn(|cx| {
                for offset in 0..listeners.len() {
                    let index = (next_listener + offset) % listeners.len();
                    if let Poll::Ready(result) =
                        listeners[index].poll_accept(cx)
                    {
                        next_listener = (index + 1) % listeners.len();
                        return Poll::Ready(result);
                    }
                }
                Poll::Pending
            });
            tokio::select! {
                biased;
                () = context.cancelled() => break Ok(()),
                joined = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = joined { warn!(%error, "gRPC connection task failed"); }
                },
                accepted = accepted => {
                    let (stream, peer) = match accepted {
                        Ok(accepted) => { retry_delay = policy.tcp.accept_retry.initial; accepted },
                        Err(error) => match classify_accept_error(&error) {
                            AcceptErrorClass::Transient => continue,
                            AcceptErrorClass::Fatal => break Err(Error::msg(format!("gRPC accept: {error}"))),
                            AcceptErrorClass::ResourcePressure => {
                                warn!(%error, ?retry_delay, "gRPC accept resource pressure");
                                tokio::select! {
                                    biased;
                                    () = context.cancelled() => break Ok(()),
                                    () = tokio::time::sleep(retry_delay) => {}
                                }
                                retry_delay = retry_delay.saturating_mul(2).min(policy.tcp.accept_retry.max);
                                continue;
                            }
                        },
                    };
                    if !policy.acl.is_allowed(peer.ip()) {
                        debug!(%peer, "gRPC connection rejected by listener ACL");
                        continue;
                    }
                    let Ok(permit) = permits.clone().try_acquire_owned() else {
                        debug!(%peer, "gRPC connection rejected at capacity");
                        continue;
                    };
                    let handler = handler.clone();
                    let tls_configs = tls_configs.clone();
                    let config = config.clone();
                    let cancellation = cancellation.clone();
                    connections.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = serve(stream, peer, tls_configs, handler, config, cancellation).await {
                            debug!(%peer, %error, "gRPC dedicated connection closed");
                        }
                    });
                }
            }
        };
        drop(listeners);
        cancellation.cancel();
        let drain = async { while connections.join_next().await.is_some() {} };
        match policy.graceful_timeout {
            Some(grace) => {
                if tokio::time::timeout(grace, drain).await.is_err() {
                    warn!(
                        remaining = connections.len(),
                        "gRPC dedicated graceful timeout expired"
                    );
                    connections.abort_all();
                    while connections.join_next().await.is_some() {}
                }
            }
            None => drain.await,
        }
        info!(listen = ?policy.listen, "gRPC dedicated listener stopped");
        result
    }
}

/// Existing HTTP configuration is the socket inventory for every vhost.
/// Check desired topology, even when the HTTP runnable is currently stopped:
/// allowing a reserved bind there would make its next start nondeterministic.
fn validate_bindings(
    policy: &ListenerConfig,
    state: &AppState,
) -> Result<()> {
    let Some(http) = state.registry_ref().resolve::<HttpConfigProvider>()
    else {
        return Ok(());
    };
    let snapshot = http.snapshot();
    for listener in snapshot
        .listeners
        .values()
        .filter(|listener| listener.transport() == ListenerTransport::Tcp)
    {
        for reserved in &policy.listen {
            for address in &listener.listen {
                if binds_overlap(*reserved, *address) {
                    return Err(Error::msg(format!(
                        "gRPC reserved bind {reserved} conflicts with edge TCP listener '{}' at {address}; reuseport must not mix different services",
                        listener.id
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Server names borrow TLS policy, not vhost application routing. Each policy
/// is compiled once; aliases of the same TLS owner share the resulting config.
fn prepare_tls(
    policy: &ListenerConfig,
    certs: Arc<CertResolver>,
    names: &VhostTable,
) -> Result<HashMap<String, Arc<ServerConfig>>> {
    let mut by_name = HashMap::new();
    let mut by_key: HashMap<Host, Arc<ServerConfig>> = HashMap::new();
    for hostname in &policy.hosts {
        let (key, host) = names.resolve_exact(hostname).ok_or_else(|| {
            Error::msg(format!(
                "gRPC TLS hostname '{hostname}' has no configured TLS policy"
            ))
        })?;
        if !certs.contains(&hostname.to_string()) {
            return Err(Error::msg(format!(
                "gRPC TLS hostname '{hostname}' has no loaded certificate"
            )));
        }
        let config = if let Some(config) = by_key.get(&key) {
            config.clone()
        } else {
            let tls_policy = host.tls_policy();
            let auth = &tls_policy.client_auth;
            if !auth.is_required() {
                return Err(Error::msg(format!(
                    "gRPC TLS hostname '{hostname}' requires tls.client_auth.mode=required"
                )));
            }
            let ca = auth.ca_bundle.as_deref().ok_or_else(|| {
                Error::msg(format!("gRPC TLS hostname '{hostname}' has no configured client-auth CA"))
            })?;
            let subject = match (&auth.organization, &auth.unit) {
                (Some(organization), Some(unit)) => {
                    Some(PolicyConfig::new(organization.clone(), unit.clone()))
                }
                (None, None) => None,
                _ => {
                    return Err(Error::msg(format!(
                        "gRPC TLS hostname '{hostname}' must configure organization and unit together"
                    )));
                }
            };
            let config = Arc::new(
                create_tcp_auth_config(
                    ca,
                    certs.clone(),
                    vec![b"h2".to_vec()],
                    subject.as_ref(),
                )
                .map_err(|error| {
                    Error::msg(format!(
                        "gRPC TLS hostname '{hostname}': {error}"
                    ))
                })?,
            );
            by_key.insert(key, config.clone());
            config
        };
        by_name.insert(hostname.to_string(), config);
    }
    Ok(by_name)
}

async fn serve(
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    tls_configs: Arc<HashMap<String, Arc<ServerConfig>>>,
    handler: Arc<ManagementGrpcHandler>,
    config: Arc<GrpcConfig>,
    cancellation: CancellationToken,
) -> std::result::Result<(), String> {
    let policy = config.listener.as_ref().expect("listener configuration");
    let local = stream.local_addr().map_err(|error| error.to_string())?;
    stream
        .set_nodelay(policy.tcp.nodelay)
        .map_err(|error| error.to_string())?;
    let socket = socket2::SockRef::from(&stream);
    match policy.tcp.keepalive {
        Some(time) => socket
            .set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(time)),
        None => socket.set_keepalive(false),
    }
    .map_err(|error| error.to_string())?;
    let handshake = async {
        let start = LazyConfigAcceptor::new(
            rustls::server::Acceptor::default(),
            stream,
        )
        .await
        .map_err(|error| error.to_string())?;
        let name = start
            .client_hello()
            .server_name()
            .ok_or("gRPC TLS requires SNI")?
            .to_ascii_lowercase();
        let tls = tls_configs.get(&name).cloned().ok_or_else(|| {
            format!(
                "gRPC TLS server name '{name}' is not enabled on this listener"
            )
        })?;
        start.into_stream(tls).await.map_err(|error| error.to_string())
    };
    let tls = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Ok(()),
        tls = async {
            match policy.handshake_timeout {
                Some(bound) => tokio::time::timeout(bound, handshake).await.map_err(|_| "gRPC TLS handshake timed out".to_owned())?,
                None => handshake.await,
            }
        } => tls?,
    };
    let session = tls.get_ref().1;
    if session.alpn_protocol() != Some(b"h2") {
        return Err("gRPC requires h2 ALPN".into());
    }
    let client_cert = session
        .peer_certificates()
        .and_then(|certs| certs.first())
        .and_then(|cert| {
            let parsed =
                claviron::ssl::parsers::take_first_cert_from_der(cert.as_ref())
                    .ok()?;
            Some(TlsClientCertInfo {
                subject_dn: parsed.subject().to_string(),
                issuer_dn: parsed.issuer().to_string(),
                identity: claviron::ssl::peer::peer_identity(cert.as_ref())
                    .ok()
                    .map(Arc::new),
            })
        });
    let ctx = Arc::new(ConnCtx {
        state: Default::default(),
        listener: ListenerId::try_from("grpc-dedicated".to_owned())
            .map_err(|error| error.to_string())?,
        proto: Some(Proto::H2),
        remote: peer,
        local_ip: local.ip(),
        local_port: local.port(),
        real_ip: Some(peer.ip()),
        country_code: None,
        tls: Some(TlsInfo {
            protocol_version: session.protocol_version(),
            cipher_suite: session
                .negotiated_cipher_suite()
                .map(|suite| suite.suite()),
            client_auth: if client_cert.is_some() {
                ClientAuthStatus::Verified
            } else {
                ClientAuthStatus::NotProvided
            },
            client_cert,
        }),
    });
    let service =
        service_fn(move |request: http::Request<hyper::body::Incoming>| {
            let ctx = ctx.clone();
            let handler = handler.clone();
            async move {
                // Every accepted H2 request reaches the same Tonic service.
                // Listener ACL and mTLS already established the caller.
                let mut request = request.map(boxed_body);
                request.extensions_mut().insert(ctx);
                request
                    .extensions_mut()
                    .insert(ManagementTransport(LISTENER_SERVICE));
                match handler.call(request).await {
                    Ok(response) => Ok::<_, Infallible>(response),
                    Err(error) => match error {},
                }
            }
        });
    let builder = h2_builder(policy);
    let connection = builder.serve_connection(TokioIo::new(tls), service);
    tokio::pin!(connection);
    tokio::select! {
        result = connection.as_mut() => result.map_err(|error| error.to_string()),
        () = cancellation.cancelled() => {
            connection.as_mut().graceful_shutdown();
            connection.await.map_err(|error| error.to_string())
        }
    }
}

fn h2_builder(policy: &ListenerConfig) -> http2::Builder<TokioExecutor> {
    let config = &policy.h2;
    let mut builder = http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .auto_date_header(true)
        .keep_alive_interval(config.keep_alive_interval)
        .keep_alive_timeout(config.keep_alive_timeout)
        .max_concurrent_streams(config.max_concurrent_streams)
        .adaptive_window(true)
        .max_frame_size(config.max_frame_size)
        .max_header_list_size(config.max_header_list_size)
        .max_pending_accept_reset_streams(
            config.max_pending_accept_reset_streams,
        )
        .max_local_error_reset_streams(config.max_local_error_reset_streams)
        .max_send_buf_size(config.max_send_buf_size);
    builder
}
