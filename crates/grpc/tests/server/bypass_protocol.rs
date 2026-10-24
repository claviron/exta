use super::*;
use crate::server::greeter::helloworld::{
    HelloReply, HelloRequest,
    greeter_server::{Greeter, GreeterServer},
};
use claviron::http::ext::{ClientAuthStatus, TlsClientCertInfo, TlsInfo};
use prost::Message;

struct Echo;

#[tonic::async_trait]
impl Greeter for Echo {
    async fn say_hello(
        &self,
        request: tonic::Request<HelloRequest>,
    ) -> Result<tonic::Response<HelloReply>, Status> {
        let owner =
            request.extensions().get::<ManagementTransport>().unwrap().0;
        let identity = request.extensions().get::<Arc<ConnInfo>>().unwrap();
        assert_eq!(identity.client_cn.as_deref(), Some("operator"));
        Ok(tonic::Response::new(HelloReply {
            message: format!("{owner}:{}", request.get_ref().name),
        }))
    }
}

fn handler() -> ManagementGrpcHandler {
    handler_for(claviron::runtime::AppState::standalone(
        "grpc-admission-test",
        ".",
    ))
}

fn handler_for(state: claviron::runtime::AppState) -> ManagementGrpcHandler {
    ManagementGrpcHandler::with_routes(
        tonic::service::Routes::new(GreeterServer::new(Echo)).prepare(),
        Arc::new(Semaphore::new(1)),
        &GrpcConfig::default(),
        "management.example.test".to_owned(),
        state,
    )
}

fn request(
    version: http::Version,
    verified: bool,
) -> Request<RouteBody> {
    let proto = if version == http::Version::HTTP_3 {
        claviron::tls::Proto::H3
    } else {
        claviron::tls::Proto::H2
    };
    let payload = HelloRequest { name: "hello".to_owned() }.encode_to_vec();
    let mut frame = vec![0]; // gRPC's uncompressed message flag.
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    let mut request = Request::builder().method("POST").version(version)
        .uri("https://management.example.test/claviron.helloworld.Greeter/SayHello")
        .header("content-type", "application/grpc").header("te", "trailers")
        .body(claviron::http::bytes_body(frame.into())).unwrap();
    request.extensions_mut().insert(Arc::new(ConnCtx {
        state: Default::default(),
        listener: "management".parse().unwrap(),
        proto: Some(proto),
        remote: "192.0.2.1:12345".parse().unwrap(),
        local_ip: "192.0.2.2".parse().unwrap(),
        local_port: 443,
        real_ip: None,
        country_code: None,
        tls: Some(TlsInfo {
            protocol_version: None,
            cipher_suite: None,
            client_auth: if verified {
                ClientAuthStatus::Verified
            } else {
                ClientAuthStatus::NotProvided
            },
            client_cert: Some(TlsClientCertInfo {
                subject_dn: "CN=operator".to_owned(),
                issuer_dn: "CN=example CA".to_owned(),
                identity: Some(Arc::new(claviron::ssl::peer::PeerIdentity {
                    certificate: Arc::from([]),
                    subject_dn: "CN=operator".into(),
                    issuer_dn: "CN=example CA".into(),
                    common_names: vec!["operator".into()],
                    subject_uris: vec!["urn:example:subject:one".into()],
                })),
            }),
        }),
    }));
    request
}

#[tokio::test]
async fn grpc_h2_h3_dispatch_preserves_messages_identity_and_status_trailers() {
    for (version, owner) in [
        (http::Version::HTTP_2, "HttpsServer"),
        (http::Version::HTTP_3, "H3Server"),
    ] {
        let response = handler().call(request(version, true)).await.unwrap();
        assert_eq!(response.version(), version);
        assert_eq!(response.headers()["content-type"], "application/grpc");
        let body = response.into_body().collect().await.unwrap();
        assert_eq!(body.trailers().unwrap()["grpc-status"], "0");
        let bytes = body.to_bytes();
        let reply = HelloReply::decode(&bytes[5..]).unwrap();
        assert_eq!(reply.message, format!("{owner}:hello"));
    }
}

#[tokio::test]
async fn grpc_h3_requires_verified_mtls_and_http1_remains_rejected() {
    for version in [http::Version::HTTP_2, http::Version::HTTP_3] {
        let response = handler().call(request(version, false)).await.unwrap();
        assert_eq!(response.version(), version);
        assert_eq!(response.headers()["grpc-status"], "16");
    }
    let mut missing_context = request(http::Version::HTTP_3, true);
    missing_context.extensions_mut().remove::<Arc<ConnCtx>>();
    let response = handler().call(missing_context).await.unwrap();
    assert_eq!(response.headers()["grpc-status"], "16");
    let response =
        handler().call(request(http::Version::HTTP_11, true)).await.unwrap();
    assert_eq!(response.headers()["grpc-status"], "9");
}

struct AccessCheck {
    allow: std::sync::atomic::AtomicBool,
    calls: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl crate::access::GrpcAccessPolicy for AccessCheck {
    async fn authorize(
        &self,
        peer: &claviron::ssl::peer::PeerIdentity,
    ) -> Result<
        Option<claviron::auth::AnyAuthenticated>,
        crate::access::AccessError,
    > {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(peer.subject_uris, ["urn:example:subject:one"]);
        if self.allow.load(std::sync::atomic::Ordering::SeqCst) {
            Ok(None)
        } else {
            Err(crate::access::AccessError::Forbidden)
        }
    }
}
#[tokio::test]
async fn grpc_access_policy_is_shared_by_h2_h3_connection_and_resets_on_reconnect()
 {
    use std::sync::atomic::{AtomicBool, Ordering};
    for version in [http::Version::HTTP_2, http::Version::HTTP_3] {
        let state = AppState::standalone("grpc-access-test", ".");
        let policy = Arc::new(AccessCheck {
            allow: AtomicBool::new(true),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        state.registry_ref().insert(policy.clone()).unwrap();
        state
            .registry_ref()
            .bind_dyn::<dyn crate::access::GrpcAccessPolicy, AccessCheck>(
                |value| value,
            )
            .unwrap();
        let handler = handler_for(state);
        let first = request(version, true);
        let connection =
            first.extensions().get::<Arc<ConnCtx>>().unwrap().clone();
        let response = handler.call(first).await.unwrap();
        assert!(!response.headers().contains_key("grpc-status"));
        policy.allow.store(false, Ordering::SeqCst);
        let mut same_connection = request(version, true);
        same_connection.extensions_mut().insert(connection);
        let response = handler.call(same_connection).await.unwrap();
        assert!(!response.headers().contains_key("grpc-status"));
        assert_eq!(policy.calls.load(Ordering::SeqCst), 1);

        let denied = request(version, true);
        let denied_connection =
            denied.extensions().get::<Arc<ConnCtx>>().unwrap().clone();
        let response = handler.call(denied).await.unwrap();
        assert_eq!(response.headers()["grpc-status"], "7");
        policy.allow.store(true, Ordering::SeqCst);
        let mut still_denied = request(version, true);
        still_denied.extensions_mut().insert(denied_connection);
        still_denied
            .headers_mut()
            .insert("x-access-target", "allowed".parse().unwrap());
        let response = handler.call(still_denied).await.unwrap();
        assert_eq!(response.headers()["grpc-status"], "7");
        assert_eq!(policy.calls.load(Ordering::SeqCst), 2);
        let response = handler.call(request(version, false)).await.unwrap();
        assert_eq!(response.headers()["grpc-status"], "16");
        assert_eq!(policy.calls.load(Ordering::SeqCst), 2);
    }
}
