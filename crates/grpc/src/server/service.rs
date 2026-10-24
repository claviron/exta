use std::net::SocketAddr;

use claviron::runtime::AppState;
use claviron::runtime::registry::Error;
use rustls::pki_types::CertificateDer;
use tonic_reflection::server::Builder as ReflBuilder;

#[cfg(feature = "acme")]
use crate::server::acme::create_acme_service;
use crate::server::aliases::create_hosting_service;
use crate::server::applications::create_application_manager;
use crate::server::control::create_server_service;
use crate::server::greeter::create_hello_service;
use crate::server::linked::create_linked_application_manager;
use crate::server::services::create_service_manager;
#[cfg(feature = "tasks")]
use crate::server::tasks::create_task_service;
#[cfg(feature = "workers")]
use crate::server::workers::create_worker_service;

const DESCRIPTORS: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/descriptors.bin"));

pub(crate) fn create_management_routes(
    state: AppState
) -> claviron::runtime::registry::Result<tonic::service::Routes> {
    let hello_service = create_hello_service(state.clone());

    let hosting_service = create_hosting_service(state.clone())
        .map_err(|s| Error::msg(s.to_string()))?;
    let server_service =
        create_server_service(state.clone(), management_capabilities());
    let service_manager = create_service_manager(state.clone())
        .map_err(|status| Error::msg(status.to_string()))?;

    let application_manager = create_application_manager(state.clone())
        .map_err(|status| Error::msg(status.to_string()))?;
    let linked_application_manager =
        create_linked_application_manager(state.clone());
    #[cfg(feature = "acme")]
    let acme_service = create_acme_service(state.clone())
        .map_err(|status| Error::msg(status.to_string()))?;

    #[cfg(feature = "tasks")]
    let task_service = create_task_service(state.clone())
        .map_err(|status| Error::msg(status.to_string()))?;

    #[cfg(feature = "workers")]
    let worker_service = create_worker_service(state.clone())
        .map_err(|status| Error::msg(status.to_string()))?;

    let reflection_service = ReflBuilder::configure()
        .register_encoded_file_descriptor_set(DESCRIPTORS)
        .build_v1()
        .expect("reflection");

    let routes = tonic::service::Routes::new(hello_service)
        .add_service(hosting_service)
        .add_service(server_service)
        .add_service(service_manager)
        .add_service(application_manager)
        .add_service(linked_application_manager);

    #[cfg(feature = "acme")]
    let routes = routes.add_service(acme_service);

    #[cfg(any(feature = "users", feature = "authorization"))]
    let routes =
        routes.add_service(super::management::create_service(state.clone()));

    #[cfg(feature = "tasks")]
    let routes = routes.add_service(task_service);

    #[cfg(feature = "workers")]
    let routes = routes.add_service(worker_service);

    #[cfg(feature = "mtls")]
    let routes = routes
        .add_service(crate::server::mtls::create_mtls_service(state.clone()));

    #[cfg(feature = "certificates")]
    let routes = routes.add_service(
        crate::server::certificates::create_certificate_transfer(state.clone()),
    );

    let routes = routes.add_service(reflection_service);

    #[cfg(feature = "dns")]
    let routes = routes
        .add_service(crate::server::dns::create_dns_service(state.clone()));

    #[cfg(feature = "domains")]
    let routes = routes.add_service(
        crate::server::domains::create_domain_service(state.clone()),
    );

    #[cfg(feature = "metrics")]
    let routes = with_metrics_route(routes, state);

    Ok(routes.prepare())
}

// These declarations mirror the routes installed below; they describe this
// endpoint, not whether every backing provider is currently available.
fn management_capabilities() -> Vec<String> {
    let names = vec![
        "server",
        "services",
        "applications",
        "linked_applications",
        "hosting",
        "reflection",
        #[cfg(feature = "users")]
        "users",
        #[cfg(feature = "authorization")]
        "authorization",
        #[cfg(feature = "tasks")]
        "tasks",
        #[cfg(feature = "workers")]
        "workers",
        #[cfg(feature = "acme")]
        "acme",
        #[cfg(feature = "mtls")]
        "mtls",
        #[cfg(feature = "certificates")]
        "certificates",
        #[cfg(feature = "dns")]
        "dns",
        #[cfg(feature = "domains")]
        "domains",
        #[cfg(feature = "metrics")]
        "metrics",
    ];
    names.into_iter().map(String::from).collect()
}

#[cfg(feature = "metrics")]
fn with_metrics_route(
    routes: tonic::service::Routes,
    state: AppState,
) -> tonic::service::Routes {
    let metrics = claviron::http::metrics::routes(&state).with_state(state);
    routes.into_axum_router().merge(metrics).into()
}

#[derive(Debug)]
pub(crate) struct ConnInfo {
    pub(crate) addr: SocketAddr,
    #[allow(unused)]
    pub(crate) certificates: Vec<CertificateDer<'static>>,
    pub(crate) client_cn: Option<String>,
}

#[cfg(all(test, feature = "metrics"))]
mod tests {
    use std::sync::Arc;

    use claviron::metrics::{MetricsFamily, MetricsProvider};
    use http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    struct TestMetrics;

    impl MetricsFamily for TestMetrics {
        fn name(&self) -> &'static str {
            "test"
        }

        fn write_prometheus(
            &self,
            _state: &AppState,
            output: &mut String,
        ) -> Result<(), String> {
            output.push_str("claviron_grpc_metrics_route_test 1\n");
            Ok(())
        }
    }

    fn routes_with_metrics() -> tonic::service::Routes {
        let state = AppState::standalone("grpc-metrics-test", ".");
        claviron::metrics::register(&state).expect("register metrics provider");
        state
            .registry_ref()
            .resolve::<MetricsProvider>()
            .expect("resolve metrics provider")
            .register(Arc::new(TestMetrics));
        with_metrics_route(tonic::service::Routes::default(), state).prepare()
    }

    #[tokio::test]
    async fn serves_prometheus_metrics_on_exact_path() {
        let response = routes_with_metrics()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(tonic::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "text/plain; version=0.0.4"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "claviron_grpc_metrics_route_test 1\n");
    }

    #[tokio::test]
    async fn does_not_capture_paths_below_metrics() {
        let response = routes_with_metrics()
            .oneshot(
                Request::builder()
                    .uri("/metrics/extra")
                    .body(tonic::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.headers().get("grpc-status").unwrap(), "12");
    }
}
