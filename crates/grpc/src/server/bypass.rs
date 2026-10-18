use std::sync::Arc;
use std::time::Duration;

use claviron::edge::BypassHandler;
use claviron::http::ext::ConnCtx;
use claviron::http::{RouteBody, RouteFuture, RouteResponse, boxed_body};
use http::{Request, Response};
use http_body_util::BodyExt;
use tokio::sync::Semaphore;
use tonic::Status;
use tower::ServiceExt;

use super::config::GrpcConfig;
use super::service::ConnInfo;
use super::services::ManagementTransport;

const RUN_TASK_PATH: &str = "/claviron.tasks.TaskManager/RunTask";

#[derive(Clone)]
pub(crate) struct ManagementGrpcHandler {
    routes: tonic::service::Routes,
    request_timeout: Duration,
    permits: Arc<Semaphore>,
    auth_guard: AuthGuard,
}

impl ManagementGrpcHandler {
    pub(crate) fn with_routes(
        routes: tonic::service::Routes,
        permits: Arc<Semaphore>,
        cfg: &GrpcConfig,
        host: String,
    ) -> Self {
        Self {
            routes,
            request_timeout: cfg.request_timeout,
            permits,
            auth_guard: AuthGuard { host },
        }
    }
}

impl BypassHandler for ManagementGrpcHandler {
    fn name(&self) -> &'static str {
        "management_grpc"
    }

    fn call(
        &self,
        mut req: Request<RouteBody>,
    ) -> RouteFuture {
        if req.version() != http::Version::HTTP_2 {
            return Box::pin(async move {
                Ok(status_response(Status::failed_precondition(
                    "management gRPC requires HTTP/2",
                )))
            });
        }

        let conn_ctx = req.extensions().get::<Arc<ConnCtx>>();
        let client_cert_present =
            conn_ctx.and_then(|ctx| ctx.tls.as_ref()).is_some_and(|tls| {
                matches!(
                    tls.client_auth,
                    claviron::http::ext::ClientAuthStatus::Verified
                ) && tls.client_cert.is_some()
            });
        let conn_info = conn_ctx.map(|ctx| Arc::new(conn_info_from_ctx(ctx)));
        if let Some(status) =
            self.auth_guard.connection_status(client_cert_present)
        {
            return Box::pin(async move { Ok(status_response(status)) });
        }

        if let Some(conn_info) = conn_info {
            req.extensions_mut().insert(conn_info);
        }
        // A dedicated driver supplies its own owner. Otherwise the trusted
        // edge connection, never a header, identifies the serving transport.
        if req.extensions().get::<ManagementTransport>().is_none() {
            let owner = req.extensions().get::<Arc<ConnCtx>>().map(|ctx| {
                if ctx.proto == Some(claviron::tls::Proto::H3) {
                    "H3Server"
                } else if ctx.tls.is_some() {
                    "HttpsServer"
                } else {
                    "HttpServer"
                }
            });
            if let Some(owner) = owner {
                req.extensions_mut().insert(ManagementTransport(owner));
            }
        }

        let routes = self.routes.clone();
        let request_timeout =
            request_timeout_for(req.uri().path(), self.request_timeout);
        let permits = self.permits.clone();
        let req = req.map(|body| {
            let body = body.map_err(|err| Status::internal(err.to_string()));
            tonic::body::Body::new(body)
        });

        Box::pin(async move {
            let Ok(_permit) = permits.acquire_owned().await else {
                return Ok(status_response(Status::unavailable(
                    "gRPC service is shutting down",
                )));
            };

            match request_timeout {
                Some(request_timeout) => {
                    match tokio::time::timeout(
                        request_timeout,
                        routes.oneshot(req),
                    )
                    .await
                    {
                        Ok(Ok(resp)) => Ok(route_response(resp)),
                        Ok(Err(err)) => match err {},
                        Err(_) => Ok(status_response(
                            Status::deadline_exceeded("gRPC request timed out"),
                        )),
                    }
                }
                None => match routes.oneshot(req).await {
                    Ok(resp) => Ok(route_response(resp)),
                    Err(err) => match err {},
                },
            }
        })
    }
}

fn request_timeout_for(
    path: &str,
    configured: Duration,
) -> Option<Duration> {
    // RunTask is a synchronous result RPC whose task-owned execution timeout
    // may intentionally exceed the general management request bound. Tonic
    // still honors a caller's grpc-timeout header, while TaskManager bounds
    // the execution itself when the caller sends no transport deadline.
    (path != RUN_TASK_PATH).then_some(configured)
}

#[derive(Clone)]
struct AuthGuard {
    host: String,
}

impl AuthGuard {
    fn connection_status(
        &self,
        client_cert_present: bool,
    ) -> Option<Status> {
        if !client_cert_present {
            return Some(Status::unauthenticated(format!(
                "management gRPC host '{}' requires a TLS client certificate",
                self.host
            )));
        }
        None
    }
}

fn route_response(resp: Response<tonic::body::Body>) -> RouteResponse {
    resp.map(boxed_body)
}

fn status_response(status: Status) -> RouteResponse {
    route_response(status.into_http::<tonic::body::Body>())
}

fn conn_info_from_ctx(ctx: &ConnCtx) -> ConnInfo {
    let client_cn = ctx
        .tls
        .as_ref()
        .and_then(|tls| tls.client_cert.as_ref())
        .and_then(|cert| common_name_from_subject(&cert.subject_dn));

    ConnInfo { addr: ctx.remote, certificates: Vec::new(), client_cn }
}

fn common_name_from_subject(subject: &str) -> Option<String> {
    subject.split(',').find_map(|part| {
        let part = part.trim();
        part.strip_prefix("CN=")
            .filter(|cn| !cn.is_empty())
            .map(ToOwned::to_owned)
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{RUN_TASK_PATH, request_timeout_for};

    #[test]
    fn run_task_uses_its_task_and_client_owned_deadlines() {
        assert_eq!(
            request_timeout_for(RUN_TASK_PATH, Duration::from_secs(30)),
            None
        );
    }

    #[test]
    fn ordinary_management_requests_keep_the_configured_bound() {
        let configured = Duration::from_secs(30);
        assert_eq!(
            request_timeout_for(
                "/claviron.tasks.TaskManager/ListTasks",
                configured
            ),
            Some(configured)
        );
    }
}
