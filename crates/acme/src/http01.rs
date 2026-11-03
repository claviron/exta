//! Native HTTP-01 contribution. Host selection is preparation work; storage
//! owns expiry and publication, independently of the transport or Rust router.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use claviron::edge::extension::RouteLayer;
use claviron::edge::pipeline::{DispatchCall, HostLayer, HostLayerBuilder};
use claviron::edge::{Host, HostConfig, Routable, RouteProtocol};
use claviron::http::{
    RouteBody, RouteResponse, ServiceResult, bytes_body, empty_body, err_status,
};
use claviron::runtime::{AppState, registry};
use http::{Method, Request, Response, StatusCode, header};

use crate::{AcmeError, AcmeProvider, Http01Config, Http01Hosts};

// RFC 8555 fixes this path prefix; it is not an operator routing default.
const PREFIX: &str = "/.well-known/acme-challenge/";

/// Return live raw authorization bytes, or None for an absent/expired token.
/// Implementations own TTL, cache/database access and cross-worker visibility.
/// Bind an implementation with the runtime registry before host preparation.
#[async_trait]
pub trait Http01Storage: Send + Sync + 'static {
    async fn get(
        &self,
        token: &str,
    ) -> Result<Option<Bytes>, AcmeError>;
}

struct FileStorage(PathBuf);

#[async_trait]
impl Http01Storage for FileStorage {
    async fn get(
        &self,
        token: &str,
    ) -> Result<Option<Bytes>, AcmeError> {
        let path = self.0.join(token);
        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(Some(bytes.into())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(error) => Err(AcmeError::io_error(
                "Failed to read HTTP-01 token",
                &path,
                error,
            )),
        }
    }
}

pub struct Http01Layer {
    storage: Arc<dyn Http01Storage>,
}

impl From<Arc<dyn Http01Storage>> for Http01Layer {
    fn from(storage: Arc<dyn Http01Storage>) -> Self {
        Self { storage }
    }
}

impl RouteLayer for Http01Layer {
    fn prepare(
        &self,
        layer: &mut HostLayerBuilder,
    ) -> claviron::edge::Result<()> {
        let storage = self.storage.clone();
        layer.request(move |request: Request<RouteBody>| {
            let Some(token) = request.uri().path().strip_prefix(PREFIX) else {
                return DispatchCall::ready(ServiceResult::Unhandled(request));
            };
            if !crate::clients::valid_token(token) {
                return DispatchCall::ready(ServiceResult::Handled(
                    err_status(StatusCode::FORBIDDEN),
                ));
            }
            if request.method() != Method::GET
                && request.method() != Method::HEAD
            {
                let mut response = err_status(StatusCode::METHOD_NOT_ALLOWED);
                response.headers_mut().insert(
                    header::ALLOW,
                    http::HeaderValue::from_static("GET, HEAD"),
                );
                return DispatchCall::ready(ServiceResult::Handled(response));
            }
            let (head, body) = request.into_parts();
            drop(body);
            let storage = storage.clone();
            DispatchCall::new(async move {
                ServiceResult::Handled(
                    reply(
                        storage.as_ref(),
                        head.uri.path(),
                        head.method == Method::HEAD,
                    )
                    .await,
                )
            })
        });
        Ok(())
    }
}

impl HostLayer for Http01Layer {
    fn prepare(
        self,
        layer: &mut HostLayerBuilder,
    ) -> claviron::edge::Result<()> {
        RouteLayer::prepare(&self, layer)
    }
}

async fn reply(
    storage: &dyn Http01Storage,
    path: &str,
    head: bool,
) -> RouteResponse {
    // Selection above established the prefix and the token alphabet.
    let token = &path[PREFIX.len()..];
    match storage.get(token).await {
        Ok(Some(bytes)) => {
            let length = bytes.len();
            let mut response = Response::new(if head {
                empty_body()
            } else {
                bytes_body(bytes)
            });
            response.headers_mut().insert(
                header::CONTENT_LENGTH,
                http::HeaderValue::from(length),
            );
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/plain"),
            );
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                http::HeaderValue::from_static("no-store"),
            );
            response
        }
        Ok(None) => err_status(StatusCode::NOT_FOUND),
        Err(error) => {
            tracing::warn!(%error, "HTTP-01 storage lookup failed");
            err_status(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

pub(crate) fn validate_hosts(config: &Http01Config) -> Result<(), String> {
    if let Http01Config::Scoped { hosts: Http01Hosts::Named(names) } = config {
        for name in names {
            name.parse::<Host>()?;
        }
    }
    Ok(())
}

fn selects(
    config: Option<&Http01Config>,
    host: &Host,
) -> bool {
    match config {
        Some(Http01Config::Enabled(enabled)) => *enabled,
        Some(Http01Config::Scoped { hosts: Http01Hosts::Any(_) }) => true,
        Some(Http01Config::Scoped { hosts: Http01Hosts::Named(names) }) => {
            names.iter().any(|name| name.parse::<Host>().as_ref() == Ok(host))
        }
        None => false,
    }
}

impl Routable for AcmeProvider {
    fn match_protocol(
        &self,
        protocol: RouteProtocol,
    ) -> bool {
        protocol == RouteProtocol::Http
    }

    fn match_host(
        &self,
        key: &Host,
        _host: &HostConfig,
    ) -> bool {
        self.snapshot()
            .is_some_and(|config| selects(config.http01.as_ref(), key))
    }

    fn layers(
        self: Arc<Self>,
        state: &AppState,
        key: &Host,
        _host: Arc<HostConfig>,
    ) -> registry::Result<Vec<Arc<dyn RouteLayer>>> {
        let mut prepared =
            self.http01.lock().expect("HTTP-01 preparation poisoned");
        let Some(config) = self
            .snapshot()
            .filter(|config| selects(config.http01.as_ref(), key))
        else {
            return Ok(Vec::new());
        };
        if prepared.is_none() {
            let storage = match state
                .registry_ref()
                .resolve_dyn::<dyn Http01Storage>()
            {
                Some(storage) => storage,
                None => {
                    if config.challenges_dir().as_os_str().is_empty() {
                        return Err(registry::Error::msg(
                            "HTTP-01 requires Http01Storage or challenges_dir",
                        ));
                    }
                    Arc::new(FileStorage(config.challenges_dir().clone()))
                        as Arc<dyn Http01Storage>
                }
            };
            *prepared = Some(Arc::new(Http01Layer::from(storage)));
        }
        Ok(vec![prepared.as_ref().expect("prepared HTTP-01 layer").clone()])
    }
}

#[cfg(test)]
#[path = "../tests/unit/http01.rs"]
mod tests;
