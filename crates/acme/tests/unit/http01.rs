use super::*;

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};

use claviron::edge::pipeline::HostPipelineBuilder;
use claviron::http::boxed_body;
use http_body_util::BodyExt;

struct Storage {
    bytes: Bytes,
    reads: AtomicUsize,
    expired: AtomicBool,
    failed: AtomicBool,
}

#[async_trait]
impl Http01Storage for Storage {
    async fn get(
        &self,
        token: &str,
    ) -> Result<Option<Bytes>, AcmeError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if self.failed.load(Ordering::Relaxed) {
            return Err(AcmeError::Unexpected("storage unavailable".into()));
        }
        Ok((token == "token" && !self.expired.load(Ordering::Relaxed))
            .then(|| self.bytes.clone()))
    }
}

struct Unread(Arc<AtomicUsize>);

impl http_body::Body for Unread {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        panic!("HTTP-01 must not poll the request body")
    }
}

impl Drop for Unread {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn storage() -> Arc<Storage> {
    Arc::new(Storage {
        bytes: Bytes::from_static(b"token.authorization"),
        reads: AtomicUsize::new(0),
        expired: AtomicBool::new(false),
        failed: AtomicBool::new(false),
    })
}

async fn execute(
    storage: Arc<Storage>,
    method: Method,
    path: &str,
    drops: &Arc<AtomicUsize>,
) -> RouteResponse {
    let mut builder = HostPipelineBuilder::new();
    builder
        .layer(Http01Layer::from(storage as Arc<dyn Http01Storage>))
        .unwrap();
    let pipeline = builder.build();
    let request = Request::builder()
        .method(method)
        .uri(path)
        .body(boxed_body(Unread(drops.clone())))
        .unwrap();
    let ServiceResult::Unhandled(prepared) = pipeline.prepare(request) else {
        panic!("consuming actions run during dispatch");
    };
    prepared
        .dispatch(|request| async move {
            let mut response = Response::new(request.into_body());
            *response.status_mut() = StatusCode::IM_A_TEAPOT;
            response
        })
        .await
}

#[test]
fn http01_selects_only_configured_canonical_hosts() {
    let provider = AcmeProvider::empty("acme.yaml".into());
    assert!(provider.match_protocol(RouteProtocol::Http));
    assert!(!provider.match_protocol(RouteProtocol::Https));
    assert!(!provider.match_protocol(RouteProtocol::Quic));
    let host = "example.test".parse().unwrap();
    assert!(!selects(None, &host));
    for (yaml, expected) in [
        ("false", false),
        ("true", true),
        ("hosts: any", true),
        ("hosts: [EXAMPLE.test]", true),
        ("hosts: [other.test]", false),
        ("hosts: []", false),
    ] {
        let config: Http01Config = serde_yaml::from_str(yaml).unwrap();
        validate_hosts(&config).unwrap();
        assert_eq!(selects(Some(&config), &host), expected, "{yaml}");
    }
    for invalid in ["{}", "hosts: example.test", "hosts: any\nunknown: true"] {
        assert!(
            serde_yaml::from_str::<Http01Config>(invalid).is_err(),
            "{invalid}"
        );
    }
}

#[tokio::test]
async fn http01_keeps_nonmatches_unread_and_rejects_before_storage() {
    let storage = storage();
    let drops = Arc::new(AtomicUsize::new(0));
    for (method, path, status) in [
        (Method::GET, "/ordinary", StatusCode::IM_A_TEAPOT),
        (
            Method::GET,
            "/.well-known/acme-challenge/../token",
            StatusCode::FORBIDDEN,
        ),
        (
            Method::POST,
            "/.well-known/acme-challenge/token",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
    ] {
        let response =
            execute(storage.clone(), method.clone(), path, &drops).await;
        assert_eq!(response.status(), status);
        if method == Method::POST {
            assert_eq!(response.headers()[header::ALLOW], "GET, HEAD");
        }
        drop(response);
    }
    assert_eq!(storage.reads.load(Ordering::Relaxed), 0);
    assert_eq!(drops.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn http01_shares_get_bytes_and_preserves_head_length() {
    let storage = storage();
    let drops = Arc::new(AtomicUsize::new(0));
    let response = execute(
        storage.clone(),
        Method::GET,
        "/.well-known/acme-challenge/token",
        &drops,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "text/plain");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ptr(), storage.bytes.as_ptr());
    let response = execute(
        storage.clone(),
        Method::HEAD,
        "/.well-known/acme-challenge/token",
        &drops,
    )
    .await;
    assert_eq!(
        response.headers()[header::CONTENT_LENGTH],
        storage.bytes.len().to_string()
    );
    assert!(
        response.into_body().collect().await.unwrap().to_bytes().is_empty()
    );
    assert_eq!(drops.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn http01_does_not_cache_expired_values_or_hide_storage_errors() {
    let storage = storage();
    let drops = Arc::new(AtomicUsize::new(0));
    storage.expired.store(true, Ordering::Relaxed);
    let response = execute(
        storage.clone(),
        Method::GET,
        "/.well-known/acme-challenge/token",
        &drops,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    storage.failed.store(true, Ordering::Relaxed);
    let response = execute(
        storage.clone(),
        Method::GET,
        "/.well-known/acme-challenge/token",
        &drops,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}
