//! DNS-over-HTTPS (RFC 8484) endpoint for the dedicated hostname owned
//! by `DnsProvider` through Claviron's exclusive host-binding boundary.
//!
//! Gated behind the `doh` feature; pulls in axum/http/hickory-proto/
//! Claviron's facade only when the caller opts in.

use std::sync::Arc;

use axum::body::to_bytes;
use axum::extract::{Extension, Request};
use axum::http::Method;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use claviron::helpers::base64::base64_decode;
use http::{HeaderValue, StatusCode};

use crate::DnsProvider;

const CT_DNS: &str = "application/dns-message";

/// Exact `/dns-query` endpoint. The standalone router returns 404 for
/// every other path and Axum never merges this service into an app host.
pub async fn handle_doh_request(
    Extension(dns_service): Extension<Arc<DnsProvider>>,
    req: Request,
) -> Response {
    let uri = req.uri().clone();
    let method = req.method().clone();
    let dns_bytes = if method == Method::GET {
        let raw_q = uri.query().unwrap_or("");
        let Some(encoded) =
            raw_q.split('&').find_map(|p| p.strip_prefix("dns="))
        else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        match base64_decode(encoded) {
            Ok(v) => Bytes::from(v),
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        }
    } else if method == Method::POST {
        let (_parts, body) = req.into_parts();
        match to_bytes(body, usize::MAX).await {
            Ok(b) => b,
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        }
    } else {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    };

    let Ok(msg) = hickory_proto::op::Message::from_vec(&dns_bytes) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if msg.metadata.message_type != hickory_proto::op::MessageType::Query {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let dns = match dns_service.handler() {
        Ok(h) => h,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let Ok(resp) = dns.handle_query(msg).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let Ok(bytes) = resp.to_vec() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    (
        [(http::header::CONTENT_TYPE, HeaderValue::from_static(CT_DNS))],
        Bytes::from(bytes),
    )
        .into_response()
}
