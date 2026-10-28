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
use crate::observation::{Failure, Observation, Transport};

const CT_DNS: &str = "application/dns-message";

/// Exact `/dns-query` endpoint. The standalone router returns 404 for
/// every other path and Axum never merges this service into an app host.
pub async fn handle_doh_request(
    Extension(dns_service): Extension<Arc<DnsProvider>>,
    req: Request,
) -> Response {
    let mut observation = Observation::begin(&dns_service, Transport::Doh);
    let uri = req.uri().clone();
    let method = req.method().clone();
    let dns_bytes = if method == Method::GET {
        let raw_q = uri.query().unwrap_or("");
        let Some(encoded) =
            raw_q.split('&').find_map(|p| p.strip_prefix("dns="))
        else {
            observation.fail(Failure::Malformed);
            return StatusCode::BAD_REQUEST.into_response();
        };
        match base64_decode(encoded) {
            Ok(v) => Bytes::from(v),
            Err(_) => {
                observation.fail(Failure::Malformed);
                return StatusCode::BAD_REQUEST.into_response();
            }
        }
    } else if method == Method::POST {
        let (_parts, body) = req.into_parts();
        match to_bytes(body, usize::MAX).await {
            Ok(b) => b,
            Err(_) => {
                observation.fail(Failure::Read);
                return StatusCode::BAD_REQUEST.into_response();
            }
        }
    } else {
        observation.fail(Failure::Method);
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    };

    let Ok(msg) = hickory_proto::op::Message::from_vec(&dns_bytes) else {
        observation.fail(Failure::Malformed);
        return StatusCode::BAD_REQUEST.into_response();
    };
    if msg.metadata.message_type != hickory_proto::op::MessageType::Query {
        observation.fail(Failure::ResponsePacket);
        return StatusCode::BAD_REQUEST.into_response();
    }
    observation.query(&msg);

    let dns = match dns_service.handler() {
        Ok(h) => h,
        Err(_) => {
            observation.fail(Failure::Unavailable);
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    let Ok(resp) = dns.handle_query(msg).await else {
        observation.fail(Failure::Processing);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let Ok(bytes) = resp.to_vec() else {
        observation.fail(Failure::Encode);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    observation.sent(resp.metadata.response_code);

    (
        [(http::header::CONTENT_TYPE, HeaderValue::from_static(CT_DNS))],
        Bytes::from(bytes),
    )
        .into_response()
}
