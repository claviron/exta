//! One service admission per connection, with request-local operation identity.
use std::sync::Arc;
use std::time::Duration;

use claviron::auth::AnyAuthenticated;
use claviron::auth::access::{
    AccessError, AccessPolicy, AccessTarget, PeerIdentity,
};
use claviron::runtime::AppState;
use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Shared};
use tonic::Status;

#[derive(Clone)]
pub(crate) struct Admission {
    pub(crate) target: AccessTarget,
    pub(crate) actor: Option<AnyAuthenticated>,
}

type Decision = Result<Option<AnyAuthenticated>, Status>;

/// Retained by the accepted connection, never by a global client/certificate map.
pub(crate) struct Session {
    decision: Shared<BoxFuture<'static, Decision>>,
}

impl Session {
    pub(crate) fn new(
        state: AppState,
        peer: Option<Arc<PeerIdentity>>,
        bound: Duration,
    ) -> Self {
        let decision = async move {
            let target = AccessTarget {
                service: "grpc".into(),
                operation: "connect".into(),
            };
            let client_cn = peer.as_ref().and_then(|peer| {
                match peer.common_names.as_slice() {
                    [name] => Some(name.as_str()),
                    _ => None,
                }
            });
            let decision = tokio::time::timeout(bound, async {
                let Some(policy) =
                    state.registry_ref().resolve_dyn::<dyn AccessPolicy>()
                else {
                    return Ok(None);
                };
                let peer = peer.as_deref().ok_or_else(|| {
                    Status::unauthenticated(
                        "verified certificate identity is unavailable",
                    )
                })?;
                let actor =
                    policy.authorize(peer, &target).await.map_err(|error| {
                        let message = error.to_string();
                        match error {
                            AccessError::Unauthenticated => {
                                Status::unauthenticated(message)
                            }
                            AccessError::Forbidden => {
                                Status::permission_denied(message)
                            }
                            AccessError::Unavailable => {
                                Status::unavailable(message)
                            }
                            AccessError::Unsupported => {
                                Status::unimplemented(message)
                            }
                        }
                    })?;
                tracing::info!(
                    service = %target.service,
                    operation = %target.operation,
                    client_cn,
                    code = ?tonic::Code::Ok,
                    "✅ gRPC access policy accepted a TLS-authenticated peer"
                );
                Ok(actor)
            })
            .await
            .unwrap_or_else(|_| {
                Err(Status::deadline_exceeded("gRPC admission timed out"))
            });
            if let Err(error) = &decision {
                tracing::error!(
                    service = %target.service,
                    operation = %target.operation,
                    client_cn,
                    code = ?error.code(),
                    error = %error.message(),
                    "gRPC access policy rejected a TLS-authenticated peer"
                );
            }
            decision
        }
        .boxed()
        .shared();
        Self { decision }
    }

    pub(crate) async fn admit(
        &self,
        target: AccessTarget,
    ) -> Result<Admission, Status> {
        // Concurrent streams share initialization and the terminal result,
        // including a denial. Cancelling one RPC does not restart validation.
        let actor = self.decision.clone().await?;
        Ok(Admission { target, actor })
    }
}

#[cfg(test)]
#[path = "../../tests/access.rs"]
mod tests;
