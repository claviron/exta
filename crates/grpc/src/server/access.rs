//! One admission decision per routed request, shared by every gRPC ingress.
use claviron::auth::AnyAuthenticated;
use claviron::auth::access::{
    AccessError, AccessPolicy, AccessTarget, PeerIdentity,
};
use claviron::runtime::AppState;
use tonic::Status;

#[derive(Clone)]
pub(crate) struct Admission {
    pub(crate) target: AccessTarget,
    pub(crate) actor: Option<AnyAuthenticated>,
}

pub(crate) async fn admit(
    state: &AppState,
    peer: Option<&PeerIdentity>,
    target: AccessTarget,
) -> Result<Admission, Status> {
    let Some(policy) = state.registry_ref().resolve_dyn::<dyn AccessPolicy>()
    else {
        return Ok(Admission { target, actor: None });
    };
    let peer = peer.ok_or_else(|| {
        Status::unauthenticated("verified certificate identity is unavailable")
    })?;
    let actor = policy.authorize(peer, &target).await.map_err(|error| {
        let message = error.to_string();
        match error {
            AccessError::Unauthenticated => Status::unauthenticated(message),
            AccessError::Forbidden => Status::permission_denied(message),
            AccessError::Unavailable => Status::unavailable(message),
            AccessError::Unsupported => Status::unimplemented(message),
        }
    })?;
    Ok(Admission { target, actor })
}

#[cfg(test)]
#[path = "../../tests/access.rs"]
mod tests;
