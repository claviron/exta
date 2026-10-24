use super::*;
use async_trait::async_trait;
use std::any::Any;
use std::borrow::Cow;
use std::sync::{Arc, Mutex};
use tonic::Code;

struct Actor;
impl claviron::auth::Authenticated for Actor {
    fn auth_subject(&self) -> Cow<'_, str> {
        "bound-subject".into()
    }
    fn auth_identifier(&self) -> &str {
        "display-name"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
struct Policy {
    targets: Mutex<Vec<AccessTarget>>,
}
#[async_trait]
impl AccessPolicy for Policy {
    async fn authorize(
        &self,
        peer: &PeerIdentity,
        target: &AccessTarget,
    ) -> Result<Option<AnyAuthenticated>, AccessError> {
        self.targets.lock().unwrap().push(target.clone());
        assert_eq!(peer.common_names, ["operator"]);
        match target.operation.as_str() {
            "peer-only" => Ok(None),
            "bind" => Ok(Some(Arc::new(Actor))),
            "unauthenticated" => Err(AccessError::Unauthenticated),
            "unavailable" => Err(AccessError::Unavailable),
            "unsupported" => Err(AccessError::Unsupported),
            _ => Err(AccessError::Forbidden),
        }
    }
}
fn target(operation: &str) -> AccessTarget {
    AccessTarget { service: "grpc".into(), operation: operation.into() }
}
fn peer() -> PeerIdentity {
    PeerIdentity {
        certificate: Arc::from([]),
        subject_dn: "CN=operator".into(),
        issuer_dn: "CN=example CA".into(),
        common_names: vec!["operator".into()],
        subject_uris: vec![],
    }
}
fn bind(state: &AppState) -> Arc<Policy> {
    let policy = Arc::new(Policy { targets: Mutex::new(vec![]) });
    state.registry_ref().insert(policy.clone()).unwrap();
    state
        .registry_ref()
        .bind_dyn::<dyn AccessPolicy, Policy>(|value| value)
        .unwrap();
    policy
}
#[tokio::test]
async fn access_no_policy_preserves_peer_only_admission_without_a_user_model() {
    let state = AppState::standalone("access-test", ".");
    let admission = admit(&state, None, target("peer-only")).await.unwrap();
    assert!(admission.actor.is_none());
}
#[tokio::test]
async fn access_policy_binding_and_denials_are_target_specific_and_not_cached()
{
    let state = AppState::standalone("access-test", ".");
    let policy = bind(&state);
    let peer = peer();
    assert!(
        admit(&state, Some(&peer), target("peer-only"))
            .await
            .unwrap()
            .actor
            .is_none()
    );
    assert_eq!(
        admit(&state, Some(&peer), target("bind"))
            .await
            .unwrap()
            .actor
            .unwrap()
            .auth_subject(),
        "bound-subject"
    );
    for (operation, code) in [
        ("forbidden", Code::PermissionDenied),
        ("unauthenticated", Code::Unauthenticated),
        ("unavailable", Code::Unavailable),
        ("unsupported", Code::Unimplemented),
    ] {
        let Err(status) = admit(&state, Some(&peer), target(operation)).await
        else {
            panic!("policy error must not fall back")
        };
        assert_eq!(status.code(), code);
    }
    assert_eq!(policy.targets.lock().unwrap().len(), 6);
    let Err(status) = admit(&state, None, target("bind")).await else {
        panic!("missing identity must fail")
    };
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(policy.targets.lock().unwrap().len(), 6);
}
