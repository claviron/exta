use super::DnsZoneListener;
use claviron::orbit::placement::Scope;
use claviron::runtime::AppState;
use claviron::runtime::registry::Component;

#[test]
fn zone_changes_reach_the_notify_owner_and_every_serving_process() {
    let listener = DnsZoneListener;
    let scope = <DnsZoneListener as Component<AppState>>::as_scoped(&listener)
        .expect(
            "zone changes need explicit placement, independent of DNS sockets",
        )
        .scope();
    for role in [Scope::Master, Scope::Worker, Scope::Any] {
        assert!(scope.includes(role), "zone changes must reach {role:?}");
    }
}
