use std::sync::Arc;

use async_trait::async_trait;
use claviron::orbit::placement::{
    Dispatch, DispatchPolicy, Dispatched, Scope, Scoped,
};
use claviron::runtime::registry::{
    Component, Error as RegistryError, Runnable, priority,
};
use claviron::runtime::{AppState, RunContext, ServiceStartPolicy};

use crate::providers::{DnsConfigProvider, DnsProvider};

/// UDP and TCP DNS server. Binds and serves its sockets in `run()`; `boot()`
/// creates nothing, so `--check-config` can boot every provider safely.
/// Splitting this out from `DnsProvider` lets DoH-only deployments use the
/// provider without compiling the listener. Registered in every process, it
/// takes listener placement from the single prepared `dns.yaml` owner. By
/// default it serves in every worker (or standalone), not in the master.
pub struct DnsServer {
    config: Arc<DnsConfigProvider>,
}

impl DnsServer {
    pub fn new(config: Arc<DnsConfigProvider>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Component<AppState> for DnsServer {
    type Deps = (Arc<DnsProvider>,);

    fn name(&self) -> &'static str {
        "DnsServer"
    }

    fn run_priority(&self) -> Option<u8> {
        Some(priority::LATE)
    }

    fn as_runnable(
        self: std::sync::Arc<Self>
    ) -> Option<std::sync::Arc<dyn Runnable<AppState, Self::Deps>>> {
        Some(self)
    }

    fn as_scoped(&self) -> Option<&dyn Scoped> {
        Some(self)
    }

    fn as_dispatched(&self) -> Option<&dyn Dispatched> {
        Some(self)
    }
}

impl Scoped for DnsServer {
    fn scope(&self) -> Scope {
        self.config.current().scope
    }
}

impl Dispatched for DnsServer {
    fn dispatch(&self) -> Dispatch {
        self.config.current().dispatch
    }

    fn dispatch_policy(&self) -> Option<DispatchPolicy> {
        self.config.current().dispatch_policy
    }
}

#[async_trait]
impl Runnable<AppState, <Self as Component<AppState>>::Deps> for DnsServer {
    fn start_policy(
        &self,
        _state: &AppState,
    ) -> ServiceStartPolicy {
        if self.config.current().enabled {
            ServiceStartPolicy::Automatic
        } else {
            ServiceStartPolicy::Unavailable
        }
    }

    async fn run(
        self: Arc<Self>,
        (provider,): <Self as Component<AppState>>::Deps,
        state: AppState,
        context: RunContext,
    ) -> Result<(), RegistryError> {
        // Run-mode gate: dns disabled in config → return early.
        if !provider.config_snapshot().enabled {
            return Ok(());
        }
        let address = provider.config_snapshot().address;
        let udp = super::udp::bind_udp(address)?;
        let tcp = super::tcp::bind_tcp(address).await?;
        // Bound: the kernel queues connections from here on. Say so, so
        // the authority can announce the zones.
        super::announce::listening(&state).await;
        // UDP answers queries; TCP answers the same queries and zone
        // transfers. Both end with the generation.
        tokio::try_join!(
            super::udp::serve_udp(provider.clone(), udp, context.clone()),
            super::tcp::serve_tcp(provider, tcp, context)
        )
        .map(|_| ())
        .map_err(|e| RegistryError::msg(e.to_string()))
    }
}

#[cfg(test)]
#[path = "../../tests/placement.rs"]
mod tests;
