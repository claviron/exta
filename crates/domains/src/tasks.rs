//! The synchronizations, as thin task bodies over [`Domains`].
//!
//! Each registers as a manual task: it exists without a line in
//! `tasks.yaml` and runs on request; a line under its name replaces the
//! entry whole, which is how an operator schedules it (`timing: {kind:
//! cron, ...}`). Worker-scoped with `dispatch = "one"`: every worker can do
//! the work and the Orbit contest picks one per occurrence. Concurrency and
//! pacing are the registrars' pools, declared in `domains.yaml`.

use claviron::runtime::AppState;
use claviron::tasks::{Error, TaskResult, task};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{Domains, SyncReport};

fn service(
    state: &AppState,
    task: &str,
) -> TaskResult<Domains> {
    Domains::from_state(state)
        .map_err(|error| Error::other(format!("{task}: {error}")))
}

fn log(
    task: &str,
    report: &SyncReport,
) {
    if report.failed.is_empty() {
        info!(
            task,
            found = report.found,
            created = report.created.len(),
            updated = report.updated.len(),
            skipped = report.skipped,
            "✅ synchronization completed"
        );
    } else {
        warn!(
            task,
            found = report.found,
            created = report.created.len(),
            updated = report.updated.len(),
            skipped = report.skipped,
            failed = report.failed.len(),
            "⚠️ synchronization completed with failures"
        );
        for (domain, message) in &report.failed {
            warn!(task, domain, %message, "synchronization failed for a domain");
        }
    }
}

/// Pull every configured registrar's domain list into the store.
#[task(
    name = "sync_domains",
    scope = "workers",
    dispatch = "one",
    config = "timing: { kind: manual }\n",
    crate_path = "claviron"
)]
pub async fn sync_domains(
    state: AppState,
    _token: CancellationToken,
) -> TaskResult<()> {
    let report = service(&state, "sync_domains")?
        .sync_domains(None)
        .await
        .map_err(|error| Error::other(format!("sync_domains: {error}")))?;
    log("sync_domains", &report);
    Ok(())
}

/// Pull registrar-hosted records into the store for every unexpired domain
/// whose DNS provider is a configured registrar.
#[task(
    name = "sync_dns_records",
    scope = "workers",
    dispatch = "one",
    config = "timing: { kind: manual }\n",
    crate_path = "claviron"
)]
pub async fn sync_dns_records(
    state: AppState,
    _token: CancellationToken,
) -> TaskResult<()> {
    let report = service(&state, "sync_dns_records")?
        .sync_records(None)
        .await
        .map_err(|error| Error::other(format!("sync_dns_records: {error}")))?;
    log("sync_dns_records", &report);
    Ok(())
}

/// Infer the DNS provider of every stored domain that has none, from the
/// delegation its registrar reports.
#[task(
    name = "sync_dns_providers",
    scope = "workers",
    dispatch = "one",
    config = "timing: { kind: manual }\n",
    crate_path = "claviron"
)]
pub async fn sync_dns_providers(
    state: AppState,
    _token: CancellationToken,
) -> TaskResult<()> {
    let report =
        service(&state, "sync_dns_providers")?.sync_providers().await.map_err(
            |error| Error::other(format!("sync_dns_providers: {error}")),
        )?;
    log("sync_dns_providers", &report);
    Ok(())
}
