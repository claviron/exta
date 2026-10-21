# claviron-acme

ACME certificate issuance and renewal for
[Claviron](https://crates.io/crates/claviron). The crate registers accounts,
completes HTTP-01 challenges, and produces certificate material for file-based
or database-backed deployments.

## Capabilities

- Account registration, signed orders, challenge validation, CSR finalization,
  and certificate retrieval.
- ES256 and RS256 account keys and JWS signing.
- File helpers for account creation, issuance, and renewal.
- Database-backed accounts, issuance attempts, certificates, aliases, and server
  assignments through `AcmeStore` and Claviron's hosting store.
- Optional HTTP reachability pre-validation and per-common-name attempt throttling.
- Managed certificate renewal and stale challenge-file cleanup tasks.

Issuance and serving are separate. This crate obtains and persists material;
Claviron's hosting/TLS services update the certificate resolver used by later
handshakes.

## Features

Default features are empty.

| Feature | Adds |
| --- | --- |
| `server` | `AcmeProvider`, `register`, and prepared `acme.yaml` configuration. |
| `db` | SQLx-backed `AcmeStore` and hosting integration. Database action helpers also require `server`. |
| `postgres` | `db` with Claviron's PostgreSQL backend. |
| `sqlite` | `db` with SQLite support, using the configured hosting database. |
| `tasks` | Database-backed renewal and challenge cleanup task registrations; combine with `server`. |

## Register with an application

```toml
[dependencies]
claviron = { version = "0.2.0-alpha.20", default-features = false, features = ["edge", "http01", "postgres", "tasks"] }
claviron-acme = { version = "0.2.0-alpha.20", features = ["server", "postgres", "tasks"] }
```

In the application's registration callback:

```rust
fn configure(state: &claviron::runtime::AppState)
    -> claviron::runtime::registry::Result<()>
{
    claviron_acme::register(state)
}
```

Choose `sqlite` instead of `postgres` for a SQLite hosting deployment. The
application must provide the configured database and hosting schema. Selecting
the task feature does not choose a renewal schedule for the deployment.

## Configuration

`AcmeProvider` owns `acme.yaml` under the application's configuration directory.
An absent file disables ACME configuration. New operations use the newly
prepared snapshot after reload; an in-flight order retains its original one.

```yaml
base_dir: storage/acme
default_account: default
challenges_dir: storage/acme/challenges
production_url: https://acme-v02.api.letsencrypt.org
staging_url: https://acme-staging-v02.api.letsencrypt.org
organization:
  name: Example
  unit: Operations
  country: US
  state: California
  city: San Francisco
  email: operator@example.com
algorithm: ES256
renew_before: 30
pre-validation: true
throttle_window: 1h
max_attempts_per_cn: 3
```

Paths are relative to the application working directory. `renew_before` is in
days. These values are an example deployment policy, not a claim about CA quotas.

For HTTP-01, enable Claviron's `http01` feature and ACME handling on the selected
cleartext listener. The provider publishes its challenge directory to the HTTP
integration. The validating CA must be able to retrieve the token over public
port 80 from that directory. Reachability pre-validation checks this path, not
TLS installation or trust.

## Operations and renewal

The public modules separate protocol clients from higher-level operations:

- `clients::{AccountClient, CertClient}` implement ACME exchanges.
- `actions::{account, certificate, renew}` provide the file workflow.
- `actions::database` provides database issuance and renewal with `db` + `server`.
- `AcmeStore` owns account and attempt-log persistence; callers need not query
  its tables directly.

With `server` + `tasks`, `acme_renew` scans due ACME-owned certificates and
`acme_gc` removes stale challenge files. Configure renewal timing through
Claviron's task system. Attempt logs are written before network issuance and
feed the configured throttle. Successful database writes propagate through the
hosting certificate lifecycle rather than directly editing the TLS resolver.

The [gRPC extension](../grpc/README.md) can expose these operations when its
`acme` feature and the ACME provider are installed.

## Boundaries

Only HTTP-01 challenges are implemented: no DNS-01, TLS-ALPN-01, wildcard
issuance through DNS-01, external account binding, or account-key rollover.
ES384 and EdDSA account generation/signing are not implemented.

The file issuance helper does not persist staging certificates, and file renewal
is production-only. Protect account keys, private certificate keys, and their
backups; configuration reload is not a secret-management system.

Part of [Claviron Extra](../../README.md).
