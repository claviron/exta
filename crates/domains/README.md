# claviron-domains

Registrar-held domain management for
[Claviron](https://crates.io/crates/claviron). One `Domains` API joins registrar
operations with stored domain inventory, delegation, and registrar-hosted DNS
records.

## Capabilities

- GoDaddy and Namecheap integrations behind the object-safe `Registrar` contract.
- Stored inventory and live registrar information as separate APIs.
- Renewal, nameserver delegation, contacts, and registrar-hosted record operations.
- Namecheap registration and glue-host creation/update.
- Domain templates and synchronization reports with per-domain failures.
- Per-registrar pooled HTTP clients with declared capacity and timeouts.

## Features

Default features are empty: no registrar integration is selected automatically.
The base crate includes the domain service, configuration, store, and contracts.

| Feature | Adds |
| --- | --- |
| `godaddy` | GoDaddy API integration. |
| `namecheap` | Namecheap XML API integration. |
| `tasks` | `sync_domains`, `sync_dns_records`, and `sync_dns_providers` task registrations. |

Current integration coverage:

| Operation | GoDaddy | Namecheap |
| --- | --- | --- |
| Inventory, details, contacts, renewal | Yes | Yes |
| Nameserver delegation and hosted DNS records | Yes | Yes |
| New domain registration | Not implemented | Yes |
| Glue-host creation/update | Not implemented | Yes |

Unsupported operations return an explicit error; they do not silently substitute
another registrar workflow.

## Register with an application

```toml
[dependencies]
claviron = { version = "0.2.0-alpha.18", default-features = false, features = ["server", "postgres"] }
claviron-domains = { version = "0.2.0-alpha.18", features = ["godaddy", "namecheap", "tasks"] }
```

```rust
fn configure(state: &claviron::runtime::AppState)
    -> claviron::runtime::registry::Result<()>
{
    claviron_domains::register(state)
}
```

The application supplies the hosting/domain database schema and registrar/provider
seed data. Registration installs the configuration owner; it does not purchase
domains or run synchronization by itself.

## Configuration

`domains.yaml` declares credentials and the outbound budget for each selected
registrar. For example:

```yaml
godaddy:
  api_key: ${GODADDY_API_KEY}
  api_secret: ${GODADDY_API_SECRET}
  http:
    connect_timeout: 2s
    request_timeout: 30s
    rate_limit_pause: 60s
    pool:
      min_idle: 0
      max_idle: 2
      max_live: 4
      max_concurrency: 4
      max_waiting: 64
```

These limits are example declarations, not hidden defaults. Namecheap uses the
same `http` shape with `api_key`, `username`, and `client_ip` credentials.
Bind these environment values through Claviron's environment preparation.
Missing configuration leaves registrars unconfigured.

Each registrar has its own client pool. `max_concurrency` bounds requests and
synchronization width; `max_live` bounds pooled clients. A rate-limit response
pauses admission according to the provider's `Retry-After`, or the declared
`rate_limit_pause` when no retry delay is supplied. Configuration reload replaces
the registrar set and retires the previous pools.

## Stored inventory versus live operations

Create a service handle with `Domains::from_state(&state)`. Its operations make
the source of each result explicit:

- `list` and `get` read the recorded inventory.
- `info`, `contacts`, `nameservers`, and `records` query the registrar.
- `record` and `refresh` bring registrar state into the store.
- `renew` and `register` perform the registrar operation and record its result.
- `set_nameservers`, record mutations, and glue operations act through the
  selected registrar's supported API.

Persisted fields reflect what the registrar reports; unavailable values remain
absent. Registrar HTTP/XML details stay behind the `Registrar` contract.

## Synchronization and management

The `tasks` feature registers `sync_domains`, `sync_dns_records`, and
`sync_dns_providers` as manual, worker-scoped tasks with coordinated `one`
dispatch. Configure the application's task/Orbit dispatcher policy and add task
timing when scheduled synchronization is wanted.

Synchronization is not automatic renewal. Renewal remains an explicit registrar
operation; the synchronization tasks refresh inventory and records, not domain
purchases or renewal payments.

The [gRPC extension](../grpc/README.md) uses this same `Domains` service when its
`domains` feature is enabled. Registrar-hosted DNS records are distinct from
the authoritative zones served by [claviron-dns](../dns/README.md); selecting
one does not silently publish the other.

Part of [Claviron Extra](../../README.md).
