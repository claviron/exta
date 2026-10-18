# Claviron Extra

Optional infrastructure services for [Claviron](https://crates.io/crates/claviron):
certificate issuance and renewal, authoritative DNS, registrar operations, and
mTLS-secured administration.

Applications select and register these crates explicitly. They use Claviron's
public facade for configuration, service lifecycle, hosting, database access,
and fleet coordination; they are not required by the core runtime.

## Crates

| Crate | Responsibility | Main selections |
| --- | --- | --- |
| [claviron-acme](crates/acme/README.md) | ACME accounts, HTTP-01 issuance, certificate persistence, and renewal tasks. | `server`, `postgres` or `sqlite`, `tasks` |
| [claviron-dns](crates/dns/README.md) | Authoritative DNS over UDP/TCP, optional DoH, immutable serving snapshots, and zone management. | `server` (default), `postgres`, `doh` |
| [claviron-domains](crates/domains/README.md) | Registrar-held domains, registration and renewal operations, delegation, registrar-hosted records, and synchronization. | `godaddy`, `namecheap`, `tasks` |
| [claviron-grpc](crates/grpc/README.md) | Typed management over an mTLS vhost or dedicated HTTP/2 listener, plus generated protocol types and client stubs. | `server`, `workers`, `tasks`, `acme`, `dns`, `domains`, `mtls`, `certificates` |

Each crate README describes its feature boundaries, registration, configuration,
and current limitations.

## How they fit together

- ACME produces certificate material. Claviron's hosting and TLS services publish
  it to the serving certificate resolver; issuance is not part of a handshake.
- DNS answers from prepared zone snapshots, not a database query per packet.
- Domains talks to registrars and records their state. Registrar-hosted DNS
  records and this repository's authoritative DNS zones are separate surfaces.
- gRPC exposes the registered services to management clients. It delegates to
  their existing stores and lifecycle APIs rather than maintaining another
  control plane.

[Orbit Link](https://crates.io/crates/orbitive) and Claviron's fleet APIs provide
same-host coordination. A command being accepted is distinct from every worker
having completed it; management clients observe later snapshots for convergence.

## Application registration

Call only the registrations your application's dependencies and features enable:

```rust
use claviron::runtime::{AppState, registry};

fn configure(state: &AppState) -> registry::Result<()> {
    claviron_acme::register(state)?;
    claviron_dns::register(state)?;
    claviron_domains::register(state)?;
    claviron_grpc::register(state)
}
```

The application owns its binary, configuration directory, environment bindings,
database setup, and deployment. Enabling a Cargo feature does not replace service
registration or install an application's database schema.

## Configuration and ownership

`acme.yaml`, `dns.yaml`, `domains.yaml`, and `grpc.yaml` belong in the application's
Claviron configuration directory. Providers use the runtime's prepared
configuration and declared environment; credentials need not be embedded in
source or read from the process environment on requests.

Missing configuration leaves the corresponding capability unconfigured or
disabled. Reload and restart are distinct: refreshing a data snapshot does not
silently rebind a running listener. See each crate's README for that boundary.

gRPC management requires verified client certificates. TLS material, registrar
credentials, TSIG secrets, and database backups remain operator-owned secrets.

## Development status

APIs and configuration may change between alpha releases. Backward compatibility
is not guaranteed.
