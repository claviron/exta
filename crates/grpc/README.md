# claviron-grpc

Typed, mTLS-secured administration for
[Claviron](https://crates.io/crates/claviron). Serve management RPCs on a dedicated
HTTP/2 listener, an exclusive HTTP/2 or HTTP/3 Edge vhost, or both, using the same prepared Tonic
service set.

Generated protobuf messages, service definitions, and client stubs are available
without enabling the management server. Clients own their channel and TLS setup.

## Management surfaces

The base server exposes server identity/reload/shutdown, live hosting and aliases,
services, embedded applications, linked applications, and reflection.
Optional features add workers, tasks, DNS, registrar-held domains, ACME, local
certificate issuance, certificate transfer, and a protected metrics endpoint.

These APIs use the runtime's existing authoritative state. gRPC does not launch
linked runner processes, maintain another worker table, or duplicate service
lifecycle controllers.

## Features

Default features are empty.

| Feature | Adds |
| --- | --- |
| `server` | Provider, configuration, dedicated listener, and vhost management serving. |
| `workers` | Worker inspection, lifecycle commands, rolling restart, and fleet resize; includes `server`. |
| `tasks` | Task-management routes when combined with `server`, plus Claviron's task capability. |
| `acme` | ACME persistence dependency and ACME RPCs when combined with `server`. |
| `dns` | DNS management routes and service dependency; includes `server`, not a DNS listener or PostgreSQL selection. |
| `domains` | Registrar/domain management routes with GoDaddy and Namecheap integrations; includes `server`. |
| `mtls-manager` | Direct Rust API for local CA, server, and client certificate issuance/renewal; includes `server`. |
| `mtls` | `mtls-manager` plus its RPC routes. |
| `certificate-manager` | Direct Rust API for certificate import/export; includes `server`. |
| `certificates` | `certificate-manager` plus certificate-transfer RPC routes. |
| `metrics` | Protected HTTP `GET /metrics` alongside management; includes `server`. |

The application registers backing providers separately. For example, DNS RPCs
need a configured DNS provider and its explicit PostgreSQL feature; selecting
the gRPC `dns` feature alone does not supply that deployment.

## Register with an application

```toml
[dependencies]
claviron = { version = "0.2.0-alpha.19", default-features = false, features = ["edge", "tls", "postgres"] }
claviron-grpc = { version = "0.2.0-alpha.19", features = ["server", "workers", "mtls", "certificates"] }
```

```rust
fn configure(state: &claviron::runtime::AppState)
    -> claviron::runtime::registry::Result<()>
{
    claviron_grpc::register(state)
}
```

Database-backed operations require the configured hosting store and schema.
Protobuf generation uses `protoc` at build time, including protocol-only builds.
The [proto directory](proto) contains the source contracts.

## Vhost configuration

`grpc.yaml` is read from the application's Claviron configuration directory:

```yaml
vhosts: [management]
request_timeout: 30s
max_requests: 100
```

`management` is a canonical vhost key. Its existing Edge policy must allow
HTTP/2 or HTTP/3, provide a server certificate, and require trusted client certificates
with `tls.client_auth.mode: required`. Public hostnames belong to that host's
aliases. The management binding is exclusive, not merged into an application
router. Plaintext, unverified clients and HTTP/1 requests cannot enter RPC handling.
H3 uses Edge's existing QUIC listener and body/trailer handling; there is no
gRPC-specific H3 feature or dedicated QUIC listener. The application selects
Claviron's `http3` feature and permits H3 on its management vhost. Clients
must independently support gRPC over H3; H2 clients continue to use H2.

## Dedicated listener

Add a `listener` independently of `vhosts`, or use `vhosts: []` for a dedicated
listener only:

```yaml
vhosts: []
request_timeout: 30s
max_requests: 100
listener:
  scope: workers
  dispatch: each
  hosts: [management.example.test]
  listen: [127.0.0.1:9443]
  max_connections: 16
  acl:
    policy: deny
    allowed: [127.0.0.0/8]
  handshake_timeout: 10s
  graceful_timeout: 30s
```

These bounds are example policy, not required timeout defaults. `listener.hosts`
contains actual TLS server names whose existing Claviron TLS policies supply
certificates, trust, and required client authentication. It declares no separate
certificate or CA-file configuration. Listener-local ACL checks use the real
accepted peer, not forwarded headers.

All declared binds share the listener connection cap. Conflicts with configured
web TCP listeners are rejected. Listener topology and TLS-policy changes require
a new listener generation; data/config reload is not an implicit socket rebind.
With no listener and no selected vhosts, nothing serves management traffic.

## Lifecycle and trust boundaries

Fleet commands generally acknowledge submission, not completion. Clients observe
later worker/service/application snapshots and generations to confirm the result.
`RunTask` instead waits for one local task occurrence; a task execution budget
and a gRPC transport deadline are separate controls.

Verified TLS client identity is required on both ingresses. A management
connection cannot stop or restart the very ingress carrying that connection.
Direct `MtlsManager` and `CertificateManager` calls use the same issuance/store
logic without requiring a network request; the calling application must enforce
its own identity, ownership, and private-key export permissions.

Local issuance, certificate import/export, and ACME issuance are separate
operations. Import does not silently issue a replacement certificate or alter
runtime trust. Creating or renewing a CA does not automatically replace the
trust material pinned by already running listeners.

Part of [Claviron Extra](../../README.md).
