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
claviron = { version = "0.2.0-alpha.20", default-features = false, features = ["edge", "tls", "postgres"] }
claviron-grpc = { version = "0.2.0-alpha.20", features = ["server", "workers", "mtls", "certificates"] }
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

## Service access policy

All server builds can use `claviron::auth::access::{PeerIdentity, AccessTarget,
AccessPolicy}` without selecting user or role management. Bind a host-owned
policy with `registry.bind_dyn`. No `validate_user` switch or separate
application model is installed. Without a policy, existing mTLS admission stays
in effect. A registered policy is consulted on every call; errors never fall
back to certificate-only admission.

The accepting transport validates the certificate before providing its exact
public leaf DER, structured CNs and URI SAN candidates in `PeerIdentity`.
`AccessTarget` uses `service = "grpc"` and the actual fully qualified RPC path,
not a header or a submitted scope. The same policy protects dedicated H2 and
Edge H2/H3 calls, including reflection and capability discovery. Hosts grant
those discovery operations explicitly when their policy requires it.

`Ok(None)` grants peer-only access. `Ok(Some(actor))` also supplies the host's
`AnyAuthenticated` subject to user-management handlers. These handlers require
that actor and the matching operation admission; mTLS alone cannot synthesize a
user. The policy owns lookup, active-state checks, role interpretation and
binding to a stable application subject. CN-only credentials need no invented
identifier, and multiple URI candidates are retained for explicit host selection.
The issuer DN is display metadata, not a trust-anchor identity; the host owns
trust-domain restrictions through its configured TLS trust and access policy.
No permission claims are inferred from certificate names or URI contents.

## User-management protocol

[users.proto](proto/users.proto) defines schema discovery, user/role/permission
record management, and direct assignment operations. Application-defined JSON
fields and optional UI metadata use the shared
[management.proto](proto/management.proto) envelope. Public references and
revision tokens are opaque; no common users table or fixed profile fields are
required. Validation and management scope belong to the downstream application.
The native contracts are `claviron::auth::users::UserManager` for user CRUD and
`claviron::auth::authorization::AuthorizationManager` for role/permission CRUD
and assignments. Their `users` and `authorization` features are independent.

Enable `users` for user CRUD, `authorization` for role/permission CRUD and
direct assignments, or both. Each enables `server` and its matching Claviron
capability. One `UserManagement` service dispatches to the corresponding manager
bound in the application registry. A missing manager or disabled resource returns
`UNIMPLEMENTED`; `server` alone installs neither capability. Protocol types and
client stubs remain available without these features.
The base server's hosting services still require the host's choice of a
Claviron database backend; these management features do not select one.

Bind the application's existing `UserManager` and/or `AuthorizationManager`
with `registry.bind_dyn`. User-management calls require an application actor
returned by the host's `claviron::auth::access::AccessPolicy`.
Managers recheck current authority, scope, validation and revisions on every call.

Declare work bounds in `grpc.yaml`, for example:

```yaml
user_management:
  max_page_size: 100
  max_document_bytes: 16384
  max_assignment_members: 256
```

These are explicit example values, not defaults. List, JSON mutation and
assignment replacement calls require the applicable bounds before delegation.
Reload updates these bounds without replacing the manager. Tonic's default
inbound message-size bound also applies. JSON decoding preserves exact integer
values and rejects non-object documents. No database or GUI is installed here.

`GetAssignmentSchema` discovers pivot operations through `AuthorizationManager`
independently of user CRUD schemas; its revision does not replace a user schema
revision. `GetAssignments` and `ReplaceAssignments` use the same provider even
when user CRUD is disabled.

### Schema contract

Schemas come from the selected application manager, with separate projections:

- `record_schema_json` describes authorized output fields.
- `create.data_schema_json` describes the complete creation object. Required
  fields use `required`; accepted choices use `enum` or `const`. A default does
  not satisfy a requirement for an explicitly submitted choice. Account types
  and other domain fields are application-defined, not fixed gRPC fields.
- `update.data_schema_json` describes editable values. Updates are sparse:
  validate supplied fields and the resulting record without requiring unchanged
  fields to be submitted again.

Data schemas explicitly declare JSON Schema 2020-12 through `$schema`. The
provider declares its unknown-field policy and enforces the same constraints
when writing. Optional `ui_schema_json` uses JSON Forms UI Schema; its controls
refer to data properties. Layout, visibility and read-only hints grant no write
authority. Clients reject unsupported forms rather than silently dropping rules.

Field, constraint, UI or operation changes require a new schema revision.
Validation remains server-side and returns JSON-Pointer field violations through
the mutation-result envelope. No schema is inferred from database columns.

A server adapter routes user records to UserManager and role/permission records
to AuthorizationManager. Every assignment operation belongs to AuthorizationManager,
including user-role and user-permission pivots. Its `assignment_schema` discovers
relationship capabilities independently of a user's CRUD form. A deployment may
provide either manager; omitted capabilities must not load or require the other.

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

`CertAuthority` supplies public trust only. Local issuance explicitly acquires
a `CertSigner` for the selected authority; reading trust does not load its CA key.

Local issuance, certificate import/export, and ACME issuance are separate
operations. Import does not silently issue a replacement certificate or alter
runtime trust. Creating or renewing a CA does not automatically replace the
trust material pinned by already running listeners.

Client issuance accepts an optional `subject_uri`, stored in a URI SAN separately
from the CN and DNS/IP aliases. Responses report URI identities parsed from the
signed certificate. Export and same-key renewal preserve them. The application
AccessPolicy owns user binding and authorization; the issuer infers neither.

Part of [Claviron Extra](../../README.md).
