# claviron-dns

Authoritative DNS for [Claviron](https://crates.io/crates/claviron), with UDP/TCP
listeners, an optional DNS-over-HTTPS endpoint, and database-backed zone
snapshots. Queries use the prepared in-memory snapshot, not SQL.

## Capabilities

- Authoritative answers for managed zones, including wildcard and CNAME handling.
- UDP and length-prefixed TCP DNS on the configured address.
- `GET` and `POST /dns-query` on a dedicated DoH vhost.
- Typed zone, SOA, and record management through `management::DnsStore`.
- PostgreSQL notifications or SQLite fleet events that refresh the serving snapshot.
- TSIG-authenticated TCP zone transfers to configured secondaries, and NOTIFY
  when zone serials change.
- An in-process resolver over the same snapshot for Claviron applications.

This is not a public recursive resolver. Queries outside owned zones are refused.

## Features

| Feature | Adds |
| --- | --- |
| None (`default-features = false`) | Protocol and internal data-model code without service registration. |
| `service` | Configuration, provider, snapshot, query handler, management store, and resolver integration; no DNS socket listener. |
| `server` (default) | `service` plus the managed UDP/TCP listener. |
| `postgres` | Explicit PostgreSQL backend and LISTEN/NOTIFY integration; implies `service`. |
| `sqlite` | SQLite on the hosting DB profile and committed-write fleet events; implies `service`. |
| `upstream` | Bind the snapshot as the upstream resolver; implies `service` and the facade's `upstream` capability. |
| `doh` | `service` plus an exclusive Edge `/dns-query` binding and TLS integration. Does not itself select the UDP/TCP listener. |

`server` does not select a database backend. Enable `postgres` or `sqlite` to
match `db.yaml`'s `hosting:` profile. Without an explicit profile, hosting selects
`postgres.default`; DNS does not fall back when another profile is selected.

## Register with an application

```toml
[dependencies]
claviron = { version = "0.2.0-alpha.20", default-features = false, features = ["server", "postgres"] }
claviron-dns = { version = "0.2.0-alpha.20", default-features = false, features = ["server", "postgres"] }
```

```rust
fn configure(state: &claviron::runtime::AppState)
    -> claviron::runtime::registry::Result<()>
{
    claviron_dns::register(state)
}
```

The application supplies its database configuration and the `dns` schema,
including the serial/notification triggers. Registration does not create the
database schema.

For SQLite, select `sqlite` and configure `hosting: sqlite.hosting` in `db.yaml`.
The selected file must contain `dns_zones`, `dns_records`, and their SOA serial
triggers. Mutations use immediate transactions; failed writes emit no event.
Obtain a management store through `DnsProvider::store()` to announce commits.
Direct `DnsStore::sqlite()` / `DnsStore::open()` handles do not announce writes.

## Configuration

`dns.yaml` belongs in the application's Claviron configuration directory. An
absent file leaves DNS disabled.

```yaml
enabled: true
address: 127.0.0.1:5353
scope: workers
dispatch: each
```

This example binds UDP and TCP. Use the desired public address and DNS port for
a delegated nameserver deployment. `scope` and `dispatch` control listener
placement, not snapshot availability. Coordinated `one` or `pool` placement
requires the application's Orbit dispatcher and an explicit `dispatch_policy`.

For DoH, select `doh` and add:

```yaml
doh:
  vhost: dns
```

`dns` is a canonical vhost key, not a public hostname or alias. The application
must define that host and configure its TLS certificate. This binding owns the
host exclusively: only `/dns-query` is served; unrelated paths return 404.
A DoH-only build uses `default-features = false` with `postgres` and `doh`.

`tsig_keys` and `secondaries` configure authenticated transfers and secondary
notifications. Key names, permitted peer addresses, and optional per-secondary
zone lists are explicit; secrets should come from the provider's declared
environment rather than committed configuration.

## Data and reload

Zone and record writes commit through `management::DnsStore`. Database triggers
own serial changes. PostgreSQL also owns NOTIFY publication; provider-created
SQLite stores emit `claviron.dns.changed.v1` after commit. The provider rebuilds
the snapshot on reload, notifications, fleet changes and listener resynchronization.
A lagged fleet receiver reloads the full snapshot. External SQLite writers must
explicitly request a reload; SQLite has no NOTIFY.
Committed data and publication to every serving process are separate outcomes.

Snapshot reload does not rebind sockets. Address or listener-placement changes
require a new listener generation.

`DnsResolverFactory` answers names inside managed zones from the snapshot and
can delegate other names to an application-supplied resolver factory. It is not
bound by default. Enable `upstream` to register it automatically, with no
fallthrough: names outside this service's zones fail with `NxDomain`, never a
system DNS query. Applications needing a custom fallthrough can leave that
feature off and bind `DnsResolverFactory` themselves.

## Transfer and protocol boundaries

AXFR requires a configured secondary address and a valid TSIG signature. IXFR
currently returns the full zone rather than an incremental journal. Transfers
fit one DNS message; larger zones are refused rather than split into an
unsupported multi-message signed transfer.

Negative responses distinguish NXDOMAIN from NODATA and include the zone's SOA
when available. Response packets are not accepted as new queries. TSIG transfer
authentication is not general DNSSEC signing of authoritative answers.

The [gRPC extension](../grpc/README.md) exposes zone/record management through its
`dns` feature; the application still registers this provider separately.

Part of [Claviron Extra](../../README.md).
