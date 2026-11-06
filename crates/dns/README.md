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
| `metrics` | `service` plus authoritative DNS observations and the existing Claviron metrics registry. No exporter listener is created. |

`server` does not select a database backend. Enable `postgres` or `sqlite` to
match `db.yaml`'s `hosting:` profile. Without an explicit profile, hosting selects
`postgres.default`; DNS does not fall back when another profile is selected.

## Register with an application

```toml
[dependencies]
claviron = { version = "0.2.0-alpha.25", default-features = false, features = ["server", "postgres"] }
claviron-dns = { version = "0.2.0-alpha.25.1", default-features = false, features = ["server", "postgres"] }
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
tcp_backlog: 1024
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
The change listener runs in every process, independently of socket placement.
Workers refresh serving snapshots; the master (or standalone process) sends
secondary NOTIFY messages for changed serials. Committed data and publication
to every serving process are separate outcomes.

Snapshot reload does not rebind sockets. Address or listener-placement changes
require a new listener generation.

`DnsResolverFactory` answers names inside managed zones from the snapshot and
can delegate other names to an application-supplied resolver factory. It is not
bound by default. Enable `upstream` to register it automatically, with no
fallthrough: names outside this service's zones fail with `NxDomain`, never a
system DNS query. Applications needing a custom fallthrough can leave that
feature off and bind `DnsResolverFactory` themselves.

## Authoritative DNS metrics

The optional `metrics` feature is available from alpha.24. Select it on
`claviron-dns` in the application manifest. Claviron does not depend on Extra, so its
facade feature cannot implicitly enable an Extra crate's instrumentation.
The application keeps its existing protected metrics endpoint.

Collection is disabled without a `metrics` section in `dns.yaml`:

```yaml
metrics:
  enabled: true
  publish_interval: 1s
  max_age: 5s
```

Both durations are explicit operator policy, not hidden fallback values.
`publish_interval` must be positive; `max_age` must be a whole number of seconds
and at least the publication interval. The example uses the same 1s/5s policy
as the existing HTTP metrics configuration. Applying configuration updates
collection directly; the publisher waits for a configuration notification when
disabled and performs no periodic work. No DNS samples are exported while
collection or DNS itself is disabled. Already admitted observations finish
under their original collection decision. Counters survive toggling collection
within a process, and reset when that process restarts.

| Metric | Type / unit | Labels | Counts |
| --- | --- | --- | --- |
| `claviron_dns_requests_total` | Counter | `transport` | UDP datagrams received, TCP frames after their length header is read, or requests entering the DoH handler. |
| `claviron_dns_queries_total` | Counter | `transport`, `qtype` | Successfully decoded query messages, classified by the first question. A message with no question uses `NONE`. Response packets and malformed wire input are excluded. |
| `claviron_dns_responses_total` | Counter | `transport`, `rcode` | Successful UDP send, complete TCP frame write, or handoff of a DoH DNS response to the HTTP layer. |
| `claviron_dns_failures_total` | Counter | `transport`, `reason` | One terminal failure instead of a successful response handoff. |
| `claviron_dns_request_duration_seconds` | Summary, seconds | `transport` | Sum and count, without quantiles, from admission until successful handoff, failure or cancellation. |

Transport labels are `udp`, `tcp`, `doh`. Query types are `A`, `AAAA`, `CNAME`,
`MX`, `NS`, `TXT`, `SOA`, `PTR`, `SRV`, `CAA`, `AXFR`, `IXFR`, `ANY`, `OTHER`,
`NONE`. Response codes are `NOERROR`, `FORMERR`, `SERVFAIL`, `NXDOMAIN`, `NOTIMP`,
`REFUSED`, `OTHER`. Failure reasons are `malformed`, `response_packet`,
`unavailable`, `processing`, `encode`, `write`, `read`, `cancelled`, `method`.
No query name, client address, zone name or arbitrary error text becomes a label.

Unsupported DNS operations that produce NOTIMP are responses, not processing
failures. A response whose write fails increments only the `write` failure,
never the response counter. Malformed UDP packets and ignored response packets
are failures without a DNS reply. TCP connection acceptance, clean EOF between
frames, partial length headers and socket receive errors before admission are
not requests. HTTP errors in DoH count as failures; its response counter means
handoff, not confirmed delivery to a client. Later HTTP write failures belong
to HTTP metrics. These counters are separate from outbound resolver metrics.

Standalone exposition reads the local snapshot. In fleet mode, every process
publishes its own cumulative snapshot to the DNS-owned Orbit ring, including a
master if DNS is configured to run there. Any exporter merges the latest fresh
snapshot per node; it never adds its local counters on top of its published
snapshot. Labels are preserved in both modes. A graceful shutdown or disable
publishes a tombstone. A crash expires after `max_age`; a restarted node's first
snapshot replaces its previous lifetime. Fleet totals can therefore decrease
when a node resets or expires; they are a live-process cumulative view, not
durable fleet accounting. Scrape one fleet endpoint, not every worker and sum.

The fixed snapshot is 827 bytes on physical kind `190`, using the existing
Orbit snapshot scan capacity. The canonical allocation is recorded in
Claviron's SHM kind index. Changing this schema requires a new physical kind.

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
