# Architecture

## Topology

Every Shade node runs the same binary. There is no hub-vs-leaf binary distinction; whether a node connects to IRC, peers with other nodes, or both is configuration. Nodes form a full **mTLS mesh** — every node trusts a botnet CA and presents its own node certificate. The mesh CA can be self-bootstrapped (`shade init-ca` / `shade issue-cert`) or driven by an existing PKI like step-ca.

```
                     ┌─── irc.libera.chat:6697 ───┐
                     │                            │
            shade-iad-01 ◀─── mTLS mesh ───▶ shade-ord-01
                     ▲                            ▲
                     │                            │
                     └────────── shade-fra-01 ────┘
                                    │
                                 (peers)
```

Each node holds a SQLite database with the same logical content; gossip keeps them in sync.

## Workspace layout

Cargo workspace at [github.com/0xdiNGo/shade](https://github.com/0xdiNGo/shade):

| Crate | Purpose |
|---|---|
| `shade-proto` | Mesh wire types, version negotiation. I/O-free; consumable by external tools. |
| `shade-core` | Pure domain types: `User`, `Channel`, `Ban`, `Role`, `FlagSet`, audit. |
| `shade-ircd` | IRC client: parser, IRCv3 caps, SASL, mode queue, channel state. |
| `shade-mesh` | mTLS listener and dialer; peer state; snapshot + delta gossip. |
| `shade-api` | axum HTTP+JSON admin API; `/healthz`, `/readyz`, `/metrics`; CRUD endpoints (M3). |
| `shade-store` | SQLite (bundled libsqlite3) connection pool; refinery migrations. |
| `shade-bin` | Binary entrypoint; CLI subcommands: `run`, `migrate`, `init-ca`, `issue-cert`, `check-config`, `dump-state`. |

Why we under-split: bdlib's micromodularity in Wraith is a cautionary tale. Each crate above earns its boundary; we do not have a `shade-flags` crate or a `shade-config` crate.

## Storage

One SQLite file per node at `/var/lib/shade/shade.db`. WAL journal, `synchronous=NORMAL`, `foreign_keys=ON`. Schema is forward-only via [refinery](https://crates.io/crates/refinery); migration files live in `crates/shade-store/migrations/`.

Every replicated table carries `(updated_at, origin_node)`. Mesh sync is **last-write-wins** on the lex-ordered pair `(updated_at, origin_node)` — late wins, ties broken by smaller `origin_node`. Hostmask sets use add/remove tombstones with their own `updated_at` so deletes survive reorderings.

## Mesh protocol

Length-prefixed [MessagePack](https://msgpack.org) frames over a single mTLS-protected TCP stream per peer pair. Frame header: `u32 length BE | msgpack payload`. Default port 7331.

After the TLS handshake, both sides send `PeerHello { node_id, proto_version, features, clock_ms, channels }`. The peer cert SAN must match the configured `node_id`; cert fingerprint is pinned in the `peers` table. Mismatch drops the connection and increments `shade_mesh_handshake_failures_total`.

Sync model:

1. After handshake, the freshly-connected node sends `SnapshotRequest { since_ts: last_seen_for_peer }`.
2. Peer streams `SnapshotChunk`s of all rows where `updated_at > since_ts`.
3. Steady state: each domain mutation broadcast as `*Upsert`/`*Delete` to all connected peers.
4. Conflict resolution per LWW above.

Slow peers are dropped (bounded `mpsc::channel(1024)` per peer) and forced to snapshot-resync on reconnect — simpler than queueing forever.

## Role distribution

Wraith's role-distribution algorithm at `irc.cc:1818` is `roleidx % botcount` rotation across the sorted list of in-channel linked bots, run independently on each node. **It works because the input is deterministic.** We keep this model because it is genuinely good: no leader election, no consensus, no Raft. Same input → same output everywhere.

Algorithm (per-channel, recomputed on topology change):

1. Build the eligible-peer set: connected to mesh, joined to the channel, opped, advertising `feature.roles`.
2. Sort by `node_id`.
3. For role *i* needing *n* slots (counts come from Wraith's `flags.cc:41-56` table), assign to peers `[i, i+1, …, i+n-1] mod len`.
4. Run on every node independently.

Triggers for rebalance: peer connect/disconnect, peer joins/parts the channel, peer gains/loses ops, plus every 5 minutes as a backstop.

Edge case — **mesh partition**: each side rebalances among visible bots and may both think they hold ROLE_OP. Cookie-op verification (next section) papers over double-ops. Snapshot reconciliation on partition heal restores the global view before the next rebalance tick.

## Cookie ops (replay protection between bots)

When one Shade node asks another to op a user, the request is signed so a hijacked bot cannot replay it. Wraith does this with MD5 + a per-bot counter; we do it with **HMAC-SHA256** over typed payloads.

Per-channel key: `HKDF-SHA256(salt = "shade/v1/cookie", ikm = mesh_psk, info = channel_name)`.

Cookie payload (msgpack):
```
{ requester_node, target_nick, request_id (ULID), ts_ms }
```

Tag: `HMAC-SHA256(key, payload)[..16]` (128-bit truncation). Wire form: `base64(payload).base64(tag)`.

Verifier rejects:

* `ts_ms > now + 5s` (too far future)
* `ts_ms < now - 60s` (too far past)
* `request_id` seen in the last 5 minutes (ring-buffer dedupe)

PSK rotates on a quorum-advanced generation counter, with wall-clock fallback after N minutes for partition tolerance.

Why this is materially better than Wraith's MD5+counter scheme is in [Improvements Over Wraith § Cookie ops](Improvements-Over-Wraith.md#4-md5-cookie--per-bot-counter-for-op-replay-prevention).

## Authentication

Two paths:

| Surface | Mechanism |
|---|---|
| HTTP+JSON admin API | mTLS client certificate; subject CN maps to a Shade user handle. Operator must hold `+m` (master) or `+n` (owner) for write ops. |
| In-channel admin (`/MSG shade TOKEN <hex> op #foo nick`) | Short-lived bearer token (≤ 15 min) minted via API: `POST /v1/users/{handle}/irc-tokens`. Hashed-stored, single-use. |

Hostmask passive identification stays for last-seen tracking but **never grants permissions**. Wraith's AUTHSTART/AUTH MD5 challenge, telnet/DCC password auth, and SECPASS are dropped.

## Observability

* **Logs**: `tracing` ndjson to stdout. systemd/journald and container collectors consume directly. Dev mode: `format = "text"` for human-readable output.
* **Metrics**: `metrics-exporter-prometheus`. `/metrics` served on a private-network listener. Process-wide recorder via `OnceLock`.
* **Health**: `/healthz` (always ok once up), `/readyz` (composite — `irc_connected`, `peers_up`, `store_open`).
* **Audit**: every API mutation writes to the `audit_log` table with actor (handle or `node_id`), action verb, target, and JSON details.
