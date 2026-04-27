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

## IRC client

`shade-ircd` is a hand-rolled IRCv3 client. No external IRC framework: every layer was small enough to write directly, and every layer is unit-testable in isolation.

Layers, bottom to top:

| Module | Responsibility |
|---|---|
| `parser` | Zero-copy line parser. `Message<'a>` borrows from the input buffer; only `params` allocates. Handles tags, source, numerics, and trailing parameters. Property-tested via proptest; fuzzed in CI via cargo-fuzz. |
| `connection` | TLS dial (rustls + webpki-roots, plus optional pinned roots), line framing, token-bucket rate limiter (~512 B / 2 s by default), exponential backoff reconnect. Surfaces `ConnectionEvent` (Connected / Line / Disconnected) and a cloneable `Writer` handle. |
| `caps` | IRCv3 capability negotiation state machine. Pure: consumes `Message`, emits `CapAction`s. Drives `CAP LS 302` → `CAP REQ` → `CAP ACK`/`NAK` → done, including chunked-LS continuations. |
| `sasl` | SASL PLAIN and EXTERNAL encoding. Splits payloads at the IRCv3 400-byte boundary; emits the trailing `AUTHENTICATE +` terminator if a chunk lands exactly on the boundary. |
| `state` | In-memory `ServerState`: own nick, channels, members, modes, topics. Consumes parsed messages and emits high-level `StateEvent`s. Handles 001/005/332/333/353 numerics and JOIN/PART/QUIT/KICK/NICK/MODE/TOPIC commands. |
| `mode_queue` | Outbound MODE batcher. Up to 6 modes per line, removes-before-adds within a batch, two parallel queues per channel (`Standard` and `Cookie`) so cookie-op handshakes never interleave with unrelated changes. Quick-priority preemption for time-sensitive flips. |
| `session` | Async loop tying it all together. Runs the `CAP LS → NICK/USER → CAP REQ → SASL → CAP END → RPL_WELCOME → JOIN` registration sequence, replies to server `PING`, flushes the mode queue on a 250 ms tick, and emits `SessionEvent`s for the daemon to react to. Resets internal state on each reconnect. |

Why hand-rolled: the parser is small, the state machine is small, and we want zero-copy parsing for line-rate processing without surprise allocations. The Wraith reference at `src/mod/server.mod/servmsg.cc` shows what a 4500-line monolithic dispatch table grows into; we'd rather pay the up-front cost for layered modules each under 600 lines.

The `session` module exposes a `ReadyHandle` (an `Arc<AtomicBool>`-backed flag) that flips true on `RPL_WELCOME` and false on disconnect. The daemon shares the same atomic with `shade-api`'s `ReadinessProbes`, so `/readyz`'s `irc_connected` reflects live IRC state without needing a callback channel.

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
