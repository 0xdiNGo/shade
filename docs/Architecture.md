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
| `shade-core` | Pure domain types: `User`, `Channel`, `ChannelSettings`, `ChannelUserFlags`, `Mask`, `Role`, `FlagSet`, `AuditEntry`. |
| `shade-ircd` | IRC client: parser, IRCv3 caps, SASL, mode queue, channel state, async session loop. |
| `shade-mesh` | mTLS listener and dialer; peer state; snapshot + delta gossip. |
| `shade-api` | axum HTTP+JSON admin API; `/healthz`, `/readyz`, `/metrics`; `/v1` CRUD for users / channels / masks / audit. |
| `shade-store` | SQLite (bundled libsqlite3) connection pool; refinery migrations; CRUD accessors returning shade-core types. |
| `shade-bin` | Binary entrypoint. Daemon subcommands (`run`, `migrate`, `init-ca`, `issue-cert`, `check-config`, `dump-state`) and the operator CLI (`users`, `channels`, `chanset`, `chattr`, `mask`, `audit`). |

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

## Mesh implementation

`shade-mesh` is one crate; the layers compose bottom to top.

| Module | Responsibility |
|---|---|
| `codec` | Async length-prefixed MessagePack frame I/O (`u32 BE | payload`) over any `AsyncRead+AsyncWrite`. 1 MiB inbound size cap rejects oversize-announced frames before allocation. |
| `tls` | rustls `ServerConfig` / `ClientConfig` builders sharing the botnet CA trust root. `cert_node_id(&CertificateDer)` extracts SAN-DNSName-then-CN; the handshake compares it to `PeerHello.node_id` to bind transport identity to application identity. |
| `peer` | mTLS listener (`accept_peer`) + dialer (`dial_peer`) returning a `PeerStream` carrying the peer's claimed `node_id`. Dialer rejects on cert SAN mismatch. |
| `handshake` | Symmetric `PeerHello` exchange. Validates frame shape, `proto_version`, and the identity-binding equality. |
| `peer_loop` | Per-connection async task: sends our `SnapshotRequest`, replies to peer's `SnapshotRequest` with paged `SnapshotChunk`s, applies inbound `Upsert` / `Delete` via `shade_store::gossip`, drains an outbound `mpsc` from the hub onto the wire. |
| `hub` | `MeshHub`: owns the listener task and one dialer task per configured peer (with exponential-backoff reconnect), maintains the `node_id → mpsc::Sender<Frame>` registry, broadcasts outbound frames, exposes `peers_up: Arc<AtomicBool>` for `/readyz`. |

Operator commands `shade init-ca` and `shade issue-cert` (Ed25519 self-signed via rcgen) generate the bundle expected by `[node.tls]`. The daemon detects whether TLS material is on disk; if all three files exist it brings the mesh online, otherwise it logs a one-line warning and stays single-node — same M3 demo path keeps working unchanged.

LWW gating lives at the SQL layer in the upsert paths (`ON CONFLICT DO UPDATE WHERE existing.updated_at < excluded.updated_at OR (=, lex-smaller-origin)`). Local writers don't carry the gate — they always win — so concurrent local writes within the same millisecond can't accidentally lose to themselves. Remote applies go through `shade_store::gossip::apply_*`, which carries the gate. Mask deletes leave a tombstone in `mask_tombstones`; an inbound mask `Upsert` consults the tombstone first, so deletes survive reorderings.

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

## Admin API

`shade-api::v1` exposes the M3 CRUD surface. Mounted alongside `/healthz`, `/readyz`, `/metrics` on the same admin listener.

| Path | Methods |
|---|---|
| `/v1/users` | GET, POST |
| `/v1/users/:handle` | GET, PATCH, DELETE |
| `/v1/channels` | GET, POST |
| `/v1/channels/:name` | GET, DELETE |
| `/v1/channels/:name/settings` | GET, PUT |
| `/v1/channels/:name/users/:handle` | PUT, DELETE |
| `/v1/channels/:name/masks?kind=…` | GET, POST |
| `/v1/masks/:id` | DELETE |
| `/v1/audit?limit=N&actor=substr` | GET |

`PATCH` and `PUT` flag endpoints accept either an absolute set (`flags` / `global_flags`) or a Wraith-style `flags_diff` (`+ox-d`) applied to the existing row.

Every mutation writes one `AuditEntry` (`AuditSource::Api`) before returning. Audit writes are best-effort: a failure to insert is logged but does not roll back the mutation.

### Authentication (mTLS)

`admin.require_mtls = true` (the default) binds the admin listener to a rustls `WebPkiClientVerifier` rooted at `admin.client_ca`. The TLS accept loop in `shade-bin::admin_tls`:

1. Completes the handshake; clients without a cert or with a chain that doesn't validate are dropped before any HTTP bytes flow.
2. Extracts the verified peer cert's Subject CN (`shade_mesh::cert_subject_cn`) — that string is the operator's `User.handle`.
3. Wraps the admin router in an `Extension(VerifiedActor(handle))` layer for that connection. Every request is then tagged with the cryptographically authenticated actor.

Routes pull the resolved identity through `shade_api::auth::ActorClaim`, which prefers `VerifiedActor` over the `X-Actor` header, falling back to the node ID for audit when neither is set. The `X-Actor` path remains only for the dev-only `require_mtls = false` mode used in tests and the M3-style demo.

Operator certs are issued with `shade issue-admin-cert --handle <user-handle>`: Subject CN = handle, no SAN, EKU = clientAuth only. The handle must already exist as a Shade `User` (via `shadectl users upsert`) so per-channel flags can attach to it.

`shadectl` is the operator CLI (`shade users …`, `shade channels …`, `shade chattr …`, `shade mask …`, `shade audit`). Synchronous `ureq` with a rustls `tls_config` when `--cert/--key/--ca-bundle` (or `SHADECTL_CERT/SHADECTL_KEY/SHADECTL_CA_BUNDLE`) are supplied; one HTTP call per subcommand. Output is the API's raw JSON (or `--pretty` indented).

### On-JOIN policy

The daemon's `drive_session` loop runs two policy checks for every peer JOIN:

1. **Ban check.** `shade_store::masks::match_ban` is consulted with the channel and the peer's `nick!user@host`. Channel-scoped exempts beat channel-scoped bans, which beat global bans. A match → `KICK <chan> <nick> :<reason>`.
2. **Identification + auto-op.** `shade_store::users::match_by_host` looks up the peer by hostmask. If a `ChannelUserFlags` row exists carrying `+o`, the daemon sends `MODE <chan> +o <nick>`. Hostmask matching is *passive identification only* — the per-channel flag set is what grants the privilege.

Mass-action defenses (op floods, mode storms) and the `ROLE_OP` rotation that decides *which* bot actually sets the mode arrive in M5; M3's auto-op fires unconditionally on every node that thinks it should op, which is the right behavior for single-node dev but will be guarded once the mesh is in.

## Cookie verification + mass-op detection

Each Shade node feeds the `MODE` and `NOTICE` events it observes into an `OpObserver` (in `shade-bin/op_observer.rs`):

- A `MODE +o nick` from any source seeds a pending op. If a `NOTICE #c :shade-cookie/<wire>` whose payload's `target_nick` matches arrives within `COOKIE_GRACE_MS` (5 s), the op is logged as **certified by cookie**. Otherwise it ages out and gets logged as **uncertified** — that's the signal for a hijacked-bot scenario.
- A sliding 10-second per-source window flags any source issuing ≥ 5 ops as a mass-op event. M5 ships warn-level logging only; M6 may add automatic deop / lockdown.

Cookie verification consults `shade_core::cookies::verify`, which checks the HMAC-SHA256 tag (constant-time compare), enforces the `ts_ms` window (`-60s, +5s`), and runs the `request_id` through a `ReplayGuard` ring buffer. A tampered or replayed cookie is rejected with a typed error.

## Authentication

Two paths in the eventual design:

| Surface | Mechanism |
|---|---|
| HTTP+JSON admin API | mTLS client certificate; subject CN maps to a Shade user handle. Operator must hold `+m` (master) or `+n` (owner) for write ops. |
| In-channel admin (`/MSG shade TOKEN <hex> op #foo nick`) | Short-lived bearer token (≤ 15 min) minted via API: `POST /v1/users/{handle}/irc-tokens`. Hashed-stored, single-use. |

Hostmask passive identification stays for last-seen tracking but **never grants permissions**. Wraith's AUTHSTART/AUTH MD5 challenge, telnet/DCC password auth, and SECPASS are dropped.

> **As of M3:** mTLS enforcement on the admin listener is not yet wired — the API trusts the `X-Actor` request header for audit attribution and accepts any caller. Production deployments must front the admin listener with mTLS today (the listener address default `0.0.0.0:8443` deliberately invites this); native mTLS verification with subject-CN → handle mapping lands in M4 alongside the mesh listener that needs the same primitives. The in-channel token path lands in M6.

## Observability

* **Logs**: `tracing` ndjson to stdout. systemd/journald and container collectors consume directly. Dev mode: `format = "text"` for human-readable output.
* **Metrics**: `metrics-exporter-prometheus`. `/metrics` served on a private-network listener. Process-wide recorder via `OnceLock`.
* **Health**: `/healthz` (always ok once up), `/readyz` (composite — `irc_connected`, `peers_up`, `store_open`).
* **Audit**: every API mutation writes to the `audit_log` table with actor (handle or `node_id`), action verb, target, and JSON details.
