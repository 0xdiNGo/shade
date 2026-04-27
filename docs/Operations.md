# Operations

Single-node operator runbook for the M3 demo. Multi-node mesh, Ansible role, and cert-bootstrap helpers fill in as M4–M6 land.

## Current state (M3)

Shade runs as a single node with a working IRC client, an HTTP+JSON admin API, and the on-JOIN policy enforcement that auto-ops users with `+o` and kicks peers matching channel ban masks. Mesh peering is not yet wired (M4); `peers_up` stays `false` and `/readyz` stays 503 until that lands.

### Local-dev compose

```sh
cd ~/code/irc/shade/deploy
docker compose up --build
```

Two services come up:

* **`ergo`** — `ghcr.io/ergochat/ergo:stable` on `127.0.0.1:6667` (plaintext; for local dev only).
* **`shade`** — the daemon, dialing ergo, joining `#shade-test`, and ready to manage it.

### Probes

```sh
curl http://127.0.0.1:8443/healthz          # → {"ok":true}
curl http://127.0.0.1:8443/readyz           # → {"ok":false, irc_connected:true, peers_up:false, store_open:true}
curl http://127.0.0.1:9090/metrics          # Prometheus text
```

`irc_connected` flips `true` on RPL_WELCOME from ergo. `peers_up` is `false` until M4.

### Admin API

Mounted on the same admin listener. Documented in [Architecture § Admin API](Architecture.md#admin-api).

```sh
curl -sH 'X-Actor: @ops' http://127.0.0.1:8443/v1/users
curl -sH 'X-Actor: @ops' -X POST http://127.0.0.1:8443/v1/users \
  -H 'content-type: application/json' \
  -d '{"handle":"alice","global_flags":"+a","hosts":["alice!*@trusted.example"]}'
```

Production deployments **must** front the admin listener with mTLS. Today the API doesn't enforce auth itself — that's an M4 concern.

### `shadectl` operator CLI

```sh
shade users list
shade users show alice
shade users upsert alice --flags +a --host '*!*@trusted.example' --comment "the boss"
shade users chattr alice +x          # global flag diff
shade users delete alice

shade channels list
shade channels upsert "#shade-test"
shade channels show "#shade-test"
shade channels delete "#shade-test"

shade chanset get "#shade-test"
shade chanset put "#shade-test" --flags +a --mode-pls ntC --topic "Welcome"

shade chattr alice "#shade-test" +ov   # per-channel flag diff
shade chattr alice "#shade-test" -o    # remove +o for this channel

shade mask list "#shade-test" --kind ban
shade mask add  "#shade-test" '*!*@evil.example' --kind ban --reason flooding --sticky
shade mask remove 01HZ...                 # ULID

shade audit --limit 50
shade audit --actor alice                 # substring filter
```

`--base` overrides the API base URL (default reads `admin.listen` from the config file). `--actor` overrides the `X-Actor` header (default `cli:$USER`). `--pretty` indents JSON.

### M3 demo path (auto-op + auto-kick)

```sh
# Set up a privileged user with a hostmask Shade can identify them by.
shade users upsert alice --flags +a --host 'alice!*@trusted.example'
shade channels upsert "#shade-test"
shade chattr alice "#shade-test" +o

# Now have someone with that mask join #shade-test in any IRC client →
# Shade observes the JOIN, identifies alice by hostmask, sees +o in
# channel_user_flags, and sends MODE #shade-test +o alice.

# Add a ban for evil.example:
shade mask add "#shade-test" '*!*@evil.example' --reason flooding

# Anyone matching that hostmask who joins → Shade sends KICK with the reason.

# Inspect what happened:
shade audit --limit 20
```

## Coming in M4–M6

* **M4** — mTLS mesh listener + dialer, snapshot + delta gossip. `peers_up` flips, replicated tables actually replicate.
* **M5** — Role distribution + cookie ops. `ROLE_OP` rotation chooses *which* node sets the mode; HMAC-SHA256 cookies prevent replay between nodes.
* **M6** — Ansible role at `ansible/roles/shade/` with `container` and `systemd` deploy modes; Vault layout for secrets; podman quadlet files; full operator runbook (rotate mesh PSK, replace a node cert, drain a node, recover from a partition).

## Observability shape

* **Logs**: ndjson on stdout. systemd/journald, Loki, container collectors all consume directly.
* **Metrics**: Prometheus scrape on `:9090`. The recorder is wired; counters/gauges land per-feature as those features ship.
* **Health**: `/healthz` (always ok once the process binds), `/readyz` (composite — `irc_connected`, `peers_up`, `store_open`).
* **Audit**: per-mutation rows in the `audit_log` SQLite table. Audit rows are **not** mesh-replicated (M4); each node owns its own history.

## Threat model (placeholder)

A full written threat model lands before M5. The high-stakes axes:

* Compromised IRC server (we trust services for nick identity but not for op authority).
* Compromised single Shade node (mesh PSK rotation, cookie-key generation counter).
* Compromised peer cert (cert pinning + fingerprint in `peers` table).
* Compromised mesh PSK (full rebuild required; documented).
* Network partition (deterministic role rotation tolerates this; see [Architecture § Role distribution](Architecture.md#role-distribution)).

References to come once the document exists in-tree.
