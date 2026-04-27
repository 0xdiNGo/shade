# Operations

This page is a stub. It fills in as M6 lands (Ansible role + container deployment).

## Current state (M1)

You can build and run Shade today, but only as a single node with no IRC client and no mesh. What works:

```sh
# Build
cd ~/code/irc/shade
cargo build --release --bin shade

# Or via container
docker build -f deploy/Dockerfile -t shade:dev .

# Run
shade --config /etc/shade/shade.toml run

# Probe
curl http://127.0.0.1:8443/healthz   # → {"ok":true}
curl http://127.0.0.1:8443/readyz    # → {"ok":false,"irc_connected":false,"peers_up":false,"store_open":true}
curl http://127.0.0.1:9090/metrics   # Prometheus text
```

Configuration template at [`deploy/shade.example.toml`](../deploy/shade.example.toml). Local-dev compose at [`deploy/compose.yaml`](../deploy/compose.yaml).

## Coming in M6

* **Ansible role** at `ansible/roles/shade/` with two deploy modes (`container` / `systemd`) selectable via `shade_deploy_mode`.
* **Cert bootstrap** via `shade init-ca` / `shade issue-cert` for self-host, or step-ca integration for orgs with existing PKI.
* **Vault layout** for secrets: node private key, mesh PSK, optional SASL password.
* **Podman quadlet** files for systemd-managed containers without a daemon.
* **Operator runbook**: rotating mesh PSK, replacing a node cert, draining a node before maintenance, recovering from a partition.

## Observability shape

* **Logs**: ndjson on stdout. systemd/journald, Loki, container collectors all consume directly.
* **Metrics**: Prometheus scrape on `:9090`. Counters/gauges land per-feature; today we only have what `metrics` and the recorder install for free.
* **Health**: `/healthz` (always ok once the process binds), `/readyz` (composite — irc_connected, peers_up, store_open).
* **Audit**: per-mutation rows in the `audit_log` SQLite table (M3 onward).

## Threat model (placeholder)

A full written threat model lands before M5. The high-stakes axes:

* Compromised IRC server (we trust services for nick identity but not for op authority).
* Compromised single Shade node (mesh PSK rotation, cookie-key generation counter).
* Compromised peer cert (cert pinning + fingerprint in `peers` table).
* Compromised mesh PSK (full rebuild required; documented).
* Network partition (deterministic role rotation tolerates this; see [Architecture § Role distribution](Architecture.md#role-distribution)).

References to come once the document exists in-tree.
