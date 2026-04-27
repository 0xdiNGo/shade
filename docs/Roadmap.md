# Roadmap

Six milestones from scaffold to MVP demo. Each one closes with a runnable artifact. Total estimate ~9 weeks calendar.

| # | Scope | Status | Demoable artifact |
|---|---|---|---|
| **M1** | Workspace, CI, `shade run` boots, config, SQLite, migrations, `/healthz` `/readyz` `/metrics`, JSON logs, container image. | ✅ **DONE** | `docker run shade --version`; `curl /healthz` returns ok |
| **M2** | `shade-ircd`: TLS+SASL, parser, IRCv3 caps, join channels, member state, rate-limited writes, reconnect with backoff. Mode queue exists, no policy yet. | ✅ **DONE** | Bot joins a channel on a real IRCD, replies to `!ping` |
| **M3** | Domain + HTTP API: users, channels, flags, masks. `shadectl` CLI. Audit log. Single-node only. | ✅ **DONE** | Create users via API, bot auto-ops `+o` users on join, kicks banned hosts |
| **M4** | Mesh: mTLS listener, handshake, snapshot sync, delta gossip for users/channels/masks. | ✅ **DONE** | 2 nodes, write to A, read from B, identical state in <100ms |
| **M5** | Role distribution + cookie ops: `OpRequest`/`OpGrant` mesh messages, HMAC-SHA256 cookies, mass-op/deop detection. | ✅ **DONE** | 2 nodes, one with ROLE_OP, the other requests op via mesh, cookie-verified op happens; tampered cookie rejected |
| **M6** | MVP polish + Ansible role + container deployment: ergo end-to-end smoke in CI, deployable role, operator runbook + threat model. The remaining chanset toggles, in-channel `/MSG TOKEN` flow, and Argon2id login flow are tracked as v0.2 items. | ✅ **DONE** | `ansible-playbook deploy.yml` rolls out a multi-node mesh against 3 VMs running container artifacts |

## What "MVP" means

Two Shade nodes, mesh-linked over mTLS, both joined to `#shade-test` on a real IRCv3 server (probably [ergo](https://github.com/ergochat/ergo)), authenticated via SASL EXTERNAL.

* One node holds `ROLE_OP`, the other holds `ROLE_KICK`.
* `shadectl chattr alice +o-#shade-test` syncs to both nodes via gossip.
* Alice joins → `ROLE_OP` node ops her with a valid HMAC cookie.
* Eve joins matching a ban → `ROLE_KICK` node kicks her.
* `curl --cert ops.pem https://shade-1:8443/v1/peers` returns both nodes healthy.
* `kill -TERM` on either node; surviving node rebalances roles within 5 seconds.

## Out of MVP scope (v0.2+)

* Multi-network IRC (single network for v0)
* `RBL` / DNSBL on join
* Revenge actions (the rest of `deflag_t` mass-action handlers beyond mass-op/deop detection)
* Cache-invite for closed channels
* The remaining chanset toggles (we ship 12 of ~25 in MVP)
* The remaining flood thresholds (we ship 4 of 12 in MVP)
* The remaining role types (we ship 6 of 13; RESOLV dropped entirely)
* The `op #foo nick` half of the in-channel admin flow (`TOKEN <handle> <password>` for token issuance is shipped; the `op`/`deop`/`mode` etc. command handlers live in v0.2)
* Per-handle rate limiting on `/v1/login` (Argon2id is slow but not infinite)
* CRL/OCSP for admin and node certs — today, lost certs require operator-driven CA rotation

## Out forever (intentionally)

See [Improvements Over Wraith § Net of changes](Improvements-Over-Wraith.md#net-of-changes).
