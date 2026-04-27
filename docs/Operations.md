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

With `admin.require_mtls = true` (the default) the listener verifies a client cert chain rooted at `admin.client_ca` and derives the audit actor from the cert Subject CN. The dev path (`require_mtls = false`) reads `X-Actor` from the request headers — only used in tests.

```sh
# Production: mTLS to the daemon, audit actor = cert CN.
curl --cert /etc/shade/admin/alice.pem \
     --key  /etc/shade/admin/alice.key \
     --cacert /etc/shade/pki/botnet-ca.pem \
     https://shade-iad-01.internal:8443/v1/users

# Dev (require_mtls = false): plain HTTP, X-Actor header for audit.
curl -sH 'X-Actor: @ops' http://127.0.0.1:8443/v1/users
```

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

`--base` overrides the API base URL (default reads `admin.listen` from the config file; scheme defaults to `https` when `--cert` is set, `http` otherwise). `--cert`, `--key`, and `--ca-bundle` (or `SHADECTL_CERT`, `SHADECTL_KEY`, `SHADECTL_CA_BUNDLE`) supply the admin client cert that the daemon's mTLS listener requires; the cert Subject CN becomes the audit actor and `--actor` is ignored. `--actor` is honored only against a `require_mtls = false` daemon. `--pretty` indents JSON.

```sh
# Talk to a production daemon over mTLS.
shade users list \
  --cert      /etc/shade/admin/alice.pem \
  --key       /etc/shade/admin/alice.key \
  --ca-bundle /etc/shade/pki/botnet-ca.pem
```

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

### Bringing the mesh online (M4)

```sh
# On the first node (generates the botnet CA):
shade init-ca       --out-dir /etc/shade/pki

# Per-node cert issuance (run for each node_id):
shade issue-cert    --node-id shade-iad-01 \
                    --ca-dir   /etc/shade/pki \
                    --out-dir  /etc/shade/pki

# /etc/shade/pki/{botnet-ca.pem, node.pem, node.key} match the
# defaults in deploy/shade.example.toml.
```

Restart `shade run`. The daemon will detect the PEM trio and bring the mesh online; `[mesh].peers` in the config drives outbound dial attempts. `/readyz` flips `peers_up: true` as soon as one peer is connected. Without the PEM trio, the daemon stays single-node and logs a one-line warning — the M3 demo path keeps working.

For multi-node tests today, copy `botnet-ca.pem` to every node, run `issue-cert` on the side that holds the CA key, and rsync the resulting `node.pem` + `node.key` to the target node.

### Deploying with Ansible (M6)

The role at [`ansible/roles/shade`](../ansible/roles/shade) deploys Shade as a Podman-managed container under a `Type=notify` systemd unit on each node.

```sh
cd ansible

# 1. Generate the botnet CA on the bootstrap node.
ansible-playbook -i hosts.ini playbooks/bootstrap-ca.yml \
  --extra-vars "ca_node=shade-iad-01"

# 2. Issue per-node certs (signed by the CA from step 1).
ansible-playbook -i hosts.ini playbooks/issue-certs.yml

# 3. Deploy. Re-runnable on every config change or image bump.
ansible-playbook -i hosts.ini playbooks/deploy.yml \
  --extra-vars "shade_image_tag=v0.1.0"
```

The full variable reference is in [`ansible/README.md`](../ansible/README.md). Mesh PSK and SASL passwords come from Ansible Vault and are written into a `0600` `secrets.env` consumed via systemd `EnvironmentFile=` — never into the rendered config or unit file.

### Operator runbooks

#### Verifying a signed release

Every image pushed to `ghcr.io/0xdingo/shade` on a `v*` tag push is signed with cosign keyless (GitHub OIDC) and has an SBOM attached as an in-toto attestation. No managed keys are involved; the signing identity is bound to the release workflow.

```sh
# Verify the image signature.
cosign verify ghcr.io/0xdingo/shade:v0.1.0 \
  --certificate-identity-regexp 'https://github.com/0xdiNGo/shade/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Pull the SBOM attestation and inspect the predicate.
cosign download attestation ghcr.io/0xdingo/shade:v0.1.0 \
  | jq -r '.payload' | base64 -d | jq '.predicate'
```

`cosign verify` exits non-zero if the signature is invalid, the signing identity does not match, or the OIDC issuer differs — safe to use as a gate in deployment automation. The SBOM predicate is CycloneDX JSON; pipe it into `cyclonedx-cli` or any CycloneDX-aware tool for component analysis.

#### Cert rotation

When a node's cert is approaching expiry (or has been compromised):

```sh
# 1. On the bootstrap CA node, issue a fresh cert.
shade issue-cert --node-id shade-iad-01 --ca-dir /etc/shade/pki --out-dir /tmp/new-cert

# 2. Copy node.pem + node.key to the target.
scp /tmp/new-cert/node.{pem,key} target:/etc/shade/pki/

# 3. Bounce the daemon.
ssh target systemctl restart shade
```

CA rotation is a heavier procedure: re-bootstrap the CA on a new node, reissue every node cert, copy the new CA bundle to every node, restart in a rolling fashion.

#### Issuing an admin client cert

Operators authenticate to the admin listener with an mTLS client cert. The cert's Subject CN must match a `User.handle` already in the store — the handle propagates into every audit row written by that operator. Workflow:

```sh
# 1. Create the operator's user record. Hostmasks are optional; flags
#    can be tuned later via `shadectl users chattr`.
shade users upsert alice --flags +a --comment "ops on-call"

# 2. Sign a client cert keyed to that handle. CN=alice, EKU=clientAuth,
#    no SAN. 1-year validity by default.
shade issue-admin-cert --handle alice \
                       --ca-dir /etc/shade/pki \
                       --out-dir /etc/shade/admin

# 3. Distribute alice.pem + alice.key to the operator's workstation
#    over a confidential channel (Vault, age-encrypted file, USB, etc.).
#    Set SHADECTL_CERT / SHADECTL_KEY in their shell to use them by
#    default with shadectl.
```

Revocation today is by user removal: `shadectl users delete alice` strips the row and any per-channel flags. The cert itself is still cryptographically valid until expiry; until CRL/OCSP lands (v0.2), a compromised operator cert means the CA must be rotated to invalidate it.

#### Login + bearer tokens (no-cert path)

For occasional ops or scripted use where distributing an admin client cert is overkill, an operator can authenticate with `{handle, password}` and use the resulting bearer token instead.

```sh
# 1. Set a password on the user record. Run as an existing admin
#    (cert or another token).
shadectl users upsert alice --flags +a
shadectl --pretty users show alice    # confirm the record
echo 'hunter2' | curl -sf \
  --cacert /etc/shade/pki/botnet-ca.pem \
  --cert /etc/shade/admin/root.pem --key /etc/shade/admin/root.key \
  -X PUT https://shade-iad-01.internal:8443/v1/users/alice/password \
  -H 'content-type: application/json' \
  -d '{"password":"hunter2"}'

# 2. The operator runs `shade login` with --password-stdin (or
#    interactively at the prompt). The response carries the wire
#    token and its expiry.
echo 'hunter2' | shade login --handle alice --password-stdin
# {"token":"abc...","expires_at":1714530000000}

# 3. Use the token. SHADECTL_TOKEN sets it for the rest of the shell;
#    --token <wire> works one-off.
export SHADECTL_TOKEN=abc...
shadectl users list
```

Token lifetime is 1 hour. The wire form is shown to the operator exactly once; from then on the daemon stores only the SHA-256 hash. Revocation: `DELETE /v1/users/:handle/password` clears the password hash (preventing new logins for that handle) and `shadectl users delete <handle>` removes the user record entirely. Existing tokens for a deleted handle remain in `auth_tokens` until their `expires_at`; the next login attempt will prune them via the per-login GC sweep. For an immediate cut-off, `DELETE` the user and accept that no live tokens can match a now-missing handle.

The same flow is available over IRC for operators who already have an authenticated session to the bot:

```
/MSG shade TOKEN alice hunter2
```

The bot replies privately with `token <wire> expires <ts_ms>`. **Caveat**: the password and reply traverse the IRC server in cleartext above the TLS layer — fine in a trusted single-network setup, but operators with a TLS path to `/v1/login` should prefer that.

#### Mesh PSK rotation

```sh
# 1. Generate a new PSK locally (32+ bytes of /dev/urandom).
NEW_PSK=$(head -c 48 /dev/urandom | base64)

# 2. Update Ansible Vault.
ansible-vault edit ansible/group_vars/all/vault.yml
# Set vault_shade_mesh_psk: "<NEW_PSK>"

# 3. Rolling redeploy.
ansible-playbook -i hosts.ini playbooks/deploy.yml --serial 1
```

There's a brief window during the rolling rotation where some nodes have the old PSK and some have the new — cookies minted on one side fail verification on the other. Plan for ≤ 60 seconds of degraded cookie verification per node bounce; the mesh stays connected throughout (mTLS is independent of the PSK).

#### Drain a node before maintenance

```sh
# 1. Stop the daemon — peers detect the disconnect within ~1s and
#    rebalance roles among the remaining set.
systemctl stop shade

# 2. Do the maintenance work (kernel upgrade, hardware swap, ...).

# 3. Bring the daemon back up.
systemctl start shade
# /readyz will flip irc_connected:true once IRC reconnects, and
# peers_up:true once at least one mesh peer accepts the dialer.
```

The peer's snapshot exchange catches up the returning node before any new gossip is applied — same code path as a fresh boot.

#### Recover from a partition

Two halves of a partition operate independently; both think they hold all roles, so both may issue ops in their respective views. Cookie verification keeps each side's ops self-consistent. On heal:

1. The mesh handshake completes between previously-disconnected peers.
2. Each side sends `SnapshotRequest{since_ts: last_seen_for_peer}`.
3. Both sides exchange any rows newer than the watermark.
4. Last-write-wins resolves conflicts; mask tombstones are honored.
5. The next role-rebalance tick (≤ 5 minutes) restores the unified `ROLE_OP` assignment.

**No manual intervention required for a healthy heal.** If the audit log shows mass-op warnings during the partition, that's expected — operators inspect the audit log to verify legitimacy.

### CI smoke

Every PR runs `deploy/smoke.sh` end-to-end on GitHub Actions. The script boots ergo + shade via docker compose, asserts `/readyz` flips `irc_connected:true`, exercises the full `/v1` surface (users / channels / masks / audit), and tears down. Failure dumps the shade container's logs as a CI artifact.

To run the same smoke locally:

```sh
cd deploy && ./smoke.sh
```

## Threat model

See [Threat-Model.md](Threat-Model.md). The high-stakes axes:

* Compromised IRC server (services we trust for nick identity but not for op authority).
* Compromised single Shade node (mesh PSK rotation, cookie-key generation counter).
* Compromised peer cert (cert pinning + fingerprint in `peers` table; CA rotation runbook above).
* Compromised mesh PSK (rotation runbook above).
* Network partition (deterministic role rotation tolerates it; see § Recover from a partition).

## Observability shape

* **Logs**: ndjson on stdout. systemd/journald, Loki, container collectors all consume directly.
* **Metrics**: Prometheus scrape on `:9090`. The recorder is wired; counters/gauges land per-feature as those features ship.
* **Health**: `/healthz` (always ok once the process binds), `/readyz` (composite — `irc_connected`, `peers_up`, `store_open`).
* **Audit**: per-mutation rows in the `audit_log` SQLite table. Audit rows are **not** mesh-replicated (M4); each node owns its own history.

