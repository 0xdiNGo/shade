# Shade Ansible role

Container-mode deployment of Shade nodes. Each node runs the
`ghcr.io/0xdiNGo/shade:<tag>` image as a systemd-managed Podman
container, with `/etc/shade/` and `/var/lib/shade/` bind-mounted from
the host.

## Quick start

```sh
# 1. Bootstrap one node — generates the botnet CA on `shade-iad-01`
#    and issues a node cert for itself.
ansible-playbook -i hosts.ini playbooks/bootstrap-ca.yml \
  --extra-vars "ca_node=shade-iad-01"

# 2. Issue certs for the rest, sourcing the CA from the bootstrap
#    node and copying the issued node cert/key to each target.
ansible-playbook -i hosts.ini playbooks/issue-certs.yml

# 3. Deploy. This is idempotent — re-run on every config or image
#    bump.
ansible-playbook -i hosts.ini playbooks/deploy.yml \
  --extra-vars "shade_image_tag=v0.1.0"
```

## Variables

The role reads `vars/main.yml` (defaults) and merges anything from
group / host vars on top. Material that's secret should come from
Ansible Vault.

| Var | Purpose |
|---|---|
| `shade_node_id` | Stable node identifier. Must match the node-cert SAN. |
| `shade_image` | OCI image, e.g. `ghcr.io/0xdiNGo/shade`. |
| `shade_image_tag` | Image tag (`v0.1.0`, `main`, …). |
| `shade_data_dir` | Host path for SQLite + audit logs. Defaults `/var/lib/shade`. |
| `shade_pki_dir` | Host path for `botnet-ca.pem` + `node.pem` + `node.key`. Defaults `/etc/shade/pki`. |
| `shade_admin_listen` | Admin API bind, e.g. `0.0.0.0:8443`. |
| `shade_metrics_listen` | Prometheus bind, e.g. `127.0.0.1:9090`. |
| `shade_mesh_listen` | Inter-node listener, e.g. `0.0.0.0:7331`. |
| `shade_mesh_peers` | List of `{ node_id, endpoint }` for static peer dials. |
| `shade_mesh_psk_env` | Env var name holding the mesh PSK; sourced from Vault. |
| `shade_network_*` | IRC network config (server, nick, ident, realname, channels). |

## Vault layout

```yaml
# group_vars/all/vault.yml  (encrypted with `ansible-vault edit`)
vault_shade_mesh_psk: "REPLACE-WITH-REAL-PSK-32+-BYTES"
vault_shade_sasl_password: "..."
```

The role wires these into a per-node systemd dropin so the env vars
are available to the Podman container without ever appearing in the
unit file or rendered config.

## Cert-rotation runbook

See [docs/Operations.md § Cert rotation](../docs/Operations.md#cert-rotation).

## Why container-only

The role intentionally does not ship a `systemd` deploy mode using a
host-built `shade` binary. Container artifacts are signed, immutable,
and reproducible; everything else is more work for less value. If you
need a non-container deploy, copy `roles/shade/templates/shade.toml.j2`
and run the binary yourself.
