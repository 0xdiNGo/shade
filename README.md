# Shade

Modern IRC bot and channel-management mesh, written in Rust.

A successor to the [Wraith](https://github.com/wraith) bot family. Same shape — encrypted node-to-node mesh, distributed channel-protection roles, hardened cookie-op verification — but rebuilt for container-forward deployment, declarative configuration, modern observability, and an actually defensible threat model. **Not interoperable with Wraith botnets.**

## Status

**v0.1 — public beta.** All M1–M7 milestones closed: IRC client, mTLS mesh + last-write-wins gossip, role distribution + cookie ops, mass-op detection that auto-deops, native admin-listener mTLS, Argon2id login + bearer tokens, in-channel `TOKEN` flow, per-IP login rate limit, graceful shutdown, signed + SBOM-attested releases, backup/restore tooling, k3s + Helm chart for primary deployment.

Not yet recommended for hostile public-IRC environments without a private network in front. See [Threat-Model.md](docs/Threat-Model.md) for the honest defended-properties list.

## Quick start (k3s + Helm)

```sh
# 1. Add the chart (or clone this repo and `helm install ./deploy/helm/shade`).
helm install shade ./deploy/helm/shade \
  --namespace shade --create-namespace \
  --set mesh.psk=$(openssl rand -base64 48) \
  --set network.servers='{"irc.example.net:6697"}' \
  --set network.nick=shade \
  --set replicaCount=3

# 2. Watch the bootstrap Job mint the CA + per-replica node certs and the
#    StatefulSet come up.
kubectl -n shade get pods -w

# 3. Pull the operator's admin client cert out of the bootstrapped Secret.
kubectl -n shade get secret shade-pki -o jsonpath='{.data.admin\.pem}' | base64 -d > admin.pem
kubectl -n shade get secret shade-pki -o jsonpath='{.data.admin\.key}' | base64 -d > admin.key
kubectl -n shade get secret shade-pki -o jsonpath='{.data.botnet-ca\.pem}' | base64 -d > botnet-ca.pem

# 4. Talk to the admin API.
kubectl -n shade port-forward svc/shade-admin 8443:8443 &
shadectl --cert admin.pem --key admin.key --ca-bundle botnet-ca.pem users list
```

Full Helm values reference in [`deploy/helm/shade/README.md`](deploy/helm/shade/README.md). Production-deploy runbook with cert / PSK / backup / drain procedures in [`docs/Operations.md`](docs/Operations.md).

For operators who want a no-Kubernetes path, an Ansible role + Podman + systemd Type=notify deploy is documented as the Tier-2 alternative. Same binary, same image, same config — just a different wrapper.

## Verify a release

Every image pushed to `ghcr.io/0xdingo/shade:v*` is signed with cosign keyless via GitHub OIDC and ships a CycloneDX SBOM as an in-toto attestation. No managed signing keys to rotate.

```sh
cosign verify ghcr.io/0xdingo/shade:v0.1.0 \
  --certificate-identity-regexp 'https://github.com/0xdiNGo/shade/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

cosign download attestation ghcr.io/0xdingo/shade:v0.1.0 \
  | jq -r '.payload' | base64 -d | jq '.predicate'
```

## What's in the box

| Surface | Status |
|---|---|
| IRC client (parser, IRCv3 caps, SASL PLAIN/EXTERNAL, mode batcher, session loop) | Hand-rolled, fuzzed in CI |
| mTLS mesh (length-prefixed MessagePack, snapshot + delta gossip, last-write-wins) | rustls + tokio-rustls |
| Role distribution (`roleidx % botcount` rotation) | Deterministic, runs per-node |
| Cookie ops (HMAC-SHA256 over typed payloads, HKDF-SHA256 per-channel keys) | Replaces Wraith's MD5+counter |
| Mass-op response | Auto-deops victims via the `ROLE_OP` holder, 60-s cooldown |
| Admin API (`/v1/users`, `/channels`, `/masks`, `/audit`, `/login`) | mTLS-enforced; cert CN = User.handle |
| Operator login (`POST /v1/login`) + bearer tokens + IRC `TOKEN` flow | Argon2id, per-IP rate-limited |
| Graceful shutdown | SIGTERM drains in-flight HTTP, IRC QUIT, mesh frames |
| Backup / restore (`shade backup`, `shade restore`) | Online-backup API; `BEGIN EXCLUSIVE` lock probe |
| Releases | Cosign keyless signature + SBOM via syft |
| Deployment | Helm chart for k3s (Tier-1); Ansible + Podman (Tier-2) |

Not yet shipped (tracked in [Roadmap.md](docs/Roadmap.md) § Out of MVP scope): the rest of the in-channel admin command surface beyond `TOKEN`, CRL/OCSP for cert revocation, multi-network IRC, the remaining chanset toggles + flood thresholds.

## Documentation

| Page | What's there |
|---|---|
| [Architecture](docs/Architecture.md) | Crate layout, mesh + IRC client + storage design |
| [Threat-Model](docs/Threat-Model.md) | Adversaries, defended properties, **what we don't defend against** |
| [Improvements-Over-Wraith](docs/Improvements-Over-Wraith.md) | Cited critique of Wraith design choices |
| [Operations](docs/Operations.md) | Helm + Ansible install, cert/PSK rotation, backup/restore, release verification |
| [Roadmap](docs/Roadmap.md) | Milestones (M1–M7 done; v0.2 backlog) |
| [Development](docs/Development.md) | Local toolchain, CI, PR conventions |

## Contributing

PRs welcome. Conventions:

- `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` must pass.
- Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
- Threat-model-relevant changes update `docs/Threat-Model.md` in the same PR.

## License

[MIT](LICENSE).
