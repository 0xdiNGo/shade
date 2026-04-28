# Shade Helm Chart

Deploys the [Shade IRC bot](https://github.com/0xdiNGo/shade) as a
`StatefulSet` on Kubernetes (k3s, EKS, GKE, AKS, or any CNCF-conformant
cluster). Each replica is a fully-joined mesh peer; the headless `shade`
Service gives every pod a stable DNS name for peer discovery.

## Prerequisites

| Tool | Minimum version |
|------|-----------------|
| Helm | 3.10 |
| kubectl | 1.27 |
| Kubernetes | 1.27 |

Optional: Prometheus Operator (for `serviceMonitor.enabled`), a
NetworkPolicy-enforcing CNI (for `networkPolicy.enabled`).

## Quick install

```sh
# 1. Pre-create the env-vars Secret with a real mesh PSK.
kubectl create namespace shade
kubectl create secret generic my-shade-secrets \
  -n shade \
  --from-literal=SHADE_MESH_PSK="$(head -c 48 /dev/urandom | base64)" \
  --from-literal=SHADE_SASL__PASSWORD=""   # leave empty for SASL EXTERNAL

# 2. Install the chart. The bootstrap Job generates PKI on first install.
helm install my-shade ./deploy/helm/shade/ \
  -n shade \
  --set network.servers[0]="irc.example.com:6697" \
  --set network.nick="shade" \
  --set network.channels[0]="#shade"

# 3. Wait for the bootstrap Job to complete, then watch the pods come up.
kubectl -n shade wait --for=condition=complete job/my-shade-shade-bootstrap --timeout=120s
kubectl -n shade get pods -w

# 4. Check readiness.
kubectl -n shade port-forward svc/my-shade-shade-metrics 9090
curl http://localhost:9090/readyz
```

## Secrets setup

The chart creates two Secrets; both have `helm.sh/resource-policy: keep`
so they survive `helm uninstall`.

### `<release>-shade-secrets` (env vars)

Holds `SHADE_MESH_PSK` and `SHADE_SASL__PASSWORD`. Create or rotate with:

```sh
kubectl create secret generic my-shade-secrets \
  -n shade \
  --from-literal=SHADE_MESH_PSK="$(head -c 48 /dev/urandom | base64)" \
  --from-literal=SHADE_SASL__PASSWORD="<sasl-plain-password>" \
  --dry-run=client -o yaml | kubectl apply -f -
```

### `<release>-shade-pki` (TLS material)

Created by the bootstrap Job on `helm install`. Contains:

| Key | Description |
|-----|-------------|
| `botnet-ca.pem` | Mesh CA bundle (also used for admin mTLS) |
| `node.pem` | shade-0 node cert (SAN = shade-0) |
| `node.key` | shade-0 node private key |
| `admin-ca.pem` | Same as `botnet-ca.pem` (Shade reuses one CA today) |
| `admin.pem` | Initial admin operator cert (CN=admin) |
| `admin.key` | Initial admin operator private key |
| `<release>-shade-N.pem/key` | Per-node certs for replicas 1…N |

Retrieve the initial admin cert after the Job completes:

```sh
kubectl get secret my-shade-shade-pki -n shade \
  -o jsonpath='{.data.admin\.pem}' | base64 -d > admin.pem
kubectl get secret my-shade-shade-pki -n shade \
  -o jsonpath='{.data.admin\.key}' | base64 -d > admin.key
```

Then talk to the admin API:

```sh
kubectl -n shade port-forward svc/my-shade-shade-admin 8443
curl --cert admin.pem --key admin.key \
     --cacert <(kubectl get secret my-shade-shade-pki -n shade \
                -o jsonpath='{.data.botnet-ca\.pem}' | base64 -d) \
     https://localhost:8443/v1/users
```

## Per-node cert note

The bootstrap Job places `shade-0`'s cert in the shared `shade-pki` Secret as
`node.pem` / `node.key`. Replicas 1…N have their certs stored as
`<release>-shade-N.pem` / `<release>-shade-N.key` in the same Secret.

The default StatefulSet mounts the same Secret to all pods, so every pod
reads `node.pem` / `node.key` — which is the shade-0 cert. For strict
per-node TLS identity (where the mesh verifies that the SAN matches the
connecting peer's declared node_id), mount per-node cert material using a
projected volume or an External Secrets Operator `ExternalSecret` per pod.
This is a known limitation of the single-Secret approach; it's safe for
initial deployment because the CA is self-signed and the cert is used only
for mTLS session establishment, not for node_id binding.

## Values reference

| Key | Default | Description |
|-----|---------|-------------|
| `replicaCount` | `3` | Number of Shade pods (mesh peers) |
| `image.repository` | `ghcr.io/0xdingo/shade` | Container image |
| `image.tag` | chart `appVersion` | Image tag |
| `image.pullPolicy` | `IfNotPresent` | |
| `node.dataDir` | `/var/lib/shade` | SQLite data directory |
| `node.tls.caBundle` | `/etc/shade/pki/botnet-ca.pem` | |
| `node.tls.cert` | `/etc/shade/pki/node.pem` | |
| `node.tls.key` | `/etc/shade/pki/node.key` | |
| `mesh.listenPort` | `7331` | Mesh mTLS listener port |
| `mesh.pskEnv` | `SHADE_MESH_PSK` | Env var name for PSK |
| `network.servers` | `["irc.example.com:6697"]` | IRC server list |
| `network.tls` | `true` | TLS toward IRC server |
| `network.nick` | `shade` | Bot nick |
| `network.channels` | `["#shade"]` | Channels to join |
| `network.sasl.mechanism` | `EXTERNAL` | `PLAIN` or `EXTERNAL` |
| `admin.listenPort` | `8443` | Admin mTLS listener port |
| `admin.requireMtls` | `true` | Enforce client certs on admin API |
| `admin.clientCa` | `/etc/shade/pki/botnet-ca.pem` | Admin client CA |
| `admin.ingress.enabled` | `false` | Create an Ingress for admin API |
| `metrics.listenPort` | `9090` | Metrics + probe listener port |
| `logging.level` | `info` | Log level |
| `logging.format` | `json` | Log format (`json` or `text`) |
| `persistence.size` | `1Gi` | PVC size per replica |
| `persistence.storageClass` | `""` | StorageClass (empty = cluster default) |
| `bootstrapJob.enabled` | `true` | Run PKI bootstrap Job on install |
| `bootstrapJob.kubectlImage` | `bitnami/kubectl:latest` | kubectl image for the Job |
| `serviceMonitor.enabled` | `false` | Create Prometheus Operator ServiceMonitor |
| `serviceMonitor.interval` | `30s` | Scrape interval |
| `networkPolicy.enabled` | `false` | Create NetworkPolicy |
| `resources` | `{}` | Pod resource requests/limits (commented placeholders) |

Full documentation in `docs/Operations.md`.
