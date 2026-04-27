#!/usr/bin/env bash
# End-to-end smoke test driven by CI's `compose smoke` job.
#
# Brings up ergo + shade via docker compose, waits for shade to
# reach IRC + admin readiness, drives the public /v1 surface, and
# tears down. Exits non-zero on any failure.

set -euo pipefail

ADMIN="http://127.0.0.1:8443"
ERGO_PORT=6667

cd "$(dirname "$0")"

cleanup() {
  docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo ">>> docker compose up --build -d"
docker compose up --build -d

echo ">>> waiting for /healthz"
deadline=$((SECONDS + 60))
until curl -sf "$ADMIN/healthz" >/dev/null; do
  [[ $SECONDS -lt $deadline ]] || { echo "FAIL: /healthz did not come up"; docker compose logs; exit 1; }
  sleep 1
done

echo ">>> waiting for irc_connected=true on /readyz (mesh stays single-node — peers_up=false is expected)"
deadline=$((SECONDS + 60))
until curl -s "$ADMIN/readyz" | grep -q '"irc_connected":true'; do
  [[ $SECONDS -lt $deadline ]] || {
    echo "FAIL: /readyz never showed irc_connected=true"
    curl -s "$ADMIN/readyz"
    docker compose logs shade | tail -50
    exit 1
  }
  sleep 1
done
echo "    irc_connected=true"

echo ">>> POST /v1/users — create alice"
created=$(curl -sf -H 'X-Actor: ci' -H 'content-type: application/json' \
  -d '{"handle":"alice","global_flags":"+a"}' "$ADMIN/v1/users")
echo "    $created"
echo "$created" | grep -q '"handle":"alice"' || { echo "FAIL: created JSON missing handle"; exit 1; }

echo ">>> GET /v1/users/alice"
fetched=$(curl -sf "$ADMIN/v1/users/alice")
echo "    $fetched"
echo "$fetched" | grep -q '"global_flags":"+a"' || { echo "FAIL: global_flags lost"; exit 1; }

echo ">>> POST /v1/channels — create #shade-smoke"
chan=$(curl -sf -H 'content-type: application/json' \
  -d '{"name":"#shade-smoke"}' "$ADMIN/v1/channels")
echo "    $chan"
echo "$chan" | grep -q '"name":"#shade-smoke"' || { echo "FAIL: channel create"; exit 1; }

echo ">>> POST /v1/channels/%23shade-smoke/masks — add ban"
mask=$(curl -sf -H 'content-type: application/json' \
  -d '{"kind":"ban","mask":"*!*@evil.example","reason":"smoke"}' \
  "$ADMIN/v1/channels/%23shade-smoke/masks")
echo "    $mask"
echo "$mask" | grep -q '"reason":"smoke"' || { echo "FAIL: mask create"; exit 1; }

echo ">>> GET /v1/audit?limit=10 — verify audit trail"
audit=$(curl -sf "$ADMIN/v1/audit?limit=10")
echo "    $(echo "$audit" | head -c 300)..."
echo "$audit" | grep -q '"action":"user.upsert"' || { echo "FAIL: audit missing user.upsert"; exit 1; }
echo "$audit" | grep -q '"action":"channel.upsert"' || { echo "FAIL: audit missing channel.upsert"; exit 1; }
echo "$audit" | grep -q '"action":"mask.add"' || { echo "FAIL: audit missing mask.add"; exit 1; }

echo
echo "OK — full /v1 surface healthy."
