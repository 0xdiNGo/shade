# CLAUDE.md

Project context for Claude Code sessions in this repository.

## Project: Shade

Modern IRC bot and channel-management mesh, written in Rust. Clean-slate rewrite with the Wraith C/C++ bot's feature surface used as a spec source (no porting). Container-forward deployment via Ansible. mTLS mesh between nodes. SQLite per-node with last-write-wins gossip sync. axum HTTP+JSON admin API behind mTLS. Tracing JSON logs, Prometheus metrics, distroless OCI image as the primary artifact.

The Wraith reference source lives locally at `/Users/jpreston/code/irc/wraith`. Read it as a spec; do not port code.

## Identity rule (do not violate)

This project is published under the **0xdiNGo** GitHub persona. **Never** put the user's real name or any non-persona identifier into:

- git commits (author lines or `Co-Authored-By` trailers)
- `Cargo.toml` `authors` or any package metadata
- README / LICENSE / CONTRIBUTING attribution
- code comments, docstrings, or string literals
- container labels (e.g., `org.opencontainers.image.authors`)
- CI configuration

Default git author for this repo is set locally to `0xdiNGo <1714530+0xdiNGo@users.noreply.github.com>` via per-repo `git config`. Do not override with global settings, and do not infer a different identity from any other source. When in doubt, ask the user before committing.

## Architecture summary

- **Workspace crates**: `shade-proto` (mesh wire types), `shade-core` (domain types), `shade-ircd` (IRC client), `shade-mesh` (mTLS gossip), `shade-api` (axum admin API), `shade-store` (SQLite + refinery migrations), `shade-bin` (binary, also exports the `shadectl` CLI).
- **Mesh wire format**: length-prefixed MessagePack frames over mTLS streams. Length is `u32` big-endian.
- **Sync model**: snapshot-on-connect + delta gossip + last-write-wins on `(updated_at, origin_node)`. Hostmask sets use add/remove tombstones.
- **Role distribution**: deterministic `roleidx % botcount` rotation, run independently on each node. Same algorithm as Wraith's `rebalance_roles_chan` — see `src/flags.cc:41-56` (role counts) and `src/mod/irc.mod/irc.cc:1818` (rotation) in the wraith repo.
- **Cookie ops**: HMAC-SHA256 with HKDF-derived per-channel keys from a mesh PSK. Replaces Wraith's MD5+counter scheme.

## Conventions

- All work via PRs. Squash-merge with `--delete-branch` after CI green; auto-merge (`gh pr merge --auto`) is enabled on the repo and `master` is branch-protected to require `rustfmt`, `clippy`, `build + test`, and `docker build + smoke` before merge. (`fuzz parser` is run on every PR but not yet a required check.)
- `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` must pass before merge.
- Conventional Commits style: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`.
- No real-name attribution anywhere (see Identity rule above).
- Architectural changes update the relevant `docs/` page in the same PR.

## Documentation

Project docs live in `docs/` (markdown, browsable on GitHub):

- `docs/README.md` — landing
- `docs/Architecture.md` — design
- `docs/Improvements-Over-Wraith.md` — punchy, cited critique of Wraith design choices and security theater
- `docs/Roadmap.md` — milestones and status
- `docs/Operations.md` — deployment / monitoring + Ansible playbooks + cert/PSK rotation runbooks
- `docs/Threat-Model.md` — adversaries, defended properties, known gaps tracked in Roadmap
- `docs/Development.md` — toolchain, CI, PR conventions

Update the relevant page in the same PR that introduces the architectural change. At every milestone boundary, flip that milestone to ✅ in `docs/Roadmap.md` and add the relevant section(s) to `docs/Architecture.md`. The Wraith critique should stay punchy but defensible — every claim about Wraith should reference a file (and ideally a line range) in the wraith repo at `/Users/jpreston/code/irc/wraith`.

## Current state (snapshot — keep this current at milestone boundaries)

**M1 ✅** scaffold, CI, daemon, store, container.

**M2 ✅** — IRC client. Parser + fuzz harness, TLS connection runner with token-bucket rate limiter and exponential backoff, IRCv3 cap negotiation, SASL PLAIN/EXTERNAL, channel state machine, outbound MODE batcher, and the `shade-ircd::session` async loop tying it all together. `docker compose up --build` runs ergo + shade end-to-end; `/readyz`'s `irc_connected` flips on RPL_WELCOME; `!ping → pong` works.

**M3 ✅** — Domain + HTTP API + shadectl + auto-op/auto-kick. `shade-core` domain types (FlagSet/User/Channel/Mask/Role/AuditEntry). `shade-store` CRUD accessors with `match_by_host` for passive identification. `shade-api::v1` admin routes for users / channels / masks / audit, mTLS-pending. `shadectl` CLI talking to the admin API via ureq. Daemon's `apply_join_policy` kicks peers matching channel ban masks and auto-ops users with `+o` in their per-channel flag set.

**M4 ✅** — mTLS mesh + last-write-wins gossip. `shade-proto` mesh wire types (`Frame`, `PeerHello`, snapshot + upsert + delete envelopes). `shade-mesh` async length-prefixed frame codec, rustls-based listener + dialer, `PeerHello` handshake binding cert SAN to `node_id`, per-peer connection loop, `MeshHub` orchestrating accepts + dialers + broadcast fan-out. `shade-store::gossip` applies inbound `Upsert` / `Delete` under LWW, with mask delete tombstones (V0002 migration) so deletes survive reorderings. `shade init-ca` / `shade issue-cert` ship Ed25519 self-signed CA + node certs. Daemon spawns the hub when TLS material is on disk; `/readyz`'s `peers_up` mirrors the live atom.

**M5 ✅** — Role distribution + cookie ops + mass-op detection. `shade-core::compute_assignment` runs the deterministic `roleidx % botcount` rotation across `[self] + connected_peers`. `shade-core::cookies` mints HMAC-SHA256 tags over typed payloads keyed via HKDF-SHA256 from the mesh PSK. Daemon's `apply_join_policy` only opts when self holds `ROLE_OP` for the channel and emits `NOTICE shade-cookie/<wire>` so peers can verify authorization. `OpObserver` in `shade-bin` tracks observed ops + cookie NOTICEs to flag uncertified ops and detect mass-op floods (sliding 10s window, threshold 5 ops/source). `shade-ircd::SessionEvent` gains a `ModeChanged` variant so the daemon sees every observed mode.

**M6 ✅** — Ansible role at `ansible/roles/shade/` (container-mode via Podman/Docker + systemd notify-type unit), bootstrap-CA + issue-cert + deploy playbooks, vault-sourced secrets through systemd `EnvironmentFile=`. New `compose smoke (ergo + shade)` CI job runs `deploy/smoke.sh` end-to-end on every PR — boots ergo + shade via docker compose, asserts `/readyz` flips `irc_connected: true`, drives the full `/v1` surface (users / channels / masks / audit), tears down. Operator runbook in `docs/Operations.md` covers cert rotation, partition recovery, and node drain. Threat model seeded in `docs/Threat-Model.md`.

**M7 in progress (production-readiness pass).** Closes the gap between "v0.1 MVP per the Roadmap" and "internet-facing-with-adversaries safe."

- **Native admin-listener mTLS ✅** — `shade-bin::admin_tls` runs a tokio-rustls accept loop with `WebPkiClientVerifier` rooted at `admin.client_ca`. Per-connection: extract the verified peer cert subject CN, inject `shade_api::auth::VerifiedActor` into request extensions, serve via `hyper-util`. Routes pull identity through the `ActorClaim` extractor (extension wins; `X-Actor` is the dev-only fallback). New `shade issue-admin-cert --handle <h>` command issues operator certs (CN=handle, EKU=clientAuth, no SAN). `shadectl` learns `--cert/--key/--ca-bundle` flags so it can present its cert to a TLS-enforced daemon. Workspace-pinned rustls 0.23 to the `ring` provider; main installs it once at startup. Tests cover happy path + no-cert reject + wrong-CA reject.
- **Mass-op response that acts ✅** — `OpObserver::record_op` returns a typed `MassOpAction::Deop` when ≥ 5 uncertified ops in 10 s trip the per-`(channel, source)` threshold. Daemon's `apply_mass_op_response` walks the victim list, sends one `MODE -o` per nick, writes a single `mass_op.deop` audit row, and gates on `ROLE_OP` so only the deterministic role holder issues the deop. 60-second per-pair cooldown prevents op-deop flapping. Cookie-certified ops are removed from the counter so legitimate role-holder activity never trips the alarm.
- **Argon2id login + bearer tokens + in-channel TOKEN ✅** — `shade_core::password` (Argon2id m=64MiB t=3) and `shade_core::AuthToken` (32-byte random, SHA-256 at rest, base64url wire). New `auth_tokens` table (V0003 migration), local-only by design. `POST /v1/login {handle, password}` mints a token and returns `{token, expires_at}`. `shade_api::auth::bearer_auth_middleware` resolves `Authorization: Bearer <wire>` to a `VerifiedActor` via SHA-256 lookup. `PUT/DELETE /v1/users/:handle/password` set or clear the Argon2id hash. Daemon's PRIVMSG handler exposes the same flow over IRC: `TOKEN <handle> <password>` privately to the bot returns `token <wire> expires <ts>` to the sender; documented as plaintext-over-IRC and audited via `auth.token.issue`. `shadectl` learns `--token` (and `SHADECTL_TOKEN`) plus a new `shade login --handle <h>` subcommand that prompts for password and prints `{token, expires_at}` to stdout for `jq`-pipelining.
- **Graceful shutdown ✅** — `shade-bin::shutdown::Shutdown` broadcasts on Ctrl-C / SIGTERM via `tokio::sync::watch`. The metrics listener uses `axum::serve(...).with_graceful_shutdown(...)`; the admin TLS listener selects on `accept` vs. shutdown and drains its `JoinSet` of in-flight connections; `drive_session` selects on `next_event` vs. shutdown, sending `QUIT :shade shutting down` and a 250 ms flush window before exiting. `run()` wraps the drain in a 10-second `tokio::time::timeout`; tasks still alive after the deadline are aborted via runtime teardown. No more `abort()` mid-Argon2id-verify or mid-MODE-batch.
- **Per-IP login rate limit ✅** — `tower_governor` (v0.4.3, axum 0.7-compatible) wraps only the `POST /v1/login` route with a `SmartIpKeyExtractor` token-bucket: burst=10, refill 1 per 6 s (≈10 attempts/min sustained). Overflow returns 429 with `x-ratelimit-after`. Every other route is unaffected. Closes the "per-handle login rate limit" gap in `docs/Threat-Model.md`.

- **Signed releases + SBOM ✅** — `.github/workflows/release.yml` builds and pushes `ghcr.io/0xdingo/shade:<tag>` + `:latest` on every `v*` tag push, signs the image with cosign keyless (GitHub OIDC, no managed keys), generates a CycloneDX JSON SBOM via syft (`anchore/sbom-action`), and attaches it as an in-toto attestation via `cosign attest`. Operator verify runbook in `docs/Operations.md` § Verifying a signed release.

**v0.2 backlog** — see `docs/Roadmap.md` § Out of MVP scope: the rest of the in-channel admin flow (`op #foo nick` etc. command handlers; `TOKEN` issuance has shipped), CRL/OCSP for admin and node certs, the remaining chanset toggles + flood thresholds, multi-network IRC.
