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

- All work via PRs. Self-merge after CI green is acceptable on master during early milestones (M1–M3).
- `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` must pass before merge.
- Conventional Commits style: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`.
- No real-name attribution anywhere (see Identity rule above).

## Documentation

Project docs live in `docs/` (markdown, browsable on GitHub):

- `docs/README.md` — landing
- `docs/Architecture.md` — design
- `docs/Improvements-Over-Wraith.md` — punchy, cited critique of Wraith design choices and security theater
- `docs/Roadmap.md` — milestones and status
- `docs/Operations.md` — deployment / monitoring (stub until M6)
- `docs/Development.md` — toolchain, CI, PR conventions

Update the relevant page in the same PR that introduces the architectural change. At every milestone boundary, flip that milestone to ✅ in `docs/Roadmap.md` and add the relevant section(s) to `docs/Architecture.md`. The Wraith critique should stay punchy but defensible — every claim about Wraith should reference a file (and ideally a line range) in the wraith repo at `/Users/jpreston/code/irc/wraith`.
