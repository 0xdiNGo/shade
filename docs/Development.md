# Development

## Local setup

You need a working Rust toolchain (stable). Easiest on macOS:

```sh
brew install rustup
rustup default stable
```

Plus Docker or Podman for container builds. The repo uses [`rust-toolchain.toml`](../rust-toolchain.toml) to pin the channel; rustup picks it up automatically.

## Build, test, lint

```sh
cd ~/code/irc/shade

cargo fmt --all                         # auto-format
cargo fmt --all --check                 # CI fmt check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo build --workspace --all-targets   # debug
cargo build --release --bin shade       # release musl static (in CI)
```

All four checks run on every PR. CI green is required before merge.

## Running the daemon locally

```sh
cargo run --bin shade -- --config deploy/shade.example.toml run
# In another terminal:
curl http://127.0.0.1:8443/healthz
curl http://127.0.0.1:8443/readyz
curl http://127.0.0.1:9090/metrics
```

Send `SIGTERM` (or Ctrl-C) to shut down cleanly. Logs go to stdout; default is JSON, set `format = "text"` in `[logging]` for human-readable dev output.

## CLI subcommands

```
shade run            Start the Shade daemon
shade init-ca        Generate a new botnet certificate authority
shade issue-cert     Issue a node certificate signed by the botnet CA
shade migrate        Run pending database migrations against the configured data directory
shade check-config   Parse the config file and print the normalized result as JSON
shade dump-state     Dump the current SQLite state as JSON
```

`run`, `init-ca`, `issue-cert`, `dump-state` are stubbed in M1 and fill in over M2–M6. `migrate` and `check-config` work today.

## Container builds

```sh
# From the repo root
docker build -f deploy/Dockerfile -t shade:dev .

# Or run the dev compose
cd deploy
docker compose up --build
```

The Dockerfile is two-stage: builder (`rust:alpine`, target `x86_64-unknown-linux-musl`) → runtime (`gcr.io/distroless/static-debian12:nonroot`). The output binary is fully static; the runtime image has no shell and no package manager.

## CI pipeline

Defined in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml). Four jobs:

1. **rustfmt** — `cargo fmt --all --check`
2. **clippy** — `cargo clippy --workspace --all-targets -- -D warnings`
3. **build + test** — `cargo build && cargo test`, with `Swatinem/rust-cache` warmed
4. **docker build + smoke** — builds the image via buildx (GHA cache), then runs `shade --version` and `shade --help` inside it. Runs only after the first three pass.

Concurrency group cancels stale runs on force-push.

## PR conventions

* Conventional Commits: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`.
* Each PR is squash-merged on green CI.
* Author identity is locked to the `0xdiNGo` persona via per-repo `git config`. Don't override with global identity. (See [`CLAUDE.md`](../CLAUDE.md) for the full rule.)
* Milestone-level review: PRs are small and merged continuously; review happens at milestone boundaries.
* Changes that affect architecture, threat model, or the operator-facing surface should update the relevant `docs/` page in the same PR.

## Wraith reference source

The Wraith C/C++ codebase is the spec source. It lives locally at `/Users/jpreston/code/irc/wraith` (not committed; original [github.com/wraith-org/wraith](https://github.com/wraith-org/wraith)). Read it as a spec; never port code from it. Specific files we lean on most are listed inline in [Improvements Over Wraith](Improvements-Over-Wraith.md).

## Updating these docs

The docs in `docs/` are part of the main repo. Update them in the same PR that introduces the architectural change they describe.

```sh
cd ~/code/irc/shade
git checkout -b docs/some-update
$EDITOR docs/Architecture.md
git add docs/Architecture.md
git commit -m "docs: ..."
git push -u origin docs/some-update
gh pr create
```

Same persona-identity rule, same CI gates, same review cadence as code changes.

The docs are updated at every milestone boundary and whenever an architectural decision changes. Specifically: when M2/M3/M4/M5/M6 close, [Roadmap.md](Roadmap.md) flips that milestone to ✅ done and [Architecture.md](Architecture.md) gets the relevant additions.
