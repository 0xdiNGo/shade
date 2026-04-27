# Improvements Over Wraith

Wraith is a 22-year-old C/C++ bot derived from Eggdrop 1.6.12. Some of it aged extraordinarily well. Most of it didn't. This page is the technical accounting — what we kept, what we replaced, and what we threw out — with citations into the [wraith repo](https://github.com/wraith-org/wraith) so you can verify any claim.

This is a critique of design choices, not of maintainers. Wraith was state-of-the-art for 2003. The state of the art moved on; the codebase mostly didn't.

## What we kept (credit where due)

* **Deterministic role-rotation algorithm.** `roleidx % botcount` across a sorted list of eligible bots, run independently on each node — same input, same output, no consensus needed. This is genuinely good. We preserved it semantically. (`src/mod/irc.mod/irc.cc:1818`, role counts at `src/flags.cc:41-56`.)
* **Mode queue with batching.** Two queues (cookie / non-cookie), 6 modes per outbound `MODE` line, neg-then-pos ordering, priority levels. Solid. We're porting the semantics, not the code. (`src/mod/irc.mod/mode.cc`.)
* **The bot/mesh-of-bots logical shape.** Multiple bots, distributed channel-protection roles, gossip-style state sync. The shape is right; the implementation has not aged. We collapsed the hub/leaf binary distinction (one binary, role from config) but kept the functional split.
* **Per-channel chanset toggles.** The vocabulary (`enforcebans`, `dynamicbans`, `bitch`, `protect`, `cycle`, `secret`, `voice`, `autoop`, …) maps onto problems we still need to solve. We're rebuilding a curated subset (12 of ~25 toggles for MVP).

That's the credit list. The rest of this page is the bill of indictment.

---

## Security theater

### 1. Encrypted config baked into the ELF binary

Wraith's packaging step (`build.sh` invokes `wraith -q pack.cfg`) writes encrypted config blobs into ELF sections via libelf. Each binary becomes "the secret bearer." The marketing: "compromise a leaf, find nothing on disk." The reality:

* The decryption key is also in the binary.
* `strings(1)` plus entropy analysis surface high-entropy regions immediately.
* Each binary is unique by config-hash, which means **you cannot do reproducible builds**, you cannot sign artifacts in any meaningful way, you cannot do supply-chain hardening.
* The "no files on disk" property defeats curious sysadmins, not adversaries with binary-analysis skills, RAM forensics, or `gcore`.

This is obfuscation, not encryption-at-rest. Sealed config files plus a real KMS or HSM provide actual security. Shade ships a sealed sidecar config file, signed images from a registry, and reproducible builds.

References: `src/binary.cc`, `lib/libelf/`, `build.sh`.

### 2. Custom AES + base64 botnet wire protocol

Bot-to-bot traffic is hand-rolled framing: AES-256 in some symmetric mode + base64 wrapper. Twenty-three years on, the project still has its own `crypt.cc`, `enclink.cc`, and ad-hoc framing in `share.cc`.

* **No authenticated encryption.** AES-CBC with integrity-by-ciphertext-shape patterns are the textbook profile for padding-oracle and mauling attacks. Even if the implementation is careful, the design admits classes of bug that authenticated modes structurally exclude.
* **No formal protocol.** The dispatch table at `src/botcmd.cc:1206-1242` is two-letter verbs (`uy`, `un`, `va`, `vab`, `pi`, `po`, `rc`, `rr`, `ts`, `u`, `z`, …). Eggdrop heritage. Brittle (typos break things), opaque (nothing self-describing), undocumented (you read the source).
* **TLS exists.** It existed in 2003. It was widely deployed by 2010. Rolling AES yourself in 2026 is a choice, and the choice is wrong.

Shade replaces this with mTLS streams carrying length-prefixed MessagePack frames. Two crates (`rustls`, `rmp-serde`) instead of three thousand lines of bespoke crypto.

References: `src/crypt.cc`, `src/enclink.cc`, `src/mod/share.mod/share.cc`, `src/botcmd.cc:1206-1242`.

### 3. SaltedSHA1 password hashing

`USERENTRY_PASS` (PASS2 tag) format: `+<salt><sha1_hex>` with a 5-byte salt. (`src/crypt.h:19-20`, `src/userrec.cc:407-434`.)

* **SHA1 is broken.** SHAttered demonstrated practical collisions in 2017. For password verification you primarily want preimage resistance, but the broader reality is: SHA1 is end-of-life and any project that still uses it is signaling either negligence or inertia.
* **SHA1 is fast.** A modern GPU does ~10 billion SHA1/s. A stolen userfile is a few hours' work for any 8-character password. The salt makes rainbow tables harder; it does nothing against per-target brute-force.
* **5-byte salt is small.** 38 bits of entropy. For high-value targets it's pre-computable; for everyone it's smaller than the modern recommendation by a factor of two.

Shade hashes passwords with **Argon2id** (`t=3, m=64MiB, p=1`). Memory-hard; GPU-hostile; still under five seconds of latency for the operator login flow.

References: `src/userent.cc:57` (`USERENTRY_PASS`), `src/userent.cc:643-654` (writeuserfile), `src/crypt.h`.

### 4. MD5 cookie + per-bot counter for op replay prevention

When Wraith ops a user, it includes a cookie in the synthetic ban-mask: `MODE #foo +o-b alice <hash>!<salt>@<encrypted-cookie>`. The cookie is MD5(salt + time-suffix + counter), encrypted with another MD5-derived key. The verifier checks the hash and rejects counters seen before.

Pick your problem:

* **MD5 is obsolete.** Collision-broken since 2008. For the fields the protocol actually uses (HMAC-style integrity over short payloads) MD5 is *technically* still hard to invert, but using it in 2026 is signaling.
* **The "counter" is per-bot local state.** Netsplits cause counter divergence. The wrong half rejects valid cookies. Operators learn to ignore the bad-cookie alarms — exactly the wrong adaptation.
* **The cookie format co-mingles authentication, replay protection, and integrity in one ad-hoc encoding.** Three jobs, one badly-typed string, no schema.
* **The format itself is a mode/ban-mask.** Whatever your IRC server does to ban-masks (length truncation, character normalization, mode-stacking) can break the cookie.

Shade signs an HMAC-SHA256 over a typed MessagePack payload `{ requester_node, target_nick, request_id (ULID), ts_ms }`, with a per-channel key derived via HKDF from a shared mesh PSK, validity ± 60 seconds, request-ID dedupe over a 5-minute ring buffer. Materially stronger; meaningfully simpler. See [Architecture § Cookie ops](Architecture.md#cookie-ops-replay-protection-between-bots).

References: `src/mod/irc.mod/irc.cc:488-552` (`makecookie`), `src/mod/irc.mod/irc.cc:559-638` (`checkcookie`), counter state at `irc.cc:496-501`.

### 5. "Leaf bots have no local config" as a privacy claim

The README sells this hard: compromise a leaf, find no botlist, no userfile, no link addresses. The reality:

* The leaf binary contains the hub address. It has to — the leaf has to call home.
* The binary's config blobs are encrypted with a key also in the binary (see #1).
* Forensic recovery from RAM is one Volatility plugin away.
* The "encryption" is a watermark to deter casual disk forensics by curious admins. Against any actual adversary it's noise.

Shade's privacy story is honest: the config file is sealed, secrets are in env vars sourced from Ansible Vault, and we don't pretend the binary itself is a secret-bearer. The threat model is documented; the mechanisms match it.

References: `README.md`, `FEATURES.md`, `src/binary.cc`.

### 6. update.mod: the hub pushes binaries to leaves

`src/mod/update.mod/update.cc` lets a hub build a binary, push it over the encrypted botnet link, and have leaves accept and re-exec. This is not a feature; it's a single point of total compromise:

* No artifact signing.
* No provenance trail.
* No second-source verification.
* Compromise the hub once → backdoor every leaf.
* Even by 2003 standards this was sketchy; in 2026 it's malpractice.

Shade does not push binaries between nodes. Period. Updates ship as signed OCI images from a registry, deployed via Ansible (or k8s, or Argo, or whatever immutable-infra story you prefer). The bot has no opinion about its own update mechanism — that's the platform's job.

References: `src/mod/update.mod/update.cc`, `src/binary.cc`, `src/mod/share.mod/share.cc` (for the pre-existing channel that update.mod rides on).

---

## Stale crypto and protocol

### IRC: no TLS by default, no IRCv3, no SASL

Wraith's `server.mod/server.cc` knows about port 6697 and SSL exists in the codebase, but TLS is not the default — many configs run plaintext. There is no IRCv3 capability negotiation anywhere in `server.mod`; there is no SASL implementation. Identity on IRC is hostmask-based, which is trivially spoofable on any services-aware network.

Shade is TLS-only by default. We negotiate `sasl`, `server-time`, `multi-prefix`, `extended-join`, `account-tag`, `chghost`, `away-notify`, `cap-notify`, `message-tags`, with PLAIN and EXTERNAL SASL mechanisms. Identity comes from services (account-tag) when available, with hostmask matching as a passive last-seen signal only — never as an authorization decision.

References: `src/mod/server.mod/server.cc`, `src/mod/server.mod/servmsg.cc`, absence of `CAP` handling anywhere.

### TCL stubs

`configure` still probes for Tcl headers. The runtime does not use Tcl. The stubs are vestigial — code nobody understands but nobody dares delete. Wraith dropped Tcl support but never cleaned up the build system around it.

References: `configure` (Tcl header probe), absence of any `Tcl_*` calls in `src/`.

---

## Build and operations

### Autoconf, 320KB configure script

`./configure` is autoconf-generated and 320KB. Modifying the build is a multi-hour exercise in `configure.ac` magic. CMake or Cargo eliminate this entirely. (Shade is Cargo + a handful of `xtask` scripts.)

References: top-level `configure`, `build/autotools/`.

### bdlib and the "no STL" rule

Wraith hand-rolls `bd::String`, `bd::HashTable`, `bd::Array`, `bd::Stream`, `bd::AtomicFile` because `CONTRIBUTING.md` forbids STL. The 2003 justifications — binary size, predictable allocator behavior, audit-friendliness — were defensible in their era. In 2026 they're cargo-culted: STL is well-tested, well-fuzzed, well-understood; bdlib is none of those things. It's a maintenance burden whose original rationale evaporated.

Shade uses the standard library plus a handful of well-known crates. We do not maintain our own collection types.

References: `lib/bdlib/`, `CONTRIBUTING.md` (the no-STL rule).

### Travis CI

`.travis.yml` exists; Travis OSS is essentially dead. Shade uses GitHub Actions with rustfmt, clippy (`-D warnings`), build, test, and a Docker build-and-smoke job, all green on every PR.

References: `.travis.yml`.

### No structured logs

Wraith's `putlog()` writes greppable text. There is no JSON output, no trace correlation, no structured fields. Operators grep with `awk` for postmortems.

Shade emits ndjson via `tracing` to stdout; systemd/journald and container collectors ingest it directly. Every span carries node_id, request_id, channel, etc. as fields.

### No metrics

There is no `/metrics`, no SLI, no rate-limiter for outbound mode-stacks beyond the hand-tuned `floodless` toggle in `src/mod/irc.mod/chan.cc:1462`. Wraith was designed before SRE was a job category.

Shade installs a Prometheus recorder process-wide, exposes `/metrics` for scraping, and counters for cookie-validations, mesh-handshake-failures, mode-queue-flushes, etc. land as features ship.

### No fuzzing

60K LOC of C++ parsing IRC server output. Network-facing, attacker-controlled input. Zero fuzz harnesses anywhere in the repo. This is precisely the textbook profile that should be on OSS-Fuzz.

Shade's IRC line parser and mesh frame decoder are fuzzed via `cargo-fuzz` (libFuzzer) on every CI run for at least 5 minutes per target. Promotion to OSS-Fuzz is on the post-MVP list.

### EFnet/Ratbox optimization

Documentation specifically targets EFnet and IRCD-Ratbox. EFnet is a network most of the IRC world has forgotten. Ratbox has been unmaintained since around 2018. Shade targets IRCv3-compliant networks (Libera, OFTC, Snoonet, Ergo, Solanum) by default; EFnet support is an afterthought, if anyone wants it.

References: `README.md`, `FEATURES.md`.

---

## Operational gaps: DCC chat and the telnet listener

Wraith has two admin paths:

1. **DCC chat.** User connects via DCC, types password, lands on a "party line."
2. **Telnet listener.** Bot opens a TCP port; user connects with `telnet` and authenticates.

Both are 1990s admin paradigms — the bot is now an SSH-but-worse server, with a custom auth flow (AUTHSTART/AUTH MD5 challenge), no rate-limiting beyond an ignore-list, and no audit log beyond `putlog(LOG_CMDS, …)`.

References: `src/dcc.cc`, `src/chanprog.cc:555-561` (telnet listener init), `src/mod/irc.mod/msgcmds.cc:305-408` (AUTH challenge), `src/auth.cc`.

Shade replaces both with HTTP+JSON over mTLS, plus a token-based in-channel `/MSG shade TOKEN op #foo nick` for ops who live on IRC and don't want to context-switch to a terminal. Tokens are short-lived (≤ 15 min), single-use, hashed-stored, and minted via the API. Every action is audit-logged. There is no telnet listener and no "party line."

---

## Net of changes

We dropped:

* DCC chat / DCC file transfer / telnet listener / party line
* `update.mod` (hub-to-leaf binary push)
* `pack.cfg`-driven ELF config embedding
* Custom AES+base64 botnet protocol
* SaltedSHA1 password hashing
* MD5+counter cookie scheme
* TCL stubs
* Autoconf
* `bdlib`
* Travis CI
* Bot-only flag bits (`B/c/f/u/r/l/y`)
* `RESOLV` role (DNS stub)
* The 111-DCC-command surface (replaced by ~25 HTTP endpoints)

We replaced:

* Custom wire crypto → mTLS (rustls + rmp-serde)
* SaltedSHA1 → Argon2id
* MD5+counter cookies → HMAC-SHA256 over typed payloads
* Hostmask-as-auth → mTLS client cert + IRC SASL identity
* `putlog()` text → `tracing` ndjson
* No metrics → Prometheus
* No fuzz → cargo-fuzz on CI
* Autoconf → Cargo
* Travis → GitHub Actions
* Eggdrop two-letter verbs → length-prefixed MessagePack with serde-tagged enums

We kept (semantically, rebuilt cleanly):

* Deterministic role rotation
* Mode queue with batching
* Distributed bot-mesh model
* The chanset vocabulary

That's the bill. It's not nostalgia, it's accounting.
