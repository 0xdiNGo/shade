# Shade documentation

Modern IRC bot and channel-management mesh, written in Rust.

Shade is a clean-slate successor to [Wraith](https://github.com/wraith-org/wraith), an Eggdrop-derived C/C++ bot that pioneered encrypted-botnet IRC management twenty-some years ago. We did not port Wraith. We used its feature surface as a spec, threw out everything that aged badly, and rebuilt the bot for container-forward deployment, declarative configuration, and modern observability.

## Status

**Pre-alpha.** M1 (workspace, CI, daemon, store, container image) is done. M2 (IRC client) is next. Not for production. Not interoperable with Wraith botnets — and not trying to be.

## Where to start

| Page | What's there |
|---|---|
| [Architecture](Architecture.md) | The Shade design: workspace layout, mesh, store, role distribution, cookie ops, auth model. |
| [Improvements Over Wraith](Improvements-Over-Wraith.md) | Punchy, cited critique of Wraith's design choices and what we replaced them with. |
| [Roadmap](Roadmap.md) | Milestones, status, what each one demos. |
| [Operations](Operations.md) | Deployment, monitoring, cert bootstrap. (Stub — fills in as M6 lands.) |
| [Development](Development.md) | Local setup, CI pipeline, PR conventions. |

## Repo

[github.com/0xdiNGo/shade](https://github.com/0xdiNGo/shade) · MIT License · maintained as the [`0xdiNGo`](https://github.com/0xdiNGo) persona.
