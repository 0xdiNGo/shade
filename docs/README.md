# Shade documentation

Modern IRC bot and channel-management mesh, written in Rust.

Shade is a clean-slate successor to [Wraith](https://github.com/wraith-org/wraith), an Eggdrop-derived C/C++ bot that pioneered encrypted-botnet IRC management twenty-some years ago. We did not port Wraith. We used its feature surface as a spec, threw out everything that aged badly, and rebuilt the bot for container-forward deployment, declarative configuration, and modern observability.

## Status

**v0.1.** All six MVP milestones are done — workspace + CI + daemon, IRC client, admin API + shadectl, mTLS mesh + LWW gossip, role distribution + cookie ops, Ansible role + ergo end-to-end CI smoke + operator runbook. The known v0.2 items (in-channel `/MSG TOKEN` flow, Argon2id login, native admin-listener mTLS, the remaining chanset toggles) are tracked in [docs/Roadmap.md § Out of MVP scope](Roadmap.md#out-of-mvp-scope-v02). Not interoperable with Wraith botnets — and not trying to be.

## Where to start

| Page | What's there |
|---|---|
| [Architecture](Architecture.md) | The Shade design: workspace layout, mesh, store, role distribution, cookie ops, auth model. |
| [Improvements Over Wraith](Improvements-Over-Wraith.md) | Punchy, cited critique of Wraith's design choices and what we replaced them with. |
| [Roadmap](Roadmap.md) | Milestones, status, what each one demos. |
| [Operations](Operations.md) | Deployment, monitoring, cert bootstrap, Ansible playbooks, runbooks for partition recovery and PSK rotation. |
| [Development](Development.md) | Local setup, CI pipeline, PR conventions. |
| [Threat Model](Threat-Model.md) | What Shade defends against, what it doesn't, and what the open security work is. |

## Repo

[github.com/0xdiNGo/shade](https://github.com/0xdiNGo/shade) · MIT License · maintained as the [`0xdiNGo`](https://github.com/0xdiNGo) persona.
