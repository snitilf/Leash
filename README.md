# Leash

[![CI](https://github.com/snitilf/Leash/actions/workflows/ci.yml/badge.svg)](https://github.com/snitilf/Leash/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

A command-line tool, written in Rust for Linux, that wraps an AI coding agent and mediates
everything it does at the operating-system boundary.

AI coding agents run with your full user permissions: they can read any file, run any program,
and reach any host, and the only record of what they did is their own summary. Leash sits between
the agent and the machine. Using seccomp user-notification and Landlock, the kernel pauses every
file open, process spawn, and network connection in the agent's process tree and asks Leash first.
Leash inspects the arguments and answers allow or deny; Landlock is a kernel-enforced backstop
underneath. Measured cost: about 31 to 34 microseconds added per trapped file syscall at p50, on a
2 vCPU Ubuntu 24.04 VM ([measurement 0001](docs/measurements/0001-m1-overhead.md)).

![Leash denying a read of ~/.ssh and holding a .env write for approval](docs/assets/demo.gif)

The design has three capabilities:

- **Record.** A complete, append-only trace of what the agent actually did: ground truth, not
  the agent's self-report.
- **Enforce.** A declarative policy over paths, hosts, and binaries. Actions are allowed, denied,
  or held for human approval; any supervisor error resolves to deny.
- **Rewind (planned, M3).** Workspace snapshots at step boundaries, so a run can be rewound, or
  two runs diffed by their actual effects. Not implemented yet.

Because Leash works at the syscall layer, it is agent-agnostic and vendor-agnostic: no SDK
integration, nothing the supervised process can reason around.

## Status

- Record: implemented and tested.
- Enforce: implemented and tested.
- Rewind: planned for milestone M3. The `rewind` and `diff` subcommands are reserved and print
  "not implemented yet".
- Platform: Linux 5.19 or later on x86-64 only. CI runs on Ubuntu 24.04.

## Quickstart

Requires a Rust toolchain to build, and Linux 5.19 or later on x86-64 to run. The repo ships a
dev container (`.devcontainer/`) with the capabilities seccomp and Landlock need.

```
cargo build --release
export PATH="$PWD/target/release:$PATH"
leash --help
```

Without a policy, a run is record-only: everything is allowed and written to the trace.

```
$ leash run -- sh -c 'cat /etc/hostname'
leash: record-only run; no policy is enforced, and only un-mediated I/O paths (SR-4), foreign-ABI entries (SR-3), and undecodable facts are denied
codespaces-77710d
leash: run 20261123T234345Z-rdzo2f recorded; report: /home/vscode/.local/state/leash/runs/20261123T234345Z-rdzo2f/report.txt
```

With [`examples/policy.toml`](examples/policy.toml), reads under `~/.ssh` are denied and writing
`.env` in the workspace needs a yes from the terminal:

```
$ leash run --policy examples/policy.toml -- sh -c 'cat ~/.ssh/id_demo'
leash: enforce run
cat: /home/vscode/.ssh/id_demo: Permission denied

$ leash run --policy examples/policy.toml -- sh -c 'echo API_KEY=demo > .env; cat .env'
leash: enforce run
leash: the agent asks for:
  write /tmp/ws/.env (rule fs.3)
  create /tmp/ws/.env (rule fs.3)
allow? [y/N] (denies in 60s): y
API_KEY=demo
```

Each run directory holds `meta.json`, the append-only `trace.jsonl`, and a `report.txt`. The two
decisions above, as recorded in the trace:

```
{"seq":36,"ts":1795477425883,"type":"syscall","pid":4692,"syscall":"openat","fact":{"family":"fs","path":"/home/vscode/.ssh/id_demo","access":["read"]},"decision":"deny","matched_rule":"fs.1"}
{"seq":4,"ts":1795477425911,"type":"syscall","pid":4705,"syscall":"openat","fact":{"family":"fs","path":"/tmp/ws/.env","access":["write","create"]},"decision":"ask","ask_resolution":"approved","matched_rule":"fs.3"}
```

The output above is captured from real runs on Ubuntu 24.04 (kernel 6.8), lightly trimmed. The
policy format is specified in [docs/design/policy.md](docs/design/policy.md).

## Known limitations

On kernels without upstream fix `cce436aafc2a`, a signal that wakes a supervised process at the
wrong moment can make a supervisor-realized side effect run twice, and the trace can then contain
a response the process never saw. Userspace cannot close this race, so Leash accepts it as a
narrow residual and keeps the Linux 5.19 floor. See
[ADR-0021](docs/adr/0021-accept-wait-killable-recv-post-send-race.md).

## Documentation

The project is documentation-driven: every decision is recorded before it is implemented.
Start at [docs/README.md](docs/README.md) for the document hierarchy. The specification is
[docs/spec/SPEC.md](docs/spec/SPEC.md), the design (how it is built) is in
[docs/design/](docs/design/), the decision records are in [docs/adr/](docs/adr/), and the
project vocabulary is [docs/CONTEXT.md](docs/CONTEXT.md).

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
