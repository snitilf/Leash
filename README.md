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

## Build

Requires a Rust toolchain and Linux 5.19 or later on x86-64 to run.

```
cargo build --release
```

The binary is `target/release/leash`. Usage:

```
leash run [--policy <path>] -- <command...>
```

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
