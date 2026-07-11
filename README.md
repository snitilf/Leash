# Leash

A command-line tool, written in Rust for Linux, that wraps an AI coding agent and mediates
everything it does at the operating-system boundary.

AI coding agents run with your full user permissions: they can read any file, run any program,
and reach any host, and the only record of what they did is their own summary. Leash sits between
the agent and the machine. Using seccomp user-notification and Landlock, the kernel pauses every
file open, process spawn, and network connection in the agent's process tree and asks Leash first.
That yields three capabilities in one tool:

- **Record.** A complete, append-only trace of what the agent actually did: ground truth, not
  the agent's self-report.
- **Enforce.** A declarative policy over paths, hosts, and binaries. Actions are allowed, denied,
  or held for human approval; any supervisor error resolves to deny.
- **Rewind.** Workspace snapshots at step boundaries, so a run can be rewound, or two runs
  diffed by their actual effects.

Because Leash works at the syscall layer, it is agent-agnostic and vendor-agnostic: no SDK
integration, nothing the supervised process can reason around.

## Status

Implementation in progress. The specification is settled (v0.6) and the design layer is frozen
(2026-07-08). The M0 overlay spike passed on x86-64 and the M1 recorder milestone is being
built: the crate skeleton, the trace recorder, the preflight host probes, the spawn protocol,
and the record-only notify loop for the filesystem family have landed, with behavioral tests
running in CI on ubuntu-24.04. Requires Linux 5.19 or later on x86-64 (ARM64 is deferred,
ADR-0014).

## Documentation

The project is documentation-driven: every decision is recorded before it is implemented.
Start at [docs/README.md](docs/README.md) for the document hierarchy. The specification is
[docs/spec/SPEC.md](docs/spec/SPEC.md), the design (how it is built) is in
[docs/design/](docs/design/), the decision records are in [docs/adr/](docs/adr/), and the
project vocabulary is [docs/CONTEXT.md](docs/CONTEXT.md).
