<div align="center">

# Leash

### Your coding agent runs as you. Leash decides what it gets to touch.

[![CI](https://github.com/snitilf/Leash/actions/workflows/ci.yml/badge.svg)](https://github.com/snitilf/Leash/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

[How it works](#how-it-works) · [Quick start](#quick-start) · [Docs](#documentation)

</div>

Leash is a Linux command-line tool, written in Rust, that wraps an AI coding agent and supervises it at the syscall layer.

An agent runs with your permissions.
It can read `~/.ssh`, run `curl`, and connect to any host, and the only record of what it did is its own summary.

Leash puts the kernel in the loop.
Every file open, program launch, and network connection in the agent's process tree stops and waits while Leash checks it against your policy.
Leash allows it, denies it, or asks you in the terminal.
Every decision lands in an append-only trace, so you read what the agent did, not what it says it did.

It works with any agent, because it never talks to the agent.
No SDK, no plugin, nothing the agent can argue with.

![Leash denying a read of ~/.ssh and holding a .env write for approval](docs/assets/demo.gif)

## Under the hood

- Interception: a seccomp filter with user notification pauses each mediated syscall and hands it to a single-threaded decision loop (`src/supervisor/run.rs`).
- No path races on allowed opens: in enforce mode, Leash never lets the kernel re-read a path the agent could have swapped.
  A confined broker resolves it with `openat2` beneath a root directory handle and hands back the file descriptor itself (`src/supervisor/broker.rs`, [ADR-0020](docs/adr/0020-confined-realizer-and-socket-duplication.md)).
- Kernel backstop: in enforce mode, Landlock rules derived from the same policy refuse filesystem access that the seccomp layer never saw (`src/sandbox/landlock.rs`, [ADR-0003](docs/adr/0003-defense-in-depth-seccomp-and-landlock.md)).
- Fail closed: a supervisor error, an unreadable argument, a failed trace write, or an unanswered prompt all resolve to deny.
- Policy: TOML rules over paths, binaries, and hosts, first match wins, validated in full before the agent starts (`src/policy/`).
- Trace: JSONL, append-only, and synced before the agent starts.
  The report is rebuilt from the trace alone (`src/recorder.rs`).
- Cost: about 31 to 34 microseconds added per trapped file syscall at p50, on a 2 vCPU Ubuntu 24.04 VM ([measurement 0001](docs/measurements/0001-m1-overhead.md)).
- Tests: 290+, including an escape suite that swaps symlinks mid-decision, opens through `/proc` magic links, and writes outside the Landlock rules.
  CI runs fmt, clippy with warnings as errors, the full suite on Ubuntu 24.04, an MSRV check, and `cargo audit`.

## How it works

1. `leash run -- <agent>` checks the kernel, loads and validates the policy, and creates a run directory before the agent exists.
2. The agent starts under the seccomp filter.
   Every child it spawns inherits the filter, and there is no way to drop it.
3. The kernel pauses each file open, exec, `connect`, `bind`, `sendto`, and cross-process access, and passes it to Leash.
4. Leash reads the arguments out of the agent's memory, resolves the path or address, and matches the policy.
5. Allow, deny, or ask.
   An ask names the exact action and the rule that matched, and denies after 60 seconds by default.
6. The decision is written to `trace.jsonl` before the syscall is answered.
   When the agent exits, Leash writes `report.txt`.

No policy file means record-only mode: everything is allowed and everything is recorded.
A camera, not a bouncer.

## Status

| Part | State |
| --- | --- |
| Record | Working and tested. |
| Enforce | Working and tested. |
| Rewind | Planned for milestone M3: workspace snapshots, rewind to a step, diff two runs. `leash rewind` and `leash diff` print "not implemented yet". |
| Platform | Linux 5.19 or later, x86-64. |

## Quick start

You need a Rust toolchain to build, and Linux 5.19 or later on x86-64 to run.
The dev container in `.devcontainer/` has the capabilities seccomp and Landlock need, so a GitHub codespace works.

```sh
cargo build --release
export PATH="$PWD/target/release:$PATH"
leash --help
```

With [`examples/policy.toml`](examples/policy.toml), reads under `~/.ssh` are denied and writing `.env` needs a yes:

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

The approved write, as one event in `trace.jsonl` (pretty-printed):

```json
{
  "seq": 4,
  "ts": 1795477425911,
  "type": "syscall",
  "pid": 4705,
  "syscall": "openat",
  "fact": {
    "family": "fs",
    "path": "/tmp/ws/.env",
    "access": ["write", "create"]
  },
  "decision": "ask",
  "ask_resolution": "approved",
  "matched_rule": "fs.3"
}
```

All output above is from real runs on Ubuntu 24.04 (kernel 6.8).
Without `--policy`, a run is record-only: no policy is enforced, and everything is still traced.

## Known limitations

Leash names its gaps instead of hiding them.
The main ones:

- On kernels without upstream fix `cce436aafc2a`, a badly timed signal can make an allowed side effect run twice ([ADR-0021](docs/adr/0021-accept-wait-killable-recv-post-send-race.md)).
- Landlock can restrict TCP ports but not hosts, so host rules rest on the seccomp layer alone.
- Enforce mode denies Unix-domain socket connects (dbus, `docker.sock`) until the address parser learns them.

The full list, with what bounds each one, is in [docs/design/escapes.md](docs/design/escapes.md).

## Documentation

The project is documentation-driven: every decision is written down before it is built.

- [Specification](docs/spec/SPEC.md): numbered requirements, the security ones included.
- [Design](docs/design/): architecture, the notify loop, syscalls, policy, trace, and the escape inventory.
- [Decision records](docs/adr/): 21 ADRs, from "why Rust" to which kernel races to accept.
- [Measurements](docs/measurements/): overhead and kernel behavior, with the method behind each number.
- [Glossary](docs/CONTEXT.md): the project's vocabulary, used exactly.

## Working on Leash

| Command | What it does |
| --- | --- |
| `cargo build --release` | Builds `target/release/leash`. |
| `cargo test` | Runs the unit tests everywhere, and the integration and escape tests on Linux. |
| `cargo clippy --all-targets -- -D warnings` | Lints with warnings as errors, as CI does. |
| `cargo fmt --check` | Checks formatting. |
| `cargo +1.96 check` | Checks the minimum supported Rust version. |
| `cargo bench --bench overhead` | Runs the overhead harness on Linux. CI does not run it. |

## License

Leash is dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
