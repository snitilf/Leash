# Architecture Decision Records

An ADR records a decision that is **hard to reverse**, **surprising without context**, and **the result of a real trade-off**. If a decision is not all three, it does not get an ADR — it lives in the spec or the design, or it is simply the obvious thing.

ADRs are **immutable once accepted**. A decision that changes is not edited; a new ADR supersedes it, and the old one is marked `superseded by ADR-NNNN`. This preserves the reasoning trail — the deterministic brain remembers why it once chose differently.

## Format

```md
# ADR-NNNN: {short title of the decision}

- Status: proposed | accepted | superseded by ADR-NNNN
  (an accepted ADR whose core decision stands but a clause is later narrowed may carry a short
  "refined by ADR-NNNN" note on the status line; the body stays immutable)
- Date: YYYY-MM-DD

## Context
{The forces at play. What makes this a real decision.}

## Decision
{What we chose.}

## Consequences
{What follows — the good, the bad, and what it forecloses.}

## Alternatives considered
{The roads not taken, and why — so no one re-proposes them.}
```

Numbering: scan this directory for the highest number, increment by one.

## Index

| ID | Title | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | accepted |
| [0002](0002-supervisor-child-process-separation.md) | Supervisor and child are separate processes; the log lives in the supervisor | accepted |
| [0003](0003-defense-in-depth-seccomp-and-landlock.md) | Enforce with seccomp-unotify *and* Landlock (defense in depth) | accepted (backstop clause refined by ADR-0013) |
| [0004](0004-policy-as-declarative-data.md) | Policy is declarative data, not code | accepted |
| [0005](0005-time-travel-by-snapshot-not-replay.md) | Time travel is filesystem snapshots, never agent replay | accepted |
| [0006](0006-mediate-at-os-boundary-not-sdk.md) | Mediate at the OS boundary, never via an agent SDK | accepted |
| [0007](0007-implementation-language-rust.md) | Implement in Rust | accepted |
| [0008](0008-project-name-leash.md) | Name the project "Leash" | accepted |
| [0009](0009-snapshot-mechanism-overlayfs-with-copy-fallback.md) | Snapshot mechanism is overlayfs, with a plain-copy fallback | accepted (gate refined by ADR-0014) |
| [0010](0010-two-explicit-modes-record-only-and-enforce.md) | Two explicit run modes, record-only and enforce | accepted |
| [0011](0011-single-threaded-notify-decision-loop.md) | Single-threaded notify decision loop | accepted |
| [0012](0012-kernel-floor-linux-5-19.md) | Raise the kernel floor to Linux 5.19 | accepted (probe clauses refined by ADR-0015) |
| [0013](0013-kernel-backstop-per-expressible-dimension.md) | Kernel backstop per dimension the kernel can express, not absolutely | accepted |
| [0014](0014-defer-arm64-reference-target.md) | Defer the ARM64 reference target; the M0 gate is x86-64 only | accepted |
| [0015](0015-preflight-version-gate-and-derived-probes.md) | The version check is a hard gate, and ADDFD support is derived, not probed | accepted |
| [0016](0016-raw-libc-for-the-seccomp-boundary.md) | Raw libc syscalls for the seccomp boundary | accepted (Landlock question closed by ADR-0018) |
| [0017](0017-record-only-allows-use-continue.md) | Record-only allows are realized with CONTINUE | accepted |
| [0018](0018-enforcement-path-dependency-decisions.md) | Enforcement-path dependency decisions for M2 (raw-libc Landlock, toml crate, hand-rolled glob matcher) | accepted |

These encode the project's load-bearing decisions. They are the committed, authoritative source.
