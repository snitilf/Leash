# Architecture Decision Records

An ADR records a decision that is **hard to reverse**, **surprising without context**, and **the result of a real trade-off**. If a decision is not all three, it does not get an ADR — it lives in the spec or the design, or it is simply the obvious thing.

ADRs are **immutable once accepted**. A decision that changes is not edited; a new ADR supersedes it, and the old one is marked `superseded by ADR-NNNN`. This preserves the reasoning trail — the deterministic brain remembers why it once chose differently.

## Format

```md
# ADR-NNNN: {short title of the decision}

- Status: proposed | accepted | superseded by ADR-NNNN
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
| [0003](0003-defense-in-depth-seccomp-and-landlock.md) | Enforce with seccomp-unotify *and* Landlock (defense in depth) | accepted |
| [0004](0004-policy-as-declarative-data.md) | Policy is declarative data, not code | accepted |
| [0005](0005-time-travel-by-snapshot-not-replay.md) | Time travel is filesystem snapshots, never agent replay | accepted |
| [0006](0006-mediate-at-os-boundary-not-sdk.md) | Mediate at the OS boundary, never via an agent SDK | accepted |
| [0007](0007-implementation-language-rust.md) | Implement in Rust | accepted |
| [0008](0008-project-name-leash.md) | Name the project "Leash" | accepted |
| [0009](0009-snapshot-mechanism-overlayfs-with-copy-fallback.md) | Snapshot mechanism is overlayfs, with a plain-copy fallback | accepted |
| [0010](0010-two-explicit-modes-record-only-and-enforce.md) | Two explicit run modes, record-only and enforce | accepted |

These encode the project's load-bearing decisions. They are the committed, authoritative source.
