# Design

*How* Leash is built. This layer is written after the specification is settled: a design that
commits to *how* before *what* builds the wrong thing precisely. Every design choice cites the spec
requirement it satisfies and, where it is a hard-to-reverse trade-off, an ADR.

Status: **in progress.** The mediation and recording files are drafted and in review; the snapshot
file and the escape-traceability file are still to come (see the file table).

## Reading order

1. [`architecture.md`](architecture.md) - system and trust model, invariants I1-I5, module
   decomposition, supervisor lifecycle. Read this first; every other file cites its invariants.
2. [`syscalls.md`](syscalls.md) - which syscalls are mediated, denied-and-recorded, or passed
   through, and how each allow is realized safely (FR-4).
3. [`notify-loop.md`](notify-loop.md) - the notify-fd protocol and the fail-closed enumeration (FR-9).
4. [`policy.md`](policy.md) - the TOML schema, evaluation, and Landlock derivation (FR-18).
5. [`trace.md`](trace.md) - run directory, event schema, session report (FR-2, FR-16, FR-5).
6. [`snapshot.md`](snapshot.md) - step detection, overlay and copy fallback, rewind, diff (planned).
7. [`escapes.md`](escapes.md) - escape-vector-to-mechanism traceability (planned).

## Files and status

| File | Covers | Status |
|---|---|---|
| `architecture.md` | model, invariants, modules, lifecycle | draft, in review (slate 1) |
| `syscalls.md` | mediated-syscall enumeration (FR-4) | draft, in review (slate 2) |
| `notify-loop.md` | notify protocol, fail-closed (FR-9) | draft, in review (slate 2) |
| `policy.md` | policy schema, evaluation, Landlock derivation (FR-18) | draft, in review (slate 2) |
| `trace.md` | run dir, event schema, report (FR-2, FR-16, FR-5) | draft, in review (slate 2) |
| `snapshot.md` | step, snapshot, rewind, diff (FR-11-13, FR-17) | planned (slate 3, provisional until the M0 spike) |
| `escapes.md` | escape traceability (SR-2, NFR-5) | planned (slate 5, written last) |

## Open parameters

Design parameters deliberately left unfixed, each with the review or event that closes it. This is
the same discipline the spec uses for its open questions: a value is fixed at a review slate or
deferred with a named trigger, never left implicit.

| Parameter | Where | Default / leaning | Closes at |
|---|---|---|---|
| Path/binary glob syntax and anchoring | `policy.md` | shell-style `**` | slate 2 |
| Host matching (exact / suffix / IP / CIDR; DNS-name vs connected-IP) | `policy.md` | to decide | slate 2 |
| `mode = ["execute"]` vs the `exec` table (one control or two) | `policy.md` | to decide | slate 2 |
| Run-id format (sortable + unique + one path component) | `trace.md` | timestamp + short random suffix | slate 2 |
| fsync granularity (step-boundary vs per-event option) | `trace.md` | fsync at step boundaries | slate 2 |
| Event envelope field names, mapping to the agent-audit-trail draft | `trace.md` | align where practical | slate 2 |
| `openat2` resolve-flag set, and admitting in-workspace symlinks | `syscalls.md` | `RESOLVE_BENEATH \| RESOLVE_NO_SYMLINKS` | M0 spike / slate 2 |
| Injected-socket fidelity for a host-enforced `connect` (socket options) | `syscalls.md` | accept loss, name residual | slate 2 |
| Child memory-read cap (path / `sockaddr` length bound) | `notify-loop.md` | to set | slate 2 |
| Ask timeout default (FR-10 timeout-to-deny) | `notify-loop.md` | to set | slate 2 |
| Coalescing window for step detection (FR-17) | `snapshot.md` | to set from measurement | slate 3 / M1 |
| Upperdir size limit (fork-bomb / fill-the-upper backstop) | `snapshot.md` | to set | slate 3 |

## Governing decisions

The design does not re-open settled decisions. The load-bearing ones it builds on are ADR-0002
(supervisor/child separation), ADR-0003 as refined by ADR-0013 (defense in depth; kernel backstop per
expressible dimension), ADR-0004 (declarative policy), ADR-0006 (mediate at the OS boundary), ADR-0009
(snapshot mechanism, gated on the M0 spike), ADR-0010 (two modes), ADR-0011 (single-threaded notify
loop), and ADR-0012 (kernel floor 5.19).
