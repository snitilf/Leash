# Trace and session report

- Status: draft, in review (slate 2)
- Governs: the per-run directory layout, the JSONL event schema, durability, and the human-readable
  session report.
- Cites: FR-2, FR-3, FR-5, FR-16, FR-19, FR-21; NFR-3; ADR-0002, ADR-0010, ADR-0011. Invariants I2,
  I3 are defined in [`architecture.md`](architecture.md).

The **trace** is the ground-truth account of what the agent did, authored solely by the supervisor
(FR-3, I2). This file fixes where it lives, the shape of each **event**, and the **session report**
derived from it at run end. Events are produced by the notify loop
([`notify-loop.md`](notify-loop.md)) in decision order (ADR-0011). Terms in **bold** are in
[`../CONTEXT.md`](../CONTEXT.md).

## 1. Per-run directory

Each **run** owns one directory under an operator-configurable state directory, defaulting per XDG
(FR-21):

```
$XDG_STATE_HOME/leash/runs/<run-id>/
  meta.json         run-start facts: mode, attendance, policy digest, kernel + Landlock ABI +
                    snapshot mechanism stamps, argv, workspace path, start time
  trace.jsonl       the ordered, append-only event stream
  report.txt        the human-readable session report, written at run end
  snapshots/        per-step snapshot state (see snapshot.md)
```

The state directory lies outside the **workspace**, and in **enforce** mode the child is denied
access to it by both layers: no policy rule grants it, and the derived Landlock ruleset does not
include it (FR-21, FR-3). An escape test confirms the child cannot open `trace.jsonl` under any path,
including `/proc` self-reference ([`escapes.md`](escapes.md), I2).

The `<run-id>` format is an open parameter (section 5). The requirement on it is fixed: sortable by
start time, unique without coordination, and safe as a single path component.

## 2. Event schema

`trace.jsonl` is one JSON object per line, appended in decision order, never rewritten (FR-2, FR-16).
JSONL is the format FR-16 names; the field set aligns with the draft agent-audit-trail schema where
practical (FR-16), and carries a `schema_version` so a reader can decode it without guessing.

Every event shares an envelope and adds a type-specific body under `type`:

| Field | Meaning |
|---|---|
| `seq` | monotonic sequence number, the authoritative order (decision order, ADR-0011) |
| `ts` | supervisor wall-clock timestamp at the moment of decision |
| `type` | `run_start`, `syscall`, `step`, or `run_end` |

A `syscall` event, the common case, adds:

| Field | Meaning |
|---|---|
| `pid` | the child pid that trapped |
| `syscall` | the syscall name |
| `fact` | the typed fact the decision was made on: resolved path, host+port, or binary, plus access mode |
| `decision` | `allow`, `deny`, or `ask` (with the ask's resolution: approved, denied, timed-out) |
| `matched_rule` | the id of the policy rule that decided it, or the base rule ([`policy.md`](policy.md)) |
| `would_deny` | present in record-only when a present policy would have denied (ADR-0010) |

`run_start` carries the same facts as `meta.json` so the stream is self-contained. `step` marks a
**step** boundary with the step index (FR-17, [`snapshot.md`](snapshot.md)). `run_end` carries the
exit status of the child tree and the final step index.

The `fact` is what the supervisor resolved, not what the child's memory said after the fact: the
trace records the kernel-trusted value the decision used (I4), so the trace and the decision cannot
disagree.

## 3. Ordering and integrity

Order is the `seq` field, and it is decision order because the loop is single-threaded (ADR-0011): no
reordering, no interleaving, no synchronization to reason about (ADR-0002). The child contributes to
the trace only by attempting syscalls; it has no channel to read, delay, or suppress an entry (I2,
FR-3). The recorder is the single writer.

The record-before-respond ordering ([`notify-loop.md`](notify-loop.md) section 3) means an event is
written before the action it describes is released, so the trace can never lag reality in the unsafe
direction: there is no allowed action absent from the trace. A recorder write failure denies the
action and aborts the run (I3), because an unrecordable action must not proceed.

## 4. Durability

The trace is evidence, so it must survive the failure modes it is meant to document. The tension is
NFR-2: an `fsync` per event would put a disk flush on the decision path of every mediated syscall.

The design fsyncs at **step** boundaries and at run end, not per event. Within a step, events live in
the append buffer and the OS page cache. This protects the trace against a supervisor crash (the page
cache outlives the process and the OS flushes it) at full speed, and bounds what a power-loss can lose
to the events of the final, not-yet-quiesced step, which is acceptable because the same power loss
also stopped the child, so no un-flushed event describes an action the machine outlived. Whether a
stricter per-event or per-N-event fsync is offered for higher-assurance runs is an open parameter
(section 5). This durability claim is one to test, not assume (NFR-5): the fault test kills the
supervisor mid-step and confirms the flushed prefix of the trace is intact and consistent.

## 5. Open parameters (resolved at slate 2)

- `<run-id>` format: a sortable timestamp plus a short random suffix, or a ULID. The constraint in
  section 1 is fixed; the spelling is not.
- fsync granularity: step-boundary (the default above) versus an optional per-event mode for runs
  that value durability over overhead.
- Exact envelope field names and the mapping to the agent-audit-trail draft, pending a look at that
  schema's current shape (FR-16 is a SHOULD-align, not a MUST-match).

## 6. Session report

At run end the supervisor writes `report.txt`, the human-readable summary FR-5 requires, derived
entirely from the trace (never from a second source that could disagree). It lists the files touched,
the processes spawned, and the network connections attempted, each with its **decision**, grouped for
a human to skim. It names the active **mode** (FR-19); a record-only report says so in as many words
and never uses enforcement language for a run that enforced nothing (ADR-0010). Because it is derived
from the trace, the report is regenerable after the fact from `trace.jsonl` alone, so a run can be
re-summarized without re-running the agent (which Leash never does anyway).
