# Trace and session report

- Status: settled (slate 2 closed 2026-07-08)
- Governs: the per-run directory layout, the JSONL event schema, durability, and the human-readable
  session report.
- Cites: FR-2, FR-3, FR-5, FR-16, FR-19, FR-21; NFR-3; ADR-0002, ADR-0010, ADR-0011, ADR-0019.
  Invariants I2, I3, I4 are defined in [`architecture.md`](architecture.md).

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
                    Landlock residuals, snapshot mechanism stamps, argv, workspace path, start time
  trace.jsonl       the ordered, append-only event stream
  report.txt        the human-readable session report, written at run end
  snapshots/        per-step snapshot state (see snapshot.md)
```

The state directory lies outside the **workspace**, and in **enforce** mode the child is denied
access to it by both layers: no policy rule grants it, and the derived Landlock ruleset does not
include it (FR-21, FR-3). An escape test confirms the child cannot open `trace.jsonl` under any path,
including `/proc` self-reference ([`escapes.md`](escapes.md), I2).

The `<run-id>` is a UTC timestamp plus a short random suffix, `20260708T153012Z-7k3m9q`: a compact
ISO-style timestamp, a hyphen, six characters of lowercase base32 (section 5). It sorts by start
time in a directory listing, is unique without coordination, and is a single safe path component.

## 2. Event schema

`trace.jsonl` is one JSON object per line, appended in decision order, never rewritten (FR-2, FR-16).
JSONL is the machine-readable format FR-16 gives as its example (FR-16 mandates a documented
machine-readable format, not JSONL specifically); the field set aligns with the draft
agent-audit-trail schema where practical (FR-16), and carries a `schema_version` so a reader can decode
it without guessing.

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
| `fact` | the typed fact the decision was made on: filesystem path plus access mode, network host plus port, process-creation flags, cross-process target pid, or binary |
| `decision` | `allow`, `deny`, or `ask` |
| `ask_resolution` | present only for an `ask`: `approved`, `denied`, `timed_out`, or `unattended` |
| `matched_rule` | the id of the policy rule that decided it, or the base rule ([`policy.md`](policy.md)) |
| `would_deny` | present in record-only when a present policy would have denied (ADR-0010) |

Fact details fixed by the notify loop:

- A two-path filesystem fact (`rename`, `link`, `symlink` families) carries the second path in an
  optional `dest` field alongside `path`; single-path facts omit it.
- An event whose decision was made without a trusted typed fact carries the `raw` fact family with
  no fields: the denied-and-recorded set ([`syscalls.md`](syscalls.md) section 5), and a case-C
  event where the pointer argument could not be read within its cap
  ([`notify-loop.md`](notify-loop.md) section 4), which is a deny except for the record-only
  network allow fixed below (ADR-0019, recorded 2026-07-23). The envelope's `syscall` field still names the
  call, which is the recordable substance of those events.
- A process-creation fact carries optional `flags`.
  `clone` and `clone3` fill it from the kernel-trusted scalar or bounded `clone_args` read; `fork` and `vfork` omit it.
- A cross-process fact always carries `target_pid`, read from the kernel-trusted scalar register argument (`ptrace`, `process_vm_readv`, `process_vm_writev`).
  `pidfd_getfd` produces no cross-process fact at all: its pidfd argument cannot be safely resolved under `CONTINUE`, so it carries the `raw` family instead.
  It is denied and recorded in both modes as a member of the denied-and-recorded set ([`syscalls.md`](syscalls.md) section 5), under the `sr4:pidfd_getfd` id, because an imported fd is I/O the trace could not otherwise attribute (ADR-0019, recorded 2026-07-23).
- A network fact carries the destination `host` string and `port` parsed from the trapped `sockaddr`.
  By the recorded decision of 2026-07-23 (the issue #26 hygiene pass), `host` carries the canonical form of the destination: an IPv4-mapped IPv6 address is written as its IPv4 form, so a dual-stack `connect` to `93.184.216.34` records `"93.184.216.34"` and never `"::ffff:93.184.216.34"` ([`policy.md`](policy.md) section 2.2).
  A native IPv6 destination is unchanged.
  This narrows the set of values the field can take without changing its type, so `schema_version` does not move; a reader that accepted the mapped form still decodes the canonical one.
  Older traces can carry the mapped form, so a reader spanning both forms should canonicalize on its own side.
  If the `sockaddr` cannot be read or parsed within its bound, the event is recorded as `raw`.
  In record-only that raw network event is allowed, because record-only enforces nothing outside the denied-and-recorded set (ADR-0019, recorded 2026-07-23; FR-9 and I3 carry the same mode scope).
  In enforce mode the same untrusted network fact denies fail-closed.

In a run with no policy, `matched_rule` carries a fixed base id naming what decided the event:
`base:record_only` (the record-only base allow, [`policy.md`](policy.md) section 3),
`sr4:io_uring`, `sr4:pidfd_getfd`, and `sr3:foreign_abi` (the denied-and-recorded set), and
`failsafe:memory_read` (a case-C deny). These are trace vocabulary, not policy rules; a loaded policy's rule ids never
collide with them because they carry a `:` and rule ids are plain names.

`run_start` carries the same facts as `meta.json` so the stream is self-contained. `step` marks a
**step** boundary with the step index (FR-17, [`snapshot.md`](snapshot.md)). `run_end` carries the
exit status of the child tree and the final step index.

The `fact` is what the supervisor resolved, not what the child's memory said after the fact: the
trace records the kernel-trusted value the decision used (I4), so the trace and the decision cannot
disagree. What "resolved" means depends on the mode. In enforce mode it is the `openat2`
anchor-based resolution of [`syscalls.md`](syscalls.md) section 4. In record-only, where allows are
realized with `CONTINUE` (ADR-0017), the supervisor records the once-read path made absolute by
prefixing the kernel-trusted `/proc/<pid>/cwd` (for `AT_FDCWD`-relative paths) or
`/proc/<pid>/fd/<dirfd>` (for dirfd-relative paths); symlinks within the path are not chased and
`..` components are not collapsed, so the recorded value is the argument as the child presented
it, anchored. If that `/proc` anchor cannot be read, the path is recorded relative, as the child
gave it, and the syscall is still allowed: the anchor is a supervisor-side convenience for the
trace, not child memory, and record-only enforces nothing (ADR-0010), so a failure to anchor never
denies. This is distinct from a failure to read the path pointer itself, which is untrusted child
memory and denies as a case-C event ([`notify-loop.md`](notify-loop.md) section 4).

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
also stopped the child, so no un-flushed event describes an action the machine outlived. A stricter
per-event fsync is offered as an opt-in flag for runs that value durability over overhead
(section 5). This durability claim is one to test, not assume (NFR-5): the fault test kills the
supervisor mid-step and confirms the flushed prefix of the trace is intact and consistent.

## 5. Parameters fixed at slate 2

- `<run-id>` format: UTC timestamp plus six random base32 characters, e.g. `20260708T153012Z-7k3m9q`
  (section 1). Chosen over a ULID because the timestamp is readable in a plain `ls`.
- fsync granularity: step-boundary by default; per-event as an opt-in flag (section 4).
- Envelope field names are fixed as documented in section 2 (`seq`, `ts`, `type`, `pid`, `syscall`,
  `fact`, `decision`, `matched_rule`, `would_deny`). Mapping to the agent-audit-trail draft is a
  deferred alignment pass (FR-16 is a SHOULD-align, not a MUST-match); trigger: when the M1
  serializer is written, the draft's then-current shape is reviewed and any renames land as a
  `schema_version` bump.

## 6. Session report

At run end the supervisor writes `report.txt`, the human-readable summary FR-5 requires, derived entirely from the trace and never from a second source that could disagree.
It lists the files touched, executed binaries, process-creation attempts, cross-process control attempts, and network connections attempted, each with its **decision**, grouped for a human to skim.
It also lists the denied attempts that carry no typed fact, including the denied-and-recorded set and the case-C denies of section 2, so a refused action is visible even without a fact to name it.
It names the active **mode** (FR-19); a record-only report says so in as many words and never uses enforcement language for a run that enforced nothing (ADR-0010).
Because it is derived from the trace, the report is regenerable after the fact from `trace.jsonl` alone, so a run can be re-summarized without re-running the agent.
