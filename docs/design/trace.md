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
access to it (FR-21, FR-3).
Measurement 0003 question 1 found the traces readable under the example policy, and writable under a broad write grant, before this deny existed.
An implicit, first-ranked seccomp deny (`implicit:state_root`, ADR-0024) now refuses every access to the state root, reads included, and the moving, replacing or altering of its ancestors, before any policy rule.
Landlock backs it up only where no policy grant overlaps the root, and where none overlaps it denies reads as well as writes.
A snapshot run will refuse before spawn when a write-class grant overlaps the state root (ADR-0024, not yet implemented).
An escape test confirms the child cannot open `trace.jsonl` under any path,
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
| `type` | `run_start`, `syscall`, `step`, `cgroup_kill`, `capture_failed`, or `run_end` |

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
| `errno` | present only on an enforce-mode realization failure (`failsafe:realization`) or an invalid metadata operand (`failsafe:unsupported_operand`): the symbolic errno name the child received, e.g. `ENOENT` or `E2BIG` |
| `operand_decisions` | present for enforce-mode two-path filesystem operations; one independent `path`/`dest` decision and matched-rule id per required access mode |

Fact details fixed by the notify loop:

- A two-path filesystem fact (`rename`, `link`, `symlink` families) carries the second path in an
  optional `dest` field alongside `path`; single-path facts omit it.
  In enforce mode `operand_decisions` records the independent evidence for each operand that is
  actually authorized.
  For symlink creation only `dest` appears because `path` is stored link text, not a resource
  Leash accesses.
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

- A realization failure is an enforce-mode filesystem event under `failsafe:realization` for an operation the confined broker could not carry out ([`syscalls.md`](syscalls.md) sections 3.1 and 4).
  It arises in two places.
  When path preparation fails before policy evaluation, it is the only event for the syscall.
  When an allowed operation cannot be realized after the allow is recorded (the kernel refuses to inject the descriptor, or the broker refuses an `O_PATH` open of a kind it cannot reopen), it is a second event for the same syscall and fact, written after the `allow` and before the agent is answered.
  It stays a fail-closed `deny`, and the child receives the errno the event names.
  The event records that errno by symbolic name in `errno` (an unnamed value is written `errno_<n>`).
  This is an additive optional field, so `schema_version` does not move; a reader that ignores it still decodes the event.
  The field exists because the same decision covers different situations: a path that does not exist (`ENOENT`, `ENOTDIR`), which the kernel would have answered the same way for an unconfined process, a refused resolution (`ELOOP` from a magic link, `EXDEV` from an escape beneath the authoritative root), which is a security refusal, except that `EXDEV` or `ELOOP` after a recorded allow on an `openat2` is the caller's own `resolve` restriction refusing its spelling, and a realization the allow could not complete (`EMFILE`, `ENFILE`, `ENOMEM` or `EIO` from a refused injection, `EOPNOTSUPP` from an `O_PATH` kind the broker does not reopen, `EACCES` from an `O_PATH` substitute the file mode refuses to reopen for reading).
  The errno is what lets a reader tell them apart without changing what the decision means.

In a run with no policy, `matched_rule` carries a fixed base id naming what decided the event:
`base:record_only` (the record-only base allow, [`policy.md`](policy.md) section 3),
`sr4:io_uring`, `sr4:pidfd_getfd`, and `sr3:foreign_abi` (the denied-and-recorded set), and
`failsafe:memory_read` (a case-C deny), and `failsafe:realization` (an enforce-mode path preparation failure, or a realization failure recorded as a second event after the allow, either with its `errno`).
An enforce run with a policy adds `implicit:state_root`, the implicit deny of the state root and of moving, replacing or altering its ancestors, and `implicit:supervisor_proc`, the implicit deny of the supervisor's and broker's `/proc/<pid>/` trees; both rank before every policy rule (FR-21, ADR-0024).
A snapshot run (`snapshot_integrity`) adds `implicit:cgroup`, the implicit deny of every cgroup2 mount, found by path or by the filesystem type of the pinned handle, and of moving, replacing or altering its ancestors, ranked the same way (ADR-0024 decision 4), `snapshot:aio`, `snapshot:clone3` and `snapshot:xattrat` (a call answered `ENOSYS`, ADR-0024 and ADR-0025), and `snapshot:metadata`, which only a seccomp filter and run flag that disagree can produce.
`failsafe:unsupported_operand` is a metadata call whose own arguments the kernel would refuse (ADR-0025); it carries the `errno` the child received, such as `E2BIG` or `EINVAL`.
Its `landlock_residuals` also carry `landlock:snapshot_store_read_overlap` when a read-only grant overlaps the state root or a cgroup2 mount (ADR-0024 decision 5).
These are trace vocabulary, not policy rules; a loaded policy's rule ids never
collide with them because they carry a `:` and rule ids are plain names.

`run_start` carries the same facts as `meta.json` so the stream is self-contained.
`step` marks a committed **step** boundary with the step index (FR-17, [`snapshot.md`](snapshot.md)).
`run_end` carries the exit status of the child tree and the final committed step index.

A snapshot run (`snapshot_integrity`, ADR-0024) adds one optional field to `run_start` and `meta.json`, optional fields to `step` and `run_end`, and two event types.
All are additive, so `schema_version` does not move, and a reader that ignores them still decodes the trace.
Non-snapshot runs write neither.

- `run_cgroup` is the absolute path of the run cgroup, `leash-<run-id>` under Leash's own cgroup.
  Rewind reads it to check that the cgroup is gone (ADR-0024 decision 17).
- A `cgroup_kill` event is written when Leash kills a run cgroup or encounters a per-entry error during stale cleanup.
  `reason` is `run_end` (the root exited and leftover processes were killed), `abort` (the run failed closed and the whole tree was killed), or `stale_cleanup` (the cgroup of a dead run was found at the start of this run and removed, or inspecting its lock or cgroup failed).
  A stale-cleanup error on the run lock or cgroup emits a `stale_cleanup` event with `error` set and no kill performed.
  Kills performed by the `RunCgroup` `Drop` backstop on unwind or early return are not recorded in the trace.
  `cgroup` is the target cgroup's name.
  `processes` is the count listed in `cgroup.procs` just before the kill, and is absent when the list could not be read or no kill was attempted.
  `error` is present only when checking the lock, opening or killing the cgroup failed, or `populated` did not reach 0 in time.
  `removal_error` is present only when the kill succeeded and removing the cgroup directory or its descendants failed; at run end that failure is recorded here without discarding `run_end`.
  At run end the event precedes `run_end`.
  An abort event is written on a best-effort basis, because the trace itself may be what failed.

ADR-0022 requires snapshot-enabled runs to record their backend and consistency-contract
version, and to bind each successful step to its durably published snapshot. These additions
are required design, with schema implementation and validation pending. Existing live-copy
captures must not be relabeled exact. A failed or unpublished capture must not produce a
successful step; a published snapshot without its committed step is an orphan during recovery.
A failed final capture must be represented as failure, not as a successful final boundary.

A snapshot run also writes these (ADR-0024 decisions 10, 14 and 16), all additive and all absent from a run that takes no snapshots.

- A `step` event of a snapshot run carries, besides `step`:
  - `manifest_digest`: the lowercase hex sha256 of the exact manifest bytes the store published for the step, as `load_manifest` returns it.
  - `capture_pause_us`: microseconds the agent tree was frozen, from the start of the freeze to just before the step event is written.
    The event must be durable before the thaw, so the thaw wait is not included.
    It is `0` for step 0 and the final step, where no agent is running.
  - `capture`: `{"entries": <files, directories and symlinks captured>, "bytes": <sum of regular-file sizes>, "new_objects": <content objects this capture added to the store>}`.
  A `step` event is written, and the trace synced, only after the manifest is published and the cgroup is confirmed still frozen, and before the thaw.
  Step 0 is captured after the run cgroup exists and before the agent is created, so its event follows `run_start` and any `stale_cleanup` events.
  The final step is captured after `cgroup.kill` reported `populated 0`, so its event follows the `cgroup_kill` event with reason `run_end` and precedes `run_end`.
  Each digest is also printed to stderr as `leash: step <n> snapshot <digest>` when its step commits.
- `run_end` carries `chain_head`: the chain head over every committed step digest, `restore::chain_head` over the `(step, digest)` pairs the store returned.
  It is recomputed from those digests and never read back from the trace, and it is printed at run end as `leash: snapshot chain head <head>`.
  It is absent in a run that takes no snapshots and in a run that aborted, which has no `run_end`.
  `final_step` names the last committed step.
- A `capture_failed` event is written, on a best-effort basis because the trace may be what failed, when a capture boundary fails and the run aborts closed.
  It carries `step` (the step the boundary would have closed), `phase` and `error` (text).
  `phase` is `freeze` (`frozen=1` not confirmed in time), `capture` (the store could not capture or publish, or a limit was hit), `frozen_check` (the cgroup was no longer frozen after the capture), `step_event` (the step event could not be written or made durable) or `thaw` (`frozen=0` not confirmed in time).
  A failed boundary has no `step` event, except `thaw`, where the step event was already durable and the thaw failed afterwards.
  A manifest published before a `frozen_check`, `step_event` or `thaw` failure stays in the store as an orphan: published, never committed.
  The run then kills the whole run cgroup (a `cgroup_kill` event with reason `abort`), exits 125 and writes no `run_end`.
  Hitting a capture limit (entries, total bytes, per-file size, store growth) is a `capture` failure, so it ends the run.
- A snapshot run records the `clone3` `ENOSYS` denial and the legacy AIO denial as events (matched rules `snapshot:clone3` and `snapshot:aio`).

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

A realization failure ([`errno`](#2-event-schema) present) is rendered by its errno, not by its `deny` decision alone.
`ENOENT` and `ENOTDIR` mean the path, or a component of it, does not exist; the report shows such a path as `not found`, because the policy refused nothing and a reader must not take a glibc locale probe for a blocked access.
Any other errno is a refusal or a failed realization and renders as `denied (<ERRNO>)`, for example `denied (ELOOP)`, so the cause stays visible.
An event with no `errno` (every policy decision, and traces written before the field existed) renders as `denied` exactly as before.
The decision recorded in the trace is unchanged in all cases; only the report's wording differs.
