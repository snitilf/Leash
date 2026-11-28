# Snapshots, rewind, and diff

- Status: architecture revised 2026-11-01 by ADR-0022.
  Snapshot scope, protected storage and rewind rules revised 2026-11-24 by ADR-0024 (enforce-mode snapshots without a custodian).
  The ADR-0024 capture barrier, workspace lock, step digests and chain head (sections 2 and 3), the restore engine and the `leash rewind` command (section 5) are implemented.
  Exact-capture implementation and adversarial validation pending.
  The historical M0 results below do not prove concurrent capture correctness.
- Governs: FR-11, FR-12, FR-13, FR-17, FR-21; ADR-0005, ADR-0009, ADR-0022, ADR-0024, ADR-0026.

## 1. Consistency contract and step detection

Exactness requires exclusive workspace ownership throughout run and rewind. External
writers, including editors, build daemons, shared mappings and hard-link aliases, must
be stopped by the operator. The Leash workspace lock excludes other Leash operations;
it does not enforce or reliably detect external-writer exclusion.

A step is derived from mediated mutating events. The coalescing window remains 250 ms,
chosen from the M1 measurements in `../measurements/0001-m1-overhead.md`; confirmation
against a real agent session remains pending. Event quiescence proposes a boundary,
not proof of filesystem quiescence. Writes through existing descriptors and shared
mappings do not necessarily tick this clock. The barrier below makes captures exact
within ADR-0022's supported filesystem state, regardless of those timing gaps. It does
not make an application transaction atomic. Initial and final snapshots are mandatory.

An agent that writes only through open descriptors or shared mappings, or that mutates faster than the window forever, gets no mid-run boundary.
The step clock proposes a boundary only from mediated mutating events, and a boundary needs a quiet window of 250 ms.
Granularity is lost, exactness is not.
Every capture that does run is exact, because it runs under the barrier whatever proposed it.
The final capture runs after `populated 0`, when no process of the tree exists, so it is exact for any agent.

## 2. Capture barrier

Snapshots exist only in enforce mode, and only when the operator passes `--snapshots` (ADR-0024).
Before spawn, verify a writable delegated cgroup v2 with working `cgroup.freeze` and `cgroup.kill`.
Also verify Landlock ABI 3 or higher, and that no write-class Landlock grant overlaps the state root or any cgroup2 mount.
The ABI comes from the preflight probe, which a test replaces to prove the refusal because no available host has an ABI below 3.
The overlap check runs on the anchors Landlock really opens, not on the grant roots the policy spells.
Landlock cannot open a path that does not exist, so it anchors such a grant at the deepest existing ancestor and puts the rights there: `~/.local/state/mytool/**` with no `mytool` grants write on `~/.local/state`, and `/scratch/**` with no `/scratch` grants write on `/`.
The session therefore builds the ruleset first, which opens the anchors without applying anything, and compares each anchor's canonical path and its rights, masked by the anchor's file type, with the state root and with every cgroup2 mount of `/proc/self/mountinfo`, by path component, as an ancestor or a descendant.
It also compares the `(st_dev, st_ino)` of each anchor with those of the protected path and of its ancestors, and the reverse, so a bind mount alias of the state root is caught.
It refuses on write, truncate, any `MAKE_*`, remove or refer rights, names the policy rule, the grant path as spelled, the anchor when the path is missing, the right and the protected path, and runs before the cgroup probe and before any run directory exists.
Place the child in the run cgroup before untrusted execution; keep the supervisor outside.
Leash creates the child directly inside the cgroup with `clone3(CLONE_INTO_CGROUP)` and a descriptor on the pinned run cgroup, so membership is atomic: the child is a member before it runs one instruction, before it installs its filter, and before `execve`.
No `cgroup.procs` write is involved, no attach descriptor is handed to the child, and a failed entry fails the spawn before any agent code exists.
The child also closes every inherited descriptor above 2 before `execve`, as it does for all descriptors.
Descendants inherit membership.
The setup probe proves `clone3(CLONE_INTO_CGROUP)` survival, lock xattr round-trip, freeze, thaw and kill on a sacrificial `leash-probe-<random>` cgroup holding a real process, never on the run cgroup.
The probe process execs nothing, so the probe needs no binary on the host: it writes one ready byte, closes the pipe and waits in `pause()`.
It asks the kernel for SIGKILL when the supervisor dies (`PR_SET_PDEATHSIG`) and checks its parent right after, so a crashed supervisor does not leave a populated probe cgroup behind.
On Linux 6.8 a `clone3(CLONE_INTO_CGROUP)` child is immediately SIGKILLed whenever the caller's cgroup kill count differs from the target cgroup's kill count, and a newly created cgroup starts at kill count 0 even under a previously killed parent (measurement 0003 section 8).
Probing through `clone3(CLONE_INTO_CGROUP)` catches a previously killed parent cgroup before any run directory is created, and never writes `cgroup.kill` on the real run cgroup before spawn.
The run cgroup is created from the pre-generated run id before the run directory and before the broker exist, so a refusal or failure while creating it leaves no run directory and no broker.
Any failure after that and before the run directory exists removes the empty cgroup.
Stale cleanup skips a cgroup that has no `run.lock`, so no other run touches the new cgroup in the meantime.
The run lock is taken and bound to the cgroup once the run directory exists, after `run_start` is synced and before the broker forks.
The lock is close-on-exec and the broker closes every other descriptor first, so it never holds the lock.
A failure to take or bind the lock happens after the run directory exists, so it is recorded: a `cgroup_kill` event with reason `abort` and the error, removes the empty cgroup, writes no `run_end` and exits 125.
A per-run `flock` on `<run_dir>/run.lock`, held for the whole run, marks the run alive, and its `<st_dev>:<st_ino>` identity is stored in the `user.leash.lock` xattr of the run cgroup directory.
At the start of every snapshot run Leash kills and removes the sibling `leash-<run-id>` cgroups under its current parent whose name validates, whose `run.lock` resolves beneath its state root without symlinks as a regular file, whose lock can be taken, and whose `user.leash.lock` xattr matches that lock inode, and records each in the new trace.
It never touches a cgroup whose lock is held, whose lock file does not exist under its state root, whose `user.leash.lock` xattr is absent or differs (such as a copied state root with a fresh `run.lock` inode), or whose name is not exactly `leash-` and a generated run id.
The same cleanup removes a leftover `leash-probe-*` cgroup that holds no process (`populated 0`) and is at least 30 seconds old, and records nothing when it does.
It never kills anything in a cgroup with that name, and the age limit keeps it from removing the sacrificial cgroup of a probe that another Leash under the same parent is running at that moment.
Because stale cleanup scans only Leash's current parent cgroup, when each run is launched in its own per-run `systemd-run --user --scope -p Delegate=yes` scope a crashed run's cgroup tree sits under that earlier scope and is not cleaned by a later run in a fresh scope; systemd scope behavior remains unverified because systemd is absent in the codespace.
Snapshot-enabled runs refuse before spawn when any prerequisite is unavailable.
Process enumeration and SIGSTOP are not substitutes for this barrier.

At a candidate boundary the supervisor runs this exact order:

1. Answer the current notification.
   The loop answers each notification, ask prompts included, before it polls for a boundary, so no received-but-unanswered notification exists when a freeze starts.
2. Stop receiving notifications.
3. Write `cgroup.freeze=1`.
4. Wait boundedly for `cgroup.events` to report `frozen=1`.
5. Capture into a staging location, preserving all supported content and metadata.
6. Re-read `frozen=1`.
7. Publish the snapshot durably.
8. Write the step event.
9. Write `cgroup.freeze=0`.
10. Resume receiving notifications.

The supervisor never receives a notification between freeze and thaw.
Answering notifications during the freeze wait would let mutations in after the boundary decision.

Legacy AIO (`io_setup`, `io_submit`) is denied and recorded in a snapshot run, because the freezer stops tasks, not in-flight I/O.
`clone3` is answered `ENOSYS` before its argument struct is read and the denial is recorded as an event, so a task cannot enter the run cgroup's control plane through `CLONE_INTO_CGROUP`.
The supervisor marks itself non-dumpable before it starts the broker.

A freeze that does not complete in time aborts the run closed and kills the whole cgroup.
The kernel allows one notify listener per filter chain, and Leash's is already in the agent's chain, so an agent's own `SECCOMP_FILTER_FLAG_NEW_LISTENER` fails with `EBUSY` (tested in `tests/capture_barrier_linux.rs`).
None of the agent actions tested wedges a freeze, and the abort path is exercised through the `BarrierOps` seam.
Unverified: a task in uninterruptible sleep (a FUSE mount that never answers, a hard NFS mount) may stall a freeze until the timeout, and the run then aborts closed.
A barrier, capture, publication or thaw error also aborts the run closed and kills the whole cgroup.
Incomplete captures never appear as successful steps.
Recovery ignores unpublished staging data.
The frozen re-check runs inside the capture, after the whole tree is read and before the manifest is published, so a cgroup that thawed leaves no manifest for the step.
A published snapshot without a committed step event is an orphan, not a successful boundary.
The only orphan a boundary can leave is a `step_event` failure: the manifest was published, and the event never became durable.
The committed steps are derived from the `step` events in `trace.jsonl`, excluding a step whose event is followed by `capture_failed` with phase `step_event` for the same step.
`store::published_steps` lists the manifests on disk, orphans included, and `store::committed_steps_from_trace` lists the committed steps (trace.md section 2).

In a `--snapshots` run, the run ends when the root process exits.
Leash then writes `cgroup.kill`, records that, waits boundedly for `populated=0`, and takes the final snapshot.
Every abort path kills the whole cgroup.
Initial capture precedes spawn.

The run takes an exclusive workspace lock at start: an `flock` on the pinned workspace directory handle and an `flock` on a file under the state root (ADR-0024 decision 13, ADR-0026).
External writers remain the operator contract of ADR-0022.
Captures enforce hard limits on entry count, total bytes, per-file apparent size and store growth, and a minimum interval between boundaries.
Each step event records the capture pause.

Implementation notes, with the constants chosen:

- The workspace lock is two non-blocking `flock`s, both taken before any run directory exists.
  The first is on the workspace directory itself, through a handle opened once (`O_DIRECTORY | O_CLOEXEC`).
  It is keyed by the directory inode, so it does not depend on the state root or on the spelling of the path, and a run with a different `--state-dir` is refused too (ADR-0026).
  The second is on `<state_root>/locks/<sha256 of the canonical workspace path>.lock`, taken `O_NOFOLLOW` through handles beneath the state root.
  The canonical path is read from the directory handle, so no path is resolved twice.
  A held lock refuses the run before spawn: "the workspace directory is locked by another process" (the state-root lock file refuses with "another leash run or rewind owns this workspace").
  `workspace_lock::WorkspaceLock::acquire` takes both locks and is the helper `leash rewind` reuses.
  A leftover process that holds the directory `flock` blocks later runs, which fails closed.
  The broker does not hold the locks because `broker_child` calls `close_all_except` as its first act (`broker.rs`), not because the descriptors are close-on-exec.
  The agent child closes every descriptor above 2 before `execve`, so it holds neither.
- The run's store is `<run_dir>/snapshots`.
  The supervisor opens it as a pinned `O_DIRECTORY | O_NOFOLLOW` handle before spawn.
  Capture uses a duplicate of the workspace directory handle that the lock holds, so the locked directory is the captured directory.
  Both handles are used for the whole run.
- Step 0 is captured after the run cgroup exists and before `clone3` creates the agent, and its step event is durable before the agent exists.
- The freeze wait is bounded by `FREEZE_TIMEOUT` (2 s) and the thaw wait by `THAW_TIMEOUT` (2 s).
  An idle tree freezes in about 5 ms (measurement 0003), so the bounds are slack for a loaded host, not a working budget.
- `MIN_BOUNDARY_INTERVAL` (1 s, provisional) holds a boundary back until that long after the previous boundary ended, on top of the 250 ms quiescence window.
  Mutations that arrive meanwhile join the held-back step.
  Step 0 counts as a boundary.
- The step event records the pause from the start of the freeze to just before the event is written, because the event must be durable before the thaw (ADR-0024 decision 10).
  The thaw wait, normally a few milliseconds, is not in it.
- A boundary starts only at the top of the notify loop, after `handle_notification` has answered the notification it received, ask prompts included.
  No notification is received but unanswered then, and no prompt is pending.
- The final capture needs no freeze: it runs after `cgroup.kill` reported `populated 0`, so no process of the tree exists.
- A capture limit hit, or any entry capture refuses, at a boundary ends the run like any other capture error.
  The agent cannot make Leash skip a step.
- Orphans (processes outliving their parent): with Yama `ptrace_scope` 1 the supervisor cannot open `/proc/<pid>/mem` of a process that was reparented away from the run, because `proc_mem_open` asks for ptrace attach access.
  A mediated syscall from such a process fails closed (`failsafe:memory_read`, `EACCES`).
  The freeze still stops it, because the cgroup holds it, and its unmediated writes are captured at a frozen moment like any other.

## 3. Copy backend, store and supported state

Copy is the initial backend.
It uses the same barrier as overlay and may pause the agent for time proportional to workspace size.
The fallback is a storage choice, never weaker consistency.
Snapshot metadata records the mechanism and consistency contract; historical live copies must not be relabeled exact.

The store is content-addressed.
Objects are keyed by sha256 of their bytes, and each step has one manifest that lists paths, object digests and supported metadata.
A capture is written to staging and then renamed into place, so a reader never sees a partial snapshot.
Hard caps on entries, bytes, apparent file size and store growth bound every capture, and exhaustion fails the capture closed.
Each step event carries the manifest digest, and `run_end` carries a chain head over the digests of the committed steps, printed at run end.
The chain is recomputed from the manifests of the committed steps, never read from the trace, and an orphan manifest is not in it.
Each step digest is printed when committed, so a crashed run has one.
Pre-rewind snapshots are outside the chain.

ADR-0022 defines supported state: names, file bytes, symlink targets, directories, within-workspace hard-link topology, modes, ownership, modification timestamps and supported xattrs/ACLs.
Unsupported objects or metadata fail explicitly.
Raw inode numbers, ctime, access times, open descriptors and process state are excluded.
A copy must not silently skip an unreadable entry or unsupported metadata.

### Protected storage

ADR-0024 replaces the ADR-0022 protected-storage prerequisite for this implementation.
Protection during the run comes from three controls.
Every enforce run adds an implicit, first-ranked deny for the state root that covers every access, read included.
A snapshot run adds the same kind of deny, matched id `implicit:cgroup`, for every cgroup2 mount in the mount namespace, read included, as depth.
It is decided twice.
By path, against the mounts read once before the run, which also covers the ancestors of a mount.
By identity, on the handle the broker pinned: an object whose `fstatfs` type is `CGROUP2_SUPER_MAGIC` is denied whatever its path, so a bind mount of a cgroup directory and a cgroup2 mount made after the run started are covered.
It also denies removing, replacing or altering an ancestor of a mount, and the metadata calls a snapshot run traps (xattrs, timestamps, `fchmodat2`, `lchown` and the descriptor forms), because Landlock has no right for them (ADR-0025).
`clone3` returning `ENOSYS` is what closes `CLONE_INTO_CGROUP`, because `open_tree` and descriptor passing can still yield a directory descriptor.
The state-root deny also covers rename, removal and replacement of every ancestor directory of the state root.
It matches by path identity, so a second mount of the same directory is a residual, and metadata reads (`stat`, `readlink`, `inotify_add_watch`) are unmediated.
Landlock cannot subtract a subtree from a grant, so a snapshot run refuses before spawn when any grant with write, truncate, make, remove or refer rights overlaps the state root or any cgroup2 mount.
A read-only overlap is allowed and is stamped into the trace as the single-layer residual `landlock:snapshot_store_read_overlap`.
At rest, snapshots are ordinary files owned by the operator.
Content hashes detect corruption, not forgery.
Digests in step events, the chain head in `run_end`, and `leash rewind --expect <digest>` narrow forgery.
At rest, a store is checkable only against a chain head the operator kept outside the store.

The custodian design in ADR-0022 remains the deferred hardening path.
It would restore protection of retained snapshots against same-uid processes between runs.
Until it exists, no cross-run authorization boundary is claimed, and the text below records what that path would require.

ADR-0022 selects a separately provisioned custodian under a distinct host UID as the design direction for canonical baselines, snapshots and authoritative manifests.
The supervisor would retain a private control capability, become non-dumpable, and leak no storage or control descriptor through child inheritance or stdio.
Custodian requests would be validated against pinned run/workspace handles, with no writable canonical handles returned.
UID-only authorization is insufficient because the child shares the operator UID.
Custodian activation additionally requires the bootstrap authorization, capability revocation, independent cgroup-termination monitor, staging recovery and bounded import/restore gates in ADR-0022.
Their concrete authentication and privilege protocol is not selected.
A socketpair does not authenticate bootstrap, and no_new_privs alone does not prevent indirect launch through unconfined services.

## 4. Overlay backend

ADR-0009 remains the intended optimized backend, gated on complete lifecycle and
copy-equivalence validation. Historical mount-spike success does not enable it.
The live lower tree must not change; snapshots retain an immutable baseline sufficient
to reconstruct old visible states independently of the original workspace. Upper-layer
captures preserve cumulative changed state, not necessarily only the latest delta.

Whiteouts may be device nodes or xattr-marked files. Opaque directories, redirects,
copy-up and hard-link topology require explicit interpretation. Mount options must be
chosen and tested for the supported semantics: disabling inode indexing can break
lower-layer hard links during copy-up. Neither lower nor upper storage may be directly
modified while mounted. Capturing a layer still requires the section 2 barrier.

## 5. Rewind and diff

Rewind and diff follow ADR-0024 rules 17-22.

Rewind requires the run's cgroup to be gone, not a `run_end` event, so a crashed run can be rewound.
The cgroup-gone check returns a tri-state (`Gone`, `Present`, `Unknown`) by pinning the recorded parent directory on a cgroup2 mount first, or walking up to the nearest existing ancestor when opening the parent returns `ENOENT`, so a vanished transient scope under a cgroup2 mount reports `Gone` while a non-cgroup2, inaccessible, or unresolvable path never fails open as `Gone`.
Rewind treats `Unknown` as not gone and also takes `<run_dir>/run.lock` before modifying the workspace.
It takes the run lock first, so a held lock means a live run, then checks the cgroup.
When the cgroup is `Present` and the lock was free, it releases the lock, runs the stale cleanup against the recorded parent, and takes the lock again before it checks once more.
`leash rewind` is the command; its grammar, checks, output and exit codes are in [`cli.md`](cli.md) section 1.
It also takes the workspace lock (both flocks, ADR-0026) for the whole rewind, and restores through the locked directory handle.
Every snapshot `leash run` kills and removes stale run cgroups under its current parent cgroup; non-snapshot runs do not clean stale cgroups.
`leash rewind` cannot reach a dead run's cgroup any other way, so it runs the same cleanup on the parent that the run's `meta.json` records for its run cgroup, and with no cgroup skipped.
That cleanup may therefore kill and remove every stale Leash cgroup under the recorded parent, not only the rewound run's.
A run cgroup is stale when its name is a valid Leash run name, its run lock under this state root can be taken, and its `user.leash.lock` xattr matches that lock file's `<st_dev>:<st_ino>`; a name from metadata is validated first, and nothing else is killed.
Under per-run `systemd-run --scope` launches, a crashed run's cgroup lives in its own earlier scope, so a later run's parent-cgroup scan does not reach it (unverified, as systemd is absent in the codespace).
Rewind also requires exclusive workspace ownership, and no live overlay mount or remaining references that could mutate the restored state.
It targets only steps with a committed step event.
The committed steps come from the trace (section 2), and the chain is recomputed over them (`restore::recompute_chain` takes the committed step list), so an orphan manifest is neither a target nor part of the chain.
The trace is read as untrusted input.
Before any write, the recomputed digest of the target manifest must equal the digest in its step event, and `--expect` must match the chain head or that digest.
Every store object the plan writes is verified before the first write.
Without `--step`, it restores step 0, the workspace as it was before the agent started.
It takes the workspace from the working directory or a flag, and refuses when that differs from the run metadata.

Rewind treats the store as hostile input.
It validates every manifest path: relative, with no empty, `.` or `..` component.
It applies changes with `openat2` and `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` from a workspace directory handle.
It writes a temporary file and renames it into place, and never writes in place.
It hashes the bytes it writes, and refuses to run as root.
A forged store can therefore only produce workspace content, never a write elsewhere.
The root refusal checks the real effective uid of the process as well as the identity the caller passes in.
A parent path is opened in chunks of components, each with the same resolve flags, so a tree deeper than `PATH_MAX` still restores.
A file with a hard link outside the workspace is never changed in place, because that would change the outside name too.
Rewind replaces it with a new inode and relinks its other workspace names to the new one.
Ownership and permission problems are found in a preflight pass before the first write.
A killed rewind can leave `.leash-restore-*` temporary names behind.
The next rewind removes them from the directories it touches, except names the target itself contains.
It fsyncs each directory it changed before it applies directory metadata.
`--expect <digest>` refuses a store whose digest does not match.

Rewind first snapshots the current workspace, so every rewind can be undone.
The safety snapshot is a complete store of its own at `<run_dir>/rewind/undo-<n>/`, with its own `objects/` and `manifests/step-000000.json`.
It is outside `snapshots/`, so it is never part of the chain, never a step, and never reachable by `--step`.
Rewind prints where it went and the `leash rewind <run-id> --undo <n>` command that restores it.
`--undo <n>` takes a new safety snapshot first, so an undo can itself be undone.
The agent can plant an entry that capture refuses, for example `mknod(S_IFSOCK)`, a mode-000 file, or a cap overrun.
If that snapshot cannot be taken, rewind refuses and names `--no-undo`, which skips it.
With `--no-undo`, rewind plans from a tolerant scan of the workspace instead (`scan_current`).
The scan walks the workspace the way capture does, but it stores no object and no manifest, and its output is never a snapshot.
It hashes only readable regular files within the size caps.
An entry it cannot capture is reported as refused and appears in the plan as a removal.
When the target has a regular file at that path, the refused entry is rewritten from the target instead.
That covers sockets, fifos, devices, mount points, unreadable files, files over a cap, and unsupported extended attributes.
An unreadable directory is reported too, and a plan that must write inside it fails when applied.
The entry count cap and names that are not UTF-8 still fail the scan, because a plan cannot name such entries.
It prints a change summary before it applies anything.
It restores the selected supported state and never replaces a mounted upperdir.
Failures are explicit, with recoverable staging and the prior state retained until restoration can be committed.
Rewind reverses filesystem effects only, and says so; it does not reverse effects already emitted off-host.

Diff compares reconstructed visible states.
A run reference without a step names the final committed step, never an orphan manifest, and a run with no `trace.jsonl` has no step known to be committed.
Whiteouts mean deletion, opaque directories replace hidden lower entries, recoverable rename relations are reported, and hard links are treated as shared objects.
Copy and overlay must produce equivalent results over their supported state, backed by the same fixtures and behavioral cases.

## 6. Validation and fault surface

Before any exactness claim, Linux tests must cover continuous existing-fd writes,
shared mappings, concurrent rename and hard-link activity, forking descendants,
cgroup escape attempts, unsupported asynchronous I/O, freezer timeout, capture and
publication failure, and descendants surviving their initial parent. Restore and diff
must preserve the full supported state. Tests run against each enabled backend.

Snapshot tests need a delegated cgroup.
A test first runs a sudo step that creates a delegated cgroup and chowns it to the test user, then runs the supervisor unprivileged inside it.
The Landlock ABI-below-3 refusal is tested through an injected probe, because no available host has an ABI below 3.
The `systemd-run` hint is unverified until a CI leg runs it.

The 2 GiB default configurable upper-layer limit from ADR-0009 remains a requirement
for overlay; polling size is not proof of a hard bound. Capacity enforcement and
capture-storage exhaustion need explicit fail-closed tests before a bounded-storage
claim. No backend may publish partial state on ENOSPC.

## 7. The M0 spike checklist

This section doubles as the acceptance criteria of the ADR-0009 validation spike (issue #13). The
spike was run by the operator on the x86-64 reference target, a KVM VPS (FR-15); the ARM64 leg was
cancelled when that target was deferred (ADR-0014, spec OQ-9). On the target:

- [ ] overlay mount of a workspace via privileged mount
- [ ] overlay mount via an unprivileged user namespace
- [ ] upper-layer capture at a boundary while the mount is live
- [ ] rewind to an earlier snapshot restores the workspace exactly
- [ ] whiteout handling: a deletion reads as a deletion, in capture, rewind, and diff
- [ ] cross-directory rename handling: copy-up plus whiteout is interpreted correctly
- [ ] hard-link handling: linked names are attributed to one inode
- [ ] the copy fallback, on a host (or configuration) where overlay is unavailable, produces
      identical observable rewind and diff behavior

The gate, as narrowed by ADR-0014: all items pass on the x86-64 target, with the
unprivileged-userns item accepted as a documented host-class limitation where the host blocks
unprivileged user namespaces outright; with that met, this file settles and the design layer can
freeze. A failure would have superseded ADR-0009 rather than quietly bending it, with this file
rewritten around the surviving mechanism.

### Spike results

x86-64 leg, Ubuntu 24.04.4 / kernel 6.8, 2026-07-08: every privileged-path item passed, mount with
upper-only writes over an untouched lower, capture, exact rewind, whiteout recorded as a char device
0/0, cross-directory rename as copy-up plus whiteout, hard link resolving to one inode, and
copy-fallback equivalence. The unprivileged-user-namespace item did not run: the host blocks
unprivileged userns via `apparmor_restrict_unprivileged_userns=1` (section 3), so on that class of
host the privileged mount or the copy fallback carries the mechanism; the skip is accepted as a
host-class limitation, not a failure (ADR-0014). The overlay mechanism holds on x86-64; no
supersede is warranted. The ARM64 leg was cancelled with the target deferral (ADR-0014, spec OQ-9);
the same spike script runs unchanged if OQ-9 ever reopens the target. With the narrowed gate met,
this file is settled.
