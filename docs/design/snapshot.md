# Snapshots, rewind, and diff

- Status: architecture revised 2026-11-01 by ADR-0022.
  Snapshot scope, protected storage and rewind rules revised 2026-11-24 by ADR-0024 (enforce-mode snapshots without a custodian).
  The ADR-0024 controls in sections 2, 3 and 5 are specified, not yet implemented.
  Exact-capture implementation and adversarial validation pending.
  The historical M0 results below do not prove concurrent capture correctness.
- Governs: FR-11, FR-12, FR-13, FR-17, FR-21; ADR-0005, ADR-0009, ADR-0022, ADR-0024.

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

## 2. Capture barrier

Snapshots exist only in enforce mode, and only when the operator passes `--snapshots` (ADR-0024).
Before spawn, verify a writable delegated cgroup v2 with working `cgroup.freeze` and `cgroup.kill`.
Also verify Landlock ABI 3 or higher, and that no write-class Landlock grant overlaps the state root or any cgroup2 mount.
Place the child in the run cgroup before untrusted execution; keep the supervisor outside.
Leash creates the child directly inside the cgroup with `clone3(CLONE_INTO_CGROUP)` and a descriptor on the pinned run cgroup, so membership is atomic: the child is a member before it runs one instruction, before it installs its filter, and before `execve`.
No `cgroup.procs` write is involved, no attach descriptor is handed to the child, and a failed entry fails the spawn before any agent code exists.
The child also closes every inherited descriptor above 2 before `execve`, as it does for all descriptors.
Descendants inherit membership.
The setup probe proves freeze, thaw and kill on a sacrificial cgroup holding a real process, never on the run cgroup, because on Linux 6.8 a cgroup that has been written `cgroup.kill` SIGKILLs every later `CLONE_INTO_CGROUP` child, even when it was empty at the time.
A per-run `flock` on `<run_dir>/run.lock`, held for the whole run, marks the run alive.
At the start of every snapshot run Leash kills and removes the sibling `leash-<run-id>` cgroups whose name validates and whose run lock under its state root can be taken, and records each in the new trace.
It never touches a cgroup whose lock is held, whose lock file does not exist under its state root, or whose name is not exactly `leash-` and a generated run id.
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
An agent that parks a thread on its own nested seccomp listener reaches this path.
A barrier, capture, publication or thaw error also aborts the run closed and kills the whole cgroup.
Incomplete captures never appear as successful steps.
Recovery ignores unpublished staging data.
A published snapshot without a committed step event is an orphan, not a successful boundary.

In a `--snapshots` run, the run ends when the root process exits.
Leash then writes `cgroup.kill`, records that, waits boundedly for `populated=0`, and takes the final snapshot.
Every abort path kills the whole cgroup.
Initial capture precedes spawn.

The run takes an exclusive workspace lock (an `flock` under the state root) at start.
External writers remain the operator contract of ADR-0022.
Captures enforce hard limits on entry count, total bytes, per-file apparent size and store growth, and a minimum interval between boundaries.
Each step event records the capture pause.

## 3. Copy backend, store and supported state

Copy is the initial backend.
It uses the same barrier as overlay and may pause the agent for time proportional to workspace size.
The fallback is a storage choice, never weaker consistency.
Snapshot metadata records the mechanism and consistency contract; historical live copies must not be relabeled exact.

The store is content-addressed.
Objects are keyed by sha256 of their bytes, and each step has one manifest that lists paths, object digests and supported metadata.
A capture is written to staging and then renamed into place, so a reader never sees a partial snapshot.
Hard caps on entries, bytes, apparent file size and store growth bound every capture, and exhaustion fails the capture closed.
Each step event carries the manifest digest, and `run_end` carries a chain head over all digests, printed at run end.
The chain is recomputed from the manifests, never read from the trace.
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
A snapshot run adds the same kind of deny for every cgroup2 mount in the mount namespace, read included, as depth.
`clone3` returning `ENOSYS` is what closes `CLONE_INTO_CGROUP`, because `open_tree` and descriptor passing can still yield a directory descriptor.
The state-root deny also covers rename, removal and replacement of every ancestor directory of the state root.
It matches by path identity, so a second mount of the same directory is a residual, and metadata reads (`stat`, `readlink`, `inotify_add_watch`) are unmediated.
Landlock cannot subtract a subtree from a grant, so a snapshot run refuses before spawn when any grant with write, truncate, make, remove or refer rights overlaps the state root or any cgroup2 mount.
A read-only overlap is allowed and is stamped into the trace as a single-layer residual.
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
Every `leash run` and `leash rewind` kills and removes stale run cgroups that run metadata names.
A run cgroup is stale when its run lock can be taken.
Only a Leash-named child of Leash's own cgroup is killed; a name from metadata is validated first.
Rewind also requires exclusive workspace ownership, and no live overlay mount or remaining references that could mutate the restored state.
It targets only steps with a committed step event.
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
