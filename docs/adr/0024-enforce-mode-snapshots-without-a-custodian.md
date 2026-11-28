# ADR-0024: Enforce-mode snapshots without a custodian

- Status: accepted (metadata residual refined by ADR-0025)
- Date: 2026-11-24
- Tier: 3 (trades a security invariant of ADR-0022 for a narrower, named one)
- Partly supersedes: ADR-0022 (mode scope, protected-storage prerequisite, historical-read authorization)

## Context

ADR-0022 makes exact snapshots depend on two things.
The first is a capture barrier: the agent's whole process tree frozen in a cgroup v2 freezer while the workspace is captured.
The second is protected storage: a custodian under a distinct host UID, so that a same-uid agent can never mutate retained snapshot state, in either mode, during or between runs.
ADR-0022 also leaves the custodian's bootstrap authorization unselected, and makes rewind sources, history reads and pruning unavailable until that authorization exists.

The custodian has no selected design for its hardest part, so under ADR-0022 rewind can never ship.
The barrier, by contrast, can be built and tested now: a privileged dev container and CI runners give a writable cgroup v2 on the reference kernel.
Enforce mode already gives the supervisor what the custodian was meant to provide during a run: a seccomp decision layer in front of every path the agent opens, and a Landlock domain the agent cannot leave.

## Decision

Snapshots, rewind and diff ship with the ADR-0022 capture barrier and without the custodian, under these rules.

### Scope

1. Snapshots exist only in enforce mode, and only when the operator passes `--snapshots`.
   Record-only runs refuse `--snapshots` before spawn.
   Without a policy domain, nothing keeps a record-only agent inside the freezer cgroup or away from the store.
2. A host without a writable, delegated cgroup v2 with working `cgroup.freeze` and `cgroup.kill` refuses `--snapshots` before spawn.
   The message names `systemd-run --user --scope -p Delegate=yes`, a hint that is unverified until a CI leg runs it.
   Leash creates the run cgroup as a child of its own cgroup and enables no controllers in it.
   `cgroup.freeze` and `cgroup.kill` are core files and need none, so the cgroup v2 "no internal processes" rule does not apply (measurement 0003).

### Protection during the run

3. Every enforce run, with or without `--snapshots`, adds an implicit, first-ranked deny for the state root.
   It covers every open, read included, and every mutation of the state root or its ancestors, and is evaluated before policy rules.
   The deny also covers rename, removal and replacement of every ancestor directory of the state root.
   It matches by path identity, so a second mount of the same directory is a residual.
   Metadata reads (`stat`, `readlink`, `inotify_add_watch`) are unmediated.
   This implements what FR-21 already requires and `architecture.md` already claims.
4. A `--snapshots` run also adds an implicit, first-ranked deny for every cgroup2 mount in the mount namespace, read included.
   The read deny is depth.
   `clone3` returning `ENOSYS` (rule 7) is what closes `CLONE_INTO_CGROUP`, because `open_tree` and descriptor passing can still yield a directory descriptor.
5. Landlock cannot subtract a subtree from a grant.
   So a `--snapshots` run refuses before spawn when any Landlock grant with write, truncate, make, remove or refer rights covers the state root or any cgroup2 mount, as an ancestor or a descendant.
   A read-only overlap is allowed and is stamped into the trace as a single-layer residual: only the seccomp layer denies those reads.
6. A `--snapshots` run requires Landlock ABI 3 or higher, so path truncation is in the backstop.
   The refusal is tested through an injected probe, because no available host has an ABI below 3.
7. In a `--snapshots` run, `clone3` is answered `ENOSYS` before its argument struct is read.
   The denial is recorded as an event.
   The struct lives in agent memory, so a flag check would race.
   C libraries fall back to `clone`, which has no cgroup argument.
8. In a `--snapshots` run, legacy AIO (`io_setup`, `io_submit`) is denied and recorded.
   The freezer stops tasks, not in-flight I/O.
9. The supervisor marks itself non-dumpable before it starts the broker.
   Landlock's ptrace scoping already blocks `/proc/<supervisor>/fd` in enforce mode; this is depth.

### Capture barrier

10. The ADR-0022 barrier applies, with this exact order.
    The supervisor answers the current notification, stops receiving, writes `cgroup.freeze=1`, and waits boundedly for `frozen=1`.
    It captures, re-reads `frozen=1`, publishes the snapshot durably, writes the step event, writes `cgroup.freeze=0`, and resumes receiving.
    It never receives a notification between freeze and thaw.
    The loop answers each notification before it polls for a boundary, ask prompts included, so no received-but-unanswered notification exists when a freeze starts.
11. A freeze that does not complete in time aborts the run closed and kills the whole cgroup.
    An agent that parks a thread on its own nested seccomp listener reaches this path.
12. In a `--snapshots` run, the run ends when the root process exits.
    Leash then writes `cgroup.kill`, records that, waits boundedly for `populated=0`, and takes the final snapshot.
    Every abort path kills the whole cgroup.
13. The run takes an exclusive workspace lock (an `flock` under the state root) at start.
    External writers remain the operator contract of ADR-0022.
14. Captures enforce hard limits on entry count, total bytes, per-file apparent size and store growth, and a minimum interval between boundaries.
    Each step event records the capture pause.

### At rest

15. Snapshots at rest are ordinary files owned by the operator.
    A process running as the operator can rewrite them, including the same agent in a later record-only run.
    Content hashes detect corruption, not forgery: a rewritten manifest with matching new objects passes them.
16. To narrow forgery, each step event carries its manifest digest and `run_end` carries a chain head over all digests, printed at run end.
    The chain is recomputed from the manifests, never read from the trace.
    Each step digest is printed when committed, so a crashed run has one.
    Pre-rewind snapshots are outside the chain.
    `leash rewind --expect <digest>` refuses a store that does not match.
    Rewind prints a change summary before it applies anything.

### Rewind

17. Rewind requires the run's cgroup to be gone, not a `run_end` event, so a crashed run can be rewound.
    Every `leash run` and `leash rewind` kills and removes stale run cgroups that run metadata names.
    A run cgroup is stale when its run lock can be taken.
    Only a Leash-named child of Leash's own cgroup is killed; a name from metadata is validated first.
18. Rewind targets only steps with a committed step event.
    Without `--step`, it restores step 0, the workspace as it was before the agent started.
19. Rewind takes the workspace from the working directory or a flag, and refuses when it differs from the run metadata.
20. Rewind treats the store as hostile input.
    It validates every manifest path (relative, no empty, `.` or `..` component), applies changes with `openat2` and `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` from a workspace directory handle, writes a temporary file and renames it into place, never writes in place, hashes the bytes it writes, and refuses to run as root.
21. Rewind first snapshots the current workspace, so every rewind can be undone.
    The agent can plant an entry that capture refuses, for example `mknod(S_IFSOCK)`, a mode-000 file, or a cap overrun.
    If that snapshot cannot be taken, rewind refuses and names `--no-undo`, which skips it.
22. Rewind reverses filesystem effects only, and says so.

## Consequences

ADR-0022's "both modes" and "same-uid permissions are not protection" statements no longer hold for this implementation.
The traded invariant is protection of retained snapshots against the same uid, by any process outside the run's tree, during or between runs.
Examples are a concurrent record-only run and an enforce run with another `--state-dir`.
It is replaced by protection during the enforce run (two layers for writes, one named layer for reads that a policy allows), corruption detection at rest, and forgery detection when the operator passes `--expect`.
Rewind is confined beneath the workspace, so a forged store can only produce workspace content, never a write elsewhere.

FR-8, FR-11, FR-12, FR-19, FR-21 and SR-4 change in SPEC v0.10 to match.
`escapes.md` names four residuals.
The first is at-rest forgery without `--expect`.
The second is single-layer reads of the store under a read grant.
The third is metadata-only calls (`fchmodat2`, `utimensat`, xattr calls) that are unmediated and outside Landlock, which can deny a rewind but cannot forge one.
The fourth is an out-of-tree helper reached through an allowed channel, such as policy-allowed localhost TCP: such a helper is unfrozen and unconfined.
The custodian stays in ADR-0022 as future hardening, and would restore the traded invariant.
Overlay remains gated by ADR-0009 and ADR-0022.

## Alternatives considered

- Build the custodian first: blocked on an unselected bootstrap authorization; no date.
- Record-only snapshots with a subtracting Landlock ruleset: Landlock grants cannot subtract, and enumerating siblings breaks files created later.
- Check `CLONE_INTO_CGROUP` in the `clone3` struct: the struct is in agent memory and can change after the check.
- Keep answering notifications during the freeze wait: lets mutations in after the boundary decision.
- Snapshots on by default in enforce mode: would break enforce runs on every host without a delegated cgroup.
