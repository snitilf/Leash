# Snapshots, rewind, and diff

- Status: provisional, gated on the ADR-0009 M0 validation spike (issue #13). Settles when the
  spike passes on both reference targets; if it fails on a target, ADR-0009 is superseded and this
  file is rewritten around the surviving mechanism.
- Governs: how workspace state is captured at step boundaries, how rewind restores it, and how
  diff compares two runs or steps.
- Cites: FR-11, FR-12, FR-13, FR-17, FR-21; NFR-4, NFR-5; SR-2; ADR-0005, ADR-0006, ADR-0009.
  Invariants I1, I5 are defined in [`architecture.md`](architecture.md).

Time travel in Leash operates on effects, not the agent (ADR-0005): the **workspace**'s write
layer is captured as **snapshots** at **step** boundaries (FR-11), **rewind** restores the
workspace to one of them (FR-12), and **diff** compares the filesystem effects of two runs or
steps from theirs (FR-13). The agent is never re-run; a language model is non-deterministic, so
re-execution would not reproduce the run and no such claim is made. Everything in this file is
owned by the `snapshot` module ([`architecture.md`](architecture.md) section 4): it mounts and
captures the overlay or the copy fallback and implements rewind and diff, and none of it sits on
the decision loop's hot path. Snapshots persist under the per-run directory (FR-21,
[`trace.md`](trace.md) section 1). Terms in **bold** are defined in
[`../CONTEXT.md`](../CONTEXT.md).

## 1. Step detection (FR-17)

A **step** is a coalesced burst of the child's mediated filesystem writes. Steps are derived from
the timestamps of the mutating mediated **events** the notify loop already produces: open-for-write
([`syscalls.md`](syscalls.md) section 2) and the mutation family, create, rename, unlink, mkdir,
link, symlink, truncate ([`syscalls.md`](syscalls.md) section 3.2). This is exactly the
"supervisor-observed events" FR-17 requires (ADR-0006), and it needs no per-`write` trap: Leash
does not mediate `read`/`write` at all, per the fd-authorization model, so per-byte activity is
invisible by design and the step clock ticks on the events that introduce or mutate paths. Because
every process in the tree is mediated (I1), the step clock sees a grandchild's writes as readily as
the agent's; a subshell writing files is not a blind spot.

The boundary falls when mutating-event activity quiesces for longer than a coalescing window. The
window's value is an open parameter (the [`README.md`](README.md) table), to be set from real
measurement at slate 3 with M1 as the closing trigger, not guessed. Two properties are fixed
regardless of the value: the boundary MUST NOT fall inside a burst, and run start and run end are
always step boundaries, so every run has at least the initial and final snapshots even if the agent
never writes. Each boundary emits a `step` event into the trace ([`trace.md`](trace.md) section 2)
and triggers a capture (section 2).

One gap, stated honestly: writes through a `mmap(MAP_SHARED)` mapping are not syscalls. They
produce no mediated event, so they cannot drive step timing; a burst of shared-mapping stores looks
like quiescence to the step clock. Content is not lost: the snapshot captures the actual resulting
filesystem state at the next boundary (the overlay holds real file content, not syscall-derived
state), so what the agent produced is always in some snapshot. The cost is granularity only: for an
mmap-heavy writer, changes land in the step whose boundary follows them rather than defining steps
of their own. This is a named residual, enumerated in [`escapes.md`](escapes.md).

## 2. Overlay mechanism (ADR-0009)

For the duration of a run the workspace is mounted with an overlayfs write layer: the real
workspace directory is the `lowerdir` and stays untouched, the child's writes land in an
`upperdir`, and overlayfs uses a `workdir` for its internal atomicity. A **snapshot** is a capture
of the upper layer at a step boundary. Because the upper layer contains only what changed, snapshot
cost scales with the size of the change, not the size of the workspace, which is what makes
frequent step boundaries affordable on a Raspberry Pi 4 class device (NFR-4) and on workspaces with
large dependency trees.

Upper-layer semantics are not a plain file tree, and everything downstream inherits them:

- A deletion is a **whiteout**: a character device with device number 0/0 in the upper layer, not
  an absence. A naive reader sees a device node where the agent deleted a file.
- A directory whose lower contents should stop showing through carries an **opaque marker**
  (the `trusted.overlay.opaque` xattr, or its user-namespace equivalent); readers must treat the
  directory as replacing, not merging with, the lower one.
- A rename or hard link that crosses layers forces a copy-up, so the upper layer records it as new
  content plus a whiteout at the old name, not as a rename.

The mechanism actually in use (overlay or the fallback of section 3) is selected at preflight and
stamped into the trace via `meta.json` ([`architecture.md`](architecture.md) section 5.1), so a
reader of a run always knows which semantics its snapshots carry.

## 3. Copy fallback (ADR-0009)

Overlay mounting needs either privilege or an unprivileged user namespace with overlay support,
and availability varies by kernel config, distro policy, and filesystem. Preflight probes both
routes; where neither works, Leash falls back to a documented plain-copy mechanism: the workspace
is copied per step instead of layered. The fallback MUST have the same observable rewind and diff
behavior as the overlay (ADR-0009), which is a shared test obligation: the equivalence suite runs
against both mechanisms, and a behavior only one of them exhibits is a bug in one of them. The
fallback's cost scales with workspace size rather than change size, which is exactly why it is the
fallback and not the default; it exists because rewind is a headline capability and refusing to
snapshot on an unsupported host fails the operator harder than a slower mechanism does.

## 4. Rewind (FR-12)

`leash rewind` restores the workspace to a chosen earlier snapshot. With the overlay it is layer
manipulation, not file surgery: the current upper layer is swapped for the captured one, which is
fast, proportional to change size, and easy to reason about. With the copy fallback it is restoring
the copied tree. Rewind targets are step boundaries; there is nothing between boundaries to rewind
to, because the boundary is where state was captured.

Rewind reverses filesystem effects only. It MUST NOT claim to reverse effects already emitted
off-host: a network send, an external API call, a pushed commit. Those are recorded in the trace
but are not reversible, and no Leash output implies otherwise (FR-12, ADR-0005). The word for this
operation is rewind; it never means re-running the agent.

## 5. Diff (FR-13)

`leash diff` compares the filesystem effects of two runs, or two steps, computed from their
snapshots. It MUST interpret write-layer semantics, never naively compare file trees. Each of the
following is a named case the diff handles and tests:

- **Whiteouts.** A char 0/0 device in the upper layer reads as "deleted", not as a created device
  node.
- **Opaque directories.** An opaque-marked directory reads as a replacement of the lower directory,
  so lower entries absent from it are deletions, not unchanged files.
- **Cross-layer renames.** A copied-up file plus a whiteout at the old name reads as a rename where
  that is recoverable, and at minimum never reads as an unrelated create-plus-delete of identical
  content without noting the relation.
- **Hard links.** Two upper-layer names for one inode read as one change, not two independent
  files; link count changes are reported as such.

The same cases apply to the copy fallback through the equivalence obligation of section 3: the
fallback's capture format must preserve enough to answer them identically.

## 6. Escape and fault surface (SR-2, NFR-5)

Two families of hostile input bear on this file, both enumerated and tested in
[`escapes.md`](escapes.md) (planned; written last, as the traceability layer over the rest of the
design):

- **Rename and hard-link races on the overlay** (SR-2): the child racing capture with renames or
  link games to smuggle content past a snapshot boundary or to make the diff misattribute a change.
  The single-threaded decision loop and supervisor-side execution of the mutation family bound what
  a race can do, but the overlay-level behavior is claimed only when the escape tests pass.
- **Resource exhaustion**: a fork bomb or a deliberate fill-the-upper-layer loop turning the
  snapshot mechanism into a disk-exhaustion vector. The backstop is an upperdir size limit, an open
  parameter in the [`README.md`](README.md) table (slate 3); hitting it resolves per fail-closed,
  the run stops rather than the host filling.

Per I5 and NFR-5, no reversibility claim is made anywhere (docs, report, pitch) until the
write-layer-semantics tests of section 5 pass. Until then, rewind and diff are described as
implemented, not as correct.

## 7. The M0 spike checklist

This section doubles as the acceptance criteria of the ADR-0009 validation spike (issue #13). The
spike is run by the operator on both reference targets, the Raspberry Pi and the KVM VPS (FR-15,
NFR-4), because it needs the physical hardware; the spike scripts can be authored in advance. On
each target:

- [ ] overlay mount of a workspace via privileged mount
- [ ] overlay mount via an unprivileged user namespace
- [ ] upper-layer capture at a boundary while the mount is live
- [ ] rewind to an earlier snapshot restores the workspace exactly
- [ ] whiteout handling: a deletion reads as a deletion, in capture, rewind, and diff
- [ ] cross-directory rename handling: copy-up plus whiteout is interpreted correctly
- [ ] hard-link handling: linked names are attributed to one inode
- [ ] the copy fallback, on a host (or configuration) where overlay is unavailable, produces
      identical observable rewind and diff behavior

The gate, per ADR-0009's own text: all items pass on both targets, and this file settles and the
design layer can freeze; any target fails, and ADR-0009 is superseded rather than quietly bent,
with this file rewritten around the surviving mechanism.
