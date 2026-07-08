# ADR-0009: Snapshot mechanism is overlayfs, with a plain-copy fallback

- Status: accepted (M0 gate clause refined by ADR-0014)
- Date: 2026-07-07

## Context

ADR-0005 commits Leash to time travel by workspace snapshots. The mechanism that captures a
snapshot is hard to reverse: rewind (FR-12) and diff (FR-13) inherit its semantics, and its
per-snapshot cost bounds how often a step boundary is affordable (FR-11). Candidates: overlayfs
upper-layer capture, copy-on-write filesystem snapshots (btrfs/ZFS), and per-step file copies.
The tool must work on ordinary hosts (ext4 is the common default) and on both reference targets
(Raspberry Pi and VPS, FR-15).

## Decision

The workspace is mounted with an overlayfs write layer for the duration of a run; the agent's
writes land in the upper layer while the lower layer stays untouched. A snapshot is a capture of
the upper layer at a step boundary, so snapshot cost scales with what changed, not with workspace
size. Where an overlay mount is unavailable (privileges, kernel config, filesystem), Leash falls
back to a documented plain-copy mechanism with the same observable rewind/diff behavior, and the
trace records which mechanism was active.

This decision is gated on a validation spike (milestone M0) proving overlay mount, capture,
rewind, and whiteout/rename handling on both reference targets before the design freezes. If the
spike fails on a target, this ADR is superseded rather than quietly bent.

## Consequences

- Snapshots are cheap and proportional to change size, which keeps frequent step boundaries
  affordable and feeds the step definition (OQ-1).
- Rewind is layer manipulation, not file surgery: restoring a snapshot means replacing the upper
  layer, which is fast and easy to reason about.
- Diff must interpret overlay write-layer semantics correctly (whiteouts for deletions, renames,
  hard links), which FR-13 already requires.
- Two mechanisms must stay behaviorally equivalent, which costs a shared test suite run against
  both.
- Overlay mounting needs privileges or unprivileged user namespaces; host support becomes part of
  the preflight check alongside the FR-14 kernel floor.

## Alternatives considered

- **Copy-on-write filesystem snapshots (btrfs/ZFS).** Rejected as primary: near-free where
  available, but most hosts run ext4, so the common case would fall to a fallback anyway.
- **Per-step copies as primary.** Rejected: cost scales with workspace size, making meaningful
  step frequency unaffordable on real workspaces (dependency trees, build artifacts). Retained
  as the fallback because it works anywhere.
- **No fallback (overlayfs or refuse).** Rejected: rewind is a headline capability; refusing to
  snapshot on unsupported hosts fails the operator harder than a slower fallback does.
