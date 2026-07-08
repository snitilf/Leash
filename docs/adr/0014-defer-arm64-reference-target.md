# ADR-0014: Defer the ARM64 reference target; the M0 gate is x86-64 only

- Status: accepted
- Date: 2026-07-08

## Context

The spec (v0.3) named two reference targets: an x86-64 KVM VPS and an ARM64 Raspberry Pi (FR-15,
NFR-4). ADR-0009 gated the design freeze on the M0 overlay spike passing on both. The x86-64 leg
ran on 2026-07-08 (Ubuntu 24.04, kernel 6.8) and passed every privileged-path item: mount, capture,
rewind, whiteout, cross-directory rename, hard link, and copy-fallback equivalence. One checklist
item was skipped, not failed: the unprivileged-user-namespace overlay mount, because stock Ubuntu
24.04 blocks unprivileged userns creation outright (`apparmor_restrict_unprivileged_userns=1`)
before overlay is ever attempted. The Raspberry Pi will not be used, so the ARM64 leg has no
hardware to run on. Holding the design freeze on a leg that will never run blocks all
implementation for no evidence gain.

## Decision

The ARM64/Raspberry Pi reference target is deferred, recorded in the spec as OQ-9 (spec v0.4
narrows FR-15 to x86-64 and drops NFR-4's Pi clause). ADR-0009's freeze gate is narrowed to the
x86-64 leg. The skipped unprivileged-userns item is accepted as a documented host-class limitation,
not a failure: on hosts that block unprivileged user namespaces, a privileged overlay mount or the
copy fallback carries the mechanism, which the design already provides (snapshot.md section 3, the
preflight probe in architecture.md section 5.1). With that, the M0 gate is met, snapshot.md
settles, and the design layer can freeze.

## Consequences

- Implementation is unblocked; the design layer freezes on x86-64 evidence alone.
- No ARM64 claim is made anywhere until OQ-9 closes: reopening requires the M0 spike's ARM64 leg
  to pass on hardware and the syscall table's ARM64 column to be validated there. The spike script
  runs unchanged for that leg.
- syscalls.md keeps its "Also on ARM64" columns as documentation for the deferred target; they
  carry no support claim.
- The rootless-overlay route is known to be unavailable on a common host class; the preflight
  probe distinguishes that case and stamps the selected mechanism and reason into the trace.

## Alternatives considered

- **Run the ARM64 leg anyway.** Rejected: there is no hardware and no planned use; the evidence
  would validate a target nobody runs.
- **Drop ARM64 from the spec entirely.** Rejected: deferral with a named trigger preserves the
  option and the honesty rule (no claim without a test) equally well, and the syscall table's
  ARM64 groundwork keeps its value.
- **Keep the gate as-is and freeze anyway.** Rejected: a gate that is quietly waived stops being
  a gate. Narrowing it in a recorded decision is the honest form.
