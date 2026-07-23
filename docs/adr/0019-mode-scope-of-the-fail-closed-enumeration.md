# ADR-0019: Which fail-closed arcs are scoped by mode, and which are not

- Status: accepted
- Date: 2026-07-23

## Context

FR-9 and invariant I3 state the fail-closed rule with no mode qualifier: any supervisor error
resolves the pending action to deny.
ADR-0010 states an opposing pressure just as plainly.
Record-only enforces nothing, is described as a camera rather than a bouncer, and FR-19 permits
exactly one class of record-only denial: the SR-4 denied-and-recorded set of syscalls that would
establish an un-mediated I/O path.

The M2 slice landed two arcs that split by mode, and neither split was written down as a decision.
Both are cases where the supervisor cannot build a trustworthy fact, so the two looked alike in
code, and the record-only leg of each was implemented as an allow
(`src/supervisor/run.rs`, `record_network_read_failure` and the `PIDFD_GETFD` branch).
Reading them as one class is the error this ADR corrects.
What matters is not whether the fact can be built, but whether letting the syscall through leaves
the trace able to describe what the child then did.

A `sockaddr` the supervisor cannot decode is one case.
The `connect` still goes through a socket the supervisor watched the child open, and the event is
still written; only the destination is missing.

`pidfd_getfd` is the other, and it is not the same case.
It pulls a file descriptor out of another process, which is the fd-inheritance escape in syscall
form ([`../design/syscalls.md`](../design/syscalls.md) section 3.4).
The imported fd names a resource no mediated syscall ever decided, so every later `read` or `write`
on it is I/O the trace cannot attribute to anything.
That is the definition SR-4 uses, and SR-4 is the one exception FR-19 already carves out of
record-only non-enforcement.

## Decision

Two arcs, two different answers.

**The undecodable network address is scoped by mode.**

- In **enforce** mode a network address the supervisor cannot decode denies fail-closed, recorded
  as a `raw` event under the `failsafe:memory_read` base id.
- In **record-only** mode it records a `raw` event under the `base:record_only` id and the syscall
  continues.

**`pidfd_getfd` is not scoped by mode.**
It joins the SR-4 denied-and-recorded set of
[`../design/syscalls.md`](../design/syscalls.md) section 5, alongside `io_uring_setup`, and is
denied and recorded in **both** modes under the `sr4:pidfd_getfd` base id.
Denying it in record-only is not policy enforcement, exactly as the `io_uring_setup` denial is not:
no rule is involved, and the refusal is what stops the trace lying about I/O the child performed.
The v1 design already said `pidfd_getfd` is denied outright, with no mode qualifier
([`../design/syscalls.md`](../design/syscalls.md) section 3.4,
[`../design/escapes.md`](../design/escapes.md) section 3), so the record-only allow in the shipped
code is a defect against the design rather than a decision this ADR reverses.
The runtime correction lands in the issue #26 implementation PR; until it does, the shipped build
allows `pidfd_getfd` in record-only, and that gap is named in
[`../design/escapes.md`](../design/escapes.md) section 4.

Everything else in the enumeration stays fail-closed in both modes.
A path or `clone_args` that cannot be read or decoded denies in both modes, because those families
carry the mediation FR-4 puts at the centre of the mediated set and a silent gap there would
misrepresent what the child did to the filesystem.
The rest of the SR-4 denied-and-recorded set denies in both modes.
Recorder-write failures, supervisor crashes, and decision timeouts deny in both modes.

This refines one clause of ADR-0017, which read "case-C memory-read failures deny in both modes".
The decision ADR-0017 records, that record-only allows are realized with `CONTINUE`, stands
unchanged.

## Consequences

- FR-9 and I3 carry an explicit mode scope for the network arc, and NFR-1 carries the sentence that
  keeps the three consistent: not failing open is a property of what a mode claims to enforce, and
  record-only claims nothing outside SR-4.
  The change is recorded in the spec rather than in the design alone, because it changes what the
  system does.
- SR-4 now names `pidfd_getfd` alongside `io_uring_setup`, so the class has two members and the
  test for "must record-only deny this" has one answer: does letting it through create I/O the
  trace cannot see.
- A residual follows from the network arc, and it is named in
  [`../design/escapes.md`](../design/escapes.md) section 4: in record-only a child can make a
  network attempt whose destination the trace cannot name, by handing `connect` a `sockaddr` the
  supervisor will not decode.
  The event is still written, so the attempt stays visible and the trace is not silently
  incomplete; only the destination is missing.
  It weakens no enforcement claim, because record-only makes none.
- A second residual, this one temporary, follows from the `pidfd_getfd` gap between this decision
  and the implementation PR.
  It is named in the same section so it cannot be lost between the two PRs.
- The cost of the network carve-out is that a reader of the fail-closed table must hold one mode
  asymmetry in mind.
  It is bounded by being one row, scoped to one family, with the reason written into the row.

## Alternatives considered

- **Deny both arcs in both modes, the unqualified reading of FR-9.** Rejected for the network arc:
  it makes record-only enforce on a path FR-19 does not list, and lets a child block its own
  syscalls through a supervisor limitation rather than through a policy.
  It breaks the mode contract operators calibrate their trust on, which is what FR-19's last
  sentence exists to protect.
  Accepted for `pidfd_getfd`, where the un-mediated I/O path makes it an SR-4 member.
- **Scope both arcs by mode, treating "the fact cannot be built" as one class.** Rejected: this is
  the reading the shipped code took, and it lets record-only import an fd whose later I/O the trace
  cannot attribute, which is the silent incompleteness SR-4 exists to prevent.
- **Allow the network arc in both modes.** Rejected outright: that is a fail-open in the mode that
  makes an enforcement claim, which NFR-1 forbids and no residual could excuse.
- **Widen the network carve-out to every case-C arc in record-only.** Rejected: an undecodable path
  is a filesystem action the trace would misrepresent, and the filesystem family is the centre of
  FR-4's mediated set.
  The network family is scoped here because its fact is a fixed-size struct with a decode step,
  which is where this failure actually lives.
- **Record the narrowing in the design layer only.** Rejected: ADRs are immutable, and a clause of
  ADR-0017 is being narrowed, so the refinement needs its own numbered decision
  ([`README.md`](README.md)).
