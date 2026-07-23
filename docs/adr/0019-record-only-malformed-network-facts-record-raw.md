# ADR-0019: A network address the supervisor cannot decode records raw and continues in record-only

- Status: accepted
- Date: 2026-07-23

## Context

Every network decision is built from a `sockaddr` read out of child memory under a 128-byte cap
([`../design/notify-loop.md`](../design/notify-loop.md) section 2).
When that read fails, comes back short, or carries an address family the supervisor does not
decode, there is no trusted typed fact to decide on.
The fail-closed enumeration resolves that arc as case C, and case C denies.

FR-9 and invariant I3 state the rule with no mode qualifier: any supervisor error resolves the
pending action to deny.
ADR-0010 states the opposing pressure just as plainly.
Record-only enforces nothing, is described as a camera rather than a bouncer, and FR-19 permits
exactly one class of record-only denial: the SR-4 denied-and-recorded set of syscalls that would
establish an un-mediated I/O path.
A `connect` whose address the supervisor cannot decode is not one of those.

Denying it in record-only would constrain a run the operator was told constrains nothing, and it
would do so on a path the child chooses: passing a short or exotic `sockaddr` is enough to trigger
it.
That hands a child a way to make its own syscalls fail, and hands the operator an enforcement
effect the mode's contract disclaims.
The M2 network slice landed taking the ADR-0010 reading in code
(`src/supervisor/run.rs`, `record_network_read_failure`), which is what forced the question into
the open.

## Decision

The case-C arc is scoped by mode, for the network family alone.

- In **enforce** mode a network address the supervisor cannot decode denies fail-closed, recorded
  as a `raw` event under the `failsafe:memory_read` base id.
- In **record-only** mode it records a `raw` event under the `base:record_only` id and the syscall
  continues.

Everything else in the enumeration stays fail-closed in both modes.
A path or `clone_args` that cannot be read or decoded denies in both modes, because those families
carry the mediation FR-4 puts at the centre of the mediated set and a silent gap there would
misrepresent what the child did to the filesystem.
The SR-4 denied-and-recorded set denies in both modes.
Recorder-write failures, supervisor crashes, and decision timeouts deny in both modes.

This refines one clause of ADR-0017, which read "case-C memory-read failures deny in both modes".
The decision ADR-0017 records, that record-only allows are realized with `CONTINUE`, stands
unchanged.

## Consequences

- FR-9 and I3 now carry an explicit mode scope for this one arc, and NFR-1 carries the sentence
  that keeps the three consistent: not failing open is a property of what a mode claims to
  enforce, and record-only claims nothing outside SR-4.
  The change is recorded in the spec rather than in the design alone, because it changes what the
  system does.
- A residual follows, and it is named in [`../design/escapes.md`](../design/escapes.md) section 4:
  in record-only a child can make a network attempt whose destination the trace cannot name, by
  handing `connect` a `sockaddr` the supervisor will not decode.
  The event is still written, so the attempt stays visible and the trace is not silently
  incomplete; only the destination is missing.
  It weakens no enforcement claim, because record-only makes none.
- Enforce mode is untouched, so nothing here shortens the enforcement slice.
  The escape test for this arc is bound to enforce mode, where the denial is a claim (I5, NFR-5).
- The mode asymmetry is now something a reader must hold in mind when reading the fail-closed
  table, which is a real cost.
  It is bounded by being one row, scoped to one family, with the reason written into the row.

## Alternatives considered

- **Deny in both modes, the unqualified reading of FR-9.** Rejected: it makes record-only enforce
  on a path FR-19 does not list, and lets a child block its own syscalls through a supervisor
  limitation rather than through a policy.
  It breaks the mode contract operators calibrate their trust on, which is the thing FR-19's last
  sentence exists to protect.
- **Allow in both modes.** Rejected outright: that is a fail-open in the mode that makes an
  enforcement claim, which NFR-1 forbids and no residual could excuse.
- **Widen the carve-out to every case-C arc in record-only.** Rejected: an undecodable path is a
  filesystem action the trace would misrepresent, and the filesystem family is the centre of FR-4's
  mediated set.
  The network family is scoped here because its fact is a fixed-size struct with a decode step,
  which is where this failure actually lives.
- **Record the narrowing in the design layer only.** Rejected: ADRs are immutable, and a clause of
  ADR-0017 is being narrowed, so the refinement needs its own numbered decision
  ([`README.md`](README.md)).
