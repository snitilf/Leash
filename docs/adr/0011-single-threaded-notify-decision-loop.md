# ADR-0011: Single-threaded notify decision loop

- Status: accepted
- Date: 2026-07-07

## Context

Every mediated syscall is delivered to the supervisor as a notification on the seccomp notify
fd. The supervisor must, per notification: validate it, gather facts (which may include reading
the child's memory), evaluate the policy, record an event, and respond. Something has to decide
how many of these are in flight at once.

The forces pull in opposite directions. Latency (NFR-2) argues for concurrency: while one
notification waits on an ask (FR-10), others could proceed. Auditability (NFR-6) and
fail-closed integrity (NFR-1, FR-9) argue against it: the recorder is single-writer (ADR-0002),
the trace is an ordered sequence (FR-2), and every error path in the loop must provably resolve
to deny. Concurrent decision handling means shared state, lock ordering, and interleavings that
multiply the paths a reviewer and the escape tests must cover.

## Decision

The supervisor processes notifications on a single decision thread: one notification is
received, decided, recorded, and responded to before the next is received. Event order in the
trace is decision order. There is no worker pool and no per-notification thread.

An ask (FR-10, FR-20) blocks the loop until the operator answers or the timeout denies. Other
mediated syscalls in the child tree stall behind it.

## Consequences

- The fail-closed enumeration (FR-9) stays finite and checkable: one loop, one state machine,
  every error arc visibly terminating in deny. This is the property NFR-6 demands of the
  decision path.
- The recorder needs no synchronization; single writer, single thread, trace order is
  decision order (ADR-0002, FR-2).
- A pending ask stalls the entire child tree, not just the asking process. Accepted: an ask
  already pauses the child by design, and a stalled sibling merely observes a slow syscall.
- Mediation latency is serialized. If M1 measurements (NFR-2, OQ-5) show the loop itself is the
  bottleneck on real agent workloads, revisiting this decision means superseding this ADR, with
  the burden of re-proving the ordering and fail-closed arguments under concurrency.

## Alternatives considered

- Thread-per-notification: minimal latency, but decision-time state is shared across threads,
  trace ordering needs a serialization point anyway, and the fail-closed proof must cover
  cross-thread interleavings. Rejected: the correctness surface grows faster than the latency
  shrinks, and no measurement yet shows the latency matters.
- Fixed worker pool: same shared-state and ordering problems as thread-per-notification, with
  added queueing policy to specify and test. Rejected for the same reasons.
- Single-threaded loop with async ask (park the asking notification, keep serving others):
  the most likely future refinement, since it removes the whole-tree stall without full
  concurrency. Rejected for now: it reintroduces out-of-order responses and a parked-state
  cleanup path (what happens when the child dies while parked) that v1 does not need to carry.
