# The notify loop

- Status: settled (slate 2 closed 2026-07-08)
- Governs: the protocol the supervisor runs on the seccomp notification fd, how it reads child
  memory safely, and how every error path resolves to deny.
- Cites: FR-2, FR-3, FR-9, FR-10, FR-20; NFR-1, NFR-6; SR-2, SR-3; ADR-0002, ADR-0011, ADR-0012.
  Invariants I2, I3, I4, I5 are defined in [`architecture.md`](architecture.md).

This is the state machine that turns one `seccomp_notif` into one **decision** and one **event**. It
runs on the single decision thread (ADR-0011). Which syscalls arrive here, and how each allow is
realized, are in [`syscalls.md`](syscalls.md); the two files share the allow-realization rule in
section 4 there and section 3 here, and must agree. Terms in **bold** are in
[`../CONTEXT.md`](../CONTEXT.md).

## 1. The happy path

One notification, start to finish, before the next is received (ADR-0011):

1. **Receive.** `ioctl(SECCOMP_IOCTL_NOTIF_RECV)` returns a `seccomp_notif`: the notification id, the
   child pid, the syscall number, and the register arguments (a kernel-trusted snapshot at trap
   time).
2. **Validate.** `ioctl(SECCOMP_IOCTL_NOTIF_ID_VALID)` confirms the notification is still live (the
   child has not died, the id has not been reused). If it fails, the child is gone; there is
   nothing to release (section 4, case B).
3. **Gather facts.** Register arguments are used directly. Any **pointer** argument (a path, a
   `sockaddr`) is read from `/proc/<pid>/mem` at the address the registers give, into a bounded
   buffer, and `ID_VALID` is re-checked immediately after the read so a stale read is discarded
   (section 2). The result is a typed fact: syscall, resolved path or address, access mode, pid.
4. **Evaluate.** The typed fact goes to the pure `policy` engine (ADR-0004), which returns a decision
   (allow / deny / **ask**) and the id of the matched rule. The engine reads no memory and performs
   no IO (NFR-6); everything it needs is in the fact.
5. **Record.** The `recorder` writes the event (syscall, fact, decision, matched-rule id, mode,
   timestamp) before the response is sent. The ordering is deliberate and load-bearing: see
   section 3.
6. **Respond.** `ioctl(SECCOMP_IOCTL_NOTIF_SEND)` carries the response: `CONTINUE`, an errno (deny or
   the spoofed return of a supervisor-executed operation), or an `ADDFD` injection whose return value
   is the injected fd number, done atomically with `SECCOMP_ADDFD_FLAG_SEND` so the inject and the
   response are one step. Which one is fixed by the allow-realization rule.
7. **Loop.** Receive the next notification.

An **ask** (FR-10) suspends step 4 until the operator answers or the timeout fires; this is the only
intentional block in the loop, and it is bounded (section 5). Every other step is bounded by
construction: the memory read is size-capped, the engine is total, the recorder write is a bounded
append.

## 2. Reading child memory safely

The child's pointer arguments are the whole TOCTOU problem (SR-2, I4). The rules:

- Never dereference a child pointer in the supervisor's own address space. Read it out of
  `/proc/<pid>/mem` at the address from the trap-time registers.
- Bracket the read with `ID_VALID`: check validity, read, check validity again. A read that spans the
  child's death is discarded, and the id cannot have been silently reused underneath it.
- Cap every read. The caps, fixed at slate 2, are the kernel's own limits: 4096 bytes for a path
  (`PATH_MAX`), 128 bytes for a `sockaddr` (`sizeof(struct sockaddr_storage)`), the current kernel
  struct size for `clone_args` (and likewise for `openat2`'s `open_how`, read under the same
  struct-size rule), and one page as the absolute ceiling for any read. An unbounded or
  attacker-chosen length is a denial-of-service on the single decision thread; over the cap
  resolves to deny (section 4, case C), because a value larger than the kernel itself would accept
  is hostile by definition.
- The value read is used once, to build the typed fact, and for a pointer-argument allow it is never
  handed back to the child as a re-editable argument. That is why the allow-realization rule
  (section 3) forbids `CONTINUE` for pointer-argument decisions: `CONTINUE` re-reads child memory at
  kernel-execution time, reopening the window this read just closed.

## 3. The allow-realization rule, and why record precedes respond

The rule from [`syscalls.md`](syscalls.md) section 4, restated so this file is self-contained:
`CONTINUE` only for a decision on the syscall number or scalar registers; `ADDFD` with a
supervisor-opened fd for a pointer-argument allow that returns an fd; supervisor-executed with a
spoofed return for a pointer-argument allow that returns no fd; `execve` alone allowed by `CONTINUE`
under the Landlock `FS_EXECUTE` backstop. The rule binds decisions that constrain: in
**record-only** mode every allow is realized with `CONTINUE`, the event carrying the once-read
value from step 3, and the residual is named in [`escapes.md`](escapes.md) section 4 (ADR-0017).

Record precedes respond (step 5 before step 6) because the **trace** is the authority (FR-3, I2): the
child must never take an action the supervisor could not record. If the recorder write fails, the
decision resolves to deny and the run aborts (section 4, case E) rather than release an unrecorded
action. This is the concrete meaning of "the supervisor is the sole author of the trace" on the write
path: an unrecordable allow is not an allow.

## 4. Fail-closed enumeration

Every way the loop can fail, and how each resolves to deny (FR-9, NFR-1, I3). The enumeration is
finite and checkable precisely because the loop is single-threaded (ADR-0011); each arc is listed
with the escape or fault test that proves it in [`escapes.md`](escapes.md) (I5). A deny is a decision
and is written as an event (FR-2); a dropped notification (case B, case I) made no decision and its
syscall never took effect, so it records none.

| # | Fault | Resolution | Why it does not fail open |
|---|---|---|---|
| A | `NOTIF_RECV` returns `EINTR` | retry the receive | no notification was dequeued; nothing is pending release |
| B | `ID_VALID` fails, or `RECV`/`SEND` reports the notification dead (the child exited, or a fatal signal is ending it) | drop the notification, continue | the child's syscall does not complete; there is nothing to release to a dead or dying process |
| C | child-memory read fails, or exceeds the size cap | deny (`SEND` an errno, e.g. `EACCES`) | a fact that cannot be trusted cannot be allowed (I4) |
| D | the `policy` engine cannot decide | impossible by construction: the engine is total and returns a decision for every fact; deny-by-default is the base rule in **enforce** mode (FR-19) | there is no undecided fact |
| E | the recorder write fails | deny this action, then abort the run and tear down | no allow the supervisor cannot record (section 3, FR-3) |
| F | an **ask** reaches its timeout (FR-10), or the run is unattended (FR-20) | deny | timeout-to-deny and unattended-to-deny are the specified behaviors |
| G | the supervisor process crashes or is killed | the kernel closes the notification fd; every pending and subsequent mediated syscall in the child fails (documented as `-ENOSYS` for the no-listener case) and none executes | the boundary holds by the action not taking effect; fail-closed is enforced by the kernel, not by supervisor code that is no longer running |
| H | the decision thread hangs on a non-ask step | prevented: every non-ask step is bounded (section 1); the only unbounded wait is the ask, which has a timeout (case F) | there is no unbounded blocking point outside the ask |
| I | a non-fatal signal to the child cancels a received notification, restarting the syscall | prevented by `WAIT_KILLABLE_RECV` (section 4.1); only a fatal signal cancels, and a child being killed does not need its action completed | a supervisor-performed side effect cannot run twice, and no event is recorded for an action that then restarts |

### 4.1 Signal cancellation and double execution

Without protection, a non-fatal signal delivered to a child blocked on a notification cancels it: the
supervisor's `SEND` fails `ENOENT`, and with `SA_RESTART` the syscall restarts and re-traps as a fresh
notification. For an allow realized by the supervisor performing the side effect and spoofing the
return (rename, unlink, mkdir, a host-enforced connect; [`syscalls.md`](syscalls.md) section 4), a
cancellation after the side effect but before `SEND` would re-trap the syscall and run the side effect
a second time, and the trace would already carry an event for a response that was never delivered.
Agents take `SIGCHLD` and timer signals routinely, so this is a normal path.

The filter is installed with `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (ADR-0012), which makes a
received notification interruptible only by a fatal signal. Once the supervisor has `RECV`d, the
notification will not be cancelled by an ordinary signal, so the perform-then-`SEND` sequence
completes; the only interruption left is a fatal signal, in which case the child is being killed and
its syscall correctly does not complete (case B). This is why the kernel floor is 5.19: the
supervisor-executed allow is unsound below the kernel that provides this flag.

Case G is the backstop under all the others and is the reason a supervisor bug cannot fail open: even
an outright crash degrades to the kernel denying the child's next mediated syscall. It carries one
subtlety to test, not assume (NFR-5): `-ENOSYS` must not let the child fall through to an
alternate code path that reaches the same effect un-mediated. The escape test kills the supervisor
mid-run and confirms the child's next `openat` and `connect` fail rather than succeed
([`escapes.md`](escapes.md)).

## 5. The ask, and the whole-tree stall

An **ask** blocks the decision loop until the operator answers or the FR-10 timeout denies. The
default timeout is 60 seconds, operator-configurable (slate 2): long enough for a person at the
keyboard, short enough to bound the stall described below. Under
ADR-0011 that stalls every other mediated syscall in the child tree behind it, which is the accepted
cost recorded in that ADR: the asking child is paused by design, and a sibling only observes a slow
syscall. The timeout is what bounds the stall and what makes case F above a finite arc rather than an
indefinite hang. In an unattended **run** the ask does not queue at all; it denies immediately
(FR-20), so the stall is an attended-run phenomenon only.

If M1 measurements show the ask stall is a real problem on agent workloads (NFR-2, OQ-5), the
recorded next step is the async-ask refinement named in ADR-0011's alternatives, which supersedes
that ADR rather than quietly threading this loop. The async-ask path reintroduces out-of-order
responses and a parked-notification cleanup arc (what happens to a parked ask when the child dies),
which is exactly why it is deferred until a measurement justifies carrying that complexity.
