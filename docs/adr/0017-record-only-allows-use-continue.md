# ADR-0017: Record-only allows are realized with CONTINUE

- Status: accepted, narrowed on 2026-07-23 (issue #26) in one arc: the "case-C memory-read
  failures deny in both modes" line below now excludes a malformed or over-cap network address,
  which records a `raw` allow in record-only ([`../design/notify-loop.md`](../design/notify-loop.md)
  sections 2 and 4). The decision this ADR records is otherwise unchanged.
- Date: 2026-07-10

## Context

The allow-realization rule ([`../design/syscalls.md`](../design/syscalls.md) section 4,
[`../design/notify-loop.md`](../design/notify-loop.md) section 3) forbids `CONTINUE` for an allow
decided on a pointer argument, because `CONTINUE` re-reads child memory at kernel-execution time
and reopens the TOCTOU window the supervisor's bracketed read just closed (I4). The rule is stated
without a mode qualifier, so read literally it binds record-only runs too: every trapped `openat`
would be realized by `ADDFD` and every `rename`/`unlink`/`mkdir` by a supervisor-executed
operation, even when the decision is unconditionally allow.

Building the notify loop for record-only (#18) exposed that the literal reading does not hold
together:

- The rule's realization machinery is enforce-shaped. Path resolution for `ADDFD` and
  supervisor-executed allows is specified as `openat2` with `RESOLVE_BENEATH` against a
  supervisor-held anchor dirfd derived from the policy's allowed roots. `RESOLVE_BENEATH` rejects
  absolute paths by design. A record-only run has no policy and must allow the agent's ordinary
  absolute-path accesses (`/usr/lib/...`, `/etc/...`, `/tmp/...`), so there is no anchor set to
  resolve beneath. Realizing record-only allows "fully" would mean inventing an anchor-less
  resolution story the design does not define, and acting on a supervisor-side re-resolution that
  the rule's own logic says is the unsafe pattern.
- The rule's purpose is enforcement soundness: a racing sibling thread must not swap a checked path
  for a forbidden one between decision and use. In record-only every decision is allow regardless
  of the pointer's value; there is no constraint for the race to defeat. What a race can do is make
  the trace misdescribe the argument the kernel used, and the design already prices that class of
  effect: `clone3` under `CONTINUE` "can at most misrecord the flags in the trace"
  (syscalls.md section 3.3), and `connect` is explicitly `CONTINUE` "where the policy imposes no
  host constraint" (section 3.5). Record-only is the policy that imposes no constraint anywhere.

## Decision

The allow-realization rule is scoped to decisions that constrain. In record-only mode every allow,
including pointer-argument allows of the filesystem family, is realized with
`SECCOMP_USER_NOTIF_FLAG_CONTINUE`; the event records the value the supervisor read at decision
time, once, per notify-loop.md section 2. The `ADDFD` and supervisor-executed realizations, and the
anchor-based `openat2` resolution they require, are enforce-mode machinery and are built with the
enforce slice.

Unchanged by this decision: the denied-and-recorded set (SR-4, `io_uring_*`, foreign-ABI entry) is
denied in both modes; case-C memory-read failures deny in both modes; the bracketed bounded read
and record-before-respond ordering apply in both modes.

## Consequences

- A named residual: in record-only, a deliberately racing child can make its own trace misdescribe
  a pointer argument (the recorded path is the trap-time read, the executed path may differ). This
  joins the existing record-only residual family ("record-only trace protection rests on
  filesystem permissions"; record-only is a camera, not a bouncer) and is recorded in
  [`../design/escapes.md`](../design/escapes.md) section 4. It does not weaken any enforcement
  claim, because record-only makes none.
- The record-only notify loop stays thin: no supervisor-side opens, no spoofed returns, no
  side-effect replay hazards, and the `WAIT_KILLABLE_RECV` double-execution concern
  (notify-loop.md section 4.1) has no supervisor-executed arm to protect in this mode.
- The enforce slice must build the full realization machinery before any enforcement claim is
  made; nothing from this decision can be reused to shortcut that. The escape test for the TOCTOU
  row in escapes.md remains bound to enforce mode, where the mitigation exists.
- syscalls.md section 4 and notify-loop.md section 3 each gain a scoping sentence citing this ADR;
  the two restatements of the rule must continue to agree.

## Alternatives considered

- **Full realization in record-only (ADDFD + supervisor-executed).** Rejected: it requires an
  anchor-less resolution rule the design does not define, adds the side-effect-replay and fidelity
  hazards of supervisor execution to a mode that enforces nothing, and grows #18 substantially,
  all to defend a trace-fidelity property the design already names as unprotected in this mode
  against a hostile same-uid child.
- **Hybrid: ADDFD for fd-returning opens, CONTINUE for mutations.** Rejected: it buys fidelity for
  half the family while the other half keeps the residual, so the residual must be named anyway;
  the added machinery does not remove the line from escapes.md, only narrows it.
- **Scope the rule per-syscall instead of per-mode.** Rejected: the connect precedent already
  scopes by constraint ("where the policy imposes no host constraint"); mode is the general form
  of the same test, and one sentence covers it.
