# ADR-0012: Raise the kernel floor to Linux 5.19

- Status: accepted
- Date: 2026-07-08

## Context

FR-14 set the kernel floor at the lower bounds of the two mechanisms in isolation: seccomp
user-notification (the `NEW_LISTENER` flag is Linux 5.0, `SECCOMP_ADDFD` is 5.9) and Landlock
(filesystem rules are ABI 1, Linux 5.13). Designing the notify loop and the Landlock derivation
against real kernel behavior surfaced two hard requirements those bounds do not meet.

- **Signal-cancelled notifications (the supervisor-executed allow is unsound below 5.19).** A
  non-fatal signal delivered to a child blocked on a user-notification cancels the notification: the
  supervisor's `NOTIF_SEND` fails `ENOENT`, and with `SA_RESTART` the syscall restarts and re-traps.
  The design's allow-realization rule performs some allows by executing the operation in the
  supervisor and spoofing the return (rename, unlink, mkdir, a host-enforced connect). If the
  notification is cancelled after the side effect but before `SEND`, the restarted syscall re-traps
  and the side effect runs a second time, and the trace records a response that was never delivered.
  `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (Linux 5.19) makes a received notification interruptible
  only by a fatal signal, which closes this. `SECCOMP_ADDFD_FLAG_SEND` (Linux 5.14) gives the atomic
  inject-and-respond the fd-injection allows want. Agents routinely take `SIGCHLD` and timer signals,
  so this is a normal path, not a corner case.
- **Cross-directory rename/link needs Landlock ABI 2.** `LANDLOCK_ACCESS_FS_REFER` is ABI 2 (Linux
  5.19). On ABI 1 (the old 5.13 floor) a Landlock-sandboxed process is denied every rename or link
  that crosses directory hierarchies, unconditionally, and passing `FS_REFER` in `handled_access_fs`
  on ABI 1 fails ruleset creation with `EINVAL`. On a 5.13 to 5.18 kernel the derived ruleset would
  therefore deny cross-directory renames the policy allows, violating the design's own rule that
  Landlock must never deny what the policy permits.

Both point at the same version. The reference targets (Raspberry Pi, VPS; FR-15, NFR-4) ship 6.x
kernels, so the floor move costs nothing on the hardware Leash actually targets; it excludes only
older long-term-support kernels in the 5.9 to 5.18 range.

## Decision

The kernel floor is Linux 5.19. Below it, Leash refuses to run (FR-14, unchanged in posture). The
floor is stated as a version because 5.19 is where every capability Leash depends on is present:
`WAIT_KILLABLE_RECV`, `ADDFD` and `ADDFD_FLAG_SEND`, and Landlock ABI 2 (`FS_REFER`). Preflight
requires the capabilities, not merely the version string, so a backported kernel that reports an
older version but carries the features is judged on the features.

FR-14 is updated to name 5.19 and the reason. `LANDLOCK_ACCESS_FS_TRUNCATE` (ABI 3, Linux 6.2) sits
above this floor and is handled as an ABI-gated backstop with a named residual below 6.2, not as a
further floor raise (see `docs/design/syscalls.md`).

## Consequences

- The supervisor-executed allow (rename, unlink, mkdir, host-enforced connect) is sound: no
  double-execution, no phantom trace event. This is a correctness precondition for the
  allow-realization rule, not a nicety.
- Cross-directory rename and link can be granted through Landlock, so the derived ruleset does not
  contradict the policy.
- Leash does not run on 5.9 to 5.18 kernels. Accepted, because the targets are 6.x and because the
  alternative (below) is more dangerous than a clear refusal.
- Preflight gains capability probes for the two seccomp flags and the Landlock ABI, alongside the
  existing kernel-floor and overlay checks.

## Alternatives considered

- **Stay at 5.9 and carry idempotency bookkeeping for the supervisor-executed allows.** Rejected:
  it puts hand-written de-duplication logic on the most security-sensitive path, exactly where a
  subtle bug fails open or corrupts the trace, to support kernels the project does not target. A
  refusal to run is honest; a fragile workaround is not (NFR-1, I3).
- **Raise the floor to 6.2 for `FS_TRUNCATE` too.** Rejected: truncation below ABI 3 is a missing
  backstop, not a wrong denial, so it is handled as a named residual (I5, NFR-5) rather than
  excluding more kernels than the two hard requirements demand.
