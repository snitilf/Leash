# ADR-0021: Accept the residual WAIT_KILLABLE_RECV post-SEND race

- Status: accepted
- Date: 2026-08-17

## Context

[`WAIT_KILLABLE_RECV` signal measurements](../measurements/0002-wait-killable-recv-signals.md) found that kernels before upstream fix `cce436aafc2a` can discard an already-delivered reply when a signal wakes the tracee and `SEND` wins the race to the notification lock.
The tracee then restarts the syscall, so a supervisor-realized side effect can run twice and the trace can contain a response the child never observed.
Userspace cannot close this race, and requiring the fix or a verified backport would exclude supported kernels from Linux 5.19 through 6.17.

## Decision

Leash accepts this narrow residual on kernels without `cce436aafc2a` and keeps the Linux 5.19 floor from ADR-0012.
This ADR refines ADR-0012's absolute signal-safety consequence: `WAIT_KILLABLE_RECV` remains required, but it does not guarantee single execution after `SEND` on an unfixed kernel.

## Consequences

Supported unfixed kernels retain a rare double-execution and phantom-trace risk for supervisor-realized side effects.
The risk is named in the notify-loop design and measured behaviorally rather than hidden behind successful flag installation.

## Alternatives considered

Raising the floor to a kernel containing `cce436aafc2a`, or requiring a verified backport, would restore the original guarantee but is rejected because it would exclude the currently supported kernel range for a narrow race.
