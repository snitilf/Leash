# Measurement 0002: WAIT_KILLABLE_RECV signal semantics (issue #36)

- Status: measured 2026-07-26 on the codespace Linux host; CI-kernel confirmation follows on the
  merge branch (the same suite runs there, kernel 6.17.0-1022-azure).
- Governs: the resolution of issue #36 and the correctness of the claims in
  `design/notify-loop.md` section 4.1 and ADR-0012 about signal cancellation of received
  notifications.
- Cites: ADR-0012, ADR-0020; SPEC.md FR-3, FR-9, I3, I4; `design/notify-loop.md` section 4.1.
- Method recorded before any number, per the project's evidence discipline.

This document records what a caught, non-fatal signal does to a seccomp user notification that the
supervisor has already received, measured, not read out of kernel source.
The trigger was CI run 31973092653 (kernel 6.17.0-1022-azure): a caught SIGALRM cancelled a
received ask notification, the trapped syscall returned EINTR and re-trapped, and the operator saw
a second prompt for one held open, contradicting `notify-loop.md` section 4.1 as written.

## 1. What is measured

One kernel behavior, in five cases (`tests/wait_killable_recv_linux.rs`):

1. **Post-RECV, no SA_RESTART**: `RECV` a notification, `tgkill` the trapped thread with a caught
   SIGUSR1, then check `ID_VALID`, `SEND`, and the child's syscall result.
2. **Pre-RECV control**: signal the trapped thread after the notification is queued but before
   `RECV`; the documented pre-5.19-style behavior (EINTR, handler runs, notification dies) must
   still hold here.
3. **Post-RECV, SA_RESTART**: same as case 1 with the handler installed with `SA_RESTART`.
4. **Post-RECV signal storm**: five SIGUSR1 deliveries, 50 ms apart, while one notification is
   pending.
5. **CI replica**: the exact anomaly shape from run 31973092653, a single-threaded python child
   that arms `setitimer(ITIMER_REAL, 1.0)` and opens a file while the supervisor holds the
   notification for 1.5 s.

The probe uses the production filter-install path (`spawn_supervised`, which passes
`NEW_LISTENER | WAIT_KILLABLE_RECV`) and signals the trapped thread by tid, taken from the
notification's `pid` field, so a process-directed signal cannot land on an unrelated thread and
prove nothing.

## 2. Finding: the flag bit was wrong

Before any kernel-semantics question could be answered, the probe showed cancellation on every
kernel tried, including where the source said it was impossible.
The cause was in our own constant: `src/supervisor/notify.rs` defined
`SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` as `1 << 4`, but uapi `include/uapi/linux/seccomp.h`
defines it as `1 << 5`; bit 4 is `SECCOMP_FILTER_FLAG_TSYNC_ESRCH`.
The kernel accepted the mask (bit 4 is a valid flag), installation succeeded, and the preflight
probe passed, because preflight validates flag-mask acceptance, not semantics.
The filter simply never had `wait_killable_recv` set, so every notification wait was interruptible
and every caught signal cancelled a received notification, on every kernel, exactly matching the
CI anomaly.
With the constant corrected to `1 << 5`, the documented semantics appear.

Lesson recorded for `design/notify-loop.md` section 4.1: a claimed kernel guarantee must be pinned
by a behavioral test, not by the success of the install that was supposed to enable it.

## 3. Results with the corrected flag

Kernel: Linux 6.8.0-1052-azure x86_64 (GitHub codespace, `.devcontainer/devcontainer.json`).
Suite: `cargo test --test wait_killable_recv_linux`, 6 of 6 pass.

| Case | Expected per `notify-loop.md` 4.1 | Observed |
|------|-----------------------------------|----------|
| 1. post-RECV signal | notification survives; `SEND` succeeds; handler runs only after the syscall completes | `ID_VALID` true after the signal; `SEND` ok; child output `HANDLER_RAN` then `RESULT:errno-13` (the `EACCES` we sent); no second trap |
| 2. pre-RECV control | notification cancelled; syscall returns EINTR; handler runs | `ID_VALID` false; `SEND` fails `ENOENT`; child output `HANDLER_RAN` then `RESULT:errno-4` |
| 3. post-RECV with SA_RESTART | as case 1 | as case 1 |
| 4. signal storm (5x) | as case 1 | as case 1; one notification, one `SEND`, no re-trap |
| 5. CI replica (python + setitimer) | no handler and no second trap while pending | `handler-ran-while-pending=false`, `second-trap-before-send=false`, no PEP 475 retry |

Ask-level end-to-end confirmation: `tests/ask_linux.rs` case
`a_caught_signal_during_the_ask_does_not_disturb_the_held_syscall` restores the scenario that
failed in CI (caught SIGALRM during a pending ask) and pins one prompt, one recorded open, one
completion.

## 4. Residual risk, recorded not claimed away

Upstream fix `cce436aafc2a` ("seccomp: Fix a race with WAIT_KILLABLE_RECV if the tracer replies
too fast", merged 2025-07-25, first released after 6.17, bugzilla 220291 reported by the Syd
sandbox) covers a narrower race: a signal wakes the tracee from its interruptible wait, and the
supervisor's `SEND` lands before the tracee re-acquires the notification lock; the old re-check
(`state == SENT`) then misses the already-`REPLIED` notification and the tracee discards the reply
and restarts the syscall.
The window is the microseconds between the wake and the lock.
The consequence is the double-execution case `notify-loop.md` section 4.1 exists to prevent, so on
kernels without the fix a supervisor-performed side effect can still run twice, rarely.
Neither measured kernel (6.8.0-1052-azure codespace, 6.17.0-1022-azure CI) carries the fix.
Leash cannot close that race from userspace; the kernel floor stays 5.19 (ADR-0012 unchanged) and
this residual risk is now named in `notify-loop.md` section 4.1.

## 5. Reproduction

```sh
cargo test --test wait_killable_recv_linux -- --test-threads=1 --nocapture
cargo test --test ask_linux a_caught_signal
```

Both require Linux with seccomp user notification; on the dev host they run in the project
codespace (`.devcontainer/devcontainer.json`), and in CI on every pull request.
