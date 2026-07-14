# ADR-0016: Raw libc syscalls for the seccomp boundary

- Status: accepted (the deferred Landlock question is closed by ADR-0018)
- Date: 2026-07-09

## Context

The Rust standard for this repo prefers vetted crates over hand-rolled FFI and requires a recorded
justification when raw `libc` is used. The preflight probes (PR #22) introduced the first raw
`libc` syscalls, with hand-defined constants for the seccomp and Landlock operations the `libc`
crate does not expose. The spawn protocol (#17) and the notify loop (#18) are about to build far
more kernel-boundary code, so whichever choice the probes made was going to become load-bearing by
default. That choice needs to be deliberate.

The seccomp surface Leash depends on is the user-notification protocol: `SECCOMP_SET_MODE_FILTER`
with `NEW_LISTENER` and `WAIT_KILLABLE_RECV`, the `SECCOMP_IOCTL_NOTIF_RECV` / `NOTIF_SEND` /
`NOTIF_ID_VALID` / `NOTIF_ADDFD` ioctls, and `ADDFD_FLAG_SEND`. The vetted crates in this space do
not cover it: `seccompiler` compiles BPF filter programs and stops there, and the general `nix`
bindings do not wrap the notify ioctls or the ADDFD structures. Wrapping Leash's protocol in any
of them would still leave the security-critical calls hand-rolled, plus a dependency.

## Decision

The seccomp boundary is implemented with raw `libc` syscalls and hand-defined constants, wrapped
in safe module-level APIs per the house standard: every `unsafe` block carries a `// SAFETY:`
comment, constants are stable kernel ABI values, and raw pointers and fds do not leak past the
module boundary. This is the standing justification the standard asks for; individual uses do not
need to re-argue it, they need to meet it.

The Landlock side is a separate question and stays open. The `landlock` crate is maintained by the
Landlock kernel author and covers ruleset creation and ABI probing well; whether to adopt it for
the sandbox setup is decided when #18 builds that code, not here. Until then the one Landlock call
in the tree (the preflight ABI query) stays raw for consistency with its neighbors.

## Consequences

- No new dependency on the enforcement path; `cargo audit` and review effort stay focused on code
  this repo owns. The cost is that Leash owns the correctness of its constants and struct layouts,
  reviewed against the kernel headers rather than delegated to a crate.
- The notify loop (#17, #18) builds on this decision directly. Its FFI grows under the same
  discipline: minimal `unsafe`, SAFETY comments, safe wrappers at the module boundary.
- If a maintained crate later covers the unotify protocol properly, adopting it is a tier 3 change
  (dependency on the enforcement path) and a new ADR.

## Alternatives considered

- **`seccompiler` for filter construction.** Rejected for now: it covers only BPF program
  assembly, the one part of the surface that is straightforward, and none of the notify protocol
  where the risk lives. Reconsider at #17 if the hand-written filter program proves error-prone.
- **`nix` as a general syscall wrapper.** Rejected: it does not wrap the seccomp notify ioctls, so
  it would add a broad dependency without covering the calls that matter.
- **The `landlock` crate, now.** Deferred, not rejected: it is credible (kernel-author maintained)
  but the code it would serve does not exist yet. Deciding it at #18, with the ruleset code in
  front of us, is the cheaper and better-informed call.
