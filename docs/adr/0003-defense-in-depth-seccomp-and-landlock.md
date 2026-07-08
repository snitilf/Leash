# ADR-0003: Enforce with seccomp user-notification *and* Landlock

- Status: accepted (the defense-in-depth decision stands; two clauses in the Decision are refined by ADR-0013: "never rely on seccomp alone" becomes per-expressible-dimension, and "allowed paths/hosts" is corrected because Landlock cannot express hosts, only TCP ports)
- Date: 2026-07-07

## Context

Two Linux mechanisms can restrict a process's actions. **seccomp user-notification** is expressive — the supervisor can inspect each mediated syscall's arguments and decide allow/deny/ask, including "ask the human." But it *is policy logic*, and logic has bugs; a mistake means an escape. **Landlock** is coarse (filesystem hierarchies, and TCP on newer kernels) and cannot express "ask," but it is enforced by the kernel and cannot be reasoned around by the child.

## Decision

Use both, as layers. seccomp-unotify is the expressive **decision** layer. Landlock is an always-on **hard wall** applied by the child before it executes the agent, granting only the workspace and explicitly allowed paths/hosts. Where the two disagree, the more restrictive wins. No security-critical boundary may rely on the seccomp layer alone. This is invariant of the architecture; see the threat model for the escape classes each layer must resist.

## Consequences

- A bug in the seccomp policy logic does not automatically become a filesystem escape — Landlock still holds at the kernel.
- Two mechanisms must be kept in agreement, and Landlock's versioned ABI must be queried at runtime and degraded explicitly (never assume a capability exists).
- Some controls (interactive "ask") exist only in the seccomp layer and therefore carry no Landlock backstop; these are called out as such.

## Alternatives considered

- **seccomp-unotify only.** Rejected: single layer of fallible policy logic guarding security-critical boundaries.
- **Landlock only.** Rejected: cannot record, cannot decide per-argument, cannot ask the human — it is a wall, not a camera or a bouncer.
- **A container / gVisor / microVM.** Rejected as the primary mechanism: those *isolate* but do not *record and explain per action* on the developer's own workspace. Different threat model; see ADR-0006 and the spec's Non-Goals.
