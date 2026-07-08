# ADR-0013: A kernel backstop is required per dimension the kernel can express, not absolutely

- Status: accepted
- Date: 2026-07-08

## Context

ADR-0003 chose defense in depth: the seccomp-unotify decision layer plus an always-on Landlock
boundary, so a gap in the decision logic is still caught by the kernel. In stating it, ADR-0003 wrote
an absolute: "No security-critical boundary may rely on the seccomp layer alone." Designing the
network mediation showed that absolute is not achievable for one real boundary.

Landlock's network rules are port-based: `NET_CONNECT_TCP` and `NET_BIND_TCP` (ABI 4) restrict which
TCP ports a process may connect to or bind, and nothing more. They cannot express a host allowlist.
So the policy's host dimension (FR-7, "connect to `api.anthropic.com` but not elsewhere") has no
kernel construct that can back it: the kernel can be told the port, never the host. Host-level egress
enforcement therefore rests on the seccomp decision alone, which the ADR-0003 sentence forbids. This
is not a design shortcut; it is a limit of what the kernel can express. The defense-in-depth decision
itself is sound and unchanged; only its absolute corollary is wrong.

## Decision

The backstop rule is refined, and this refinement governs where it and ADR-0003 differ:

Every enforced boundary MUST have a kernel backstop in each dimension the kernel can express one.
Where the kernel cannot express a dimension (TCP host identity is the known case), the boundary is
enforced by the seccomp layer alone; that seccomp enumeration is treated as security-critical (it
must be complete on its own, and is reviewed and escape-tested as such), and the residual is named
explicitly in `docs/design/escapes.md`.

Concretely, for `connect`: the port dimension is backstopped by Landlock; the host dimension is not,
and rests on the supervisor's decision, realized so the child cannot race the address it was checked
against (the `ADDFD` supervisor-side connect, `docs/design/syscalls.md`). The residual, that host
enforcement has no kernel backstop, is stated where the controls are enumerated.

ADR-0003's defense-in-depth decision stands; its "never rely on seccomp alone" sentence is refined by
this ADR to "never rely on seccomp alone for a dimension the kernel can back."

## Consequences

- The design stops overclaiming compliance with an unachievable rule and states the host-egress
  residual plainly, which is the honest posture the threat model demands (SR-2, NFR-5).
- The seccomp network enumeration carries a heavier review burden than the filesystem one, because it
  has no coarse kernel floor beneath it. This is called out at the enumeration.
- If a future kernel gains host-aware Landlock (or Leash adopts a different network-mediation
  mechanism, a separate decision), the host dimension gains a backstop and this residual shrinks.

## Alternatives considered

- **Supersede ADR-0003 wholesale.** Rejected: defense in depth is still the right decision and is
  actively relied on everywhere else; replacing the whole ADR would un-accept a sound choice to fix
  one corollary. This ADR refines, it does not replace.
- **Route all network egress through a proxy or a network namespace to regain a host backstop.**
  A real option, but a different architecture than ADR-0003's Landlock choice and out of scope for
  v1; recorded here so it is a deliberate future decision, not a silent gap.
