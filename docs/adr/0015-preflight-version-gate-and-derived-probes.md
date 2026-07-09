# ADR-0015: The version check is a hard gate, and ADDFD support is derived, not probed

- Status: accepted
- Date: 2026-07-09

## Context

ADR-0012 set the kernel floor at Linux 5.19 and said preflight "requires the capabilities, not
merely the version string, so a backported kernel that reports an older version but carries the
features is judged on the features." It also listed, as a consequence, "capability probes for the
two seccomp flags" (`WAIT_KILLABLE_RECV` and `ADDFD_FLAG_SEND`).

Implementing preflight (issue #16, PR #22) forced both sentences into concrete choices, and the
review of that PR found the code had resolved them one way without a record:

- The implementation refuses any kernel whose reported version is below 5.19 before consulting
  the capability probes, so a 5.15 kernel with backported features is refused. That contradicts
  the "judged on the features" sentence read literally.
- `ADDFD_FLAG_SEND` (Linux 5.14) is not probed directly. A side-effect-free probe for it does not
  really exist: proving it takes a live notify fd with a pending notification, which means
  installing a filter, which preflight must not do. The implementation instead derives it from the
  observed `WAIT_KILLABLE_RECV` probe: that flag was added strictly later (5.19), so a kernel that
  proves it necessarily carries `ADDFD` (5.9) and `ADDFD_FLAG_SEND` (5.14).

## Decision

Both implementation choices stand, and this ADR is their record.

1. **The 5.19 version check is a hard gate in addition to the capability probes.** A kernel that
   reports a version below 5.19 is refused even if every capability probe would pass. The probes
   are verified on top of the version gate, not instead of it: a 5.19+ kernel missing a capability
   (a distro that disabled seccomp filtering or Landlock) is also refused. This refines the
   "judged on the features" sentence of ADR-0012; the floor itself and its rationale are unchanged.
2. **`SECCOMP_ADDFD` / `ADDFD_FLAG_SEND` are derived from the `WAIT_KILLABLE_RECV` probe**, by the
   strict ordering of when the flags entered the kernel, and the first live ADDFD in the spawn
   protocol (#17) is the behavioral confirmation. If that first live use ever fails on a host the
   derivation accepted, the run fails closed at that point and the derivation is reopened. This
   narrows ADR-0012's consequence "probes for the two seccomp flags" to one direct probe plus a
   documented derivation.

## Consequences

- Preflight stays fail-closed and simple: two independent refusal reasons (version below floor,
  capability missing) instead of a matrix where features can override the version string.
- Kernels in the 5.9 to 5.18 range with backported 5.19 features are refused. Accepted: no
  reference target ships such a kernel, and supporting them would add a path the project cannot
  observe on any hardware it tests (the same honesty argument as ADR-0012's own rejection of a
  below-floor fallback).
- The ADDFD capability claim rests on an inference until #17's first live ADDFD. The inference is
  from an observed capability with strict version ordering, not from the version string, and the
  gap is closed by construction the first time the capability is actually used.

## Alternatives considered

- **Let capabilities override the version gate** (the literal reading of ADR-0012). Rejected: it
  adds a permissive branch that no target exercises and no CI kernel can test, exactly where a
  wrong answer weakens the boundary. A clear refusal is testable; a backport heuristic is not.
- **Probe ADDFD directly.** Rejected: there is no side-effect-free probe. Every known method
  installs a seccomp filter on some process, and preflight installing filters would violate its
  own contract of leaving the host untouched (the no-filter behavioral test pins that contract).
