# ADR-0006: Mediate at the OS boundary, never via an agent SDK

- Status: accepted
- Date: 2026-07-07

## Context

Existing agent-observability tools (LangSmith, AgentOps, and similar) integrate as libraries inside the agent and record the *model's* API calls. That approach is blind to what the agent actually does to the machine, works only for the specific agent it is wired into, and — being inside the child's trust domain — can in principle be deceived by a hostile agent.

## Decision

Leash mediates at the **operating-system boundary** (syscalls, via seccomp and Landlock), never through an agent SDK or cooperation from the agent. Any feature that would require the agent's cooperation is, at most, optional enrichment and may never be the enforcement or recording path.

## Consequences

- Leash is **agent-agnostic**: it works with any agent from any vendor, including closed-source ones, with no integration.
- Leash cannot be deceived by the agent about what it did — the kernel is the witness.
- Leash sees syscalls, not intent: it knows a file was read, not *why* the agent read it. Semantic, model-level context is out of band. This is an accepted limitation, not a defect.

## Alternatives considered

- **SDK / wrapper integration.** Rejected: vendor-specific, deceivable, and blind to machine effects — it would make Leash a worse copy of existing tools instead of a categorically different one.
