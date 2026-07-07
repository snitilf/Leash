# ADR-0005: Time travel is filesystem snapshots, never agent replay

- Status: accepted
- Date: 2026-07-07

## Context

Users want to "rewind" a run to before a mistake and "diff" two runs. A naive framing is "replay the agent," but the agent is driven by a non-deterministic language model: re-running it does not reproduce the same actions, so deterministic re-execution of the agent is impossible and any claim of it is false.

## Decision

Time travel operates on **effects, not the agent**. The workspace's write layer is captured at **step** boundaries as **snapshots**. **Rewind** restores the workspace to an earlier snapshot; **diff** compares the effects of two runs from their snapshots and traces. Leash never claims to re-run the model deterministically. The term `replay` is forbidden in code, docs, and pitch (see CONTEXT.md).

## Consequences

- The feature is honest and defensible under expert questioning: we reverse and compare filesystem effects, which are real and deterministic, not model behavior.
- Correctness depends on handling write-layer semantics precisely (whiteouts, opaque dirs, cross-layer renames, hard links, shared mmap writes) — these are explicit test obligations.
- "Rewind" covers filesystem effects only; effects that already left the machine (network sends, external API calls) are not reversible and are out of scope for rewind (they are still recorded).

## Alternatives considered

- **Deterministic replay of the agent.** Rejected as false — the model is non-deterministic. Recorded permanently here so it is never re-proposed.
- **Full VM/disk snapshots.** Rejected as too heavy for a few-hours-a-week local tool and for per-step granularity; the write-layer approach is lighter and targets exactly the workspace.
