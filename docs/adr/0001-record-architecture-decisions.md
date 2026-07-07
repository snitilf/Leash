# ADR-0001: Record architecture decisions

- Status: accepted
- Date: 2026-07-07

## Context

Leash is intended to be developed incrementally over ~12 months, at a few hours a week, possibly by more than one contributor (including AI models of varying capability). Decisions made early will be revisited by someone — perhaps the original author months later — who no longer remembers the reasoning. Without a durable record, that person re-litigates settled questions or "fixes" deliberate choices, and the project's behavior becomes non-deterministic with respect to its own intent.

## Decision

We record every hard-to-reverse, non-obvious, trade-off-bearing decision as an Architecture Decision Record in `docs/adr/`, using the format in `docs/adr/README.md`. ADRs are immutable once accepted; a superseding ADR replaces an old one rather than editing it. Requirements and decisions carry stable IDs so other documents and the code can cite them.

## Consequences

- Any contributor can reconstruct *why* the system is shaped as it is, from the repository alone, without the original author.
- There is a small standing cost: real decisions must be written down before implementation.
- Working notes and tooling can stay untracked without losing the project's reasoning, because the reasoning lives here.

## Alternatives considered

- **Keep decisions in code comments / commit messages.** Rejected: not discoverable, not indexed, and lost in noise.
- **Keep decisions only in untracked working notes.** Rejected: the project's memory must survive in the repository itself.
