# ADR-0004: Policy is declarative data, not code

- Status: accepted
- Date: 2026-07-07

## Context

Users must be able to read, diff, review, and trust exactly what an agent is permitted to do. A policy expressed as imperative code is unreviewable as configuration, hard to test in isolation, and easy to get subtly wrong.

## Decision

Policy is **declarative data** (a text format such as TOML — exact format is an open question in the spec) expressed over paths, hosts, and binaries, evaluated by a pure decision engine. New capabilities are new *predicates* the engine evaluates, not new bespoke code branches per rule. The evaluation engine is side-effect-free so it can be exhaustively unit-tested without a live child.

## Consequences

- A user can audit a policy by reading one file and diffing changes to it.
- Policy evaluation is pure and exhaustively testable; the dangerous, hard-to-test machinery (the notify loop) stays thin and delegates to it.
- The expressiveness of policy is bounded by the predicate set, which must grow deliberately (each new predicate is a security-relevant change).

## Alternatives considered

- **Policy as a scripting hook / embedded language.** Rejected: maximally expressive but unreviewable and unsafe as untrusted-adjacent configuration; turns every policy into a program to audit.
- **Hard-coded policy.** Rejected: users cannot express their own boundaries, defeating the tool's purpose.
