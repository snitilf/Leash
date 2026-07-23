# Leash — Documentation (the project's source of truth)

This directory is the **deterministic brain** of Leash. Every structural decision the project makes is derived from, and recorded in, the documents here. Code follows documentation — not the other way around.

## The governing rule

> **No decision without a record. No code without a governing document.**
>
> A change to *what* the system does is made in the **spec** first.
> A change to *how* it is built is made in the **design** first.
> A hard-to-reverse choice with real trade-offs is recorded as an **ADR** before it is implemented.
> The words used to describe any of it are fixed in **CONTEXT.md**.

Given the same governing documents, the same structure reproduces. That reproducibility is what "deterministic" means here: a contributor (human or model) can regenerate a decision by reading the docs, because the reasoning — not just the outcome — is written down.

## The document hierarchy

| Layer | Location | Answers | Changes when |
|---|---|---|---|
| **Ubiquitous language** | [`CONTEXT.md`](CONTEXT.md) | *What does each term mean?* | A domain term is coined or sharpened |
| **Specification** | [`spec/SPEC.md`](spec/SPEC.md) | *What must the system do, and why?* | A requirement is added/changed |
| **Design** | [`design/`](design/) | *How is it built?* | An implementation approach is chosen |
| **Decisions (ADRs)** | [`adr/`](adr/) | *Why did we choose this over the alternative?* | A hard-to-reverse trade-off is made |

Each layer references the ones above it by **stable ID** (requirement IDs like `FR-3`, decision IDs like `ADR-0004`, glossary terms). That ID web is the traceability that makes decisions auditable.

**Work tracking** (the execution layer that sits *on top of* these docs — GitHub Issues/PRs, and how to set it up) is documented separately in [`process/work-tracking.md`](process/work-tracking.md). Knowledge lives here in `docs/`; work items live in the issue tracker; the two are never merged.

## How work flows through it (the deterministic loop)

1. **Resolve open questions** → settle every decision branch with the operator.
2. **Record the resolution** → a requirement in the spec, or an ADR, using the project's vocabulary.
3. **Implement** to the governing doc, test-first.
4. **Review** against both the standard and the spec.
5. **Reconcile** the docs with reality.

## Status

- **Implementation in progress.**
  The spec is settled at v0.8 (see [`spec/SPEC.md`](spec/SPEC.md)), and the design layer in [`design/`](design/) is frozen as of 2026-07-08.
  The M0 x86-64 overlay spike and M1 recorder milestone are complete: preflight, spawn, the record-only notify loop, durable traces, reports, the `leash run` CLI, Linux behavioral CI, and the first overhead measurement have landed ([`measurements/0001-m1-overhead.md`](measurements/0001-m1-overhead.md)).
- **M2 enforcement is in progress.**
  Policy parsing and pure evaluation, Landlock ruleset derivation and application primitives, and typed process, network, and cross-process trace/report facts have landed.
  Enforce mode still refuses before spawning because safe pointer-argument allow realization and its escape suite remain open in issue #25.
  FR-2 family completeness remains open in issue #26, and attended approval remains blocked on #25 in issue #30.
- One spec item remains deferred on purpose: OQ-9 (the ARM64 target), closing on a real ARM64 need.
  OQ-5 closed on 2026-07-13 into NFR-2's concrete budget from the M1 measurements.
- No design parameter remains open.
  The step-coalescing window closed at 250 ms from the M1 gap measurements (see the design README's open-parameters table), with the first real agent-session trace named as its confirming input.
