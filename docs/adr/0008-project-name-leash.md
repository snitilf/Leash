# ADR-0008: Name the project "Leash"

- Status: accepted
- Date: 2026-07-07

## Context

The project needs a name that works as a CLI command, carries the pitch, and is memorable to a technical audience. The tool both *restrains* an agent (policy/sandbox) and *records and reverses* what it did (trace/rewind); the restraining aspect is the primary value proposition.

## Decision

The project is named **Leash**. The primary command reads `leash run -- <agent command>`.

If and when a crate is published to crates.io, it will be published as `leash-cli` (or similar), because the bare `leash` name is held by an unrelated, inactive crate. The project, repository, and binary command remain `leash`; only the registry publish name differs, and only if we publish.

## Consequences

- The CLI is ergonomic (`leash run -- claude ...`) and the pitch has a strong hook: "keep your coding agent on a leash."
- The control metaphor foregrounds the enforcement value; the recording/rewind capabilities are framed as *how* Leash keeps the agent in check.
- A crates.io publish requires a distinct crate name (`leash-cli`); this is deferred and low-cost.
- All existing documents, ADRs, and `CONTEXT.md` are already consistent with this name — no rename churn.

## Alternatives considered

- **Proctor** — precise (supervises an untrusted party, watches for and stops misbehavior) but a weaker pitch hook and longer to type.
- **Tether / Rein / Warden** — all viable control metaphors, none clearly better than Leash, and each would cost a full repo-wide rename for no material gain.
