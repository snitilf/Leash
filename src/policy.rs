//! policy parsing and evaluation (docs/design/policy.md).
//!
//! assumptions: the engine is pure and total. facts in, decision plus matched-rule id out,
//! no io, no child memory access, no panic path (NFR-6, ADR-0004). the typed fact it
//! receives is kernel-trusted; validating that is the notify loop's job, not ours.
//! rejection is total and upfront: a policy loads whole or not at all (FR-18).
