# ADR-0018: Enforcement-path dependency decisions for M2

- Status: accepted
- Date: 2026-07-13

## Context

ADR-0016 settled the seccomp boundary on raw libc and hand-defined constants, and explicitly
deferred the Landlock side to the moment the ruleset code would be written (the deferral names
#18; the ruleset work moved to #25, which is that moment). Starting #25 also surfaced two more
dependency questions on the enforcement path: policy files are TOML and no TOML parser exists in
the tree, and policy path/binary rules use the gitignore-style glob syntax fixed by
`../design/policy.md` section 2.1, whose matching decides allow versus deny.

The dependency policy here is strict: every crate is justified, and code on the enforcement path
gets the most conservative treatment because a wrong decision there is a policy violation, not a
bug report. All three questions were resolved with the operator on 2026-07-13, before slice 1 of
#25.

## Decision

1. **Landlock: raw libc**, closing ADR-0016's deferred question the same way as its seccomp half.
   The surface is three syscalls (`landlock_create_ruleset`, `landlock_add_rule`,
   `landlock_restrict_self`) with stable ABI constants. Two facts tipped it: the child applies the
   ruleset between fork and exec, where only bare syscalls are safe, so the application half is
   raw no matter what; and Leash's preflight degrade table (ADR-0015) already owns the
   ABI-compatibility policy, so the `landlock` crate's best-effort-downgrade model would overlap
   it and could mask a degrade this project requires to be deliberate and recorded. Same
   discipline as ADR-0016: hand-defined constants reviewed against kernel headers, SAFETY
   comments, safe module-boundary wrappers.
2. **TOML parsing: the `toml` crate.** The de facto standard (toml-rs, serde-integrated,
   maintained), so the whole-file-or-nothing rejection policy.md requires falls out of typed
   serde structs with unknown fields denied. A hand-rolled parser for an operator-supplied input
   format would be a worse risk than the dependency. Justified in `Cargo.toml` per house
   convention when it lands.
3. **Glob matching: hand-rolled.** The syntax policy.md fixes is deliberately small (`*`, `**`,
   `?`, anchored to the full resolved path; no classes, braces, or negation). A vetted glob crate
   (`globset`) speaks a richer dialect, so a rule could silently mean more than the spec says;
   owning a small, total matcher with an exhaustive test table keeps rule semantics exactly the
   documented ones.

## Consequences

- One new dependency (`toml`) on the policy-loading path; zero on the syscall path. `cargo audit`
  covers it; its justification comment lands with the code.
- Leash owns the Landlock constants and the glob matcher, both reviewed and exhaustively tested;
  the matcher's test table is part of #25 slice 1's acceptance.
- ADR-0016's "the Landlock side stays open" sentence is closed by this ADR; its seccomp decision
  is untouched.
- Adopting the `landlock` crate or a glob crate later is a tier 3 change and a new ADR, same as
  ADR-0016 states for the seccomp side.

## Alternatives considered

- **`landlock` crate (kernel-author maintained, credible).** Rejected for the reasons in decision
  1; deferred-then-declined, not disqualified. Revisit only if the raw surface grows past the
  three syscalls.
- **Hand-rolled TOML subset.** Rejected: owning a parser for a format with real edge cases
  (strings, escapes, tables) to avoid one well-vetted dependency inverts the risk it is meant to
  reduce.
- **`globset` for matching.** Rejected: dialect mismatch with policy.md 2.1; constraining a richer
  engine down to the spec'd syntax is more code than the matcher itself.
