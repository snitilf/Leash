# ADR-0010: Two explicit run modes, record-only and enforce

- Status: accepted
- Date: 2026-07-07

## Context

A security tool wants deny-by-default, but a first-time operator has no policy yet: their first
run under deny-by-default would be a wall of denials that breaks the agent before it does anything
useful, and teaches operators to write overly broad allow rules just to make runs pass. The
opposite posture, allow-by-default with a blocklist, fails open by construction. The default
posture shapes both the first-run experience and whether the tool's security claims stay honest.

## Decision

Leash runs in exactly one of two modes, and the active mode is explicit: announced at run start,
stamped into the trace, and named in the session report.

- **Record-only**: every mediated syscall is allowed and traced. Nothing is enforced. If a policy
  is present, actions it would have denied are flagged in the trace and report. This is the mode
  a run gets when no policy file exists.
- **Enforce**: deny-by-default. Every mediated syscall not allowed by the policy is denied or
  asked, per the policy. Enforce mode requires a policy file.

The mode never changes mid-run.

## Consequences

- First runs work out of the box and produce exactly the material an operator needs to write
  their first policy (the record of what the agent actually touched).
- In record-only mode Leash is a camera, not a bouncer. Documentation and output must never blur
  this line; describing a record-only run as "sandboxed" would be an overclaim.
- Enforce mode inherits the full fail-closed discipline (NFR-1, FR-9) with no soft middle ground,
  which keeps the enforcement story testable and honest.
- Two modes cost a small amount of surface: mode selection, mode stamping, and would-deny
  flagging all need tests.

## Alternatives considered

- **Deny-by-default always, single mode.** Rejected: hostile first-run experience that pushes
  operators toward sloppy broad allow rules, weakening real-world security to preserve
  theoretical purity.
- **Allow-by-default with deny rules (blocklist).** Rejected: fails open by construction;
  anything the operator forgot to deny is allowed. Contradicts NFR-1.
- **Implicit mode (enforce if a policy happens to exist).** Rejected: whether a run was actually
  protected must never depend on silent filesystem state; the mode is stamped and announced.
