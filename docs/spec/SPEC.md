# Leash — Software Specification

- Status: **DRAFT v0.1** (open questions unresolved; see §11)
- Date: 2026-07-07
- Governs: what Leash must do and why. *How* it is built is the design (`docs/design/`).

This document uses the key words **MUST**, **MUST NOT**, **SHOULD**, **MAY** per RFC 2119. Every requirement has a stable ID (`FR-n`, `NFR-n`); other documents, tests, and code cite these IDs. Terms in **bold** are defined in [`CONTEXT.md`](../CONTEXT.md) and are used exactly as defined there.

---

## 1. Purpose

Leash is a command-line tool that supervises an AI coding **agent** at the operating-system boundary so that a developer can **see** everything the agent did (ground-truth **trace**), **constrain** what it may do (**policy**), and **reverse** what it did to their files (**snapshot**/**rewind**). It exists because agents run with the developer's full privileges and are increasingly run unattended, while today the only record of their actions is the agent's own self-report.

## 2. Scope

- **In scope:** supervising a single agent invocation on one Linux host; recording, policy enforcement, interactive approval, workspace snapshot/rewind, and run diffing.
- **Out of scope:** see §9. Notably: multi-host orchestration, kernel-exploit defense, and any dependency on agent cooperation (ADR-0006).

## 3. Actors

- **Operator** — the developer running Leash. Trusted. Authors the **policy**, answers **ask** approvals, reads traces, invokes rewind/diff.
- **Agent** — the supervised AI tool and its **child** process tree. Untrusted (see the threat model).
- **Supervisor** — the `leash` process acting on the operator's behalf.

## 4. Problem statement

From the operator's perspective:

1. *"I can't see what the agent did"* — the transcript is the agent's self-report, not ground truth.
2. *"I can't stop it doing something harmful"* — prompt injection and plain error can make an agent read secrets, exfiltrate data, or damage files, all within the operator's privileges.
3. *"I can't undo it"* — when an agent corrupts the workspace mid-run, there is no reliable rewind (git covers only committed, tracked files).

## 5. Goals and non-goals

**Goals.** Ground-truth recording; enforceable, reviewable policy; honest reversibility of filesystem effects; agent-agnostic operation; low enough overhead to run always-on; defensibility under expert scrutiny.

**Non-goals.** Defending the kernel; defending against a malicious operator; understanding agent *intent*; deterministic re-execution of the agent (ADR-0005); being a general-purpose container runtime (ADR-0003).

## 6. Functional requirements

### 6.1 Running & recording
- **FR-1** — Leash MUST launch an agent via `leash run -- <command>` and supervise the entire **child** process tree, including descendants created by `fork`/`clone`/`exec`.
- **FR-2** — Leash MUST record every **mediated syscall** and its **decision** as an ordered, append-only **event** in the run's **trace**.
- **FR-3** — The **trace** MUST be authored solely by the **supervisor**; the **child** MUST NOT be able to read, modify, delay, or suppress it (ADR-0002).
- **FR-4** — At minimum, the mediated set MUST cover: filesystem access (open/read/write/create/delete/rename), process creation and program execution, and network connection establishment. The exact syscall list is enumerated in the design and is an explicit, reviewed artifact.
- **FR-5** — Leash MUST produce, at the end of a run, a human-readable **session report** summarizing files touched, processes spawned, and network connections attempted, each with its decision.

### 6.2 Policy & enforcement
- **FR-6** — Leash MUST evaluate each mediated syscall against a declarative **policy** (ADR-0004) and resolve a **decision** of allow, deny, or **ask**.
- **FR-7** — Policy MUST be expressible over at least: filesystem paths, network hosts, and executable binaries.
- **FR-8** — Enforcement MUST be defense-in-depth: the expressive seccomp-unotify decision layer AND an always-on Landlock boundary (ADR-0003). A denied action MUST NOT take effect.
- **FR-9** — Every **decision** MUST be **fail-closed**: any supervisor error, crash, or decision timeout resolves the pending action to **deny** (see NFR-1).
- **FR-10** — For an **ask** decision, Leash MUST pause the child and block the action until the operator approves or denies; on no response within a configured bound, it MUST deny.

### 6.3 Time travel
- **FR-11** — Leash MUST capture **snapshots** of the **workspace** at **step** boundaries during a run (ADR-0005).
- **FR-12** — Leash MUST provide `leash rewind` to restore the workspace to a chosen earlier snapshot of a run. Rewind reverses filesystem effects only; it MUST NOT claim to reverse effects already emitted off-host (e.g. network sends).
- **FR-13** — Leash MUST provide `leash diff` to compare the filesystem effects of two runs (or two steps), correctly interpreting write-layer semantics (deletions/whiteouts, renames, hard links).

### 6.4 Interface & portability
- **FR-14** — Leash MUST run on Linux meeting the kernel floor (seccomp user-notification ≥ 5.9, Landlock ≥ 5.13). On a host below the floor it MUST refuse to run with a clear message rather than silently degrade security.
- **FR-15** — Leash MUST run on both x86-64 and ARM64 (the Raspberry Pi and VPS targets).
- **FR-16** — Traces MUST be persisted in a documented, machine-readable format (e.g. JSONL) so they can be inspected by other tools; the format SHOULD align with the draft agent-audit-trail schema where practical.

## 7. Non-functional requirements

- **NFR-1 — Fail-closed integrity.** The system MUST never fail open. This is the paramount property; where any requirement conflicts with it, fail-closed wins.
- **NFR-2 — Overhead.** Added latency per mediated syscall and end-to-end wall-clock overhead on a representative agent task MUST be measured and reported (§10); Leash SHOULD keep overhead low enough to run always-on. A concrete budget is an open question (OQ-5).
- **NFR-3 — Auditability.** Policy MUST be human-readable and diffable; the trace MUST be sufficient to reconstruct what the agent did without the agent's cooperation.
- **NFR-4 — Portability & footprint.** MUST build and run on a Raspberry Pi 4 class device; MUST NOT require significant ongoing cloud/compute spend.
- **NFR-5 — Defensibility.** Every control described as *enforced* MUST have passing **escape**-attempt tests (see the threat model); no claim without a test.
- **NFR-6 — Reviewability.** The security-critical code paths (decision loop, enforcement setup, recorder) MUST be small and isolated enough to be audited; policy evaluation MUST be pure and exhaustively unit-testable.

## 8. Security requirements

The threat model is maintained as a working document during development and will be promoted into `docs/` once it is load-bearing for external readers. In summary:

- **SR-1** — The system MUST treat the agent and all its descendants as hostile.
- **SR-2** — The system MUST resist the enumerated **escape** classes: child-process laundering, symlink/TOCTOU races, `/proc` self-reference, alternate-syscall equivalents (including `io_uring` and `openat2`), fd inheritance/passing, and recorder-tampering. Each enforced control MUST map to tests for the escapes it claims to stop.
- **SR-3** — The system MUST NOT rely on any control the child can disable or reason around (the rationale for ADR-0003's Landlock backstop).

## 9. Out of scope (explicit)

- Kernel exploits / privilege escalation past the OS boundary.
- Hardware and micro-architectural side channels.
- A malicious **operator** (Leash protects the operator *from their agent*, not the world from the operator).
- Covert exfiltration through channels the policy *allows* (if a host is allowed, data can leave through it).
- Deterministic re-execution of the agent (ADR-0005).
- Multi-host / fleet orchestration and any hosted service (Leash is a local CLI).

## 10. Acceptance criteria (what counts as done)

A capability is "done" only when:
1. It satisfies its FR/NFR IDs, demonstrated by an **observed behavioral check**, not by inspection of the diff.
2. For any enforcement claim, the relevant **escape** tests pass (NFR-5).
3. Fail-closed behavior is demonstrated for the relevant error/timeout paths (FR-9).
4. Overhead numbers, where claimed, are measured with a stated method, kernel, and architecture (NFR-2).

The certified/golden test inventory is maintained alongside the test suite as it takes shape.

## 11. Open questions (to resolve by grilling → ADR/spec update)

These are **decisions the operator (you) must make**. Each will be resolved into a requirement or an ADR before the design phase. Recommended answers are noted; they are proposals, not defaults.

- **OQ-1 — What is a "step"?** Per mediated write? Per agent turn/tool-call boundary (if detectable without SDK)? Per fixed interval? *Recommendation:* snapshot at mediated-write boundaries, coalesced, to keep steps meaningful without SDK cooperation. (Feeds FR-11, CONTEXT "Step".)
- **OQ-2 — Snapshot mechanism.** overlayfs upper-layer capture vs copy-on-write file snapshots vs per-step copies. Depends on kernel/distro support on Pi and VPS. *Recommendation:* overlayfs where available, with a documented fallback; validate on both targets first.
- **OQ-3 — Policy file format & schema.** TOML vs YAML vs a small DSL; the predicate vocabulary. *Recommendation:* TOML with a fixed predicate set (path globs, host allowlists, binary allowlists).
- **OQ-4 — Default policy posture.** Deny-by-default with an allowlist, or monitor-only on first run? *Recommendation:* ship a "record-only" mode for first-run trust-building and a "deny-by-default" mode for enforcement; make the active mode explicit and never implicit.
- **OQ-5 — Overhead budget.** The concrete NFR-2 target (e.g. "< X µs p99 per mediated syscall; < Y% wall-clock on a reference task"). *Recommendation:* set after the Phase-1 recorder exists and real numbers are in hand — do not guess it now.
- **OQ-6 — `io_uring` posture.** Mediate it, or deny it outright as an un-mediated I/O path? *Recommendation:* deny by default initially (fail-closed), revisit if a real workload needs it. (Feeds SR-2.)
- **OQ-7 — Interactive approval UX.** Terminal prompt only, or also a non-interactive mode for unattended runs (auto-deny asks, or a pre-approved policy)? *Recommendation:* terminal prompt for attended use; for unattended use, asks resolve to deny unless the policy pre-authorizes.
- **OQ-8 — Trace persistence location & retention.** Where traces/snapshots live and how long they are kept. *Recommendation:* under a per-run directory in a configurable state dir; retention is the operator's to prune.

## 12. Traceability

| Requirement | Realized by decision | Verified by |
|---|---|---|
| FR-3 (log integrity) | ADR-0002 | recorder-tamper escape tests |
| FR-8 (defense in depth) | ADR-0003 | per-layer escape tests |
| FR-6/FR-7 (policy) | ADR-0004 | policy-engine unit tests |
| FR-11..13 (time travel) | ADR-0005 | overlay-semantics tests |
| FR-1/FR-4 (agent-agnostic coverage) | ADR-0006 | inheritance + coverage tests |
| NFR-4 (footprint), FR-15 | ADR-0007 | build/run on Pi + VPS |

*(This table grows as requirements and ADRs are added; every FR/NFR should trace to a decision and a verification.)*
