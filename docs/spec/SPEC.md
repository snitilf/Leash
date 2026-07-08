# Leash — Software Specification

- Status: **v0.3, settled** (section 11 holds one explicitly deferred item, OQ-5, with a named closing trigger)
- Date: 2026-07-08 (v0.3 revised FR-14's kernel floor to 5.19 per ADR-0012; v0.2 dated 2026-07-07)
- Governs: what Leash must do and why. *How* it is built is the design (`docs/design/`).

Key words **MUST**, **MUST NOT**, **SHOULD**, **MAY** per RFC 2119. IDs are stable and cited by other documents, tests, and code: `F-n` features, `FR-n` functional requirements, `NFR-n` non-functional requirements, `SR-n` security requirements, `OQ-n` open questions. Terms in **bold** are defined in [`CONTEXT.md`](../CONTEXT.md) and used exactly as defined there.

---

## 1. Purpose

Leash is a command-line tool that supervises an AI coding **agent** at the operating-system boundary so a developer can see everything the agent did (ground-truth **trace**), constrain what it may do (**policy**), and reverse what it did to their files (**snapshot**/**rewind**). Agents run with the developer's full privileges, increasingly unattended, and the only record today is the agent's own self-report.

## 2. Scope

- **In scope:** supervising a single agent invocation on one Linux host; recording, policy enforcement, interactive approval, workspace snapshot/rewind, run diffing.
- **Out of scope:** see section 9. Notably: multi-host orchestration, kernel-exploit defense, any dependency on agent cooperation (ADR-0006).

## 3. Actors

- **Operator** — the developer running Leash. Trusted. Authors the **policy**, answers **ask** approvals, reads traces, invokes rewind/diff.
- **Agent** — the supervised AI tool and its **child** process tree. Untrusted.
- **Supervisor** — the `leash` process acting on the operator's behalf.

## 4. Goals and non-goals

**Goals.** Ground-truth recording; enforceable, reviewable policy; honest reversibility of filesystem effects; agent-agnostic operation; overhead low enough to run always-on; defensibility under expert scrutiny.

**Non-goals.** Defending the kernel; defending against a malicious operator; understanding agent *intent*; deterministic re-execution of the agent (ADR-0005); being a general-purpose container runtime (ADR-0003).

## 5. Features

| ID | Feature | Requirements |
|---|---|---|
| F-1 | Supervised run (`leash run`) | FR-1, FR-2, FR-4, FR-14, FR-15 |
| F-2 | Ground-truth trace and session report | FR-2, FR-3, FR-5, FR-16, FR-21 |
| F-3 | Policy enforcement | FR-6..FR-9, FR-18, FR-19, SR-1..SR-4 |
| F-4 | Interactive approval (**ask**) | FR-10, FR-20 |
| F-5 | Snapshots and rewind (`leash rewind`) | FR-11, FR-12, FR-17 |
| F-6 | Run diff (`leash diff`) | FR-13 |
| F-7 | Run management (list/prune) | FR-21 |

### 5.1 Post-MVP candidates

These carry no requirements yet and nothing in this table is promised; promoting one means writing its FRs in a spec update first.

| ID | Candidate | Notes |
|---|---|---|
| F-8 | TUI timeline | Interactive browser for a run's steps and events, on top of F-5/F-6. Roadmap M3. |
| F-9 | Policy-drafting helper | Generate a starter policy from a record-only trace (ADR-0010 makes the input available). |
| F-10 | io_uring mediation | Replace SR-4's denial with equivalent mediation plus escape tests, if a real workload needs it. |

## 6. Functional requirements

### 6.1 Running & recording
- **FR-1** — Leash MUST launch an agent via `leash run -- <command>` and supervise the entire **child** process tree, including descendants created by `fork`/`clone`/`exec`.
- **FR-2** — Leash MUST record every **mediated syscall** and its **decision** as an ordered, append-only **event** in the run's **trace**.
- **FR-3** — The **trace** MUST be authored solely by the **supervisor**; the **child** MUST NOT be able to read, modify, delay, or suppress it (ADR-0002).
- **FR-4** — The mediated set MUST cover at minimum: filesystem access (open/read/write/create/delete/rename), process creation and program execution, and network connection establishment. The exact syscall list is enumerated in the design.
- **FR-5** — Leash MUST produce, at the end of a run, a human-readable **session report**: files touched, processes spawned, network connections attempted, each with its decision.

### 6.2 Policy & enforcement
- **FR-6** — Leash MUST evaluate each mediated syscall against a declarative **policy** (ADR-0004) and resolve a **decision** of allow, deny, or **ask**.
- **FR-7** — Policy MUST be expressible over at least: filesystem paths, network hosts, and executable binaries.
- **FR-8** — Enforcement MUST be defense-in-depth: the seccomp-unotify decision layer AND an always-on Landlock boundary (ADR-0003). A denied action MUST NOT take effect.
- **FR-9** — Every **decision** MUST be **fail-closed**: any supervisor error, crash, or decision timeout resolves the pending action to **deny** (NFR-1).
- **FR-10** — For an **ask** decision, Leash MUST pause the child and block the action until the operator approves or denies; on no response within a configured bound, it MUST deny.
- **FR-18** — The **policy** MUST be a TOML file with an explicit schema-version field and a fixed, versioned predicate vocabulary covering at least: filesystem path globs, network host allowlists, and executable binary allowlists, each rule resolving to allow, deny, or **ask**. A policy that fails to parse, has an unknown schema version, or contains unknown predicates MUST be rejected before the run starts, never partially applied.
- **FR-19** — Leash MUST run in exactly one of two modes (ADR-0010), announced at run start, stamped into the **trace**, and named in the **session report**: **record-only** (every mediated syscall allowed and traced; actions a present policy would have denied are flagged) and **enforce** (deny-by-default per the policy; requires a policy file). A run with no policy file is record-only. The mode MUST NOT change mid-run. Record-only output MUST NOT be described as enforcement.
- **FR-20** — In an attended run, an **ask** is a terminal prompt, subject to FR-10's timeout-to-deny. In an unattended run (no controlling terminal, or explicitly requested), an **ask** MUST resolve to deny immediately unless the policy pre-authorizes the action; unattended asks MUST NOT queue or block. Attendance is stamped into the trace.

### 6.3 Time travel
- **FR-11** — Leash MUST capture **snapshots** of the **workspace** at **step** boundaries during a run (ADR-0005, ADR-0009).
- **FR-12** — `leash rewind` MUST restore the workspace to a chosen earlier snapshot of a run. Rewind reverses filesystem effects only; it MUST NOT claim to reverse effects already emitted off-host.
- **FR-13** — `leash diff` MUST compare the filesystem effects of two runs (or two steps), correctly interpreting write-layer semantics (deletions/whiteouts, renames, hard links).
- **FR-17** — A **step** is a coalesced burst of the child's mediated filesystem writes: writes closer together than a coalescing window (a design parameter) belong to one step; the boundary falls when write activity quiesces and MUST NOT fall inside a burst. Run start and end are always step boundaries. Steps MUST be derived solely from supervisor-observed events (ADR-0006).

### 6.4 Interface & portability
- **FR-14** — Leash MUST run on Linux 5.19 or later (ADR-0012). This floor is set by the capabilities the supervisor depends on, not by either mechanism's earliest appearance: `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (5.19), so a signal-cancelled notification cannot double-execute a supervisor-performed action; `SECCOMP_ADDFD` and `SECCOMP_ADDFD_FLAG_SEND` (5.9, 5.14); and Landlock ABI 2 (5.19), so cross-directory rename and link the policy allows are not denied by the backstop. Preflight MUST verify the capabilities, not merely the version string. Below the floor Leash MUST refuse to run with a clear message rather than silently degrade security.
- **FR-15** — Leash MUST run on x86-64 and ARM64 (the Raspberry Pi and VPS targets).
- **FR-16** — Traces MUST persist in a documented, machine-readable format (e.g. JSONL); the format SHOULD align with the draft agent-audit-trail schema where practical.
- **FR-21** — Traces and snapshots MUST persist under a per-run directory in an operator-configurable state directory (default per XDG, e.g. `$XDG_STATE_HOME/leash/runs/<run-id>`). The state directory MUST lie outside the **workspace**, and in enforce mode the child MUST be denied access to it (FR-3). Leash MUST NOT delete run data automatically; retention is the operator's, assisted by a listing/pruning subcommand.

## 7. Non-functional requirements

- **NFR-1 — Fail-closed integrity.** The system MUST never fail open. Where any requirement conflicts with this, fail-closed wins.
- **NFR-2 — Overhead.** Added latency per mediated syscall and end-to-end wall-clock overhead on a representative agent task MUST be measured and reported (section 10). Leash SHOULD keep overhead low enough to run always-on. The concrete budget is deferred (section 11, OQ-5).
- **NFR-3 — Auditability.** Policy MUST be human-readable and diffable; the trace MUST suffice to reconstruct what the agent did without the agent's cooperation.
- **NFR-4 — Portability & footprint.** MUST build and run on a Raspberry Pi 4 class device; MUST NOT require significant ongoing cloud/compute spend.
- **NFR-5 — Defensibility.** Every control described as *enforced* MUST have passing **escape**-attempt tests. No claim without a test.
- **NFR-6 — Reviewability.** Security-critical code paths (decision loop, enforcement setup, recorder) MUST be small and isolated enough to audit; policy evaluation MUST be pure and exhaustively unit-testable.

## 8. Security requirements

The threat model is a working document, promoted into `docs/` once load-bearing for external readers.

- **SR-1** — The system MUST treat the agent and all its descendants as hostile.
- **SR-2** — The system MUST resist the enumerated **escape** classes: child-process laundering, symlink/TOCTOU races, `/proc` self-reference, alternate-syscall equivalents (including `io_uring` and `openat2`), fd inheritance/passing, recorder-tampering. Each enforced control MUST map to tests for the escapes it claims to stop.
- **SR-3** — The system MUST NOT rely on any control the child can disable or reason around (ADR-0003).
- **SR-4** — In **enforce** mode, syscalls that establish un-mediated I/O paths (notably `io_uring_setup`) MUST be denied. Relaxing this for a path requires a spec change adding equivalent mediation and escape tests for that path first.

## 9. Out of scope (explicit)

- Kernel exploits / privilege escalation past the OS boundary.
- Hardware and micro-architectural side channels.
- A malicious **operator** (Leash protects the operator from their agent, not the world from the operator).
- Covert exfiltration through channels the policy allows.
- Deterministic re-execution of the agent (ADR-0005).
- Multi-host / fleet orchestration and any hosted service (Leash is a local CLI).

## 10. Acceptance criteria

A capability is done only when:
1. It satisfies its FR/NFR IDs, demonstrated by an **observed behavioral check**, not inspection of the diff.
2. For any enforcement claim, the relevant **escape** tests pass (NFR-5).
3. Fail-closed behavior is demonstrated for the relevant error/timeout paths (FR-9).
4. Overhead numbers, where claimed, are measured with a stated method, kernel, and architecture (NFR-2).

The certified/golden test inventory is maintained alongside the test suite.

## 11. Open questions

OQ-1..OQ-4 and OQ-6..OQ-8 were resolved on 2026-07-07 into FR-17..FR-21, SR-4, ADR-0009, and ADR-0010. One item remains, deferred on purpose:

- **OQ-5 — Overhead budget (deferred).** The concrete NFR-2 target is set from real measurements once the M1 recorder exists on both reference targets; a number chosen earlier would be a guess. *Trigger to close:* M1 measurements per section 10, item 4.

## 12. Traceability

| Requirement | Realized by decision | Verified by |
|---|---|---|
| FR-3 (log integrity) | ADR-0002 | recorder-tamper escape tests |
| FR-8 (defense in depth) | ADR-0003 | per-layer escape tests |
| FR-6/FR-7 (policy) | ADR-0004 | policy-engine unit tests |
| FR-11..13 (time travel) | ADR-0005, ADR-0009 | overlay-semantics tests, mechanism-equivalence tests |
| FR-17 (step semantics) | ADR-0006, ADR-0009 | step-boundary tests |
| FR-18 (policy format) | ADR-0004 | policy schema/rejection tests |
| FR-19 (run modes) | ADR-0010 | mode-stamping and would-deny tests |
| FR-20 (approval UX) | ADR-0010 | attended/unattended ask tests |
| FR-21 (trace persistence) | ADR-0002 | state-dir isolation escape tests |
| SR-4 (io_uring denial) | ADR-0003 | io_uring bypass escape tests |
| FR-1/FR-4 (agent-agnostic coverage) | ADR-0006 | inheritance + coverage tests |
| NFR-4 (footprint), FR-15 | ADR-0007 | build/run on Pi + VPS |

Every FR/NFR should trace to a decision and a verification; the table grows with the spec.
