# Leash — Software Specification

- Status: **v0.8, settled** (section 11 holds one explicitly deferred item, OQ-9, with a named closing trigger)
- Date: 2026-07-23 (v0.8 scoped FR-9's undecodable-network arc by mode, made NFR-1 consistent with it, and named `pidfd_getfd` as SR-4's second member, all per ADR-0019, from the issue #26 hygiene pass; v0.7 dated 2026-07-13 closed OQ-5 into NFR-2's concrete budget from the M1 measurements; v0.6 added FR-22's exit-code contract; v0.5 recorded FR-14's mode split for the Landlock leg per ADR-0015; v0.4 deferred the ARM64 target per ADR-0014; v0.3 revised FR-14's kernel floor to 5.19 per ADR-0012; v0.2 dated 2026-07-07)
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
| F-1 | Supervised run (`leash run`) | FR-1, FR-2, FR-4, FR-14, FR-15, FR-22 |
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
| F-10 | io_uring mediation | Replace SR-4's `io_uring` denial with equivalent mediation plus escape tests, if a real workload needs it. |

## 6. Functional requirements

### 6.1 Running & recording
- **FR-1** — Leash MUST launch an agent via `leash run -- <command>` and supervise the entire **child** process tree, including descendants created by `fork`/`clone`/`exec`.
- **FR-2** — Leash MUST record every **mediated syscall** and its **decision** as an ordered, append-only **event** in the run's **trace**.
- **FR-3** — The **trace** MUST be authored solely by the **supervisor**; the **child** MUST NOT be able to read, modify, delay, or suppress it (ADR-0002).
- **FR-4** — The mediated set MUST cover at minimum: filesystem access (opening a path, with read and write access decided at that point, plus create, delete, and rename), process creation and program execution, and network connection establishment. The exact syscall list is enumerated in the design.
- **FR-5** — Leash MUST produce, at the end of a run, a human-readable **session report**: files touched, processes spawned, network connections attempted, each with its decision.
- **FR-22** — `leash run` MUST exit with the supervised command's exit status (128 plus the signal number when the command was killed by a signal). A failure of Leash itself MUST exit with a code distinct from ordinary agent outcomes (125) so a wrapper can distinguish agent failure from supervisor failure; the **trace** remains the authority (a missing `run_end` means the supervisor failed). Usage errors exit 2.

### 6.2 Policy & enforcement
- **FR-6** — Leash MUST evaluate each mediated syscall against a declarative **policy** (ADR-0004) and resolve a **decision** of allow, deny, or **ask**.
- **FR-7** — Policy MUST be expressible over at least: filesystem paths, network hosts, and executable binaries.
- **FR-8** — In **enforce** mode, enforcement MUST be defense-in-depth: the seccomp-unotify decision layer AND a Landlock boundary applied by the child before the agent executes, backstopping every dimension the kernel can express (ADR-0003, ADR-0013). A denied action MUST NOT take effect. Record-only enforces nothing and applies no Landlock ruleset (FR-19).
- **FR-9** — Every **decision** MUST be **fail-closed**: any supervisor error, crash, or decision timeout resolves the pending action to **deny** (NFR-1).
  One arc is scoped by mode (ADR-0010, ADR-0019).
  Where the supervisor cannot decode a network address from the trapped `sockaddr`, **enforce** MUST deny the pending action, while **record-only** MUST record the attempt as an **event** carrying no destination and let it continue, because record-only enforces nothing outside SR-4's denied set (FR-19) and denying there would constrain a mode that makes no enforcement claim.
  That arc is the only one scoped by mode.
  Every other arc remains fail-closed in both modes: a filesystem or process-creation fact the supervisor cannot decode, a recorder-write failure, a supervisor crash, a decision timeout, and every syscall establishing an un-mediated I/O path (SR-4, which covers `io_uring_setup` and `pidfd_getfd`).
- **FR-10** — For an **ask** decision, Leash MUST pause the child and block the action until the operator approves or denies; on no response within a configured bound, it MUST deny.
- **FR-18** — The **policy** MUST be a TOML file with an explicit schema-version field and a fixed, versioned predicate vocabulary covering at least: filesystem path globs, network host allowlists, and executable binary allowlists, each rule resolving to allow, deny, or **ask**. A policy that fails to parse, has an unknown schema version, or contains unknown predicates MUST be rejected before the run starts, never partially applied.
- **FR-19** — Leash MUST run in exactly one of two modes (ADR-0010), announced at run start, stamped into the **trace**, and named in the **session report**: **record-only** (every mediated syscall allowed and traced, except syscalls that establish an un-mediated I/O path, which are denied and recorded so the trace stays complete, SR-4; actions a present policy would have denied are flagged) and **enforce** (deny-by-default per the policy, with the **workspace** allowed by default per its definition; requires a policy file). A run with no policy file is record-only. The mode MUST NOT change mid-run. Record-only output MUST NOT be described as enforcement.
- **FR-20** — In an attended run, an **ask** is a terminal prompt, subject to FR-10's timeout-to-deny. In an unattended run (no controlling terminal, or explicitly requested), an **ask** MUST resolve to deny immediately unless the policy pre-authorizes the action; unattended asks MUST NOT queue or block. Attendance is stamped into the trace.

### 6.3 Time travel
- **FR-11** — Leash MUST capture **snapshots** of the **workspace** at **step** boundaries during a run (ADR-0005, ADR-0009).
- **FR-12** — `leash rewind` MUST restore the workspace to a chosen earlier snapshot of a run. Rewind reverses filesystem effects only; it MUST NOT claim to reverse effects already emitted off-host.
- **FR-13** — `leash diff` MUST compare the filesystem effects of two runs (or two steps), correctly interpreting write-layer semantics (deletions/whiteouts, renames, hard links).
- **FR-17** — A **step** is a coalesced burst of the child's mediated filesystem writes: writes closer together than a coalescing window (a design parameter) belong to one step; the boundary falls when write activity quiesces and MUST NOT fall inside a burst. Run start and end are always step boundaries. Steps MUST be derived solely from supervisor-observed events (ADR-0006).

### 6.4 Interface & portability
- **FR-14** — Leash MUST run on Linux 5.19 or later (ADR-0012). This floor is set by the capabilities the supervisor depends on, not by either mechanism's earliest appearance: `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (5.19), so a signal-cancelled notification cannot double-execute a supervisor-performed action; `SECCOMP_ADDFD` and `SECCOMP_ADDFD_FLAG_SEND` (5.9, 5.14); and Landlock ABI 2 (5.19), so cross-directory rename and link the policy allows are not denied by the backstop. Preflight MUST verify the capabilities, not merely the version string; the version check is itself a hard gate alongside the probes (ADR-0015). Below the floor Leash MUST refuse to run with a clear message rather than silently degrade security. The Landlock ABI 2 leg of the floor applies to enforce mode only: record-only applies no Landlock ruleset (ADR-0010), so a host below that ABI MAY still run record-only; the version gate and the seccomp legs apply in both modes.
- **FR-15** — Leash MUST run on x86-64 (the VPS reference target). ARM64 support is deferred (OQ-9, ADR-0014).
- **FR-16** — Traces MUST persist in a documented, machine-readable format (e.g. JSONL); the format SHOULD align with the draft agent-audit-trail schema where practical.
- **FR-21** — Traces and snapshots MUST persist under a per-run directory in an operator-configurable state directory (default per XDG, e.g. `$XDG_STATE_HOME/leash/runs/<run-id>`). The state directory MUST lie outside the **workspace**, and in enforce mode the child MUST be denied access to it (FR-3). Leash MUST NOT delete run data automatically; retention is the operator's, assisted by a listing/pruning subcommand.

## 7. Non-functional requirements

- **NFR-1 — Fail-closed integrity.** The system MUST never fail open. Where any requirement conflicts with this, fail-closed wins.
  Failing open is measured against what a **mode** claims to enforce.
  **Record-only** claims nothing beyond SR-4's denied set (FR-19), so recording an undecodable network attempt and letting it continue is not a fail-open in that mode (FR-9, ADR-0019); in **enforce**, where the claim is made, the same arc denies.
- **NFR-2 — Overhead.** Added latency per mediated syscall and end-to-end wall-clock overhead on a representative agent task MUST be measured and reported (section 10). Leash SHOULD keep overhead low enough to run always-on. On the reference environment (x86-64 KVM, `docs/measurements/0001-m1-overhead.md` section 3), added latency per mediated filesystem syscall MUST NOT exceed 50 microseconds at p50 and 200 microseconds at p99, added latency per exec MUST NOT exceed 2 milliseconds at p50, and end-to-end wall-clock MUST NOT exceed 3x even on a syscall-dense worst-case workload (budget set from the M1 measurements, measurement 0001 section 5; measured 2026-07-13: 31-37 us p50, 2.46x worst case). A typical-agent-session wall-clock target is deferred until a real agent session is measured on the reference environment; that measurement is the trigger to add it.
- **NFR-3 — Auditability.** Policy MUST be human-readable and diffable; the trace MUST suffice to reconstruct what the agent did without the agent's cooperation.
- **NFR-4 — Portability & footprint.** MUST NOT require significant ongoing cloud/compute spend; SHOULD stay light enough for modest hardware. The Raspberry Pi 4 class target is deferred with ARM64 (OQ-9).
- **NFR-5 — Defensibility.** Every control described as *enforced* MUST have passing **escape**-attempt tests. No claim without a test.
- **NFR-6 — Reviewability.** Security-critical code paths (decision loop, enforcement setup, recorder) MUST be small and isolated enough to audit; policy evaluation MUST be pure and exhaustively unit-testable.

## 8. Security requirements

The threat model is a working document, promoted into `docs/` once load-bearing for external readers.

- **SR-1** — The system MUST treat the agent and all its descendants as hostile.
- **SR-2** — The system MUST resist the enumerated **escape** classes: child-process laundering, symlink/TOCTOU races, `/proc` self-reference, alternate-syscall equivalents (including `io_uring` and `openat2`), fd inheritance/passing, recorder-tampering. Each enforced control MUST map to tests for the escapes it claims to stop.
- **SR-3** — The system MUST NOT rely on any control the child can disable or reason around (ADR-0003).
- **SR-4** — Syscalls that establish an un-mediated I/O path MUST be denied in both modes: in **enforce** because the policy could not otherwise constrain the path, and in **record-only** because the path would make the **trace** silently incomplete. The denial MUST be recorded as an **event**, so the attempt is visible and record-only remains non-enforcing in every other respect. Relaxing this for a path requires a spec change adding equivalent mediation and escape tests for that path first.
  The class has two members in v1.
  `io_uring_setup` submits I/O out of band through a shared ring the filter never observes.
  `pidfd_getfd` imports a file descriptor out of another process, so the resource it names was decided by no mediated syscall and every later read or write on it is I/O the trace cannot attribute (ADR-0019).
  Membership is decided by that test, not by the list: a syscall belongs here when letting it through would leave the trace unable to describe I/O the child performed.

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

OQ-1..OQ-4 and OQ-6..OQ-8 were resolved on 2026-07-07 into FR-17..FR-21, SR-4, ADR-0009, and ADR-0010; OQ-5 closed on 2026-07-13 (below). One item remains, deferred on purpose:

- **OQ-5 — Overhead budget (closed 2026-07-13).** Resolved into NFR-2's concrete budget from the M1 measurements (`docs/measurements/0001-m1-overhead.md`): 50 us p50 / 200 us p99 per mediated filesystem syscall, 2 ms p50 per exec, 3x wall-clock on the syscall-dense worst case. The same measurements fixed the FR-17 coalescing window at 250 ms (design, snapshot.md section 1). One follow-on input stays named: a real agent-session measurement adds the typical-session wall-clock target and confirms the window.
- **OQ-9 — ARM64 target (deferred).** FR-15 and NFR-4 originally named ARM64 and a Raspberry Pi 4 class device; the ARM64 leg of the M0 spike was cancelled and the MVP targets x86-64 only (ADR-0014). *Trigger to reopen:* a real need for an ARM64 host. Before any support claim, the M0 spike's ARM64 leg must pass on hardware and the syscall table's ARM64 column (design, syscalls.md section 3) must be validated there.

## 12. Traceability

| Requirement | Realized by decision | Verified by |
|---|---|---|
| FR-3 (trace integrity) | ADR-0002 | recorder-tamper escape tests |
| FR-8 (defense in depth) | ADR-0003, ADR-0013 | per-layer escape tests |
| FR-6/FR-7 (policy) | ADR-0004 | policy-engine unit tests |
| FR-2/FR-9 (ordered trace, fail-closed), NFR-6 | ADR-0011, ADR-0019 (mode scope of the undecodable-network arc) | fail-closed enumeration, notify-loop fault tests |
| FR-11..13 (time travel) | ADR-0005, ADR-0009 | overlay-semantics tests, mechanism-equivalence tests |
| FR-14 (kernel floor) | ADR-0012, ADR-0015 | preflight capability probes on 5.19+ |
| FR-17 (step semantics) | ADR-0006, ADR-0009 | step-boundary tests |
| NFR-2 (overhead budget) | OQ-5 closure, measurement 0001 | `benches/overhead.rs` on the reference environment |
| FR-18 (policy format) | ADR-0004 | policy schema/rejection tests |
| FR-19 (run modes) | ADR-0010 | mode-stamping and would-deny tests |
| FR-20 (approval UX) | ADR-0010 | attended/unattended ask tests |
| FR-21 (trace persistence) | ADR-0002 | state-dir isolation escape tests |
| FR-22 (exit-code contract) | design (cli.md section 6) | exit-code contract tests |
| SR-4 (un-mediated I/O path denial: `io_uring_setup`, `pidfd_getfd`) | ADR-0019, design (syscalls.md section 5) | io_uring and `pidfd_getfd` escape tests |
| FR-1/FR-4 (agent-agnostic coverage) | ADR-0006 | inheritance + coverage tests |
| NFR-4 (footprint), FR-15 | ADR-0007, ADR-0014 | build/run on the VPS reference target |

Every FR/NFR should trace to a decision and a verification; the table grows with the spec.
