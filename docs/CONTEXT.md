# Leash — Context (Ubiquitous Language)

The canonical vocabulary of the Leash project. Every document, identifier, commit message, and test name uses these terms exactly. When multiple words exist for one concept, the canonical term is defined and the rejected synonyms are listed under `_Avoid_`.

This file is a **glossary, not a spec**. It defines what terms *are*, never how things *work* (that is the spec/design) or why choices were made (that is an ADR).

## Core

**Agent**:
The AI coding tool being supervised (e.g. Claude Code, Cursor's agent) — treated as untrusted. Includes every process it spawns.
_Avoid_: AI, model, assistant, tool (when you mean the supervised program)

**Supervisor**:
The trusted `leash` process that mediates the agent. Holds the policy, the recorder, and the snapshot manager. The sole author of the audit log.
_Avoid_: monitor, parent, host

**Child**:
The supervised process tree rooted at the agent. Everything inside the security boundary; untrusted.
_Avoid_: target, sandbox (the child is *inside* the sandbox, it is not the sandbox)

**Workspace**:
The directory tree the agent is permitted to read and write by default — normally the project repository it is working on.
_Avoid_: project dir, sandbox dir, working directory (ambiguous with process cwd)

## Mediation

**Mediated syscall**:
A system call the supervisor intercepts and decides on before the kernel executes it. The set of mediated syscalls is explicit and reviewed.
_Avoid_: hooked call, trapped call (use "mediated")

**Decision**:
The supervisor's verdict on a mediated syscall: **allow**, **deny**, or **ask**. Always resolves; on error it resolves to **deny** (**fail-closed**), with the one mode-scoped exception FR-9 states.
_Avoid_: verdict, ruling, judgement

**Policy**:
The declarative, user-authored rules (data, not code) that determine decisions. Expressed over paths, hosts, and binaries.
_Avoid_: config, ruleset (reserve "ruleset" for the Landlock kernel object)

**Ask** (an approval):
A decision that pauses the child and requests a human yes/no before proceeding.
_Avoid_: prompt (collides with LLM "prompt"), confirm

**Record-only** (mode):
The run mode in which every mediated syscall is allowed and traced, except the un-mediated-I/O-path syscalls SR-4 denies in both modes; nothing else is enforced (FR-19). The mode a run gets when no policy file exists.
_Avoid_: monitor mode, audit mode, dry-run

**Enforce** (mode):
The run mode in which decisions are enforced deny-by-default per the **policy** (FR-19). Requires a policy file.
_Avoid_: strict mode, secure mode, sandbox mode

## Recording & time travel

**Event**:
One recorded fact about something the child did — a mediated syscall and its decision. The unit of the audit log.
_Avoid_: log line, record (reserve "record" for ADRs)

**Trace**:
The ordered, append-only sequence of events for one supervised run. The ground-truth account of what the agent did.
_Avoid_: log, history, transcript (a transcript is the agent's *self-report*; a trace is ground truth — the distinction is the whole point of the project)

**Run**:
One complete supervised session — one invocation of `leash run`. Produces one trace.
_Avoid_: session, execution

**Session report**:
The human-readable summary produced at the end of a **run** (FR-5): the files touched, processes spawned, and network connections attempted, each with its **decision**, plus the active **mode**. A fixed compound term carried from the spec; it is the one sanctioned use of the word "session", which is otherwise avoided in favor of **run**.
_Avoid_: run report, summary (the canonical compound is "session report")

**Snapshot**:
The captured state of the workspace at a **step** boundary, enabling rewind and diff. Implemented over the workspace's write layer.
_Avoid_: checkpoint, backup

**Step**:
One coalesced burst of the child's mediated filesystem writes; steps partition a run, and a snapshot is captured at each step boundary (FR-17). Rewind targets are step boundaries.
_Avoid_: tick, frame

**Rewind**:
Restoring the workspace to an earlier snapshot. Reverses *effects on the filesystem*; it does **not** re-run the agent.
_Avoid_: replay (forbidden — implies deterministic re-execution of the model, which Leash never does), rollback, undo (informal only)

**Diff** (of runs):
A comparison of the effects of two runs, computed from their snapshots/traces.
_Avoid_: compare, delta

## Security

**Boundary**:
The trust line between supervisor (trusted) and child (untrusted). No child action crosses it un-mediated.
_Avoid_: barrier, wall (informal only)

**Escape**:
An action by the child that achieves a policy-forbidden effect despite the boundary. Every claimed control must have tests proving named escapes fail.
_Avoid_: bypass (acceptable informally; "escape" is canonical), breakout

**Fail-closed**:
The property that any supervisor error, crash, or timeout resolves a pending decision to **deny**, never allow. FR-9 states the rule and the one arc it scopes by **mode**.
_Avoid_: fail-safe, fail-secure
