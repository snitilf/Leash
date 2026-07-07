# ADR-0002: Supervisor and child are separate processes; the log lives in the supervisor

- Status: accepted
- Date: 2026-07-07

## Context

Leash's central value is that its **trace** is *ground truth* — trustworthy precisely because the untrusted agent cannot influence it. If the child could read, write, block, or race the audit log or the decision path, the trace would be no more trustworthy than the agent's own self-report, and the project would have no reason to exist.

## Decision

The **supervisor** and the **child** are distinct OS processes. The audit log and every decision are produced solely by the supervisor. The child generates events only by *attempting* actions; it never writes, reads, or has shared memory with the log or the decision logic. This is invariant **I2**.

## Consequences

- The trace is defensible as evidence: an attacker who fully controls the agent still cannot forge or suppress log entries.
- Communication crosses a process boundary (the seccomp notification fd and controlled channels), which constrains the design and adds some latency — an acceptable price for integrity.
- The recorder is single-writer (the supervisor), simplifying its correctness argument.

## Alternatives considered

- **In-process instrumentation / a library the agent loads.** Rejected: anything in the child's address space is reachable by a hostile child, and defeats the entire ground-truth premise. Also see ADR-0006.
