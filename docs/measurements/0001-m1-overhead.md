# Measurement 0001: M1 record-only overhead (NFR-2) and step-gap data (FR-17)

- Status: method settled, results pending (droplet run outstanding)
- Governs: the evidence base for closing OQ-5 (the NFR-2 overhead budget) and for fixing the
  step-coalescing window (the last open design parameter, `design/README.md` table).
- Cites: NFR-2, FR-17; SPEC.md section 10 item 4, section 11 OQ-5; ADR-0006, ADR-0011.
- Method recorded before any number, per the project's evidence discipline
  (spec section 10: overhead numbers are measured with a stated method, kernel, and architecture).

This document reports what M1's record-only supervision costs, measured, not estimated. It does
not choose the budget: the NFR-2 budget and the coalescing window are operator decisions made
from this data and recorded in the spec and design docs, which will cite this file.

## 1. What is measured

Three things, each with its own method:

1. **Per-syscall-class added latency** (micro): the p50/p90/p99 cost the notify round-trip plus
   recording adds to each mediated syscall class, isolated by a tight-loop microbenchmark run
   bare and under `leash run --`.
2. **End-to-end wall-clock delta** (macro): a reproducible file-heavy scripted workload timed
   with Leash on vs off.
3. **Inter-mutating-event gap distribution** (gaps): mined from real traces, this is the data
   the coalescing-window decision needs. The window must sit above the intra-burst gap cluster
   and below the inter-burst cluster (snapshot.md section 1: a boundary must never fall inside
   a burst).

## 2. Harness

All three live in `benches/overhead.rs` (`cargo bench --bench overhead`, custom `harness = false`
main; Linux-only body, no-op elsewhere). CI does not run benches; timing numbers never gate CI.

### 2.1 Micro method

The bench binary re-execs itself as a child that loops one syscall class N times, timing each
iteration with `CLOCK_MONOTONIC` inside the child (so measurement excludes leash startup and
teardown). Classes, matching the mediated surface as of M1:

| class | loop body | N per rep |
|---|---|---|
| `open_read` | `openat(O_RDONLY)` + `close` on a pre-created file | 10000 |
| `open_write` | `openat(O_WRONLY\|O_CREAT)` + `close` | 10000 |
| `mutate` | `rename` A to B, B to A | 10000 |
| `exec` | fork + exec `/bin/true` + wait | 500 |

Each class runs bare and under `leash run --`, 3 repetitions each, warmup prefix discarded.
Reported: p50/p90/p99/min/max per distribution, bare and leash side by side (the added latency
is the difference of the distributions, but both are reported).

Validity gates, enforced by the harness before a number is trusted:
- **Trap completeness:** after each leash rep the harness parses `trace.jsonl` and requires the
  event count for the class to match N. If leash did not trap every iteration the rep is void.
- **Self-check:** a bare-vs-bare run must show a delta indistinguishable from noise before any
  leash number is read.

### 2.2 Macro method

`benches/workloads/macro.sh`: offline and deterministic. It materializes a source tree via
`git archive HEAD` of this repository, runs a recursive read/grep pass, performs a scripted
series of file creates, edits, and renames simulating an agent editing session, then
`git init && git add -A && git commit`. Wall-clock is measured around the whole script,
`leash run -- sh macro.sh` vs bare, 5 alternating repetitions; median and spread reported.

A real agent session (`leash run -- <agent> <small task>`) on the reference box is a
supplementary, labeled-anecdotal data point; it is not reproducible and is reported separately.
Its trace is however a primary input to the gap analysis.

### 2.3 Gap method

`cargo bench --bench overhead -- gaps <trace.jsonl>`: filters events to the mutating set
snapshot.md section 1 defines (open-for-write plus the mutation family: create, rename, unlink,
mkdir, link, symlink, truncate), computes the distribution of consecutive inter-event gaps, and
reports a histogram plus percentiles per trace. Inputs: the macro-workload trace and at least
one real agent-session trace.

Known resolution limit, stated up front: `Event.ts` is unix-epoch milliseconds
(trace.md section 2), so sub-millisecond intra-burst gaps collapse to 0-1 ms. That is sufficient
to place a window in the tens-of-milliseconds-to-seconds range; only if the intra-burst and
inter-burst clusters turn out inseparable at millisecond granularity would a trace-schema
resolution bump be considered, as its own change-controlled item, not preemptively.

## 3. Environment

A number without its environment is meaningless. Every result table below carries:

- Box: (pending: the KVM reference VPS; a macOS laptop cannot produce these numbers)
- Kernel: `uname -a` (pending)
- CPU: model and core count (pending)
- Leash commit: (pending)
- Rust toolchain: (pending)

Exact reproduction commands are recorded with the results.

## 4. Results

Pending the droplet run.

### 4.1 Micro: per-class latency (bare vs leash), ns

(pending)

### 4.2 Macro: wall-clock delta

(pending)

### 4.3 Gap distributions

(pending)

## 5. Candidate ranges and decision handoff

Filled after section 4: candidate NFR-2 budget ranges and candidate coalescing-window values the
data supports, with the trade-offs stated. The choices themselves are made by the operator and
recorded in SPEC.md (closing OQ-5 into a concrete NFR-2 budget) and in snapshot.md section 1 and
the design README parameter table (fixing the window), each citing this document.
