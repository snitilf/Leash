# Measurement 0001: M1 record-only overhead (NFR-2) and step-gap data (FR-17)

- Status: measured 2026-07-13 on the reference box; one supplementary input (a real
  agent-session gap trace) remains pending and is named in section 4.3
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

A number without its environment is meaningless. All results in section 4 come from:

- Box: DigitalOcean KVM droplet "leash" (the reference VPS), 2 vCPU DO-Premium-Intel @ 2.0 GHz,
  3.8 GiB RAM, x86-64
- OS / kernel: Ubuntu 24.04.4 LTS, Linux 6.8.0-124-generic
- Leash commit: 3503baf, plus one harness-only fix (drop the `--bench` flag cargo passes to
  custom-main bench targets before positional arg parsing; no effect on what is measured)
- Rust toolchain: rustc 1.97.0, bench profile (optimized)
- Reproduction: `cargo bench --bench overhead -- micro`, `cargo bench --bench overhead -- macro
  benches/workloads/macro.sh`, and for gaps a traced run
  (`leash run --unattended --state-dir <dir> -- sh benches/workloads/macro.sh <work>`) followed
  by `cargo bench --bench overhead -- gaps <trace.jsonl>`
- Measured 2026-07-13. The box is a shared-tenancy 2 vCPU cloud instance: the bare-vs-bare
  self-check delta was -154 ns p50 (noise floor), small against every leash delta below.

## 4. Results

### 4.1 Micro: per-class latency (bare vs leash), ns

3 reps per cell, medians of per-rep quantiles; warmup discarded; every leash rep passed the
trap-completeness gate (zero voids).

| class | bare p50 | leash p50 | added p50 | bare p99 | leash p99 | added p99 |
|---|---|---|---|---|---|---|
| open_read | 1596 | 35144 | 33548 | 3113 | 63183 | 60070 |
| open_write | 1832 | 32555 | 30723 | 3321 | 59280 | 55959 |
| mutate (2 renames) | 11416 | 86209 | 74793 | 23540 | 139641 | 116101 |
| exec (/bin/true) | 639287 | 1148502 | 509215 | 885874 | 1660894 | 775020 |

Read: record-only supervision adds roughly 31-34 us p50 per trapped filesystem syscall
(56-60 us p99), about 37 us per rename, and about 0.5 ms p50 per exec (an exec traps several
syscalls: the execve itself plus the new image's opens).

### 4.2 Macro: wall-clock delta

`benches/workloads/macro.sh` (materialize the tracked tree, recursive read pass, 200
create/append/rename triplets, git init + add + commit), 5 alternating reps, fresh workdir
each:

- bare: median 429 ms, spread 77 ms (404-481)
- leash: median 1054 ms, spread 326 ms (955-1281)
- delta: +625 ms at the median, a 2.46x factor

This workload is deliberately syscall-dense (about 10800 mediated events in about one second
of bare runtime); it is the worst case, not the typical agent profile, where wall-clock is
dominated by model inference and the same per-syscall cost amortizes to noise. The factor is
reported as measured; no claim is made that typical sessions see it.

### 4.3 Gap distributions

From the traced macro run (10771 events, 1981 mutating events, 1980 consecutive gaps):

- gap ms: min 0, p50 0, p90 2, p99 3, max 10
- histogram (inclusive upper bound in ms -> count): <=0: 1556, <=1: 214, <=2: 134, <=5: 74,
  <=10: 2

The intra-burst cluster on a continuous write workload sits entirely at or below 10 ms even on
a loaded 2 vCPU box, comfortably resolvable at the trace's ms timestamp resolution; no schema
resolution bump is needed. The inter-burst side (agent think time between tool calls) is not in
this trace: no agent CLI exists on the reference box yet. That input is named pending; model
inference latency bounds it below at hundreds of milliseconds in practice, so the clusters
cannot overlap unless a window is chosen inside 10-100 ms.

## 5. Candidate ranges and decision handoff

What the data supports, for the operator to choose from (recorded in SPEC.md closing OQ-5, and
in snapshot.md section 1 plus the design README table for the window, citing this document):

- **NFR-2 per-syscall budget:** measured 31-37 us p50 added per mediated fs syscall. A budget of
  **at most 50 us p50 / 200 us p99 added per mediated filesystem syscall** on the reference
  environment holds today with headroom for the enforce-mode policy engine; exec at
  **at most 2 ms p50** likewise.
- **NFR-2 end-to-end:** the honest worst-case factor is about 2.5x on a syscall-dense scripted
  workload. A budget of **at most 3x wall-clock on the syscall-dense worst case** is defensible
  now; a typical-agent-session target should wait for a real agent trace rather than be guessed.
- **Coalescing window:** intra-burst gaps max out at 10 ms; anything at or above 100 ms cannot
  split a burst of this shape. Candidates: 100 ms (finest useful step granularity), 250 ms
  (5x margin over the observed max plus scheduler headroom), 500 ms (the current placeholder,
  most conservative). The pending real-agent trace is the named confirming input for whichever
  value is chosen.
