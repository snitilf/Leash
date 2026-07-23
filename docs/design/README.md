# Design

*How* Leash is built. This layer is written after the specification is settled: a design that
commits to *how* before *what* builds the wrong thing precisely. Every design choice cites the spec
requirement it satisfies and, where it is a hard-to-reverse trade-off, an ADR.

Status: **frozen (2026-07-08).** All eight files are settled. The M0 spike's gate, narrowed to the
x86-64 leg by ADR-0014 (the ARM64 target is deferred, spec OQ-9), passed on 2026-07-08, settling
`snapshot.md` and freezing the layer; `cli.md` was added by the recorded decisions of 2026-07-11
(FR-22). Changes from here follow change control; a frozen file is amended by a recorded decision,
not edited casually. Three amendments have landed since:

- 2026-07-13, from slice 1 of #25: the glob and host pins in `policy.md` sections 2.1 and 2.2
  (dated inline there), and the 250 ms coalescing window in `snapshot.md` section 1, whose
  provenance is the open-parameters row below and the measurement it cites rather than an inline
  date.
- 2026-07-14, from slice 2 of #25: the workspace base allow in `policy.md` section 1 (dated
  inline).
- 2026-07-23, from the issue #26 hygiene pass, carrying ADR-0019 and spec v0.8: the IPv4-mapped
  normalization in `policy.md` sections 2.2 and 7, the mode-scoped network arc in
  `notify-loop.md` sections 2 and 4 and `syscalls.md` section 4, `pidfd_getfd` joining the
  denied-and-recorded set in `syscalls.md` sections 3.4 and 5, the `host` field, the cross-process
  fact, and the raw-fact wording in `trace.md` section 2, invariant I3 in `architecture.md`
  section 3, and the escape row and residual entry in `escapes.md` sections 3 and 4. Each carries its
  provenance where it lands, as an inline date or as the ADR-0019 citation.

The issue #26 implementation applies the IPv4-mapped normalization at the `sockaddr` and policy-load seams and denies `pidfd_getfd` in both modes under the stable SR-4 rule id.

## Reading order

1. [`architecture.md`](architecture.md) - system and trust model, invariants I1-I5, module
   decomposition, supervisor lifecycle. Read this first; every other file cites its invariants.
2. [`syscalls.md`](syscalls.md) - which syscalls are mediated, denied-and-recorded, or passed
   through, and how each allow is realized safely (FR-4).
3. [`notify-loop.md`](notify-loop.md) - the notify-fd protocol and the fail-closed enumeration (FR-9).
4. [`policy.md`](policy.md) - the TOML schema, evaluation, and Landlock derivation (FR-18).
5. [`trace.md`](trace.md) - run directory, event schema, session report (FR-2, FR-16, FR-5).
6. [`snapshot.md`](snapshot.md) - step detection, overlay and copy fallback, rewind, diff (FR-11-13).
7. [`escapes.md`](escapes.md) - escape-vector-to-mechanism traceability (SR-2, NFR-5).
8. [`cli.md`](cli.md) - command surface, run lifecycle announcements, exit codes (FR-5, FR-19,
   FR-20, FR-21, FR-22).

## Files and status

| File | Covers | Status |
|---|---|---|
| `architecture.md` | model, invariants, modules, lifecycle | settled |
| `syscalls.md` | mediated-syscall enumeration (FR-4) | settled |
| `notify-loop.md` | notify protocol, fail-closed (FR-9) | settled |
| `policy.md` | policy schema, evaluation, Landlock derivation (FR-18) | settled |
| `trace.md` | run dir, event schema, report (FR-2, FR-16, FR-5) | settled |
| `snapshot.md` | step, snapshot, rewind, diff (FR-11-13, FR-17) | settled (M0 gate met per ADR-0014) |
| `escapes.md` | escape traceability (SR-2, NFR-5) | settled |
| `cli.md` | command surface, lifecycle, exit codes (FR-22) | settled |

## Open parameters

Design parameters were deliberately left unfixed until a named review or event closed them, the
same discipline the spec uses for its open questions. All but one were fixed at the closing slate
of 2026-07-08; the coalescing window closed last, on 2026-07-13, from the M1 overhead
measurements (`../measurements/0001-m1-overhead.md`, with OQ-5).
No parameter is open. Two closed rows carry later amendments, both recorded on 2026-07-23 for
issue #26: host matching gained IPv4-mapped normalization, and the child memory-read cap gained
the record-only network exception.

| Parameter | Where | Resolution | Closed |
|---|---|---|---|
| Path/binary glob syntax and anchoring | `policy.md` section 2.1 | gitignore-style `*` / `**` / `?`, anchored to the full resolved path | slate 2 |
| Host matching | `policy.md` section 2.2 | exact hostname, `*.suffix`, IP, CIDR; hostname rules via supervisor-side resolution against the connected IP; residual named in `escapes.md`; IPv4-mapped IPv6 forms normalized to IPv4 on both the destination and the rule side | slate 2, amended 2026-07-23 for #26 |
| `mode = ["execute"]` vs the `exec` table | `policy.md` section 2.3 | one control: the `exec` table; no `execute` mode on `fs` | slate 2 |
| Run-id format | `trace.md` sections 1, 5 | UTC timestamp + 6-char base32 suffix, e.g. `20260708T153012Z-7k3m9q` | slate 2 |
| fsync granularity | `trace.md` sections 4, 5 | step-boundary default, per-event as an opt-in flag | slate 2 |
| Event envelope field names | `trace.md` sections 2, 5 | fixed as documented; audit-trail draft alignment deferred to the M1 serializer, renames land as a `schema_version` bump | slate 2 |
| `openat2` resolve-flag set, in-workspace symlinks | `syscalls.md` section 4 | `RESOLVE_BENEATH \| RESOLVE_NO_MAGICLINKS` beneath the workspace (in-tree symlinks work); `RESOLVE_BENEATH \| RESOLVE_NO_SYMLINKS` for other roots | slate 2 |
| Socket fidelity for a host-enforced network operation | `syscalls.md` section 3.5 | the supervisor duplicates the child's actual socket with `pidfd_getfd`; the confined broker operates on the shared open file description | ADR-0020 |
| Child memory-read cap | `notify-loop.md` section 2 | 4096 bytes (path), 128 bytes (`sockaddr`), kernel struct size (`clone_args`), 65,535 bytes for a destination-bearing `sendto` payload and as the absolute fixed-read ceiling; over cap denies, except a malformed or over-cap network address in record-only, which records a `raw` allow (`notify-loop.md` section 2, case C) | ADR-0020, amended 2026-07-23 |
| Ask timeout default | `notify-loop.md` section 5 | 60 seconds, operator-configurable; timeout denies (FR-10) | slate 2 |
| Coalescing window for step detection (FR-17) | `snapshot.md` section 1 | 250 ms, set from the M1 gap measurements (`measurements/0001` section 4.3: intra-burst gaps max 10 ms, 25x margin); first real agent-session trace named as the confirming input | 2026-07-13, with OQ-5 |
| Upperdir size limit | `snapshot.md` section 6 | 2 GiB default, operator-configurable; preflight warns when free disk is below the cap; hitting it fails closed | slate 3 |

## Governing decisions

The design does not re-open settled decisions. The load-bearing ones it builds on are ADR-0002
(supervisor/child separation), ADR-0003 as refined by ADR-0013 (defense in depth; kernel backstop per
expressible dimension), ADR-0004 (declarative policy), ADR-0006 (mediate at the OS boundary), ADR-0009
as refined by ADR-0014 (snapshot mechanism, M0 gate met on x86-64), ADR-0010 (two modes), ADR-0011
(single-threaded notify loop), ADR-0012 (kernel floor 5.19), and ADR-0014 (ARM64 target deferred).
