# Command surface and run lifecycle

- Status: settled (decisions taken 2026-07-11)
- Governs: the operator-facing command surface, run lifecycle announcements, and exit codes.
- Cites: FR-5, FR-19, FR-20, FR-21, FR-22; ADR-0010. Module boundary from
  [`architecture.md`](architecture.md) section 4.

The `cli` parses arguments, computes attendance, resolves the state root, selects and stamps the
**mode**, dispatches, and maps the outcome to an exit code. It never touches the notify fd and never
decides a syscall: every decision belongs to the `supervisor` and the `policy` engine
([`architecture.md`](architecture.md) section 4). This file fixes the command grammar, how a **run**
is announced and torn down, and what the shell sees when it finishes. Terms in **bold** are in
[`../CONTEXT.md`](../CONTEXT.md).

## 1. Command surface

The one implemented subcommand is `run`:

```
leash run [--unattended] [--state-dir <dir>] [--policy <path>] -- <command...>
```

The `--` separator is required. Everything after it is the child command and passes to the child
verbatim, including arguments that look like flags: `leash run -- rm -rf ./build` runs `rm` with
`-rf ./build`, and the `-rf` is never parsed by Leash. Both `--state-dir <dir>` and
`--state-dir=<dir>` forms are accepted. Both `--policy <path>` and `--policy=<path>` forms are
accepted. `--unattended` takes no value.

Every usage error exits 2 (section 6) and prints a message to stderr naming the mistake. The
normative set:

| Usage error | Condition |
|---|---|
| no subcommand | `leash` invoked with no arguments, or a bare option before any subcommand |
| unknown subcommand or flag | a subcommand that is not `run` (and not a reserved name below), or a flag `run` does not accept |
| `run` without `--` | `run` invoked with no `--` separator |
| empty command after `--` | `--` present but nothing follows it |
| a flag given twice | `--unattended`, `--state-dir`, or `--policy` repeated |
| `--state-dir` missing its value | `--state-dir` is the last token before `--`, or is immediately followed by `--` |
| `--policy` missing its value | `--policy` is the last token before `--`, is immediately followed by `--`, or is given as `--policy=` |

Reserved subcommands parse but are not implemented in this slice. `diff` and `rewind` are the M3
time-travel milestone (FR-12, FR-13); `runs` is the FR-21 listing and pruning subcommand. Each exits
2 with a stable message that names where the work lives, for example
`leash: 'rewind' is not implemented yet (planned: time-travel milestone M3)` and
`leash: 'runs' is not implemented yet (planned: FR-21 run management)`. The message names the
milestone or requirement, never a fabricated issue number.

## 2. Mode selection

A run with no policy file is **record-only** (FR-19). A run with `--policy <path>` is **enforce**
mode. The policy is loaded and validated before the child exists and before a run directory is
created; a load or validation error is a supervisor failure, not a mid-run decision.

The mode is decided once, before the child exists, and MUST NOT change mid-run. It is announced on
stderr at run start, stamped into `meta.json` and the `run_start` event, and named in the **session
report** (FR-19). Record-only output MUST NOT be described as enforcement: the announcement and the
report say record-only in as many words and use no enforcement language for a run that enforced
nothing (ADR-0010).

## 3. Attendance

A run is attended if and only if both stdin and stderr are terminals, tested with `isatty` on file
descriptors 0 and 2. `--unattended` forces unattended regardless of the terminal state (FR-20).
Attendance is stamped into the trace and `meta.json`.

In this slice no **ask** exists, so attendance only stamps: nothing yet reads it to decide whether an
ask queues or denies. The rule is fixed now, before asks land, so the stamp's meaning does not drift
later. A trace recorded today records the same attended or unattended fact that FR-20 will act on
when asks arrive.

## 4. State directory

The state root defaults per XDG through the recorder's resolution: `$XDG_STATE_HOME/leash` when that
variable is set, else `$HOME/.local/state/leash` (FR-21). `--state-dir` overrides the default. A
relative `--state-dir` resolves against the current working directory.

The **workspace** is the canonicalized cwd at startup. If the cwd cannot be canonicalized the run
refuses as a supervisor failure (section 6): a run that cannot name its own workspace cannot reason
about isolating the state root from it. The effective state root is canonicalized through its deepest
existing ancestor, with the non-existing remainder appended lexically. The root directory always
exists, so this resolution is total.

The state directory MUST lie outside the workspace (FR-21, so the child cannot reach the trace
through the workspace it is allowed to write). If the resolved state root equals the workspace or
lies beneath it, the run is refused as a usage error before anything is created. Resolving both sides
to canonical, existing-ancestor paths first is what makes this check catch relative paths and
symlinks that point into the workspace, not just literal prefixes. A state root that does not yet
exist but lies outside the workspace is accepted and created.

## 5. Run lifecycle and durability

A `run` proceeds in a fixed order. stdout belongs to the child throughout; every Leash announcement
goes to stderr.

1. Preflight: probe the host and evaluate the result ([`architecture.md`](architecture.md)
   section 5.1). A refusal is a supervisor failure, with the message on stderr and no run directory
   created. In enforce mode, policy load and validation also happen here, before any artifact is
   created or child is spawned.
2. Create the run directory and write `meta.json`.
3. Announce the mode on stderr.
4. Append the `run_start` event and sync it, before the child is spawned.
5. Spawn the child ([`architecture.md`](architecture.md) section 5.2).
6. Serve the notify loop until the child tree exits ([`notify-loop.md`](notify-loop.md)).
7. Decode the wait status.
8. Append the `run_end` event and sync it.
9. Render `report.txt` from `trace.jsonl` and write it, create-new plus fsync.
10. Print the run id and the report path to stderr.

The `run_start` sync at step 4 precedes the spawn at step 5 so that any run which produced a child
also left durable evidence that it did. The durability contracts follow from this ordering:

- A spawn failure leaves `meta.json` and a trace containing the synced `run_start`, no `run_end`, and
  no report, and exits supervisor-failure. The evidence that a run was attempted survives even though
  no child ran.
- A trace-write failure mid-run aborts fail-closed (the notify loop's case E,
  [`notify-loop.md`](notify-loop.md) section 4): the child is killed, no `run_end` is appended, and
  no report is written. The partial trace is the evidence.
- An undecodable wait status is a supervisor failure: no `run_end` is stamped, because an untruthful
  exit stamp is worse than none. A reader must not be handed an exit status the supervisor could not
  actually read.
- A report-write failure after a synced `run_end` is a supervisor failure. The trace is already
  durable and the report is regenerable from `trace.jsonl` alone
  ([`trace.md`](trace.md) section 6), which remains the authority, so the lost artifact is
  reconstructable and the run's account is not.

## 6. Exit codes

The exit code is normative (FR-22). It follows the convention wrappers like `timeout` and `docker`
use: pass the child's own result through, and reserve a distinct code for "the wrapper itself
failed".

| Outcome | Exit code |
|---|---|
| child exited with status N | N |
| child killed by signal S | 128 plus S |
| usage error, or a reserved subcommand | 2 |
| supervisor failure | 125 |

A supervisor failure is any of: a preflight refusal, a spawn or setup failure, a run-loop abort
(trace-write failure), an undecodable wait status, or a report-write failure. 125 is the code
`timeout` and `docker` reserve for a failure of the wrapper rather than the wrapped command.

One residual, stated honestly: a child that itself exits 125 (or 2) is indistinguishable at the shell
from the corresponding Leash outcome, because the child's status is passed through unchanged. The
**trace** is the authority that resolves it: a present `run_end` carries the real child result, so the
125 or 2 came from the child; an absent `run_end` means the supervisor failed before it could stamp
one. The shell code alone cannot tell these apart; the trace always can.

## 7. Module boundary

The `cli` parses arguments, computes attendance, resolves the state root, selects and stamps the
mode, dispatches, and maps the outcome to an exit code. The orchestration of the run belongs to
`supervisor::session`: preflight, the run directory, the lifecycle events, the spawn, the notify
loop, and the report ([`architecture.md`](architecture.md) section 4). The `cli` never touches the
notify fd and never decides a syscall. The split keeps the security-critical machinery in the
supervisor and leaves the cli a thin, testable argument-and-outcome layer.
