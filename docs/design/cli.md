# Command surface and run lifecycle

- Status: settled (decisions taken 2026-07-11)
- Governs: the operator-facing command surface, run lifecycle announcements, and exit codes.
- Cites: FR-5, FR-11, FR-12, FR-13, FR-19, FR-20, FR-21, FR-22; ADR-0010, ADR-0024. Module boundary from
  [`architecture.md`](architecture.md) section 4.

The `cli` parses arguments, computes attendance, resolves the state root, selects and stamps the
**mode**, dispatches, and maps the outcome to an exit code. It never touches the notify fd and never
decides a syscall: every decision belongs to the `supervisor` and the `policy` engine
([`architecture.md`](architecture.md) section 4). This file fixes the command grammar, how a **run**
is announced and torn down, and what the shell sees when it finishes. Terms in **bold** are in
[`../CONTEXT.md`](../CONTEXT.md).

## 1. Command surface

The `run` command starts a supervised run:

```
leash run [--unattended] [--state-dir <dir>] [--policy <path>] [--ask-timeout <seconds>] -- <command...>
```

The `--` separator is required. Everything after it is the child command and passes to the child
verbatim, including arguments that look like flags: `leash run -- rm -rf ./build` runs `rm` with
`-rf ./build`, and the `-rf` is never parsed by Leash. Both `--state-dir <dir>` and
`--state-dir=<dir>` forms are accepted. Both `--policy <path>` and `--policy=<path>` forms are
accepted. `--unattended` takes no value. `--ask-timeout <seconds>` sets the FR-10 attended-ask
timeout (both `--ask-timeout <n>` and `--ask-timeout=<n>` forms; whole seconds in 1..=3600,
default 60).

Two top-level options are accepted, and only as the first argument, before any subcommand:
`-h`/`--help` prints the usage text to stdout and exits 0, and `-V`/`--version` prints
`leash <version>` (the crate version) to stdout and exits 0. Both are handled before any platform
check, so they work on hosts that cannot supervise. They take nothing after them: `leash --help extra`
is a usage error. They are not subcommand flags: `leash run --help` is not supported and keeps the
`run` grammar above (it is a missing-`--` error, or an unknown flag if a `--` follows), and nothing
after `--` is ever parsed.

Every usage error exits 2 (section 6) and prints a message to stderr naming the mistake. The
normative set:

| Usage error | Condition |
|---|---|
| no subcommand | `leash` invoked with no arguments, or a bare option before any subcommand other than `--help`/`-h` and `--version`/`-V` |
| top-level option with extra arguments | `--help`, `-h`, `--version`, or `-V` followed by any further argument |
| unknown subcommand or flag | a subcommand that is not `run`, `runs`, `diff` or `rewind`, or a flag the subcommand does not accept |
| `run` without `--` | `run` invoked with no `--` separator |
| empty command after `--` | `--` present but nothing follows it |
| a flag given twice | `--unattended`, `--state-dir`, `--policy`, or `--ask-timeout` repeated |
| `--state-dir` missing its value | `--state-dir` is the last token before `--`, or is immediately followed by `--` |
| `--policy` missing its value | `--policy` is the last token before `--`, is immediately followed by `--`, or is given as `--policy=` |
| `--ask-timeout` missing its value | `--ask-timeout` is immediately followed by `--`, or is given as `--ask-timeout=` |
| `--ask-timeout` invalid | the value is not a whole number of seconds in 1..=3600 |

Run management uses explicit operator actions:

```
leash runs [--state-dir <dir>]
leash runs prune <run-id>... [--state-dir <dir>]
```

`runs` lists each run directory with its id, mode, start time in Unix epoch milliseconds,
command, and exit outcome. It reports corrupt or incomplete runs instead of skipping them.
A missing runs directory produces an empty listing.
The listing treats a run directory as untrusted input: it never follows a symlinked run directory or file, reads only regular files, never blocks on a fifo, and refuses a `meta.json` over 64 KiB or a `trace.jsonl` over 256 MiB, listing that run as corrupt instead.
A run id that is not printable ASCII is printed escaped. `runs prune` requires at least one run id
and is currently unavailable: it exits with an error without deleting data until deletion
can safely bind to the selected directories under concurrent changes. No retention operation
runs automatically. The state directory accepts the same space and equals forms as `run`; unknown flags,
missing values, duplicate flags, and unexpected positional arguments are usage errors.

### `diff` (implemented, FR-13)

```
leash diff <run-id>[:<step>] <run-id>[:<step>] [--state-dir <dir>]
```

`diff` compares the filesystem effects of two runs or two steps, old side first.
A missing `:<step>` means the highest committed step of that run, taken from its trace and never from a manifest that has no step event.
The step is plain decimal digits; the run id is a plain directory name (not empty, not `.` or `..`, no `/`).
Either violation is a usage error, as is a missing or extra run argument.
The store is `<state-root>/runs/<run-id>/snapshots`.
Every component below the state root is opened with `O_NOFOLLOW`, so a symlinked `runs`, run directory or `snapshots` is refused.
An unknown run, a run with no snapshots or no committed step, and an unknown step exit 2 with a message naming the problem.
A store or manifest that cannot be read or fails validation exits 125 with the reason.
`diff` reads only the two manifests; it never reads the workspace or object contents.

Output is one change per line, sorted by path (a rename by its old path), with two spaces after the status letter:

| Line | Meaning |
|---|---|
| `A  <path>` | present only in the new state |
| `D  <path>` | present only in the old state |
| `M  <path>` | regular file content changed (sha256 or size), or symlink target changed |
| `R  <old> -> <new>` | a regular file removed and one added with the same sha256 and size |
| `T  <path> (<from> -> <to>)` | entry kind changed; kinds are `file`, `dir`, `symlink` |
| `m  <path> (<fields>)` | metadata changed; fields in the order `mode`, `uid`, `gid`, `mtime`, `xattrs`, `acl` |
| `L  <path>` | only the hard-link grouping of an unchanged file changed |

A summary line follows, listing the non-zero counts in the order added, removed, modified, renamed, type changed, metadata changed, link changed, for example `3 added, 1 removed, 2 modified, 1 renamed`.
No changes prints `no differences` and exits 0; otherwise the exit code is also 0.
A path containing a control character prints in quoted, escaped form, as `leash runs` does for ids.

Rules the output follows:

- A directory is reported as itself and for each entry inside it; nothing is collapsed.
- A rename pairs removed and added files one to one; candidates sharing a hash pair in sorted path order and the leftovers stay `D` and `A`.
- Hard links are one object: names of one inode that gain new content are each `M`, never a rename.
  `L` considers only names present on both sides, so adding or removing one name does not flag its siblings.
- A file with changed content does not report `mtime`; its mode, uid, gid and xattr changes still appear as `m`.
- Directory mtimes change whenever an entry is added or removed, so they appear as `m` lines.

### `rewind` (implemented, FR-12)

```
leash rewind <run-id> [--step N] [--expect <digest>] [--no-undo] [--workspace <dir>] [--state-dir <dir>]
leash rewind <run-id> --undo <n> [--expect <digest>] [--no-undo] [--workspace <dir>] [--state-dir <dir>]
```

`rewind` restores the workspace of a finished snapshot run to step `N`, or to step 0 (the workspace as it was before the agent started) when `--step` is omitted.
It is non-interactive: the operator invoked it, so it asks nothing.
It prints the change summary before the first write, and the safety snapshot is the way back.
The rules it enforces are ADR-0024 decisions 17 to 22; the mechanics are in [`snapshot.md`](snapshot.md) section 5.

Flags:

- `--step N` is a plain decimal number.
- `--expect <digest>` is 64 hexadecimal digits, upper or lower case, kept outside the store by the operator.
  It must equal the chain head recomputed from the store, or the manifest digest of the target step.
  With `--undo <n>` it must equal the manifest digest of the safety snapshot, which rewind prints when it takes one.
  Without it, the store is checked only against the trace beside it, so an attacker who can write both the store and the trace is not detected; rewind says so (see the output below).
- `--no-undo` skips the safety snapshot.
- `--workspace <dir>` names the workspace when the working directory is not it.
  A relative path resolves against the working directory.
- `--state-dir <dir>` is as for `run`, and must lie outside the workspace.
- `--undo <n>` restores safety snapshot `n` of the run instead of a step.
  It cannot be combined with `--step`, because a safety snapshot is outside the chain.
  The undo store has no trace and no chain, so `--expect` is its only check against forgery.

The usage errors, all exit 2, are: no run id, a run id that is not a plain directory name, a flag given twice, an unknown flag, a missing flag value, `--step` or `--undo` that is not a non-negative whole number, `--expect` that is not 64 hexadecimal digits, `--undo` with `--step`, and an extra positional argument.

The order of checks, each before any write to the workspace:

0. The process is not root.
   Root is refused first, before the run directory is opened, so no cleanup runs as root and no root-owned entry appears under the state root.
1. The run is a directory under `<state-root>/runs`, opened component by component with `O_NOFOLLOW`; `meta.json` is a regular file of at most 64 KiB.
   An unknown run, a run with no `snapshots` directory, and a run whose metadata records no run cgroup (not a snapshot run) are refused.
2. The workspace, the working directory or `--workspace` canonicalized, equals the workspace in `meta.json`.
3. The run is over.
   `run.lock` is taken without blocking; a held lock means the run is live.
   The recorded run cgroup must be `Gone`; `Present` and `Unknown` are refused and the message names the cgroup.
   A present cgroup of a dead run is first offered to the stale cleanup (ADR-0024 decision 17), which runs on the parent cgroup that `meta.json` records for the run cgroup.
   It does not skip any cgroup, so it may kill and remove every stale Leash cgroup under that parent, not only this run's.
   It touches a cgroup only when its name is a valid Leash run name, its run lock under this state root can be taken, and its lock xattr matches that lock file's inode.
   A missing `run_end` is fine, so a crashed run can be rewound.
4. The workspace lock (the `flock` on the workspace directory and the one under the state root, ADR-0026) is taken without blocking, and held to the end; a held lock refuses, whatever state directory the holder used.
   The locked directory handle is the one that is scanned, captured and restored.
   The canonical path read back from that handle must equal the workspace that check 2 compared, or rewind refuses with `the workspace changed while rewind opened it`; a path component swapped for a symlink between the two cannot redirect the restore.
5. The target step has a committed `step` event in `trace.jsonl` and a manifest in the store.
   The committed steps are derived from the `step` events of the trace (`store::committed_steps_from_trace`), never from the manifests on disk.
   A `step` event followed by `capture_failed` with phase `step_event` for the same step is not committed.
   The trace is untrusted input, read once through a handle by the same streaming reader that `diff` uses, so the two agree on the committed steps.
   It has no whole-file size limit: at most its size at open is read, each line is at most 1 MiB, there are at most 1,000,000 step events, and only one line is held in memory at a time.
   An empty line refuses, because the recorder never writes one.
   A final line without a newline (a crash mid-write) is ignored; any other malformed line refuses.
   The first event must be a `run_start` that agrees with `meta.json`.
   A manifest with no committed `step` event is an orphan of an aborted capture and is not a target.
6. The chain is recomputed from the manifests of the committed steps; an orphan manifest is not in it.
   The recomputed digest of the target must equal the digest in the trace's step event, and `--expect`, when given, must equal the chain head or that digest.
7. Every store object the plan writes is verified, so a corrupt object refuses the rewind before the workspace changes.

Exit codes:

| Outcome | Exit code |
|---|---|
| rewound, or the workspace already matched | 0 |
| usage error; unknown run (a symlinked run directory counts as unknown); run without snapshots or not a snapshot run; unknown step, or a step with no committed event; workspace differs from the run's; state directory inside the workspace; unknown `--undo` number (a symlinked undo directory counts as unknown) | 2 |
| live run (lock held); cgroup `Present` or `Unknown`; workspace lock held; the workspace changed while it was opened; trace, metadata, store or digest mismatch; a trace or metadata file that is not a regular file or is over its cap; `--expect` mismatch; an undo store that is not exactly step 0 (an incomplete or forged safety snapshot); safety snapshot impossible; running as root; apply failed; a failed write of the result to stdout | 125 |

A failed write to stdout after the workspace was restored also exits 125, because the operator cannot be shown the result; the workspace stays restored, and the error says that it could not write the output.

Output goes to stdout except warnings and errors, which go to stderr and start with `leash: `.
A successful rewind prints these lines, in order (angle brackets are values):

```
chain head: <64 hex>
step <N> digest: <64 hex>
safety snapshot: <state-root>/runs/<run-id>/rewind/undo-<n> (undo <n>)
safety snapshot digest: <64 hex>
to undo this rewind: leash rewind <run-id> --undo <n> --expect <64 hex> --workspace <dir> --state-dir <dir>
<change summary>
rewound the workspace to step <N>: <r> removed, <d> directories created, <w> files written, <l> hard links, <s> symlinks, <m> metadata fixes
rewind reverses filesystem effects only; anything the agent sent off this machine is not undone
```

- The first two lines are printed once the integrity checks pass; a refusal prints both values it compared in the error instead.
- The safety snapshot digest is the manifest digest of the snapshot, and the undo command carries it as `--expect`, so the undo is checked against the value printed when the snapshot was taken.
- The undo command is shell-quoted, so it can be pasted as printed.
- Without `--expect`, stderr says `leash: note: no --expect given; the store is checked only against the trace beside it, so a forged store and trace are not detected; pass the chain head printed at run end`, before the first write.
  With `--undo` the note reads `the undo store is checked against nothing, so a forged undo store is not detected; pass the safety snapshot digest printed by the earlier rewind`.
- The change summary is the restore engine's: a counts line, then one `  <action> <path>` line per change, sorted by path, with a path that holds a control character printed quoted and escaped.
- When the plan is empty, the output is `workspace already matches step <N>`, then the effects line, and nothing is written; no safety snapshot is kept.
- With `--undo <n>`, the first two lines are absent, the result line reads `restored the workspace from undo snapshot <n>: ...`, and a new safety snapshot is still taken first.
- With `--no-undo`, the safety snapshot and undo lines are absent, and stderr says `leash: warning: --no-undo: no safety snapshot is taken, so this rewind cannot be undone`, followed by one warning per workspace entry that capture would refuse (`leash: warning: <path> cannot be captured (<reason>); the plan replaces or removes it`).
- The effects line is the last line of every successful rewind, an empty plan included.

The safety snapshot (ADR-0024 decision 21) is a complete store of its own at `<run-dir>/rewind/undo-<n>/`, outside `snapshots/`, so it is never part of the chain, never a step, and never reachable by `--step`.
The number is the lowest free one.
If it cannot be taken, because capture refuses an entry (a socket, a mode-000 file) or a cap is hit, rewind exits 125 naming `--no-undo`.
An unused safety snapshot is removed again: after a refusal, or when the plan is empty.
When the apply fails, the error names the safety snapshot and prints the `--undo` command that restores it.
On macOS, `rewind` exits 125 with a message that it requires linux.

### Snapshots (specified by ADR-0024, not yet implemented)

The `run --snapshots` flag below is specified and not yet implemented; `run` does not accept it.
`diff` and `rewind` are implemented; see their sections above.

```
leash run --snapshots [--unattended] [--state-dir <dir>] --policy <path> [--ask-timeout <seconds>] -- <command...>
```

`--snapshots` is available in enforce mode only.
`--snapshots` without `--policy` is a usage error that exits 2 (FR-22), not a supervisor failure.
It refuses before spawn, as a supervisor failure with the message on stderr and no run directory created, in these cases:

- the host has no writable, delegated cgroup v2 with working `cgroup.freeze` and `cgroup.kill`; the message names the hint `systemd-run --user --scope -p Delegate=yes`, which is unverified until a CI leg runs it;
- the Landlock ABI is below 3, a refusal tested through an injected probe because no available host has an ABI below 3;
- a Landlock grant with write, truncate, make, remove or refer rights overlaps the state root or any cgroup2 mount, as an ancestor or a descendant, judged on the anchors Landlock opens (a grant on a missing path is anchored at its deepest existing ancestor); the message names the rule, the grant path, the rights and the protected path.

The refusals come in this order: the Landlock ABI and the grant overlaps, then the cgroup delegation probe, then the workspace lock, then the creation of the run cgroup, all before any run directory or broker exists.
A failure to create the run cgroup, or any later failure before the run directory exists, is a supervisor failure with no run directory created, and removes the cgroup.
Taking or binding the run lock happens once the run directory exists, so a failure there leaves a run directory with `run_start`, a `cgroup_kill` event with reason `abort` that names the error, and no `run_end`, and exits 125 with the empty cgroup removed.

The session already applies all three refusals and the implicit `implicit:cgroup` deny when its `snapshot_integrity` field is set.
What is still missing is the `--snapshots` flag that sets it, which the capture slice adds.

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
The notify-loop ask resolution path treats an unattended **ask** as an immediate deny and records `ask_resolution: "unattended"`.
An attended **ask** prompts on the controlling terminal (`/dev/tty`), listing every ask-matched action of the held syscall with its matched rule; an approval realizes the allow, and a denial, an unreadable terminal, or the FR-10 timeout denies (notify-loop.md section 5).

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
   created or child is spawned. A snapshot run also creates its run cgroup here, after the
   delegation probe and the workspace lock ([`snapshot.md`](snapshot.md) section 2).
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
| usage error | 2 |
| supervisor failure | 125 |

`runs`, `diff` and `rewind` have no child, so they exit only 0, 2 or 125 (the `diff` and `rewind` sections give their cases).

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
