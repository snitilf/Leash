# Measurement 0003: kernel prerequisites for enforce-mode snapshots (ADR-0024)

- Status: measured 2026-11-24 in a privileged GitHub codespace; systemd paths were not testable there and are named in section 6.
- Governs: the evidence base for the decisions in ADR-0024 that rest on kernel behavior, and for the claims in `design/escapes.md`, `design/architecture.md` and `design/snapshot.md` about the state directory, the freezer, `CLONE_INTO_CGROUP` and legacy AIO.
- Cites: ADR-0022, ADR-0024; SPEC.md FR-21.
- Method recorded before any result, per the project's evidence discipline (spec section 10: measurements state method, kernel and architecture).

This document records five questions that had to be answered by observation before ADR-0024 could be written.
Each was a yes-or-no question about kernel or Leash behavior, so each is reported with a count of runs and a one-line verdict.
It does not choose any design; the decisions are in ADR-0024, and section 7 maps each result to them.

Numbering note: `0002-wait-killable-recv-signals.md` already exists, so this document is 0003.

## 1. Environment

All results come from one host and one kernel.

- Host: GitHub codespace on branch `chore/devcontainer-cgroup-freezer`, commit `64e9a32`.
- Dev container: privileged, as defined for PR #50 in `.devcontainer/devcontainer.json` (`--privileged --cgroupns=private --security-opt seccomp=unconfined`).
- Kernel: `Linux 6.8.0-1070-azure #78~22.04.1-Ubuntu SMP`, from `uname -a`.
- Architecture: x86-64 (`uname -m` reports `x86_64`).
- Userland: Ubuntu 24.04.3 LTS (container image).
  The kernel is the Azure 6.8 kernel of the codespace host.
- Landlock ABI: 4, as returned by `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` (`abi.c`).
  `/sys/kernel/security/lsm` does not exist in this container, but Landlock works.
- cgroup: cgroup2 mounted at `/sys/fs/cgroup` (`rw`), private cgroup namespace, `/proc/self/cgroup` reads `0::/`.
  Root `cgroup.controllers` was `cpuset cpu io memory hugetlb pids rdma misc`; root `cgroup.subtree_control` was empty.
- User: `uid=1000(vscode)`; tests that need root cgroup writes ran under `sudo`.
- systemd: absent.
  PID 1 is a `/bin/sh` keepalive loop; there is no `systemd-run`, no `loginctl`, no `/run/systemd/system`, and `XDG_RUNTIME_DIR` is unset.
- Leash: built with `cargo build --release` in the codespace checkout.
  The spike did not modify, commit or push anything in the repository.

Incident that affects provenance.
Cleaning up a hung run, the operator ran `sudo pkill sleep`, which killed the container keepalive, and the codespace restarted into a recovery container.
A `gh codespace rebuild` restored the privileged container on the same kernel (hostname changed, cgroup2 `rw` again, `/tmp` wiped).
Questions 1 to 4 and the first pass of question 5 ran on the first container.
The question 5 controller experiments ran on the rebuilt container.

The test programs are small C files and shell scripts (`abi.c`, `q1_agent.sh`, `q1_proc.c`, `q2_freezer.c`, `q3_clone_into.c`, `q4_aio.c`, `q5*.sh`, `wcg.c`).
The full sources and raw logs were kept outside the repository and are cited here by name only.

## 2. Question 1: state-directory exposure in enforce mode

### Method

Question: does an enforce-mode agent have any protection for the Leash state directory, as `design/escapes.md` and `design/architecture.md` claim ("denied the state directory by both layers")?

First, a code search.
The only state-directory check in `src/` is `resolve_state_root` in `src/cli.rs`, which refuses a state root inside the workspace.
No code in `src/policy/`, `src/sandbox/` or `src/supervisor/broker.rs` refers to the state directory.
`derive_hull` in `src/sandbox/landlock.rs` documents that deny rules never subtract from the hull, and a unit test pins that.

Then a behavioral test.
An agent script (`q1_agent.sh`) ran under `leash run` with the default state directory (`~/.local/state/leash`) after two deliberate earlier runs had created previous run directories.
The runs directory held 6 run directories by the time of the write-test listing, because other spike runs had also written there.
The script tried to list the runs directory, read `meta.json` and `trace.jsonl` of previous runs and of the live run, append to and truncate the live trace, create a file in the live run directory, rename and delete a previous run, and open every `/proc/<pid>/fd/*` of the supervisor and of its parent shell (`q1_proc.c`).
Two policies were used.

```
leash run --policy examples/policy.toml     -- sh q1_agent.sh   # policy A: the shipped example
leash run --policy q1_policy_home_rw.toml   -- sh q1_agent.sh   # policy B: example plus one rule
```

Policy B adds this rule above the `/**` read rule, modelling an operator who lets the agent work under `$HOME`:

```
[[fs]]
path   = "~/**"
mode   = ["read", "write", "create", "delete"]
action = "allow"
```

### Result

Policy A (`examples/policy.toml`, mode enforce), one full run for reads and one for writes:

- Listing the runs directory succeeded and showed all 6 run directories.
- Reading `meta.json` and `trace.jsonl` of every previous run succeeded, and so did reading the live trace of the current run (913 lines and growing).
- Append, truncate and create in the current run directory failed with `Permission denied`.
- Rename and delete of a previous run failed with `Permission denied`.
- `/proc/<pid>/fd/*` of the supervisor and of the parent shell: 0 of 11 and 0 of 3 descriptors opened (the supervisor and the parent shell).

Policy B (home read and write allowed), one run:

```
APPEND_OK   TRUNC_OK   CREATE_OK   MV_OK   RM_OK
fd probes of the supervisor: fds=12 opened=0
exit=125
leash: report could not be rendered: trace line 1 is not valid json
```

After the run, the surviving run directory held a `planted` file and a `trace.jsonl` whose first 400 bytes were NULs (the agent truncated it and the supervisor kept writing at its old offset).
There was no `report.txt`, and the deleted previous run was gone.

Control for the `/proc` denial (`q3_out.txt`, a Landlock-only process with no seccomp):

```
[pre-landlock]  same-uid unsandboxed helper: readlink fd/0 = pipe:[129321] ; open fd/0 = OK
[post-landlock] same-uid unsandboxed helper: readlink fd/0 = Permission denied ; open fd/0 = Permission denied
```

`/proc/sys/kernel/yama/ptrace_scope` was 1, but Yama gates attach mode and not the read mode that `/proc/<pid>/fd` uses.
The attribution to Landlock's own ptrace scoping is an inference from this control, not read from kernel source.

Side observation: under policy A even `sh -c 'x 2>/dev/null'` failed with `cannot create /dev/null: Permission denied`.

Counts: policy A ran twice (once for reads, once for writes), policy B once.
Each behaved deterministically; policy B was not repeated.

### Verdict

- No implicit state-directory deny exists in the code: CONFIRMED.
- The claim "denied the state directory by both layers": REFUTED as stated.
  Under `examples/policy.toml` the traces, including the live one, are readable, and write denial was incidental to the example granting no write outside the workspace.
  With one `~/**` write grant the agent destroyed the live trace and a previous run.
- The supervisor's `/proc/<pid>/fd/*` descriptors are unreadable to the agent in enforce mode (0 of 11 opened under policy A, 0 of 12 under policy B): CONFIRMED, attributed to Landlock by the control above.
  `/proc/<pid>/exe` is not part of this verdict: the script printed its `readlink`, but no result was recorded, so it was not tested.

## 3. Question 2: cgroup v2 freezer against seccomp user notification

### Method

Question: can the supervisor freeze the agent's cgroup while a seccomp notification is outstanding, with and without `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (flag value `1<<5`)?

`q2_freezer.c`, run as root because moving a process needs write access to the root `cgroup.procs`.
The parent forks a child, places it in a cgroup `/sys/fs/cgroup/spike`, and the child installs a filter that returns `SECCOMP_RET_USER_NOTIF` for `openat`, with `NEW_LISTENER` and, when the flag argument is 1, `WAIT_KILLABLE_RECV`.
The child passes the listener fd to the parent over `SCM_RIGHTS`.
A second thread of the child calls `openat("/etc/hostname")` while the main thread sits in a futex wait.
Liveness is judged from `cgroup.events` (`frozen`, polled every 5 ms for up to 2 s) and from `/proc/<pid>/task/*/{status,wchan}`.

Cases, each run 3 times:

- A: the parent receives the notification, does not answer, then writes `cgroup.freeze=1`.
- B: the parent writes `cgroup.freeze=1` before receiving.
- D: as A, with a second child thread spinning on a counter in a shared page.

```
for combo in "A 1 cont" "A 1 eperm" "A 0 cont" "B 1 cont" "B 1 eperm" "B 0 cont" "D 1 cont" "D 0 cont"; do
  for i in 1 2 3; do sudo ./q2_freezer $combo; done; done
```

Arguments are `<case> <WAIT_KILLABLE_RECV 0|1> <response cont|eperm>`.

### Result

Case A with the flag (received, unanswered), 3 of 3 runs:

```
[ 512ms] write cgroup.freeze=1 (notification received, unanswered)
[2515ms] frozen=1 within 2s? NO (final frozen=0)
 tid=5424 state=D wchan=seccomp_do_user_notification.constprop.0 syscall=257
[2525ms] SEND(CONTINUE) ret=0
[2530ms] after respond: frozen=1 within 2s? YES (took 5ms)
```

`frozen` never reached 1 in the 2 s window while the notification was unanswered, and reached 1 on the first 5 ms poll after the response (3 of 3).
After thaw the child saw `openat=3` for `CONTINUE` and `EPERM` for `-EPERM` (3 of 3 each).
How long `frozen=0` persists if the supervisor never answers was not tested.

Case A without the flag, 3 of 3 runs:

```
[ 524ms] write cgroup.freeze=1 (notification received, unanswered)
[ 529ms] frozen=1 within 2s? YES
 NOTIF_ID_VALID=-1
[ 538ms] SEND(CONTINUE) ret=-1 errno=No such file or directory
[ 546ms] RECV ret=0 id=<old id + 1> pid=6631 nr=257
```

The freeze completed in about 5 ms, the received notification was invalidated, the response failed with `ENOENT`, and after thaw the syscall was restarted and produced a new notification with a new id.
Answering that new notification gave the correct result (3 of 3).
The first pass in `q2_out.txt` did not re-receive and the child hung until that step was added; `q2_out_flag0_rerun.txt` has the corrected runs.

Case B (freeze before receive), three combinations (`B 1 cont`, `B 1 eperm`, `B 0 cont`), 3 runs per combination, 9 of 9 runs:
`frozen=1` within 6 ms, `poll(POLLIN)=0` on the listener while frozen (no notification visible), and after thaw the notification was delivered and the response applied correctly.

Case D (multi-threaded), 3 runs each:

- With the flag: `frozen` stayed 0, but the spinning thread was stopped (`counter advanced 0 in 1000ms`) and the main thread was parked (`S get_signal`).
  Only the thread in the received notification stayed in `D seccomp_do_user_notification`.
  After the response, `frozen=1` was immediate.
- Without the flag: `frozen=1` in about 5 ms, the spinner stopped, the response failed with `ENOENT`, and a new notification worked after thaw.

Not tested: a supervisor that never answers, and the effect of `SIGKILL` on a pending killable wait.

### Verdict

- With the flag, a received and unanswered notification prevents `frozen=1`, and the freeze completes within 5 ms of the response: CONFIRMED (3 of 3 in A, 3 of 3 in D).
- Without the flag, the freeze completes at once but the received notification is cancelled, the response fails with `ENOENT`, and the syscall re-traps after thaw: CONFIRMED (3 of 3 in A, 3 of 3 in D).
- Freezing before receiving works with or without the flag and delivers the notification after thaw: CONFIRMED (9 of 9).

## 4. Question 3: `CLONE_INTO_CGROUP` under Landlock

### Method

Question: can a Landlock-restricted agent with only a read-only directory fd for a cgroup place a new process into that cgroup with `clone3(CLONE_INTO_CGROUP)`, and how far outside its own cgroup can it reach?

`q3_clone_into.c`, run as root as an orchestrator.
All test cgroups are `chown`ed to `vscode`.
Layout:

```
/sys/fs/cgroup/spike-parent/{agent,sib}     /sys/fs/cgroup/spike-other
```

The orchestrator forks an "agent" and writes its pid into `spike-parent/agent/cgroup.procs`.
The agent drops to uid 1000 (`setgroups(0)`, `setgid`, `setuid`).
A still-unsandboxed child first writes its own pid to `spike-parent/cgroup.procs` as a control.
The agent then applies Landlock (ABI 4, all 15 filesystem rights handled, read-only `READ_FILE|READ_DIR|EXECUTE` beneath `/`, full rights beneath `/tmp`) plus `no_new_privs`, and tries:

- (a) direct migration: `open(cgroup.procs, O_WRONLY)` and `sh -c 'echo $$ > .../cgroup.procs'`.
- (b) `clone3(CLONE_INTO_CGROUP)` with an `O_RDONLY|O_DIRECTORY` fd of the agent's own cgroup, of `spike-parent`, and of the sibling `sib`.
- (c) the same with targets outside `spike-parent`: `spike-other` and the root cgroup.

Variant 2 repeats the test with a `vscode`-owned common ancestor (`spike-gp/{parent,other}`, built with `-DP`, `-DOTHER`, `-DTOP`).
A third mode (`seccomp`) installs a user-notification filter on `clone3` to see what the supervisor can read.

```
sudo ./q3_clone_into clone       # variant 1: root-owned common ancestor
sudo ./q3_clone_into_gp clone    # variant 2: vscode-owned common ancestor
sudo ./q3_clone_into seccomp
```

### Result

Variant 1, identical in 3 of 3 runs:

```
[control pre-landlock] unsandboxed child wrote pid to spike-parent/cgroup.procs: OK
[a1]  open(spike-parent/cgroup.procs, O_WRONLY) -> Permission denied
[a2]  sh -c 'echo $$ > spike-parent/cgroup.procs': rc=512, own cgroup unchanged
[b0 own cgroup]  clone3(CLONE_INTO_CGROUP): OK, child in 0::/spike-parent/agent
[b1 spike-parent] OK, child in 0::/spike-parent
[b2 sibling sib]  OK, child in 0::/spike-parent/sib
[c1 spike-other]  FAILED errno=13 (Permission denied)
[c2 root cgroup]  FAILED errno=13 (Permission denied)
```

Variant 2, 3 of 3 runs: the same direct writes failed, and the clone into own cgroup, parent, sibling, `spike-gp/other` and the grandparent `spike-gp` all succeeded.

The directory fd was opened with `O_RDONLY|O_DIRECTORY`, and that open succeeded under a ruleset that granted `READ_DIR` beneath `/`.
That the grant is what allowed the open is an inference: the test did not remove the grant, and it did not try an `O_PATH` descriptor.

What seccomp sees, one run:

```
supervisor RECV: nr=435 args[0]=0x7fff226f2b40 args[1]=88    (a pointer and a size, no flags)
supervisor read 88 bytes of clone_args from /proc/<pid>/mem: flags=0x200000000 CLONE_INTO_CGROUP=SET
supervisor responds -EPERM: child saw errno=Operation not permitted
```

A BPF program cannot see `flags`.
A notification supervisor can read the struct from `/proc/<pid>/mem`, which is a time-of-check to time-of-use hazard; racing that read was not tested.
Leash already reads the struct for `clone3` in `src/supervisor/run.rs`, and a search of `src/` for `INTO_CGROUP` finds nothing.

The explanation that the reach is bounded by the common ancestor is consistent with both variants.
It was not read from kernel source.

### Verdict

- Direct migration through `cgroup.procs` is denied by Landlock (the unsandboxed control moved itself): CONFIRMED.
- `clone3(CLONE_INTO_CGROUP)` with a read-only directory fd succeeds under Landlock and places the child in the target cgroup: CONFIRMED (3 of 3 in each layout).
- A target outside the agent's parent was reachable only when the agent's uid could write the common ancestor's `cgroup.procs`, in both layouts tested: CONFIRMED (root-owned ancestor: `spike-other` and root refused, 3 of 3; user-owned ancestor: sibling and grandparent reached, 3 of 3).
- Seccomp filters cannot see the flag, a notification supervisor can read it: CONFIRMED (1 run).

## 5. Question 4: legacy AIO under `leash run`

### Method

Question: are `io_setup`, `io_submit` and `io_getevents` mediated or blocked in enforce mode today?

`q4_aio.c` calls `io_setup`, `open`, `io_submit` of an `IOCB_CMD_PWRITE`, and `io_getevents` through raw `syscall()`.
It ran once unsandboxed as a control and three times under enforce mode:

```
leash run --policy examples/policy.toml -- ./q4_aio aioN.txt
```

`src/sandbox/filter.rs` was also searched for the AIO syscall names.

### Result

All three Leash runs matched the unsandboxed control:

```
io_setup -> 0   open aio1.txt -> 3   io_submit -> 1   io_getevents -> 1 res=22
exit=0          (each aioN.txt contains "written via io_submit")
```

`grep -c io_` over the trace was 0, and the trace held only the `execve` and `openat` events.
The filter has no entry for `io_setup`, `io_submit`, `io_getevents` or `io_destroy`; it lists only the `io_uring_*` trio, which was not tested.

### Verdict

Legacy AIO is allowed, unmediated and unrecorded today: CONFIRMED (3 of 3 under Leash, equal to the control).
The write completed with 22 bytes; only the preceding `openat` is mediated.

## 6. Question 5: cgroup delegation and controllers

### Method

Question: what does a delegated cgroup need for `cgroup.freeze` and `cgroup.kill` to work, and what changes if controllers are enabled?

The cgroups were created with `sudo` and chowned to `vscode`, which is not the delegation a service manager would make, so the tests ran as `vscode` inside a `vscode`-owned cgroup `D` (`q5.sh`, `q5d.sh`, `q5e.sh`, with `wcg.c` doing a single `write(2)` to report the exact errno).

- P1: no controller enabled, `D` contains a process, create a child, move a process into it, then freeze, thaw and kill.
- E1 to E3: enable a non-threaded controller (`+memory`) and a threaded controller (`+pids`) in `D` while `D` still holds a process, then after moving the shell into a leaf.
- Layout test: `D` empty, a `supervisor` leaf holding the shell, an `agent` leaf with `+pids +memory`.
- Root-cgroup caveat: enabling controllers at the root while the root holds processes.

Not testable here, and therefore not tested: every systemd path (`systemd-run --user --scope -p Delegate=yes`, the user manager subtree, SSH sessions without `user@UID.service`).
The codespace has no systemd, so the behavior of `Delegate=yes` scopes is reasoning from documentation and is not a result of this measurement.

### Result

P1 (first container 2 of 2 runs, rebuilt container once):

```
D cgroup.controllers=[] subtree_control=[]
mkdir D/child                           rc=0
echo <pid> > D/child/cgroup.procs       rc=0     (D keeps its own processes)
echo 1 > D/child/cgroup.freeze          populated 1 / frozen 1 (within 200 ms)
echo 0 > D/child/cgroup.freeze          frozen 0
echo 1 > D/child/cgroup.kill            populated 0 ; rmdir rc=0
```

Exact errnos from `q5e_run.log`, rebuilt container:

```
E1 +memory in D with an internal process:  errno=16 Device or resource busy
E2 +pids in D with an internal process:    accepted; D=domain threaded, leafA=domain invalid
   write(<pid> > D/leafA/cgroup.procs):    errno=95 Operation not supported
   -pids:                                  OK (reversible)
E3 shell moved to leaf, +pids +memory:     OK
   write(<pid> > D/cgroup.procs):          errno=16 Device or resource busy
```

Working layout (`q5d_run.log`): with `D` empty of processes, the `supervisor` leaf holding the shell and `D/agent` created under controllers `+pids +memory`, `D/agent/pids.max`, `memory.max`, `cgroup.freeze`, `cgroup.kill` and `cgroup.procs` were owned by `vscode`, `pids.max` accepted `20`, and freeze, thaw and kill worked.
The supervisor migrated a fresh child into `D/agent` and stayed in its own leaf.

Root-cgroup caveat in containers: with the shell and other processes left in the root cgroup, writing `+pids` to the root `cgroup.subtree_control` turned the root into `domain threaded` and every new child became `domain invalid`.
Placing any process in a child then failed with `EOPNOTSUPP` (or a generic "I/O error" from the dash `echo` builtin).
Enabling `+memory` or `+io` at the root failed outright, and enabling `+pids`, `+cpu` or `+cpuset` followed by any migration failed; with no root controller the same migration succeeded (`q5_diag_out.txt`).
The working method moved every process out of the root cgroup first (`q5c_wrap.sh`), after which `+pids +memory` could be enabled; the environment was restored afterwards (root `subtree_control` empty, root type `domain`, no `spike*` directories).
The earlier "I/O error" lines in `q5d_run.log` are these same `EBUSY` and `EOPNOTSUPP` errors.
Without any controller enabled at the parent, `D`'s `cgroup.controllers` was empty (first container).

Not tested: any systemd path, `subtree_control` writes by an unprivileged non-owner, and `cgroup.threads` or threaded-subtree designs.

### Verdict

- The "no internal processes" rule does not apply when only `cgroup.freeze` and `cgroup.kill` are used and no controller is in the parent's `subtree_control`: CONFIRMED (2 of 2 on the first container, 1 of 1 on the rebuilt container).
- With a controller in the parent's `subtree_control` the rule bites: `EBUSY` for non-threaded controllers, silent `EOPNOTSUPP` on first placement for threaded ones, and `EBUSY` when placing a process in the controller-enabled parent: CONFIRMED (one run each of E1 to E3).
- A supervisor running from the root cgroup of a container cannot enable controllers without breaking its children: CONFIRMED (one run; the working layouts needed the root evacuated first).
- Behavior under systemd: INCONCLUSIVE (not testable in this environment).

## 7. Consequences for ADR-0024

Numbers refer to the decisions in ADR-0024.

- Decision 3 (implicit, first-ranked deny for the state root, in every enforce run, read included): required by question 1.
  The existing claim of denial by both layers was refuted, the example policy leaves every trace readable, and one ordinary `~/**` write grant let the agent destroy the live trace and a previous run.
  The `/proc/<pid>/fd` denial already holds through Landlock and needs no new rule; decision 9 is depth, not a fix for an observed gap.
- Decision 4 (implicit deny for every cgroup2 mount in a `--snapshots` run, read included): supported by question 3 as depth, not as the closing control.
  Observed: Landlock did not stop `clone3(CLONE_INTO_CGROUP)`, and a read-only directory fd was enough.
  Inference, not run: a read deny on the mount removes that fd from the agent's reach, but `open_tree` and descriptor passing may still yield a directory descriptor, which is why decision 7 is the closing control.
  Inference, not run: what Landlock checks at `open` of a cgroup directory, and whether an `O_PATH` descriptor would also work.
  The reach extends to the whole delegated subtree when the agent's uid owns the common ancestor.
- Decision 7 (`clone3` answered `ENOSYS` before its struct is read): supported by question 3, and the control that closes `CLONE_INTO_CGROUP`.
  The flag is invisible to BPF and readable only through `/proc/<pid>/mem`, which is a TOCTOU hazard that was not tested, and a clone-flag check was therefore not measured as safe.
  `ENOSYS` removes the argument struct from the decision.
- Decision 8 (legacy AIO denied and recorded in a `--snapshots` run): required by question 4.
  AIO is allowed, unmediated and unrecorded today, and the freezer was measured only against synchronous notifications; the claim that the freezer does not stop in-flight I/O is a design premise, not a result of this measurement.
- Decision 10 (barrier order: answer the current notification, stop receiving, freeze, wait for `frozen=1`): required by question 2.
  With `WAIT_KILLABLE_RECV`, a received and unanswered notification blocks `frozen=1` until the response, so every received notification must be answered before waiting.
  Freezing before receiving was safe in 9 of 9 runs, and the notification is delivered after thaw.
  Without the flag the freeze would succeed but cancel the received notification.
  The unmeasured case (a supervisor that never answers) is the one decision 11 closes by aborting the run.
- Decision 2 (run cgroup as a child of Leash's own cgroup, no controllers): supported by question 5.
  Freeze and kill worked with no controller and with the parent holding processes.
  Enabling controllers needs a supervisor leaf and an empty parent, and the root cgroup of a container needs evacuating first, so the no-controller choice avoids all three failure modes.
  The `systemd-run --user --scope -p Delegate=yes` hint in decision 2 rests on documentation, not on this measurement, because systemd was not available.
