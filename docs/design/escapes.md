# Escapes and residuals

- Status: settled (2026-07-08). The M0 spike's gate, narrowed to the x86-64 leg by ADR-0014, is met; this file freezes with the design layer.
- Governs: the escape classes the design must resist, the mechanism and test that stop each, and the residual risks that are accepted and named.
- Cites: FR-1, FR-3, FR-4, FR-9; NFR-5; SR-1, SR-2, SR-3, SR-4; ADR-0002, ADR-0003, ADR-0011, ADR-0012, ADR-0013, ADR-0019, ADR-0021, ADR-0024. Invariants I1-I5 are defined in [`architecture.md`](architecture.md).

This file is written last because it audits the rest of the design layer. Every other file points a
residual or an escape test here; this is where those promises are collected and checked against each
other. It is the traceability layer: each control the design describes as enforced maps to the escape
it stops and the test that proves it, and each risk the design does not defend against is named rather
than hidden. Terms in **bold** are defined in [`../CONTEXT.md`](../CONTEXT.md).

## 1. The discipline (SR-2, NFR-5, I5)

No control is described as enforced without a passing **escape**-attempt test (I5, NFR-5). This is the
rule that overrides convenience: an enforcement claim is not the design saying a boundary holds, it is
a test demonstrating a hostile child cannot cross it. This file is where every enforced control across
the design layer maps to the escape it stops and the test that proves it (section 3), and where every
residual the design accepts is stated with what bounds it (section 4). The adversary is fixed by the
trust model in [`architecture.md`](architecture.md) section 2: the agent and every process it spawns,
treated as hostile (SR-1), acting through prompt injection, a compromised dependency, or plain error,
and running with the operator's privileges. It actively tries to do what the **policy** forbids. A
control that has not been red-teamed against that adversary is not enforced, it is hoped for.

## 2. In scope and out of scope

A precise scope is the strength of the design, not an admission. Overclaiming any out-of-scope item
is disqualifying: it makes the operator trust a boundary that is not there.

In scope, and defended against with a mechanism and a test in section 3:

- A hostile child reading, writing, or connecting outside the policy: the direct case the boundary exists for.
- Child-process laundering: doing the forbidden thing from a grandchild, subshell, or helper binary spawned by the agent.
- Path tricks: symlink swaps, `..` traversal, hardlinks, `/proc/<pid>/...` and `/proc/self` self-reference, and TOCTOU on a path argument between the supervisor's check and the kernel's use.
- Alternate-syscall equivalents: reaching a mediated effect through a syscall the design failed to enumerate, or through an out-of-band submission path (`io_uring`).
- fd inheritance and passing: obtaining a file descriptor the child was never authorized for, from a parent, over `SCM_RIGHTS`, or by pulling it out of another process.
- Recorder tampering: making the supervisor block, crash, drop an **event**, or lose the **trace**, and getting a default-allow when it does.

Out of scope, stated plainly (spec section 9). These are not defended against, and the design does not
claim otherwise:

- Kernel exploits and privilege escalation past the OS boundary. If the child gains root or breaks the kernel, the boundary Leash mediates is gone; Leash does not defend the kernel.
- Hardware and micro-architectural side channels.
- A malicious operator. Leash protects the operator from their agent, not the world from the operator.
- Covert exfiltration through channels the policy allows. If the policy permits `api.anthropic.com`, data can leave through it by timing or steganography; an allowed channel is allowed.

## 3. Escape-to-mechanism traceability

One row per escape class. The mechanism is the control that stops it, the invariant is the property
that control preserves, and the escape test states concretely what is attempted and what must be
observed (denied, recorded, or fails-closed). No claim in this table is settled until its test passes
(I5). No cell is blank; where a control leans on a residual, the residual is in section 4 and the row
says so.

| Escape | Mechanism that stops it | Invariant | Escape test (what it attempts, what must be observed) |
|---|---|---|---|
| Child-process laundering (do the forbidden thing from a grandchild) | Seccomp filter inherited across `fork`, `clone`, `clone3` and preserved across `execve` unconditionally; the process-creation family is mediated only to record and to let policy forbid spawning, not to preserve inheritance ([`syscalls.md`](syscalls.md) section 1) | I1 | Agent spawns `bash -c` and a helper binary that each attempt a forbidden `openat` and `connect`; both grandchildren must be mediated and denied exactly as the agent is, including a `clone` variant the design never enumerated |
| Symlink swap / TOCTOU on a path argument | Confined-broker path resolution with `openat2` against an inherited authoritative root dirfd under the ADR-0020 flag rule, then realization against retained handles, never `CONTINUE` on a pointer argument ([`syscalls.md`](syscalls.md) sections 3-4, [`notify-loop.md`](notify-loop.md) section 2) | I4 | A sibling thread swaps an allowed path to point at a forbidden target between the supervisor's read and the broker's commit; the retained handle must keep the effect on the resolved-beneath target |
| `/proc` self-reference (`/proc/self/cwd`, `/proc/<pid>/root`, `/proc/<pid>/fd/N`) | Confined-broker resolution uses `RESOLVE_NO_MAGICLINKS` under every anchor, while `RESOLVE_BENEATH` (every anchor except `/`, ADR-0023) rejects escaping routes to `/proc` and the `/` anchor relies on the magic-link refusal alone ([`syscalls.md`](syscalls.md) section 4) | I4 | Child reaches for a forbidden file via `/proc/self/cwd/../secret` and `/proc/<pid>/fd/N`; resolution must refuse the magic link and the access must be denied, not silently followed |
| Alternate-syscall equivalent for one filesystem effect (`open` vs `openat` vs `openat2`) | All path-introducing variants are in the mediated set on every supported arch, decided identically at the path-introducing syscall ([`syscalls.md`](syscalls.md) section 3.1) | I1, I4 | Child opens the same forbidden path via `open`, `openat`, and `openat2` in turn; each must produce a mediated event and the same deny |
| Access-mode confusion on an `O_PATH` open (`O_PATH \| O_WRONLY` on a file whose reads are denied) | For `open` and `openat` the fact and the broker use only the bits `O_PATH` honors, so the open is judged as the `read` it is; `openat2` refuses the combination with `EINVAL`, as the kernel does; the broker masks the flags again, so a stray `O_CREAT` or `O_TRUNC` has no effect ([`syscalls.md`](syscalls.md) section 3.1) | I4 | With reads of `{workspace}/.env` denied and workspace writes allowed, the agent opens `.env` with `O_PATH` plus `O_WRONLY`, `O_RDWR`, and `O_WRONLY \| O_CREAT \| O_TRUNC`; each must be denied by the read-deny rule and recorded with `access: ["read"]`, and `openat2` with `O_PATH \| O_WRONLY` must fail `EINVAL` (`escape_o_path_with_write_access_bits_cannot_bypass_a_read_deny`) |
| Realization failure after a recorded allow (the kernel refuses the `ADDFD`, or the `O_PATH` substitute refuses the object's kind) | The failure is recorded as a second `failsafe:realization` deny with the errno before the agent is answered, a failed write of it aborts the run with nothing sent, and the loop goes on; a create or truncate committed before the injection persists and ticks the step clock ([`notify-loop.md`](notify-loop.md) section 4 case J) | I2, I3 | With the agent's descriptor table full, a read open and an `O_CREAT` open each fail `EMFILE`, the trace carries the `allow` then the `EMFILE` deny for the same fact, the created file persists, and the agent's next syscall is served (`enforce_survives_an_addfd_the_kernel_refuses`, `enforce_survives_a_refused_addfd_after_a_create`); unit tests show a failed write of the second event sends nothing, and an `O_PATH` fifo, socket, device, or `O_NOFOLLOW` symlink is refused `EOPNOTSUPP` |
| `io_uring` out-of-band I/O submission | `io_uring_setup` (and thus `io_uring_enter`, `io_uring_register`) is denied-and-recorded in both modes: the trap records the attempt, then refuses it, so the ring never opens an un-mediated I/O path (SR-4, [`syscalls.md`](syscalls.md) section 5) | I3 | Child calls `io_uring_setup`; the attempt must appear as an event and the call must fail with an errno, in enforce and in record-only, so no ring I/O ever bypasses the mediation surface |
| `clone3` into another cgroup, and in-flight AIO across a freeze (snapshot runs only) | `clone3` is answered `ENOSYS` before its struct is read, recorded as `snapshot:clone3`, so `CLONE_INTO_CGROUP` is unreachable without a racy flag check; `io_setup` and `io_submit` are trapped and answered `ENOSYS`, recorded as `snapshot:aio`, so no I/O is in flight when the freezer stops tasks (ADR-0024 decisions 7 and 8) | I3 | In a snapshot run, raw `clone3` and `io_setup` and `io_submit` each fail with `ENOSYS` and appear as events; `fork`, `posix_spawn` and `sh -c 'true &'` still work; without snapshots both syscalls behave as before |
| Alternate network path (`connect` vs `sendto` on an unconnected socket) | `connect`, `bind`, and destination-bearing `sendto` are mediated; a constrained allow executes in the confined broker on a duplicate of the actual child socket and once-copied pointer inputs, never `CONTINUE` ([`syscalls.md`](syscalls.md) section 3.5, ADR-0020) | I4 | Child sends to a forbidden host both via `connect` then write and via `sendto` on an unconnected socket; both must be mediated and denied against the host allowlist. `sendmsg` to an unconnected socket is the residual in section 4 |
| Foreign-ABI / arch-confusion entry (x32, 32-bit `int 0x80`) | Filter pins `AUDIT_ARCH_*` and additionally denies any syscall number with `__X32_SYSCALL_BIT` (bit 30) set, so an x32 number is never read against the x86-64 table; the 32-bit path is caught by the arch pin ([`syscalls.md`](syscalls.md) section 5) | I1, I3 | Child issues an x32 syscall (arch reports x86-64, bit 30 set) and a 32-bit `int 0x80` call; both must be denied-and-recorded, never dispatched against the native table |
| fd inheritance at spawn | Child closes every file descriptor not on its allowlist immediately before `execve` ([`architecture.md`](architecture.md) section 5.2 step 6) | I1 | Supervisor leaks an extra fd to a forbidden resource into the child; after exec the child must find that fd closed and unable to reach the resource |
| fd passing by pulling one out of another process (`pidfd_getfd`) | `pidfd_getfd` is denied outright in v1, in both modes as a member of the denied-and-recorded set (SR-4, ADR-0019, [`syscalls.md`](syscalls.md) sections 3.4 and 5): its argument is a pidfd (a mutable fd-table index), not a scalar pid, so it is not `CONTINUE`-safe, and an imported fd is I/O the trace could not attribute; a sound in-tree form is deferred | I1 | Child obtains a pidfd for an out-of-tree process and calls `pidfd_getfd` to steal its fd; the call must be denied-and-recorded, in record-only as well as enforce |
| Cross-process laundering via `ptrace` / `process_vm_*` | Mediated on tree membership: the supervisor tracks the live child tree from the `fork`/`clone`/`clone3` events it already observes, and denies when the target pid is outside the tree; the pid is a kernel-trusted scalar register, so the decision is `CONTINUE`-safe ([`syscalls.md`](syscalls.md) section 3.4) | I4 | Child `ptrace`s and `process_vm_writev`s an out-of-tree process to make it perform a forbidden action; both must be denied, while in-tree use (agent tracing its own subprocess) is allowed. The pid-reuse window is the residual in section 4 |
| Recorder tampering / blinding the supervisor | In enforce mode the child is denied the state directory (FR-3, FR-21) by an implicit, first-ranked seccomp deny, matched id `implicit:state_root`, evaluated before every policy rule: every mediated access whose resolved path is the state root or beneath it is denied, read included; so is removing, replacing or altering (chmod, chown, truncate) an ancestor of the root, naming one as the destination of a rename or link, and doing the same to each symlink the operator's `--state-dir` spelling traversed (a link that leads to the root cannot be swapped away). The root is canonicalized once before any process exists, is required to build an enforce run, must be valid UTF-8, and is matched by path component on the identity read back from the opened handle, so a symlink into it is judged by where it lands. Exec is decided on the spelled path, its lexical normalization and the supervisor's resolution of it, and denied when any is beneath the root. A sibling rule, `implicit:supervisor_proc`, denies every path under `/proc/<pid>/` (`task/*` included) of the supervisor and of its broker, and the broker closes every inherited descriptor but its socket and anchors, so neither the trace descriptor nor the supervisor memory is reachable through `/proc`. Landlock backs the deny up only where no policy grant overlaps the state root, because its grants never subtract (ADR-0024); where no grant overlaps, it denies reads too. `mknod` and `mknodat` are not mediated ([`syscalls.md`](syscalls.md) section 6), so creating a node there is held back only by that Landlock backstop (section 4); the recorder is the single writer of the trace (ADR-0002); record precedes respond, so an unrecordable allow becomes a deny-and-abort; on any recorder-write failure the run fails closed ([`notify-loop.md`](notify-loop.md) sections 3-4 case E) | I2, I3 | Child attempts to open, write, delete, or race the trace and the state directory; every attempt in enforce mode must be denied, and a forced recorder-write failure must abort the run rather than release an unrecorded action. Record-only trace protection is the residual in section 4 |
| Supervisor death (crash or kill) as a way to shed mediation | The kernel closes the notification fd when the supervisor dies; every pending and subsequent mediated syscall in the child then fails (documented `-ENOSYS` for the no-listener case), enforced by the kernel, not by supervisor code that is no longer running ([`notify-loop.md`](notify-loop.md) section 4 case G) | I3 | The supervisor is killed mid-run; the child's next `openat` and `connect` must fail rather than fall through to an alternate code path that reaches the same effect un-mediated |
| Signal-cancellation double execution before `SEND` | The filter is installed with `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (ADR-0012), so before `SEND` a received notification is cancellable only by a fatal signal; the distinct post-`SEND` reply-loss race is accepted by ADR-0021 ([`notify-loop.md`](notify-loop.md) section 4.1 case I) | I3 | A non-fatal signal (SIGCHLD, a timer) is delivered to a child while the supervisor holds a received notification; before `SEND`, the notification must stay valid and no restarted notification may appear |
| Cgroup escape (direct `cgroup.procs` write, `CLONE_INTO_CGROUP`) | Specified by ADR-0024, not yet implemented: `clone3` is answered `ENOSYS` before its argument struct is read, which closes `CLONE_INTO_CGROUP` (a directory descriptor suffices, and `open_tree` and descriptor passing can still yield one); a snapshot run also adds an implicit, first-ranked deny for every cgroup2 mount in the mount namespace, read included, as depth; a run refuses before spawn when a write-class Landlock grant overlaps the cgroup2 mount (ADR-0024, [`snapshot.md`](snapshot.md) section 2) | I1, I5 | Child writes its pid to a parent cgroup's `cgroup.procs`, opens a cgroup directory read-only, and calls `clone3` with `CLONE_INTO_CGROUP`; each must be denied or fail with `ENOSYS`, and the child must stay in the run cgroup |
| Freezer evasion (nested seccomp listener parks a thread) | Specified by ADR-0024, not yet implemented: the freeze wait is bounded; a freeze that does not reach `frozen=1` in time aborts the run closed and kills the whole cgroup (ADR-0024 rules 10-11) | I3 | Child installs its own seccomp listener and parks a thread on it; the capture must not complete, the run must abort closed, and no step event may be written |
| Legacy AIO in flight across a capture | Specified by ADR-0024, not yet implemented: `io_setup` and `io_submit` are denied and recorded in a snapshot run, because the freezer stops tasks, not in-flight I/O (ADR-0024 rule 8, SR-4) | I3 | Child calls `io_setup` and `io_submit` while a capture is pending; both must be denied, recorded as events, and no I/O may be in flight at the boundary |
| Rewind on a hostile store (forged manifest or objects) | Specified by ADR-0024, not yet implemented: rewind validates every manifest path, applies changes with `openat2` and `RESOLVE_BENEATH \| RESOLVE_NO_SYMLINKS` from a workspace directory handle, writes a temporary file and renames it, hashes the bytes it writes, refuses root, and refuses a store that does not match `--expect` (ADR-0024 rules 16 and 20, [`snapshot.md`](snapshot.md) section 5). At-rest forgery without `--expect` is a residual in section 4 | I1, I5 | A manifest carrying an absolute path, a `..` component and a symlink pointing outside the workspace is fed to rewind; nothing outside the workspace may be written, and a store whose digest differs from `--expect` must be refused |
| Resource exhaustion (fork bomb, fill the upper layer) | An upperdir size limit backstops the snapshot mechanism; hitting it resolves per fail-closed, the run stops rather than the host filling ([`snapshot.md`](snapshot.md) section 6) | I3 | Child runs a fork bomb and a fill-the-upper loop; the run must stop at the limit fail-closed, and the host disk must not be exhausted |
| Rename / hardlink race on the overlay (smuggle content past a snapshot boundary or misattribute a diff) | ADR-0022 requires a whole-tree capture barrier, broker and asynchronous-I/O quiescence, and exclusive ownership; implementation and adversarial validation are pending ([`snapshot.md`](snapshot.md) sections 1, 6) | I1, I5 | Child races capture with cross-layer renames and hardlink games to hide content from a snapshot or make diff read a rename as an unrelated create-plus-delete; capture, rewind, and diff must interpret the write-layer semantics correctly at the overlay level. Existing-descriptor and shared-mapping timing gaps and the ownership contract are residuals in section 4 |
| Un-enumerated policy-relevant syscall (the default-allow residual) | Filesystem and network effects are independently caught by the Landlock backstop, which does not depend on the enumeration being complete (ADR-0003); process creation cannot escape mediation because inheritance is automatic (I1); the enumeration is a tier:2 review surface with `strace`-based coverage tests ([`syscalls.md`](syscalls.md) section 6) | I1 | An `strace`-based coverage run over a real agent workload must surface any policy-relevant syscall reaching the kernel un-enumerated; a forbidden filesystem or network effect attempted through such a syscall must still be caught by Landlock. The host-egress dimension is the residual in section 4 |

## 4. Accepted residuals

ADR-0020 replaces the injected-socket fidelity residual with child-socket duplication through `pidfd_getfd`.
The confined broker operates on the same open file description, so socket type, protocol, options, status, and binding state are preserved.
Destination-bearing UDP `sendto` remains without a Landlock port backstop on the supported ABI range and is enforced by the seccomp decision plus the confined broker.
Suffix hostname policies are rejected before enforce spawn rather than accepted with an unprovable match.

Each item is a risk the design does not fully close, stated with why it is accepted or unavoidable and
what bounds it. Every one is named here rather than hidden; that is the point of the section. Each is
promised by a sibling file and consolidated here so the audit is in one place.

- **Post-`SEND` reply loss can double-execute a supervisor-realized side effect on an unfixed kernel.**
  On kernels without upstream fix `cce436aafc2a`, a signal can wake the tracee and race with `SEND` so the tracee discards an already-delivered reply and restarts the syscall ([`notify-loop.md`](notify-loop.md) section 4.1, ADR-0021).
  What bounds it: `WAIT_KILLABLE_RECV` closes cancellation before `SEND`, the remaining window is the few microseconds between signal wakeup and notification-lock reacquisition, and kernels carrying the fix close it.
- **Host-level TCP egress has no kernel backstop.**
  Landlock's network rules are port-based, so they cannot enforce a host allowlist ([`syscalls.md`](syscalls.md) section 3.5, [`policy.md`](policy.md) section 6, ADR-0013).
  Host identity is enforced by the seccomp decision and realized by the confined broker on a `pidfd_getfd` duplicate of the child's actual socket.
  What bounds it: the seccomp enumeration for the network family is treated as security-critical and drawn most conservatively, because it is the one dimension where the enumeration must be complete on its own.
  Named, not hidden.
- **UDP destination ports have no Landlock backstop on the supported ABI range.**
  ADR-0020 realizes destination-bearing `sendto` in the confined broker on the actual child socket, so the seccomp decision controls the copied host and port without a pointer race.
  The available Landlock network ABI handles TCP ports only.
  What bounds it: `sendto` is in the security-critical enumeration, unsupported address families and over-cap payloads fail closed, and the residual is stamped in run metadata.
- **Hostname rules resolve names at the supervisor, and names move.** A hostname rule is matched by the supervisor resolving the rule's name itself and comparing the child's kernel-trusted destination IP against the resolved set ([`policy.md`](policy.md) section 2.2). A CDN rotating addresses between the cache refresh and the connect can make a legitimate connect miss the allowlist, and one IP serving several hosts can let a connect reach a co-hosted service on an allowed address. What bounds it: the child's own resolver is never trusted, a false miss fails closed (denied, visible, retryable), and the co-hosting exposure requires the allowed host to actually share the address and the port. Named, not hidden.
- **`sendmsg` to an unconnected socket is not conditionally trappable.** The BPF filter sees only register arguments; `sendmsg`'s destination lives in `msghdr.msg_name` behind the message pointer, so the filter cannot condition on it without trapping every `sendmsg`, a hot-path cost on connected-socket data traffic ([`syscalls.md`](syscalls.md) section 3.5). What bounds it: v1 mediates the connection boundary at `connect`, `bind`, and `sendto`; widening to all `sendmsg` is a tier:2 change if a workload sends to unconnected sockets that way. Named, not hidden.
- **pid reuse in the tree-membership check.** `ptrace` and `process_vm_*` are decided on whether the target pid is in the supervisor's tracked tree ([`syscalls.md`](syscalls.md) section 3.4). Between the supervisor's bookkeeping and the kernel's use of the pid, a pid could be reused. What bounds it: the pid is a kernel-trusted scalar taken at trap time, the tree is rebuilt from observed `fork`/`clone`/`clone3` events, and the window is narrow; closing it fully would need pidfd-based identity, deferred with `pidfd_getfd`. Named, not hidden.
- **Record-only trace fidelity under a racing child.** In record-only mode every allow is realized with `CONTINUE` (ADR-0017), so the kernel re-reads pointer arguments at execution time; a deliberately racing sibling thread can swap a path between the supervisor's bounded read and the kernel's use, making the child's own trace misdescribe that argument ([`syscalls.md`](syscalls.md) section 4, [`notify-loop.md`](notify-loop.md) section 3). What bounds it: the recorded value is the once-read trap-time value, never re-read (I4 on the recording side); no enforcement claim rests on it, because record-only makes none; and in enforce mode the allow-realization rule applies in full, where the escape test for the TOCTOU row in section 3 holds. Named, not hidden.
- **An undecodable network address leaves the destination unnamed in record-only.** A `sockaddr` the supervisor cannot read within its 128-byte cap, or cannot decode, yields no trusted destination; in record-only the event is recorded as `raw` and the syscall continues rather than being denied (ADR-0019, [`notify-loop.md`](notify-loop.md) sections 2 and 4). A child can trigger this deliberately by passing a short or exotic `sockaddr`, so the trace can carry a network attempt whose destination it cannot name. What bounds it: the attempt is still recorded, so the trace is incomplete in one field rather than silently missing an action; the child gains no reach it did not already have in a mode that enforces nothing (ADR-0010); and in enforce mode, where the boundary is claimed, the same arc denies fail-closed. Named, not hidden.
- **A non-IP socket address family carries no typed network fact.** The `sockaddr` parse decodes `AF_INET` and `AF_INET6` only; every other family, `AF_UNIX` above all (dbus, `docker.sock`, nscd, X11 - routine traffic under an agent), takes the same arc as an undecodable address: recorded as `raw` and continued in record-only, denied fail-closed in enforce ([`syscalls.md`](syscalls.md) section 3.5, ADR-0019). What bounds it: a local-socket `connect` or `bind` is still recorded as an attempt with the syscall named, and the host allowlist this family exists to enforce is an IP-level boundary that an `AF_UNIX` address carries no operand for. Its cost is real and is on the enforce side: until the parse grows a typed local-socket fact, enabling enforce mode denies routine `AF_UNIX` use, so widening the parse is a prerequisite of that mode rather than an optional refinement. Named, not hidden.
- **Record-only state protection is not established by same-uid permissions.**
  Ordinary record-only trace protection retains the FR-21 residual.
  Snapshots exist only in enforce mode (ADR-0024), where the implicit state-root deny protects them during the run.
- **The state-root deny is a path decision with named gaps.**
  Each of these is a residual of the implicit deny, not a control:
  - Exec is decided at trap time on the resolved spelling of the path, not on an opened handle, so a swap of a symlink or directory after the check is a residual; exec of a file the agent cannot create under the root reads nothing from it anyway.
    Its resolution uses the supervisor's view of the filesystem, which equals the agent's unless the agent changed its root.
  - `mknod` and `mknodat` are not mediated, and they create regular files and FIFOs as well as device nodes.
    Where a policy grant overlaps the root, a node planted there (a pre-created `report.txt` breaks the `create_new` of the report and fails the run closed) is held back only by Landlock where no grant overlaps.
  - A hard link into the store that existed before the run is the same inode under a name outside the root, and the deny matches names, not inodes.
  - On a case-insensitive filesystem a differently-cased spelling would resolve to the root; the identity read back from the handle is expected to be the stored case, but this is unverified.
  - A path under the root that exists answers `EACCES` and one that does not answers `ENOENT`, because the path is resolved before it is judged, so an agent can learn whether a name under the root exists (an existence oracle).
- **At-rest forgery without `--expect`.**
  Snapshots at rest are ordinary files owned by the operator, so any process running as that uid between runs can rewrite them, including a later record-only agent.
  Content hashes detect corruption, not forgery, because a rewritten manifest with matching new objects passes them (ADR-0024 rule 15).
  What bounds it: step events carry manifest digests, `run_end` carries a chain head printed at run end, `leash rewind --expect <digest>` refuses a mismatch, and rewind confines every write beneath the workspace.
  The ADR-0022 custodian would close it and is deferred.
- **Single-layer reads of the store under a read grant.**
  A read-only policy grant that overlaps the state root or any cgroup2 mount is allowed and stamped into the trace; only the seccomp layer denies those reads (ADR-0024 rule 5).
  What bounds it: the implicit first-ranked deny still covers every read, and the overlap is visible in the trace.
- **Metadata-only calls can deny a rewind but not forge one.**
  `fchmodat2`, `utimensat` and xattr calls are unmediated and outside Landlock (ADR-0024).
  What bounds it: they change metadata, not content or names, so a rewind can fail or be noisy, but a forged snapshot cannot result from them.
- **Metadata reads of the state root are unmediated.**
  `stat`, `readlink` and `inotify_add_watch` are not covered by the implicit state-root deny (ADR-0024 rule 3).
  What bounds it: the deny covers every open and every mutation, so content cannot be read or changed through them.
  The deny matches by path identity, so a second mount of the same directory is also a residual.
- **Out-of-tree helper reached through an allowed channel.**
  A process outside the run's tree, reached through a channel the policy allows (policy-allowed localhost TCP, or `sendmsg` to an unconnected socket, which is already a residual above), is neither frozen nor confined by the run's Landlock domain.
  Such a helper can read or write the store during the run, because the implicit deny and the freezer apply only to the run's tree (ADR-0024 Consequences).
  What bounds it: the operator's policy decides which channels exist, a store can be checked against an operator-held digest (`--expect`), and rewind confines every write beneath the workspace.

- **Existing-descriptor and shared-mapping writes do not necessarily drive step timing.**
  Event quiescence cannot establish a consistent capture. ADR-0022 requires whole-cgroup
  freeze, broker quiescence and a verified strategy for outstanding asynchronous mutation
  before capture.
  These controls and their bypass tests are pending.
  The prior M0 spike does not establish concurrent capture fidelity.
- **External workspace writers are outside the exactness contract.** The operator must stop
  editors, build daemons, shared mappings and writes through hard-link aliases during run
  and rewind. A Leash lock excludes other Leash operations only. External-writer exclusion
  is neither enforced nor reliably detected; exactness is conditional on ownership.
- **Freezer support is insufficient without containment and I/O quiescence.** Child migration,
  control-plane writes, pending broker operations and legacy asynchronous I/O can invalidate
  the barrier.
  ADR-0022 requires explicit prevention or verified draining, bounded freeze completion, whole-tree shutdown, and failure tests before any exactness claim.
  ADR-0024 specifies these controls for snapshot runs, which are restricted to enforce mode, and they are not yet implemented.

- **`truncate` has no Landlock backstop below ABI 3.** The dedicated `FS_TRUNCATE` right arrived at Landlock ABI 3 (Linux 6.2), above the kernel floor of ABI 2 ([`syscalls.md`](syscalls.md) section 3.2, degrade table in [`architecture.md`](architecture.md) section 5.1). What bounds it: where the running ABI lacks the right, the seccomp layer mediates `truncate` and the missing backstop is stamped into the trace as a residual, per ADR-0013; the boundary still holds on the seccomp layer. Named, not hidden.
- **The ask prompt shares its terminal with the child.** The attended ask prompts on the controlling terminal ([`notify-loop.md`](notify-loop.md) section 5), and the child can write lookalike text to that same terminal, so an operator could in principle read a spoofed prompt or misattribute a real one. What bounds it: a lookalike line is only text and cannot realize an allow - an allow happens solely when the supervisor's own prompt path collects an explicit approval while a syscall is actually held; the real prompt names the exact action and its matched rule, so an unexpected request is visible as such; and unattended runs never prompt at all (FR-20). Named, not hidden.
- **The default-allow enumeration residual.** A policy-relevant syscall absent from the mediated set passes unmediated ([`syscalls.md`](syscalls.md) section 6). What bounds it: filesystem and network effects are independently caught by the Landlock backstop for enforce mode (which does not depend on a complete enumeration, ADR-0003), process creation cannot escape because filter inheritance is automatic (I1), and the enumeration is reviewed as a tier:2 surface with `strace`-based coverage tests over a real workload. The one dimension Landlock cannot backstop is host-level egress (first residual above), which is why the network family is drawn most conservatively. Named, not hidden.

## 5. Coverage check

This is the completeness audit over the design layer before the freeze: every security requirement is
addressed, and every enforcement claim has a home in section 3 or an entry in section 4.

- **SR-1** (treat the agent and all descendants as hostile) is the adversary fixed in section 1 and in [`architecture.md`](architecture.md) section 2; every row in section 3 red-teams against it.
- **SR-2** (resist the enumerated escape classes, each control mapping to tests) is the whole of section 3: child-process laundering, symlink/TOCTOU, `/proc` self-reference, alternate-syscall equivalents (`open`/`openat`/`openat2`, `io_uring`, `connect`/`sendto`), fd inheritance/passing, and recorder-tampering each have a row with a mechanism, an invariant, and a test.
- **SR-3** (do not rely on any control the child can disable) is preserved by every mechanism resting on a kernel-enforced property: filter inheritance (I1), the Landlock backstop and its degrade table, kernel-driven fail-closed on supervisor death (I3), and the arch pin. Where a dimension has no kernel backstop (host egress, record-only trace, sub-ABI `truncate`), it is named in section 4, not claimed as enforced.
- **SR-4** (deny un-mediated I/O paths in both modes: `io_uring_setup` and `pidfd_getfd`) is the `io_uring`, `pidfd_getfd`, and foreign-ABI rows of section 3 and the denied-and-recorded set of [`syscalls.md`](syscalls.md) section 5.
  The snapshot-run `clone3` `ENOSYS` and legacy AIO denials have their own rows in section 3 and are specified by ADR-0024, not yet implemented.
- **NFR-5** (no control described as enforced without a passing escape test) is the discipline of section 1 and the test column of section 3: an untested claim is not an enforcement claim.

Every control the design layer describes as enforced has a row in the section 3 table; every risk it
does not close has an entry in section 4. The M0 spike settled the snapshot mechanism on the x86-64
target (issue #13, ADR-0014), so this file and the design layer freeze together. The freeze carries a
standing obligation into implementation: the design is complete and honest on the security axis only
when the section 3 tests pass, and no control is claimed as enforced before its test does (I5).
