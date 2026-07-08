# Mediated syscalls

- Status: draft, in review (slate 2)
- Governs: which syscalls the seccomp filter mediates, denies, or passes through, and how each
  allowed one is realized safely.
- Cites: FR-2, FR-4, FR-15; SR-2, SR-3, SR-4; ADR-0003, ADR-0006, ADR-0011. Invariants I1, I4, I5
  are defined in [`architecture.md`](architecture.md).

This file fixes the mediation surface: the exact sets of syscalls the child is trapped on, denied
outright, or allowed to run unmediated, and the rule for how an allowed mediated syscall is carried
out without opening a TOCTOU window. The notify-loop protocol that drives these decisions is in
[`notify-loop.md`](notify-loop.md); the escape tests each choice must survive are in
[`escapes.md`](escapes.md). Terms in **bold** are defined in [`../CONTEXT.md`](../CONTEXT.md).

## 1. Three sets, one default

The seccomp filter sorts every syscall into one of three sets:

- **Mediated** - the filter returns `SECCOMP_RET_USER_NOTIF`; the child blocks and the supervisor
  decides (allow / deny / **ask**) and records an **event** (FR-2, FR-4).
- **Denied by the filter** - the filter returns `SECCOMP_RET_ERRNO` directly, without ever waking
  the supervisor. Reserved for syscalls that establish an un-mediated I/O path (SR-4).
- **Pass-through** - the filter returns `SECCOMP_RET_ALLOW`; the kernel runs the syscall with no
  supervisor involvement.

The default for any syscall not named in the first two sets is pass-through. The alternative,
default-mediate, was rejected: trapping every syscall (including `read`, `write`, `futex`, `mmap`)
would serialize the child's entire execution through the single decision loop (ADR-0011) and destroy
the always-on overhead budget (NFR-2), for no security gain over the fd-authorization model in
section 2. The cost of default-allow is stated honestly in section 6: a policy-relevant syscall we
failed to enumerate passes unmediated, caught only by the Landlock backstop (for filesystem and
network) and by the enumeration-review discipline. Moving any syscall between sets is a tier:2 change
and requires the escape tests in [`escapes.md`](escapes.md) (I5).

Filter inheritance is a kernel property, not something the mediated set buys us: a seccomp filter is
inherited across `fork`, `clone`, `clone3`, and preserved across `execve` once `no_new_privs` is set
(I1). A grandchild is trapped exactly as the agent is even for a `clone` variant we never enumerated.
We mediate the process-creation family (section 3.3) to record it and to let policy forbid spawning,
never to preserve inheritance.

## 2. The fd-authorization model

Leash decides filesystem access at the syscall that introduces a path, not at every byte moved.
`openat` carries the path and the requested access mode; that is where the **decision** is made. The
returned file descriptor is then a capability the child already holds a decision for, so `read`,
`write`, `pread`, `pwrite`, `lseek`, `close`, and `mmap` on it are pass-through. Mediating them would
add a decision-loop round trip to the child's hot path (NFR-2) and re-decide an access already
resolved at open.

Consequence, stated plainly: the **trace** records that a file was opened for write, not the bytes
written. The byte-level content is out of scope for the trace; the **snapshot** captures the actual
resulting file content anyway ([`snapshot.md`](snapshot.md)), so nothing about what the agent
produced is lost. **Step** detection (FR-17) is driven by the timestamps of mutating mediated events
(open-for-write, create, rename, unlink, and the rest of section 3.2), which is exactly the
"supervisor-observed events" FR-17 requires, and needs no per-`write` trap.

## 3. The mediated set, by family

The decision basis column states what the decision reads. Register arguments arrive in the
`seccomp_notif` as a kernel-trusted snapshot taken at trap time, so a decision on a scalar or flag
argument is safe. A **pointer** argument (a path, a `sockaddr`) points into child memory and is
TOCTOU-prone; it is read as described in [`notify-loop.md`](notify-loop.md) and never trusted as a
bare value. The response column states how an allow is realized; the rule behind it is section 4.

### 3.1 Path-introducing (returns an fd)

| Syscall | Also on ARM64 | Decision basis | Allow realized by | Landlock backstop |
|---|---|---|---|---|
| `openat`, `openat2` | yes | path + access mode (pointer) | `ADDFD`: supervisor opens the resolved path, injects the fd | `FS_READ_FILE` / `FS_WRITE_FILE` |
| `open`, `creat` | no (x86-64 legacy only) | path + access mode (pointer) | `ADDFD` | same |

### 3.2 Filesystem mutation (no fd returned)

| Syscall | Also on ARM64 | Decision basis | Allow realized by | Landlock backstop |
|---|---|---|---|---|
| `renameat`, `renameat2` | yes | source + dest paths (pointers) | supervisor performs it on the resolved paths, spoofs the return | `FS_REFER` (+ dir rights) |
| `rename` | no (x86-64) | as above | as above | as above |
| `unlinkat` | yes | path + flags (pointer + scalar) | supervisor-executed, spoofed return | `FS_REMOVE_FILE` / `FS_REMOVE_DIR` |
| `unlink`, `rmdir` | no (x86-64) | path (pointer) | as above | as above |
| `mkdirat` | yes | path (pointer) | supervisor-executed, spoofed return | `FS_MAKE_DIR` |
| `mkdir` | no (x86-64) | path (pointer) | as above | as above |
| `linkat`, `symlinkat` | yes | paths (pointers) | supervisor-executed, spoofed return | `FS_MAKE_REG` / `FS_MAKE_SYM` |
| `link`, `symlink` | no (x86-64) | paths (pointers) | as above | as above |
| `truncate` | yes | path + length (pointer + scalar) | supervisor-executed, spoofed return | `FS_WRITE_FILE` |

`ftruncate`, `fchmod`, `fchown`, `fchdir` act on an fd already decided at open and are pass-through;
their path-taking cousins `chmod`, `chown`, `fchmodat`, `fchownat`, `chdir` are mediated on the same
supervisor-executed pattern when a policy governs metadata. Metadata-only predicates are an open
parameter for slate 2 (see the open-parameters table in [`README.md`](README.md)); until a policy
expresses them, these are traced and allowed.

### 3.3 Process creation and program execution

| Syscall | Also on ARM64 | Decision basis | Allow realized by | Landlock backstop |
|---|---|---|---|---|
| `fork`, `vfork` | no (x86-64) | none (creation itself) | `CONTINUE` (scalar decision) | none (I1 is automatic) |
| `clone`, `clone3` | yes | flags (scalar / struct) | `CONTINUE` | none (I1 is automatic) |
| `execve`, `execveat` | yes | binary path (pointer) | `CONTINUE`, backstopped by Landlock | `FS_EXECUTE` |

`execve` cannot be injected: there is no fd to `ADDFD` and the exec replaces the address space. The
allow is realized with `CONTINUE`, which re-reads the path from child memory, so the enforcing
control for "which binaries may run" is the Landlock `FS_EXECUTE` right, checked by the kernel at
execution against the resolved file (SR-3). The supervisor's decision on the read path drives the
trace and any **ask**; the kernel drives enforcement. This split is stated as a residual in
[`escapes.md`](escapes.md).

`clone3` is decided on a `clone_args` struct in child memory; the flag word is read once and the
decision is on that read value. Because the enforcing property (filter inheritance) is automatic, a
swapped flag after the read cannot escape mediation; it can at most misrecord the flags in the trace,
which the notify loop bounds by reading once and recording what it read (I4).

### 3.4 Cross-process control

These reach into another process, and their escape is laundering: the child manipulates a process
*outside* the tree, which is not under the filter, and makes it perform the forbidden action
un-mediated (SR-2). Landlock does not stop them. They are mediated on **tree membership**: the
supervisor tracks the live child tree from the `fork`/`clone`/`clone3` events it already observes, and
the decision is whether the target pid is in that set.

| Syscall | Also on ARM64 | Decision basis | Allow realized by | Deny when |
|---|---|---|---|---|
| `ptrace` | yes | target pid (scalar) | `CONTINUE` | target is outside the tree |
| `process_vm_readv`, `process_vm_writev` | yes | target pid (scalar) | `CONTINUE` | target is outside the tree |
| `pidfd_getfd` | yes | target pidfd (scalar) | `CONTINUE` | the pidfd names a process outside the tree |

The target pid is a scalar register argument, kernel-trusted at trap time, so the decision is
`CONTINUE`-safe (section 4). In-tree use (an agent running `strace` on its own subprocess) is allowed;
reaching out of the tree is denied. `pidfd_getfd` is the fd-inheritance escape in syscall form: it
lets a process pull a file descriptor out of another process, so it is mediated the same way. The
residual is pid reuse between the supervisor's tree bookkeeping and the kernel's use of the pid; it is
a line in [`escapes.md`](escapes.md).

### 3.5 Network

| Syscall | Also on ARM64 | Decision basis | Allow realized by | Landlock backstop |
|---|---|---|---|---|
| `connect` | yes | `sockaddr` host + port (pointer) | supervisor connects a fresh socket, injects it with `ADDFD`; or `CONTINUE` for allow-all policies | `NET_CONNECT_TCP` (port only) |
| `bind` | yes | `sockaddr` port (pointer) | supervisor-executed or `CONTINUE` per policy | `NET_BIND_TCP` (port only) |
| `sendto`, `sendmsg` | yes | destination `sockaddr` when the socket is unconnected (pointer) | as `connect` | `NET_CONNECT_TCP` (port only) |

Network is arch-uniform: `socket`, `connect`, and `bind` exist directly on both x86-64 and ARM64
(the multiplexed `socketcall` is a 32-bit-x86 artifact and is denied as a foreign-ABI syscall,
section 5). `socket` itself is traced but allowed; the boundary is enforced at `connect`/`bind`.

Landlock's network rules are **port-based**, so they cannot enforce a host allowlist (FR-7); they
backstop the port dimension only. Host-level enforcement therefore rests on the seccomp decision,
which makes the `sockaddr` TOCTOU real: with a bare `CONTINUE`, a second thread could rewrite the
address between the supervisor's read and the kernel's connect. The design closes it by realizing a
host-enforced allow as a supervisor-side connect injected with `ADDFD` (the supervisor opens a
socket, connects it to the validated address, and installs it over the child's fd number), never as
`CONTINUE`. `CONTINUE` is used only where the policy imposes no host constraint. The fidelity cost of
the injected socket (socket options the child set before `connect`) is an open parameter for slate 2
and a line in [`escapes.md`](escapes.md).

## 4. The allow-realization rule (normative)

One rule governs every "allow" response, and it is the load-bearing security decision of this file
(I4). It is stated once here and once in [`notify-loop.md`](notify-loop.md); the two must agree.

1. If the decision reads only the syscall number or scalar/flag register arguments, the allow is
   realized with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`. The kernel re-executes the same syscall; there
   is no child-controlled memory to race.
2. If the decision reads a pointer argument (a path, a `sockaddr`) and the syscall returns an fd, the
   allow is realized with `SECCOMP_ADDFD`: the supervisor opens the resolved resource itself and
   injects the fd. The child never gets a re-editable argument between check and use.
3. If the decision reads a pointer argument and no fd can be injected as the return value (the
   mutation family, `connect` under a host policy), the supervisor performs the operation itself on
   the resolved target and spoofs the return value. `CONTINUE` is not used, because `CONTINUE`
   re-reads the pointer. Where the child also needs the resulting resource, not just a return code,
   the supervisor hands it back with `ADDFD` over the argument fd: for a host-enforced `connect` it
   opens a socket, connects it to the validated address, installs it over the child's socket fd
   (`ADDFD` with `SETFD`), and returns success. The fidelity limit of this, socket options the child
   set before `connect`, is the open parameter noted in section 3.5.
4. `execve` is the one exception where an allow must use `CONTINUE`; its enforcement is delegated to
   the Landlock `FS_EXECUTE` backstop (section 3.3), and the residual is recorded.

Path resolution for cases 2 and 3 is done by the supervisor under a no-symlink, no-magic-link,
beneath-the-workspace constraint (`openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
RESOLVE_NO_MAGICLINKS`), which is what defeats the symlink and `/proc` self-reference escapes (SR-2).
The exact resolve-flag set is an open parameter pending the M0 spike and slate 2.

## 5. The denied-by-filter set

These the filter rejects with `SECCOMP_RET_ERRNO` before the supervisor is ever consulted, because
they can establish I/O the mediation surface cannot see (SR-4, SR-3):

- `io_uring_setup` (and therefore `io_uring_enter`, `io_uring_register`, which are useless without
  it). `io_uring` submits reads, writes, opens, and connects out of band through a shared ring the
  seccomp filter does not observe; it is a first-class bypass. It is denied by the filter in **both**
  modes, and the reason differs by mode. In **enforce** it is an un-mediated I/O path the policy
  could not constrain (SR-4). In **record-only** it would make the **trace** silently incomplete: the
  ring's I/O would never appear as an **event**, so the camera would have a blind spot the operator
  could not see, which defeats what record-only is for. Denying it is not policy enforcement (there is
  no rule involved); it is the filter refusing to let the agent make the trace lie, so it does not
  contradict "record-only enforces nothing". The cost, that an agent genuinely needing `io_uring`
  fails in record-only rather than running with a partial trace, is the recommended trade and is
  called out for slate 2. Relaxing SR-4 for a path requires a spec change adding equivalent mediation
  and its escape tests first.
- Foreign-ABI entry: any syscall whose `seccomp_data.arch` does not match the architecture the filter
  was compiled for. The filter pins `AUDIT_ARCH_X86_64` or `AUDIT_ARCH_AARCH64` and denies the
  mismatch, closing the classic seccomp arch-confusion bypass (a binary invoking the x86-32 or x32
  ABI to reach a syscall number the filter reads differently). This is the same reason `socketcall`
  and the 32-bit legacy multiplexers are denied. (FR-15, SR-3.)

Denied means the syscall's effect never happens; the child receives an errno. This is consistent with
fail-closed (I3): the boundary holds by the action not taking effect.

## 6. Pass-through, and its residual

Everything not named above is pass-through: the compute and memory syscalls (`mmap` of an authorized
fd, `mprotect`, `brk`, `futex`, `nanosleep`, `getpid`, the `read`/`write` family per section 2), and
fd operations on already-decided descriptors (`dup3`, `fcntl`, `close`). None crosses the **boundary**
to a resource that was not already decided.

The residual of default-allow: a policy-relevant syscall absent from the mediated set passes
unmediated. Three things bound it. Filesystem and network effects are independently caught by the
Landlock backstop, which does not depend on the enumeration being complete (ADR-0003). Process
creation cannot escape mediation because inheritance is automatic (I1, section 1). And the enumeration
is reviewed as a tier:2 surface, with `strace`-based coverage tests over a real agent workload to
surface any policy-relevant syscall reaching the kernel un-enumerated ([`escapes.md`](escapes.md),
NFR-5). What Landlock cannot backstop, host-level network egress, is the one place the enumeration
must be complete on its own, which is why the network family is the most conservatively drawn.
