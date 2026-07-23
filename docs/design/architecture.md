# Architecture

- Status: settled (design layer frozen 2026-07-08)
- Governs: how the supervisor is structured and how it brings a run into being.
- Cites: FR-1, FR-3, FR-8, FR-9, FR-14, FR-15; SR-1, SR-3; ADR-0002, ADR-0003, ADR-0006, ADR-0007,
  ADR-0011, ADR-0019.

This is the entry point to the design. It fixes the process and trust model, the invariants every
other design file cites, the module decomposition, and the supervisor lifecycle from preflight to
shutdown. Terms in **bold** are defined in [`../CONTEXT.md`](../CONTEXT.md) and used exactly.

## 1. System overview

Leash is one **supervisor** process mediating one **child** process tree at the operating-system
boundary (ADR-0006). The child is launched under a seccomp filter that returns
`SECCOMP_RET_USER_NOTIF` for every **mediated syscall**; the child blocks and the supervisor,
holding the notification fd, decides allow / deny / **ask**, records an **event**, and only then
lets the kernel proceed. **Landlock** adds a second, kernel-enforced boundary in **enforce** mode,
applied by the child before it execs the agent: a filesystem boundary always, and a network-port
boundary where the running ABI supports it (ADR-0003, ADR-0013). It holds even where the decision
logic has a gap. In **record-only** mode nothing is enforced, so no Landlock ruleset is applied
(ADR-0010).

```
  leash (supervisor, trusted)              child (agent + whole process tree, untrusted)
  +-----------------------------+          +--------------------------------+
  | cli          policy engine  |  notify  |  agent / node / bash / curl    |
  | supervisor   recorder       |<-- fd ---|  every mediated syscall traps   |
  | sandbox      snapshot mgr   |          |  via the seccomp filter         |
  |              approval UI     |          |  Landlock ruleset applied       |
  +-----------------------------+          |  by the child before exec       |
        |                                  +--------------------------------+
        | authors                                    |
        v                                            v
   trace + snapshots (state dir)              workspace (overlay write layer)
```

The trace and snapshots live under a per-run directory in the state directory, outside the
**workspace** and, in **enforce** mode, denied to the child (FR-21, FR-3). The workspace is mounted
with an overlay write layer for the duration of the run so the child's writes are captured
(ADR-0009, detailed in [`snapshot.md`](snapshot.md)).

## 2. Trust model

The **operator** is trusted. The child, meaning the agent and every process it spawns, is hostile
by assumption (SR-1): it may act through prompt injection, a compromised dependency, or plain error,
and it runs with the operator's privileges. The **boundary** is the trust line between the two; no
child action crosses it un-mediated.

Out of scope, stated plainly and not defended against: kernel exploits and privilege escalation past
the OS boundary, hardware and micro-architectural side channels, a malicious operator, and covert
exfiltration through channels the policy allows (spec section 9). The escape classes that are in
scope, and the mechanism that stops each, are enumerated in [`escapes.md`](escapes.md).

## 3. Invariants

These are the properties every design choice in this layer preserves. Other design files cite them
by ID. ADR-0002 already refers to I2 by this number; the full list is fixed here.

- **I1** - No policy-relevant syscall of the supervised child tree reaches the kernel un-mediated.
  New processes created by `fork`, `clone`, `clone3`, and `execve` inherit the seccomp filter, so
  a grandchild is mediated exactly as the agent is. Any change to process handling re-verifies this.
  (FR-1, FR-4, SR-2.)
- **I2** - The supervisor is the sole author of the **trace** and the sole owner of the decision
  path. In **enforce** mode the child is denied the state directory by both layers (FR-3, FR-21), so
  it can never read, mutate, delay, or block the trace. In **record-only** mode no Landlock ruleset
  is applied (nothing is enforced, ADR-0010), so trace integrity rests on filesystem permissions: the
  state directory lies outside the **workspace** with restrictive permissions, but a hostile same-uid
  child is not defended against. This matches the spec, which scopes state-directory denial to enforce
  mode (FR-21), and matches record-only being a camera, not a bouncer; the residual is named in
  [`escapes.md`](escapes.md). (FR-3, FR-21, ADR-0002.)
- **I3** - Every decision **fails closed**. Any supervisor error, crash, or decision timeout
  resolves the pending action to deny; the child never gets a default-allow. One arc is scoped by
  mode, the same way I2 is: where the supervisor cannot decode a network address from the trapped
  `sockaddr`, **enforce** denies, while **record-only** records the attempt with no destination and
  continues, because record-only enforces nothing outside the denied-and-recorded set (ADR-0010,
  ADR-0019, and FR-9 as it scopes this arc). That arc is the only one scoped by mode. Every other
  arc denies in both modes: an undecodable filesystem or process-creation fact, a recorder-write
  failure, a crash, a decision timeout, and the denied-and-recorded set (SR-4, whose members are
  `io_uring_setup` and `pidfd_getfd`; the latter imports an fd the trace could not otherwise
  attribute, so it denies in record-only too). The residuals are named in
  [`escapes.md`](escapes.md). (FR-9, NFR-1.)
- **I4** - Decisions are made against kernel-trusted data, never against child-controlled memory
  read naively. Pointer arguments are resolved by the supervisor itself, not trusted as the child
  presented them. (SR-2; TOCTOU handling in [`notify-loop.md`](notify-loop.md).)
- **I5** - No control is described as enforced without a passing **escape**-attempt test. (NFR-5.)

## 4. Module decomposition

Six modules. The split exists so the security-critical, hard-to-test machinery (the notify loop,
the sandbox setup) stays thin and delegates every decision to pure, exhaustively testable code
(NFR-6, ADR-0004).

| Module | Responsibility | Depends on |
|---|---|---|
| `policy` | Parse and validate the **policy**; evaluate a decision from a typed fact. Pure: facts in, decision plus matched-rule id out, no IO. | nothing outside its own types |
| `supervisor` | Own the notify fd; run the decision loop; orchestrate preflight, spawn, run, shutdown. | `policy`, `recorder`, `snapshot`, `sandbox` |
| `recorder` | Single writer of the **trace** and the **session report**. | its own event types |
| `snapshot` | Mount and capture the overlay (or the copy fallback); implement rewind and diff. | none on the hot path |
| `sandbox` | Build the seccomp filter; compile and apply the Landlock ruleset; own the child-side spawn steps. | `policy` (to derive the Landlock subset) |
| `cli` | Parse arguments; select and stamp the **mode**; dispatch `run`, `rewind`, `diff`, and run management. | `supervisor`, `snapshot`, `recorder` |

The load-bearing seam is between `supervisor` and `policy`. The supervisor gathers facts from the
kernel and the notification, hands the `policy` engine a typed fact, and gets back a decision and
the id of the matched rule (which the recorder stamps into the event). The engine performs no IO and
reads no child memory, so it is unit-testable without a live child (ADR-0004). Enforcement of a
decision (deny, allow, ask, or fd injection) is the supervisor's job, not the engine's.

## 5. Supervisor lifecycle

### 5.1 Preflight

Before any child exists, the supervisor confirms the host can support the boundary it is about to
claim, and refuses to run rather than silently degrade (FR-14). Preflight bundles three probes:

- **Kernel floor.** Leash requires Linux 5.19 or later, and preflight verifies the capabilities, not
  just the version string (FR-14, ADR-0012): `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`,
  `SECCOMP_ADDFD` with `ADDFD_FLAG_SEND`, and Landlock ABI 2. Below the floor, refuse with a clear
  message. `ptrace`-based interception was considered as a below-floor fallback and rejected: it is
  high-overhead, racy on `fork`/`clone`, and awkward with multi-threaded children, so degrading to it
  would weaken the boundary Leash claims. Refusing to run is the honest failure.
- **Landlock ABI.** The supported ABI is queried at runtime and the handled access rights are masked
  to it, never assumed (an unmasked right on an older ABI fails ruleset creation with `EINVAL`).
  Rights arrived over versions: filesystem access from ABI 1, cross-directory rename/link
  (`FS_REFER`) from ABI 2 (Linux 5.19, the floor), file truncation (`FS_TRUNCATE`) from ABI 3 (Linux
  6.2), TCP connect/bind (`NET_*`) from ABI 4 (Linux 6.7). The floor guarantees ABI 2; anything above
  it is probed, and the degrade table fixes what happens when a backstop the policy could use is
  above the running ABI.
- **Overlay support.** Whether an overlay mount is available (privileged mount, or an unprivileged
  user namespace) selects the snapshot mechanism: overlay if available, plain-copy fallback
  otherwise (ADR-0009). The probe distinguishes a kernel that lacks overlay from a host that merely
  restricts unprivileged user namespaces (for example stock Ubuntu 24.04 with
  `apparmor_restrict_unprivileged_userns=1`, confirmed by the M0 spike): the latter still supports a
  privileged overlay mount, so a privileged run gets overlay and only an unprivileged run on such a
  host falls to the copy fallback. The selected mechanism, and the reason for it, is stamped into the
  trace.

Landlock backstop degrade table. Record-only applies no Landlock at all (nothing is enforced,
ADR-0010); the table is about which backstop the enforce-mode ruleset can carry at a given ABI. Per
ADR-0013 the seccomp layer is the primary decision layer, so a missing backstop degrades to
seccomp-only with a named residual, it does not refuse the run:

| Backstop | Needs | Record-only | Enforce |
|---|---|---|---|
| Landlock ruleset at all | - | not applied | applied |
| Filesystem access + cross-dir rename/link | ABI 2 (floor guarantees) | not applied | applied |
| Truncation | ABI 3 (Linux 6.2) | not applied | applied where present; below, seccomp mediates `truncate` and the missing backstop is stamped as a residual |
| Network port | ABI 4 (Linux 6.7) | not applied | applied where present; below, seccomp enforces the port and the missing backstop is stamped |
| Network host | kernel cannot express it at any ABI | not applied | always seccomp-only; residual named (ADR-0013) |

The rule behind the table: in enforce mode no policy-required boundary is left to hold **silently**
(I3, SR-3), but "silently" is the operative word. Where the kernel can back a dimension, Leash uses
the backstop; where it cannot at the running ABI, the seccomp layer enforces it and the gap is
stamped into the trace, never hidden (ADR-0013). The only hard refusal is below the kernel floor. The
seccomp layer mediates the relevant syscalls for the trace in both modes regardless of Landlock.

### 5.2 Spawn protocol

The ordering is forced by the kernel API and by the invariants; each step precedes the next for a
stated reason.

1. Supervisor prepares the per-run directory in the state directory and mounts the overlay write
   layer over the workspace (or selects the copy fallback). (FR-21, ADR-0009.)
2. Supervisor creates a socketpair for the notify-fd handoff, then forks the child.
3. Child installs the seccomp filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER` and
   `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (so a non-fatal signal cannot cancel a received
   notification and let a supervisor-performed action double-execute, ADR-0012), which returns the
   notification fd, and sets `no_new_privs`. The filter survives `execve` regardless; `no_new_privs`
   is what lets an unprivileged supervisor install the filter and makes it bind across a setuid
   `execve` so the agent cannot shed it.
4. Child sends the notification fd to the supervisor over the socketpair using `SCM_RIGHTS`, then
   waits for the supervisor to acknowledge that it holds the fd and is ready to serve.
5. In **enforce** mode the child applies the Landlock ruleset granting exactly the workspace, the
   explicitly allowed paths, and the TCP port backstop for allowed hosts (ADR-0003, ADR-0013). In
   **record-only** mode this step is skipped: nothing is enforced (ADR-0010). Landlock is applied by
   the child, pre-exec, because a process can only restrict itself and its descendants.
6. Child closes every file descriptor not on its allowlist (to close fd-inheritance escapes, see
   [`escapes.md`](escapes.md)) and calls `execve` on the agent command. Because the filter is
   already installed, the `execve` of the agent is itself the first mediated event (FR-1, FR-4).

Any failure before step 6 aborts the run before the agent executes: the supervisor tears down the
overlay and the run directory and exits non-zero (I3, FR-9). A run that cannot establish the full
boundary does not start.

### 5.3 Run

The supervisor serves the notify fd on a single decision thread (ADR-0011): receive one
notification, validate it, gather facts, evaluate the policy, record the event, respond, repeat.
The protocol, the fact-gathering rules, and the complete fail-closed enumeration are in
[`notify-loop.md`](notify-loop.md). Filesystem-write events feed **step** detection and snapshot
capture ([`snapshot.md`](snapshot.md)).

### 5.4 Shutdown

When the agent process tree exits (or the run is aborted), the supervisor reaps the tree, captures
the final snapshot at the run-end **step** boundary (FR-17), writes the run-end event, finalizes the
trace, and emits the human-readable **session report** (FR-5). The active mode is named in the report
(FR-19). Teardown of the overlay mount is part of shutdown; the captured snapshots persist under the
run directory (FR-21).

## 6. Concurrency model

The decision loop is single-threaded: one notification is fully handled before the next is received
(ADR-0011). Trace order is decision order, the recorder needs no synchronization (ADR-0002), and the
fail-closed enumeration stays finite and checkable (NFR-6). The accepted cost is that a pending ask
stalls other mediated syscalls in the child tree; an ask already pauses the child by design, so a
stalled sibling only observes a slow syscall. If M1 measurements show the loop is the overhead
bottleneck (NFR-2, OQ-5), revisiting this means superseding ADR-0011, not quietly threading the loop.
