# Architecture

- Status: draft, in review (slate 1)
- Governs: how the supervisor is structured and how it brings a run into being.
- Cites: FR-1, FR-3, FR-8, FR-9, FR-14, FR-15; SR-1, SR-3; ADR-0002, ADR-0003, ADR-0006, ADR-0007, ADR-0011.

This is the entry point to the design. It fixes the process and trust model, the invariants every
other design file cites, the module decomposition, and the supervisor lifecycle from preflight to
shutdown. Terms in **bold** are defined in [`../CONTEXT.md`](../CONTEXT.md) and used exactly.

## 1. System overview

Leash is one **supervisor** process mediating one **child** process tree at the operating-system
boundary (ADR-0006). The child is launched under a seccomp filter that returns
`SECCOMP_RET_USER_NOTIF` for every **mediated syscall**; the child blocks and the supervisor,
holding the notification fd, decides allow / deny / **ask**, records an **event**, and only then
lets the kernel proceed. **Landlock** adds a second, always-on filesystem and network boundary
applied by the child before it execs the agent, so the kernel enforces a floor even where the
decision logic has a gap (ADR-0003).

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

- **I1** - No policy-relevant syscall of the monitored child tree reaches the kernel un-mediated.
  New processes created by `fork`, `clone`, `clone3`, and `execve` inherit the seccomp filter, so
  a grandchild is mediated exactly as the agent is. Any change to process handling re-verifies this.
  (FR-1, FR-4, SR-2.)
- **I2** - The child can never read, mutate, delay, or block the **trace** or the supervisor's
  decision path. The supervisor is the sole author of the trace. (FR-3, ADR-0002.)
- **I3** - Every decision **fails closed**. Any supervisor error, crash, or decision timeout
  resolves the pending action to deny; the child never gets a default-allow. (FR-9, NFR-1.)
- **I4** - Decisions are made against kernel-trusted data, never against child-controlled memory
  read naively. Pointer arguments are resolved by the supervisor itself, not trusted as the child
  presented them. (SR-2; TOCTOU handling in [`notify-loop.md`](notify-loop.md).)
- **I5** - No control is described as enforced without a passing **escape**-attempt test. (NFR-5.)

## 4. Module decomposition

Six modules. The split exists so the security-critical, hard-to-test machinery (the notify loop,
the sandbox setup) stays thin and delegates every judgement to pure, exhaustively testable code
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

- **Kernel floor.** seccomp user-notification requires Linux 5.9 or later; Landlock requires 5.13
  or later (FR-14). Below the floor, refuse with a clear message. `ptrace`-based interception was
  considered as a below-floor fallback and rejected: it is high-overhead, racy on `fork`/`clone`,
  and awkward with multi-threaded children, so degrading to it would weaken the boundary Leash
  claims. Refusing to run is the honest failure.
- **Landlock ABI.** The supported ABI is queried at runtime, never assumed. Capabilities were added
  over versions: filesystem rules exist from ABI 1, network (TCP connect/bind) rules from ABI 4.
  The floor (5.13) guarantees filesystem Landlock but not network Landlock. The degrade table below
  fixes what happens when the policy needs a capability the running ABI lacks.
- **Overlay support.** Whether an overlay mount is available (privileged mount, or an unprivileged
  user namespace) selects the snapshot mechanism: overlay if available, plain-copy fallback
  otherwise (ADR-0009). The selected mechanism is stamped into the trace.

Landlock ABI degrade table:

| Policy needs | ABI provides it | Record-only mode | Enforce mode |
|---|---|---|---|
| Filesystem rules | yes (ABI >= 1, floor guarantees) | apply | apply |
| Network rules | yes (ABI >= 4) | apply | apply |
| Network rules | no (ABI < 4) | warn, stamp the gap in the trace, continue (nothing is enforced anyway) | refuse to start: the policy asks for a boundary the kernel cannot back |

The rule behind the table: in enforce mode Leash never starts a run in which a policy-required
boundary would silently not hold (I3, SR-3). In record-only mode nothing is enforced, so a missing
capability is recorded as a gap rather than a refusal. The seccomp layer still mediates network
syscalls for the trace in both modes; the table is only about the Landlock backstop.

### 5.2 Spawn protocol

The ordering is forced by the kernel API and by the invariants; each step precedes the next for a
stated reason.

1. Supervisor prepares the per-run directory in the state directory and mounts the overlay write
   layer over the workspace (or selects the copy fallback). (FR-21, ADR-0009.)
2. Supervisor creates a socketpair for the notify-fd handoff, then forks the child.
3. Child installs the seccomp filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER`, which returns the
   notification fd, and sets `no_new_privs` so the filter and the coming Landlock ruleset survive
   `execve`.
4. Child sends the notification fd to the supervisor over the socketpair using `SCM_RIGHTS`, then
   waits for the supervisor to acknowledge that it holds the fd and is ready to serve.
5. Child applies the Landlock ruleset granting exactly the workspace and the explicitly allowed
   paths and hosts (ADR-0003). Landlock is applied by the child, pre-exec, because a process can
   only restrict itself and its descendants.
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
