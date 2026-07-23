# ADR-0020: Confined broker realization and child-socket duplication

- Status: accepted
- Date: 2026-07-23

## Context

Issue #25 must realize an enforce-mode allow without letting a child race a pointer argument between policy evaluation and kernel use.
The settled syscall design assigned pointer-bearing operations to the supervisor, but the supervisor itself is outside the child's Landlock domain.
An unrestricted supervisor opening or mutating a path would therefore bypass the filesystem backstop required by ADR-0003 and ADR-0013.

The fresh-socket network design also lacked enough information to preserve a child socket's type, protocol, options, local binding, and status flags.
It could not implement `sendto` because replacing a socket does not transmit the payload or produce the syscall's byte-count result.
`pidfd_getfd` can duplicate the child's actual open file description, including socket state, and operations on that duplicate affect the same socket object.

The review also found three semantics that the existing design did not settle.
Two-path filesystem operations need independent source and destination authorization.
The append-only trace cannot promise that every recorded allow completed after the record was written.
Hostname suffix rules cannot be enforced from an IP-only `sockaddr` without observing or controlling DNS.

## Decision

Leash uses one short-lived broker process per enforce run for every supervisor-realized side effect.
The supervisor builds the Landlock ruleset and authoritative root handles, forks the broker while still single-threaded, and requires the broker to apply the same ruleset before the agent is spawned.
Broker setup failure aborts before agent exec.
The unrestricted supervisor may copy bytes and duplicate descriptors, but it never performs the policy-governed filesystem or network effect.

Filesystem realization is a two-phase broker protocol.
The prepare phase resolves beneath an inherited root handle with `openat2`, returns a stable broker token plus the policy identity, and performs no mutation.
The supervisor evaluates and records that identity.
After a final notification-validity check, the commit phase uses the retained fd or parent-dirfd token to perform the operation.
An fd-returning open comes back over `SCM_RIGHTS` and is installed with seccomp `ADDFD`.
Any broker error is returned as the trapped syscall's errno.

The workspace resolver uses `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`.
Other policy roots additionally use `RESOLVE_NO_SYMLINKS`.
Existing targets are pinned before recording.
Creation uses a pinned parent plus a single basename, and a raced-in final symlink is rejected rather than followed.
The policy identity is the path represented by the pinned dentry under the selected authoritative root, not a claim that an inode has one globally canonical hard-link name.

Two-path authorization is operation-specific.
A rename requires delete on the source and create on the destination, plus delete on an existing replaced destination.
`RENAME_EXCHANGE` requires delete and create on both existing operands.
A hard link requires read on the source and create on the destination.
A symlink's first operand is stored text and is not evaluated as an accessed path; only the created link destination requires create.
Unsupported flags, including `RENAME_WHITEOUT` and unsupported `AT_EMPTY_PATH` forms, fail closed until separately specified and tested.
The trace records independent operand decisions and matched-rule identifiers.

For `connect`, `bind`, and destination-bearing `sendto`, the supervisor opens a pidfd for the trapped process and uses `pidfd_getfd` to duplicate the argument fd.
It passes that duplicate to the confined broker with `SCM_RIGHTS`.
The broker validates that it is a socket and performs the operation against the once-copied `sockaddr`.
This preserves the socket's open file description and removes the fresh-socket replacement and `ADDFD SETFD` path.
The fd-table lookup occurs after the seccomp trap, just as the native syscall's fd lookup would, so a sibling replacement race selects the descriptor present at lookup time without changing the validated destination.

`sendto` payload and flags are copied once before policy evaluation and passed to the broker.
The v1 payload cap is 65,535 bytes, which covers the maximum IPv4 UDP datagram and bounds supervisor memory use.
Larger payloads and unsupported address families fail closed.
UDP port enforcement has no Landlock backstop on the supported ABI range and is stamped as a residual under ADR-0013.

Exact hostname rules are resolved by the supervisor into a short-lived address cache before matching.
IP, CIDR, and `*` rules match directly.
Suffix hostname rules are rejected for enforce mode until a separately designed DNS-observation or proxy mechanism can bind a concrete queried name to the destination address.
Parsing the syntax remains backward compatible, but an unenforceable policy cannot start an enforce run.

An event records the observed attempt and policy decision, not proof that a later broker commit completed.
Recording still precedes every allow response and every broker commit.
If the notification dies after recording but before commit, no side effect occurs and the attempt event remains.
If the broker blocks past the configured operation deadline, Leash kills the broker, aborts the run, and lets the notification fd close fail-closed.
It does not invent a native errno for an operation whose native completion is unknown.

Issue #25 resolves every `ask` decision to deny without opening a terminal.
Issue #30 may reuse the same broker prepare and commit protocol after it adds the interactive state machine.

## Consequences

- Landlock independently constrains both direct child operations and every supervisor-realized filesystem or network effect.
- The broker IPC protocol and lifecycle become security-critical and requires Linux E2E coverage.
- Network fidelity improves because the original socket object is used instead of a fresh approximation.
- `pidfd_getfd` needs the existing Linux 5.19 floor and ptrace permission from the parent supervisor; failure denies the operation.
- Destination-bearing `sendto` has a larger bounded child-memory read than ordinary facts.
- Suffix hostname policies fail before spawn instead of silently under-matching.
- A trace is precise about decisions and attempts but is not an operation-completion journal.
- The single decision loop remains deterministic, while a broker timeout converts indefinite blocking into a fail-closed run abort.

## Alternatives considered

- **Let the supervisor perform effects directly.**
  Rejected because it bypasses the child's Landlock domain.
- **Use a broker thread.**
  Rejected because a blocked filesystem or network operation cannot be safely killed without terminating the supervisor, and forking the agent after creating the thread complicates the child setup boundary.
- **Create a fresh socket and replace the child's fd.**
  Rejected because it loses socket state and cannot faithfully implement `sendto`.
- **Trap and broker every socket creation and fd-table mutation.**
  Rejected because it greatly expands the mediated hot path when duplicating the actual socket preserves the required state.
- **Continue the child syscall after checking its pointer.**
  Rejected because a sibling can rewrite the pointed-to path, address, or payload.
- **Treat suffix rules as matching any IP returned for the bare suffix.**
  Rejected because a wildcard names an unbounded set of hosts and resolving the suffix apex does not represent that set.
