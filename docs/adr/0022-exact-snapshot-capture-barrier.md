# ADR-0022: Exact snapshots require exclusive ownership and a capture barrier

- Status: accepted; partly superseded by ADR-0024 (mode scope, protected-storage prerequisite, historical-read authorization).
  The capture barrier and supported state still apply.
- Date: 2026-11-01
- Change-control tier: 3

## Context

ADR-0009 selected overlayfs with a copy fallback, but neither copying a live tree nor
copying an overlay upper layer establishes a point-in-time snapshot. Writes through
already-open descriptors and shared mappings continue without mediated path events.
The single-threaded notify loop does not stop those writers. The M0 spike established
basic mechanism behavior, not concurrent capture correctness.

## Decision

This ADR refines ADR-0009: both backends require the same consistency barrier. The
copy backend is the initial implementation target; overlay remains unavailable until
its complete lifecycle and equivalent observable behavior pass validation.

Exactness is conditional on exclusive workspace ownership during run and rewind.
The operator must stop external writers, including editor autosave, build daemons,
shared mappings and writes through hard-link aliases. A Leash lock excludes other
Leash operations only. External-writer exclusion is an operator contract, not an
enforced or reliably detectable security control.

Snapshot-enabled runs require a usable delegated cgroup v2 with a verified freezer
and whole-tree termination path. Unavailable support causes refusal before spawn;
there is no unfrozen-copy or process-enumeration fallback. The child enters the run
cgroup before untrusted execution and cannot migrate out or alter its controls.
The supervisor remains outside it. These integrity restrictions apply in both modes,
without turning record-only into general policy enforcement. In both modes, the
same-uid child must also be unable to mutate retained baselines, staging captures,
committed snapshots or the metadata authorizing them. Restrictive same-uid permissions
alone are not protection. The protection mechanism and escape tests are prerequisites;
until established, exact snapshots remain disabled rather than claiming integrity.


### Protected storage direction (unimplemented)

Use a small custodian under a distinct host UID for canonical snapshot storage and
its authoritative manifests. Provisioning must supply an inaccessible-to-agent store
and a private control channel for the trusted supervisor. Exact snapshots refuse
before spawn if provisioning or its protection probes fail. The agent continues under
the operator UID; the custodian is not a privileged agent launcher.

Create the private control socketpair before untrusted execution. Do not authorize
custodian mutation requests solely by the operator UID: the agent shares it. Make the
supervisor non-dumpable, close every sensitive child-inherited descriptor, check stdio,
and drop child capabilities with no_new_privs. The custodian must never return writable
canonical-storage handles. Requests use validated run identities and pinned workspace
handles, not arbitrary privileged paths. Canonical state stays protected between runs;
operator-owned exports and discovery indexes are not authoritative. Provisioning must
also protect storage ancestors against replacement or deletion. This is a design
direction, not a claim that the service or its authentication protocol exists.

Landlock alone is insufficient: positive ancestor grants cannot express an arbitrary
subtree exception, ABI 2 lacks truncate control, metadata operations remain outside
its protection, and existing or transferred descriptors retain access. A namespace-only
alternative is not selected: mapping the operator UID into a new user namespace does
not create a distinct host owner, and hiding a mount does not remove other aliases or
handles to persistent storage. Private temporary mounts could isolate transient data,
but do not alone protect durable state across runs. A mapped subordinate host UID
requires separately provisioned UID delegation and remains a custodian variant.

The additional gate covers direct and metadata mutation, ancestor replacement, hard-link
aliases, proc/ptrace access, inherited and transferred descriptors, forged custodian
requests, capabilities, daemon failure and later-run tampering. Ordinary record-only
access outside protected resources must remain available. Test on the Linux floor and
with Landlock unavailable; either custody protects storage independently or exact
snapshots refuse. Custodian failure never authorizes an incomplete capture.


### Custodian activation gates

The custodian direction must not be implemented as a public same-UID storage service.
A socketpair protects an already established channel, not its bootstrap. The operator
and agent share a UID, so UID credentials cannot distinguish them. Before activation,
select and review independent bootstrap authorization that the child cannot obtain,
forge or delegate through an unsandboxed service. No concrete credential mechanism is
selected here. A setuid launcher plus child no_new_privs is not sufficient by itself
when the child can ask an existing unconfined service to launch that helper.

An authorized bootstrap creates a fresh unpredictable run identity and a private,
nontransferable-in-protocol capability scoped to that run and its permitted operations.
It cannot select or overwrite an existing run. Custodian authentication binds the
channel, run identity and generation; request-supplied UID, PID or run name is not
proof of authority. Finalization revokes all write capabilities and makes canonical
history immutable to ordinary run clients. New runs cannot mutate prior runs.

Historical reads, exports, rewind sources and pruning require independent authorization
outside the child authority. Until that authorization is selected and validated, these
operations are unavailable. There is no public same-UID history API, including a
read-only one. Discovery indexes must not expose protected content or grant authority.
Prune is a separate administrative capability; an active-run capability never grants
it. Export destinations outside protected storage become ordinary operator-controlled
data and cannot be treated as canonical history or silently exposed to a running child.

The lifecycle protocol must revoke capabilities on supervisor death, disconnect or
custodian restart. It must not automatically reattach a client by UID or claimed PID.
An independently alive trusted lifecycle monitor must own the authority to terminate
the run cgroup when the supervisor dies; the storage UID alone does not confer that
authority. Provisioning must establish and test this bounded termination authority.
On lost control, terminate the whole cgroup, mark the run incomplete, and quarantine
uncommitted staging. Do not resume the child or commit a successful final boundary.
A custodian crash requires the surviving supervisor/lifecycle monitor to terminate
the run. Recovery preserves committed history, rejects old capability generations,
and retains quarantined staging for authorized inspection or pruning; retention is
not automatic deletion (FR-21).

A separate storage UID also does not grant workspace read access or arbitrary chown
rights. The import/restore protocol must be selected and reviewed before activation.
Prefer an unprivileged supervisor streaming a bounded manifest and file data under
its ordinary workspace permissions; store source ownership as semantic metadata,
not by chowning canonical files to the agent UID. Reject unreadable source objects and
unsupported ownership or metadata explicitly. Validate entry counts, sizes, names,
object types, link topology and run association; never accept arbitrary privileged
host paths. Restores and exports must use the operator's ordinary permissions or a
separately authorized bounded restore operation. The custodian must not become a
same-UID-requested privileged filesystem deputy. No blanket privileged copy/chown
operation is authorized by this ADR.

Activation tests include forged bootstrap, replayed/revoked capabilities, unrelated
same-UID clients, indirect helper launch through unconfined services, historical read
and export attempts, prune attempts, channel loss, service restart, supervisor death,
whole-cgroup termination, quarantined staging, unreadable inputs, unsupported ownership,
manifest traversal and resource-limit violations. These are required design gates,
not a claim that authentication, lifecycle or import/restore is implemented or settled.

### Capture protocol

At a boundary, stop dispatching broker mutations, complete outstanding broker work,
request freeze and wait boundedly for `cgroup.events` to report `frozen=1`. Capture
only after this barrier succeeds. Unsupported asynchronous mutation paths, including
legacy AIO submission, must be denied or demonstrably drained; the freezer alone
is not an I/O-completion barrier. Publish a durable staged snapshot before recording
a successful step, then thaw. Any barrier, capture, publication or thaw failure
aborts the run closed and terminates the whole cgroup. Do not publish a successful
boundary for an incomplete capture. Initial capture precedes spawn; final capture
requires the entire run cgroup to be empty, including descendants.

A snapshot preserves names, regular-file bytes, symlink targets, directory structure,
hard-link topology within the workspace, modes, ownership, modification timestamps,
and supported extended attributes/ACLs. Unsupported objects or metadata cause
explicit refusal, never silent omission. Raw inode numbers, ctime, access times,
open descriptors, process state and application-level transaction consistency are
outside the exactness contract. Captures are filesystem states, not application
checkpoints. Rewind is offline and requires exclusive ownership too.

Overlay snapshots must retain an immutable baseline sufficient to reconstruct the
historical visible tree after the original workspace changes. No mounted lower or
upper tree may be modified directly. Rewind must release the live mount and its
references before restoration. Overlay options and metadata must preserve the same
supported snapshot semantics as copy; upper-layer size is cumulative changed state,
not necessarily the latest step's delta.

## Consequences

The operator contract trades unrestricted concurrent workspace editing for a bounded,
testable exactness claim. No security invariant is relaxed: failures remain closed,
and I5 still requires passing bypass tests before an enforcement claim. Some hosts
can record events but cannot meet the prerequisites for exact snapshots. Freeze
pauses may be proportional to workspace size with copy. Snapshot metadata must state
the consistency contract and backend; existing captures must not be relabeled exact.

The 250 ms step window is a heuristic over mediated events, not evidence that all
writes stopped. Linux tests must cover persistent-fd writers, shared mappings,
forking descendants, cgroup escape, asynchronous writes, freeze timeouts, failed
publication and whole-tree shutdown before exactness is claimed.

## Alternatives considered

- Live copy or before/after hashes: neither proves a common point-in-time state.
- SIGSTOP with process enumeration: races with process creation and misses descendants.
- Mandatory private workspace copies: stronger separation from ordinary external edits,
  but changes workspace/publication semantics and still needs consistent initial import.
- Overlay-only: does not solve writer quiescence and excludes otherwise usable hosts.

## References

- [Linux cgroup v2 freezer and termination interfaces](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [Landlock rights and descriptor limitations](https://docs.kernel.org/userspace-api/landlock.html)
- [Linux user namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [OverlayFS layer mutation restrictions and filesystem semantics](https://docs.kernel.org/filesystems/overlayfs.html)
