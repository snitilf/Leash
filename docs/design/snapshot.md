# Snapshots, rewind, and diff

- Status: architecture revised 2026-11-01 by ADR-0022; exact-capture implementation and
  adversarial validation pending. The historical M0 results below do not prove concurrent
  capture correctness.
- Governs: FR-11, FR-12, FR-13, FR-17, FR-21; ADR-0005, ADR-0009, ADR-0022.

## 1. Consistency contract and step detection

Exactness requires exclusive workspace ownership throughout run and rewind. External
writers, including editors, build daemons, shared mappings and hard-link aliases, must
be stopped by the operator. The Leash workspace lock excludes other Leash operations;
it does not enforce or reliably detect external-writer exclusion.

A step is derived from mediated mutating events. The coalescing window remains 250 ms,
chosen from the M1 measurements in `../measurements/0001-m1-overhead.md`; confirmation
against a real agent session remains pending. Event quiescence proposes a boundary,
not proof of filesystem quiescence. Writes through existing descriptors and shared
mappings do not necessarily tick this clock. The barrier below makes captures exact
within ADR-0022's supported filesystem state, regardless of those timing gaps. It does
not make an application transaction atomic. Initial and final snapshots are mandatory.

## 2. Capture barrier

Before spawn, verify delegated cgroup v2, usable freezer completion, whole-tree
termination, and protection against child migration or control-plane modification.
Both modes must protect baselines, staged and committed snapshots, and their authoritative
metadata from same-uid child mutation; permissions alone do not suffice. These controls
and their escape tests are prerequisites to enabling exact snapshots.
Place the child in the run cgroup before untrusted execution; keep the supervisor
outside. Descendants inherit membership. Snapshot-enabled runs refuse if these
prerequisites are unavailable, in both modes. Process enumeration and SIGSTOP are not
substitutes for this barrier.

At a candidate boundary:

1. Stop dispatching broker mutations and finish outstanding broker operations.
2. Request `cgroup.freeze=1` and wait boundedly for `cgroup.events` `frozen=1`.
3. Establish that no supported asynchronous mutation remains outstanding. Deny
   unsupported submission paths, including legacy AIO, or prove a completion barrier;
   stopping userspace tasks alone does not establish this.
4. Capture into a staging location, preserving all supported content and metadata.
5. Durably publish the snapshot, then durably record its successful step event.
6. Thaw and resume dispatch.

A barrier, capture, publication or thaw error aborts the run closed and terminates its
whole cgroup. Incomplete captures must never appear as successful steps. Recovery
ignores unpublished staging data; a published snapshot without a committed step is
an orphan, not a successful boundary. Initial capture precedes spawn. Final capture
waits for the entire run cgroup to become empty, not merely the initial child to exit.

## 3. Copy backend and supported state

Copy is the initial backend. It uses the same barrier as overlay and may pause the
agent for time proportional to workspace size. The fallback is a storage choice,
never weaker consistency. Snapshot metadata records the mechanism and consistency
contract; historical live copies must not be relabeled exact.

ADR-0022 defines supported state: names, file bytes, symlink targets, directories,
within-workspace hard-link topology, modes, ownership, modification timestamps and
supported xattrs/ACLs. Unsupported objects or metadata fail explicitly. Raw inode
numbers, ctime, access times, open descriptors and process state are excluded. A copy
must not silently skip an unreadable entry or unsupported metadata.


### Protected storage prerequisite

ADR-0022 selects a separately provisioned custodian under a distinct host UID as the
design direction for canonical baselines, snapshots and authoritative manifests. It
is unimplemented. Exact snapshots refuse before spawn until provisioning, authenticated
private control, storage-ancestor protection and adversarial tests succeed. The agent
keeps the operator UID. Operator-owned exports and discovery indexes are not canonical
state, and a later run must not be able to corrupt earlier retained captures.

The supervisor retains a private control capability, becomes non-dumpable, and leaks
no storage or control descriptor through child inheritance or stdio. Custodian requests
are validated against pinned run/workspace handles; no writable canonical handles are
returned. UID-only authorization is insufficient because the child shares the operator
UID. Namespace-only hiding and a policy-independent Landlock ruleset are not substitutes
for this complete storage boundary. Required tests include proc/ptrace access, metadata
and ancestor mutations, inherited/transferred handles, forged requests, service failure,
and cross-run corruption attempts, while ordinary record-only access remains available.


Custodian activation additionally requires the bootstrap authorization, capability
revocation, independent cgroup-termination monitor, staging recovery and bounded
import/restore gates in ADR-0022. Their concrete authentication and privilege protocol
is not selected. No cross-run history read, export, rewind source or prune is available
until independent authorization outside the child's authority is validated. Same-UID
read-only access is not a safe fallback. A socketpair does not authenticate bootstrap,
and no_new_privs alone does not prevent indirect launch through unconfined services.

## 4. Overlay backend

ADR-0009 remains the intended optimized backend, gated on complete lifecycle and
copy-equivalence validation. Historical mount-spike success does not enable it.
The live lower tree must not change; snapshots retain an immutable baseline sufficient
to reconstruct old visible states independently of the original workspace. Upper-layer
captures preserve cumulative changed state, not necessarily only the latest delta.

Whiteouts may be device nodes or xattr-marked files. Opaque directories, redirects,
copy-up and hard-link topology require explicit interpretation. Mount options must be
chosen and tested for the supported semantics: disabling inode indexing can break
lower-layer hard links during copy-up. Neither lower nor upper storage may be directly
modified while mounted. Capturing a layer still requires the section 2 barrier.

## 5. Rewind and diff

Rewind requires an ended run, exclusive workspace ownership, and no live overlay mount
or remaining references that could mutate the restored state. Restore the selected
supported state; never replace a mounted upperdir. Failures must be explicit, with
recoverable staging and the prior state retained until restoration can be committed.
Rewind reverses filesystem effects only, not effects already emitted off-host.

Diff compares reconstructed visible states. Whiteouts mean deletion, opaque directories
replace hidden lower entries, recoverable rename relations are reported, and hard links
are treated as shared objects. Copy and overlay must produce equivalent results over
their supported state, backed by the same fixtures and behavioral cases.

## 6. Validation and fault surface

Before any exactness claim, Linux tests must cover continuous existing-fd writes,
shared mappings, concurrent rename and hard-link activity, forking descendants,
cgroup escape attempts, unsupported asynchronous I/O, freezer timeout, capture and
publication failure, and descendants surviving their initial parent. Restore and diff
must preserve the full supported state. Tests run against each enabled backend.

The 2 GiB default configurable upper-layer limit from ADR-0009 remains a requirement
for overlay; polling size is not proof of a hard bound. Capacity enforcement and
capture-storage exhaustion need explicit fail-closed tests before a bounded-storage
claim. No backend may publish partial state on ENOSPC.

## 7. The M0 spike checklist

This section doubles as the acceptance criteria of the ADR-0009 validation spike (issue #13). The
spike was run by the operator on the x86-64 reference target, a KVM VPS (FR-15); the ARM64 leg was
cancelled when that target was deferred (ADR-0014, spec OQ-9). On the target:

- [ ] overlay mount of a workspace via privileged mount
- [ ] overlay mount via an unprivileged user namespace
- [ ] upper-layer capture at a boundary while the mount is live
- [ ] rewind to an earlier snapshot restores the workspace exactly
- [ ] whiteout handling: a deletion reads as a deletion, in capture, rewind, and diff
- [ ] cross-directory rename handling: copy-up plus whiteout is interpreted correctly
- [ ] hard-link handling: linked names are attributed to one inode
- [ ] the copy fallback, on a host (or configuration) where overlay is unavailable, produces
      identical observable rewind and diff behavior

The gate, as narrowed by ADR-0014: all items pass on the x86-64 target, with the
unprivileged-userns item accepted as a documented host-class limitation where the host blocks
unprivileged user namespaces outright; with that met, this file settles and the design layer can
freeze. A failure would have superseded ADR-0009 rather than quietly bending it, with this file
rewritten around the surviving mechanism.

### Spike results

x86-64 leg, Ubuntu 24.04.4 / kernel 6.8, 2026-07-08: every privileged-path item passed, mount with
upper-only writes over an untouched lower, capture, exact rewind, whiteout recorded as a char device
0/0, cross-directory rename as copy-up plus whiteout, hard link resolving to one inode, and
copy-fallback equivalence. The unprivileged-user-namespace item did not run: the host blocks
unprivileged userns via `apparmor_restrict_unprivileged_userns=1` (section 3), so on that class of
host the privileged mount or the copy fallback carries the mechanism; the skip is accepted as a
host-class limitation, not a failure (ADR-0014). The overlay mechanism holds on x86-64; no
supersede is warranted. The ARM64 leg was cancelled with the target deferral (ADR-0014, spec OQ-9);
the same spike script runs unchanged if OQ-9 ever reopens the target. With the narrowed gate met,
this file is settled.
