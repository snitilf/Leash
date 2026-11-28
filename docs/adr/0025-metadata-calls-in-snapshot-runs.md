# ADR-0025: Metadata calls in snapshot runs

- Status: accepted
- Date: 2026-11-27
- Tier: 3 (enforcement path of a snapshot run; changes a residual that ADR-0024 accepted)
- Refines: ADR-0024 (the metadata-only residual, and the path of decision 4)

## Context

ADR-0024 leaves the metadata-only calls (`fchmodat2`, `utimensat`, the xattr calls) unmediated and outside Landlock, and names them a residual that can deny a rewind but cannot forge one.
Landlock has no right for `chmod`, `chown`, extended attributes or timestamps, so on a cgroup2 mount nothing but the supervisor can keep the agent from changing the run cgroup's metadata.
The `user.leash.lock` attribute of the run cgroup is the marker that tells the next run's stale-cgroup cleanup which cgroups it may kill.
An agent that could set or remove it, or change the mode of a control file, would be changing the supervisor's own bookkeeping, which is more than a noisy rewind.
The same calls on the state root are the lesser case that ADR-0024 already accepted.

A snapshot run therefore cannot leave these calls unmediated.
The calls come in three shapes, and each needs its own answer.
Some name a path, and the path can be re-resolved by the kernel after the supervisor judged it.
Some name an open descriptor, whose object is already fixed.
Some are newer than any C library, so nothing legitimate calls them yet, and their numbers are not in the filter unless someone lists them.

## Decision

1. In a `--snapshots` run the seccomp filter also traps `setxattr`, `lsetxattr`, `removexattr`, `lremovexattr`, `utime`, `utimes`, `futimesat`, `utimensat`, `fchmodat2` and `lchown`.
   Each is decided as a **write** to the resolved path, after `implicit:state_root` and `implicit:cgroup` and then by policy, the same as `chmod`.
   An allow is realized by the broker on the handle it pinned before the decision, never by `CONTINUE`, so the object that was judged is the object that is changed.
   The legacy time calls are converted to one `utimensat` on the handle.
2. `setxattrat` (463), `removexattrat` (466, Linux 6.13) and `file_setattr` (469, Linux 6.17) are trapped in the same runs and answered `ENOSYS`, recorded as `snapshot:xattrat`.
   No C library calls them yet, so refusing them costs nothing today.
   A later ADR may mediate them like their older siblings.
   The numbers are checked against `arch/x86/entry/syscalls/syscall_64.tbl` and pinned in the filter tests.
3. `fchmod`, `fchown`, `fsetxattr`, `fremovexattr` and the descriptor forms of `utimensat` and `futimesat` (a null path, which is `futimens` and `futimes`) are judged on the descriptor's target, read from `/proc/<pid>/fd/<n>`, as a write to that path, and then continued.
   The object is the descriptor's, fixed when the agent opened it, and the only pointer left in the call is a timestamp or value the agent owns.
   The supervisor also duplicates the descriptor with `pidfd_getfd`, reads its filesystem type and `(st_dev, st_ino)`, and closes the duplicate: an object on cgroup2 or the state root directory is denied whatever path the link spells, and a descriptor that cannot be duplicated is denied.
4. `utimensat` and `fchmodat2` with `AT_EMPTY_PATH` and an empty path act on the object of their directory descriptor, as the kernel does.
   They are realized by the broker on the descriptor's target path, not continued, because the empty string lives in agent memory and could be rewritten before the kernel read it.
5. A call whose own arguments the kernel would refuse before it looked at any path, such as an unknown flag or an xattr value over 65536 bytes, is answered with that errno and recorded as `failsafe:unsupported_operand`.
   It is not a failed memory read and is not answered `EACCES`.
6. Policy governs these calls as writes in snapshot runs.
   Outside snapshot runs they stay unmediated, and the filter is unchanged byte for byte.

## Consequences

The calls that name a path are as safe as `chmod` already is: the broker holds the object, the decision is on its resolved identity, and a symlink that leads into the state root or a cgroup2 mount is judged where it lands.
`lsetxattr` and `lremovexattr` on a symlink cannot be realized, because a symlink cannot be reached through its proc link without being followed.
A `user.` name gets `EPERM`, which is what the kernel answers for that namespace on a symlink.
Another namespace gets `EOPNOTSUPP`.

The descriptor forms keep one residual.
A sibling thread can `dup2` another descriptor onto `<n>` between the supervisor's read of `/proc/<pid>/fd/<n>`, its duplicate of the descriptor, and the `CONTINUE`.
The judged object and the acted-on object can then differ.
The residual is bounded by what the agent can hold: no descriptor on a protected file can be opened from inside the tree, because the open is denied, so the only descriptors the agent can swap in are on files it may already write.
A descriptor on a protected file could still arrive through `open_tree`, which yields an `O_PATH` descriptor that these calls refuse with `EBADF` (unverified on Linux 6.13 and later), or through an out-of-tree helper that passes one over a socket.
That helper is the fourth residual of ADR-0024.

An anonymous target is judged as a path.
A descriptor on a pipe, a socket or a deleted memfd reads back as `pipe:[N]`, `socket:[N]` or `/memfd:name (deleted)`, which policy usually does not allow, so `fchmod` or `fsetxattr` on one is usually denied.
That is a compatibility cost, and a rare one.

Policy authors who allow writes in a workspace need no change.
A policy that never allowed a path now also governs that path's timestamps, modes, owners and attributes in a snapshot run.

## Alternatives considered

- Leave the calls unmediated and keep the ADR-0024 residual: refused, because the run cgroup's lock attribute is the supervisor's own state, and the overlap refusal cannot cover it since Landlock has no right to grant or withhold.
- Continue the path forms after judging a pointer read: the path lives in agent memory and can change before the kernel reads it, so the judged path and the changed object can differ.
- Realize the descriptor forms in the broker: the broker does not hold the agent's descriptors, and passing each one would add a descriptor transfer to a call that is already bound to its object.
- Deny the descriptor forms outright: breaks `futimens`, `fchmod` and `fchown`, which `tar`, `cp -a`, `rsync` and every package manager call on files they just wrote.
- Mediate `setxattrat`, `removexattrat` and `file_setattr` now: nothing calls them, so the mediation could not be tested against a real caller, and refusing them is the smaller surface.
