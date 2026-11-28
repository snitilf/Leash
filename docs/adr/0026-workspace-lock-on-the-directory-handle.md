# ADR-0026: The workspace lock is also taken on the workspace directory handle

- Status: accepted
- Date: 2026-11-27
- Tier: 2
- Refines: ADR-0024 decision 13

## Context

ADR-0024 decision 13 says a run takes an exclusive workspace lock, an `flock` under the state root.
The lock file is named by the sha256 of the canonical workspace path, so it lives under the state root the operator chose.
Two runs on one workspace with different `--state-dir` values lock two different files, and both proceed.
They then capture and mutate one tree at the same time, and a rewind under one state directory can run while a run under another is live.
This was reproduced: the second run started and finished while the first held its lock.

The canonical path was also resolved twice, once by `canonicalize` when the lock was taken and again when capture opened the workspace by path.
A path can name a different directory between the two.

## Decision

1. A run and a rewind also take `flock(LOCK_EX | LOCK_NB)` on the workspace directory itself, through a handle opened once.
   The lock is keyed by the directory inode, so it does not depend on the state root or on how the path is spelled.
2. The handle is opened once, before anything is created under the state root, and the directory lock is taken on it first.
   The lock file name under the state root comes from the canonical path of that handle, read from `/proc/self/fd`, so no path is resolved a second time.
3. Capture reuses the same handle through a duplicate, so the locked directory is the captured directory, and both are held for the whole run.
4. `WorkspaceLock::acquire` takes both locks and is the helper `leash rewind` uses.
   It refuses when either lock is held.
5. The lock file under the state root stays.
   It costs nothing, keeps the lock inspectable under the state root, and a failure of either lock refuses the run.

## Consequences

- A leftover process that holds the `flock` on the workspace directory blocks later runs and rewinds on it.
  That fails closed.
  Examples are a stray process that inherited the descriptor, or an operator's `flock(1)` on the directory.
  The agent's own processes are killed with the run cgroup, so they cannot outlive the run holding it.
- The lock is advisory.
  A process that does not call `flock` is not excluded, and external writers stay the operator contract of ADR-0022.
- A filesystem that does not support `flock` on a directory refuses the run with an I/O error, which is fail-closed.
  This was not exercised beyond the local filesystems of the test hosts.
- The agent can open the workspace directory and call `flock` on its own descriptor while it runs.
  That contends with the supervisor's lock and is refused for the agent.
  It changes nothing for the run.

## Alternatives considered

- A lock file in a fixed per-user location keyed by path: it depends on the environment (`HOME`, `XDG_*`), so a different environment bypasses it the same way.
- Keep resolving the path twice: leaves the window between `canonicalize` and the open.
- An `fcntl` lock on a file inside the workspace: it writes into the captured tree and is visible to the agent.
