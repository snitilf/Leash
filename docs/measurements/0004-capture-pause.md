# Measurement 0004: capture pause of `leash run --snapshots`

- Status: measured 2026-11-27 on the codespace Linux host, before and after the store change described in section 4.
- Governs: the provisional `MIN_BOUNDARY_INTERVAL` of one second and the recorded capture pause (ADR-0024 decision 14).
- Cites: ADR-0024 decisions 10 and 14; `design/snapshot.md` sections 1 and 2; `design/trace.md` section 2.

The first version of this document read `capture_pause_us` as milliseconds.
It is microseconds (`pause.as_micros()` in `supervisor/barrier.rs`), so the first numbers were 0.4 to 1.0 seconds, not 0.4 to 1.0 milliseconds, and the conclusion drawn from them was wrong.
This version corrects the unit, records what the time went to, and measures again after the fix.

## 1. Environment

- Kernel `6.8.0-1070-azure`, architecture x86-64 (`x86_64`).
- GitHub Codespace, AMD EPYC 7763 64-Core Processor, 4 vCPUs, 16 GB of memory.
- Root file system is `overlay` on a 32 GB disk, the same file system for the workspace, the state root and the object store.
- `rustc 1.100.0`, release builds (`cargo build --release`).
  "Before" is commit `830b9e1` and "after" is commit `74c19c0`, both with ACL capture.
- The run is unprivileged, inside a delegated cgroup v2 made by `sudo mkdir` plus `chown`, the same shape as the CI cgroup job.

## 2. Method

Each run is `leash run --snapshots --policy <p> --state-dir <s> -- sh -c '<agent>'` through the real binary, in a fresh copy of a clean checkout with no `target/` directory.
No exclusions exist, so the `.git` directory is part of the workspace and is captured.
The policy reads and executes everywhere and writes inside the workspace only.

The agent makes five bursts of edits with `sleep 1.4` between them, which is longer than the 250 ms quiet window plus the one second minimum between boundaries, so every burst closes its own step:

1. Append a line to one source file.
2. Append a line to a second source file and create `scratch.txt`.
3. Append a line to a third source file.
4. Delete `scratch.txt` and rename the third source file to `.bak`.
5. Create a directory with two small files and append another line to the first source file.

The numbers come from the `step` events of `trace.jsonl`: `capture_pause_us` is the time in microseconds that the agent tree was frozen, from the start of the freeze to just before the step event is written.
Step 0 is taken before the agent exists and the last step after the run cgroup was killed, so neither pauses anything and both record a pause of 0.
The four mid-run steps of each run are reported.
Each workspace was run three times, so each cell below is the median of three runs and the range is the lowest and highest of the three.

Two workspaces:

- `leash`: a clean local clone of this repository, 191 files and 86 directories including `.git`, 276 entries and 4,569,977 bytes in the manifest.
- `serde`: a depth-1 clone of `serde-rs/serde`, 376 files and 63 directories including `.git`, 452 entries and 1,663,630 bytes in the manifest.

Every run exited 0, and the entries, bytes and new-object counts of each step were the same in all runs and in both builds.

## 3. Results

Pause per mid-run step, in milliseconds (the raw values are microseconds):

| Workspace | Step | New objects | Before median | Before range | After median | After range |
|---|---|---|---|---|---|---|
| leash | 1 | 1 | 407.8 | 400.6 to 471.6 | 24.9 | 22.6 to 68.1 |
| leash | 2 | 2 | 420.8 | 416.3 to 433.4 | 29.8 | 29.1 to 31.5 |
| leash | 3 | 1 | 414.2 | 410.9 to 438.9 | 27.0 | 23.8 to 73.4 |
| leash | 4 | 0 | 467.4 | 403.9 to 486.8 | 20.3 | 20.0 to 67.4 |
| serde | 1 | 1 | 660.6 | 646.8 to 1,027.7 | 28.1 | 27.2 to 28.6 |
| serde | 2 | 2 | 734.6 | 619.0 to 858.7 | 31.0 | 29.9 to 99.3 |
| serde | 3 | 1 | 648.7 | 629.3 to 691.4 | 27.0 | 26.4 to 28.7 |
| serde | 4 | 0 | 668.8 | 651.8 to 889.3 | 24.4 | 24.3 to 91.9 |

Over the twelve mid-run pauses of each workspace the median was 418.6 ms before and 28.0 ms after for `leash`, and 664.7 ms before and 28.3 ms after for `serde`.
The highest single pause was 1,027.7 ms before and 99.3 ms after.

## 4. What the time went to, and the change

Before the change, every step re-captured every regular file by copying it into a staging file, calling `fsync` on that file, hashing it, and only then looking for an object with the same digest in the store.
When the object was already there, which is nearly every file on every step after the first, the staged copy was deleted again.
So each mid-run step paid one `fsync` per file, 276 or 452 of them, to store nothing.
The pause tracked the number of entries (0.4 s for 276, 0.66 s for 452), which is what a per-file `fsync` predicts.

The change reads each file once to hash it and looks for the object first.
An object that exists is not staged, written or synced.
Only a new object is read a second time into a staging file, and the copy must hash to the same digest and leave the file unchanged, or the capture is refused.
A new object is still synced, renamed into place, and its bucket directory is still synced before the manifest is published, so the manifest is published only after its objects are durable (ADR-0024 decision 10).
Exactness is unchanged: every byte is still read and hashed on every step, and the manifest and its digest are the same bytes as before.
Tests cover an unchanged object being left alone, a lost object being stored again before the next manifest names it, and a capture that fails after storing objects publishing nothing and the retry having every object.

The remaining 20 to 30 ms per step was not profiled further.
It is consistent with reading and hashing every file again on each step plus the two syncs of the manifest and its directory, but that split was not measured.

## 5. Conclusion

Before the change, a mid-run capture froze the agent for 0.4 to 1.0 s, with a worst case just over one second, for workspaces of 276 to 452 entries and 1.7 to 4.6 MB.
That is the same size as the one second minimum between boundaries (ADR-0024 decision 14), so a busy agent could be frozen for about as long as it ran between steps, roughly a third of its wall time.
That was a performance defect, not a property to accept, and the store change above removes most of it.
After the change a mid-run capture froze the agent for a median of 28 ms, with a worst case of 99 ms in 24 pauses, about 3 percent of the one second minimum interval at the median and 10 percent at the worst case seen.
The minimum interval therefore bounds the cost: an agent that mutates continuously is frozen for roughly 3 percent of its wall time on these workspaces.
The one second value can stay provisional, and it should be revisited once a measurement on a workspace of tens of thousands of entries exists, because the pause still grows with the number of files that are read and hashed each step.
This measurement does not cover such workspaces, gigabytes of content, a cold page cache, or a slower disk, and three runs per workspace do not bound the tail.
