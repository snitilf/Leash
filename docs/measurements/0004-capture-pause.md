# Measurement 0004: capture pause of `leash run --snapshots`

- Status: measured 2026-11-27 on the codespace Linux host.
- Governs: the provisional `MIN_BOUNDARY_INTERVAL` of one second (ADR-0024 decision 14) and the claim that a mid-run capture is short for a repository-sized workspace.
- Cites: ADR-0024; `design/snapshot.md` sections 1 and 2; `design/trace.md` section 2.

## 1. Environment

- Kernel `6.8.0-1070-azure`, architecture x86-64 (`x86_64`).
- GitHub Codespace, AMD EPYC 7763 64-Core Processor, 4 vCPUs, 16 GB of memory.
- Root file system is `overlay` on a 32 GB disk, the same file system for the workspace, the state root and the object store.
- `rustc 1.100.0`, release build (`cargo build --release`) of commit `e421301`.
  The later commits on the branch change tests and this document only.
- The run is unprivileged, inside a delegated cgroup v2 made by `sudo mkdir` plus `chown`, the same shape as the CI cgroup job.
- Landlock ABI and the cgroup freezer are the ones the host provides; no setting was changed for the measurement.

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

The numbers come from the `step` events of `trace.jsonl`: `capture_pause_us` is the time the agent tree was frozen, from the start of the freeze to just before the step event is written.
`entries`, `bytes` and `new_objects` are the capture statistics in the same event.
Step 0 is taken before the agent exists and the last step after the run cgroup was killed, so neither pauses anything and both record a pause of 0.
Each workspace was run three times; the table gives the median and the range of the three.

Two workspaces:

- `leash`: a clean local clone of this repository, 191 files and 86 directories including `.git`.
- `serde`: a depth-1 clone of `serde-rs/serde`, 376 files and 63 directories including `.git`.

## 3. Results

`leash` workspace (276 entries and 4,569,977 bytes at step 0, 189 objects stored by step 0):

| Step | Entries | Bytes | New objects | Pause median (us) | Pause range (us) |
|---|---|---|---|---|---|
| 0 | 276 | 4,569,977 | 189 | 0 | 0 |
| 1 | 276 | 4,569,988 | 1 | 553,890 | 486,669 to 729,669 |
| 2 | 277 | 4,570,007 | 2 | 783,895 | 422,204 to 1,181,059 |
| 3 | 277 | 4,570,018 | 1 | 585,448 | 558,041 to 634,442 |
| 4 | 276 | 4,570,010 | 0 | 485,709 | 405,457 to 607,096 |
| 5 (final) | 279 | 4,570,025 | 3 | 0 | 0 |

`serde` workspace (452 entries and 1,663,630 bytes at step 0, 371 objects stored by step 0):

| Step | Entries | Bytes | New objects | Pause median (us) | Pause range (us) |
|---|---|---|---|---|---|
| 0 | 452 | 1,663,630 | 371 | 0 | 0 |
| 1 | 452 | 1,663,641 | 1 | 836,277 | 738,466 to 3,282,080 |
| 2 | 453 | 1,663,660 | 2 | 889,744 | 683,441 to 10,515,773 |
| 3 | 453 | 1,663,671 | 1 | 781,270 | 648,454 to 1,031,581 |
| 4 | 452 | 1,663,663 | 0 | 1,252,548 | 694,189 to 7,588,999 |
| 5 (final) | 455 | 1,663,678 | 3 | 0 | 0 |

Every run exited 0, and every step in the table had the same entries, bytes and new-object counts in all three runs.

## 4. Conclusion

For a workspace of a few hundred entries and a few megabytes, a mid-run capture froze the agent for about 0.4 to 1.3 ms in the typical case.
The pause followed the entry count more than the byte count: the serde workspace (452 entries, 1.7 MB) paused about one and a half times as long as the leash workspace (276 entries, 4.6 MB).
That fits the statistics, because each step stored only zero to three new objects whatever the workspace size, so changed content was not what the time went to.
Three of the 24 mid-run pauses (all in one run on the serde workspace) took 3.3 to 10.5 ms, so the tail is an order of magnitude above the median on this shared host, and three runs per workspace do not bound it.
Every pause is far below the one second minimum between boundaries, so the minimum interval, not the pause, limits how often the agent is frozen, and the provisional value stays.
The measurement says nothing about workspaces of tens of thousands of entries, about gigabytes of content, or about a cold page cache, and the capture caps in the store (`DEFAULT_MAX_ENTRIES`, `DEFAULT_MAX_TOTAL_BYTES`) remain untested against pauses of that size.
