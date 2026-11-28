//! `leash diff` end to end: real snapshot stores under a fake state root, compared by
//! the compiled binary (FR-13, docs/design/cli.md).

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, symlink};
use std::path::Path;
use std::process::{Command, Output};

use leash::snapshot::store::{Limits, capture};

fn open_dir(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .unwrap()
}

/// create a workspace directory. it keeps any default ACL its parent hands down, because
/// capture records ACLs.
fn create_workspace_dir(path: &Path) {
    fs::create_dir(path).unwrap();
}

fn set_mtime(path: &Path, sec: i64) {
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let ts = libc::timespec {
        tv_sec: sec,
        tv_nsec: 0,
    };
    let times = [ts, ts];
    // SAFETY: c_path is NUL-terminated and times points to a valid 2-element array.
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
    assert_eq!(rc, 0, "utimensat: {}", std::io::Error::last_os_error());
}

fn leash(state: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_leash"))
        .arg("diff")
        .args(args)
        .arg("--state-dir")
        .arg(state)
        .output()
        .expect("leash binary must spawn")
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

fn store_dir(state: &Path, run: &str) -> std::path::PathBuf {
    let dir = state.join("runs").join(run).join("snapshots");
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// write the `trace.jsonl` of `run` with one `step` event per committed step, and any raw lines
/// after them. a step is committed when its event is in the trace (ADR-0024 decision 16), not
/// when its manifest exists.
fn write_trace(state: &Path, run: &str, committed: &[u64], extra: &[&str]) {
    let mut lines: Vec<String> = committed
        .iter()
        .enumerate()
        .map(|(seq, step)| format!(r#"{{"seq":{seq},"ts":0,"type":"step","step":{step}}}"#))
        .collect();
    lines.extend(extra.iter().map(|l| (*l).to_string()));
    let dir = state.join("runs").join(run);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("trace.jsonl"), lines.join("\n") + "\n").unwrap();
}

/// run-a: step 0 is the starting tree, step 1 the tree after the agent worked.
/// run-b: one step, identical to run-a step 0 except for one file.
fn fixture(state: &Path, scratch: &Path) {
    let ws = scratch.join("ws");
    create_workspace_dir(&ws);
    fs::write(ws.join("a.txt"), "one").unwrap();
    fs::write(ws.join("b.txt"), "bee").unwrap();
    fs::create_dir(ws.join("d")).unwrap();
    fs::write(ws.join("d/x"), "x").unwrap();
    symlink("a.txt", ws.join("l")).unwrap();
    set_mtime(&ws.join("d"), 1_000_000_000);

    let a = store_dir(state, "run-a");
    capture(&open_dir(&ws), &open_dir(&a), 0, &Limits::default()).unwrap();

    // run-b starts from the same tree with a.txt different
    let b = store_dir(state, "run-b");
    fs::write(ws.join("a.txt"), "uno").unwrap();
    capture(&open_dir(&ws), &open_dir(&b), 0, &Limits::default()).unwrap();
    fs::write(ws.join("a.txt"), "one").unwrap();

    // the agent works: edit, rename, delete, add, retarget a link
    fs::write(ws.join("a.txt"), "two!").unwrap();
    fs::rename(ws.join("b.txt"), ws.join("c.txt")).unwrap();
    fs::remove_file(ws.join("d/x")).unwrap();
    fs::write(ws.join("d/y"), "y").unwrap();
    fs::remove_file(ws.join("l")).unwrap();
    symlink("c.txt", ws.join("l")).unwrap();
    set_mtime(&ws.join("d"), 2_000_000_000);
    capture(&open_dir(&ws), &open_dir(&a), 1, &Limits::default()).unwrap();
    write_trace(state, "run-a", &[0, 1], &[]);
    write_trace(state, "run-b", &[0], &[]);
}

const A_STEP0_TO_STEP1: &str = "\
M  a.txt
R  b.txt -> c.txt
m  d (mtime)
D  d/x
A  d/y
M  l
1 added, 1 removed, 2 modified, 1 renamed, 1 metadata changed
";

#[test]
fn diffs_two_steps_of_one_run() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    fixture(&state, tmp.path());

    let out = leash(&state, &["run-a:0", "run-a:1"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), A_STEP0_TO_STEP1);
    assert_eq!(stderr(&out), "");

    // a missing step means the final committed step
    let out = leash(&state, &["run-a:0", "run-a"]);
    assert_eq!(stdout(&out), A_STEP0_TO_STEP1);

    // the reverse direction swaps added and removed
    let out = leash(&state, &["run-a:1", "run-a:0"]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    assert!(text.contains("D  d/y\n"), "{text}");
    assert!(text.contains("A  d/x\n"), "{text}");
    assert!(text.contains("R  c.txt -> b.txt\n"), "{text}");
}

#[test]
fn run_against_itself_has_no_differences() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    fixture(&state, tmp.path());

    for args in [
        &["run-a", "run-a"][..],
        &["run-a:0", "run-a:0"],
        &["run-b", "run-b"],
    ] {
        let out = leash(&state, args);
        assert_eq!(out.status.code(), Some(0), "{args:?}: {}", stderr(&out));
        assert_eq!(stdout(&out), "no differences\n", "{args:?}");
    }
}

#[test]
fn diffs_two_different_runs() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    fixture(&state, tmp.path());

    // run-b (only step 0) against run-a step 0: only a.txt content differs
    let out = leash(&state, &["run-a:0", "run-b"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "M  a.txt\n1 modified\n");
}

#[test]
fn unknown_run_step_and_missing_snapshots_are_usage_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    fixture(&state, tmp.path());
    // a run directory with no snapshots directory, and one with an empty store
    fs::create_dir_all(state.join("runs/no-snaps")).unwrap();
    fs::create_dir_all(state.join("runs/empty/snapshots")).unwrap();

    for (args, needle) in [
        (&["nope", "run-a"][..], "unknown run 'nope'"),
        (&["run-a", "run-a:9"], "no committed step 9"),
        (&["no-snaps", "run-a"], "run 'no-snaps' has no snapshots"),
        (&["run-a", "empty"], "run 'empty' has no snapshots"),
    ] {
        let out = leash(&state, args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", stderr(&out));
        assert_eq!(stdout(&out), "");
        assert!(stderr(&out).contains(needle), "{args:?}: {}", stderr(&out));
    }

    // a missing state directory is an unknown run
    let out = leash(&tmp.path().join("absent"), &["x", "y"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
}

#[test]
fn bad_run_id_is_a_usage_error_and_never_escapes_the_state_root() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    fixture(&state, tmp.path());
    for bad in ["../x", "a/b", "..", "run-a:x", "run-a:-1"] {
        let out = leash(&state, &[bad, "run-a"]);
        assert_eq!(out.status.code(), Some(2), "{bad}: {}", stderr(&out));
    }
    let out = leash(&state, &["run-a"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn symlinked_run_or_snapshots_directory_is_not_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    fixture(&state, tmp.path());
    symlink(state.join("runs/run-a"), state.join("runs/link-run")).unwrap();
    fs::create_dir_all(state.join("runs/link-snaps")).unwrap();
    symlink(
        state.join("runs/run-a/snapshots"),
        state.join("runs/link-snaps/snapshots"),
    )
    .unwrap();

    let out = leash(&state, &["link-run", "run-a"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).contains("unknown run"), "{}", stderr(&out));
    let out = leash(&state, &["link-snaps", "run-a"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).contains("no snapshots"), "{}", stderr(&out));
}

#[test]
fn corrupt_manifest_fails_with_the_reason() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    fixture(&state, tmp.path());
    let manifest = state.join("runs/run-b/snapshots/manifests/step-000000.json");
    fs::remove_file(&manifest).unwrap();
    fs::write(&manifest, "{ not a manifest").unwrap();

    let out = leash(&state, &["run-a", "run-b"]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    let err = stderr(&out);
    assert!(err.contains("run 'run-b' step 0"), "{err}");
}

/// a manifest newer than the last committed step: published, but its step event never became
/// durable, so the default step of `leash diff` must not be it.
fn plant_orphan(state: &Path, scratch: &Path) {
    let ws = scratch.join("ws");
    fs::write(ws.join("orphan.txt"), "late").unwrap();
    let a = state.join("runs/run-a/snapshots");
    capture(&open_dir(&ws), &open_dir(&a), 2, &Limits::default()).unwrap();
}

#[test]
fn an_orphan_manifest_is_never_the_default_step() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    fixture(&state, tmp.path());
    plant_orphan(&state, tmp.path());

    // the final committed step is 1, although a manifest for step 2 exists
    let out = leash(&state, &["run-a:0", "run-a"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), A_STEP0_TO_STEP1);

    // and the orphan cannot be named either
    let out = leash(&state, &["run-a:0", "run-a:2"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("no committed step 2 (committed: 0, 1)"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_step_event_followed_by_its_own_step_event_failure_is_not_committed() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    fixture(&state, tmp.path());
    // the event for step 1 was written but could not be made durable: the run recorded
    // capture_failed for that step and aborted
    write_trace(
        &state,
        "run-a",
        &[0, 1],
        &[
            r#"{"seq":2,"ts":0,"type":"capture_failed","step":1,"phase":"step_event","error":"sync"}"#,
        ],
    );

    let out = leash(&state, &["run-a:0", "run-a"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "no differences\n", "the default is step 0");
    let out = leash(&state, &["run-a:0", "run-a:1"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("no committed step 1 (committed: 0)"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_run_without_a_trace_has_no_committed_step() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    fixture(&state, tmp.path());
    fs::remove_file(state.join("runs/run-a/trace.jsonl")).unwrap();

    let out = leash(&state, &["run-b", "run-a"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).contains("no trace.jsonl"), "{}", stderr(&out));
}
