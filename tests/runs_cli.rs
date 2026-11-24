//! run management through the compiled command, without a supervised child.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime};

use leash::recorder::{
    Attendance, EventBody, Mode, RunDir, RunMeta, SnapshotMechanism, TRACE_SCHEMA_VERSION,
};

fn fixture(root: &Path, seconds: u64, complete: bool) -> RunDir {
    let meta = RunMeta {
        schema_version: TRACE_SCHEMA_VERSION,
        mode: Mode::RecordOnly,
        attendance: Attendance::Unattended,
        policy_digest: None,
        kernel: "test".into(),
        landlock_abi: None,
        landlock_residuals: None,
        snapshot_mechanism: SnapshotMechanism::Copy,
        snapshot_reason: "test".into(),
        argv: vec!["echo".into(), "hello world".into()],
        workspace: "/workspace".into(),
        start_ts: seconds * 1000,
    };
    let dir = RunDir::create(
        root,
        &meta,
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds),
    )
    .unwrap();
    let mut trace = dir.trace_writer().unwrap();
    trace
        .append(meta.start_ts, EventBody::RunStart(meta))
        .unwrap();
    if complete {
        trace
            .append(
                seconds * 1000 + 1,
                EventBody::RunEnd {
                    exit_code: Some(7),
                    signal: None,
                    final_step: 0,
                },
            )
            .unwrap();
    }
    trace.sync().unwrap();
    dir
}

#[test]
fn lists_recorded_and_damaged_runs_without_skipping_them() {
    let root = tempfile::tempdir().unwrap();
    let complete = fixture(root.path(), 100, true);
    let incomplete = fixture(root.path(), 101, false);
    fs::create_dir(root.path().join("runs/corrupt")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_leash"))
        .args(["runs", "--state-dir"])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let complete_line = stdout
        .lines()
        .find(|line| line.starts_with(&complete.id))
        .unwrap();
    for fact in ["record-only", "100000", "echo", "hello world", "exit 7"] {
        assert!(
            complete_line.contains(fact),
            "missing {fact:?} in {complete_line:?}"
        );
    }
    let incomplete_line = stdout
        .lines()
        .find(|line| line.starts_with(&incomplete.id))
        .unwrap();
    assert!(incomplete_line.contains("incomplete"));
    assert!(
        stdout
            .lines()
            .any(|line| line.starts_with("corrupt\t") && line.contains("corrupt or incomplete"))
    );
}

#[test]
fn prune_refuses_and_leaves_all_run_data_untouched() {
    let root = tempfile::tempdir().unwrap();
    let selected = fixture(root.path(), 100, true);
    let other = fixture(root.path(), 101, true);
    let before = fs::read(selected.path.join("trace.jsonl")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_leash"))
        .args(["runs", "prune", &selected.id, "--state-dir"])
        .arg(root.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&output.stderr).contains("pruning is unavailable"));
    assert_eq!(fs::read(selected.path.join("trace.jsonl")).unwrap(), before);
    assert!(other.path.join("trace.jsonl").is_file());
}
