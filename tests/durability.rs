//! durability fault test (trace.md section 4, issue #19): a trace writer killed
//! mid-run must leave a flushed prefix that is intact and parseable. the trace is
//! evidence; it has to survive the failures it documents.
//!
//! the test re-execs this test binary as the victim: with LEASH_TORTURE_DIR set,
//! `torture_child` becomes a writer loop that appends and syncs step events forever;
//! the parent waits for output to accumulate, kills it with sigkill, and audits what
//! survived on disk.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

use leash::recorder::{
    Attendance, EventBody, Mode, RunDir, RunMeta, SnapshotMechanism, TRACE_SCHEMA_VERSION,
};

fn sample_meta() -> RunMeta {
    RunMeta {
        schema_version: TRACE_SCHEMA_VERSION,
        mode: Mode::RecordOnly,
        attendance: Attendance::Unattended,
        policy_digest: None,
        kernel: "test".into(),
        landlock_abi: None,
        snapshot_mechanism: SnapshotMechanism::Copy,
        snapshot_reason: "durability test".into(),
        argv: vec!["torture".into()],
        workspace: "/nonexistent".into(),
        start_ts: 0,
    }
}

/// the victim: loops forever appending and syncing. only active when re-exec'd by
/// `killed_writer_leaves_parseable_prefix` with the env var set.
#[test]
fn torture_child() {
    let Ok(root) = std::env::var("LEASH_TORTURE_DIR") else {
        return; // normal test runs skip; this body only runs re-exec'd
    };
    let dir = RunDir::create(Path::new(&root), &sample_meta(), SystemTime::now()).unwrap();
    let mut writer = dir.trace_writer().unwrap();
    for i in 0.. {
        writer.append(i, EventBody::Step { step: i }).unwrap();
        writer.sync().unwrap();
    }
}

#[test]
fn killed_writer_leaves_parseable_prefix() {
    let root = tempfile::tempdir().unwrap();

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["torture_child", "--exact", "--nocapture"])
        .env("LEASH_TORTURE_DIR", root.path())
        .spawn()
        .unwrap();

    // wait until the victim has demonstrably written events, then kill it mid-loop
    let deadline = Instant::now() + Duration::from_secs(10);
    let trace_path = loop {
        assert!(Instant::now() < deadline, "victim never produced a trace");
        if let Some(run) = std::fs::read_dir(root.path().join("runs"))
            .ok()
            .and_then(|mut d| d.next())
        {
            let p = run.unwrap().path().join("trace.jsonl");
            if std::fs::metadata(&p)
                .map(|m| m.len() > 2048)
                .unwrap_or(false)
            {
                break p;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    child.kill().unwrap();
    child.wait().unwrap();

    // audit the survivors: every terminated line parses, seq is contiguous from 0
    let raw = std::fs::read_to_string(&trace_path).unwrap();
    let complete = match raw.rfind('\n') {
        Some(end) => &raw[..end],
        None => panic!("no complete line survived"),
    };
    let mut expected_seq = 0u64;
    for line in complete.lines() {
        let v: serde_json::Value = serde_json::from_str(line).expect("a flushed line must parse");
        assert_eq!(v["seq"], expected_seq, "seq gap in the flushed prefix");
        assert_eq!(v["type"], "step");
        expected_seq += 1;
    }
    assert!(expected_seq > 0, "at least one event must have survived");
}
