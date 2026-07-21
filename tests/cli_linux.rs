//! behavioral tests for `leash run` end to end (docs/design/cli.md; FR-5, FR-19, FR-20,
//! FR-21, FR-22; issue #20).
//!
//! these run only on linux and drive the real compiled binary via CARGO_BIN_EXE_leash:
//! the whole spine (preflight, run dir, lifecycle events, spawn, notify loop, report) is
//! exercised as an operator would. the agent under test is /bin/sh -c, so the fork
//! happens inside the leash process, not this harness: no re-exec dispatch and no spawn
//! lock are needed here. every spawned leash process is watched by a deadline poll that
//! SIGKILLs it so a wedged run cannot hang CI.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(15);

fn leash_exe() -> &'static str {
    env!("CARGO_BIN_EXE_leash")
}

/// run the leash binary with a deadline; SIGKILL it if it outlives the budget.
fn run_leash(args: &[&str], cwd: &Path) -> Output {
    let mut child: Child = Command::new(leash_exe())
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("leash binary must spawn");
    let start = Instant::now();
    loop {
        match child.try_wait().expect("try_wait") {
            Some(_) => return child.wait_with_output().expect("wait_with_output"),
            None if start.elapsed() > DEADLINE => {
                let _ = child.kill();
                let out = child.wait_with_output().expect("wait_with_output");
                panic!(
                    "leash exceeded the deadline; stderr so far: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    }
}

/// the single run directory produced under `<state>/runs/`.
fn only_run_dir(state: &Path) -> PathBuf {
    let runs: Vec<_> = std::fs::read_dir(state.join("runs"))
        .expect("runs dir must exist")
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(runs.len(), 1, "exactly one run directory: {runs:?}");
    runs.into_iter().next().unwrap()
}

fn trace_events(run_dir: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(run_dir.join("trace.jsonl"))
        .expect("trace.jsonl must exist")
        .lines()
        .map(|l| serde_json::from_str(l).expect("every trace line parses"))
        .collect()
}

/// acceptance 1 (FR-5, FR-21, FR-22): a real run produces the complete run directory
/// and the exit code mirrors the agent.
#[test]
fn run_produces_run_dir_and_mirrors_the_exit_code() {
    let ws = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let out = run_leash(
        &[
            "run",
            "--unattended",
            "--state-dir",
            state.path().to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "cat /etc/hosts >/dev/null; exit 7",
        ],
        ws.path(),
    );
    assert_eq!(
        out.status.code(),
        Some(7),
        "exit mirrors the agent (FR-22); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let run_dir = only_run_dir(state.path());
    assert!(run_dir.join("meta.json").is_file());
    assert!(run_dir.join("report.txt").is_file());
    assert!(run_dir.join("snapshots").is_dir());

    let meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(run_dir.join("meta.json")).unwrap()).unwrap();
    assert_eq!(meta["mode"], "record_only");
    assert_eq!(meta["attendance"], "unattended");
    assert_eq!(meta["policy_digest"], serde_json::Value::Null);
    assert_eq!(meta["landlock_abi"], serde_json::Value::Null);
    assert_eq!(meta["landlock_residuals"], serde_json::Value::Null);

    let events = trace_events(&run_dir);
    assert_eq!(events.first().unwrap()["type"], "run_start");
    let end = events.last().unwrap();
    assert_eq!(end["type"], "run_end");
    assert_eq!(end["exit_code"], 7);
    assert_eq!(end["final_step"], 0);
    // the agent's file read must be in the trace with its resolved path
    assert!(
        events.iter().any(|e| e["type"] == "syscall"
            && e["fact"]["family"] == "fs"
            && e["fact"]["path"] == "/etc/hosts"),
        "the agent's open of /etc/hosts must be recorded"
    );
}

/// acceptance 2 (FR-5, trace.md section 6): the report regenerates from trace.jsonl
/// alone and equals what the run wrote.
#[test]
fn report_regenerates_from_trace_alone() {
    let ws = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let out = run_leash(
        &[
            "run",
            "--unattended",
            "--state-dir",
            state.path().to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "echo hi > out.txt",
        ],
        ws.path(),
    );
    // gather the evidence before asserting, so a failure names its cause: the child's
    // exit is mirrored, and a denied syscall shows up in the trace, not in the code
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let run_dir = only_run_dir(state.path());
    let trace = std::fs::read_to_string(run_dir.join("trace.jsonl")).unwrap_or_default();
    assert_eq!(
        out.status.code(),
        Some(0),
        "leash stderr:\n{stderr}\ntrace:\n{trace}"
    );

    let on_disk = std::fs::read_to_string(run_dir.join("report.txt")).unwrap();
    let regenerated = leash::recorder::report::render_report(&trace).expect("render");
    let again = leash::recorder::report::render_report(&trace).expect("render");
    assert_eq!(regenerated, again, "rendering is deterministic");
    assert_eq!(
        regenerated, on_disk,
        "the on-disk report is exactly the rendering of the trace"
    );
}

/// acceptance 3 (FR-19, ADR-0010): record-only is announced and the report never uses
/// enforcement language.
#[test]
fn record_only_announcement_and_report_language() {
    let ws = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let out = run_leash(
        &[
            "run",
            "--unattended",
            "--state-dir",
            state.path().to_str().unwrap(),
            "--",
            "/bin/true",
        ],
        ws.path(),
    );
    assert_eq!(out.status.code(), Some(0));

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("record-only"),
        "the mode is announced at run start (FR-19): {stderr}"
    );

    let run_dir = only_run_dir(state.path());
    let report = std::fs::read_to_string(run_dir.join("report.txt")).unwrap();
    assert!(report.contains("nothing was enforced"));
    assert!(!report.contains("enforce mode"));
    assert!(!report.contains("blocked"));
}

/// FR-22: signal death maps to 128 plus the signal, and run_end records the signal.
#[test]
fn signal_death_maps_to_128_plus_signal() {
    let ws = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let out = run_leash(
        &[
            "run",
            "--unattended",
            "--state-dir",
            state.path().to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "kill -9 $$",
        ],
        ws.path(),
    );
    assert_eq!(out.status.code(), Some(137), "128 + SIGKILL");

    let run_dir = only_run_dir(state.path());
    let events = trace_events(&run_dir);
    let end = events.last().unwrap();
    assert_eq!(end["type"], "run_end");
    assert_eq!(end["signal"], 9);
    assert_eq!(end["exit_code"], serde_json::Value::Null);
}

/// cli.md section 1: usage errors and reserved subcommands exit 2 with stable text.
#[test]
fn usage_and_reserved_subcommands_exit_2() {
    let ws = tempfile::tempdir().unwrap();
    for (args, needle) in [
        (vec![], "no subcommand"),
        (vec!["run"], "--"),
        (vec!["run", "--"], "command"),
        (vec!["run", "--policy", "--", "echo"], "policy"),
        (vec!["run", "--policy=", "--", "echo"], "policy"),
        (
            vec!["run", "--policy", "a", "--policy=b", "--", "echo"],
            "given twice",
        ),
        (vec!["frobnicate"], "unknown"),
        (
            vec!["rewind"],
            "leash: 'rewind' is not implemented yet (planned: time-travel milestone M3)",
        ),
        (
            vec!["runs"],
            "leash: 'runs' is not implemented yet (planned: FR-21 run management)",
        ),
    ] {
        let out = run_leash(&args, ws.path());
        assert_eq!(out.status.code(), Some(2), "args {args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
        assert!(
            stderr.contains(&needle.to_lowercase()),
            "args {args:?}: stderr {stderr:?} must contain {needle:?}"
        );
    }
}

/// cli.md section 2: `--policy` selects enforce mode, loads the policy before spawn,
/// and stamps the Landlock metadata. The enforce notify loop still refuses before
/// spawning the agent until safe allow realization lands.
#[test]
fn policy_selects_enforce_and_stamps_landlock_metadata() {
    let ws = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let policy_path = state.path().join("policy.toml");
    let policy_text = "schema_version = 1\n\
        [[fs]]\npath=\"/**\"\nmode=[\"read\"]\naction=\"allow\"\n\
        [[exec]]\nbinary=\"/**\"\naction=\"allow\"\n";
    std::fs::write(&policy_path, policy_text).unwrap();

    let out = run_leash(
        &[
            "run",
            "--unattended",
            "--state-dir",
            state.path().to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--",
            "/bin/true",
        ],
        ws.path(),
    );
    assert_eq!(
        out.status.code(),
        Some(125),
        "enforce mode is fail-closed until safe allow realization lands; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let run_dir = only_run_dir(state.path());
    let meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(run_dir.join("meta.json")).unwrap()).unwrap();
    let expected = leash::policy::Policy::load_with_digest(
        &policy_path,
        &leash::policy::ExpandContext {
            workspace: ws.path().to_str().unwrap(),
            home: &std::env::var("HOME").unwrap(),
        },
    )
    .unwrap();
    assert_eq!(meta["mode"], "enforce");
    assert_eq!(meta["policy_digest"], expected.digest);
    assert!(
        meta["landlock_abi"].as_u64().unwrap() >= 2,
        "preflight guarantees the ABI-2 floor"
    );
    let residuals = meta["landlock_residuals"].as_array().unwrap();
    assert!(
        residuals
            .iter()
            .any(|r| r == leash::sandbox::landlock::RESIDUAL_TCP_HOST),
        "host-level TCP residual is always stamped in enforce"
    );
}

/// policy load errors are supervisor failures and happen before the run directory exists.
#[test]
fn invalid_policy_exits_125_before_artifacts() {
    let ws = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let policy_path = state.path().join("bad-policy.toml");
    std::fs::write(&policy_path, "schema_version = 2\n").unwrap();

    let out = run_leash(
        &[
            "run",
            "--unattended",
            "--state-dir",
            state.path().to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--",
            "/bin/true",
        ],
        ws.path(),
    );
    assert_eq!(out.status.code(), Some(125));
    assert!(
        !state.path().join("runs").exists(),
        "policy errors fail before creating a run directory"
    );
}

/// cli.md sections 5-6: a spawn failure exits 125 and leaves durable evidence - a synced
/// run_start, no run_end, no report. the agent is a bare name that fails PATH resolution,
/// so the spawn itself errs before any fork (a name with a slash would spawn fine and
/// fail only at execve, which is a mirrored child outcome, not a supervisor failure).
#[test]
fn spawn_failure_exits_125_with_durable_run_start() {
    let ws = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let out = run_leash(
        &[
            "run",
            "--unattended",
            "--state-dir",
            state.path().to_str().unwrap(),
            "--",
            "no-such-binary-xyzzy",
        ],
        ws.path(),
    );
    assert_eq!(out.status.code(), Some(125), "supervisor failure (FR-22)");

    let run_dir = only_run_dir(state.path());
    assert!(run_dir.join("meta.json").is_file());
    let events = trace_events(&run_dir);
    assert_eq!(events.first().unwrap()["type"], "run_start");
    assert!(
        events.iter().all(|e| e["type"] != "run_end"),
        "no run_end: the supervisor failed before stamping one"
    );
    assert!(
        !run_dir.join("report.txt").exists(),
        "no report for a run that never spawned"
    );
}

/// cli.md section 5 + rev-2 abort contract: a trace-write failure after run_start kills
/// the child, appends no run_end, writes no report, and surfaces as a session error
/// (which the cli maps to the supervisor-failure exit). library-level, through the
/// run_session_with_writer seam, with a sink that dies after the first write.
#[test]
fn trace_failure_mid_run_aborts_without_run_end_or_report() {
    use leash::recorder::{
        Attendance, Mode, RunDir, RunMeta, SnapshotMechanism, TRACE_SCHEMA_VERSION, TraceSink,
        TraceWriter,
    };
    use leash::supervisor::session::{SessionError, SessionSpec, run_session_with_writer};
    use std::io::{self as stdio, Write};
    use std::time::SystemTime;

    /// dies after `ok_writes` successful writes; sync always succeeds.
    struct FailingSink {
        bytes: Vec<u8>,
        ok_writes: usize,
        writes: usize,
    }
    impl Write for FailingSink {
        fn write(&mut self, buf: &[u8]) -> stdio::Result<usize> {
            if self.writes >= self.ok_writes {
                return Err(stdio::Error::other("disk gone"));
            }
            self.writes += 1;
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> stdio::Result<()> {
            Ok(())
        }
    }
    impl TraceSink for FailingSink {
        fn sync(&mut self) -> stdio::Result<()> {
            Ok(())
        }
    }

    let state = tempfile::tempdir().unwrap();
    let ws = tempfile::tempdir().unwrap();
    let meta = RunMeta {
        schema_version: TRACE_SCHEMA_VERSION,
        mode: Mode::RecordOnly,
        attendance: Attendance::Unattended,
        policy_digest: None,
        kernel: "test".into(),
        landlock_abi: None,
        landlock_residuals: None,
        snapshot_mechanism: SnapshotMechanism::Copy,
        snapshot_reason: "test fixture".into(),
        argv: vec!["/bin/sh".into(), "-c".into(), "sleep 5".into()],
        workspace: ws.path().to_path_buf(),
        start_ts: 1,
    };
    let run_dir = RunDir::create(state.path(), &meta, SystemTime::now()).unwrap();
    let spec = SessionSpec {
        argv: meta.argv.clone(),
        mode: Mode::RecordOnly,
        attendance: Attendance::Unattended,
        state_root: state.path().to_path_buf(),
        workspace: ws.path().to_path_buf(),
        policy_path: None,
    };
    // run_start is write 1 and succeeds; the child's execve event is write 2 and dies
    let mut writer = TraceWriter::new(FailingSink {
        bytes: Vec::new(),
        ok_writes: 1,
        writes: 0,
    });

    let started = Instant::now();
    let result = run_session_with_writer(&spec, meta, &run_dir, &mut writer);
    let elapsed = started.elapsed();

    assert!(
        matches!(result, Err(SessionError::Run(_))),
        "a mid-run trace failure is a session error: {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(4),
        "the child (sleep 5) must be killed, not waited for: {elapsed:?}"
    );
    let sink = writer.into_inner();
    let written = String::from_utf8(sink.bytes).unwrap();
    assert!(
        !written.contains("run_end"),
        "no run_end after an abort: the supervisor failed before stamping one"
    );
    assert!(
        written.lines().count() == 1 && written.contains("run_start"),
        "exactly the synced run_start is the evidence: {written:?}"
    );
    assert!(
        !run_dir.path.join("report.txt").exists(),
        "no report for an aborted run"
    );
}

/// cli.md section 4 (FR-21): a state dir inside the workspace is refused before
/// anything is created.
#[test]
fn state_dir_inside_workspace_is_refused() {
    let ws = tempfile::tempdir().unwrap();
    let out = run_leash(
        &[
            "run",
            "--unattended",
            "--state-dir",
            "./state",
            "--",
            "/bin/true",
        ],
        ws.path(),
    );
    assert_eq!(out.status.code(), Some(2), "usage-class refusal");
    assert!(
        !ws.path().join("state").exists(),
        "nothing may be created inside the workspace"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("workspace"),
        "the refusal names the workspace rule: {stderr}"
    );
}
