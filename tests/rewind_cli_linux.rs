//! `leash rewind` end to end (ADR-0024 decisions 17 to 22, docs/design/cli.md section 1,
//! docs/design/snapshot.md section 5), driven through the real compiled binary.
//!
//! most tests build a fake snapshot run directly: `store::capture` into
//! `<state>/runs/<id>/snapshots`, a hand-written `meta.json` and `trace.jsonl`, and a run
//! cgroup path that is gone. they need a readable cgroup2 mount but no delegated cgroup. the
//! tests that need a present cgroup, and the one that rewinds a real snapshot run, need a
//! delegated cgroup and skip without one (`LEASH_REQUIRE_FREEZER=1` turns the skip into a
//! failure, which is how CI proves they ran).

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{self, File};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::SystemTime;

use leash::recorder::{Attendance, Mode, RunMeta, SnapshotMechanism, TRACE_SCHEMA_VERSION};
use leash::rewind::{RewindError, RewindHooks, RewindRequest, RewindTarget, run_rewind_with_hooks};
use leash::runs::META_READ_CAP;
use leash::snapshot::restore::{RestoreContext, recompute_chain};
use leash::snapshot::store::{Limits, capture, load_manifest};
use leash::supervisor::run_cgroup::{
    CgroupParent, RunCgroup, RunCgroupState, RunLock, run_cgroup_gone,
};
use leash::supervisor::workspace_lock::WorkspaceLock;
use serde_json::{Value, json};

const NOTICE: &str = "rewind reverses filesystem effects only; anything the agent sent off this machine is not undone";

fn leash_bin() -> &'static str {
    env!("CARGO_BIN_EXE_leash")
}

fn run_leash(args: &[&str], cwd: &Path) -> Output {
    Command::new(leash_bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// a stripped-down state of a tree: kind, mode, mtime and content (or target) per path.
fn tree_state(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
        let mut names: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        names.sort();
        for path in names {
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let meta = fs::symlink_metadata(&path).unwrap();
            let kind = if meta.is_dir() {
                "dir".to_string()
            } else if meta.file_type().is_symlink() {
                format!("symlink -> {}", fs::read_link(&path).unwrap().display())
            } else if meta.is_file() {
                format!("file {:?}", fs::read(&path).unwrap())
            } else {
                "other".to_string()
            };
            out.insert(
                rel,
                format!(
                    "{kind} mode={:o} mtime={}.{}",
                    meta.mode() & 0o7777,
                    meta.mtime(),
                    meta.mtime_nsec()
                ),
            );
            if meta.is_dir() {
                walk(root, &path, out);
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// strip an inherited default ACL, which capture refuses.
fn create_dir(path: &Path) {
    fs::create_dir(path).unwrap();
    strip_default_acl(path);
}

fn strip_default_acl(path: &Path) {
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: c_path and the attribute name are NUL-terminated.
    let _ = unsafe { libc::removexattr(c_path.as_ptr(), c"system.posix_acl_default".as_ptr()) };
}

fn open_dir(path: &Path) -> File {
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .unwrap()
}

/// a run cgroup path that `run_cgroup_gone` reports as gone, or `None` when this host shows
/// no readable cgroup2 mount (the caller skips, or fails under `LEASH_REQUIRE_FREEZER=1`).
fn gone_cgroup_path(id: &str) -> Option<PathBuf> {
    let mut parents = vec![PathBuf::from("/sys/fs/cgroup")];
    if let Ok(parent) = CgroupParent::locate() {
        parents.push(parent.path().to_path_buf());
    }
    for parent in parents {
        let path = parent.join(format!("leash-{id}"));
        if matches!(run_cgroup_gone(&path, id), Ok(RunCgroupState::Gone)) {
            return Some(path);
        }
    }
    assert!(
        std::env::var("LEASH_REQUIRE_FREEZER").as_deref() != Ok("1"),
        "LEASH_REQUIRE_FREEZER=1 but no cgroup2 mount is readable here"
    );
    eprintln!("skipping: no readable cgroup2 mount");
    None
}

/// a fake snapshot run: a workspace, a state root, and a run directory with a store, a
/// `meta.json` and a `trace.jsonl` the test controls.
struct Fixture {
    state: tempfile::TempDir,
    _ws_dir: tempfile::TempDir,
    ws: PathBuf,
    id: String,
    run_dir: PathBuf,
    meta: RunMeta,
    trace: Vec<String>,
    committed: Vec<u64>,
}

impl Fixture {
    /// `cgroup` picks the recorded run cgroup from the run id; `None` uses a gone one.
    fn new(cgroup: Option<&dyn Fn(&str) -> PathBuf>) -> Option<Self> {
        Self::with(cgroup, false)
    }

    /// `nested` puts the workspace two levels below the temporary directory, so a test can
    /// swap an ancestor of it.
    fn with(cgroup: Option<&dyn Fn(&str) -> PathBuf>, nested: bool) -> Option<Self> {
        let id = leash::recorder::generate_run_id(SystemTime::now()).unwrap();
        let cgroup = match cgroup {
            Some(pick) => pick(&id),
            None => gone_cgroup_path(&id)?,
        };
        let state = tempfile::tempdir().unwrap();
        let ws_dir = tempfile::tempdir().unwrap();
        let mut ws = ws_dir.path().canonicalize().unwrap();
        strip_default_acl(&ws);
        if nested {
            ws = ws.join("outer");
            create_dir(&ws);
            ws = ws.join("ws");
            create_dir(&ws);
        }
        let run_dir = state.path().join("runs").join(&id);
        fs::create_dir_all(run_dir.join("snapshots")).unwrap();
        let meta = RunMeta {
            schema_version: TRACE_SCHEMA_VERSION,
            mode: Mode::Enforce,
            attendance: Attendance::Unattended,
            policy_digest: None,
            kernel: "test".into(),
            landlock_abi: Some(3),
            landlock_residuals: Some(Vec::new()),
            snapshot_mechanism: SnapshotMechanism::Copy,
            snapshot_reason: "test".into(),
            argv: vec!["agent".into()],
            workspace: ws.clone(),
            start_ts: 1,
            run_cgroup: Some(cgroup),
        };
        fs::write(
            run_dir.join("meta.json"),
            serde_json::to_vec(&meta).unwrap(),
        )
        .unwrap();
        let mut start = serde_json::to_value(&meta).unwrap();
        start["seq"] = 0.into();
        start["ts"] = 1.into();
        start["type"] = "run_start".into();
        let fixture = Self {
            state,
            _ws_dir: ws_dir,
            ws,
            id,
            run_dir,
            meta,
            trace: vec![start.to_string()],
            committed: Vec::new(),
        };
        fixture.flush_trace();
        Some(fixture)
    }

    fn gone() -> Option<Self> {
        Self::new(None)
    }

    /// replace the digest the trace's step event for `step` carries.
    fn rebind_step_digest(&mut self, step: u64, digest: &str) {
        let needle = format!("\"step\":{step},");
        for line in &mut self.trace {
            if line.contains("\"type\":\"step\"") && line.contains(&needle) {
                let old = line.split("\"manifest_digest\":\"").nth(1).unwrap()[..64].to_string();
                *line = line.replace(&old, digest);
            }
        }
        self.flush_trace();
    }

    fn flush_trace(&self) {
        let mut text = self.trace.join("\n");
        text.push('\n');
        fs::write(self.run_dir.join("trace.jsonl"), text).unwrap();
    }

    fn store(&self) -> File {
        open_dir(&self.run_dir.join("snapshots"))
    }

    fn write(&self, name: &str, data: &str) {
        let path = self.ws.join(name);
        let mut missing = Vec::new();
        let mut ancestor = path.parent().unwrap();
        while !ancestor.exists() {
            missing.push(ancestor.to_path_buf());
            ancestor = ancestor.parent().unwrap();
        }
        for dir in missing.iter().rev() {
            create_dir(dir);
        }
        fs::write(path, data).unwrap();
    }

    /// capture the workspace as `step` without a step event: an orphan manifest.
    fn capture_orphan(&self, step: u64) -> String {
        capture(&open_dir(&self.ws), &self.store(), step, &Limits::default()).unwrap();
        load_manifest(&self.store(), step).unwrap().1
    }

    /// capture the workspace as `step` and commit it with a step event.
    fn commit_step(&mut self, step: u64) -> String {
        let digest = self.capture_orphan(step);
        let seq = self.trace.len();
        self.trace.push(
            json!({
                "seq": seq, "ts": 2, "type": "step", "step": step,
                "manifest_digest": digest, "capture_pause_us": 0,
                "capture": {"entries": 0, "bytes": 0, "new_objects": 0},
            })
            .to_string(),
        );
        self.committed.push(step);
        self.flush_trace();
        digest
    }

    fn state_arg(&self) -> String {
        self.state.path().to_string_lossy().into_owned()
    }

    /// `leash rewind <id> <extra...>` from inside the workspace.
    fn rewind(&self, extra: &[&str]) -> Output {
        self.rewind_in(&self.ws, extra)
    }

    fn rewind_in(&self, cwd: &Path, extra: &[&str]) -> Output {
        let state = self.state_arg();
        let mut args = vec!["rewind", self.id.as_str(), "--state-dir", state.as_str()];
        args.extend_from_slice(extra);
        run_leash(&args, cwd)
    }

    fn chain_head(&self) -> String {
        recompute_chain(&self.store(), &self.committed)
            .unwrap()
            .head
    }

    fn undo_dir(&self) -> PathBuf {
        self.run_dir.join("rewind")
    }
}

/// the original tree has a nested file, a symlink, an empty directory and two modes.
fn populate(f: &Fixture) {
    f.write("a.txt", "one\n");
    f.write("sub/b.txt", "two\n");
    create_dir(&f.ws.join("empty"));
    symlink("a.txt", f.ws.join("link")).unwrap();
    let mut perms = fs::metadata(f.ws.join("a.txt")).unwrap().permissions();
    perms.set_mode(0o640);
    fs::set_permissions(f.ws.join("a.txt"), perms).unwrap();
}

/// what an agent does to the tree: edit, delete, add, retype.
fn agent_edits(f: &Fixture) {
    f.write("a.txt", "changed\n");
    fs::remove_file(f.ws.join("sub/b.txt")).unwrap();
    f.write("new.txt", "new\n");
    f.write("sub/deep/c.txt", "c\n");
    fs::remove_file(f.ws.join("link")).unwrap();
    fs::write(f.ws.join("link"), "now a file\n").unwrap();
    fs::remove_dir(f.ws.join("empty")).unwrap();
}

fn assert_success_notice(out: &Output) {
    assert!(out.status.success(), "{}", stderr(out));
    assert!(
        stdout(out).lines().any(|l| l == NOTICE),
        "the filesystem-effects notice is printed: {}",
        stdout(out)
    );
}

// ---- the happy paths ----

#[test]
fn the_default_step_restores_the_original_tree_exactly() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    let original = tree_state(&f.ws);
    let digest0 = f.commit_step(0);
    agent_edits(&f);
    f.commit_step(1);
    assert_ne!(tree_state(&f.ws), original);

    let out = f.rewind(&[]);
    assert_success_notice(&out);
    assert_eq!(tree_state(&f.ws), original, "the tree is exactly as it was");

    let text = stdout(&out);
    assert!(
        text.contains(&format!("chain head: {}", f.chain_head())),
        "{text}"
    );
    assert!(
        text.contains(&format!("step 0 digest: {digest0}")),
        "{text}"
    );
    assert!(text.contains("safety snapshot: "), "{text}");
    assert!(
        text.contains("to undo this rewind: leash rewind "),
        "{text}"
    );
    assert!(
        text.lines()
            .any(|l| l.starts_with("rewound the workspace to step 0: ")),
        "{text}"
    );
    // the summary precedes the result and lists the changes
    assert!(text.contains("  write a.txt"), "{text}");
    assert!(text.contains("  remove new.txt"), "{text}");
    assert!(
        text.find("  remove new.txt") < text.find("rewound the workspace"),
        "{text}"
    );
}

#[test]
fn step_n_restores_that_step() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    f.commit_step(0);
    agent_edits(&f);
    let after_edits = tree_state(&f.ws);
    f.commit_step(1);
    f.write("later.txt", "later\n");
    f.commit_step(2);

    let out = f.rewind(&["--step", "1"]);
    assert_success_notice(&out);
    assert_eq!(tree_state(&f.ws), after_edits);
    assert!(stdout(&out).contains("rewound the workspace to step 1: "));
}

#[test]
fn a_crashed_run_with_a_torn_trace_tail_can_be_rewound() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    let original = tree_state(&f.ws);
    f.commit_step(0);
    agent_edits(&f);
    // a crash mid-write leaves an unterminated last line and no run_end
    let mut text = fs::read_to_string(f.run_dir.join("trace.jsonl")).unwrap();
    text.push_str("{\"seq\":9,\"ts\":3,\"type\":\"sys");
    fs::write(f.run_dir.join("trace.jsonl"), text).unwrap();

    let out = f.rewind(&[]);
    assert_success_notice(&out);
    assert_eq!(tree_state(&f.ws), original);
}

#[test]
fn an_empty_plan_says_so_and_changes_nothing() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    f.commit_step(0);
    let before = tree_state(&f.ws);

    let out = f.rewind(&[]);
    assert_success_notice(&out);
    assert!(
        stdout(&out).contains("workspace already matches step 0"),
        "{}",
        stdout(&out)
    );
    assert_eq!(tree_state(&f.ws), before);
    assert!(
        !f.undo_dir().join("undo-1").exists(),
        "an empty plan leaves no safety snapshot behind"
    );
}

#[test]
fn summary_paths_with_control_characters_are_escaped() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    f.commit_step(0);
    f.write("bad\nname", "x");
    f.write("esc\u{1b}[2Jseq", "x");

    let out = f.rewind(&[]);
    assert_success_notice(&out);
    let text = stdout(&out);
    assert!(text.contains(r#"remove "bad\nname""#), "{text}");
    assert!(text.contains(r#"remove "esc\u{1b}[2Jseq""#), "{text}");
    assert!(
        !text.contains('\u{1b}'),
        "no raw escape character reaches the terminal"
    );
    assert!(!text.lines().any(|l| l == "name"), "{text}");
}

// ---- the safety snapshot ----

#[test]
fn the_printed_undo_command_restores_the_pre_rewind_state_exactly() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    f.commit_step(0);
    agent_edits(&f);
    f.commit_step(1);
    let before_rewind = tree_state(&f.ws);

    let out = f.rewind(&[]);
    assert_success_notice(&out);
    let command = stdout(&out)
        .lines()
        .find_map(|l| l.strip_prefix("to undo this rewind: ").map(str::to_owned))
        .expect("the undo command is printed");
    assert!(command.contains("--undo 1"), "{command}");
    assert_ne!(tree_state(&f.ws), before_rewind);

    // run the printed command exactly as the shell would, with `leash` on the path
    let bin_dir = tempfile::tempdir().unwrap();
    symlink(leash_bin(), bin_dir.path().join("leash")).unwrap();
    let path = format!(
        "{}:{}",
        bin_dir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    // from a directory that is not the workspace: the command names it
    let elsewhere = tempfile::tempdir().unwrap();
    let undo = Command::new("sh")
        .args(["-c", &command])
        .env("PATH", path)
        .current_dir(elsewhere.path())
        .output()
        .unwrap();
    assert_success_notice(&undo);
    assert_eq!(tree_state(&f.ws), before_rewind, "the undo is exact");
    let text = stdout(&undo);
    assert!(
        text.lines()
            .any(|l| l.starts_with("restored the workspace from undo snapshot 1: ")),
        "{text}"
    );
    assert!(
        text.contains("--undo 2"),
        "the undo is itself undoable: {text}"
    );
}

#[test]
fn the_safety_snapshot_is_outside_the_chain_and_never_a_step() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    f.commit_step(0);
    agent_edits(&f);
    f.commit_step(1);
    let head = f.chain_head();

    assert_success_notice(&f.rewind(&[]));
    assert_eq!(f.chain_head(), head, "the chain is unchanged");
    let steps: Vec<_> = fs::read_dir(f.run_dir.join("snapshots/manifests"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(steps.len(), 2, "{steps:?}");
    assert!(
        f.undo_dir()
            .join("undo-1/manifests/step-000000.json")
            .exists()
    );
    // the safety snapshot is not a step to rewind to, and the undo number is not a step
    let out = f.rewind(&["--step", "2"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
}

#[test]
fn a_planted_socket_refuses_the_safety_snapshot_and_no_undo_removes_it() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    let original = tree_state(&f.ws);
    f.commit_step(0);
    agent_edits(&f);
    let socket = f.ws.join("sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let before = tree_state(&f.ws);

    let out = f.rewind(&[]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert!(stderr(&out).contains("--no-undo"), "{}", stderr(&out));
    assert_eq!(tree_state(&f.ws), before, "a refused rewind writes nothing");
    assert!(socket.exists());
    assert!(
        !f.undo_dir().join("undo-1").exists(),
        "no partial snapshot is left"
    );

    let out = f.rewind(&["--no-undo"]);
    assert_success_notice(&out);
    assert!(
        stderr(&out).contains("cannot be undone"),
        "the warning names the loss: {}",
        stderr(&out)
    );
    assert!(
        !stdout(&out).contains("to undo this rewind"),
        "{}",
        stdout(&out)
    );
    assert!(!socket.exists(), "the socket is removed");
    assert_eq!(tree_state(&f.ws), original);
    assert!(!f.undo_dir().join("undo-1").exists());
}

// ---- the request ----

#[test]
fn unknown_run_unknown_step_and_bad_arguments_exit_2() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    f.commit_step(0);
    let state = f.state_arg();

    let unknown = run_leash(
        &["rewind", "20260101T000000Z-abcdef", "--state-dir", &state],
        &f.ws,
    );
    assert_eq!(unknown.status.code(), Some(2), "{}", stderr(&unknown));
    assert!(
        stderr(&unknown).contains("unknown run"),
        "{}",
        stderr(&unknown)
    );

    let out = f.rewind(&["--step", "7"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("no committed step 7"),
        "{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("committed steps: 0"),
        "{}",
        stderr(&out)
    );

    let out = f.rewind(&["--undo", "9"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));

    for bad in [
        vec!["rewind"],
        vec!["rewind", "../x"],
        vec!["rewind", "r", "--bogus"],
        vec!["rewind", "r", "--step", "-1"],
        vec!["rewind", "r", "--step", "x"],
        vec!["rewind", "r", "--expect", "abc"],
        vec!["rewind", "r", "--undo", "1", "--step", "0"],
    ] {
        let out = run_leash(&bad, &f.ws);
        assert_eq!(out.status.code(), Some(2), "{bad:?}: {}", stderr(&out));
    }
}

#[test]
fn a_run_without_snapshots_or_a_run_cgroup_is_not_a_target() {
    let Some(f) = Fixture::gone() else { return };
    // no committed step at all, but a store directory: step 0 is unknown
    let out = f.rewind(&[]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));

    fs::remove_dir(f.run_dir.join("snapshots")).unwrap();
    let out = f.rewind(&[]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).contains("no snapshots"), "{}", stderr(&out));

    // a record-only run records no run cgroup and is not a snapshot run
    fs::create_dir(f.run_dir.join("snapshots")).unwrap();
    let mut meta = f.meta.clone();
    meta.run_cgroup = None;
    fs::write(
        f.run_dir.join("meta.json"),
        serde_json::to_vec(&meta).unwrap(),
    )
    .unwrap();
    let out = f.rewind(&[]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("not a snapshot run"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn an_orphan_manifest_is_not_a_target() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    f.commit_step(0);
    agent_edits(&f);
    // published, never committed: the capture barrier aborted before the step event
    f.capture_orphan(1);
    let before = tree_state(&f.ws);

    let out = f.rewind(&["--step", "1"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("no committed step event"),
        "{}",
        stderr(&out)
    );
    assert_eq!(tree_state(&f.ws), before);

    // the orphan is not in the chain either: the head covers the committed steps only
    let out = f.rewind(&["--step", "0"]);
    assert_success_notice(&out);
    assert!(
        stdout(&out).contains(&format!("chain head: {}", f.chain_head())),
        "{}",
        stdout(&out)
    );
}

#[test]
fn a_step_event_followed_by_a_failed_step_event_boundary_is_not_committed() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    f.commit_step(0);
    agent_edits(&f);
    f.commit_step(1);
    // the step event reached the trace, but the barrier then reported that it could not be
    // made durable, so the boundary did not commit
    let seq = f.trace.len();
    f.trace.push(
        json!({
            "seq": seq, "ts": 3, "type": "capture_failed", "step": 1,
            "phase": "step_event", "error": "disk full",
        })
        .to_string(),
    );
    f.flush_trace();
    let before = tree_state(&f.ws);

    let out = f.rewind(&["--step", "1"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("no committed step event"),
        "{}",
        stderr(&out)
    );
    assert_eq!(tree_state(&f.ws), before);
    // a failed thaw happens after the step event was durable, so that step stays committed
    f.trace.pop();
    f.trace.push(
        json!({
            "seq": seq, "ts": 3, "type": "capture_failed", "step": 1,
            "phase": "thaw", "error": "stuck",
        })
        .to_string(),
    );
    f.flush_trace();
    assert_success_notice(&f.rewind(&["--step", "1"]));
}

#[test]
fn a_workspace_that_is_not_the_runs_is_refused() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    f.commit_step(0);
    let elsewhere = tempfile::tempdir().unwrap();
    let other = elsewhere.path().canonicalize().unwrap();
    fs::write(other.join("keep.txt"), "keep").unwrap();

    // from the wrong directory
    let out = f.rewind_in(&other, &[]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("is not the workspace of run"),
        "{}",
        stderr(&out)
    );
    // and by flag
    let flag = other.to_string_lossy().into_owned();
    let out = f.rewind_in(&f.ws, &["--workspace", &flag]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert_eq!(fs::read_to_string(other.join("keep.txt")).unwrap(), "keep");

    // the flag also names the right workspace from elsewhere
    f.write("extra.txt", "x");
    let right = f.ws.to_string_lossy().into_owned();
    let out = f.rewind_in(&other, &["--workspace", &right]);
    assert_success_notice(&out);
    assert!(!f.ws.join("extra.txt").exists());
}

#[test]
fn a_state_directory_inside_the_workspace_is_a_usage_error() {
    let Some(mut f) = Fixture::gone() else { return };
    f.commit_step(0);
    let inside = f.ws.join("state");
    let out = run_leash(
        &["rewind", &f.id, "--state-dir", &inside.to_string_lossy()],
        &f.ws,
    );
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
}

// ---- is the run over ----

#[test]
fn a_live_run_is_refused() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    f.commit_step(0);
    agent_edits(&f);
    let before = tree_state(&f.ws);
    let _lock = RunLock::acquire(&f.run_dir).unwrap();

    let out = f.rewind(&[]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert!(stderr(&out).contains("still running"), "{}", stderr(&out));
    assert_eq!(tree_state(&f.ws), before);
}

#[test]
fn a_cgroup_that_cannot_be_proven_gone_is_refused() {
    // a path on a filesystem that is not cgroup2 is Unknown, never Gone
    let unreadable: &dyn Fn(&str) -> PathBuf =
        &|id| std::env::temp_dir().join(format!("leash-{id}"));
    let Some(mut f) = Fixture::new(Some(unreadable)) else {
        return;
    };
    populate(&f);
    f.commit_step(0);
    agent_edits(&f);
    let before = tree_state(&f.ws);

    let out = f.rewind(&[]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    let cgroup = f.meta.run_cgroup.clone().unwrap();
    assert!(
        stderr(&out).contains("cannot confirm")
            && stderr(&out).contains(&cgroup.to_string_lossy().into_owned()),
        "{}",
        stderr(&out)
    );
    assert_eq!(tree_state(&f.ws), before);
}

#[test]
fn a_cgroup_that_is_present_and_not_stale_is_refused() {
    if !common::delegated_cgroup_or_skip("present_cgroup") {
        return;
    }
    let parent = CgroupParent::locate().unwrap();
    let pick: &dyn Fn(&str) -> PathBuf = &|id| parent.child_path(id).unwrap();
    let Some(mut f) = Fixture::new(Some(pick)) else {
        return;
    };
    populate(&f);
    f.commit_step(0);
    agent_edits(&f);
    let before = tree_state(&f.ws);
    // no lock xattr binds it to the run lock, so the cleanup must leave it alone
    let cgroup = f.meta.run_cgroup.clone().unwrap();
    fs::create_dir(&cgroup).unwrap();

    let out = f.rewind(&[]);
    let _ = fs::remove_dir(&cgroup);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("still exists")
            && stderr(&out).contains(&cgroup.to_string_lossy().into_owned()),
        "{}",
        stderr(&out)
    );
    assert_eq!(tree_state(&f.ws), before);
}

#[test]
fn a_stale_cgroup_of_a_dead_run_is_cleaned_and_the_rewind_proceeds() {
    if !common::delegated_cgroup_or_skip("stale_cgroup") {
        return;
    }
    let parent = CgroupParent::locate().unwrap();
    let pick: &dyn Fn(&str) -> PathBuf = &|id| parent.child_path(id).unwrap();
    let Some(mut f) = Fixture::new(Some(pick)) else {
        return;
    };
    populate(&f);
    let original = tree_state(&f.ws);
    f.commit_step(0);
    agent_edits(&f);
    // a crashed run: its cgroup is bound to its run lock, and the lock is free
    let lock = RunLock::acquire(&f.run_dir).unwrap();
    let group = RunCgroup::create(&parent, &f.id).unwrap();
    group.bind_lock(&lock).unwrap();
    std::mem::forget(group);
    drop(lock);
    let cgroup = f.meta.run_cgroup.clone().unwrap();
    assert!(cgroup.exists());

    let out = f.rewind(&[]);
    assert_success_notice(&out);
    assert!(!cgroup.exists(), "the stale cgroup is gone");
    assert_eq!(tree_state(&f.ws), original);
}

/// the stale cleanup is driven by the untrusted `meta.json`, so it runs only after the trace
/// and the store have passed their read-only checks (ADR-0024 decision 17).
#[test]
fn a_stale_cgroup_is_not_cleaned_when_the_trace_or_the_expect_check_refuses() {
    if !common::delegated_cgroup_or_skip("stale_cgroup_after_checks") {
        return;
    }
    let parent = CgroupParent::locate().unwrap();
    let pick: &dyn Fn(&str) -> PathBuf = &|id| parent.child_path(id).unwrap();
    let Some(mut f) = Fixture::new(Some(pick)) else {
        return;
    };
    populate(&f);
    f.commit_step(0);
    agent_edits(&f);
    let before = tree_state(&f.ws);
    let lock = RunLock::acquire(&f.run_dir).unwrap();
    let group = RunCgroup::create(&parent, &f.id).unwrap();
    group.bind_lock(&lock).unwrap();
    std::mem::forget(group);
    drop(lock);
    let cgroup = f.meta.run_cgroup.clone().unwrap();
    assert!(cgroup.exists());

    // a digest that matches neither the chain head nor the step
    let wrong = "0".repeat(64);
    let out = f.rewind(&["--expect", &wrong]);
    let expect_survived = cgroup.exists();
    // a trace that disagrees with meta.json
    let trace = f.trace[0].clone();
    f.trace[0] = trace.replace(&*f.ws.to_string_lossy(), "/somewhere/else");
    f.flush_trace();
    let disagreeing = f.rewind(&[]);
    let trace_survived = cgroup.exists();
    let _ = fs::remove_dir(&cgroup);

    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert!(stderr(&out).contains("--expect"), "{}", stderr(&out));
    assert!(
        expect_survived,
        "a refused --expect left the stale cgroup alone"
    );
    assert_eq!(
        disagreeing.status.code(),
        Some(125),
        "{}",
        stderr(&disagreeing)
    );
    assert!(
        stderr(&disagreeing).contains("disagrees"),
        "{}",
        stderr(&disagreeing)
    );
    assert!(
        trace_survived,
        "a refused trace left the stale cgroup alone"
    );
    assert_eq!(tree_state(&f.ws), before);
}

#[test]
fn a_held_workspace_lock_is_refused() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    f.commit_step(0);
    agent_edits(&f);
    let before = tree_state(&f.ws);
    let _lock = WorkspaceLock::acquire(f.state.path(), &f.ws).unwrap();

    let out = f.rewind(&[]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("the workspace directory is locked by another process"),
        "{}",
        stderr(&out)
    );
    assert_eq!(tree_state(&f.ws), before);
}

#[test]
fn a_workspace_lock_taken_under_another_state_directory_is_refused() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    f.commit_step(0);
    agent_edits(&f);
    let before = tree_state(&f.ws);
    // a run that names this workspace under a different --state-dir holds the lock on the
    // workspace directory itself (ADR-0026)
    let other_state = tempfile::tempdir().unwrap();
    let _lock = WorkspaceLock::acquire(other_state.path(), &f.ws).unwrap();

    let out = f.rewind(&[]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("the workspace directory is locked by another process"),
        "{}",
        stderr(&out)
    );
    assert_eq!(tree_state(&f.ws), before);
}

// ---- integrity ----

#[test]
fn expect_accepts_the_chain_head_or_the_step_digest_and_refuses_anything_else() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    let digest0 = f.commit_step(0);
    agent_edits(&f);
    f.commit_step(1);
    let head = f.chain_head();
    let before = tree_state(&f.ws);

    let wrong = "ab".repeat(32);
    let out = f.rewind(&["--expect", &wrong]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    let message = stderr(&out);
    assert!(
        message.contains(&wrong) && message.contains(&head) && message.contains(&digest0),
        "both the given and the actual values are printed: {message}"
    );
    assert_eq!(tree_state(&f.ws), before, "a refusal writes nothing");
    assert!(!f.undo_dir().exists(), "and takes no safety snapshot");

    let out = f.rewind(&["--expect", &head.to_uppercase()]);
    assert_success_notice(&out);

    // the step digest also matches, for the step that is rewound to
    agent_edits_again(&f);
    let out = f.rewind(&["--expect", &digest0]);
    assert_success_notice(&out);
}

fn agent_edits_again(f: &Fixture) {
    f.write("again.txt", "again");
}

#[test]
fn a_tampered_manifest_is_refused_before_any_write() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    let digest0 = f.commit_step(0);
    agent_edits(&f);
    f.commit_step(1);
    let before = tree_state(&f.ws);

    // a forger rewrites the manifest of step 0 so it still parses and validates
    let path = f.run_dir.join("snapshots/manifests/step-000000.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let mtime = manifest["entries"][0]["mtime_sec"].as_i64().unwrap();
    manifest["entries"][0]["mtime_sec"] = (mtime + 1).into();
    fs::remove_file(&path).unwrap();
    fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let forged = load_manifest(&f.store(), 0).unwrap().1;
    assert_ne!(forged, digest0);

    let out = f.rewind(&[]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    let message = stderr(&out);
    assert!(
        message.contains(&forged) && message.contains(&digest0),
        "both digests are printed: {message}"
    );
    assert_eq!(tree_state(&f.ws), before, "nothing is written");
    assert!(!f.undo_dir().exists(), "not even a safety snapshot");
}

#[test]
fn a_corrupt_object_refuses_the_rewind_before_any_write() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    f.commit_step(0);
    agent_edits(&f);
    f.commit_step(1);
    let before = tree_state(&f.ws);

    // flip the bytes of the object behind a.txt at step 0
    let (manifest, _) = load_manifest(&f.store(), 0).unwrap();
    let sha = manifest
        .entries
        .iter()
        .find(|e| e.path == "a.txt")
        .and_then(|e| e.sha256.clone())
        .unwrap();
    let object = f
        .run_dir
        .join("snapshots/objects")
        .join(&sha[..2])
        .join(&sha);
    fs::remove_file(&object).unwrap();
    fs::write(&object, "tampered\n").unwrap();

    let out = f.rewind(&[]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("failed verification"),
        "{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("nothing was changed"),
        "{}",
        stderr(&out)
    );
    assert_eq!(tree_state(&f.ws), before);
    assert!(
        !f.undo_dir().join("undo-1").exists(),
        "the unused safety snapshot is removed"
    );
}

#[test]
fn a_trace_that_disagrees_with_the_run_metadata_is_refused() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    f.commit_step(0);
    f.trace[0] = f.trace[0].replace(&*f.ws.to_string_lossy(), "/somewhere/else");
    f.flush_trace();
    let out = f.rewind(&[]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    assert!(stderr(&out).contains("disagrees"), "{}", stderr(&out));
}

// ---- forgery honesty and the safety snapshot digest ----

const NO_EXPECT_NOTE: &str = "leash: note: no --expect given; the store is checked only against the trace beside it, so a forged store and trace are not detected; pass the chain head printed at run end";

/// the value of the `<prefix>` line of rewind's output.
fn line_value(out: &Output, prefix: &str) -> String {
    stdout(out)
        .lines()
        .find_map(|l| l.strip_prefix(prefix).map(str::to_owned))
        .unwrap_or_else(|| panic!("no {prefix:?} line in: {}", stdout(out)))
}

/// run a printed command the way the shell would, with `leash` on the path.
fn run_printed(command: &str) -> Output {
    let bin_dir = tempfile::tempdir().unwrap();
    symlink(leash_bin(), bin_dir.path().join("leash")).unwrap();
    let path = format!(
        "{}:{}",
        bin_dir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let elsewhere = tempfile::tempdir().unwrap();
    Command::new("sh")
        .args(["-c", command])
        .env("PATH", path)
        .current_dir(elsewhere.path())
        .output()
        .unwrap()
}

#[test]
fn without_expect_the_forgery_note_is_printed_and_with_expect_it_is_not() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    f.commit_step(0);
    agent_edits(&f);
    f.commit_step(1);

    let out = f.rewind(&[]);
    assert_success_notice(&out);
    assert!(
        stderr(&out).lines().any(|l| l == NO_EXPECT_NOTE),
        "{}",
        stderr(&out)
    );

    agent_edits_again(&f);
    let head = f.chain_head();
    let out = f.rewind(&["--expect", &head]);
    assert_success_notice(&out);
    assert!(
        !stderr(&out).contains("no --expect given"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn the_safety_snapshot_digest_is_printed_and_is_the_undo_manifest_digest() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    f.commit_step(0);
    agent_edits(&f);
    f.commit_step(1);

    let out = f.rewind(&[]);
    assert_success_notice(&out);
    let digest = line_value(&out, "safety snapshot digest: ");
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "{digest}"
    );
    let undo_store = open_dir(&f.undo_dir().join("undo-1"));
    assert_eq!(load_manifest(&undo_store, 0).unwrap().1, digest);
    let command = line_value(&out, "to undo this rewind: ");
    assert!(
        command.contains(&format!("--undo 1 --expect {digest} ")),
        "{command}"
    );
}

#[test]
fn undo_checks_expect_against_the_undo_manifest_digest() {
    let Some(mut f) = Fixture::gone() else { return };
    populate(&f);
    f.commit_step(0);
    agent_edits(&f);
    f.commit_step(1);
    let out = f.rewind(&[]);
    assert_success_notice(&out);
    let digest = line_value(&out, "safety snapshot digest: ");
    let after_rewind = tree_state(&f.ws);

    let wrong = "cd".repeat(32);
    let out = f.rewind(&["--undo", "1", "--expect", &wrong]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    let message = stderr(&out);
    assert!(
        message.contains(&wrong) && message.contains(&digest),
        "both values are printed: {message}"
    );
    assert_eq!(tree_state(&f.ws), after_rewind);

    // without --expect the undo store is checked against nothing, and says so
    let out = f.rewind(&["--undo", "1"]);
    assert_success_notice(&out);
    assert!(
        stderr(&out).contains("no --expect given; the undo store is checked against nothing"),
        "{}",
        stderr(&out)
    );

    // the right digest restores
    let out = f.rewind(&["--undo", "1", "--expect", &digest]);
    assert_success_notice(&out);
    assert!(
        !stderr(&out).contains("no --expect given"),
        "{}",
        stderr(&out)
    );
}

// ---- hostile run directories ----

fn assert_refused(out: &Output, code: i32, needle: &str) {
    assert_eq!(out.status.code(), Some(code), "{}", stderr(out));
    assert!(
        stderr(out).contains(needle),
        "wanted {needle:?} in: {}",
        stderr(out)
    );
}

/// a run with two committed steps and a workspace the agent changed.
fn edited_fixture() -> Option<Fixture> {
    let mut f = Fixture::gone()?;
    populate(&f);
    f.commit_step(0);
    agent_edits(&f);
    f.commit_step(1);
    Some(f)
}

fn mkfifo(path: &Path) {
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: c_path is NUL-terminated and names a path this test owns.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
}

#[test]
fn a_symlinked_run_directory_is_not_followed() {
    let Some(f) = edited_fixture() else { return };
    let before = tree_state(&f.ws);
    let real = f.state.path().join("real-run");
    fs::rename(&f.run_dir, &real).unwrap();
    symlink(&real, &f.run_dir).unwrap();

    let out = f.rewind(&[]);
    assert_refused(&out, 2, "unknown run");
    assert_eq!(tree_state(&f.ws), before);
    assert!(!real.join("rewind").exists());
}

#[test]
fn a_symlinked_snapshots_directory_is_not_followed() {
    let Some(f) = edited_fixture() else { return };
    let before = tree_state(&f.ws);
    let real = f.run_dir.join("snapshots-real");
    fs::rename(f.run_dir.join("snapshots"), &real).unwrap();
    symlink(&real, f.run_dir.join("snapshots")).unwrap();

    let out = f.rewind(&[]);
    assert_refused(&out, 2, "no snapshots");
    assert_eq!(tree_state(&f.ws), before);
}

#[test]
fn a_symlinked_rewind_directory_is_not_followed_or_written_through() {
    let Some(f) = edited_fixture() else { return };
    let before = tree_state(&f.ws);
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), f.run_dir.join("rewind")).unwrap();

    let out = f.rewind(&[]);
    assert_refused(&out, 125, "rewind directory");
    assert_eq!(tree_state(&f.ws), before);
    assert_eq!(
        fs::read_dir(outside.path()).unwrap().count(),
        0,
        "nothing was written through the link"
    );
}

#[test]
fn a_symlinked_undo_snapshot_is_not_followed() {
    let Some(f) = edited_fixture() else { return };
    assert_success_notice(&f.rewind(&[]));
    let after_rewind = tree_state(&f.ws);
    let real = f.run_dir.join("undo-real");
    fs::rename(f.undo_dir().join("undo-1"), &real).unwrap();
    symlink(&real, f.undo_dir().join("undo-1")).unwrap();

    let out = f.rewind(&["--undo", "1"]);
    assert_refused(&out, 2, "no undo snapshot 1");
    assert_eq!(tree_state(&f.ws), after_rewind);
}

#[test]
fn a_fifo_trace_or_meta_is_refused_without_blocking() {
    let Some(f) = edited_fixture() else { return };
    let before = tree_state(&f.ws);
    let trace = f.run_dir.join("trace.jsonl");
    fs::remove_file(&trace).unwrap();
    mkfifo(&trace);
    let out = f.rewind(&[]);
    assert_refused(&out, 125, "not a regular file");
    assert_eq!(tree_state(&f.ws), before);
    fs::remove_file(&trace).unwrap();
    f.flush_trace();

    let meta = f.run_dir.join("meta.json");
    fs::remove_file(&meta).unwrap();
    mkfifo(&meta);
    let out = f.rewind(&[]);
    assert_refused(&out, 125, "not a regular file");
    assert_eq!(tree_state(&f.ws), before);
}

#[test]
fn a_huge_sparse_trace_and_an_oversized_meta_are_refused_unread() {
    let Some(f) = edited_fixture() else { return };
    let before = tree_state(&f.ws);
    let trace = f.run_dir.join("trace.jsonl");
    fs::remove_file(&trace).unwrap();
    // sparse: nothing is written, and the size alone must refuse it
    File::create(&trace)
        .unwrap()
        .set_len(2 * 1024 * 1024 * 1024)
        .unwrap();
    let out = f.rewind(&[]);
    assert_refused(&out, 125, "longer than");
    assert_eq!(tree_state(&f.ws), before);
    fs::remove_file(&trace).unwrap();
    f.flush_trace();

    let meta = f.run_dir.join("meta.json");
    fs::remove_file(&meta).unwrap();
    File::create(&meta)
        .unwrap()
        .set_len(META_READ_CAP + 1)
        .unwrap();
    let out = f.rewind(&[]);
    assert_refused(&out, 125, "read limit");
    assert_eq!(tree_state(&f.ws), before);
}

#[test]
fn a_trace_of_only_newlines_or_one_huge_line_is_refused_cleanly() {
    let Some(f) = edited_fixture() else { return };
    let before = tree_state(&f.ws);
    let trace = f.run_dir.join("trace.jsonl");

    fs::write(&trace, vec![b'\n'; 16 * 1024 * 1024]).unwrap();
    let out = f.rewind(&[]);
    assert_refused(&out, 125, "line 1 is empty");

    // one line over the line cap, with and without its newline
    let mut huge = vec![b'x'; leash::snapshot::store::TRACE_LINE_CAP + 10];
    fs::write(&trace, &huge).unwrap();
    let out = f.rewind(&[]);
    assert_refused(&out, 125, "longer than");
    huge.push(b'\n');
    fs::write(&trace, &huge).unwrap();
    let out = f.rewind(&[]);
    assert_refused(&out, 125, "longer than");

    assert_eq!(tree_state(&f.ws), before);
    assert!(!f.undo_dir().exists(), "no safety snapshot was taken");
}

/// a completed rewind of the edited fixture, so `rewind/undo-1` is a real safety snapshot.
/// returns the digest it printed.
fn with_an_undo_snapshot(f: &Fixture) -> String {
    let out = f.rewind(&[]);
    assert_success_notice(&out);
    line_value(&out, "safety snapshot digest: ")
}

#[test]
fn a_forged_undo_store_with_a_corrupt_object_is_refused_before_any_write() {
    let Some(f) = edited_fixture() else { return };
    let digest = with_an_undo_snapshot(&f);
    let after_rewind = tree_state(&f.ws);

    // the undo store holds the tree as the agent left it, so a.txt is "changed"
    let undo_store = f.undo_dir().join("undo-1");
    let (manifest, _) = load_manifest(&open_dir(&undo_store), 0).unwrap();
    let sha = manifest
        .entries
        .iter()
        .find(|e| e.path == "a.txt")
        .and_then(|e| e.sha256.clone())
        .unwrap();
    let object = undo_store.join("objects").join(&sha[..2]).join(&sha);
    fs::remove_file(&object).unwrap();
    fs::write(&object, "tampered\n").unwrap();

    let out = f.rewind(&["--undo", "1", "--expect", &digest]);
    assert_refused(&out, 125, "failed verification");
    assert_eq!(tree_state(&f.ws), after_rewind, "nothing was written");
    assert!(
        !f.undo_dir().join("undo-2").exists(),
        "the unused safety snapshot is removed"
    );
}

#[test]
fn an_undo_store_whose_manifest_is_not_step_zero_is_an_integrity_failure() {
    let Some(f) = edited_fixture() else { return };
    with_an_undo_snapshot(&f);
    let after_rewind = tree_state(&f.ws);
    let manifests = f.undo_dir().join("undo-1/manifests");

    // a manifest under another step number
    fs::rename(
        manifests.join("step-000000.json"),
        manifests.join("step-000007.json"),
    )
    .unwrap();
    let out = f.rewind(&["--undo", "1"]);
    assert_refused(&out, 125, "never completed or is not a safety snapshot");
    assert_eq!(tree_state(&f.ws), after_rewind);

    // step 0 plus an extra manifest
    fs::rename(
        manifests.join("step-000007.json"),
        manifests.join("step-000000.json"),
    )
    .unwrap();
    fs::copy(
        manifests.join("step-000000.json"),
        manifests.join("step-000001.json"),
    )
    .unwrap();
    let out = f.rewind(&["--undo", "1"]);
    assert_refused(&out, 125, "never completed or is not a safety snapshot");
    assert_eq!(tree_state(&f.ws), after_rewind);
}

#[test]
fn a_failed_apply_prints_an_undo_command_that_works() {
    // the engine checks every owner before its first write; a target that records an owner
    // an unprivileged process cannot create is refused after the safety snapshot is taken
    // and before the workspace changes, which is the failure path the message covers
    // SAFETY: geteuid takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let Some(mut f) = edited_fixture() else {
        return;
    };
    let before = tree_state(&f.ws);
    // a forger rewrites step 0 and the trace's digest for it, so the forgery is consistent
    let path = f.run_dir.join("snapshots/manifests/step-000000.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let entry = manifest["entries"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|e| e["path"] == "a.txt")
        .unwrap();
    entry["uid"] = 0.into();
    fs::remove_file(&path).unwrap();
    fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let forged = load_manifest(&f.store(), 0).unwrap().1;
    f.rebind_step_digest(0, &forged);

    let out = f.rewind(&[]);
    assert_refused(&out, 125, "rewind failed");
    assert_eq!(tree_state(&f.ws), before, "the refusal wrote nothing");
    let message = stderr(&out);
    let command = message
        .lines()
        .find_map(|l| l.split("restore it with: ").nth(1))
        .unwrap_or_else(|| panic!("no undo command in: {message}"))
        .to_string();
    assert!(command.contains("--undo 1 --expect "), "{command}");

    // the printed command works: it restores the safety snapshot, which is the tree as it is
    let undo = run_printed(&command);
    assert_success_notice(&undo);
    assert!(
        stdout(&undo).contains("workspace already matches undo snapshot 1"),
        "{}",
        stdout(&undo)
    );
    assert_eq!(tree_state(&f.ws), before);
}

// ---- root, and the workspace swapped under the open ----

fn request(f: &Fixture) -> RewindRequest {
    RewindRequest {
        run_id: f.id.clone(),
        target: RewindTarget::Step(0),
        expect: None,
        no_undo: false,
        workspace: f.ws.clone(),
        state_root: f.state.path().canonicalize().unwrap(),
    }
}

#[test]
fn root_is_refused_before_anything_is_opened_or_created() {
    let Some(f) = edited_fixture() else { return };
    let before = tree_state(&f.ws);
    let hooks = RewindHooks {
        identity: Some(RestoreContext {
            euid: 0,
            egid: 0,
            groups: Vec::new(),
        }),
        before_workspace_open: None,
    };
    let result = run_rewind_with_hooks(&request(&f), &mut Vec::new(), &mut Vec::new(), &hooks);
    match result {
        Err(RewindError::Failure(message)) => assert!(message.contains("root"), "{message}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(
        !f.state.path().join("locks").exists(),
        "no lock directory was created under the state root"
    );
    assert!(
        !f.run_dir.join("run.lock").exists(),
        "the run lock was not created, so no cleanup could have run"
    );
    assert!(!f.undo_dir().exists());
    assert_eq!(tree_state(&f.ws), before);
}

#[test]
fn a_workspace_path_swapped_between_the_check_and_the_open_is_refused() {
    let Some(mut f) = Fixture::with(None, true) else {
        return;
    };
    populate(&f);
    f.commit_step(0);
    agent_edits(&f);
    let before = tree_state(&f.ws);
    let outer = f.ws.parent().unwrap().to_path_buf();
    let top = outer.parent().unwrap().to_path_buf();
    // a decoy workspace the swap points the path at
    let decoy = top.join("decoy");
    create_dir(&decoy);
    create_dir(&decoy.join("ws"));
    fs::write(decoy.join("ws/keep.txt"), "keep").unwrap();
    let decoy_before = tree_state(&decoy);

    let moved = top.join("outer.moved");
    let swap = || {
        fs::rename(&outer, &moved).unwrap();
        symlink(&decoy, &outer).unwrap();
    };
    let hooks = RewindHooks {
        identity: None,
        before_workspace_open: Some(&swap),
    };
    let result = run_rewind_with_hooks(&request(&f), &mut Vec::new(), &mut Vec::new(), &hooks);
    match result {
        Err(RewindError::Failure(message)) => assert!(
            message.contains("the workspace changed while rewind opened it"),
            "{message}"
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(tree_state(&decoy), decoy_before, "the decoy is untouched");
    assert_eq!(
        tree_state(&moved.join("ws")),
        before,
        "the real workspace is untouched"
    );
    assert!(
        !f.undo_dir().exists(),
        "no safety snapshot was taken of either"
    );
}

// ---- a real snapshot run ----

const POLICY: &str = "schema_version = 1\n\
    [[fs]]\npath=\"/**\"\nmode=[\"read\"]\naction=\"allow\"\n\
    [[exec]]\nbinary=\"/**\"\naction=\"allow\"\n";

/// rewind the workspace of a session the supervisor ran with snapshots on: the run's own
/// step events and chain head, its real cgroup (gone at the end) and its real store.
#[test]
fn a_real_snapshot_run_rewinds_to_its_first_and_its_final_step() {
    if !common::delegated_cgroup_or_skip("real_snapshot_run") {
        return;
    }
    use leash::supervisor::session::{SessionSpec, run_session};

    let state = tempfile::tempdir().unwrap();
    let ws_dir = tempfile::tempdir().unwrap();
    let ws = ws_dir.path().canonicalize().unwrap();
    strip_default_acl(&ws);
    fs::write(ws.join("a.txt"), "one\n").unwrap();
    create_dir(&ws.join("sub"));
    fs::write(ws.join("sub/b.txt"), "two\n").unwrap();
    let original = tree_state(&ws);
    let policy = state.path().join("policy.toml");
    fs::write(
        &policy,
        format!(
            "{POLICY}[[fs]]\npath={:?}\nmode=[\"read\",\"write\",\"create\",\"delete\"]\naction=\"allow\"\n",
            format!("{}/**", ws.display())
        ),
    )
    .unwrap();
    let script = format!(
        "import os\nws = {ws:?}\n\
         open(ws + '/a.txt', 'w').write('changed\\n')\n\
         os.remove(ws + '/sub/b.txt')\n\
         open(ws + '/new.txt', 'w').write('new\\n')\n",
        ws = ws.display().to_string()
    );
    let outcome = run_session(SessionSpec {
        argv: vec!["/usr/bin/python3".into(), "-c".into(), script],
        mode: Mode::Enforce,
        attendance: Attendance::Unattended,
        state_root: state.path().to_path_buf(),
        state_root_spelling: state.path().to_path_buf(),
        workspace: ws.clone(),
        policy_path: Some(policy),
        ask_timeout: std::time::Duration::from_secs(60),
        snapshot_integrity: true,
    })
    .unwrap();
    let after_run = tree_state(&ws);
    assert_ne!(after_run, original, "the agent changed the workspace");

    let trace = fs::read_to_string(outcome.run_path.join("trace.jsonl")).unwrap();
    let events: Vec<Value> = trace
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let end = events.iter().find(|e| e["type"] == "run_end").unwrap();
    let final_step = end["final_step"].as_u64().unwrap();
    let chain_head = end["chain_head"].as_str().unwrap();
    assert!(final_step >= 1);

    let state_arg = state.path().to_string_lossy().into_owned();
    let id = outcome.run_id.clone();
    let rewind = |extra: &[&str]| {
        let mut args = vec!["rewind", id.as_str(), "--state-dir", state_arg.as_str()];
        args.extend_from_slice(extra);
        run_leash(&args, &ws)
    };

    let out = rewind(&["--expect", chain_head]);
    assert_success_notice(&out);
    assert_eq!(tree_state(&ws), original, "step 0 is the original tree");
    assert!(
        stdout(&out).contains(&format!("chain head: {chain_head}")),
        "{}",
        stdout(&out)
    );

    let out = rewind(&["--step", &final_step.to_string()]);
    assert_success_notice(&out);
    assert_eq!(
        tree_state(&ws),
        after_run,
        "the final step is the end state"
    );
}
