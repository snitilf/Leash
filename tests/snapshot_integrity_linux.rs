//! the protection of a snapshot-integrity enforce run (ADR-0024 decisions 4, 5 and 6): the
//! implicit deny of every cgroup2 mount, the refusal of a policy whose Landlock grants could
//! change the state root or a cgroup2 mount, and the refusal of a host whose Landlock ABI is
//! below 3.
//!
//! the tests that run an agent need a delegated cgroup v2 (see `run_cgroup_linux.rs` for how
//! to make one); without one they skip and say why, and with `LEASH_REQUIRE_FREEZER=1` they
//! fail instead. the refusal tests run before any cgroup is touched, so they need none.
//! every test forks, so all of them serialize under one lock.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use leash::recorder::{Attendance, Mode};
use leash::supervisor::cgroup_mounts::CgroupMounts;
use leash::supervisor::preflight;
use leash::supervisor::session::{
    ExitDisposition, SessionError, SessionHooks, SessionSpec, run_session, run_session_with_hooks,
};

static SPAWN_LOCK: Mutex<()> = Mutex::new(());

fn spawn_lock() -> MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

const POLICY: &str = "schema_version = 1\n\
    [[fs]]\npath=\"/**\"\nmode=[\"read\"]\naction=\"allow\"\n\
    [[exec]]\nbinary=\"/**\"\naction=\"allow\"\n";

const CGROUP_RULE: &str = "implicit:cgroup";
const OVERLAP_RESIDUAL: &str = "landlock:snapshot_store_read_overlap";

/// the first cgroup2 mount of this mount namespace, as the supervisor reads it.
fn mount() -> PathBuf {
    CgroupMounts::from_proc_self()
        .unwrap()
        .paths()
        .first()
        .cloned()
        .expect("this host has a cgroup2 mount")
}

/// the supervisor's own cgroup directory, the parent of every run cgroup.
fn parent_cgroup_dir() -> PathBuf {
    let own = std::fs::read_to_string("/proc/self/cgroup")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .unwrap()
        .to_string();
    mount().join(own.trim_start_matches('/'))
}

struct Session {
    state: tempfile::TempDir,
    ws: tempfile::TempDir,
    snapshot: bool,
}

impl Session {
    fn new() -> Self {
        Self::with_state(tempfile::tempdir().unwrap())
    }

    fn with_state(state: tempfile::TempDir) -> Self {
        std::fs::write(state.path().join("policy.toml"), POLICY).unwrap();
        Self {
            state,
            ws: tempfile::tempdir().unwrap(),
            snapshot: true,
        }
    }

    /// the same session without snapshot integrity, as a plain enforce run.
    fn plain() -> Self {
        Self {
            snapshot: false,
            ..Self::new()
        }
    }

    fn write_policy(&self, policy: &str) {
        std::fs::write(self.state.path().join("policy.toml"), policy).unwrap();
    }

    fn ws(&self) -> PathBuf {
        self.ws.path().to_path_buf()
    }

    fn spec(&self, argv: &[&str]) -> SessionSpec {
        SessionSpec {
            argv: argv.iter().map(ToString::to_string).collect(),
            mode: Mode::Enforce,
            attendance: Attendance::Unattended,
            state_root: self.state.path().to_path_buf(),
            state_root_spelling: self.state.path().to_path_buf(),
            workspace: self.ws.path().to_path_buf(),
            policy_path: Some(self.state.path().join("policy.toml")),
            ask_timeout: Duration::from_secs(60),
            snapshot_integrity: self.snapshot,
        }
    }

    fn run(&self, argv: &[&str]) -> Result<Run, SessionError> {
        finish(run_session(self.spec(argv))?)
    }

    fn python(&self, script: &str) -> Result<Run, SessionError> {
        self.run(&["/usr/bin/python3", "-c", script])
    }

    /// no run directory was created, which is what "refused before spawn" means here.
    fn assert_no_run_directory(&self) {
        assert!(
            !self.state.path().join("runs").exists(),
            "a refused run must not create a run directory"
        );
    }
}

struct Run {
    exit: ExitDisposition,
    events: Vec<serde_json::Value>,
}

fn finish(outcome: leash::supervisor::session::SessionOutcome) -> Result<Run, SessionError> {
    let events = std::fs::read_to_string(outcome.run_path.join("trace.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    Ok(Run {
        exit: outcome.exit,
        events,
    })
}

impl Run {
    fn assert_exit_zero(&self) {
        assert!(
            matches!(self.exit, ExitDisposition::Exited(0)),
            "the agent script asserts its own expectations: {:?}",
            self.exit
        );
    }

    fn run_cgroup(&self) -> PathBuf {
        PathBuf::from(self.events[0]["run_cgroup"].as_str().unwrap())
    }

    fn residuals(&self) -> Vec<String> {
        self.events[0]["landlock_residuals"]
            .as_array()
            .map(|a| a.iter().map(|v| v.as_str().unwrap().to_string()).collect())
            .unwrap_or_default()
    }

    fn rule_events(&self, rule: &str) -> Vec<&serde_json::Value> {
        self.events
            .iter()
            .filter(|e| e["matched_rule"] == rule)
            .collect()
    }

    /// is there a deny decided by `rule` for a syscall starting with one of `syscalls`,
    /// whose fact `field` is `value`?
    fn has_deny(&self, rule: &str, syscalls: &[&str], field: &str, value: &Path) -> bool {
        let value = value.to_string_lossy();
        self.events.iter().any(|e| {
            e["decision"] == "deny"
                && e["matched_rule"] == rule
                && e["syscall"]
                    .as_str()
                    .is_some_and(|s| syscalls.iter().any(|prefix| s.starts_with(prefix)))
                && e["fact"][field] == value.as_ref()
        })
    }

    fn denies_seen(&self) -> Vec<&serde_json::Value> {
        self.events
            .iter()
            .filter(|e| e["decision"] == "deny")
            .collect()
    }
}

/// python that runs in the agent and defines `mount`, `own` (its run cgroup directory),
/// `parent` (the supervisor's cgroup directory) and `denied(fn, what)`, which passes only
/// when the call fails with the EACCES the supervisor answers a denial with.
fn agent_prelude() -> String {
    format!(
        "import errno, os\n\
         mount = {mount:?}\n\
         parent = {parent:?}\n\
         me = open('/proc/%d/cgroup' % os.getpid()).read().split('0::')[1].strip()\n\
         own = (mount + '/' + me.lstrip('/')).rstrip('/')\n\
         def denied(fn, what):\n\
         \x20   try:\n\
         \x20       fn()\n\
         \x20   except OSError as e:\n\
         \x20       assert e.errno == errno.EACCES, (what, e)\n\
         \x20       return\n\
         \x20   raise SystemExit('was allowed: ' + what)\n",
        mount = mount().to_string_lossy(),
        parent = parent_cgroup_dir().to_string_lossy(),
    )
}

fn delegated(test: &str) -> bool {
    common::delegated_cgroup_or_skip(test)
}

// --- decision 4: the implicit cgroup2 deny ---

#[test]
fn the_agent_cannot_open_list_or_stat_open_anything_under_the_cgroup_mount() {
    let _guard = spawn_lock();
    if !delegated("cgroup_reads") {
        return;
    }
    let session = Session::new();
    let script = format!(
        "{}\
         files = [d + '/' + n for d in (own, parent) for n in ('cgroup.procs', 'cgroup.freeze', 'cgroup.kill')]\n\
         for p in files:\n\
         \x20   denied(lambda: os.close(os.open(p, os.O_RDONLY)), 'open ' + p)\n\
         \x20   denied(lambda: os.close(os.open(p, os.O_PATH)), 'stat-open ' + p)\n\
         for d in (own, parent, mount):\n\
         \x20   denied(lambda: os.listdir(d), 'list ' + d)\n\
         \x20   denied(lambda: os.close(os.open(d, os.O_PATH | os.O_DIRECTORY)), 'stat-open ' + d)\n",
        agent_prelude()
    );
    let run = session.python(&script).unwrap();
    run.assert_exit_zero();

    let own = run.run_cgroup();
    let parent = parent_cgroup_dir();
    for dir in [&own, &parent] {
        for name in ["cgroup.procs", "cgroup.freeze", "cgroup.kill"] {
            let path = dir.join(name);
            assert!(
                run.has_deny(CGROUP_RULE, &["open"], "path", &path),
                "no {CGROUP_RULE} deny for {}: {:#?}",
                path.display(),
                run.denies_seen()
            );
        }
    }
    for dir in [own, parent, mount()] {
        assert!(
            run.has_deny(CGROUP_RULE, &["open"], "path", &dir),
            "no {CGROUP_RULE} deny for {}: {:#?}",
            dir.display(),
            run.denies_seen()
        );
    }
}

#[test]
fn the_agent_cannot_move_or_alter_an_ancestor_of_the_cgroup_mount() {
    let _guard = spawn_lock();
    if !delegated("cgroup_ancestors") {
        return;
    }
    let session = Session::new();
    std::fs::write(session.ws().join("f"), b"x").unwrap();
    let ancestor = mount().parent().unwrap().to_path_buf();
    let script = format!(
        "{}\
         anc = {ancestor:?}\n\
         ws = {ws:?}\n\
         denied(lambda: os.chmod(anc, 0o755), 'chmod ancestor')\n\
         denied(lambda: os.rename(anc, anc + '-moved'), 'rename ancestor')\n\
         denied(lambda: os.rename(ws + '/f', anc), 'rename onto ancestor')\n\
         denied(lambda: os.rmdir(anc), 'rmdir ancestor')\n",
        agent_prelude(),
        ancestor = ancestor.to_string_lossy(),
        ws = session.ws().to_string_lossy(),
    );
    let run = session.python(&script).unwrap();
    run.assert_exit_zero();
    assert!(run.has_deny(CGROUP_RULE, &["chmod", "fchmodat"], "path", &ancestor));
    assert!(run.has_deny(CGROUP_RULE, &["rename"], "path", &ancestor));
    assert!(run.has_deny(CGROUP_RULE, &["rename"], "dest", &ancestor));
    assert!(run.has_deny(CGROUP_RULE, &["rmdir", "unlinkat"], "path", &ancestor));
    assert!(session.ws().join("f").exists(), "the file was not moved");
}

/// one escape test per operation the agent could use to change the run cgroup's metadata or
/// plant a sibling run cgroup: `statement` runs in the agent and must be denied, and the trace
/// must hold a deny for `syscalls` on the path `expected` names, decided by `implicit:cgroup`.
fn escape(test: &str, statement: &str, syscalls: &[&str], expected: impl Fn(&Run) -> PathBuf) {
    let _guard = spawn_lock();
    if !delegated(test) {
        return;
    }
    let session = Session::new();
    let script = format!("{}{statement}", agent_prelude());
    let run = session.python(&script).unwrap();
    run.assert_exit_zero();
    let path = expected(&run);
    assert!(
        run.has_deny(CGROUP_RULE, syscalls, "path", &path),
        "{test}: no {CGROUP_RULE} deny {syscalls:?} for {}; denies seen: {:#?}",
        path.display(),
        run.denies_seen()
    );
}

#[test]
fn mkdir_of_a_fake_run_cgroup_sibling_is_denied() {
    // the parent cgroup is where Leash's stale cleanup looks for dead runs, so a planted
    // leash-<id> directory there holding same-uid processes would be killed by a later run
    escape(
        "mkdir_fake_sibling",
        "fake = parent + '/leash-20200101T000000Z-deadbeef'\n\
         denied(lambda: os.mkdir(fake), 'mkdir ' + fake)\n",
        &["mkdir"],
        |_| parent_cgroup_dir().join("leash-20200101T000000Z-deadbeef"),
    );
}

#[test]
fn rmdir_of_the_run_cgroup_is_denied() {
    escape(
        "rmdir_run_cgroup",
        "denied(lambda: os.rmdir(own), 'rmdir ' + own)\n",
        &["rmdir", "unlinkat"],
        Run::run_cgroup,
    );
}

#[test]
fn chmod_of_a_cgroup_control_file_is_denied() {
    escape(
        "chmod_control_file",
        "denied(lambda: os.chmod(own + '/cgroup.procs', 0o666), 'chmod')\n",
        &["chmod", "fchmodat"],
        |run| run.run_cgroup().join("cgroup.procs"),
    );
}

#[test]
fn chown_of_the_run_cgroup_is_denied() {
    escape(
        "chown_run_cgroup",
        "denied(lambda: os.chown(own, os.getuid(), os.getgid()), 'chown')\n",
        &["chown", "fchownat"],
        Run::run_cgroup,
    );
}

#[test]
fn setxattr_of_the_run_lock_is_denied() {
    escape(
        "setxattr_run_lock",
        "denied(lambda: os.setxattr(own, 'user.leash.lock', b'0:0'), 'setxattr')\n",
        &["setxattr"],
        Run::run_cgroup,
    );
}

#[test]
fn removexattr_of_the_run_lock_is_denied() {
    escape(
        "removexattr_run_lock",
        "denied(lambda: os.removexattr(own, 'user.leash.lock'), 'removexattr')\n",
        &["removexattr"],
        Run::run_cgroup,
    );
}

#[test]
fn utimensat_of_a_cgroup_control_file_is_denied() {
    escape(
        "utimensat_control_file",
        "denied(lambda: os.utime(own + '/cgroup.procs', (1, 1)), 'utime')\n",
        &["utimensat", "utimes", "utime", "futimesat"],
        |run| run.run_cgroup().join("cgroup.procs"),
    );
}

#[test]
fn the_same_metadata_calls_on_a_workspace_file_are_allowed_and_recorded() {
    let _guard = spawn_lock();
    if !delegated("metadata_in_workspace") {
        return;
    }
    let session = Session::new();
    let file = session.ws().join("f");
    std::fs::write(&file, b"x").unwrap();
    let script = format!(
        "import errno, os\n\
         f = {file:?}\n\
         os.chmod(f, 0o600)\n\
         os.chown(f, os.getuid(), os.getgid())\n\
         os.utime(f, (5, 7))\n\
         assert os.stat(f).st_mtime == 7\n\
         assert os.stat(f).st_mode & 0o777 == 0o600\n\
         fd = os.open(f, os.O_RDWR)\n\
         os.fchmod(fd, 0o640)\n\
         os.utime(fd, (9, 11))\n\
         assert os.stat(f).st_mtime == 11\n\
         assert os.stat(f).st_mode & 0o777 == 0o640\n\
         try:\n\
         \x20   os.setxattr(f, 'user.leash.test', b'1')\n\
         \x20   os.removexattr(f, 'user.leash.test')\n\
         except OSError as e:\n\
         \x20   assert e.errno == errno.ENOTSUP, e\n",
        file = file.to_string_lossy(),
    );
    let run = session.python(&script).unwrap();
    run.assert_exit_zero();
    assert!(
        run.rule_events(CGROUP_RULE).is_empty(),
        "nothing outside the cgroup mount is denied by it"
    );
    for syscalls in [
        &["chmod", "fchmodat"][..],
        &["chown", "fchownat"],
        &["utimensat"],
        &["fchmod"],
        &["setxattr"],
    ] {
        assert!(
            run.events.iter().any(|e| e["decision"] == "allow"
                && e["syscall"]
                    .as_str()
                    .is_some_and(|s| syscalls.iter().any(|p| s.starts_with(p)))
                && e["fact"]["path"] == file.to_string_lossy().as_ref()),
            "no allow event for {syscalls:?}: {:#?}",
            run.events
        );
    }
}

// --- decision 5: the overlap refusal ---

/// the refusal's text, asserting it is the overlap refusal and not another failure.
fn overlap_refusal(result: Result<Run, SessionError>) -> String {
    match result {
        Err(error @ SessionError::SnapshotGrantOverlap(_)) => error.to_string(),
        Err(other) => panic!("expected the overlap refusal, got: {other}"),
        Ok(_) => panic!("the run must be refused before spawn"),
    }
}

#[test]
fn a_home_write_grant_that_covers_the_state_root_is_refused_before_any_run_directory() {
    let _guard = spawn_lock();
    let home = std::env::var("HOME").expect("HOME is set");
    let state = tempfile::tempdir_in(&home).unwrap();
    let state_path = state.path().to_path_buf();
    let session = Session::with_state(state);
    session.write_policy(&format!(
        "{POLICY}[[fs]]\npath=\"~/**\"\nmode=[\"read\", \"write\"]\naction=\"allow\"\n"
    ));
    let message = overlap_refusal(session.run(&["/bin/true"]));
    assert!(message.contains("rule fs.2"), "names the rule: {message}");
    assert!(
        message.contains(&format!("beneath \"{home}\"")),
        "names the grant path: {message}"
    );
    assert!(message.contains("write"), "names the right: {message}");
    assert!(
        message.contains(&format!("state root \"{}\"", state_path.display())),
        "names the state root: {message}"
    );
    session.assert_no_run_directory();
}

#[test]
fn a_write_grant_over_sys_is_refused_for_the_cgroup_mount_it_covers() {
    let _guard = spawn_lock();
    for (mode, right) in [
        ("write", "write, truncate"),
        ("create", "make, refer"),
        ("delete", "truncate, remove, refer"),
    ] {
        let session = Session::new();
        session.write_policy(&format!(
            "{POLICY}[[fs]]\npath=\"/sys/**\"\nmode=[\"{mode}\"]\naction=\"allow\"\n"
        ));
        let message = overlap_refusal(session.run(&["/bin/true"]));
        assert!(message.contains("rule fs.2"), "{mode}: {message}");
        assert!(message.contains("beneath \"/sys\""), "{mode}: {message}");
        assert!(message.contains(right), "{mode}: {message}");
        assert!(
            message.contains(&format!("cgroup2 mount \"{}\"", mount().display())),
            "{mode}: {message}"
        );
        session.assert_no_run_directory();
    }
}

#[test]
fn a_grant_beneath_the_state_root_or_a_mount_is_refused_like_one_above_it() {
    let _guard = spawn_lock();
    let session = Session::new();
    let state = session.state.path().to_path_buf();
    for (glob, what) in [
        (format!("{}/runs/**", state.display()), "state root"),
        (format!("{}/**", mount().display()), "cgroup2 mount"),
    ] {
        session.write_policy(&format!(
            "{POLICY}[[fs]]\npath=\"{glob}\"\nmode=[\"read\", \"write\"]\naction=\"allow\"\n"
        ));
        let message = overlap_refusal(session.run(&["/bin/true"]));
        assert!(message.contains(what), "{glob}: {message}");
        session.assert_no_run_directory();
    }
}

#[test]
fn a_workspace_that_is_beneath_the_state_root_is_refused_under_the_base_rule() {
    let _guard = spawn_lock();
    let state = tempfile::tempdir().unwrap();
    std::fs::write(state.path().join("policy.toml"), POLICY).unwrap();
    let ws = state.path().join("workspace");
    std::fs::create_dir(&ws).unwrap();
    let other = Session::new();
    let mut spec = other.spec(&["/bin/true"]);
    spec.state_root = state.path().to_path_buf();
    spec.state_root_spelling = state.path().to_path_buf();
    spec.policy_path = Some(state.path().join("policy.toml"));
    spec.workspace = ws;
    let message = overlap_refusal(run_session(spec).and_then(finish));
    assert!(message.contains("rule base:workspace"), "{message}");
    assert!(!state.path().join("runs").exists());
}

#[test]
fn the_cgroup_grant_the_overlap_test_documents_is_refused_before_spawn() {
    let _guard = spawn_lock();
    let session = Session::new();
    session.write_policy(&format!(
        "{POLICY}[[fs]]\npath=\"/sys/fs/cgroup/**\"\nmode=[\"read\", \"write\"]\naction=\"allow\"\n"
    ));
    overlap_refusal(session.run(&["/bin/true"]));
    session.assert_no_run_directory();
}

#[test]
fn a_read_only_policy_runs_and_stamps_the_single_layer_residual() {
    let _guard = spawn_lock();
    if !delegated("read_overlap_residual") {
        return;
    }
    let session = Session::new();
    let run = session.run(&["/bin/true"]).unwrap();
    run.assert_exit_zero();
    let residuals = run.residuals();
    assert_eq!(
        residuals
            .iter()
            .filter(|r| r.as_str() == OVERLAP_RESIDUAL)
            .count(),
        1,
        "stamped exactly once: {residuals:?}"
    );
}

// --- decision 6: the Landlock ABI ---

#[test]
fn a_host_with_landlock_abi_2_is_refused_before_spawn() {
    let _guard = spawn_lock();
    let session = Session::new();
    let abi_2 = || -> Result<preflight::Capabilities, preflight::PreflightError> {
        let mut caps = preflight::probe()?;
        caps.landlock_abi = 2;
        Ok(caps)
    };
    let result = run_session_with_hooks(
        session.spec(&["/bin/true"]),
        SessionHooks {
            capabilities: &abi_2,
            ..SessionHooks::default()
        },
    );
    match result {
        Err(
            error @ SessionError::SnapshotLandlockAbi {
                abi: 2,
                required: 3,
            },
        ) => {
            let text = error.to_string();
            assert!(text.contains("ABI 2") && text.contains("ABI 3"), "{text}");
        }
        other => panic!("expected the ABI refusal, got {other:?}"),
    }
    session.assert_no_run_directory();

    // the same host without snapshot integrity is not refused on ABI 2
    let plain = Session::plain();
    let result = run_session_with_hooks(
        plain.spec(&["/bin/true"]),
        SessionHooks {
            capabilities: &abi_2,
            ..SessionHooks::default()
        },
    );
    assert!(result.is_ok(), "{:?}", result.err());
}

// --- other runs are unchanged ---

const READ_CONTROLLERS: &str = "import os\n\
    mount = {mount:?}\n\
    data = open(mount + '/cgroup.controllers').read()\n\
    assert isinstance(data, str)\n\
    f = {file:?}\n\
    os.utime(f, (5, 7))\n\
    os.chmod(f, 0o600)\n";

#[test]
fn a_non_snapshot_enforce_run_is_unchanged() {
    let _guard = spawn_lock();
    let session = Session::plain();
    let file = session.ws().join("f");
    std::fs::write(&file, b"x").unwrap();
    // a write grant over a cgroup2 mount is the operator's business without snapshots
    session.write_policy(&format!(
        "{POLICY}[[fs]]\npath=\"/sys/**\"\nmode=[\"write\"]\naction=\"allow\"\n"
    ));
    let script = READ_CONTROLLERS
        .replace("{mount:?}", &format!("{:?}", mount().to_string_lossy()))
        .replace("{file:?}", &format!("{:?}", file.to_string_lossy()));
    let run = session.python(&script).unwrap();
    run.assert_exit_zero();
    assert!(run.rule_events(CGROUP_RULE).is_empty());
    assert!(!run.residuals().contains(&OVERLAP_RESIDUAL.to_string()));
    assert!(
        run.events[0]["run_cgroup"].is_null(),
        "no run cgroup without snapshots"
    );
    let metadata = |e: &&serde_json::Value| {
        e["syscall"]
            .as_str()
            .is_some_and(|s| s.starts_with("utime") || s.contains("xattr"))
    };
    assert_eq!(
        run.events.iter().filter(metadata).count(),
        0,
        "the metadata calls are not trapped without snapshots"
    );
    let controllers = mount().join("cgroup.controllers");
    assert!(
        run.events.iter().any(|e| e["decision"] == "allow"
            && e["fact"]["path"] == controllers.to_string_lossy().as_ref()),
        "the cgroup file is read under the ordinary policy: {:#?}",
        run.events
    );
}

#[test]
fn a_record_only_run_is_unchanged() {
    let _guard = spawn_lock();
    let session = Session::plain();
    let file = session.ws().join("f");
    std::fs::write(&file, b"x").unwrap();
    let mut spec = session.spec(&["/usr/bin/python3", "-c", ""]);
    let script = READ_CONTROLLERS
        .replace("{mount:?}", &format!("{:?}", mount().to_string_lossy()))
        .replace("{file:?}", &format!("{:?}", file.to_string_lossy()));
    spec.argv = vec!["/usr/bin/python3".into(), "-c".into(), script];
    spec.mode = Mode::RecordOnly;
    spec.policy_path = None;
    let run = finish(run_session(spec).unwrap()).unwrap();
    run.assert_exit_zero();
    assert!(run.rule_events(CGROUP_RULE).is_empty());
    assert!(run.events[0]["landlock_residuals"].is_null());
    assert!(run.events[0]["run_cgroup"].is_null());
    assert!(
        !run.events.iter().any(|e| e["syscall"]
            .as_str()
            .is_some_and(|s| s.starts_with("utime") || s.contains("xattr"))),
        "the metadata calls are not trapped in record-only"
    );
}
