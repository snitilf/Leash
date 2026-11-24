//! the run cgroup of a snapshot run (ADR-0024 decisions 2, 11, 12, 17).
//!
//! these tests need a delegated cgroup v2: a cgroup this process may create children in,
//! with working `cgroup.freeze` and `cgroup.kill`. without one they skip and say why. with
//! `LEASH_REQUIRE_FREEZER=1` they fail instead, which is how the CI leg that provisions a
//! delegated cgroup proves they ran. to run them locally, as root create a cgroup, chown it
//! to the test user, move the test shell into it, and run `cargo test` from that shell:
//!
//! ```sh
//! sudo mkdir /sys/fs/cgroup/leash-dev && sudo chown -R $USER /sys/fs/cgroup/leash-dev
//! echo $$ | sudo tee /sys/fs/cgroup/leash-dev/cgroup.procs
//! LEASH_REQUIRE_FREEZER=1 cargo test --test run_cgroup_linux
//! ```
//!
//! every test forks, so all of them serialize under one lock.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use leash::recorder::{Attendance, Mode, TraceSink, TraceWriter, generate_run_id};
use leash::sandbox::filter::build_filter;
use leash::supervisor::run::{RunConfig, RunError, run_loop};
use leash::supervisor::run_cgroup::{CgroupParent, RunCgroup, cleanup_stale, run_cgroup_gone};
use leash::supervisor::session::{ExitDisposition, SessionError, SessionSpec, run_session};
use leash::supervisor::spawn::{SpawnError, SpawnSpec, spawn_in_cgroup_with_filter};

static SPAWN_LOCK: Mutex<()> = Mutex::new(());

fn spawn_lock() -> MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

const POLICY: &str = "schema_version = 1\n\
    [[fs]]\npath=\"/**\"\nmode=[\"read\"]\naction=\"allow\"\n\
    [[exec]]\nbinary=\"/**\"\naction=\"allow\"\n";

/// Leash's own cgroup, the way the agent sees it: the `0::` line of /proc/self/cgroup.
fn own_cgroup() -> String {
    std::fs::read_to_string("/proc/self/cgroup")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .unwrap()
        .to_string()
}

struct Session {
    state: tempfile::TempDir,
    ws: tempfile::TempDir,
}

impl Session {
    fn new() -> Self {
        let state = tempfile::tempdir().unwrap();
        std::fs::write(state.path().join("policy.toml"), POLICY).unwrap();
        Self {
            state,
            ws: tempfile::tempdir().unwrap(),
        }
    }

    fn run(&self, argv: &[&str]) -> Result<RunResult, SessionError> {
        let outcome = run_session(SessionSpec {
            argv: argv.iter().map(ToString::to_string).collect(),
            mode: Mode::Enforce,
            attendance: Attendance::Unattended,
            state_root: self.state.path().to_path_buf(),
            workspace: self.ws.path().to_path_buf(),
            policy_path: Some(self.state.path().join("policy.toml")),
            ask_timeout: Duration::from_secs(60),
            snapshot_integrity: true,
        })?;
        Ok(RunResult {
            exit: outcome.exit,
            events: trace_events(&outcome.run_path),
            run_path: outcome.run_path,
        })
    }

    fn python(&self, script: &str) -> Result<RunResult, SessionError> {
        self.run(&["/usr/bin/python3", "-c", script])
    }
}

struct RunResult {
    exit: ExitDisposition,
    events: Vec<serde_json::Value>,
    run_path: PathBuf,
}

impl RunResult {
    fn of_type(&self, kind: &str) -> Vec<&serde_json::Value> {
        self.events.iter().filter(|e| e["type"] == kind).collect()
    }

    fn assert_exit_zero(&self) {
        assert!(
            matches!(self.exit, ExitDisposition::Exited(0)),
            "the agent script asserts its own expectations: {:?}",
            self.exit
        );
    }
}

fn trace_events(run_dir: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(run_dir.join("trace.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn recorded_cgroup(run: &RunResult) -> PathBuf {
    PathBuf::from(
        run.events[0]["run_cgroup"]
            .as_str()
            .expect("run_start names the run cgroup"),
    )
}

#[test]
fn the_agent_tree_is_in_the_run_cgroup_and_the_supervisor_and_broker_are_not() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("agent_tree_cgroup") {
        return;
    }
    let session = Session::new();
    let supervisor = own_cgroup();
    let script = format!(
        "import os, subprocess\n\
        sup = {supervisor:?}\n\
        def cg(pid):\n\
        \x20   return open('/proc/%s/cgroup' % pid).read().split('0::')[1].strip()\n\
        me = cg('self')\n\
        assert me != sup and me.rsplit('/', 1)[1].startswith('leash-'), (me, sup)\n\
        assert me.rsplit('/', 1)[0] in (sup, ''), (me, sup)\n\
        kid = subprocess.check_output(['/bin/cat', '/proc/self/cgroup']).decode()\n\
        assert kid.split('0::')[1].strip() == me, 'a descendant inherits the cgroup'\n\
        sup_pid = os.getppid()\n\
        assert cg(sup_pid) == sup, 'the supervisor stays outside'\n\
        siblings = []\n\
        for d in os.listdir('/proc'):\n\
        \x20   if d.isdigit() and int(d) != os.getpid():\n\
        \x20       try:\n\
        \x20           ppid = [l for l in open('/proc/%s/status' % d) if l.startswith('PPid:')][0].split()[1]\n\
        \x20           if int(ppid) == sup_pid:\n\
        \x20               siblings.append(d)\n\
        \x20       except (OSError, IndexError):\n\
        \x20           pass\n\
        assert siblings, 'the broker is the supervisor other child'\n\
        assert all(cg(p) == sup for p in siblings), 'the broker stays outside'\n"
    );
    let run = session.python(&script).unwrap();
    run.assert_exit_zero();

    let cgroup = recorded_cgroup(&run);
    assert_eq!(
        cgroup.file_name().unwrap().to_str().unwrap(),
        format!(
            "leash-{}",
            run.run_path.file_name().unwrap().to_str().unwrap()
        )
    );
    assert!(!cgroup.exists(), "the run cgroup is removed at run end");
    assert_eq!(own_cgroup(), supervisor, "the supervisor never moved");
    let meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(run.run_path.join("meta.json")).unwrap())
            .unwrap();
    assert_eq!(meta["run_cgroup"], run.events[0]["run_cgroup"]);
}

#[test]
fn a_backgrounded_grandchild_is_killed_at_root_exit_and_the_run_returns_promptly() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("grandchild_killed") {
        return;
    }
    let session = Session::new();
    let started = Instant::now();
    let run = session
        .run(&["/bin/sh", "-c", "sleep 30 & exit 0"])
        .unwrap();
    let elapsed = started.elapsed();
    run.assert_exit_zero();
    assert!(
        elapsed < Duration::from_secs(15),
        "the run must not wait for the backgrounded sleep: {elapsed:?}"
    );
    let kills = run.of_type("cgroup_kill");
    assert_eq!(kills.len(), 1, "{:?}", run.events);
    assert_eq!(kills[0]["reason"], "run_end");
    assert!(
        kills[0]["processes"].as_u64().unwrap() >= 1,
        "the leftover sleep is counted: {:?}",
        kills[0]
    );
    assert!(kills[0].get("error").is_none());
    let kill_seq = kills[0]["seq"].as_u64().unwrap();
    let end_seq = run.of_type("run_end")[0]["seq"].as_u64().unwrap();
    assert!(kill_seq < end_seq, "the kill is recorded before run_end");
    assert!(
        !recorded_cgroup(&run).exists(),
        "an empty run cgroup is removed"
    );
}

/// a sink that fails exactly once, on the write that records the second `sleep` exec, then
/// keeps recording: the abort path's own event must still be visible to the test.
struct TripSink {
    lines: Arc<Mutex<Vec<String>>>,
    sleeps: usize,
}

impl Write for TripSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let text = String::from_utf8_lossy(buf).into_owned();
        if text.contains("\"execve\"") && text.contains("sleep") {
            self.sleeps += 1;
            if self.sleeps == 2 {
                return Err(io::Error::other("disk gone"));
            }
        }
        self.lines.lock().unwrap().push(text);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TraceSink for TripSink {
    fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn an_abort_kills_the_whole_tree_and_removes_the_cgroup() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("abort_kills_tree") {
        return;
    }
    let parent = CgroupParent::locate().unwrap();
    let id = generate_run_id(SystemTime::now()).unwrap();
    let cgroup = RunCgroup::create(&parent, &id).unwrap();
    let path = cgroup.path().to_path_buf();
    let child = spawn_in_cgroup_with_filter(
        &SpawnSpec {
            argv: vec![
                "/bin/sh".into(),
                "-c".into(),
                "sleep 30 & sleep 30 & wait".into(),
            ],
            stdout: None,
            mode: Mode::RecordOnly,
            landlock_ruleset: None,
        },
        &build_filter(),
        cgroup,
    )
    .unwrap();
    let root = child.pid as u32;
    let lines = Arc::new(Mutex::new(Vec::new()));
    let mut writer = TraceWriter::new(TripSink {
        lines: Arc::clone(&lines),
        sleeps: 0,
    });
    let started = Instant::now();
    let result = run_loop(
        child,
        RunConfig::record_only(root, Attendance::Unattended),
        &mut writer,
    );
    assert!(
        matches!(result, Err(RunError::Recorder(_))),
        "the trace failure aborts the run: {result:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "the sleeping tree is killed, not waited for"
    );
    assert!(
        !path.exists(),
        "rmdir only succeeds when every process of the tree is gone"
    );
    let recorded = lines.lock().unwrap().join("");
    assert!(
        recorded.contains("\"cgroup_kill\"") && recorded.contains("\"reason\":\"abort\""),
        "the abort records the cgroup kill: {recorded}"
    );
}

#[test]
fn a_cgroup_that_cannot_be_entered_aborts_before_the_agent_runs() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("attach_failure") {
        return;
    }
    let parent = CgroupParent::locate().unwrap();
    let id = generate_run_id(SystemTime::now()).unwrap();
    let cgroup = RunCgroup::create(&parent, &id).unwrap();
    // the pinned descriptor outlives the directory, and clone3 refuses to enter it
    std::fs::remove_dir(cgroup.path()).unwrap();
    let marker = tempfile::tempdir().unwrap().keep().join("agent-ran");
    let result = spawn_in_cgroup_with_filter(
        &SpawnSpec {
            argv: vec![
                "/bin/sh".into(),
                "-c".into(),
                format!("touch {}", marker.display()),
            ],
            stdout: None,
            mode: Mode::RecordOnly,
            landlock_ruleset: None,
        },
        &build_filter(),
        cgroup,
    );
    assert!(
        matches!(result, Err(SpawnError::Fork(_))),
        "no child is created: {result:?}"
    );
    assert!(!marker.exists(), "the agent never ran");
}

#[test]
fn a_parent_cgroup_that_is_not_writable_refuses_before_any_run_directory() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("not_writable") {
        return;
    }
    // SAFETY: geteuid takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping not_writable: root ignores directory permissions");
        return;
    }
    let parent = CgroupParent::locate().unwrap();
    let dir = parent.path().to_path_buf();
    struct Restore(PathBuf);
    impl Drop for Restore {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
        }
    }
    let _restore = Restore(dir.clone());
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    }
    let session = Session::new();
    let error = session
        .run(&["/bin/true"])
        .err()
        .expect("an unwritable parent refuses");
    assert!(matches!(error, SessionError::RunCgroup(_)), "{error:?}");
    let text = error.to_string();
    assert!(
        text.contains("systemd-run --user --scope -p Delegate=yes"),
        "the refusal names the delegation hint: {text}"
    );
    assert!(
        !session.state.path().join("runs").exists(),
        "refused before any run directory exists"
    );
}

#[test]
fn the_attach_descriptor_and_run_lock_do_not_survive_into_the_agent() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("fd_leak") {
        return;
    }
    let session = Session::new();
    let run = session
        .python(
            "import os\n\
            for fd in os.listdir('/proc/self/fd'):\n\
            \x20   try:\n\
            \x20       target = os.readlink('/proc/self/fd/' + fd)\n\
            \x20   except OSError:\n\
            \x20       continue\n\
            \x20   assert 'cgroup' not in target and 'leash-' not in target, (fd, target)\n\
            \x20   assert not target.endswith('run.lock'), (fd, target)\n\
            \x20   assert int(fd) <= 2 or target.startswith('/proc'), (fd, target)\n",
        )
        .unwrap();
    run.assert_exit_zero();
}

/// the agent's own writes to the cgroup control files are denied. today the layer that
/// denies them is the ordinary enforce policy (no write grant, seccomp and Landlock); the
/// implicit cgroup2 deny of ADR-0024 decision 4 is a follow-up slice.
#[test]
fn the_agent_cannot_write_cgroup_procs_or_freeze_under_the_default_policy() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("agent_cgroup_writes") {
        return;
    }
    let session = Session::new();
    let supervisor = own_cgroup();
    let script = format!(
        "import os\n\
        sup = '/sys/fs/cgroup' + {supervisor:?}\n\
        me = '/sys/fs/cgroup' + open('/proc/self/cgroup').read().split('0::')[1].strip()\n\
        for directory in (me, sup):\n\
        \x20   for name in ('cgroup.procs', 'cgroup.freeze', 'cgroup.kill'):\n\
        \x20       try:\n\
        \x20           os.open(directory.rstrip('/') + '/' + name, os.O_WRONLY)\n\
        \x20       except PermissionError:\n\
        \x20           continue\n\
        \x20       raise SystemExit('write open of %s/%s was allowed' % (directory, name))\n"
    );
    let run = session.python(&script).unwrap();
    run.assert_exit_zero();
    let denied: Vec<_> = run
        .events
        .iter()
        .filter(|e| {
            e["type"] == "syscall"
                && e["decision"] == "deny"
                && e["fact"]["path"]
                    .as_str()
                    .is_some_and(|p| p.contains("/cgroup."))
        })
        .collect();
    assert_eq!(denied.len(), 6, "{denied:?}");
}

/// a policy that grants write on the cgroup2 mount overlaps the control plane, which the
/// run must refuse before spawn (ADR-0024 decision 5), but that refusal is a follow-up
/// slice, so today the grant is honored and the agent could move itself out.
#[test]
#[ignore = "ADR-0024 decisions 4 and 5: the cgroup2 implicit deny and the overlap refusal are a follow-up slice"]
fn a_policy_grant_that_overlaps_the_cgroup_control_plane_is_refused() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("overlap_refused") {
        return;
    }
    let session = Session::new();
    std::fs::write(
        session.state.path().join("policy.toml"),
        format!(
            "{POLICY}[[fs]]\npath=\"/sys/fs/cgroup/**\"\nmode=[\"read\", \"write\"]\naction=\"allow\"\n"
        ),
    )
    .unwrap();
    let result = session.run(&["/bin/true"]);
    assert!(
        result.is_err(),
        "a write grant over a cgroup2 mount is refused before spawn"
    );
}

/// a leftover run cgroup: a `leash-<id>` directory holding a sleeping process, plus the run
/// directory whose lock says whether that run is alive. dropping it cleans up.
struct Leftover {
    cgroup: PathBuf,
    sleeper: Child,
}

impl Leftover {
    fn new(parent: &CgroupParent, name: &str) -> Self {
        let cgroup = parent.path().join(name);
        std::fs::create_dir(&cgroup).unwrap();
        let sleeper = Command::new("/bin/sleep").arg("60").spawn().unwrap();
        std::fs::write(cgroup.join("cgroup.procs"), sleeper.id().to_string()).unwrap();
        Self { cgroup, sleeper }
    }

    fn sleeper_alive(&mut self) -> bool {
        self.sleeper.try_wait().unwrap().is_none()
    }
}

impl Drop for Leftover {
    fn drop(&mut self) {
        let _ = std::fs::write(self.cgroup.join("cgroup.kill"), "1");
        let _ = self.sleeper.kill();
        let _ = self.sleeper.wait();
        for _ in 0..200 {
            if std::fs::remove_dir(&self.cgroup).is_ok() || !self.cgroup.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

fn dead_run_dir(state_root: &Path, id: &str) -> PathBuf {
    let dir = state_root.join("runs").join(id);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("run.lock"), "").unwrap();
    dir
}

#[test]
fn a_stale_cgroup_from_a_dead_run_is_cleaned_at_the_next_run() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("stale_cleanup") {
        return;
    }
    let session = Session::new();
    let parent = CgroupParent::locate().unwrap();
    let id = generate_run_id(SystemTime::now()).unwrap();
    dead_run_dir(session.state.path(), &id);
    let mut stale = Leftover::new(&parent, &format!("leash-{id}"));
    assert!(stale.sleeper_alive());

    let run = session.run(&["/bin/true"]).unwrap();
    run.assert_exit_zero();

    let kills = run.of_type("cgroup_kill");
    let cleanup: Vec<_> = kills
        .iter()
        .filter(|e| e["reason"] == "stale_cleanup")
        .collect();
    assert_eq!(cleanup.len(), 1, "{:?}", run.events);
    assert_eq!(cleanup[0]["cgroup"], format!("leash-{id}"));
    assert_eq!(cleanup[0]["processes"], 1);
    assert!(cleanup[0].get("error").is_none(), "{:?}", cleanup[0]);
    assert!(!stale.cgroup.exists(), "the stale cgroup is removed");
    stale.sleeper.wait().unwrap();
    assert!(
        run_cgroup_gone(&stale.cgroup, &id).unwrap(),
        "rewind's check sees the stale cgroup gone"
    );
}

#[test]
fn a_cgroup_whose_lock_is_held_or_unprovable_is_left_alone() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("stale_untouched") {
        return;
    }
    let session = Session::new();
    let parent = CgroupParent::locate().unwrap();

    // 1: a live run, its lock held by another open file description
    let live_id = generate_run_id(SystemTime::now()).unwrap();
    let live_dir = dead_run_dir(session.state.path(), &live_id);
    let lock = std::fs::File::open(live_dir.join("run.lock")).unwrap();
    // SAFETY: the descriptor is open for the call; flock reads no memory.
    assert_eq!(
        unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) },
        0
    );
    let mut live = Leftover::new(&parent, &format!("leash-{live_id}"));

    // 2: a valid name with no run directory under this state root
    let mut orphan = Leftover::new(&parent, "leash-20200101T000000Z-aaaaaa");

    // 3: a name that does not validate, even with a matching run directory
    let mut bogus = Leftover::new(&parent, "leash-not-a-run-id");
    dead_run_dir(session.state.path(), "not-a-run-id");

    let run = session.run(&["/bin/true"]).unwrap();
    run.assert_exit_zero();
    assert!(
        run.of_type("cgroup_kill")
            .iter()
            .all(|e| e["reason"] != "stale_cleanup"),
        "nothing was provably dead: {:?}",
        run.events
    );
    for left in [&mut live, &mut orphan, &mut bogus] {
        assert!(
            left.cgroup.exists(),
            "{} was touched",
            left.cgroup.display()
        );
        assert!(left.sleeper_alive(), "{} was killed", left.cgroup.display());
    }

    // the library function agrees, and the lock is the only thing that changes the answer
    let events = cleanup_stale(&parent, session.state.path(), None).unwrap();
    assert!(events.is_empty(), "{events:?}");
    drop(lock);
    let events = cleanup_stale(&parent, session.state.path(), None).unwrap();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].cgroup, format!("leash-{live_id}"));
    live.sleeper.wait().unwrap();
    assert!(!live.cgroup.exists());
}
