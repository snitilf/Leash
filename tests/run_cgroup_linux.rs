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

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use leash::cli::session_exit_code;
use leash::recorder::{
    AskResolution, Attendance, CgroupKillEvent, Mode, TraceSink, TraceWriter, generate_run_id,
};
use leash::sandbox::filter::build_filter;
use leash::supervisor::cgroup::{self, Cgroup};
use leash::supervisor::run::{RunConfig, RunError, run_loop};
use leash::supervisor::run_cgroup::{
    CgroupParent, RunCgroup, RunCgroupError, RunCgroupState, cleanup_stale, run_cgroup_gone,
};
use leash::supervisor::session::{
    ExitDisposition, SessionError, SessionHooks, SessionSpec, run_session, run_session_with_hooks,
};
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

    fn write_policy(&self, policy: &str) {
        std::fs::write(self.state.path().join("policy.toml"), policy).unwrap();
    }

    fn spec(&self, argv: &[&str], attendance: Attendance) -> SessionSpec {
        SessionSpec {
            argv: argv.iter().map(ToString::to_string).collect(),
            mode: Mode::Enforce,
            attendance,
            state_root: self.state.path().to_path_buf(),
            state_root_spelling: self.state.path().to_path_buf(),
            workspace: self.ws.path().to_path_buf(),
            policy_path: Some(self.state.path().join("policy.toml")),
            ask_timeout: Duration::from_secs(60),
            snapshot_integrity: true,
        }
    }

    fn run(&self, argv: &[&str]) -> Result<RunResult, SessionError> {
        let outcome = run_session(self.spec(argv, Attendance::Unattended))?;
        Ok(RunResult {
            exit: outcome.exit,
            events: trace_events(&outcome.run_path),
            run_path: outcome.run_path,
        })
    }

    fn run_with_hooks(
        &self,
        argv: &[&str],
        attendance: Attendance,
        hooks: SessionHooks<'_>,
    ) -> Result<RunResult, SessionError> {
        let outcome = run_session_with_hooks(self.spec(argv, attendance), hooks)?;
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

/// watches `parent` (the supervisor) and its direct children from outside the sandbox and
/// records each observed `(pid, cgroup_path)` pair. `/proc/<pid>/status` and
/// `/proc/<pid>/cgroup` are world-readable even for non-dumpable processes, whereas inside
/// the sandbox `implicit:supervisor_proc` denies the agent access to the supervisor's and
/// broker's `/proc/<pid>` trees.
const CHILD_CGROUP_WATCHER: &str = "import os, sys, time\n\
parent, out = sys.argv[1], sys.argv[2]\n\
seen = set()\n\
end = time.time() + 120\n\
while time.time() < end:\n\
\x20   for d in os.listdir('/proc'):\n\
\x20       if not d.isdigit():\n\
\x20           continue\n\
\x20       try:\n\
\x20           if d == parent:\n\
\x20               cg = open('/proc/%s/cgroup' % d).read().split('0::')[1].strip()\n\
\x20               seen.add((int(d), cg))\n\
\x20               continue\n\
\x20           ppid = [l for l in open('/proc/%s/status' % d) if l.startswith('PPid:')][0].split()[1]\n\
\x20           if ppid == parent:\n\
\x20               cg = open('/proc/%s/cgroup' % d).read().split('0::')[1].strip()\n\
\x20               seen.add((int(d), cg))\n\
\x20       except (OSError, IndexError):\n\
\x20           pass\n\
\x20   with open(out + '.tmp', 'w') as f:\n\
\x20       f.write(''.join('%d %s\\n' % pair for pair in sorted(seen)))\n\
\x20   os.replace(out + '.tmp', out)\n\
\x20   time.sleep(0.005)\n";

#[test]
fn the_agent_tree_is_in_the_run_cgroup_and_the_supervisor_and_broker_are_not() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("agent_tree_cgroup") {
        return;
    }
    let session = Session::new();
    let supervisor = own_cgroup();
    let watch_dir = tempfile::tempdir().unwrap();
    let watch_out = watch_dir.path().join("children");
    let mut watcher = Command::new("/usr/bin/python3")
        .args(["-c", CHILD_CGROUP_WATCHER, &std::process::id().to_string()])
        .arg(&watch_out)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !watch_out.exists() {
        assert!(Instant::now() < deadline, "watcher never started");
        std::thread::sleep(Duration::from_millis(5));
    }

    // the agent verifies itself and a descendant; supervisor and broker cgroups are observed
    // from outside the sandbox because implicit:supervisor_proc denies their /proc trees.
    let script = format!(
        "import os, subprocess, time\n\
        sup = {supervisor:?}\n\
        def cg(pid):\n\
        \x20   return open('/proc/%s/cgroup' % pid).read().split('0::')[1].strip()\n\
        me = cg(os.getpid())\n\
        assert me != sup and me.rsplit('/', 1)[1].startswith('leash-'), (me, sup)\n\
        assert me.rsplit('/', 1)[0] in (sup, ''), (me, sup)\n\
        kid = subprocess.check_output(['/bin/sh', '-c', 'cat /proc/$$/cgroup']).decode()\n\
        assert kid.split('0::')[1].strip() == me, 'a descendant inherits the cgroup'\n\
        time.sleep(0.5)\n"
    );
    let run = session.python(&script).unwrap();
    let _ = watcher.kill();
    let _ = watcher.wait();
    run.assert_exit_zero();

    let cgroup = recorded_cgroup(&run);
    let run_id = run.run_path.file_name().unwrap().to_str().unwrap();
    let expected_name = format!("leash-{run_id}");
    assert_eq!(cgroup.file_name().unwrap().to_str().unwrap(), expected_name);
    assert!(!cgroup.exists(), "the run cgroup is removed at run end");
    assert_eq!(own_cgroup(), supervisor, "the supervisor never moved");

    let expected_rel = if supervisor == "/" {
        format!("/{expected_name}")
    } else {
        format!("{supervisor}/{expected_name}")
    };
    let observed: Vec<(u32, String)> = std::fs::read_to_string(&watch_out)
        .unwrap()
        .lines()
        .map(|line| {
            let (pid, cg) = line.split_once(' ').unwrap();
            (pid.parse().unwrap(), cg.to_string())
        })
        .collect();
    // exclude the watcher itself (also a child of this test process) and group by pid so we
    // can assert each observed pid (supervisor, broker, agent, and any caught probe child)
    // was seen in exactly one cgroup and it is the expected one.
    let mut by_pid: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
    for (pid, cg) in observed {
        if pid != watcher.id() {
            by_pid.entry(pid).or_default().insert(cg);
        }
    }
    for (pid, cgs) in &by_pid {
        assert_eq!(
            cgs.len(),
            1,
            "pid {pid} must remain in a single cgroup for its lifetime: {cgs:?}"
        );
    }
    let single_cg = |cgs: BTreeSet<String>| cgs.into_iter().next().unwrap();

    let supervisor_pid = std::process::id();
    let supervisor_observed = by_pid
        .remove(&supervisor_pid)
        .expect("external watcher must observe the supervisor pid");
    assert_eq!(
        single_cg(supervisor_observed),
        supervisor,
        "supervisor must stay in {supervisor}"
    );

    let probe_prefix = format!("{}/leash-probe-", supervisor.trim_end_matches('/'));
    let children: BTreeMap<u32, String> = by_pid
        .into_iter()
        .map(|(pid, cgs)| (pid, single_cg(cgs)))
        .filter(|(_, cg)| !cg.starts_with(&probe_prefix))
        .collect();
    assert_eq!(
        children.len(),
        2,
        "expected exactly the broker and agent direct children: {children:?}"
    );
    let broker_count = children.values().filter(|cg| *cg == &supervisor).count();
    let agent_count = children.values().filter(|cg| *cg == &expected_rel).count();
    assert_eq!(
        broker_count, 1,
        "expected exactly one child (broker) in {supervisor}: {children:?}"
    );
    assert_eq!(
        agent_count, 1,
        "expected exactly one child (agent) in {expected_rel}: {children:?}"
    );

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
    assert!(kills[0].get("removal_error").is_none());
    let kill_seq = kills[0]["seq"].as_u64().unwrap();
    let end_seq = run.of_type("run_end")[0]["seq"].as_u64().unwrap();
    assert!(kill_seq < end_seq, "the kill is recorded before run_end");
    assert!(
        !recorded_cgroup(&run).exists(),
        "an empty run cgroup is removed"
    );
}

#[test]
fn nonzero_exit_and_signal_terminated_root_preserve_status_and_kill_tree() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("nonzero_and_signaled_root") {
        return;
    }
    let session = Session::new();

    // nonzero exit status is preserved (FR-22) while backgrounded descendants are killed
    let started = Instant::now();
    let nonzero = session
        .run(&["/bin/sh", "-c", "sleep 30 & exit 42"])
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(15));
    assert_eq!(nonzero.exit, ExitDisposition::Exited(42));
    assert_eq!(nonzero.exit.shell_code(), 42);
    let end = nonzero.of_type("run_end");
    assert_eq!(end.len(), 1);
    assert_eq!(end[0]["exit_code"], 42);
    assert!(end[0]["signal"].is_null());
    let kills = nonzero.of_type("cgroup_kill");
    assert_eq!(kills.len(), 1);
    assert_eq!(kills[0]["reason"], "run_end");
    assert!(kills[0]["processes"].as_u64().unwrap() >= 1);
    assert!(kills[0].get("error").is_none());
    assert!(kills[0].get("removal_error").is_none());
    assert!(!recorded_cgroup(&nonzero).exists());

    // signal-terminated root preserves the signal (128 + signal) and kills the tree
    let started = Instant::now();
    let signaled = session
        .python(
            "import os, signal, subprocess\n\
            subprocess.Popen(['/bin/sleep', '30'])\n\
            os.kill(os.getpid(), signal.SIGKILL)\n",
        )
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(15));
    assert_eq!(signaled.exit, ExitDisposition::Signaled(libc::SIGKILL));
    assert_eq!(signaled.exit.shell_code(), 128 + libc::SIGKILL);
    let end = signaled.of_type("run_end");
    assert_eq!(end.len(), 1);
    assert!(end[0]["exit_code"].is_null());
    assert_eq!(end[0]["signal"], libc::SIGKILL);
    let kills = signaled.of_type("cgroup_kill");
    assert_eq!(kills.len(), 1);
    assert_eq!(kills[0]["reason"], "run_end");
    assert!(kills[0]["processes"].as_u64().unwrap() >= 1);
    assert!(kills[0].get("error").is_none());
    assert!(kills[0].get("removal_error").is_none());
    assert!(!recorded_cgroup(&signaled).exists());
}

#[test]
fn root_exit_while_descendant_is_blocked_in_pending_notification_kills_tree() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("root_exit_pending_notif") {
        return;
    }
    let session = Session::new();
    let ws = session.ws.path().canonicalize().unwrap();
    let trigger = ws.join("trigger-ask");
    std::fs::write(&trigger, "ask").unwrap();
    let child2_pid_file = ws.join("child2.pid");
    let root_pid_file = ws.join("root.pid");
    let go_block = ws.join("go-block");
    let go_exit = ws.join("go-exit");

    session.write_policy(&format!(
        "schema_version = 1\n\
        [[fs]]\npath={:?}\nmode=[\"read\"]\naction=\"ask\"\n\
        [[fs]]\npath={:?}\nmode=[\"read\",\"write\",\"create\"]\naction=\"allow\"\n\
        [[fs]]\npath=\"/**\"\nmode=[\"read\"]\naction=\"allow\"\n\
        [[exec]]\nbinary=\"/**\"\naction=\"allow\"\n",
        trigger.to_string_lossy(),
        format!("{}/**", ws.to_string_lossy()),
    ));

    let prompter_ws = ws.clone();
    let prompter = move |_asks: &[leash::supervisor::ask::PendingAsk], _timeout: Duration| {
        let child2_pid: u32 = std::fs::read_to_string(prompter_ws.join("child2.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let root_pid: u32 = std::fs::read_to_string(prompter_ws.join("root.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();

        // tell child2 to invoke openat("/etc/hostname") while the supervisor is parked here,
        // so child2 is deterministically queued in a pending seccomp notification.
        std::fs::write(prompter_ws.join("go-block"), "1").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut blocked = false;
        while Instant::now() < deadline {
            if let Ok(wchan) = std::fs::read_to_string(format!("/proc/{child2_pid}/wchan"))
                && wchan.contains("seccomp")
            {
                blocked = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            blocked,
            "child2 must be blocked in seccomp_do_user_notification before root exits"
        );

        // now let the root process exit while child2 stays blocked in that pending notification
        std::fs::write(prompter_ws.join("go-exit"), "1").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut root_exited = false;
        while Instant::now() < deadline {
            if let Ok(stat) = std::fs::read_to_string(format!("/proc/{root_pid}/stat"))
                && stat
                    .rsplit_once(") ")
                    .is_some_and(|(_, rest)| rest.starts_with('Z'))
            {
                root_exited = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            root_exited,
            "root must reach zombie state before prompt returns"
        );
        AskResolution::Denied
    };

    let script = format!(
        "import os, time\n\
        with open({root_pid:?}, 'w') as f:\n\
        \x20   f.write(str(os.getpid()))\n\
        p2 = os.fork()\n\
        if p2 == 0:\n\
        \x20   with open({child2_pid:?}, 'w') as f:\n\
        \x20       f.write(str(os.getpid()))\n\
        \x20   while not os.path.exists({go_block:?}):\n\
        \x20       time.sleep(0.005)\n\
        \x20   try:\n\
        \x20       open('/etc/hostname').read()\n\
        \x20   except OSError:\n\
        \x20       pass\n\
        \x20   time.sleep(30)\n\
        \x20   os._exit(0)\n\
        while not os.path.exists({child2_pid:?}) or os.path.getsize({child2_pid:?}) == 0:\n\
        \x20   time.sleep(0.005)\n\
        p1 = os.fork()\n\
        if p1 == 0:\n\
        \x20   try:\n\
        \x20       open({trigger:?}).read()\n\
        \x20   except OSError:\n\
        \x20       pass\n\
        \x20   time.sleep(30)\n\
        \x20   os._exit(0)\n\
        while not os.path.exists({go_exit:?}):\n\
        \x20   time.sleep(0.005)\n\
        os._exit(0)\n",
        root_pid = root_pid_file.to_str().unwrap(),
        child2_pid = child2_pid_file.to_str().unwrap(),
        go_block = go_block.to_str().unwrap(),
        trigger = trigger.to_str().unwrap(),
        go_exit = go_exit.to_str().unwrap(),
    );

    let started = Instant::now();
    let run = session
        .run_with_hooks(
            &["/usr/bin/python3", "-c", &script],
            Attendance::Attended,
            SessionHooks {
                prompter: &prompter,
                ..SessionHooks::default()
            },
        )
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "cgroup.kill must terminate the child blocked in a pending notification promptly"
    );
    run.assert_exit_zero();
    let kills = run.of_type("cgroup_kill");
    assert_eq!(kills.len(), 1);
    assert_eq!(kills[0]["reason"], "run_end");
    assert!(kills[0]["processes"].as_u64().unwrap() >= 1);
    assert!(kills[0].get("error").is_none());
    assert!(kills[0].get("removal_error").is_none());
    assert_eq!(run.of_type("run_end").len(), 1);
    assert!(!recorded_cgroup(&run).exists());
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
fn dropping_run_cgroup_kills_live_process_tree_and_removes_cgroup() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("drop_kills_tree") {
        return;
    }
    let parent = CgroupParent::locate().unwrap();
    let id = generate_run_id(SystemTime::now()).unwrap();
    let cgroup = RunCgroup::create(&parent, &id).unwrap();
    let path = cgroup.path().to_path_buf();

    let mut shell = Command::new("/bin/sh")
        .args(["-c", "read x; sleep 60 & sleep 60 & wait"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = shell.stdin.take().unwrap();
    cgroup.cgroup().attach(shell.id()).unwrap();
    drop(stdin);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if cgroup.cgroup().members().unwrap().len() >= 3 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let members = cgroup.cgroup().members().unwrap();
    assert!(
        members.len() >= 3,
        "shell and both sleeps must be in the run cgroup before drop: {members:?}"
    );

    // dropping RunCgroup without calling kill_all or remove must kill the tree and rmdir
    drop(cgroup);

    let status = shell.wait().unwrap();
    assert!(!status.success(), "the process tree was killed on drop");
    assert!(
        !path.exists(),
        "Drop backstop killed every descendant and removed the cgroup"
    );
    let reap_deadline = Instant::now() + Duration::from_secs(2);
    for pid in members {
        let pid_t = libc::pid_t::try_from(pid).unwrap();
        loop {
            // SAFETY: signal 0 only checks whether pid still exists.
            let rc = unsafe { libc::kill(pid_t, 0) };
            if rc != 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                break;
            }
            assert!(
                Instant::now() < reap_deadline,
                "pid {pid} survived RunCgroup Drop backstop"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[test]
fn kill_timeout_fails_closed_with_exit_125_and_no_run_end() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("kill_timeout") {
        return;
    }
    let session = Session::new();
    let kill_timeout_hook = |cg: &RunCgroup, reason| {
        // kill the real tree so nothing leaks, then surface a timeout to the loop
        let _ = cg.kill_all(reason);
        CgroupKillEvent {
            reason,
            cgroup: cg.name().to_string(),
            processes: Some(1),
            error: Some("cgroup populated did not reach 0".into()),
            removal_error: None,
        }
    };
    let result = run_session_with_hooks(
        session.spec(&["/bin/true"], Attendance::Unattended),
        SessionHooks {
            kill: &kill_timeout_hook,
            ..SessionHooks::default()
        },
    );
    assert!(
        matches!(result, Err(SessionError::Run(RunError::RunCgroup(_)))),
        "kill timeout must fail closed: {result:?}"
    );
    assert_eq!(session_exit_code(result), ExitCode::from(125));

    let runs: Vec<PathBuf> = std::fs::read_dir(session.state.path().join("runs"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(runs.len(), 1);
    let events = trace_events(&runs[0]);
    let kills: Vec<_> = events
        .iter()
        .filter(|e| e["type"] == "cgroup_kill")
        .collect();
    assert_eq!(kills.len(), 1, "no duplicate abort kill event: {events:?}");
    assert_eq!(kills[0]["reason"], "run_end");
    assert!(kills[0]["error"].as_str().unwrap().contains("populated"));
    assert!(
        events.iter().all(|e| e["type"] != "run_end"),
        "a kill timeout must never stamp run_end: {events:?}"
    );
    assert!(!runs[0].join("report.txt").exists());
    let cg = PathBuf::from(events[0]["run_cgroup"].as_str().unwrap());
    assert!(!cg.exists(), "the cgroup directory was cleaned up");
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
fn a_probe_failure_refuses_before_any_run_directory_exists() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("probe_failure") {
        return;
    }
    let session = Session::new();
    let failing_probe = |_: &Path| Err(io::Error::new(io::ErrorKind::TimedOut, "freeze timed out"));
    let result = run_session_with_hooks(
        session.spec(&["/bin/true"], Attendance::Unattended),
        SessionHooks {
            probe: &failing_probe,
            ..SessionHooks::default()
        },
    );
    let error = result.as_ref().expect_err("probe failure must refuse");
    assert!(
        matches!(error, SessionError::RunCgroup(RunCgroupError::Probe { .. })),
        "{error:?}"
    );
    let text = error.to_string();
    assert!(
        text.contains("systemd-run --user --scope -p Delegate=yes"),
        "the refusal names the delegation hint: {text}"
    );
    assert!(
        !session.state.path().join("runs").exists(),
        "probe refusal must happen before any run directory exists"
    );
    assert_eq!(session_exit_code(result), ExitCode::from(125));
}

#[test]
fn probe_delegation_refuses_a_previously_killed_parent_cgroup() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("probe_killed_parent") {
        return;
    }
    let parent = CgroupParent::locate().unwrap();
    let killed_dir = parent
        .path()
        .join(format!("leash-test-killed-{}", std::process::id()));
    let _ = std::fs::remove_dir(&killed_dir);
    std::fs::create_dir(&killed_dir).unwrap();

    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::write(self.0.join("cgroup.kill"), "1");
            for _ in 0..200 {
                if std::fs::remove_dir(&self.0).is_ok() || !self.0.exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
    let _cleanup = Cleanup(killed_dir.clone());

    // increment kill_seq on killed_dir while empty
    std::fs::write(killed_dir.join("cgroup.kill"), "1").unwrap();

    // fork a helper so the test process itself never moves into the killed cgroup.
    // first measure whether a raw clone3(CLONE_INTO_CGROUP) into a fresh child of the
    // killed parent is SIGKILLed on this kernel, then assert probe_delegation refuses if
    // and only if that raw child was SIGKILLed.
    // SAFETY: fork in a single-threaded section under SPAWN_LOCK; child exits with _exit.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        #[repr(C)]
        #[derive(Default)]
        struct CloneArgs {
            flags: u64,
            pidfd: u64,
            child_tid: u64,
            parent_tid: u64,
            exit_signal: u64,
            stack: u64,
            stack_size: u64,
            tls: u64,
            set_tid: u64,
            set_tid_size: u64,
            cgroup: u64,
        }
        const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

        let exit_code = (|| -> i32 {
            if std::fs::write(
                killed_dir.join("cgroup.procs"),
                std::process::id().to_string(),
            )
            .is_err()
            {
                return 1;
            }
            let raw_dir = killed_dir.join("raw-probe");
            let _ = std::fs::remove_dir(&raw_dir);
            if std::fs::create_dir(&raw_dir).is_err() {
                return 2;
            }
            let Ok(raw_file) = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(&raw_dir)
            else {
                let _ = std::fs::remove_dir(&raw_dir);
                return 3;
            };
            let args = CloneArgs {
                flags: CLONE_INTO_CGROUP,
                exit_signal: libc::SIGCHLD as u64,
                cgroup: raw_file.as_raw_fd() as u64,
                ..CloneArgs::default()
            };
            // SAFETY: args is a live clone_args; child immediately calls _exit(0).
            let raw_pid = unsafe {
                libc::syscall(libc::SYS_clone3, &raw const args, size_of::<CloneArgs>())
                    as libc::pid_t
            };
            if raw_pid < 0 {
                drop(raw_file);
                let _ = std::fs::remove_dir(&raw_dir);
                return 4;
            }
            if raw_pid == 0 {
                // SAFETY: immediate raw exit in the clone3 child.
                unsafe { libc::_exit(0) };
            }
            let mut raw_status = 0;
            // SAFETY: waitpid on the clone3 child we just created.
            if unsafe { libc::waitpid(raw_pid, &raw mut raw_status, 0) } != raw_pid {
                drop(raw_file);
                let _ = std::fs::remove_dir(&raw_dir);
                return 5;
            }
            drop(raw_file);
            for _ in 0..200 {
                if std::fs::remove_dir(&raw_dir).is_ok() || !raw_dir.exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            let raw_sigkilled =
                libc::WIFSIGNALED(raw_status) && libc::WTERMSIG(raw_status) == libc::SIGKILL;
            let raw_exited_ok = libc::WIFEXITED(raw_status) && libc::WEXITSTATUS(raw_status) == 0;
            if !raw_sigkilled && !raw_exited_ok {
                return 6;
            }
            let probe = cgroup::probe_delegation(&killed_dir, Duration::from_secs(2));
            if probe.is_err() != raw_sigkilled {
                return if raw_sigkilled { 7 } else { 8 };
            }
            0
        })();
        // SAFETY: terminate forked helper without running destructors.
        unsafe { libc::_exit(exit_code) };
    }
    let mut status = 0;
    // SAFETY: waitpid on our forked child.
    assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
    assert!(
        status == 0,
        "probe_delegation must refuse iff raw clone3(CLONE_INTO_CGROUP) into a fresh child is SIGKILLed (wait status {status:#x})"
    );
}

#[test]
fn a_parent_cgroup_that_is_not_writable_refuses_before_any_run_directory() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("not_writable") {
        return;
    }
    let parent = CgroupParent::locate().unwrap();
    let dir = parent.path().to_path_buf();

    // SAFETY: geteuid takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        // root ignores 0o555 permissions, so test unwritable refusal from an unprivileged
        // child (nobody, uid 65534) inside the root-owned parent cgroup.
        use std::os::unix::fs::PermissionsExt;
        let session = Session::new();
        std::fs::set_permissions(session.state.path(), std::fs::Permissions::from_mode(0o777))
            .unwrap();
        std::fs::set_permissions(session.ws.path(), std::fs::Permissions::from_mode(0o777))
            .unwrap();
        let spec = session.spec(&["/bin/true"], Attendance::Unattended);
        let state_runs = session.state.path().join("runs");
        // SAFETY: fork under SPAWN_LOCK; child drops privileges and exits with _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // SAFETY: dropping privileges in our forked test child.
            let dropped = unsafe { libc::setgid(65534) == 0 && libc::setuid(65534) == 0 };
            let ok = dropped
                && match run_session(spec) {
                    Err(e @ SessionError::RunCgroup(RunCgroupError::NotWritable { .. })) => {
                        e.to_string()
                            .contains("systemd-run --user --scope -p Delegate=yes")
                            && !state_runs.exists()
                    }
                    _ => false,
                };
            // SAFETY: exit child without running parent destructors.
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        let mut status = 0;
        // SAFETY: waitpid on our forked child.
        assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
        assert_eq!(
            status, 0,
            "unprivileged child must refuse unwritable parent before creating runs/"
        );
        assert!(!state_runs.exists());
        return;
    }

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
    assert!(
        matches!(
            error,
            SessionError::RunCgroup(RunCgroupError::NotWritable { .. })
        ),
        "{error:?}"
    );
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
            // fstat answers for the agent's own descriptors; /proc/self would be resolved in
            // the broker, not here
            "import os\n\
            open_fds = []\n\
            for fd in range(3, 1024):\n\
            \x20   try:\n\
            \x20       os.fstat(fd)\n\
            \x20   except OSError:\n\
            \x20       continue\n\
            \x20   open_fds.append(fd)\n\
            assert not open_fds, open_fds\n",
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
        me = '/sys/fs/cgroup' + open('/proc/%d/cgroup' % os.getpid()).read().split('0::')[1].strip()\n\
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
    session.write_policy(&format!(
        "{POLICY}[[fs]]\npath=\"/sys/fs/cgroup/**\"\nmode=[\"read\", \"write\"]\naction=\"allow\"\n"
    ));
    let result = session.run(&["/bin/true"]);
    assert!(
        result.is_err(),
        "a write grant over a cgroup2 mount is refused before spawn"
    );
}

#[test]
fn chmod_zero_on_run_cgroup_and_controls_cannot_block_freeze_kill_or_remove() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("chmod_zero_escape") {
        return;
    }
    // SAFETY: geteuid takes no arguments.
    if unsafe { libc::geteuid() } == 0 {
        assert!(
            std::env::var("LEASH_REQUIRE_FREEZER").as_deref() != Ok("1"),
            "LEASH_REQUIRE_FREEZER=1: chmod_zero_escape must run as an unprivileged user because root ignores mode 0o000"
        );
        eprintln!("skipping chmod_zero_escape: root ignores mode 0o000");
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    let parent = CgroupParent::locate().unwrap();
    let id = generate_run_id(SystemTime::now()).unwrap();
    let mut cgroup = RunCgroup::create(&parent, &id).unwrap();
    let cg_path = cgroup.path().to_path_buf();

    let mut shell = Command::new("/bin/sh")
        .args(["-c", "read x; sleep 60 & sleep 60 & wait"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = shell.stdin.take().unwrap();
    cgroup.cgroup().attach(shell.id()).unwrap();
    drop(stdin);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if cgroup.cgroup().members().unwrap().len() >= 3 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        cgroup.cgroup().members().unwrap().len() >= 3,
        "shell and both sleeps must be live in the run cgroup"
    );

    let nested = cg_path.join("nested");
    let deep = nested.join("deep");
    std::fs::create_dir_all(&deep).unwrap();
    let mut deep_sleeper = Command::new("/bin/sleep").arg("60").spawn().unwrap();
    std::fs::write(deep.join("cgroup.procs"), deep_sleeper.id().to_string()).unwrap();
    assert!(deep_sleeper.try_wait().unwrap().is_none());

    struct Restore {
        cg: PathBuf,
        nested: PathBuf,
        deep: PathBuf,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            let mode = std::fs::Permissions::from_mode(0o700);
            let _ = std::fs::set_permissions(&self.cg, mode.clone());
            for name in [
                "cgroup.kill",
                "cgroup.freeze",
                "cgroup.events",
                "cgroup.procs",
            ] {
                let _ = std::fs::set_permissions(self.cg.join(name), mode.clone());
            }
            let _ = std::fs::set_permissions(&self.nested, mode.clone());
            let _ = std::fs::set_permissions(&self.deep, mode);
        }
    }
    let _restore = Restore {
        cg: cg_path.clone(),
        nested: nested.clone(),
        deep: deep.clone(),
    };

    // chmod 0 nested dirs, control files, and the run cgroup directory itself
    let zero = std::fs::Permissions::from_mode(0o000);
    std::fs::set_permissions(&deep, zero.clone()).unwrap();
    std::fs::set_permissions(&nested, zero.clone()).unwrap();
    for name in [
        "cgroup.kill",
        "cgroup.freeze",
        "cgroup.events",
        "cgroup.procs",
    ] {
        std::fs::set_permissions(cg_path.join(name), zero.clone()).unwrap();
    }
    std::fs::set_permissions(&cg_path, zero).unwrap();

    // confirm reopening by path is genuinely blocked by chmod 0
    let reopen_err = std::fs::OpenOptions::new()
        .write(true)
        .open(cg_path.join("cgroup.kill"))
        .unwrap_err();
    assert_eq!(reopen_err.kind(), io::ErrorKind::PermissionDenied);

    // held control descriptors and fchmod-before-removal must still freeze, thaw, kill, and remove
    cgroup
        .cgroup()
        .set_frozen(true, Duration::from_secs(2))
        .unwrap();
    cgroup
        .cgroup()
        .set_frozen(false, Duration::from_secs(2))
        .unwrap();
    cgroup.cgroup().kill(Duration::from_secs(5)).unwrap();
    cgroup.remove().unwrap();

    let shell_status = shell.wait().unwrap();
    assert!(
        !shell_status.success(),
        "shell tree must be terminated: {shell_status:?}"
    );
    let deep_status = deep_sleeper.wait().unwrap();
    assert!(
        !deep_status.success(),
        "nested/deep sleeper must be terminated: {deep_status:?}"
    );
    assert!(!deep.exists(), "chmod-0 nested/deep cgroup was removed");
    assert!(!cg_path.exists(), "chmod-0 run cgroup was removed");
}

#[test]
fn a_nested_cgroup_inside_a_live_run_cgroup_is_removed_depth_first_and_run_end_is_written() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("nested_cgroup_removal") {
        return;
    }
    let session = Session::new();
    let ws = session.ws.path().canonicalize().unwrap();
    session.write_policy(&format!(
        "{POLICY}[[fs]]\npath={:?}\nmode=[\"read\",\"write\",\"create\"]\naction=\"allow\"\n",
        format!("{}/**", ws.to_string_lossy()),
    ));
    let cg_file = ws.join("cg.txt");
    let done_file = ws.join("done");
    let cg_file_bg = cg_file.clone();
    let done_file_bg = done_file.clone();

    let helper = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let rel = loop {
            if let Ok(text) = std::fs::read_to_string(&cg_file_bg)
                && !text.trim().is_empty()
            {
                break text.trim().to_string();
            }
            assert!(Instant::now() < deadline, "agent never reported its cgroup");
            std::thread::sleep(Duration::from_millis(5));
        };
        let live_cg = Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
        let nested = live_cg.join("nested").join("deep");
        std::fs::create_dir_all(&nested).unwrap();
        let mut deep_sleeper = Command::new("/bin/sleep").arg("60").spawn().unwrap();
        std::fs::write(nested.join("cgroup.procs"), deep_sleeper.id().to_string()).unwrap();
        assert!(
            deep_sleeper.try_wait().unwrap().is_none(),
            "sleeper inside nested/deep must stay alive until run end"
        );
        std::fs::write(&done_file_bg, "1").unwrap();
        (nested, deep_sleeper)
    });

    let script = format!(
        "import os, time\n\
        cg = open('/proc/%d/cgroup' % os.getpid()).read().split('0::')[1].strip()\n\
        with open({cg_file:?}, 'w') as f:\n\
        \x20   f.write(cg)\n\
        while not os.path.exists({done_file:?}):\n\
        \x20   time.sleep(0.005)\n",
        cg_file = cg_file.to_str().unwrap(),
        done_file = done_file.to_str().unwrap(),
    );
    let run = session.python(&script).unwrap();
    let (nested, mut deep_sleeper) = helper.join().unwrap();

    run.assert_exit_zero();
    assert_eq!(run.of_type("run_end").len(), 1);
    assert_eq!(run.of_type("run_end")[0]["exit_code"], 0);
    let kills = run.of_type("cgroup_kill");
    assert_eq!(kills.len(), 1);
    assert!(kills[0].get("error").is_none());
    assert!(kills[0].get("removal_error").is_none());
    let deep_status = deep_sleeper.wait().unwrap();
    assert!(
        !deep_status.success(),
        "sleeper inside nested/deep must be killed: {deep_status:?}"
    );
    assert!(!nested.exists(), "nested descendant cgroup was removed");
    assert!(!recorded_cgroup(&run).exists(), "run cgroup was removed");
}

#[test]
fn a_failed_rmdir_after_successful_kill_records_removal_error_and_preserves_run_end() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("nonfatal_rmdir") {
        return;
    }
    // SAFETY: geteuid takes no arguments.
    if unsafe { libc::geteuid() } == 0 {
        assert!(
            std::env::var("LEASH_REQUIRE_FREEZER").as_deref() != Ok("1"),
            "LEASH_REQUIRE_FREEZER=1: nonfatal_rmdir must run as an unprivileged user because root ignores parent directory 0o555"
        );
        eprintln!("skipping nonfatal_rmdir: root ignores parent directory 0o555");
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let parent = CgroupParent::locate().unwrap();
    let parent_dir = parent.path().to_path_buf();
    let session = Session::new();
    let ws = session.ws.path().canonicalize().unwrap();
    session.write_policy(&format!(
        "{POLICY}[[fs]]\npath={:?}\nmode=[\"read\",\"write\",\"create\"]\naction=\"allow\"\n",
        format!("{}/**", ws.to_string_lossy()),
    ));

    struct Restore {
        parent: PathBuf,
        child: Option<PathBuf>,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.parent, std::fs::Permissions::from_mode(0o755));
            if let Some(child) = &self.child {
                let _ = std::fs::remove_dir(child);
            }
        }
    }
    let mut restore = Restore {
        parent: parent_dir.clone(),
        child: None,
    };

    let ready_file = ws.join("ready");
    let go_file = ws.join("go");
    let ready_bg = ready_file.clone();
    let go_bg = go_file.clone();
    let parent_bg = parent_dir.clone();

    let helper = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready_bg.exists() {
            assert!(Instant::now() < deadline, "agent never reached ready");
            std::thread::sleep(Duration::from_millis(5));
        }
        std::fs::set_permissions(&parent_bg, std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::write(&go_bg, "1").unwrap();
    });

    let script = format!(
        "import os, time\n\
        with open({ready:?}, 'w') as f:\n\
        \x20   f.write('1')\n\
        while not os.path.exists({go:?}):\n\
        \x20   time.sleep(0.005)\n",
        ready = ready_file.to_str().unwrap(),
        go = go_file.to_str().unwrap(),
    );
    let run = session.python(&script).unwrap();
    helper.join().unwrap();
    restore.child = Some(recorded_cgroup(&run));

    run.assert_exit_zero();
    let end = run.of_type("run_end");
    assert_eq!(end.len(), 1, "completed run must still stamp run_end");
    assert_eq!(end[0]["exit_code"], 0);
    let kills = run.of_type("cgroup_kill");
    assert_eq!(kills.len(), 1);
    assert!(kills[0].get("error").is_none());
    assert!(
        kills[0]["removal_error"].as_str().is_some(),
        "rmdir failure is recorded in removal_error: {:?}",
        kills[0]
    );
}

/// a leftover run cgroup: a `leash-<id>` directory holding a sleeping process, optionally
/// bound to a `run.lock` inode through `user.leash.lock`. dropping it cleans up.
struct Leftover {
    cgroup: PathBuf,
    sleeper: Child,
}

impl Leftover {
    fn new_unbound(parent: &CgroupParent, name: &str) -> Self {
        let cgroup = parent.path().join(name);
        std::fs::create_dir(&cgroup).unwrap();
        let sleeper = Command::new("/bin/sleep").arg("60").spawn().unwrap();
        std::fs::write(cgroup.join("cgroup.procs"), sleeper.id().to_string()).unwrap();
        Self { cgroup, sleeper }
    }

    fn new_bound(parent: &CgroupParent, name: &str, lock_path: &Path) -> Self {
        let left = Self::new_unbound(parent, name);
        let meta = std::fs::metadata(lock_path).unwrap();
        let identity = format!("{}:{}", meta.dev(), meta.ino());
        Cgroup::open(&left.cgroup)
            .unwrap()
            .set_lock_identity(&identity)
            .unwrap();
        left
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
        if let Ok(group) = Cgroup::open(&self.cgroup) {
            let _ = cgroup::remove_descendants(group.dir(), Duration::from_secs(2));
        }
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
    let dir = dead_run_dir(session.state.path(), &id);
    let mut stale = Leftover::new_bound(&parent, &format!("leash-{id}"), &dir.join("run.lock"));
    // add a populated nested descendant cgroup to verify stale cleanup kills processes in
    // descendants and removes the hierarchy depth-first
    let nested = stale.cgroup.join("nested").join("deep");
    std::fs::create_dir_all(&nested).unwrap();
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut deep_sleeper = ChildGuard(Command::new("/bin/sleep").arg("60").spawn().unwrap());
    std::fs::write(nested.join("cgroup.procs"), deep_sleeper.0.id().to_string()).unwrap();
    assert!(stale.sleeper_alive());
    assert!(
        deep_sleeper.0.try_wait().unwrap().is_none(),
        "sleeper inside stale nested/deep must be alive before cleanup"
    );
    assert_eq!(
        run_cgroup_gone(&stale.cgroup, &id).unwrap(),
        RunCgroupState::Present
    );

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
    assert!(
        cleanup[0].get("removal_error").is_none(),
        "{:?}",
        cleanup[0]
    );
    assert!(!nested.exists(), "nested descendant cgroup is removed");
    assert!(!stale.cgroup.exists(), "the stale cgroup is removed");
    let stale_status = stale.sleeper.wait().unwrap();
    assert!(
        !stale_status.success(),
        "stale sleeper must be killed: {stale_status:?}"
    );
    let deep_status = deep_sleeper.0.wait().unwrap();
    assert!(
        !deep_status.success(),
        "stale nested/deep sleeper must be killed: {deep_status:?}"
    );
    assert_eq!(
        run_cgroup_gone(&stale.cgroup, &id).unwrap(),
        RunCgroupState::Gone,
        "rewind's check sees the stale cgroup gone"
    );
    assert_eq!(
        run_cgroup_gone(Path::new(&format!("/nonexistent/leash-{id}")), &id).unwrap(),
        RunCgroupState::Unknown,
        "unresolvable paths never fail open as Gone"
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

    // 1: a live run, bound to its lock, with its lock held by another open file description
    let live_id = generate_run_id(SystemTime::now()).unwrap();
    let live_dir = dead_run_dir(session.state.path(), &live_id);
    let live_lock_path = live_dir.join("run.lock");
    let lock = std::fs::File::open(&live_lock_path).unwrap();
    // SAFETY: the descriptor is open for the call; flock reads no memory.
    assert_eq!(
        unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) },
        0
    );
    let mut live = Leftover::new_bound(&parent, &format!("leash-{live_id}"), &live_lock_path);

    // 2: a valid name with no run directory under this state root
    let mut orphan = Leftover::new_unbound(&parent, "leash-20200101T000000Z-aaaaaa");

    // 3: a name that does not validate, even with a matching run directory
    let mut bogus = Leftover::new_unbound(&parent, "leash-not-a-run-id");
    dead_run_dir(session.state.path(), "not-a-run-id");

    // 4: a valid name with an unlocked run.lock, but no user.leash.lock xattr on the cgroup
    let unbound_id = "20200101T000001Z-bbbbbb";
    dead_run_dir(session.state.path(), unbound_id);
    let mut unbound = Leftover::new_unbound(&parent, &format!("leash-{unbound_id}"));

    let run = session.run(&["/bin/true"]).unwrap();
    run.assert_exit_zero();
    assert!(
        run.of_type("cgroup_kill")
            .iter()
            .all(|e| e["reason"] != "stale_cleanup"),
        "nothing was provably dead: {:?}",
        run.events
    );
    for left in [&mut live, &mut orphan, &mut bogus, &mut unbound] {
        assert!(
            left.cgroup.exists(),
            "{} was touched",
            left.cgroup.display()
        );
        assert!(left.sleeper_alive(), "{} was killed", left.cgroup.display());
    }

    // the library function agrees, and releasing the live lock cleans only the bound live run
    let events = cleanup_stale(&parent, session.state.path(), None).unwrap();
    assert!(events.is_empty(), "{events:?}");
    drop(lock);
    let events = cleanup_stale(&parent, session.state.path(), None).unwrap();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].cgroup, format!("leash-{live_id}"));
    live.sleeper.wait().unwrap();
    assert!(!live.cgroup.exists());
    assert!(unbound.cgroup.exists() && unbound.sleeper_alive());
}

#[test]
fn a_copied_run_directory_with_unlocked_lock_does_not_kill_a_live_run() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("copied_state_root") {
        return;
    }
    let parent = CgroupParent::locate().unwrap();
    let live_state = tempfile::tempdir().unwrap();
    let live_id = generate_run_id(SystemTime::now()).unwrap();
    let live_dir = dead_run_dir(live_state.path(), &live_id);
    let live_lock_path = live_dir.join("run.lock");
    let _held_lock = std::fs::File::open(&live_lock_path).unwrap();
    // SAFETY: descriptor is open for flock.
    assert_eq!(
        unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&_held_lock), libc::LOCK_EX) },
        0
    );
    let mut live = Leftover::new_bound(&parent, &format!("leash-{live_id}"), &live_lock_path);

    // `cp -a` copies the state root to a new directory with a fresh unlocked run.lock inode
    let copied_parent = tempfile::tempdir().unwrap();
    let copied_state = copied_parent.path().join("state-copy");
    let status = Command::new("cp")
        .args(["-a"])
        .arg(live_state.path())
        .arg(&copied_state)
        .status()
        .unwrap();
    assert!(status.success(), "cp -a must succeed");

    let events = cleanup_stale(&parent, &copied_state, None).unwrap();
    assert!(
        events.is_empty(),
        "copied run.lock inode must not match user.leash.lock: {events:?}"
    );
    assert!(live.cgroup.exists(), "live cgroup must not be removed");
    assert!(live.sleeper_alive(), "live process must not be killed");
}

#[test]
fn cleanup_stale_isolates_fifo_and_symlink_errors_and_still_cleans_valid_stale_cgroups() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("cleanup_stale_isolation") {
        return;
    }
    let parent = CgroupParent::locate().unwrap();
    let state = tempfile::tempdir().unwrap();

    // 1: planted FIFO at runs/<fifo_id>/run.lock
    let fifo_id = "20200102T000001Z-aaaaaa";
    let fifo_dir = state.path().join("runs").join(fifo_id);
    std::fs::create_dir_all(&fifo_dir).unwrap();
    let fifo_path = CString::new(fifo_dir.join("run.lock").to_str().unwrap()).unwrap();
    // SAFETY: fifo_path is a nul-terminated path in our tempdir.
    assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
    let mut fifo_cg = Leftover::new_unbound(&parent, &format!("leash-{fifo_id}"));

    // 2: symlinked runs/<link_id> pointing outside the state root
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("run.lock"), "").unwrap();
    let link_id = "20200102T000002Z-bbbbbb";
    std::os::unix::fs::symlink(outside.path(), state.path().join("runs").join(link_id)).unwrap();
    let mut link_cg = Leftover::new_bound(
        &parent,
        &format!("leash-{link_id}"),
        &outside.path().join("run.lock"),
    );

    // 3: valid stale run with unlocked regular run.lock and matching xattr
    let valid_id = "20200102T000003Z-cccccc";
    let valid_dir = dead_run_dir(state.path(), valid_id);
    let mut valid_cg = Leftover::new_bound(
        &parent,
        &format!("leash-{valid_id}"),
        &valid_dir.join("run.lock"),
    );

    let started = Instant::now();
    let events = cleanup_stale(&parent, state.path(), None).unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "planted FIFO must not block cleanup_stale"
    );
    assert_eq!(events.len(), 3, "all three entries reported: {events:?}");

    let by_name = |id: &str| {
        events
            .iter()
            .find(|e| e.cgroup == format!("leash-{id}"))
            .unwrap()
    };
    assert!(by_name(fifo_id).error.is_some());
    assert!(fifo_cg.cgroup.exists() && fifo_cg.sleeper_alive());

    assert!(by_name(link_id).error.is_some());
    assert!(link_cg.cgroup.exists() && link_cg.sleeper_alive());

    let valid_ev = by_name(valid_id);
    assert!(valid_ev.error.is_none(), "{valid_ev:?}");
    assert!(valid_ev.removal_error.is_none(), "{valid_ev:?}");
    assert!(!valid_cg.cgroup.exists());
    valid_cg.sleeper.wait().unwrap();
}

#[test]
fn run_cgroup_gone_walks_missing_parent_under_cgroup2_but_marks_non_cgroup2_unknown() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("run_cgroup_gone_ancestor") {
        return;
    }
    let parent = CgroupParent::locate().unwrap();
    let id = generate_run_id(SystemTime::now()).unwrap();
    let name = format!("leash-{id}");

    // a missing parent beneath a real cgroup2 ancestor (such as a vanished systemd-run scope)
    // reports Gone, whether one or several parent levels disappeared.
    let vanished_scope = parent.path().join("vanished.scope").join(&name);
    assert_eq!(
        run_cgroup_gone(&vanished_scope, &id).unwrap(),
        RunCgroupState::Gone
    );
    let vanished_nested = parent
        .path()
        .join("vanished.slice")
        .join("vanished.scope")
        .join(&name);
    assert_eq!(
        run_cgroup_gone(&vanished_nested, &id).unwrap(),
        RunCgroupState::Gone
    );

    // a missing parent under /tmp has a non-cgroup2 nearest existing ancestor, so it stays Unknown.
    let tmp = tempfile::tempdir().unwrap();
    let tmp_missing = tmp.path().join("vanished.scope").join(&name);
    assert_eq!(
        run_cgroup_gone(&tmp_missing, &id).unwrap(),
        RunCgroupState::Unknown
    );
}
