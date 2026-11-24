//! the snapshot-run syscall filter (ADR-0024 decisions 7, 8, 9; SR-4): with
//! `snapshot_integrity` set, `clone3` is answered ENOSYS before its argument struct is
//! read, legacy AIO is trapped and denied, and the supervisor is non-dumpable.
//!
//! every test drives `run_session` directly with an enforce policy and a python3 agent
//! that issues the raw syscalls through ctypes. spawns are serialized under SPAWN_LOCK
//! because the harness runs tests on parallel threads and each session forks.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use leash::recorder::{Attendance, Mode};
use leash::supervisor::session::{ExitDisposition, SessionError, SessionSpec, run_session};

static SPAWN_LOCK: Mutex<()> = Mutex::new(());

fn spawn_lock() -> MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

const POLICY: &str = "schema_version = 1\n\
    [[fs]]\npath=\"/**\"\nmode=[\"read\"]\naction=\"allow\"\n\
    [[exec]]\nbinary=\"/**\"\naction=\"allow\"\n";

struct Run {
    exit: ExitDisposition,
    events: Vec<serde_json::Value>,
}

fn enforce(script: &str, snapshot_integrity: bool) -> Run {
    let _guard = spawn_lock();
    enforce_locked(script, snapshot_integrity)
}

/// `enforce` for a caller that already holds the spawn lock.
fn enforce_locked(script: &str, snapshot_integrity: bool) -> Run {
    let state = tempfile::tempdir().unwrap();
    let ws = tempfile::tempdir().unwrap();
    let policy_path = state.path().join("policy.toml");
    std::fs::write(&policy_path, POLICY).unwrap();
    let outcome = run_session(SessionSpec {
        argv: vec!["/usr/bin/python3".into(), "-c".into(), script.into()],
        mode: Mode::Enforce,
        attendance: Attendance::Unattended,
        state_root: state.path().to_path_buf(),
        state_root_spelling: state.path().to_path_buf(),
        workspace: ws.path().to_path_buf(),
        policy_path: Some(policy_path),
        ask_timeout: Duration::from_secs(60),
        snapshot_integrity,
    })
    .expect("session must complete");
    Run {
        exit: outcome.exit,
        events: trace_events(&outcome.run_path),
    }
}

fn trace_events(run_dir: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(run_dir.join("trace.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn events_for<'a>(run: &'a Run, syscall: &str) -> Vec<&'a serde_json::Value> {
    run.events
        .iter()
        .filter(|e| e["syscall"] == syscall)
        .collect()
}

fn assert_exit_zero(run: &Run) {
    assert!(
        matches!(run.exit, ExitDisposition::Exited(0)),
        "the agent script asserts its own expectations: {:?}",
        run.exit
    );
}

/// a raw clone3 with a valid 88-byte struct (flags 0, exit_signal SIGCHLD): a plain fork.
const RAW_CLONE3: &str = "import ctypes, errno, os, struct\n\
    libc = ctypes.CDLL(None, use_errno=True)\n\
    buf = ctypes.create_string_buffer(struct.pack('<QQQQQQQQQQQ', 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0), 88)\n\
    rc = libc.syscall(435, buf, 88)\n";

#[test]
fn clone3_is_enosys_and_recorded_in_a_snapshot_run() {
    let script = format!(
        "{RAW_CLONE3}\
         assert rc == -1 and ctypes.get_errno() == errno.ENOSYS, (rc, ctypes.get_errno())\n\
         bad = libc.syscall(435, 0, 0)\n\
         assert bad == -1 and ctypes.get_errno() == errno.ENOSYS, 'size 0 is also ENOSYS'\n"
    );
    let run = enforce(&script, true);
    assert_exit_zero(&run);
    let denied = events_for(&run, "clone3");
    assert_eq!(denied.len(), 2, "both attempts recorded: {denied:?}");
    for ev in denied {
        assert_eq!(ev["decision"], "deny");
        assert_eq!(ev["matched_rule"], "snapshot:clone3");
    }
}

#[test]
fn glibc_process_creation_still_works_in_a_snapshot_run() {
    let script = "import os, subprocess\n\
        pid = os.fork()\n\
        if pid == 0:\n    os._exit(0)\n\
        assert os.waitpid(pid, 0)[1] == 0\n\
        spawned = os.posix_spawn('/bin/true', ['true'], os.environ)\n\
        assert os.waitpid(spawned, 0)[1] == 0\n\
        assert subprocess.run(['/bin/sh', '-c', 'true & wait']).returncode == 0\n";
    let run = enforce(script, true);
    assert_exit_zero(&run);
    assert!(
        events_for(&run, "clone3")
            .iter()
            .all(|e| e["matched_rule"] == "snapshot:clone3"),
        "every clone3 attempt is the snapshot denial"
    );
}

#[test]
fn threads_fall_back_to_clone_in_a_snapshot_run() {
    // glibc's pthread_create tries clone3 first and falls back to clone on ENOSYS.
    let script = "import threading\n\
        t = threading.Thread(target=lambda: None)\n\
        t.start()\n\
        t.join()\n";
    let run = enforce(script, true);
    assert_exit_zero(&run);
    let denied = events_for(&run, "clone3");
    assert!(
        !denied.is_empty(),
        "glibc tried clone3 first, so the denial is on the trace"
    );
    assert!(
        denied
            .iter()
            .all(|e| e["matched_rule"] == "snapshot:clone3")
    );
    assert!(
        events_for(&run, "clone")
            .iter()
            .any(|e| e["decision"] == "allow"),
        "the libc fallback to clone was allowed: {:?}",
        events_for(&run, "clone")
    );
}

#[test]
fn clone3_is_unchanged_without_snapshot_integrity() {
    let script = format!(
        "{RAW_CLONE3}\
         if rc == 0:\n    os._exit(0)\n\
         assert rc > 0, (rc, ctypes.get_errno())\n\
         assert os.waitpid(rc, 0)[1] == 0\n"
    );
    let run = enforce(&script, false);
    assert_exit_zero(&run);
    let seen = events_for(&run, "clone3");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0]["decision"], "allow");
    assert_eq!(seen[0]["matched_rule"], "base:process_creation");
}

#[test]
fn aio_is_denied_and_recorded_in_a_snapshot_run() {
    let script = "import ctypes, errno\n\
        libc = ctypes.CDLL(None, use_errno=True)\n\
        ctx = ctypes.c_ulong(0)\n\
        assert libc.syscall(206, 8, ctypes.byref(ctx)) == -1\n\
        assert ctypes.get_errno() == errno.ENOSYS, ctypes.get_errno()\n\
        assert ctx.value == 0\n\
        assert libc.syscall(209, 0, 0, 0) == -1\n\
        assert ctypes.get_errno() == errno.ENOSYS, ctypes.get_errno()\n";
    let run = enforce(script, true);
    assert_exit_zero(&run);
    for name in ["io_setup", "io_submit"] {
        let seen = events_for(&run, name);
        assert_eq!(seen.len(), 1, "{name} recorded once: {seen:?}");
        assert_eq!(seen[0]["decision"], "deny");
        assert_eq!(seen[0]["matched_rule"], "snapshot:aio");
    }
}

#[test]
fn aio_is_unchanged_without_snapshot_integrity() {
    let script = "import ctypes\n\
        libc = ctypes.CDLL(None, use_errno=True)\n\
        ctx = ctypes.c_ulong(0)\n\
        assert libc.syscall(206, 8, ctypes.byref(ctx)) == 0, ctypes.get_errno()\n\
        assert libc.syscall(207, ctx) == 0\n";
    let run = enforce(script, false);
    assert_exit_zero(&run);
    assert!(
        events_for(&run, "io_setup").is_empty() && events_for(&run, "io_submit").is_empty(),
        "AIO is not trapped, so a non-snapshot trace is identical to today's"
    );
}

#[test]
fn record_only_with_snapshot_integrity_is_refused_before_spawn() {
    let _guard = spawn_lock();
    let state = tempfile::tempdir().unwrap();
    let ws = tempfile::tempdir().unwrap();
    let result = run_session(SessionSpec {
        argv: vec!["/bin/true".into()],
        mode: Mode::RecordOnly,
        attendance: Attendance::Unattended,
        state_root: state.path().to_path_buf(),
        state_root_spelling: state.path().to_path_buf(),
        workspace: ws.path().to_path_buf(),
        policy_path: None,
        ask_timeout: Duration::from_secs(60),
        snapshot_integrity: true,
    });
    let error = result.expect_err("record-only must refuse the flag");
    assert!(matches!(error, SessionError::SnapshotIntegrityNeedsEnforce));
    assert!(
        !state.path().join("runs").exists(),
        "refused before any run directory exists"
    );
}

/// watches the children of `parent` from outside the run and records, per child, the owner
/// of its `/proc/<pid>/status` at every poll. the agent cannot do this itself: the
/// supervisor's and broker's `/proc/<pid>` trees are denied to it (implicit:supervisor_proc).
const WATCHER: &str = "import os, sys, time\n\
parent, out = sys.argv[1], sys.argv[2]\n\
seen = set()\n\
end = time.time() + 120\n\
while time.time() < end:\n\
\x20   for d in os.listdir('/proc'):\n\
\x20       if not d.isdigit():\n\
\x20           continue\n\
\x20       try:\n\
\x20           ppid = [l for l in open('/proc/%s/status' % d) if l.startswith('PPid:')][0].split()[1]\n\
\x20           if ppid == parent:\n\
\x20               seen.add((int(d), os.stat('/proc/%s/status' % d).st_uid))\n\
\x20       except (OSError, IndexError):\n\
\x20           pass\n\
\x20   with open(out + '.tmp', 'w') as f:\n\
\x20       f.write(''.join('%d %d\\n' % pair for pair in sorted(seen)))\n\
\x20   os.replace(out + '.tmp', out)\n\
\x20   time.sleep(0.005)\n";

#[test]
fn supervisor_and_broker_are_non_dumpable_during_a_run() {
    // /proc/<pid>/status has no Dumpable field. the kernel's visible effect is that a
    // non-dumpable process's /proc/<pid> files are owned by root, while a dumpable one's
    // belong to its own uid. this process is the supervisor, so a watcher process started
    // before the run sees its children (the broker, then the agent) and who owns their
    // /proc files. the agent could not look: the supervisor and broker /proc trees are
    // denied to it. the agent's own dumpable state is not asserted from inside: execve
    // resets it, so an agent-side check could never fail. the child reset is proven instead
    // by the supervisor reading the agent's execve path through /proc/<pid>/mem, which a
    // non-dumpable target refuses (the run would fail closed).
    // SAFETY: geteuid takes no arguments and cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    for snapshot_integrity in [false, true] {
        let _guard = spawn_lock();
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("children");
        let mut watcher = (!root).then(|| {
            std::process::Command::new("/usr/bin/python3")
                .args(["-c", WATCHER, &std::process::id().to_string()])
                .arg(&out)
                .spawn()
                .unwrap()
        });
        // the agent outlives a few hundred polls, so the watcher sees it and the broker
        let run = enforce_locked("import time\ntime.sleep(1)\n", snapshot_integrity);
        if let Some(watcher) = watcher.as_mut() {
            let _ = watcher.kill();
            let _ = watcher.wait();
        }
        assert_exit_zero(&run);
        if root {
            // root cannot tell the two ownerships apart; only the in-process check below runs.
            continue;
        }
        let seen: Vec<(u32, u32)> = std::fs::read_to_string(&out)
            .unwrap()
            .lines()
            .map(|line| {
                let (pid, uid) = line.split_once(' ').unwrap();
                (pid.parse().unwrap(), uid.parse().unwrap())
            })
            .collect();
        // SAFETY: getuid takes no arguments and cannot fail.
        let me = unsafe { libc::getuid() };
        let pids: std::collections::BTreeSet<u32> = seen.iter().map(|(pid, _)| *pid).collect();
        assert!(
            pids.iter().any(|pid| seen
                .iter()
                .filter(|(p, _)| p == pid)
                .all(|(_, owner)| *owner == 0)),
            "the broker is non-dumpable: no child had root-owned /proc files throughout: {seen:?}"
        );
        // the agent is root-owned only until the child resets it right before execv
        assert!(
            seen.iter().any(|(_, owner)| *owner == me),
            "the agent is dumpable once exec'd: no child had caller-owned /proc files: {seen:?}"
        );
    }
    // the in-process observable, checked for root too: this process is the supervisor.
    // SAFETY: PR_GET_DUMPABLE takes no pointer arguments.
    assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
}
