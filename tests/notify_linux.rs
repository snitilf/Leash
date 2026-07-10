//! behavioral tests for the record-only notify loop (docs/design/notify-loop.md;
//! FR-2, FR-4, FR-9, SR-4).
//!
//! these run only on linux, against a real seccomp listener: they spawn an agent under
//! the filter and serve it with the production `run_loop`, proving that filesystem
//! syscalls appear as ordered events with resolved paths (issue #18 acceptance 1), that
//! record precedes respond under a failing trace sink (case E, acceptance 2), that an
//! unreadable or over-cap path argument denies and is recorded (case C, acceptance 3-4),
//! and that io_uring_setup is denied-and-recorded in record-only (SR-4).
//!
//! the agent under test is this test binary re-exec'd, the pattern from spawn_linux.rs:
//! a trigger env var selects a helper `main` that performs the syscalls under test and
//! exits with a known code. every spawn is serialized under SPAWN_LOCK, and a watchdog
//! SIGKILLs the child if a test outlives its deadline so CI never hangs.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::CString;
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use leash::recorder::{Mode, TraceSink, TraceWriter};
use leash::supervisor::run::{RunError, run_loop};
use leash::supervisor::spawn::{SpawnSpec, spawn_supervised};
use serde_json::Value;

const DEADLINE: Duration = Duration::from_secs(15);

// serializes fork and environment mutation across all behavioral tests.
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

fn spawn_guard() -> MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// re-exec agent dispatch (see spawn_linux.rs for the pattern)
// ---------------------------------------------------------------------------

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

#[test]
fn agent_dispatch() {
    // hold the spawn lock: the harness runs tests on parallel threads, and without it
    // this test can race into another test's env-trigger window and run an agent branch
    // in the harness process (observed in CI: the io_uring branch, unsandboxed, exited
    // the whole binary with 14). in the re-exec'd child this lock is a fresh,
    // uncontended static, so agent behavior is unchanged.
    let _g = spawn_guard();

    // the open agent: one read-only open of /etc/hosts, then a create-for-write open of
    // the path in LEASH_TARGET. exits 0 when both succeed.
    if std::env::var_os("LEASH_NOTIFY_OPEN_AGENT").is_some() {
        let target = cstr(&std::env::var("LEASH_TARGET").unwrap());
        let ro = cstr("/etc/hosts");
        // SAFETY: raw open syscalls with nul-terminated paths we own; the supervisor
        // records them and continues.
        unsafe {
            let a = libc::syscall(libc::SYS_open, ro.as_ptr(), libc::O_RDONLY);
            let b = libc::syscall(
                libc::SYS_open,
                target.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT,
                0o644,
            );
            std::process::exit(if a >= 0 && b >= 0 { 0 } else { 4 });
        }
    }

    // the relative-path agent: chdir into LEASH_CHDIR and open a cwd-relative name,
    // then open LEASH_DIR as a directory fd and openat a name under it.
    if std::env::var_os("LEASH_NOTIFY_RELPATH_AGENT").is_some() {
        let cwd = cstr(&std::env::var("LEASH_CHDIR").unwrap());
        let dir = cstr(&std::env::var("LEASH_DIR").unwrap());
        let rel = cstr("rel-file");
        let named = cstr("dir-file");
        // SAFETY: chdir/open/openat with paths we own; chdir is pass-through, the opens
        // are mediated and recorded.
        unsafe {
            if libc::chdir(cwd.as_ptr()) != 0 {
                std::process::exit(5);
            }
            let a = libc::syscall(libc::SYS_open, rel.as_ptr(), libc::O_RDONLY);
            let d = libc::open(dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
            if d < 0 {
                std::process::exit(6);
            }
            let b = libc::syscall(libc::SYS_openat, d, named.as_ptr(), libc::O_RDONLY);
            std::process::exit(if a >= 0 && b >= 0 { 0 } else { 7 });
        }
    }

    // the mutation agent: creat, rename, unlink one file under LEASH_DIR, then mkdir
    // and rmdir a directory. exits 0 when every call succeeds.
    if std::env::var_os("LEASH_NOTIFY_MUTATE_AGENT").is_some() {
        let dir = std::env::var("LEASH_DIR").unwrap();
        let a = cstr(&format!("{dir}/a.txt"));
        let b = cstr(&format!("{dir}/b.txt"));
        let d = cstr(&format!("{dir}/subdir"));
        // SAFETY: raw filesystem syscalls on paths we own inside a test tempdir.
        unsafe {
            let fd = libc::syscall(
                libc::SYS_open,
                a.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT,
                0o644,
            );
            if fd < 0 {
                std::process::exit(8);
            }
            libc::close(fd as i32);
            if libc::syscall(libc::SYS_rename, a.as_ptr(), b.as_ptr()) != 0 {
                std::process::exit(9);
            }
            if libc::syscall(libc::SYS_unlink, b.as_ptr()) != 0 {
                std::process::exit(10);
            }
            if libc::syscall(libc::SYS_mkdir, d.as_ptr(), 0o755) != 0 {
                std::process::exit(11);
            }
            if libc::syscall(libc::SYS_rmdir, d.as_ptr()) != 0 {
                std::process::exit(12);
            }
        }
        std::process::exit(0);
    }

    // the bad-pointer agent (case C): an open with a null path pointer and an open with
    // an over-cap path (8 KiB of 'a', no nul). both must fail EACCES, the case-c errno,
    // and the run must survive them.
    if std::env::var_os("LEASH_NOTIFY_BADPTR_AGENT").is_some() {
        let no_nul = [b'a'; 8192];
        // SAFETY: the pointers are deliberately hostile; the supervisor must refuse to
        // read them and fail the syscalls without touching this process otherwise.
        unsafe {
            let r1 = libc::syscall(libc::SYS_open, 0usize, libc::O_RDONLY);
            let e1 = io::Error::last_os_error().raw_os_error();
            let r2 = libc::syscall(libc::SYS_open, no_nul.as_ptr(), libc::O_RDONLY);
            let e2 = io::Error::last_os_error().raw_os_error();
            let ok = r1 == -1 && e1 == Some(libc::EACCES) && r2 == -1 && e2 == Some(libc::EACCES);
            std::process::exit(if ok { 0 } else { 13 });
        }
    }

    // the io_uring agent (SR-4): io_uring_setup must fail with ENOSYS in record-only.
    if std::env::var_os("LEASH_NOTIFY_IOURING_AGENT").is_some() {
        let mut params = [0u8; 256];
        // SAFETY: io_uring_setup reads/writes the params buffer we own; the supervisor
        // denies it before the kernel ever sees it.
        unsafe {
            let r = libc::syscall(libc::SYS_io_uring_setup, 1u32, params.as_mut_ptr());
            let e = io::Error::last_os_error().raw_os_error();
            std::process::exit(if r == -1 && e == Some(libc::ENOSYS) {
                0
            } else {
                14
            });
        }
    }
    // no trigger: a normal test run, nothing to do.
}

// ---------------------------------------------------------------------------
// harness: run an agent under the production loop, collect the trace
// ---------------------------------------------------------------------------

/// an in-memory sink that can be told to fail after n successful writes (the case-E
/// seam, same shape as the recorder's own fault tests).
#[derive(Default)]
struct MemSink {
    bytes: Vec<u8>,
    fail_after: Option<usize>,
    writes: usize,
}

impl Write for MemSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(n) = self.fail_after
            && self.writes >= n
        {
            return Err(io::Error::other("disk gone"));
        }
        self.writes += 1;
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TraceSink for MemSink {
    fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// SIGKILL the pid if the test outlives the deadline, so a wedged loop cannot hang CI.
struct Watchdog {
    cancel: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Watchdog {
    fn arm(pid: libc::pid_t) -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancel);
        let handle = std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < DEADLINE {
                if flag.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            // SAFETY: kill takes scalar args; the runaway child must not hang CI.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        });
        Self {
            cancel,
            handle: Some(handle),
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn self_exe() -> String {
    std::env::current_exe()
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

fn agent_spec() -> SpawnSpec {
    SpawnSpec {
        argv: vec![
            self_exe(),
            "--exact".into(),
            "agent_dispatch".into(),
            "--nocapture".into(),
        ],
        stdout: None,
        mode: Mode::RecordOnly,
    }
}

/// spawn the re-exec agent with `envs` set, serve it with `run_loop` over `sink`, and
/// return the loop result plus the parsed trace events.
fn serve_agent(envs: &[(&str, &str)], sink: MemSink) -> (Result<i32, RunError>, Vec<Value>) {
    for (k, v) in envs {
        // SAFETY: set under SPAWN_LOCK; no other thread forks or reads env concurrently.
        unsafe { std::env::set_var(k, v) };
    }
    let child = spawn_supervised(&agent_spec()).expect("spawn must succeed");
    for (k, _) in envs {
        // SAFETY: set under SPAWN_LOCK.
        unsafe { std::env::remove_var(k) };
    }

    let _watchdog = Watchdog::arm(child.pid);
    let mut writer = TraceWriter::new(sink);
    let result = run_loop(child, Mode::RecordOnly, &mut writer);

    let events: Vec<Value> = String::from_utf8(writer.into_inner().bytes)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    (result.map(|o| o.wait_status), events)
}

fn exited_with(status: i32) -> Option<i32> {
    libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status))
}

/// the syscall events whose name matches, in trace order.
fn syscall_events<'a>(events: &'a [Value], name: &str) -> Vec<&'a Value> {
    events
        .iter()
        .filter(|e| e["type"] == "syscall" && e["syscall"] == name)
        .collect()
}

// ---------------------------------------------------------------------------
// slices
// ---------------------------------------------------------------------------

/// slice 1: the production loop serves a trivial agent to exit, the trace is ordered,
/// and the agent's execve is recorded as the first mediated event.
#[test]
fn run_loop_serves_a_trivial_agent_to_exit() {
    let _g = spawn_guard();
    let child = spawn_supervised(&SpawnSpec {
        argv: vec!["/bin/true".into()],
        stdout: None,
        mode: Mode::RecordOnly,
    })
    .expect("spawn");
    let _watchdog = Watchdog::arm(child.pid);

    let mut writer = TraceWriter::new(MemSink::default());
    let outcome = run_loop(child, Mode::RecordOnly, &mut writer).expect("loop must serve to exit");
    assert_eq!(exited_with(outcome.wait_status), Some(0));

    let events: Vec<Value> = String::from_utf8(writer.into_inner().bytes)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(!events.is_empty(), "at least the execve must be recorded");
    assert_eq!(events[0]["syscall"], "execve");
    assert_eq!(events[0]["fact"]["binary"], "/bin/true");
    assert_eq!(events[0]["decision"], "allow");
    for (i, ev) in events.iter().enumerate() {
        assert_eq!(ev["seq"], i as u64, "seq is dense and ordered");
    }
}

/// slice 2 (acceptance 1): an agent's opens appear as ordered events with resolved
/// paths and the access the flags requested.
#[test]
fn opens_appear_as_ordered_events_with_resolved_paths() {
    let _g = spawn_guard();
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("out.txt");

    let (result, events) = serve_agent(
        &[
            ("LEASH_NOTIFY_OPEN_AGENT", "1"),
            ("LEASH_TARGET", target.to_str().unwrap()),
        ],
        MemSink::default(),
    );
    assert_eq!(exited_with(result.expect("loop must complete")), Some(0));

    let opens = syscall_events(&events, "open");
    assert_eq!(opens.len(), 2, "both opens must be recorded: {events:?}");
    assert_eq!(opens[0]["fact"]["path"], "/etc/hosts");
    assert_eq!(opens[0]["fact"]["access"], serde_json::json!(["read"]));
    assert_eq!(opens[1]["fact"]["path"], target.to_str().unwrap());
    assert_eq!(
        opens[1]["fact"]["access"],
        serde_json::json!(["write", "create"])
    );
    for ev in &opens {
        assert_eq!(ev["decision"], "allow");
        assert_eq!(ev["matched_rule"], "base:record_only");
    }
    assert!(
        target.exists(),
        "the continued open must actually create the file"
    );
}

/// slice 3: relative paths anchor at the kernel-reported cwd, dirfd-relative paths at
/// the kernel-reported fd link (the record-only resolution rule, trace.md section 2).
#[test]
fn relative_and_dirfd_paths_resolve_against_proc() {
    let _g = spawn_guard();
    let cwd_dir = tempfile::tempdir().unwrap();
    let fd_dir = tempfile::tempdir().unwrap();
    std::fs::write(cwd_dir.path().join("rel-file"), b"x").unwrap();
    std::fs::write(fd_dir.path().join("dir-file"), b"y").unwrap();
    // the loop records the kernel's own answer for the anchor, so expectations must be
    // canonical the way /proc links are (tempdirs on macos-style symlinked /tmp differ)
    let cwd_canon = cwd_dir.path().canonicalize().unwrap();
    let fd_canon = fd_dir.path().canonicalize().unwrap();

    let (result, events) = serve_agent(
        &[
            ("LEASH_NOTIFY_RELPATH_AGENT", "1"),
            ("LEASH_CHDIR", cwd_dir.path().to_str().unwrap()),
            ("LEASH_DIR", fd_dir.path().to_str().unwrap()),
        ],
        MemSink::default(),
    );
    assert_eq!(exited_with(result.expect("loop must complete")), Some(0));

    let paths: Vec<String> = events
        .iter()
        .filter(|e| e["type"] == "syscall" && e["fact"]["family"] == "fs")
        .map(|e| e["fact"]["path"].as_str().unwrap().to_string())
        .collect();
    let rel_expected = cwd_canon.join("rel-file");
    let named_expected = fd_canon.join("dir-file");
    assert!(
        paths.iter().any(|p| Path::new(p) == rel_expected),
        "cwd-relative open must resolve to {rel_expected:?}: {paths:?}"
    );
    assert!(
        paths.iter().any(|p| Path::new(p) == named_expected),
        "dirfd-relative open must resolve to {named_expected:?}: {paths:?}"
    );
}

/// slice 4 (acceptance 1): renames and unlinks appear as ordered events, the rename
/// carrying both paths.
#[test]
fn renames_and_unlinks_appear_with_both_paths() {
    let _g = spawn_guard();
    let dir = tempfile::tempdir().unwrap();
    let dirstr = dir.path().to_str().unwrap();

    let (result, events) = serve_agent(
        &[("LEASH_NOTIFY_MUTATE_AGENT", "1"), ("LEASH_DIR", dirstr)],
        MemSink::default(),
    );
    assert_eq!(exited_with(result.expect("loop must complete")), Some(0));

    let renames = syscall_events(&events, "rename");
    assert_eq!(renames.len(), 1, "{events:?}");
    assert_eq!(renames[0]["fact"]["path"], format!("{dirstr}/a.txt"));
    assert_eq!(renames[0]["fact"]["dest"], format!("{dirstr}/b.txt"));

    let unlinks = syscall_events(&events, "unlink");
    assert_eq!(unlinks.len(), 1);
    assert_eq!(unlinks[0]["fact"]["path"], format!("{dirstr}/b.txt"));
    assert_eq!(unlinks[0]["fact"]["access"], serde_json::json!(["delete"]));

    let mkdirs = syscall_events(&events, "mkdir");
    let rmdirs = syscall_events(&events, "rmdir");
    assert_eq!((mkdirs.len(), rmdirs.len()), (1, 1));

    // decision order: create, rename, unlink, mkdir, rmdir as the agent issued them
    let order: Vec<&str> = events
        .iter()
        .filter(|e| e["type"] == "syscall" && e["fact"]["family"] == "fs")
        .map(|e| e["syscall"].as_str().unwrap())
        .collect();
    let interesting: Vec<&str> = order
        .iter()
        .copied()
        .filter(|s| ["open", "rename", "unlink", "mkdir", "rmdir"].contains(s))
        .collect();
    assert_eq!(
        interesting,
        vec!["open", "rename", "unlink", "mkdir", "rmdir"],
        "events must appear in decision order"
    );
}

/// slices 5 + acceptance 3-4 (case C): an unreadable pointer and an over-cap path both
/// deny with EACCES, both are recorded, and the run survives.
#[test]
fn over_cap_or_unreadable_path_resolves_to_deny() {
    let _g = spawn_guard();
    let (result, events) = serve_agent(&[("LEASH_NOTIFY_BADPTR_AGENT", "1")], MemSink::default());
    assert_eq!(
        exited_with(result.expect("the run must survive case-c denies")),
        Some(0),
        "the agent must observe EACCES on both hostile opens"
    );

    let denies: Vec<&Value> = events
        .iter()
        .filter(|e| e["type"] == "syscall" && e["decision"] == "deny")
        .collect();
    assert_eq!(
        denies.len(),
        2,
        "both case-c denies must be recorded: {events:?}"
    );
    for ev in denies {
        assert_eq!(ev["matched_rule"], "failsafe:memory_read");
        assert_eq!(ev["fact"]["family"], "raw");
        assert_eq!(ev["syscall"], "open");
    }
}

/// slice 6 + acceptance 2 (case E): when the trace cannot be written, the pending open
/// is denied, not allowed, and the run aborts. the O_CREAT open is the probe: had the
/// loop responded CONTINUE before (or despite) the failed record, the file would exist.
#[test]
fn failed_trace_write_denies_and_aborts() {
    let _g = spawn_guard();
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("must-not-exist.txt");

    // one successful write serves the execve event; the next recorded syscall (the
    // loader's first mediated open, well before the agent's target open) hits the dead
    // sink and the run aborts, so nothing after the failure may execute
    let sink = MemSink {
        fail_after: Some(1),
        ..MemSink::default()
    };
    let (result, events) = serve_agent(
        &[
            ("LEASH_NOTIFY_OPEN_AGENT", "1"),
            ("LEASH_TARGET", target.to_str().unwrap()),
        ],
        sink,
    );

    assert!(
        matches!(result, Err(RunError::Recorder(_))),
        "a failed trace write must abort the run (case E): {result:?}"
    );
    assert!(
        !target.exists(),
        "record precedes respond: the unrecordable open must never execute"
    );
    // the trace holds exactly the events written before the failure
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["syscall"], "execve");
}

/// slice 7 (SR-4): io_uring_setup is denied with ENOSYS and recorded, in record-only.
/// closes the observation-only note in spawn_linux.rs.
#[test]
fn io_uring_setup_is_denied_and_recorded_in_record_only() {
    let _g = spawn_guard();
    let (result, events) = serve_agent(&[("LEASH_NOTIFY_IOURING_AGENT", "1")], MemSink::default());
    assert_eq!(
        exited_with(result.expect("loop must complete")),
        Some(0),
        "the agent must observe ENOSYS from io_uring_setup"
    );

    let denies = syscall_events(&events, "io_uring_setup");
    assert_eq!(denies.len(), 1, "{events:?}");
    assert_eq!(denies[0]["decision"], "deny");
    assert_eq!(denies[0]["matched_rule"], "sr4:io_uring");
    assert_eq!(denies[0]["fact"]["family"], "raw");
}

/// enforce mode without a policy engine must refuse to run (fail closed), not fall
/// through to record-only behavior.
#[test]
fn enforce_mode_is_refused_until_the_policy_engine_exists() {
    let _g = spawn_guard();
    let child = spawn_supervised(&SpawnSpec {
        argv: vec!["/bin/true".into()],
        stdout: None,
        mode: Mode::RecordOnly,
    })
    .expect("spawn");
    let pid = child.pid;
    let _watchdog = Watchdog::arm(pid);

    let mut writer = TraceWriter::new(MemSink::default());
    let result = run_loop(child, Mode::Enforce, &mut writer);
    assert!(matches!(result, Err(RunError::UnsupportedMode)));
    // the refused run must not leave the child running or unreaped
    // SAFETY: kill/waitpid on the child we spawned; ESRCH means it is already gone.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
    }
}
