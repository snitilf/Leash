//! behavioral tests for the spawn protocol (architecture.md section 5.2; FR-1, I1, I3).
//!
//! these run only on linux, against a real seccomp listener: they spawn a child under
//! the filter and drive the notify fd, proving the agent's execve is the first mediated
//! event, that a grandchild traps identically (I1), that a live ADDFD injects a
//! supervisor-opened fd (ADR-0015), that io_uring_setup arrives as a notification, that
//! spare fds are closed at exec (escapes.md), and that a failed setup aborts before the
//! agent runs (I3). each drive carries a wall-clock deadline and SIGKILLs the child if
//! exceeded, so a stuck WAIT_KILLABLE_RECV cannot hang CI.
//!
//! the agent under test is this test binary re-exec'd (the pattern from durability.rs):
//! a trigger env var selects a helper `main` that performs one specific action and exits
//! with a known code, bypassing the harness. every spawn is serialized under SPAWN_LOCK
//! so no thread forks or mutates the environment while another is doing either.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use leash::recorder::Mode;
use leash::sandbox::child::CHILD_SETUP_EXIT;
use leash::sandbox::filter::SockFilter;
use leash::supervisor::notify::{NotifyFd, SECCOMP_ADDFD_FLAG_SEND, SeccompNotif};
use leash::supervisor::spawn::{
    SpawnError, SpawnSpec, SupervisedChild, spawn_supervised, spawn_with_filter,
};

const DEADLINE: Duration = Duration::from_secs(15);

// serializes fork and environment mutation across all behavioral tests; see the module doc.
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

fn spawn_guard() -> MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// re-exec agent dispatch: when a trigger env var is set, the test binary is the
// agent. each helper does one action and exits directly, never returning to the
// harness. keyed off env vars so the parent selects the behavior per spawn.
// ---------------------------------------------------------------------------

/// the sentinel path the addfd agent opens; the supervisor recognizes it by suffix.
const ADDFD_SENTINEL: &str = "/nonexistent/leash-addfd-sentinel";
const ADDFD_MARKER: &[u8] = b"injected-by-supervisor";

#[test]
fn agent_dispatch() {
    // hold the spawn lock: without it this test can race into another test's
    // env-trigger window on a parallel harness thread and run an agent branch in the
    // harness process (observed in CI on notify_linux.rs's twin of this dispatch). in
    // the re-exec'd child the lock is a fresh, uncontended static.
    let _g = spawn_guard();

    // the addfd agent: open the sentinel (the supervisor injects a real fd via
    // ADDFD_FLAG_SEND), then write the marker to whatever fd came back.
    if std::env::var_os("LEASH_ADDFD_AGENT").is_some() {
        let path = CString::new(ADDFD_SENTINEL).unwrap();
        // SAFETY: open with a borrowed nul-terminated path; the supervisor completes
        // this trapped syscall with an injected fd rather than resolving the path.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY) };
        if fd < 0 {
            std::process::exit(2);
        }
        // SAFETY: write the marker to the injected fd.
        let n = unsafe { libc::write(fd, ADDFD_MARKER.as_ptr().cast(), ADDFD_MARKER.len()) };
        std::process::exit(if n == ADDFD_MARKER.len() as isize {
            0
        } else {
            3
        });
    }

    // the io_uring agent: print a marker to stdout (proving the redirect), then attempt
    // io_uring_setup so the supervisor observes the trap.
    if std::env::var_os("LEASH_IOURING_AGENT").is_some() {
        let marker = b"IOURING_AGENT_RAN\n";
        // SAFETY: write the marker to fd 1 (redirected by the spawn).
        unsafe { libc::write(1, marker.as_ptr().cast(), marker.len()) };
        let mut params = [0u8; 256]; // io_uring_params, generously sized and zeroed
        // SAFETY: io_uring_setup reads/writes the params buffer we own; it traps at entry
        // regardless of whether io_uring is enabled, which is all this observes.
        unsafe { libc::syscall(libc::SYS_io_uring_setup, 1u32, params.as_mut_ptr()) };
        std::process::exit(0);
    }

    // the fd-leak agent: check that the fd the parent leaked in is closed after exec.
    if let Ok(fdstr) = std::env::var("LEASH_LEAKED_FD") {
        let fd: i32 = fdstr.parse().unwrap();
        // SAFETY: F_GETFD only queries the fd flags; -1/EBADF means the fd is closed.
        let r = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        std::process::exit(if r == -1 { 0 } else { 7 });
    }
    // no trigger: a normal test run, nothing to do.
}

fn spec(argv: &[&str]) -> SpawnSpec {
    SpawnSpec {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        stdout: None,
        mode: Mode::RecordOnly,
    }
}

fn self_exe() -> String {
    std::env::current_exe()
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

/// one observed mediated syscall: the trapping pid and the syscall number.
#[derive(Debug, Clone, Copy)]
struct Trap {
    pid: u32,
    nr: i32,
}

/// answer CONTINUE to every trap until the child exits, recording what trapped. the
/// child is SIGKILLed if it outlives the deadline. returns the traps in order and the
/// raw wait status.
fn drive(child: SupervisedChild) -> (Vec<Trap>, i32) {
    drive_with(child, |_, _| Handling::Continue)
}

/// what the driver should do with a received trap.
enum Handling {
    /// let the syscall run.
    Continue,
    /// the responder already answered this notification (e.g. via addfd); do not reply.
    Answered,
}

/// like `drive`, but `on_trap` may intercept a notification and answer it itself. it is
/// handed the notify fd and the notification so it can, for instance, inject an fd.
fn drive_with<F>(child: SupervisedChild, mut on_trap: F) -> (Vec<Trap>, i32)
where
    F: FnMut(&NotifyFd, &SeccompNotif) -> Handling,
{
    let SupervisedChild { pid, notify } = child;
    let mut traps = Vec::new();
    let start = Instant::now();
    loop {
        if start.elapsed() > DEADLINE {
            // SAFETY: kill takes scalar args; SIGKILL the runaway child so CI never hangs.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            let status = reap(pid);
            panic!("child {pid} exceeded the deadline (status {status}); traps: {traps:?}");
        }
        if poll_readable(notify.as_raw_fd(), 50) {
            match notify.recv() {
                Ok(n) => {
                    traps.push(Trap {
                        pid: n.pid,
                        nr: n.data.nr,
                    });
                    match on_trap(&notify, &n) {
                        // continue is sound here: the harness makes no decision on child
                        // memory, it only lets syscalls through to observe the tree.
                        Handling::Continue => {
                            let _ = notify.send_continue(n.id);
                        }
                        Handling::Answered => {}
                    }
                }
                Err(_) => continue,
            }
        } else if let Some(status) = try_reap(pid) {
            return (traps, status);
        }
    }
}

fn poll_readable(fd: i32, timeout_ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll reads and writes the single pollfd we own.
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    rc > 0 && (pfd.revents & libc::POLLIN) != 0
}

fn try_reap(pid: libc::pid_t) -> Option<i32> {
    let mut status = 0;
    // SAFETY: waitpid with WNOHANG writes status for the child we own; 0 means still alive.
    let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    (rc == pid).then_some(status)
}

fn reap(pid: libc::pid_t) -> i32 {
    let mut status = 0;
    // SAFETY: waitpid writes the status of the child we own into a local we own.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    status
}

fn exited_with(status: i32) -> Option<i32> {
    libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status))
}

/// read a nul-terminated string from the trapped child's memory via /proc/<pid>/mem. the
/// child is blocked at the trap, so the memory is stable for the read. this is the read
/// path the supervisor uses to resolve a path argument (notify-loop.md).
fn read_child_cstr(pid: u32, addr: u64) -> Vec<u8> {
    let f = std::fs::File::open(format!("/proc/{pid}/mem")).unwrap();
    let mut buf = [0u8; 512];
    let n = f.read_at(&mut buf, addr).unwrap_or(0);
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    buf[..end].to_vec()
}

/// acceptance 1 (FR-1): the agent's own execve is the first thing the supervisor sees.
#[test]
fn spawned_childs_execve_is_the_first_mediated_event() {
    let _g = spawn_guard();
    let child = spawn_supervised(&spec(&["/bin/true"])).expect("spawn must succeed");
    let (traps, status) = drive(child);
    assert!(
        !traps.is_empty(),
        "the supervisor must see at least the execve"
    );
    assert_eq!(
        i64::from(traps[0].nr),
        libc::SYS_execve,
        "the first mediated event must be the agent's execve"
    );
    assert_eq!(
        exited_with(status),
        Some(0),
        "the agent must run and exit 0"
    );
}

/// acceptance 2 (I1): a grandchild spawned via sh -c is mediated exactly as the agent is.
/// partial evidence for the escapes.md laundering row; the forbidden-and-denied half
/// completes when enforce mode and the policy engine land (#25).
#[test]
fn grandchild_via_sh_dash_c_traps_identically() {
    let _g = spawn_guard();
    let child = spawn_supervised(&spec(&["/bin/sh", "-c", "/bin/true"])).expect("spawn");
    let (traps, status) = drive(child);
    let execs: Vec<u32> = traps
        .iter()
        .filter(|t| i64::from(t.nr) == libc::SYS_execve)
        .map(|t| t.pid)
        .collect();
    assert_eq!(
        i64::from(traps[0].nr),
        libc::SYS_execve,
        "the shell's own execve is first"
    );
    assert!(
        execs.iter().any(|&p| p != traps[0].pid),
        "the grandchild's execve must trap under a distinct pid (inheritance across fork+exec): {traps:?}"
    );
    assert_eq!(exited_with(status), Some(0));
}

/// discharges the ADR-0015 gap: the first live ADDFD with ADDFD_FLAG_SEND. the agent
/// opens a sentinel path; the supervisor recognizes it, opens a file of its own, and
/// injects that fd as the syscall's result. the marker the agent writes to the returned
/// fd lands in the supervisor's file, proving the injection completed the syscall.
#[test]
fn live_addfd_injects_a_supervisor_opened_fd() {
    let _g = spawn_guard();
    let target = tempfile::NamedTempFile::new().unwrap();
    let target_path = target.path().to_path_buf();

    let spec = spec(&[&self_exe(), "--exact", "agent_dispatch", "--nocapture"]);
    // SAFETY: set under SPAWN_LOCK; no other thread forks or reads env concurrently.
    unsafe { std::env::set_var("LEASH_ADDFD_AGENT", "1") };

    let child = spawn_supervised(&spec).expect("spawn");
    let mut injected = false;
    let mut injected_fds: Vec<OwnedFd> = Vec::new();
    let (_traps, status) = drive_with(child, |notify, n| {
        let is_open = i64::from(n.data.nr) == libc::SYS_open;
        let is_openat = i64::from(n.data.nr) == libc::SYS_openat;
        if !injected && (is_open || is_openat) {
            // open takes the path in arg0; openat in arg1.
            let path_addr = if is_open {
                n.data.args[0]
            } else {
                n.data.args[1]
            };
            let path = read_child_cstr(n.pid, path_addr);
            if path.ends_with(ADDFD_SENTINEL.as_bytes()) {
                let file = std::fs::File::create(&target_path).unwrap();
                let fd: OwnedFd = file.into();
                notify
                    .send_addfd(n.id, fd.as_fd(), SECCOMP_ADDFD_FLAG_SEND)
                    .expect("live addfd with ADDFD_FLAG_SEND must succeed");
                injected_fds.push(fd);
                injected = true;
                return Handling::Answered;
            }
        }
        Handling::Continue
    });
    // SAFETY: set under SPAWN_LOCK.
    unsafe { std::env::remove_var("LEASH_ADDFD_AGENT") };

    assert!(
        injected,
        "the supervisor never saw the sentinel open to inject into"
    );
    assert_eq!(
        exited_with(status),
        Some(0),
        "the agent wrote to the injected fd"
    );
    let written = std::fs::read(&target_path).unwrap();
    assert_eq!(
        written, ADDFD_MARKER,
        "the marker must land in the supervisor-opened file, proving the injection"
    );
}

/// io_uring_setup arrives as a user notification (observation only at this layer; the
/// unconditional deny is implemented in the notify loop and tested in notify_linux.rs).
/// also exercises the stdout redirect: the agent's marker, written to fd 1, must land
/// in the redirected file.
#[test]
fn io_uring_setup_arrives_as_user_notif() {
    let _g = spawn_guard();
    let out = tempfile::NamedTempFile::new().unwrap();
    let out_fd: OwnedFd = std::fs::File::create(out.path()).unwrap().into();

    let mut spec = spec(&[&self_exe(), "--exact", "agent_dispatch", "--nocapture"]);
    spec.stdout = Some(out_fd);
    // SAFETY: set under SPAWN_LOCK.
    unsafe { std::env::set_var("LEASH_IOURING_AGENT", "1") };

    let child = spawn_supervised(&spec).expect("spawn");
    let (traps, status) = drive(child);
    // SAFETY: set under SPAWN_LOCK.
    unsafe { std::env::remove_var("LEASH_IOURING_AGENT") };

    assert!(
        traps
            .iter()
            .any(|t| i64::from(t.nr) == libc::SYS_io_uring_setup),
        "io_uring_setup must arrive as a notification: {traps:?}"
    );
    assert_eq!(exited_with(status), Some(0));
    let captured = std::fs::read_to_string(out.path()).unwrap();
    assert!(
        captured.contains("IOURING_AGENT_RAN"),
        "the agent's stdout must reach the redirected file: {captured:?}"
    );
}

/// escapes.md fd-inheritance-at-spawn row: a fd the parent leaks into the child (here a
/// non-CLOEXEC fd the child inherits across fork) must be closed by close_range before
/// exec, so the agent cannot reach it. this is what keeps the child off the decision path.
#[test]
fn fds_not_on_the_allowlist_are_closed_at_exec() {
    let _g = spawn_guard();
    let leak = tempfile::NamedTempFile::new().unwrap();
    let cpath = CString::new(leak.path().as_os_str().as_encoded_bytes()).unwrap();
    // a raw, non-CLOEXEC fd: it survives exec unless close_range closes it, so it is a
    // real test of step 6 rather than of O_CLOEXEC.
    // SAFETY: open a file we own for writing; the returned fd is owned by this test.
    let leaked_fd = unsafe { libc::open(cpath.as_ptr(), libc::O_WRONLY) };
    assert!(leaked_fd >= 3, "need a spare fd number to leak");

    let spec = spec(&[&self_exe(), "--exact", "agent_dispatch", "--nocapture"]);
    // SAFETY: set under SPAWN_LOCK.
    unsafe { std::env::set_var("LEASH_LEAKED_FD", leaked_fd.to_string()) };

    let child = spawn_supervised(&spec).expect("spawn");
    let (_traps, status) = drive(child);
    // SAFETY: set under SPAWN_LOCK.
    unsafe { std::env::remove_var("LEASH_LEAKED_FD") };
    // SAFETY: close our own copy of the leaked fd.
    unsafe { libc::close(leaked_fd) };

    assert_eq!(
        exited_with(status),
        Some(0),
        "the leaked fd must be closed at exec (a non-zero exit means it survived)"
    );
}

/// acceptance 3 (I3): a setup that cannot establish the boundary aborts non-zero before
/// the agent runs. the broken-filter seam injects a program the kernel rejects, so the
/// child dies at filter install, before it can send the ready byte.
#[test]
fn setup_failure_aborts_nonzero_before_the_agent_runs() {
    let _g = spawn_guard();
    // an empty program is rejected by the kernel (EINVAL) at install; it passes the
    // length guard, so it exercises the child's fail-closed path, not spawn's.
    let broken: Vec<SockFilter> = Vec::new();
    let err = spawn_with_filter(&spec(&["/bin/true"]), &broken)
        .expect_err("a rejected filter must abort the spawn");
    match err {
        SpawnError::ChildSetup { status } => {
            assert_ne!(
                exited_with(status),
                Some(0),
                "the child must abort non-zero"
            );
        }
        other => panic!("expected ChildSetup, got {other:?}"),
    }
}

/// the step-6 failure arc: the handshake completes, so spawn returns Ok, but the agent
/// binary does not exist. the execve traps (mediated), the supervisor continues it, the
/// kernel fails it, and the child exits with the setup code - the agent never runs.
#[test]
fn exec_failure_after_handshake_fails_the_run() {
    let _g = spawn_guard();
    let child = spawn_supervised(&spec(&["/nonexistent/leash-agent-xyzzy"]))
        .expect("handshake completes before the doomed execve");
    let (traps, status) = drive(child);
    assert_eq!(
        i64::from(traps[0].nr),
        libc::SYS_execve,
        "the doomed execve is the only mediated event"
    );
    assert_eq!(
        exited_with(status),
        Some(CHILD_SETUP_EXIT),
        "a failed exec must exit with the setup code, never run an agent"
    );
}
