//! Linux behavioral test for the Landlock parent-build, child-apply seam.
//!
//! This test does not claim full policy mediation. The driver answers `CONTINUE` to every
//! seccomp notification and verifies that the already-applied Landlock ruleset still denies
//! an outside write in the child.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use leash::policy::{ExpandContext, Policy};
use leash::recorder::Mode;
use leash::sandbox::landlock;
use leash::supervisor::notify::NotifyFd;
use leash::supervisor::spawn::{SpawnSpec, SupervisedChild, spawn_supervised};

const DEADLINE: Duration = Duration::from_secs(15);

static SPAWN_LOCK: Mutex<()> = Mutex::new(());

fn spawn_guard() -> MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn landlock_agent_dispatch() {
    let Some(path) = std::env::var_os("LEASH_LANDLOCK_OUTSIDE") else {
        return;
    };
    let path = CString::new(path.as_encoded_bytes()).unwrap();
    // SAFETY: open reads the nul-terminated path. The expected result is a Landlock deny.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o600) };
    if fd >= 0 {
        // SAFETY: fd was returned by open and is no longer needed.
        unsafe { libc::close(fd) };
        std::process::exit(7);
    }
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    std::process::exit(if errno == libc::EACCES || errno == libc::EPERM {
        0
    } else {
        8
    });
}

#[test]
fn landlock_denies_write_outside_hull_even_when_seccomp_continues() {
    let _g = spawn_guard();
    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap().path().join("blocked");

    let policy_text = "schema_version = 1\n\
        [[fs]]\npath=\"/**\"\nmode=[\"read\"]\naction=\"allow\"\n\
        [[fs]]\npath=\"{workspace}/**\"\nmode=[\"write\", \"create\"]\naction=\"allow\"\n\
        [[exec]]\nbinary=\"/**\"\naction=\"allow\"\n";
    let policy = Policy::parse(
        policy_text,
        &ExpandContext {
            workspace: workspace.path().to_str().unwrap(),
            home: "/tmp",
        },
    )
    .unwrap();
    let hull = landlock::derive_hull(&policy, 4);
    let ruleset = landlock::build_ruleset(&hull).expect("ruleset builds");

    let spec = SpawnSpec {
        argv: vec![
            self_exe(),
            "--exact".into(),
            "landlock_agent_dispatch".into(),
            "--nocapture".into(),
        ],
        stdout: None,
        mode: Mode::Enforce,
        landlock_ruleset: Some(ruleset.as_raw_fd()),
    };
    // SAFETY: set under SPAWN_LOCK; no other test thread forks or reads env concurrently.
    unsafe { std::env::set_var("LEASH_LANDLOCK_OUTSIDE", &outside) };
    let child = spawn_supervised(&spec).expect("spawn");
    // SAFETY: remove under SPAWN_LOCK after the child has inherited its environment.
    unsafe { std::env::remove_var("LEASH_LANDLOCK_OUTSIDE") };

    let status = drive_continue(child);
    assert_eq!(
        exited_with(status),
        Some(0),
        "helper exits 0 only when Landlock denied the outside write"
    );
    assert!(
        !outside.exists(),
        "the denied outside file must not have been created"
    );
}

fn self_exe() -> String {
    std::env::current_exe()
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

fn drive_continue(child: SupervisedChild) -> i32 {
    let SupervisedChild { pid, notify } = child;
    let start = Instant::now();
    loop {
        if start.elapsed() > DEADLINE {
            // SAFETY: kill takes scalar args; SIGKILL the runaway child so CI never hangs.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            let status = reap(pid);
            panic!("child {pid} exceeded the deadline (status {status})");
        }
        if poll_readable(notify.as_raw_fd(), 50) {
            continue_one(&notify);
        } else if let Some(status) = try_reap(pid) {
            return status;
        }
    }
}

fn continue_one(notify: &NotifyFd) {
    if let Ok(n) = notify.recv() {
        let _ = notify.send_continue(n.id);
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
    // SAFETY: waitpid with WNOHANG writes status for the child we own.
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
