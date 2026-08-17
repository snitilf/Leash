//! probe: what the kernel actually guarantees for a RECV'd seccomp user-notification
//! when the target task receives a non-fatal signal (issue #36; docs/design/notify-loop.md
//! section 4.1; ADR-0012; docs/measurements/0002-wait-killable-recv-signals.md).
//!
//! outcome: the guarantee in section 4.1 holds once the filter is installed with the
//! correct flag bit. the original anomaly (CI run 31973092653: a caught SIGALRM cancelled
//! a RECV'd ask notification) traced to our own constant, which named bit 4
//! (TSYNC_ESRCH) instead of bit 5 (WAIT_KILLABLE_RECV); the install succeeded and the
//! preflight mask probe passed, but every wait stayed interruptible. these tests pin the
//! semantics behaviorally so a silent no-op flag cannot pass as protection again.
//!
//! mechanics: the child is the re-exec'd test binary (or python3 for the CI replica)
//! spawned through the production spawn path, so the filter under test carries the
//! production flags. the child announces its target syscall with a GO marker carrying its
//! tid, so the parent aims each signal at the trapped thread itself (a process-directed
//! signal could land on another thread of the child and prove nothing). handler
//! execution and the child's syscall result come back over the redirected stdout pipe
//! with distinctive markers.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use leash::recorder::Mode;
use leash::supervisor::spawn::{SpawnSpec, SupervisedChild, spawn_supervised};

const DEADLINE: Duration = Duration::from_secs(15);
const GO: &str = "GO ";
const HANDLER: &str = "HANDLER_RAN\n";
const TARGET: &str = "/etc/hostname";

static SPAWN_LOCK: Mutex<()> = Mutex::new(());

fn spawn_guard() -> MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// re-exec dispatch: with LEASH_WKR_AGENT set, the test binary is the probe child.
// same pattern as spawn_linux.rs's agent_dispatch (see ARCH-001: hold the lock even
// here; in the re-exec'd child it is a fresh, uncontended static).
// ---------------------------------------------------------------------------

/// the probe child's signal handler: prove the handler ran by writing a marker.
/// write(2) is async-signal-safe; fd 1 is the redirected pipe.
extern "C" fn signal_handler(_sig: libc::c_int) {
    // SAFETY: fd 1 is valid for the child's life; the buffer is static.
    unsafe { libc::write(1, HANDLER.as_ptr().cast(), HANDLER.len()) };
}

fn install_signal_handler(signal: libc::c_int, sa_restart: bool) {
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = signal_handler as *const () as usize;
    sa.sa_flags = if sa_restart { libc::SA_RESTART } else { 0 };
    // SAFETY: sa points at a valid zeroed mask we now empty.
    unsafe { libc::sigemptyset(&mut sa.sa_mask) };
    // SAFETY: sa is a fully-initialized sigaction for this process.
    let rc = unsafe { libc::sigaction(signal, &sa, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "sigaction: {}", std::io::Error::last_os_error());
}

#[test]
fn wkr_dispatch() {
    let _g = spawn_guard();
    let Ok(variant) = std::env::var("LEASH_WKR_AGENT") else {
        return;
    };
    let signal = if variant == "storm" {
        libc::SIGRTMIN()
    } else {
        libc::SIGUSR1
    };
    install_signal_handler(signal, variant == "restart");
    // announce with our thread id: a process-directed signal could land on the libtest
    // main thread instead of this trapped worker thread, so the parent aims by tid.
    // SAFETY: gettid takes no arguments and cannot fail.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    write_all(1, format!("GO {tid}\n").as_bytes());
    // settle: give the parent time to park in poll before the trap, so the target
    // notification is identified by order and nothing else can interleave
    unsafe { libc::usleep(300_000) };
    let path = std::ffi::CString::new(TARGET).unwrap();
    // SAFETY: open reads a nul-terminated path; this is the trapped syscall under test.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let report = if fd >= 0 {
        "RESULT:ok\n".to_string()
    } else {
        format!("RESULT:errno-{errno}\n")
    };
    write_all(1, report.as_bytes());
    std::process::exit(0);
}

fn write_all(fd: RawFd, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        // SAFETY: fd is valid for the writer's life; bytes outlives the call.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        assert!(n > 0, "write: {}", std::io::Error::last_os_error());
        bytes = &bytes[n as usize..];
    }
}

// ---------------------------------------------------------------------------
// parent-side harness
// ---------------------------------------------------------------------------

struct Probe {
    child: SupervisedChild,
    out: OwnedFd,
    seen: String,
}

impl Probe {
    fn pid(&self) -> libc::pid_t {
        self.child.pid
    }

    /// drain whatever the child has printed so far into `seen`.
    fn pump(&mut self) {
        let mut buf = [0u8; 4096];
        loop {
            let mut pfd = libc::pollfd {
                fd: self.out.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: pfd points at a valid one-element array; the fd is valid.
            let ready = unsafe { libc::poll(&mut pfd, 1, 0) };
            if ready <= 0 {
                return;
            }
            // SAFETY: the fd is valid and buf is writable for its length.
            let n = unsafe { libc::read(self.out.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                return;
            }
            self.seen
                .push_str(&String::from_utf8_lossy(&buf[..n as usize]));
        }
    }

    /// continue every notification until the child's GO marker has been observed and
    /// the target trap is queued, then RECV and return the target notification.
    fn recv_target(&mut self) -> leash::supervisor::notify::SeccompNotif {
        let start = Instant::now();
        let mut saw_go = false;
        loop {
            assert!(
                start.elapsed() < DEADLINE,
                "target trap never arrived; child output so far:\n{}",
                self.seen
            );
            let mut pfd = libc::pollfd {
                fd: self.child.notify.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: pfd points at a valid one-element array; the fd is valid.
            let ready = unsafe { libc::poll(&mut pfd, 1, 100) };
            self.pump();
            if !saw_go && self.seen.contains(GO) {
                saw_go = true;
            }
            if ready <= 0 {
                continue;
            }
            let n = self.child.notify.recv().expect("recv after poll");
            if saw_go {
                assert_eq!(
                    n.pid,
                    announced_tid(&self.seen),
                    "post-GO notification came from a different thread"
                );
                return n;
            }
            self.child.notify.send_continue(n.id).expect("continue");
        }
    }

    /// the notify fd goes quiet within `budget` (no re-trap, no second notification).
    /// true if no NEW notification arrives within budget. only POLLIN counts: when
    /// the child exits the kernel wakes the fd with EPOLLHUP (commit 95036a79e7b5),
    /// which is silence, not a notification.
    fn notify_is_quiet(&self, budget: Duration) -> bool {
        let mut pfd = libc::pollfd {
            fd: self.child.notify.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd points at a valid one-element array; the fd is valid.
        let rc = unsafe { libc::poll(&mut pfd, 1, budget.as_millis() as i32) };
        rc == 0 || pfd.revents & libc::POLLIN == 0
    }

    /// reap the child with a deadline, returning its final output.
    fn reap(mut self) -> String {
        let start = Instant::now();
        loop {
            self.pump();
            let mut status = 0;
            // SAFETY: waitpid on the child we spawned; WNOHANG never blocks.
            let rc = unsafe { libc::waitpid(self.child.pid, &mut status, libc::WNOHANG) };
            if rc == self.child.pid {
                self.pump();
                return self.seen;
            }
            // ECHILD: a WNOHANG probe in a serve loop already reaped it; the output
            // left in the pipe is still ours to drain.
            if rc == -1 {
                self.pump();
                return self.seen;
            }
            if start.elapsed() > DEADLINE {
                // capture where the child is stuck before killing it: wchan names the
                // kernel wait site, stack the syscall path (issue #36 debugging aid).
                let wchan = std::fs::read_to_string(format!("/proc/{}/wchan", self.child.pid))
                    .unwrap_or_default();
                let stack = std::fs::read_to_string(format!("/proc/{}/stack", self.child.pid))
                    .unwrap_or_default();
                let proc_status =
                    std::fs::read_to_string(format!("/proc/{}/status", self.child.pid))
                        .unwrap_or_default();
                let state = proc_status
                    .lines()
                    .find(|l| l.starts_with("State:"))
                    .unwrap_or("State: unknown")
                    .to_string();
                let sigpnd = proc_status
                    .lines()
                    .find(|l| l.starts_with("SigPnd:"))
                    .unwrap_or("")
                    .to_string();
                // SAFETY: the child is ours; SIGKILL is the watchdog of last resort.
                unsafe { libc::kill(self.child.pid, libc::SIGKILL) };
                // SAFETY: reaping the killed child.
                unsafe { libc::waitpid(self.child.pid, &mut status, 0) };
                panic!(
                    "probe child exceeded the deadline; {state} {sigpnd} wchan={} \
                     stack=[{}] output so far:\n{}",
                    wchan.trim(),
                    stack.trim().replace('\n', "; "),
                    self.seen
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

/// spawn the re-exec'd probe child through the production spawn path (production filter,
/// production flags) with stdout+stderr redirected to a pipe the parent reads.
fn spawn_probe(variant: &str) -> Probe {
    let mut fds = [0; 2];
    // SAFETY: fds is a valid two-element out-array.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: pipe2 returned two owned descriptors.
    let (read_end, write_end) =
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };

    // the env window is guarded by the spawn lock (ARCH-001); the child inherits it.
    // SAFETY: set_var/remove_var are unsafe in edition 2024 because env mutation can
    // race other threads' env reads; the spawn lock serializes every env window in this
    // binary, and the child is spawned inside the window.
    unsafe { std::env::set_var("LEASH_WKR_AGENT", variant) };
    let child = spawn_supervised(&SpawnSpec {
        argv: vec![
            self_exe(),
            "--exact".into(),
            "wkr_dispatch".into(),
            "--nocapture".into(),
        ],
        stdout: Some(write_end),
        mode: Mode::RecordOnly,
        landlock_ruleset: None,
    })
    .expect("probe child must spawn");
    unsafe { std::env::remove_var("LEASH_WKR_AGENT") };

    Probe {
        child,
        out: read_end,
        seen: String::new(),
    }
}

fn self_exe() -> String {
    std::env::current_exe()
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

/// SIGUSR1 the trapped thread; tgkill returning 0 proves the signal was posted to it.
/// process-directed kill could deliver to another thread of the child and prove nothing
/// about the trapped wait, so every case aims at the trapped tid.
fn post_signal(pid: libc::pid_t, tid: u32) {
    let tid = libc::pid_t::try_from(tid).expect("notification tid fits pid_t");
    // SAFETY: pid/tid name the child's trapped thread, both live at call time.
    let rc = unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGUSR1) };
    assert_eq!(rc, 0, "tgkill: {}", std::io::Error::last_os_error());
}

fn post_queued_signal(pid: libc::pid_t, tid: u32) {
    let tid = libc::pid_t::try_from(tid).expect("notification tid fits pid_t");
    let signal = libc::SIGRTMIN();
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    info.si_signo = signal;
    info.si_code = libc::SI_QUEUE;
    let rc = unsafe { libc::syscall(libc::SYS_rt_tgsigqueueinfo, pid, tid, signal, &info) };
    assert_eq!(
        rc,
        0,
        "rt_tgsigqueueinfo: {}",
        std::io::Error::last_os_error()
    );
}

/// the trapped thread's tid, parsed from the GO marker the child announced.
fn announced_tid(output: &str) -> u32 {
    let line = output
        .lines()
        .find(|l| l.starts_with(GO))
        .unwrap_or_else(|| panic!("no GO marker in:\n{output}"));
    line[GO.len()..].trim().parse().expect("GO carries a tid")
}

/// the shared assertions for a protected (post-RECV) wait, per the kernel source:
/// the handler must not run while the supervisor holds the notification, no re-trap
/// may appear, the SEND must succeed, and the child must observe the spoofed errno,
/// with the deferred handler running before its result report.
fn assert_wait_held(
    mut probe: Probe,
    n: &leash::supervisor::notify::SeccompNotif,
    expected_handlers: usize,
) {
    probe.pump();
    assert!(
        !probe.seen.contains(HANDLER) && !probe.seen.contains("RESULT:"),
        "the handler ran or the syscall returned while RECV'd and pending:\n{}",
        probe.seen
    );
    assert!(
        probe.notify_is_quiet(Duration::from_millis(300)),
        "a second notification appeared (a cancelled-and-restarted syscall):\n{}",
        probe.seen
    );
    probe
        .child
        .notify
        .send_error(n.id, libc::EACCES)
        .expect("SEND must succeed on a live, protected notification");

    let output = probe.reap();
    let handler_count = output.matches(HANDLER).count();
    let handler_at = output.rfind(HANDLER);
    let result_at = output.find("RESULT:errno-13");
    assert_eq!(
        handler_count, expected_handlers,
        "every queued signal must reach the deferred handler:\n{output}"
    );
    assert!(
        result_at.is_some(),
        "the child must observe the spoofed EACCES:\n{output}"
    );
    assert!(
        handler_at.unwrap() < result_at.unwrap(),
        "the handler runs before the syscall's caller resumes:\n{output}"
    );
}

/// case 1 (the section 4.1 case): a caught non-fatal signal, no SA_RESTART, delivered
/// after the supervisor RECV'd the notification, must not cancel it.
#[test]
fn post_recv_signal_does_not_cancel_a_received_notification() {
    let _g = spawn_guard();
    let mut probe = spawn_probe("held");
    let n = probe.recv_target();
    let tid = announced_tid(&probe.seen);
    println!(
        "PROBE notif id={} notif.pid={} go-tid={tid} child-tgid={}",
        n.id,
        n.pid,
        probe.pid()
    );

    post_signal(probe.pid(), n.pid);
    std::thread::sleep(Duration::from_millis(200));
    probe.pump();
    println!(
        "PROBE after-signal: valid={:?} seen-handler={} seen-result={}",
        probe.child.notify.id_valid(n.id),
        probe.seen.contains(HANDLER),
        probe.seen.contains("RESULT:")
    );
    let send = probe.child.notify.send_error(n.id, libc::EACCES);
    println!("PROBE send result: {send:?}");
    let quiet = probe.notify_is_quiet(Duration::from_millis(300));
    println!("PROBE notify-quiet-after-send: {quiet}");
    if !quiet {
        let n2 = probe.child.notify.recv().expect("second notification");
        println!(
            "PROBE second notif id={} pid={} nr={}",
            n2.id, n2.pid, n2.data.nr
        );
        let _ = probe.child.notify.send_error(n2.id, libc::EACCES);
    }
    let output = probe.reap();
    println!("PROBE child final output:\n{output}");

    assert!(send.is_ok(), "SEND must succeed on a live notification");
    assert!(
        !output.contains("RESULT:errno-4"),
        "the trapped syscall must not return EINTR"
    );
}

/// case 2 (control): the same signal delivered before RECV must cancel. poll-readable
/// on the notify fd proves the child is in the INIT wait; the interrupted path then
/// list_del's the notification, so nothing remains to RECV.
#[test]
fn pre_recv_signal_cancels_the_notification() {
    let _g = spawn_guard();
    let mut probe = spawn_probe("held");

    // serve startup traps until GO, then wait for the target trap to queue
    let start = Instant::now();
    loop {
        probe.pump();
        if probe.seen.contains(GO) {
            break;
        }
        // continue whatever traps so the child reaches its target
        let mut pfd = libc::pollfd {
            fd: probe.child.notify.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd points at a valid one-element array; the fd is valid.
        let ready = unsafe { libc::poll(&mut pfd, 1, 100) };
        if ready > 0 {
            let n = probe.child.notify.recv().expect("recv after poll");
            probe.child.notify.send_continue(n.id).expect("continue");
        }
        assert!(start.elapsed() < DEADLINE, "no GO marker:\n{}", probe.seen);
    }
    assert!(
        !probe.notify_is_quiet(DEADLINE),
        "the target trap never queued:\n{}",
        probe.seen
    );

    post_signal(probe.pid(), announced_tid(&probe.seen));
    std::thread::sleep(Duration::from_millis(300));

    probe.pump();
    assert!(
        probe.seen.contains(HANDLER),
        "pre-RECV the signal must reach the handler:\n{}",
        probe.seen
    );
    assert!(
        probe.seen.contains("RESULT:errno-4"),
        "pre-RECV the syscall must return EINTR:\n{}",
        probe.seen
    );
    assert!(
        probe.notify_is_quiet(Duration::from_millis(300)),
        "a cancelled notification must leave nothing to RECV:\n{}",
        probe.seen
    );
    probe.reap();
}

/// case 3: SA_RESTART must be irrelevant under the protection; identical to case 1.
#[test]
fn post_recv_signal_with_sa_restart_also_does_not_cancel() {
    let _g = spawn_guard();
    let mut probe = spawn_probe("restart");
    let n = probe.recv_target();

    post_signal(probe.pid(), n.pid);
    std::thread::sleep(Duration::from_millis(200));

    assert_wait_held(probe, &n, 1);
}

/// case 4 (adversarial, NFR-5): a storm of queued real-time signals after RECV must not
/// cancel the notification.
#[test]
fn a_signal_storm_after_recv_still_does_not_cancel() {
    let _g = spawn_guard();
    let mut probe = spawn_probe("storm");
    let n = probe.recv_target();

    for _ in 0..5 {
        post_queued_signal(probe.pid(), n.pid);
        std::thread::sleep(Duration::from_millis(50));
    }

    assert_wait_held(probe, &n, 5);
}

/// case 5 (CI replica, reports rather than asserts): python arms a caught SIGALRM one
/// second before opening the target, exactly the issue #30 CI scenario. the verdict
/// line records whether the handler ran while the notification was RECV'd and pending.
#[test]
fn ci_replica_python_alarm_during_a_pending_notification() {
    let _g = spawn_guard();
    let script = concat!(
        "import signal,os\n",
        "signal.signal(signal.SIGALRM,lambda s,f: os.write(1,b'ALARM_HANDLED\\n'))\n",
        "os.write(1,('GO %d\\n'%os.getpid()).encode())\n",
        "signal.setitimer(signal.ITIMER_REAL,1.0)\n",
        "import errno\n",
        "try:\n",
        "    os.open('/etc/hostname',os.O_RDONLY)\n",
        "    os.write(1,b'OPEN_OK\\n')\n",
        "except PermissionError:\n",
        "    os.write(1,b'OPEN_EACCES\\n')\n",
        "except OSError as e:\n",
        "    os.write(1,('OPEN_ERR_%d\\n'%e.errno).encode())\n",
    );
    let mut fds = [0; 2];
    // SAFETY: fds is a valid two-element out-array.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: pipe2 returned two owned descriptors.
    let (read_end, write_end) =
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let child = spawn_supervised(&SpawnSpec {
        argv: vec!["/usr/bin/python3".into(), "-c".into(), script.into()],
        stdout: Some(write_end),
        mode: Mode::RecordOnly,
        landlock_ruleset: None,
    })
    .expect("python probe child must spawn");
    let mut probe = Probe {
        child,
        out: read_end,
        seen: String::new(),
    };

    let n = probe.recv_target();
    std::thread::sleep(Duration::from_millis(1500));
    probe.pump();

    let handler_before_send = probe.seen.contains("ALARM_HANDLED");
    let quiet = probe.notify_is_quiet(Duration::from_millis(100));
    println!(
        "CI-REPLICA VERDICT: handler-ran-while-pending={handler_before_send} \
         second-trap-before-send={}",
        !quiet
    );

    probe
        .child
        .notify
        .send_error(n.id, libc::EACCES)
        .expect("SEND for the replica notification");

    // serve any retry (PEP 475 re-traps after EINTR) so the child can exit
    let start = Instant::now();
    let mut retried = false;
    while start.elapsed() < Duration::from_secs(3) {
        if probe.notify_is_quiet(Duration::from_millis(100)) {
            if retried {
                break;
            }
            // waitpid without blocking: the child may already be gone
            let mut status = 0;
            // SAFETY: WNOHANG on the child we spawned.
            let rc = unsafe { libc::waitpid(probe.pid(), &mut status, libc::WNOHANG) };
            if rc == probe.pid() {
                break;
            }
            continue;
        }
        let n = probe.child.notify.recv().expect("recv after poll");
        retried = true;
        probe
            .child
            .notify
            .send_error(n.id, libc::EACCES)
            .expect("SEND for the retried notification");
    }
    let output = probe.reap();
    println!("CI-REPLICA DETAIL: retried={retried}\n{output}");
}
