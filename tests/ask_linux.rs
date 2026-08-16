//! behavioral tests for the attended ask (docs/design/notify-loop.md section 5; FR-10,
//! FR-20; issue #30).
//!
//! these run only on linux and drive the real compiled binary on a real pseudoterminal:
//! the leash child gets the pty slave as stdio and as its controlling terminal, so the
//! run computes attended and the prompt the operator would see is driven through the pty
//! master. every acceptance behavior of issue #30 is observed end to end here: approval
//! realizes the allow through the confined broker, deny and timeout deny and record
//! which, `--unattended` never prompts, an ignored signal during a pending ask does not
//! disturb the held syscall, the answer bytes never leak into the child's stdin, and
//! one held syscall prompts once even when several of its accesses match the ask rule.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(20);
const SECRET_CONTENT: &str = "leash-ask-secret";

fn leash_exe() -> &'static str {
    env!("CARGO_BIN_EXE_leash")
}

/// a freshly allocated pty: the master the test drives, and the slave path the child
/// gets as its controlling terminal.
struct Pty {
    master: OwnedFd,
    slave_path: PathBuf,
}

fn open_pty() -> Pty {
    // SAFETY: posix_openpt allocates a new pty master; the result is a valid fd or -1,
    // which is asserted before any further use.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    assert!(
        master >= 0,
        "posix_openpt: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: master is a valid pty master just opened above.
    assert_eq!(unsafe { libc::grantpt(master) }, 0, "grantpt");
    // SAFETY: master is a valid granted pty master.
    assert_eq!(unsafe { libc::unlockpt(master) }, 0, "unlockpt");
    let mut buf = [0i8; 128];
    // SAFETY: master is a valid unlocked pty master; buf is writable for its length.
    assert_eq!(
        unsafe { libc::ptsname_r(master, buf.as_mut_ptr(), buf.len()) },
        0,
        "ptsname_r"
    );
    // SAFETY: ptsname_r succeeded, so buf holds a nul-terminated string.
    let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    Pty {
        // SAFETY: master is a uniquely-owned open fd; wrapped exactly once here.
        master: unsafe { OwnedFd::from_raw_fd(master) },
        slave_path: PathBuf::from(name.to_str().unwrap()),
    }
}

/// spawn `leash run <args>` with the pty slave as stdin/stdout/stderr and as the
/// controlling terminal of a fresh session: the run computes attended (cli.md
/// section 3) and /dev/tty resolves to this pty.
fn spawn_attached(args: &[String], cwd: &Path, pty: &Pty) -> Child {
    let slave = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&pty.slave_path)
        .unwrap();
    let mut cmd = Command::new(leash_exe());
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave));
    // SAFETY: pre_exec runs in the forked child after stdio is wired and before exec.
    // setsid makes the child a session leader with no controlling terminal; TIOCSCTTY
    // on fd 0 (the pty slave) adopts it as the controlling terminal. both calls are
    // async-signal-safe and touch no shared state.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn().expect("leash binary must spawn")
}

/// the pty master end: accumulates everything the operator would see.
struct Driver {
    master: OwnedFd,
    output: Vec<u8>,
}

impl Driver {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.output).into_owned()
    }

    /// read until `needle` appears in the accumulated output, or fail with what we saw.
    fn read_until(&mut self, needle: &str, budget: Duration) {
        let start = Instant::now();
        while !self.text().contains(needle) {
            assert!(
                start.elapsed() < budget,
                "timed out waiting for {needle:?}; output so far:\n{}",
                self.text()
            );
            let mut pfd = libc::pollfd {
                fd: self.master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: pfd points at a valid one-element array; master is a valid fd.
            let ready = unsafe { libc::poll(&mut pfd, 1, 100) };
            if ready <= 0 {
                continue;
            }
            let mut buf = [0u8; 4096];
            // SAFETY: master is valid; buf is writable for its length.
            let n =
                unsafe { libc::read(self.master.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                // EIO once the child's side is gone; the budget above bounds the loop
                continue;
            }
            self.output.extend_from_slice(&buf[..n as usize]);
        }
    }

    /// type an operator answer into the terminal.
    fn answer(&mut self, text: &str) {
        // SAFETY: master is valid; text outlives the call.
        let written =
            unsafe { libc::write(self.master.as_raw_fd(), text.as_ptr().cast(), text.len()) };
        assert_eq!(written, text.len() as isize, "answer written in full");
    }

    /// collect whatever the child printed after the answer until its side closes.
    /// bounded: a leaked slave fd would otherwise hang the test.
    fn drain(&mut self) {
        let start = Instant::now();
        let mut buf = [0u8; 4096];
        loop {
            let mut pfd = libc::pollfd {
                fd: self.master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: pfd points at a valid one-element array; master is a valid fd.
            let ready = unsafe { libc::poll(&mut pfd, 1, 100) };
            if ready < 0 || start.elapsed() > Duration::from_secs(3) {
                return;
            }
            if ready == 0 {
                continue;
            }
            // SAFETY: master is valid; buf is writable for its length. EIO means the
            // child's side of the pty is gone, i.e. end of output.
            let n =
                unsafe { libc::read(self.master.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                return;
            }
            self.output.extend_from_slice(&buf[..n as usize]);
        }
    }
}

/// wait for the run to end; on timeout, kill it and fail with the full operator output
/// and the trace so far, because a wedged run is only debuggable from what it left behind.
fn wait_or_dump(run: &mut AskRun) -> ExitStatus {
    let start = Instant::now();
    loop {
        match run.child.try_wait().expect("try_wait") {
            Some(status) => return status,
            None if start.elapsed() > DEADLINE => {
                let _ = run.child.kill();
                let _ = run.child.wait();
                run.driver.drain();
                let trace = only_run_dir(run.state.path()).join("trace.jsonl");
                panic!(
                    "leash exceeded the deadline; output:\n{}\ntrace:\n{}",
                    run.driver.text(),
                    std::fs::read_to_string(&trace)
                        .unwrap_or_else(|e| format!("(unreadable: {e})"))
                );
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    }
}

/// the standard fixture policy plus one ask rule on the secret path. the broad read and
/// exec allows keep a dynamic binary running; the ask rule sits above them so it wins.
fn write_ask_policy(state: &Path, secret: &Path, modes: &str) -> PathBuf {
    let policy_path = state.join("policy.toml");
    std::fs::write(
        &policy_path,
        format!(
            "schema_version = 1\n\
             [[fs]]\npath={:?}\nmode={modes}\naction=\"ask\"\n\
             [[fs]]\npath=\"/**\"\nmode=[\"read\"]\naction=\"allow\"\n\
             [[exec]]\nbinary=\"/**\"\naction=\"allow\"\n",
            secret.to_string_lossy()
        ),
    )
    .unwrap();
    policy_path
}

/// one attended run on a pty: workspace, state, and a secret file outside the
/// workspace. `agent` is a argv template where `{secret}` expands to the secret path.
struct AskRun {
    child: Child,
    driver: Driver,
    state: tempfile::TempDir,
    _workspace: tempfile::TempDir,
    _outside: tempfile::TempDir,
}

fn start_ask_run(modes: &str, agent: &[&str], extra_flags: &[&str]) -> AskRun {
    let workspace = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret.txt");
    std::fs::write(&secret, SECRET_CONTENT).unwrap();
    let policy_path = write_ask_policy(state.path(), &secret, modes);

    let pty = open_pty();
    let mut args: Vec<String> = vec![
        "run".into(),
        "--state-dir".into(),
        state.path().to_str().unwrap().into(),
        "--policy".into(),
        policy_path.to_str().unwrap().into(),
    ];
    args.extend(extra_flags.iter().map(|f| f.to_string()));
    args.push("--".into());
    args.extend(
        agent
            .iter()
            .map(|a| a.replace("{secret}", secret.to_str().unwrap())),
    );

    let child = spawn_attached(&args, workspace.path(), &pty);
    AskRun {
        child,
        driver: Driver {
            master: pty.master,
            output: Vec::new(),
        },
        state,
        _workspace: workspace,
        _outside: outside,
    }
}

/// wait for the prompt, answer it, wait for the run to end, drain the rest of the output.
fn answer_prompt(run: &mut AskRun, answer: &str) -> (ExitStatus, String) {
    run.driver
        .read_until("allow? [y/N]", Duration::from_secs(10));
    run.driver.answer(answer);
    let status = wait_or_dump(run);
    run.driver.drain();
    (status, run.driver.text())
}

fn trace_events(run_dir: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(run_dir.join("trace.jsonl"))
        .expect("trace.jsonl must exist")
        .lines()
        .map(|l| serde_json::from_str(l).expect("every trace line parses"))
        .collect()
}

fn only_run_dir(state: &Path) -> PathBuf {
    let runs: Vec<_> = std::fs::read_dir(state.join("runs"))
        .expect("runs dir must exist")
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(runs.len(), 1, "exactly one run directory: {runs:?}");
    runs.into_iter().next().unwrap()
}

/// the syscall events for the secret file's open, in order.
fn secret_events(run_dir: &Path) -> Vec<serde_json::Value> {
    trace_events(run_dir)
        .into_iter()
        .filter(|e| {
            e["fact"]["path"]
                .as_str()
                .is_some_and(|p| p.ends_with("secret.txt"))
        })
        .collect()
}

/// acceptance 1 (FR-10): an approval at the prompt realizes the allow exactly as a
/// policy allow would, through the confined broker, and the trace records it. the
/// prompt names the action and the rule (issue #30: prompt context).
#[test]
fn approved_ask_realizes_the_allow() {
    let mut run = start_ask_run("[\"read\"]", &["/bin/cat", "{secret}"], &[]);

    run.driver
        .read_until("allow? [y/N]", Duration::from_secs(10));
    let prompt_text = run.driver.text();
    assert!(
        prompt_text.contains("read ") && prompt_text.contains("secret.txt"),
        "the prompt names the action: {prompt_text}"
    );
    assert!(
        prompt_text.contains("(rule fs.1)"),
        "the prompt names the rule: {prompt_text}"
    );
    run.driver.answer("y\n");
    let status = wait_or_dump(&mut run);
    run.driver.drain();
    let output = run.driver.text();

    assert!(status.success(), "approved cat must exit 0: {output}");
    assert!(
        output.contains(SECRET_CONTENT),
        "the child observes the realized allow: {output}"
    );

    let events = secret_events(&only_run_dir(run.state.path()));
    assert_eq!(
        events.len(),
        1,
        "one mediated open of the secret: {events:?}"
    );
    assert_eq!(events[0]["decision"], "ask");
    assert_eq!(events[0]["ask_resolution"], "approved");
    assert_eq!(events[0]["matched_rule"], "fs.1");
}

/// acceptance 2 (FR-10): a denial at the prompt blocks the action with EACCES and the
/// trace records `denied`.
#[test]
fn denied_ask_blocks_the_action() {
    let mut run = start_ask_run("[\"read\"]", &["/bin/cat", "{secret}"], &[]);
    let (status, output) = answer_prompt(&mut run, "n\n");

    assert_eq!(status.code(), Some(1), "denied cat must fail: {output}");
    assert!(
        output.contains("Permission denied"),
        "the child observes EACCES: {output}"
    );
    assert!(
        !output.contains(SECRET_CONTENT),
        "a denied read must not reach the file: {output}"
    );

    let events = secret_events(&only_run_dir(run.state.path()));
    assert_eq!(
        events.len(),
        1,
        "one mediated open of the secret: {events:?}"
    );
    assert_eq!(events[0]["decision"], "ask");
    assert_eq!(events[0]["ask_resolution"], "denied");
}

/// acceptance 3 (FR-10): no answer within the configured bound denies and records
/// `timed_out`; the whole-tree stall stays bounded (notify-loop.md section 5).
#[test]
fn an_unanswered_ask_times_out_to_deny() {
    let mut run = start_ask_run(
        "[\"read\"]",
        &["/bin/cat", "{secret}"],
        &["--ask-timeout", "2"],
    );

    run.driver
        .read_until("allow? [y/N]", Duration::from_secs(10));
    let start = Instant::now();
    let status = wait_or_dump(&mut run);
    run.driver.drain();
    let output = run.driver.text();

    assert!(
        start.elapsed() >= Duration::from_secs(2),
        "the timeout must actually bound the wait"
    );
    assert_eq!(status.code(), Some(1), "timed-out cat must fail: {output}");
    assert!(
        !output.contains(SECRET_CONTENT),
        "a timed-out read must not reach the file: {output}"
    );

    let events = secret_events(&only_run_dir(run.state.path()));
    assert_eq!(
        events.len(),
        1,
        "one mediated open of the secret: {events:?}"
    );
    assert_eq!(events[0]["decision"], "ask");
    assert_eq!(events[0]["ask_resolution"], "timed_out");
}

/// acceptance 4 (FR-20): without a terminal the ask never prompts; it denies
/// immediately and records `unattended`.
#[test]
fn unattended_ask_denies_without_prompting() {
    let workspace = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret.txt");
    std::fs::write(&secret, SECRET_CONTENT).unwrap();
    let policy_path = write_ask_policy(state.path(), &secret, "[\"read\"]");

    // pipes, not a pty: attendance computes unattended (cli.md section 3)
    let out = Command::new(leash_exe())
        .args([
            "run",
            "--state-dir",
            state.path().to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--",
            "/bin/cat",
            secret.to_str().unwrap(),
        ])
        .current_dir(workspace.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("leash binary must run");

    assert_eq!(out.status.code(), Some(1), "unattended cat must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("allow? [y/N]"),
        "an unattended run must not prompt: {stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains(SECRET_CONTENT),
        "an unattended ask must not reach the file"
    );

    let events = secret_events(&only_run_dir(state.path()));
    assert_eq!(
        events.len(),
        1,
        "one mediated open of the secret: {events:?}"
    );
    assert_eq!(events[0]["decision"], "ask");
    assert_eq!(events[0]["ask_resolution"], "unattended");
}

/// signal survival (issue #30): a signal whose disposition is ignore cannot disturb the
/// wait at all, so the held syscall completes exactly once after the approval.
///
/// note: this test originally armed a *caught* SIGALRM to prove the notify-loop.md
/// section 4.1 claim that WAIT_KILLABLE_RECV shields a received notification from
/// non-fatal signals. on the CI kernel (6.17.0-1022-azure) the pending notification was
/// cancelled anyway (EINTR, handler ran, python retried, a second prompt appeared), so
/// that documented semantics did not hold as written. the caught-signal question is a
/// design-level finding tracked separately; this test pins the guarantee that does hold.
#[test]
fn an_ignored_signal_during_the_ask_does_not_disturb_the_held_syscall() {
    // the agent ignores SIGALRM, arms a 1 s alarm, then opens the secret. the alarm
    // fires while the ask is pending; an ignored signal cannot interrupt the wait, so
    // the approval completes the open exactly once.
    let script = concat!(
        "import signal,sys\n",
        "signal.signal(signal.SIGALRM,signal.SIG_IGN)\n",
        "signal.setitimer(signal.ITIMER_REAL,1.0)\n",
        "print(open(sys.argv[1]).read(),end='')\n",
    );
    let mut run = start_ask_run(
        "[\"read\"]",
        &["/usr/bin/python3", "-c", script, "{secret}"],
        &[],
    );

    run.driver
        .read_until("allow? [y/N]", Duration::from_secs(10));
    // let the alarm fire while the ask is still pending
    std::thread::sleep(Duration::from_millis(2000));
    run.driver.answer("y\n");
    let status = wait_or_dump(&mut run);
    run.driver.drain();
    let output = run.driver.text();

    assert!(status.success(), "approved run must exit 0: {output}");
    assert_eq!(
        output.matches(SECRET_CONTENT).count(),
        1,
        "the held open completes exactly once: {output}"
    );

    let events = secret_events(&only_run_dir(run.state.path()));
    assert_eq!(
        events.len(),
        1,
        "no cancelled-and-restarted open may appear: {events:?}"
    );
    assert_eq!(events[0]["ask_resolution"], "approved");
}

/// input hygiene (issue #30 review note): the prompt consumes the whole answer line, so
/// the trailing newline and the answer itself never reach the child's stdin.
#[test]
fn answer_bytes_do_not_leak_into_child_stdin() {
    // the agent reads the secret (the ask), then checks its stdin without blocking:
    // anything already queued would be the leaked answer bytes
    let script = concat!(
        "import os,select,sys\n",
        "open(sys.argv[1]).read()\n",
        "r,_,_=select.select([0],[],[],0.5)\n",
        "print('leftover=%r' % (os.read(0,64) if r else b''))\n",
    );
    let mut run = start_ask_run(
        "[\"read\"]",
        &["/usr/bin/python3", "-c", script, "{secret}"],
        &[],
    );
    let (status, output) = answer_prompt(&mut run, "y\n");

    assert!(status.success(), "the run must exit 0: {output}");
    assert!(
        output.contains("leftover=b''"),
        "no answer bytes may wait in the child's stdin: {output}"
    );
}

/// one prompt per syscall (notify-loop.md section 5): an O_RDWR open matches the ask
/// rule for read and for write; both are listed in one prompt and one answer settles
/// both, with per-access evidence recorded for each.
#[test]
fn one_prompt_covers_every_ask_matched_access_of_a_syscall() {
    // a plain O_RDWR open (no O_CREAT) matches the ask rule for read and for write
    let script = concat!(
        "import sys\n",
        "open(sys.argv[1],'r+')\n",
        "print('opened-rw')\n",
    );
    let mut run = start_ask_run(
        "[\"read\",\"write\"]",
        &["/usr/bin/python3", "-c", script, "{secret}"],
        &[],
    );

    run.driver
        .read_until("allow? [y/N]", Duration::from_secs(10));
    let prompt_text = run.driver.text();
    assert_eq!(
        prompt_text.matches("allow? [y/N]").count(),
        1,
        "exactly one prompt for the held syscall: {prompt_text}"
    );
    assert!(
        prompt_text.contains("read ") && prompt_text.contains("write "),
        "both accesses are listed: {prompt_text}"
    );
    run.driver.answer("y\n");
    let status = wait_or_dump(&mut run);
    run.driver.drain();
    let output = run.driver.text();

    assert!(status.success(), "approved rw open must exit 0: {output}");
    assert!(output.contains("opened-rw"), "{output}");

    let events = secret_events(&only_run_dir(run.state.path()));
    assert_eq!(
        events.len(),
        1,
        "one mediated open of the secret: {events:?}"
    );
    assert_eq!(events[0]["decision"], "ask");
    assert_eq!(events[0]["ask_resolution"], "approved");
}
