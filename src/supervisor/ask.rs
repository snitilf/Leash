//! the attended ask prompt (docs/design/notify-loop.md section 5; FR-10, FR-20).
//!
//! assumptions: one prompt per held syscall lists every ask-matched item with its rule,
//! and one answer covers them all. the prompt goes to the controlling terminal
//! (/dev/tty), never to stdout, which belongs to the child. every failure of the prompt
//! path resolves the ask to deny (I3): an ask the operator cannot answer is a deny,
//! never an allow. the timeout is a deadline, not a per-read budget, so a signal stream
//! cannot stretch the wait; the timeout is what bounds the whole-tree stall (ADR-0011).
//!
//! this module is cross-platform on purpose: the parsing and readline seams test on any
//! host with pipes; only the /dev/tty open and the pty end-to-end path are linux-proven
//! (tests/ask_linux.rs).

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::time::{Duration, Instant};

use crate::policy::Request;
use crate::recorder::{AskResolution, FsAccess};

/// longest accepted answer line; anything longer is garbage and denies.
const MAX_ANSWER: usize = 1024;

/// one ask-matched action of a held syscall, listed in the prompt so the operator sees
/// exactly what one answer covers (notify-loop.md section 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAsk {
    /// what the action is, e.g. "write /etc/ssh/config" or "connect 10.0.0.1:443"
    pub summary: String,
    /// the matched rule id, e.g. "fs.2"
    pub rule: String,
}

impl PendingAsk {
    /// describe one ask-matched request with the rule that matched it.
    pub fn new(request: &Request<'_>, rule: String) -> Self {
        let summary = match request {
            Request::Fs { path, access } => {
                let mut modes = String::new();
                for (i, one) in access.iter().enumerate() {
                    if i > 0 {
                        modes.push('+');
                    }
                    modes.push_str(match one {
                        FsAccess::Read => "read",
                        FsAccess::Write => "write",
                        FsAccess::Create => "create",
                        FsAccess::Delete => "delete",
                    });
                }
                format!("{modes} {path}")
            }
            Request::Net { ip, hostname, port } => match hostname {
                Some(name) => format!("connect {name} ({ip}:{port})"),
                None => format!("connect {ip}:{port}"),
            },
            Request::Exec { binary } => format!("exec {binary}"),
        };
        Self { summary, rule }
    }
}

/// the operator's answer to a prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Approve,
    Deny,
}

/// how a prompt attempt failed. the timeout is its own kind because FR-10 stamps it
/// as `timed_out`; every io failure collapses to deny.
#[derive(Debug)]
enum PromptError {
    Timeout,
    Io(io::Error),
}

impl From<io::Error> for PromptError {
    fn from(e: io::Error) -> Self {
        PromptError::Io(e)
    }
}

/// an explicit yes approves; anything else denies. the default must be the safe one:
/// an empty line, garbage, or an over-long line all land here.
fn parse_answer(line: &str) -> bool {
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// the prompt text for one held syscall: every ask-matched item with its rule, then the
/// question with the deny-by-default hint and the timeout.
fn format_prompt(asks: &[PendingAsk], timeout: Duration) -> String {
    let mut out = String::from("leash: the agent asks for:\n");
    for ask in asks {
        let _ = writeln!(out, "  {} (rule {})", ask.summary, ask.rule);
    }
    let _ = write!(out, "allow? [y/N] (denies in {}s): ", timeout.as_secs());
    out
}

/// the production prompter (FR-10): ask on the controlling terminal.
pub fn tty_prompt(asks: &[PendingAsk], timeout: Duration) -> AskResolution {
    let result = prompt_on_tty(asks, timeout);
    if let Err(PromptError::Io(e)) = &result {
        eprintln!("leash: ask prompt failed ({e}); denying");
    }
    resolution_of(result)
}

/// fail-closed mapping of a prompt outcome (I3): a timeout stamps `timed_out`, and any
/// io failure - the tty missing in a run that computed attended, a failed write, a
/// failed read - denies.
fn resolution_of(result: Result<Answer, PromptError>) -> AskResolution {
    match result {
        Ok(Answer::Approve) => AskResolution::Approved,
        Ok(Answer::Deny) => AskResolution::Denied,
        Err(PromptError::Timeout) => AskResolution::TimedOut,
        Err(PromptError::Io(_)) => AskResolution::Denied,
    }
}

/// open the controlling terminal, show the prompt, read one answer line.
fn prompt_on_tty(asks: &[PendingAsk], timeout: Duration) -> Result<Answer, PromptError> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/dev/tty")?;
    tty.write_all(format_prompt(asks, timeout).as_bytes())?;
    let line = read_line(tty.as_fd(), deadline(timeout))?;
    Ok(if parse_answer(&line) {
        Answer::Approve
    } else {
        Answer::Deny
    })
}

/// the instant the wait ends. the timeout is a single deadline for the whole prompt, not
/// a per-read budget: poll retries EINTR against this same instant, so signals to the
/// supervisor cannot stretch the stall.
fn deadline(timeout: Duration) -> Instant {
    Instant::now() + timeout
}

/// read one line from `fd`, giving up at `deadline`. a full line is read so the trailing
/// newline is consumed here and never leaks into the child's stdin. anything the
/// operator types past the first line is their own input and stays queued for them.
fn read_line(fd: BorrowedFd<'_>, deadline: Instant) -> Result<String, PromptError> {
    let mut buf = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(PromptError::Timeout);
        }
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // round up: a truncated poll budget could fire just before the deadline, and
        // the timeout must never deny a hair early
        let millis = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        // SAFETY: pfd points at a valid one-element array; the fd outlives the call,
        // borrowed from the caller.
        let ready = unsafe { libc::poll(&mut pfd, 1, millis) };
        if ready < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(PromptError::Io(err));
        }
        if ready == 0 {
            return Err(PromptError::Timeout);
        }
        let mut chunk = [0u8; 256];
        // SAFETY: fd is a valid open descriptor borrowed from the caller and outlives
        // the call; chunk is a valid writable buffer of chunk.len() bytes.
        let n = unsafe { libc::read(fd.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(PromptError::Io(err));
        }
        if n == 0 {
            break;
        }
        let n = n as usize;
        let done = chunk[..n].contains(&b'\n');
        buf.extend_from_slice(&chunk[..n]);
        if done || buf.len() >= MAX_ANSWER {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::Duration;

    fn fs_ask(access: &[FsAccess]) -> PendingAsk {
        PendingAsk::new(
            &Request::Fs {
                path: "/etc/ssh/config",
                access,
            },
            "fs.2".to_string(),
        )
    }

    #[test]
    fn pending_ask_describes_each_request_family() {
        assert_eq!(
            fs_ask(&[FsAccess::Read, FsAccess::Write]).summary,
            "read+write /etc/ssh/config"
        );
        let net = PendingAsk::new(
            &Request::Net {
                ip: "10.0.0.1".parse().unwrap(),
                hostname: Some("api.example.com"),
                port: 443,
            },
            "net.1".to_string(),
        );
        assert_eq!(net.summary, "connect api.example.com (10.0.0.1:443)");
        let exec = PendingAsk::new(
            &Request::Exec {
                binary: "/usr/bin/git",
            },
            "exec.1".to_string(),
        );
        assert_eq!(exec.summary, "exec /usr/bin/git");
    }

    #[test]
    fn only_an_explicit_yes_approves() {
        for yes in ["y", "Y", "yes", "YES", "  yes  ", "y\n"] {
            assert!(parse_answer(yes), "{yes:?} approves");
        }
        for no in ["", "\n", "n", "no", "N", "garbage", "yy", "yesplease"] {
            assert!(!parse_answer(no), "{no:?} denies");
        }
    }

    #[test]
    fn prompt_lists_every_item_with_its_rule_and_the_timeout() {
        let text = format_prompt(
            &[
                fs_ask(&[FsAccess::Write]),
                PendingAsk::new(
                    &Request::Exec {
                        binary: "/usr/bin/git",
                    },
                    "exec.1".to_string(),
                ),
            ],
            Duration::from_secs(60),
        );
        assert!(text.contains("write /etc/ssh/config (rule fs.2)"), "{text}");
        assert!(text.contains("exec /usr/bin/git (rule exec.1)"), "{text}");
        assert!(text.contains("denies in 60s"), "{text}");
        assert!(text.contains("[y/N]"), "{text}");
    }

    /// pipe pair with a raw fd read end: the readline seam runs on any host.
    fn pipe_pair() -> (UnixStream, UnixStream) {
        UnixStream::pair().unwrap()
    }

    #[test]
    fn readline_returns_a_full_answer_line() {
        let (mut writer, reader) = pipe_pair();
        writer.write_all(b"yes\n").unwrap();
        let line = read_line(reader.as_fd(), deadline(Duration::from_secs(5))).unwrap();
        assert_eq!(line, "yes\n");
    }

    #[test]
    fn readline_accepts_eof_without_a_newline() {
        let (mut writer, reader) = pipe_pair();
        writer.write_all(b"y").unwrap();
        drop(writer);
        let line = read_line(reader.as_fd(), deadline(Duration::from_secs(5))).unwrap();
        assert_eq!(line, "y");
    }

    #[test]
    fn readline_times_out_against_the_deadline() {
        let (_writer, reader) = pipe_pair();
        let start = Instant::now();
        let err = read_line(reader.as_fd(), deadline(Duration::from_millis(100))).unwrap_err();
        assert!(matches!(err, PromptError::Timeout));
        assert!(start.elapsed() >= Duration::from_millis(100));
    }

    #[test]
    fn readline_survives_a_slow_writer_within_the_deadline() {
        let (mut writer, reader) = pipe_pair();
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            writer.write_all(b"y\n").unwrap();
        });
        let line = read_line(reader.as_fd(), deadline(Duration::from_secs(5))).unwrap();
        handle.join().unwrap();
        assert_eq!(line, "y\n");
    }

    #[test]
    fn every_prompt_failure_mode_denies_or_times_out_fail_closed() {
        assert!(matches!(
            resolution_of(Err(PromptError::Timeout)),
            AskResolution::TimedOut
        ));
        assert!(matches!(
            resolution_of(Err(PromptError::Io(io::Error::other("gone")))),
            AskResolution::Denied
        ));
        assert!(matches!(
            resolution_of(Ok(Answer::Approve)),
            AskResolution::Approved
        ));
        assert!(matches!(
            resolution_of(Ok(Answer::Deny)),
            AskResolution::Denied
        ));
    }
}
