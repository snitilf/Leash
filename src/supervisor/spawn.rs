//! the spawn protocol: fork the child, establish the boundary, hand the notify fd back
//! (architecture.md section 5.2; FR-1).
//!
//! this is the supervisor half of the handshake in `sandbox::child`. it uses a raw
//! `fork` rather than `std::process::Command`: `Command::spawn` parks the parent reading
//! the child's CLOEXEC error pipe until the child execs, but the child must block for the
//! supervisor's ack first, and the supervisor cannot send it while parked in `spawn` -
//! a deadlock. so the parent forks, the child runs `child::enter`, and the parent drives
//! the SCM_RIGHTS receive and ack here.
//!
//! everything the child touches after fork is allocation-free and built before the fork
//! (the filter, the argv array, the resolved exec path), because a fork from a
//! multithreaded process (which `cargo test` and the real run are) inherits held locks;
//! see `sandbox::child`. the exec path is resolved here, in the parent, so the child
//! calls `execv` and never glibc's non-as-safe PATH search.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::recorder::Mode;
use crate::sandbox::child::{self, CHILD_BOUNDARY_READY, ChildSetup, SUPERVISOR_ACK, SockFprog};
use crate::sandbox::filter::{SockFilter, build_filter};
use crate::supervisor::notify::NotifyFd;

/// what to launch and how.
pub struct SpawnSpec {
    /// the agent command and its arguments; `argv[0]` is resolved to an executable.
    pub argv: Vec<String>,
    /// an fd to redirect the child's stdout and stderr onto, if any.
    pub stdout: Option<OwnedFd>,
    /// record-only or enforce; the same seccomp filter is installed in both modes.
    pub mode: Mode,
    /// parent-built Landlock ruleset fd to apply in the child, enforce mode only.
    pub landlock_ruleset: Option<RawFd>,
}

/// a launched, supervised child with its boundary established.
#[derive(Debug)]
pub struct SupervisedChild {
    /// the child's pid.
    pub pid: libc::pid_t,
    /// the supervisor's end of the seccomp notify listener.
    pub notify: NotifyFd,
}

impl SupervisedChild {
    /// wait for the child to exit and reap it. returns the raw wait status.
    pub fn wait(&self) -> io::Result<i32> {
        reap(self.pid)
    }
}

/// why a spawn failed. every variant is fatal to the run (I3): the boundary was not
/// established, so no agent ran.
#[derive(Debug, thiserror::Error)]
pub enum SpawnError {
    /// `argv[0]` could not be resolved to an executable on `PATH`.
    #[error("executable not found: {0}")]
    ExecNotFound(String),
    /// the filter program is too large to install.
    #[error("filter program too large: {0} instructions")]
    FilterTooLarge(usize),
    /// the handshake socketpair could not be created.
    #[error("socketpair failed: {0}")]
    Socketpair(#[source] io::Error),
    /// `fork` failed.
    #[error("fork failed: {0}")]
    Fork(#[source] io::Error),
    /// the child set up its half of the boundary but the notify-fd handshake failed.
    #[error("notify-fd handshake failed: {0}")]
    Handshake(#[source] io::Error),
    /// the child exited before completing setup; it never reached the agent `execve`.
    #[error("child aborted during setup (wait status {status})")]
    ChildSetup {
        /// the raw wait status of the aborted child.
        status: i32,
    },
}

/// launch `spec` under the seccomp filter and return the supervised child.
pub fn spawn_supervised(spec: &SpawnSpec) -> Result<SupervisedChild, SpawnError> {
    let filter = build_filter();
    spawn_with_filter(spec, &filter)
}

/// the same as `spawn_supervised` but with a caller-supplied filter program. the seam the
/// fail-closed test uses to inject a deliberately broken program without a test-only
/// branch in production code.
pub fn spawn_with_filter(
    spec: &SpawnSpec,
    filter: &[SockFilter],
) -> Result<SupervisedChild, SpawnError> {
    // the fprog length field is u16 and the kernel caps programs at BPF_MAXINSNS (4096).
    if filter.len() > 4096 {
        return Err(SpawnError::FilterTooLarge(filter.len()));
    }

    // built before the fork so the child allocates nothing: the exec path, the argv
    // array (and its pointer table), and the filter header.
    let argv0 = spec.argv.first().map(String::as_str).unwrap_or("");
    let exec_path = resolve_exec(argv0)?;
    let argv_owned: Vec<CString> = spec
        .argv
        .iter()
        .map(|a| CString::new(a.as_bytes()))
        .collect::<Result<_, _>>()
        .map_err(|_| SpawnError::ExecNotFound(argv0.to_string()))?;
    let mut argv_ptrs: Vec<*const libc::c_char> = argv_owned.iter().map(|a| a.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    let (supervisor_sock, child_sock) = socketpair()?;

    let setup = ChildSetup {
        supervisor_sock: supervisor_sock.as_raw_fd(),
        child_sock: child_sock.as_raw_fd(),
        redirect: spec.stdout.as_ref().map(AsRawFd::as_raw_fd),
        prog: SockFprog::new(filter),
        landlock_ruleset: spec.landlock_ruleset,
        exec_path: exec_path.as_ptr(),
        argv: argv_ptrs.as_ptr(),
    };

    // SAFETY: fork from here; the child branch does nothing but call child::enter, which
    // is async-signal-safe and never returns. all buffers the child reads are built above
    // and live across the fork (COW preserves their addresses).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(SpawnError::Fork(io::Error::last_os_error()));
    }
    if pid == 0 {
        // SAFETY: we are the child of the fork, first thing after it, with a valid setup.
        unsafe { child::enter(&setup) };
    }

    // parent: drop the child's socket end so our recv sees EOF if the child dies, then
    // run the handshake. keep the owned buffers alive until we are done reading them.
    drop(child_sock);
    let result = parent_handshake(&supervisor_sock, pid);
    drop(exec_path);
    drop(argv_owned);
    drop(argv_ptrs);
    drop(supervisor_sock);
    result
}

/// receive the notify fd from the child, ack, and wrap it. on any failure reap the child
/// and report it as a setup abort so no zombie is left (I3).
fn parent_handshake(
    supervisor_sock: &OwnedFd,
    pid: libc::pid_t,
) -> Result<SupervisedChild, SpawnError> {
    let notify_fd = match recv_notify_fd(supervisor_sock.as_raw_fd()) {
        Some(fd) => fd,
        None => {
            let status = reap(pid).unwrap_or(-1);
            return Err(SpawnError::ChildSetup { status });
        }
    };

    // ack that we hold the fd and are ready to serve.
    let ack = [SUPERVISOR_ACK];
    // SAFETY: write one byte from a stack buffer to our socket end.
    let n = unsafe { libc::write(supervisor_sock.as_raw_fd(), ack.as_ptr().cast(), 1) };
    if n != 1 {
        drop(notify_fd);
        let _ = reap(pid);
        return Err(SpawnError::Handshake(io::Error::last_os_error()));
    }
    let mut boundary_ready = [0u8; 1];
    // SAFETY: read writes one byte into local storage. EOF means child setup failed
    // after listener handoff, most notably while applying Landlock.
    let n = unsafe {
        libc::read(
            supervisor_sock.as_raw_fd(),
            boundary_ready.as_mut_ptr().cast(),
            boundary_ready.len(),
        )
    };
    if n != 1 || boundary_ready[0] != CHILD_BOUNDARY_READY {
        drop(notify_fd);
        let status = reap(pid).unwrap_or(-1);
        return Err(SpawnError::ChildSetup { status });
    }

    let notify = NotifyFd::new(notify_fd).map_err(SpawnError::Handshake)?;
    Ok(SupervisedChild { pid, notify })
}

/// resolve `argv0` to a nul-terminated executable path, mirroring `execvp` search but in
/// the parent so the child can call `execv`. a path containing `/` is used as-is (its
/// existence is proven when `execv` runs); a bare name is searched on `PATH`.
fn resolve_exec(argv0: &str) -> Result<CString, SpawnError> {
    let not_found = || SpawnError::ExecNotFound(argv0.to_string());
    if argv0.is_empty() {
        return Err(not_found());
    }
    if argv0.contains('/') {
        return CString::new(argv0.as_bytes()).map_err(|_| not_found());
    }
    let path = std::env::var_os("PATH").ok_or_else(not_found)?;
    for dir in std::env::split_paths(&path) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let candidate = dir.join(argv0);
        // access(X_OK) matches what execv needs to succeed; a later exec failure still
        // funnels to the child's _exit, covered by the exec-failure test.
        if let Ok(c) = CString::new(candidate.as_os_str().as_encoded_bytes())
            && unsafe { libc::access(c.as_ptr(), libc::X_OK) } == 0
        {
            return Ok(c);
        }
    }
    Err(not_found())
}

/// create the SOCK_CLOEXEC handshake socketpair. CLOEXEC so neither end survives the
/// agent `execve` (the notify-fd socket must not leak into the agent).
fn socketpair() -> Result<(OwnedFd, OwnedFd), SpawnError> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: socketpair writes two fds into the array we own; on error it returns -1.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(SpawnError::Socketpair(io::Error::last_os_error()));
    }
    // SAFETY: both fds were just created and are owned solely by us.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// receive one byte plus the SCM_RIGHTS notify fd from the child. returns None on EOF, a
/// short read, or a message carrying no fd (the child aborted setup).
fn recv_notify_fd(sock: RawFd) -> Option<OwnedFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut cmsg_buf = [0u64; 4];
    let controllen = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) } as usize;

    // SAFETY: msghdr is zeroed then pointed at the stack iovec and control buffer we own;
    // recvmsg fills them and, on an SCM_RIGHTS message, installs the fd into our table.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr().cast();
        msg.msg_controllen = controllen;

        let n = libc::recvmsg(sock, &mut msg, 0);
        if n != 1 {
            return None;
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
        {
            return None;
        }
        let mut fd: libc::c_int = -1;
        std::ptr::copy_nonoverlapping(libc::CMSG_DATA(cmsg).cast::<libc::c_int>(), &raw mut fd, 1);
        if fd < 0 {
            return None;
        }
        // SAFETY: fd was just installed by recvmsg and is owned solely by us.
        Some(OwnedFd::from_raw_fd(fd))
    }
}

/// waitpid the child and return its raw wait status.
fn reap(pid: libc::pid_t) -> io::Result<i32> {
    let mut status = 0;
    // SAFETY: waitpid writes the status of the child pid we own into a local we own.
    let rc = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(status)
}
