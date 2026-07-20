//! the post-fork child sequence (architecture.md section 5.2 steps 3, 4, 6).
//!
//! `enter` runs in the child between `fork` and `execve`. it must be strictly
//! async-signal-safe: `cargo test` and the real supervisor are multithreaded, and a
//! fork from a threaded process inherits locks (malloc's among them) held by threads
//! that do not exist in the child, so any allocation or non-as-safe libc call can
//! deadlock. everything that allocates (the argv array, the exec path, the filter
//! program) is built by the parent before the fork and passed in by pointer; this
//! function only issues syscalls and reads the borrowed buffers. exec is `execv` on a
//! parent-resolved path, never `execvp`, because glibc's PATH search is not as-safe.
//!
//! every failure funnels to `_exit(CHILD_SETUP_EXIT)` (never `exit`, which would run
//! atexit handlers across the fork boundary). the boundary is fail-closed: the agent's
//! `execve` is reached only if every prior step succeeded (I3).

use std::os::fd::RawFd;

use super::filter::SockFilter;
use crate::supervisor::notify::{
    SECCOMP_FILTER_FLAG_NEW_LISTENER, SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
    SECCOMP_SET_MODE_FILTER,
};

/// exit code the child uses for any pre-exec setup or exec failure. distinct from the
/// agent's own codes so a reaped child is unambiguous.
pub const CHILD_SETUP_EXIT: i32 = 121;

/// the handshake byte the child sends once it holds the notify fd.
pub const CHILD_READY: u8 = b'L';
/// the ack byte the supervisor sends once it holds the notify fd and is ready to serve.
pub const SUPERVISOR_ACK: u8 = b'A';

/// `struct sock_fprog`: the header the kernel reads to install a cbpf program.
#[repr(C)]
pub struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

impl SockFprog {
    /// borrow a built filter as an installable program. the returned header points into
    /// `filter`, which must outlive it (and outlive the fork, since the child reads it).
    pub fn new(filter: &[SockFilter]) -> Self {
        Self {
            len: filter.len() as u16,
            filter: filter.as_ptr(),
        }
    }
}

/// everything the child needs, all pre-built by the parent so the child allocates nothing.
///
/// the raw fds and pointers borrow buffers owned by the caller for the life of the spawn;
/// see `supervisor::spawn`, which constructs and owns them.
pub struct ChildSetup {
    /// the supervisor's end of the handshake socket; the child closes it immediately.
    pub supervisor_sock: RawFd,
    /// the child's end of the handshake socket; carries the notify fd out and the ack in.
    pub child_sock: RawFd,
    /// an fd to `dup2` onto stdout and stderr before exec, if the run redirects them.
    pub redirect: Option<RawFd>,
    /// the seccomp program header (points into the caller's filter buffer).
    pub prog: SockFprog,
    /// a parent-built Landlock ruleset fd to apply after the notify ack, if any.
    pub landlock_ruleset: Option<RawFd>,
    /// the resolved executable path (a nul-terminated C string owned by the caller).
    pub exec_path: *const libc::c_char,
    /// the argv array, nul-terminated (owned by the caller).
    pub argv: *const *const libc::c_char,
}

/// run the child sequence. never returns: it `execve`s the agent or `_exit`s.
///
/// # Safety
/// must be called only in the child of a `fork`, before any other work, with a `setup`
/// whose fds are open and whose pointers are valid for the call. the sequence is
/// async-signal-safe; the caller guarantees nothing else runs in the child first.
pub unsafe fn enter(setup: &ChildSetup) -> ! {
    // step 3 prelude: drop the supervisor's socket end; the child never uses it.
    // SAFETY: supervisor_sock is an fd owned by the spawn, valid until this close.
    unsafe { libc::close(setup.supervisor_sock) };

    if let Some(fd) = setup.redirect {
        // SAFETY: fd is a valid open fd for the life of the spawn; dup2 onto the two
        // standard streams cannot fail here except on a bad fd, which _exits below.
        if unsafe { libc::dup2(fd, libc::STDOUT_FILENO) } < 0
            || unsafe { libc::dup2(fd, libc::STDERR_FILENO) } < 0
        {
            die();
        }
    }

    // step 3: no_new_privs, then install the filter, which returns the notify fd.
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS takes scalar args and touches no memory.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        die();
    }
    let flags = SECCOMP_FILTER_FLAG_NEW_LISTENER | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
    // SAFETY: prog points at the caller's filter buffer, valid and NEW_LISTENER makes the
    // call return the notify fd rather than installing silently. a negative return _exits.
    let notify_fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            flags,
            &raw const setup.prog,
        )
    };
    if notify_fd < 0 {
        die();
    }
    let notify_fd = notify_fd as RawFd;

    // step 4: hand the notify fd to the supervisor, then close our copy so a threaded
    // agent can never reach the decision path, and block for the ack.
    if !send_notify_fd(setup.child_sock, notify_fd) {
        die();
    }
    // SAFETY: notify_fd was just returned by the kernel and not closed yet.
    unsafe { libc::close(notify_fd) };
    if !recv_ack(setup.child_sock) {
        die();
    }

    // step 5: apply the parent-built Landlock ruleset in the child. a process can only
    // restrict itself, and no allocation is permitted in this post-fork path.
    if let Some(fd) = setup.landlock_ruleset
        && !unsafe { super::landlock::restrict_self(fd) }
    {
        die();
    }

    // step 6: close every inherited fd except the standard streams, then exec. the
    // handshake socket is >= 3 and closed here; close_range needs no /proc walk.
    // SAFETY: close_range over [3, u32::MAX] with no flags closes the child's spare fds.
    unsafe { libc::syscall(libc::SYS_close_range, 3u32, libc::c_uint::MAX, 0) };
    // SAFETY: exec_path and argv are nul-terminated buffers owned by the caller; on
    // success execv never returns, on failure it returns -1 and we _exit.
    unsafe { libc::execv(setup.exec_path, setup.argv) };
    die();
}

/// send one byte plus the notify fd as SCM_RIGHTS. returns false on any error.
fn send_notify_fd(sock: RawFd, notify_fd: RawFd) -> bool {
    let mut byte = [CHILD_READY];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // u64 backing keeps the control buffer aligned for cmsghdr; sized for one int fd.
    let mut cmsg_buf = [0u64; 4];
    let controllen = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) } as usize;

    // SAFETY: msghdr is zeroed then filled with the iovec and control buffer above, all
    // stack-owned for the call; sendmsg reads them and the fd table entry for notify_fd.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr().cast();
        msg.msg_controllen = controllen;

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return false;
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &raw const notify_fd,
            libc::CMSG_DATA(cmsg).cast::<libc::c_int>(),
            1,
        );

        libc::sendmsg(sock, &msg, 0) == 1
    }
}

/// block for the supervisor's single ack byte. returns false on EOF or a wrong byte.
fn recv_ack(sock: RawFd) -> bool {
    let mut byte = [0u8; 1];
    // SAFETY: read into a stack byte we own; a short or errored read fails the handshake.
    let n = unsafe { libc::read(sock, byte.as_mut_ptr().cast(), 1) };
    n == 1 && byte[0] == SUPERVISOR_ACK
}

/// terminate the child without running atexit handlers.
fn die() -> ! {
    // SAFETY: _exit is async-signal-safe and always valid.
    unsafe { libc::_exit(CHILD_SETUP_EXIT) };
}
