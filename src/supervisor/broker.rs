//! Landlock-confined side-effect broker for enforce mode (ADR-0020).
//!
//! The unrestricted supervisor owns policy evaluation, recording, seccomp notification
//! responses, and descriptor duplication. The broker is a separate process in the same
//! Landlock domain as the agent. It resolves and pins filesystem operands before the
//! decision is recorded, then commits approved effects against those retained handles.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::sandbox::landlock::{PreparedRuleset, RootAnchor};

const MAX_PACKET: usize = 1_048_576;
const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Why the broker could not be started or complete a request.
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// Local IPC, process, or descriptor operation failed.
    #[error("broker I/O failed: {0}")]
    Io(#[from] io::Error),
    /// The broker rejected malformed protocol data.
    #[error("broker protocol failed: {0}")]
    Protocol(String),
    /// The broker setup handshake failed before the agent was spawned.
    #[error("broker setup failed: {0}")]
    Setup(String),
    /// A broker operation exceeded its bounded deadline.
    #[error("broker operation exceeded its deadline")]
    Timeout,
}

/// A path pinned in the broker without performing a side effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedPath {
    token: u64,
    identity: PathBuf,
    exists: bool,
}

impl PreparedPath {
    /// Broker token used by a later commit.
    pub fn token(&self) -> u64 {
        self.token
    }

    /// Stable policy identity returned by the broker.
    pub fn identity(&self) -> &Path {
        &self.identity
    }

    /// Whether the final entry existed during preparation.
    pub fn exists(&self) -> bool {
        self.exists
    }
}

/// Result of a broker-executed syscall.
#[derive(Debug)]
pub enum BrokerResult {
    /// Successful scalar return value.
    Value(i64),
    /// Successful fd-returning operation.
    Fd(OwnedFd),
    /// Native positive errno.
    Errno(i32),
}

/// Network operation executed against a duplicate of the child's socket.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NetworkOperation {
    /// `connect(2)`.
    Connect,
    /// `bind(2)`.
    Bind,
    /// destination-bearing `sendto(2)`.
    SendTo,
}

/// Parent-side handle for one per-run broker process.
#[derive(Debug)]
pub struct Broker {
    pid: libc::pid_t,
    socket: OwnedFd,
    anchors: Vec<AnchorMeta>,
    workspace: PathBuf,
}

#[derive(Debug)]
struct AnchorMeta {
    root: PathBuf,
}

impl Broker {
    /// Fork, confine, and handshake with a broker before the agent is spawned.
    pub fn spawn(prepared: &PreparedRuleset, workspace: &Path) -> Result<Self, BrokerError> {
        let (parent_socket, child_socket) = seqpacket_pair()?;
        let anchors = prepared
            .anchors()
            .iter()
            .map(|anchor| AnchorMeta {
                root: anchor.root().to_path_buf(),
            })
            .collect::<Vec<_>>();

        // SAFETY: the caller invokes broker setup before agent spawn while the supervisor
        // is single-threaded. Both branches immediately close the unused socket end.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(BrokerError::Io(io::Error::last_os_error()));
        }
        if pid == 0 {
            drop(parent_socket);
            let code = broker_child(
                child_socket,
                prepared.ruleset_fd(),
                prepared.anchors(),
                workspace,
            );
            // SAFETY: the broker child must not run supervisor destructors.
            unsafe { libc::_exit(code) };
        }

        drop(child_socket);
        let mut broker = Self {
            pid,
            socket: parent_socket,
            anchors,
            workspace: workspace.to_path_buf(),
        };
        match broker.recv_response(SETUP_TIMEOUT)? {
            (Response::Ready, None) => Ok(broker),
            (Response::SetupError { message }, None) => {
                let _ = broker.stop();
                Err(BrokerError::Setup(message))
            }
            (other, _) => {
                let _ = broker.stop();
                Err(BrokerError::Protocol(format!(
                    "unexpected setup response: {other:?}"
                )))
            }
        }
    }

    /// Resolve and pin one absolute policy path without performing a side effect.
    pub fn prepare_path(
        &mut self,
        path: &Path,
        follow_final_symlink: bool,
        allow_missing: bool,
    ) -> Result<BrokerResultOrPath, BrokerError> {
        let Some((anchor, relative)) = self.select_anchor(path) else {
            return Ok(BrokerResultOrPath::Result(BrokerResult::Errno(
                libc::EACCES,
            )));
        };
        self.send_request(
            &Request::PreparePath {
                anchor,
                relative,
                follow_final_symlink,
                allow_missing,
            },
            None,
        )?;
        match self.recv_response(OPERATION_TIMEOUT)? {
            (
                Response::Prepared {
                    token,
                    identity,
                    exists,
                },
                None,
            ) => Ok(BrokerResultOrPath::Path(PreparedPath {
                token,
                identity: PathBuf::from(std::ffi::OsString::from_vec(identity)),
                exists,
            })),
            (Response::Errno { errno }, None) => {
                Ok(BrokerResultOrPath::Result(BrokerResult::Errno(errno)))
            }
            (other, _) => Err(BrokerError::Protocol(format!(
                "unexpected prepare response: {other:?}"
            ))),
        }
    }

    /// Commit an fd-returning open against a prepared path.
    pub fn commit_open(
        &mut self,
        prepared: PreparedPath,
        flags: u64,
        mode: u32,
    ) -> Result<BrokerResult, BrokerError> {
        self.send_request(
            &Request::CommitOpen {
                token: prepared.token,
                flags,
                mode,
            },
            None,
        )?;
        self.decode_result()
    }

    /// Release a prepared path after a deny or dead notification.
    pub fn release(&mut self, prepared: PreparedPath) -> Result<(), BrokerError> {
        self.send_request(
            &Request::Release {
                token: prepared.token,
            },
            None,
        )?;
        match self.recv_response(OPERATION_TIMEOUT)? {
            (Response::Released, None) => Ok(()),
            (other, _) => Err(BrokerError::Protocol(format!(
                "unexpected release response: {other:?}"
            ))),
        }
    }

    /// Execute a network operation on a duplicate of the child's actual socket.
    pub fn network(
        &mut self,
        operation: NetworkOperation,
        socket: OwnedFd,
        address: Vec<u8>,
        payload: Vec<u8>,
        flags: i32,
    ) -> Result<BrokerResult, BrokerError> {
        self.send_request(
            &Request::Network {
                operation,
                address,
                payload,
                flags,
            },
            Some(socket.as_fd()),
        )?;
        self.decode_result()
    }

    fn decode_result(&mut self) -> Result<BrokerResult, BrokerError> {
        match self.recv_response(OPERATION_TIMEOUT)? {
            (Response::Result { value }, None) => Ok(BrokerResult::Value(value)),
            (Response::Result { value: _ }, Some(fd)) => Ok(BrokerResult::Fd(fd)),
            (Response::Errno { errno }, None) => Ok(BrokerResult::Errno(errno)),
            (other, _) => Err(BrokerError::Protocol(format!(
                "unexpected operation response: {other:?}"
            ))),
        }
    }

    fn select_anchor(&self, path: &Path) -> Option<(usize, Vec<u8>)> {
        if !path.is_absolute() {
            return None;
        }
        let workspace_anchor = self
            .anchors
            .iter()
            .position(|anchor| anchor.root == self.workspace);
        let selected = if path.starts_with(&self.workspace) {
            workspace_anchor
        } else {
            self.anchors
                .iter()
                .enumerate()
                .filter(|(_, anchor)| path.starts_with(&anchor.root))
                .max_by_key(|(_, anchor)| anchor.root.as_os_str().len())
                .map(|(index, _)| index)
        }?;
        let root = &self.anchors[selected].root;
        let relative = path.strip_prefix(root).ok()?;
        Some((selected, relative.as_os_str().as_bytes().to_vec()))
    }

    fn send_request(
        &self,
        request: &Request,
        fd: Option<BorrowedFd<'_>>,
    ) -> Result<(), BrokerError> {
        send_packet(self.socket.as_raw_fd(), request, fd)?;
        Ok(())
    }

    fn recv_response(
        &mut self,
        timeout: Duration,
    ) -> Result<(Response, Option<OwnedFd>), BrokerError> {
        if !poll_readable(self.socket.as_raw_fd(), timeout)? {
            self.kill();
            return Err(BrokerError::Timeout);
        }
        recv_packet(self.socket.as_raw_fd()).map_err(BrokerError::Io)
    }

    fn stop(&mut self) -> Result<(), BrokerError> {
        let _ = self.send_request(&Request::Shutdown, None);
        self.wait()
    }

    fn wait(&mut self) -> Result<(), BrokerError> {
        if self.pid <= 0 {
            return Ok(());
        }
        let mut status = 0;
        // SAFETY: pid is the broker child owned by this object.
        let waited = unsafe { libc::waitpid(self.pid, &raw mut status, 0) };
        self.pid = 0;
        if waited < 0 {
            return Err(BrokerError::Io(io::Error::last_os_error()));
        }
        Ok(())
    }

    fn kill(&mut self) {
        if self.pid > 0 {
            // SAFETY: pid is the broker child owned by this object.
            unsafe { libc::kill(self.pid, libc::SIGKILL) };
            let _ = self.wait();
        }
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        if self.pid > 0 && self.stop().is_err() {
            self.kill();
        }
    }
}

/// A prepare call returns either a retained path or a native errno.
#[derive(Debug)]
pub enum BrokerResultOrPath {
    /// Prepared path token.
    Path(PreparedPath),
    /// Native operation result, currently an errno.
    Result(BrokerResult),
}

#[derive(Debug, Serialize, Deserialize)]
enum Request {
    PreparePath {
        anchor: usize,
        relative: Vec<u8>,
        follow_final_symlink: bool,
        allow_missing: bool,
    },
    CommitOpen {
        token: u64,
        flags: u64,
        mode: u32,
    },
    Release {
        token: u64,
    },
    Network {
        operation: NetworkOperation,
        address: Vec<u8>,
        payload: Vec<u8>,
        flags: i32,
    },
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
enum Response {
    Ready,
    SetupError {
        message: String,
    },
    Prepared {
        token: u64,
        identity: Vec<u8>,
        exists: bool,
    },
    Result {
        value: i64,
    },
    Errno {
        errno: i32,
    },
    Released,
}

struct HeldPath {
    target: Option<OwnedFd>,
    parent: Option<OwnedFd>,
    basename: Option<CString>,
}

struct BrokerState<'a> {
    socket: OwnedFd,
    anchors: &'a [RootAnchor],
    workspace: &'a Path,
    held: HashMap<u64, HeldPath>,
    next_token: u64,
}

fn broker_child(
    socket: OwnedFd,
    ruleset: BorrowedFd<'_>,
    anchors: &[RootAnchor],
    workspace: &Path,
) -> i32 {
    // SAFETY: prctl changes only this broker process.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        let _ = send_packet(
            socket.as_raw_fd(),
            &Response::SetupError {
                message: io::Error::last_os_error().to_string(),
            },
            None,
        );
        return 70;
    }
    // SAFETY: ruleset is inherited from the parent and remains live for this call.
    if !unsafe { crate::sandbox::landlock::restrict_self(ruleset.as_raw_fd()) } {
        let _ = send_packet(
            socket.as_raw_fd(),
            &Response::SetupError {
                message: io::Error::last_os_error().to_string(),
            },
            None,
        );
        return 71;
    }
    if send_packet(socket.as_raw_fd(), &Response::Ready, None).is_err() {
        return 72;
    }

    let mut state = BrokerState {
        socket,
        anchors,
        workspace,
        held: HashMap::new(),
        next_token: 1,
    };
    match state.run() {
        Ok(()) => 0,
        Err(_) => 73,
    }
}

impl BrokerState<'_> {
    fn run(&mut self) -> io::Result<()> {
        loop {
            let (request, passed_fd) = recv_packet::<Request>(self.socket.as_raw_fd())?;
            match request {
                Request::PreparePath {
                    anchor,
                    relative,
                    follow_final_symlink,
                    allow_missing,
                } => self.prepare_path(anchor, &relative, follow_final_symlink, allow_missing)?,
                Request::CommitOpen { token, flags, mode } => {
                    self.commit_open(token, flags, mode)?
                }
                Request::Release { token } => {
                    self.held.remove(&token);
                    self.respond(&Response::Released, None)?;
                }
                Request::Network {
                    operation,
                    address,
                    payload,
                    flags,
                } => self.network(operation, passed_fd, &address, &payload, flags)?,
                Request::Shutdown => return Ok(()),
            }
        }
    }

    fn prepare_path(
        &mut self,
        anchor_index: usize,
        relative: &[u8],
        follow_final_symlink: bool,
        allow_missing: bool,
    ) -> io::Result<()> {
        let Some(anchor) = self.anchors.get(anchor_index) else {
            return self.errno(libc::EACCES);
        };
        if relative.contains(&0) {
            return self.errno(libc::EINVAL);
        }
        let relative_c =
            CString::new(relative).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let workspace_anchor = anchor.root() == self.workspace;
        let resolve = RESOLVE_BENEATH
            | RESOLVE_NO_MAGICLINKS
            | if workspace_anchor {
                0
            } else {
                RESOLVE_NO_SYMLINKS
            };

        let target = if relative.is_empty() {
            dup_fd(anchor.as_fd()).map(Some)
        } else {
            let flags = u64::try_from(libc::O_PATH | libc::O_CLOEXEC).unwrap_or_default()
                | if follow_final_symlink {
                    0
                } else {
                    u64::try_from(libc::O_NOFOLLOW).unwrap_or_default()
                };
            openat2(anchor.as_fd().as_raw_fd(), &relative_c, flags, 0, resolve).map(Some)
        };

        let (target, exists) = match target {
            Ok(target) => (target, true),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) && allow_missing => {
                (None, false)
            }
            Err(error) => {
                return self.errno(error.raw_os_error().unwrap_or(libc::EACCES));
            }
        };

        let (parent, basename) = if relative.is_empty() {
            (None, None)
        } else {
            match prepare_parent(anchor.as_fd(), relative, resolve) {
                Ok(parts) => (Some(parts.0), Some(parts.1)),
                Err(error) => {
                    return self.errno(error.raw_os_error().unwrap_or(libc::EACCES));
                }
            }
        };
        let identity = match &target {
            Some(fd) => fd_identity(fd.as_fd())?,
            None => anchor.root().join(std::ffi::OsStr::from_bytes(relative)),
        };
        if !identity.starts_with(anchor.root()) {
            return self.errno(libc::EXDEV);
        }

        let token = self.next_token;
        self.next_token = self.next_token.checked_add(1).unwrap_or(1);
        self.held.insert(
            token,
            HeldPath {
                target,
                parent,
                basename,
            },
        );
        self.respond(
            &Response::Prepared {
                token,
                identity: identity.as_os_str().as_bytes().to_vec(),
                exists,
            },
            None,
        )
    }

    fn commit_open(&mut self, token: u64, flags: u64, mode: u32) -> io::Result<()> {
        let Some(held) = self.held.remove(&token) else {
            return self.errno(libc::EBADF);
        };
        if flags & u64::try_from(libc::O_TMPFILE).unwrap_or_default()
            == u64::try_from(libc::O_TMPFILE).unwrap_or_default()
        {
            return self.errno(libc::EOPNOTSUPP);
        }

        let opened = match held.target {
            Some(target) => open_existing(target.as_fd(), flags, mode),
            None => {
                let Some(parent) = held.parent else {
                    return self.errno(libc::ENOENT);
                };
                let Some(basename) = held.basename else {
                    return self.errno(libc::ENOENT);
                };
                open_missing(parent.as_fd(), &basename, flags, mode)
            }
        };
        match opened {
            Ok(fd) => self.respond(&Response::Result { value: 0 }, Some(fd.as_fd())),
            Err(error) => self.errno(error.raw_os_error().unwrap_or(libc::EACCES)),
        }
    }

    fn network(
        &mut self,
        operation: NetworkOperation,
        socket: Option<OwnedFd>,
        address: &[u8],
        payload: &[u8],
        flags: i32,
    ) -> io::Result<()> {
        let Some(socket) = socket else {
            return self.errno(libc::EBADF);
        };
        if address.len() < size_of::<libc::sa_family_t>() || address.len() > 128 {
            return self.errno(libc::EINVAL);
        }
        let family = u16::from_ne_bytes([address[0], address[1]]) as i32;
        if !matches!(family, libc::AF_INET | libc::AF_INET6) {
            return self.errno(libc::EAFNOSUPPORT);
        }
        let length = address.len() as libc::socklen_t;
        let address_ptr = address.as_ptr().cast::<libc::sockaddr>();
        // SAFETY: socket is owned, address and payload remain valid for the call, and
        // their lengths are bounded before this match.
        let result = unsafe {
            match operation {
                NetworkOperation::Connect => {
                    libc::connect(socket.as_raw_fd(), address_ptr, length) as isize
                }
                NetworkOperation::Bind => {
                    libc::bind(socket.as_raw_fd(), address_ptr, length) as isize
                }
                NetworkOperation::SendTo => libc::sendto(
                    socket.as_raw_fd(),
                    payload.as_ptr().cast(),
                    payload.len(),
                    flags,
                    address_ptr,
                    length,
                ),
            }
        };
        if result < 0 {
            self.errno(
                io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EACCES),
            )
        } else {
            self.respond(
                &Response::Result {
                    value: result as i64,
                },
                None,
            )
        }
    }

    fn errno(&self, errno: i32) -> io::Result<()> {
        self.respond(&Response::Errno { errno }, None)
    }

    fn respond(&self, response: &Response, fd: Option<BorrowedFd<'_>>) -> io::Result<()> {
        send_packet(self.socket.as_raw_fd(), response, fd)
    }
}

fn open_existing(target: BorrowedFd<'_>, flags: u64, _mode: u32) -> io::Result<OwnedFd> {
    let create = u64::try_from(libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW).unwrap_or_default();
    if flags & u64::try_from(libc::O_CREAT | libc::O_EXCL).unwrap_or_default()
        == u64::try_from(libc::O_CREAT | libc::O_EXCL).unwrap_or_default()
    {
        return Err(io::Error::from_raw_os_error(libc::EEXIST));
    }
    if flags & u64::try_from(libc::O_PATH).unwrap_or_default() != 0 {
        return dup_fd(target);
    }
    let path = CString::new(format!("/proc/self/fd/{}", target.as_raw_fd()))
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let clean_flags = flags & !create;
    let clean_flags = libc::c_int::try_from(clean_flags)
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: path names the retained descriptor and flags were range-checked.
    owned_fd(unsafe { libc::open(path.as_ptr(), clean_flags) })
}

fn open_missing(
    parent: BorrowedFd<'_>,
    basename: &CStr,
    flags: u64,
    mode: u32,
) -> io::Result<OwnedFd> {
    if flags & u64::try_from(libc::O_CREAT).unwrap_or_default() == 0 {
        return Err(io::Error::from_raw_os_error(libc::ENOENT));
    }
    let flags = flags | u64::try_from(libc::O_NOFOLLOW).unwrap_or_default();
    openat2(
        parent.as_raw_fd(),
        basename,
        flags,
        u64::from(mode),
        RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    )
}

fn prepare_parent(
    anchor: BorrowedFd<'_>,
    relative: &[u8],
    resolve: u64,
) -> io::Result<(OwnedFd, CString)> {
    let path = Path::new(std::ffi::OsStr::from_bytes(relative));
    let basename = path
        .file_name()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
    let basename = CString::new(basename.as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let parent_fd = if parent.as_os_str().is_empty() {
        dup_fd(anchor)?
    } else {
        let parent = CString::new(parent.as_os_str().as_bytes())
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        openat2(
            anchor.as_raw_fd(),
            &parent,
            u64::try_from(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC).unwrap_or_default(),
            0,
            resolve,
        )?
    };
    Ok((parent_fd, basename))
}

fn openat2(dirfd: RawFd, path: &CStr, flags: u64, mode: u64, resolve: u64) -> io::Result<OwnedFd> {
    let how = OpenHow {
        flags,
        mode,
        resolve,
    };
    // SAFETY: openat2 reads the nul-terminated path and complete open_how.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path.as_ptr(),
            &raw const how,
            size_of::<OpenHow>(),
        )
    };
    owned_fd(fd as RawFd)
}

fn dup_fd(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    // SAFETY: fcntl duplicates the live borrowed descriptor.
    owned_fd(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) })
}

fn owned_fd(fd: RawFd) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: the successful syscall returned a newly owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn fd_identity(fd: BorrowedFd<'_>) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

fn seqpacket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut pair = [-1; 2];
    // SAFETY: socketpair writes two descriptors into pair.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair returned two distinct owned descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) })
}

fn send_packet<T: Serialize>(
    socket: RawFd,
    value: &T,
    fd: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() > MAX_PACKET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "broker packet exceeds cap",
        ));
    }
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    // usize storage provides cmsghdr alignment.
    let mut control = [0usize; 8];
    // SAFETY: zeroed msghdr is initialized with valid storage below.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    if let Some(fd) = fd {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = size_of_val(&control);
        // SAFETY: control is aligned and large enough for one RawFd SCM_RIGHTS message.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            if header.is_null() {
                return Err(io::Error::other("SCM_RIGHTS control buffer too small"));
            }
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize;
            libc::CMSG_DATA(header)
                .cast::<RawFd>()
                .write(fd.as_raw_fd());
            message.msg_controllen = libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize;
        }
    }
    // SAFETY: sendmsg borrows initialized message storage for the duration of the call.
    let sent = unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) };
    if sent == bytes.len() as isize {
        Ok(())
    } else if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(io::Error::other("short broker packet send"))
    }
}

fn recv_packet<T: for<'de> Deserialize<'de>>(socket: RawFd) -> io::Result<(T, Option<OwnedFd>)> {
    let mut bytes = vec![0u8; MAX_PACKET];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut control = [0usize; 8];
    // SAFETY: zeroed msghdr is initialized with writable storage below.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size_of_val(&control);
    // SAFETY: recvmsg writes only into the declared data and control buffers.
    let received = unsafe { libc::recvmsg(socket, &raw mut message, libc::MSG_CMSG_CLOEXEC) };
    if received <= 0 {
        return Err(if received == 0 {
            io::Error::new(io::ErrorKind::UnexpectedEof, "broker socket closed")
        } else {
            io::Error::last_os_error()
        });
    }
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated broker packet",
        ));
    }
    bytes.truncate(received as usize);
    let value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;

    // SAFETY: recvmsg initialized any returned cmsghdr in the aligned control storage.
    let fd = unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null() {
            None
        } else if (*header).cmsg_level == libc::SOL_SOCKET
            && (*header).cmsg_type == libc::SCM_RIGHTS
            && (*header).cmsg_len >= libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize
        {
            let raw = libc::CMSG_DATA(header).cast::<RawFd>().read();
            Some(OwnedFd::from_raw_fd(raw))
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected broker control message",
            ));
        }
    };
    Ok((value, fd))
}

fn poll_readable(fd: RawFd, timeout: Duration) -> io::Result<bool> {
    let millis = timeout.as_millis().min(i32::MAX as u128) as i32;
    let mut pollfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll reads and writes one local pollfd.
    let rc = unsafe { libc::poll(&raw mut pollfd, 1, millis) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc > 0 && pollfd.revents & libc::POLLIN != 0)
    }
}
