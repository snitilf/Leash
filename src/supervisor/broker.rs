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

/// two hex digits per byte on the wire, for the fields that can reach 64 KiB. json spells a
/// `Vec<u8>` as decimal numbers, up to four characters a byte, and a packet over the
/// socket's send buffer (about 208 KiB) is refused with `EMSGSIZE`, which would end the run
/// over one large value. hex is two characters a byte whatever the byte.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            text.push(char::from(DIGITS[usize::from(byte >> 4)]));
            text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        serializer.serialize_str(&text)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        let digit = |c: u8| match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(D::Error::custom("not a lowercase hex digit")),
        };
        let raw = text.as_bytes();
        if raw.len() % 2 != 0 {
            return Err(D::Error::custom("odd number of hex digits"));
        }
        raw.as_chunks::<2>()
            .0
            .iter()
            .map(|pair| Ok(digit(pair[0])? << 4 | digit(pair[1])?))
            .collect()
    }
}
const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;

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
    on_cgroup2: bool,
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

    /// Whether the pinned object, or the directory a missing entry would be created in, is on
    /// a cgroup2 filesystem. read from the retained handle, so a bind mount or a mount made
    /// after the run started is told apart by what it is and not by where it is.
    pub fn on_cgroup2(&self) -> bool {
        self.on_cgroup2
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

/// Filesystem mutation committed against one or two prepared paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MutationOperation {
    /// `truncate(2)`.
    Truncate {
        /// New byte length.
        length: i64,
    },
    /// `renameat2(2)` with zero, NOREPLACE, or EXCHANGE flags.
    Rename {
        /// Kernel rename flags.
        flags: u32,
    },
    /// `mkdirat(2)`.
    Mkdir {
        /// Requested creation mode.
        mode: u32,
    },
    /// `unlinkat(2)`, optionally with `AT_REMOVEDIR`.
    Unlink {
        /// Kernel unlink flags.
        flags: i32,
    },
    /// `linkat(2)`.
    Link {
        /// Kernel link flags.
        flags: i32,
    },
    /// `symlinkat(2)` where the target is stored text.
    Symlink {
        /// Verbatim symlink target.
        target: Vec<u8>,
    },
    /// Path-based chmod realized against the pinned target.
    Chmod {
        /// Requested mode.
        mode: u32,
    },
    /// Path-based chown.
    Chown {
        /// Requested uid, including `u32::MAX` for unchanged.
        uid: u32,
        /// Requested gid, including `u32::MAX` for unchanged.
        gid: u32,
        /// `fchownat` flags.
        flags: i32,
    },
    /// `fchmodat2(2)` with `AT_SYMLINK_NOFOLLOW`: refused with `EOPNOTSUPP` when the final
    /// component is a symlink, as the kernel does.
    ChmodNoFollow {
        /// Requested mode.
        mode: u32,
    },
    /// `setxattr(2)` or `lsetxattr(2)` against the pinned target (snapshot runs).
    Setxattr {
        /// Attribute name, without the terminating nul.
        name: Vec<u8>,
        /// Attribute value.
        #[serde(with = "hex_bytes")]
        value: Vec<u8>,
        /// `XATTR_CREATE` or `XATTR_REPLACE`, or zero.
        flags: i32,
        /// whether the final symlink was followed when the path was prepared
        follow: bool,
    },
    /// `removexattr(2)` or `lremovexattr(2)` against the pinned target (snapshot runs).
    Removexattr {
        /// Attribute name, without the terminating nul.
        name: Vec<u8>,
        /// whether the final symlink was followed when the path was prepared
        follow: bool,
    },
    /// `utimensat(2)` against the pinned target (snapshot runs). The legacy `utime`,
    /// `utimes` and `futimesat` calls are converted to this form by the supervisor.
    Utimens {
        /// access seconds, access nanoseconds, modify seconds, modify nanoseconds; `None`
        /// means "now" for both, as a null `times` pointer does
        times: Option<[i64; 4]>,
        /// `0` or `AT_SYMLINK_NOFOLLOW`
        flags: i32,
    },
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
    /// The broker process id, so its `/proc/<pid>` tree can be denied to the agent.
    pub fn pid(&self) -> u32 {
        u32::try_from(self.pid).unwrap_or(0)
    }

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
                    on_cgroup2,
                },
                None,
            ) => Ok(BrokerResultOrPath::Path(PreparedPath {
                token,
                identity: PathBuf::from(std::ffi::OsString::from_vec(identity)),
                exists,
                on_cgroup2,
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

    /// Commit a filesystem mutation against prepared operands.
    pub fn commit_mutation(
        &mut self,
        primary: PreparedPath,
        secondary: Option<PreparedPath>,
        operation: MutationOperation,
    ) -> Result<BrokerResult, BrokerError> {
        self.send_request(
            &Request::CommitMutation {
                primary: primary.token,
                secondary: secondary.map(|path| path.token),
                operation,
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
    CommitMutation {
        primary: u64,
        secondary: Option<u64>,
        operation: MutationOperation,
    },
    Release {
        token: u64,
    },
    Network {
        operation: NetworkOperation,
        address: Vec<u8>,
        #[serde(with = "hex_bytes")]
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
        on_cgroup2: bool,
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

/// close every descriptor of this process except those in `keep`, with `close_range` over
/// the gaps between them.
fn close_all_except(keep: &[libc::c_int]) {
    let mut keep: Vec<libc::c_uint> = keep
        .iter()
        .filter_map(|fd| libc::c_uint::try_from(*fd).ok())
        .collect();
    keep.sort_unstable();
    keep.dedup();
    let mut next: libc::c_uint = 0;
    for fd in keep {
        if fd > next {
            // SAFETY: close_range closes only descriptors of this process in [next, fd - 1].
            unsafe { libc::syscall(libc::SYS_close_range, next, fd - 1, 0 as libc::c_uint) };
        }
        next = fd + 1;
    }
    // SAFETY: as above, for the open-ended tail.
    unsafe {
        libc::syscall(
            libc::SYS_close_range,
            next,
            libc::c_uint::MAX,
            0 as libc::c_uint,
        )
    };
}

fn broker_child(
    socket: OwnedFd,
    ruleset: BorrowedFd<'_>,
    anchors: &[RootAnchor],
    workspace: &Path,
) -> i32 {
    // the fork inherited every descriptor the supervisor holds, among them the live trace and
    // the run directory. the broker keeps only stdio, its socket, the ruleset (until it has
    // restricted itself) and the policy anchors, so a compromised broker cannot write the
    // trace through an inherited descriptor.
    let mut keep: Vec<libc::c_int> = vec![0, 1, 2, socket.as_raw_fd(), ruleset.as_raw_fd()];
    keep.extend(anchors.iter().map(|anchor| anchor.as_fd().as_raw_fd()));
    close_all_except(&keep);
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
    // the ruleset descriptor has done its job; this process is the forked copy and the
    // parent still owns the original
    close_all_except(
        &keep
            .iter()
            .copied()
            .filter(|fd| *fd != ruleset.as_raw_fd())
            .collect::<Vec<_>>(),
    );
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
                Request::CommitMutation {
                    primary,
                    secondary,
                    operation,
                } => self.commit_mutation(primary, secondary, operation)?,
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
        let namespace_root = anchor.root() == Path::new("/");
        let resolve = anchor_resolve_flags(workspace_anchor, namespace_root);

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
            None => {
                let parent = parent
                    .as_ref()
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
                let basename = basename
                    .as_deref()
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
                fd_identity(parent.as_fd())?.join(std::ffi::OsStr::from_bytes(basename.to_bytes()))
            }
        };
        if !identity.starts_with(anchor.root()) {
            return self.errno(libc::EXDEV);
        }

        // the filesystem the handle is on: the object itself, or the directory a missing
        // entry would be created in
        let on_cgroup2 = target
            .as_ref()
            .or(parent.as_ref())
            .is_some_and(|fd| fd_on_cgroup2(fd.as_fd()));
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
                on_cgroup2,
            },
            None,
        )
    }

    fn commit_open(&mut self, token: u64, flags: u64, mode: u32) -> io::Result<()> {
        let Some(held) = self.held.remove(&token) else {
            return self.errno(libc::EBADF);
        };
        // the supervisor already hands over the bits an O_PATH open honors; masking again
        // here keeps a stray O_CREAT or O_TRUNC from ever creating or truncating
        let flags = crate::supervisor::fact::effective_open_flags(flags);
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

    fn commit_mutation(
        &mut self,
        primary_token: u64,
        secondary_token: Option<u64>,
        operation: MutationOperation,
    ) -> io::Result<()> {
        let Some(primary) = self.held.remove(&primary_token) else {
            return self.errno(libc::EBADF);
        };
        let secondary = match secondary_token {
            Some(token) => match self.held.remove(&token) {
                Some(path) => Some(path),
                None => return self.errno(libc::EBADF),
            },
            None => None,
        };

        let result = match operation {
            MutationOperation::Truncate { length } => truncate_held(&primary, length),
            MutationOperation::Rename { flags } => {
                let Some(secondary) = secondary.as_ref() else {
                    return self.errno(libc::EINVAL);
                };
                rename_held(&primary, secondary, flags)
            }
            MutationOperation::Mkdir { mode } => mkdir_held(&primary, mode),
            MutationOperation::Unlink { flags } => unlink_held(&primary, flags),
            MutationOperation::Link { flags } => {
                let Some(secondary) = secondary.as_ref() else {
                    return self.errno(libc::EINVAL);
                };
                link_held(&primary, secondary, flags)
            }
            MutationOperation::Symlink { target } => symlink_held(&primary, &target),
            MutationOperation::Chmod { mode } => chmod_held(&primary, mode),
            MutationOperation::Chown { uid, gid, flags } => chown_held(&primary, uid, gid, flags),
            MutationOperation::ChmodNoFollow { mode } => chmod_nofollow_held(&primary, mode),
            MutationOperation::Setxattr {
                name,
                value,
                flags,
                follow,
            } => setxattr_held(&primary, &name, &value, flags, follow),
            MutationOperation::Removexattr { name, follow } => {
                removexattr_held(&primary, &name, follow)
            }
            MutationOperation::Utimens { times, flags } => utimens_held(&primary, times, flags),
        };
        match result {
            Ok(value) => self.respond(&Response::Result { value }, None),
            Err(error) => self.errno(error.raw_os_error().unwrap_or(libc::EACCES)),
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
        return open_path_substitute(target, flags);
    }
    let path = CString::new(format!("/proc/self/fd/{}", target.as_raw_fd()))
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let clean_flags = flags & !create;
    let clean_flags = libc::c_int::try_from(clean_flags)
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: path names the retained descriptor and flags were range-checked.
    owned_fd(unsafe { libc::open(path.as_ptr(), clean_flags) })
}

/// realize an `O_PATH` open (issue #53). `SECCOMP_IOCTL_NOTIF_ADDFD` cannot inject an `O_PATH`
/// descriptor (the kernel's `fget` rejects `FMODE_PATH` files with EBADF), and answering with
/// CONTINUE would re-resolve the path the agent can swap (ADR-0020). the broker therefore
/// returns a read-only descriptor on the same pinned object. the policy already evaluated
/// the open as a read of that object, so no authority is added. only directories and regular
/// files are substituted: a read-only open of a fifo can block the broker and one of a device
/// can have side effects, and a symlink cannot be reopened without following it. those kinds
/// are refused with EOPNOTSUPP, which the supervisor records as a realization failure.
fn open_path_substitute(target: BorrowedFd<'_>, flags: u64) -> io::Result<OwnedFd> {
    let mut stat: libc::stat = unsafe { zeroed() };
    // SAFETY: target is a live descriptor and stat points to writable local storage.
    if unsafe { libc::fstat(target.as_raw_fd(), &raw mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let kind = stat.st_mode & libc::S_IFMT;
    if flags & u64::try_from(libc::O_DIRECTORY).unwrap_or_default() != 0 && kind != libc::S_IFDIR {
        return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
    }
    let reopen_flags = match kind {
        libc::S_IFDIR => libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        libc::S_IFREG => libc::O_RDONLY | libc::O_NOCTTY | libc::O_CLOEXEC,
        _ => return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP)),
    };
    let path = CString::new(format!("/proc/self/fd/{}", target.as_raw_fd()))
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: path names the retained descriptor and the flags are a fixed valid set.
    owned_fd(unsafe { libc::open(path.as_ptr(), reopen_flags) })
}

fn truncate_held(path: &HeldPath, length: i64) -> io::Result<i64> {
    if length < 0 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let target = required_target(path)?;
    let opened = open_existing(
        target,
        u64::try_from(libc::O_WRONLY | libc::O_CLOEXEC).unwrap_or_default(),
        0,
    )?;
    // SAFETY: opened is a live writable descriptor and length was validated.
    rc_zero(unsafe { libc::ftruncate(opened.as_raw_fd(), length) })
}

fn rename_held(source: &HeldPath, destination: &HeldPath, flags: u32) -> io::Result<i64> {
    const RENAME_NOREPLACE: u32 = 1;
    const RENAME_EXCHANGE: u32 = 2;
    if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE) != 0
        || flags == RENAME_NOREPLACE | RENAME_EXCHANGE
    {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let (source_parent, source_name) = required_parent_name(source)?;
    let (destination_parent, destination_name) = required_parent_name(destination)?;
    // SAFETY: both names are retained C strings relative to live parent descriptors.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            source_parent.as_raw_fd(),
            source_name.as_ptr(),
            destination_parent.as_raw_fd(),
            destination_name.as_ptr(),
            flags,
        )
    };
    rc_zero(rc as i32)
}

fn mkdir_held(path: &HeldPath, mode: u32) -> io::Result<i64> {
    // an anchor root has no parent or name, and it exists: the kernel answers a mkdir of any
    // existing path `EEXIST`, which is what `tar -x -C <root>` expects of `.`
    if path.parent.is_none() && path.target.is_some() {
        return Err(io::Error::from_raw_os_error(libc::EEXIST));
    }
    let (parent, name) = required_parent_name(path)?;
    // SAFETY: name is retained and parent is a live directory descriptor.
    rc_zero(unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode) })
}

fn unlink_held(path: &HeldPath, flags: i32) -> io::Result<i64> {
    if !matches!(flags, 0 | libc::AT_REMOVEDIR) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let (parent, name) = required_parent_name(path)?;
    // SAFETY: name is retained and parent is a live directory descriptor.
    rc_zero(unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) })
}

fn link_held(source: &HeldPath, destination: &HeldPath, flags: i32) -> io::Result<i64> {
    if flags != 0 {
        return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
    }
    let (source_parent, source_name) = required_parent_name(source)?;
    let (destination_parent, destination_name) = required_parent_name(destination)?;
    // SAFETY: both names are retained C strings relative to live parent descriptors.
    rc_zero(unsafe {
        libc::linkat(
            source_parent.as_raw_fd(),
            source_name.as_ptr(),
            destination_parent.as_raw_fd(),
            destination_name.as_ptr(),
            0,
        )
    })
}

fn symlink_held(destination: &HeldPath, target: &[u8]) -> io::Result<i64> {
    let target = CString::new(target).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let (parent, name) = required_parent_name(destination)?;
    // SAFETY: target and name are C strings and parent is a live directory descriptor.
    rc_zero(unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr()) })
}

fn chmod_held(path: &HeldPath, mode: u32) -> io::Result<i64> {
    let target = required_target(path)?;
    let proc_path = proc_fd_path(target)?;
    // SAFETY: proc_path resolves to the retained target descriptor.
    rc_zero(unsafe { libc::chmod(proc_path.as_ptr(), mode) })
}

fn chown_held(path: &HeldPath, uid: u32, gid: u32, flags: i32) -> io::Result<i64> {
    if flags & !libc::AT_SYMLINK_NOFOLLOW != 0 {
        return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
    }
    if flags == libc::AT_SYMLINK_NOFOLLOW && !acts_on_pinned_target(path)? {
        let (parent, name) = required_parent_name(path)?;
        // SAFETY: name is retained and parent is a live directory descriptor.
        return rc_zero(unsafe {
            libc::fchownat(
                parent.as_raw_fd(),
                name.as_ptr(),
                uid,
                gid,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        });
    }
    let target = required_target(path)?;
    let proc_path = proc_fd_path(target)?;
    // SAFETY: proc_path resolves to the retained target descriptor.
    rc_zero(unsafe { libc::chown(proc_path.as_ptr(), uid, gid) })
}

/// `S_ISLNK` of the pinned target, so a no-follow call can refuse a symlink it cannot act on.
fn target_is_symlink(target: BorrowedFd<'_>) -> io::Result<bool> {
    let mut stat: libc::stat = unsafe { zeroed() };
    // SAFETY: target is a live descriptor and stat points to writable local storage.
    if unsafe { libc::fstat(target.as_raw_fd(), &raw mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat.st_mode & libc::S_IFMT == libc::S_IFLNK)
}

/// whether a no-follow call acts on the pinned target through its proc link, as the following
/// form does, instead of through the parent and name.
/// a target that is not a symlink is the same object either way, and the pinned handle is the
/// object the policy decision was made on. an anchor root has no parent or name (it is a
/// canonical directory, never a symlink), so the handle is the only way to reach it. a symlink
/// cannot be reached through its proc link without being followed: it is acted on by name, and
/// an anchor root that were one is refused rather than followed.
fn acts_on_pinned_target(path: &HeldPath) -> io::Result<bool> {
    let Some(target) = path.target.as_ref() else {
        return Ok(false);
    };
    if !target_is_symlink(target.as_fd())? {
        return Ok(true);
    }
    if path.parent.is_none() {
        return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
    }
    Ok(false)
}

fn chmod_nofollow_held(path: &HeldPath, mode: u32) -> io::Result<i64> {
    if target_is_symlink(required_target(path)?)? {
        return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
    }
    chmod_held(path, mode)
}

/// the errno for a no-follow xattr call whose target is a symlink. a symlink cannot be reached
/// through its proc link without being followed, so the call cannot be realized. the kernel
/// itself refuses the `user.` namespace on anything but a regular file or directory with
/// `EPERM`, and that is the answer a `user.` name gets; another namespace is `EOPNOTSUPP`.
fn symlink_xattr_errno(name: &[u8]) -> i32 {
    if name.starts_with(b"user.") {
        libc::EPERM
    } else {
        libc::EOPNOTSUPP
    }
}

/// the xattr name or value as the C string the kernel takes, refusing an interior nul.
fn xattr_name(name: &[u8]) -> io::Result<CString> {
    CString::new(name).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

fn setxattr_held(
    path: &HeldPath,
    name: &[u8],
    value: &[u8],
    flags: i32,
    follow: bool,
) -> io::Result<i64> {
    let target = required_target(path)?;
    if !follow && target_is_symlink(target)? {
        return Err(io::Error::from_raw_os_error(symlink_xattr_errno(name)));
    }
    let name = xattr_name(name)?;
    let proc_path = proc_fd_path(target)?;
    // SAFETY: proc_path and name are C strings, value is a live slice of the given length.
    rc_zero(unsafe {
        libc::setxattr(
            proc_path.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            flags,
        )
    })
}

fn removexattr_held(path: &HeldPath, name: &[u8], follow: bool) -> io::Result<i64> {
    let target = required_target(path)?;
    if !follow && target_is_symlink(target)? {
        return Err(io::Error::from_raw_os_error(symlink_xattr_errno(name)));
    }
    let name = xattr_name(name)?;
    let proc_path = proc_fd_path(target)?;
    // SAFETY: proc_path and name are C strings.
    rc_zero(unsafe { libc::removexattr(proc_path.as_ptr(), name.as_ptr()) })
}

fn utimens_held(path: &HeldPath, times: Option<[i64; 4]>, flags: i32) -> io::Result<i64> {
    if flags & !libc::AT_SYMLINK_NOFOLLOW != 0 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let spec = times.map(|t| {
        [
            libc::timespec {
                tv_sec: t[0],
                tv_nsec: t[1],
            },
            libc::timespec {
                tv_sec: t[2],
                tv_nsec: t[3],
            },
        ]
    });
    let spec_ptr = spec.as_ref().map_or(std::ptr::null(), |t| t.as_ptr());
    if flags == libc::AT_SYMLINK_NOFOLLOW && !acts_on_pinned_target(path)? {
        let (parent, name) = required_parent_name(path)?;
        // SAFETY: name is retained, parent is a live directory descriptor, and spec_ptr is
        // null or points at two live timespecs.
        return rc_zero(unsafe {
            libc::utimensat(
                parent.as_raw_fd(),
                name.as_ptr(),
                spec_ptr,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        });
    }
    let target = required_target(path)?;
    let proc_path = proc_fd_path(target)?;
    // SAFETY: proc_path resolves to the retained target descriptor and spec_ptr is null or
    // points at two live timespecs.
    rc_zero(unsafe { libc::utimensat(libc::AT_FDCWD, proc_path.as_ptr(), spec_ptr, 0) })
}

fn required_target(path: &HeldPath) -> io::Result<BorrowedFd<'_>> {
    path.target
        .as_ref()
        .map(AsFd::as_fd)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
}

fn required_parent_name(path: &HeldPath) -> io::Result<(BorrowedFd<'_>, &CStr)> {
    let parent = path
        .parent
        .as_ref()
        .map(AsFd::as_fd)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EBUSY))?;
    let name = path
        .basename
        .as_deref()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EBUSY))?;
    Ok((parent, name))
}

fn proc_fd_path(fd: BorrowedFd<'_>) -> io::Result<CString> {
    CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd()))
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

fn rc_zero(rc: i32) -> io::Result<i64> {
    if rc == 0 {
        Ok(0)
    } else {
        Err(io::Error::last_os_error())
    }
}

/// openat2 resolve flags per anchor (adr-0020, adr-0023). the workspace follows in-tree
/// symlinks but stays beneath; the namespace root is the real `/`, so in-root resolution
/// gives ordinary semantics and lets absolute symlinks restart at `/` (beneath would
/// reject all of them); every narrower root refuses symlinks outright. magic links are
/// refused everywhere.
fn anchor_resolve_flags(workspace_anchor: bool, namespace_root: bool) -> u64 {
    if namespace_root && !workspace_anchor {
        RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS
    } else if workspace_anchor {
        RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS
    } else {
        RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS
    }
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

pub(crate) fn openat2(
    dirfd: RawFd,
    path: &CStr,
    flags: u64,
    mode: u64,
    resolve: u64,
) -> io::Result<OwnedFd> {
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

/// whether `fd` is on a cgroup2 filesystem, by `fstatfs`. a descriptor the kernel cannot
/// describe is not reported as cgroup2: the path rule still covers the mounts known at start.
fn fd_on_cgroup2(fd: BorrowedFd<'_>) -> bool {
    let mut stat: libc::statfs = unsafe { zeroed() };
    // SAFETY: stat is a valid out-buffer and fd is open; fstatfs works on O_PATH descriptors.
    if unsafe { libc::fstatfs(fd.as_raw_fd(), &raw mut stat) } != 0 {
        return false;
    }
    crate::supervisor::cgroup_mounts::is_cgroup2_magic(stat.f_type as i64)
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn namespace_root_resolves_in_root_and_still_refuses_magic_links() {
        let flags = anchor_resolve_flags(false, true);
        assert_eq!(flags, RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS);
        assert_eq!(flags & RESOLVE_BENEATH, 0);
    }

    #[test]
    fn workspace_stays_beneath_and_narrow_roots_refuse_symlinks() {
        assert_eq!(
            anchor_resolve_flags(true, false),
            RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS
        );
        assert_eq!(
            anchor_resolve_flags(false, false),
            RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS
        );
        // a workspace that is itself `/` keeps the stricter beneath rule
        assert_eq!(
            anchor_resolve_flags(true, true),
            RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS
        );
    }

    /// the worst bytes for a text encoding that spells each byte as a decimal number.
    fn heaviest(len: usize) -> Vec<u8> {
        vec![0xff; len]
    }

    #[test]
    fn a_maximum_xattr_value_crosses_the_broker_socket_whole() {
        let (near, far) = seqpacket_pair().unwrap();
        let value = heaviest(65_536);
        send_packet(
            near.as_raw_fd(),
            &Request::CommitMutation {
                primary: 1,
                secondary: None,
                operation: MutationOperation::Setxattr {
                    name: b"user.big".to_vec(),
                    value: value.clone(),
                    flags: 0,
                    follow: true,
                },
            },
            None,
        )
        .expect("a 64 KiB value fits one broker packet");
        let (request, _): (Request, _) = recv_packet(far.as_raw_fd()).unwrap();
        match request {
            Request::CommitMutation {
                operation: MutationOperation::Setxattr { value: got, .. },
                ..
            } => assert!(got == value, "the value arrives unchanged"),
            other => panic!("unexpected request: {other:?}"),
        }
    }

    #[test]
    fn a_maximum_network_payload_crosses_the_broker_socket_whole() {
        let (near, far) = seqpacket_pair().unwrap();
        let payload = heaviest(65_535);
        send_packet(
            near.as_raw_fd(),
            &Request::Network {
                operation: NetworkOperation::SendTo,
                address: vec![0xff; 128],
                payload: payload.clone(),
                flags: 0,
            },
            None,
        )
        .expect("a 64 KiB payload fits one broker packet");
        let (request, _): (Request, _) = recv_packet(far.as_raw_fd()).unwrap();
        match request {
            Request::Network { payload: got, .. } => {
                assert!(got == payload, "the payload arrives unchanged");
            }
            other => panic!("unexpected request: {other:?}"),
        }
    }
}
