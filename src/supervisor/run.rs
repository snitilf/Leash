//! the notify decision loop, record-only (docs/design/notify-loop.md; FR-2, FR-4, FR-9).
//!
//! assumptions: single decision thread (ADR-0011): one notification is received,
//! decided, recorded, and responded before the next. record precedes respond (section 3):
//! an action the recorder cannot write is denied and the run aborts (case E). every
//! pointer argument is read bounded and bracketed by ID_VALID (section 2). record-only
//! allows are realized with CONTINUE (ADR-0017); the denied-and-recorded set and every
//! untrusted-fact path deny in this mode too, with the one arc ADR-0019 scopes by mode:
//! an undecodable network address records a `raw` allow in record-only and a `raw` deny
//! in enforce (case C). the fail-closed arcs A-I of section 4 are the contract of this
//! module; each is named where it is handled.
//!
//! the per-notification state machine is written against the [`Notifier`] seam so the
//! arcs are unit-tested deterministically on any host; only the real notify-fd and /proc
//! wiring and `run_loop` itself are linux-only. on a non-linux host the state machine's
//! only consumer is the unit tests, hence the scoped dead-code allow.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[cfg(target_os = "linux")]
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, FromRawFd};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::Duration;

use crate::policy::{Evaluation, Policy, Request};
#[cfg(target_os = "linux")]
use crate::recorder::FsOperand;
use crate::recorder::{
    AskResolution, Attendance, Decision, EventBody, Fact, FsOperandDecision, RecorderError,
    SyscallEvent, TraceSink, TraceWriter,
};
use crate::sandbox::filter::{
    AUDIT_ARCH_X86_64, DENIED_RECORDED, SNAPSHOT_METADATA, SNAPSHOT_TRAPPED, X32_SYSCALL_BIT, nr,
};
use crate::supervisor::ask;
#[cfg(target_os = "linux")]
use crate::supervisor::broker::{
    BrokerResult, BrokerResultOrPath, MutationOperation, NetworkOperation,
};
use crate::supervisor::fact::{
    AccessSpec, FsShape, PathArg, fd_metadata_name, flags, fs_shape, syscall_name,
};
use crate::supervisor::mem::MemReadError;
#[cfg(target_os = "linux")]
use crate::supervisor::notify::SECCOMP_ADDFD_FLAG_SEND;
use crate::supervisor::notify::SeccompNotif;

/// the attended-ask timeout when `--ask-timeout` is not given (notify-loop.md section 5).
pub const DEFAULT_ASK_TIMEOUT: Duration = Duration::from_secs(60);
const CLONE_ARGS_MIN_SIZE: u64 = 8;
const CLONE_ARGS_MAX_SIZE: u64 = 88;
const OPEN_HOW_SIZE: usize = 24;

/// the `RESOLVE_*` bits of `openat2(2)`.
const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLVE_CACHED: u64 = 0x20;
/// the bits the kernel accepts at all; any other is `EINVAL`.
const RESOLVE_VALID: u64 = 0x3f;
/// the bits Leash honors for the caller: they only restrict how the caller's own spelling of
/// the path may resolve, so Leash checks the spelling against them and still opens the object
/// the policy judged. `RESOLVE_IN_ROOT` changes what the spelling means and `RESOLVE_CACHED`
/// changes whether the call may block, and neither is honored.
const RESOLVE_HONORED: u64 =
    RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH;

/// the restrictions an `openat2` caller put on how its path may resolve, and what they apply to.
#[derive(Debug, Clone, Default)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct ChildResolve {
    /// the honored `RESOLVE_*` bits; zero when the caller asked for none
    bits: u64,
    /// the directory a relative `given` starts from; `None` when it could not be read
    dir: Option<PathBuf>,
    /// the path as the caller spelled it, before it was anchored
    given: PathBuf,
}

#[derive(Debug, Clone)]
enum FsInvocation {
    Open {
        flags: u64,
        mode: u32,
        unsupported_errno: Option<i32>,
        resolve: ChildResolve,
    },
    Mutation(MutationInvocation),
}

#[derive(Debug, Clone)]
enum MutationInvocation {
    Truncate {
        length: i64,
    },
    Rename {
        flags: u32,
    },
    Mkdir {
        mode: u32,
    },
    Unlink {
        flags: i32,
    },
    Link {
        flags: i32,
    },
    Symlink {
        target: Vec<u8>,
    },
    Chmod {
        mode: u32,
    },
    Chown {
        uid: u32,
        gid: u32,
        flags: i32,
    },
    ChmodNoFollow {
        mode: u32,
    },
    Setxattr {
        name: Vec<u8>,
        value: Vec<u8>,
        flags: i32,
        follow: bool,
    },
    Removexattr {
        name: Vec<u8>,
        follow: bool,
    },
    Utimens {
        times: Option<[i64; 4]>,
        flags: i32,
    },
}

/// matched-rule ids for a policy-less run (trace.md section 2).
pub mod rule {
    /// the record-only base allow
    pub const RECORD_ONLY: &str = "base:record_only";
    /// the io_uring unconditional deny (SR-4)
    pub const IO_URING: &str = "sr4:io_uring";
    /// foreign-arch or x32 entry (syscalls.md section 5)
    pub const FOREIGN_ABI: &str = "sr3:foreign_abi";
    /// a pointer argument could not be read within its cap (case C)
    pub const MEMORY_READ: &str = "failsafe:memory_read";
    /// process creation has no policy predicate in schema version 1
    pub const PROCESS_CREATION: &str = "base:process_creation";
    /// in-tree cross-process control
    pub const PROCESS_TREE: &str = "base:process_tree";
    /// cross-process control attempted outside the supervised tree
    pub const PROCESS_TREE_DENY: &str = "failsafe:process_tree";
    /// the pidfd_getfd unconditional deny (SR-4, ADR-0019)
    pub const PIDFD_GETFD: &str = "sr4:pidfd_getfd";
    /// broker path preparation or realization refused the operand
    pub const REALIZATION: &str = "failsafe:realization";
    /// a metadata call's own arguments are invalid (an unknown flag, an xattr value over
    /// the kernel's limit), answered with the kernel's errno before any path is judged
    pub const UNSUPPORTED_OPERAND: &str = "failsafe:unsupported_operand";
    /// `clone3` answered ENOSYS in a snapshot run, before its struct is read (ADR-0024)
    pub const SNAPSHOT_CLONE3: &str = "snapshot:clone3";
    /// legacy AIO denied in a snapshot run (ADR-0024)
    pub const SNAPSHOT_AIO: &str = "snapshot:aio";
    /// `setxattrat`, `removexattrat` or `file_setattr` answered ENOSYS in a snapshot run:
    /// they name a path with no open and no libc wrapper uses them yet (ADR-0025)
    pub const SNAPSHOT_XATTRAT: &str = "snapshot:xattrat";
    /// a snapshot-only metadata call reached a run that is not a snapshot run, which only a
    /// filter and flag that disagree can do (ADR-0024 decision 4)
    pub const SNAPSHOT_METADATA: &str = "snapshot:metadata";
}

/// how the run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunOutcome {
    /// raw wait status of the direct child.
    pub wait_status: i32,
    /// index of the final step boundary (FR-17); 0 when no snapshot capture was wired
    pub final_step: u64,
}

/// fatal loop errors. every one aborts the run fail-closed (I3): the notify fd is
/// dropped on unwind, so the kernel denies everything still pending (case G is the
/// backstop under all of these).
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// case E: the recorder write failed; the pending action was denied and the run aborts.
    #[error("trace write failed; run aborted (case E): {0}")]
    Recorder(#[from] RecorderError),
    /// the notify fd itself failed outside the per-notification arcs.
    #[error("notify fd failed: {0}")]
    Notify(#[source] io::Error),
    /// enforce mode reached the loop without its confined realization broker.
    #[error("enforce mode requires a confined realization broker")]
    MissingBroker,
    /// snapshot integrity restrictions were requested outside enforce mode.
    #[error("snapshot integrity restrictions require enforce mode")]
    SnapshotIntegrityNeedsEnforce,
    /// snapshot integrity restrictions were requested without the cgroup2 mounts their
    /// implicit deny protects (ADR-0024 decision 4).
    #[error("snapshot integrity restrictions require the cgroup2 mounts of the run")]
    SnapshotIntegrityNeedsCgroupMounts,
    /// the installed seccomp filter and the run's snapshot flag disagree.
    #[error("snapshot filter mismatch: filter installed {installed}, run requires {required}")]
    SnapshotFilterMismatch {
        /// whether the child's filter traps the snapshot-only syscalls
        installed: bool,
        /// whether the run's `snapshot_integrity` flag is set
        required: bool,
    },
    /// enforce mode reached the loop without a loaded policy.
    #[error("enforce mode requires a loaded policy")]
    EnforceWithoutPolicy,
    /// enforce mode reached the loop without the resolved state root its implicit deny
    /// protects (FR-21).
    #[error("enforce mode requires the resolved state root")]
    EnforceWithoutStateRoot,
    /// the confined side-effect broker failed, so the run aborts fail-closed.
    #[cfg(target_os = "linux")]
    #[error("confined realization broker failed: {0}")]
    Broker(#[from] crate::supervisor::broker::BrokerError),
    /// snapshot capture is disabled until coherent, race-safe capture is available.
    #[error("snapshot capture is not available")]
    CaptureUnavailable,
    /// a step-boundary capture failed; the run aborts fail-closed rather than record a
    /// boundary whose snapshot does not exist (snapshot.md section 6)
    #[error("snapshot capture failed; run aborted: {0}")]
    Snapshot(#[from] crate::snapshot::SnapshotError),
    /// the run cgroup could not be watched, killed or removed (ADR-0024 decisions 11, 12).
    #[error("run cgroup failed: {0}")]
    RunCgroup(#[source] io::Error),
}

/// immutable inputs for one notify-loop run.
#[derive(Clone, Copy)]
pub struct RunConfig<'a> {
    /// record-only or enforce
    pub mode: crate::recorder::Mode,
    /// loaded policy; required in enforce mode and absent for current record-only CLI runs
    pub policy: Option<&'a Policy>,
    /// whether an operator is available for ask decisions
    pub attendance: Attendance,
    /// maximum wait for an attended ask
    pub ask_timeout: Duration,
    /// resolves the asks of one held syscall in an attended run (FR-10). production
    /// prompts on the controlling terminal (ask::tty_prompt); tests script the answer.
    pub prompter: &'a dyn Fn(&[ask::PendingAsk], Duration) -> AskResolution,
    /// root of the supervised process tree
    pub root_pid: u32,
    /// step-boundary capture target (FR-11). when present, the loop runs the step clock
    /// and captures at every boundary; when absent, no steps exist and the final step
    /// index is 0.
    pub capture: Option<&'a dyn crate::snapshot::BoundaryCapture>,
    /// confined side-effect broker; required in enforce mode
    #[cfg(target_os = "linux")]
    pub broker: Option<&'a RefCell<crate::supervisor::broker::Broker>>,
    /// pre-resolved exact hostname rules
    pub resolved_hosts: Option<&'a HashMap<String, Vec<IpAddr>>>,
    /// snapshot integrity restrictions apply (ADR-0024 decisions 7 and 8): `clone3` is
    /// answered ENOSYS unread and legacy AIO is denied. enforce mode only.
    pub snapshot_integrity: bool,
    /// the resolved state root of an enforce run; evaluated as an implicit deny before any
    /// policy rule (FR-21, ADR-0024). the enforce constructors require it, so an enforce
    /// run cannot be built without one; record-only runs carry none.
    pub state_root: Option<&'a crate::supervisor::state_root::StateRoot>,
    /// the cgroup2 mounts of the supervisor's mount namespace, denied as an implicit rule
    /// before any policy rule in a snapshot-integrity run (ADR-0024 decision 4). required
    /// when `snapshot_integrity` is set; unused otherwise.
    pub cgroup_mounts: Option<&'a crate::supervisor::cgroup_mounts::CgroupMounts>,
}

impl std::fmt::Debug for RunConfig<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // the prompter is a behavior, not data; it prints as present-or-absent nothing
        f.debug_struct("RunConfig")
            .field("mode", &self.mode)
            .field("attendance", &self.attendance)
            .field("ask_timeout", &self.ask_timeout)
            .field("root_pid", &self.root_pid)
            .finish_non_exhaustive()
    }
}

impl<'a> RunConfig<'a> {
    /// current policy-less record-only behavior.
    pub fn record_only(root_pid: u32, attendance: Attendance) -> Self {
        Self {
            mode: crate::recorder::Mode::RecordOnly,
            policy: None,
            attendance,
            ask_timeout: DEFAULT_ASK_TIMEOUT,
            prompter: &ask::tty_prompt,
            root_pid,
            capture: None,
            #[cfg(target_os = "linux")]
            broker: None,
            resolved_hosts: None,
            snapshot_integrity: false,
            state_root: None,
            cgroup_mounts: None,
        }
    }

    /// enforce with a validated policy.
    pub fn enforce(
        root_pid: u32,
        attendance: Attendance,
        policy: &'a Policy,
        state_root: &'a crate::supervisor::state_root::StateRoot,
    ) -> Self {
        Self {
            mode: crate::recorder::Mode::Enforce,
            policy: Some(policy),
            attendance,
            ask_timeout: DEFAULT_ASK_TIMEOUT,
            prompter: &ask::tty_prompt,
            root_pid,
            capture: None,
            #[cfg(target_os = "linux")]
            broker: None,
            resolved_hosts: None,
            snapshot_integrity: false,
            state_root: Some(state_root),
            cgroup_mounts: None,
        }
    }

    /// enforce with the confined broker and pre-resolved hostname cache.
    #[cfg(target_os = "linux")]
    pub fn enforce_with_broker(
        root_pid: u32,
        attendance: Attendance,
        policy: &'a Policy,
        broker: &'a RefCell<crate::supervisor::broker::Broker>,
        resolved_hosts: &'a HashMap<String, Vec<IpAddr>>,
        state_root: &'a crate::supervisor::state_root::StateRoot,
    ) -> Self {
        Self {
            mode: crate::recorder::Mode::Enforce,
            policy: Some(policy),
            attendance,
            ask_timeout: DEFAULT_ASK_TIMEOUT,
            prompter: &ask::tty_prompt,
            root_pid,
            capture: None,
            broker: Some(broker),
            resolved_hosts: Some(resolved_hosts),
            snapshot_integrity: false,
            state_root: Some(state_root),
            cgroup_mounts: None,
        }
    }

    /// set the attended-ask timeout (FR-10); the CLI passes `--ask-timeout` through here.
    pub fn with_ask_timeout(mut self, timeout: Duration) -> Self {
        self.ask_timeout = timeout;
        self
    }

    /// apply the snapshot integrity restrictions (ADR-0024 decisions 7 and 8).
    pub fn with_snapshot_integrity(mut self, snapshot_integrity: bool) -> Self {
        self.snapshot_integrity = snapshot_integrity;
        self
    }

    /// name the cgroup2 mounts a snapshot-integrity run denies (ADR-0024 decision 4).
    pub fn with_cgroup_mounts(
        mut self,
        mounts: &'a crate::supervisor::cgroup_mounts::CgroupMounts,
    ) -> Self {
        self.cgroup_mounts = Some(mounts);
        self
    }

    /// wire step-boundary capture (FR-11); the session passes the run-directory target.
    pub fn with_capture(mut self, capture: &'a dyn crate::snapshot::BoundaryCapture) -> Self {
        self.capture = Some(capture);
        self
    }

    fn validate(self) -> Result<Self, RunError> {
        if self.capture.is_some() {
            return Err(RunError::CaptureUnavailable);
        }
        if self.snapshot_integrity && self.mode != crate::recorder::Mode::Enforce {
            return Err(RunError::SnapshotIntegrityNeedsEnforce);
        }
        if self.snapshot_integrity && self.cgroup_mounts.is_none() {
            return Err(RunError::SnapshotIntegrityNeedsCgroupMounts);
        }
        if self.mode == crate::recorder::Mode::Enforce && self.policy.is_none() {
            return Err(RunError::EnforceWithoutPolicy);
        }
        if self.mode == crate::recorder::Mode::Enforce && self.state_root.is_none() {
            return Err(RunError::EnforceWithoutStateRoot);
        }
        #[cfg(target_os = "linux")]
        if self.mode == crate::recorder::Mode::Enforce && self.broker.is_none() {
            return Err(RunError::MissingBroker);
        }
        Ok(self)
    }
}

/// what one loop iteration needs from the kernel: the notify-fd operations plus the
/// /proc reads behind the facts. `NotifyFd` and /proc implement it for real; tests
/// script it, which is what makes the fail-closed arcs deterministically testable.
pub(crate) trait Notifier {
    /// is the notification still alive (ID_VALID)?
    fn id_valid(&self, id: u64) -> io::Result<bool>;
    /// allow the trapped syscall to execute (CONTINUE).
    fn send_continue(&self, id: u64) -> io::Result<()>;
    /// fail the trapped syscall with an errno.
    fn send_error(&self, id: u64, errno: i32) -> io::Result<()>;
    /// complete the trapped syscall with a successful scalar value.
    fn send_success(&self, id: u64, value: i64) -> io::Result<()>;
    /// atomically inject an fd and complete an fd-returning syscall.
    fn send_addfd(
        &self,
        id: u64,
        srcfd: BorrowedFd<'_>,
        flags: u32,
        newfd_flags: u32,
    ) -> io::Result<i32>;
    /// duplicate one descriptor from the trapped process.
    fn duplicate_fd(&self, pid: u32, target_fd: RawFd) -> io::Result<OwnedFd>;
    /// what the trapped process's descriptor is, read from a duplicate of it that is closed
    /// before this returns. the supervisor may duplicate the agent's descriptors; only the
    /// agent is denied `pidfd_getfd` (SR-4).
    fn describe_fd(&self, pid: u32, target_fd: RawFd) -> io::Result<FdFacts> {
        let duplicate = self.duplicate_fd(pid, target_fd)?;
        fd_facts(duplicate)
    }
    /// bounded nul-terminated read from child memory (mem.rs caps).
    fn read_path(&self, pid: u32, addr: u64) -> Result<Vec<u8>, MemReadError>;
    /// bounded fixed-size read from child memory.
    fn read_bytes(&self, pid: u32, addr: u64, len: usize) -> Result<Vec<u8>, MemReadError>;
    /// bounded fixed-size read of a leading u64 field (open_how flags).
    fn read_u64(&self, pid: u32, addr: u64) -> Result<u64, MemReadError>;
    /// the kernel's answer for a relative path's anchor: readlink of /proc cwd or fd/N.
    fn dir_prefix(&self, pid: u32, anchor: DirAnchor) -> io::Result<PathBuf>;
    /// whether `target` is the supervised root or a descendant of it.
    fn process_in_tree(&self, root: u32, target: u32) -> io::Result<bool>;
}

/// what an open descriptor is, as the kernel describes the object and not as its `/proc`
/// link spells it: the filesystem it is on and its identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FdFacts {
    /// `f_type` of `fstatfs`: the filesystem magic
    pub f_type: i64,
    /// `st_dev` of the object
    pub dev: u64,
    /// `st_ino` of the object
    pub ino: u64,
}

/// describe an owned descriptor, then close it.
pub(crate) fn fd_facts(fd: OwnedFd) -> io::Result<FdFacts> {
    use std::os::unix::fs::MetadataExt;
    let mut statfs: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: fd is open and statfs is a writable local buffer; fstatfs works on O_PATH.
    if unsafe { libc::fstatfs(fd.as_raw_fd(), &raw mut statfs) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let metadata = std::fs::File::from(fd).metadata()?;
    Ok(FdFacts {
        f_type: statfs.f_type as i64,
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}

/// the implicit denies that depend on what a descriptor is rather than where its link says
/// it is: an object on cgroup2, and the state root itself.
fn fd_identity_deny(config: &RunConfig<'_>, facts: &FdFacts) -> Option<Evaluation> {
    if let Some(eval) = cgroup2_identity_deny(
        config,
        crate::supervisor::cgroup_mounts::is_cgroup2_magic(facts.f_type),
    ) {
        return Some(eval);
    }
    (config.mode == crate::recorder::Mode::Enforce
        && config
            .state_root
            .is_some_and(|root| root.is_identity(facts.dev, facts.ino)))
    .then_some(Evaluation {
        decision: Decision::Deny,
        matched: crate::policy::MatchId::ImplicitStateRoot,
        would_deny: None,
    })
}

/// where a relative path is anchored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirAnchor {
    /// the trapped thread's current working directory
    Cwd,
    /// an open directory fd in the trapped thread
    Fd(u32),
}

/// outcome of one handled notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Handled {
    /// a response was sent for an action that cannot mutate the workspace
    /// (an event was recorded unless the syscall is silent)
    Responded,
    /// a response was sent and the action may have mutated the workspace: an allowed
    /// filesystem write or mutation (FR-17 step-clock input, snapshot.md section 1)
    RespondedMutation,
    /// case B: the notification died mid-handling; no event, no response
    Dropped,
}

#[derive(Clone)]
struct ResolvedDecision {
    event_decision: Decision,
    response_decision: Decision,
    ask_resolution: Option<AskResolution>,
    matched_rule: String,
    would_deny: Option<bool>,
}

#[cfg(target_os = "linux")]
struct ResolvedOperand {
    effective: ResolvedDecision,
    evidence: Vec<FsOperandDecision>,
}

fn fixed_decision(decision: Decision, matched_rule: &str) -> ResolvedDecision {
    ResolvedDecision {
        event_decision: decision,
        response_decision: decision,
        ask_resolution: None,
        matched_rule: matched_rule.to_string(),
        would_deny: None,
    }
}

fn open_mode(sys_nr: u32, notif: &SeccompNotif) -> u32 {
    match sys_nr {
        nr::OPEN => notif.data.args[2] as u32,
        nr::CREAT => notif.data.args[1] as u32,
        nr::OPENAT => notif.data.args[3] as u32,
        _ => 0,
    }
}

/// why an operand of a filesystem call could not be turned into a request.
#[derive(Debug)]
enum OperandError {
    /// agent memory could not be read within its cap: case C, denied under
    /// `failsafe:memory_read`
    Memory,
    /// the call's own arguments are invalid, and the kernel would have refused it with this
    /// errno before looking at any path: the supervisor answers the same errno and records
    /// it under `failsafe:unsupported_operand`
    Unsupported(i32),
}

impl From<MemReadError> for OperandError {
    fn from(_: MemReadError) -> Self {
        Self::Memory
    }
}

/// `AT_EMPTY_PATH`, pinned to the x86-64 value like the other abi constants here.
const AT_EMPTY_PATH: i32 = 0x1000;

/// whether this call may name its target by an empty path: `utimensat` and `fchmodat2` with
/// `AT_EMPTY_PATH` act on the object of their directory descriptor when the path is `""`.
fn empty_path_allowed(sys_nr: u32, notif: &SeccompNotif) -> bool {
    matches!(sys_nr, nr::UTIMENSAT | nr::FCHMODAT2)
        && notif.data.args[3] as i32 & AT_EMPTY_PATH != 0
}

/// decode the call's own arguments. `empty_path` says the path the agent passed was empty and
/// `AT_EMPTY_PATH` was set, so the call acts on the object `path` already names (the
/// descriptor's target) and not on something beneath it.
fn mutation_invocation<N: Notifier>(
    kernel: &N,
    sys_nr: u32,
    notif: &SeccompNotif,
    path: &std::path::Path,
    empty_path: bool,
) -> Result<MutationInvocation, OperandError> {
    let invocation = match sys_nr {
        nr::TRUNCATE => MutationInvocation::Truncate {
            length: notif.data.args[1] as i64,
        },
        nr::RENAME | nr::RENAMEAT => MutationInvocation::Rename { flags: 0 },
        nr::RENAMEAT2 => MutationInvocation::Rename {
            flags: notif.data.args[4] as u32,
        },
        nr::MKDIR => MutationInvocation::Mkdir {
            mode: notif.data.args[1] as u32,
        },
        nr::MKDIRAT => MutationInvocation::Mkdir {
            mode: notif.data.args[2] as u32,
        },
        nr::RMDIR => MutationInvocation::Unlink {
            flags: libc::AT_REMOVEDIR,
        },
        nr::UNLINK => MutationInvocation::Unlink { flags: 0 },
        nr::UNLINKAT => MutationInvocation::Unlink {
            flags: notif.data.args[2] as i32,
        },
        nr::LINK => MutationInvocation::Link { flags: 0 },
        nr::LINKAT => MutationInvocation::Link {
            flags: notif.data.args[4] as i32,
        },
        nr::SYMLINK | nr::SYMLINKAT => MutationInvocation::Symlink {
            target: path.as_os_str().as_bytes().to_vec(),
        },
        nr::CHMOD => MutationInvocation::Chmod {
            mode: notif.data.args[1] as u32,
        },
        nr::FCHMODAT => MutationInvocation::Chmod {
            mode: notif.data.args[2] as u32,
        },
        nr::CHOWN => MutationInvocation::Chown {
            uid: notif.data.args[1] as u32,
            gid: notif.data.args[2] as u32,
            flags: 0,
        },
        nr::FCHOWNAT => MutationInvocation::Chown {
            uid: notif.data.args[2] as u32,
            gid: notif.data.args[3] as u32,
            flags: notif.data.args[4] as i32,
        },
        nr::LCHOWN => MutationInvocation::Chown {
            uid: notif.data.args[1] as u32,
            gid: notif.data.args[2] as u32,
            flags: AT_SYMLINK_NOFOLLOW,
        },
        nr::FCHMODAT2 => {
            let flags = notif.data.args[3] as i32;
            if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
                return Err(OperandError::Unsupported(libc::EINVAL));
            }
            let mode = notif.data.args[2] as u32;
            // an empty path names the descriptor's own object, which is not followed
            if flags & AT_SYMLINK_NOFOLLOW != 0 || empty_path {
                MutationInvocation::ChmodNoFollow { mode }
            } else {
                MutationInvocation::Chmod { mode }
            }
        }
        nr::UTIMENSAT => {
            let flags = notif.data.args[3] as i32;
            if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
                return Err(OperandError::Unsupported(libc::EINVAL));
            }
            MutationInvocation::Utimens {
                times: read_times(kernel, notif, notif.data.args[2], TimeLayout::Timespec)?,
                flags: if empty_path {
                    AT_SYMLINK_NOFOLLOW
                } else {
                    flags & AT_SYMLINK_NOFOLLOW
                },
            }
        }
        nr::UTIMES => MutationInvocation::Utimens {
            times: read_times(kernel, notif, notif.data.args[1], TimeLayout::Timeval)?,
            flags: 0,
        },
        nr::FUTIMESAT => MutationInvocation::Utimens {
            times: read_times(kernel, notif, notif.data.args[2], TimeLayout::Timeval)?,
            flags: 0,
        },
        nr::UTIME => MutationInvocation::Utimens {
            times: read_times(kernel, notif, notif.data.args[1], TimeLayout::Utimbuf)?,
            flags: 0,
        },
        nr::SETXATTR | nr::LSETXATTR => {
            let size = usize::try_from(notif.data.args[3]).unwrap_or(usize::MAX);
            if size > XATTR_SIZE_MAX {
                return Err(OperandError::Unsupported(libc::E2BIG));
            }
            let name = kernel.read_path(notif.pid, notif.data.args[1])?;
            let value = if size == 0 {
                Vec::new()
            } else {
                kernel.read_bytes(notif.pid, notif.data.args[2], size)?
            };
            MutationInvocation::Setxattr {
                name,
                value,
                flags: notif.data.args[4] as i32,
                follow: sys_nr == nr::SETXATTR,
            }
        }
        nr::REMOVEXATTR | nr::LREMOVEXATTR => MutationInvocation::Removexattr {
            name: kernel.read_path(notif.pid, notif.data.args[1])?,
            follow: sys_nr == nr::REMOVEXATTR,
        },
        _ => return Err(OperandError::Unsupported(libc::ENOSYS)),
    };
    Ok(invocation)
}

/// the largest xattr value the kernel accepts (`XATTR_SIZE_MAX`).
const XATTR_SIZE_MAX: usize = 65_536;

/// `AT_SYMLINK_NOFOLLOW`, pinned to the x86-64 value like the other abi constants here, since
/// the macos dev host's libc disagrees (0x20).
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

/// how a metadata call lays out the two timestamps behind its `times` pointer.
#[derive(Clone, Copy)]
enum TimeLayout {
    /// `struct timespec[2]`: seconds and nanoseconds, nanoseconds may be UTIME_NOW or OMIT
    Timespec,
    /// `struct timeval[2]`: seconds and microseconds
    Timeval,
    /// `struct utimbuf`: access and modification seconds
    Utimbuf,
}

/// read the timestamps a `utime` family call asks for, as `[atime_sec, atime_nsec,
/// mtime_sec, mtime_nsec]`; a null pointer means "now" and reads nothing. a microsecond
/// value too large to scale is left out of range, which the kernel refuses with EINVAL.
fn read_times<N: Notifier>(
    kernel: &N,
    notif: &SeccompNotif,
    addr: u64,
    layout: TimeLayout,
) -> Result<Option<[i64; 4]>, MemReadError> {
    if addr == 0 {
        return Ok(None);
    }
    let take = |bytes: &[u8], at: usize| {
        i64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap_or([0; 8]))
    };
    Ok(Some(match layout {
        TimeLayout::Timespec => {
            let b = kernel.read_bytes(notif.pid, addr, 32)?;
            [take(&b, 0), take(&b, 8), take(&b, 16), take(&b, 24)]
        }
        TimeLayout::Timeval => {
            let b = kernel.read_bytes(notif.pid, addr, 32)?;
            let nsec = |usec: i64| usec.checked_mul(1000).unwrap_or(i64::MAX);
            [
                take(&b, 0),
                nsec(take(&b, 8)),
                take(&b, 16),
                nsec(take(&b, 24)),
            ]
        }
        TimeLayout::Utimbuf => {
            let b = kernel.read_bytes(notif.pid, addr, 16)?;
            [take(&b, 0), 0, take(&b, 8), 0]
        }
    }))
}

fn resolve_decision(config: &RunConfig<'_>, request: &Request<'_>) -> ResolvedDecision {
    let mut asks = Vec::new();
    let eval = evaluate_tracked(config, request, &mut asks);
    let resolution = settle_asks(config, &asks);
    finalize_decision(eval, resolution)
}

/// pure evaluation (ADR-0004); an ask-matched request is collected for the syscall's
/// shared prompt instead of being settled here, so one held syscall prompts once even
/// when several of its accesses match ask rules (notify-loop.md section 5).
fn evaluate_tracked(
    config: &RunConfig<'_>,
    request: &Request<'_>,
    asks: &mut Vec<ask::PendingAsk>,
) -> Evaluation {
    evaluate_operand(config, request, false, asks)
}

/// the implicit denies, ranked before every policy rule: the state root (FR-21, ADR-0024
/// decision 3), the cgroup2 mounts of a snapshot-integrity run (decision 4), and the
/// supervisor's `/proc` tree. they apply only in an enforce run that carries the root;
/// `destination` marks the second operand of a rename or link, where naming an ancestor of
/// a protected path replaces it.
fn implicit_state_root_deny(
    config: &RunConfig<'_>,
    request: &Request<'_>,
    destination: bool,
) -> Option<Evaluation> {
    if config.mode != crate::recorder::Mode::Enforce {
        return None;
    }
    let root = config.state_root?;
    let cgroups = config.cgroup_mounts.filter(|_| config.snapshot_integrity);
    let (state_root, cgroup, supervisor_proc) = match request {
        Request::Fs { path, access } => {
            let path = std::path::Path::new(path);
            (
                root.denies_fs(path, access, destination),
                cgroups.is_some_and(|m| m.denies_fs(path, access, destination)),
                root.denies_proc(path),
            )
        }
        Request::Exec { binary } => {
            let binary = std::path::Path::new(binary);
            (
                root.denies_exec(binary),
                cgroups.is_some_and(|m| m.denies_exec(binary)),
                root.denies_proc(binary),
            )
        }
        Request::Net { .. } => (false, false, false),
    };
    let matched = if state_root {
        crate::policy::MatchId::ImplicitStateRoot
    } else if cgroup {
        crate::policy::MatchId::ImplicitCgroup
    } else if supervisor_proc {
        crate::policy::MatchId::ImplicitSupervisorProc
    } else {
        return None;
    };
    Some(Evaluation {
        decision: Decision::Deny,
        matched,
        would_deny: None,
    })
}

fn evaluate_operand(
    config: &RunConfig<'_>,
    request: &Request<'_>,
    destination: bool,
    asks: &mut Vec<ask::PendingAsk>,
) -> Evaluation {
    if let Some(eval) = implicit_state_root_deny(config, request, destination) {
        return eval;
    }
    let eval = match config.policy {
        Some(policy) => policy.evaluate(request, config.mode),
        None => Evaluation {
            decision: Decision::Allow,
            matched: crate::policy::MatchId::BaseRecordOnly,
            would_deny: None,
        },
    };
    if eval.decision == Decision::Ask {
        asks.push(ask::PendingAsk::new(request, eval.matched.to_string()));
    }
    eval
}

/// settle one held syscall's asks with a single prompt (notify-loop.md section 5):
/// every ask-matched item is listed and one answer covers them all. an unattended run
/// never prompts; the ask denies immediately (FR-20).
fn settle_asks(config: &RunConfig<'_>, asks: &[ask::PendingAsk]) -> Option<AskResolution> {
    if asks.is_empty() {
        return None;
    }
    Some(match config.attendance {
        Attendance::Unattended => AskResolution::Unattended,
        Attendance::Attended => (config.prompter)(asks, config.ask_timeout),
    })
}

/// turn a pure evaluation into the recorded and answered decision. an ask keeps `ask` as
/// the event decision; the response follows the shared resolution, and only an approval
/// realizes the allow (FR-10).
fn finalize_decision(eval: Evaluation, resolution: Option<AskResolution>) -> ResolvedDecision {
    if eval.decision != Decision::Ask {
        return ResolvedDecision {
            event_decision: eval.decision,
            response_decision: eval.decision,
            ask_resolution: None,
            matched_rule: eval.matched.to_string(),
            would_deny: eval.would_deny,
        };
    }
    // settle_asks ran for every ask; an absent resolution here is unreachable, and deny
    // is the only safe reading of unreachable (I3).
    let resolution = resolution.unwrap_or(AskResolution::Denied);
    let response_decision = match resolution {
        AskResolution::Approved => Decision::Allow,
        AskResolution::Denied | AskResolution::TimedOut | AskResolution::Unattended => {
            Decision::Deny
        }
    };
    ResolvedDecision {
        event_decision: Decision::Ask,
        response_decision,
        ask_resolution: Some(resolution),
        matched_rule: eval.matched.to_string(),
        would_deny: eval.would_deny,
    }
}

/// a `send` that tolerates the target dying first: ENOENT means the child is gone and
/// its syscall never completes (case B); any other failure is fatal (fail closed).
fn tolerate_dead(result: io::Result<()>) -> Result<(), RunError> {
    match result {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(()),
        Err(e) => Err(RunError::Notify(e)),
    }
}

/// handle one received notification: classify, gather facts, record, respond
/// (notify-loop.md section 1, steps 2-6).
pub(crate) fn handle_notification<N: Notifier, S: TraceSink>(
    kernel: &N,
    notif: &SeccompNotif,
    writer: &mut TraceWriter<S>,
    config: &RunConfig<'_>,
    ts: u64,
) -> Result<Handled, RunError> {
    let sys_nr = notif.data.nr as u32;

    // the denied-and-recorded set (syscalls.md section 5): record the attempt, then
    // refuse it, in both modes. ENOSYS matches both the no-listener fail-closed path
    // and a kernel built without the feature.
    if notif.data.arch != AUDIT_ARCH_X86_64 || sys_nr & X32_SYSCALL_BIT != 0 {
        record(
            writer,
            ts,
            notif,
            "foreign_abi",
            Fact::Raw {},
            &fixed_decision(Decision::Deny, rule::FOREIGN_ABI),
        )?;
        tolerate_dead(kernel.send_error(notif.id, libc::ENOSYS))?;
        return Ok(Handled::Responded);
    }
    if DENIED_RECORDED.contains(&sys_nr) {
        let name = syscall_name(sys_nr).unwrap_or("unknown");
        let matched_rule = if sys_nr == nr::PIDFD_GETFD {
            rule::PIDFD_GETFD
        } else {
            rule::IO_URING
        };
        record(
            writer,
            ts,
            notif,
            name,
            Fact::Raw {},
            &fixed_decision(Decision::Deny, matched_rule),
        )?;
        tolerate_dead(kernel.send_error(notif.id, libc::ENOSYS))?;
        return Ok(Handled::Responded);
    }

    // snapshot runs (ADR-0024 decisions 7 and 8). clone3 is answered before its struct
    // is read: the struct lives in agent memory, so a CLONE_INTO_CGROUP flag check would
    // race the agent rewriting it. libc falls back to clone, which has no cgroup argument.
    // AIO is denied because the freezer stops tasks, not in-flight I/O.
    // a trapped snapshot-filter syscall is denied and recorded whatever the flag says, so
    // a filter and flag that disagree can never allow it unrecorded.
    if SNAPSHOT_TRAPPED.contains(&sys_nr) || (config.snapshot_integrity && sys_nr == nr::CLONE3) {
        let matched_rule = match sys_nr {
            nr::CLONE3 => rule::SNAPSHOT_CLONE3,
            nr::SETXATTRAT | nr::REMOVEXATTRAT | nr::FILE_SETATTR => rule::SNAPSHOT_XATTRAT,
            _ => rule::SNAPSHOT_AIO,
        };
        record(
            writer,
            ts,
            notif,
            syscall_name(sys_nr).unwrap_or("unknown"),
            Fact::Raw {},
            &fixed_decision(Decision::Deny, matched_rule),
        )?;
        tolerate_dead(kernel.send_error(notif.id, libc::ENOSYS))?;
        return Ok(Handled::Responded);
    }

    // metadata calls trapped only in a snapshot run (ADR-0024 decision 4). a filter and flag
    // that disagree deny and record, as the AIO calls do, so one can never pass unrecorded.
    if SNAPSHOT_METADATA.contains(&sys_nr) && !config.snapshot_integrity {
        record(
            writer,
            ts,
            notif,
            syscall_name(sys_nr).unwrap_or("unknown"),
            Fact::Raw {},
            &fixed_decision(Decision::Deny, rule::SNAPSHOT_METADATA),
        )?;
        tolerate_dead(kernel.send_error(notif.id, libc::ENOSYS))?;
        return Ok(Handled::Responded);
    }
    if let Some(name) = fd_metadata_name(sys_nr, notif.data.args[1])
        && SNAPSHOT_METADATA.contains(&sys_nr)
    {
        return handle_fd_metadata(kernel, notif, writer, config, ts, name);
    }

    // the filesystem families (syscalls.md sections 3.1-3.2): the recorded slice.
    if let Some(shape) = fs_shape(sys_nr) {
        return handle_fs(kernel, notif, writer, config, ts, &shape, sys_nr);
    }

    // execve/execveat: recorded with the same bracketed path read (Fact::Exec); the
    // allow is CONTINUE by rule 4 of syscalls.md section 4 in every mode.
    if sys_nr == nr::EXECVE || sys_nr == nr::EXECVEAT {
        return handle_exec(kernel, notif, writer, config, ts, sys_nr);
    }

    if is_process_creation(sys_nr) {
        return handle_process(kernel, notif, writer, config, ts, sys_nr);
    }
    if is_network(sys_nr) {
        return handle_network(kernel, notif, writer, config, ts, sys_nr);
    }
    if is_cross_process(sys_nr) {
        return handle_cross_process(kernel, notif, writer, config, ts, sys_nr);
    }

    tolerate_dead(kernel.send_continue(notif.id))?;
    Ok(Handled::Responded)
}

/// a snapshot-run metadata call that names an open descriptor (`fchmod`, `fchown`,
/// `fsetxattr`, `fremovexattr`, and `futimens` as a null-path `utimensat`). the descriptor's
/// target is read back from `/proc/<pid>/fd/<n>`, judged as a write to that path like
/// `chmod`, and the call continues when allowed: the object is the descriptor's, fixed when
/// the agent opened it, and the only pointer left is a timestamp or value the agent owns.
/// the descriptor is also duplicated with `pidfd_getfd` (the supervisor may, only the agent is
/// denied it), described with `fstatfs` and `fstat`, and the duplicate closed at once: an object
/// on cgroup2, or the state root directory itself, is denied whatever path the link spells.
/// a descriptor on a cgroup2 file cannot be opened (the open is denied), so this is depth.
/// a link or a duplicate that cannot be read denies (case C). what remains is the window
/// between the readlink and the duplicate, in which the agent can `dup2` another object into
/// the slot (escapes.md).
fn handle_fd_metadata<N: Notifier, S: TraceSink>(
    kernel: &N,
    notif: &SeccompNotif,
    writer: &mut TraceWriter<S>,
    config: &RunConfig<'_>,
    ts: u64,
    name: &'static str,
) -> Result<Handled, RunError> {
    if !kernel.id_valid(notif.id).map_err(RunError::Notify)? {
        return Ok(Handled::Dropped);
    }
    let fd = notif.data.args[0] as u32;
    let target = kernel.dir_prefix(notif.pid, DirAnchor::Fd(fd));
    // the descriptor itself, read from a duplicate that is closed before the call returns
    let facts = kernel.describe_fd(notif.pid, fd as RawFd);
    if !kernel.id_valid(notif.id).map_err(RunError::Notify)? {
        return Ok(Handled::Dropped);
    }
    let (Ok(path), Ok(facts)) = (target, facts) else {
        record(
            writer,
            ts,
            notif,
            name,
            Fact::Raw {},
            &fixed_decision(Decision::Deny, rule::MEMORY_READ),
        )?;
        tolerate_dead(kernel.send_error(notif.id, libc::EACCES))?;
        return Ok(Handled::Responded);
    };
    let access = vec![crate::recorder::FsAccess::Write];
    let path_text = path.to_string_lossy();
    // what the descriptor is outranks where its link says it is
    let decision = match fd_identity_deny(config, &facts) {
        Some(eval) => finalize_decision(eval, None),
        None => resolve_decision(
            config,
            &Request::Fs {
                path: &path_text,
                access: &access,
            },
        ),
    };
    let fact = Fact::Fs {
        path: path.clone(),
        access: access.clone(),
        dest: None,
    };
    record(writer, ts, notif, name, fact, &decision)?;
    respond_continue_or_deny(kernel, notif.id, &decision)?;
    Ok(mutation_handled(decision.response_decision, &access))
}

/// gather, record, and respond for one filesystem-family notification.
fn handle_fs<N: Notifier, S: TraceSink>(
    kernel: &N,
    notif: &SeccompNotif,
    writer: &mut TraceWriter<S>,
    config: &RunConfig<'_>,
    ts: u64,
    shape: &FsShape,
    sys_nr: u32,
) -> Result<Handled, RunError> {
    // bracket open (notify-loop.md section 2): a read against a dead or reused id
    // must never become a fact.
    if !kernel.id_valid(notif.id).map_err(RunError::Notify)? {
        return Ok(Handled::Dropped);
    }

    let gathered: Result<
        (
            PathBuf,
            Option<PathBuf>,
            Vec<crate::recorder::FsAccess>,
            FsInvocation,
        ),
        GatherError,
    > = (|| {
        let anchored = read_anchored_parts(
            kernel,
            notif,
            &shape.path,
            empty_path_allowed(sys_nr, notif),
        )?;
        let (path, empty_path) = (anchored.path.clone(), anchored.empty);
        let dest = match &shape.dest {
            Some(arg) => Some(read_anchored(kernel, notif, arg)?),
            None => None,
        };
        let (access, invocation) = match shape.access {
            AccessSpec::Fixed(list) => {
                let invocation = match mutation_invocation(kernel, sys_nr, notif, &path, empty_path)
                {
                    Ok(invocation) => invocation,
                    Err(OperandError::Memory) => return Err(GatherError::Memory),
                    Err(OperandError::Unsupported(errno)) => {
                        return Err(GatherError::Unsupported {
                            errno,
                            path,
                            dest,
                            access: list.to_vec(),
                        });
                    }
                };
                (list.to_vec(), FsInvocation::Mutation(invocation))
            }
            AccessSpec::OpenFlags { arg } => {
                // with O_PATH the kernel ignores every other bit (access mode, O_CREAT,
                // O_TRUNC), so the fact and the realization see only the bits it honors
                let flags = crate::supervisor::fact::effective_open_flags(notif.data.args[arg]);
                (
                    crate::supervisor::fact::open_flags_access(flags),
                    FsInvocation::Open {
                        flags,
                        mode: open_mode(sys_nr, notif),
                        unsupported_errno: None,
                        resolve: ChildResolve::default(),
                    },
                )
            }
            AccessSpec::OpenHow { arg } => {
                let size = usize::try_from(notif.data.args[3]).unwrap_or(0);
                if size < OPEN_HOW_SIZE {
                    return Err(GatherError::Memory);
                }
                let read_size = if config.mode == crate::recorder::Mode::Enforce {
                    size.min(crate::supervisor::mem::ABSOLUTE_READ_CAP)
                } else {
                    OPEN_HOW_SIZE
                };
                let bytes = kernel.read_bytes(notif.pid, notif.data.args[arg], read_size)?;
                let flags = u64::from_ne_bytes(bytes[0..8].try_into().unwrap_or([0; 8]));
                let mode = u64::from_ne_bytes(bytes[8..16].try_into().unwrap_or([0; 8]));
                let resolve = u64::from_ne_bytes(bytes[16..24].try_into().unwrap_or([0; 8]));
                let unsupported_errno = if size > crate::supervisor::mem::ABSOLUTE_READ_CAP
                    || bytes[OPEN_HOW_SIZE..].iter().any(|byte| *byte != 0)
                {
                    Some(libc::E2BIG)
                } else if crate::supervisor::fact::openat2_o_path_invalid(flags) {
                    // openat2(2) refuses O_PATH with a bit O_PATH does not honor, where the
                    // legacy calls ignore it. nothing is opened, so the raw access stands
                    Some(libc::EINVAL)
                } else if resolve & !RESOLVE_VALID != 0
                    || resolve & (RESOLVE_BENEATH | RESOLVE_IN_ROOT)
                        == RESOLVE_BENEATH | RESOLVE_IN_ROOT
                {
                    Some(libc::EINVAL)
                } else if resolve & (RESOLVE_IN_ROOT | RESOLVE_CACHED) != 0 {
                    Some(libc::EOPNOTSUPP)
                } else {
                    None
                };
                (
                    crate::supervisor::fact::open_flags_access(flags),
                    FsInvocation::Open {
                        flags,
                        mode: u32::try_from(mode).unwrap_or(u32::MAX),
                        unsupported_errno,
                        resolve: ChildResolve {
                            bits: resolve & RESOLVE_HONORED,
                            dir: anchored.dir,
                            given: anchored.given,
                        },
                    },
                )
            }
        };
        Ok((path, dest, access, invocation))
    })();

    // bracket close: a read spanning the child's death is discarded (case B).
    if !kernel.id_valid(notif.id).map_err(RunError::Notify)? {
        return Ok(Handled::Dropped);
    }

    match gathered {
        Ok((path, dest, access, invocation)) => {
            #[cfg(not(target_os = "linux"))]
            let _ = &invocation;
            #[cfg(target_os = "linux")]
            if config.mode == crate::recorder::Mode::Enforce {
                return handle_fs_enforce(
                    kernel, notif, writer, config, ts, shape, path, dest, access, invocation,
                );
            }
            let path_text = path.to_string_lossy();
            let decision = resolve_decision(
                config,
                &Request::Fs {
                    path: &path_text,
                    access: &access,
                },
            );
            let fact = Fact::Fs {
                path: path.clone(),
                access: access.clone(),
                dest: dest.clone(),
            };
            record(writer, ts, notif, shape.name, fact, &decision)?;
            respond_continue_or_deny(kernel, notif.id, &decision)?;
            Ok(mutation_handled(decision.response_decision, &access))
        }
        // the call's own arguments are invalid, so the kernel would have refused it with this
        // errno before it looked at any path. it is answered as the kernel would, and
        // recorded under its own rule so it is not mistaken for a failed memory read
        Err(GatherError::Unsupported {
            errno,
            path,
            dest,
            access,
        }) => {
            record_event(
                writer,
                ts,
                notif,
                shape.name,
                Fact::Fs { path, access, dest },
                &fixed_decision(Decision::Deny, rule::UNSUPPORTED_OPERAND),
                None,
                Some(crate::recorder::errno_name(errno)),
            )?;
            tolerate_dead(kernel.send_error(notif.id, errno))?;
            Ok(Handled::Responded)
        }
        // case C: a fact that cannot be trusted cannot be allowed (I4).
        Err(GatherError::Memory) => {
            record(
                writer,
                ts,
                notif,
                shape.name,
                Fact::Raw {},
                &fixed_decision(Decision::Deny, rule::MEMORY_READ),
            )?;
            tolerate_dead(kernel.send_error(notif.id, libc::EACCES))?;
            Ok(Handled::Responded)
        }
    }
}

/// why gathering the operands of a filesystem call failed.
enum GatherError {
    /// agent memory could not be read: case C
    Memory,
    /// the call's own arguments are invalid and the kernel would refuse them with `errno`
    Unsupported {
        errno: i32,
        path: PathBuf,
        dest: Option<PathBuf>,
        access: Vec<crate::recorder::FsAccess>,
    },
}

impl From<MemReadError> for GatherError {
    fn from(_: MemReadError) -> Self {
        Self::Memory
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn handle_fs_enforce<N: Notifier, S: TraceSink>(
    kernel: &N,
    notif: &SeccompNotif,
    writer: &mut TraceWriter<S>,
    config: &RunConfig<'_>,
    ts: u64,
    shape: &FsShape,
    lexical_path: PathBuf,
    lexical_dest: Option<PathBuf>,
    access: Vec<crate::recorder::FsAccess>,
    invocation: FsInvocation,
) -> Result<Handled, RunError> {
    let broker = config.broker.ok_or(RunError::MissingBroker)?;
    let symlink_target = matches!(
        invocation,
        FsInvocation::Mutation(MutationInvocation::Symlink { .. })
    );
    let (primary_input, secondary_input) = if symlink_target {
        (
            lexical_dest
                .as_ref()
                .ok_or_else(|| RunError::Notify(io::Error::from_raw_os_error(libc::EINVAL)))?,
            None,
        )
    } else {
        (&lexical_path, lexical_dest.as_ref())
    };
    let (primary_follow, primary_missing, secondary_follow, secondary_missing) =
        path_prepare_modes(&invocation);

    let primary =
        match broker
            .borrow_mut()
            .prepare_path(primary_input, primary_follow, primary_missing)?
        {
            BrokerResultOrPath::Path(path) => path,
            BrokerResultOrPath::Result(BrokerResult::Errno(errno)) => {
                return record_realization_deny(
                    kernel,
                    notif,
                    writer,
                    ts,
                    shape.name,
                    lexical_path,
                    lexical_dest,
                    access,
                    errno,
                );
            }
            BrokerResultOrPath::Result(_) => {
                return Err(RunError::Notify(io::Error::other(
                    "broker prepare returned a non-errno result",
                )));
            }
        };
    let secondary = if let Some(input) = secondary_input {
        // bind the result first: a `borrow_mut()` temporary in the match scrutinee would
        // live through the arms, and the arms release the primary through the same cell
        let prepared =
            broker
                .borrow_mut()
                .prepare_path(input, secondary_follow, secondary_missing)?;
        match prepared {
            BrokerResultOrPath::Path(path) => Some(path),
            BrokerResultOrPath::Result(BrokerResult::Errno(errno)) => {
                broker.borrow_mut().release(primary)?;
                return record_realization_deny(
                    kernel,
                    notif,
                    writer,
                    ts,
                    shape.name,
                    lexical_path,
                    lexical_dest,
                    access,
                    errno,
                );
            }
            BrokerResultOrPath::Result(_) => {
                broker.borrow_mut().release(primary)?;
                return Err(RunError::Notify(io::Error::other(
                    "broker prepare returned a non-errno result",
                )));
            }
        }
    } else {
        None
    };

    let primary_identity = primary.identity().to_path_buf();
    let secondary_identity = secondary.as_ref().map(|path| path.identity().to_path_buf());
    let (fact_path, fact_dest) = if symlink_target {
        (lexical_path.clone(), Some(primary_identity.clone()))
    } else {
        (primary_identity.clone(), secondary_identity.clone())
    };
    let primary_access = primary_access(&invocation, &access);
    let primary_operand = if symlink_target {
        FsOperand::Dest
    } else {
        FsOperand::Path
    };
    let mut asks = Vec::new();
    let primary_evals = evaluate_required_fs(
        config,
        &primary_identity,
        primary.on_cgroup2(),
        &primary_access,
        false,
        &mut asks,
    );
    let secondary_evals = secondary.as_ref().map(|path| {
        let required = secondary_access(&invocation, path.exists());
        evaluate_required_fs(
            config,
            path.identity(),
            path.on_cgroup2(),
            &required,
            true,
            &mut asks,
        )
    });
    let ask_resolution = settle_asks(config, &asks);
    let primary_decision = finalize_operand(primary_operand, primary_evals, ask_resolution);
    let secondary_decision =
        secondary_evals.map(|evals| finalize_operand(FsOperand::Dest, evals, ask_resolution));
    let operand_decisions = if symlink_target {
        Some(primary_decision.evidence.clone())
    } else {
        secondary_decision.as_ref().map(|secondary| {
            primary_decision
                .evidence
                .iter()
                .chain(&secondary.evidence)
                .cloned()
                .collect()
        })
    };
    let decision = if primary_decision.effective.response_decision != Decision::Allow {
        primary_decision.effective.clone()
    } else if let Some(decision) = secondary_decision
        && decision.effective.response_decision != Decision::Allow
    {
        decision.effective
    } else {
        primary_decision.effective
    };

    let realized_path = fact_path.clone();
    let realized_dest = fact_dest.clone();
    record_with_operands(
        writer,
        ts,
        notif,
        shape.name,
        Fact::Fs {
            path: fact_path,
            access: access.clone(),
            dest: fact_dest,
        },
        &decision,
        operand_decisions,
    )?;

    if decision.response_decision != Decision::Allow {
        broker.borrow_mut().release(primary)?;
        if let Some(secondary) = secondary {
            broker.borrow_mut().release(secondary)?;
        }
        tolerate_dead(kernel.send_error(notif.id, libc::EACCES))?;
        return Ok(Handled::Responded);
    }

    if !kernel.id_valid(notif.id).map_err(RunError::Notify)? {
        broker.borrow_mut().release(primary)?;
        if let Some(secondary) = secondary {
            broker.borrow_mut().release(secondary)?;
        }
        return Ok(Handled::Dropped);
    }

    let close_on_exec = match &invocation {
        FsInvocation::Open { flags, .. } if flags & libc::O_CLOEXEC as u64 != 0 => {
            libc::O_CLOEXEC as u32
        }
        _ => 0,
    };
    // set only when the broker realized an O_PATH open, so an errno the supervisor chose
    // for an unsupported openat2 request is never mistaken for the substitute's refusal
    let mut o_path = false;
    let mut resolve_refused = false;
    let result = match invocation {
        FsInvocation::Open {
            flags,
            mode,
            unsupported_errno,
            resolve,
        } => {
            if let Some(errno) = unsupported_errno {
                broker.borrow_mut().release(primary)?;
                BrokerResult::Errno(errno)
            } else if let Some(errno) = child_resolve_refusal(&resolve, flags) {
                broker.borrow_mut().release(primary)?;
                resolve_refused = true;
                BrokerResult::Errno(errno)
            } else {
                o_path = flags & crate::supervisor::fact::flags::O_PATH != 0;
                broker.borrow_mut().commit_open(primary, flags, mode)?
            }
        }
        FsInvocation::Mutation(operation) => {
            let operation = broker_mutation(operation);
            broker
                .borrow_mut()
                .commit_mutation(primary, secondary, operation)?
        }
    };
    deliver_realization(
        kernel,
        notif,
        writer,
        ts,
        shape.name,
        Fact::Fs {
            path: realized_path,
            access: access.clone(),
            dest: realized_dest,
        },
        &access,
        result,
        Realization {
            o_path,
            resolve_refused,
            newfd_flags: close_on_exec,
        },
    )
}

/// the errno an `openat2` caller's own `resolve` restrictions give the path it spelled, or
/// `None` when they allow it (or there are none).
///
/// the restrictions only narrow how the caller's spelling may resolve, so the object opened is
/// still the one the policy judged, pinned by the broker. they are checked by resolving the
/// spelling once more, without opening anything, from the directory it starts from with the
/// caller's own bits. only the answers the restrictions themselves cause are returned,
/// `EXDEV` and `ELOOP`; any other failure is left to the real open, which answers it. a
/// spelling that cannot be checked at all is refused `EOPNOTSUPP`, as every `resolve` was
/// before they were honored.
#[cfg(target_os = "linux")]
fn child_resolve_refusal(check: &ChildResolve, flags: u64) -> Option<i32> {
    use std::ffi::CString;
    if check.bits == 0 {
        return None;
    }
    let base_dir = if check.given.is_absolute() {
        std::path::Path::new("/")
    } else if let Some(dir) = check.dir.as_deref() {
        dir
    } else {
        return Some(libc::EOPNOTSUPP);
    };
    let Ok(base_path) = CString::new(base_dir.as_os_str().as_bytes()) else {
        return Some(libc::EOPNOTSUPP);
    };
    // SAFETY: base_path is a nul-terminated path and the flags are a fixed valid set.
    let base_fd = unsafe {
        libc::open(
            base_path.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if base_fd < 0 {
        return Some(libc::EOPNOTSUPP);
    }
    // SAFETY: base_fd was just returned by open and nothing else owns it.
    let base = unsafe { OwnedFd::from_raw_fd(base_fd) };
    let probe = |spelling: &std::path::Path, extra: i32| -> Result<(), i32> {
        let Ok(spelling) = CString::new(spelling.as_os_str().as_bytes()) else {
            return Ok(());
        };
        crate::supervisor::broker::openat2(
            base.as_raw_fd(),
            &spelling,
            u64::try_from(libc::O_PATH | libc::O_CLOEXEC | extra).unwrap_or_default(),
            0,
            check.bits,
        )
        .map(drop)
        .map_err(|error| error.raw_os_error().unwrap_or(0))
    };
    let honored =
        i32::try_from(flags & (libc::O_NOFOLLOW | libc::O_DIRECTORY) as u64).unwrap_or_default();
    let refusal = |errno: i32| matches!(errno, libc::EXDEV | libc::ELOOP).then_some(errno);
    match probe(&check.given, honored) {
        Ok(()) => None,
        // a create names something that does not exist yet: its directory is what resolves
        Err(libc::ENOENT) if flags & libc::O_CREAT as u64 != 0 => {
            let parent = match check.given.parent() {
                Some(parent) if parent.as_os_str().is_empty() => std::path::Path::new("."),
                Some(parent) => parent,
                None => return None,
            };
            probe(parent, libc::O_DIRECTORY).err().and_then(refusal)
        }
        Err(errno) => refusal(errno),
    }
}

#[cfg(not(target_os = "linux"))]
fn child_resolve_refusal(_check: &ChildResolve, _flags: u64) -> Option<i32> {
    None
}

/// how an allowed filesystem syscall's broker result is to be delivered.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
struct Realization {
    /// the open was `O_PATH`, so a broker EOPNOTSUPP (the substitute refuses the object's
    /// kind) or EACCES (the file mode refuses its read-only reopen) is a realization
    /// failure, not an answer the kernel would have given
    o_path: bool,
    /// the caller's own `openat2` `resolve` restrictions refuse the path it spelled, which
    /// the allow already recorded did not take into account
    resolve_refused: bool,
    /// the `newfd_flags` an injected descriptor is installed with
    newfd_flags: u32,
}

/// deliver the broker's realization of an allowed filesystem syscall whose allow event is
/// already in the trace. when the allow cannot be realized after all (the kernel refuses
/// the ADDFD, or the O_PATH substitute refuses the object's kind or cannot reopen it for
/// reading), the failure is recorded as a second event under `failsafe:realization` with
/// the errno, and only then answered: record precedes respond for this event too
/// (notify-loop.md section 3). a failed write of that event returns with nothing sent
/// here; the loop then treats it as case E, sends a best-effort EIO, and aborts the run. a
/// create or truncate the broker committed before the ADDFD stays on disk, so the step
/// clock is classified from the allow alone.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn deliver_realization<N: Notifier, S: TraceSink>(
    kernel: &N,
    notif: &SeccompNotif,
    writer: &mut TraceWriter<S>,
    ts: u64,
    syscall: &str,
    fact: Fact,
    access: &[crate::recorder::FsAccess],
    result: BrokerResult,
    realization: Realization,
) -> Result<Handled, RunError> {
    let delivery = match result {
        // the substitute refuses the object's kind, or its read-only reopen is refused by the
        // file mode where the O_PATH open itself needs no read permission
        BrokerResult::Errno(errno @ (libc::EOPNOTSUPP | libc::EACCES)) if realization.o_path => {
            Delivery::Refused { errno }
        }
        BrokerResult::Errno(errno) if realization.resolve_refused => Delivery::Refused { errno },
        result => respond_broker_result(kernel, notif.id, result, realization.newfd_flags)?,
    };
    if let Delivery::Refused { errno } = delivery {
        record_event(
            writer,
            ts,
            notif,
            syscall,
            fact,
            &fixed_decision(Decision::Deny, rule::REALIZATION),
            None,
            Some(crate::recorder::errno_name(errno)),
        )?;
        tolerate_dead(kernel.send_error(notif.id, errno))?;
    }
    Ok(mutation_handled(Decision::Allow, access))
}

/// classify one handled filesystem action for the step clock (snapshot.md section 1):
/// mutating means the response let it proceed and the access writes, creates, or
/// deletes. reads and denials never tick the clock.
fn mutation_handled(response: Decision, access: &[crate::recorder::FsAccess]) -> Handled {
    let writes = access.iter().any(|a| *a != crate::recorder::FsAccess::Read);
    if response == Decision::Allow && writes {
        Handled::RespondedMutation
    } else {
        Handled::Responded
    }
}

#[cfg(target_os = "linux")]
fn path_prepare_modes(invocation: &FsInvocation) -> (bool, bool, bool, bool) {
    match invocation {
        FsInvocation::Open { flags, .. } => (
            flags & libc::O_NOFOLLOW as u64 == 0,
            flags & libc::O_CREAT as u64 != 0,
            false,
            false,
        ),
        FsInvocation::Mutation(MutationInvocation::Truncate { .. })
        | FsInvocation::Mutation(MutationInvocation::Chmod { .. })
        | FsInvocation::Mutation(MutationInvocation::Chown { flags: 0, .. }) => {
            (true, false, false, false)
        }
        FsInvocation::Mutation(MutationInvocation::Chown { .. })
        | FsInvocation::Mutation(MutationInvocation::ChmodNoFollow { .. }) => {
            (false, false, false, false)
        }
        FsInvocation::Mutation(
            MutationInvocation::Setxattr { follow, .. }
            | MutationInvocation::Removexattr { follow, .. },
        ) => (*follow, false, false, false),
        FsInvocation::Mutation(MutationInvocation::Utimens { flags, .. }) => {
            (flags & AT_SYMLINK_NOFOLLOW == 0, false, false, false)
        }
        FsInvocation::Mutation(MutationInvocation::Rename { .. }) => (false, false, false, true),
        FsInvocation::Mutation(MutationInvocation::Mkdir { .. }) => (false, true, false, false),
        FsInvocation::Mutation(MutationInvocation::Unlink { .. }) => (false, false, false, false),
        FsInvocation::Mutation(MutationInvocation::Link { flags }) => {
            (*flags & libc::AT_SYMLINK_FOLLOW != 0, false, false, true)
        }
        FsInvocation::Mutation(MutationInvocation::Symlink { .. }) => (false, true, false, false),
    }
}

#[cfg(target_os = "linux")]
fn primary_access(
    invocation: &FsInvocation,
    open_access: &[crate::recorder::FsAccess],
) -> Vec<crate::recorder::FsAccess> {
    use crate::recorder::FsAccess::{Create, Delete, Read, Write};
    match invocation {
        FsInvocation::Open { .. } => open_access.to_vec(),
        FsInvocation::Mutation(MutationInvocation::Rename { flags }) if *flags & 2 != 0 => {
            vec![Delete, Create]
        }
        FsInvocation::Mutation(MutationInvocation::Rename { .. }) => vec![Delete],
        FsInvocation::Mutation(MutationInvocation::Link { .. }) => vec![Read],
        FsInvocation::Mutation(MutationInvocation::Mkdir { .. })
        | FsInvocation::Mutation(MutationInvocation::Symlink { .. }) => vec![Create],
        FsInvocation::Mutation(MutationInvocation::Unlink { .. }) => vec![Delete],
        FsInvocation::Mutation(
            MutationInvocation::Truncate { .. }
            | MutationInvocation::Chmod { .. }
            | MutationInvocation::Chown { .. }
            | MutationInvocation::ChmodNoFollow { .. }
            | MutationInvocation::Setxattr { .. }
            | MutationInvocation::Removexattr { .. }
            | MutationInvocation::Utimens { .. },
        ) => vec![Write],
    }
}

#[cfg(target_os = "linux")]
fn secondary_access(
    invocation: &FsInvocation,
    destination_exists: bool,
) -> Vec<crate::recorder::FsAccess> {
    use crate::recorder::FsAccess::{Create, Delete};
    match invocation {
        FsInvocation::Mutation(MutationInvocation::Rename { flags }) if *flags & 2 != 0 => {
            vec![Delete, Create]
        }
        FsInvocation::Mutation(MutationInvocation::Rename { .. }) if destination_exists => {
            vec![Create, Delete]
        }
        FsInvocation::Mutation(
            MutationInvocation::Rename { .. } | MutationInvocation::Link { .. },
        ) => vec![Create],
        _ => Vec::new(),
    }
}

/// the implicit cgroup deny decided on what the pinned handle is, not where its path says it
/// is (ADR-0024 decision 4): an object on a cgroup2 filesystem is denied for every access,
/// whatever its spelling, so a bind mount of a cgroup directory and a cgroup2 mount made
/// after the mounts were read are covered. the path rule stays for the ancestors of a mount,
/// which are on another filesystem and which only it can protect.
fn cgroup2_identity_deny(config: &RunConfig<'_>, on_cgroup2: bool) -> Option<Evaluation> {
    (on_cgroup2
        && config.mode == crate::recorder::Mode::Enforce
        && config.snapshot_integrity
        && config.state_root.is_some())
    .then_some(Evaluation {
        decision: Decision::Deny,
        matched: crate::policy::MatchId::ImplicitCgroup,
        would_deny: None,
    })
}

#[cfg(target_os = "linux")]
fn evaluate_required_fs(
    config: &RunConfig<'_>,
    path: &std::path::Path,
    on_cgroup2: bool,
    access: &[crate::recorder::FsAccess],
    destination: bool,
    asks: &mut Vec<ask::PendingAsk>,
) -> Vec<(crate::recorder::FsAccess, Evaluation)> {
    let path_text = path.to_string_lossy();
    access
        .iter()
        .map(|required| {
            if let Some(eval) = cgroup2_identity_deny(config, on_cgroup2) {
                return (*required, eval);
            }
            let eval = evaluate_operand(
                config,
                &Request::Fs {
                    path: &path_text,
                    access: std::slice::from_ref(required),
                },
                destination,
                asks,
            );
            (*required, eval)
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn finalize_operand(
    operand: FsOperand,
    evals: Vec<(crate::recorder::FsAccess, Evaluation)>,
    resolution: Option<AskResolution>,
) -> ResolvedOperand {
    let mut first_allow = None;
    let mut first_deny = None;
    let mut evidence = Vec::with_capacity(evals.len());
    for (required, eval) in evals {
        let decision = finalize_decision(eval, resolution);
        evidence.push(FsOperandDecision {
            operand,
            access: required,
            decision: decision.event_decision,
            ask_resolution: decision.ask_resolution,
            matched_rule: decision.matched_rule.clone(),
        });
        if decision.response_decision != Decision::Allow && first_deny.is_none() {
            first_deny = Some(decision.clone());
        }
        if first_allow.is_none() {
            first_allow = Some(decision);
        }
    }
    ResolvedOperand {
        effective: first_deny
            .or(first_allow)
            .unwrap_or_else(|| fixed_decision(Decision::Deny, rule::REALIZATION)),
        evidence,
    }
}

#[cfg(target_os = "linux")]
fn broker_mutation(invocation: MutationInvocation) -> MutationOperation {
    match invocation {
        MutationInvocation::Truncate { length } => MutationOperation::Truncate { length },
        MutationInvocation::Rename { flags } => MutationOperation::Rename { flags },
        MutationInvocation::Mkdir { mode } => MutationOperation::Mkdir { mode },
        MutationInvocation::Unlink { flags } => MutationOperation::Unlink { flags },
        MutationInvocation::Link { flags } => MutationOperation::Link { flags },
        MutationInvocation::Symlink { target } => MutationOperation::Symlink { target },
        MutationInvocation::Chmod { mode } => MutationOperation::Chmod { mode },
        MutationInvocation::Chown { uid, gid, flags } => {
            MutationOperation::Chown { uid, gid, flags }
        }
        MutationInvocation::ChmodNoFollow { mode } => MutationOperation::ChmodNoFollow { mode },
        MutationInvocation::Setxattr {
            name,
            value,
            flags,
            follow,
        } => MutationOperation::Setxattr {
            name,
            value,
            flags,
            follow,
        },
        MutationInvocation::Removexattr { name, follow } => {
            MutationOperation::Removexattr { name, follow }
        }
        MutationInvocation::Utimens { times, flags } => MutationOperation::Utimens { times, flags },
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn record_realization_deny<N: Notifier, S: TraceSink>(
    kernel: &N,
    notif: &SeccompNotif,
    writer: &mut TraceWriter<S>,
    ts: u64,
    syscall: &str,
    path: PathBuf,
    dest: Option<PathBuf>,
    access: Vec<crate::recorder::FsAccess>,
    errno: i32,
) -> Result<Handled, RunError> {
    record_event(
        writer,
        ts,
        notif,
        syscall,
        Fact::Fs { path, access, dest },
        &fixed_decision(Decision::Deny, rule::REALIZATION),
        None,
        Some(crate::recorder::errno_name(errno)),
    )?;
    tolerate_dead(kernel.send_error(notif.id, errno))?;
    Ok(Handled::Responded)
}

/// whether a broker result reached the agent.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
enum Delivery {
    /// the result was sent, or the agent is gone and nothing is owed
    Delivered,
    /// the kernel refused to install the descriptor. nothing has been sent: the
    /// notification is still pending, and the caller records the failure and then answers
    /// it with this errno
    Refused { errno: i32 },
}

/// answer a trapped syscall with the broker's result. a descriptor the kernel refuses to
/// install (`ADDFD|SEND` fails, which leaves the notification pending) is reported as
/// `Refused` with the errno the agent is to receive: its own limits (`EMFILE`, `ENFILE`,
/// `ENOMEM`) as they are, anything else as EIO. only a failure of the notify fd on a send
/// is an error.
#[cfg(target_os = "linux")]
fn respond_broker_result<N: Notifier>(
    kernel: &N,
    id: u64,
    result: BrokerResult,
    newfd_flags: u32,
) -> Result<Delivery, RunError> {
    match result {
        BrokerResult::Value(value) => {
            tolerate_dead(kernel.send_success(id, value)).map(|()| Delivery::Delivered)
        }
        BrokerResult::Fd(fd) => {
            match kernel.send_addfd(id, fd.as_fd(), SECCOMP_ADDFD_FLAG_SEND, newfd_flags) {
                Ok(_) => Ok(Delivery::Delivered),
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(Delivery::Delivered),
                Err(error) => Ok(Delivery::Refused {
                    errno: match error.raw_os_error() {
                        Some(errno @ (libc::EMFILE | libc::ENFILE | libc::ENOMEM)) => errno,
                        _ => libc::EIO,
                    },
                }),
            }
        }
        BrokerResult::Errno(errno) => {
            tolerate_dead(kernel.send_error(id, errno)).map(|()| Delivery::Delivered)
        }
    }
}

/// gather, record, and respond for execve/execveat.
fn handle_exec<N: Notifier, S: TraceSink>(
    kernel: &N,
    notif: &SeccompNotif,
    writer: &mut TraceWriter<S>,
    config: &RunConfig<'_>,
    ts: u64,
    sys_nr: u32,
) -> Result<Handled, RunError> {
    let (name, arg) = if sys_nr == nr::EXECVE {
        (
            "execve",
            PathArg {
                path_arg: 0,
                dirfd_arg: None,
                anchor: true,
            },
        )
    } else {
        (
            "execveat",
            PathArg {
                path_arg: 1,
                dirfd_arg: Some(0),
                anchor: true,
            },
        )
    };

    if !kernel.id_valid(notif.id).map_err(RunError::Notify)? {
        return Ok(Handled::Dropped);
    }
    let gathered = read_anchored(kernel, notif, &arg);
    if !kernel.id_valid(notif.id).map_err(RunError::Notify)? {
        return Ok(Handled::Dropped);
    }

    match gathered {
        Ok(binary) => {
            let binary_text = binary.to_string_lossy();
            let decision = resolve_decision(
                config,
                &Request::Exec {
                    binary: &binary_text,
                },
            );
            record(writer, ts, notif, name, Fact::Exec { binary }, &decision)?;
            respond_continue_or_deny(kernel, notif.id, &decision)?;
            Ok(Handled::Responded)
        }
        Err(_) => {
            record(
                writer,
                ts,
                notif,
                name,
                Fact::Raw {},
                &fixed_decision(Decision::Deny, rule::MEMORY_READ),
            )?;
            tolerate_dead(kernel.send_error(notif.id, libc::EACCES))?;
            Ok(Handled::Responded)
        }
    }
}

fn handle_process<N: Notifier, S: TraceSink>(
    kernel: &N,
    notif: &SeccompNotif,
    writer: &mut TraceWriter<S>,
    config: &RunConfig<'_>,
    ts: u64,
    sys_nr: u32,
) -> Result<Handled, RunError> {
    let name = syscall_name(sys_nr).unwrap_or("unknown");
    let flags = if sys_nr == nr::CLONE {
        Some(notif.data.args[0])
    } else if sys_nr == nr::CLONE3 {
        let size = notif.data.args[1];
        if !(CLONE_ARGS_MIN_SIZE..=CLONE_ARGS_MAX_SIZE).contains(&size) {
            record(
                writer,
                ts,
                notif,
                name,
                Fact::Raw {},
                &fixed_decision(Decision::Deny, rule::MEMORY_READ),
            )?;
            tolerate_dead(kernel.send_error(notif.id, libc::EACCES))?;
            return Ok(Handled::Responded);
        }
        if !kernel.id_valid(notif.id).map_err(RunError::Notify)? {
            return Ok(Handled::Dropped);
        }
        let read = kernel.read_u64(notif.pid, notif.data.args[0]);
        if !kernel.id_valid(notif.id).map_err(RunError::Notify)? {
            return Ok(Handled::Dropped);
        }
        match read {
            Ok(flags) => Some(flags),
            Err(_) => {
                record(
                    writer,
                    ts,
                    notif,
                    name,
                    Fact::Raw {},
                    &fixed_decision(Decision::Deny, rule::MEMORY_READ),
                )?;
                tolerate_dead(kernel.send_error(notif.id, libc::EACCES))?;
                return Ok(Handled::Responded);
            }
        }
    } else {
        None
    };

    record(
        writer,
        ts,
        notif,
        name,
        Fact::Process { flags },
        &fixed_decision(
            Decision::Allow,
            if config.mode == crate::recorder::Mode::RecordOnly {
                rule::RECORD_ONLY
            } else {
                rule::PROCESS_CREATION
            },
        ),
    )?;
    tolerate_dead(kernel.send_continue(notif.id))?;
    Ok(Handled::Responded)
}

fn handle_cross_process<N: Notifier, S: TraceSink>(
    kernel: &N,
    notif: &SeccompNotif,
    writer: &mut TraceWriter<S>,
    config: &RunConfig<'_>,
    ts: u64,
    sys_nr: u32,
) -> Result<Handled, RunError> {
    let name = syscall_name(sys_nr).unwrap_or("unknown");
    let target_pid = match sys_nr {
        nr::PTRACE => notif.data.args[1] as u32,
        nr::PROCESS_VM_READV | nr::PROCESS_VM_WRITEV => notif.data.args[0] as u32,
        _ => 0,
    };
    let in_tree = target_pid == 0
        || target_pid == notif.pid
        || kernel
            .process_in_tree(config.root_pid, target_pid)
            .unwrap_or(false);
    let decision = if config.mode == crate::recorder::Mode::RecordOnly {
        fixed_decision(Decision::Allow, rule::RECORD_ONLY)
    } else if in_tree {
        fixed_decision(Decision::Allow, rule::PROCESS_TREE)
    } else {
        fixed_decision(Decision::Deny, rule::PROCESS_TREE_DENY)
    };
    record(
        writer,
        ts,
        notif,
        name,
        Fact::CrossProcess { target_pid },
        &decision,
    )?;
    respond_continue_or_deny(kernel, notif.id, &decision)?;
    Ok(Handled::Responded)
}

fn handle_network<N: Notifier, S: TraceSink>(
    kernel: &N,
    notif: &SeccompNotif,
    writer: &mut TraceWriter<S>,
    config: &RunConfig<'_>,
    ts: u64,
    sys_nr: u32,
) -> Result<Handled, RunError> {
    let name = syscall_name(sys_nr).unwrap_or("unknown");
    let (addr_arg, len_arg) = match sys_nr {
        nr::CONNECT | nr::BIND => (1, 2),
        nr::SENDTO => {
            if notif.data.args[4] == 0 {
                tolerate_dead(kernel.send_continue(notif.id))?;
                return Ok(Handled::Responded);
            }
            (4, 5)
        }
        _ => unreachable!("network table checked before call"),
    };
    let len = match usize::try_from(notif.data.args[len_arg]) {
        Ok(len) if len <= 128 => len,
        _ => {
            record_network_read_failure(kernel, notif, writer, config, ts, name)?;
            return Ok(Handled::Responded);
        }
    };

    if !kernel.id_valid(notif.id).map_err(RunError::Notify)? {
        return Ok(Handled::Dropped);
    }
    let sockaddr = kernel.read_bytes(notif.pid, notif.data.args[addr_arg], len);
    let payload = if sys_nr == nr::SENDTO && config.mode == crate::recorder::Mode::Enforce {
        match usize::try_from(notif.data.args[2]) {
            Ok(length) if length <= crate::supervisor::mem::NETWORK_PAYLOAD_CAP => {
                kernel.read_bytes(notif.pid, notif.data.args[1], length)
            }
            _ => Err(MemReadError::NoNulWithinCap(
                crate::supervisor::mem::NETWORK_PAYLOAD_CAP,
            )),
        }
    } else {
        Ok(Vec::new())
    };
    if !kernel.id_valid(notif.id).map_err(RunError::Notify)? {
        return Ok(Handled::Dropped);
    }
    let sockaddr = match sockaddr {
        Ok(sockaddr) => sockaddr,
        Err(_) => {
            record_network_read_failure(kernel, notif, writer, config, ts, name)?;
            return Ok(Handled::Responded);
        }
    };
    let payload = match payload {
        Ok(payload) => payload,
        Err(_) => {
            record_network_read_failure(kernel, notif, writer, config, ts, name)?;
            return Ok(Handled::Responded);
        }
    };
    #[cfg(not(target_os = "linux"))]
    let _ = &payload;
    let (ip, port) = match parse_sockaddr(sockaddr.clone()) {
        Ok(dest) => dest,
        Err(_) => {
            record_network_read_failure(kernel, notif, writer, config, ts, name)?;
            return Ok(Handled::Responded);
        }
    };
    let host = ip.to_string();
    let hostname = resolved_hostname(config, ip);
    let decision = resolve_decision(
        config,
        &Request::Net {
            ip,
            hostname: hostname.as_deref(),
            port,
        },
    );
    record(writer, ts, notif, name, Fact::Net { host, port }, &decision)?;
    if config.mode == crate::recorder::Mode::RecordOnly {
        respond_continue_or_deny(kernel, notif.id, &decision)?;
        return Ok(Handled::Responded);
    }
    if decision.response_decision != Decision::Allow {
        tolerate_dead(kernel.send_error(notif.id, libc::EACCES))?;
        return Ok(Handled::Responded);
    }

    #[cfg(target_os = "linux")]
    {
        if !kernel.id_valid(notif.id).map_err(RunError::Notify)? {
            return Ok(Handled::Dropped);
        }
        let target_fd = RawFd::try_from(notif.data.args[0])
            .map_err(|_| RunError::Notify(io::Error::from_raw_os_error(libc::EBADF)))?;
        let socket = match kernel.duplicate_fd(notif.pid, target_fd) {
            Ok(socket) => socket,
            Err(error) => {
                tolerate_dead(
                    kernel.send_error(notif.id, error.raw_os_error().unwrap_or(libc::EBADF)),
                )?;
                return Ok(Handled::Responded);
            }
        };
        let operation = match sys_nr {
            nr::CONNECT => NetworkOperation::Connect,
            nr::BIND => NetworkOperation::Bind,
            nr::SENDTO => NetworkOperation::SendTo,
            _ => unreachable!("network table checked above"),
        };
        let flags = if sys_nr == nr::SENDTO {
            notif.data.args[3] as i32
        } else {
            0
        };
        let result = config
            .broker
            .ok_or(RunError::MissingBroker)?
            .borrow_mut()
            .network(operation, socket, sockaddr, payload, flags)?;
        // a network operation returns no descriptor, so nothing here can be refused; a
        // refusal would still owe the agent an answer, and an errno never releases an action
        if let Delivery::Refused { errno } = respond_broker_result(kernel, notif.id, result, 0)? {
            tolerate_dead(kernel.send_error(notif.id, errno))?;
        }
    }
    Ok(Handled::Responded)
}

fn resolved_hostname(config: &RunConfig<'_>, ip: IpAddr) -> Option<String> {
    let policy = config.policy?;
    let cache = config.resolved_hosts?;
    for rule in &policy.net {
        if let crate::policy::HostRule::Exact(host) = &rule.host
            && cache
                .get(host)
                .is_some_and(|addresses| addresses.contains(&ip))
        {
            return Some(host.clone());
        }
    }
    None
}

fn record_network_read_failure<N: Notifier, S: TraceSink>(
    kernel: &N,
    notif: &SeccompNotif,
    writer: &mut TraceWriter<S>,
    config: &RunConfig<'_>,
    ts: u64,
    name: &str,
) -> Result<(), RunError> {
    let decision = if config.mode == crate::recorder::Mode::RecordOnly {
        fixed_decision(Decision::Allow, rule::RECORD_ONLY)
    } else {
        fixed_decision(Decision::Deny, rule::MEMORY_READ)
    };
    record(writer, ts, notif, name, Fact::Raw {}, &decision)?;
    respond_continue_or_deny(kernel, notif.id, &decision)
}

fn respond_continue_or_deny<N: Notifier>(
    kernel: &N,
    id: u64,
    decision: &ResolvedDecision,
) -> Result<(), RunError> {
    match decision.response_decision {
        Decision::Allow => tolerate_dead(kernel.send_continue(id)),
        Decision::Deny | Decision::Ask => tolerate_dead(kernel.send_error(id, libc::EACCES)),
    }
}

fn parse_sockaddr(bytes: Vec<u8>) -> Result<(IpAddr, u16), MemReadError> {
    if bytes.len() < 2 {
        return Err(MemReadError::Short {
            wanted: 2,
            got: bytes.len(),
        });
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as i32;
    match family {
        libc::AF_INET => {
            if bytes.len() < 8 {
                return Err(MemReadError::Short {
                    wanted: 8,
                    got: bytes.len(),
                });
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            Ok((IpAddr::V4(ip), port))
        }
        libc::AF_INET6 => {
            if bytes.len() < 28 {
                return Err(MemReadError::Short {
                    wanted: 28,
                    got: bytes.len(),
                });
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&bytes[8..24]);
            let ip = Ipv6Addr::from(addr);
            Ok((ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4), port))
        }
        _ => Err(MemReadError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported sockaddr family",
        ))),
    }
}

fn is_process_creation(sys_nr: u32) -> bool {
    matches!(sys_nr, nr::CLONE | nr::FORK | nr::VFORK | nr::CLONE3)
}

fn is_network(sys_nr: u32) -> bool {
    matches!(sys_nr, nr::CONNECT | nr::SENDTO | nr::BIND)
}

fn is_cross_process(sys_nr: u32) -> bool {
    matches!(
        sys_nr,
        nr::PTRACE | nr::PROCESS_VM_READV | nr::PROCESS_VM_WRITEV
    )
}

/// read one path argument and anchor it per the record-only resolution rule
/// (trace.md section 2): absolute values stand, relative values are prefixed with the
/// kernel-trusted /proc cwd or fd link; a symlink target is recorded verbatim.
///
/// the two failures here are not the same class. a failed read of the path pointer is
/// untrusted child memory (case C): the fact cannot be built, so the caller denies. a
/// failed read of the /proc anchor is a supervisor-side fidelity gap, not child memory;
/// under ADR-0010 record-only enforces nothing, so it must not deny. the path is recorded
/// as the child gave it, relative, rather than guessing an anchor (the child may have
/// chdir'd, which is pass-through and unobserved, so the supervisor's own cwd could be
/// wrong) or refusing the syscall.
fn read_anchored<N: Notifier>(
    kernel: &N,
    notif: &SeccompNotif,
    arg: &PathArg,
) -> Result<PathBuf, MemReadError> {
    read_anchored_with(kernel, notif, arg, false).map(|(path, _)| path)
}

/// read and anchor one path operand. when `allow_empty` is set and the path is empty, the
/// result is the anchor itself, with no trailing separator, and the flag is true: the call
/// (`AT_EMPTY_PATH`) acts on the object the descriptor holds. an empty path without
/// `allow_empty` is the kernel's ENOENT and keeps its old reading.
fn read_anchored_with<N: Notifier>(
    kernel: &N,
    notif: &SeccompNotif,
    arg: &PathArg,
    allow_empty: bool,
) -> Result<(PathBuf, bool), MemReadError> {
    read_anchored_parts(kernel, notif, arg, allow_empty)
        .map(|anchored| (anchored.path, anchored.empty))
}

/// a path operand as anchored, with the parts it was built from.
struct Anchored {
    /// the operand the policy judges
    path: PathBuf,
    /// the path was empty and `path` is the anchor itself
    empty: bool,
    /// the directory a relative spelling starts from, when it was read
    dir: Option<PathBuf>,
    /// the spelling the caller gave
    given: PathBuf,
}

fn read_anchored_parts<N: Notifier>(
    kernel: &N,
    notif: &SeccompNotif,
    arg: &PathArg,
    allow_empty: bool,
) -> Result<Anchored, MemReadError> {
    let bytes = kernel.read_path(notif.pid, notif.data.args[arg.path_arg])?;
    let empty = allow_empty && bytes.is_empty();
    let given = bytes_to_path(bytes);
    let unanchored = |given: PathBuf| Anchored {
        path: given.clone(),
        empty: false,
        dir: None,
        given,
    };
    if given.is_absolute() || !arg.anchor {
        return Ok(unanchored(given));
    }
    let anchor = match arg.dirfd_arg {
        Some(i) if u64::from(notif.data.args[i] as u32) != flags::AT_FDCWD => {
            DirAnchor::Fd(notif.data.args[i] as u32)
        }
        _ => DirAnchor::Cwd,
    };
    match kernel.dir_prefix(notif.pid, anchor) {
        Ok(prefix) if empty => Ok(Anchored {
            path: prefix.clone(),
            empty: true,
            dir: Some(prefix),
            given,
        }),
        Ok(prefix) => Ok(Anchored {
            path: prefix.join(&given),
            empty: false,
            dir: Some(prefix),
            given,
        }),
        Err(_) => Ok(unanchored(given)),
    }
}

#[cfg(unix)]
fn bytes_to_path(bytes: Vec<u8>) -> PathBuf {
    use std::os::unix::ffi::OsStringExt;
    PathBuf::from(std::ffi::OsString::from_vec(bytes))
}

/// append one syscall event; record precedes respond, so this runs before any send.
/// a failure here is case E: the caller denies the pending action and aborts the run.
fn record<S: TraceSink>(
    writer: &mut TraceWriter<S>,
    ts: u64,
    notif: &SeccompNotif,
    name: &str,
    fact: Fact,
    decision: &ResolvedDecision,
) -> Result<(), RunError> {
    record_with_operands(writer, ts, notif, name, fact, decision, None)
}

fn record_with_operands<S: TraceSink>(
    writer: &mut TraceWriter<S>,
    ts: u64,
    notif: &SeccompNotif,
    name: &str,
    fact: Fact,
    decision: &ResolvedDecision,
    operand_decisions: Option<Vec<FsOperandDecision>>,
) -> Result<(), RunError> {
    record_event(
        writer,
        ts,
        notif,
        name,
        fact,
        decision,
        operand_decisions,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn record_event<S: TraceSink>(
    writer: &mut TraceWriter<S>,
    ts: u64,
    notif: &SeccompNotif,
    name: &str,
    fact: Fact,
    decision: &ResolvedDecision,
    operand_decisions: Option<Vec<FsOperandDecision>>,
    errno: Option<String>,
) -> Result<(), RunError> {
    writer.append(
        ts,
        EventBody::Syscall(SyscallEvent {
            pid: notif.pid,
            syscall: name.to_string(),
            fact,
            decision: decision.event_decision,
            ask_resolution: decision.ask_resolution,
            matched_rule: decision.matched_rule.clone(),
            would_deny: decision.would_deny,
            operand_decisions,
            errno,
        }),
    )?;
    Ok(())
}

/// the child's filter must be the one the run's flag calls for: a default filter under a
/// snapshot run leaves AIO unmediated, and a snapshot filter under a plain run is
/// unexpected. either way the loop refuses before serving a single notification.
#[cfg(any(target_os = "linux", test))]
fn require_matching_filter(installed: bool, required: bool) -> Result<(), RunError> {
    if installed == required {
        Ok(())
    } else {
        Err(RunError::SnapshotFilterMismatch {
            installed,
            required,
        })
    }
}

#[cfg(target_os = "linux")]
pub use linux::{run_loop, run_loop_with_cgroup_kill};

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::supervisor::mem::proc::ChildMem;
    use crate::supervisor::notify::NotifyFd;
    use crate::supervisor::run_cgroup::RunCgroup;
    use crate::supervisor::spawn::SupervisedChild;
    use std::os::fd::AsRawFd;
    use std::time::{Instant, SystemTime};

    /// the real kernel side: the notify fd plus per-notification /proc reads.
    struct ProcNotifier<'a> {
        notify: &'a NotifyFd,
    }

    impl Notifier for ProcNotifier<'_> {
        fn id_valid(&self, id: u64) -> io::Result<bool> {
            self.notify.id_valid(id)
        }
        fn send_continue(&self, id: u64) -> io::Result<()> {
            self.notify.send_continue(id)
        }
        fn send_error(&self, id: u64, errno: i32) -> io::Result<()> {
            self.notify.send_error(id, errno)
        }
        fn send_success(&self, id: u64, value: i64) -> io::Result<()> {
            self.notify.send_success(id, value)
        }
        fn send_addfd(
            &self,
            id: u64,
            srcfd: BorrowedFd<'_>,
            flags: u32,
            newfd_flags: u32,
        ) -> io::Result<i32> {
            self.notify.send_addfd(id, srcfd, flags, newfd_flags)
        }
        fn duplicate_fd(&self, pid: u32, target_fd: RawFd) -> io::Result<OwnedFd> {
            let tgid = process_tgid(pid)?;
            // SAFETY: pidfd_open takes the thread-group leader pid and zero flags.
            let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, tgid, 0) };
            if pidfd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: pidfd is live, target_fd is looked up in that process, flags are zero.
            let duplicate = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, target_fd, 0) };
            // SAFETY: pidfd_open returned a descriptor owned by this scope.
            unsafe { libc::close(pidfd as RawFd) };
            if duplicate < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: pidfd_getfd returned a new descriptor.
            Ok(unsafe { OwnedFd::from_raw_fd(duplicate as RawFd) })
        }
        fn read_path(&self, pid: u32, addr: u64) -> Result<Vec<u8>, MemReadError> {
            ChildMem::open(pid)?.read_path(addr)
        }
        fn read_bytes(&self, pid: u32, addr: u64, len: usize) -> Result<Vec<u8>, MemReadError> {
            ChildMem::open(pid)?.read_exact(addr, len)
        }
        fn read_u64(&self, pid: u32, addr: u64) -> Result<u64, MemReadError> {
            let bytes = ChildMem::open(pid)?.read_exact(addr, 8)?;
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes);
            Ok(u64::from_ne_bytes(raw))
        }
        fn dir_prefix(&self, pid: u32, anchor: DirAnchor) -> io::Result<PathBuf> {
            let link = match anchor {
                DirAnchor::Cwd => format!("/proc/{pid}/cwd"),
                DirAnchor::Fd(fd) => format!("/proc/{pid}/fd/{fd}"),
            };
            std::fs::read_link(link)
        }
        fn process_in_tree(&self, root: u32, target: u32) -> io::Result<bool> {
            process_in_tree(root, target)
        }
    }

    /// serve the notify fd until every process holding the filter has exited, then reap
    /// the direct child (architecture.md section 5.3). the loop owns the child: on the
    /// case-E abort it kills the tree's root and drops the notify fd, which fails every
    /// pending and future mediated syscall closed (case G).
    ///
    /// a child born into a run cgroup (snapshot runs) changes two things. the run ends when
    /// the root process exits, not when the last filter holder does, and Leash then kills
    /// every leftover process through `cgroup.kill` before it finishes. every abort path
    /// and every error kills the whole cgroup, not only the direct child, and the cgroup
    /// directory is removed on the way out (ADR-0024 decisions 11 and 12).
    pub fn run_loop<S: TraceSink>(
        child: SupervisedChild,
        config: RunConfig<'_>,
        writer: &mut TraceWriter<S>,
    ) -> Result<RunOutcome, RunError> {
        run_loop_with_cgroup_kill(child, config, writer, &RunCgroup::kill_all)
    }

    /// `run_loop` with an injectable cgroup kill operation, the seam tests use to exercise a
    /// `cgroup.kill` timeout failing closed without test-only branches in production code.
    pub fn run_loop_with_cgroup_kill<S: TraceSink>(
        mut child: SupervisedChild,
        config: RunConfig<'_>,
        writer: &mut TraceWriter<S>,
        kill_cgroup: &dyn Fn(
            &RunCgroup,
            crate::recorder::CgroupKillReason,
        ) -> crate::recorder::CgroupKillEvent,
    ) -> Result<RunOutcome, RunError> {
        let Some(mut cgroup) = child.cgroup.take() else {
            let mut run_end_kill_done = false;
            return run_loop_in(
                child,
                config,
                writer,
                None,
                kill_cgroup,
                &mut run_end_kill_done,
            );
        };
        let mut run_end_kill_done = false;
        let result = run_loop_in(
            child,
            config,
            writer,
            Some(&mut cgroup),
            kill_cgroup,
            &mut run_end_kill_done,
        );
        if result.is_err() {
            if !run_end_kill_done {
                // the loop already killed the direct child; take the rest of the tree with it.
                // best-effort record: the run is already failing, so a trace error here only
                // loses the note, never the kill.
                let mut event = kill_cgroup(&cgroup, crate::recorder::CgroupKillReason::Abort);
                if event.error.is_none()
                    && let Err(e) = cgroup.remove()
                {
                    event.removal_error = Some(e.to_string());
                }
                let _ = writer.append(now_ms(), EventBody::CgroupKill(event));
            } else {
                let _ = cgroup.remove();
            }
        }
        result
    }

    fn run_loop_in<S: TraceSink>(
        child: SupervisedChild,
        config: RunConfig<'_>,
        writer: &mut TraceWriter<S>,
        cgroup: Option<&mut RunCgroup>,
        kill_cgroup: &dyn Fn(
            &RunCgroup,
            crate::recorder::CgroupKillReason,
        ) -> crate::recorder::CgroupKillEvent,
        run_end_kill_done: &mut bool,
    ) -> Result<RunOutcome, RunError> {
        let config = match config.validate() {
            Ok(config) => config,
            Err(e) => {
                abort_run(&child);
                return Err(e);
            }
        };
        if let Err(e) = require_matching_filter(child.snapshot_filter, config.snapshot_integrity) {
            abort_run(&child);
            return Err(e);
        }
        let kernel = ProcNotifier {
            notify: &child.notify,
        };
        // the step clock runs only when a capture target is wired (FR-11, FR-17);
        // without one there are no boundaries and the final step index stays 0.
        let mut clock = config
            .capture
            .map(|_| crate::snapshot::StepClock::new(crate::snapshot::STEP_WINDOW));
        // a run cgroup ends the run at the root's exit: a pidfd for the root joins the poll set
        let root_pidfd = match cgroup.as_ref().map(|_| pidfd_open(child.pid)).transpose() {
            Ok(fd) => fd,
            Err(e) => {
                abort_run(&child);
                return Err(RunError::RunCgroup(e));
            }
        };

        loop {
            // close a step boundary if activity has quiesced. capture first, then the
            // step event, then fsync (trace.md section 4): a recorded boundary always
            // has its snapshot on disk, and a capture failure stops the run closed.
            if let (Some(clock), Some(capture)) = (clock.as_mut(), config.capture)
                && let Some(step) = clock.poll(Instant::now())
            {
                if let Err(e) = capture.capture(step) {
                    abort_run(&child);
                    return Err(e.into());
                }
                if let Err(e) = writer
                    .append(now_ms(), EventBody::Step { step })
                    .and_then(|_| writer.sync())
                {
                    abort_run(&child);
                    return Err(e.into());
                }
            }
            let mut set = [
                libc::pollfd {
                    fd: child.notify.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    // a negative fd is ignored by poll: no root watch outside a run cgroup
                    fd: root_pidfd.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: poll reads and writes the two pollfds we own; the timeout bounds the
            // wait so a wedged fd cannot hang the supervisor without the loop noticing
            // (arc H).
            let rc = unsafe { libc::poll(set.as_mut_ptr(), 2, 100) };
            let [pfd, root_exit] = set;
            if rc < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue; // case A at the poll: nothing dequeued
                }
                abort_run(&child);
                return Err(RunError::Notify(e));
            }
            if root_exit.revents & libc::POLLIN != 0 {
                // the root exited: nothing more of the tree is trusted to run on
                break;
            }
            if pfd.revents & libc::POLLIN != 0 {
                let notif = match child.notify.recv() {
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue, // case A
                    // case B at the recv: the notification died between poll and recv,
                    // or the last filter user just exited (the next poll reports HUP)
                    Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
                    Err(e) => {
                        abort_run(&child);
                        return Err(RunError::Notify(e));
                    }
                };
                match handle_notification(&kernel, &notif, writer, &config, now_ms()) {
                    Ok(handled) => {
                        if handled == Handled::RespondedMutation
                            && let Some(clock) = clock.as_mut()
                        {
                            clock.on_mutation(Instant::now());
                        }
                    }
                    Err(e) => {
                        // case E (or a dead fd): deny the pending action best-effort,
                        // then tear down; an unrecordable allow is not an allow
                        let _ = child.notify.send_error(notif.id, libc::EIO);
                        abort_run(&child);
                        return Err(e);
                    }
                }
                continue;
            }
            // POLLHUP: every filter user has exited, nothing more can trap. POLLERR and
            // POLLNVAL should be unreachable while we own the fd, but leaving them
            // unhandled would spin this loop forever; a closed listener denies
            // everything anyway (case G), so treating them as shutdown is fail-closed.
            if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                break;
            }
        }

        let wait_status = child.wait().map_err(RunError::Notify)?;
        if let Some(cgroup) = cgroup {
            // the root is reaped; whatever is left in the cgroup outlived it. kill it and
            // wait for populated 0 before the final capture (ADR-0024 decision 12).
            *run_end_kill_done = true;
            let mut event = kill_cgroup(cgroup, crate::recorder::CgroupKillReason::RunEnd);
            let incomplete = event.error.clone();
            if incomplete.is_none()
                && let Err(e) = cgroup.remove()
            {
                // kill succeeded and populated reached 0, so a removal failure is recorded
                // on the event without discarding the completed run or blocking run_end.
                event.removal_error = Some(e.to_string());
            }
            writer.append(now_ms(), EventBody::CgroupKill(event))?;
            if let Some(error) = incomplete {
                return Err(RunError::RunCgroup(io::Error::other(error)));
            }
        }
        // run end is always a boundary (snapshot.md section 1): the final capture lands
        // after the tree is reaped, so no write can slip past it.
        let final_step = match (clock.as_mut(), config.capture) {
            (Some(clock), Some(capture)) => {
                let step = clock.finish();
                capture.capture(step)?;
                writer.append(now_ms(), EventBody::Step { step })?;
                writer.sync()?;
                step
            }
            _ => 0,
        };
        Ok(RunOutcome {
            wait_status,
            final_step,
        })
    }

    /// a pidfd for `pid`, which the caller owns as an unreaped child, so the pid cannot be
    /// recycled before the descriptor exists.
    fn pidfd_open(pid: libc::pid_t) -> io::Result<OwnedFd> {
        // SAFETY: pidfd_open takes scalars and returns a new descriptor or -1.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the descriptor was just created and nothing else owns it.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
    }

    /// kill the direct child and reap it; the notify fd closes when `child` drops.
    fn abort_run(child: &SupervisedChild) {
        // SAFETY: the pid is our forked child, still unreaped; SIGKILL then reap.
        unsafe { libc::kill(child.pid, libc::SIGKILL) };
        let _ = child.wait();
    }

    fn process_in_tree(root: u32, target: u32) -> io::Result<bool> {
        let mut current = target;
        for _ in 0..256 {
            if current == root {
                return Ok(true);
            }
            if current <= 1 {
                return Ok(false);
            }
            current = parent_pid(current)?;
        }
        Ok(false)
    }

    fn process_tgid(pid: u32) -> io::Result<u32> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
        for line in status.lines() {
            if let Some(tgid) = line.strip_prefix("Tgid:") {
                return tgid
                    .trim()
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad Tgid"));
            }
        }
        Err(io::Error::new(io::ErrorKind::InvalidData, "missing Tgid"))
    }

    fn parent_pid(pid: u32) -> io::Result<u32> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
        for line in status.lines() {
            if let Some(ppid) = line.strip_prefix("PPid:") {
                return ppid
                    .trim()
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad PPid"));
            }
        }
        Err(io::Error::new(io::ErrorKind::InvalidData, "missing PPid"))
    }

    /// wall-clock milliseconds for the event envelope; the clock going backwards past
    /// the epoch would already have failed run setup, so 0 never actually stamps.
    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    #[test]
    fn snapshot_capture_cannot_be_activated() {
        struct Capture;
        impl crate::snapshot::BoundaryCapture for Capture {
            fn capture(&self, _: u64) -> Result<(), crate::snapshot::SnapshotError> {
                panic!("capture must not run")
            }
        }
        let capture = Capture;
        let config = super::RunConfig::record_only(1, crate::recorder::Attendance::Unattended)
            .with_capture(&capture);
        assert!(matches!(
            config.validate(),
            Err(super::RunError::CaptureUnavailable)
        ));
    }
    use super::*;
    use crate::supervisor::notify::SeccompData;
    use serde_json::Value;

    /// a state root no unit-test path falls under, for configs that must carry one.
    fn test_root() -> &'static crate::supervisor::state_root::StateRoot {
        static ROOT: std::sync::OnceLock<crate::supervisor::state_root::StateRoot> =
            std::sync::OnceLock::new();
        ROOT.get_or_init(|| {
            crate::supervisor::state_root::StateRoot::from_resolved(
                "/nonexistent/leash-test".into(),
            )
            .unwrap()
        })
    }
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io::Write;

    /// an ordinary file on ext4, which no implicit rule is about
    const ORDINARY_FILE: FdFacts = FdFacts {
        f_type: 0xEF53,
        dev: 2049,
        ino: 7,
    };
    /// `CGROUP2_SUPER_MAGIC`
    const CGROUP2: i64 = 0x6367_7270;

    /// a scripted kernel side: fixed child memory, programmable id_valid answers, and a
    /// log of every response sent.
    #[derive(Default)]
    struct FakeNotifier {
        mem: HashMap<u64, Vec<u8>>,
        cwd: &'static str,
        fd_dirs: HashMap<u32, &'static str>,
        // what a descriptor is (`describe_fd`): a scripted answer or an errno. a descriptor
        // in `fd_dirs` without one is an ordinary file on ext4
        fd_facts: HashMap<u32, Result<FdFacts, i32>>,
        // answers consumed per id_valid call; empty means "always valid"
        id_valid_script: RefCell<Vec<bool>>,
        sent: RefCell<Vec<String>>,
        send_errno: Option<i32>,  // error every send with this errno
        addfd_errno: Option<i32>, // refuse every ADDFD with this errno
    }

    impl FakeNotifier {
        fn with_cstr(mut self, addr: u64, s: &str) -> Self {
            let mut v = s.as_bytes().to_vec();
            v.push(0);
            self.mem.insert(addr, v);
            self
        }
        /// script a fixed-size struct (a `sockaddr`) at an address.
        fn with_bytes(mut self, addr: u64, bytes: Vec<u8>) -> Self {
            self.mem.insert(addr, bytes);
            self
        }
        fn sent(&self) -> Vec<String> {
            self.sent.borrow().clone()
        }
    }

    impl Notifier for FakeNotifier {
        fn id_valid(&self, _id: u64) -> io::Result<bool> {
            let mut script = self.id_valid_script.borrow_mut();
            if script.is_empty() {
                return Ok(true);
            }
            Ok(script.remove(0))
        }
        fn send_continue(&self, id: u64) -> io::Result<()> {
            if let Some(errno) = self.send_errno {
                return Err(io::Error::from_raw_os_error(errno));
            }
            self.sent.borrow_mut().push(format!("continue:{id}"));
            Ok(())
        }
        fn send_error(&self, id: u64, errno: i32) -> io::Result<()> {
            if let Some(e) = self.send_errno {
                return Err(io::Error::from_raw_os_error(e));
            }
            self.sent.borrow_mut().push(format!("error:{id}:{errno}"));
            Ok(())
        }
        fn send_success(&self, id: u64, value: i64) -> io::Result<()> {
            self.sent.borrow_mut().push(format!("success:{id}:{value}"));
            Ok(())
        }
        fn send_addfd(
            &self,
            id: u64,
            _srcfd: BorrowedFd<'_>,
            flags: u32,
            newfd_flags: u32,
        ) -> io::Result<i32> {
            if let Some(errno) = self.addfd_errno {
                return Err(io::Error::from_raw_os_error(errno));
            }
            self.sent
                .borrow_mut()
                .push(format!("addfd:{id}:{flags}:{newfd_flags}"));
            Ok(9)
        }
        fn duplicate_fd(&self, _pid: u32, _target_fd: RawFd) -> io::Result<OwnedFd> {
            Err(io::Error::from_raw_os_error(libc::EBADF))
        }
        fn describe_fd(&self, _pid: u32, target_fd: RawFd) -> io::Result<FdFacts> {
            let fd = u32::try_from(target_fd).unwrap_or(u32::MAX);
            match self.fd_facts.get(&fd) {
                Some(Ok(facts)) => Ok(*facts),
                Some(Err(errno)) => Err(io::Error::from_raw_os_error(*errno)),
                None if self.fd_dirs.contains_key(&fd) => Ok(ORDINARY_FILE),
                None => Err(io::Error::from_raw_os_error(libc::EBADF)),
            }
        }
        fn read_path(&self, _pid: u32, addr: u64) -> Result<Vec<u8>, MemReadError> {
            match self.mem.get(&addr) {
                Some(bytes) => {
                    let nul = bytes
                        .iter()
                        .position(|&b| b == 0)
                        .ok_or(MemReadError::NoNulWithinCap(4096))?;
                    Ok(bytes[..nul].to_vec())
                }
                None => Err(MemReadError::Io(io::Error::other("unmapped"))),
            }
        }
        fn read_bytes(&self, _pid: u32, addr: u64, len: usize) -> Result<Vec<u8>, MemReadError> {
            let bytes = self
                .mem
                .get(&addr)
                .ok_or_else(|| MemReadError::Io(io::Error::other("unmapped")))?;
            if bytes.len() < len {
                return Err(MemReadError::Short {
                    wanted: len,
                    got: bytes.len(),
                });
            }
            Ok(bytes[..len].to_vec())
        }
        fn read_u64(&self, _pid: u32, addr: u64) -> Result<u64, MemReadError> {
            let bytes = self
                .mem
                .get(&addr)
                .ok_or_else(|| MemReadError::Io(io::Error::other("unmapped")))?;
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[..8]);
            Ok(u64::from_ne_bytes(raw))
        }
        fn dir_prefix(&self, _pid: u32, anchor: DirAnchor) -> io::Result<PathBuf> {
            match anchor {
                DirAnchor::Cwd => Ok(PathBuf::from(self.cwd)),
                DirAnchor::Fd(fd) => self
                    .fd_dirs
                    .get(&fd)
                    .map(PathBuf::from)
                    .ok_or_else(|| io::Error::other("no such fd")),
            }
        }
        fn process_in_tree(&self, root: u32, target: u32) -> io::Result<bool> {
            Ok(root == target || target == 4242)
        }
    }

    /// a sink that can be told to fail after n writes (the case-E seam).
    #[derive(Default)]
    struct ScriptedSink {
        bytes: Vec<u8>,
        fail_after: Option<usize>,
        writes: usize,
    }

    impl Write for ScriptedSink {
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

    impl TraceSink for ScriptedSink {
        fn sync(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn notif(sys_nr: u32, args: [u64; 6]) -> SeccompNotif {
        SeccompNotif {
            id: 7,
            pid: 4242,
            flags: 0,
            data: SeccompData {
                nr: sys_nr as i32,
                arch: AUDIT_ARCH_X86_64,
                instruction_pointer: 0,
                args,
            },
        }
    }

    fn writer() -> TraceWriter<ScriptedSink> {
        TraceWriter::new(ScriptedSink::default())
    }

    fn policy(text: &str) -> Policy {
        Policy::parse(
            text,
            &crate::policy::ExpandContext {
                workspace: "/work",
                home: "/home/op",
            },
        )
        .unwrap()
    }

    fn handle_notification<N: Notifier, S: TraceSink>(
        kernel: &N,
        notif: &SeccompNotif,
        writer: &mut TraceWriter<S>,
        ts: u64,
    ) -> Result<Handled, RunError> {
        let config = RunConfig::record_only(notif.pid, Attendance::Unattended);
        super::handle_notification(kernel, notif, writer, &config, ts)
    }

    fn events(writer: TraceWriter<ScriptedSink>) -> Vec<Value> {
        String::from_utf8(writer.into_inner().bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn an_absolute_open_records_an_allow_then_continues() {
        let kernel = FakeNotifier::default().with_cstr(0x1000, "/etc/hosts");
        let mut w = writer();
        let n = notif(nr::OPENAT, [flags::AT_FDCWD, 0x1000, 0, 0, 0, 0]);

        let handled = handle_notification(&kernel, &n, &mut w, 1_000).unwrap();

        assert_eq!(handled, Handled::Responded);
        assert_eq!(kernel.sent(), vec!["continue:7"]);
        let ev = &events(w)[0];
        assert_eq!(ev["syscall"], "openat");
        assert_eq!(ev["fact"]["path"], "/etc/hosts");
        assert_eq!(ev["fact"]["access"], serde_json::json!(["read"]));
        assert_eq!(ev["decision"], "allow");
        assert_eq!(ev["matched_rule"], rule::RECORD_ONLY);
    }

    #[test]
    fn a_relative_open_is_anchored_at_the_cwd_and_a_dirfd_open_at_its_link() {
        let kernel = FakeNotifier {
            cwd: "/work",
            fd_dirs: HashMap::from([(5, "/data")]),
            ..FakeNotifier::default()
        }
        .with_cstr(0x1000, "notes.txt")
        .with_cstr(0x2000, "cache/blob");

        let mut w = writer();
        handle_notification(
            &kernel,
            &notif(nr::OPENAT, [flags::AT_FDCWD, 0x1000, 0, 0, 0, 0]),
            &mut w,
            1_000,
        )
        .unwrap();
        handle_notification(
            &kernel,
            &notif(nr::OPENAT, [5, 0x2000, 0, 0, 0, 0]),
            &mut w,
            1_001,
        )
        .unwrap();

        let evs = events(w);
        assert_eq!(evs[0]["fact"]["path"], "/work/notes.txt");
        assert_eq!(evs[1]["fact"]["path"], "/data/cache/blob");
    }

    #[test]
    fn an_unreadable_anchor_records_the_relative_path_and_still_allows() {
        // ADR-0010: record-only enforces nothing. a /proc anchor that cannot be read is
        // a supervisor-side fidelity gap (the real one that surfaced on the CI kernel),
        // not untrusted child memory, so the open is allowed with the path as the child
        // gave it, not denied. fd 9 is not in fd_dirs, so dir_prefix fails for it.
        let kernel = FakeNotifier::default().with_cstr(0x1000, "out.txt");
        let mut w = writer();
        let handled = handle_notification(
            &kernel,
            &notif(
                nr::OPENAT,
                [9, 0x1000, flags::O_WRONLY | flags::O_CREAT, 0, 0, 0],
            ),
            &mut w,
            1_000,
        )
        .unwrap();

        assert_eq!(handled, Handled::RespondedMutation);
        assert_eq!(kernel.sent(), vec!["continue:7"]);
        let ev = &events(w)[0];
        assert_eq!(ev["fact"]["path"], "out.txt", "recorded unanchored");
        assert_eq!(ev["decision"], "allow");
    }

    #[test]
    fn a_rename_carries_both_paths() {
        let kernel = FakeNotifier::default()
            .with_cstr(0x1000, "/work/a.txt")
            .with_cstr(0x2000, "/work/b.txt");
        let mut w = writer();
        handle_notification(
            &kernel,
            &notif(nr::RENAME, [0x1000, 0x2000, 0, 0, 0, 0]),
            &mut w,
            1_000,
        )
        .unwrap();

        let ev = &events(w)[0];
        assert_eq!(ev["fact"]["path"], "/work/a.txt");
        assert_eq!(ev["fact"]["dest"], "/work/b.txt");
        assert_eq!(ev["decision"], "allow");
    }

    #[test]
    fn openat2_reads_its_flags_from_child_memory() {
        let mut open_how = Vec::with_capacity(OPEN_HOW_SIZE);
        open_how.extend_from_slice(&(flags::O_WRONLY | flags::O_CREAT).to_ne_bytes());
        open_how.extend_from_slice(&0_u64.to_ne_bytes());
        open_how.extend_from_slice(&0_u64.to_ne_bytes());
        let mut kernel = FakeNotifier::default().with_cstr(0x1000, "/work/out");
        kernel.mem.insert(0x3000, open_how);

        let mut w = writer();
        handle_notification(
            &kernel,
            &notif(nr::OPENAT2, [flags::AT_FDCWD, 0x1000, 0x3000, 24, 0, 0]),
            &mut w,
            1_000,
        )
        .unwrap();
        assert_eq!(
            events(w)[0]["fact"]["access"],
            serde_json::json!(["write", "create"])
        );
    }

    // --- fail-closed arcs (notify-loop.md section 4) ---

    #[test]
    fn arc_b_a_dead_notification_is_dropped_without_event_or_response() {
        // dies at the bracket open
        let kernel = FakeNotifier {
            id_valid_script: RefCell::new(vec![false]),
            ..FakeNotifier::default()
        }
        .with_cstr(0x1000, "/etc/hosts");
        let mut w = writer();
        let handled = handle_notification(
            &kernel,
            &notif(nr::OPENAT, [flags::AT_FDCWD, 0x1000, 0, 0, 0, 0]),
            &mut w,
            1_000,
        )
        .unwrap();
        assert_eq!(handled, Handled::Dropped);
        assert!(
            kernel.sent().is_empty(),
            "no response for a dropped notification"
        );
        assert!(
            events(w).is_empty(),
            "a dropped notification records no event"
        );
    }

    #[test]
    fn arc_b_a_read_spanning_the_childs_death_is_discarded() {
        // valid at the bracket open, dead at the re-check: the read is discarded even
        // though it succeeded
        let kernel = FakeNotifier {
            id_valid_script: RefCell::new(vec![true, false]),
            ..FakeNotifier::default()
        }
        .with_cstr(0x1000, "/etc/hosts");
        let mut w = writer();
        let handled = handle_notification(
            &kernel,
            &notif(nr::OPENAT, [flags::AT_FDCWD, 0x1000, 0, 0, 0, 0]),
            &mut w,
            1_000,
        )
        .unwrap();
        assert_eq!(handled, Handled::Dropped);
        assert!(events(w).is_empty());
    }

    #[test]
    fn arc_c_an_unreadable_path_denies_with_a_recorded_event() {
        let kernel = FakeNotifier::default(); // nothing mapped
        let mut w = writer();
        let handled = handle_notification(
            &kernel,
            &notif(nr::OPENAT, [flags::AT_FDCWD, 0xdead, 0, 0, 0, 0]),
            &mut w,
            1_000,
        )
        .unwrap();
        assert_eq!(handled, Handled::Responded);
        assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::EACCES)]);
        let ev = &events(w)[0];
        assert_eq!(ev["decision"], "deny");
        assert_eq!(ev["matched_rule"], rule::MEMORY_READ);
        assert_eq!(ev["fact"]["family"], "raw");
    }

    #[test]
    fn arc_e_a_failed_trace_write_is_fatal_and_nothing_was_released() {
        let kernel = FakeNotifier::default().with_cstr(0x1000, "/etc/hosts");
        let mut w = TraceWriter::new(ScriptedSink {
            fail_after: Some(0),
            ..ScriptedSink::default()
        });
        let result = handle_notification(
            &kernel,
            &notif(nr::OPENAT, [flags::AT_FDCWD, 0x1000, 0, 0, 0, 0]),
            &mut w,
            1_000,
        );
        assert!(matches!(result, Err(RunError::Recorder(_))));
        assert!(
            kernel.sent().is_empty(),
            "record precedes respond: no response was sent for the unrecorded action"
        );
    }

    #[test]
    fn sr4_io_uring_is_denied_and_recorded() {
        let kernel = FakeNotifier::default();
        let mut w = writer();
        handle_notification(&kernel, &notif(nr::IO_URING_SETUP, [0; 6]), &mut w, 1_000).unwrap();
        assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::ENOSYS)]);
        let ev = &events(w)[0];
        assert_eq!(ev["syscall"], "io_uring_setup");
        assert_eq!(ev["decision"], "deny");
        assert_eq!(ev["matched_rule"], rule::IO_URING);
    }

    #[test]
    fn foreign_abi_entries_are_denied_and_recorded() {
        let kernel = FakeNotifier::default();
        let mut w = writer();
        // an x32 openat: reports the x86-64 arch with bit 30 set in the number
        handle_notification(
            &kernel,
            &notif(nr::OPENAT | X32_SYSCALL_BIT, [0; 6]),
            &mut w,
            1_000,
        )
        .unwrap();
        let mut foreign = notif(nr::OPENAT, [0; 6]);
        foreign.data.arch = 0x4000_0003; // AUDIT_ARCH_I386
        handle_notification(&kernel, &foreign, &mut w, 1_001).unwrap();

        let evs = events(w);
        assert_eq!(evs.len(), 2);
        for ev in &evs {
            assert_eq!(ev["decision"], "deny");
            assert_eq!(ev["matched_rule"], rule::FOREIGN_ABI);
        }
        assert_eq!(
            kernel.sent(),
            vec![
                format!("error:7:{}", libc::ENOSYS),
                format!("error:7:{}", libc::ENOSYS)
            ]
        );
    }

    #[cfg(target_os = "linux")]
    fn a_descriptor() -> BrokerResult {
        BrokerResult::Fd(OwnedFd::from(std::fs::File::open("/dev/null").unwrap()))
    }

    /// issue #53: the kernel refusing one ADDFD fails that syscall only. nothing is sent
    /// yet: the caller is told the errno to record first and then answer with.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_refused_addfd_is_reported_unanswered() {
        for (refused, expected) in [
            (libc::EBADF, libc::EIO),
            (libc::EINVAL, libc::EIO),
            (libc::EMFILE, libc::EMFILE),
            (libc::ENFILE, libc::ENFILE),
            (libc::ENOMEM, libc::ENOMEM),
        ] {
            let kernel = FakeNotifier {
                addfd_errno: Some(refused),
                ..FakeNotifier::default()
            };
            let delivery = respond_broker_result(&kernel, 7, a_descriptor(), 0).unwrap();
            assert_eq!(
                delivery,
                Delivery::Refused { errno: expected },
                "ADDFD errno {refused}"
            );
            assert!(kernel.sent().is_empty(), "record precedes respond");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_addfd_for_a_dead_child_is_not_a_failure() {
        let kernel = FakeNotifier {
            addfd_errno: Some(libc::ENOENT),
            ..FakeNotifier::default()
        };
        assert_eq!(
            respond_broker_result(&kernel, 7, a_descriptor(), 0).unwrap(),
            Delivery::Delivered
        );
        assert!(kernel.sent().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_delivered_descriptor_reports_no_failure() {
        let kernel = FakeNotifier::default();
        assert_eq!(
            respond_broker_result(&kernel, 7, a_descriptor(), libc::O_CLOEXEC as u32).unwrap(),
            Delivery::Delivered
        );
        assert_eq!(
            kernel.sent(),
            vec![format!(
                "addfd:7:{SECCOMP_ADDFD_FLAG_SEND}:{}",
                libc::O_CLOEXEC
            )]
        );
    }

    /// deliver an allowed open's broker result the way handle_fs_enforce does, after its
    /// allow event is already written.
    #[cfg(target_os = "linux")]
    fn deliver(
        kernel: &FakeNotifier,
        w: &mut TraceWriter<ScriptedSink>,
        access: &[crate::recorder::FsAccess],
        result: BrokerResult,
        o_path: bool,
    ) -> Result<Handled, RunError> {
        deliver_realization(
            kernel,
            &notif(nr::OPENAT, [flags::AT_FDCWD, 0x1000, 0, 0, 0, 0]),
            w,
            1_000,
            "openat",
            Fact::Fs {
                path: PathBuf::from("/ws/file"),
                access: access.to_vec(),
                dest: None,
            },
            access,
            result,
            Realization {
                o_path,
                resolve_refused: false,
                newfd_flags: 0,
            },
        )
    }

    /// the refused ADDFD is recorded under failsafe:realization before the errno is sent,
    /// and the loop goes on.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_refused_addfd_is_recorded_then_answered() {
        use crate::recorder::FsAccess::Read;
        let kernel = FakeNotifier {
            addfd_errno: Some(libc::EMFILE),
            ..FakeNotifier::default()
        };
        let mut w = writer();
        let handled = deliver(&kernel, &mut w, &[Read], a_descriptor(), false).unwrap();
        assert_eq!(handled, Handled::Responded, "a read never ticks the clock");
        assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::EMFILE)]);
        let events = events(w);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["decision"], "deny");
        assert_eq!(events[0]["matched_rule"], "failsafe:realization");
        assert_eq!(events[0]["errno"], "EMFILE");
        assert_eq!(events[0]["fact"]["path"], "/ws/file");
    }

    /// record precedes respond on the second event too: when it cannot be written the run
    /// aborts with no answer sent for the pending notification.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_write_of_the_realization_event_aborts_unanswered() {
        use crate::recorder::FsAccess::Read;
        let kernel = FakeNotifier {
            addfd_errno: Some(libc::EMFILE),
            ..FakeNotifier::default()
        };
        let mut w = TraceWriter::new(ScriptedSink {
            fail_after: Some(0),
            ..ScriptedSink::default()
        });
        let result = deliver(&kernel, &mut w, &[Read], a_descriptor(), false);
        assert!(matches!(result, Err(RunError::Recorder(_))), "{result:?}");
        assert!(
            kernel.sent().is_empty(),
            "no errno is sent before the failure is recorded"
        );
    }

    /// the broker creates or truncates before the ADDFD, and a refused ADDFD does not undo
    /// that, so the step clock must still see the mutation.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_refused_addfd_after_a_create_or_truncate_still_ticks_the_step_clock() {
        use crate::recorder::FsAccess::{Create, Read, Write};
        for access in [vec![Write, Create], vec![Read, Write]] {
            let kernel = FakeNotifier {
                addfd_errno: Some(libc::EMFILE),
                ..FakeNotifier::default()
            };
            let mut w = writer();
            let handled = deliver(&kernel, &mut w, &access, a_descriptor(), false).unwrap();
            assert_eq!(handled, Handled::RespondedMutation, "{access:?}");
            assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::EMFILE)]);
            assert_eq!(events(w)[0]["errno"], "EMFILE");
        }
    }

    /// only a dead notify fd ends the loop: when the error response cannot be sent either,
    /// the failure is the listener's, not the one notification's.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_refused_addfd_on_a_broken_notify_fd_surfaces() {
        use crate::recorder::FsAccess::Read;
        let kernel = FakeNotifier {
            addfd_errno: Some(libc::EBADF),
            send_errno: Some(libc::EBADF),
            ..FakeNotifier::default()
        };
        let mut w = writer();
        assert!(matches!(
            deliver(&kernel, &mut w, &[Read], a_descriptor(), false),
            Err(RunError::Notify(_))
        ));
        assert_eq!(events(w).len(), 1, "the failure was recorded first");
    }

    /// the O_PATH substitute refuses a fifo, device, socket, or symlink with EOPNOTSUPP. that
    /// is a realization failure the trace must show, not an answer the kernel would give.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_unrealizable_o_path_kind_is_recorded_then_answered() {
        use crate::recorder::FsAccess::Read;
        let kernel = FakeNotifier::default();
        let mut w = writer();
        let handled = deliver(
            &kernel,
            &mut w,
            &[Read],
            BrokerResult::Errno(libc::EOPNOTSUPP),
            true,
        )
        .unwrap();
        assert_eq!(handled, Handled::Responded);
        assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::EOPNOTSUPP)]);
        let events = events(w);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["matched_rule"], "failsafe:realization");
        assert_eq!(events[0]["errno"], "EOPNOTSUPP");
    }

    /// an O_PATH open needs no read permission, but its substitute is a read-only reopen, so
    /// EACCES on a file whose mode refuses the broker a read is a realization failure too.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_dac_refused_o_path_reopen_is_recorded_then_answered() {
        use crate::recorder::FsAccess::Read;
        let kernel = FakeNotifier::default();
        let mut w = writer();
        let handled = deliver(
            &kernel,
            &mut w,
            &[Read],
            BrokerResult::Errno(libc::EACCES),
            true,
        )
        .unwrap();
        assert_eq!(handled, Handled::Responded);
        assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::EACCES)]);
        let events = events(w);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["decision"], "deny");
        assert_eq!(events[0]["matched_rule"], "failsafe:realization");
        assert_eq!(events[0]["errno"], "EACCES");
    }

    /// any other broker errno is the answer the open would have had, already covered by
    /// the allow event: it is sent as is with no second event.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_broker_errno_is_answered_without_a_second_event() {
        use crate::recorder::FsAccess::Read;
        for (errno, o_path) in [
            (libc::EOPNOTSUPP, false),
            (libc::EACCES, false),
            (libc::ENOTDIR, true),
            (libc::EEXIST, false),
        ] {
            let kernel = FakeNotifier::default();
            let mut w = writer();
            deliver(&kernel, &mut w, &[Read], BrokerResult::Errno(errno), o_path).unwrap();
            assert_eq!(kernel.sent(), vec![format!("error:7:{errno}")]);
            assert!(events(w).is_empty(), "errno {errno}, o_path {o_path}");
        }
    }

    #[test]
    fn a_dead_child_at_send_time_is_not_fatal() {
        // the decision was recorded, then the child died before the response landed:
        // the syscall never completes (case B), the loop continues
        let kernel = FakeNotifier {
            send_errno: Some(libc::ENOENT),
            ..FakeNotifier::default()
        }
        .with_cstr(0x1000, "/etc/hosts");
        let mut w = writer();
        let handled = handle_notification(
            &kernel,
            &notif(nr::OPENAT, [flags::AT_FDCWD, 0x1000, 0, 0, 0, 0]),
            &mut w,
            1_000,
        )
        .unwrap();
        assert_eq!(handled, Handled::Responded);
        assert_eq!(events(w).len(), 1, "the decision stays in the trace");
    }

    #[test]
    fn process_and_cross_process_syscalls_record_typed_facts() {
        let kernel = FakeNotifier::default();
        let mut w = writer();
        handle_notification(&kernel, &notif(nr::CLONE, [0; 6]), &mut w, 1_000).unwrap();
        handle_notification(
            &kernel,
            &notif(nr::PTRACE, [0, 71, 0, 0, 0, 0]),
            &mut w,
            1_001,
        )
        .unwrap();
        handle_notification(
            &kernel,
            &notif(nr::PROCESS_VM_READV, [72, 0, 0, 0, 0, 0]),
            &mut w,
            1_002,
        )
        .unwrap();
        handle_notification(
            &kernel,
            &notif(nr::PROCESS_VM_WRITEV, [73, 0, 0, 0, 0, 0]),
            &mut w,
            1_003,
        )
        .unwrap();
        assert_eq!(kernel.sent().len(), 4);
        assert!(kernel.sent().iter().all(|s| s.starts_with("continue:")));
        let evs = events(w);
        assert_eq!(evs[0]["fact"]["family"], "process");
        assert_eq!(evs[0]["fact"]["flags"], 0);
        assert_eq!(evs[1]["fact"]["family"], "cross_process");
        assert_eq!(evs[1]["fact"]["target_pid"], 71);
        assert_eq!(evs[2]["fact"]["family"], "cross_process");
        assert_eq!(evs[2]["fact"]["target_pid"], 72);
        assert_eq!(evs[3]["fact"]["target_pid"], 73);
        assert!(evs.iter().all(|ev| ev["decision"] == "allow"));
        assert!(evs.iter().all(|ev| ev["matched_rule"] == rule::RECORD_ONLY));
    }

    #[test]
    fn clone3_only_reads_flags_for_supported_struct_sizes() {
        for size in [CLONE_ARGS_MIN_SIZE, CLONE_ARGS_MAX_SIZE] {
            let kernel =
                FakeNotifier::default().with_bytes(0x1000, 0x1234_u64.to_ne_bytes().to_vec());
            let mut w = writer();
            handle_notification(
                &kernel,
                &notif(nr::CLONE3, [0x1000, size, 0, 0, 0, 0]),
                &mut w,
                1_000,
            )
            .unwrap();
            assert_eq!(kernel.sent(), vec!["continue:7"]);
            assert_eq!(events(w)[0]["fact"]["flags"], 0x1234);
        }

        for size in [
            0,
            CLONE_ARGS_MIN_SIZE - 1,
            CLONE_ARGS_MAX_SIZE + 1,
            u64::MAX,
        ] {
            let kernel = FakeNotifier::default();
            let mut w = writer();
            handle_notification(
                &kernel,
                &notif(nr::CLONE3, [0xdead, size, 0, 0, 0, 0]),
                &mut w,
                1_000,
            )
            .unwrap();
            assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::EACCES)]);
            let ev = &events(w)[0];
            assert_eq!(ev["fact"]["family"], "raw");
            assert_eq!(ev["decision"], "deny");
            assert_eq!(ev["matched_rule"], rule::MEMORY_READ);
        }
    }

    #[test]
    fn snapshot_run_answers_clone3_enosys_without_reading_the_struct() {
        let p = policy("schema_version = 1\n");
        let config = RunConfig::enforce(4242, Attendance::Unattended, &p, test_root())
            .with_snapshot_integrity(true);
        // an unmapped struct pointer: any read would surface as memory_read, not the snapshot rule
        for args in [
            [0xdead, CLONE_ARGS_MIN_SIZE, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0],
        ] {
            let kernel = FakeNotifier::default();
            let mut w = writer();
            super::handle_notification(&kernel, &notif(nr::CLONE3, args), &mut w, &config, 1_000)
                .unwrap();
            assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::ENOSYS)]);
            let ev = &events(w)[0];
            assert_eq!(ev["syscall"], "clone3");
            assert_eq!(ev["decision"], "deny");
            assert_eq!(ev["matched_rule"], rule::SNAPSHOT_CLONE3);
        }
    }

    #[test]
    fn snapshot_run_denies_aio_and_leaves_clone_alone() {
        let p = policy("schema_version = 1\n");
        let config = RunConfig::enforce(4242, Attendance::Unattended, &p, test_root())
            .with_snapshot_integrity(true);
        for (sys_nr, name) in [(nr::IO_SETUP, "io_setup"), (nr::IO_SUBMIT, "io_submit")] {
            let kernel = FakeNotifier::default();
            let mut w = writer();
            super::handle_notification(&kernel, &notif(sys_nr, [0; 6]), &mut w, &config, 1_000)
                .unwrap();
            assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::ENOSYS)]);
            let ev = &events(w)[0];
            assert_eq!(ev["syscall"], name);
            assert_eq!(ev["matched_rule"], rule::SNAPSHOT_AIO);
        }
        let kernel = FakeNotifier::default();
        let mut w = writer();
        super::handle_notification(&kernel, &notif(nr::CLONE, [0; 6]), &mut w, &config, 1_000)
            .unwrap();
        assert_eq!(kernel.sent(), vec!["continue:7"]);
    }

    #[test]
    fn snapshot_filter_syscalls_are_denied_and_recorded_even_with_the_flag_off() {
        let p = policy("schema_version = 1\n");
        let config = RunConfig::enforce(4242, Attendance::Unattended, &p, test_root());
        for sys_nr in [nr::IO_SETUP, nr::IO_SUBMIT] {
            let kernel = FakeNotifier::default();
            let mut w = writer();
            super::handle_notification(&kernel, &notif(sys_nr, [0; 6]), &mut w, &config, 1_000)
                .unwrap();
            assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::ENOSYS)]);
            assert_eq!(events(w)[0]["matched_rule"], rule::SNAPSHOT_AIO);
        }
    }

    #[test]
    fn the_path_attribute_calls_newer_than_libc_are_answered_enosys_and_recorded() {
        // setxattrat (6.13), removexattrat (6.13) and file_setattr (6.17) name a path and can
        // set `user.leash.lock` or a file attribute with no open. nothing in libc calls them
        // yet, so they are answered ENOSYS, and the flag decides nothing: a filter and flag
        // that disagree still deny and record them
        let p = policy("schema_version = 1\n");
        for snapshot_integrity in [true, false] {
            let config = RunConfig::enforce(4242, Attendance::Unattended, &p, test_root())
                .with_snapshot_integrity(snapshot_integrity);
            for (sys_nr, name) in [
                (nr::SETXATTRAT, "setxattrat"),
                (nr::REMOVEXATTRAT, "removexattrat"),
                (nr::FILE_SETATTR, "file_setattr"),
            ] {
                let kernel = FakeNotifier::default();
                let mut w = writer();
                super::handle_notification(&kernel, &notif(sys_nr, [0; 6]), &mut w, &config, 1)
                    .unwrap();
                assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::ENOSYS)]);
                let ev = &events(w)[0];
                assert_eq!(ev["syscall"], name);
                assert_eq!(ev["decision"], "deny");
                assert_eq!(ev["matched_rule"], rule::SNAPSHOT_XATTRAT);
            }
        }
    }

    #[test]
    fn a_filter_and_flag_that_disagree_are_refused_in_both_directions() {
        assert!(require_matching_filter(true, true).is_ok());
        assert!(require_matching_filter(false, false).is_ok());
        for (installed, required) in [(false, true), (true, false)] {
            assert!(matches!(
                require_matching_filter(installed, required),
                Err(RunError::SnapshotFilterMismatch { .. })
            ));
        }
    }

    #[test]
    fn snapshot_integrity_is_refused_outside_enforce() {
        let config =
            RunConfig::record_only(1, Attendance::Unattended).with_snapshot_integrity(true);
        assert!(matches!(
            config.validate(),
            Err(RunError::SnapshotIntegrityNeedsEnforce)
        ));
    }

    #[test]
    fn network_unreadable_sockaddr_records_raw_and_allows_in_record_only() {
        let kernel = FakeNotifier::default();
        let mut w = writer();
        handle_notification(
            &kernel,
            &notif(nr::CONNECT, [3, 0xdead, 16, 0, 0, 0]),
            &mut w,
            1_000,
        )
        .unwrap();
        assert_eq!(kernel.sent(), vec!["continue:7"]);
        let ev = &events(w)[0];
        assert_eq!(ev["syscall"], "connect");
        assert_eq!(ev["fact"]["family"], "raw");
        assert_eq!(ev["decision"], "allow");
        assert_eq!(ev["matched_rule"], rule::RECORD_ONLY);
    }

    /// A bare enforce config lacks the confined broker and must refuse before serving.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_enforce_run_without_a_broker_is_refused() {
        let p = policy("schema_version = 1\n");
        let refused = RunConfig::enforce(4242, Attendance::Unattended, &p, test_root())
            .validate()
            .expect_err("enforce must not validate");
        assert!(matches!(refused, RunError::MissingBroker), "{refused:?}");
        assert_eq!(
            RunError::MissingBroker.to_string(),
            "enforce mode requires a confined realization broker"
        );
        RunConfig::record_only(4242, Attendance::Unattended)
            .validate()
            .expect("record-only is the mode that serves");
    }

    /// an enforce config whose state root has been cleared must refuse, whatever else it has:
    /// the implicit deny cannot be silently absent (FR-21).
    #[test]
    fn an_enforce_run_without_a_state_root_is_refused() {
        let p = policy("schema_version = 1\n");
        let mut config = RunConfig::enforce(4242, Attendance::Unattended, &p, test_root());
        config.state_root = None;
        let refused = config.validate().expect_err("enforce must not validate");
        assert!(
            matches!(refused, RunError::EnforceWithoutStateRoot),
            "{refused:?}"
        );
    }

    /// the enforce leg of the same arc. ADR-0019 scopes exactly one arc of the
    /// fail-closed enumeration by mode; the record-only leg above allows, and here the
    /// identical untrusted fact denies fail-closed under `failsafe:memory_read`
    /// (`notify-loop.md` section 4 case C, spec FR-9, trace.md section 2).
    #[test]
    fn network_unreadable_sockaddr_records_raw_and_denies_in_enforce() {
        let kernel = FakeNotifier::default();
        let p = policy("schema_version = 1\n");
        let config = RunConfig::enforce(4242, Attendance::Unattended, &p, test_root());
        let mut w = writer();
        super::handle_notification(
            &kernel,
            &notif(nr::CONNECT, [3, 0xdead, 16, 0, 0, 0]),
            &mut w,
            &config,
            1_000,
        )
        .unwrap();

        assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::EACCES)]);
        let ev = &events(w)[0];
        assert_eq!(ev["syscall"], "connect");
        assert_eq!(ev["fact"]["family"], "raw");
        assert_eq!(ev["decision"], "deny");
        assert_eq!(ev["matched_rule"], rule::MEMORY_READ);
    }

    #[test]
    fn network_overcap_sockaddr_uses_the_mode_specific_raw_decision() {
        for enforce in [false, true] {
            let kernel = FakeNotifier::default();
            let p = policy("schema_version = 1\n");
            let config = if enforce {
                RunConfig::enforce(4242, Attendance::Unattended, &p, test_root())
            } else {
                RunConfig::record_only(4242, Attendance::Unattended)
            };
            let mut w = writer();
            super::handle_notification(
                &kernel,
                &notif(nr::SENDTO, [3, 0, 0, 0, 0xdead, 129]),
                &mut w,
                &config,
                1_000,
            )
            .unwrap();

            let ev = &events(w)[0];
            assert_eq!(ev["syscall"], "sendto");
            assert_eq!(ev["fact"]["family"], "raw");
            if enforce {
                assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::EACCES)]);
                assert_eq!(ev["decision"], "deny");
                assert_eq!(ev["matched_rule"], rule::MEMORY_READ);
            } else {
                assert_eq!(kernel.sent(), vec!["continue:7"]);
                assert_eq!(ev["decision"], "allow");
                assert_eq!(ev["matched_rule"], rule::RECORD_ONLY);
            }
        }
    }

    /// the `host` field uses the canonical form pinned by `policy.md` section 2.2 and
    /// `trace.md` section 2: IPv4-mapped IPv6 records as IPv4, while native IPv6 is
    /// unchanged.
    #[test]
    fn a_network_fact_records_the_destination_host_and_port() {
        fn sockaddr_in(port: u16, octets: [u8; 4]) -> Vec<u8> {
            let mut v = (libc::AF_INET as u16).to_ne_bytes().to_vec();
            v.extend_from_slice(&port.to_be_bytes());
            v.extend_from_slice(&octets);
            v.extend_from_slice(&[0u8; 8]); // sin_zero
            v
        }
        fn sockaddr_in6(port: u16, addr: Ipv6Addr) -> Vec<u8> {
            let mut v = (libc::AF_INET6 as u16).to_ne_bytes().to_vec();
            v.extend_from_slice(&port.to_be_bytes());
            v.extend_from_slice(&[0u8; 4]); // sin6_flowinfo
            v.extend_from_slice(&addr.octets());
            v.extend_from_slice(&[0u8; 4]); // sin6_scope_id
            v
        }

        let mapped = Ipv6Addr::from(Ipv4Addr::new(1, 2, 3, 4).to_ipv6_mapped().octets());
        let native = "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap();
        let kernel = FakeNotifier::default()
            .with_bytes(0x2000, sockaddr_in(443, [1, 2, 3, 4]))
            .with_bytes(0x3000, sockaddr_in6(443, mapped))
            .with_bytes(0x4000, sockaddr_in6(53, native));
        let mut w = writer();
        for (addr, len) in [(0x2000u64, 16u64), (0x3000, 28), (0x4000, 28)] {
            handle_notification(
                &kernel,
                &notif(nr::CONNECT, [3, addr, len, 0, 0, 0]),
                &mut w,
                1_000,
            )
            .unwrap();
        }

        assert!(kernel.sent().iter().all(|s| s.starts_with("continue:")));
        let evs = events(w);
        assert!(evs.iter().all(|e| e["fact"]["family"] == "net"));
        assert_eq!(evs[0]["fact"]["host"], "1.2.3.4");
        assert_eq!(evs[0]["fact"]["port"], 443);
        assert_eq!(evs[1]["fact"]["host"], "1.2.3.4");
        assert_eq!(evs[2]["fact"]["host"], "2606:4700:4700::1111");
        assert_eq!(evs[2]["fact"]["port"], 53);
    }

    #[test]
    fn pidfd_getfd_is_denied_and_recorded_under_sr4_in_both_modes() {
        let p = policy("schema_version = 1\n");
        for config in [
            RunConfig::record_only(4242, Attendance::Unattended),
            RunConfig::enforce(4242, Attendance::Unattended, &p, test_root()),
        ] {
            let kernel = FakeNotifier::default();
            let mut w = writer();
            super::handle_notification(
                &kernel,
                &notif(nr::PIDFD_GETFD, [0; 6]),
                &mut w,
                &config,
                1_000,
            )
            .unwrap();

            assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::ENOSYS)]);
            let ev = &events(w)[0];
            assert_eq!(ev["fact"]["family"], "raw");
            assert_eq!(ev["decision"], "deny");
            assert_eq!(ev["matched_rule"], rule::PIDFD_GETFD);
        }
    }

    #[test]
    fn enforce_unmatched_outside_fs_denies_by_default() {
        let p = policy("schema_version = 1\n");
        let config = RunConfig::enforce(4242, Attendance::Unattended, &p, test_root());
        let decision = resolve_decision(
            &config,
            &Request::Fs {
                path: "/etc/hosts",
                access: &[crate::recorder::FsAccess::Read],
            },
        );

        assert_eq!(decision.event_decision, Decision::Deny);
        assert_eq!(decision.response_decision, Decision::Deny);
        assert_eq!(decision.matched_rule, "base:enforce");
    }

    #[test]
    fn the_implicit_state_root_deny_outranks_every_policy_rule() {
        use crate::recorder::FsAccess::{Create, Delete, Read, Write};
        let p = policy(
            "schema_version = 1\n\
             [[fs]]\npath=\"/**\"\nmode=[\"read\",\"write\",\"create\",\"delete\"]\naction=\"allow\"\n\
             [[exec]]\nbinary=\"/**\"\naction=\"allow\"\n",
        );
        let root =
            crate::supervisor::state_root::StateRoot::from_resolved("/var/leash".into()).unwrap();
        let config = RunConfig::enforce(4242, Attendance::Unattended, &p, &root);
        let denied = |path: &str, access: &[crate::recorder::FsAccess], destination: bool| {
            let mut asks = Vec::new();
            let eval = evaluate_operand(
                &config,
                &Request::Fs { path, access },
                destination,
                &mut asks,
            );
            (eval.decision, eval.matched.to_string())
        };
        for access in [Read, Write, Create, Delete] {
            assert_eq!(
                denied("/var/leash/runs/r/trace.jsonl", &[access], false),
                (Decision::Deny, "implicit:state_root".to_string())
            );
        }
        assert_eq!(
            denied("/var", &[Delete], false),
            (Decision::Deny, "implicit:state_root".to_string())
        );
        assert_eq!(
            denied("/var", &[Create], true),
            (Decision::Deny, "implicit:state_root".to_string())
        );
        // string-prefix siblings and plain ancestor reads fall through to the policy
        assert_eq!(
            denied("/var/leash2/f", &[Write], false),
            (Decision::Allow, "fs.1".to_string())
        );
        assert_eq!(
            denied("/var", &[Read], false),
            (Decision::Allow, "fs.1".to_string())
        );
        let decision = resolve_decision(
            &config,
            &Request::Exec {
                binary: "/var/leash/bin/x",
            },
        );
        assert_eq!(decision.matched_rule, "implicit:state_root");
        assert_eq!(decision.response_decision, Decision::Deny);
    }

    #[test]
    fn the_implicit_cgroup_deny_applies_only_to_a_snapshot_integrity_run() {
        use crate::recorder::FsAccess::{Create, Delete, Read, Write};
        let p = policy(
            "schema_version = 1\n\
             [[fs]]\npath=\"/**\"\nmode=[\"read\",\"write\",\"create\",\"delete\"]\naction=\"allow\"\n\
             [[exec]]\nbinary=\"/**\"\naction=\"allow\"\n",
        );
        let mounts = crate::supervisor::cgroup_mounts::CgroupMounts::from_resolved(vec![
            "/sys/fs/cgroup".into(),
        ])
        .unwrap();
        let eval = |config: &RunConfig<'_>,
                    path: &str,
                    access: &[crate::recorder::FsAccess],
                    destination: bool| {
            let mut asks = Vec::new();
            let eval = evaluate_operand(
                config,
                &Request::Fs { path, access },
                destination,
                &mut asks,
            );
            (eval.decision, eval.matched.to_string())
        };
        let snapshot = RunConfig::enforce(4242, Attendance::Unattended, &p, test_root())
            .with_snapshot_integrity(true)
            .with_cgroup_mounts(&mounts);
        for access in [Read, Write, Create, Delete] {
            assert_eq!(
                eval(
                    &snapshot,
                    "/sys/fs/cgroup/user.slice/cgroup.procs",
                    &[access],
                    false
                ),
                (Decision::Deny, "implicit:cgroup".to_string())
            );
        }
        assert_eq!(
            eval(&snapshot, "/sys/fs", &[Delete], false),
            (Decision::Deny, "implicit:cgroup".to_string())
        );
        assert_eq!(
            eval(&snapshot, "/sys", &[Create], true),
            (Decision::Deny, "implicit:cgroup".to_string())
        );
        assert_eq!(
            eval(&snapshot, "/sys/fs", &[Read], false),
            (Decision::Allow, "fs.1".to_string())
        );
        let exec = resolve_decision(
            &snapshot,
            &Request::Exec {
                binary: "/sys/fs/cgroup/x",
            },
        );
        assert_eq!(exec.matched_rule, "implicit:cgroup");

        // the same mounts without the snapshot flag, and a config without mounts, are inert
        let plain = RunConfig::enforce(4242, Attendance::Unattended, &p, test_root())
            .with_cgroup_mounts(&mounts);
        assert_eq!(
            eval(&plain, "/sys/fs/cgroup/cgroup.procs", &[Read], false),
            (Decision::Allow, "fs.1".to_string())
        );
        let unmounted = RunConfig::enforce(4242, Attendance::Unattended, &p, test_root())
            .with_snapshot_integrity(true);
        assert_eq!(
            eval(&unmounted, "/sys/fs/cgroup/cgroup.procs", &[Read], false),
            (Decision::Allow, "fs.1".to_string())
        );
        // validate refuses the snapshot run that was built without its mounts
        assert!(matches!(
            unmounted.validate(),
            Err(RunError::SnapshotIntegrityNeedsCgroupMounts)
        ));
    }

    #[test]
    fn the_state_root_deny_keeps_its_own_id_where_a_path_is_in_both_sets() {
        let p = policy("schema_version = 1\n");
        let root =
            crate::supervisor::state_root::StateRoot::from_resolved("/sys/fs/cgroup/state".into())
                .unwrap();
        let mounts = crate::supervisor::cgroup_mounts::CgroupMounts::from_resolved(vec![
            "/sys/fs/cgroup".into(),
        ])
        .unwrap();
        let config = RunConfig::enforce(4242, Attendance::Unattended, &p, &root)
            .with_snapshot_integrity(true)
            .with_cgroup_mounts(&mounts);
        let decision = resolve_decision(
            &config,
            &Request::Fs {
                path: "/sys/fs/cgroup/state/runs",
                access: &[crate::recorder::FsAccess::Read],
            },
        );
        assert_eq!(decision.matched_rule, "implicit:state_root");
    }

    /// an enforce snapshot config over a policy that grants everything, with the cgroup2
    /// mount at /sys/fs/cgroup, so any refusal comes from an implicit rule.
    fn metadata_run<R>(body: impl FnOnce(&RunConfig<'_>) -> R) -> R {
        let p = policy(
            "schema_version = 1\n\
             [[fs]]\npath=\"/**\"\nmode=[\"read\",\"write\",\"create\",\"delete\"]\naction=\"allow\"\n",
        );
        let mounts = crate::supervisor::cgroup_mounts::CgroupMounts::from_resolved(vec![
            "/sys/fs/cgroup".into(),
        ])
        .unwrap();
        let config = RunConfig::enforce(4242, Attendance::Unattended, &p, test_root())
            .with_snapshot_integrity(true)
            .with_cgroup_mounts(&mounts);
        body(&config)
    }

    #[test]
    fn descriptor_metadata_calls_are_judged_on_the_descriptors_target() {
        let fd_calls: [(u32, [u64; 6], &str); 5] = [
            (nr::FCHMOD, [5, 0o777, 0, 0, 0, 0], "fchmod"),
            (nr::FCHOWN, [5, 0, 0, 0, 0, 0], "fchown"),
            (nr::FSETXATTR, [5, 0x1000, 0x2000, 1, 0, 0], "fsetxattr"),
            (nr::FREMOVEXATTR, [5, 0x1000, 0, 0, 0, 0], "fremovexattr"),
            // futimens: utimensat with a null path
            (nr::UTIMENSAT, [5, 0, 0, 0, 0, 0], "utimensat"),
        ];
        for (sys_nr, args, name) in fd_calls {
            // the target is a control file of the cgroup2 mount: denied by the implicit rule
            let kernel = FakeNotifier {
                fd_dirs: HashMap::from([(5, "/sys/fs/cgroup/leash-x/cgroup.procs")]),
                ..FakeNotifier::default()
            };
            let mut w = writer();
            metadata_run(|config| {
                super::handle_notification(&kernel, &notif(sys_nr, args), &mut w, config, 1)
                    .unwrap();
            });
            assert_eq!(
                kernel.sent(),
                vec![format!("error:7:{}", libc::EACCES)],
                "{name}"
            );
            let ev = &events(w)[0];
            assert_eq!(ev["syscall"], name);
            assert_eq!(ev["decision"], "deny", "{name}");
            assert_eq!(ev["matched_rule"], "implicit:cgroup", "{name}");
            assert_eq!(ev["fact"]["path"], "/sys/fs/cgroup/leash-x/cgroup.procs");

            // an ordinary file is decided by policy and continues
            let kernel = FakeNotifier {
                fd_dirs: HashMap::from([(5, "/work/file")]),
                ..FakeNotifier::default()
            };
            let mut w = writer();
            let handled = metadata_run(|config| {
                super::handle_notification(&kernel, &notif(sys_nr, args), &mut w, config, 1)
                    .unwrap()
            });
            assert_eq!(handled, Handled::RespondedMutation, "{name}");
            assert_eq!(kernel.sent(), vec!["continue:7".to_string()], "{name}");
            let ev = &events(w)[0];
            assert_eq!(ev["decision"], "allow", "{name}");
            assert_eq!(ev["matched_rule"], "fs.1", "{name}");
        }
    }

    #[test]
    fn an_invalid_operand_is_answered_with_the_kernels_errno_under_its_own_rule() {
        // each call is refused by the kernel before it looks at a path, so the answer is the
        // kernel's errno and the record says why, not failsafe:memory_read with EACCES
        let calls: [(u32, [u64; 6], &str, i32, &str); 3] = [
            (
                nr::SETXATTR,
                [0x1000, 0x2000, 0x3000, 65_537, 0, 0],
                "setxattr",
                libc::E2BIG,
                "E2BIG",
            ),
            (
                nr::FCHMODAT2,
                [flags::AT_FDCWD, 0x1000, 0o600, 0x2000, 0, 0],
                "fchmodat2",
                libc::EINVAL,
                "EINVAL",
            ),
            (
                nr::UTIMENSAT,
                [flags::AT_FDCWD, 0x1000, 0, 0x4000, 0, 0],
                "utimensat",
                libc::EINVAL,
                "EINVAL",
            ),
        ];
        for (sys_nr, args, name, errno, errno_name) in calls {
            let kernel = FakeNotifier::default()
                .with_cstr(0x1000, "/work/f")
                .with_cstr(0x2000, "user.k");
            let mut w = writer();
            let handled = metadata_run(|config| {
                super::handle_notification(&kernel, &notif(sys_nr, args), &mut w, config, 1)
                    .unwrap()
            });
            assert_eq!(handled, Handled::Responded, "{name}");
            assert_eq!(kernel.sent(), vec![format!("error:7:{errno}")], "{name}");
            let ev = &events(w)[0];
            assert_eq!(ev["syscall"], name);
            assert_eq!(ev["decision"], "deny", "{name}");
            assert_eq!(ev["matched_rule"], rule::UNSUPPORTED_OPERAND, "{name}");
            assert_eq!(ev["errno"], errno_name, "{name}");
            assert_eq!(ev["fact"]["path"], "/work/f", "{name}");
        }
    }

    #[test]
    fn an_object_on_a_cgroup2_filesystem_is_denied_by_what_it_is_whatever_its_path() {
        let p = policy("schema_version = 1\n");
        let root = test_root();
        let snapshot = RunConfig::enforce(4242, Attendance::Unattended, &p, root)
            .with_snapshot_integrity(true);
        let eval = cgroup2_identity_deny(&snapshot, true).expect("denied");
        assert_eq!(eval.decision, Decision::Deny);
        assert_eq!(eval.matched.to_string(), "implicit:cgroup");
        // another filesystem is left to the path rule and to policy
        assert!(cgroup2_identity_deny(&snapshot, false).is_none());
        // a run without snapshot integrity is the operator's business
        let plain = RunConfig::enforce(4242, Attendance::Unattended, &p, root);
        assert!(cgroup2_identity_deny(&plain, true).is_none());
        // and so is record-only, which has no implicit rules
        let record = RunConfig::record_only(4242, Attendance::Unattended);
        assert!(cgroup2_identity_deny(&record, true).is_none());
    }

    #[test]
    fn an_unreadable_operand_is_still_a_memory_read_failure() {
        // the xattr name pointer is unmapped, which is case C and stays EACCES
        let kernel = FakeNotifier::default().with_cstr(0x1000, "/work/f");
        let mut w = writer();
        metadata_run(|config| {
            super::handle_notification(
                &kernel,
                &notif(nr::SETXATTR, [0x1000, 0xdead, 0x3000, 1, 0, 0]),
                &mut w,
                config,
                1,
            )
            .unwrap();
        });
        assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::EACCES)]);
        assert_eq!(events(w)[0]["matched_rule"], rule::MEMORY_READ);
    }

    #[test]
    fn a_descriptor_whose_link_looks_harmless_is_denied_by_what_it_is() {
        // the link spells a path nothing denies, as a bind mount alias would; the descriptor
        // is on cgroup2, which fstatfs says whatever the spelling
        let fd_calls: [(u32, [u64; 6], &str); 5] = [
            (nr::FCHMOD, [5, 0o777, 0, 0, 0, 0], "fchmod"),
            (nr::FCHOWN, [5, 0, 0, 0, 0, 0], "fchown"),
            (nr::FSETXATTR, [5, 0x1000, 0x2000, 1, 0, 0], "fsetxattr"),
            (nr::FREMOVEXATTR, [5, 0x1000, 0, 0, 0, 0], "fremovexattr"),
            (nr::UTIMENSAT, [5, 0, 0, 0, 0, 0], "utimensat"),
        ];
        for (sys_nr, args, name) in fd_calls {
            let kernel = FakeNotifier {
                fd_dirs: HashMap::from([(5, "/mnt/alias/cgroup.procs")]),
                fd_facts: HashMap::from([(
                    5,
                    Ok(FdFacts {
                        f_type: CGROUP2,
                        ..ORDINARY_FILE
                    }),
                )]),
                ..FakeNotifier::default()
            };
            let mut w = writer();
            metadata_run(|config| {
                super::handle_notification(&kernel, &notif(sys_nr, args), &mut w, config, 1)
                    .unwrap();
            });
            assert_eq!(
                kernel.sent(),
                vec![format!("error:7:{}", libc::EACCES)],
                "{name}"
            );
            let ev = &events(w)[0];
            assert_eq!(ev["decision"], "deny", "{name}");
            assert_eq!(ev["matched_rule"], "implicit:cgroup", "{name}");
            assert_eq!(ev["fact"]["path"], "/mnt/alias/cgroup.procs", "{name}");
        }
    }

    #[test]
    fn a_descriptor_on_the_state_root_is_denied_whatever_its_link_says() {
        let base = tempfile::tempdir().unwrap();
        let state = base.path().canonicalize().unwrap();
        let root = crate::supervisor::state_root::StateRoot::from_resolved(state.clone()).unwrap();
        let (dev, ino) = {
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::metadata(&state).unwrap();
            (m.dev(), m.ino())
        };
        let p = policy(
            "schema_version = 1\n[[fs]]\npath=\"/**\"\nmode=[\"write\"]\naction=\"allow\"\n",
        );
        let mounts = crate::supervisor::cgroup_mounts::CgroupMounts::from_resolved(vec![
            "/sys/fs/cgroup".into(),
        ])
        .unwrap();
        let config = RunConfig::enforce(4242, Attendance::Unattended, &p, &root)
            .with_snapshot_integrity(true)
            .with_cgroup_mounts(&mounts);
        let kernel = FakeNotifier {
            fd_dirs: HashMap::from([(5, "/mnt/alias")]),
            fd_facts: HashMap::from([(
                5,
                Ok(FdFacts {
                    f_type: 0xEF53,
                    dev,
                    ino,
                }),
            )]),
            ..FakeNotifier::default()
        };
        let mut w = writer();
        super::handle_notification(
            &kernel,
            &notif(nr::FCHMOD, [5, 0o777, 0, 0, 0, 0]),
            &mut w,
            &config,
            1,
        )
        .unwrap();
        assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::EACCES)]);
        let ev = &events(w)[0];
        assert_eq!(ev["decision"], "deny");
        assert_eq!(ev["matched_rule"], "implicit:state_root");
    }

    #[test]
    fn a_descriptor_that_cannot_be_duplicated_denies_and_records() {
        // the link reads back but pidfd_getfd does not (the descriptor was closed meanwhile):
        // nothing the supervisor could not look at is allowed
        let kernel = FakeNotifier {
            fd_dirs: HashMap::from([(5, "/work/file")]),
            fd_facts: HashMap::from([(5, Err(libc::EBADF))]),
            ..FakeNotifier::default()
        };
        let mut w = writer();
        metadata_run(|config| {
            super::handle_notification(
                &kernel,
                &notif(nr::FCHMOD, [5, 0o777, 0, 0, 0, 0]),
                &mut w,
                config,
                1,
            )
            .unwrap();
        });
        assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::EACCES)]);
        let ev = &events(w)[0];
        assert_eq!(ev["decision"], "deny");
        assert_eq!(ev["matched_rule"], rule::MEMORY_READ);
    }

    #[test]
    fn the_identity_deny_follows_the_filesystem_type_and_the_state_root_alone() {
        let p = policy("schema_version = 1\n");
        let root = test_root();
        let snapshot = RunConfig::enforce(4242, Attendance::Unattended, &p, root)
            .with_snapshot_integrity(true);
        let cgroup = FdFacts {
            f_type: CGROUP2,
            ..ORDINARY_FILE
        };
        let eval = fd_identity_deny(&snapshot, &cgroup).expect("cgroup2 is denied");
        assert_eq!(eval.decision, Decision::Deny);
        assert_eq!(eval.matched.to_string(), "implicit:cgroup");
        assert!(fd_identity_deny(&snapshot, &ORDINARY_FILE).is_none());
        // without snapshot integrity the cgroup rule is not armed
        let plain = RunConfig::enforce(4242, Attendance::Unattended, &p, root);
        assert!(fd_identity_deny(&plain, &cgroup).is_none());
        let record = RunConfig::record_only(4242, Attendance::Unattended);
        assert!(fd_identity_deny(&record, &cgroup).is_none());
    }

    #[test]
    fn a_real_descriptor_is_described_by_its_filesystem_and_identity() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        let metadata = std::fs::metadata(&file).unwrap();
        let fd = OwnedFd::from(std::fs::File::open(&file).unwrap());
        let facts = fd_facts(fd).unwrap();
        assert_eq!((facts.dev, facts.ino), (metadata.dev(), metadata.ino()));
        assert_ne!(facts.f_type, CGROUP2, "a temporary file is not on cgroup2");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_descriptor_on_the_cgroup2_mount_is_described_as_cgroup2() {
        let Ok(mounts) = crate::supervisor::cgroup_mounts::CgroupMounts::from_proc_self() else {
            return;
        };
        let Some(mount) = mounts.paths().first() else {
            return;
        };
        let Ok(file) = std::fs::File::open(mount.join("cgroup.controllers")) else {
            return;
        };
        let facts = fd_facts(OwnedFd::from(file)).unwrap();
        assert_eq!(facts.f_type, CGROUP2);
    }

    #[test]
    fn a_descriptor_that_cannot_be_resolved_denies_the_metadata_call() {
        // fd 9 is not in fd_dirs, so its target cannot be read back
        let kernel = FakeNotifier::default();
        let mut w = writer();
        metadata_run(|config| {
            super::handle_notification(
                &kernel,
                &notif(nr::FCHMOD, [9, 0o777, 0, 0, 0, 0]),
                &mut w,
                config,
                1,
            )
            .unwrap();
        });
        assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::EACCES)]);
        assert_eq!(events(w)[0]["matched_rule"], rule::MEMORY_READ);
    }

    #[test]
    fn snapshot_metadata_calls_are_denied_and_recorded_when_the_flag_is_off() {
        let p = policy("schema_version = 1\n");
        let config = RunConfig::enforce(4242, Attendance::Unattended, &p, test_root());
        for &sys_nr in SNAPSHOT_METADATA {
            let kernel = FakeNotifier::default();
            let mut w = writer();
            super::handle_notification(&kernel, &notif(sys_nr, [0; 6]), &mut w, &config, 1)
                .unwrap();
            assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::ENOSYS)]);
            let ev = &events(w)[0];
            assert_eq!(ev["decision"], "deny");
            assert_eq!(ev["matched_rule"], rule::SNAPSHOT_METADATA);
        }
    }

    #[test]
    fn path_metadata_calls_decode_their_operands_from_child_memory() {
        let path = std::path::Path::new("/work/f");
        let mut times = Vec::new();
        for v in [10_i64, 20, 30, 40] {
            times.extend_from_slice(&v.to_ne_bytes());
        }
        let kernel = FakeNotifier::default()
            .with_cstr(0x1000, "user.leash.lock")
            .with_bytes(0x2000, b"value".to_vec())
            .with_bytes(0x3000, times.clone());

        let set = mutation_invocation(
            &kernel,
            nr::LSETXATTR,
            &notif(nr::LSETXATTR, [0, 0x1000, 0x2000, 5, 1, 0]),
            path,
            false,
        )
        .unwrap();
        assert!(matches!(
            set,
            MutationInvocation::Setxattr { ref name, ref value, flags: 1, follow: false }
                if name == b"user.leash.lock" && value == b"value"
        ));
        let oversized = mutation_invocation(
            &kernel,
            nr::SETXATTR,
            &notif(nr::SETXATTR, [0, 0x1000, 0x2000, 65_537, 0, 0]),
            path,
            false,
        );
        assert!(
            matches!(oversized, Err(OperandError::Unsupported(libc::E2BIG))),
            "a value past XATTR_SIZE_MAX is E2BIG, not a memory failure: {oversized:?}"
        );

        let remove = mutation_invocation(
            &kernel,
            nr::REMOVEXATTR,
            &notif(nr::REMOVEXATTR, [0, 0x1000, 0, 0, 0, 0]),
            path,
            false,
        )
        .unwrap();
        assert!(matches!(
            remove,
            MutationInvocation::Removexattr { ref name, follow: true } if name == b"user.leash.lock"
        ));

        let timespec = mutation_invocation(
            &kernel,
            nr::UTIMENSAT,
            &notif(nr::UTIMENSAT, [0, 0, 0x3000, 0x100, 0, 0]),
            path,
            false,
        )
        .unwrap();
        assert!(matches!(
            timespec,
            MutationInvocation::Utimens {
                times: Some([10, 20, 30, 40]),
                flags: 0x100
            }
        ));
        let timeval = mutation_invocation(
            &kernel,
            nr::UTIMES,
            &notif(nr::UTIMES, [0, 0x3000, 0, 0, 0, 0]),
            path,
            false,
        )
        .unwrap();
        assert!(matches!(
            timeval,
            MutationInvocation::Utimens {
                times: Some([10, 20_000, 30, 40_000]),
                flags: 0
            }
        ));
        let now = mutation_invocation(
            &kernel,
            nr::UTIME,
            &notif(nr::UTIME, [0, 0, 0, 0, 0, 0]),
            path,
            false,
        )
        .unwrap();
        assert!(matches!(
            now,
            MutationInvocation::Utimens {
                times: None,
                flags: 0
            }
        ));

        let lchown = mutation_invocation(
            &kernel,
            nr::LCHOWN,
            &notif(nr::LCHOWN, [0, 7, 8, 0, 0, 0]),
            path,
            false,
        )
        .unwrap();
        assert!(matches!(
            lchown,
            MutationInvocation::Chown {
                uid: 7,
                gid: 8,
                flags: AT_SYMLINK_NOFOLLOW
            }
        ));
        let follow = mutation_invocation(
            &kernel,
            nr::FCHMODAT2,
            &notif(nr::FCHMODAT2, [0, 0, 0o600, 0, 0, 0]),
            path,
            false,
        )
        .unwrap();
        assert!(matches!(follow, MutationInvocation::Chmod { mode: 0o600 }));
        let nofollow = mutation_invocation(
            &kernel,
            nr::FCHMODAT2,
            &notif(nr::FCHMODAT2, [0, 0, 0o600, 0x100, 0, 0]),
            path,
            false,
        )
        .unwrap();
        assert!(matches!(
            nofollow,
            MutationInvocation::ChmodNoFollow { mode: 0o600 }
        ));
        // AT_EMPTY_PATH only matters when the path is empty: the kernel ignores it otherwise
        let ignored = mutation_invocation(
            &kernel,
            nr::FCHMODAT2,
            &notif(nr::FCHMODAT2, [0, 0, 0o600, 0x1000, 0, 0]),
            path,
            false,
        )
        .unwrap();
        assert!(matches!(ignored, MutationInvocation::Chmod { mode: 0o600 }));
        let empty = mutation_invocation(
            &kernel,
            nr::FCHMODAT2,
            &notif(nr::FCHMODAT2, [0, 0, 0o600, 0x1000, 0, 0]),
            path,
            true,
        )
        .unwrap();
        assert!(
            matches!(empty, MutationInvocation::ChmodNoFollow { mode: 0o600 }),
            "an empty path names the descriptor's own object: {empty:?}"
        );
        let unknown_flag = mutation_invocation(
            &kernel,
            nr::FCHMODAT2,
            &notif(nr::FCHMODAT2, [0, 0, 0o600, 0x2000, 0, 0]),
            path,
            false,
        );
        assert!(
            matches!(unknown_flag, Err(OperandError::Unsupported(libc::EINVAL))),
            "{unknown_flag:?}"
        );

        let utimens_ignored = mutation_invocation(
            &kernel,
            nr::UTIMENSAT,
            &notif(nr::UTIMENSAT, [0, 0, 0x3000, 0x1000, 0, 0]),
            path,
            false,
        )
        .unwrap();
        assert!(matches!(
            utimens_ignored,
            MutationInvocation::Utimens { flags: 0, .. }
        ));
        let utimens_empty = mutation_invocation(
            &kernel,
            nr::UTIMENSAT,
            &notif(nr::UTIMENSAT, [0, 0, 0x3000, 0x1000, 0, 0]),
            path,
            true,
        )
        .unwrap();
        assert!(
            matches!(
                utimens_empty,
                MutationInvocation::Utimens {
                    flags: AT_SYMLINK_NOFOLLOW,
                    ..
                }
            ),
            "AT_EMPTY_PATH with an empty path acts on the descriptor's object: {utimens_empty:?}"
        );
        let utimens_bad = mutation_invocation(
            &kernel,
            nr::UTIMENSAT,
            &notif(nr::UTIMENSAT, [0, 0, 0x3000, 0x4000, 0, 0]),
            path,
            false,
        );
        assert!(
            matches!(utimens_bad, Err(OperandError::Unsupported(libc::EINVAL))),
            "{utimens_bad:?}"
        );
    }

    #[test]
    fn the_supervisor_proc_tree_is_denied_before_policy_under_its_own_rule() {
        let p = policy(
            "schema_version = 1\n\
             [[fs]]\npath=\"/**\"\nmode=[\"read\",\"write\",\"create\",\"delete\"]\naction=\"allow\"\n",
        );
        let root = crate::supervisor::state_root::StateRoot::from_resolved("/var/leash".into())
            .unwrap()
            .with_supervisor_pids([100, 200]);
        let config = RunConfig::enforce(4242, Attendance::Unattended, &p, &root);
        for path in ["/proc/100/mem", "/proc/200/task/201/fd/3", "/proc/100"] {
            let mut asks = Vec::new();
            let eval = evaluate_operand(
                &config,
                &Request::Fs {
                    path,
                    access: &[crate::recorder::FsAccess::Read],
                },
                false,
                &mut asks,
            );
            assert_eq!(eval.decision, Decision::Deny, "{path}");
            assert_eq!(
                eval.matched.to_string(),
                "implicit:supervisor_proc",
                "{path}"
            );
        }
        let mut asks = Vec::new();
        let other = evaluate_operand(
            &config,
            &Request::Fs {
                path: "/proc/1000/mem",
                access: &[crate::recorder::FsAccess::Read],
            },
            false,
            &mut asks,
        );
        assert_eq!(other.decision, Decision::Allow);
    }

    #[test]
    fn a_run_without_a_state_root_is_not_subject_to_the_implicit_deny() {
        let config = RunConfig::record_only(4242, Attendance::Unattended);
        let decision = resolve_decision(
            &config,
            &Request::Fs {
                path: "/var/leash/runs/r/trace.jsonl",
                access: &[crate::recorder::FsAccess::Read],
            },
        );
        assert_eq!(decision.response_decision, Decision::Allow);
    }

    #[test]
    fn unattended_ask_resolves_to_deny_without_prompting() {
        let p = policy(
            "schema_version = 1\n\
             [[fs]]\npath=\"/etc/**\"\nmode=[\"read\"]\naction=\"ask\"\n",
        );
        let config = RunConfig::enforce(4242, Attendance::Unattended, &p, test_root());
        let decision = resolve_decision(
            &config,
            &Request::Fs {
                path: "/etc/hosts",
                access: &[crate::recorder::FsAccess::Read],
            },
        );

        assert_eq!(decision.event_decision, Decision::Ask);
        assert_eq!(decision.response_decision, Decision::Deny);
        assert_eq!(decision.ask_resolution, Some(AskResolution::Unattended));
        assert_eq!(decision.matched_rule, "fs.1");
    }

    fn attended_config<'a>(
        policy: &'a Policy,
        prompter: &'a dyn Fn(&[crate::supervisor::ask::PendingAsk], Duration) -> AskResolution,
    ) -> RunConfig<'a> {
        let mut config = RunConfig::enforce(4242, Attendance::Attended, policy, test_root());
        config.prompter = prompter;
        config
    }

    #[test]
    fn an_approved_ask_realizes_the_allow() {
        let p = policy(
            "schema_version = 1\n\
             [[fs]]\npath=\"/etc/**\"\nmode=[\"read\"]\naction=\"ask\"\n",
        );
        let config = attended_config(&p, &|_asks, _timeout| AskResolution::Approved);
        let decision = resolve_decision(
            &config,
            &Request::Fs {
                path: "/etc/hosts",
                access: &[crate::recorder::FsAccess::Read],
            },
        );

        assert_eq!(decision.event_decision, Decision::Ask);
        assert_eq!(decision.response_decision, Decision::Allow);
        assert_eq!(decision.ask_resolution, Some(AskResolution::Approved));
        assert_eq!(decision.matched_rule, "fs.1");
    }

    #[test]
    fn a_denied_ask_and_a_timed_out_ask_both_deny() {
        let p = policy(
            "schema_version = 1\n\
             [[fs]]\npath=\"/etc/**\"\nmode=[\"read\"]\naction=\"ask\"\n",
        );
        for resolution in [AskResolution::Denied, AskResolution::TimedOut] {
            let prompter = move |_asks: &[crate::supervisor::ask::PendingAsk], _timeout| resolution;
            let config = attended_config(&p, &prompter);
            let decision = resolve_decision(
                &config,
                &Request::Fs {
                    path: "/etc/hosts",
                    access: &[crate::recorder::FsAccess::Read],
                },
            );

            assert_eq!(decision.event_decision, Decision::Ask);
            assert_eq!(decision.response_decision, Decision::Deny);
            assert_eq!(decision.ask_resolution, Some(resolution));
        }
    }

    #[test]
    fn one_held_syscall_prompts_once_for_every_ask_matched_access() {
        let p = policy(
            "schema_version = 1\n\
             [[fs]]\npath=\"/etc/**\"\nmode=[\"read\",\"write\"]\naction=\"ask\"\n",
        );
        let calls = std::cell::Cell::new(0);
        let prompter = &|asks: &[crate::supervisor::ask::PendingAsk], _timeout| {
            calls.set(calls.get() + 1);
            assert_eq!(asks.len(), 2, "both ask-matched accesses listed together");
            assert!(asks.iter().all(|a| a.rule == "fs.1"));
            AskResolution::Approved
        };
        let config = attended_config(&p, prompter);

        // an O_RDWR open evaluates read and write for one held syscall; both land in the
        // same prompt and one answer settles both (notify-loop.md section 5)
        let mut asks = Vec::new();
        let read = evaluate_tracked(
            &config,
            &Request::Fs {
                path: "/etc/hosts",
                access: &[crate::recorder::FsAccess::Read],
            },
            &mut asks,
        );
        let write = evaluate_tracked(
            &config,
            &Request::Fs {
                path: "/etc/hosts",
                access: &[crate::recorder::FsAccess::Write],
            },
            &mut asks,
        );
        let resolution = settle_asks(&config, &asks);
        let read = finalize_decision(read, resolution);
        let write = finalize_decision(write, resolution);

        assert_eq!(calls.get(), 1, "one prompt per syscall");
        for decision in [read, write] {
            assert_eq!(decision.event_decision, Decision::Ask);
            assert_eq!(decision.response_decision, Decision::Allow);
            assert_eq!(decision.ask_resolution, Some(AskResolution::Approved));
        }
    }

    #[test]
    fn an_unattended_run_never_calls_the_prompter() {
        let p = policy(
            "schema_version = 1\n\
             [[fs]]\npath=\"/etc/**\"\nmode=[\"read\"]\naction=\"ask\"\n",
        );
        let mut config = RunConfig::enforce(4242, Attendance::Unattended, &p, test_root());
        config.prompter = &|_asks, _timeout| panic!("unattended runs must not prompt");
        let decision = resolve_decision(
            &config,
            &Request::Fs {
                path: "/etc/hosts",
                access: &[crate::recorder::FsAccess::Read],
            },
        );

        assert_eq!(decision.response_decision, Decision::Deny);
        assert_eq!(decision.ask_resolution, Some(AskResolution::Unattended));
    }

    #[test]
    fn no_ask_means_no_prompt() {
        let p = policy("schema_version = 1\n");
        let mut config = RunConfig::enforce(4242, Attendance::Attended, &p, test_root());
        config.prompter = &|_asks, _timeout| panic!("a run without asks must not prompt");
        let decision = resolve_decision(
            &config,
            &Request::Fs {
                path: "/etc/hosts",
                access: &[crate::recorder::FsAccess::Read],
            },
        );

        assert_eq!(decision.event_decision, Decision::Deny);
        assert_eq!(decision.ask_resolution, None);
    }

    #[test]
    fn execve_is_recorded_as_an_exec_fact() {
        let kernel = FakeNotifier::default().with_cstr(0x1000, "/usr/bin/make");
        let mut w = writer();
        handle_notification(
            &kernel,
            &notif(nr::EXECVE, [0x1000, 0, 0, 0, 0, 0]),
            &mut w,
            1_000,
        )
        .unwrap();
        let ev = &events(w)[0];
        assert_eq!(ev["syscall"], "execve");
        assert_eq!(ev["fact"]["family"], "exec");
        assert_eq!(ev["fact"]["binary"], "/usr/bin/make");
        assert_eq!(ev["decision"], "allow");
        assert_eq!(kernel.sent(), vec!["continue:7"]);
    }

    #[test]
    fn symlink_records_the_target_verbatim_and_anchors_the_link_path() {
        let kernel = FakeNotifier {
            cwd: "/work",
            ..FakeNotifier::default()
        }
        .with_cstr(0x1000, "../target")
        .with_cstr(0x2000, "link");
        let mut w = writer();
        handle_notification(
            &kernel,
            &notif(nr::SYMLINK, [0x1000, 0x2000, 0, 0, 0, 0]),
            &mut w,
            1_000,
        )
        .unwrap();
        let ev = &events(w)[0];
        assert_eq!(
            ev["fact"]["path"], "../target",
            "stored content, not resolved"
        );
        assert_eq!(ev["fact"]["dest"], "/work/link");
        assert_eq!(ev["fact"]["access"], serde_json::json!(["create"]));
    }

    #[test]
    fn access_kinds_follow_the_syscall_family() {
        let kernel = FakeNotifier {
            cwd: "/w",
            ..FakeNotifier::default()
        }
        .with_cstr(0x1000, "/w/x");
        let mut w = writer();
        for (n, args) in [
            (nr::UNLINK, [0x1000u64, 0, 0, 0, 0, 0]),
            (nr::MKDIR, [0x1000, 0, 0, 0, 0, 0]),
            (nr::CHMOD, [0x1000, 0o644, 0, 0, 0, 0]),
            (nr::TRUNCATE, [0x1000, 0, 0, 0, 0, 0]),
        ] {
            handle_notification(&kernel, &notif(n, args), &mut w, 1_000).unwrap();
        }
        let evs = events(w);
        assert_eq!(evs[0]["fact"]["access"], serde_json::json!(["delete"]));
        assert_eq!(evs[1]["fact"]["access"], serde_json::json!(["create"]));
        assert_eq!(evs[2]["fact"]["access"], serde_json::json!(["write"]));
        assert_eq!(evs[3]["fact"]["access"], serde_json::json!(["write"]));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rename_exchange_requires_delete_and_create_on_both_operands() {
        let invocation = FsInvocation::Mutation(MutationInvocation::Rename { flags: 2 });
        assert_eq!(
            primary_access(&invocation, &[]),
            vec![
                crate::recorder::FsAccess::Delete,
                crate::recorder::FsAccess::Create
            ]
        );
        assert_eq!(
            secondary_access(&invocation, true),
            vec![
                crate::recorder::FsAccess::Delete,
                crate::recorder::FsAccess::Create
            ]
        );
    }
}
