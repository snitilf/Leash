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
use std::os::fd::{BorrowedFd, OwnedFd, RawFd};
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
use crate::sandbox::filter::{AUDIT_ARCH_X86_64, DENIED_RECORDED, X32_SYSCALL_BIT, nr};
#[cfg(target_os = "linux")]
use crate::supervisor::broker::{
    BrokerResult, BrokerResultOrPath, MutationOperation, NetworkOperation,
};
use crate::supervisor::fact::{AccessSpec, FsShape, PathArg, flags, fs_shape, syscall_name};
use crate::supervisor::mem::MemReadError;
#[cfg(target_os = "linux")]
use crate::supervisor::notify::SECCOMP_ADDFD_FLAG_SEND;
use crate::supervisor::notify::SeccompNotif;

const ASK_TIMEOUT: Duration = Duration::from_secs(60);
const CLONE_ARGS_MIN_SIZE: u64 = 8;
const CLONE_ARGS_MAX_SIZE: u64 = 88;
const OPEN_HOW_SIZE: usize = 24;

#[derive(Debug, Clone)]
enum FsInvocation {
    Open {
        flags: u64,
        mode: u32,
        unsupported_errno: Option<i32>,
    },
    Mutation(MutationInvocation),
}

#[derive(Debug, Clone)]
enum MutationInvocation {
    Truncate { length: i64 },
    Rename { flags: u32 },
    Mkdir { mode: u32 },
    Unlink { flags: i32 },
    Link { flags: i32 },
    Symlink { target: Vec<u8> },
    Chmod { mode: u32 },
    Chown { uid: u32, gid: u32, flags: i32 },
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
}

/// how the run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunOutcome {
    /// raw wait status of the direct child.
    pub wait_status: i32,
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
    /// enforce mode reached the loop without a loaded policy.
    #[error("enforce mode requires a loaded policy")]
    EnforceWithoutPolicy,
    /// the confined side-effect broker failed, so the run aborts fail-closed.
    #[cfg(target_os = "linux")]
    #[error("confined realization broker failed: {0}")]
    Broker(#[from] crate::supervisor::broker::BrokerError),
}

/// immutable inputs for one notify-loop run.
#[derive(Debug, Clone, Copy)]
pub struct RunConfig<'a> {
    /// record-only or enforce
    pub mode: crate::recorder::Mode,
    /// loaded policy; required in enforce mode and absent for current record-only CLI runs
    pub policy: Option<&'a Policy>,
    /// whether an operator is available for ask decisions
    pub attendance: Attendance,
    /// maximum wait for an attended ask
    pub ask_timeout: Duration,
    /// root of the supervised process tree
    pub root_pid: u32,
    /// confined side-effect broker; required in enforce mode
    #[cfg(target_os = "linux")]
    pub broker: Option<&'a RefCell<crate::supervisor::broker::Broker>>,
    /// pre-resolved exact hostname rules
    pub resolved_hosts: Option<&'a HashMap<String, Vec<IpAddr>>>,
}

impl<'a> RunConfig<'a> {
    /// current policy-less record-only behavior.
    pub fn record_only(root_pid: u32, attendance: Attendance) -> Self {
        Self {
            mode: crate::recorder::Mode::RecordOnly,
            policy: None,
            attendance,
            ask_timeout: ASK_TIMEOUT,
            root_pid,
            #[cfg(target_os = "linux")]
            broker: None,
            resolved_hosts: None,
        }
    }

    /// enforce with a validated policy.
    pub fn enforce(root_pid: u32, attendance: Attendance, policy: &'a Policy) -> Self {
        Self {
            mode: crate::recorder::Mode::Enforce,
            policy: Some(policy),
            attendance,
            ask_timeout: ASK_TIMEOUT,
            root_pid,
            #[cfg(target_os = "linux")]
            broker: None,
            resolved_hosts: None,
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
    ) -> Self {
        Self {
            mode: crate::recorder::Mode::Enforce,
            policy: Some(policy),
            attendance,
            ask_timeout: ASK_TIMEOUT,
            root_pid,
            broker: Some(broker),
            resolved_hosts: Some(resolved_hosts),
        }
    }

    fn validate(self) -> Result<Self, RunError> {
        if self.mode == crate::recorder::Mode::Enforce && self.policy.is_none() {
            return Err(RunError::EnforceWithoutPolicy);
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
    /// a response was sent (an event was recorded unless the syscall is silent)
    Responded,
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

fn mutation_invocation(
    sys_nr: u32,
    notif: &SeccompNotif,
    path: &std::path::Path,
) -> Result<MutationInvocation, MemReadError> {
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
        _ => {
            return Err(MemReadError::Io(io::Error::from_raw_os_error(libc::ENOSYS)));
        }
    };
    Ok(invocation)
}

fn resolve_decision(config: &RunConfig<'_>, request: &Request<'_>) -> ResolvedDecision {
    let eval = match config.policy {
        Some(policy) => policy.evaluate(request, config.mode),
        None => Evaluation {
            decision: Decision::Allow,
            matched: crate::policy::MatchId::BaseRecordOnly,
            would_deny: None,
        },
    };
    if eval.decision != Decision::Ask {
        return ResolvedDecision {
            event_decision: eval.decision,
            response_decision: eval.decision,
            ask_resolution: None,
            matched_rule: eval.matched.to_string(),
            would_deny: eval.would_deny,
        };
    }

    let ask_resolution = resolve_ask(config);
    let response_decision = match ask_resolution {
        AskResolution::Approved => Decision::Allow,
        AskResolution::Denied | AskResolution::TimedOut | AskResolution::Unattended => {
            Decision::Deny
        }
    };
    ResolvedDecision {
        event_decision: Decision::Ask,
        response_decision,
        ask_resolution: Some(ask_resolution),
        matched_rule: eval.matched.to_string(),
        would_deny: eval.would_deny,
    }
}

fn resolve_ask(config: &RunConfig<'_>) -> AskResolution {
    if config.attendance == Attendance::Unattended {
        return AskResolution::Unattended;
    }
    let _ = config.ask_timeout;
    AskResolution::Denied
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
        MemReadError,
    > = (|| {
        let path = read_anchored(kernel, notif, &shape.path)?;
        let dest = match &shape.dest {
            Some(arg) => Some(read_anchored(kernel, notif, arg)?),
            None => None,
        };
        let (access, invocation) = match shape.access {
            AccessSpec::Fixed(list) => (
                list.to_vec(),
                FsInvocation::Mutation(mutation_invocation(sys_nr, notif, &path)?),
            ),
            AccessSpec::OpenFlags { arg } => {
                let flags = notif.data.args[arg];
                (
                    crate::supervisor::fact::open_flags_access(flags),
                    FsInvocation::Open {
                        flags,
                        mode: open_mode(sys_nr, notif),
                        unsupported_errno: None,
                    },
                )
            }
            AccessSpec::OpenHow { arg } => {
                let size = usize::try_from(notif.data.args[3]).unwrap_or(0);
                if size < OPEN_HOW_SIZE {
                    return Err(MemReadError::Short {
                        wanted: OPEN_HOW_SIZE,
                        got: size,
                    });
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
                } else if resolve != 0 {
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
            Ok(Handled::Responded)
        }
        // case C: a fact that cannot be trusted cannot be allowed (I4).
        Err(_) => {
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
        match broker
            .borrow_mut()
            .prepare_path(input, secondary_follow, secondary_missing)?
        {
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
    let primary_decision =
        resolve_required_fs(config, &primary_identity, &primary_access, primary_operand);
    let secondary_decision = secondary.as_ref().map(|path| {
        let required = secondary_access(&invocation, path.exists());
        resolve_required_fs(config, path.identity(), &required, FsOperand::Dest)
    });
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
    let result = match invocation {
        FsInvocation::Open {
            flags,
            mode,
            unsupported_errno,
        } => {
            if let Some(errno) = unsupported_errno {
                broker.borrow_mut().release(primary)?;
                BrokerResult::Errno(errno)
            } else {
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
    respond_broker_result(kernel, notif.id, result, close_on_exec)?;
    Ok(Handled::Responded)
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
        FsInvocation::Mutation(MutationInvocation::Chown { .. }) => (false, false, false, false),
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
            | MutationInvocation::Chown { .. },
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

#[cfg(target_os = "linux")]
fn resolve_required_fs(
    config: &RunConfig<'_>,
    path: &std::path::Path,
    access: &[crate::recorder::FsAccess],
    operand: FsOperand,
) -> ResolvedOperand {
    let path_text = path.to_string_lossy();
    let mut first_allow = None;
    let mut first_deny = None;
    let mut evidence = Vec::with_capacity(access.len());
    for required in access {
        let decision = resolve_decision(
            config,
            &Request::Fs {
                path: &path_text,
                access: std::slice::from_ref(required),
            },
        );
        evidence.push(FsOperandDecision {
            operand,
            access: *required,
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
    record(
        writer,
        ts,
        notif,
        syscall,
        Fact::Fs { path, access, dest },
        &fixed_decision(Decision::Deny, rule::REALIZATION),
    )?;
    tolerate_dead(kernel.send_error(notif.id, errno))?;
    Ok(Handled::Responded)
}

#[cfg(target_os = "linux")]
fn respond_broker_result<N: Notifier>(
    kernel: &N,
    id: u64,
    result: BrokerResult,
    newfd_flags: u32,
) -> Result<(), RunError> {
    match result {
        BrokerResult::Value(value) => tolerate_dead(kernel.send_success(id, value)),
        BrokerResult::Fd(fd) => {
            match kernel.send_addfd(id, fd.as_fd(), SECCOMP_ADDFD_FLAG_SEND, newfd_flags) {
                Ok(_) => Ok(()),
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
                Err(error) => Err(RunError::Notify(error)),
            }
        }
        BrokerResult::Errno(errno) => tolerate_dead(kernel.send_error(id, errno)),
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
        respond_broker_result(kernel, notif.id, result, 0)?;
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
    let bytes = kernel.read_path(notif.pid, notif.data.args[arg.path_arg])?;
    let path = bytes_to_path(bytes);
    if path.is_absolute() || !arg.anchor {
        return Ok(path);
    }
    let anchor = match arg.dirfd_arg {
        Some(i) if u64::from(notif.data.args[i] as u32) != flags::AT_FDCWD => {
            DirAnchor::Fd(notif.data.args[i] as u32)
        }
        _ => DirAnchor::Cwd,
    };
    match kernel.dir_prefix(notif.pid, anchor) {
        Ok(prefix) => Ok(prefix.join(path)),
        Err(_) => Ok(path),
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
        }),
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub use linux::run_loop;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::supervisor::mem::proc::ChildMem;
    use crate::supervisor::notify::NotifyFd;
    use crate::supervisor::spawn::SupervisedChild;
    use std::os::fd::AsRawFd;
    use std::time::SystemTime;

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
    pub fn run_loop<S: TraceSink>(
        child: SupervisedChild,
        config: RunConfig<'_>,
        writer: &mut TraceWriter<S>,
    ) -> Result<RunOutcome, RunError> {
        let config = match config.validate() {
            Ok(config) => config,
            Err(e) => {
                abort_run(&child);
                return Err(e);
            }
        };
        let kernel = ProcNotifier {
            notify: &child.notify,
        };

        loop {
            let mut pfd = libc::pollfd {
                fd: child.notify.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll reads one pollfd we own; the timeout bounds the wait so a
            // wedged fd cannot hang the supervisor without the loop noticing (arc H).
            let rc = unsafe { libc::poll(&raw mut pfd, 1, 100) };
            if rc < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue; // case A at the poll: nothing dequeued
                }
                abort_run(&child);
                return Err(RunError::Notify(e));
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
                    Ok(_) => {}
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
        Ok(RunOutcome { wait_status })
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
    use super::*;
    use crate::supervisor::notify::SeccompData;
    use serde_json::Value;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io::Write;

    /// a scripted kernel side: fixed child memory, programmable id_valid answers, and a
    /// log of every response sent.
    #[derive(Default)]
    struct FakeNotifier {
        mem: HashMap<u64, Vec<u8>>,
        cwd: &'static str,
        fd_dirs: HashMap<u32, &'static str>,
        // answers consumed per id_valid call; empty means "always valid"
        id_valid_script: RefCell<Vec<bool>>,
        sent: RefCell<Vec<String>>,
        send_errno: Option<i32>, // error every send with this errno
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
            self.sent
                .borrow_mut()
                .push(format!("addfd:{id}:{flags}:{newfd_flags}"));
            Ok(9)
        }
        fn duplicate_fd(&self, _pid: u32, _target_fd: RawFd) -> io::Result<OwnedFd> {
            Err(io::Error::from_raw_os_error(libc::EBADF))
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

        assert_eq!(handled, Handled::Responded);
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
        let refused = RunConfig::enforce(4242, Attendance::Unattended, &p)
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

    /// the enforce leg of the same arc. ADR-0019 scopes exactly one arc of the
    /// fail-closed enumeration by mode; the record-only leg above allows, and here the
    /// identical untrusted fact denies fail-closed under `failsafe:memory_read`
    /// (`notify-loop.md` section 4 case C, spec FR-9, trace.md section 2).
    #[test]
    fn network_unreadable_sockaddr_records_raw_and_denies_in_enforce() {
        let kernel = FakeNotifier::default();
        let p = policy("schema_version = 1\n");
        let config = RunConfig::enforce(4242, Attendance::Unattended, &p);
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
                RunConfig::enforce(4242, Attendance::Unattended, &p)
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
            RunConfig::enforce(4242, Attendance::Unattended, &p),
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
        let config = RunConfig::enforce(4242, Attendance::Unattended, &p);
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
    fn unattended_ask_resolves_to_deny_without_prompting() {
        let p = policy(
            "schema_version = 1\n\
             [[fs]]\npath=\"/etc/**\"\nmode=[\"read\"]\naction=\"ask\"\n",
        );
        let config = RunConfig::enforce(4242, Attendance::Unattended, &p);
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
