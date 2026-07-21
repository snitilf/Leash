//! the notify decision loop, record-only (docs/design/notify-loop.md; FR-2, FR-4, FR-9).
//!
//! assumptions: single decision thread (ADR-0011): one notification is received,
//! decided, recorded, and responded before the next. record precedes respond (section 3):
//! an action the recorder cannot write is denied and the run aborts (case E). every
//! pointer argument is read bounded and bracketed by ID_VALID (section 2). record-only
//! allows are realized with CONTINUE (ADR-0017); the denied-and-recorded set and every
//! untrusted-fact path deny in this mode too. the fail-closed arcs A-I of section 4 are
//! the contract of this module; each is named where it is handled.
//!
//! the per-notification state machine is written against the [`Notifier`] seam so the
//! arcs are unit-tested deterministically on any host; only the real notify-fd and /proc
//! wiring and `run_loop` itself are linux-only. on a non-linux host the state machine's
//! only consumer is the unit tests, hence the scoped dead-code allow.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::policy::{Evaluation, Policy, Request};
use crate::recorder::{
    AskResolution, Attendance, Decision, EventBody, Fact, RecorderError, SyscallEvent, TraceSink,
    TraceWriter,
};
use crate::sandbox::filter::{AUDIT_ARCH_X86_64, DENIED_RECORDED, X32_SYSCALL_BIT, nr};
use crate::supervisor::fact::{AccessSpec, FsShape, PathArg, flags, fs_shape, syscall_name};
use crate::supervisor::mem::MemReadError;
#[cfg(target_os = "linux")]
use crate::supervisor::notify::SECCOMP_ADDFD_FLAG_SEND;
use crate::supervisor::notify::SeccompNotif;

const ASK_TIMEOUT: Duration = Duration::from_secs(60);

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
    /// enforce mode reached the loop without a loaded policy.
    #[error("enforce mode requires a loaded policy")]
    EnforceWithoutPolicy,
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
        }
    }

    fn validate(self) -> Result<Self, RunError> {
        if self.mode == crate::recorder::Mode::Enforce && self.policy.is_none() {
            return Err(RunError::EnforceWithoutPolicy);
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
    /// complete the trapped syscall with a successful scalar return value.
    fn send_success(&self, id: u64, value: i64) -> io::Result<()>;
    /// complete an fd-returning syscall by injecting a supervisor-owned fd.
    fn send_addfd(&self, id: u64, srcfd: BorrowedFd<'_>, flags: u32) -> io::Result<i32>;
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

struct ResolvedDecision {
    event_decision: Decision,
    response_decision: Decision,
    ask_resolution: Option<AskResolution>,
    matched_rule: String,
    would_deny: Option<bool>,
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

    #[cfg(target_os = "linux")]
    {
        return prompt_for_ask(config.ask_timeout);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config.ask_timeout;
        AskResolution::TimedOut
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
        record(
            writer,
            ts,
            notif,
            name,
            Fact::Raw {},
            &fixed_decision(Decision::Deny, rule::IO_URING),
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
            FsResponse,
        ),
        MemReadError,
    > = (|| {
        let path = read_anchored(kernel, notif, &shape.path)?;
        let dest = match &shape.dest {
            Some(arg) => Some(read_anchored(kernel, notif, arg)?),
            None => None,
        };
        let (access, response) = match shape.access {
            AccessSpec::Fixed(list) => (
                list.to_vec(),
                FsResponse::Mutation(mutation_call(sys_nr, notif)),
            ),
            AccessSpec::OpenFlags { arg } => {
                let flags = notif.data.args[arg];
                (
                    crate::supervisor::fact::open_flags_access(flags),
                    FsResponse::Open { flags },
                )
            }
            AccessSpec::OpenHow { arg } => {
                let raw_flags = kernel.read_u64(notif.pid, notif.data.args[arg])?;
                (
                    crate::supervisor::fact::open_flags_access(raw_flags),
                    FsResponse::Open { flags: raw_flags },
                )
            }
        };
        Ok((path, dest, access, response))
    })();

    // bracket close: a read spanning the child's death is discarded (case B).
    if !kernel.id_valid(notif.id).map_err(RunError::Notify)? {
        return Ok(Handled::Dropped);
    }

    match gathered {
        Ok((path, dest, access, response)) => {
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
            respond_fs(kernel, notif, response, &path, dest.as_deref(), &decision)?;
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
    _config: &RunConfig<'_>,
    ts: u64,
    sys_nr: u32,
) -> Result<Handled, RunError> {
    let name = syscall_name(sys_nr).unwrap_or("unknown");
    let flags = if sys_nr == nr::CLONE {
        Some(notif.data.args[0])
    } else if sys_nr == nr::CLONE3 {
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
        &fixed_decision(Decision::Allow, rule::RECORD_ONLY),
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
    if sys_nr == nr::PIDFD_GETFD {
        record(
            writer,
            ts,
            notif,
            name,
            Fact::CrossProcess { target_pid: None },
            &fixed_decision(Decision::Deny, "sr2:pidfd_getfd"),
        )?;
        tolerate_dead(kernel.send_error(notif.id, libc::EPERM))?;
        return Ok(Handled::Responded);
    }

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
    let decision = if in_tree {
        fixed_decision(Decision::Allow, "base:process_tree")
    } else {
        fixed_decision(Decision::Deny, "sr2:process_tree")
    };
    record(
        writer,
        ts,
        notif,
        name,
        Fact::CrossProcess {
            target_pid: Some(target_pid),
        },
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
    };

    if !kernel.id_valid(notif.id).map_err(RunError::Notify)? {
        return Ok(Handled::Dropped);
    }
    let sockaddr = kernel.read_bytes(notif.pid, notif.data.args[addr_arg], len);
    if !kernel.id_valid(notif.id).map_err(RunError::Notify)? {
        return Ok(Handled::Dropped);
    }
    let (ip, port) = match sockaddr.and_then(parse_sockaddr) {
        Ok(dest) => dest,
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
    };
    let host = ip.to_string();
    let decision = resolve_decision(
        config,
        &Request::Net {
            ip,
            hostname: None,
            port,
        },
    );
    record(writer, ts, notif, name, Fact::Net { host, port }, &decision)?;
    respond_network(kernel, notif, sys_nr, ip, port, &decision)?;
    Ok(Handled::Responded)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FsResponse {
    Open { flags: u64 },
    Mutation(MutationCall),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MutationCall {
    Truncate { len: i64 },
    Rename,
    RenameAt2 { flags: u64 },
    Mkdir { mode: u32 },
    Rmdir,
    Unlink,
    UnlinkAt { flags: u64 },
    Link,
    LinkAt { flags: u64 },
    Symlink,
    Chmod { mode: u32 },
    Chown { uid: u32, gid: u32 },
    FchownAt { uid: u32, gid: u32, flags: u64 },
    None,
}

fn mutation_call(sys_nr: u32, notif: &SeccompNotif) -> MutationCall {
    match sys_nr {
        nr::TRUNCATE => MutationCall::Truncate {
            len: notif.data.args[1] as i64,
        },
        nr::RENAME | nr::RENAMEAT => MutationCall::Rename,
        nr::RENAMEAT2 => MutationCall::RenameAt2 {
            flags: notif.data.args[4],
        },
        nr::MKDIR => MutationCall::Mkdir {
            mode: notif.data.args[1] as u32,
        },
        nr::MKDIRAT => MutationCall::Mkdir {
            mode: notif.data.args[2] as u32,
        },
        nr::RMDIR => MutationCall::Rmdir,
        nr::UNLINK => MutationCall::Unlink,
        nr::UNLINKAT => MutationCall::UnlinkAt {
            flags: notif.data.args[2],
        },
        nr::LINK => MutationCall::Link,
        nr::LINKAT => MutationCall::LinkAt {
            flags: notif.data.args[4],
        },
        nr::SYMLINK | nr::SYMLINKAT => MutationCall::Symlink,
        nr::CHMOD => MutationCall::Chmod {
            mode: notif.data.args[1] as u32,
        },
        nr::FCHMODAT => MutationCall::Chmod {
            mode: notif.data.args[2] as u32,
        },
        nr::CHOWN => MutationCall::Chown {
            uid: notif.data.args[1] as u32,
            gid: notif.data.args[2] as u32,
        },
        nr::FCHOWNAT => MutationCall::FchownAt {
            uid: notif.data.args[2] as u32,
            gid: notif.data.args[3] as u32,
            flags: notif.data.args[4],
        },
        _ => MutationCall::None,
    }
}

fn respond_fs<N: Notifier>(
    kernel: &N,
    notif: &SeccompNotif,
    response: FsResponse,
    path: &Path,
    dest: Option<&Path>,
    decision: &ResolvedDecision,
) -> Result<(), RunError> {
    if decision.response_decision != Decision::Allow {
        return tolerate_dead(kernel.send_error(notif.id, libc::EACCES));
    }
    match response {
        FsResponse::Open { flags } => respond_open(kernel, notif, path, flags),
        FsResponse::Mutation(call) => respond_mutation(kernel, notif, call, path, dest),
    }
}

fn respond_open<N: Notifier>(
    kernel: &N,
    notif: &SeccompNotif,
    path: &Path,
    flags: u64,
) -> Result<(), RunError> {
    #[cfg(target_os = "linux")]
    {
        match open_for_addfd(path, flags) {
            Ok(fd) => {
                let addfd_flags = SECCOMP_ADDFD_FLAG_SEND;
                match kernel.send_addfd(notif.id, fd.as_fd(), addfd_flags) {
                    Ok(_) => Ok(()),
                    Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(()),
                    Err(e) => Err(RunError::Notify(e)),
                }
            }
            Err(errno) => tolerate_dead(kernel.send_error(notif.id, errno)),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, flags);
        tolerate_dead(kernel.send_continue(notif.id))
    }
}

fn respond_mutation<N: Notifier>(
    kernel: &N,
    notif: &SeccompNotif,
    call: MutationCall,
    path: &Path,
    dest: Option<&Path>,
) -> Result<(), RunError> {
    #[cfg(target_os = "linux")]
    {
        let result = perform_mutation(call, path, dest);
        match result {
            Ok(value) => tolerate_dead(kernel.send_success(notif.id, value)),
            Err(errno) => tolerate_dead(kernel.send_error(notif.id, errno)),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (call, path, dest);
        tolerate_dead(kernel.send_continue(notif.id))
    }
}

fn respond_network<N: Notifier>(
    kernel: &N,
    notif: &SeccompNotif,
    sys_nr: u32,
    _ip: IpAddr,
    _port: u16,
    decision: &ResolvedDecision,
) -> Result<(), RunError> {
    if decision.response_decision != Decision::Allow {
        return tolerate_dead(kernel.send_error(notif.id, libc::EACCES));
    }
    if sys_nr == nr::CONNECT || sys_nr == nr::BIND || sys_nr == nr::SENDTO {
        return tolerate_dead(kernel.send_continue(notif.id));
    }
    tolerate_dead(kernel.send_error(notif.id, libc::EACCES))
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
            Ok((IpAddr::V6(Ipv6Addr::from(addr)), port))
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
        nr::PTRACE | nr::PROCESS_VM_READV | nr::PROCESS_VM_WRITEV | nr::PIDFD_GETFD
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
        Some(i) if notif.data.args[i] != flags::AT_FDCWD => {
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
        }),
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub use linux::run_loop;
#[cfg(target_os = "linux")]
use linux::{open_for_addfd, perform_mutation, prompt_for_ask};

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::supervisor::mem::proc::ChildMem;
    use crate::supervisor::notify::NotifyFd;
    use crate::supervisor::spawn::SupervisedChild;
    use std::os::fd::{AsRawFd, FromRawFd};
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
        fn send_addfd(&self, id: u64, srcfd: BorrowedFd<'_>, flags: u32) -> io::Result<i32> {
            self.notify.send_addfd(id, srcfd, flags)
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

    pub(super) fn open_for_addfd(path: &Path, flags: u64) -> Result<std::fs::File, i32> {
        let c_path = path_cstr(path)?;
        let mut open_flags = (flags as i32) & !libc::O_CLOEXEC;
        open_flags |= libc::O_CLOEXEC;
        // SAFETY: open reads a nul-terminated path and returns a new fd or -1.
        let fd = unsafe { libc::open(c_path.as_ptr(), open_flags, 0o666) };
        if fd < 0 {
            return Err(errno());
        }
        // SAFETY: fd was returned by open and is owned by this process.
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    pub(super) fn perform_mutation(
        call: MutationCall,
        path: &Path,
        dest: Option<&Path>,
    ) -> Result<i64, i32> {
        match call {
            MutationCall::Truncate { len } => call_truncate(path, len as libc::off_t),
            MutationCall::Rename => call_rename(path, dest),
            MutationCall::RenameAt2 { flags } => call_renameat2(path, dest, flags),
            MutationCall::Mkdir { mode } => call_mkdir(path, mode as libc::mode_t),
            MutationCall::Rmdir => call_rmdir(path),
            MutationCall::Unlink => call_unlink(path),
            MutationCall::UnlinkAt { flags } => call_unlinkat(path, flags),
            MutationCall::Link => call_link(path, dest),
            MutationCall::LinkAt { flags } => call_linkat(path, dest, flags),
            MutationCall::Symlink => call_symlink(path, dest),
            MutationCall::Chmod { mode } => call_chmod(path, mode as libc::mode_t),
            MutationCall::Chown { uid, gid } => {
                call_chown(path, uid as libc::uid_t, gid as libc::gid_t)
            }
            MutationCall::FchownAt { uid, gid, flags } => {
                call_fchownat(path, uid as libc::uid_t, gid as libc::gid_t, flags)
            }
            MutationCall::None => Ok(0),
        }
    }

    fn call_truncate(path: &Path, len: libc::off_t) -> Result<i64, i32> {
        let path = path_cstr(path)?;
        // SAFETY: truncate reads a nul-terminated path.
        rc_unit(unsafe { libc::truncate(path.as_ptr(), len) })
    }

    fn call_rename(path: &Path, dest: Option<&Path>) -> Result<i64, i32> {
        let old = path_cstr(path)?;
        let new = path_cstr(dest.ok_or(libc::EINVAL)?)?;
        // SAFETY: rename reads two nul-terminated paths.
        rc_unit(unsafe { libc::rename(old.as_ptr(), new.as_ptr()) })
    }

    fn call_renameat2(path: &Path, dest: Option<&Path>, flags: u64) -> Result<i64, i32> {
        let old = path_cstr(path)?;
        let new = path_cstr(dest.ok_or(libc::EINVAL)?)?;
        // SAFETY: renameat2 reads two nul-terminated paths. Absolute paths ignore AT_FDCWD.
        rc_unit(unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                old.as_ptr(),
                libc::AT_FDCWD,
                new.as_ptr(),
                flags as libc::c_uint,
            ) as libc::c_int
        })
    }

    fn call_mkdir(path: &Path, mode: libc::mode_t) -> Result<i64, i32> {
        let path = path_cstr(path)?;
        // SAFETY: mkdir reads a nul-terminated path.
        rc_unit(unsafe { libc::mkdir(path.as_ptr(), mode) })
    }

    fn call_rmdir(path: &Path) -> Result<i64, i32> {
        let path = path_cstr(path)?;
        // SAFETY: rmdir reads a nul-terminated path.
        rc_unit(unsafe { libc::rmdir(path.as_ptr()) })
    }

    fn call_unlink(path: &Path) -> Result<i64, i32> {
        let path = path_cstr(path)?;
        // SAFETY: unlink reads a nul-terminated path.
        rc_unit(unsafe { libc::unlink(path.as_ptr()) })
    }

    fn call_unlinkat(path: &Path, flags: u64) -> Result<i64, i32> {
        let path = path_cstr(path)?;
        // SAFETY: unlinkat reads a nul-terminated path. Absolute paths ignore AT_FDCWD.
        rc_unit(unsafe { libc::unlinkat(libc::AT_FDCWD, path.as_ptr(), flags as libc::c_int) })
    }

    fn call_link(path: &Path, dest: Option<&Path>) -> Result<i64, i32> {
        let old = path_cstr(path)?;
        let new = path_cstr(dest.ok_or(libc::EINVAL)?)?;
        // SAFETY: link reads two nul-terminated paths.
        rc_unit(unsafe { libc::link(old.as_ptr(), new.as_ptr()) })
    }

    fn call_linkat(path: &Path, dest: Option<&Path>, flags: u64) -> Result<i64, i32> {
        let old = path_cstr(path)?;
        let new = path_cstr(dest.ok_or(libc::EINVAL)?)?;
        // SAFETY: linkat reads two nul-terminated paths. Absolute paths ignore AT_FDCWD.
        rc_unit(unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                old.as_ptr(),
                libc::AT_FDCWD,
                new.as_ptr(),
                flags as libc::c_int,
            )
        })
    }

    fn call_symlink(path: &Path, dest: Option<&Path>) -> Result<i64, i32> {
        let target = path_cstr(path)?;
        let link = path_cstr(dest.ok_or(libc::EINVAL)?)?;
        // SAFETY: symlink reads two nul-terminated paths.
        rc_unit(unsafe { libc::symlink(target.as_ptr(), link.as_ptr()) })
    }

    fn call_chmod(path: &Path, mode: libc::mode_t) -> Result<i64, i32> {
        let path = path_cstr(path)?;
        // SAFETY: chmod reads a nul-terminated path.
        rc_unit(unsafe { libc::chmod(path.as_ptr(), mode) })
    }

    fn call_chown(path: &Path, uid: libc::uid_t, gid: libc::gid_t) -> Result<i64, i32> {
        let path = path_cstr(path)?;
        // SAFETY: chown reads a nul-terminated path.
        rc_unit(unsafe { libc::chown(path.as_ptr(), uid, gid) })
    }

    fn call_fchownat(
        path: &Path,
        uid: libc::uid_t,
        gid: libc::gid_t,
        flags: u64,
    ) -> Result<i64, i32> {
        let path = path_cstr(path)?;
        // SAFETY: fchownat reads a nul-terminated path. Absolute paths ignore AT_FDCWD.
        rc_unit(unsafe {
            libc::fchownat(
                libc::AT_FDCWD,
                path.as_ptr(),
                uid,
                gid,
                flags as libc::c_int,
            )
        })
    }

    fn rc_unit(rc: libc::c_int) -> Result<i64, i32> {
        if rc == 0 { Ok(0) } else { Err(errno()) }
    }

    fn path_cstr(path: &Path) -> Result<std::ffi::CString, i32> {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)
    }

    fn errno() -> i32 {
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
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

    pub(super) fn prompt_for_ask(timeout: Duration) -> AskResolution {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;

        let Ok(mut tty) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
        else {
            return AskResolution::Denied;
        };
        if tty
            .write_all(b"leash: allow requested action? [y/N] ")
            .is_err()
        {
            return AskResolution::Denied;
        }
        let _ = tty.flush();

        let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        let mut pfd = libc::pollfd {
            fd: tty.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll reads and writes one pollfd we own.
        let rc = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
        if rc == 0 {
            return AskResolution::TimedOut;
        }
        if rc < 0 {
            return AskResolution::Denied;
        }

        let mut byte = [0u8; 1];
        match tty.read(&mut byte) {
            Ok(1) if byte[0] == b'y' || byte[0] == b'Y' => AskResolution::Approved,
            Ok(_) | Err(_) => AskResolution::Denied,
        }
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
            if let Some(e) = self.send_errno {
                return Err(io::Error::from_raw_os_error(e));
            }
            self.sent.borrow_mut().push(format!("success:{id}:{value}"));
            Ok(())
        }
        fn send_addfd(&self, id: u64, _srcfd: BorrowedFd<'_>, flags: u32) -> io::Result<i32> {
            if let Some(e) = self.send_errno {
                return Err(io::Error::from_raw_os_error(e));
            }
            self.sent.borrow_mut().push(format!("addfd:{id}:{flags}"));
            Ok(3)
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
        let how_flags = (flags::O_WRONLY | flags::O_CREAT).to_ne_bytes().to_vec();
        let mut kernel = FakeNotifier::default().with_cstr(0x1000, "/work/out");
        kernel.mem.insert(0x3000, how_flags);

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
        for n in [nr::CLONE, nr::PTRACE] {
            handle_notification(&kernel, &notif(n, [0; 6]), &mut w, 1_000).unwrap();
        }
        assert_eq!(kernel.sent().len(), 2);
        assert!(kernel.sent().iter().all(|s| s.starts_with("continue:")));
        let evs = events(w);
        assert_eq!(evs[0]["fact"]["family"], "process");
        assert_eq!(evs[0]["fact"]["flags"], 0);
        assert_eq!(evs[1]["fact"]["family"], "cross_process");
        assert_eq!(evs[1]["fact"]["target_pid"], 0);
    }

    #[test]
    fn network_unreadable_sockaddr_denies_as_case_c() {
        let kernel = FakeNotifier::default();
        let mut w = writer();
        handle_notification(
            &kernel,
            &notif(nr::CONNECT, [3, 0xdead, 16, 0, 0, 0]),
            &mut w,
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
    fn mutation_replay_arguments_follow_linux_syscall_signatures() {
        assert_eq!(
            mutation_call(nr::TRUNCATE, &notif(nr::TRUNCATE, [0x1000, 99, 0, 0, 0, 0])),
            MutationCall::Truncate { len: 99 }
        );
        assert_eq!(
            mutation_call(nr::MKDIR, &notif(nr::MKDIR, [0x1000, 0o700, 0, 0, 0, 0])),
            MutationCall::Mkdir { mode: 0o700 }
        );
        assert_eq!(
            mutation_call(
                nr::MKDIRAT,
                &notif(nr::MKDIRAT, [5, 0x1000, 0o755, 0, 0, 0])
            ),
            MutationCall::Mkdir { mode: 0o755 }
        );
        assert_eq!(
            mutation_call(
                nr::UNLINKAT,
                &notif(nr::UNLINKAT, [5, 0x1000, flags::AT_REMOVEDIR, 0, 0, 0])
            ),
            MutationCall::UnlinkAt {
                flags: flags::AT_REMOVEDIR
            }
        );
        assert_eq!(
            mutation_call(
                nr::RENAMEAT2,
                &notif(nr::RENAMEAT2, [5, 0x1000, 6, 0x2000, 1, 0])
            ),
            MutationCall::RenameAt2 { flags: 1 }
        );
        assert_eq!(
            mutation_call(
                nr::LINKAT,
                &notif(nr::LINKAT, [5, 0x1000, 6, 0x2000, 0x400, 0])
            ),
            MutationCall::LinkAt { flags: 0x400 }
        );
        assert_eq!(
            mutation_call(
                nr::FCHMODAT,
                &notif(nr::FCHMODAT, [5, 0x1000, 0o600, 0, 0, 0])
            ),
            MutationCall::Chmod { mode: 0o600 }
        );
        assert_eq!(
            mutation_call(nr::CHOWN, &notif(nr::CHOWN, [0x1000, 501, 20, 0, 0, 0])),
            MutationCall::Chown { uid: 501, gid: 20 }
        );
        assert_eq!(
            mutation_call(
                nr::FCHOWNAT,
                &notif(nr::FCHOWNAT, [5, 0x1000, 501, 20, 0x100, 0])
            ),
            MutationCall::FchownAt {
                uid: 501,
                gid: 20,
                flags: 0x100
            }
        );
    }

    #[test]
    fn enforce_unmatched_outside_fs_denies_by_default() {
        let kernel = FakeNotifier::default().with_cstr(0x1000, "/etc/hosts");
        let p = policy("schema_version = 1\n");
        let config = RunConfig::enforce(4242, Attendance::Unattended, &p);
        let mut w = writer();
        super::handle_notification(
            &kernel,
            &notif(nr::OPENAT, [flags::AT_FDCWD, 0x1000, 0, 0, 0, 0]),
            &mut w,
            &config,
            1_000,
        )
        .unwrap();

        assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::EACCES)]);
        let ev = &events(w)[0];
        assert_eq!(ev["decision"], "deny");
        assert_eq!(ev["matched_rule"], "base:enforce");
    }

    #[test]
    fn unattended_ask_records_ask_and_denies() {
        let kernel = FakeNotifier::default().with_cstr(0x1000, "/etc/hosts");
        let p = policy(
            "schema_version = 1\n\
             [[fs]]\npath=\"/etc/**\"\nmode=[\"read\"]\naction=\"ask\"\n",
        );
        let config = RunConfig::enforce(4242, Attendance::Unattended, &p);
        let mut w = writer();
        super::handle_notification(
            &kernel,
            &notif(nr::OPENAT, [flags::AT_FDCWD, 0x1000, 0, 0, 0, 0]),
            &mut w,
            &config,
            1_000,
        )
        .unwrap();

        assert_eq!(kernel.sent(), vec![format!("error:7:{}", libc::EACCES)]);
        let ev = &events(w)[0];
        assert_eq!(ev["decision"], "ask");
        assert_eq!(ev["ask_resolution"], "unattended");
        assert_eq!(ev["matched_rule"], "fs.1");
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
}
