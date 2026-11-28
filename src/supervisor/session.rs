//! session orchestration: preflight, run directory, lifecycle events, spawn, notify loop,
//! and report (docs/design/cli.md section 7).
//!
//! this file holds the pure session types and the wait-status decode; the linux-only
//! `run_session` that actually drives preflight through report-writing (cli.md section 5)
//! is wired up in a later change. every error here maps to the supervisor-failure exit
//! (cli.md section 6): a session never fails open, and an undecodable wait status is an
//! error rather than a guess (cli.md section 5 durability contract) so the run never
//! stamps an exit it could not truthfully read.

use std::path::PathBuf;

use crate::recorder::{Attendance, Mode};

/// how the child ended, decoded from the raw wait status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitDisposition {
    /// the child called `exit` (or returned from `main`) with this status.
    Exited(i32),
    /// the child was killed by this signal.
    Signaled(i32),
}

impl ExitDisposition {
    /// the shell-visible exit code for this disposition (cli.md section 6):
    /// `Exited(n)` passes `n` through unchanged; `Signaled(s)` is `128 + s`, the
    /// convention `timeout` and `docker` use.
    pub fn shell_code(self) -> i32 {
        match self {
            ExitDisposition::Exited(n) => n,
            ExitDisposition::Signaled(s) => 128 + s,
        }
    }
}

/// a raw wait status that decoded to neither an exit nor a signal death (stopped,
/// continued, or otherwise malformed). cli.md section 5: an undecodable status must be an
/// error, never a guess, so no `run_end` gets stamped with a status the supervisor could
/// not actually read.
#[derive(Debug, thiserror::Error)]
#[error("wait status {status:#x} is neither an exit nor a signal death")]
pub struct MalformedWaitStatus {
    /// the raw status as returned by `waitpid`.
    pub status: i32,
}

/// decode a raw `waitpid` status into how the child ended. hand-decoded against the
/// documented bit layout (not `libc::WIFEXITED` and friends) so this builds and tests on
/// any host, including macOS, where those macros are not the linux abi.
pub fn decode_wait_status(status: i32) -> Result<ExitDisposition, MalformedWaitStatus> {
    let low = status & 0x7f;
    if low == 0 {
        // WIFEXITED: low byte all zero, exit code in the next byte up.
        return Ok(ExitDisposition::Exited((status >> 8) & 0xff));
    }
    // WIFSIGNALED, glibc's <bits/waitstatus.h> formula: the low seven bits plus one,
    // arithmetic-shifted right by one as a signed byte, is positive exactly for a
    // terminating signal (0x7f, the stopped marker, and 0 are excluded by construction).
    let signaled = (((low + 1) as i8) >> 1) > 0;
    if signaled {
        return Ok(ExitDisposition::Signaled(low));
    }
    // low == 0x7f is WIFSTOPPED; status == 0xffff is WIFCONTINUED. neither is a
    // terminal disposition for a reaped child, so both (and anything else left over)
    // are malformed here.
    Err(MalformedWaitStatus { status })
}

/// what to run and under which stamps: the fully-resolved inputs to a session, computed by
/// the cli before dispatch (cli.md section 7).
#[derive(Debug, Clone)]
pub struct SessionSpec {
    /// the child command and its arguments, verbatim.
    pub argv: Vec<String>,
    /// record-only or enforce, decided once before the child exists.
    pub mode: Mode,
    /// attended or unattended, stamped into the trace.
    pub attendance: Attendance,
    /// the resolved state root the run directory is created under.
    pub state_root: PathBuf,
    /// the absolute state-root path as the operator spelled it, before canonicalization. an
    /// enforce run walks it for symlink hops and protects each one (FR-21, ADR-0024).
    pub state_root_spelling: PathBuf,
    /// the canonicalized workspace the run supervises.
    pub workspace: PathBuf,
    /// optional policy path; present means enforce mode and is loaded during preflight.
    pub policy_path: Option<PathBuf>,
    /// the attended-ask timeout (FR-10), from `--ask-timeout` or the 60 s default.
    pub ask_timeout: std::time::Duration,
    /// snapshot integrity restrictions apply (ADR-0024 decisions 7 and 8): `clone3` is
    /// answered ENOSYS and legacy AIO is denied. enforce mode only; false by default.
    pub snapshot_integrity: bool,
}

/// the refusal of a snapshot run whose policy grants a mutating Landlock right over the state
/// root or a cgroup2 mount (ADR-0024 decision 5).
#[derive(Debug, thiserror::Error)]
#[error(
    "snapshot integrity refused: {origin} grants {rights} beneath \"{grant}\"{anchoring}, which {relation} {what} \"{protected}\"; a Landlock grant cannot subtract a subtree, so the agent could change snapshot state or its own cgroup. Narrow the rule so it does not cover that path, or remove those rights from it (ADR-0024 decision 5)",
    grant = grant.display(),
    protected = protected.display()
)]
pub struct GrantOverlapRefusal {
    /// the policy rule or base grant that gave the right, such as `rule fs.3`
    pub origin: String,
    /// the mutating rights, such as `write, truncate`
    pub rights: String,
    /// the grant's hierarchy root as the policy spelled it
    pub grant: PathBuf,
    /// empty, or why the rights sit elsewhere than the spelled root: a missing root is
    /// anchored by Landlock at its deepest existing ancestor
    pub anchoring: String,
    /// how the grant, or its anchor, relates to the protected path
    pub relation: &'static str,
    /// `state root` or `cgroup2 mount`
    pub what: &'static str,
    /// the protected path
    pub protected: PathBuf,
}

/// how a completed run ended.
#[derive(Debug, Clone)]
pub struct SessionOutcome {
    /// the run id (the run directory's name).
    pub run_id: String,
    /// absolute path of the run directory.
    pub run_path: PathBuf,
    /// how the child ended.
    pub exit: ExitDisposition,
}

/// why a session failed; each variant maps to the supervisor-failure exit code, 125
/// (cli.md section 6).
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// preflight evaluated the host below the floor and refused to run.
    #[error("preflight refused: {0}")]
    Refused(String),
    /// preflight could not probe the host at all.
    #[error("preflight probe failed: {0}")]
    Preflight(#[from] crate::supervisor::preflight::PreflightError),
    /// snapshot integrity restrictions need the enforce-mode policy domain.
    #[error(
        "snapshot integrity restrictions require enforce mode; record-only cannot keep the agent away from snapshot state"
    )]
    SnapshotIntegrityNeedsEnforce,
    /// a snapshot run needs Landlock ABI 3 or higher so path truncation is in the backstop
    /// (ADR-0024 decision 6).
    #[error(
        "snapshot integrity refused: Landlock ABI {abi} is below the required ABI {required}, so path truncation would not be in the Landlock backstop (ADR-0024 decision 6)"
    )]
    SnapshotLandlockAbi {
        /// the ABI the host reported
        abi: u32,
        /// the lowest ABI a snapshot run accepts
        required: u32,
    },
    /// a policy grant with a mutating right overlaps the state root or a cgroup2 mount
    /// (ADR-0024 decision 5). Landlock cannot subtract a subtree from a grant, so only the
    /// grant can be narrowed.
    #[error(transparent)]
    SnapshotGrantOverlap(Box<GrantOverlapRefusal>),
    /// the cgroup2 mounts of this mount namespace could not be read, so the implicit deny
    /// that protects them could not be armed (ADR-0024 decision 4).
    #[error("cgroup2 mounts could not be read: {0}")]
    CgroupMounts(#[source] std::io::Error),
    /// the supervisor could not mark itself non-dumpable.
    #[cfg(target_os = "linux")]
    #[error("could not mark the supervisor non-dumpable: {0}")]
    NonDumpable(#[source] std::io::Error),
    /// the policy file was missing or invalid.
    #[error("policy failed to load: {0}")]
    Policy(#[from] crate::policy::PolicyError),
    /// the policy load path needs HOME to expand `~`.
    #[error("policy expansion needs HOME to be set")]
    PolicyHome,
    /// an enforce session must name the policy that selected enforce mode.
    #[error("enforce mode requires a policy path")]
    MissingPolicy,
    /// the Landlock ruleset could not be constructed.
    #[error("Landlock setup failed: {0}")]
    Landlock(#[from] crate::sandbox::landlock::LandlockError),
    /// the recorder could not create the run directory or write to the trace.
    #[error("recorder failed: {0}")]
    Recorder(#[from] crate::recorder::RecorderError),
    /// the state root could not be resolved before the child started, so the implicit deny
    /// that protects it could not be armed (FR-21).
    #[error("state root could not be resolved: {0}")]
    StateRoot(#[source] std::io::Error),
    /// the child could not be spawned or the boundary could not be established.
    // spawn.rs is itself cfg(linux) (see supervisor::mod), so this variant is too; a
    // session on a non-linux host can never reach the point of constructing one.
    #[cfg(target_os = "linux")]
    #[error("spawn failed: {0}")]
    Spawn(#[from] crate::supervisor::spawn::SpawnError),
    /// the notify loop aborted (notify-loop.md's fail-closed arcs).
    #[error("run loop failed: {0}")]
    Run(#[from] crate::supervisor::run::RunError),
    /// the run cgroup of a snapshot run could not be set up (ADR-0024 decision 2).
    #[cfg(target_os = "linux")]
    #[error("run cgroup: {0}")]
    RunCgroup(#[from] crate::supervisor::run_cgroup::RunCgroupError),
    /// the confined realization broker could not be established or served.
    #[cfg(target_os = "linux")]
    #[error("broker failed: {0}")]
    Broker(#[from] crate::supervisor::broker::BrokerError),
    /// the reaped wait status could not be decoded as an exit or a signal death.
    #[error("child wait status undecodable: {0}")]
    WaitStatus(#[from] MalformedWaitStatus),
    /// `report.txt` could not be rendered or written after a durable `run_end`.
    #[error("report could not be written: {0}")]
    Report(#[source] std::io::Error),
    /// the just-written trace did not render (a recorder bug surfacing, never swallowed).
    #[error("report could not be rendered: {0}")]
    Render(#[from] crate::recorder::report::ReportError),
}

#[cfg(target_os = "linux")]
pub use linux::{SessionHooks, run_session, run_session_with_hooks, run_session_with_writer};

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::recorder::{
        AskResolution, CgroupKillEvent, CgroupKillReason, EventBody, Mode, RecorderError, RunDir,
        RunMeta, TRACE_SCHEMA_VERSION, TraceSink, TraceWriter,
    };
    use crate::sandbox::landlock::{
        self, LandlockHull, PreparedRuleset, ProtectedStore, StoreKind,
    };
    use crate::supervisor::broker::Broker;
    use crate::supervisor::cgroup;
    use crate::supervisor::cgroup_mounts::CgroupMounts;
    use crate::supervisor::preflight::{self, Outcome};
    use crate::supervisor::run::run_loop_with_cgroup_kill;
    use crate::supervisor::run_cgroup::{
        CgroupParent, PROBE_TIMEOUT, RunCgroup, RunCgroupError, RunLock, cleanup_stale,
    };
    use crate::supervisor::spawn::{SpawnSpec, spawn_supervised_in_cgroup, spawn_supervised_with};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io::Write;
    use std::net::{IpAddr, ToSocketAddrs};
    use std::os::fd::AsRawFd;
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    /// injectable seams for a session, used by tests to exercise cgroup probe refusal,
    /// `cgroup.kill` timeout, and attended-ask flows without test-only branches in production
    /// code.
    pub struct SessionHooks<'a> {
        /// proves delegation, `clone3(CLONE_INTO_CGROUP)`, lock xattrs, freeze, thaw and kill
        /// on the parent cgroup before any run directory exists.
        pub probe: &'a dyn Fn(&Path) -> std::io::Result<()>,
        /// kills the run cgroup at run end or abort.
        pub kill: &'a dyn Fn(&RunCgroup, CgroupKillReason) -> CgroupKillEvent,
        /// resolves attended asks (defaults to `ask::tty_prompt`).
        pub prompter: &'a dyn Fn(&[crate::supervisor::ask::PendingAsk], Duration) -> AskResolution,
        /// probes the host capabilities, the Landlock ABI included (defaults to
        /// `preflight::probe`). a test injects an ABI no available host has, to prove the
        /// ADR-0024 decision 6 refusal.
        pub capabilities:
            &'a dyn Fn() -> Result<preflight::Capabilities, preflight::PreflightError>,
    }

    impl Default for SessionHooks<'_> {
        fn default() -> Self {
            Self {
                probe: &|parent| cgroup::probe_delegation(parent, PROBE_TIMEOUT),
                kill: &RunCgroup::kill_all,
                prompter: &crate::supervisor::ask::tty_prompt,
                capabilities: &preflight::probe,
            }
        }
    }

    struct EnforcementSetup {
        policy: Option<crate::policy::Policy>,
        policy_digest: Option<String>,
        landlock_abi: Option<u32>,
        landlock_residuals: Option<Vec<String>>,
        ruleset: Option<PreparedRuleset>,
        resolved_hosts: HashMap<String, Vec<IpAddr>>,
    }

    /// drive one run start to finish: preflight, run directory, lifecycle events, spawn,
    /// the notify loop, and the report, in the fixed order of cli.md section 5. every
    /// failure path returns without writing artifacts the run cannot vouch for.
    pub fn run_session(spec: SessionSpec) -> Result<SessionOutcome, SessionError> {
        run_session_with_hooks(spec, SessionHooks::default())
    }

    /// `run_session` with injectable cgroup and prompt hooks, the seam tests use to exercise
    /// probe refusal before run-dir creation, kill timeout fail-closed behavior, and attended
    /// ask synchronization.
    pub fn run_session_with_hooks(
        spec: SessionSpec,
        hooks: SessionHooks<'_>,
    ) -> Result<SessionOutcome, SessionError> {
        refuse_snapshot_integrity_outside_enforce(&spec)?;
        // first, before any run directory, broker or child exists (ADR-0024 decision 9)
        set_non_dumpable()?;
        let caps = (hooks.capabilities)()?;
        let (caps, mechanism, mechanism_reason) = match preflight::evaluate(&caps, spec.mode) {
            Outcome::Proceed {
                caps,
                mechanism,
                mechanism_reason,
            } => (caps, mechanism, mechanism_reason),
            Outcome::Refuse(message) => return Err(SessionError::Refused(message)),
        };
        // the host-side refusals of a snapshot run come before anything exists: the ABI, then
        // the policy's grants against the state root and the cgroup2 mounts (ADR-0024
        // decisions 4 to 6). the mounts are read once, here, and denied for the whole run.
        if spec.snapshot_integrity && caps.landlock_abi < landlock::SNAPSHOT_MIN_ABI {
            return Err(SessionError::SnapshotLandlockAbi {
                abi: caps.landlock_abi,
                required: landlock::SNAPSHOT_MIN_ABI,
            });
        }
        let cgroup_mounts = if spec.snapshot_integrity {
            Some(CgroupMounts::from_proc_self().map_err(SessionError::CgroupMounts)?)
        } else {
            None
        };
        let enforcement = prepare_enforcement(&spec, caps.landlock_abi, cgroup_mounts.as_ref())?;
        // a snapshot run needs a writable delegated cgroup with working clone3 entry,
        // lock xattrs, freeze, thaw and kill; refuse before any run directory or broker
        // exists (cli.md section 1, ADR-0024 decision 2).
        let (run_id, run_cgroup, located_parent) = if spec.snapshot_integrity {
            let parent = CgroupParent::locate()?;
            (hooks.probe)(parent.path()).map_err(|source| RunCgroupError::Probe { source })?;
            let id = crate::recorder::generate_run_id(SystemTime::now())?;
            let path = parent.child_path(&id)?;
            (Some(id), Some(path), Some(parent))
        } else {
            (None, None, None)
        };

        let meta = RunMeta {
            schema_version: TRACE_SCHEMA_VERSION,
            mode: spec.mode,
            attendance: spec.attendance,
            policy_digest: enforcement.policy_digest,
            kernel: caps.kernel_release,
            landlock_abi: enforcement.landlock_abi,
            landlock_residuals: enforcement.landlock_residuals,
            snapshot_mechanism: mechanism,
            snapshot_reason: mechanism_reason,
            argv: spec.argv.clone(),
            workspace: spec.workspace.clone(),
            start_ts: now_ms()?,
            run_cgroup,
        };
        let run_dir = match run_id {
            Some(id) => RunDir::create_with_id(&spec.state_root, &meta, id)?,
            None => RunDir::create(&spec.state_root, &meta, SystemTime::now())?,
        };
        let mut writer = run_dir.trace_writer()?;
        run_session_with_writer_and_ruleset(
            &spec,
            meta,
            &run_dir,
            &mut writer,
            enforcement.policy.as_ref(),
            enforcement.ruleset.as_ref(),
            &enforcement.resolved_hosts,
            located_parent.as_ref(),
            cgroup_mounts.as_ref(),
            &hooks,
        )
    }

    /// the flag is honored only in enforce mode; refuse before anything exists.
    fn refuse_snapshot_integrity_outside_enforce(spec: &SessionSpec) -> Result<(), SessionError> {
        if spec.snapshot_integrity && spec.mode != Mode::Enforce {
            return Err(SessionError::SnapshotIntegrityNeedsEnforce);
        }
        Ok(())
    }

    /// mark the supervisor non-dumpable (ADR-0024 decision 9): a same-uid process can
    /// no longer ptrace it or read its `/proc/<pid>` files that need dumpability. the
    /// flag is inherited by the broker. the agent child resets it to the default in
    /// `sandbox::child::enter`, because the supervisor reads the child's memory through
    /// `/proc/<child>/mem` and that access check consults the child's flag, not ours.
    /// the supervisor's own ptrace-class access to the child is unaffected by this flag.
    fn set_non_dumpable() -> Result<(), SessionError> {
        // SAFETY: PR_SET_DUMPABLE takes scalar arguments and touches no memory.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(SessionError::NonDumpable(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn prepare_enforcement(
        spec: &SessionSpec,
        landlock_abi: u32,
        cgroup_mounts: Option<&CgroupMounts>,
    ) -> Result<EnforcementSetup, SessionError> {
        if spec.mode == Mode::RecordOnly {
            return Ok(EnforcementSetup {
                policy: None,
                policy_digest: None,
                landlock_abi: None,
                landlock_residuals: None,
                ruleset: None,
                resolved_hosts: HashMap::new(),
            });
        }

        let Some(path) = &spec.policy_path else {
            return Err(SessionError::MissingPolicy);
        };
        let home = std::env::var("HOME").map_err(|_| SessionError::PolicyHome)?;
        let workspace = spec.workspace.to_string_lossy();
        let loaded = crate::policy::Policy::load_with_digest(
            path,
            &crate::policy::ExpandContext {
                workspace: &workspace,
                home: &home,
            },
        )?;
        let resolved_hosts = resolve_policy_hosts(&loaded.policy)?;
        let mut hull: LandlockHull = landlock::derive_hull(&loaded.policy, landlock_abi);
        // the ruleset is prepared first because the overlap check must judge the anchors
        // Landlock really opened: a grant on a missing path is anchored at its deepest
        // existing ancestor, and the rights land there
        let ruleset = landlock::prepare_ruleset(&hull)?;
        if let Some(mounts) = cgroup_mounts {
            check_snapshot_overlaps(
                spec,
                &loaded.policy,
                &mut hull,
                &ruleset,
                mounts,
                landlock_abi,
            )?;
        }

        Ok(EnforcementSetup {
            policy: Some(loaded.policy),
            policy_digest: Some(loaded.digest),
            landlock_abi: Some(landlock_abi),
            landlock_residuals: Some(hull.residuals),
            ruleset: Some(ruleset),
            resolved_hosts,
        })
    }

    /// refuse a policy whose Landlock grants could change the state root or a cgroup2 mount,
    /// and stamp the read-only overlaps that are allowed (ADR-0024 decision 5). a grant
    /// overlaps as an ancestor or a descendant, compared by component on the canonical anchors
    /// of the prepared ruleset and again by (device, inode) along the ancestor chains, so a
    /// bind mount alias of the state root is caught too. the state root may not exist yet, so
    /// it is resolved as far as it does.
    fn check_snapshot_overlaps(
        spec: &SessionSpec,
        policy: &crate::policy::Policy,
        hull: &mut LandlockHull,
        ruleset: &PreparedRuleset,
        mounts: &CgroupMounts,
        abi: u32,
    ) -> Result<(), SessionError> {
        let mut stores = vec![ProtectedStore {
            kind: StoreKind::StateRoot,
            path: crate::supervisor::state_root::resolve_leniently(&spec.state_root),
        }];
        stores.extend(mounts.paths().iter().map(|path| ProtectedStore {
            kind: StoreKind::CgroupMount,
            path: path.clone(),
        }));
        // anchors are opened one per grant, in order
        let grants: Vec<landlock::AnchoredGrant> = hull
            .fs
            .iter()
            .zip(ruleset.anchors())
            .map(|(grant, anchor)| landlock::AnchoredGrant {
                grant_root: grant.root.clone(),
                anchor: anchor.root().to_path_buf(),
                anchored_elsewhere: !grant.root.exists(),
                rights: anchor.allowed_access(),
                identity: anchor.identity(),
            })
            .collect();
        let overlaps =
            landlock::snapshot_store_overlaps(&grants, &stores, &landlock::path_identity);
        if let Some(first) = overlaps.mutating.first() {
            let origins = landlock::mutating_grant_origins(policy, &first.grant_root, abi);
            let origin = match origins.as_slice() {
                [] => "a policy rule".to_string(),
                [one] => format!("rule {one}"),
                many => format!("rules {}", many.join(", ")),
            };
            return Err(SessionError::SnapshotGrantOverlap(Box::new(
                GrantOverlapRefusal {
                    origin,
                    rights: landlock::mutating_right_names(first.mutating_rights()).join(", "),
                    grant: first.grant_root.clone(),
                    anchoring: if first.anchored_elsewhere {
                        format!(
                            ", which does not exist, so Landlock anchors it at \"{}\"",
                            first.anchor.display()
                        )
                    } else {
                        String::new()
                    },
                    relation: first.relation.describe(),
                    what: first.store.kind.describe(),
                    protected: first.store.path.clone(),
                },
            )));
        }
        if !overlaps.read_only.is_empty() {
            hull.residuals
                .push(landlock::RESIDUAL_SNAPSHOT_STORE_READ_OVERLAP.to_string());
        }
        Ok(())
    }

    fn resolve_policy_hosts(
        policy: &crate::policy::Policy,
    ) -> Result<HashMap<String, Vec<IpAddr>>, SessionError> {
        let mut cache = HashMap::new();
        for rule in &policy.net {
            match &rule.host {
                crate::policy::HostRule::Exact(host) => {
                    let addresses = (host.as_str(), 0)
                        .to_socket_addrs()
                        .map_err(|error| {
                            SessionError::Refused(format!(
                                "could not resolve exact policy host {host:?}: {error}"
                            ))
                        })?
                        .map(|address| address.ip())
                        .collect::<Vec<_>>();
                    if addresses.is_empty() {
                        return Err(SessionError::Refused(format!(
                            "exact policy host {host:?} resolved to no addresses"
                        )));
                    }
                    cache.insert(host.clone(), addresses);
                }
                crate::policy::HostRule::Suffix(suffix) => {
                    return Err(SessionError::Refused(format!(
                        "suffix host policy \"*.{suffix}\" is not enforceable in schema version 1 (ADR-0020)"
                    )));
                }
                crate::policy::HostRule::Any
                | crate::policy::HostRule::Ip(_)
                | crate::policy::HostRule::Cidr { .. } => {}
            }
        }
        Ok(cache)
    }

    /// the body of `run_session` with the trace writer injected: the seam the fail-closed
    /// session test uses to force a trace-write failure mid-run (the same philosophy as
    /// `spawn_with_filter`). a real run always passes the writer over the run directory's
    /// trace.jsonl; the report step reads that file back, which is what makes the report
    /// derived from the trace rather than from live state (trace.md section 6).
    pub fn run_session_with_writer<S: TraceSink>(
        spec: &SessionSpec,
        meta: RunMeta,
        run_dir: &RunDir,
        writer: &mut TraceWriter<S>,
    ) -> Result<SessionOutcome, SessionError> {
        run_session_with_writer_and_ruleset(
            spec,
            meta,
            run_dir,
            writer,
            None,
            None,
            &HashMap::new(),
            None,
            None,
            &SessionHooks::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn run_session_with_writer_and_ruleset<S: TraceSink>(
        spec: &SessionSpec,
        meta: RunMeta,
        run_dir: &RunDir,
        writer: &mut TraceWriter<S>,
        policy: Option<&crate::policy::Policy>,
        prepared_ruleset: Option<&PreparedRuleset>,
        resolved_hosts: &HashMap<String, Vec<IpAddr>>,
        located_parent: Option<&CgroupParent>,
        cgroup_mounts: Option<&CgroupMounts>,
        hooks: &SessionHooks<'_>,
    ) -> Result<SessionOutcome, SessionError> {
        refuse_snapshot_integrity_outside_enforce(spec)?;
        // the implicit cgroup deny cannot be armed without the mounts, so a snapshot run
        // that reaches here without them is refused before the broker or the child exist
        if spec.snapshot_integrity && cgroup_mounts.is_none() {
            return Err(SessionError::Run(
                crate::supervisor::run::RunError::SnapshotIntegrityNeedsCgroupMounts,
            ));
        }
        // an enforce run resolves its state root once, here, before any process exists: the
        // implicit deny compares resolved paths against this value (FR-21, ADR-0024). a root
        // that cannot be resolved refuses the run. record-only has no deny, so it needs none.
        let state_root = match meta.mode {
            Mode::RecordOnly => None,
            Mode::Enforce => Some(
                crate::supervisor::state_root::StateRoot::resolve(&spec.state_root_spelling)
                    .map_err(SessionError::StateRoot)?,
            ),
        };

        // step 3: announce the mode on stderr; stdout belongs to the child (FR-19)
        match meta.mode {
            // the same FR-19/ADR-0019 wording the session report uses (report.rs): no policy
            // is enforced, but the denied-and-recorded set, foreign-ABI entries, and
            // undecodable facts are refused in this mode too.
            Mode::RecordOnly => eprintln!(
                "leash: record-only run; no policy is enforced, and only un-mediated I/O paths (SR-4), foreign-ABI entries (SR-3), and undecodable facts are denied"
            ),
            Mode::Enforce => eprintln!("leash: enforce run"),
        }

        // step 4: run_start is appended and synced before the child exists, so any run
        // that produced a child also left durable evidence that it did (cli.md section 5)
        let mode = meta.mode;
        let recorded_cgroup = meta.run_cgroup.clone();
        writer.append(meta.start_ts, EventBody::RunStart(meta))?;
        writer.sync()?;

        let broker = match mode {
            Mode::RecordOnly => None,
            Mode::Enforce => Some(RefCell::new(Broker::spawn(
                prepared_ruleset.ok_or(SessionError::Run(
                    crate::supervisor::run::RunError::MissingBroker,
                ))?,
                &spec.workspace,
            )?)),
        };

        // the supervisor and its broker are the processes whose /proc tree the agent must not
        // reach (implicit:supervisor_proc)
        let state_root = match (state_root, broker.as_ref()) {
            (Some(root), Some(broker)) => {
                Some(root.with_supervisor_pids([std::process::id(), broker.borrow().pid()]))
            }
            (root, _) => root,
        };

        // a snapshot run holds its run lock for the whole run, cleans up the cgroups of
        // dead runs, then creates its own and binds it to the lock. taken after the broker
        // forks so the broker never inherits the lock (ADR-0024 decisions 2 and 17).
        let snapshot_cgroup = start_run_cgroup(
            spec,
            run_dir,
            recorded_cgroup.as_deref(),
            located_parent,
            writer,
        )?;

        // steps 5-6: spawn and serve until the tree exits
        let spawn_spec = SpawnSpec {
            argv: spec.argv.clone(),
            stdout: None,
            mode,
            landlock_ruleset: prepared_ruleset.map(|ruleset| ruleset.ruleset_fd().as_raw_fd()),
        };
        let (child, _run_lock) = match snapshot_cgroup {
            Some((lock, cgroup)) => (spawn_supervised_in_cgroup(&spawn_spec, cgroup)?, Some(lock)),
            None => (
                spawn_supervised_with(&spawn_spec, spec.snapshot_integrity)?,
                None,
            ),
        };
        let mut config = match mode {
            Mode::RecordOnly => {
                crate::supervisor::run::RunConfig::record_only(child.pid as u32, spec.attendance)
            }
            Mode::Enforce => crate::supervisor::run::RunConfig::enforce_with_broker(
                child.pid as u32,
                spec.attendance,
                policy.ok_or(crate::supervisor::run::RunError::EnforceWithoutPolicy)?,
                broker
                    .as_ref()
                    .ok_or(crate::supervisor::run::RunError::MissingBroker)?,
                resolved_hosts,
                state_root
                    .as_ref()
                    .ok_or(crate::supervisor::run::RunError::EnforceWithoutStateRoot)?,
            ),
        }
        .with_ask_timeout(spec.ask_timeout)
        .with_snapshot_integrity(spec.snapshot_integrity);
        if let Some(mounts) = cgroup_mounts {
            config = config.with_cgroup_mounts(mounts);
        }
        config.prompter = hooks.prompter;
        let outcome = run_loop_with_cgroup_kill(child, config, writer, hooks.kill)?;

        // step 7: an undecodable status stamps nothing (an untruthful exit is worse
        // than none, cli.md section 5)
        let exit = decode_wait_status(outcome.wait_status)?;
        let (exit_code, signal) = match exit {
            ExitDisposition::Exited(code) => (Some(code), None),
            ExitDisposition::Signaled(sig) => (None, Some(sig)),
        };

        // step 8: run_end, synced, before the report exists
        writer.append(
            now_ms()?,
            EventBody::RunEnd {
                exit_code,
                signal,
                final_step: outcome.final_step,
            },
        )?;
        writer.sync()?;

        // step 9: the report is rendered from the trace on disk, never from live state
        let trace = std::fs::read_to_string(run_dir.path.join("trace.jsonl"))
            .map_err(SessionError::Report)?;
        let report = crate::recorder::report::render_report(&trace)?;
        let report_path = run_dir.path.join("report.txt");
        let mut file = std::fs::File::create_new(&report_path).map_err(SessionError::Report)?;
        file.write_all(report.as_bytes())
            .map_err(SessionError::Report)?;
        file.sync_data().map_err(SessionError::Report)?;

        // step 10: name the run and the report for the operator
        eprintln!(
            "leash: run {} recorded; report: {}",
            run_dir.id,
            report_path.display()
        );

        Ok(SessionOutcome {
            run_id: run_dir.id.clone(),
            run_path: run_dir.path.clone(),
            exit,
        })
    }

    /// the run lock and run cgroup of a snapshot run, with stale-cgroup cleanup between
    /// them; `None` for every other run. the cleanup is recorded in the new run's trace.
    fn start_run_cgroup<S: TraceSink>(
        spec: &SessionSpec,
        run_dir: &RunDir,
        recorded: Option<&Path>,
        located_parent: Option<&CgroupParent>,
        writer: &mut TraceWriter<S>,
    ) -> Result<Option<(RunLock, RunCgroup)>, SessionError> {
        if !spec.snapshot_integrity {
            return Ok(None);
        }
        let recorded = recorded.ok_or(RunCgroupError::MissingPath)?;
        let opened_parent;
        let parent = match located_parent {
            Some(parent) => parent,
            None => {
                let parent_path = recorded.parent().ok_or(RunCgroupError::MissingPath)?;
                opened_parent = CgroupParent::open_writable(parent_path)?;
                opened_parent.probe()?;
                &opened_parent
            }
        };
        let lock = RunLock::acquire(&run_dir.path)?;
        match cleanup_stale(parent, &spec.state_root, Some(&run_dir.id)) {
            Ok(events) => {
                for event in events {
                    writer.append(now_ms()?, EventBody::CgroupKill(event))?;
                }
            }
            // a cgroup that cannot be listed cannot hold a stale run Leash could clean; the
            // new run does not depend on it, so say so and go on
            Err(e) => eprintln!("leash: could not scan for stale run cgroups: {e}"),
        }
        let cgroup = RunCgroup::create(parent, &run_dir.id)?;
        cgroup.bind_lock(&lock)?;
        if cgroup.path() != recorded {
            return Err(RunCgroupError::PathMismatch {
                created: cgroup.path().to_path_buf(),
                recorded: recorded.to_path_buf(),
            }
            .into());
        }
        Ok(Some((lock, cgroup)))
    }

    /// wall-clock milliseconds; a clock before the epoch cannot stamp anything sane.
    fn now_ms() -> Result<u64, SessionError> {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .map_err(|_| SessionError::Recorder(RecorderError::ClockBeforeEpoch))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // --- decode_wait_status ---

    #[test]
    fn exited_zero_decodes() {
        assert_eq!(
            decode_wait_status(0x0000).unwrap(),
            ExitDisposition::Exited(0)
        );
    }

    #[test]
    fn exited_seven_decodes() {
        assert_eq!(
            decode_wait_status(0x0700).unwrap(),
            ExitDisposition::Exited(7)
        );
    }

    #[test]
    fn signaled_nine_decodes() {
        assert_eq!(decode_wait_status(9).unwrap(), ExitDisposition::Signaled(9));
    }

    #[test]
    fn signaled_eleven_decodes() {
        assert_eq!(
            decode_wait_status(0x008b).unwrap(),
            ExitDisposition::Signaled(11)
        );
    }

    #[test]
    fn stopped_status_is_undecodable() {
        assert!(decode_wait_status(0x137f).is_err());
    }

    #[test]
    fn continued_status_is_undecodable() {
        assert!(decode_wait_status(0xffff).is_err());
    }

    #[test]
    fn malformed_status_names_the_raw_value() {
        let err = decode_wait_status(0x137f).unwrap_err();
        assert_eq!(err.status, 0x137f);
        assert!(err.to_string().contains("137f"));
    }

    // --- ExitDisposition::shell_code ---

    #[test]
    fn exited_shell_code_passes_the_status_through() {
        assert_eq!(ExitDisposition::Exited(7).shell_code(), 7);
        assert_eq!(ExitDisposition::Exited(0).shell_code(), 0);
    }

    #[test]
    fn signaled_shell_code_is_128_plus_the_signal() {
        assert_eq!(ExitDisposition::Signaled(9).shell_code(), 137);
        assert_eq!(ExitDisposition::Signaled(11).shell_code(), 139);
    }

    #[test]
    fn exited_125_is_indistinguishable_from_a_supervisor_failure_at_the_shell() {
        // cli.md section 6's documented residual: a child that itself exits 125 (the
        // same code a supervisor failure uses) passes through unchanged here. only the
        // trace's presence or absence of run_end can tell the two apart.
        assert_eq!(ExitDisposition::Exited(125).shell_code(), 125);
    }
}
