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
    /// the canonicalized workspace the run supervises.
    pub workspace: PathBuf,
    /// optional policy path; present means enforce mode and is loaded during preflight.
    pub policy_path: Option<PathBuf>,
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
    /// the child could not be spawned or the boundary could not be established.
    // spawn.rs is itself cfg(linux) (see supervisor::mod), so this variant is too; a
    // session on a non-linux host can never reach the point of constructing one.
    #[cfg(target_os = "linux")]
    #[error("spawn failed: {0}")]
    Spawn(#[from] crate::supervisor::spawn::SpawnError),
    /// the notify loop aborted (notify-loop.md's fail-closed arcs).
    #[error("run loop failed: {0}")]
    Run(#[from] crate::supervisor::run::RunError),
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
pub use linux::{run_session, run_session_with_writer};

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::recorder::{
        EventBody, Mode, RecorderError, RunDir, RunMeta, TRACE_SCHEMA_VERSION, TraceSink,
        TraceWriter,
    };
    use crate::sandbox::landlock::{self, LandlockHull};
    use crate::supervisor::preflight::{self, Outcome};
    use crate::supervisor::run::run_loop;
    use crate::supervisor::spawn::{SpawnSpec, spawn_supervised};
    use std::io::Write;
    use std::os::fd::{AsRawFd, OwnedFd, RawFd};
    use std::time::SystemTime;

    struct EnforcementSetup {
        policy: Option<crate::policy::Policy>,
        policy_digest: Option<String>,
        landlock_abi: Option<u32>,
        landlock_residuals: Option<Vec<String>>,
        ruleset: Option<OwnedFd>,
    }

    /// drive one run start to finish: preflight, run directory, lifecycle events, spawn,
    /// the notify loop, and the report, in the fixed order of cli.md section 5. every
    /// failure path returns without writing artifacts the run cannot vouch for.
    pub fn run_session(spec: SessionSpec) -> Result<SessionOutcome, SessionError> {
        let caps = preflight::probe()?;
        let (caps, mechanism, mechanism_reason) = match preflight::evaluate(&caps, spec.mode) {
            Outcome::Proceed {
                caps,
                mechanism,
                mechanism_reason,
            } => (caps, mechanism, mechanism_reason),
            Outcome::Refuse(message) => return Err(SessionError::Refused(message)),
        };

        let enforcement = prepare_enforcement(&spec, caps.landlock_abi)?;

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
        };
        let run_dir = RunDir::create(&spec.state_root, &meta, SystemTime::now())?;
        let mut writer = run_dir.trace_writer()?;
        run_session_with_writer_and_ruleset(
            &spec,
            meta,
            &run_dir,
            &mut writer,
            enforcement.policy.as_ref(),
            enforcement.ruleset.as_ref().map(AsRawFd::as_raw_fd),
        )
    }

    fn prepare_enforcement(
        spec: &SessionSpec,
        landlock_abi: u32,
    ) -> Result<EnforcementSetup, SessionError> {
        if spec.mode == Mode::RecordOnly {
            return Ok(EnforcementSetup {
                policy: None,
                policy_digest: None,
                landlock_abi: None,
                landlock_residuals: None,
                ruleset: None,
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
        let hull: LandlockHull = landlock::derive_hull(&loaded.policy, landlock_abi);
        let ruleset = landlock::build_ruleset(&hull)?;

        Ok(EnforcementSetup {
            policy: Some(loaded.policy),
            policy_digest: Some(loaded.digest),
            landlock_abi: Some(landlock_abi),
            landlock_residuals: Some(hull.residuals),
            ruleset: Some(ruleset),
        })
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
        run_session_with_writer_and_ruleset(spec, meta, run_dir, writer, None, None)
    }

    fn run_session_with_writer_and_ruleset<S: TraceSink>(
        spec: &SessionSpec,
        meta: RunMeta,
        run_dir: &RunDir,
        writer: &mut TraceWriter<S>,
        _policy: Option<&crate::policy::Policy>,
        landlock_ruleset: Option<RawFd>,
    ) -> Result<SessionOutcome, SessionError> {
        // step 3: announce the mode on stderr; stdout belongs to the child (FR-19)
        match meta.mode {
            Mode::RecordOnly => eprintln!(
                "leash: record-only run; nothing is enforced, every action is allowed and recorded"
            ),
            Mode::Enforce => eprintln!("leash: enforce run"),
        }

        // step 4: run_start is appended and synced before the child exists, so any run
        // that produced a child also left durable evidence that it did (cli.md section 5)
        let mode = meta.mode;
        writer.append(meta.start_ts, EventBody::RunStart(meta))?;
        writer.sync()?;

        if mode == Mode::Enforce {
            return Err(SessionError::Run(
                crate::supervisor::run::RunError::UnsupportedMode,
            ));
        }

        // steps 5-6: spawn and serve until the tree exits
        let child = spawn_supervised(&SpawnSpec {
            argv: spec.argv.clone(),
            stdout: None,
            mode,
            landlock_ruleset,
        })?;
        let config = match mode {
            Mode::RecordOnly => {
                crate::supervisor::run::RunConfig::record_only(child.pid as u32, spec.attendance)
            }
            Mode::Enforce => {
                return Err(SessionError::Run(
                    crate::supervisor::run::RunError::UnsupportedMode,
                ));
            }
        };
        let outcome = run_loop(child, config, writer)?;

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
                // step detection is the snapshot slice; run start and end are the only
                // boundaries, so the final step index is 0 (FR-17 deferred)
                final_step: 0,
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
