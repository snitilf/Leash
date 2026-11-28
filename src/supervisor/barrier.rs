//! the capture barrier of a snapshot run (ADR-0024 decisions 10, 11, 14 and 16;
//! docs/design/snapshot.md section 2).
//!
//! assumptions: the notify loop is single-threaded and answers each notification before it
//! polls for a boundary, so no notification is received but unanswered when a boundary
//! starts. the run cgroup holds the agent's whole tree, born into it with
//! `clone3(CLONE_INTO_CGROUP)`, and the supervisor and broker are outside it. a received
//! but unanswered notification blocks `frozen=1` under `WAIT_KILLABLE_RECV`, while an
//! unreceived one is interrupted and restarted after the thaw (measurement 0003 question
//! 2), which is why the barrier never receives between freeze and thaw.
//!
//! the order at a boundary, run by `run::run_loop`:
//! 1. the current notification has been answered (the loop is synchronous)
//! 2. stop receiving
//! 3. write `cgroup.freeze=1` and wait boundedly for `frozen=1`
//! 4. capture into the store, staging the manifest
//! 5. re-read `cgroup.events` and require `frozen=1` still, before anything is published
//! 6. publish the manifest durably, then write the step event and sync the trace
//! 7. write `cgroup.freeze=0` and wait boundedly for `frozen=0`
//! 8. resume receiving
//!
//! step 5 runs inside the store's capture, as its `before_publish` check, so a cgroup that
//! thawed during the capture leaves no manifest for the step at all. a manifest that exists
//! for a step was captured and published under an unbroken freeze. the only published
//! manifest that can lack a step event is one whose event could not be made durable
//! (`capture_failed` phase `step_event`), which `committed_steps_from_trace` excludes.
//!
//! any failure aborts the run closed: the failure is recorded when the recorder still
//! works, the whole run cgroup is killed, and the run exits 125 with no `run_end`.
//! an agent cannot make Leash skip a boundary: a capture limit hit, an entry capture
//! refuses, a freeze that never completes and a thaw that never completes all end the run.

use std::cell::RefCell;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::FromRawFd;
use std::path::Path;
use std::time::Duration;

use crate::recorder::{
    CaptureFailedEvent, CapturePhase, CaptureSummary, EventBody, RecorderError, StepSnapshot,
    TraceSink, TraceWriter,
};
use crate::snapshot::BoundaryCapture;
use crate::snapshot::restore::chain_head;
use crate::snapshot::store::{self, Limits, Published, StoreError};
use crate::supervisor::cgroup::Cgroup;
use crate::supervisor::run::RunError;

/// how long the barrier waits for `cgroup.events` to report `frozen=1` after it writes
/// `cgroup.freeze=1`. measured freezes of an idle tree take about 5 ms (measurement 0003),
/// so two seconds is slack for a loaded host, not a working budget. a tree that has not
/// frozen by then is not going to: the run aborts and the whole cgroup is killed.
pub const FREEZE_TIMEOUT: Duration = Duration::from_secs(2);

/// how long the barrier waits for `frozen=0` after it writes `cgroup.freeze=0`. a thaw
/// that does not complete leaves an agent stopped with a committed step, so the run aborts.
pub const THAW_TIMEOUT: Duration = Duration::from_secs(2);

pub use crate::snapshot::MIN_BOUNDARY_INTERVAL;

/// the freezer operations of a boundary and its timing, as a seam: production uses the
/// run cgroup's own control files, tests substitute failures that no real tree can be made
/// to produce (an agent cannot install its own `NEW_LISTENER` filter under Leash's, so a
/// freeze that times out has no kernel-level trigger an agent can reach).
#[derive(Clone, Copy)]
pub struct BarrierOps<'a> {
    /// write `cgroup.freeze=1` and wait for `frozen=1` for at most the timeout.
    pub freeze: &'a dyn Fn(&Cgroup, Duration) -> io::Result<()>,
    /// write `cgroup.freeze=0` and wait for `frozen=0` for at most the timeout.
    pub thaw: &'a dyn Fn(&Cgroup, Duration) -> io::Result<()>,
    /// read `cgroup.events` and report whether `frozen` is 1 right now.
    pub is_frozen: &'a dyn Fn(&Cgroup) -> io::Result<bool>,
    /// the freeze wait bound.
    pub freeze_timeout: Duration,
    /// the thaw wait bound.
    pub thaw_timeout: Duration,
    /// the least time between the end of one boundary and the start of the next.
    pub min_interval: Duration,
}

impl Default for BarrierOps<'static> {
    fn default() -> Self {
        Self {
            freeze: &|group, timeout| group.set_frozen(true, timeout),
            thaw: &|group, timeout| group.set_frozen(false, timeout),
            is_frozen: &Cgroup::is_frozen,
            freeze_timeout: FREEZE_TIMEOUT,
            thaw_timeout: THAW_TIMEOUT,
            min_interval: MIN_BOUNDARY_INTERVAL,
        }
    }
}

/// the snapshot sink of one run over its store: the workspace and the store are pinned
/// directory handles opened before the agent exists, and every digest the store returned
/// and the trace committed is kept to recompute the chain head at run end.
pub struct StoreCapture<'a> {
    workspace: File,
    store: File,
    limits: Limits,
    committed: RefCell<Vec<(u64, String)>>,
    chain: ChainHeadFn<'a>,
}

/// how the chain head is computed from the committed `(step, digest)` pairs. production uses
/// `restore::chain_head`; tests substitute a failure, which a store of valid digests never
/// produces.
pub type ChainHeadFn<'a> = &'a dyn Fn(&[(u64, String)]) -> Result<String, StoreError>;

impl StoreCapture<'static> {
    /// open `workspace` and `store_dir` as pinned directory handles. both are opened
    /// `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`, so a symlink in either place is refused.
    pub fn open(workspace: &Path, store_dir: &Path, limits: Limits) -> io::Result<Self> {
        Self::with_workspace(open_pinned_dir(workspace)?, store_dir, limits)
    }

    /// capture through an already open workspace directory handle, and open `store_dir` as a
    /// pinned handle. the run passes a duplicate of the handle its workspace lock holds, so
    /// the directory that is locked is the directory that is captured, with no second
    /// resolution of a path between the two (ADR-0026).
    pub fn with_workspace(workspace: File, store_dir: &Path, limits: Limits) -> io::Result<Self> {
        Ok(Self {
            workspace,
            store: open_pinned_dir(store_dir)?,
            limits,
            committed: RefCell::new(Vec::new()),
            chain: &chain_head,
        })
    }
}

impl<'a> StoreCapture<'a> {
    /// compute the chain head with `chain` instead of `restore::chain_head`.
    pub fn with_chain_head<'b>(self, chain: ChainHeadFn<'b>) -> StoreCapture<'b> {
        StoreCapture {
            workspace: self.workspace,
            store: self.store,
            limits: self.limits,
            committed: self.committed,
            chain,
        }
    }

    /// the store handle, for checking a run's snapshots from the supervisor side.
    pub fn store(&self) -> &File {
        &self.store
    }
}

impl BoundaryCapture for StoreCapture<'_> {
    fn capture_gated(
        &self,
        step: u64,
        before_publish: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Published, StoreError> {
        store::capture_gated(
            &self.workspace,
            &self.store,
            step,
            &self.limits,
            before_publish,
        )
    }

    fn committed(&self, step: u64, manifest_digest: &str) {
        self.committed
            .borrow_mut()
            .push((step, manifest_digest.to_string()));
    }

    fn chain_head(&self) -> Result<String, StoreError> {
        (self.chain)(&self.committed.borrow())
    }
}

fn open_pinned_dir(path: &Path) -> io::Result<File> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: c_path is nul-terminated; open returns a new descriptor or -1.
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was just returned by open and nothing else owns it.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// the step event body for a committed snapshot. `pause` is zero for step 0 and the final
/// step, where no agent is running.
pub fn step_event(step: u64, published: &Published, pause: Duration) -> EventBody {
    EventBody::Step {
        step,
        snapshot: Some(StepSnapshot {
            manifest_digest: published.manifest_digest.clone(),
            capture_pause_us: u64::try_from(pause.as_micros()).unwrap_or(u64::MAX),
            capture: CaptureSummary {
                entries: published.stats.entries,
                bytes: published.stats.total_bytes,
                new_objects: published.stats.new_objects,
            },
        }),
    }
}

/// record that a boundary failed, when the recorder still works, and build the error that
/// aborts the run. a failure to record the failure is ignored: the run is already failing.
pub fn fail_boundary<S: TraceSink>(
    writer: &mut TraceWriter<S>,
    ts: u64,
    step: u64,
    phase: CapturePhase,
    error: impl std::fmt::Display,
) -> RunError {
    let message = error.to_string();
    let _ = writer
        .append(
            ts,
            EventBody::CaptureFailed(CaptureFailedEvent {
                step,
                phase,
                error: message.clone(),
            }),
        )
        .and_then(|_| writer.sync());
    RunError::Barrier {
        step,
        phase,
        message,
    }
}

/// commit one step: write its event, make the trace durable, add the digest to the chain,
/// and print it to stderr so a crashed run still showed its digests (ADR-0024 decision
/// 16). an error means the step is not committed.
pub fn commit_step<S: TraceSink>(
    writer: &mut TraceWriter<S>,
    ts: u64,
    capture: &dyn BoundaryCapture,
    step: u64,
    published: &Published,
    pause: Duration,
) -> Result<(), RecorderError> {
    writer.append(ts, step_event(step, published, pause))?;
    writer.sync()?;
    capture.committed(step, &published.manifest_digest);
    // a closed stderr must not stop the run: the digest is in the trace as well
    let _ = writeln!(
        io::stderr(),
        "leash: step {step} snapshot {}",
        published.manifest_digest
    );
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::recorder::TraceWriter;

    struct Sink(Vec<u8>);
    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl TraceSink for Sink {
        fn sync(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn ws_and_store() -> (tempfile::TempDir, tempfile::TempDir) {
        (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap())
    }

    #[test]
    fn store_capture_publishes_commits_and_chains_the_digests_it_returned() {
        let (ws, store) = ws_and_store();
        std::fs::write(ws.path().join("a"), "one").unwrap();
        let capture = StoreCapture::open(ws.path(), store.path(), Limits::default()).unwrap();
        let first = capture.capture(0).unwrap();
        capture.committed(0, &first.manifest_digest);
        std::fs::write(ws.path().join("b"), "two").unwrap();
        let second = capture.capture(1).unwrap();
        capture.committed(1, &second.manifest_digest);
        let expected = chain_head(&[
            (0, first.manifest_digest.clone()),
            (1, second.manifest_digest.clone()),
        ])
        .unwrap();
        assert_eq!(capture.chain_head().unwrap(), expected);
        assert_ne!(first.manifest_digest, second.manifest_digest);
    }

    #[test]
    fn an_uncommitted_capture_is_not_in_the_chain() {
        let (ws, store) = ws_and_store();
        let capture = StoreCapture::open(ws.path(), store.path(), Limits::default()).unwrap();
        let first = capture.capture(0).unwrap();
        capture.committed(0, &first.manifest_digest);
        let _orphan = capture.capture(1).unwrap();
        assert_eq!(
            capture.chain_head().unwrap(),
            chain_head(&[(0, first.manifest_digest)]).unwrap()
        );
    }

    #[test]
    fn a_symlinked_workspace_or_store_is_refused() {
        let (ws, store) = ws_and_store();
        let links = tempfile::tempdir().unwrap();
        let ws_link = links.path().join("ws");
        std::os::unix::fs::symlink(ws.path(), &ws_link).unwrap();
        assert!(StoreCapture::open(&ws_link, store.path(), Limits::default()).is_err());
        let store_link = links.path().join("store");
        std::os::unix::fs::symlink(store.path(), &store_link).unwrap();
        assert!(StoreCapture::open(ws.path(), &store_link, Limits::default()).is_err());
    }

    #[test]
    fn a_limit_hit_is_a_capture_error_and_publishes_nothing() {
        let (ws, store) = ws_and_store();
        std::fs::write(ws.path().join("a"), "x").unwrap();
        std::fs::write(ws.path().join("b"), "y").unwrap();
        let limits = Limits {
            max_entries: 1,
            ..Limits::default()
        };
        let capture = StoreCapture::open(ws.path(), store.path(), limits).unwrap();
        assert!(matches!(
            capture.capture(0),
            Err(StoreError::EntryLimitExceeded { .. })
        ));
        assert!(!store.path().join("manifests/step-000000.json").exists());
    }

    #[test]
    fn commit_step_writes_a_durable_event_then_joins_the_chain() {
        let (ws, store) = ws_and_store();
        let capture = StoreCapture::open(ws.path(), store.path(), Limits::default()).unwrap();
        let published = capture.capture(0).unwrap();
        let mut writer = TraceWriter::new(Sink(Vec::new()));
        commit_step(
            &mut writer,
            5,
            &capture,
            0,
            &published,
            Duration::from_micros(42),
        )
        .unwrap();
        let text = String::from_utf8(writer.into_inner().0).unwrap();
        let event: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(event["type"], "step");
        assert_eq!(event["step"], 0);
        assert_eq!(event["manifest_digest"], published.manifest_digest);
        assert_eq!(event["capture_pause_us"], 42);
        assert_eq!(event["capture"]["entries"], 0);
        assert_eq!(
            capture.chain_head().unwrap(),
            chain_head(&[(0, published.manifest_digest)]).unwrap()
        );
    }

    #[test]
    fn a_failed_boundary_is_recorded_and_aborts_with_the_phase() {
        let mut writer = TraceWriter::new(Sink(Vec::new()));
        let error = fail_boundary(&mut writer, 9, 3, CapturePhase::Freeze, "never froze");
        assert!(matches!(
            error,
            RunError::Barrier {
                step: 3,
                phase: CapturePhase::Freeze,
                ..
            }
        ));
        let text = String::from_utf8(writer.into_inner().0).unwrap();
        let event: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(event["type"], "capture_failed");
        assert_eq!(event["phase"], "freeze");
        assert_eq!(event["error"], "never froze");
    }
}
