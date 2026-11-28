//! `leash rewind`: restore a finished snapshot run's workspace to an earlier step (FR-12,
//! ADR-0024 decisions 17 to 22, docs/design/snapshot.md section 5).
//!
//! assumptions: argv and the state root come from the trusted operator, and everything
//! beneath the state root is untrusted input, a hostile run's leftovers included. the run
//! directory is opened component by component with `O_NOFOLLOW`, files are read through
//! handles, regular files only and capped. the store is checked against the trace's step
//! digests and an optional `--expect` digest before anything is written, then the restore
//! engine (`snapshot::restore`) applies the plan confined beneath the workspace.
//!
//! the safety snapshot (decision 21) lives in its own namespace, `<run_dir>/rewind/undo-<n>/`.
//! each `undo-<n>` is a complete store of its own (`objects/`, `manifests/step-000000.json`),
//! outside `snapshots/`, so it is never part of the chain, never listed as a step and never
//! reachable by `--step`. `leash rewind <run-id> --undo <n>` restores it, taking a new safety
//! snapshot first, so an undo can itself be undone.
//!
//! the command runs without a prompt: the operator invoked it, the change summary is printed
//! before the first write, and the safety snapshot is the way back.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// what a rewind restores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewindTarget {
    /// the committed step with this number of the run's own store
    Step(u64),
    /// the safety snapshot `rewind/undo-<n>` of an earlier rewind of the run
    Undo(u64),
}

/// a resolved rewind request: the caller (the cli) has canonicalized the workspace and the
/// state root and checked that the state root lies outside the workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewindRequest {
    /// the run directory name under `<state_root>/runs`
    pub run_id: String,
    /// the step or undo snapshot to restore
    pub target: RewindTarget,
    /// a chain head or step digest, lowercase hex, that the store must match
    pub expect: Option<String>,
    /// skip the safety snapshot
    pub no_undo: bool,
    /// the canonical workspace directory
    pub workspace: PathBuf,
    /// the state root
    pub state_root: PathBuf,
}

/// why a rewind did not happen.
#[derive(Debug, thiserror::Error)]
pub enum RewindError {
    /// the request names something that does not exist or does not fit: an unknown run or
    /// step, a run that is not a snapshot run, a workspace that is not the run's. exit 2.
    #[error("leash: {0}")]
    Usage(String),
    /// a refusal or failure at run time: a live run, a held lock, an integrity mismatch, a
    /// safety snapshot that cannot be taken, an apply error. exit 125.
    #[error("leash: {0}")]
    Failure(String),
}

impl From<io::Error> for RewindError {
    fn from(e: io::Error) -> Self {
        Self::Failure(format!("cannot write output: {e}"))
    }
}

/// the line every successful rewind prints last (ADR-0024 decision 22).
pub const EFFECTS_NOTICE: &str = "rewind reverses filesystem effects only; anything the agent sent off this machine is not undone";

/// the directory of a run that holds its safety snapshots.
pub const SAFETY_DIR: &str = "rewind";

/// the directory name of safety snapshot `n` under [`SAFETY_DIR`].
pub fn undo_dir_name(n: u64) -> String {
    format!("undo-{n}")
}

/// quote `text` for a POSIX shell so a printed command can be pasted. plain words stay
/// as they are, other text goes in single quotes, and text with a control character uses
/// `$'...'` with every control character escaped, so a path can never inject a line break
/// or a terminal escape into the output.
pub fn shell_quote(text: &str) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "_-./:@%+=,".contains(c);
    if !text.is_empty() && text.chars().all(plain) {
        return text.to_string();
    }
    if text.chars().any(char::is_control) {
        let mut quoted = String::from("$'");
        for c in text.chars() {
            match c {
                '\\' => quoted.push_str("\\\\"),
                '\'' => quoted.push_str("\\'"),
                c if c.is_control() => {
                    let mut buf = [0u8; 4];
                    for byte in c.encode_utf8(&mut buf).bytes() {
                        quoted.push_str(&format!("\\x{byte:02x}"));
                    }
                }
                c => quoted.push(c),
            }
        }
        quoted.push('\'');
        return quoted;
    }
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// the command that restores safety snapshot `n` of `run_id`.
pub fn undo_command(run_id: &str, n: u64, workspace: &Path, state_root: &Path) -> String {
    format!(
        "leash rewind {} --undo {n} --workspace {} --state-dir {}",
        shell_quote(run_id),
        shell_quote(&workspace.to_string_lossy()),
        shell_quote(&state_root.to_string_lossy()),
    )
}

/// restore the workspace of `req` and report to `out` (results) and `err` (warnings).
/// every refusal happens before the first write to the workspace.
#[cfg(target_os = "linux")]
pub fn run_rewind(
    req: &RewindRequest,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), RewindError> {
    linux::run(req, out, err)
}

/// rewind reads snapshot stores, which only linux produces.
#[cfg(not(target_os = "linux"))]
pub fn run_rewind(
    _req: &RewindRequest,
    _out: &mut dyn Write,
    _err: &mut dyn Write,
) -> Result<(), RewindError> {
    Err(RewindError::Failure(
        "rewind restores snapshot stores, which only linux produces (kernel 5.19 or later)".into(),
    ))
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    use serde::Deserialize;

    use super::*;
    use crate::recorder::{RunMeta, TRACE_SCHEMA_VERSION};
    use crate::run_diff::open_dir_at;
    use crate::runs::{META_READ_CAP, TRACE_READ_CAP};
    use crate::snapshot::diff::display_path;
    use crate::snapshot::restore::{
        RestoreContext, RestoreError, RestoreOp, apply_with_context, current_manifest, plan,
        recompute_chain, scan_current,
    };
    use crate::snapshot::store::{
        Limits, Manifest, ManifestEntry, committed_steps, load_manifest, verify_object,
    };
    use crate::supervisor::run_cgroup::{
        CgroupParent, RunCgroupState, RunLock, cleanup_stale, is_valid_run_id, run_cgroup_gone,
    };
    use crate::supervisor::workspace_lock::WorkspaceLock;

    fn usage(message: impl Into<String>) -> RewindError {
        RewindError::Usage(message.into())
    }

    fn failure(message: impl Into<String>) -> RewindError {
        RewindError::Failure(message.into())
    }

    /// the run directory, its store and its metadata, opened through handles.
    struct OpenRun {
        run_dir: File,
        store: File,
        meta: RunMeta,
    }

    pub(super) fn run(
        req: &RewindRequest,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<(), RewindError> {
        let label = display_path(&req.run_id);
        if !is_valid_run_id(&req.run_id) {
            return Err(usage(format!("unknown run '{label}'")));
        }
        if req.state_root.starts_with(&req.workspace) {
            return Err(usage(format!(
                "the state directory {} lies inside the workspace {}",
                display_path(&req.state_root.to_string_lossy()),
                display_path(&req.workspace.to_string_lossy())
            )));
        }
        let open = open_run(req, &label)?;
        check_workspace(req, &open.meta, &label)?;

        // the run must be over: its lock free and its cgroup gone. the lock stays held for
        // the whole rewind, so nothing can start cleaning this run up underneath it.
        let recorded = open
            .meta
            .run_cgroup
            .clone()
            .ok_or_else(|| usage(format!("run '{label}' is not a snapshot run")))?;
        let _run_lock = ensure_run_over(req, &open.run_dir, &recorded, &label)?;
        let _workspace_lock = WorkspaceLock::acquire(&req.state_root, &req.workspace)
            .map_err(|e| failure(e.to_string()))?;

        // the target and the integrity checks come before any write, the safety snapshot
        // included
        let target = resolve_target(req, &open, &label, out)?;

        let ctx = RestoreContext::from_process().map_err(|e| failure(e.to_string()))?;
        if ctx.euid == 0 {
            return Err(failure(RestoreError::RunningAsRoot.to_string()));
        }
        let workspace = open_workspace(req)?;
        let limits = Limits::default();

        // the safety snapshot (decision 21): capture the workspace into a store of its own.
        // when it cannot be taken the rewind refuses, and --no-undo plans from a tolerant
        // scan instead.
        let mut safety = None;
        let current = if req.no_undo {
            let (manifest, refused) = scan_current(&workspace, &limits)
                .map_err(|e| failure(format!("cannot scan the workspace: {e}")))?;
            writeln!(
                err,
                "leash: warning: --no-undo: no safety snapshot is taken, so this rewind cannot be undone"
            )?;
            for entry in &refused {
                writeln!(
                    err,
                    "leash: warning: {} cannot be captured ({}); the plan replaces or removes it",
                    display_path(&entry.path),
                    entry.reason
                )?;
            }
            manifest
        } else {
            let undo = create_undo_store(&open.run_dir, req)?;
            let manifest = current_manifest(&workspace, &undo.store, 0, &limits).map_err(|e| {
                failure(format!(
                    "cannot take the safety snapshot of the workspace: {e}; \
                     pass --no-undo to rewind without one (the rewind then cannot be undone)"
                ))
            })?;
            safety = Some(undo);
            manifest
        };

        let rewind_plan = plan(&current, &target.manifest);
        if rewind_plan.is_empty() {
            writeln!(out, "workspace already matches {}", target.label)?;
            writeln!(out, "{EFFECTS_NOTICE}")?;
            return Ok(());
        }
        verify_plan_objects(&target.store, &target.manifest, &rewind_plan)?;

        if let Some(undo) = &safety {
            writeln!(
                out,
                "safety snapshot: {} (undo {})",
                display_path(&undo.path.to_string_lossy()),
                undo.n
            )?;
            writeln!(
                out,
                "to undo this rewind: {}",
                undo_command(&req.run_id, undo.n, &req.workspace, &req.state_root)
            )?;
        }
        write!(out, "{}", rewind_plan.summary())?;
        out.flush()?;

        // from here the workspace changes, so the safety snapshot stays whatever happens
        if let Some(undo) = safety.as_mut() {
            undo.keep = true;
        }
        match apply_with_context(
            &workspace,
            &target.store,
            &target.manifest,
            &rewind_plan,
            &ctx,
        ) {
            Ok(stats) => {
                writeln!(
                    out,
                    "{} {}: {} removed, {} directories created, {} files written, {} hard links, {} symlinks, {} metadata fixes",
                    target.verb,
                    target.label,
                    stats.removed,
                    stats.dirs_created,
                    stats.files_written,
                    stats.hard_links,
                    stats.symlinks,
                    stats.metadata_fixed + stats.dirs_finalized
                )?;
                writeln!(out, "{EFFECTS_NOTICE}")?;
                Ok(())
            }
            Err(e) => {
                let mut message =
                    format!("rewind failed: {e}; the workspace may be partially restored");
                match &safety {
                    Some(undo) => message.push_str(&format!(
                        "; the safety snapshot is at {}, restore it with: {}",
                        display_path(&undo.path.to_string_lossy()),
                        undo_command(&req.run_id, undo.n, &req.workspace, &req.state_root)
                    )),
                    None => {
                        message.push_str("; --no-undo was given, so there is no safety snapshot")
                    }
                }
                Err(failure(message))
            }
        }
    }

    // ---- the run directory ----

    fn open_run(req: &RewindRequest, label: &str) -> Result<OpenRun, RewindError> {
        let unknown = || usage(format!("unknown run '{label}'"));
        let root_c = CString::new(req.state_root.as_os_str().as_bytes())
            .map_err(|_| failure("state directory contains a NUL byte"))?;
        let root = open_dir_at(None, &root_c, true).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                usage(format!("unknown run '{label}' (no state directory)"))
            } else {
                failure(format!("cannot open state directory: {e}"))
            }
        })?;
        // a missing or symlinked runs directory, run directory or store is never followed
        let runs = open_dir_at(Some(&root), c"runs", false).map_err(|_| unknown())?;
        let id_c = CString::new(req.run_id.as_str()).map_err(|_| unknown())?;
        let run_dir = open_dir_at(Some(&runs), &id_c, false).map_err(|_| unknown())?;
        let store = open_dir_at(Some(&run_dir), c"snapshots", false)
            .map_err(|_| usage(format!("run '{label}' has no snapshots")))?;
        let meta_bytes = read_capped_at(&run_dir, c"meta.json", META_READ_CAP)
            .map_err(|e| failure(format!("run '{label}': meta.json: {e}")))?;
        let meta: RunMeta = serde_json::from_slice(&meta_bytes)
            .map_err(|e| failure(format!("run '{label}': meta.json: {e}")))?;
        if meta.schema_version != TRACE_SCHEMA_VERSION {
            return Err(failure(format!(
                "run '{label}': meta.json: unsupported schema version {}",
                meta.schema_version
            )));
        }
        if meta.run_cgroup.is_none() {
            return Err(usage(format!(
                "run '{label}' is not a snapshot run: its metadata records no run cgroup"
            )));
        }
        Ok(OpenRun {
            run_dir,
            store,
            meta,
        })
    }

    /// read a file of a run directory without trusting it: never follow a symlink, never
    /// block on a fifo, accept only a regular file, and stop at `cap` bytes.
    fn read_capped_at(dir: &File, name: &CStr, cap: u64) -> io::Result<Vec<u8>> {
        // SAFETY: dir is a live directory descriptor and name is nul-terminated; openat
        // returns a fresh descriptor or -1.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd was returned by openat and is uniquely owned here.
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata()?;
        let too_large = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("larger than the {cap}-byte read limit"),
            )
        };
        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a regular file",
            ));
        }
        if meta.len() > cap {
            return Err(too_large());
        }
        let mut bytes = Vec::new();
        // the file can still grow after the size check, so the read itself is capped too
        file.take(cap + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > cap {
            return Err(too_large());
        }
        Ok(bytes)
    }

    /// ADR-0024 decision 19: the workspace must be the run's.
    fn check_workspace(
        req: &RewindRequest,
        meta: &RunMeta,
        label: &str,
    ) -> Result<(), RewindError> {
        let same = meta.workspace == req.workspace
            || meta
                .workspace
                .canonicalize()
                .is_ok_and(|canonical| canonical == req.workspace);
        if same {
            return Ok(());
        }
        Err(usage(format!(
            "the workspace {} is not the workspace of run '{label}' ({}); \
             run rewind from that directory or pass --workspace",
            display_path(&req.workspace.to_string_lossy()),
            display_path(&meta.workspace.to_string_lossy())
        )))
    }

    // ---- is the run over ----

    /// take the run lock and require the recorded cgroup to be gone (ADR-0024 decision 17).
    /// a held lock means the run is alive. `Present` is first offered to the stale cleanup,
    /// which kills and removes a cgroup whose run lock can be taken and whose lock xattr
    /// matches; `Unknown` is never treated as gone.
    fn ensure_run_over(
        req: &RewindRequest,
        run_dir: &File,
        recorded: &Path,
        label: &str,
    ) -> Result<RunLock, RewindError> {
        let live = || {
            failure(format!(
                "run '{label}' is still running: its run.lock is held; wait for it to end"
            ))
        };
        let take = || match RunLock::try_acquire_in(run_dir) {
            Ok(Some(lock)) => Ok(lock),
            Ok(None) => Err(live()),
            Err(e) => Err(failure(format!("run '{label}': cannot take run.lock: {e}"))),
        };
        let state_of = || {
            run_cgroup_gone(recorded, &req.run_id).map_err(|e| {
                failure(format!(
                    "run '{label}': the recorded run cgroup {} is not valid for this run: {e}",
                    display_path(&recorded.to_string_lossy())
                ))
            })
        };
        let cgroup = display_path(&recorded.to_string_lossy());
        let lock = take()?;
        match state_of()? {
            RunCgroupState::Gone => return Ok(lock),
            RunCgroupState::Unknown => {
                return Err(failure(format!(
                    "cannot confirm that the run cgroup {cgroup} is gone: it is not under a readable cgroup2 \
                     mount in this namespace; run rewind where the run's cgroup hierarchy is visible"
                )));
            }
            RunCgroupState::Present => {}
        }
        // the lock is free, so the run is dead and its cgroup is stale. the cleanup takes
        // the lock itself, so release ours for the duration.
        drop(lock);
        if let Some(parent_path) = recorded.parent()
            && let Ok(parent) = CgroupParent::open_writable(parent_path)
        {
            let _ = cleanup_stale(&parent, &req.state_root, None);
        }
        let lock = take()?;
        match state_of()? {
            RunCgroupState::Gone => Ok(lock),
            RunCgroupState::Present => Err(failure(format!(
                "the run cgroup {cgroup} still exists, so processes of the run may still be \
                 running; stop them and remove the cgroup, then rewind"
            ))),
            RunCgroupState::Unknown => Err(failure(format!(
                "cannot confirm that the run cgroup {cgroup} is gone after cleaning it up"
            ))),
        }
    }

    // ---- the target ----

    /// what `apply` restores and where its objects live.
    struct Target {
        manifest: Manifest,
        /// the store that holds the objects of `manifest`
        store: File,
        /// "step 3" or "undo snapshot 2"
        label: String,
        /// "rewound the workspace to" or "restored the workspace from"
        verb: &'static str,
    }

    fn resolve_target(
        req: &RewindRequest,
        open: &OpenRun,
        label: &str,
        out: &mut dyn Write,
    ) -> Result<Target, RewindError> {
        match req.target {
            RewindTarget::Step(step) => resolve_step(req, open, label, step, out),
            RewindTarget::Undo(n) => resolve_undo(&open.run_dir, label, n),
        }
    }

    fn resolve_step(
        req: &RewindRequest,
        open: &OpenRun,
        label: &str,
        step: u64,
        out: &mut dyn Write,
    ) -> Result<Target, RewindError> {
        let trace = read_trace(&open.run_dir, &open.meta, label)?;
        let chain = recompute_chain(&open.store)
            .map_err(|e| failure(format!("run '{label}': snapshot store: {e}")))?;
        let Some(trace_digest) = trace.get(&step) else {
            let committed: Vec<String> = trace.keys().map(u64::to_string).collect();
            let committed = if committed.is_empty() {
                "none".to_string()
            } else {
                committed.join(", ")
            };
            return Err(if chain.digest(step).is_some() {
                usage(format!(
                    "run '{label}' step {step} has a snapshot but no committed step event, so it is not a \
                     rewind target (committed steps: {committed})"
                ))
            } else {
                usage(format!(
                    "run '{label}' has no committed step {step} (committed steps: {committed})"
                ))
            });
        };
        let Some(store_digest) = chain.digest(step) else {
            return Err(failure(format!(
                "run '{label}' step {step} has a committed step event but no snapshot in the store"
            )));
        };
        if store_digest != trace_digest {
            return Err(failure(format!(
                "the snapshot store does not match the trace for run '{label}' step {step}: \
                 the store's manifest digest is {store_digest}, the trace's step event says {trace_digest}"
            )));
        }
        if let Some(expect) = &req.expect
            && expect != &chain.head
            && expect != store_digest
        {
            return Err(failure(format!(
                "--expect {expect} matches neither the chain head {} nor the digest of step {step} {store_digest}",
                chain.head
            )));
        }
        let (manifest, loaded_digest) = load_manifest(&open.store, step)
            .map_err(|e| failure(format!("run '{label}' step {step}: {e}")))?;
        if loaded_digest != store_digest {
            return Err(failure(format!(
                "the manifest of step {step} changed while it was being checked: \
                 {store_digest} then {loaded_digest}"
            )));
        }
        writeln!(out, "chain head: {}", chain.head)?;
        writeln!(out, "step {step} digest: {store_digest}")?;
        let store = open.store.try_clone().map_err(|e| failure(e.to_string()))?;
        Ok(Target {
            manifest,
            store,
            label: format!("step {step}"),
            verb: "rewound the workspace to",
        })
    }

    fn resolve_undo(run_dir: &File, label: &str, n: u64) -> Result<Target, RewindError> {
        let missing = || usage(format!("run '{label}' has no undo snapshot {n}"));
        let safety =
            open_dir_at(Some(run_dir), &c_name(SAFETY_DIR)?, false).map_err(|_| missing())?;
        let store = open_dir_at(Some(&safety), &c_name(&undo_dir_name(n))?, false)
            .map_err(|_| missing())?;
        let steps = committed_steps(&store)
            .map_err(|e| failure(format!("run '{label}' undo snapshot {n}: {e}")))?;
        if steps != [0] {
            return Err(usage(format!(
                "undo snapshot {n} of run '{label}' was never completed"
            )));
        }
        let (manifest, _) = load_manifest(&store, 0)
            .map_err(|e| failure(format!("run '{label}' undo snapshot {n}: {e}")))?;
        Ok(Target {
            manifest,
            store,
            label: format!("undo snapshot {n}"),
            verb: "restored the workspace from",
        })
    }

    fn c_name(name: &str) -> Result<CString, RewindError> {
        CString::new(name).map_err(|_| failure("name contains a NUL byte"))
    }

    // ---- the trace ----

    #[derive(Deserialize)]
    struct EventKind {
        #[serde(rename = "type")]
        kind: String,
    }

    #[derive(Deserialize)]
    struct StepEvent {
        step: u64,
        manifest_digest: Option<String>,
    }

    #[derive(Deserialize)]
    struct StartEvent {
        workspace: PathBuf,
        run_cgroup: Option<PathBuf>,
    }

    /// the committed steps of the trace: step number to the manifest digest its step event
    /// carries. the trace is untrusted: it is read through a handle, capped, and every line
    /// is parsed strictly, except that an unterminated final line (a crash mid-write) is
    /// ignored when it does not parse.
    fn read_trace(
        run_dir: &File,
        meta: &RunMeta,
        label: &str,
    ) -> Result<BTreeMap<u64, String>, RewindError> {
        let bad = |what: String| failure(format!("run '{label}': trace.jsonl: {what}"));
        let bytes = read_capped_at(run_dir, c"trace.jsonl", TRACE_READ_CAP)
            .map_err(|e| bad(e.to_string()))?;
        let text = std::str::from_utf8(&bytes).map_err(|e| bad(e.to_string()))?;
        let terminated = text.ends_with('\n');
        let lines: Vec<&str> = text.split('\n').collect();
        let mut steps = BTreeMap::new();
        let mut events = 0usize;
        for (index, line) in lines.iter().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let torn_tail = index + 1 == lines.len() && !terminated;
            let at = index + 1;
            let kind: EventKind = match serde_json::from_str(line) {
                Ok(kind) => kind,
                Err(_) if torn_tail => continue,
                Err(e) => return Err(bad(format!("line {at}: {e}"))),
            };
            match kind.kind.as_str() {
                "run_start" => {
                    if events != 0 {
                        return Err(bad(format!("line {at}: a second run_start")));
                    }
                    let start: StartEvent =
                        serde_json::from_str(line).map_err(|e| bad(format!("line {at}: {e}")))?;
                    if start.workspace != meta.workspace || start.run_cgroup != meta.run_cgroup {
                        return Err(bad("run_start disagrees with meta.json".into()));
                    }
                }
                _ if events == 0 => return Err(bad("the first event is not run_start".into())),
                "step" => {
                    let step: StepEvent = match serde_json::from_str(line) {
                        Ok(step) => step,
                        Err(_) if torn_tail => continue,
                        Err(e) => return Err(bad(format!("line {at}: {e}"))),
                    };
                    // a step event without a digest binds no snapshot: not a target
                    let Some(digest) = step.manifest_digest else {
                        continue;
                    };
                    if digest.len() != 64
                        || !digest
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    {
                        return Err(bad(format!(
                            "line {at}: the digest of step {} is not 64 lowercase hex digits",
                            step.step
                        )));
                    }
                    if steps.insert(step.step, digest).is_some() {
                        return Err(bad(format!("step {} is committed twice", step.step)));
                    }
                }
                _ => {}
            }
            events += 1;
        }
        if events == 0 {
            return Err(bad("no events".into()));
        }
        Ok(steps)
    }

    // ---- the safety snapshot ----

    /// a safety snapshot store, removed again unless `keep` is set.
    struct Undo {
        n: u64,
        path: PathBuf,
        store: File,
        keep: bool,
    }

    impl Drop for Undo {
        fn drop(&mut self) {
            if !self.keep {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }

    /// create the next free `rewind/undo-<n>` directory of the run and open it as a store.
    fn create_undo_store(run_dir: &File, req: &RewindRequest) -> Result<Undo, RewindError> {
        let fail = |what: &str, e: io::Error| {
            failure(format!(
                "cannot take the safety snapshot of the workspace: {what}: {e}; \
                 pass --no-undo to rewind without one (the rewind then cannot be undone)"
            ))
        };
        // SAFETY: run_dir is a live directory descriptor and the name is nul-terminated.
        let made = unsafe { libc::mkdirat(run_dir.as_raw_fd(), c"rewind".as_ptr(), 0o700) };
        if made != 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EEXIST) {
                return Err(fail("cannot create the rewind directory", e));
            }
        }
        let safety = open_dir_at(Some(run_dir), c"rewind", false)
            .map_err(|e| fail("cannot open the rewind directory", e))?;
        for n in 1..=u64::from(u32::MAX) {
            let name = c_name(&undo_dir_name(n))?;
            // SAFETY: safety is a live directory descriptor and name is nul-terminated.
            let made = unsafe { libc::mkdirat(safety.as_raw_fd(), name.as_ptr(), 0o700) };
            if made != 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EEXIST) {
                    continue;
                }
                return Err(fail("cannot create the undo directory", e));
            }
            let store = open_dir_at(Some(&safety), &name, false)
                .map_err(|e| fail("cannot open the undo directory", e))?;
            let path = req
                .state_root
                .join("runs")
                .join(&req.run_id)
                .join(SAFETY_DIR)
                .join(undo_dir_name(n));
            return Ok(Undo {
                n,
                path,
                store,
                keep: false,
            });
        }
        Err(failure("no free undo snapshot number"))
    }

    fn open_workspace(req: &RewindRequest) -> Result<File, RewindError> {
        let path = c_name(&req.workspace.to_string_lossy())?;
        open_dir_at(None, &path, false).map_err(|e| {
            failure(format!(
                "cannot open the workspace {}: {e}",
                display_path(&req.workspace.to_string_lossy())
            ))
        })
    }

    /// verify every store object the plan will write before the first write, so a corrupt
    /// or missing object refuses the rewind instead of leaving the workspace half restored.
    fn verify_plan_objects(
        store: &File,
        target: &Manifest,
        rewind_plan: &crate::snapshot::restore::RestorePlan,
    ) -> Result<(), RewindError> {
        let entries: HashMap<&str, &ManifestEntry> = target
            .entries
            .iter()
            .map(|e| (e.path.as_str(), e))
            .collect();
        let mut seen = HashSet::new();
        for op in &rewind_plan.ops {
            if let RestoreOp::WriteFile { path } = op
                && let Some(sha) = entries.get(path.as_str()).and_then(|e| e.sha256.as_deref())
                && seen.insert(sha)
            {
                verify_object(store, sha).map_err(|e| {
                    failure(format!(
                        "the store's object for {} failed verification: {e}; nothing was changed",
                        display_path(path)
                    ))
                })?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_words_are_not_quoted() {
        assert_eq!(shell_quote("/home/me/work-1.2"), "/home/me/work-1.2");
        assert_eq!(
            shell_quote("20260101T000000Z-abc123"),
            "20260101T000000Z-abc123"
        );
    }

    #[test]
    fn spaces_and_quotes_are_single_quoted() {
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("$(x)`y`"), "'$(x)`y`'");
    }

    #[test]
    fn control_characters_are_escaped_never_printed() {
        assert_eq!(shell_quote("a\nb"), "$'a\\x0ab'");
        assert_eq!(shell_quote("\x1b[2J"), "$'\\x1b[2J'");
        assert_eq!(shell_quote("a\\b\tc'"), "$'a\\\\b\\x09c\\''");
    }

    #[test]
    fn the_undo_command_names_the_run_the_snapshot_the_workspace_and_the_state_root() {
        assert_eq!(
            undo_command(
                "20260101T000000Z-abc123",
                2,
                Path::new("/w/my project"),
                Path::new("/s")
            ),
            "leash rewind 20260101T000000Z-abc123 --undo 2 --workspace '/w/my project' --state-dir /s"
        );
    }
}
