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
    shell_quote_bytes(text.as_bytes())
}

/// `shell_quote` for a path, from its raw bytes: a name that is not UTF-8 is not rewritten
/// with replacement characters, which would name a different path, but written with each
/// invalid byte as a three-digit octal escape `\ooo` inside `$'...'`, which is unambiguous
/// whatever digits follow it (a `\x` escape is not, in ksh93). that form is bash and zsh
/// syntax, not POSIX `sh`; a path made of valid UTF-8 without control characters is quoted
/// for any shell.
pub fn shell_quote_path(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    shell_quote_bytes(path.as_os_str().as_bytes())
}

fn shell_quote_bytes(bytes: &[u8]) -> String {
    let plain = |b: &u8| b.is_ascii_alphanumeric() || b"_-./:@%+=,".contains(b);
    if !bytes.is_empty() && bytes.iter().all(plain) {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let needs_escapes = bytes
        .utf8_chunks()
        .any(|chunk| !chunk.invalid().is_empty() || chunk.valid().chars().any(char::is_control));
    if needs_escapes {
        let mut quoted = String::from("$'");
        for chunk in bytes.utf8_chunks() {
            for c in chunk.valid().chars() {
                match c {
                    '\\' => quoted.push_str("\\\\"),
                    '\'' => quoted.push_str("\\'"),
                    c if c.is_control() => {
                        let mut buf = [0u8; 4];
                        for byte in c.encode_utf8(&mut buf).bytes() {
                            quoted.push_str(&format!("\\{byte:03o}"));
                        }
                    }
                    c => quoted.push(c),
                }
            }
            for byte in chunk.invalid() {
                quoted.push_str(&format!("\\{byte:03o}"));
            }
        }
        quoted.push('\'');
        return quoted;
    }
    // valid UTF-8 with no control character, so the lossy conversion changes nothing
    format!(
        "'{}'",
        String::from_utf8_lossy(bytes).replace('\'', "'\\''")
    )
}

/// the command that restores safety snapshot `n` of `run_id`, checked against the manifest
/// digest `digest` the rewind printed when it took the snapshot.
pub fn undo_command(
    run_id: &str,
    n: u64,
    digest: &str,
    workspace: &Path,
    state_root: &Path,
) -> String {
    format!(
        "leash rewind {} --undo {n} --expect {digest} --workspace {} --state-dir {}",
        shell_quote(run_id),
        shell_quote_path(workspace),
        shell_quote_path(state_root),
    )
}

/// the last line a finished snapshot run prints: the command that rewinds it, checked against
/// the chain head the run just printed. the workspace and state directory are spelled out so
/// the command works from any directory and for a non-default state root, and every value
/// is shell-quoted so the line can be pasted.
pub fn rewind_hint(run_id: &str, chain_head: &str, workspace: &Path, state_root: &Path) -> String {
    format!(
        "leash: to undo this run: leash rewind {} --expect {chain_head} --workspace {} --state-dir {}",
        shell_quote(run_id),
        shell_quote_path(workspace),
        shell_quote_path(state_root),
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
    linux::run(req, out, err, &RewindHooks::default())
}

/// test seams of [`run_rewind`]: the identity the rewind believes it runs as, and a call
/// made after the workspace is checked and just before it is opened and locked.
#[cfg(target_os = "linux")]
#[doc(hidden)]
#[derive(Default)]
pub struct RewindHooks<'a> {
    /// replaces the identity of the process, so the root refusal can be tested
    pub identity: Option<crate::snapshot::restore::RestoreContext>,
    /// runs between the workspace check and the open of the workspace
    pub before_workspace_open: Option<&'a dyn Fn()>,
}

/// [`run_rewind`] with test seams.
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub fn run_rewind_with_hooks(
    req: &RewindRequest,
    out: &mut dyn Write,
    err: &mut dyn Write,
    hooks: &RewindHooks<'_>,
) -> Result<(), RewindError> {
    linux::run(req, out, err, hooks)
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
    use std::collections::{HashMap, HashSet};
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    use super::*;
    use crate::recorder::{RunMeta, TRACE_SCHEMA_VERSION};
    use crate::run_diff::open_dir_at;
    use crate::runs::META_READ_CAP;
    use crate::snapshot::diff::display_path;
    use crate::snapshot::restore::{
        RestoreContext, RestoreError, RestoreOp, apply_with_context, plan, recompute_chain,
        scan_current,
    };
    use crate::snapshot::store::{
        Limits, Manifest, ManifestEntry, TraceRead, capture, load_manifest, published_steps,
        read_trace, verify_object,
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
        hooks: &RewindHooks<'_>,
    ) -> Result<(), RewindError> {
        // root is refused before anything is opened: the stale-run cleanup and the workspace
        // lock would otherwise create root-owned entries, and the cleanup would run as root
        let ctx = match &hooks.identity {
            Some(ctx) => ctx.clone(),
            None => RestoreContext::from_process().map_err(|e| failure(e.to_string()))?,
        };
        if ctx.euid == 0 {
            return Err(failure(RestoreError::RunningAsRoot.to_string()));
        }
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
        // the target and the integrity checks are read-only, so they come before anything
        // that acts on the run directory: the stale cleanup below is driven by the untrusted
        // `meta.json` and may kill and remove cgroups, so it runs only for a run whose trace
        // and store already passed
        let target = resolve_target(req, &open, &label)?;
        let _run_lock = ensure_run_over(req, &open.run_dir, &recorded, &label)?;
        if let Some(hook) = hooks.before_workspace_open {
            hook();
        }
        let workspace_lock = WorkspaceLock::acquire(&req.state_root, &req.workspace)
            .map_err(|e| failure(e.to_string()))?;
        // the checks above compared a path, and the lock opened it a moment later. the path
        // read back from the locked handle is the directory that was really opened, so a
        // component swapped for a symlink in between is caught here, before any write.
        if workspace_lock.canonical_workspace() != req.workspace {
            return Err(failure(format!(
                "the workspace changed while rewind opened it: expected {}, opened {}",
                display_path(&req.workspace.to_string_lossy()),
                display_path(&workspace_lock.canonical_workspace().to_string_lossy())
            )));
        }

        // the values the checks compared are printed once the whole of them has passed
        for line in &target.heading {
            writeln!(out, "{line}")?;
        }
        if req.expect.is_none() {
            let what = match req.target {
                RewindTarget::Step(_) => {
                    "the store is checked only against the trace beside it, so a forged store \
                     and trace are not detected; pass the chain head printed at run end"
                }
                RewindTarget::Undo(_) => {
                    "the undo store is checked against nothing, so a forged undo store is not \
                     detected; pass the safety snapshot digest printed by the earlier rewind"
                }
            };
            writeln!(err, "leash: note: no --expect given; {what}")?;
        }
        // the locked directory handle itself is what is scanned, captured and restored,
        // so the directory that is locked is the directory that changes (ADR-0026)
        let workspace = workspace_lock.workspace_dir();
        let limits = Limits::default();

        // the safety snapshot (decision 21): capture the workspace into a store of its own.
        // when it cannot be taken the rewind refuses, and --no-undo plans from a tolerant
        // scan instead.
        let mut safety = None;
        let current = if req.no_undo {
            let (manifest, refused) = scan_current(workspace, &limits)
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
            let mut undo = create_undo_store(&open.run_dir, req)?;
            let refused = |e: &dyn std::fmt::Display| {
                failure(format!(
                    "cannot take the safety snapshot of the workspace: {e}; \
                     pass --no-undo to rewind without one (the rewind then cannot be undone)"
                ))
            };
            capture(workspace, &undo.store, 0, &limits).map_err(|e| refused(&e))?;
            let (manifest, digest) = load_manifest(&undo.store, 0).map_err(|e| refused(&e))?;
            undo.digest = digest;
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
            writeln!(out, "safety snapshot digest: {}", undo.digest)?;
            writeln!(
                out,
                "to undo this rewind: {}",
                undo_command(
                    &req.run_id,
                    undo.n,
                    &undo.digest,
                    &req.workspace,
                    &req.state_root
                )
            )?;
        }
        write!(out, "{}", rewind_plan.summary())?;
        out.flush()?;

        // from here the workspace changes, so the safety snapshot stays whatever happens
        if let Some(undo) = safety.as_mut() {
            undo.keep = true;
        }
        match apply_with_context(
            workspace,
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
                        undo_command(
                            &req.run_id,
                            undo.n,
                            &undo.digest,
                            &req.workspace,
                            &req.state_root
                        )
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
        /// the lines to print once every check has passed: the chain head and the digest
        /// the target was checked against
        heading: Vec<String>,
    }

    fn resolve_target(
        req: &RewindRequest,
        open: &OpenRun,
        label: &str,
    ) -> Result<Target, RewindError> {
        match req.target {
            RewindTarget::Step(step) => resolve_step(req, open, label, step),
            RewindTarget::Undo(n) => resolve_undo(&open.run_dir, label, n, req.expect.as_deref()),
        }
    }

    fn resolve_step(
        req: &RewindRequest,
        open: &OpenRun,
        label: &str,
        step: u64,
    ) -> Result<Target, RewindError> {
        let trace = read_checked_trace(&open.run_dir, &open.meta, label)?;
        // the committed set comes from the trace's step events, never from the manifests on
        // disk, so an orphan manifest is neither a target nor part of the chain
        let committed = &trace.committed;
        let published = published_steps(&open.store)
            .map_err(|e| failure(format!("run '{label}': snapshot store: {e}")))?;
        if !committed.contains(&step) {
            let listed: Vec<String> = committed.iter().map(u64::to_string).collect();
            let committed = if listed.is_empty() {
                "none".to_string()
            } else {
                listed.join(", ")
            };
            return Err(if published.contains(&step) {
                usage(format!(
                    "run '{label}' step {step} has a snapshot but no committed step event, so it is not a \
                     rewind target (committed steps: {committed})"
                ))
            } else {
                usage(format!(
                    "run '{label}' has no committed step {step} (committed steps: {committed})"
                ))
            });
        }
        let chain = recompute_chain(&open.store, committed)
            .map_err(|e| failure(format!("run '{label}': snapshot store: {e}")))?;
        let Some(trace_digest) = trace.digests.get(&step) else {
            return Err(failure(format!(
                "run '{label}' step {step} is committed but its step event carries no manifest digest"
            )));
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
        let heading = vec![
            format!("chain head: {}", chain.head),
            format!("step {step} digest: {store_digest}"),
        ];
        let store = open.store.try_clone().map_err(|e| failure(e.to_string()))?;
        Ok(Target {
            manifest,
            store,
            label: format!("step {step}"),
            verb: "rewound the workspace to",
            heading,
        })
    }

    fn resolve_undo(
        run_dir: &File,
        label: &str,
        n: u64,
        expect: Option<&str>,
    ) -> Result<Target, RewindError> {
        let missing = || usage(format!("run '{label}' has no undo snapshot {n}"));
        let safety =
            open_dir_at(Some(run_dir), &c_name(SAFETY_DIR)?, false).map_err(|_| missing())?;
        let store = open_dir_at(Some(&safety), &c_name(&undo_dir_name(n))?, false)
            .map_err(|_| missing())?;
        let steps = published_steps(&store)
            .map_err(|e| failure(format!("run '{label}' undo snapshot {n}: {e}")))?;
        if steps != [0] {
            // a store that is not exactly step 0 is an integrity failure of a directory a
            // rewind made, not a request that names something missing
            return Err(failure(format!(
                "undo snapshot {n} of run '{label}' was never completed or is not a safety snapshot \
                 (its manifests are {steps:?}, expected only step 0)"
            )));
        }
        let (manifest, digest) = load_manifest(&store, 0)
            .map_err(|e| failure(format!("run '{label}' undo snapshot {n}: {e}")))?;
        if let Some(expect) = expect
            && expect != digest
        {
            return Err(failure(format!(
                "--expect {expect} does not match the digest of undo snapshot {n} {digest}"
            )));
        }
        Ok(Target {
            manifest,
            store,
            label: format!("undo snapshot {n}"),
            verb: "restored the workspace from",
            heading: Vec::new(),
        })
    }

    fn c_name(name: &str) -> Result<CString, RewindError> {
        CString::new(name).map_err(|_| failure("name contains a NUL byte"))
    }

    // ---- the trace ----

    /// read the trace once, through the store's streaming capped reader, and check what
    /// rewind needs beyond the committed steps: the trace starts with the `run_start` of
    /// this run's `meta.json`. every use of the trace goes through `read_trace`, so rewind
    /// and `diff` agree on which steps are committed by construction.
    fn read_checked_trace(
        run_dir: &File,
        meta: &RunMeta,
        label: &str,
    ) -> Result<TraceRead, RewindError> {
        let bad = |what: String| failure(format!("run '{label}': trace.jsonl: {what}"));
        let trace = read_trace(run_dir).map_err(|e| bad(e.to_string()))?;
        if trace.events == 0 {
            return Err(bad("no events".into()));
        }
        let Some(start) = &trace.run_start else {
            return Err(bad("the first event is not run_start".into()));
        };
        if start.workspace.as_deref() != Some(meta.workspace.as_path())
            || start.run_cgroup != meta.run_cgroup
        {
            return Err(bad("run_start disagrees with meta.json".into()));
        }
        Ok(trace)
    }

    // ---- the safety snapshot ----

    /// a safety snapshot store, removed again unless `keep` is set. it is removed through
    /// the handle of the `rewind` directory, never by path, and never through a symlink.
    struct Undo {
        n: u64,
        path: PathBuf,
        /// the `rewind` directory the snapshot lives in
        parent: File,
        /// the snapshot's name in `parent`
        name: CString,
        store: File,
        /// the manifest digest of the snapshot, set once it is captured
        digest: String,
        keep: bool,
    }

    impl Drop for Undo {
        fn drop(&mut self) {
            if !self.keep {
                let _ = remove_tree_at(&self.parent, &self.name, 0);
            }
        }
    }

    /// the deepest tree `remove_tree_at` descends into: a store has three levels.
    const REMOVE_DEPTH_LIMIT: u32 = 16;

    /// remove the directory `name` of `parent` and everything beneath it, descriptor by
    /// descriptor with `unlinkat`. a symlink is unlinked itself and never followed.
    fn remove_tree_at(parent: &File, name: &CStr, depth: u32) -> io::Result<()> {
        // SAFETY: parent is a live directory descriptor and name is nul-terminated;
        // O_NOFOLLOW makes a symlink fail with ELOOP or ENOTDIR instead of opening its target.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let e = io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::ENOENT) => Ok(()),
                Some(libc::ENOTDIR | libc::ELOOP) => unlink_at(parent, name, 0),
                _ => Err(e),
            };
        }
        // SAFETY: fd was returned by openat and is uniquely owned here.
        let dir = unsafe { File::from_raw_fd(fd) };
        if depth >= REMOVE_DEPTH_LIMIT {
            return Err(io::Error::other("directory tree is too deep"));
        }
        let mut first_error = None;
        for child in read_names(&dir)? {
            if let Err(e) = remove_tree_at(&dir, &child, depth + 1) {
                first_error.get_or_insert(e);
            }
        }
        match first_error {
            Some(e) => Err(e),
            None => unlink_at(parent, name, libc::AT_REMOVEDIR),
        }
    }

    fn unlink_at(parent: &File, name: &CStr, flags: libc::c_int) -> io::Result<()> {
        // SAFETY: parent is a live directory descriptor and name is nul-terminated.
        if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// the entry names of an open directory, without `.` and `..`.
    fn read_names(dir: &File) -> io::Result<Vec<CString>> {
        // SAFETY: dir is a live directory descriptor; "." reopens it as a fresh descriptor
        // that the stream below owns.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a uniquely owned directory descriptor; fdopendir takes ownership on
        // success.
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            let e = io::Error::last_os_error();
            // SAFETY: fdopendir failed, so fd is still ours to close.
            unsafe { libc::close(fd) };
            return Err(e);
        }
        let mut names = Vec::new();
        let result = loop {
            // SAFETY: __errno_location returns the current thread's errno slot.
            unsafe { *libc::__errno_location() = 0 };
            // SAFETY: stream is a live DIR* owned by this function.
            let ent = unsafe { libc::readdir(stream) };
            if ent.is_null() {
                let e = io::Error::last_os_error();
                break if e.raw_os_error() == Some(0) {
                    Ok(())
                } else {
                    Err(e)
                };
            }
            // SAFETY: ent is non-null and d_name is NUL-terminated, valid until the next
            // readdir or closedir.
            let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
            if name != c"." && name != c".." {
                names.push(name.to_owned());
            }
        };
        // SAFETY: stream came from fdopendir and is closed exactly once.
        unsafe { libc::closedir(stream) };
        result.map(|()| names)
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
                parent: safety,
                name,
                store,
                digest: String::new(),
                keep: false,
            });
        }
        Err(failure("no free undo snapshot number"))
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

    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    mod remove_tests {
        use super::*;
        use std::os::unix::fs::symlink;

        #[test]
        fn remove_tree_at_unlinks_a_symlink_and_never_follows_it() {
            let outside = tempfile::tempdir().unwrap();
            std::fs::write(outside.path().join("keep.txt"), "keep").unwrap();
            let parent = tempfile::tempdir().unwrap();
            let tree = parent.path().join("undo-1");
            std::fs::create_dir_all(tree.join("objects/ab")).unwrap();
            std::fs::write(tree.join("objects/ab/obj"), "x").unwrap();
            symlink(outside.path(), tree.join("objects/link")).unwrap();
            symlink(outside.path().join("keep.txt"), tree.join("file-link")).unwrap();

            let handle = File::open(parent.path()).unwrap();
            remove_tree_at(&handle, c"undo-1", 0).unwrap();
            assert!(!tree.exists());
            assert_eq!(
                std::fs::read_to_string(outside.path().join("keep.txt")).unwrap(),
                "keep",
                "the link target is untouched"
            );
        }

        #[test]
        fn remove_tree_at_a_symlink_name_removes_only_the_link() {
            let outside = tempfile::tempdir().unwrap();
            std::fs::write(outside.path().join("keep.txt"), "keep").unwrap();
            let parent = tempfile::tempdir().unwrap();
            symlink(outside.path(), parent.path().join("undo-1")).unwrap();

            let handle = File::open(parent.path()).unwrap();
            remove_tree_at(&handle, c"undo-1", 0).unwrap();
            assert!(!parent.path().join("undo-1").exists());
            assert!(outside.path().join("keep.txt").exists());
        }

        #[test]
        fn remove_tree_at_a_missing_name_is_fine() {
            let parent = tempfile::tempdir().unwrap();
            let handle = File::open(parent.path()).unwrap();
            remove_tree_at(&handle, c"nothing", 0).unwrap();
        }
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
        assert_eq!(shell_quote("a\nb"), "$'a\\012b'");
        assert_eq!(shell_quote("\x1b[2J"), "$'\\033[2J'");
        assert_eq!(shell_quote("a\\b\tc'"), "$'a\\\\b\\011c\\''");
    }

    #[test]
    fn the_undo_command_names_the_run_the_snapshot_the_workspace_and_the_state_root() {
        assert_eq!(
            undo_command(
                "20260101T000000Z-abc123",
                2,
                &"ab".repeat(32),
                Path::new("/w/my project"),
                Path::new("/s")
            ),
            format!(
                "leash rewind 20260101T000000Z-abc123 --undo 2 --expect {} --workspace '/w/my project' --state-dir /s",
                "ab".repeat(32)
            )
        );
    }

    #[test]
    fn the_run_end_hint_names_the_run_the_head_the_workspace_and_the_state_root() {
        assert_eq!(
            rewind_hint(
                "20260101T000000Z-abc123",
                &"cd".repeat(32),
                Path::new("/work/my repo"),
                Path::new("/state")
            ),
            format!(
                "leash: to undo this run: leash rewind 20260101T000000Z-abc123 --expect {} --workspace '/work/my repo' --state-dir /state",
                "cd".repeat(32)
            )
        );
    }

    #[test]
    fn a_path_that_is_not_utf8_is_quoted_from_its_bytes() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(b"/w/caf\xe9 dir"));
        assert_eq!(shell_quote_path(path), "$'/w/caf\\351 dir'");
        let hint = rewind_hint("id", &"0".repeat(64), path, Path::new("/s"));
        assert!(hint.contains("--workspace $'/w/caf\\351 dir' "), "{hint}");
        assert!(!hint.contains('\u{fffd}'), "{hint}");
    }

    #[test]
    fn a_valid_utf8_path_is_quoted_the_same_as_its_text() {
        for text in [
            "/w/plain",
            "/w/a b",
            "/w/it's",
            "/w/caf\u{e9}",
            "/w/a\nb",
            "",
        ] {
            assert_eq!(
                shell_quote_path(Path::new(text)),
                shell_quote(text),
                "{text:?}"
            );
        }
    }

    #[test]
    fn the_run_end_hint_cannot_carry_a_line_break_from_a_path() {
        let hint = rewind_hint("id", &"0".repeat(64), Path::new("/a\nb"), Path::new("/s"));
        assert!(!hint.contains('\n'), "{hint:?}");
    }
}
