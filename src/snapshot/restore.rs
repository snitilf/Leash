//! rewind restore engine (ADR-0024 rules 16-22, docs/design/snapshot.md section 5).
//!
//! assumptions: the store is hostile input. a forged manifest or object must only be able
//! to produce workspace content, never a write outside the workspace. every operation is
//! relative to a workspace directory handle, parents are resolved with `openat2` and
//! `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`, no existing file is
//! ever opened for writing, and the process must not be root. the workspace is quiescent
//! (the run's cgroup is gone), so the plan computed from a fresh capture still describes it.
//!
//! the caller must take a safety snapshot of the current workspace before `apply`
//! (ADR-0024 rule 21, `current_manifest` into a scratch store). `apply` stops at the first
//! error and leaves the workspace partially restored; the safety snapshot is the way back.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};

use sha2::{Digest, Sha256};

use super::store::{
    EntryKind, Limits, Manifest, ManifestEntry, StoreError, capture, committed_steps, hex_encode,
    load_manifest, validate_manifest, validate_relative_path, verify_object,
};

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const COPY_BUF_LEN: usize = 64 * 1024;
const MAX_XATTR_RETRIES: usize = 4;

/// chain head over step manifest digests.
///
/// the head is the lowercase hex sha256 of the concatenation, in the order given, of one
/// ASCII line per step: `"<step>:<manifest digest hex>\n"`. `<step>` is the decimal step
/// number with no padding and `<manifest digest hex>` is the 64-character lowercase hex
/// sha256 of the exact manifest bytes (`load_manifest`'s second return value). callers
/// pass ascending step order; the function does not sort, so a reordered input yields a
/// different head. an empty list hashes the empty string.
pub fn chain_head(digests: &[(u64, String)]) -> String {
    let mut hasher = Sha256::new();
    for (step, digest) in digests {
        hasher.update(format!("{step}:{digest}\n").as_bytes());
    }
    hex_encode(&hasher.finalize())
}

/// recompute the chain head from the manifests actually present in `store`.
///
/// loads every committed manifest in ascending step order and uses the digest of the bytes
/// it read from disk. the chain is never read from a trace.
pub fn recompute_chain(store: &File) -> Result<String, StoreError> {
    let mut digests = Vec::new();
    for step in committed_steps(store)? {
        let (_, digest) = load_manifest(store, step)?;
        digests.push((step, digest));
    }
    Ok(chain_head(&digests))
}

/// capture the current workspace into `scratch_store` at `step` and return its manifest.
///
/// used for the pre-rewind safety snapshot (ADR-0024 rule 21) and as the `current` input to
/// `plan`. `scratch_store` must not be the run's store: pre-rewind snapshots are outside
/// the chain.
pub fn current_manifest(
    workspace: &File,
    scratch_store: &File,
    step: u64,
    limits: &Limits,
) -> Result<Manifest, StoreError> {
    capture(workspace, scratch_store, step, limits)?;
    Ok(load_manifest(scratch_store, step)?.0)
}

/// which metadata fields of an existing entry differ from the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MetaChange {
    /// permission bits differ.
    pub mode: bool,
    /// modification time differs.
    pub mtime: bool,
    /// owner or group differs.
    pub owner: bool,
    /// user extended attributes differ.
    pub xattrs: bool,
}

impl MetaChange {
    fn any(self) -> bool {
        self.mode || self.mtime || self.owner || self.xattrs
    }
}

impl fmt::Display for MetaChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.mode {
            parts.push("mode");
        }
        if self.mtime {
            parts.push("mtime");
        }
        if self.owner {
            parts.push("owner");
        }
        if self.xattrs {
            parts.push("xattrs");
        }
        write!(f, "{}", parts.join(", "))
    }
}

/// one planned workspace operation. paths are relative, `/`-joined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOp {
    /// remove an entry that the target does not have, or that changes kind.
    Remove {
        /// relative path.
        path: String,
        /// kind of the entry being removed (directories use `AT_REMOVEDIR`).
        kind: EntryKind,
    },
    /// create a directory (metadata is applied in the final directory pass).
    Mkdir {
        /// relative path.
        path: String,
    },
    /// write a regular file from the store (new content or new link grouping).
    WriteFile {
        /// relative path.
        path: String,
    },
    /// create a hard link to a file written earlier in the plan, replacing any existing name.
    LinkFile {
        /// relative path of the new name.
        path: String,
        /// relative path of the earlier group member to link from.
        source: String,
    },
    /// create a symlink with the target recorded in the manifest.
    Symlink {
        /// relative path.
        path: String,
    },
    /// fix metadata of an existing file or symlink whose content is already right.
    SetMetadata {
        /// relative path.
        path: String,
        /// which fields differ.
        change: MetaChange,
    },
}

/// a directory whose mode, mtime, owner and xattrs are applied after all content changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirFinalize {
    /// relative path.
    pub path: String,
    /// the directory is created by this plan.
    pub created: bool,
    /// which metadata fields differ from the current directory.
    pub change: MetaChange,
}

/// the operations that make the workspace equal a target manifest.
///
/// `ops` run in order: removals (deepest first), directory creations (shallowest first),
/// then file, link and symlink writes and metadata fixes. `finalize_dirs` runs last,
/// deepest first, because creating and removing entries changes directory mtimes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestorePlan {
    /// content operations in execution order.
    pub ops: Vec<RestoreOp>,
    /// directories whose metadata needs to be applied last, deepest first.
    pub finalize_dirs: Vec<DirFinalize>,
}

/// the kind of change shown in a plan summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeAction {
    /// an entry is removed.
    Remove,
    /// a directory is created.
    CreateDir,
    /// a file is written from the store.
    WriteFile,
    /// a hard link is created.
    Link,
    /// a symlink is created.
    Symlink,
    /// metadata of an existing entry is fixed.
    Metadata,
}

impl fmt::Display for ChangeAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Remove => "remove",
            Self::CreateDir => "create dir",
            Self::WriteFile => "write",
            Self::Link => "hard link",
            Self::Symlink => "symlink",
            Self::Metadata => "metadata",
        })
    }
}

/// one line of the change summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedChange {
    /// what happens to the path.
    pub action: ChangeAction,
    /// relative path.
    pub path: String,
    /// extra detail (changed metadata fields), empty when there is none.
    pub detail: String,
}

/// human summary of a plan, printed before rewind applies anything.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlanSummary {
    /// entries removed.
    pub removed: usize,
    /// directories created.
    pub dirs_created: usize,
    /// files written from the store.
    pub files_written: usize,
    /// hard links created.
    pub hard_links: usize,
    /// symlinks created.
    pub symlinks: usize,
    /// existing entries whose metadata is fixed (files, symlinks and directories).
    pub metadata_fixed: usize,
    /// every change, sorted by path.
    pub changes: Vec<PlannedChange>,
}

impl PlanSummary {
    /// true when nothing would change.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

impl fmt::Display for PlanSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return writeln!(f, "the workspace already matches the target");
        }
        writeln!(
            f,
            "{} removed, {} directories created, {} files written, {} hard links, {} symlinks, {} metadata fixes",
            self.removed,
            self.dirs_created,
            self.files_written,
            self.hard_links,
            self.symlinks,
            self.metadata_fixed
        )?;
        for change in &self.changes {
            if change.detail.is_empty() {
                writeln!(f, "  {} {}", change.action, change.path)?;
            } else {
                writeln!(f, "  {} {} ({})", change.action, change.path, change.detail)?;
            }
        }
        Ok(())
    }
}

impl RestorePlan {
    /// true when applying the plan would change nothing.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty() && self.finalize_dirs.is_empty()
    }

    /// counts and a per-path list of what the plan does.
    pub fn summary(&self) -> PlanSummary {
        let mut s = PlanSummary::default();
        let mut push = |action, path: &str, detail: String| {
            s.changes.push(PlannedChange {
                action,
                path: path.to_owned(),
                detail,
            });
        };
        let mut counts = [0usize; 6];
        for op in &self.ops {
            match op {
                RestoreOp::Remove { path, .. } => {
                    counts[0] += 1;
                    push(ChangeAction::Remove, path, String::new());
                }
                RestoreOp::Mkdir { path } => {
                    counts[1] += 1;
                    push(ChangeAction::CreateDir, path, String::new());
                }
                RestoreOp::WriteFile { path } => {
                    counts[2] += 1;
                    push(ChangeAction::WriteFile, path, String::new());
                }
                RestoreOp::LinkFile { path, source } => {
                    counts[3] += 1;
                    push(ChangeAction::Link, path, format!("to {source}"));
                }
                RestoreOp::Symlink { path } => {
                    counts[4] += 1;
                    push(ChangeAction::Symlink, path, String::new());
                }
                RestoreOp::SetMetadata { path, change } => {
                    counts[5] += 1;
                    push(ChangeAction::Metadata, path, change.to_string());
                }
            }
        }
        for dir in self.finalize_dirs.iter().filter(|d| !d.created) {
            counts[5] += 1;
            push(ChangeAction::Metadata, &dir.path, dir.change.to_string());
        }
        s.removed = counts[0];
        s.dirs_created = counts[1];
        s.files_written = counts[2];
        s.hard_links = counts[3];
        s.symlinks = counts[4];
        s.metadata_fixed = counts[5];
        s.changes.sort_by(|a, b| a.path.cmp(&b.path));
        s
    }
}

fn depth(path: &str) -> usize {
    path.bytes().filter(|&b| b == b'/').count()
}

/// members of each link group, as sorted path lists keyed by group id.
fn group_members(manifest: &Manifest) -> HashMap<u64, Vec<&str>> {
    let mut groups: HashMap<u64, Vec<&str>> = HashMap::new();
    for entry in &manifest.entries {
        if let (EntryKind::File, Some(group)) = (entry.kind, entry.link_group) {
            groups.entry(group).or_default().push(entry.path.as_str());
        }
    }
    for members in groups.values_mut() {
        members.sort_unstable();
    }
    groups
}

/// the set of paths that share an inode with `entry` (just itself when not linked).
fn link_peers<'a>(entry: &'a ManifestEntry, groups: &HashMap<u64, Vec<&'a str>>) -> Vec<&'a str> {
    match entry.link_group.and_then(|g| groups.get(&g)) {
        Some(members) if members.len() > 1 => members.clone(),
        _ => vec![entry.path.as_str()],
    }
}

fn meta_change(current: &ManifestEntry, target: &ManifestEntry) -> MetaChange {
    MetaChange {
        // symlink permission bits are not settable and are always 0777 on linux
        mode: target.kind != EntryKind::Symlink && current.mode != target.mode,
        mtime: (current.mtime_sec, current.mtime_nsec) != (target.mtime_sec, target.mtime_nsec),
        owner: current.uid != target.uid || current.gid != target.gid,
        xattrs: current.xattrs != target.xattrs,
    }
}

/// compute the operations that make a workspace described by `current` equal `target`.
///
/// both manifests are expected to be valid (`validate_manifest`); `apply` re-validates the
/// target. entries absent from `target` are removed deepest first, missing directories are
/// created shallowest first, files whose content or hard-link grouping differs are written
/// (the first member of a group from the store, the others hard linked from it), symlinks
/// whose target differs are recreated, and entries that differ only in mode, mtime, owner
/// or user xattrs get a metadata fix. a kind change is a removal followed by a creation.
/// directory metadata is applied last, deepest first.
pub fn plan(current: &Manifest, target: &Manifest) -> RestorePlan {
    let cur: HashMap<&str, &ManifestEntry> = current
        .entries
        .iter()
        .map(|e| (e.path.as_str(), e))
        .collect();
    let tgt: HashMap<&str, &ManifestEntry> = target
        .entries
        .iter()
        .map(|e| (e.path.as_str(), e))
        .collect();

    // removals: absent from the target, or present with a different kind
    let mut removals: Vec<&ManifestEntry> = current
        .entries
        .iter()
        .filter(|c| tgt.get(c.path.as_str()).is_none_or(|t| t.kind != c.kind))
        .collect();
    removals.sort_by(|a, b| {
        depth(&b.path)
            .cmp(&depth(&a.path))
            .then_with(|| a.path.cmp(&b.path))
    });

    let same_kind = |t: &ManifestEntry| {
        cur.get(t.path.as_str())
            .copied()
            .filter(|c| c.kind == t.kind)
    };

    let mut mkdirs: Vec<&ManifestEntry> = target
        .entries
        .iter()
        .filter(|t| t.kind == EntryKind::Dir && same_kind(t).is_none())
        .collect();
    mkdirs.sort_by(|a, b| {
        depth(&a.path)
            .cmp(&depth(&b.path))
            .then_with(|| a.path.cmp(&b.path))
    });

    let cur_groups = group_members(current);
    let tgt_groups = group_members(target);
    let mut group_first: HashMap<u64, &str> = HashMap::new();

    let mut ops: Vec<RestoreOp> = removals
        .iter()
        .map(|c| RestoreOp::Remove {
            path: c.path.clone(),
            kind: c.kind,
        })
        .collect();
    ops.extend(mkdirs.iter().map(|d| RestoreOp::Mkdir {
        path: d.path.clone(),
    }));

    let mut finalize: Vec<DirFinalize> = mkdirs
        .iter()
        .map(|d| DirFinalize {
            path: d.path.clone(),
            created: true,
            change: MetaChange {
                mode: true,
                mtime: true,
                owner: true,
                xattrs: !d.xattrs.is_empty(),
            },
        })
        .collect();

    let mut sorted_targets: Vec<&ManifestEntry> = target.entries.iter().collect();
    sorted_targets.sort_by(|a, b| a.path.cmp(&b.path));
    for t in sorted_targets {
        let c = same_kind(t);
        match t.kind {
            EntryKind::Dir => {
                if let Some(c) = c {
                    let change = meta_change(c, t);
                    if change.any() {
                        finalize.push(DirFinalize {
                            path: t.path.clone(),
                            created: false,
                            change,
                        });
                    }
                }
            }
            EntryKind::Symlink => match c {
                Some(c) if c.target == t.target => {
                    let change = meta_change(c, t);
                    if change.any() {
                        ops.push(RestoreOp::SetMetadata {
                            path: t.path.clone(),
                            change,
                        });
                    }
                }
                _ => ops.push(RestoreOp::Symlink {
                    path: t.path.clone(),
                }),
            },
            EntryKind::File => {
                let unchanged = c.is_some_and(|c| {
                    c.sha256 == t.sha256
                        && c.size == t.size
                        && link_peers(c, &cur_groups) == link_peers(t, &tgt_groups)
                });
                let first = t.link_group.and_then(|g| group_first.get(&g).copied());
                if let Some(g) = t.link_group {
                    group_first.entry(g).or_insert(t.path.as_str());
                }
                match (unchanged, c, first) {
                    (false, _, Some(source)) => ops.push(RestoreOp::LinkFile {
                        path: t.path.clone(),
                        source: source.to_owned(),
                    }),
                    (false, _, None) => ops.push(RestoreOp::WriteFile {
                        path: t.path.clone(),
                    }),
                    (true, Some(c), _) => {
                        let change = meta_change(c, t);
                        if change.any() {
                            ops.push(RestoreOp::SetMetadata {
                                path: t.path.clone(),
                                change,
                            });
                        }
                    }
                    (true, None, _) => {}
                }
            }
        }
    }

    finalize.sort_by(|a, b| {
        depth(&b.path)
            .cmp(&depth(&a.path))
            .then_with(|| a.path.cmp(&b.path))
    });
    RestorePlan {
        ops,
        finalize_dirs: finalize,
    }
}

// ---- apply ----

/// errors from applying a restore plan.
#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    /// the process runs as root; rewind refuses because root could write through anything.
    #[error("refusing to restore as root (effective uid 0); run rewind as the workspace owner")]
    RunningAsRoot,
    /// the target manifest, or an object it names, was rejected by the store.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// an I/O error with the operation and relative path.
    #[error("{op} failed for {path}: {source}")]
    Io {
        /// operation being attempted.
        op: &'static str,
        /// relative path involved.
        path: String,
        /// underlying OS error.
        #[source]
        source: io::Error,
    },
    /// a directory on the way to `path` is a symlink, or resolution left the workspace.
    #[error("refusing to follow a symlink or leave the workspace while resolving {path}")]
    UnsafePath {
        /// relative path whose resolution was refused.
        path: String,
    },
    /// the target records an owner this unprivileged process cannot create.
    #[error("cannot restore owner {uid}:{gid} of {path}: running as {euid}:{egid} without root")]
    Ownership {
        /// relative path.
        path: String,
        /// target uid.
        uid: u32,
        /// target gid.
        gid: u32,
        /// effective uid of this process.
        euid: u32,
        /// effective gid of this process.
        egid: u32,
    },
    /// the bytes written for a file do not hash to the manifest digest.
    #[error("bytes written for {path} hash to {actual}, manifest says {expected}")]
    ContentMismatch {
        /// relative path.
        path: String,
        /// digest the manifest names.
        expected: String,
        /// digest of the bytes actually written.
        actual: String,
    },
    /// the bytes written for a file are not as long as the manifest says.
    #[error("{path} is {actual} bytes in the store, manifest says {expected}")]
    SizeMismatch {
        /// relative path.
        path: String,
        /// size the manifest names.
        expected: u64,
        /// bytes actually written.
        actual: u64,
    },
    /// the plan names a path the target manifest does not describe, or one of another kind.
    #[error("restore plan does not match the target manifest at {path}: {reason}")]
    InvalidPlan {
        /// relative path.
        path: String,
        /// what is wrong.
        reason: &'static str,
    },
    /// the workspace handle is not a directory.
    #[error("workspace handle is not a directory")]
    InvalidWorkspace,
    /// the OS random generator failed when creating a temporary name.
    #[error("random source failed: {0}")]
    Random(String),
}

/// what `apply` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApplyStats {
    /// entries removed.
    pub removed: u64,
    /// directories created.
    pub dirs_created: u64,
    /// files written from the store.
    pub files_written: u64,
    /// hard links created.
    pub hard_links: u64,
    /// symlinks created.
    pub symlinks: u64,
    /// files and symlinks whose metadata was fixed in place.
    pub metadata_fixed: u64,
    /// directories whose metadata was applied in the final pass.
    pub dirs_finalized: u64,
    /// content bytes written.
    pub bytes_written: u64,
}

/// the identity `apply` runs as. a seam so the root refusal and the ownership preflight
/// can be tested without being root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreContext {
    /// effective uid.
    pub euid: u32,
    /// effective gid.
    pub egid: u32,
    /// supplementary group ids.
    pub groups: Vec<u32>,
}

impl RestoreContext {
    /// the identity of the current process.
    pub fn from_process() -> Result<Self, RestoreError> {
        // SAFETY: geteuid and getegid take no arguments and cannot fail.
        let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
        // SAFETY: a zero-length query with a null list only returns the group count.
        let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if count < 0 {
            return Err(last_err("getgroups", "<process>"));
        }
        let mut groups: Vec<libc::gid_t> = vec![0; count as usize];
        // SAFETY: groups has room for `count` gids.
        let got = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
        if got < 0 {
            return Err(last_err("getgroups", "<process>"));
        }
        groups.truncate(got as usize);
        Ok(Self { euid, egid, groups })
    }

    fn can_own(&self, uid: u32, gid: u32) -> bool {
        uid == self.euid && (gid == self.egid || self.groups.contains(&gid))
    }
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn io_err(op: &'static str, path: &str, source: io::Error) -> RestoreError {
    RestoreError::Io {
        op,
        path: path.to_owned(),
        source,
    }
}

fn last_err(op: &'static str, path: &str) -> RestoreError {
    io_err(op, path, io::Error::last_os_error())
}

/// turn a libc return code into a result, reading errno immediately.
fn check(rc: libc::c_int, op: &'static str, path: &str) -> Result<(), RestoreError> {
    if rc == 0 {
        Ok(())
    } else {
        Err(last_err(op, path))
    }
}

fn cstring(s: &str, path: &str) -> Result<CString, RestoreError> {
    CString::new(s).map_err(|_| RestoreError::InvalidPlan {
        path: path.to_owned(),
        reason: "path contains a NUL byte",
    })
}

fn split_path(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn fstat(fd: RawFd, path: &str) -> Result<libc::stat, RestoreError> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fd is a live descriptor and fstat initializes `st` on success.
    check(unsafe { libc::fstat(fd, st.as_mut_ptr()) }, "fstat", path)?;
    // SAFETY: fstat returned 0, so `st` is fully initialized.
    Ok(unsafe { st.assume_init() })
}

fn fstatat_nofollow(dir: RawFd, name: &CStr, path: &str) -> Result<libc::stat, RestoreError> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: dir is a live directory descriptor, name is NUL-terminated, and
    // AT_SYMLINK_NOFOLLOW stats a symlink itself.
    let rc = unsafe {
        libc::fstatat(
            dir,
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    check(rc, "fstatat", path)?;
    // SAFETY: fstatat returned 0, so `st` is fully initialized.
    Ok(unsafe { st.assume_init() })
}

/// open the directory `rel` beneath `root`, refusing any symlink or magic link on the way
/// and any escape from `root`. `rel` empty means `root` itself.
fn open_dir_beneath(root: &File, rel: &str, path: &str) -> Result<File, RestoreError> {
    let c_rel = cstring(if rel.is_empty() { "." } else { rel }, path)?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: root is a live directory descriptor, c_rel is NUL-terminated, and `how` is a
    // complete open_how of the size passed.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            c_rel.as_ptr(),
            &raw const how,
            size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        let err = io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::ELOOP | libc::EXDEV) => RestoreError::UnsafePath {
                path: path.to_owned(),
            },
            _ => io_err("openat2", path, err),
        });
    }
    // SAFETY: openat2 returned a fresh descriptor that nothing else owns.
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

fn temp_name() -> Result<CString, RestoreError> {
    let mut rnd = [0u8; 16];
    getrandom::fill(&mut rnd).map_err(|e| RestoreError::Random(e.to_string()))?;
    CString::new(format!(".leash-restore-{}", hex_encode(&rnd)))
        .map_err(|_| RestoreError::Random("temporary name has a NUL byte".into()))
}

/// a temporary directory entry that is unlinked on drop unless it was renamed into place.
struct TempName<'a> {
    dir: &'a File,
    name: CString,
    armed: bool,
}

impl Drop for TempName<'_> {
    fn drop(&mut self) {
        if self.armed {
            // SAFETY: dir is a live directory descriptor and name is NUL-terminated.
            let _ = unsafe { libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0) };
        }
    }
}

/// rename `tmp` over `name` in the same directory and disarm the cleanup.
fn commit_temp(tmp: &mut TempName<'_>, name: &CStr, path: &str) -> Result<(), RestoreError> {
    let fd = tmp.dir.as_raw_fd();
    // SAFETY: fd is a live directory descriptor and both names are NUL-terminated.
    let rc = unsafe { libc::renameat(fd, tmp.name.as_ptr(), fd, name.as_ptr()) };
    check(rc, "renameat", path)?;
    tmp.armed = false;
    Ok(())
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(digits, 16).ok()
        })
        .collect()
}

fn list_user_xattrs(fd: RawFd, path: &str) -> Result<Vec<CString>, RestoreError> {
    let mut buf = Vec::new();
    for _ in 0..MAX_XATTR_RETRIES {
        // SAFETY: fd is live; a null list with size 0 queries the needed length.
        let needed = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
        if needed < 0 {
            let err = io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(libc::EOPNOTSUPP | libc::ENOSYS)) {
                return Ok(Vec::new());
            }
            return Err(io_err("flistxattr", path, err));
        }
        if needed == 0 {
            return Ok(Vec::new());
        }
        let mut list = vec![0u8; needed as usize];
        // SAFETY: fd is live and list has `list.len()` writable bytes.
        let got = unsafe { libc::flistxattr(fd, list.as_mut_ptr().cast(), list.len()) };
        if got < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ERANGE) {
                continue;
            }
            return Err(io_err("flistxattr", path, err));
        }
        list.truncate(got as usize);
        buf = list;
        break;
    }
    Ok(buf
        .split(|&b| b == 0)
        .filter(|name| name.starts_with(b"user."))
        .filter_map(|name| CString::new(name).ok())
        .collect())
}

/// make the `user.*` xattrs of `fd` exactly `wanted`. `elevate_mode` is applied first when
/// anything changes, so an owner can write xattrs on a mode-000 entry; the caller sets the
/// final mode afterwards.
fn sync_xattrs(
    fd: RawFd,
    wanted: &BTreeMap<String, String>,
    path: &str,
    existing: bool,
    elevate_mode: u32,
) -> Result<(), RestoreError> {
    let have = if existing {
        list_user_xattrs(fd, path)?
    } else {
        Vec::new()
    };
    let stale: Vec<&CString> = have
        .iter()
        .filter(|name| !name.to_str().is_ok_and(|n| wanted.contains_key(n)))
        .collect();
    if stale.is_empty() && wanted.is_empty() {
        return Ok(());
    }
    // SAFETY: fd is a live descriptor.
    check(
        unsafe { libc::fchmod(fd, elevate_mode as libc::mode_t) },
        "fchmod",
        path,
    )?;
    for name in stale {
        // SAFETY: fd is live and name is NUL-terminated.
        if unsafe { libc::fremovexattr(fd, name.as_ptr()) } != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENODATA) {
                return Err(io_err("fremovexattr", path, err));
            }
        }
    }
    for (name, hex) in wanted {
        let value = decode_hex(hex).ok_or_else(|| RestoreError::InvalidPlan {
            path: path.to_owned(),
            reason: "xattr value is not hex",
        })?;
        let c_name = cstring(name, path)?;
        // SAFETY: fd is live, c_name is NUL-terminated, and value has `value.len()` bytes.
        let rc =
            unsafe { libc::fsetxattr(fd, c_name.as_ptr(), value.as_ptr().cast(), value.len(), 0) };
        check(rc, "fsetxattr", path)?;
    }
    Ok(())
}

fn mtime_spec(entry: &ManifestEntry) -> [libc::timespec; 2] {
    [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: entry.mtime_sec as libc::time_t,
            tv_nsec: entry.mtime_nsec as libc::c_long,
        },
    ]
}

/// apply owner, xattrs, mode and mtime to an open inode, in an order that survives the
/// kernel clearing setuid bits on chown and requiring write access for xattrs.
fn apply_inode_meta(
    fd: RawFd,
    entry: &ManifestEntry,
    path: &str,
    existing: bool,
    elevate_mode: u32,
) -> Result<(), RestoreError> {
    sync_xattrs(fd, &entry.xattrs, path, existing, elevate_mode)?;
    let st = fstat(fd, path)?;
    if st.st_uid != entry.uid || st.st_gid != entry.gid {
        // SAFETY: fd is a live descriptor.
        check(
            unsafe { libc::fchown(fd, entry.uid, entry.gid) },
            "fchown",
            path,
        )?;
    }
    // SAFETY: fd is a live descriptor.
    check(
        unsafe { libc::fchmod(fd, entry.mode as libc::mode_t) },
        "fchmod",
        path,
    )?;
    let times = mtime_spec(entry);
    // SAFETY: fd is live and times is a valid two-element array.
    check(
        unsafe { libc::futimens(fd, times.as_ptr()) },
        "futimens",
        path,
    )
}

/// owner and mtime of a symlink, through its parent directory, never following it.
fn set_symlink_meta(
    dir: RawFd,
    name: &CStr,
    entry: &ManifestEntry,
    path: &str,
) -> Result<(), RestoreError> {
    let st = fstatat_nofollow(dir, name, path)?;
    if st.st_uid != entry.uid || st.st_gid != entry.gid {
        // SAFETY: dir is live, name is NUL-terminated, and AT_SYMLINK_NOFOLLOW chowns the
        // link itself.
        let rc = unsafe {
            libc::fchownat(
                dir,
                name.as_ptr(),
                entry.uid,
                entry.gid,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        check(rc, "fchownat", path)?;
    }
    let times = mtime_spec(entry);
    // SAFETY: dir is live, name is NUL-terminated, times is a valid two-element array.
    let rc = unsafe {
        libc::utimensat(
            dir,
            name.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    check(rc, "utimensat", path)
}

/// apply `plan` so the workspace equals `target`, as the current process.
///
/// see `apply_with_context`.
pub fn apply(
    workspace: &File,
    store: &File,
    target: &Manifest,
    plan: &RestorePlan,
) -> Result<ApplyStats, RestoreError> {
    apply_with_context(
        workspace,
        store,
        target,
        plan,
        &RestoreContext::from_process()?,
    )
}

/// apply `plan` so the workspace equals `target`, as the identity in `ctx`.
///
/// the store is hostile input. `apply` refuses when `ctx.euid` is 0, re-validates `target`,
/// and checks the whole plan (paths, entry kinds, owners this process can create) before
/// the first write. every operation is relative to the `workspace` handle and resolves its
/// parent with `openat2` beneath the handle with no symlinks, so a symlink where a directory
/// is expected is an error and is never traversed. file content comes from `verify_object`,
/// is copied into a random-named `O_EXCL | O_NOFOLLOW` temporary file next to the
/// destination, is hashed as it is written and compared with the manifest, fsynced, given
/// its metadata, and renamed over the destination. an existing destination file is never
/// opened for writing, so a hard link from outside the workspace is never written through.
///
/// `apply` stops at the first error, naming the path, and leaves the workspace partially
/// restored. the caller takes the safety snapshot first (ADR-0024 rule 21) and keeps it.
/// directories that must be writable are made owner-writable while they change and get
/// their target mode in the final pass. a directory the owner cannot open (no read or
/// search permission) fails the run rather than being chmodded.
pub fn apply_with_context(
    workspace: &File,
    store: &File,
    target: &Manifest,
    plan: &RestorePlan,
    ctx: &RestoreContext,
) -> Result<ApplyStats, RestoreError> {
    if ctx.euid == 0 {
        return Err(RestoreError::RunningAsRoot);
    }
    validate_manifest(target)?;
    let ws = fstat(workspace.as_raw_fd(), "<workspace>")?;
    if (ws.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(RestoreError::InvalidWorkspace);
    }
    let entries: HashMap<&str, &ManifestEntry> = target
        .entries
        .iter()
        .map(|e| (e.path.as_str(), e))
        .collect();
    let mut applier = Applier {
        workspace,
        store,
        entries,
        stats: ApplyStats::default(),
        touched: BTreeSet::new(),
    };
    applier.preflight(plan, ctx)?;
    for op in &plan.ops {
        applier.run(op)?;
    }
    applier.finalize(plan)?;
    Ok(applier.stats)
}

struct Applier<'a> {
    workspace: &'a File,
    store: &'a File,
    entries: HashMap<&'a str, &'a ManifestEntry>,
    stats: ApplyStats,
    /// directories whose contents changed, so their mtime and mode are applied last.
    touched: BTreeSet<String>,
}

impl<'a> Applier<'a> {
    fn entry(&self, path: &str, kind: EntryKind) -> Result<&'a ManifestEntry, RestoreError> {
        let entry = self
            .entries
            .get(path)
            .copied()
            .ok_or_else(|| RestoreError::InvalidPlan {
                path: path.to_owned(),
                reason: "path is not in the target manifest",
            })?;
        if entry.kind != kind {
            return Err(RestoreError::InvalidPlan {
                path: path.to_owned(),
                reason: "entry kind differs from the operation",
            });
        }
        Ok(entry)
    }

    fn check_owner(
        &self,
        ctx: &RestoreContext,
        path: &str,
        kind: EntryKind,
    ) -> Result<(), RestoreError> {
        let entry = self.entry(path, kind)?;
        if ctx.can_own(entry.uid, entry.gid) {
            Ok(())
        } else {
            Err(RestoreError::Ownership {
                path: path.to_owned(),
                uid: entry.uid,
                gid: entry.gid,
                euid: ctx.euid,
                egid: ctx.egid,
            })
        }
    }

    /// validate every path, kind and owner in the plan before anything is written.
    fn preflight(&self, plan: &RestorePlan, ctx: &RestoreContext) -> Result<(), RestoreError> {
        for op in &plan.ops {
            match op {
                RestoreOp::Remove { path, .. } => validate_relative_path(path)?,
                RestoreOp::Mkdir { path } => {
                    validate_relative_path(path)?;
                    self.check_owner(ctx, path, EntryKind::Dir)?;
                }
                RestoreOp::WriteFile { path } => {
                    validate_relative_path(path)?;
                    self.check_owner(ctx, path, EntryKind::File)?;
                }
                RestoreOp::LinkFile { path, source } => {
                    validate_relative_path(path)?;
                    validate_relative_path(source)?;
                    self.entry(path, EntryKind::File)?;
                    self.entry(source, EntryKind::File)?;
                }
                RestoreOp::Symlink { path } => {
                    validate_relative_path(path)?;
                    self.check_owner(ctx, path, EntryKind::Symlink)?;
                }
                RestoreOp::SetMetadata { path, change } => {
                    validate_relative_path(path)?;
                    let kind = self
                        .entries
                        .get(path.as_str())
                        .map_or(EntryKind::File, |e| e.kind);
                    if kind == EntryKind::Dir {
                        return Err(RestoreError::InvalidPlan {
                            path: path.clone(),
                            reason: "directory metadata belongs in finalize_dirs",
                        });
                    }
                    if change.owner {
                        self.check_owner(ctx, path, kind)?;
                    } else {
                        self.entry(path, kind)?;
                    }
                }
            }
        }
        for dir in &plan.finalize_dirs {
            validate_relative_path(&dir.path)?;
            if dir.change.owner && !dir.created {
                self.check_owner(ctx, &dir.path, EntryKind::Dir)?;
            } else {
                self.entry(&dir.path, EntryKind::Dir)?;
            }
        }
        Ok(())
    }

    /// open the parent directory of `path` for modification and return it with the name.
    fn open_parent(&mut self, path: &str) -> Result<(File, CString), RestoreError> {
        let (parent, name) = split_path(path);
        let dir = open_dir_beneath(self.workspace, parent, path)?;
        if !parent.is_empty() {
            self.touched.insert(parent.to_owned());
            // a restored directory can be read-only; the owner needs rwx while it changes
            // and the final pass puts the target mode back. the workspace root is left
            // alone: it is not in the manifest and its mode is not ours to change.
            let st = fstat(dir.as_raw_fd(), path)?;
            let mode = st.st_mode & 0o7777;
            if mode & 0o700 != 0o700 {
                // SAFETY: dir is a live directory descriptor.
                let rc = unsafe { libc::fchmod(dir.as_raw_fd(), mode | 0o700) };
                check(rc, "fchmod", path)?;
            }
        }
        Ok((dir, cstring(name, path)?))
    }

    fn run(&mut self, op: &RestoreOp) -> Result<(), RestoreError> {
        match op {
            RestoreOp::Remove { path, kind } => self.remove(path, *kind),
            RestoreOp::Mkdir { path } => self.mkdir(path),
            RestoreOp::WriteFile { path } => self.write_file(path),
            RestoreOp::LinkFile { path, source } => self.link_file(path, source),
            RestoreOp::Symlink { path } => self.symlink(path),
            RestoreOp::SetMetadata { path, .. } => self.set_metadata(path),
        }
    }

    fn remove(&mut self, path: &str, kind: EntryKind) -> Result<(), RestoreError> {
        let (dir, name) = self.open_parent(path)?;
        let flags = if kind == EntryKind::Dir {
            libc::AT_REMOVEDIR
        } else {
            0
        };
        // SAFETY: dir is a live directory descriptor and name is NUL-terminated.
        let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flags) };
        check(rc, "unlinkat", path)?;
        self.stats.removed += 1;
        Ok(())
    }

    fn mkdir(&mut self, path: &str) -> Result<(), RestoreError> {
        let (dir, name) = self.open_parent(path)?;
        // SAFETY: dir is a live directory descriptor and name is NUL-terminated.
        let rc = unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) };
        check(rc, "mkdirat", path)?;
        self.stats.dirs_created += 1;
        Ok(())
    }

    fn write_file(&mut self, path: &str) -> Result<(), RestoreError> {
        let entry = self.entry(path, EntryKind::File)?;
        let sha = entry
            .sha256
            .as_deref()
            .ok_or_else(|| RestoreError::InvalidPlan {
                path: path.to_owned(),
                reason: "file has no digest",
            })?;
        let (dir, name) = self.open_parent(path)?;
        // the object is verified before anything is created next to the destination
        let mut object = verify_object(self.store, sha)?;
        let tmp_name = temp_name()?;
        // SAFETY: dir is a live directory descriptor, tmp_name is NUL-terminated, and
        // O_CREAT | O_EXCL | O_NOFOLLOW creates a new file and returns a fresh descriptor.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                tmp_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(last_err("openat", path));
        }
        // SAFETY: openat returned a fresh descriptor that nothing else owns.
        let tmp = unsafe { File::from_raw_fd(fd) };
        let mut guard = TempName {
            dir: &dir,
            name: tmp_name,
            armed: true,
        };
        // SAFETY: tmp is a live descriptor; umask must not leave the file unwritable.
        check(
            unsafe { libc::fchmod(tmp.as_raw_fd(), 0o600) },
            "fchmod",
            path,
        )?;

        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; COPY_BUF_LEN];
        let mut written = 0u64;
        let mut sink: &File = &tmp;
        loop {
            match object.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    hasher.update(&buf[..n]);
                    sink.write_all(&buf[..n])
                        .map_err(|e| io_err("write", path, e))?;
                    written += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(io_err("read", path, e)),
            }
        }
        let actual = hex_encode(&hasher.finalize());
        if actual != sha {
            return Err(RestoreError::ContentMismatch {
                path: path.to_owned(),
                expected: sha.to_owned(),
                actual,
            });
        }
        if entry.size != Some(written) {
            return Err(RestoreError::SizeMismatch {
                path: path.to_owned(),
                expected: entry.size.unwrap_or(0),
                actual: written,
            });
        }
        // SAFETY: tmp is a live descriptor.
        check(unsafe { libc::fsync(tmp.as_raw_fd()) }, "fsync", path)?;
        apply_inode_meta(tmp.as_raw_fd(), entry, path, false, 0o600)?;
        commit_temp(&mut guard, &name, path)?;
        self.stats.files_written += 1;
        self.stats.bytes_written += written;
        Ok(())
    }

    fn link_file(&mut self, path: &str, source: &str) -> Result<(), RestoreError> {
        self.entry(path, EntryKind::File)?;
        self.entry(source, EntryKind::File)?;
        let (src_dir, src_name) = self.open_parent(source)?;
        let (dir, name) = self.open_parent(path)?;
        let tmp_name = temp_name()?;
        // SAFETY: both directory descriptors are live and both names are NUL-terminated;
        // flags 0 never follows a symlink source.
        let rc = unsafe {
            libc::linkat(
                src_dir.as_raw_fd(),
                src_name.as_ptr(),
                dir.as_raw_fd(),
                tmp_name.as_ptr(),
                0,
            )
        };
        check(rc, "linkat", path)?;
        let mut guard = TempName {
            dir: &dir,
            name: tmp_name,
            armed: true,
        };
        commit_temp(&mut guard, &name, path)?;
        self.stats.hard_links += 1;
        Ok(())
    }

    fn symlink(&mut self, path: &str) -> Result<(), RestoreError> {
        let entry = self.entry(path, EntryKind::Symlink)?;
        let target = entry
            .target
            .as_deref()
            .ok_or_else(|| RestoreError::InvalidPlan {
                path: path.to_owned(),
                reason: "symlink has no target",
            })?;
        let c_target = cstring(target, path)?;
        let (dir, name) = self.open_parent(path)?;
        let tmp_name = temp_name()?;
        // SAFETY: dir is a live directory descriptor and both strings are NUL-terminated.
        let rc = unsafe { libc::symlinkat(c_target.as_ptr(), dir.as_raw_fd(), tmp_name.as_ptr()) };
        check(rc, "symlinkat", path)?;
        let mut guard = TempName {
            dir: &dir,
            name: tmp_name,
            armed: true,
        };
        set_symlink_meta(dir.as_raw_fd(), &guard.name, entry, path)?;
        commit_temp(&mut guard, &name, path)?;
        self.stats.symlinks += 1;
        Ok(())
    }

    fn set_metadata(&mut self, path: &str) -> Result<(), RestoreError> {
        let entry = self
            .entries
            .get(path)
            .copied()
            .ok_or_else(|| RestoreError::InvalidPlan {
                path: path.to_owned(),
                reason: "path is not in the target manifest",
            })?;
        let (dir, name) = self.open_parent(path)?;
        match entry.kind {
            EntryKind::Symlink => set_symlink_meta(dir.as_raw_fd(), &name, entry, path)?,
            EntryKind::File => {
                // SAFETY: dir is a live directory descriptor and name is NUL-terminated;
                // read-only, O_NOFOLLOW and O_NONBLOCK so a swapped-in symlink or fifo
                // cannot be followed or block, and the open file is checked below.
                let fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY
                            | libc::O_NOFOLLOW
                            | libc::O_NONBLOCK
                            | libc::O_NOCTTY
                            | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(last_err("openat", path));
                }
                // SAFETY: openat returned a fresh descriptor that nothing else owns.
                let file = unsafe { File::from_raw_fd(fd) };
                let st = fstat(file.as_raw_fd(), path)?;
                if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
                    return Err(RestoreError::InvalidPlan {
                        path: path.to_owned(),
                        reason: "workspace entry is not a regular file",
                    });
                }
                apply_inode_meta(file.as_raw_fd(), entry, path, true, 0o600)?;
            }
            EntryKind::Dir => {
                return Err(RestoreError::InvalidPlan {
                    path: path.to_owned(),
                    reason: "directory metadata belongs in finalize_dirs",
                });
            }
        }
        self.stats.metadata_fixed += 1;
        Ok(())
    }

    /// apply directory metadata last, deepest first, for every directory the plan lists and
    /// every target directory whose contents changed.
    fn finalize(&mut self, plan: &RestorePlan) -> Result<(), RestoreError> {
        let mut dirs: BTreeSet<String> =
            plan.finalize_dirs.iter().map(|d| d.path.clone()).collect();
        for touched in &self.touched {
            if self
                .entries
                .get(touched.as_str())
                .is_some_and(|e| e.kind == EntryKind::Dir)
            {
                dirs.insert(touched.clone());
            }
        }
        let mut ordered: Vec<String> = dirs.into_iter().collect();
        ordered.sort_by(|a, b| depth(b).cmp(&depth(a)).then_with(|| a.cmp(b)));
        for path in ordered {
            let entry = self.entry(&path, EntryKind::Dir)?;
            let dir = open_dir_beneath(self.workspace, &path, &path)?;
            apply_inode_meta(dir.as_raw_fd(), entry, &path, true, 0o700)?;
            self.stats.dirs_finalized += 1;
        }
        Ok(())
    }
}
