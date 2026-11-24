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

use std::collections::HashMap;
use std::fmt;
use std::fs::File;

use sha2::{Digest, Sha256};

use super::store::{
    EntryKind, Limits, Manifest, ManifestEntry, StoreError, capture, committed_steps, hex_encode,
    load_manifest,
};

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
