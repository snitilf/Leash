//! content-addressed exact snapshot store (ADR-0022, docs/design/snapshot.md).
//!
//! layout under a caller-provided store root directory handle (e.g. `<run_dir>/snapshots`):
//! - `objects/<2-hex>/<64-hex-sha256>` (mode 0400, staged, fsynced, renamed into place)
//! - `manifests/step-<6-digit>.json` (mode 0400, staged, fsynced, renamed, parent fsynced)
//! - `staging/` (temporary files; ignored by loads and step listings)
//!
//! nothing is published before all of its objects are durable on disk.
//!
//! extended attributes:
//! - `user.*` attributes are recorded for regular files and directories, with values
//!   lowercase hex-encoded.
//! - symlink extended attributes are not recorded (reading them safely without following
//!   symlinks would require `llistxattr` via `/proc/self/fd`, which is avoided here).
//! - `security.selinux` is ignored so SELinux-labeled hosts do not fail captures.
//! - any other non-`user.` extended attribute fails capture closed as unsupported metadata.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::io;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// current manifest schema version.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// maximum manifest file size accepted by `load_manifest` (256 MiB).
pub const MANIFEST_READ_CAP: u64 = 256 * 1024 * 1024;

/// provisional default maximum number of entries in a single capture.
///
/// provisional: chosen as a safe initial upper bound until measured against real
/// workspaces and tuned alongside operator configuration.
pub const DEFAULT_MAX_ENTRIES: u64 = 200_000;

/// provisional default maximum sum of regular-file sizes in a single capture (4 GiB).
///
/// provisional: chosen as a safe initial upper bound until measured against real
/// workspaces and tuned alongside operator configuration.
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// provisional default maximum size of a single regular file (1 GiB).
///
/// provisional: chosen as a safe initial upper bound until measured against real
/// workspaces and tuned alongside operator configuration.
pub const DEFAULT_MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024;

/// provisional default maximum bytes of new objects written by a single capture (4 GiB).
///
/// provisional: chosen as a safe initial upper bound until measured against real
/// workspaces and tuned alongside operator configuration.
pub const DEFAULT_MAX_STORE_GROWTH: u64 = 4 * 1024 * 1024 * 1024;

/// resource bounds enforced fail-closed during snapshot capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// maximum number of directory entries (files, directories, symlinks) captured.
    pub max_entries: u64,
    /// maximum sum of regular-file sizes in this capture.
    pub max_total_bytes: u64,
    /// maximum size of any single regular file (checked from `fstat` before reading).
    pub max_file_size: u64,
    /// maximum bytes of new objects written to the store by this capture.
    pub max_store_growth: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            max_store_growth: DEFAULT_MAX_STORE_GROWTH,
        }
    }
}

/// errors from snapshot store capture, loading, and verification.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// an I/O error with the operation and relative path (or store component).
    #[error("{op} failed for {path}: {source}")]
    Io {
        /// operation being attempted.
        op: &'static str,
        /// relative path or store component involved.
        path: String,
        /// underlying OS error.
        #[source]
        source: io::Error,
    },
    /// the workspace root handle is not a directory.
    #[error("workspace root handle is not a directory")]
    InvalidRoot,
    /// the snapshot store root handle is not a directory.
    #[error("snapshot store handle is not a directory")]
    InvalidStore,
    /// an entry kind that exact snapshots refuse rather than omit.
    #[error("unsupported entry at {path}: {kind}")]
    UnsupportedEntry {
        /// relative path of the unsupported entry.
        path: String,
        /// human-readable kind (fifo, socket, char device, block device, ...).
        kind: &'static str,
    },
    /// an entry on a different filesystem device than the workspace root.
    #[error("cross-device entry (mount point) at {path}")]
    CrossDevice {
        /// relative path of the cross-device entry.
        path: String,
    },
    /// a filename or symlink target that is not valid UTF-8.
    #[error("non-UTF-8 name at {path}")]
    UnsupportedName {
        /// lossy or escaped relative path for diagnostics.
        path: String,
    },
    /// an unsupported extended attribute (anything other than `user.*` and `security.selinux`).
    #[error("unsupported extended attribute {attr:?} at {path}")]
    UnsupportedMetadata {
        /// relative path of the entry.
        path: String,
        /// attribute name.
        attr: String,
    },
    /// a regular file changed size or mtime while it was being read.
    #[error("file modified during capture at {path}")]
    ConcurrentModification {
        /// relative path of the modified file.
        path: String,
    },
    /// the capture exceeded `Limits::max_entries`.
    #[error("entry count exceeded limit of {limit}")]
    EntryLimitExceeded {
        /// configured entry limit.
        limit: u64,
    },
    /// a single regular file exceeded `Limits::max_file_size`.
    #[error("file {path} size {size} exceeds limit of {limit} bytes")]
    FileSizeLimitExceeded {
        /// relative path of the oversized file.
        path: String,
        /// file size reported by `fstat`.
        size: u64,
        /// configured single-file limit.
        limit: u64,
    },
    /// cumulative file bytes in this capture exceeded `Limits::max_total_bytes`.
    #[error("total captured bytes {total} exceeds limit of {limit} bytes")]
    TotalBytesLimitExceeded {
        /// attempted cumulative bytes.
        total: u64,
        /// configured total-bytes limit.
        limit: u64,
    },
    /// new object bytes written by this capture exceeded `Limits::max_store_growth`.
    #[error("store growth {growth} exceeds limit of {limit} bytes")]
    StoreGrowthLimitExceeded {
        /// attempted cumulative new object bytes.
        growth: u64,
        /// configured store-growth limit.
        limit: u64,
    },
    /// a manifest for this step already exists in the store.
    #[error("manifest for step {step} already exists")]
    ManifestExists {
        /// step number that already has a committed manifest.
        step: u64,
    },
    /// a manifest file exceeded `MANIFEST_READ_CAP`.
    #[error("manifest for step {step} exceeds read cap of {limit} bytes")]
    ManifestTooLarge {
        /// step number being loaded.
        step: u64,
        /// maximum manifest size in bytes.
        limit: u64,
    },
    /// a manifest failed parsing or structural validation.
    #[error("invalid manifest: {reason}")]
    InvalidManifest {
        /// why the manifest was rejected.
        reason: String,
    },
    /// a caller-provided object digest is not 64 lowercase hex characters.
    #[error("invalid sha256 digest: {0}")]
    InvalidDigest(String),
    /// an object file in the store is not a regular file or is otherwise invalid.
    #[error("invalid object {digest}: {reason}")]
    InvalidObject {
        /// expected lowercase hex sha256 digest.
        digest: String,
        /// why the object was rejected.
        reason: &'static str,
    },
    /// an object file's bytes do not match its content-addressed sha256 digest.
    #[error("corrupt object: expected {expected}, got {actual}")]
    ObjectCorrupt {
        /// expected lowercase hex sha256 digest.
        expected: String,
        /// actual lowercase hex sha256 digest of the stored bytes.
        actual: String,
    },
    /// the OS random generator failed when creating a staging filename.
    #[error("random source failed: {0}")]
    Random(String),
}

/// supported entry kinds in a snapshot manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// regular file with content stored in `objects/`.
    File,
    /// directory.
    Dir,
    /// symbolic link with verbatim target.
    Symlink,
}

/// aggregate counts recorded in a snapshot manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestTotals {
    /// total number of entries in `entries`.
    pub entries: u64,
    /// number of regular-file entries.
    pub files: u64,
    /// number of directory entries.
    pub dirs: u64,
    /// number of symlink entries.
    pub symlinks: u64,
    /// sum of `size` across all regular-file entries.
    pub total_bytes: u64,
}

/// one captured entry inside a workspace snapshot manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    /// relative UTF-8 path with components joined by `'/'`.
    pub path: String,
    /// entry kind.
    pub kind: EntryKind,
    /// permission bits including setuid, setgid, and sticky (`st_mode & 0o7777`).
    pub mode: u32,
    /// owner user id.
    pub uid: u32,
    /// owner group id.
    pub gid: u32,
    /// modification time seconds since unix epoch.
    pub mtime_sec: i64,
    /// modification time nanoseconds (`0..1_000_000_000`).
    pub mtime_nsec: i64,
    /// byte length for regular files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// lowercase hex SHA-256 content digest for regular files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// verbatim UTF-8 link target for symlinks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// shared group id for regular-file entries that are hard links to the same inode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_group: Option<u64>,
    /// `user.*` extended attributes with lowercase hex-encoded values (files and dirs only).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub xattrs: BTreeMap<String, String>,
}

/// durable manifest describing the exact captured workspace tree at one step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// schema version (`MANIFEST_SCHEMA_VERSION`).
    pub schema_version: u32,
    /// step number this snapshot represents.
    pub step: u64,
    /// aggregate entry and byte counts.
    pub totals: ManifestTotals,
    /// all workspace entries, sorted lexicographically by `path`.
    pub entries: Vec<ManifestEntry>,
}

/// statistics returned after publishing a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureStats {
    /// total entries captured.
    pub entries: u64,
    /// regular-file entries captured.
    pub files: u64,
    /// directory entries captured.
    pub dirs: u64,
    /// symlink entries captured.
    pub symlinks: u64,
    /// sum of file sizes across all regular-file entries.
    pub total_bytes: u64,
    /// number of new content objects written to `objects/`.
    pub new_objects: u64,
    /// number of file objects deduplicated against existing objects or hard links.
    pub reused_objects: u64,
    /// bytes of new objects written to `objects/` by this capture.
    pub store_growth: u64,
}

/// result of publishing a durable snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    /// lowercase hex SHA-256 digest of the exact manifest bytes written.
    pub manifest_digest: String,
    /// capture counts and store growth statistics.
    pub stats: CaptureStats,
}

/// file size and modification timestamp snapshot used to detect concurrent modification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFingerprint {
    /// file size in bytes.
    pub size: u64,
    /// mtime seconds.
    pub mtime_sec: i64,
    /// mtime nanoseconds.
    pub mtime_nsec: i64,
}

/// verify that a regular file's size and mtime did not change while reading it.
pub fn check_file_unchanged(
    path: &str,
    before: FileFingerprint,
    after: FileFingerprint,
    bytes_read: u64,
) -> Result<(), StoreError> {
    if bytes_read != before.size
        || after.size != before.size
        || after.mtime_sec != before.mtime_sec
        || after.mtime_nsec != before.mtime_nsec
    {
        return Err(StoreError::ConcurrentModification {
            path: path.to_owned(),
        });
    }
    Ok(())
}

/// classification of an extended attribute name during capture.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum XattrAction {
    /// record this `user.*` attribute.
    Record,
    /// ignore `security.selinux` so SELinux-labeled hosts do not fail captures.
    Ignore,
    /// fail capture closed as unsupported metadata.
    Reject,
}

/// decide how to handle an extended attribute name.
///
/// `user.*` is recorded, `security.selinux` is ignored, and all other namespaces are
/// rejected fail-closed.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn classify_xattr(name: &str) -> XattrAction {
    if name == "security.selinux" {
        XattrAction::Ignore
    } else if name.starts_with("user.") {
        XattrAction::Record
    } else {
        XattrAction::Reject
    }
}

/// compute the lowercase hex SHA-256 digest of exact manifest bytes.
pub fn manifest_digest(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

/// parse raw JSON manifest bytes and validate all structural invariants.
pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, StoreError> {
    let manifest: Manifest =
        serde_json::from_slice(bytes).map_err(|e| StoreError::InvalidManifest {
            reason: format!("json parse error: {e}"),
        })?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

/// validate all structural and semantic invariants of a manifest.
///
/// rejects:
/// - unsupported `schema_version`
/// - absolute paths, empty paths, trailing slashes, NUL bytes, empty components, `.` or `..`
/// - duplicate paths
/// - entries whose parent directory is missing or not a directory
/// - invalid mode bits (`> 0o7777`) or invalid `mtime_nsec`
/// - missing or extraneous kind-specific fields
/// - malformed lowercase hex in `sha256` or `xattrs` values, or non-`user.` xattr names
/// - `link_group` members that disagree on `size` or `sha256`
/// - `totals` that disagree with `entries`
pub fn validate_manifest(manifest: &Manifest) -> Result<(), StoreError> {
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(StoreError::InvalidManifest {
            reason: format!(
                "unsupported schema_version {} (expected {})",
                manifest.schema_version, MANIFEST_SCHEMA_VERSION
            ),
        });
    }

    let mut kind_by_path: HashMap<&str, EntryKind> = HashMap::with_capacity(manifest.entries.len());
    let mut link_groups: HashMap<u64, (u64, &str)> = HashMap::new();
    let mut files = 0u64;
    let mut dirs = 0u64;
    let mut symlinks = 0u64;
    let mut total_bytes = 0u64;

    for entry in &manifest.entries {
        validate_relative_path(&entry.path)?;

        if kind_by_path
            .insert(entry.path.as_str(), entry.kind)
            .is_some()
        {
            return Err(StoreError::InvalidManifest {
                reason: format!("duplicate path {:?}", entry.path),
            });
        }

        if entry.mode > 0o7777 {
            return Err(StoreError::InvalidManifest {
                reason: format!(
                    "entry {:?} has invalid mode bits {:#o}",
                    entry.path, entry.mode
                ),
            });
        }

        if !(0..1_000_000_000).contains(&entry.mtime_nsec) {
            return Err(StoreError::InvalidManifest {
                reason: format!(
                    "entry {:?} has out-of-range mtime_nsec {}",
                    entry.path, entry.mtime_nsec
                ),
            });
        }

        for (attr, hex_val) in &entry.xattrs {
            if !attr.starts_with("user.") || attr.contains('\0') {
                return Err(StoreError::InvalidManifest {
                    reason: format!(
                        "entry {:?} has disallowed xattr name {:?}",
                        entry.path, attr
                    ),
                });
            }
            if !is_valid_hex(hex_val) {
                return Err(StoreError::InvalidManifest {
                    reason: format!(
                        "entry {:?} xattr {:?} has malformed hex value",
                        entry.path, attr
                    ),
                });
            }
        }

        match entry.kind {
            EntryKind::File => {
                files = files
                    .checked_add(1)
                    .ok_or_else(|| StoreError::InvalidManifest {
                        reason: "file count overflow".into(),
                    })?;
                let size = entry.size.ok_or_else(|| StoreError::InvalidManifest {
                    reason: format!("file {:?} missing size", entry.path),
                })?;
                let sha256 =
                    entry
                        .sha256
                        .as_deref()
                        .ok_or_else(|| StoreError::InvalidManifest {
                            reason: format!("file {:?} missing sha256", entry.path),
                        })?;
                if !is_valid_sha256_hex(sha256) {
                    return Err(StoreError::InvalidManifest {
                        reason: format!("file {:?} has malformed sha256 {:?}", entry.path, sha256),
                    });
                }
                if entry.target.is_some() {
                    return Err(StoreError::InvalidManifest {
                        reason: format!("file {:?} must not have symlink target", entry.path),
                    });
                }
                total_bytes =
                    total_bytes
                        .checked_add(size)
                        .ok_or_else(|| StoreError::InvalidManifest {
                            reason: "total_bytes overflow".into(),
                        })?;
                if let Some(group) = entry.link_group {
                    if let Some(&(expected_size, expected_sha)) = link_groups.get(&group) {
                        if expected_size != size || expected_sha != sha256 {
                            return Err(StoreError::InvalidManifest {
                                reason: format!(
                                    "link_group {group} members disagree at {:?}",
                                    entry.path
                                ),
                            });
                        }
                    } else {
                        link_groups.insert(group, (size, sha256));
                    }
                }
            }
            EntryKind::Dir => {
                dirs = dirs
                    .checked_add(1)
                    .ok_or_else(|| StoreError::InvalidManifest {
                        reason: "dir count overflow".into(),
                    })?;
                if entry.size.is_some()
                    || entry.sha256.is_some()
                    || entry.target.is_some()
                    || entry.link_group.is_some()
                {
                    return Err(StoreError::InvalidManifest {
                        reason: format!("dir {:?} has unexpected file/symlink fields", entry.path),
                    });
                }
            }
            EntryKind::Symlink => {
                symlinks = symlinks
                    .checked_add(1)
                    .ok_or_else(|| StoreError::InvalidManifest {
                        reason: "symlink count overflow".into(),
                    })?;
                let target =
                    entry
                        .target
                        .as_deref()
                        .ok_or_else(|| StoreError::InvalidManifest {
                            reason: format!("symlink {:?} missing target", entry.path),
                        })?;
                if target.is_empty() || target.contains('\0') {
                    return Err(StoreError::InvalidManifest {
                        reason: format!("symlink {:?} has invalid target", entry.path),
                    });
                }
                if entry.size.is_some()
                    || entry.sha256.is_some()
                    || entry.link_group.is_some()
                    || !entry.xattrs.is_empty()
                {
                    return Err(StoreError::InvalidManifest {
                        reason: format!(
                            "symlink {:?} has unexpected file/xattr fields",
                            entry.path
                        ),
                    });
                }
            }
        }
    }

    // verify every nested entry's parent directory exists and is a directory
    for entry in &manifest.entries {
        if let Some((parent, _)) = entry.path.rsplit_once('/') {
            match kind_by_path.get(parent) {
                Some(EntryKind::Dir) => {}
                Some(other) => {
                    return Err(StoreError::InvalidManifest {
                        reason: format!(
                            "entry {:?} parent {:?} is {:?}, not a directory",
                            entry.path, parent, other
                        ),
                    });
                }
                None => {
                    return Err(StoreError::InvalidManifest {
                        reason: format!(
                            "entry {:?} missing parent directory {:?}",
                            entry.path, parent
                        ),
                    });
                }
            }
        }
    }

    let expected_totals = ManifestTotals {
        entries: manifest.entries.len() as u64,
        files,
        dirs,
        symlinks,
        total_bytes,
    };
    if manifest.totals != expected_totals {
        return Err(StoreError::InvalidManifest {
            reason: format!(
                "totals mismatch: manifest has {:?}, computed {:?}",
                manifest.totals, expected_totals
            ),
        });
    }

    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), StoreError> {
    if path.is_empty() {
        return Err(StoreError::InvalidManifest {
            reason: "empty entry path".into(),
        });
    }
    if path.starts_with('/') {
        return Err(StoreError::InvalidManifest {
            reason: format!("absolute path {path:?} is not allowed"),
        });
    }
    if path.contains('\0') {
        return Err(StoreError::InvalidManifest {
            reason: format!("path {path:?} contains NUL byte"),
        });
    }
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(StoreError::InvalidManifest {
                reason: format!("path {path:?} contains invalid component {component:?}"),
            });
        }
    }
    Ok(())
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub(crate) fn is_valid_hex(s: &str) -> bool {
    s.len().is_multiple_of(2)
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64 && is_valid_hex(s)
}

/// parse a committed manifest filename `step-<digits>.json` into its step number.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_step_filename(name: &str) -> Option<u64> {
    let inner = name.strip_prefix("step-")?.strip_suffix(".json")?;
    if inner.len() < 6 || !inner.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let step: u64 = inner.parse().ok()?;
    if format!("step-{step:06}.json") == name {
        Some(step)
    } else {
        None
    }
}

/// canonical manifest filename for `step`.
#[cfg(target_os = "linux")]
pub(crate) fn step_manifest_filename(step: u64) -> String {
    format!("step-{step:06}.json")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn valid_sha(ch: char) -> String {
        std::iter::repeat_n(ch, 64).collect()
    }

    fn sample_file(path: &str, size: u64, sha: &str) -> ManifestEntry {
        ManifestEntry {
            path: path.into(),
            kind: EntryKind::File,
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            mtime_sec: 1_700_000_000,
            mtime_nsec: 123_456_789,
            size: Some(size),
            sha256: Some(sha.into()),
            target: None,
            link_group: None,
            xattrs: BTreeMap::new(),
        }
    }

    fn sample_dir(path: &str) -> ManifestEntry {
        ManifestEntry {
            path: path.into(),
            kind: EntryKind::Dir,
            mode: 0o755,
            uid: 1000,
            gid: 1000,
            mtime_sec: 1_700_000_000,
            mtime_nsec: 0,
            size: None,
            sha256: None,
            target: None,
            link_group: None,
            xattrs: BTreeMap::new(),
        }
    }

    fn sample_symlink(path: &str, target: &str) -> ManifestEntry {
        ManifestEntry {
            path: path.into(),
            kind: EntryKind::Symlink,
            mode: 0o777,
            uid: 1000,
            gid: 1000,
            mtime_sec: 1_700_000_000,
            mtime_nsec: 0,
            size: None,
            sha256: None,
            target: Some(target.into()),
            link_group: None,
            xattrs: BTreeMap::new(),
        }
    }

    fn manifest_from_entries(entries: Vec<ManifestEntry>) -> Manifest {
        let mut files = 0u64;
        let mut dirs = 0u64;
        let mut symlinks = 0u64;
        let mut total_bytes = 0u64;
        for e in &entries {
            match e.kind {
                EntryKind::File => {
                    files += 1;
                    total_bytes += e.size.unwrap_or(0);
                }
                EntryKind::Dir => dirs += 1,
                EntryKind::Symlink => symlinks += 1,
            }
        }
        Manifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            step: 1,
            totals: ManifestTotals {
                entries: entries.len() as u64,
                files,
                dirs,
                symlinks,
                total_bytes,
            },
            entries,
        }
    }

    #[test]
    fn valid_manifest_passes_validation_and_round_trips_json() {
        let mut file = sample_file("src/main.rs", 12, &valid_sha('a'));
        file.xattrs.insert("user.tag".into(), "6869".into());
        let m = manifest_from_entries(vec![
            sample_dir("src"),
            file,
            sample_symlink("link", "../outside"),
        ]);
        let bytes = serde_json::to_vec(&m).unwrap();
        let parsed = parse_manifest(&bytes).unwrap();
        assert_eq!(parsed, m);
        assert_eq!(manifest_digest(&bytes), manifest_digest(&bytes));
        assert_eq!(manifest_digest(&bytes).len(), 64);
    }

    #[test]
    fn rejects_absolute_paths() {
        let m = manifest_from_entries(vec![sample_file("/etc/passwd", 10, &valid_sha('a'))]);
        let err = validate_manifest(&m).unwrap_err();
        assert!(matches!(err, StoreError::InvalidManifest { .. }), "{err:?}");
    }

    #[test]
    fn rejects_empty_components_and_trailing_slashes() {
        for bad in ["", "a//b", "a/", "/a", "a///b"] {
            let m = manifest_from_entries(vec![sample_file(bad, 1, &valid_sha('a'))]);
            let err = validate_manifest(&m).unwrap_err();
            assert!(
                matches!(err, StoreError::InvalidManifest { .. }),
                "expected rejection for {bad:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_dot_and_dotdot_components() {
        for bad in [".", "..", "./a", "a/.", "a/..", "../a", "a/../b"] {
            let m = manifest_from_entries(vec![sample_file(bad, 1, &valid_sha('a'))]);
            let err = validate_manifest(&m).unwrap_err();
            assert!(
                matches!(err, StoreError::InvalidManifest { .. }),
                "expected rejection for {bad:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_duplicate_paths() {
        let m = manifest_from_entries(vec![
            sample_file("a.txt", 1, &valid_sha('a')),
            sample_file("a.txt", 1, &valid_sha('a')),
        ]);
        assert!(matches!(
            validate_manifest(&m),
            Err(StoreError::InvalidManifest { .. })
        ));
    }

    #[test]
    fn rejects_missing_parent_directory() {
        let m = manifest_from_entries(vec![sample_file("missing/child.txt", 5, &valid_sha('a'))]);
        assert!(matches!(
            validate_manifest(&m),
            Err(StoreError::InvalidManifest { .. })
        ));
    }

    #[test]
    fn rejects_non_directory_parent() {
        let m = manifest_from_entries(vec![
            sample_file("notadir", 5, &valid_sha('a')),
            sample_file("notadir/child.txt", 5, &valid_sha('b')),
        ]);
        assert!(matches!(
            validate_manifest(&m),
            Err(StoreError::InvalidManifest { .. })
        ));

        let m2 = manifest_from_entries(vec![
            sample_symlink("linkdir", "/tmp"),
            sample_file("linkdir/child.txt", 5, &valid_sha('b')),
        ]);
        assert!(matches!(
            validate_manifest(&m2),
            Err(StoreError::InvalidManifest { .. })
        ));
    }

    #[test]
    fn rejects_unknown_entry_kind_in_json() {
        let json = serde_json::json!({
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "step": 0,
            "totals": { "entries": 1, "files": 0, "dirs": 0, "symlinks": 0, "total_bytes": 0 },
            "entries": [{
                "path": "pipe",
                "kind": "fifo",
                "mode": 420,
                "uid": 1000,
                "gid": 1000,
                "mtime_sec": 0,
                "mtime_nsec": 0
            }]
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        assert!(matches!(
            parse_manifest(&bytes),
            Err(StoreError::InvalidManifest { .. })
        ));
    }

    #[test]
    fn rejects_malformed_hex_in_sha256_and_xattrs() {
        // short sha256
        let m = manifest_from_entries(vec![sample_file("a", 1, "abcd")]);
        assert!(matches!(
            validate_manifest(&m),
            Err(StoreError::InvalidManifest { .. })
        ));

        // uppercase sha256
        let m = manifest_from_entries(vec![sample_file("a", 1, &valid_sha('A'))]);
        assert!(matches!(
            validate_manifest(&m),
            Err(StoreError::InvalidManifest { .. })
        ));

        // non-hex char in sha256
        let m = manifest_from_entries(vec![sample_file("a", 1, &valid_sha('g'))]);
        assert!(matches!(
            validate_manifest(&m),
            Err(StoreError::InvalidManifest { .. })
        ));

        // odd-length hex in xattr value
        let mut f = sample_file("a", 1, &valid_sha('a'));
        f.xattrs.insert("user.bad".into(), "abc".into());
        let m = manifest_from_entries(vec![f]);
        assert!(matches!(
            validate_manifest(&m),
            Err(StoreError::InvalidManifest { .. })
        ));

        // non-user xattr name
        let mut f = sample_file("a", 1, &valid_sha('a'));
        f.xattrs.insert("trusted.bad".into(), "00".into());
        let m = manifest_from_entries(vec![f]);
        assert!(matches!(
            validate_manifest(&m),
            Err(StoreError::InvalidManifest { .. })
        ));
    }

    #[test]
    fn rejects_link_group_disagreement_on_size_or_hash() {
        // disagree on hash
        let mut a = sample_file("a", 10, &valid_sha('a'));
        let mut b = sample_file("b", 10, &valid_sha('b'));
        a.link_group = Some(1);
        b.link_group = Some(1);
        let m = manifest_from_entries(vec![a, b]);
        assert!(matches!(
            validate_manifest(&m),
            Err(StoreError::InvalidManifest { .. })
        ));

        // disagree on size
        let mut c = sample_file("c", 10, &valid_sha('a'));
        let mut d = sample_file("d", 11, &valid_sha('a'));
        c.link_group = Some(2);
        d.link_group = Some(2);
        let m = manifest_from_entries(vec![c, d]);
        assert!(matches!(
            validate_manifest(&m),
            Err(StoreError::InvalidManifest { .. })
        ));

        // agreeing link_group passes
        let mut e = sample_file("e", 10, &valid_sha('a'));
        let mut f = sample_file("f", 10, &valid_sha('a'));
        e.link_group = Some(3);
        f.link_group = Some(3);
        let m = manifest_from_entries(vec![e, f]);
        validate_manifest(&m).unwrap();
    }

    #[test]
    fn rejects_wrong_schema_version_and_mismatched_totals() {
        let mut m = manifest_from_entries(vec![sample_file("a", 5, &valid_sha('a'))]);
        m.schema_version = 99;
        assert!(matches!(
            validate_manifest(&m),
            Err(StoreError::InvalidManifest { .. })
        ));

        m.schema_version = MANIFEST_SCHEMA_VERSION;
        m.totals.total_bytes = 999;
        assert!(matches!(
            validate_manifest(&m),
            Err(StoreError::InvalidManifest { .. })
        ));
    }

    #[test]
    fn check_file_unchanged_detects_concurrent_size_or_mtime_change() {
        let base = FileFingerprint {
            size: 100,
            mtime_sec: 1_700_000_000,
            mtime_nsec: 500,
        };
        check_file_unchanged("a.txt", base, base, 100).unwrap();

        // bytes_read mismatch
        assert!(matches!(
            check_file_unchanged("a.txt", base, base, 101),
            Err(StoreError::ConcurrentModification { .. })
        ));
        // size changed in fstat
        assert!(matches!(
            check_file_unchanged("a.txt", base, FileFingerprint { size: 101, ..base }, 100),
            Err(StoreError::ConcurrentModification { .. })
        ));
        // mtime_sec changed
        assert!(matches!(
            check_file_unchanged(
                "a.txt",
                base,
                FileFingerprint {
                    mtime_sec: base.mtime_sec + 1,
                    ..base
                },
                100
            ),
            Err(StoreError::ConcurrentModification { .. })
        ));
        // mtime_nsec changed
        assert!(matches!(
            check_file_unchanged(
                "a.txt",
                base,
                FileFingerprint {
                    mtime_nsec: base.mtime_nsec + 1,
                    ..base
                },
                100
            ),
            Err(StoreError::ConcurrentModification { .. })
        ));
    }

    #[test]
    fn classify_xattr_allows_user_ignores_selinux_rejects_others() {
        assert_eq!(classify_xattr("user.foo"), XattrAction::Record);
        assert_eq!(classify_xattr("user.a.b"), XattrAction::Record);
        assert_eq!(classify_xattr("security.selinux"), XattrAction::Ignore);
        assert_eq!(classify_xattr("security.capability"), XattrAction::Reject);
        assert_eq!(
            classify_xattr("system.posix_acl_access"),
            XattrAction::Reject
        );
        assert_eq!(
            classify_xattr("trusted.overlay.opaque"),
            XattrAction::Reject
        );
    }

    #[test]
    fn parse_step_filename_accepts_canonical_names_only() {
        assert_eq!(parse_step_filename("step-000000.json"), Some(0));
        assert_eq!(parse_step_filename("step-000042.json"), Some(42));
        assert_eq!(parse_step_filename("step-1000000.json"), Some(1_000_000));
        assert_eq!(parse_step_filename("step-1.json"), None);
        assert_eq!(parse_step_filename("step-0000001.json"), None);
        assert_eq!(parse_step_filename("tmp-abcdef.json"), None);
        assert_eq!(parse_step_filename("step-000001.json.tmp"), None);
    }
}
