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
    /// the manifest digests given to a chain head, or the manifests in a store, do not form a
    /// valid chain.
    #[error("invalid snapshot chain: {reason}")]
    InvalidChain {
        /// why the chain was rejected.
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
/// - `link_group` members that disagree on size, digest, mode, owner, mtime or xattrs
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
    let mut link_groups: HashMap<u64, &ManifestEntry> = HashMap::new();
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
                    if let Some(first) = link_groups.get(&group) {
                        // members share one inode, so every field of the inode must agree
                        let same = first.size == entry.size
                            && first.sha256 == entry.sha256
                            && first.mode == entry.mode
                            && first.uid == entry.uid
                            && first.gid == entry.gid
                            && first.mtime_sec == entry.mtime_sec
                            && first.mtime_nsec == entry.mtime_nsec
                            && first.xattrs == entry.xattrs;
                        if !same {
                            return Err(StoreError::InvalidManifest {
                                reason: format!(
                                    "link_group {group} members disagree at {:?}",
                                    entry.path
                                ),
                            });
                        }
                    } else {
                        link_groups.insert(group, entry);
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

pub(crate) fn validate_relative_path(path: &str) -> Result<(), StoreError> {
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

#[cfg(target_os = "linux")]
pub use linux::{capture, committed_steps, load_manifest, verify_object};

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{BTreeMap, HashMap};
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};

    use sha2::{Digest, Sha256};

    use super::{
        CaptureStats, EntryKind, FileFingerprint, Limits, MANIFEST_READ_CAP,
        MANIFEST_SCHEMA_VERSION, Manifest, ManifestEntry, ManifestTotals, Published, StoreError,
        XattrAction, check_file_unchanged, classify_xattr, hex_encode, is_valid_sha256_hex,
        manifest_digest, parse_manifest, parse_step_filename, step_manifest_filename,
    };

    const COPY_BUF_LEN: usize = 64 * 1024;
    const MAX_XATTR_RETRIES: usize = 4;
    const MAX_SYMLINK_TARGET_BYTES: usize = 1024 * 1024;

    struct DirStream(*mut libc::DIR);

    impl DirStream {
        fn open_from_dir_fd(dir_fd: RawFd, path: &str) -> Result<Self, StoreError> {
            // openat "." creates an independent open file description at offset 0 so
            // reading entries never disturbs the caller's directory descriptor offset.
            // SAFETY: dir_fd is a live directory descriptor; "." is a static NUL-terminated
            // string; openat returns a fresh owned fd on success.
            let fd = unsafe {
                libc::openat(
                    dir_fd,
                    c".".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io_err("openat", path, io::Error::last_os_error()));
            }
            Self::from_owned_fd(fd, path)
        }

        fn from_owned_fd(fd: RawFd, path: &str) -> Result<Self, StoreError> {
            // SAFETY: fd is a uniquely owned directory descriptor; fdopendir takes
            // ownership on success.
            let ptr = unsafe { libc::fdopendir(fd) };
            if ptr.is_null() {
                let err = io::Error::last_os_error();
                // SAFETY: fdopendir failed, so we still own fd and must close it.
                unsafe {
                    libc::close(fd);
                }
                return Err(io_err("fdopendir", path, err));
            }
            Ok(Self(ptr))
        }

        fn read_names(&mut self, path: &str) -> Result<Vec<CString>, StoreError> {
            let mut names = Vec::new();
            loop {
                // SAFETY: __errno_location returns the current thread's errno slot.
                unsafe {
                    *libc::__errno_location() = 0;
                }
                // SAFETY: self.0 is a live DIR* stream owned by self.
                let ent = unsafe { libc::readdir(self.0) };
                if ent.is_null() {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error() == Some(0) {
                        break;
                    }
                    return Err(io_err("readdir", path, err));
                }
                // SAFETY: ent is non-null and d_name is a NUL-terminated C string
                // valid until the next readdir or closedir call.
                let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
                if name == c"." || name == c".." {
                    continue;
                }
                names.push(name.to_owned());
            }
            names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            Ok(names)
        }
    }

    impl Drop for DirStream {
        fn drop(&mut self) {
            // SAFETY: self.0 was returned by fdopendir and is closed exactly once here.
            unsafe {
                libc::closedir(self.0);
            }
        }
    }

    fn io_err(op: &'static str, path: impl Into<String>, source: io::Error) -> StoreError {
        StoreError::Io {
            op,
            path: path.into(),
            source,
        }
    }

    fn fstat_fd(fd: RawFd, op: &'static str, path: &str) -> Result<libc::stat, StoreError> {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fd is a live open descriptor and fstat initializes `st` on success.
        if unsafe { libc::fstat(fd, st.as_mut_ptr()) } != 0 {
            return Err(io_err(op, path, io::Error::last_os_error()));
        }
        // SAFETY: fstat returned 0, so `st` is fully initialized.
        Ok(unsafe { st.assume_init() })
    }

    fn is_dir_mode(mode: libc::mode_t) -> bool {
        (mode & libc::S_IFMT) == libc::S_IFDIR
    }

    fn is_reg_mode(mode: libc::mode_t) -> bool {
        (mode & libc::S_IFMT) == libc::S_IFREG
    }

    fn fsync_fd(fd: RawFd, op: &'static str, path: &str) -> Result<(), StoreError> {
        // SAFETY: fd is a live open descriptor.
        if unsafe { libc::fsync(fd) } != 0 {
            return Err(io_err(op, path, io::Error::last_os_error()));
        }
        Ok(())
    }

    fn openat_dir(parent_fd: RawFd, name: &CStr, path: &str) -> Result<File, StoreError> {
        // SAFETY: parent_fd and name are live; openat returns a fresh owned fd.
        let fd = unsafe {
            libc::openat(
                parent_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io_err("openat", path, io::Error::last_os_error()));
        }
        // SAFETY: fd was returned by openat and is uniquely owned here.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn ensure_dir(parent_fd: RawFd, name: &CStr, path: &str) -> Result<File, StoreError> {
        // SAFETY: parent_fd is a live directory descriptor and name is NUL-terminated.
        let rc = unsafe { libc::mkdirat(parent_fd, name.as_ptr(), 0o700) };
        let created = if rc == 0 {
            true
        } else {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EEXIST) {
                false
            } else {
                return Err(io_err("mkdirat", path, err));
            }
        };
        let dir = openat_dir(parent_fd, name, path)?;
        if created {
            fsync_fd(parent_fd, "fsync", path)?;
        }
        Ok(dir)
    }

    fn fstatat_exists(
        dir_fd: RawFd,
        name: &CStr,
        op: &'static str,
        path: &str,
    ) -> Result<bool, StoreError> {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: dir_fd is a live directory descriptor, name is NUL-terminated, and
        // AT_SYMLINK_NOFOLLOW avoids traversing symlinks.
        let rc = unsafe {
            libc::fstatat(
                dir_fd,
                name.as_ptr(),
                st.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc == 0 {
            Ok(true)
        } else {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                Ok(false)
            } else {
                Err(io_err(op, path, err))
            }
        }
    }

    fn unlink_best_effort(dir_fd: RawFd, name: &CStr) {
        // SAFETY: dir_fd is a live directory descriptor and name is NUL-terminated.
        let _ = unsafe { libc::unlinkat(dir_fd, name.as_ptr(), 0) };
    }

    fn create_staging_file(staging_dir: &File) -> Result<(File, CString), StoreError> {
        let mut rnd = [0u8; 16];
        getrandom::fill(&mut rnd).map_err(|e| StoreError::Random(e.to_string()))?;
        let name = format!("tmp-{}", hex_encode(&rnd));
        let c_name = CString::new(name.as_str()).map_err(|_| StoreError::UnsupportedName {
            path: format!("staging/{name}"),
        })?;
        // SAFETY: staging_dir and c_name are live; O_CREAT | O_EXCL creates a new file
        // with mode 0400 and returns a fresh owned descriptor.
        let fd = unsafe {
            libc::openat(
                staging_dir.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o400 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io_err(
                "openat",
                format!("staging/{name}"),
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: fd was returned by openat and is uniquely owned here.
        let file = unsafe { File::from_raw_fd(fd) };
        // ensure exact 0400 permissions regardless of process umask.
        // SAFETY: file.as_raw_fd() is a live descriptor we own.
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o400) } != 0 {
            let err = io::Error::last_os_error();
            drop(file);
            unlink_best_effort(staging_dir.as_raw_fd(), &c_name);
            return Err(io_err("fchmod", format!("staging/{name}"), err));
        }
        Ok((file, c_name))
    }

    fn rename_noreplace(
        old_dir_fd: RawFd,
        old_name: &CStr,
        new_dir_fd: RawFd,
        new_name: &CStr,
    ) -> io::Result<bool> {
        // SAFETY: both directory descriptors and NUL-terminated names are live;
        // RENAME_NOREPLACE atomically fails with EEXIST rather than clobbering.
        let rc = unsafe {
            libc::renameat2(
                old_dir_fd,
                old_name.as_ptr(),
                new_dir_fd,
                new_name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if rc == 0 {
            Ok(true)
        } else {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EEXIST) {
                Ok(false)
            } else {
                Err(err)
            }
        }
    }

    fn join_rel(prefix: &str, name: &str) -> String {
        if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        }
    }

    fn stat_size(st: &libc::stat, path: &str) -> Result<u64, StoreError> {
        u64::try_from(st.st_size).map_err(|_| {
            io_err(
                "fstat",
                path,
                io::Error::new(io::ErrorKind::InvalidData, "negative file size"),
            )
        })
    }

    fn read_xattrs(fd: RawFd, path: &str) -> Result<BTreeMap<String, String>, StoreError> {
        let list_buf = {
            let mut result = Vec::new();
            for _ in 0..MAX_XATTR_RETRIES {
                // SAFETY: fd is a live descriptor; null pointer with 0 size queries length.
                let needed = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
                if needed < 0 {
                    let err = io::Error::last_os_error();
                    if matches!(err.raw_os_error(), Some(libc::EOPNOTSUPP | libc::ENOSYS)) {
                        return Ok(BTreeMap::new());
                    }
                    return Err(io_err("flistxattr", path, err));
                }
                if needed == 0 {
                    return Ok(BTreeMap::new());
                }
                let mut buf = vec![0u8; needed as usize];
                // SAFETY: fd is live and buf has `buf.len()` writable bytes.
                let got = unsafe { libc::flistxattr(fd, buf.as_mut_ptr().cast(), buf.len()) };
                if got < 0 {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ERANGE) {
                        continue;
                    }
                    if matches!(err.raw_os_error(), Some(libc::EOPNOTSUPP | libc::ENOSYS)) {
                        return Ok(BTreeMap::new());
                    }
                    return Err(io_err("flistxattr", path, err));
                }
                buf.truncate(got as usize);
                result = buf;
                break;
            }
            result
        };

        let mut xattrs = BTreeMap::new();
        for raw_name in list_buf.split(|&b| b == 0).filter(|s| !s.is_empty()) {
            let name = match std::str::from_utf8(raw_name) {
                Ok(s) => s,
                Err(_) => {
                    return Err(StoreError::UnsupportedMetadata {
                        path: path.to_owned(),
                        attr: String::from_utf8_lossy(raw_name).into_owned(),
                    });
                }
            };
            match classify_xattr(name) {
                XattrAction::Ignore => continue,
                XattrAction::Reject => {
                    return Err(StoreError::UnsupportedMetadata {
                        path: path.to_owned(),
                        attr: name.to_owned(),
                    });
                }
                XattrAction::Record => {
                    let c_name =
                        CString::new(raw_name).map_err(|_| StoreError::UnsupportedMetadata {
                            path: path.to_owned(),
                            attr: name.to_owned(),
                        })?;
                    let value = read_one_xattr(fd, &c_name, path)?;
                    xattrs.insert(name.to_owned(), hex_encode(&value));
                }
            }
        }
        Ok(xattrs)
    }

    fn read_one_xattr(fd: RawFd, name: &CStr, path: &str) -> Result<Vec<u8>, StoreError> {
        for _ in 0..MAX_XATTR_RETRIES {
            // SAFETY: fd is live, name is NUL-terminated; null value queries length.
            let needed = unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0) };
            if needed < 0 {
                return Err(io_err("fgetxattr", path, io::Error::last_os_error()));
            }
            if needed == 0 {
                return Ok(Vec::new());
            }
            let mut buf = vec![0u8; needed as usize];
            // SAFETY: fd is live, name is NUL-terminated, buf has `buf.len()` writable bytes.
            let got =
                unsafe { libc::fgetxattr(fd, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
            if got < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ERANGE) {
                    continue;
                }
                return Err(io_err("fgetxattr", path, err));
            }
            buf.truncate(got as usize);
            return Ok(buf);
        }
        Err(io_err(
            "fgetxattr",
            path,
            io::Error::other("xattr size changed repeatedly during read"),
        ))
    }

    fn read_symlink_target(fd: RawFd, size_hint: i64, path: &str) -> Result<String, StoreError> {
        let mut cap = usize::try_from(size_hint)
            .unwrap_or(256)
            .clamp(256, 65_536)
            .saturating_add(1);
        loop {
            let mut buf = vec![0u8; cap];
            // SAFETY: fd is an O_PATH | O_NOFOLLOW symlink descriptor; empty pathname
            // reads its target into `buf` without following the link (Linux 2.6.39+).
            let got =
                unsafe { libc::readlinkat(fd, c"".as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
            if got < 0 {
                return Err(io_err("readlinkat", path, io::Error::last_os_error()));
            }
            let got = got as usize;
            if got < buf.len() {
                buf.truncate(got);
                let target = String::from_utf8(buf).map_err(|_| StoreError::UnsupportedName {
                    path: path.to_owned(),
                })?;
                if target.is_empty() || target.contains('\0') {
                    return Err(StoreError::UnsupportedName {
                        path: path.to_owned(),
                    });
                }
                return Ok(target);
            }
            if cap >= MAX_SYMLINK_TARGET_BYTES {
                return Err(io_err(
                    "readlinkat",
                    path,
                    io::Error::new(io::ErrorKind::InvalidData, "symlink target exceeds limit"),
                ));
            }
            cap = cap.saturating_mul(2).min(MAX_SYMLINK_TARGET_BYTES);
        }
    }

    fn unsupported_kind_label(mode: libc::mode_t) -> &'static str {
        match mode & libc::S_IFMT {
            libc::S_IFIFO => "fifo",
            libc::S_IFSOCK => "socket",
            libc::S_IFCHR => "char device",
            libc::S_IFBLK => "block device",
            _ => "unknown",
        }
    }

    fn open_entry_no_follow(
        dir_fd: RawFd,
        c_name: &CStr,
        rel_path: &str,
    ) -> Result<(File, libc::stat), StoreError> {
        // SAFETY: dir_fd and c_name are live; O_NOFOLLOW | O_NONBLOCK prevents symlink
        // traversal and blocking on FIFOs.
        let fd = unsafe {
            libc::openat(
                dir_fd,
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd >= 0 {
            // SAFETY: fd was returned by openat and is uniquely owned here.
            let file = unsafe { File::from_raw_fd(fd) };
            let st = fstat_fd(file.as_raw_fd(), "fstat", rel_path)?;
            return Ok((file, st));
        }

        let open_err = io::Error::last_os_error();
        if !matches!(
            open_err.raw_os_error(),
            Some(libc::ELOOP | libc::ENXIO | libc::EACCES | libc::EPERM)
        ) {
            return Err(io_err("openat", rel_path, open_err));
        }

        // symlinks fail O_NOFOLLOW with ELOOP; unix sockets fail with ENXIO; unreadable
        // device nodes may fail with EACCES/EPERM. open with O_PATH to inspect via fstat.
        // SAFETY: dir_fd and c_name are live; O_PATH | O_NOFOLLOW opens a path handle
        // without opening the underlying device or following a symlink.
        let path_fd = unsafe {
            libc::openat(
                dir_fd,
                c_name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if path_fd < 0 {
            return Err(io_err("openat", rel_path, open_err));
        }
        // SAFETY: path_fd was returned by openat and is uniquely owned here.
        let file = unsafe { File::from_raw_fd(path_fd) };
        let st = fstat_fd(file.as_raw_fd(), "fstat", rel_path)?;
        let fmt = st.st_mode & libc::S_IFMT;
        if fmt == libc::S_IFREG || fmt == libc::S_IFDIR {
            // regular file or directory that failed O_RDONLY open (e.g. EACCES): report
            // the original open error rather than treating the O_PATH fd as readable.
            return Err(io_err("openat", rel_path, open_err));
        }
        Ok((file, st))
    }

    struct CapturedRecord {
        entry: ManifestEntry,
        /// `(st_dev, st_ino)` for regular files with `st_nlink > 1`, used to assign
        /// deterministic `link_group` ids after sorting entries by path.
        hardlink_inode: Option<(u64, u64)>,
    }

    struct DirFrame {
        dir: File,
        rel_prefix: String,
        names: Vec<CString>,
        next_idx: usize,
    }

    /// capture an exact, content-addressed snapshot of `workspace` into `store` at `step`.
    ///
    /// traverses only via `openat` relative to directory descriptors, never path strings
    /// from the root. refuses symlinks traversal, cross-device entries, non-UTF-8 names or
    /// symlink targets, FIFOs, sockets, devices, unsupported extended attributes, concurrent
    /// file modifications, and any resource limit violation.
    ///
    /// objects are staged, hashed, fsynced, and atomically placed with `RENAME_NOREPLACE`
    /// before the manifest is published. on any error, no manifest is published.
    pub fn capture(
        workspace: &File,
        store: &File,
        step: u64,
        limits: &Limits,
    ) -> Result<Published, StoreError> {
        let ws_stat = fstat_fd(workspace.as_raw_fd(), "fstat", "<workspace>")?;
        if !is_dir_mode(ws_stat.st_mode) {
            return Err(StoreError::InvalidRoot);
        }
        let store_stat = fstat_fd(store.as_raw_fd(), "fstat", "<store>")?;
        if !is_dir_mode(store_stat.st_mode) {
            return Err(StoreError::InvalidStore);
        }
        let root_dev = ws_stat.st_dev;

        let objects_dir = ensure_dir(store.as_raw_fd(), c"objects", "objects")?;
        let manifests_dir = ensure_dir(store.as_raw_fd(), c"manifests", "manifests")?;
        let staging_dir = ensure_dir(store.as_raw_fd(), c"staging", "staging")?;

        let manifest_name = step_manifest_filename(step);
        let c_manifest_name =
            CString::new(manifest_name.as_str()).map_err(|_| StoreError::UnsupportedName {
                path: format!("manifests/{manifest_name}"),
            })?;
        if fstatat_exists(
            manifests_dir.as_raw_fd(),
            &c_manifest_name,
            "fstatat",
            &format!("manifests/{manifest_name}"),
        )? {
            return Err(StoreError::ManifestExists { step });
        }

        let mut records: Vec<CapturedRecord> = Vec::new();
        let mut stats = CaptureStats {
            entries: 0,
            files: 0,
            dirs: 0,
            symlinks: 0,
            total_bytes: 0,
            new_objects: 0,
            reused_objects: 0,
            store_growth: 0,
        };
        let mut hardlink_cache: HashMap<(u64, u64), (u64, String)> = HashMap::new();
        let mut copy_buf = vec![0u8; COPY_BUF_LEN];

        let root_names = DirStream::open_from_dir_fd(workspace.as_raw_fd(), "<workspace>")?
            .read_names("<workspace>")?;
        let mut stack: Vec<DirFrame> = Vec::new();
        // handle root children using workspace's fd directly without taking ownership.
        let mut root_idx = 0usize;

        loop {
            let (parent_fd, rel_prefix, c_name) = if let Some(frame) = stack.last_mut() {
                if frame.next_idx >= frame.names.len() {
                    stack.pop();
                    continue;
                }
                let name = frame.names[frame.next_idx].clone();
                frame.next_idx += 1;
                (frame.dir.as_raw_fd(), frame.rel_prefix.clone(), name)
            } else if root_idx < root_names.len() {
                let name = root_names[root_idx].clone();
                root_idx += 1;
                (workspace.as_raw_fd(), String::new(), name)
            } else {
                break;
            };

            let name = match std::str::from_utf8(c_name.as_bytes()) {
                Ok(s) => s,
                Err(_) => {
                    let lossy = String::from_utf8_lossy(c_name.as_bytes());
                    return Err(StoreError::UnsupportedName {
                        path: join_rel(&rel_prefix, &lossy),
                    });
                }
            };
            let rel_path = join_rel(&rel_prefix, name);

            if records.len() as u64 >= limits.max_entries {
                return Err(StoreError::EntryLimitExceeded {
                    limit: limits.max_entries,
                });
            }

            let (entry_file, st) = open_entry_no_follow(parent_fd, &c_name, &rel_path)?;
            if st.st_dev != root_dev {
                return Err(StoreError::CrossDevice { path: rel_path });
            }

            let mode = st.st_mode & 0o7777;
            let uid = st.st_uid;
            let gid = st.st_gid;
            let mtime_sec = st.st_mtime;
            let mtime_nsec = st.st_mtime_nsec;

            match st.st_mode & libc::S_IFMT {
                libc::S_IFREG => {
                    let size = stat_size(&st, &rel_path)?;
                    if size > limits.max_file_size {
                        return Err(StoreError::FileSizeLimitExceeded {
                            path: rel_path,
                            size,
                            limit: limits.max_file_size,
                        });
                    }
                    let next_total = stats.total_bytes.checked_add(size).ok_or(
                        StoreError::TotalBytesLimitExceeded {
                            total: u64::MAX,
                            limit: limits.max_total_bytes,
                        },
                    )?;
                    if next_total > limits.max_total_bytes {
                        return Err(StoreError::TotalBytesLimitExceeded {
                            total: next_total,
                            limit: limits.max_total_bytes,
                        });
                    }

                    let xattrs = read_xattrs(entry_file.as_raw_fd(), &rel_path)?;
                    let inode_key = (st.st_nlink > 1).then_some((st.st_dev, st.st_ino));

                    let sha256 = if let Some(key) = inode_key
                        && let Some((cached_size, cached_sha)) = hardlink_cache.get(&key)
                    {
                        if *cached_size != size {
                            return Err(StoreError::ConcurrentModification { path: rel_path });
                        }
                        stats.reused_objects += 1;
                        cached_sha.clone()
                    } else {
                        let sha = store_regular_file(
                            entry_file,
                            &st,
                            size,
                            &rel_path,
                            &objects_dir,
                            &staging_dir,
                            limits,
                            &mut stats,
                            &mut copy_buf,
                        )?;
                        if let Some(key) = inode_key {
                            hardlink_cache.insert(key, (size, sha.clone()));
                        }
                        sha
                    };

                    stats.files += 1;
                    stats.total_bytes = next_total;
                    records.push(CapturedRecord {
                        entry: ManifestEntry {
                            path: rel_path,
                            kind: EntryKind::File,
                            mode,
                            uid,
                            gid,
                            mtime_sec,
                            mtime_nsec,
                            size: Some(size),
                            sha256: Some(sha256),
                            target: None,
                            link_group: None,
                            xattrs,
                        },
                        hardlink_inode: inode_key,
                    });
                }
                libc::S_IFDIR => {
                    let xattrs = read_xattrs(entry_file.as_raw_fd(), &rel_path)?;
                    let child_names =
                        DirStream::open_from_dir_fd(entry_file.as_raw_fd(), &rel_path)?
                            .read_names(&rel_path)?;
                    stats.dirs += 1;
                    records.push(CapturedRecord {
                        entry: ManifestEntry {
                            path: rel_path.clone(),
                            kind: EntryKind::Dir,
                            mode,
                            uid,
                            gid,
                            mtime_sec,
                            mtime_nsec,
                            size: None,
                            sha256: None,
                            target: None,
                            link_group: None,
                            xattrs,
                        },
                        hardlink_inode: None,
                    });
                    stack.push(DirFrame {
                        dir: entry_file,
                        rel_prefix: rel_path,
                        names: child_names,
                        next_idx: 0,
                    });
                }
                libc::S_IFLNK => {
                    let target =
                        read_symlink_target(entry_file.as_raw_fd(), st.st_size, &rel_path)?;
                    stats.symlinks += 1;
                    records.push(CapturedRecord {
                        entry: ManifestEntry {
                            path: rel_path,
                            kind: EntryKind::Symlink,
                            mode,
                            uid,
                            gid,
                            mtime_sec,
                            mtime_nsec,
                            size: None,
                            sha256: None,
                            target: Some(target),
                            link_group: None,
                            xattrs: BTreeMap::new(),
                        },
                        hardlink_inode: None,
                    });
                }
                other => {
                    return Err(StoreError::UnsupportedEntry {
                        path: rel_path,
                        kind: unsupported_kind_label(other),
                    });
                }
            }
        }

        // sort deterministically by path, then assign link_group ids in path order for
        // inodes shared by at least two captured regular-file entries.
        records.sort_by(|a, b| a.entry.path.cmp(&b.entry.path));
        let mut inode_counts: HashMap<(u64, u64), usize> = HashMap::new();
        for rec in &records {
            if let Some(key) = rec.hardlink_inode {
                *inode_counts.entry(key).or_insert(0) += 1;
            }
        }
        let mut group_ids: HashMap<(u64, u64), u64> = HashMap::new();
        let mut next_group_id = 1u64;
        let mut entries = Vec::with_capacity(records.len());
        for mut rec in records {
            if let Some(key) = rec.hardlink_inode
                && inode_counts.get(&key).copied().unwrap_or(0) > 1
            {
                let id = *group_ids.entry(key).or_insert_with(|| {
                    let id = next_group_id;
                    next_group_id += 1;
                    id
                });
                rec.entry.link_group = Some(id);
            }
            entries.push(rec.entry);
        }

        stats.entries = entries.len() as u64;
        let manifest = Manifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            step,
            totals: ManifestTotals {
                entries: stats.entries,
                files: stats.files,
                dirs: stats.dirs,
                symlinks: stats.symlinks,
                total_bytes: stats.total_bytes,
            },
            entries,
        };

        let bytes = serde_json::to_vec(&manifest).map_err(|e| {
            io_err(
                "serialize manifest",
                format!("manifests/{manifest_name}"),
                io::Error::other(e),
            )
        })?;
        let digest = manifest_digest(&bytes);

        let (mut staged_manifest, staged_name) = create_staging_file(&staging_dir)?;
        if let Err(err) = staged_manifest
            .write_all(&bytes)
            .and_then(|()| staged_manifest.sync_all())
        {
            drop(staged_manifest);
            unlink_best_effort(staging_dir.as_raw_fd(), &staged_name);
            return Err(io_err(
                "write manifest",
                format!("manifests/{manifest_name}"),
                err,
            ));
        }
        drop(staged_manifest);

        let placed = match rename_noreplace(
            staging_dir.as_raw_fd(),
            &staged_name,
            manifests_dir.as_raw_fd(),
            &c_manifest_name,
        ) {
            Ok(placed) => placed,
            Err(err) => {
                unlink_best_effort(staging_dir.as_raw_fd(), &staged_name);
                return Err(io_err(
                    "renameat2",
                    format!("manifests/{manifest_name}"),
                    err,
                ));
            }
        };
        if !placed {
            unlink_best_effort(staging_dir.as_raw_fd(), &staged_name);
            return Err(StoreError::ManifestExists { step });
        }

        fsync_fd(
            manifests_dir.as_raw_fd(),
            "fsync",
            &format!("manifests/{manifest_name}"),
        )?;

        Ok(Published {
            manifest_digest: digest,
            stats,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn store_regular_file(
        mut src: File,
        before_stat: &libc::stat,
        size: u64,
        rel_path: &str,
        objects_dir: &File,
        staging_dir: &File,
        limits: &Limits,
        stats: &mut CaptureStats,
        copy_buf: &mut [u8],
    ) -> Result<String, StoreError> {
        let before_fp = FileFingerprint {
            size,
            mtime_sec: before_stat.st_mtime,
            mtime_nsec: before_stat.st_mtime_nsec,
        };
        let (mut staged, staged_name) = create_staging_file(staging_dir)?;
        let mut hasher = Sha256::new();
        let mut bytes_read = 0u64;

        loop {
            let n = match src.read(copy_buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    drop(staged);
                    unlink_best_effort(staging_dir.as_raw_fd(), &staged_name);
                    return Err(io_err("read", rel_path, e));
                }
            };
            bytes_read = bytes_read.saturating_add(n as u64);
            if bytes_read > size {
                drop(staged);
                unlink_best_effort(staging_dir.as_raw_fd(), &staged_name);
                return Err(StoreError::ConcurrentModification {
                    path: rel_path.to_owned(),
                });
            }
            hasher.update(&copy_buf[..n]);
            if let Err(e) = staged.write_all(&copy_buf[..n]) {
                drop(staged);
                unlink_best_effort(staging_dir.as_raw_fd(), &staged_name);
                return Err(io_err("write staging", rel_path, e));
            }
        }

        let after_stat = match fstat_fd(src.as_raw_fd(), "fstat", rel_path) {
            Ok(st) => st,
            Err(err) => {
                drop(staged);
                unlink_best_effort(staging_dir.as_raw_fd(), &staged_name);
                return Err(err);
            }
        };
        let after_size = match stat_size(&after_stat, rel_path) {
            Ok(sz) => sz,
            Err(err) => {
                drop(staged);
                unlink_best_effort(staging_dir.as_raw_fd(), &staged_name);
                return Err(err);
            }
        };
        let after_fp = FileFingerprint {
            size: after_size,
            mtime_sec: after_stat.st_mtime,
            mtime_nsec: after_stat.st_mtime_nsec,
        };
        if let Err(err) = check_file_unchanged(rel_path, before_fp, after_fp, bytes_read) {
            drop(staged);
            unlink_best_effort(staging_dir.as_raw_fd(), &staged_name);
            return Err(err);
        }

        if let Err(e) = staged.sync_all() {
            drop(staged);
            unlink_best_effort(staging_dir.as_raw_fd(), &staged_name);
            return Err(io_err("fsync staging", rel_path, e));
        }
        drop(staged);

        let sha256_hex = hex_encode(&hasher.finalize());
        let bucket = &sha256_hex[..2];
        let c_bucket =
            CString::new(bucket).map_err(|_| StoreError::InvalidDigest(sha256_hex.clone()))?;
        let c_hash = CString::new(sha256_hex.as_str())
            .map_err(|_| StoreError::InvalidDigest(sha256_hex.clone()))?;

        let bucket_path = format!("objects/{bucket}");
        let object_path = format!("objects/{bucket}/{sha256_hex}");
        let bucket_dir = match ensure_dir(objects_dir.as_raw_fd(), &c_bucket, &bucket_path) {
            Ok(dir) => dir,
            Err(err) => {
                unlink_best_effort(staging_dir.as_raw_fd(), &staged_name);
                return Err(err);
            }
        };

        let already_exists =
            match fstatat_exists(bucket_dir.as_raw_fd(), &c_hash, "fstatat", &object_path) {
                Ok(exists) => exists,
                Err(err) => {
                    unlink_best_effort(staging_dir.as_raw_fd(), &staged_name);
                    return Err(err);
                }
            };
        if already_exists {
            unlink_best_effort(staging_dir.as_raw_fd(), &staged_name);
            stats.reused_objects += 1;
            return Ok(sha256_hex);
        }

        let next_growth = stats.store_growth.checked_add(bytes_read).ok_or(
            StoreError::StoreGrowthLimitExceeded {
                growth: u64::MAX,
                limit: limits.max_store_growth,
            },
        );
        let next_growth = match next_growth {
            Ok(g) if g <= limits.max_store_growth => g,
            Ok(g) => {
                unlink_best_effort(staging_dir.as_raw_fd(), &staged_name);
                return Err(StoreError::StoreGrowthLimitExceeded {
                    growth: g,
                    limit: limits.max_store_growth,
                });
            }
            Err(err) => {
                unlink_best_effort(staging_dir.as_raw_fd(), &staged_name);
                return Err(err);
            }
        };

        let placed = match rename_noreplace(
            staging_dir.as_raw_fd(),
            &staged_name,
            bucket_dir.as_raw_fd(),
            &c_hash,
        ) {
            Ok(placed) => placed,
            Err(err) => {
                unlink_best_effort(staging_dir.as_raw_fd(), &staged_name);
                return Err(io_err("renameat2", &object_path, err));
            }
        };
        if placed {
            fsync_fd(bucket_dir.as_raw_fd(), "fsync", &bucket_path)?;
            stats.new_objects += 1;
            stats.store_growth = next_growth;
        } else {
            unlink_best_effort(staging_dir.as_raw_fd(), &staged_name);
            stats.reused_objects += 1;
        }

        Ok(sha256_hex)
    }

    /// load and validate the committed manifest for `step` from `store`.
    ///
    /// returns the parsed `Manifest` along with the lowercase hex SHA-256 digest of the
    /// exact bytes read from disk. refuses symlinks, non-regular files, manifests larger
    /// than `MANIFEST_READ_CAP`, malformed JSON/invariants, and step-number mismatches.
    pub fn load_manifest(store: &File, step: u64) -> Result<(Manifest, String), StoreError> {
        let store_stat = fstat_fd(store.as_raw_fd(), "fstat", "<store>")?;
        if !is_dir_mode(store_stat.st_mode) {
            return Err(StoreError::InvalidStore);
        }

        let manifests_dir = openat_dir(store.as_raw_fd(), c"manifests", "manifests")?;
        let name = step_manifest_filename(step);
        let rel = format!("manifests/{name}");
        let c_name = CString::new(name.as_str())
            .map_err(|_| StoreError::UnsupportedName { path: rel.clone() })?;

        // SAFETY: manifests_dir and c_name are live; O_NOFOLLOW | O_NONBLOCK prevents
        // symlink traversal and FIFO blocking.
        let fd = unsafe {
            libc::openat(
                manifests_dir.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ELOOP) {
                return Err(StoreError::InvalidManifest {
                    reason: format!("{rel} is a symlink"),
                });
            }
            return Err(io_err("openat", &rel, err));
        }
        // SAFETY: fd was returned by openat and is uniquely owned here.
        let file = unsafe { File::from_raw_fd(fd) };

        let st = fstat_fd(file.as_raw_fd(), "fstat", &rel)?;
        if !is_reg_mode(st.st_mode) {
            return Err(StoreError::InvalidManifest {
                reason: format!("{rel} is not a regular file"),
            });
        }
        let size = stat_size(&st, &rel)?;
        if size > MANIFEST_READ_CAP {
            return Err(StoreError::ManifestTooLarge {
                step,
                limit: MANIFEST_READ_CAP,
            });
        }

        let mut bytes = Vec::new();
        file.take(MANIFEST_READ_CAP + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| io_err("read", &rel, e))?;
        if bytes.len() as u64 > MANIFEST_READ_CAP {
            return Err(StoreError::ManifestTooLarge {
                step,
                limit: MANIFEST_READ_CAP,
            });
        }

        let manifest = parse_manifest(&bytes)?;
        if manifest.step != step {
            return Err(StoreError::InvalidManifest {
                reason: format!(
                    "manifest step {} does not match requested step {step}",
                    manifest.step
                ),
            });
        }

        let digest = manifest_digest(&bytes);
        Ok((manifest, digest))
    }

    /// open a content-addressed object by `sha256_hex`, verify its integrity, and return
    /// a handle rewound to offset 0.
    ///
    /// rejects malformed digests (`InvalidDigest`), symlinks and non-regular files
    /// (`InvalidObject`), and content whose SHA-256 differs from `sha256_hex`
    /// (`ObjectCorrupt`).
    pub fn verify_object(store: &File, sha256_hex: &str) -> Result<File, StoreError> {
        if !is_valid_sha256_hex(sha256_hex) {
            return Err(StoreError::InvalidDigest(sha256_hex.to_owned()));
        }
        let store_stat = fstat_fd(store.as_raw_fd(), "fstat", "<store>")?;
        if !is_dir_mode(store_stat.st_mode) {
            return Err(StoreError::InvalidStore);
        }

        let objects_dir = openat_dir(store.as_raw_fd(), c"objects", "objects")?;
        let bucket = &sha256_hex[..2];
        let bucket_path = format!("objects/{bucket}");
        let object_path = format!("objects/{bucket}/{sha256_hex}");
        let c_bucket =
            CString::new(bucket).map_err(|_| StoreError::InvalidDigest(sha256_hex.to_owned()))?;
        let c_hash = CString::new(sha256_hex)
            .map_err(|_| StoreError::InvalidDigest(sha256_hex.to_owned()))?;

        let bucket_dir = openat_dir(objects_dir.as_raw_fd(), &c_bucket, &bucket_path)?;
        // SAFETY: bucket_dir and c_hash are live; O_NOFOLLOW | O_NONBLOCK refuses symlinks
        // and avoids blocking on FIFOs.
        let fd = unsafe {
            libc::openat(
                bucket_dir.as_raw_fd(),
                c_hash.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ELOOP) {
                return Err(StoreError::InvalidObject {
                    digest: sha256_hex.to_owned(),
                    reason: "object is a symlink",
                });
            }
            return Err(io_err("openat", &object_path, err));
        }
        // SAFETY: fd was returned by openat and is uniquely owned here.
        let mut file = unsafe { File::from_raw_fd(fd) };

        let st = fstat_fd(file.as_raw_fd(), "fstat", &object_path)?;
        if !is_reg_mode(st.st_mode) {
            return Err(StoreError::InvalidObject {
                digest: sha256_hex.to_owned(),
                reason: "object is not a regular file",
            });
        }

        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; COPY_BUF_LEN];
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => hasher.update(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(io_err("read", &object_path, e)),
            }
        }

        let actual = hex_encode(&hasher.finalize());
        if actual != sha256_hex {
            return Err(StoreError::ObjectCorrupt {
                expected: sha256_hex.to_owned(),
                actual,
            });
        }

        file.seek(SeekFrom::Start(0))
            .map_err(|e| io_err("seek", &object_path, e))?;
        Ok(file)
    }

    /// list all committed step numbers present in `manifests/`, sorted ascending.
    ///
    /// returns an empty list if `manifests/` does not exist yet. ignores any entry whose
    /// filename does not match `parse_step_filename`.
    pub fn committed_steps(store: &File) -> Result<Vec<u64>, StoreError> {
        let store_stat = fstat_fd(store.as_raw_fd(), "fstat", "<store>")?;
        if !is_dir_mode(store_stat.st_mode) {
            return Err(StoreError::InvalidStore);
        }

        // SAFETY: store is a live directory descriptor; openat returns a fresh owned fd.
        let fd = unsafe {
            libc::openat(
                store.as_raw_fd(),
                c"manifests".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(Vec::new());
            }
            return Err(io_err("openat", "manifests", err));
        }

        let mut stream = DirStream::from_owned_fd(fd, "manifests")?;
        let names = stream.read_names("manifests")?;
        let mut steps = Vec::new();
        for c_name in names {
            if let Ok(name) = c_name.to_str()
                && let Some(step) = parse_step_filename(name)
            {
                steps.push(step);
            }
        }
        steps.sort_unstable();
        Ok(steps)
    }
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
    fn rejects_link_group_members_with_different_metadata() {
        type Tweak = fn(&mut ManifestEntry);
        let tweaks: [(&str, Tweak); 6] = [
            ("mode", |e| e.mode = 0o600),
            ("uid", |e| e.uid = 1001),
            ("gid", |e| e.gid = 1001),
            ("mtime_sec", |e| e.mtime_sec += 1),
            ("mtime_nsec", |e| e.mtime_nsec += 1),
            ("xattrs", |e| {
                e.xattrs.insert("user.k".into(), "00".into());
            }),
        ];
        for (what, tweak) in tweaks {
            let mut a = sample_file("a", 10, &valid_sha('a'));
            let mut b = sample_file("b", 10, &valid_sha('a'));
            a.link_group = Some(1);
            b.link_group = Some(1);
            tweak(&mut b);
            let m = manifest_from_entries(vec![a, b]);
            let err = validate_manifest(&m).unwrap_err();
            assert!(
                matches!(&err, StoreError::InvalidManifest { reason } if reason.contains("link_group")),
                "{what}: {err}"
            );
        }
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
