//! the workspace lock of a snapshot run or a rewind (ADR-0024 decision 13).
//!
//! assumptions: the lock excludes other Leash operations on one workspace, not external
//! writers, which stay the operator's contract (ADR-0022). it is an exclusive,
//! non-blocking `flock` on `<state_root>/locks/<sha256 of the canonical workspace path>.lock`,
//! so two spellings of one directory share a lock and two directories never do. the kernel
//! drops it when the holder dies, so a crashed run never leaves a stale lock. the state
//! root is opened once and every component beneath it goes through that handle with
//! `O_NOFOLLOW`, so a planted symlink under the state root cannot redirect the lock file.
//!
//! `leash run` takes it before any run directory exists and holds it for the whole run;
//! `leash rewind` takes the same lock through `WorkspaceLock::acquire`.

use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// the directory under the state root that holds the lock files.
const LOCKS_DIR: &CStr = c"locks";

/// why the workspace lock could not be taken.
#[derive(Debug, thiserror::Error)]
pub enum WorkspaceLockError {
    /// another run or rewind holds the lock.
    #[error(
        "another leash run or rewind owns this workspace ({}); wait for it to finish",
        .0.display()
    )]
    Held(PathBuf),
    /// the lock file could not be set up under the state root.
    #[error("workspace lock {op} failed for {}: {source}", .path.display())]
    Io {
        /// what was being attempted.
        op: &'static str,
        /// the path involved.
        path: PathBuf,
        /// the underlying error.
        #[source]
        source: io::Error,
    },
}

/// the exclusive lock on one workspace, held until dropped.
#[derive(Debug)]
pub struct WorkspaceLock {
    _file: File,
    path: PathBuf,
}

/// the lock file name for a canonical workspace path: the lowercase hex sha256 of the
/// path bytes, then `.lock`.
pub fn lock_file_name(canonical_workspace: &Path) -> String {
    let digest = Sha256::digest(canonical_workspace.as_os_str().as_bytes());
    let mut name = String::with_capacity(70);
    for byte in digest {
        name.push_str(&format!("{byte:02x}"));
    }
    name.push_str(".lock");
    name
}

impl WorkspaceLock {
    /// take the lock for `workspace` under `state_root`, without blocking. `workspace` is
    /// canonicalized here so every spelling of one directory maps to one lock.
    pub fn acquire(state_root: &Path, workspace: &Path) -> Result<Self, WorkspaceLockError> {
        let canonical = workspace
            .canonicalize()
            .map_err(|source| io_error("canonicalize", workspace, source))?;
        let name = lock_file_name(&canonical);
        let lock_path = state_root.join("locks").join(&name);
        let fail = |op: &'static str| {
            let path = lock_path.clone();
            move |source| io_error(op, &path, source)
        };

        let root = open_dir(libc::AT_FDCWD, state_root.as_os_str(), false).map_err(fail("open"))?;
        // SAFETY: root is a live directory descriptor and LOCKS_DIR is nul-terminated.
        let made = unsafe { libc::mkdirat(root.as_raw_fd(), LOCKS_DIR.as_ptr(), 0o700) };
        if made != 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EEXIST) {
                return Err(fail("create locks directory")(e));
            }
        }
        let locks = open_dir(
            root.as_raw_fd(),
            OsStr::from_bytes(LOCKS_DIR.to_bytes()),
            true,
        )
        .map_err(fail("open locks directory"))?;

        let c_name = CString::new(name.as_str())
            .map_err(|_| fail("name")(io::Error::from(io::ErrorKind::InvalidInput)))?;
        // SAFETY: locks is a live directory descriptor and c_name is nul-terminated. the
        // open never follows a final symlink, is non-blocking so a planted FIFO cannot
        // hang it, and is close-on-exec so no child inherits the lock.
        let fd = unsafe {
            libc::openat(
                locks.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(fail("open lock file")(io::Error::last_os_error()));
        }
        // SAFETY: fd was just returned by openat and nothing else owns it.
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata().map_err(fail("stat lock file"))?;
        if !meta.file_type().is_file() {
            return Err(fail("check lock file")(io::Error::new(
                io::ErrorKind::InvalidData,
                "the lock file is not a regular file",
            )));
        }
        // SAFETY: flock takes a live descriptor and scalar flags.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let e = io::Error::last_os_error();
            return Err(if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                WorkspaceLockError::Held(lock_path.clone())
            } else {
                fail("lock")(e)
            });
        }
        Ok(Self {
            _file: file,
            path: lock_path,
        })
    }

    /// the lock file's path under the state root.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn io_error(op: &'static str, path: &Path, source: io::Error) -> WorkspaceLockError {
    WorkspaceLockError::Io {
        op,
        path: path.to_path_buf(),
        source,
    }
}

/// open the directory `name` relative to `dir_fd`, optionally refusing a final symlink.
fn open_dir(dir_fd: libc::c_int, name: &OsStr, no_follow: bool) -> io::Result<File> {
    let c_name =
        CString::new(name.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    if no_follow {
        flags |= libc::O_NOFOLLOW;
    }
    // SAFETY: c_name is nul-terminated and dir_fd is AT_FDCWD or a live directory
    // descriptor; openat returns a new descriptor or -1.
    let fd = unsafe { libc::openat(dir_fd, c_name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was just returned by openat and nothing else owns it.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_lock_name_is_a_stable_function_of_the_workspace_path_only() {
        let a = lock_file_name(Path::new("/work/a"));
        assert_eq!(a, lock_file_name(Path::new("/work/a")));
        assert_ne!(a, lock_file_name(Path::new("/work/b")));
        assert_eq!(a.len(), 64 + ".lock".len());
        assert!(a.ends_with(".lock"));
        assert!(
            a[..64]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    #[test]
    fn a_second_acquire_on_the_same_workspace_is_refused_until_the_first_drops() {
        let state = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        let first = WorkspaceLock::acquire(state.path(), ws.path()).unwrap();
        let err = WorkspaceLock::acquire(state.path(), ws.path()).unwrap_err();
        assert!(matches!(err, WorkspaceLockError::Held(_)), "{err:?}");
        assert!(
            err.to_string()
                .contains("another leash run or rewind owns this workspace")
        );
        drop(first);
        WorkspaceLock::acquire(state.path(), ws.path()).unwrap();
    }

    #[test]
    fn two_spellings_of_one_workspace_share_a_lock_and_two_workspaces_do_not() {
        let state = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let link_dir = tempfile::tempdir().unwrap();
        let link = link_dir.path().join("alias");
        std::os::unix::fs::symlink(ws.path(), &link).unwrap();
        let _held = WorkspaceLock::acquire(state.path(), ws.path()).unwrap();
        assert!(matches!(
            WorkspaceLock::acquire(state.path(), &link),
            Err(WorkspaceLockError::Held(_))
        ));
        WorkspaceLock::acquire(state.path(), other.path()).unwrap();
    }

    #[test]
    fn a_planted_symlink_in_place_of_the_lock_file_is_refused() {
        let state = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let locks = state.path().join("locks");
        std::fs::create_dir(&locks).unwrap();
        let name = lock_file_name(&ws.path().canonicalize().unwrap());
        std::os::unix::fs::symlink(target.path().join("elsewhere"), locks.join(name)).unwrap();
        let err = WorkspaceLock::acquire(state.path(), ws.path()).unwrap_err();
        assert!(matches!(err, WorkspaceLockError::Io { .. }), "{err:?}");
        assert!(
            !target.path().join("elsewhere").exists(),
            "the symlink was not followed"
        );
    }

    #[test]
    fn a_planted_symlink_in_place_of_the_locks_directory_is_refused() {
        let state = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(target.path(), state.path().join("locks")).unwrap();
        let err = WorkspaceLock::acquire(state.path(), ws.path()).unwrap_err();
        assert!(matches!(err, WorkspaceLockError::Io { .. }), "{err:?}");
        assert_eq!(std::fs::read_dir(target.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_missing_workspace_is_an_error_not_a_lock() {
        let state = tempfile::tempdir().unwrap();
        let err =
            WorkspaceLock::acquire(state.path(), Path::new("/nonexistent/leash-ws")).unwrap_err();
        assert!(matches!(err, WorkspaceLockError::Io { .. }), "{err:?}");
    }
}
