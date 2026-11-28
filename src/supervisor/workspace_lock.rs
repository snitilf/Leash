//! the workspace lock of a snapshot run or a rewind (ADR-0024 decision 13, ADR-0026).
//!
//! assumptions: the lock excludes other Leash operations on one workspace, not external
//! writers, which stay the operator's contract (ADR-0022). it is two exclusive,
//! non-blocking `flock`s, both dropped by the kernel when the holder dies, so a crashed run
//! never leaves a stale lock:
//!
//! 1. an `flock` on the workspace directory itself, through a handle opened once. the lock
//!    is keyed by the directory inode, so it is independent of the state root and of every
//!    spelling of the path, and it stops a run that names the same workspace under a
//!    different `--state-dir`. the same handle is given to capture, so the directory that
//!    is locked is the directory that is captured and no path is resolved twice.
//! 2. an `flock` on `<state_root>/locks/<sha256 of the canonical workspace path>.lock`,
//!    where the canonical path is read from the handle. the state root is opened once and
//!    every component beneath it goes through that handle with `O_NOFOLLOW`, so a planted
//!    symlink under the state root cannot redirect the lock file.
//!
//! a leftover process that still holds the directory `flock` (an inherited descriptor in a
//! stray process) blocks later runs and rewinds on that workspace. that fails closed.
//!
//! `leash run` takes both locks before any run directory exists and holds them for the
//! whole run; `leash rewind` takes both through `WorkspaceLock::acquire`.

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
    /// the workspace directory handle that carries the directory `flock`.
    workspace: File,
    /// the state-root lock file that carries the second `flock`.
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
    /// take both locks for `workspace` under `state_root`, without blocking.
    ///
    /// the workspace is opened once here, following symlinks in its spelling, and the
    /// directory lock is taken on that handle before anything is created under
    /// `state_root`. the lock file name comes from the canonical path of the handle, so
    /// every spelling of one directory maps to one lock and there is no
    /// canonicalize-then-open window. `workspace_dir` returns the same handle for capture.
    pub fn acquire(state_root: &Path, workspace: &Path) -> Result<Self, WorkspaceLockError> {
        let dir = open_dir(libc::AT_FDCWD, workspace.as_os_str(), false)
            .map_err(|source| io_error("open workspace", workspace, source))?;
        // SAFETY: flock takes a live descriptor and scalar flags.
        if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let e = io::Error::last_os_error();
            return Err(if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                WorkspaceLockError::Held(workspace.to_path_buf())
            } else {
                io_error("lock workspace", workspace, e)
            });
        }
        let canonical = canonical_path_of(&dir, workspace)
            .map_err(|source| io_error("resolve workspace", workspace, source))?;
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
            workspace: dir,
            _file: file,
            path: lock_path,
        })
    }

    /// the workspace directory handle that holds the directory lock. a duplicate of it
    /// keeps the lock for as long as the duplicate lives, so capture can hold it directly.
    pub fn workspace_dir(&self) -> &File {
        &self.workspace
    }

    /// the lock file's path under the state root.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// the canonical path of the directory a handle names. on linux it is read from the handle
/// (`/proc/self/fd`), so it is the directory that was opened, never a second resolution of
/// the spelling.
#[cfg(target_os = "linux")]
fn canonical_path_of(dir: &File, _spelling: &Path) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{}", dir.as_raw_fd()))
}

/// off linux there is no `/proc`; this build is a development host only, so the spelling is
/// canonicalized instead.
#[cfg(not(target_os = "linux"))]
fn canonical_path_of(_dir: &File, spelling: &Path) -> io::Result<PathBuf> {
    spelling.canonicalize()
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

    #[test]
    fn a_second_acquire_with_a_different_state_root_is_refused() {
        // the state-root lock file is keyed by the state root, so two roots never share one;
        // the lock on the workspace directory itself is what stops the second run
        let first_state = tempfile::tempdir().unwrap();
        let second_state = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        let first = WorkspaceLock::acquire(first_state.path(), ws.path()).unwrap();
        let err = WorkspaceLock::acquire(second_state.path(), ws.path()).unwrap_err();
        assert!(matches!(err, WorkspaceLockError::Held(_)), "{err:?}");
        assert!(
            err.to_string()
                .contains("another leash run or rewind owns this workspace")
        );
        assert!(
            !second_state.path().join("locks").exists(),
            "a refused acquire leaves nothing under the second state root"
        );
        drop(first);
        WorkspaceLock::acquire(second_state.path(), ws.path()).unwrap();
    }

    #[test]
    fn another_spelling_and_another_state_root_still_share_the_workspace_lock() {
        let first_state = tempfile::tempdir().unwrap();
        let second_state = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        let link_dir = tempfile::tempdir().unwrap();
        let link = link_dir.path().join("alias");
        std::os::unix::fs::symlink(ws.path(), &link).unwrap();
        let _held = WorkspaceLock::acquire(first_state.path(), ws.path()).unwrap();
        assert!(matches!(
            WorkspaceLock::acquire(second_state.path(), &link),
            Err(WorkspaceLockError::Held(_))
        ));
    }

    #[test]
    fn the_lock_holds_the_workspace_directory_handle_it_will_hand_to_capture() {
        use std::os::unix::fs::MetadataExt;
        let state = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        let lock = WorkspaceLock::acquire(state.path(), ws.path()).unwrap();
        let held = lock.workspace_dir().metadata().unwrap();
        let named = std::fs::metadata(ws.path()).unwrap();
        assert!(held.is_dir());
        assert_eq!((held.dev(), held.ino()), (named.dev(), named.ino()));
        // close-on-exec, so no process the supervisor execs holds the lock
        // SAFETY: F_GETFD takes a live descriptor and no argument.
        let flags = unsafe { libc::fcntl(lock.workspace_dir().as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
    }

    #[test]
    fn a_duplicate_of_the_handle_keeps_the_lock_after_the_lock_value_drops() {
        let state = tempfile::tempdir().unwrap();
        let other_state = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        let lock = WorkspaceLock::acquire(state.path(), ws.path()).unwrap();
        let dup = lock.workspace_dir().try_clone().unwrap();
        drop(lock);
        assert!(matches!(
            WorkspaceLock::acquire(other_state.path(), ws.path()),
            Err(WorkspaceLockError::Held(_))
        ));
        drop(dup);
        WorkspaceLock::acquire(other_state.path(), ws.path()).unwrap();
    }

    #[test]
    fn a_workspace_that_is_not_a_directory_is_refused() {
        let state = tempfile::tempdir().unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        let err = WorkspaceLock::acquire(state.path(), file.path()).unwrap_err();
        assert!(matches!(err, WorkspaceLockError::Io { .. }), "{err:?}");
    }
}
