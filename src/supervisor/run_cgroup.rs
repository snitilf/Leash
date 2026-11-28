//! the run cgroup lifecycle of a snapshot run (ADR-0024 decisions 2, 11, 12 and 17;
//! snapshot.md sections 2 and 6).
//!
//! a snapshot run puts the agent's whole process tree in a cgroup named `leash-<run-id>`,
//! a child of Leash's own cgroup, with no controllers enabled. the supervisor and the
//! broker stay in their own cgroup. the cgroup is created first, before the run directory and
//! the broker exist, so a setup failure leaves neither behind; it is bound to its run
//! lock through the `user.leash.lock` xattr once the run directory exists, entered atomically through
//! `clone3(CLONE_INTO_CGROUP)` (see `spawn`), and killed and removed depth-first when the
//! run ends or aborts.
//!
//! a per-run `flock` on `<run_dir>/run.lock` marks the run alive, and its `<st_dev>:<st_ino>`
//! identity is stamped on the cgroup directory's `user.leash.lock` xattr. a cgroup whose
//! lock can be taken and whose xattr matches that lock inode belongs to a dead run and is
//! cleaned up by the next run; a cgroup whose lock is held, missing, copied to another
//! inode, or whose name does not validate is never touched.
//!
//! the pure parsers (`/proc/self/cgroup`, mountinfo, run-id validation) take text, so they
//! are unit tested without a delegated cgroup.

use std::ffi::{CStr, CString};
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::recorder::{CgroupKillEvent, CgroupKillReason};
use crate::supervisor::cgroup::{self, Cgroup};

/// the prefix of every run cgroup name.
const NAME_PREFIX: &str = "leash-";
/// the prefix of the sacrificial cgroup the setup probe creates (`cgroup::probe_delegation`).
const PROBE_PREFIX: &str = "leash-probe-";
/// a probe cgroup newer than this may belong to a probe that is running right now, in
/// another Leash under the same parent, so cleanup leaves it alone. a whole probe is a few
/// bounded steps of `PROBE_TIMEOUT` each, well inside this.
const PROBE_LEFTOVER_AGE: Duration = Duration::from_secs(30);
/// the bound on each freeze, thaw and kill confirmation in the setup probe.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// the bound on waiting for `populated 0` after `cgroup.kill`.
const KILL_TIMEOUT: Duration = Duration::from_secs(5);
/// the bound on retrying `rmdir` while the kernel finishes releasing dead tasks.
const RMDIR_TIMEOUT: Duration = Duration::from_secs(2);

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// the hint every refusal names (ADR-0024 decision 2). it is unverified on a systemd host
/// until a CI leg runs it.
const DELEGATION_HINT: &str = "run Leash inside a delegated cgroup, for example `systemd-run --user --scope -p Delegate=yes leash run ...`";

/// why a run cgroup could not be set up. every variant refuses the run before spawn.
#[derive(Debug, thiserror::Error)]
pub enum RunCgroupError {
    /// the run id is not a plain generated run id, so it cannot name a cgroup.
    #[error("run id {0:?} is not a valid run id")]
    InvalidRunId(String),
    /// Leash's own cgroup could not be found or resolved to a directory.
    #[error("cannot locate Leash's own cgroup: {0}; {DELEGATION_HINT}")]
    Locate(String),
    /// the parent cgroup cannot be written, so no child can be created in it.
    #[error("the cgroup {path} is not writable: {source}; {DELEGATION_HINT}")]
    NotWritable {
        /// the parent cgroup directory
        path: PathBuf,
        /// the access error
        #[source]
        source: io::Error,
    },
    /// creating or opening the run cgroup failed.
    #[error("cannot create the run cgroup under {path}: {source}; {DELEGATION_HINT}")]
    Create {
        /// the parent cgroup directory
        path: PathBuf,
        /// the underlying error
        #[source]
        source: io::Error,
    },
    /// the new cgroup does not support freeze and kill.
    #[error("the run cgroup failed its freeze and kill probe: {source}; {DELEGATION_HINT}")]
    Probe {
        /// the underlying error
        #[source]
        source: io::Error,
    },
    /// the run lock could not be created or taken.
    #[error("cannot take the run lock {path}: {source}")]
    Lock {
        /// the lock file
        path: PathBuf,
        /// the underlying error
        #[source]
        source: io::Error,
    },
    /// a snapshot run reached its run lifecycle without a created or recorded run cgroup.
    #[error("a snapshot run needs a run cgroup path in its metadata")]
    MissingPath,
    /// the created cgroup is not the one the run metadata names.
    #[error("the run cgroup {created} differs from the recorded {recorded}")]
    PathMismatch {
        /// the path of the cgroup that was created
        created: PathBuf,
        /// the path in the run metadata
        recorded: PathBuf,
    },
}

/// whether the recorded cgroup of a run is gone, still present, or unresolvable from this
/// mount and cgroup namespace (ADR-0024 decision 17).
///
/// `leash rewind` must treat `Unknown` as not gone (refuse rather than fail open) and must
/// also acquire `<run_dir>/run.lock` before touching the workspace, because a separate
/// cgroup namespace can expose a different hierarchy at the same path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunCgroupState {
    /// the run cgroup is absent under its pinned cgroup2 parent, or its parent directory is
    /// absent under an existing cgroup2 ancestor (such as a vanished transient scope).
    Gone,
    /// the parent cgroup2 directory exists and `leash-<run-id>` is still present under it.
    Present,
    /// the nearest existing ancestor is not on a cgroup2 filesystem, or the parent directory
    /// is inaccessible or unresolvable here, so absence cannot be proven; callers must treat
    /// this as not gone.
    Unknown,
}

/// is `id` a run id as `recorder::generate_run_id` makes it, `YYYYMMDDTHHMMSSZ-xxxxxx`?
/// the strict form is what keeps an arbitrary cgroup name or a name from metadata from
/// ever being killed.
pub fn is_valid_run_id(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 23
        && b[..8].iter().all(u8::is_ascii_digit)
        && b[8] == b'T'
        && b[9..15].iter().all(u8::is_ascii_digit)
        && b[15] == b'Z'
        && b[16] == b'-'
        && b[17..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(c))
}

fn cgroup_name(run_id: &str) -> Result<(String, CString), RunCgroupError> {
    if !is_valid_run_id(run_id) {
        return Err(RunCgroupError::InvalidRunId(run_id.to_string()));
    }
    let name = format!("{NAME_PREFIX}{run_id}");
    let c = CString::new(name.clone()).map_err(|_| RunCgroupError::InvalidRunId(name.clone()))?;
    Ok((name, c))
}

/// the cgroup path of a process, from the unified `0::<path>` line of `/proc/<pid>/cgroup`.
fn parse_proc_cgroup(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .filter(|path| path.starts_with('/') && !path.contains(" (deleted)"))
}

/// decode the octal escapes (`\040`) mountinfo uses for space, tab, newline and backslash.
fn unescape_mountinfo(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4]
                .iter()
                .all(|c| (b'0'..=b'7').contains(c))
        {
            let value = (u32::from(bytes[i + 1] - b'0') << 6)
                | (u32::from(bytes[i + 2] - b'0') << 3)
                | u32::from(bytes[i + 3] - b'0');
            out.push(value as u8);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// every cgroup2 mount in mountinfo text as (root within the cgroup filesystem, mount point).
fn parse_cgroup2_mounts(mountinfo: &str) -> Vec<(String, String)> {
    mountinfo
        .lines()
        .filter_map(|line| {
            let (left, right) = line.split_once(" - ")?;
            if right.split_whitespace().next()? != "cgroup2" {
                return None;
            }
            let mut fields = left.split_whitespace();
            let root = unescape_mountinfo(fields.nth(3)?);
            let mount_point = unescape_mountinfo(fields.next()?);
            Some((root, mount_point))
        })
        .collect()
}

/// resolve a cgroup path (relative to the filesystem root) to a directory through the
/// cgroup2 mounts that expose it.
fn resolve_cgroup_dir(cgroup_path: &str, mountinfo: &str) -> Option<PathBuf> {
    if cgroup_path.split('/').any(|part| part == "..") {
        return None;
    }
    parse_cgroup2_mounts(mountinfo)
        .into_iter()
        .find_map(|(root, mount_point)| {
            let relative = if root == "/" {
                cgroup_path
            } else {
                cgroup_path
                    .strip_prefix(root.as_str())
                    .filter(|rest| rest.is_empty() || rest.starts_with('/'))?
            };
            Some(Path::new(&mount_point).join(relative.trim_start_matches('/')))
        })
}

/// a pinned handle on the cgroup that run cgroups are created under.
pub struct CgroupParent {
    dir: File,
    path: PathBuf,
}

impl CgroupParent {
    /// find Leash's own cgroup from `/proc/self/cgroup` and the cgroup2 mount from
    /// `/proc/self/mountinfo`, pin it, and require that it is writable.
    pub fn locate() -> Result<Self, RunCgroupError> {
        let locate = |what: &str, e: io::Error| RunCgroupError::Locate(format!("{what}: {e}"));
        let proc_cgroup = std::fs::read_to_string("/proc/self/cgroup")
            .map_err(|e| locate("/proc/self/cgroup", e))?;
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
            .map_err(|e| locate("/proc/self/mountinfo", e))?;
        let cgroup_path = parse_proc_cgroup(&proc_cgroup).ok_or_else(|| {
            RunCgroupError::Locate("/proc/self/cgroup has no usable cgroup v2 entry".into())
        })?;
        let path = resolve_cgroup_dir(cgroup_path, &mountinfo).ok_or_else(|| {
            RunCgroupError::Locate(format!(
                "no cgroup2 mount exposes the cgroup {cgroup_path:?}"
            ))
        })?;
        let parent = Self::open(&path).map_err(|e| locate(&path.display().to_string(), e))?;
        parent.ensure_writable()?;
        Ok(parent)
    }

    fn open(path: &Path) -> io::Result<Self> {
        Ok(Self {
            dir: cgroup::open_cgroup_dir(path)?,
            path: path.to_path_buf(),
        })
    }

    /// the parent cgroup's directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// the path the run cgroup for `run_id` will have.
    pub fn child_path(&self, run_id: &str) -> Result<PathBuf, RunCgroupError> {
        let (name, _) = cgroup_name(run_id)?;
        Ok(self.path.join(name))
    }

    /// prove on a sacrificial child cgroup that this parent supports `clone3(CLONE_INTO_CGROUP)`,
    /// lock xattrs, freeze, thaw, and kill. must run before any run directory is created
    /// (cli.md section 1).
    pub fn probe(&self) -> Result<(), RunCgroupError> {
        cgroup::probe_delegation(&self.path, PROBE_TIMEOUT)
            .map_err(|source| RunCgroupError::Probe { source })
    }

    fn ensure_writable(&self) -> Result<(), RunCgroupError> {
        // SAFETY: the descriptor and the nul-terminated "." are live for the call.
        let rc = unsafe { libc::faccessat(self.dir.as_raw_fd(), c".".as_ptr(), libc::W_OK, 0) };
        if rc != 0 {
            return Err(RunCgroupError::NotWritable {
                path: self.path.clone(),
                source: io::Error::last_os_error(),
            });
        }
        Ok(())
    }
}

/// the exclusive per-run lock on `<run_dir>/run.lock`, held for the whole run. the kernel
/// releases it when the holder dies, which is what marks a run dead.
#[derive(Debug)]
pub struct RunLock {
    _file: File,
    identity: String,
}

impl RunLock {
    /// create `<run_dir>/run.lock` close-on-exec, confirm it is a regular file, and take it
    /// exclusively.
    pub fn acquire(run_dir: &Path) -> Result<Self, RunCgroupError> {
        let path = run_dir.join("run.lock");
        let lock_error = |source| RunCgroupError::Lock {
            path: path.clone(),
            source,
        };
        // acquire opens run.lock inside the newly created run directory with O_NONBLOCK |
        // O_NOFOLLOW | O_CLOEXEC and verifies it is a regular file via fstat below; openat2
        // is not needed here because the supervisor just created run_dir.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .map_err(lock_error)?;
        let meta = file.metadata().map_err(lock_error)?;
        if !meta.file_type().is_file() {
            return Err(lock_error(io::Error::new(
                io::ErrorKind::InvalidData,
                "run.lock is not a regular file",
            )));
        }
        let identity = lock_identity_from_meta(&meta);
        match flock_nonblocking(&file) {
            Ok(true) => Ok(Self {
                _file: file,
                identity,
            }),
            Ok(false) => Err(lock_error(io::Error::from(io::ErrorKind::WouldBlock))),
            Err(e) => Err(lock_error(e)),
        }
    }

    /// take the lock of an existing run through a pinned run directory handle, for `leash
    /// rewind`. `run.lock` is opened relative to `run_dir` with `O_NOFOLLOW | O_NONBLOCK |
    /// O_CLOEXEC` and created when missing (a run that never took one holds nothing), then
    /// checked to be a regular file. returns `Ok(None)` when another process holds the lock,
    /// which means the run is alive, and `Err` for a symlink, a fifo or any other
    /// non-regular file.
    pub fn try_acquire_in(run_dir: &File) -> io::Result<Option<Self>> {
        // SAFETY: run_dir is a live directory descriptor and the name is nul-terminated;
        // openat returns a fresh descriptor or -1.
        let fd = unsafe {
            libc::openat(
                run_dir.as_raw_fd(),
                c"run.lock".as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd was returned by openat and is uniquely owned here.
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata()?;
        if !meta.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "run.lock is not a regular file",
            ));
        }
        let identity = lock_identity_from_meta(&meta);
        Ok(flock_nonblocking(&file)?.then_some(Self {
            _file: file,
            identity,
        }))
    }

    /// `<st_dev>:<st_ino>` of the locked regular file, stamped onto the run cgroup's
    /// `user.leash.lock` xattr so a copied state root cannot match a live run's cgroup.
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// take the lock of an existing run under a pinned `state_root` directory using `openat2`
    /// with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` and
    /// `O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC`. returns `Ok(None)` when the file does not exist
    /// or its lock is held, and `Err` when the path traverses a symlink or names a non-regular
    /// file (such as a planted FIFO).
    fn try_existing_in(state_root: &File, run_id: &str) -> io::Result<Option<Self>> {
        if !is_valid_run_id(run_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid run id for run.lock",
            ));
        }
        let rel = CString::new(format!("runs/{run_id}/run.lock"))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid run.lock path"))?;
        let file = match openat2_beneath(
            state_root,
            &rel,
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        ) {
            Ok(file) => file,
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let meta = file.metadata()?;
        if !meta.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "run.lock is not a regular file",
            ));
        }
        let identity = lock_identity_from_meta(&meta);
        Ok(flock_nonblocking(&file)?.then_some(Self {
            _file: file,
            identity,
        }))
    }
}

fn lock_identity_from_meta(meta: &Metadata) -> String {
    format!("{}:{}", meta.dev(), meta.ino())
}

fn openat2_beneath(dir: &File, rel: &CStr, flags: libc::c_int) -> io::Result<File> {
    let how = OpenHow {
        flags: u64::from(flags as u32),
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: dir, rel, and how are live for the syscall; openat2 returns a fresh fd or -1.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            rel.as_ptr(),
            &raw const how,
            size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was returned by openat2 and is uniquely owned here.
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

/// `flock(LOCK_EX | LOCK_NB)`: true when taken, false when another holder has it.
fn flock_nonblocking(file: &File) -> io::Result<bool> {
    // SAFETY: the descriptor is open for the call; flock reads no memory.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(false)
    } else {
        Err(e)
    }
}

/// the run cgroup: pinned, owned, and killed and removed on drop unless already removed.
pub struct RunCgroup {
    group: Cgroup,
    parent: File,
    name: CString,
    name_text: String,
    path: PathBuf,
    removed: bool,
}

impl std::fmt::Debug for RunCgroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunCgroup")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl RunCgroup {
    /// create `leash-<run_id>` under `parent` with no controllers, pin it, and confirm
    /// freeze and thaw on it. the cgroup is removed again when that fails.
    ///
    /// `cgroup.kill` is never written to the run cgroup before spawn: on Linux 6.8 a
    /// `clone3(CLONE_INTO_CGROUP)` child is SIGKILLed at birth whenever the caller's cgroup
    /// kill count differs from the target's (measurement 0003 section 8). callers prove kill
    /// and delegation up front via `CgroupParent::probe` on a sacrificial cgroup.
    pub fn create(parent: &CgroupParent, run_id: &str) -> Result<Self, RunCgroupError> {
        let (name_text, name) = cgroup_name(run_id)?;
        let create_error = |source| RunCgroupError::Create {
            path: parent.path.clone(),
            source,
        };
        cgroup::mkdir_child(&parent.dir, &name).map_err(create_error)?;
        let opened = Cgroup::open_child(&parent.dir, &name)
            .and_then(|group| Ok((group, parent.dir.try_clone()?)));
        let (group, parent_dir) = match opened {
            Ok(opened) => opened,
            Err(e) => {
                let _ = cgroup::rmdir_child(&parent.dir, &name);
                return Err(create_error(e));
            }
        };
        let mut run = Self {
            group,
            parent: parent_dir,
            path: parent.path.join(&name_text),
            name,
            name_text,
            removed: false,
        };
        // an empty cgroup confirms frozen=1 and thaws without incrementing the kill count;
        // entry of a real process was proved on a sacrificial cgroup by CgroupParent::probe.
        let probe = run
            .group
            .set_frozen(true, PROBE_TIMEOUT)
            .and_then(|()| run.group.set_frozen(false, PROBE_TIMEOUT));
        if let Err(source) = probe {
            let _ = run.remove();
            return Err(RunCgroupError::Probe { source });
        }
        Ok(run)
    }

    /// stamp `lock.identity()` onto the run cgroup's `user.leash.lock` xattr so stale cleanup
    /// only ever kills a cgroup whose live lock matches this inode.
    pub fn bind_lock(&self, lock: &RunLock) -> Result<(), RunCgroupError> {
        self.group
            .set_lock_identity(lock.identity())
            .map_err(|source| RunCgroupError::Create {
                path: self.path.clone(),
                source,
            })
    }

    /// the cgroup's directory path, recorded in the run metadata.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// the cgroup's name, `leash-<run-id>`.
    pub fn name(&self) -> &str {
        &self.name_text
    }

    /// the pinned directory descriptor `clone3` enters the child through.
    pub fn dir_fd(&self) -> RawFd {
        self.group.dir_fd()
    }

    /// the underlying pinned cgroup, for freezer control by the capture barrier.
    pub fn cgroup(&self) -> &Cgroup {
        &self.group
    }

    /// kill every process in the cgroup and wait boundedly for `populated 0`. the event
    /// records how many were listed just before the kill.
    pub fn kill_all(&self, reason: CgroupKillReason) -> CgroupKillEvent {
        let processes = self
            .group
            .members()
            .ok()
            .map(|pids| u32::try_from(pids.len()).unwrap_or(u32::MAX));
        let error = self.group.kill(KILL_TIMEOUT).err().map(|e| e.to_string());
        CgroupKillEvent {
            reason,
            cgroup: self.name_text.clone(),
            processes,
            error,
            removal_error: None,
        }
    }

    /// remove every descendant cgroup depth-first through the pinned descriptor, then remove
    /// the run cgroup itself. the tree must already be empty; a vanished directory is success.
    pub fn remove(&mut self) -> io::Result<()> {
        let result = cgroup::remove_descendants(self.group.dir(), RMDIR_TIMEOUT)
            .and_then(|()| cgroup::rmdir_child_retrying(&self.parent, &self.name, RMDIR_TIMEOUT));
        if result.is_ok() {
            self.removed = true;
        }
        result
    }
}

impl Drop for RunCgroup {
    fn drop(&mut self) {
        if !self.removed {
            let _ = self.kill_all(CgroupKillReason::Abort);
            let _ = self.remove();
        }
    }
}

/// kill and remove the run cgroups of dead runs that sit under `parent`.
///
/// entry names are collected from the pinned `parent` directory first so a per-entry error
/// never aborts cleanup or drops events for kills already performed. a child named
/// `leash-<valid run id>` is stale only when `<state_root>/runs/<id>/run.lock` resolves
/// beneath `state_root` with `openat2` (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
/// RESOLVE_NO_MAGICLINKS`), is a regular file, its `flock` can be taken, and its
/// `<st_dev>:<st_ino>` matches the cgroup's `user.leash.lock` xattr. a held lock, a missing
/// lock file, a mismatched or absent xattr, an invalid name, and `skip` (the caller's own
/// run) are never touched. returns one event per cleaned or errored cgroup for the trace.
///
/// it also removes the empty `leash-probe-*` cgroups a crashed probe leaves behind
/// (`remove_leftover_probe`); that is housekeeping and records nothing unless it fails.
pub fn cleanup_stale(
    parent: &CgroupParent,
    state_root: &Path,
    skip: Option<&str>,
) -> io::Result<Vec<CgroupKillEvent>> {
    let state_dir = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(state_root)
    {
        Ok(dir) => dir,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let mut names = cgroup::child_dirs(&parent.dir)?;
    names.sort();

    let mut events = Vec::new();
    for cname in names {
        let Ok(name) = cname.to_str().map(str::to_string) else {
            continue;
        };
        let Some(id) = name.strip_prefix(NAME_PREFIX) else {
            continue;
        };
        if name.starts_with(PROBE_PREFIX) {
            events.extend(remove_leftover_probe(&parent.dir, &cname, name));
            continue;
        }
        if !is_valid_run_id(id) || skip == Some(id) {
            continue;
        }
        let lock = match RunLock::try_existing_in(&state_dir, id) {
            Ok(Some(lock)) => lock,
            Ok(None) => continue,
            Err(e) => {
                events.push(CgroupKillEvent {
                    reason: CgroupKillReason::StaleCleanup,
                    cgroup: name,
                    processes: None,
                    error: Some(e.to_string()),
                    removal_error: None,
                });
                continue;
            }
        };
        let group = match Cgroup::open_child(&parent.dir, &cname) {
            Ok(group) => group,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => {
                events.push(CgroupKillEvent {
                    reason: CgroupKillReason::StaleCleanup,
                    cgroup: name,
                    processes: None,
                    error: Some(e.to_string()),
                    removal_error: None,
                });
                continue;
            }
        };
        match group.lock_identity() {
            Ok(Some(bound)) if bound == lock.identity() => {}
            Ok(_) => continue,
            Err(e) => {
                events.push(CgroupKillEvent {
                    reason: CgroupKillReason::StaleCleanup,
                    cgroup: name,
                    processes: None,
                    error: Some(e.to_string()),
                    removal_error: None,
                });
                continue;
            }
        }
        let processes = group
            .members()
            .ok()
            .map(|pids| u32::try_from(pids.len()).unwrap_or(u32::MAX));
        let mut event = CgroupKillEvent {
            reason: CgroupKillReason::StaleCleanup,
            cgroup: name,
            processes,
            error: None,
            removal_error: None,
        };
        match group.kill(KILL_TIMEOUT) {
            Ok(()) => {
                let rm = cgroup::remove_descendants(group.dir(), RMDIR_TIMEOUT).and_then(|()| {
                    drop(group);
                    cgroup::rmdir_child_retrying(&parent.dir, &cname, RMDIR_TIMEOUT)
                });
                if let Err(e) = rm {
                    event.removal_error = Some(e.to_string());
                }
            }
            Err(e) => {
                event.error = Some(e.to_string());
            }
        }
        drop(lock);
        events.push(event);
    }
    Ok(events)
}

/// remove the leftover probe cgroup `cname` of a crashed probe, and only that: it must hold
/// no process (`populated 0`) and be older than `PROBE_LEFTOVER_AGE`, and nothing is ever
/// killed. a populated, young, nested or unremovable one is left alone silently, because the
/// next run tries again; only an unexpected error is reported.
fn remove_leftover_probe(parent: &File, cname: &CStr, name: String) -> Option<CgroupKillEvent> {
    let error_event = |e: io::Error| CgroupKillEvent {
        reason: CgroupKillReason::StaleCleanup,
        cgroup: name.clone(),
        processes: None,
        error: None,
        removal_error: Some(e.to_string()),
    };
    let group = match Cgroup::open_child(parent, cname) {
        Ok(group) => group,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => return Some(error_event(e)),
    };
    let age = group
        .dir()
        .metadata()
        .and_then(|meta| meta.modified())
        .map(|modified| modified.elapsed().unwrap_or(Duration::ZERO));
    match age {
        Ok(age) if age >= PROBE_LEFTOVER_AGE => {}
        Ok(_) => return None,
        Err(e) => return Some(error_event(e)),
    }
    match (group.is_populated(), group.members()) {
        (Ok(false), Ok(pids)) if pids.is_empty() => {}
        (Ok(_), Ok(_)) => return None,
        (Err(e), _) | (_, Err(e)) => return Some(error_event(e)),
    }
    drop(group);
    match cgroup::rmdir_child(parent, cname) {
        Ok(()) => None,
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::ENOENT | libc::EBUSY | libc::ENOTEMPTY)
            ) =>
        {
            None
        }
        Err(e) => Some(error_event(e)),
    }
}

/// check whether the run cgroup recorded for `run_id` is gone, still present, or
/// unresolvable from this mount and cgroup namespace (ADR-0024 decision 17).
///
/// `recorded` is `run_cgroup` from the run metadata; it must be an absolute path without
/// `..` components ending in `leash-<run_id>`, or this returns `Err(InvalidInput)` rather
/// than trust a forged path. when opening the parent directory returns `ENOENT` (for example
/// after a transient `systemd-run --scope` unit tears down), this walks up to the nearest
/// existing ancestor and returns `Ok(RunCgroupState::Gone)` if that ancestor is on a cgroup2
/// filesystem; a non-cgroup2 ancestor, `EACCES`, or any other unresolvable path returns
/// `Ok(RunCgroupState::Unknown)` instead of failing open as `Gone`.
///
/// `leash rewind` must treat `RunCgroupState::Unknown` as not gone and must also take
/// `<run_dir>/run.lock` before modifying the workspace.
pub fn run_cgroup_gone(recorded: &Path, run_id: &str) -> io::Result<RunCgroupState> {
    let (name, cname) = cgroup_name(run_id).map_err(io::Error::other)?;
    if !recorded.is_absolute()
        || recorded
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        || recorded.file_name().and_then(|n| n.to_str()) != Some(name.as_str())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "recorded run cgroup does not match the run id",
        ));
    }
    let Some(parent_path) = recorded.parent() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "recorded run cgroup has no parent directory",
        ));
    };
    let parent_dir = match cgroup::open_cgroup_dir(parent_path) {
        Ok(dir) => dir,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
            let mut ancestor = parent_path.parent();
            while let Some(dir) = ancestor {
                match cgroup::open_cgroup_dir(dir) {
                    Ok(_) => return Ok(RunCgroupState::Gone),
                    Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {
                        ancestor = dir.parent();
                    }
                    Err(_) => return Ok(RunCgroupState::Unknown),
                }
            }
            return Ok(RunCgroupState::Unknown);
        }
        Err(_) => return Ok(RunCgroupState::Unknown),
    };
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent_dir, cname, and stat are live for the call.
    let rc = unsafe {
        libc::fstatat(
            parent_dir.as_raw_fd(),
            cname.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        return Ok(RunCgroupState::Present);
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::ENOENT) {
        Ok(RunCgroupState::Gone)
    } else {
        Ok(RunCgroupState::Unknown)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const MOUNTINFO: &str = "\
24 30 0:21 / /sys rw,nosuid shared:7 - sysfs sysfs rw
31 24 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw
40 31 0:26 /leash\\040dir /mnt/with\\040space rw - cgroup2 cgroup2 rw
";

    #[test]
    fn run_ids_validate_strictly() {
        assert!(is_valid_run_id("20260708T183005Z-7k3m4q"));
        for bad in [
            "",
            "probe-0123456789abcdef",
            "20260708T183005Z-7k3m4Q",
            "20260708T183005Z-7k3m41",
            "20260708T183005Z-7k3m4",
            "20260708T183005Z-7k3m4qq",
            "../../etc/passwd/20260708T183005Z",
            "20260708T183005Z-7k3m4q/",
        ] {
            assert!(!is_valid_run_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn proc_cgroup_takes_the_unified_entry() {
        assert_eq!(
            parse_proc_cgroup("12:cpu:/x\n0::/user.slice/a.scope\n"),
            Some("/user.slice/a.scope")
        );
        assert_eq!(parse_proc_cgroup("0::/\n"), Some("/"));
        assert_eq!(parse_proc_cgroup("12:cpu:/x\n"), None);
        assert_eq!(parse_proc_cgroup("0::/gone (deleted)\n"), None);
    }

    #[test]
    fn mount_points_resolve_and_unescape() {
        assert_eq!(
            resolve_cgroup_dir("/user.slice/a.scope", MOUNTINFO),
            Some(PathBuf::from("/sys/fs/cgroup/user.slice/a.scope"))
        );
        assert_eq!(
            resolve_cgroup_dir("/", MOUNTINFO),
            Some(PathBuf::from("/sys/fs/cgroup"))
        );
    }

    #[test]
    fn a_sub_rooted_mount_only_serves_cgroups_beneath_its_root() {
        let info = "40 31 0:26 /ns /mnt/cg rw - cgroup2 cgroup2 rw\n";
        assert_eq!(
            resolve_cgroup_dir("/ns/a", info),
            Some(PathBuf::from("/mnt/cg/a"))
        );
        assert_eq!(
            resolve_cgroup_dir("/ns", info),
            Some(PathBuf::from("/mnt/cg"))
        );
        assert_eq!(resolve_cgroup_dir("/nsx/a", info), None);
        assert_eq!(resolve_cgroup_dir("/other", info), None);
    }

    #[test]
    fn a_cgroup_path_with_dotdot_never_resolves() {
        assert_eq!(resolve_cgroup_dir("/../../user.slice", MOUNTINFO), None);
    }

    #[test]
    fn no_cgroup2_mount_resolves_nothing() {
        assert_eq!(
            resolve_cgroup_dir("/", "24 30 0:21 / /sys rw - sysfs sysfs rw\n"),
            None
        );
    }

    #[test]
    fn the_run_cgroup_gone_check_refuses_mismatched_paths_and_marks_unresolvable_unknown() {
        let id = "20260708T183005Z-7k3m4q";
        assert_eq!(
            run_cgroup_gone(Path::new("/nonexistent/leash-20260708T183005Z-7k3m4q"), id).unwrap(),
            RunCgroupState::Unknown
        );
        assert!(run_cgroup_gone(Path::new("/nonexistent/leash-other"), id).is_err());
        assert!(run_cgroup_gone(Path::new("relative/leash-20260708T183005Z-7k3m4q"), id).is_err());
        assert!(
            run_cgroup_gone(
                Path::new("/sys/fs/cgroup/../tmp/leash-20260708T183005Z-7k3m4q"),
                id
            )
            .is_err()
        );
        assert!(run_cgroup_gone(Path::new("/nonexistent/x"), "not-an-id").is_err());
        // a directory on a regular filesystem is not a cgroup2 mount, so it stays Unknown,
        // including when its parent directory is missing under /tmp
        let dir = tempfile::tempdir().unwrap();
        let present = dir.path().join(format!("leash-{id}"));
        std::fs::create_dir(&present).unwrap();
        assert_eq!(
            run_cgroup_gone(&present, id).unwrap(),
            RunCgroupState::Unknown
        );
        let missing_parent = dir.path().join("missing-scope").join(format!("leash-{id}"));
        assert_eq!(
            run_cgroup_gone(&missing_parent, id).unwrap(),
            RunCgroupState::Unknown
        );
    }

    #[test]
    fn the_run_lock_is_exclusive_and_rejects_fifo_and_symlinked_run_dir() {
        let state = tempfile::tempdir().unwrap();
        let id = "20260708T183005Z-7k3m4q";
        let run_dir = state.path().join("runs").join(id);
        std::fs::create_dir_all(&run_dir).unwrap();
        let state_dir = File::open(state.path()).unwrap();

        let first = RunLock::acquire(&run_dir).unwrap();
        assert!(RunLock::acquire(&run_dir).is_err());
        assert!(RunLock::try_existing_in(&state_dir, id).unwrap().is_none());
        let first_id = first.identity().to_string();
        drop(first);

        let second = RunLock::try_existing_in(&state_dir, id).unwrap().unwrap();
        assert_eq!(second.identity(), first_id);
        drop(second);

        assert!(
            RunLock::try_existing_in(&state_dir, "20260708T183005Z-aaaaaa")
                .unwrap()
                .is_none()
        );

        // a planted FIFO must not block and must be rejected as non-regular
        let fifo_id = "20260708T183005Z-bbbbbb";
        let fifo_dir = state.path().join("runs").join(fifo_id);
        std::fs::create_dir_all(&fifo_dir).unwrap();
        let fifo_path = CString::new(fifo_dir.join("run.lock").to_str().unwrap()).unwrap();
        // SAFETY: fifo_path is a live nul-terminated path in our tempdir.
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        let err = RunLock::try_existing_in(&state_dir, fifo_id).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // a symlinked runs/<id> must be rejected by openat2 RESOLVE_NO_SYMLINKS
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("run.lock"), "").unwrap();
        let link_id = "20260708T183005Z-cccccc";
        std::os::unix::fs::symlink(outside.path(), state.path().join("runs").join(link_id))
            .unwrap();
        let err = RunLock::try_existing_in(&state_dir, link_id).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
    }
}
