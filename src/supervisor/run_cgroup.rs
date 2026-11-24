//! the run cgroup lifecycle of a snapshot run (ADR-0024 decisions 2, 11, 12 and 17;
//! snapshot.md sections 2 and 6).
//!
//! a snapshot run puts the agent's whole process tree in a cgroup named `leash-<run-id>`,
//! a child of Leash's own cgroup, with no controllers enabled. the supervisor and the
//! broker stay in their own cgroup. the cgroup is created before spawn, the child enters it
//! atomically through `clone3(CLONE_INTO_CGROUP)` (see `spawn`), and it is killed and
//! removed when the run ends or aborts.
//!
//! a per-run `flock` on `<run_dir>/run.lock` marks the run alive. a cgroup whose lock can
//! be taken belongs to a dead run and is cleaned up by the next run; a cgroup whose lock is
//! held, or whose name does not validate, is never touched.
//!
//! the pure parsers (`/proc/self/cgroup`, mountinfo, run-id validation) take text, so they
//! are unit tested without a delegated cgroup.

use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::recorder::{CgroupKillEvent, CgroupKillReason};
use crate::supervisor::cgroup::{self, Cgroup};

/// the prefix of every run cgroup name.
const NAME_PREFIX: &str = "leash-";
/// the bound on each freeze, thaw and kill confirmation in the setup probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// the bound on waiting for `populated 0` after `cgroup.kill`.
const KILL_TIMEOUT: Duration = Duration::from_secs(5);
/// the bound on retrying `rmdir` while the kernel finishes releasing dead tasks.
const RMDIR_TIMEOUT: Duration = Duration::from_secs(2);

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
    /// a snapshot run reached spawn without a recorded run cgroup.
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

    /// pin the cgroup directory at `path`, which must be on a cgroup2 filesystem, and
    /// require that it is writable: creating, killing and removing children all need it.
    pub fn open_writable(path: &Path) -> Result<Self, RunCgroupError> {
        let parent = Self::open(path).map_err(|source| RunCgroupError::Create {
            path: path.to_path_buf(),
            source,
        })?;
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
}

impl RunLock {
    /// create `<run_dir>/run.lock` close-on-exec and take it exclusively.
    pub fn acquire(run_dir: &Path) -> Result<Self, RunCgroupError> {
        let path = run_dir.join("run.lock");
        let lock_error = |source| RunCgroupError::Lock {
            path: path.clone(),
            source,
        };
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(lock_error)?;
        match flock_nonblocking(&file) {
            Ok(true) => Ok(Self { _file: file }),
            Ok(false) => Err(lock_error(io::Error::from(io::ErrorKind::WouldBlock))),
            Err(e) => Err(lock_error(e)),
        }
    }

    /// take the lock of an existing run, or `None` when it is held or does not exist.
    fn try_existing(path: &Path) -> io::Result<Option<Self>> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        Ok(flock_nonblocking(&file)?.then_some(Self { _file: file }))
    }
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
    /// create `leash-<run_id>` under `parent` with no controllers, pin it, and probe that
    /// freeze, thaw and kill work on it. the cgroup is removed again when the probe fails.
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
        // an empty cgroup confirms frozen=1, thaws, and accepts cgroup.kill; the entry of
        // a real process is exercised by the clone3 spawn itself.
        let probe = run
            .group
            .set_frozen(true, PROBE_TIMEOUT)
            .and_then(|()| run.group.set_frozen(false, PROBE_TIMEOUT))
            .and_then(|()| run.group.kill(PROBE_TIMEOUT));
        if let Err(source) = probe {
            let _ = run.remove();
            return Err(RunCgroupError::Probe { source });
        }
        Ok(run)
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
    pub fn dir_fd(&self) -> std::os::fd::RawFd {
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
        }
    }

    /// remove the cgroup directory. it must be empty; a vanished directory is success.
    pub fn remove(&mut self) -> io::Result<()> {
        let result = remove_with_retry(&self.parent, &self.name);
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

/// `rmdir` can report EBUSY for a moment after `populated 0` while the kernel releases
/// the last dead tasks, so retry within a bound.
fn remove_with_retry(parent: &File, name: &CStr) -> io::Result<()> {
    let start = Instant::now();
    loop {
        match cgroup::rmdir_child(parent, name) {
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) && start.elapsed() < RMDIR_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(5));
            }
            other => return other,
        }
    }
}

/// kill and remove the run cgroups of dead runs that sit under `parent`. a child named
/// `leash-<valid run id>` is stale only when `<state_root>/runs/<id>/run.lock` exists and
/// its lock can be taken; the lock is held while the cgroup is killed. a held lock, a
/// missing lock file, an invalid name, and `skip` (the caller's own run) are never touched.
/// returns one event per cleaned (or failed) cgroup for the new run's trace.
pub fn cleanup_stale(
    parent: &CgroupParent,
    state_root: &Path,
    skip: Option<&str>,
) -> io::Result<Vec<CgroupKillEvent>> {
    let mut events = Vec::new();
    for entry in std::fs::read_dir(&parent.path)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Some(id) = name.strip_prefix(NAME_PREFIX) else {
            continue;
        };
        if !is_valid_run_id(id) || skip == Some(id) {
            continue;
        }
        let lock_path = state_root.join("runs").join(id).join("run.lock");
        let Ok(Some(_lock)) = RunLock::try_existing(&lock_path) else {
            continue;
        };
        let Ok(cname) = CString::new(name.clone()) else {
            continue;
        };
        let event = match Cgroup::open_child(&parent.dir, &cname) {
            Ok(group) => {
                let processes = group
                    .members()
                    .ok()
                    .map(|pids| u32::try_from(pids.len()).unwrap_or(u32::MAX));
                let error = group
                    .kill(KILL_TIMEOUT)
                    .and_then(|()| {
                        drop(group);
                        remove_with_retry(&parent.dir, &cname)
                    })
                    .err()
                    .map(|e| e.to_string());
                CgroupKillEvent {
                    reason: CgroupKillReason::StaleCleanup,
                    cgroup: name,
                    processes,
                    error,
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => CgroupKillEvent {
                reason: CgroupKillReason::StaleCleanup,
                cgroup: name,
                processes: None,
                error: Some(e.to_string()),
            },
        };
        events.push(event);
    }
    Ok(events)
}

/// is the run cgroup recorded for `run_id` gone? this is the check `leash rewind` makes
/// (ADR-0024 decision 17). `recorded` is `run_cgroup` from the run metadata; it must be the
/// path of `leash-<run_id>`, or the check refuses rather than trust a forged path. a
/// missing cgroup, or a missing parent, is gone.
pub fn run_cgroup_gone(recorded: &Path, run_id: &str) -> io::Result<bool> {
    let (name, _) = cgroup_name(run_id).map_err(io::Error::other)?;
    if recorded.file_name().and_then(|n| n.to_str()) != Some(name.as_str()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "recorded run cgroup does not match the run id",
        ));
    }
    match std::fs::symlink_metadata(recorded) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e),
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
    fn the_run_cgroup_gone_check_refuses_a_mismatched_path() {
        let id = "20260708T183005Z-7k3m4q";
        assert!(
            run_cgroup_gone(Path::new("/nonexistent/leash-20260708T183005Z-7k3m4q"), id).unwrap()
        );
        assert!(run_cgroup_gone(Path::new("/nonexistent/leash-other"), id).is_err());
        assert!(run_cgroup_gone(Path::new("/nonexistent/x"), "not-an-id").is_err());
        let dir = tempfile::tempdir().unwrap();
        let present = dir.path().join(format!("leash-{id}"));
        std::fs::create_dir(&present).unwrap();
        assert!(!run_cgroup_gone(&present, id).unwrap());
    }

    #[test]
    fn the_run_lock_is_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let first = RunLock::acquire(dir.path()).unwrap();
        assert!(RunLock::acquire(dir.path()).is_err());
        assert!(
            RunLock::try_existing(&dir.path().join("run.lock"))
                .unwrap()
                .is_none()
        );
        drop(first);
        assert!(
            RunLock::try_existing(&dir.path().join("run.lock"))
                .unwrap()
                .is_some()
        );
        assert!(
            RunLock::try_existing(&dir.path().join("absent.lock"))
                .unwrap()
                .is_none()
        );
    }
}
