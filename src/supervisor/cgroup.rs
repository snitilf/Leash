//! cgroup v2 freezer primitives for exact snapshot barriers (ADR-0022).

use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

/// the xattr that binds a run cgroup to its run lock (`<st_dev>:<st_ino>` of `run.lock`).
const LOCK_XATTR: &CStr = c"user.leash.lock";

/// the deepest cgroup tree `remove_descendants` walks; a deeper one is refused.
const MAX_REMOVE_DEPTH: usize = 128;

/// a cgroup pinned by an open directory descriptor.
/// callers must prevent the child from modifying the cgroup or its controls.
pub struct Cgroup {
    dir: File,
}

impl Cgroup {
    /// open a previously created delegated cgroup without following the final symlink.
    pub fn open(path: &Path) -> io::Result<Self> {
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        Self::from_dir(dir)
    }

    /// open the child `name` of a pinned parent directory, never following a symlink.
    pub fn open_child(parent: &File, name: &CStr) -> io::Result<Self> {
        // SAFETY: parent and name are live; openat returns a new owned descriptor.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd was returned by openat and is uniquely owned here.
        Self::from_dir(unsafe { File::from_raw_fd(fd) })
    }

    /// the pinned directory descriptor, for `clone3(CLONE_INTO_CGROUP)`.
    pub fn dir_fd(&self) -> RawFd {
        self.dir.as_raw_fd()
    }

    /// the pinned directory itself, for removing the cgroup tree beneath it.
    pub fn dir(&self) -> &File {
        &self.dir
    }

    /// the pids currently listed in `cgroup.procs`.
    pub fn members(&self) -> io::Result<Vec<u32>> {
        self.read_control(c"cgroup.procs")?
            .lines()
            .map(|line| {
                line.trim()
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid cgroup pid"))
            })
            .collect()
    }

    /// wait until the kernel reports `populated 0`.
    pub fn wait_unpopulated(&self, timeout: Duration) -> io::Result<()> {
        self.wait_event("populated", false, timeout)
    }

    fn from_dir(dir: File) -> io::Result<Self> {
        ensure_cgroup2(&dir)?;
        let group = Self { dir };
        for name in [
            c"cgroup.procs",
            c"cgroup.freeze",
            c"cgroup.events",
            c"cgroup.kill",
        ] {
            if !group
                .control(name, libc::O_PATH)?
                .metadata()?
                .file_type()
                .is_file()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid cgroup control",
                ));
            }
        }
        Ok(group)
    }

    fn control(&self, name: &CStr, flags: libc::c_int) -> io::Result<File> {
        // SAFETY: the directory descriptor and nul-terminated control name remain live;
        // openat returns a new owned descriptor on success.
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd was returned by openat and has not been wrapped elsewhere.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn read_control(&self, name: &CStr) -> io::Result<String> {
        let mut value = String::new();
        self.control(name, libc::O_RDONLY)?
            .read_to_string(&mut value)?;
        Ok(value)
    }

    fn write_control(&self, name: &CStr, value: &str) -> io::Result<()> {
        self.control(name, libc::O_WRONLY)?
            .write_all(value.as_bytes())
    }

    /// attach a process before it can execute untrusted code.
    pub fn attach(&self, pid: u32) -> io::Result<()> {
        if pid == 0 || pid == std::process::id() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pid must be nonzero and must not be the supervisor",
            ));
        }
        self.write_control(c"cgroup.procs", &pid.to_string())
    }

    /// request freeze or thaw and wait for the kernel to confirm it.
    pub fn set_frozen(&self, frozen: bool, timeout: Duration) -> io::Result<()> {
        self.write_control(c"cgroup.freeze", if frozen { "1" } else { "0" })?;
        self.wait_event("frozen", frozen, timeout)
    }

    /// terminate the entire cgroup and wait until it has no living processes. `cgroup.kill`
    /// is written again on every poll iteration, not once: a task forked while an earlier
    /// write was walking the cgroup can survive a single write.
    pub fn kill(&self, timeout: Duration) -> io::Result<()> {
        let start = Instant::now();
        loop {
            self.write_control(c"cgroup.kill", "1")?;
            let events = self.read_control(c"cgroup.events")?;
            if !event_value(&events, "populated")? {
                return Ok(());
            }
            if start.elapsed() >= timeout {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "cgroup populated did not reach 0",
                ));
            }
            std::thread::sleep(
                Duration::from_millis(5).min(timeout.saturating_sub(start.elapsed())),
            );
        }
    }

    /// the `user.leash.lock` extended attribute of the cgroup directory, if set.
    pub fn lock_identity(&self) -> io::Result<Option<String>> {
        let mut buf = [0u8; 128];
        // SAFETY: the descriptor, the nul-terminated name and the buffer are live for the
        // call; fgetxattr writes at most buf.len() bytes.
        let n = unsafe {
            libc::fgetxattr(
                self.dir.as_raw_fd(),
                LOCK_XATTR.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            return if e.raw_os_error() == Some(libc::ENODATA) {
                Ok(None)
            } else {
                Err(e)
            };
        }
        let n = usize::try_from(n).map_err(io::Error::other)?;
        Ok(Some(String::from_utf8_lossy(&buf[..n]).into_owned()))
    }

    /// record the identity of the run lock on the cgroup directory itself, so a cgroup can
    /// only ever be matched to the one lock file that was held when it was created.
    pub fn set_lock_identity(&self, identity: &str) -> io::Result<()> {
        // SAFETY: the descriptor, the nul-terminated name and the value are live for the
        // call; fsetxattr reads exactly identity.len() bytes.
        let rc = unsafe {
            libc::fsetxattr(
                self.dir.as_raw_fd(),
                LOCK_XATTR.as_ptr(),
                identity.as_ptr().cast(),
                identity.len(),
                0,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn wait_event(&self, key: &str, expected: bool, timeout: Duration) -> io::Result<()> {
        let start = Instant::now();
        loop {
            let events = self.read_control(c"cgroup.events")?;
            if event_value(&events, key)? == expected {
                return Ok(());
            }
            if start.elapsed() >= timeout {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("cgroup {key} did not reach {}", u8::from(expected)),
                ));
            }
            std::thread::sleep(
                Duration::from_millis(5).min(timeout.saturating_sub(start.elapsed())),
            );
        }
    }
}

/// open a directory as a pinned cgroup v2 handle, never following a final symlink.
pub fn open_cgroup_dir(path: &Path) -> io::Result<File> {
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    ensure_cgroup2(&dir)?;
    Ok(dir)
}

/// create the cgroup directory `name` under a pinned parent.
pub fn mkdir_child(parent: &File, name: &CStr) -> io::Result<()> {
    // SAFETY: parent and name are live; mkdirat creates one child directory.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// remove the (empty) cgroup directory `name` under a pinned parent.
pub fn rmdir_child(parent: &File, name: &CStr) -> io::Result<()> {
    // SAFETY: parent and name are live; unlinkat with AT_REMOVEDIR removes one directory.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// remove the child cgroup `name`, retrying `EBUSY` for `retry`; a vanished child is success.
pub fn rmdir_child_retrying(parent: &File, name: &CStr, retry: Duration) -> io::Result<()> {
    let start = Instant::now();
    loop {
        match rmdir_child(parent, name) {
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) && start.elapsed() < retry => {
                std::thread::sleep(Duration::from_millis(5));
            }
            other => return other,
        }
    }
}

/// remove every cgroup beneath the pinned directory `dir`, deepest first, each through the
/// handle of its parent (`openat` with `O_NOFOLLOW`, `ensure_cgroup2`, `unlinkat` with
/// `AT_REMOVEDIR`), never through a path. the tree must already be empty of processes;
/// `EBUSY` is retried for `retry`, because the kernel releases the last dead tasks a moment
/// after `populated 0`.
pub fn remove_descendants(dir: &File, retry: Duration) -> io::Result<()> {
    remove_descendants_at(dir, retry, 0)
}

fn remove_descendants_at(dir: &File, retry: Duration, depth: usize) -> io::Result<()> {
    if depth > MAX_REMOVE_DEPTH {
        return Err(io::Error::other("cgroup tree is too deep to remove"));
    }
    for name in child_dirs(dir)? {
        // SAFETY: dir and name are live; openat returns a new owned descriptor.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let e = io::Error::last_os_error();
            if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) {
                continue;
            }
            return Err(e);
        }
        // SAFETY: fd was returned by openat and is uniquely owned here.
        let child = unsafe { File::from_raw_fd(fd) };
        ensure_cgroup2(&child)?;
        remove_descendants_at(&child, retry, depth + 1)?;
        drop(child);
        rmdir_child_retrying(dir, &name, retry)?;
    }
    Ok(())
}

/// the names of the subdirectories of `dir`, read through a fresh descriptor so the
/// caller's own directory offset is untouched.
pub fn child_dirs(dir: &File) -> io::Result<Vec<CString>> {
    // SAFETY: dir and "." are live; openat returns a new owned descriptor.
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
    // SAFETY: fd is a directory descriptor we own; fdopendir takes ownership on success.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let e = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so fd is still ours to close.
        unsafe { libc::close(fd) };
        return Err(e);
    }
    let mut names = Vec::new();
    let result = loop {
        // SAFETY: __errno_location returns this thread's errno slot; zeroing it is how
        // readdir end-of-stream is told apart from an error.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: stream is a live DIR owned by this function.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let e = io::Error::last_os_error();
            break if e.raw_os_error() == Some(0) {
                Ok(())
            } else {
                Err(e)
            };
        }
        // SAFETY: readdir returned a live dirent whose d_name is nul-terminated.
        let (kind, name) = unsafe { ((*entry).d_type, CStr::from_ptr((*entry).d_name.as_ptr())) };
        if (kind == libc::DT_DIR || kind == libc::DT_UNKNOWN) && name != c"." && name != c".." {
            names.push(name.to_owned());
        }
    };
    // SAFETY: stream is live and closed exactly once; this also closes fd.
    unsafe { libc::closedir(stream) };
    result.map(|()| names)
}

/// exercise delegation, `clone3(CLONE_INTO_CGROUP)` survival, lock xattr round-trip,
/// freezer confirmation, thaw, and whole-group termination using a trusted probe process.
/// the supervisor never enters the probe cgroup.
///
/// the probe child enters its sacrificial cgroup through the same `clone3(CLONE_INTO_CGROUP)`
/// path `spawn` uses, before the cgroup is ever killed, and writes a ready byte before
/// execing `/bin/sleep`. on Linux 6.8 a child created that way is SIGKILLed at birth whenever
/// the caller's cgroup kill count differs from the target's (measurement 0003 section 8), so
/// a Leash running inside a previously killed cgroup would have every agent SIGKILLed at
/// birth; this probe turns that into a refusal before any run directory exists.
pub fn probe_delegation(parent: &Path, timeout: Duration) -> io::Result<()> {
    let parent_dir = open_cgroup_dir(parent)?;
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    let name = CString::new(format!("leash-probe-{:016x}", u64::from_ne_bytes(bytes)))
        .map_err(io::Error::other)?;
    mkdir_child(&parent_dir, &name)?;

    let mut child_pid: Option<libc::pid_t> = None;
    let mut group: Option<Cgroup> = None;
    let result = (|| {
        let opened = Cgroup::open_child(&parent_dir, &name)?;
        group = Some(opened);
        let group = group
            .as_ref()
            .ok_or_else(|| io::Error::other("probe cgroup missing"))?;
        group.set_lock_identity("probe")?;
        if group.lock_identity()?.as_deref() != Some("probe") {
            return Err(io::Error::other(
                "probe cgroup did not preserve user.leash.lock xattr",
            ));
        }

        let (pid, ready_rx) = spawn_probe_child(group.dir_fd())?;
        child_pid = Some(pid);

        let handshake = read_probe_handshake(ready_rx.as_raw_fd(), timeout)?;
        if handshake.is_empty() {
            return Err(io::Error::other(
                "probe child died before starting (possible cgroup kill-sequence mismatch)",
            ));
        }
        if handshake != b"R" {
            return Err(io::Error::other("probe child failed to exec /bin/sleep"));
        }

        let pid_u32 = u32::try_from(pid).map_err(io::Error::other)?;
        if !group.members()?.contains(&pid_u32) {
            return Err(io::Error::other(
                "probe process was not born into the probe cgroup",
            ));
        }
        group.wait_event("populated", true, timeout)?;
        group.set_frozen(true, timeout)?;
        group.set_frozen(false, timeout)?;
        group.kill(timeout)?;
        Ok(())
    })();

    let mut thaw = Ok(());
    let mut reap = Ok(());
    if let Some(pid) = child_pid {
        // make a best effort to thaw before killing on failure, then bound reaping.
        if result.is_err()
            && let Some(group) = group.as_ref()
        {
            thaw = group.write_control(c"cgroup.freeze", "0");
        }
        // SAFETY: pid is our forked probe child, still unreaped.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        reap = reap_bounded(pid, timeout);
    }
    drop(group);
    let cleanup = rmdir_child_retrying(&parent_dir, &name, timeout);
    combine_results(
        result,
        [("thaw", thaw), ("reap", reap), ("remove cgroup", cleanup)],
    )
}

/// fork a probe child directly into `cgroup_fd` via `clone3(CLONE_INTO_CGROUP)` so the child
/// writes `b'R'` on the CLOEXEC pipe (proving it survived birth) and execs `/bin/sleep 60`.
/// if `execv` fails it writes `b'E'` before exiting 127.
fn spawn_probe_child(cgroup_fd: RawFd) -> io::Result<(libc::pid_t, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: pipe2 writes two fresh descriptors into fds.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors were just created by pipe2 and are owned solely here.
    let (read_end, write_end) =
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let dev_null = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/dev/null")?;

    let exec_path = c"/bin/sleep";
    let argv: [*const libc::c_char; 3] = [exec_path.as_ptr(), c"60".as_ptr(), std::ptr::null()];
    let read_fd = read_end.as_raw_fd();
    let write_fd = write_end.as_raw_fd();
    let null_fd = dev_null.as_raw_fd();

    // SAFETY: the child branch performs only async-signal-safe syscalls on pre-built
    // descriptors and static string literals, then calls execv or _exit.
    let pid = unsafe { crate::supervisor::spawn::fork_process(Some(cgroup_fd)) };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // SAFETY: we are the child of clone3(CLONE_INTO_CGROUP); only raw syscalls below.
        unsafe {
            libc::close(read_fd);
            for target in [0, 1, 2] {
                if null_fd != target {
                    let _ = libc::dup2(null_fd, target);
                }
            }
            let ready = *b"R";
            loop {
                let n = libc::write(write_fd, ready.as_ptr().cast(), 1);
                if n == 1 {
                    break;
                }
                if n < 0 && *libc::__errno_location() == libc::EINTR {
                    continue;
                }
                libc::_exit(126);
            }
            libc::execv(exec_path.as_ptr(), argv.as_ptr());
            let err_byte = *b"E";
            let _ = libc::write(write_fd, err_byte.as_ptr().cast(), 1);
            libc::_exit(127);
        }
    }

    drop(write_end);
    drop(dev_null);
    Ok((pid, read_end))
}

/// read up to 2 bytes from the probe pipe until EOF or `timeout`.
fn read_probe_handshake(fd: RawFd, timeout: Duration) -> io::Result<Vec<u8>> {
    let start = Instant::now();
    let mut out = Vec::with_capacity(2);
    while out.len() < 2 {
        let remaining = timeout.saturating_sub(start.elapsed());
        let ms = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is owned local storage for one descriptor.
        let rc = unsafe { libc::poll(&raw mut pfd, 1, ms) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if rc == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "probe child handshake timed out",
            ));
        }
        let mut byte = [0u8; 1];
        // SAFETY: fd is live and byte is owned local storage.
        let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), 1) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            break;
        }
        out.push(byte[0]);
    }
    Ok(out)
}

fn reap_bounded(pid: libc::pid_t, timeout: Duration) -> io::Result<()> {
    let start = Instant::now();
    loop {
        let mut status = 0;
        // SAFETY: pid is our forked probe child; WNOHANG never blocks.
        let rc = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        if rc == pid {
            return Ok(());
        }
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if start.elapsed() >= timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "probe process did not exit",
            ));
        }
        std::thread::sleep(Duration::from_millis(5).min(timeout.saturating_sub(start.elapsed())));
    }
}

fn combine_results<const N: usize>(
    primary: io::Result<()>,
    cleanup: [(&str, io::Result<()>); N],
) -> io::Result<()> {
    let mut errors = Vec::new();
    let mut kind = None;
    if let Err(e) = primary {
        kind = Some(e.kind());
        errors.push(format!("probe: {e}"));
    }
    for (operation, result) in cleanup {
        if let Err(e) = result {
            kind.get_or_insert(e.kind());
            errors.push(format!("{operation}: {e}"));
        }
    }
    match kind {
        Some(kind) => Err(io::Error::new(kind, errors.join("; "))),
        None => Ok(()),
    }
}

fn ensure_cgroup2(dir: &File) -> io::Result<()> {
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: dir is an open descriptor and fstatfs initializes stats on success.
    if unsafe { libc::fstatfs(dir.as_raw_fd(), stats.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful fstatfs initialized the output.
    let stats = unsafe { stats.assume_init() };
    if stats.f_type != 0x6367_7270 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a cgroup v2 filesystem",
        ));
    }
    Ok(())
}

fn event_value(events: &str, key: &str) -> io::Result<bool> {
    let mut value = None;
    for line in events.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some(key) {
            continue;
        }
        let parsed = match (parts.next(), parts.next()) {
            (Some("0"), None) => false,
            (Some("1"), None) => true,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid cgroup event",
                ));
            }
        };
        if value.replace(parsed).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate cgroup event",
            ));
        }
    }
    value.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing cgroup event"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn probe_rejects_a_non_cgroup_directory_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        assert!(probe_delegation(dir.path(), Duration::ZERO).is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn event_parser_rejects_missing_malformed_and_duplicate_values() {
        assert!(event_value("populated 1\nfrozen 1\n", "frozen").unwrap());
        assert!(!event_value("frozen 0\n", "frozen").unwrap());
        for events in ["", "frozen 2", "frozen 1 extra", "frozen 1\nfrozen 0"] {
            assert!(event_value(events, "frozen").is_err());
        }
    }

    #[test]
    fn open_rejects_a_fake_cgroup_with_all_control_files() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "cgroup.procs",
            "cgroup.freeze",
            "cgroup.events",
            "cgroup.kill",
        ] {
            std::fs::write(dir.path().join(name), "").unwrap();
        }
        assert!(Cgroup::open(dir.path()).is_err());
    }

    #[test]
    fn probe_reports_primary_and_cleanup_failures() {
        let result = combine_results(
            Err(io::Error::new(io::ErrorKind::TimedOut, "freeze timed out")),
            [
                ("reap", Err(io::Error::other("reap failed"))),
                ("remove cgroup", Err(io::Error::other("remove failed"))),
            ],
        )
        .unwrap_err();
        assert_eq!(result.kind(), io::ErrorKind::TimedOut);
        let text = result.to_string();
        assert!(text.contains("freeze timed out"));
        assert!(text.contains("reap failed"));
        assert!(text.contains("remove failed"));
    }

    #[test]
    fn attach_rejects_supervisor_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("cgroup.procs");
        std::fs::write(&file, "unchanged").unwrap();
        let group = Cgroup {
            dir: File::open(dir.path()).unwrap(),
        };
        assert_eq!(
            group.attach(std::process::id()).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(std::fs::read_to_string(file).unwrap(), "unchanged");
    }

    #[test]
    fn attach_rejects_zero_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("cgroup.procs");
        std::fs::write(&file, "unchanged").unwrap();
        let group = Cgroup {
            dir: File::open(dir.path()).unwrap(),
        };
        assert_eq!(
            group.attach(0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(std::fs::read_to_string(file).unwrap(), "unchanged");
    }

    #[test]
    fn controls_remain_pinned_after_path_replacement() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("original");
        let moved = root.path().join("moved");
        std::fs::create_dir(&original).unwrap();
        std::fs::write(original.join("cgroup.procs"), "original").unwrap();
        let group = Cgroup {
            dir: File::open(&original).unwrap(),
        };
        std::fs::rename(&original, &moved).unwrap();
        std::fs::create_dir(&original).unwrap();
        std::fs::write(original.join("cgroup.procs"), "decoy").unwrap();
        group.attach(123456).unwrap();
        assert_eq!(
            std::fs::read_to_string(moved.join("cgroup.procs")).unwrap(),
            "123456al"
        );
        assert_eq!(
            std::fs::read_to_string(original.join("cgroup.procs")).unwrap(),
            "decoy"
        );
    }

    #[test]
    fn controls_do_not_follow_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        std::fs::write(&target, "unchanged").unwrap();
        std::os::unix::fs::symlink(&target, root.path().join("cgroup.procs")).unwrap();
        let group = Cgroup {
            dir: File::open(root.path()).unwrap(),
        };
        assert!(group.attach(123456).is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "unchanged");
    }

    #[test]
    fn barrier_fails_closed_when_freeze_is_not_acknowledged() {
        let dir = tempfile::tempdir().unwrap();
        for (name, content) in [
            ("cgroup.procs", ""),
            ("cgroup.freeze", ""),
            ("cgroup.events", "populated 1\nfrozen 0\n"),
            ("cgroup.kill", ""),
        ] {
            std::fs::write(dir.path().join(name), content).unwrap();
        }
        let group = Cgroup {
            dir: File::open(dir.path()).unwrap(),
        };
        assert_eq!(
            group.set_frozen(true, Duration::ZERO).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn kill_rewrites_cgroup_kill_on_every_poll_iteration() {
        let dir = tempfile::tempdir().unwrap();
        let kill_path = dir.path().join("cgroup.kill");
        let events_path = dir.path().join("cgroup.events");
        std::fs::write(&kill_path, "0").unwrap();
        std::fs::write(&events_path, "populated 1\nfrozen 0\n").unwrap();

        // flip cgroup.kill back to "0" after the first write; only drop populated to 0 after
        // a second "1" lands, proving kill() rewrites cgroup.kill on subsequent polls.
        let kill_watch = kill_path.clone();
        let events_watch = events_path.clone();
        let watcher = std::thread::spawn(move || {
            let mut writes = 0usize;
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if std::fs::read_to_string(&kill_watch).unwrap_or_default() == "1" {
                    writes += 1;
                    if writes == 1 {
                        std::fs::write(&kill_watch, "0").unwrap();
                    } else {
                        std::fs::write(&events_watch, "populated 0\nfrozen 0\n").unwrap();
                        return writes;
                    }
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            writes
        });

        let group = Cgroup {
            dir: File::open(dir.path()).unwrap(),
        };
        group.kill(Duration::from_secs(2)).unwrap();
        assert!(watcher.join().unwrap() >= 2);
    }
}
