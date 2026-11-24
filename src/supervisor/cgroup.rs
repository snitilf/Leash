//! cgroup v2 freezer primitives for exact snapshot barriers (ADR-0022).

use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

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

    /// terminate the entire cgroup and wait until it has no living processes.
    pub fn kill(&self, timeout: Duration) -> io::Result<()> {
        self.write_control(c"cgroup.kill", "1")?;
        self.wait_event("populated", false, timeout)
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

/// exercise delegation, freezer confirmation, thaw, and whole-group termination using
/// a trusted probe process. the supervisor never enters the probe cgroup.
pub fn probe_delegation(parent: &Path, timeout: Duration) -> io::Result<()> {
    let parent_dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    ensure_cgroup2(&parent_dir)?;
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    let name = std::ffi::CString::new(format!("leash-probe-{:016x}", u64::from_ne_bytes(bytes)))
        .map_err(io::Error::other)?;
    // SAFETY: parent_dir and name are live; mkdirat creates one child directory.
    if unsafe { libc::mkdirat(parent_dir.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut child = None;
    let mut group = None;
    let result = (|| {
        // SAFETY: parent_dir and name are live; openat returns a new owned fd.
        let fd = unsafe {
            libc::openat(
                parent_dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd was returned by openat and is uniquely owned here.
        let dir = unsafe { File::from_raw_fd(fd) };
        group = Some(Cgroup::from_dir(dir)?);
        let group = group
            .as_ref()
            .ok_or_else(|| io::Error::other("probe cgroup missing"))?;
        let process = std::process::Command::new("/bin/sleep")
            .arg("60")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        child = Some(process);
        let process = child
            .as_ref()
            .ok_or_else(|| io::Error::other("probe process missing"))?;
        group.attach(process.id())?;
        let members = group.read_control(c"cgroup.procs")?;
        if !members
            .lines()
            .any(|line| line.trim() == process.id().to_string())
        {
            return Err(io::Error::other("probe process was not attached to cgroup"));
        }
        group.wait_event("populated", true, timeout)?;
        group.set_frozen(true, timeout)?;
        group.set_frozen(false, timeout)?;
        group.kill(timeout)?;
        Ok(())
    })();
    let mut thaw = Ok(());
    let mut reap = Ok(());
    if let Some(mut process) = child {
        // make a best effort to thaw before killing on failure, then bound reaping.
        if result.is_err()
            && let Some(group) = group.as_ref()
        {
            thaw = group.write_control(c"cgroup.freeze", "0");
        }
        let _ = process.kill();
        let start = Instant::now();
        loop {
            match process.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if start.elapsed() < timeout => std::thread::sleep(
                    Duration::from_millis(5).min(timeout.saturating_sub(start.elapsed())),
                ),
                Ok(None) => {
                    reap = Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "probe process did not exit",
                    ));
                    break;
                }
                Err(e) => {
                    reap = Err(e);
                    break;
                }
            }
        }
    }
    drop(group);
    // SAFETY: parent_dir and name are live and refer to the created child name.
    let cleanup = if unsafe {
        libc::unlinkat(parent_dir.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR)
    } == 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    };
    combine_results(
        result,
        [("thaw", thaw), ("reap", reap), ("remove cgroup", cleanup)],
    )
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
}
