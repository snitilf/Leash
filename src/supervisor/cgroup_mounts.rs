//! the implicit cgroup2 deny of a snapshot run (ADR-0024 decision 4).
//!
//! assumptions: the mounts are read once from `/proc/self/mountinfo`, before the child
//! exists, and every comparison below is between two resolved absolute paths, by component
//! and never by string prefix. a cgroup2 mount made later is a named residual (escapes.md
//! section 4). the fs facts this is asked about in enforce mode carry the identity read back
//! from the opened handle (ADR-0023), so a symlink that leads into a mount is judged on where
//! it landed.
//!
//! the rule is evaluated before every policy rule and cannot be allowed by one. it is depth:
//! the control that keeps the agent out of the run cgroup's control plane is `clone3` answered
//! `ENOSYS` (ADR-0024 decision 7), because a directory descriptor on a cgroup can still be
//! obtained through `open_tree` or descriptor passing, which this path check never sees. the
//! Landlock backstop for writes is the overlap refusal of decision 5.

use std::io;
use std::path::{Path, PathBuf};

use crate::recorder::FsAccess;
use crate::supervisor::state_root::{normalize_lexically, resolve_leniently};

/// the filesystem type `/proc/self/mountinfo` names for a cgroup v2 hierarchy.
const CGROUP2_FSTYPE: &str = "cgroup2";

/// every cgroup2 mount point in the supervisor's mount namespace, as resolved absolute paths.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CgroupMounts {
    mounts: Vec<PathBuf>,
}

impl CgroupMounts {
    /// read the cgroup2 mounts of this mount namespace from `/proc/self/mountinfo`, resolving
    /// each mount point through symlinks. a mount point that cannot be resolved is kept as
    /// the kernel spelled it, which is the safer reading: the deny then still names it.
    pub fn from_proc_self() -> io::Result<Self> {
        let text = std::fs::read_to_string("/proc/self/mountinfo")?;
        let mut mounts = Self::from_mountinfo(&text)?.mounts;
        let resolved: Vec<PathBuf> = mounts.iter().map(|m| resolve_leniently(m)).collect();
        mounts.extend(resolved);
        Self::from_resolved(mounts)
    }

    /// the cgroup2 mount points named by `mountinfo` text, exactly as spelled there.
    pub fn from_mountinfo(text: &str) -> io::Result<Self> {
        let mut mounts = Vec::new();
        for line in text.lines() {
            if let Some(mount) = cgroup2_mount_point(line) {
                mounts.push(PathBuf::from(mount));
            }
        }
        Self::from_resolved(mounts)
    }

    /// wrap already-resolved absolute mount points, dropping duplicates. a relative path is
    /// refused because it could never match a resolved fact path, which would silently disable
    /// the rule. so is a path that is not valid UTF-8: fact paths are compared as text.
    pub fn from_resolved(mut mounts: Vec<PathBuf>) -> io::Result<Self> {
        for mount in &mounts {
            if !mount.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "the cgroup2 mount {} is not an absolute path",
                        mount.display()
                    ),
                ));
            }
            if mount.to_str().is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "the cgroup2 mount {} is not valid UTF-8, so the implicit deny \
                         could not match it",
                        mount.display()
                    ),
                ));
            }
        }
        mounts.sort();
        mounts.dedup();
        Ok(Self { mounts })
    }

    /// the mount points, sorted and without duplicates.
    pub fn paths(&self) -> &[PathBuf] {
        &self.mounts
    }

    /// is `path` a mount point or beneath one?
    pub fn contains(&self, path: &Path) -> bool {
        self.mounts.iter().any(|mount| path.starts_with(mount))
    }

    /// is `path` a strict ancestor of a mount point, a node whose removal, replacement or
    /// modification would move or hide the mount?
    pub fn is_protected_node(&self, path: &Path) -> bool {
        self.mounts
            .iter()
            .any(|mount| path != mount && mount.starts_with(path))
    }

    /// does the implicit rule deny this filesystem access?
    ///
    /// every access to a mount or beneath it is denied, read included. a strict ancestor of a
    /// mount is denied when the access would remove, replace or alter it: a `delete`, any
    /// access to the destination operand of a rename or link, or a `write` on its own
    /// identity, which only chmod, chown and truncate of the directory itself produce.
    /// reading or listing an ancestor, and creating beside the mount, stay with the policy.
    pub fn denies_fs(&self, path: &Path, access: &[FsAccess], destination: bool) -> bool {
        if self.contains(path) {
            return true;
        }
        self.is_protected_node(path)
            && (destination
                || access.contains(&FsAccess::Delete)
                || access.contains(&FsAccess::Write))
    }

    /// does the implicit rule deny executing this binary? decided like the state-root exec
    /// check: on the spelled path, its lexical normalization and its resolution.
    pub fn denies_exec(&self, binary: &Path) -> bool {
        if self.contains(binary) {
            return true;
        }
        if !binary.is_absolute() {
            return false;
        }
        self.contains(&normalize_lexically(binary)) || self.contains(&resolve_leniently(binary))
    }
}

/// the mount point of a `mountinfo` line whose filesystem type is cgroup2, with the kernel's
/// octal escapes decoded. the line is
/// `id parent major:minor root mount-point options [optional...] - fstype source super-options`.
fn cgroup2_mount_point(line: &str) -> Option<String> {
    let (head, tail) = line.split_once(" - ")?;
    let fstype = tail.split(' ').next()?;
    if fstype != CGROUP2_FSTYPE {
        return None;
    }
    let mount_point = head.split(' ').nth(4)?;
    Some(unescape_mountinfo(mount_point))
}

/// decode the `\ooo` octal escapes the kernel writes for space, tab, newline and backslash.
fn unescape_mountinfo(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..=i + 3]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            let value = (u32::from(bytes[i + 1] - b'0') << 6)
                | (u32::from(bytes[i + 2] - b'0') << 3)
                | u32::from(bytes[i + 3] - b'0');
            if let Ok(byte) = u8::try_from(value) {
                out.push(byte);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const EVERY_ACCESS: [FsAccess; 4] = [
        FsAccess::Read,
        FsAccess::Write,
        FsAccess::Create,
        FsAccess::Delete,
    ];

    fn mounts(paths: &[&str]) -> CgroupMounts {
        CgroupMounts::from_resolved(paths.iter().map(PathBuf::from).collect()).unwrap()
    }

    #[test]
    fn only_cgroup2_lines_name_a_mount() {
        let text = "\
22 28 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw\n\
31 22 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,nsdelegate\n\
40 22 0:30 / /sys/fs/cgroup/unified rw,relatime - cgroup cgroup rw,name=systemd\n\
55 28 0:44 /sub /mnt/other rw - cgroup2 none rw\n\
60 28 0:50 / /mnt/cgroup2-not rw - tmpfs cgroup2 rw\n";
        let found = CgroupMounts::from_mountinfo(text).unwrap();
        assert_eq!(
            found.paths(),
            &[PathBuf::from("/mnt/other"), PathBuf::from("/sys/fs/cgroup")]
        );
    }

    #[test]
    fn a_mount_point_with_escaped_characters_is_decoded() {
        let text = "70 28 0:60 / /mnt/with\\040space\\134back rw - cgroup2 none rw\n";
        let found = CgroupMounts::from_mountinfo(text).unwrap();
        assert_eq!(found.paths(), &[PathBuf::from("/mnt/with space\\back")]);
    }

    #[test]
    fn a_line_without_optional_fields_or_with_several_is_parsed() {
        let bare = "31 22 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n";
        let many = "31 22 0:26 / /sys/fs/cgroup rw shared:9 master:2 unbindable - cgroup2 c rw\n";
        for text in [bare, many] {
            assert_eq!(
                CgroupMounts::from_mountinfo(text).unwrap().paths(),
                &[PathBuf::from("/sys/fs/cgroup")]
            );
        }
        assert!(
            CgroupMounts::from_mountinfo("garbage without a separator")
                .unwrap()
                .paths()
                .is_empty()
        );
    }

    #[test]
    fn duplicate_mounts_collapse() {
        let m = mounts(&["/sys/fs/cgroup", "/sys/fs/cgroup", "/a"]);
        assert_eq!(m.paths().len(), 2);
    }

    #[test]
    fn a_relative_or_non_utf8_mount_is_refused() {
        use std::os::unix::ffi::OsStringExt;
        assert!(CgroupMounts::from_resolved(vec!["cgroup".into()]).is_err());
        let bad = PathBuf::from(std::ffi::OsString::from_vec(b"/sys/\xff".to_vec()));
        let err = CgroupMounts::from_resolved(vec![bad]).unwrap_err();
        assert!(err.to_string().contains("UTF-8"), "{err}");
    }

    #[test]
    fn the_mount_and_everything_beneath_it_is_denied_for_every_access() {
        let m = mounts(&["/sys/fs/cgroup"]);
        for path in [
            "/sys/fs/cgroup",
            "/sys/fs/cgroup/user.slice/cgroup.procs",
            "/sys/fs/cgroup/cgroup.kill",
        ] {
            for access in EVERY_ACCESS {
                assert!(m.denies_fs(Path::new(path), &[access], false), "{path}");
            }
            assert!(m.denies_exec(Path::new(path)));
        }
    }

    #[test]
    fn a_sibling_sharing_a_string_prefix_is_not_beneath_the_mount() {
        let m = mounts(&["/sys/fs/cgroup"]);
        for path in ["/sys/fs/cgroup2/x", "/sys/fs/cgroup-old", "/sys/fs/cgrou"] {
            for access in EVERY_ACCESS {
                assert!(!m.denies_fs(Path::new(path), &[access], false), "{path}");
            }
        }
    }

    #[test]
    fn removing_replacing_or_altering_an_ancestor_is_denied() {
        let m = mounts(&["/sys/fs/cgroup"]);
        for ancestor in ["/sys/fs", "/sys", "/"] {
            let p = Path::new(ancestor);
            assert!(m.denies_fs(p, &[FsAccess::Delete], false), "{ancestor}");
            assert!(m.denies_fs(p, &[FsAccess::Create], true), "{ancestor} dst");
            assert!(
                m.denies_fs(p, &[FsAccess::Write], false),
                "{ancestor} chmod"
            );
        }
    }

    #[test]
    fn reading_or_creating_in_an_ancestor_is_left_to_policy() {
        let m = mounts(&["/sys/fs/cgroup"]);
        let p = Path::new("/sys/fs");
        assert!(!m.denies_fs(p, &[FsAccess::Read], false));
        assert!(!m.denies_fs(p, &[FsAccess::Create], false));
    }

    #[test]
    fn unrelated_paths_and_an_empty_set_deny_nothing() {
        let m = mounts(&["/sys/fs/cgroup"]);
        for access in EVERY_ACCESS {
            assert!(!m.denies_fs(Path::new("/home/u/project"), &[access], true));
        }
        assert!(!m.denies_exec(Path::new("/usr/bin/true")));
        assert!(!m.denies_exec(Path::new("relative/x")));
        let none = CgroupMounts::default();
        assert!(!none.denies_fs(Path::new("/sys/fs/cgroup/x"), &[FsAccess::Read], false));
    }

    #[test]
    fn exec_is_decided_on_the_lexical_spelling_too() {
        let m = mounts(&["/sys/fs/cgroup"]);
        assert!(m.denies_exec(Path::new("/usr/../sys/fs/cgroup/x")));
    }

    #[test]
    fn every_mount_of_several_is_protected() {
        let m = mounts(&["/sys/fs/cgroup", "/mnt/other/cg"]);
        assert!(m.denies_fs(Path::new("/mnt/other/cg/f"), &[FsAccess::Read], false));
        assert!(m.denies_fs(Path::new("/mnt/other"), &[FsAccess::Delete], false));
        assert!(m.denies_fs(Path::new("/mnt"), &[FsAccess::Delete], false));
    }
}
