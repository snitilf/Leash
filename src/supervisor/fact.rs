//! the x86-64 syscall-to-fact table for the filesystem families (docs/design/syscalls.md
//! sections 3.1-3.2).
//!
//! this is the pure lookup the notify loop uses to know, for a trapped syscall number,
//! where the path pointers live in the register snapshot and what access the call
//! requests. it reads no memory and performs no io; the loop does the bounded child-memory
//! reads and hands the flag values back in. like the filter table, the argument positions
//! are hand-pinned against the x86-64 abi and checked by unit tests; this module builds
//! and tests on any host.

use crate::recorder::FsAccess;
use crate::sandbox::filter::nr;

/// open(2) flag bits, x86-64 values (include/uapi/asm-generic/fcntl.h). hand-pinned for
/// the same reason as the filter's syscall numbers: the macos dev host's libc disagrees.
pub mod flags {
    /// mask over the access-mode bits
    pub const O_ACCMODE: u64 = 0o3;
    /// open write-only
    pub const O_WRONLY: u64 = 0o1;
    /// open read-write
    pub const O_RDWR: u64 = 0o2;
    /// create if absent
    pub const O_CREAT: u64 = 0o100;
    /// truncate on open; a write effect regardless of access mode
    pub const O_TRUNC: u64 = 0o1000;
    /// the dirfd value meaning "relative to the caller's cwd" (fcntl.h AT_FDCWD)
    pub const AT_FDCWD: u64 = (-100_i32 as u32) as u64;
}

/// one path-pointer argument of a trapped syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathArg {
    /// index into `seccomp_data.args` of the path pointer
    pub path_arg: usize,
    /// index of the dirfd argument the path is relative to, for the *at variants;
    /// `None` for the legacy calls, whose relative paths anchor at the caller's cwd
    pub dirfd_arg: Option<usize>,
    /// whether a relative value is anchored (cwd or dirfd) when recorded. false only for
    /// a symlink target, which is stored content, relative to the link itself, and is
    /// recorded verbatim
    pub anchor: bool,
}

impl PathArg {
    const fn at(dirfd_arg: usize, path_arg: usize) -> Self {
        Self {
            path_arg,
            dirfd_arg: Some(dirfd_arg),
            anchor: true,
        }
    }

    const fn cwd(path_arg: usize) -> Self {
        Self {
            path_arg,
            dirfd_arg: None,
            anchor: true,
        }
    }

    const fn verbatim(path_arg: usize) -> Self {
        Self {
            path_arg,
            dirfd_arg: None,
            anchor: false,
        }
    }
}

/// how the requested access is derived for one syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessSpec {
    /// fixed by the syscall itself (mkdir creates, unlink deletes)
    Fixed(&'static [FsAccess]),
    /// open(2)-style flags in the named register argument
    OpenFlags {
        /// index into `seccomp_data.args` of the flags value
        arg: usize,
    },
    /// openat2(2): flags live in the first u64 of a `struct open_how` in child memory
    /// behind the named pointer argument; the loop reads it bounded and maps the value
    /// with [`open_flags_access`]
    OpenHow {
        /// index into `seccomp_data.args` of the `open_how` pointer
        arg: usize,
    },
}

/// the register shape of one filesystem-family syscall: which arguments are paths and
/// what access the call requests. paths are listed in syscall-argument order; for the
/// two-path calls the first fills the fact's `path` and the second its `dest`
/// (trace.md section 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsShape {
    /// the syscall name as recorded in the event envelope
    pub name: &'static str,
    /// the first (or only) path argument
    pub path: PathArg,
    /// the second path argument of the rename/link/symlink families
    pub dest: Option<PathArg>,
    /// how the requested access is derived
    pub access: AccessSpec,
}

const WRITE: &[FsAccess] = &[FsAccess::Write];
const CREATE: &[FsAccess] = &[FsAccess::Create];
const DELETE: &[FsAccess] = &[FsAccess::Delete];
const WRITE_CREATE: &[FsAccess] = &[FsAccess::Write, FsAccess::Create];

/// classify a trapped syscall number as a filesystem-family call, or `None`.
pub fn fs_shape(syscall_nr: u32) -> Option<FsShape> {
    use AccessSpec::{Fixed, OpenFlags, OpenHow};
    let shape = match syscall_nr {
        // section 3.1: path-introducing
        nr::OPEN => FsShape {
            name: "open",
            path: PathArg::cwd(0),
            dest: None,
            access: OpenFlags { arg: 1 },
        },
        nr::CREAT => FsShape {
            name: "creat",
            path: PathArg::cwd(0),
            dest: None,
            access: Fixed(WRITE_CREATE),
        },
        nr::OPENAT => FsShape {
            name: "openat",
            path: PathArg::at(0, 1),
            dest: None,
            access: OpenFlags { arg: 2 },
        },
        nr::OPENAT2 => FsShape {
            name: "openat2",
            path: PathArg::at(0, 1),
            dest: None,
            access: OpenHow { arg: 2 },
        },
        // section 3.2: filesystem mutation
        nr::TRUNCATE => FsShape {
            name: "truncate",
            path: PathArg::cwd(0),
            dest: None,
            access: Fixed(WRITE),
        },
        nr::RENAME => FsShape {
            name: "rename",
            path: PathArg::cwd(0),
            dest: Some(PathArg::cwd(1)),
            access: Fixed(WRITE),
        },
        nr::RENAMEAT => FsShape {
            name: "renameat",
            path: PathArg::at(0, 1),
            dest: Some(PathArg::at(2, 3)),
            access: Fixed(WRITE),
        },
        nr::RENAMEAT2 => FsShape {
            name: "renameat2",
            path: PathArg::at(0, 1),
            dest: Some(PathArg::at(2, 3)),
            access: Fixed(WRITE),
        },
        nr::MKDIR => FsShape {
            name: "mkdir",
            path: PathArg::cwd(0),
            dest: None,
            access: Fixed(CREATE),
        },
        nr::MKDIRAT => FsShape {
            name: "mkdirat",
            path: PathArg::at(0, 1),
            dest: None,
            access: Fixed(CREATE),
        },
        nr::RMDIR => FsShape {
            name: "rmdir",
            path: PathArg::cwd(0),
            dest: None,
            access: Fixed(DELETE),
        },
        nr::UNLINK => FsShape {
            name: "unlink",
            path: PathArg::cwd(0),
            dest: None,
            access: Fixed(DELETE),
        },
        nr::UNLINKAT => FsShape {
            name: "unlinkat",
            path: PathArg::at(0, 1),
            dest: None,
            // AT_REMOVEDIR switches file vs directory removal, not the access kind
            access: Fixed(DELETE),
        },
        nr::LINK => FsShape {
            name: "link",
            path: PathArg::cwd(0),
            dest: Some(PathArg::cwd(1)),
            access: Fixed(CREATE),
        },
        nr::LINKAT => FsShape {
            name: "linkat",
            path: PathArg::at(0, 1),
            dest: Some(PathArg::at(2, 3)),
            access: Fixed(CREATE),
        },
        nr::SYMLINK => FsShape {
            name: "symlink",
            // the target is stored content, relative to the link, recorded verbatim
            path: PathArg::verbatim(0),
            dest: Some(PathArg::cwd(1)),
            access: Fixed(CREATE),
        },
        nr::SYMLINKAT => FsShape {
            name: "symlinkat",
            path: PathArg::verbatim(0),
            dest: Some(PathArg::at(1, 2)),
            access: Fixed(CREATE),
        },
        nr::CHMOD => FsShape {
            name: "chmod",
            path: PathArg::cwd(0),
            dest: None,
            // metadata changes are decided as a write to the path (syscalls.md 3.2)
            access: Fixed(WRITE),
        },
        nr::FCHMODAT => FsShape {
            name: "fchmodat",
            path: PathArg::at(0, 1),
            dest: None,
            access: Fixed(WRITE),
        },
        nr::CHOWN => FsShape {
            name: "chown",
            path: PathArg::cwd(0),
            dest: None,
            access: Fixed(WRITE),
        },
        nr::FCHOWNAT => FsShape {
            name: "fchownat",
            path: PathArg::at(0, 1),
            dest: None,
            access: Fixed(WRITE),
        },
        _ => return None,
    };
    Some(shape)
}

/// name any syscall in the mediated or denied-and-recorded tables, for the event
/// envelope's `syscall` field.
pub fn syscall_name(syscall_nr: u32) -> Option<&'static str> {
    if let Some(shape) = fs_shape(syscall_nr) {
        return Some(shape.name);
    }
    Some(match syscall_nr {
        nr::CLONE => "clone",
        nr::FORK => "fork",
        nr::VFORK => "vfork",
        nr::EXECVE => "execve",
        nr::EXECVEAT => "execveat",
        nr::CLONE3 => "clone3",
        nr::PTRACE => "ptrace",
        nr::PROCESS_VM_READV => "process_vm_readv",
        nr::PROCESS_VM_WRITEV => "process_vm_writev",
        nr::PIDFD_GETFD => "pidfd_getfd",
        nr::CONNECT => "connect",
        nr::SENDTO => "sendto",
        nr::BIND => "bind",
        nr::IO_URING_SETUP => "io_uring_setup",
        nr::IO_URING_ENTER => "io_uring_enter",
        nr::IO_URING_REGISTER => "io_uring_register",
        _ => return None,
    })
}

/// map open(2)-style flags to the requested access (policy vocabulary, policy.md
/// section 2). O_TRUNC is a write effect even on a read-only open.
pub fn open_flags_access(open_flags: u64) -> Vec<FsAccess> {
    let mut access = match open_flags & flags::O_ACCMODE {
        flags::O_WRONLY => vec![FsAccess::Write],
        flags::O_RDWR => vec![FsAccess::Read, FsAccess::Write],
        _ => vec![FsAccess::Read],
    };
    if open_flags & flags::O_TRUNC != 0 && !access.contains(&FsAccess::Write) {
        access.push(FsAccess::Write);
    }
    if open_flags & flags::O_CREAT != 0 {
        access.push(FsAccess::Create);
    }
    access
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::sandbox::filter::{DENIED_RECORDED, MEDIATED};

    #[test]
    fn every_31_and_32_family_syscall_has_a_shape_and_nothing_else_does() {
        let fs: &[u32] = &[
            nr::OPEN,
            nr::CREAT,
            nr::OPENAT,
            nr::OPENAT2,
            nr::TRUNCATE,
            nr::RENAME,
            nr::RENAMEAT,
            nr::RENAMEAT2,
            nr::MKDIR,
            nr::MKDIRAT,
            nr::RMDIR,
            nr::UNLINK,
            nr::UNLINKAT,
            nr::LINK,
            nr::LINKAT,
            nr::SYMLINK,
            nr::SYMLINKAT,
            nr::CHMOD,
            nr::FCHMODAT,
            nr::CHOWN,
            nr::FCHOWNAT,
        ];
        for &n in fs {
            assert!(fs_shape(n).is_some(), "fs syscall {n} must have a shape");
        }
        for &n in MEDIATED {
            if !fs.contains(&n) {
                assert!(fs_shape(n).is_none(), "non-fs syscall {n} must not");
            }
        }
        for &n in DENIED_RECORDED {
            assert!(fs_shape(n).is_none());
        }
    }

    #[test]
    fn every_tabled_syscall_has_a_name() {
        for &n in MEDIATED.iter().chain(DENIED_RECORDED) {
            assert!(syscall_name(n).is_some(), "tabled syscall {n} needs a name");
        }
        assert_eq!(syscall_name(9999), None);
    }

    // the register positions, pinned row by row against the x86-64 man-page signatures.
    #[test]
    fn at_variants_take_the_path_in_arg1_not_arg0() {
        for n in [
            nr::OPENAT,
            nr::OPENAT2,
            nr::MKDIRAT,
            nr::UNLINKAT,
            nr::FCHMODAT,
            nr::FCHOWNAT,
        ] {
            let s = fs_shape(n).unwrap();
            assert_eq!(s.path, PathArg::at(0, 1), "{}", s.name);
        }
    }

    #[test]
    fn legacy_calls_take_the_path_in_arg0_anchored_at_cwd() {
        for n in [
            nr::OPEN,
            nr::CREAT,
            nr::TRUNCATE,
            nr::MKDIR,
            nr::RMDIR,
            nr::UNLINK,
            nr::CHMOD,
            nr::CHOWN,
        ] {
            let s = fs_shape(n).unwrap();
            assert_eq!(s.path, PathArg::cwd(0), "{}", s.name);
            assert_eq!(s.dest, None, "{}", s.name);
        }
    }

    #[test]
    fn two_path_calls_carry_both_paths_in_argument_order() {
        for n in [nr::RENAME, nr::LINK] {
            let s = fs_shape(n).unwrap();
            assert_eq!((s.path, s.dest), (PathArg::cwd(0), Some(PathArg::cwd(1))));
        }
        for n in [nr::RENAMEAT, nr::RENAMEAT2, nr::LINKAT] {
            let s = fs_shape(n).unwrap();
            assert_eq!(
                (s.path, s.dest),
                (PathArg::at(0, 1), Some(PathArg::at(2, 3))),
                "{}",
                s.name
            );
        }
    }

    #[test]
    fn symlink_target_is_verbatim_and_the_link_path_is_anchored() {
        let s = fs_shape(nr::SYMLINK).unwrap();
        assert_eq!(s.path, PathArg::verbatim(0));
        assert_eq!(s.dest, Some(PathArg::cwd(1)));

        let s = fs_shape(nr::SYMLINKAT).unwrap();
        assert_eq!(s.path, PathArg::verbatim(0));
        assert_eq!(s.dest, Some(PathArg::at(1, 2)));
    }

    #[test]
    fn open_family_reads_flags_from_the_documented_argument() {
        assert_eq!(
            fs_shape(nr::OPEN).unwrap().access,
            AccessSpec::OpenFlags { arg: 1 }
        );
        assert_eq!(
            fs_shape(nr::OPENAT).unwrap().access,
            AccessSpec::OpenFlags { arg: 2 }
        );
        assert_eq!(
            fs_shape(nr::OPENAT2).unwrap().access,
            AccessSpec::OpenHow { arg: 2 }
        );
    }

    #[test]
    fn open_flags_map_to_the_policy_access_vocabulary() {
        use FsAccess::{Create, Read, Write};
        assert_eq!(open_flags_access(0), vec![Read]);
        assert_eq!(open_flags_access(flags::O_WRONLY), vec![Write]);
        assert_eq!(open_flags_access(flags::O_RDWR), vec![Read, Write]);
        assert_eq!(
            open_flags_access(flags::O_WRONLY | flags::O_CREAT | flags::O_TRUNC),
            vec![Write, Create]
        );
        assert_eq!(
            open_flags_access(flags::O_TRUNC),
            vec![Read, Write],
            "O_TRUNC is a write effect even on a read-only open"
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn pinned_flag_values_match_libc() {
        assert_eq!(flags::O_ACCMODE, libc::O_ACCMODE as u64);
        assert_eq!(flags::O_WRONLY, libc::O_WRONLY as u64);
        assert_eq!(flags::O_RDWR, libc::O_RDWR as u64);
        assert_eq!(flags::O_CREAT, libc::O_CREAT as u64);
        assert_eq!(flags::O_TRUNC, libc::O_TRUNC as u64);
        assert_eq!(flags::AT_FDCWD, u64::from(libc::AT_FDCWD as u32));
    }
}
