//! the seccomp cbpf program (docs/design/syscalls.md; ADR-0016).
//!
//! the filter is the sorting stage only: it pins the architecture, then routes foreign-arch
//! entries, x32-bit-30 numbers, and every tabled syscall to SECCOMP_RET_USER_NOTIF, and
//! passes everything else through. all decisions, including the unconditional denials of
//! the denied-and-recorded set, happen in the supervisor's notify loop. foreign arch and
//! x32 are routed rather than denied in-filter because syscalls.md section 5 places them
//! in the denied-and-recorded set: an in-filter errno would deny without recording.
//!
//! the syscall numbers are hand-pinned x86-64 values, not `libc::SYS_*`: the filter always
//! targets AUDIT_ARCH_X86_64 (FR-15, ADR-0014), while `libc::SYS_*` is the build target's
//! table and does not exist on the macos dev host. a linux/x86_64 unit test checks each
//! pinned value against libc.
//!
//! this module is pure construction, no syscalls; it builds and tests on any host.

/// one cbpf instruction, layout-compatible with the kernel's `struct sock_filter`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockFilter {
    /// packed opcode (instruction class, size, mode).
    pub code: u16,
    /// forward jump offset when the condition holds.
    pub jt: u8,
    /// forward jump offset when the condition does not hold.
    pub jf: u8,
    /// immediate operand: load offset, comparison value, or return value.
    pub k: u32,
}

// cbpf opcodes, from include/uapi/linux/bpf_common.h. only the four instruction forms the
// filter uses.
const BPF_LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const BPF_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const BPF_JSET_K: u16 = 0x45; // BPF_JMP | BPF_JSET | BPF_K
const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K

// byte offsets into struct seccomp_data (include/uapi/linux/seccomp.h).
const SECCOMP_DATA_NR: u32 = 0;
const SECCOMP_DATA_ARCH: u32 = 4;

/// filter return value: run the syscall with no supervisor involvement
/// (include/uapi/linux/seccomp.h).
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
/// filter return value: block the child and notify the supervisor
/// (include/uapi/linux/seccomp.h).
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;

/// the pinned architecture (include/uapi/linux/audit.h).
pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
/// the representative foreign arch for tests (include/uapi/linux/audit.h).
#[cfg(test)]
pub const AUDIT_ARCH_I386: u32 = 0x4000_0003;

/// bit 30 set in `nr` marks an x32-abi entry that still reports AUDIT_ARCH_X86_64;
/// reading such a number against the x86-64 table is the arch-confusion bypass
/// (syscalls.md section 5).
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// x86-64 syscall numbers for the tabled sets. hand-pinned; see the module doc.
// each name mirrors the syscall it numbers; a doc line per constant would only repeat
// the name, so the module doc carries the documentation.
#[allow(missing_docs)]
pub mod nr {
    // section 3.1: path-introducing
    pub const OPEN: u32 = 2;
    pub const CREAT: u32 = 85;
    pub const OPENAT: u32 = 257;
    pub const OPENAT2: u32 = 437;
    // section 3.2: filesystem mutation
    pub const TRUNCATE: u32 = 76;
    pub const RENAME: u32 = 82;
    pub const MKDIR: u32 = 83;
    pub const RMDIR: u32 = 84;
    pub const LINK: u32 = 86;
    pub const UNLINK: u32 = 87;
    pub const SYMLINK: u32 = 88;
    pub const CHMOD: u32 = 90;
    pub const CHOWN: u32 = 92;
    pub const MKDIRAT: u32 = 258;
    pub const FCHOWNAT: u32 = 260;
    pub const UNLINKAT: u32 = 263;
    pub const RENAMEAT: u32 = 264;
    pub const LINKAT: u32 = 265;
    pub const SYMLINKAT: u32 = 266;
    pub const FCHMODAT: u32 = 268;
    pub const RENAMEAT2: u32 = 316;
    // section 3.3: process creation and program execution
    pub const CLONE: u32 = 56;
    pub const FORK: u32 = 57;
    pub const VFORK: u32 = 58;
    pub const EXECVE: u32 = 59;
    pub const EXECVEAT: u32 = 322;
    pub const CLONE3: u32 = 435;
    // section 3.4: cross-process control
    pub const PTRACE: u32 = 101;
    pub const PROCESS_VM_READV: u32 = 310;
    pub const PROCESS_VM_WRITEV: u32 = 311;
    pub const PIDFD_GETFD: u32 = 438;
    // section 3.5: network
    pub const CONNECT: u32 = 42;
    pub const SENDTO: u32 = 44;
    pub const BIND: u32 = 49;
    // section 5: denied-and-recorded
    pub const IO_URING_SETUP: u32 = 425;
    pub const IO_URING_ENTER: u32 = 426;
    pub const IO_URING_REGISTER: u32 = 427;
}

/// the mediated set (syscalls.md sections 3.1-3.5): trapped, decided by policy.
pub const MEDIATED: &[u32] = &[
    nr::OPEN,
    nr::CREAT,
    nr::OPENAT,
    nr::OPENAT2,
    nr::TRUNCATE,
    nr::RENAME,
    nr::MKDIR,
    nr::RMDIR,
    nr::LINK,
    nr::UNLINK,
    nr::SYMLINK,
    nr::CHMOD,
    nr::CHOWN,
    nr::MKDIRAT,
    nr::FCHOWNAT,
    nr::UNLINKAT,
    nr::RENAMEAT,
    nr::LINKAT,
    nr::SYMLINKAT,
    nr::FCHMODAT,
    nr::RENAMEAT2,
    nr::CLONE,
    nr::FORK,
    nr::VFORK,
    nr::EXECVE,
    nr::EXECVEAT,
    nr::CLONE3,
    nr::PTRACE,
    nr::PROCESS_VM_READV,
    nr::PROCESS_VM_WRITEV,
    nr::PIDFD_GETFD,
    nr::CONNECT,
    nr::SENDTO,
    nr::BIND,
];

/// the denied-and-recorded set (syscalls.md section 5): trapped like the mediated set,
/// unconditionally denied by the supervisor after recording.
pub const DENIED_RECORDED: &[u32] = &[
    nr::IO_URING_SETUP,
    nr::IO_URING_ENTER,
    nr::IO_URING_REGISTER,
];

/// build the filter program. every tabled syscall, every x32-bit number, and every
/// foreign-arch entry routes to the notif return; everything else passes through.
///
/// shape: load arch, bail to notif on mismatch; load nr, bail to notif on bit 30; one
/// jeq per tabled number, all jumping to the shared notif return past the allow return.
/// with two tables of ~40 numbers every jump offset stays far below the u8 bound, which
/// `filter_is_well_formed` pins.
pub fn build_filter() -> Vec<SockFilter> {
    let tabled: Vec<u32> = MEDIATED.iter().chain(DENIED_RECORDED).copied().collect();
    // ld arch + jeq, ld nr + jset, one jeq per number, ret allow, ret notif
    let len = 4 + tabled.len() + 2;
    let notif_pc = len - 1;
    let mut prog = Vec::with_capacity(len);

    // the largest jump is from pc 1 to the notif return, an offset of table length + 3;
    // the compile-time check below keeps it inside the u8 jump field as the tables grow.
    const _: () = assert!(MEDIATED.len() + DENIED_RECORDED.len() + 3 <= u8::MAX as usize);
    let jump_to_notif = |from_pc: usize| -> u8 { (notif_pc - from_pc - 1) as u8 };

    prog.push(SockFilter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_ARCH,
    });
    prog.push(SockFilter {
        code: BPF_JEQ_K,
        jt: 0,
        jf: jump_to_notif(1),
        k: AUDIT_ARCH_X86_64,
    });
    prog.push(SockFilter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_NR,
    });
    prog.push(SockFilter {
        code: BPF_JSET_K,
        jt: jump_to_notif(3),
        jf: 0,
        k: X32_SYSCALL_BIT,
    });
    for nr in tabled {
        let pc = prog.len();
        prog.push(SockFilter {
            code: BPF_JEQ_K,
            jt: jump_to_notif(pc),
            jf: 0,
            k: nr,
        });
    }
    prog.push(SockFilter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });
    prog.push(SockFilter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_USER_NOTIF,
    });
    debug_assert_eq!(prog.len(), len);
    prog
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// a strict cbpf interpreter for the instruction subset the filter uses. it exists so
    /// the tests' expected outcomes come from the bpf semantics in the kernel docs, not
    /// from the construction code: unknown opcodes, out-of-range jumps, out-of-range
    /// loads, and running off the end are all hard errors.
    fn run(prog: &[SockFilter], nr: u32, arch: u32) -> Result<u32, String> {
        let mut acc: u32 = 0;
        let mut pc: usize = 0;
        // a filter this size terminates in far fewer steps; the bound catches loops,
        // which straight-line cbpf cannot have but a broken builder could emit.
        for _ in 0..prog.len() + 1 {
            let insn = prog
                .get(pc)
                .ok_or_else(|| format!("pc {pc} out of range"))?;
            match insn.code {
                BPF_LD_W_ABS => {
                    acc = match insn.k {
                        SECCOMP_DATA_NR => nr,
                        SECCOMP_DATA_ARCH => arch,
                        k => return Err(format!("load from unmodeled offset {k}")),
                    };
                    pc += 1;
                }
                BPF_JEQ_K => {
                    let off = if acc == insn.k { insn.jt } else { insn.jf };
                    pc += 1 + usize::from(off);
                }
                BPF_JSET_K => {
                    let off = if acc & insn.k != 0 { insn.jt } else { insn.jf };
                    pc += 1 + usize::from(off);
                }
                BPF_RET_K => return Ok(insn.k),
                code => return Err(format!("unmodeled opcode {code:#06x}")),
            }
        }
        Err("instruction budget exhausted without a return".to_string())
    }

    fn run_x86_64(nr: u32) -> u32 {
        run(&build_filter(), nr, AUDIT_ARCH_X86_64).expect("filter must terminate")
    }

    #[test]
    fn filter_routes_every_tabled_syscall_to_user_notif() {
        for &nr in MEDIATED.iter().chain(DENIED_RECORDED) {
            assert_eq!(
                run_x86_64(nr),
                SECCOMP_RET_USER_NOTIF,
                "tabled syscall {nr} must trap"
            );
        }
    }

    #[test]
    fn filter_passes_untabled_syscalls_through() {
        // read, write, mmap, getpid, sendmsg, futex: the hot path and the handshake
        // syscalls the child issues after filter install (spawn would deadlock if any
        // of these trapped before the supervisor holds the notify fd).
        for nr in [0, 1, 9, 39, 46, 202] {
            assert_eq!(
                run_x86_64(nr),
                SECCOMP_RET_ALLOW,
                "untabled syscall {nr} must pass through"
            );
        }
    }

    #[test]
    fn filter_routes_x32_bit_numbers_to_user_notif_even_for_allowed_syscalls() {
        // the deny itself is the notify loop's; the filter only routes. an x32 number
        // must never be read against the x86-64 table, so even pass-through numbers
        // trap once bit 30 is set.
        for nr in [0, 1, 39] {
            assert_eq!(run_x86_64(nr | X32_SYSCALL_BIT), SECCOMP_RET_USER_NOTIF);
        }
        for &nr in MEDIATED {
            assert_eq!(run_x86_64(nr | X32_SYSCALL_BIT), SECCOMP_RET_USER_NOTIF);
        }
    }

    #[test]
    fn filter_routes_foreign_arch_to_user_notif() {
        // the deny itself is the notify loop's; the filter only routes. nr is read
        // only after the arch check, so even an "allowed" i386 number traps.
        for nr in [0, 1, 39, nr::OPENAT] {
            assert_eq!(
                run(&build_filter(), nr, AUDIT_ARCH_I386).expect("filter must terminate"),
                SECCOMP_RET_USER_NOTIF
            );
        }
    }

    #[test]
    fn filter_is_well_formed() {
        let prog = build_filter();
        assert!(!prog.is_empty(), "the kernel rejects an empty program");
        assert!(prog.len() <= 4096, "BPF_MAXINSNS is 4096");
        for (pc, insn) in prog.iter().enumerate() {
            match insn.code {
                BPF_JEQ_K | BPF_JSET_K => {
                    for off in [insn.jt, insn.jf] {
                        assert!(
                            pc + 1 + usize::from(off) < prog.len(),
                            "jump at {pc} lands out of range"
                        );
                    }
                }
                BPF_LD_W_ABS | BPF_RET_K => {}
                code => panic!("unexpected opcode {code:#06x} at {pc}"),
            }
        }
        let last = prog.last().expect("non-empty");
        assert_eq!(last.code, BPF_RET_K, "the program must end in a return");
        for insn in &prog {
            if insn.code == BPF_RET_K {
                assert!(
                    insn.k == SECCOMP_RET_ALLOW || insn.k == SECCOMP_RET_USER_NOTIF,
                    "the filter only allows or routes to notif, never kills or errnos"
                );
            }
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn pinned_syscall_numbers_match_libc() {
        // the automated review-against-headers check for the hand-pinned table.
        let pairs: &[(u32, libc::c_long)] = &[
            (nr::OPEN, libc::SYS_open),
            (nr::CREAT, libc::SYS_creat),
            (nr::OPENAT, libc::SYS_openat),
            (nr::OPENAT2, libc::SYS_openat2),
            (nr::TRUNCATE, libc::SYS_truncate),
            (nr::RENAME, libc::SYS_rename),
            (nr::MKDIR, libc::SYS_mkdir),
            (nr::RMDIR, libc::SYS_rmdir),
            (nr::LINK, libc::SYS_link),
            (nr::UNLINK, libc::SYS_unlink),
            (nr::SYMLINK, libc::SYS_symlink),
            (nr::CHMOD, libc::SYS_chmod),
            (nr::CHOWN, libc::SYS_chown),
            (nr::MKDIRAT, libc::SYS_mkdirat),
            (nr::FCHOWNAT, libc::SYS_fchownat),
            (nr::UNLINKAT, libc::SYS_unlinkat),
            (nr::RENAMEAT, libc::SYS_renameat),
            (nr::LINKAT, libc::SYS_linkat),
            (nr::SYMLINKAT, libc::SYS_symlinkat),
            (nr::FCHMODAT, libc::SYS_fchmodat),
            (nr::RENAMEAT2, libc::SYS_renameat2),
            (nr::CLONE, libc::SYS_clone),
            (nr::FORK, libc::SYS_fork),
            (nr::VFORK, libc::SYS_vfork),
            (nr::EXECVE, libc::SYS_execve),
            (nr::EXECVEAT, libc::SYS_execveat),
            (nr::CLONE3, libc::SYS_clone3),
            (nr::PTRACE, libc::SYS_ptrace),
            (nr::PROCESS_VM_READV, libc::SYS_process_vm_readv),
            (nr::PROCESS_VM_WRITEV, libc::SYS_process_vm_writev),
            (nr::PIDFD_GETFD, libc::SYS_pidfd_getfd),
            (nr::CONNECT, libc::SYS_connect),
            (nr::SENDTO, libc::SYS_sendto),
            (nr::BIND, libc::SYS_bind),
            (nr::IO_URING_SETUP, libc::SYS_io_uring_setup),
            (nr::IO_URING_ENTER, libc::SYS_io_uring_enter),
            (nr::IO_URING_REGISTER, libc::SYS_io_uring_register),
        ];
        assert_eq!(pairs.len(), MEDIATED.len() + DENIED_RECORDED.len());
        for &(pinned, libc_nr) in pairs {
            assert_eq!(i64::from(pinned), libc_nr);
        }
    }
}
