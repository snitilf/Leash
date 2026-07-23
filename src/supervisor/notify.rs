//! seccomp user-notification abi: struct layouts, ioctl encodings, and the safe
//! notify-fd wrapper (include/uapi/linux/seccomp.h; ADR-0016).
//!
//! assumptions: everything in a received notification is a kernel-trusted snapshot
//! taken at trap time, but it describes a hostile process; pointer arguments inside
//! `data.args` must never be dereferenced directly, only read via the notify-loop
//! rules (docs/design/notify-loop.md). struct layouts and constants are hand-defined
//! stable kernel abi, reviewed against the header and pinned by unit tests. raw fds
//! do not leak past this module: the notify fd lives in an `OwnedFd`, injected fds
//! are passed as `BorrowedFd`.
//!
//! the layouts and encodings are pure and build on any host; the ioctl calls are
//! linux-only.

// seccomp(2) operations and filter flags, shared with preflight's probes and the
// child's filter install. not always exposed by the libc crate; stable kernel abi.
// linux-only like their callers, so the macos build carries no dead constants.
#[cfg(target_os = "linux")]
pub(crate) const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
#[cfg(target_os = "linux")]
pub(crate) const SECCOMP_GET_NOTIF_SIZES: libc::c_uint = 3;
#[cfg(target_os = "linux")]
pub(crate) const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
#[cfg(target_os = "linux")]
pub(crate) const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: libc::c_ulong = 1 << 4;

/// response flag: let the kernel execute the trapped syscall (allow). safe only for
/// decisions made on the syscall number or scalar arguments (syscalls.md section 4).
pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u64 = 1;

/// addfd flag: install into a specific fd number in the target instead of the lowest free.
pub const SECCOMP_ADDFD_FLAG_SETFD: u32 = 1;
/// addfd flag: atomically complete the blocked syscall with the new fd as its return value.
pub const SECCOMP_ADDFD_FLAG_SEND: u32 = 2;

/// the syscall snapshot taken at trap time (`struct seccomp_data`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SeccompData {
    /// syscall number, in the arch's numbering.
    pub nr: i32,
    /// audit arch token of the entry path.
    pub arch: u32,
    /// instruction pointer at trap time.
    pub instruction_pointer: u64,
    /// the six raw syscall arguments; pointers here point into child memory.
    pub args: [u64; 6],
}

/// one received notification (`struct seccomp_notif`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SeccompNotif {
    /// unique cookie for this notification; every response and validity check names it.
    pub id: u64,
    /// pid of the trapped thread.
    pub pid: u32,
    /// unused by the kernel today; zero.
    pub flags: u32,
    /// the syscall snapshot.
    pub data: SeccompData,
}

/// the supervisor's response (`struct seccomp_notif_resp`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SeccompNotifResp {
    /// the notification this responds to.
    pub id: u64,
    /// spoofed return value when `error` is zero and CONTINUE is not set.
    pub val: i64,
    /// negative errno to fail the syscall with, or zero.
    pub error: i32,
    /// response flags (`SECCOMP_USER_NOTIF_FLAG_CONTINUE` or zero).
    pub flags: u32,
}

/// fd-injection request (`struct seccomp_notif_addfd`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SeccompNotifAddfd {
    /// the notification this injects into.
    pub id: u64,
    /// addfd flags (`SECCOMP_ADDFD_FLAG_SETFD`, `SECCOMP_ADDFD_FLAG_SEND`).
    pub flags: u32,
    /// the supervisor-side fd to copy into the target.
    pub srcfd: u32,
    /// target fd number when SETFD is set.
    pub newfd: u32,
    /// flags for the new fd (`O_CLOEXEC`).
    pub newfd_flags: u32,
}

/// kernel-reported sizes of the notification structs (`struct seccomp_notif_sizes`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SeccompNotifSizes {
    /// size of the kernel's `struct seccomp_notif`.
    pub seccomp_notif: u16,
    /// size of the kernel's `struct seccomp_notif_resp`.
    pub seccomp_notif_resp: u16,
    /// size of the kernel's `struct seccomp_data`.
    pub seccomp_data: u16,
}

// ioctl encoding: dir in the top two bits, then size, type ('!' for seccomp), nr.
// mirrors _IOC in include/uapi/asm-generic/ioctl.h.
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;
const SECCOMP_IOC_MAGIC: u32 = b'!' as u32;

const fn ioc(dir: u32, nr: u32, size: u32) -> u64 {
    ((dir << 30) | (size << 16) | (SECCOMP_IOC_MAGIC << 8) | nr) as u64
}

const fn iowr(nr: u32, size: usize) -> u64 {
    ioc(IOC_READ | IOC_WRITE, nr, size as u32)
}

const fn iow(nr: u32, size: usize) -> u64 {
    ioc(IOC_WRITE, nr, size as u32)
}

/// receive one notification.
pub const SECCOMP_IOCTL_NOTIF_RECV: u64 = iowr(0, size_of::<SeccompNotif>());
/// respond to a notification.
pub const SECCOMP_IOCTL_NOTIF_SEND: u64 = iowr(1, size_of::<SeccompNotifResp>());
/// check that a notification id is still alive before acting on it.
pub const SECCOMP_IOCTL_NOTIF_ID_VALID: u64 = iow(2, size_of::<u64>());
/// inject an fd into the blocked target.
pub const SECCOMP_IOCTL_NOTIF_ADDFD: u64 = iow(3, size_of::<SeccompNotifAddfd>());

#[cfg(target_os = "linux")]
pub use linux::NotifyFd;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::io;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};

    /// the supervisor's end of a seccomp user-notification listener.
    ///
    /// owns the fd for its whole life; dropping it closes the listener, which fails
    /// every pending and future trapped syscall in the child closed (ENOSYS) - the
    /// kernel-driven half of I3.
    #[derive(Debug)]
    pub struct NotifyFd {
        fd: OwnedFd,
        notif_size: usize,
    }

    impl AsFd for NotifyFd {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.fd.as_fd()
        }
    }

    impl AsRawFd for NotifyFd {
        fn as_raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }
    }

    impl NotifyFd {
        /// wrap a notify fd received from the child's handshake. queries the kernel's
        /// struct sizes once; `recv` buffers are sized from them.
        pub fn new(fd: OwnedFd) -> io::Result<Self> {
            let mut sizes = SeccompNotifSizes::default();
            // SAFETY: GET_NOTIF_SIZES writes exactly a seccomp_notif_sizes into the
            // pointed-to struct, which we own and outlives the call.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_seccomp,
                    SECCOMP_GET_NOTIF_SIZES,
                    0,
                    &raw mut sizes,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                fd,
                notif_size: usize::from(sizes.seccomp_notif),
            })
        }

        /// block until one notification arrives.
        ///
        /// the kernel requires the receive buffer zeroed (EINVAL otherwise) and sized
        /// to its own struct, which a newer kernel may have grown past ours; the
        /// buffer covers the larger of the two and the result is read from the prefix
        /// this crate's layout describes.
        pub fn recv(&self) -> io::Result<SeccompNotif> {
            let bytes = self.notif_size.max(size_of::<SeccompNotif>());
            // u64 elements keep the buffer aligned for the u64 fields; zeroed as the
            // kernel demands.
            let mut buf = vec![0u64; bytes.div_ceil(8)];
            // SAFETY: the buffer is at least the kernel's seccomp_notif size, zeroed,
            // and exclusively ours; RECV writes one notification into it.
            let rc = unsafe {
                libc::ioctl(
                    self.fd.as_raw_fd(),
                    SECCOMP_IOCTL_NOTIF_RECV as libc::c_ulong,
                    buf.as_mut_ptr(),
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the buffer holds at least size_of::<SeccompNotif>() bytes written
            // by the kernel in this layout, and the u64 backing keeps it aligned.
            Ok(unsafe { *buf.as_ptr().cast::<SeccompNotif>() })
        }

        /// allow the trapped syscall to execute (CONTINUE). safe only for decisions
        /// made on scalars; never after validating child memory (TOCTOU).
        pub fn send_continue(&self, id: u64) -> io::Result<()> {
            self.send(SeccompNotifResp {
                id,
                val: 0,
                error: 0,
                flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
            })
        }

        /// fail the trapped syscall with `errno`.
        pub fn send_error(&self, id: u64, errno: i32) -> io::Result<()> {
            self.send(SeccompNotifResp {
                id,
                val: 0,
                error: -errno.abs(),
                flags: 0,
            })
        }

        /// complete the trapped syscall with a successful scalar return value.
        pub fn send_success(&self, id: u64, value: i64) -> io::Result<()> {
            self.send(SeccompNotifResp {
                id,
                val: value,
                error: 0,
                flags: 0,
            })
        }

        fn send(&self, resp: SeccompNotifResp) -> io::Result<()> {
            // SAFETY: SEND reads exactly a seccomp_notif_resp from the pointed-to
            // struct, which we own and outlives the call.
            let rc = unsafe {
                libc::ioctl(
                    self.fd.as_raw_fd(),
                    SECCOMP_IOCTL_NOTIF_SEND as libc::c_ulong,
                    &raw const resp,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// copy `srcfd` into the blocked target. with `SECCOMP_ADDFD_FLAG_SEND` the
        /// kernel also completes the trapped syscall with the new fd number as its
        /// return, atomically with the injection. returns the fd number in the target.
        pub fn send_addfd(
            &self,
            id: u64,
            srcfd: BorrowedFd<'_>,
            flags: u32,
            newfd_flags: u32,
        ) -> io::Result<i32> {
            let req = SeccompNotifAddfd {
                id,
                flags,
                srcfd: srcfd.as_raw_fd() as u32,
                newfd: 0,
                newfd_flags,
            };
            // SAFETY: ADDFD reads exactly a seccomp_notif_addfd from the pointed-to
            // struct, which we own and outlives the call; srcfd is borrowed for the
            // duration, so it stays open across the injection.
            let rc = unsafe {
                libc::ioctl(
                    self.fd.as_raw_fd(),
                    SECCOMP_IOCTL_NOTIF_ADDFD as libc::c_ulong,
                    &raw const req,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(rc)
        }

        /// check whether a notification is still alive (the target has not died and
        /// the id has not been reused). required before acting on child state.
        pub fn id_valid(&self, id: u64) -> io::Result<bool> {
            // SAFETY: ID_VALID reads exactly a u64 from the pointed-to value, which we
            // own and outlives the call.
            let rc = unsafe {
                libc::ioctl(
                    self.fd.as_raw_fd(),
                    SECCOMP_IOCTL_NOTIF_ID_VALID as libc::c_ulong,
                    &raw const id,
                )
            };
            if rc == 0 {
                return Ok(true);
            }
            match io::Error::last_os_error() {
                e if e.raw_os_error() == Some(libc::ENOENT) => Ok(false),
                e => Err(e),
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_encodings_match_kernel_values() {
        // pinned against the values _IOC produces for include/uapi/linux/seccomp.h;
        // a layout mistake in any struct shifts the size field and breaks this.
        assert_eq!(SECCOMP_IOCTL_NOTIF_RECV, 0xc050_2100);
        assert_eq!(SECCOMP_IOCTL_NOTIF_SEND, 0xc018_2101);
        assert_eq!(SECCOMP_IOCTL_NOTIF_ID_VALID, 0x4008_2102);
        assert_eq!(SECCOMP_IOCTL_NOTIF_ADDFD, 0x4018_2103);
    }

    #[test]
    fn struct_layouts_match_the_kernel_header() {
        // sizes from include/uapi/linux/seccomp.h at the 5.19 floor.
        assert_eq!(size_of::<SeccompData>(), 64);
        assert_eq!(size_of::<SeccompNotif>(), 80);
        assert_eq!(size_of::<SeccompNotifResp>(), 24);
        assert_eq!(size_of::<SeccompNotifAddfd>(), 24);
        assert_eq!(size_of::<SeccompNotifSizes>(), 6);
        assert_eq!(align_of::<SeccompNotif>(), 8);
    }
}
