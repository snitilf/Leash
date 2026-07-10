//! bounded reads of child memory via /proc/&lt;pid&gt;/mem (docs/design/notify-loop.md
//! section 2).
//!
//! assumptions: every value behind a child pointer is hostile input. reads are
//! size-capped at the kernel's own limits, fixed at slate 2; an over-cap or failed read
//! is not an error to recover from but a case-c deny, which the caller resolves. the
//! caller brackets each read with ID_VALID; this module only moves the bytes. the cap
//! and nul-scanning logic is pure and tested on any host; only the /proc open is
//! linux-only.

use std::io;

/// cap for a path read: PATH_MAX (notify-loop.md section 2).
pub const PATH_READ_CAP: usize = 4096;
/// the absolute ceiling for any single child-memory read: one page.
pub const ABSOLUTE_READ_CAP: usize = 4096;
/// bytes of `struct open_how` the loop needs: the leading u64 `flags` field.
pub const OPEN_HOW_FLAGS_SIZE: usize = 8;

/// why a child-memory read could not produce a trusted value. every variant resolves to
/// deny (case C): a fact that cannot be trusted cannot be allowed (I4).
#[derive(Debug, thiserror::Error)]
pub enum MemReadError {
    /// the read itself failed (unmapped address, dead process, permission)
    #[error("child memory read failed: {0}")]
    Io(#[from] io::Error),
    /// no nul terminator within the cap; a longer value than the kernel itself would
    /// accept is hostile by definition
    #[error("no nul terminator within the {0}-byte cap")]
    NoNulWithinCap(usize),
    /// the read returned fewer bytes than the fixed-size value needs
    #[error("short read: wanted {wanted} bytes, got {got}")]
    Short {
        /// bytes the value needs
        wanted: usize,
        /// bytes the read produced
        got: usize,
    },
}

/// read a nul-terminated string starting at `addr`, through `read_at`, up to `cap`
/// bytes. reads chunk by chunk, never past the next page boundary in one call, because a
/// single full-cap read fails EIO when the string sits near the end of a mapping; the
/// chunking is what makes legitimate paths near mapping ends readable while the cap
/// still bounds the total.
pub fn read_cstr_capped(
    mut read_at: impl FnMut(u64, &mut [u8]) -> io::Result<usize>,
    addr: u64,
    cap: usize,
) -> Result<Vec<u8>, MemReadError> {
    const PAGE: u64 = 4096;
    let cap = cap.min(ABSOLUTE_READ_CAP);
    let mut out: Vec<u8> = Vec::new();

    while out.len() < cap {
        let pos = addr + out.len() as u64;
        // stay inside the current page and inside the cap
        let to_page = (PAGE - (pos % PAGE)) as usize;
        let want = to_page.min(cap - out.len());
        let mut buf = vec![0u8; want];

        let mut got = 0;
        while got < want {
            match read_at(pos + got as u64, &mut buf[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                // a failure after the nul would have been reached must not deny a
                // readable value, so scan what we have before surfacing the error
                Err(e) => {
                    if let Some(nul) = buf[..got].iter().position(|&b| b == 0) {
                        out.extend_from_slice(&buf[..nul]);
                        return Ok(out);
                    }
                    return Err(MemReadError::Io(e));
                }
            }
        }

        if let Some(nul) = buf[..got].iter().position(|&b| b == 0) {
            out.extend_from_slice(&buf[..nul]);
            return Ok(out);
        }
        out.extend_from_slice(&buf[..got]);
        if got < want {
            // end of readable memory with no nul: nothing more can arrive
            return Err(MemReadError::Io(io::Error::other(
                "mapping ended before a nul terminator",
            )));
        }
    }
    Err(MemReadError::NoNulWithinCap(cap))
}

/// read exactly `len` bytes at `addr` through `read_at`. for fixed-size structs
/// (`open_how` flags); `len` is capped at one page.
pub fn read_exact_capped(
    mut read_at: impl FnMut(u64, &mut [u8]) -> io::Result<usize>,
    addr: u64,
    len: usize,
) -> Result<Vec<u8>, MemReadError> {
    let len = len.min(ABSOLUTE_READ_CAP);
    let mut buf = vec![0u8; len];
    let mut got = 0;
    while got < len {
        match read_at(addr + got as u64, &mut buf[got..])? {
            0 => return Err(MemReadError::Short { wanted: len, got }),
            n => got += n,
        }
    }
    Ok(buf)
}

/// the real reader over /proc/&lt;pid&gt;/mem.
#[cfg(target_os = "linux")]
pub mod proc {
    use super::{MemReadError, PATH_READ_CAP};
    use std::fs::File;
    use std::os::unix::fs::FileExt;

    /// one child's memory, opened once per notification burst.
    pub struct ChildMem {
        mem: File,
    }

    impl ChildMem {
        /// open /proc/&lt;pid&gt;/mem for the trapped child.
        pub fn open(pid: u32) -> Result<Self, MemReadError> {
            let mem = File::open(format!("/proc/{pid}/mem"))?;
            Ok(Self { mem })
        }

        /// read the nul-terminated path at `addr`, capped at PATH_MAX.
        pub fn read_path(&self, addr: u64) -> Result<Vec<u8>, MemReadError> {
            super::read_cstr_capped(|pos, buf| self.mem.read_at(buf, pos), addr, PATH_READ_CAP)
        }

        /// read `len` bytes at `addr` (fixed-size struct fields).
        pub fn read_exact(&self, addr: u64, len: usize) -> Result<Vec<u8>, MemReadError> {
            super::read_exact_capped(|pos, buf| self.mem.read_at(buf, pos), addr, len)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// fake memory: a flat buffer starting at `base`; reads outside it fail like an
    /// unmapped address, reads crossing the end are short like a mapping edge.
    struct FakeMem {
        base: u64,
        bytes: Vec<u8>,
    }

    impl FakeMem {
        fn read_at(&self, pos: u64, buf: &mut [u8]) -> io::Result<usize> {
            if pos < self.base || pos >= self.base + self.bytes.len() as u64 {
                return Err(io::Error::other("unmapped"));
            }
            let start = (pos - self.base) as usize;
            let n = buf.len().min(self.bytes.len() - start);
            buf[..n].copy_from_slice(&self.bytes[start..start + n]);
            Ok(n)
        }
    }

    fn read_str(mem: &FakeMem, addr: u64, cap: usize) -> Result<Vec<u8>, MemReadError> {
        read_cstr_capped(|pos, buf| mem.read_at(pos, buf), addr, cap)
    }

    #[test]
    fn reads_a_short_path_at_a_page_aligned_address() {
        let mem = FakeMem {
            base: 0x1000,
            bytes: b"/etc/hosts\0garbage".to_vec(),
        };
        assert_eq!(
            read_str(&mem, 0x1000, PATH_READ_CAP).unwrap(),
            b"/etc/hosts"
        );
    }

    #[test]
    fn reads_a_string_that_ends_at_the_edge_of_the_mapping() {
        // the whole point of chunked reads: the nul is the mapping's last byte, and a
        // naive full-cap read from addr would fail before producing it
        let mut bytes = vec![b'a'; 4096];
        bytes[4095] = 0;
        let mem = FakeMem {
            base: 0x2000,
            bytes,
        };
        let got = read_str(&mem, 0x2000 + 4000, PATH_READ_CAP).unwrap();
        assert_eq!(got, vec![b'a'; 95]);
    }

    #[test]
    fn a_string_crossing_a_page_boundary_is_assembled_from_chunks() {
        let mut bytes = vec![b'x'; 8192];
        bytes[5000] = 0;
        let mem = FakeMem {
            base: 0x10_000,
            bytes,
        };
        // starts 96 bytes before the page boundary, ends 904 after it
        let got = read_str(&mem, 0x10_000 + 4000, PATH_READ_CAP).unwrap();
        assert_eq!(got.len(), 1000);
    }

    #[test]
    fn over_cap_resolves_to_no_nul_within_cap() {
        let mem = FakeMem {
            base: 0x1000,
            bytes: vec![b'a'; 8192],
        };
        match read_str(&mem, 0x1000, PATH_READ_CAP) {
            Err(MemReadError::NoNulWithinCap(cap)) => assert_eq!(cap, PATH_READ_CAP),
            other => panic!("expected NoNulWithinCap, got {other:?}"),
        }
    }

    #[test]
    fn the_absolute_ceiling_bounds_any_requested_cap() {
        let mem = FakeMem {
            base: 0x1000,
            bytes: vec![b'a'; 16384],
        };
        match read_str(&mem, 0x1000, 16384) {
            Err(MemReadError::NoNulWithinCap(cap)) => assert_eq!(cap, ABSOLUTE_READ_CAP),
            other => panic!("expected NoNulWithinCap at the ceiling, got {other:?}"),
        }
    }

    #[test]
    fn an_unmapped_address_is_an_io_error() {
        let mem = FakeMem {
            base: 0x1000,
            bytes: b"/x\0".to_vec(),
        };
        assert!(matches!(
            read_str(&mem, 0xdead_0000, PATH_READ_CAP),
            Err(MemReadError::Io(_))
        ));
    }

    #[test]
    fn a_mapping_ending_without_a_nul_is_an_error_not_a_truncated_value() {
        let mem = FakeMem {
            base: 0x1000,
            bytes: vec![b'a'; 100],
        };
        assert!(matches!(
            read_str(&mem, 0x1000, PATH_READ_CAP),
            Err(MemReadError::Io(_))
        ));
    }

    #[test]
    fn read_exact_returns_fixed_size_values_and_shorts_are_errors() {
        let mem = FakeMem {
            base: 0x1000,
            bytes: vec![7u8; 8],
        };
        let got = read_exact_capped(|p, b| mem.read_at(p, b), 0x1000, 8).unwrap();
        assert_eq!(got, vec![7u8; 8]);
        assert!(matches!(
            read_exact_capped(|p, b| mem.read_at(p, b), 0x1000 + 4, 8),
            Err(MemReadError::Io(_) | MemReadError::Short { .. })
        ));
    }
}
