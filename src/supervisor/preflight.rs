//! preflight host probes (architecture.md section 5.1, FR-14, ADR-0012).
//!
//! assumptions: this runs before any child exists, in the trusted supervisor at startup,
//! so a probe failure is a clean refusal to run (I3, FR-9), not a mid-run event. the probes
//! read host capabilities and never trust a version string alone: where a capability can be
//! observed it is observed. the selection logic (does this host clear the floor, which
//! snapshot mechanism) is a pure function of the probed facts so it is exhaustively testable
//! without a live kernel; the probing itself is linux-only and thin.

use crate::recorder::{Mode, SnapshotMechanism};

/// the kernel floor: Linux 5.19 (ADR-0012). below this leash refuses to run.
pub const KERNEL_FLOOR: (u32, u32) = (5, 19);

/// the landlock abi the floor guarantees (ABI 2, Linux 5.19).
pub const LANDLOCK_ABI_FLOOR: u32 = 2;

/// host capabilities as probed. the pure evaluator turns these into an outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// the raw `uname` release string, kept for the trace and error messages
    pub kernel_release: String,
    /// parsed (major, minor) of the running kernel
    pub kernel_version: (u32, u32),
    /// seccomp user-notification is present (SECCOMP_GET_NOTIF_SIZES succeeded)
    pub seccomp_unotify: bool,
    /// the kernel recognizes SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (5.19), probed directly.
    /// this is the load-bearing 5.19 capability: without it a supervisor-executed allow can
    /// double-run on a signal (notify-loop.md section 4.1).
    pub wait_killable_recv: bool,
    /// SECCOMP_ADDFD_FLAG_SEND (5.14) is present. derived, not separately probed (ADR-0015):
    /// it was added strictly before wait_killable_recv (5.19), so a kernel that directly
    /// proves wait_killable_recv proves this too. the first live ADDFD in the spawn protocol
    /// (#17) is the behavioral confirmation. this is a proof from a later-added capability,
    /// not an assumption from the version string.
    pub addfd_send: bool,
    /// probed landlock abi version; 0 means landlock is unavailable
    pub landlock_abi: u32,
    /// raw overlay-related facts; the evaluator selects the mechanism from them
    pub overlay: OverlayProbe,
}

/// the facts that decide the snapshot mechanism (snapshot.md section 3, the M0 finding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayProbe {
    /// the kernel has an overlayfs (`overlay` in /proc/filesystems)
    pub kernel_has_overlay: bool,
    /// the supervisor runs as root, so a privileged overlay mount is available
    pub running_as_root: bool,
    /// the host blocks unprivileged user namespaces (e.g. stock Ubuntu 24.04's
    /// apparmor_restrict_unprivileged_userns=1), so a rootless overlay is impossible
    pub unprivileged_userns_restricted: bool,
}

/// the preflight decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// the host clears the floor; run with these capabilities and this mechanism
    Proceed {
        /// the probed capabilities, for stamping into the trace
        caps: Capabilities,
        /// the snapshot mechanism selected for this run
        mechanism: SnapshotMechanism,
        /// why that mechanism was selected (stamped into meta.json)
        mechanism_reason: String,
    },
    /// the host is below the floor; refuse with a message the operator can act on
    Refuse(String),
}

/// decide the preflight outcome from probed capabilities and the run's mode. pure and
/// total: no IO, no panic. `mode` matters because record-only applies no Landlock, so a
/// missing Landlock backstop is not a hard refusal there (architecture.md degrade table);
/// the seccomp floor is required in both modes.
pub fn evaluate(caps: &Capabilities, mode: Mode) -> Outcome {
    // the seccomp floor is non-negotiable in either mode: the whole boundary rests on it.
    // the version check is a hard gate alongside the probes; a backported below-floor
    // kernel is refused even with the capabilities present (ADR-0015).
    if caps.kernel_version < KERNEL_FLOOR {
        return refuse_floor(
            caps,
            &format!(
                "kernel {} is below the required Linux {}.{}",
                caps.kernel_release, KERNEL_FLOOR.0, KERNEL_FLOOR.1
            ),
        );
    }
    if !caps.seccomp_unotify {
        return refuse_floor(caps, "seccomp user-notification is unavailable");
    }
    if !caps.wait_killable_recv {
        return refuse_floor(
            caps,
            "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV is unsupported (a supervisor-executed \
             allow could double-run on a signal without it)",
        );
    }
    if !caps.addfd_send {
        return refuse_floor(caps, "SECCOMP_ADDFD_FLAG_SEND is unsupported");
    }
    // enforce needs the Landlock backstop; record-only applies no ruleset (ADR-0010), so a
    // low ABI only bites an enforce run (FR-14's mode split, recorded in spec v0.5). the
    // floor kernel guarantees ABI 2 regardless.
    if mode == Mode::Enforce && caps.landlock_abi < LANDLOCK_ABI_FLOOR {
        return refuse_floor(
            caps,
            &format!(
                "Landlock ABI {} is below the required ABI {} for enforce mode",
                caps.landlock_abi, LANDLOCK_ABI_FLOOR
            ),
        );
    }

    let (mechanism, mechanism_reason) = select_mechanism(&caps.overlay);
    Outcome::Proceed {
        caps: caps.clone(),
        mechanism,
        mechanism_reason,
    }
}

fn refuse_floor(caps: &Capabilities, why: &str) -> Outcome {
    Outcome::Refuse(format!(
        "leash cannot run on this host: {why}. leash requires Linux {}.{} or later with \
         seccomp user-notification and Landlock (kernel: {}).",
        KERNEL_FLOOR.0, KERNEL_FLOOR.1, caps.kernel_release
    ))
}

/// select the snapshot mechanism from the overlay facts (snapshot.md section 3, ADR-0009).
/// a privileged run always gets overlay; only an unprivileged run on a userns-restricted or
/// overlay-less host falls to the copy mechanism.
fn select_mechanism(probe: &OverlayProbe) -> (SnapshotMechanism, String) {
    if !probe.kernel_has_overlay {
        return (
            SnapshotMechanism::Copy,
            "kernel has no overlayfs; using the copy fallback".to_string(),
        );
    }
    if probe.running_as_root {
        return (
            SnapshotMechanism::Overlay,
            "privileged overlay mount available".to_string(),
        );
    }
    if probe.unprivileged_userns_restricted {
        return (
            SnapshotMechanism::Copy,
            "host restricts unprivileged user namespaces and the run is unprivileged; \
             using the copy fallback"
                .to_string(),
        );
    }
    (
        SnapshotMechanism::Overlay,
        "unprivileged user-namespace overlay available".to_string(),
    )
}

/// run the host probes. linux-only; on any other platform this is a hard refusal, because
/// leash's boundary does not exist off Linux.
#[cfg(target_os = "linux")]
pub fn probe() -> Result<Capabilities, PreflightError> {
    linux::probe()
}

/// off-linux stub so the crate builds and pure logic tests run on a dev mac.
#[cfg(not(target_os = "linux"))]
pub fn probe() -> Result<Capabilities, PreflightError> {
    Err(PreflightError::UnsupportedPlatform)
}

/// errors from probing itself (distinct from a clean below-floor refusal, which is an
/// `Outcome::Refuse`).
#[derive(Debug, thiserror::Error)]
pub enum PreflightError {
    /// leash was built or run on a non-Linux platform
    #[error("leash runs only on Linux")]
    UnsupportedPlatform,
    /// a probe syscall failed unexpectedly
    #[error("host probe failed: {0}")]
    Probe(String),
}

/// parse a `uname` release like `6.8.0-124-generic` into (major, minor). tolerant of the
/// distro suffix; pure so it is unit-tested directly.
pub fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split(['.', '-']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{Capabilities, OverlayProbe, PreflightError, parse_kernel_version};
    use std::ffi::CStr;

    // constants not always exposed by the libc crate; values are stable kernel ABI.
    const SECCOMP_GET_NOTIF_SIZES: libc::c_uint = 3;
    const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
    const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
    const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: libc::c_ulong = 1 << 4;
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_ulong = 1 << 0;

    pub fn probe() -> Result<Capabilities, PreflightError> {
        let (kernel_release, kernel_version) = uname()?;
        let wait_killable_recv = probe_wait_killable_recv();
        Ok(Capabilities {
            kernel_release,
            kernel_version,
            seccomp_unotify: probe_unotify(),
            wait_killable_recv,
            // derived from wait_killable_recv (field doc, ADR-0015): 5.14 < 5.19.
            addfd_send: wait_killable_recv,
            landlock_abi: probe_landlock_abi(),
            overlay: probe_overlay(),
        })
    }

    fn uname() -> Result<(String, (u32, u32)), PreflightError> {
        // SAFETY: utsname is a plain C struct we fully own and zero before the call; uname
        // only writes into it. we read the nul-terminated release field back through CStr.
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::uname(&mut uts) };
        if rc != 0 {
            return Err(PreflightError::Probe("uname failed".into()));
        }
        // SAFETY: uname nul-terminates release within its fixed buffer.
        let release = unsafe { CStr::from_ptr(uts.release.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        let version = parse_kernel_version(&release).ok_or_else(|| {
            PreflightError::Probe(format!("unparseable kernel release {release}"))
        })?;
        Ok((release, version))
    }

    fn probe_unotify() -> bool {
        let mut sizes = [0u8; 24]; // struct seccomp_notif_sizes is 3 x u16, padded
        // SAFETY: SECCOMP_GET_NOTIF_SIZES only writes the sizes struct; the buffer is large
        // enough and owned by us. a nonzero return just means the op is unsupported.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_GET_NOTIF_SIZES,
                0,
                sizes.as_mut_ptr(),
            )
        };
        rc == 0
    }

    fn probe_wait_killable_recv() -> bool {
        // probe the flag without installing anything: pass NEW_LISTENER | WAIT_KILLABLE_RECV
        // with a NULL program. the kernel validates the flag mask first. if WAIT_KILLABLE_RECV
        // is unknown (pre-5.19) it returns EINVAL from the mask check. if it is known, the
        // call proceeds past the mask check and fails later on the NULL program (EFAULT) or on
        // the missing no_new_privs (EACCES) - either of which proves the flag is recognized.
        // no filter is ever installed because the call errors out before install.
        let flags = SECCOMP_FILTER_FLAG_NEW_LISTENER | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
        // SAFETY: a NULL filter pointer guarantees the call cannot install a filter; it can
        // only return an error. we inspect errno to classify.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                flags,
                std::ptr::null::<libc::c_void>(),
            )
        };
        debug_assert_eq!(rc, -1, "NULL-program seccomp must fail");
        let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        err != libc::EINVAL
    }

    fn probe_landlock_abi() -> u32 {
        // landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION) returns the abi
        // version as a positive int, or -1 (EOPNOTSUPP / ENOSYS) if landlock is off.
        // SAFETY: the version query takes a NULL attr and zero size by ABI contract; it
        // creates no ruleset and returns only a version number or an error.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if rc > 0 { rc as u32 } else { 0 }
    }

    fn probe_overlay() -> OverlayProbe {
        let kernel_has_overlay = std::fs::read_to_string("/proc/filesystems")
            .map(|s| s.lines().any(|l| l.split('\t').any(|f| f == "overlay")))
            .unwrap_or(false);

        // SAFETY: geteuid is a trivial pure syscall with no arguments and no side effects.
        let running_as_root = unsafe { libc::geteuid() } == 0;

        let unprivileged_userns_restricted = userns_restricted();

        OverlayProbe {
            kernel_has_overlay,
            running_as_root,
            unprivileged_userns_restricted,
        }
    }

    fn userns_restricted() -> bool {
        // ubuntu's apparmor knob: 1 means unprivileged userns creation is blocked.
        if let Ok(v) =
            std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            && v.trim() == "1"
        {
            return true;
        }
        // a zero cap on user namespaces is the other common lockout.
        if let Ok(v) = std::fs::read_to_string("/proc/sys/user/max_user_namespaces")
            && v.trim() == "0"
        {
            return true;
        }
        false
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn caps_ok() -> Capabilities {
        Capabilities {
            kernel_release: "6.8.0-124-generic".into(),
            kernel_version: (6, 8),
            seccomp_unotify: true,
            wait_killable_recv: true,
            addfd_send: true,
            landlock_abi: 4,
            overlay: OverlayProbe {
                kernel_has_overlay: true,
                running_as_root: true,
                unprivileged_userns_restricted: false,
            },
        }
    }

    #[test]
    fn parses_kernel_versions_with_distro_suffixes() {
        assert_eq!(parse_kernel_version("6.8.0-124-generic"), Some((6, 8)));
        assert_eq!(parse_kernel_version("5.19.0"), Some((5, 19)));
        assert_eq!(parse_kernel_version("6.1"), Some((6, 1)));
        assert_eq!(parse_kernel_version("garbage"), None);
    }

    #[test]
    fn a_clean_host_proceeds_with_privileged_overlay() {
        match evaluate(&caps_ok(), Mode::Enforce) {
            Outcome::Proceed {
                mechanism,
                mechanism_reason,
                ..
            } => {
                assert_eq!(mechanism, SnapshotMechanism::Overlay);
                assert!(mechanism_reason.contains("privileged"));
            }
            Outcome::Refuse(m) => panic!("clean host refused: {m}"),
        }
    }

    #[test]
    fn below_the_kernel_floor_refuses_in_both_modes() {
        let mut caps = caps_ok();
        caps.kernel_version = (5, 15);
        caps.kernel_release = "5.15.0-generic".into();
        for mode in [Mode::RecordOnly, Mode::Enforce] {
            let out = evaluate(&caps, mode);
            assert!(
                matches!(out, Outcome::Refuse(_)),
                "5.15 must refuse in {mode:?}"
            );
            if let Outcome::Refuse(m) = out {
                assert!(m.contains("5.15"), "message names the offending kernel");
            }
        }
    }

    #[test]
    fn missing_wait_killable_recv_refuses_even_on_a_new_kernel() {
        let mut caps = caps_ok();
        caps.wait_killable_recv = false;
        assert!(matches!(
            evaluate(&caps, Mode::RecordOnly),
            Outcome::Refuse(_)
        ));
    }

    #[test]
    fn low_landlock_abi_refuses_enforce_but_allows_record_only() {
        let mut caps = caps_ok();
        caps.landlock_abi = 1;
        assert!(
            matches!(evaluate(&caps, Mode::Enforce), Outcome::Refuse(_)),
            "enforce needs the ABI-2 backstop"
        );
        assert!(
            matches!(evaluate(&caps, Mode::RecordOnly), Outcome::Proceed { .. }),
            "record-only applies no Landlock, so a low ABI is not a floor breach"
        );
    }

    #[test]
    fn userns_restricted_unprivileged_run_falls_back_to_copy() {
        let mut caps = caps_ok();
        caps.overlay.running_as_root = false;
        caps.overlay.unprivileged_userns_restricted = true;
        match evaluate(&caps, Mode::RecordOnly) {
            Outcome::Proceed {
                mechanism,
                mechanism_reason,
                ..
            } => {
                assert_eq!(mechanism, SnapshotMechanism::Copy);
                assert!(mechanism_reason.contains("unprivileged"));
            }
            Outcome::Refuse(m) => panic!("should proceed on copy fallback: {m}"),
        }
    }

    #[test]
    fn userns_restricted_privileged_run_still_gets_overlay() {
        let mut caps = caps_ok();
        caps.overlay.running_as_root = true;
        caps.overlay.unprivileged_userns_restricted = true;
        match evaluate(&caps, Mode::RecordOnly) {
            Outcome::Proceed { mechanism, .. } => {
                assert_eq!(mechanism, SnapshotMechanism::Overlay);
            }
            Outcome::Refuse(m) => panic!("privileged run should get overlay: {m}"),
        }
    }

    #[test]
    fn no_kernel_overlay_falls_back_to_copy() {
        let mut caps = caps_ok();
        caps.overlay.kernel_has_overlay = false;
        match evaluate(&caps, Mode::RecordOnly) {
            Outcome::Proceed { mechanism, .. } => assert_eq!(mechanism, SnapshotMechanism::Copy),
            Outcome::Refuse(m) => panic!("copy fallback should proceed: {m}"),
        }
    }
}
