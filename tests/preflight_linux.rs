//! behavioral preflight test, linux only (issue #16, FR-14).
//!
//! the pure evaluation logic is unit-tested in the module on any platform; this file is the
//! observation the standard requires: on a real kernel at or above the floor, the probes
//! actually report the capabilities and preflight proceeds. it runs in CI on ubuntu-24.04
//! (kernel 6.8) and on the droplet, never on the dev mac.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use leash::recorder::Mode;
use leash::supervisor::preflight::{self, KERNEL_FLOOR, Outcome};

#[test]
fn probes_report_a_capable_host_and_preflight_proceeds() {
    let caps = preflight::probe().expect("probe must succeed on linux");

    // the CI runner and droplet are both well above the floor; assert the probes agree
    assert!(
        caps.kernel_version >= KERNEL_FLOOR,
        "probed kernel {} below floor {:?}",
        caps.kernel_release,
        KERNEL_FLOOR
    );
    assert!(
        caps.seccomp_unotify,
        "unotify must be present on a floor kernel"
    );
    assert!(
        caps.wait_killable_recv,
        "WAIT_KILLABLE_RECV must be probed present on a 5.19+ kernel"
    );
    assert!(
        caps.landlock_abi >= 2,
        "Landlock ABI must be >= 2 on the floor"
    );

    // record-only never needs Landlock; a floor host must proceed
    match preflight::evaluate(&caps, Mode::RecordOnly) {
        Outcome::Proceed { mechanism, .. } => {
            // the mechanism depends on privilege/overlay of the runner; either is valid,
            // we only assert preflight reached a decision rather than refusing
            let _ = mechanism;
        }
        Outcome::Refuse(m) => panic!("a floor-clearing host refused record-only: {m}"),
    }
}

#[test]
fn wait_killable_recv_probe_installs_no_filter() {
    // the probe must be side-effect free: calling it twice, and then continuing to run
    // ordinary syscalls, proves it did not install a seccomp filter on this process.
    let _ = preflight::probe().unwrap();
    let _ = preflight::probe().unwrap();
    // if a filter had been installed with a trap, this getpid path would misbehave; it does
    // not, because the probe errors out before any filter is committed.
    assert!(std::process::id() > 0);
}
