//! helpers shared by the integration tests that need a delegated cgroup.

#![cfg(target_os = "linux")]
#![allow(dead_code)]

use leash::supervisor::run_cgroup::CgroupParent;

/// true when this process can create run cgroups under its own cgroup. when it cannot,
/// the caller must skip: the test fails instead when `LEASH_REQUIRE_FREEZER=1`, which is
/// how the CI leg that provisions a delegated cgroup proves the tests really ran.
pub fn delegated_cgroup_or_skip(test: &str) -> bool {
    match CgroupParent::locate() {
        Ok(_) => true,
        Err(e) => {
            assert!(
                std::env::var("LEASH_REQUIRE_FREEZER").as_deref() != Ok("1"),
                "LEASH_REQUIRE_FREEZER=1 but no delegated cgroup is available: {e}"
            );
            eprintln!("skipping {test}: no delegated cgroup is available ({e})");
            false
        }
    }
}
