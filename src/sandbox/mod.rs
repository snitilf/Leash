//! seccomp filter construction and landlock ruleset application (docs/design/syscalls.md,
//! architecture.md section 5.2).
//!
//! assumptions: this module runs partly in the child between fork and exec, where only
//! async-signal-safe operations are sound. the filter pins the architecture and routes
//! x32-bit-30 numbers to the notif return, where the supervisor denies them; the mediated
//! set is a tier:2 surface and changes to it require the escape tests of
//! docs/design/escapes.md. landlock is applied by the child because a process can only
//! restrict itself; failure to establish any part of the boundary aborts before exec (I3).

pub mod filter;

#[cfg(target_os = "linux")]
pub mod child;

pub use filter::{SockFilter, build_filter};
