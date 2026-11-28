//! the notify loop and run orchestration (docs/design/notify-loop.md, architecture.md
//! section 5).
//!
//! assumptions: single decision thread (ADR-0011); one notification fully handled before
//! the next. every pointer argument read from the child is hostile input, bounded and
//! bracketed by ID_VALID. every error path in this module resolves to deny (I3); there is
//! no default-allow branch to fall into. record precedes respond: an action the recorder
//! cannot write does not happen.

pub mod ask;
#[cfg(target_os = "linux")]
pub mod barrier;
#[cfg(target_os = "linux")]
pub mod broker;
#[cfg(target_os = "linux")]
pub mod cgroup;
pub mod cgroup_mounts;
pub mod fact;
pub mod mem;
pub mod notify;
pub mod preflight;
pub mod run;
#[cfg(target_os = "linux")]
pub mod run_cgroup;
pub mod session;
#[cfg(target_os = "linux")]
pub mod spawn;
pub mod state_root;
pub mod workspace_lock;
