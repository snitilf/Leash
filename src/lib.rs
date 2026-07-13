//! leash: supervise an AI coding agent at the OS boundary.
//!
//! the crate is a library with a thin binary so behavior is testable at module seams
//! and by integration tests. modules follow docs/design/architecture.md section 4.

pub mod cli;
pub mod measure;
pub mod policy;
pub mod recorder;
pub mod sandbox;
pub mod snapshot;
pub mod supervisor;
