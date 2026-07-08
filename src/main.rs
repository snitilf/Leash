//! leash: supervise an AI coding agent at the OS boundary.
//!
//! the binary wires the modules of docs/design/architecture.md section 4 together.
//! nothing here makes security decisions; those live behind the module seams.

mod cli;
mod policy;
mod recorder;
mod sandbox;
mod snapshot;
mod supervisor;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::run()
}
