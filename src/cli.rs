//! argument parsing and subcommand dispatch (run, rewind, diff, run management).
//!
//! assumptions: argv comes from the trusted operator; nothing here reads child-controlled
//! data. the cli selects and stamps the mode (FR-19) but never decides a syscall.

use std::process::ExitCode;

/// entry point for the binary; parses argv and dispatches.
pub fn run() -> ExitCode {
    // subcommands land with issue #20; until then the binary states its incompleteness
    eprintln!("leash: not implemented yet (M1 in progress, see issues #15-#20)");
    ExitCode::from(2)
}
