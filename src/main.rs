//! the leash binary: a thin shell over the library's cli module.

use std::process::ExitCode;

fn main() -> ExitCode {
    leash::cli::run()
}
