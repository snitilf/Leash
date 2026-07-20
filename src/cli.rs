//! argument parsing and subcommand dispatch (run, rewind, diff, run management).
//!
//! assumptions: argv comes from the trusted operator; nothing here reads child-controlled
//! data. the cli selects and stamps the mode (FR-19) but never decides a syscall. this module
//! covers parsing, attendance, and state-root resolution (docs/design/cli.md sections 1, 3, 4);
//! it does not orchestrate the run itself (section 7, that belongs to supervisor::session).

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::recorder::Attendance;

/// arguments to the `run` subcommand (docs/design/cli.md section 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunArgs {
    /// the child command and its arguments, verbatim, taken from after `--`
    pub command: Vec<String>,
    /// forces unattended regardless of terminal state (FR-20)
    pub unattended: bool,
    /// overrides the default state root; relative paths resolve against cwd
    pub state_dir: Option<PathBuf>,
    /// path to the policy file; present means enforce mode
    pub policy_path: Option<PathBuf>,
}

/// the parsed command line: either the one implemented subcommand, or a reserved name that
/// parses but is not implemented yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `leash run ...`
    Run(RunArgs),
    /// a reserved subcommand name that parses correctly but has no implementation yet
    NotImplemented {
        /// the subcommand name, e.g. "rewind"
        name: &'static str,
        /// the stable message printed to stderr; names the milestone or requirement, never
        /// a fabricated issue number
        message: &'static str,
    },
}

/// a malformed command line (docs/design/cli.md section 1). every variant exits 2 and prints
/// a message naming the mistake.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UsageError {
    /// `leash` invoked with no arguments, or a bare option before any subcommand
    #[error("leash: no subcommand given (try 'leash run -- <command>')")]
    NoSubcommand,
    /// a subcommand that is not `run` and not a reserved name
    #[error("leash: unknown subcommand '{0}'")]
    UnknownSubcommand(String),
    /// a flag `run` does not accept
    #[error("leash: unknown flag '{0}'")]
    UnknownFlag(String),
    /// `run` invoked with no `--` separator
    #[error("leash: 'run' requires a '--' separator before the command")]
    MissingSeparator,
    /// `--` present but nothing follows it
    #[error("leash: empty command after '--'")]
    EmptyCommand,
    /// `--unattended`, `--state-dir`, or `--policy` repeated
    #[error("leash: flag '{0}' given twice")]
    DuplicateFlag(&'static str),
    /// `--state-dir` is the last token before `--`, or immediately followed by `--`
    #[error("leash: '--state-dir' is missing its value")]
    MissingStateDirValue,
    /// `--policy` is the last token before `--`, immediately followed by `--`, or empty
    #[error("leash: '--policy' is missing its value")]
    MissingPolicyValue,
}

/// parse argv (excluding argv\[0\]) into a [`Command`] per docs/design/cli.md section 1.
pub fn parse(args: &[String]) -> Result<Command, UsageError> {
    let Some(first) = args.first() else {
        return Err(UsageError::NoSubcommand);
    };

    if first.starts_with('-') {
        return Err(UsageError::NoSubcommand);
    }

    match first.as_str() {
        "run" => parse_run(&args[1..]).map(Command::Run),
        "diff" => Ok(Command::NotImplemented {
            name: "diff",
            message: "leash: 'diff' is not implemented yet (planned: time-travel milestone M3)",
        }),
        "rewind" => Ok(Command::NotImplemented {
            name: "rewind",
            message: "leash: 'rewind' is not implemented yet (planned: time-travel milestone M3)",
        }),
        "runs" => Ok(Command::NotImplemented {
            name: "runs",
            message: "leash: 'runs' is not implemented yet (planned: FR-21 run management)",
        }),
        other => Err(UsageError::UnknownSubcommand(other.to_string())),
    }
}

/// parse the tokens after `run`.
fn parse_run(rest: &[String]) -> Result<RunArgs, UsageError> {
    if !rest.iter().any(|tok| tok == "--") {
        return Err(UsageError::MissingSeparator);
    }

    let mut unattended = false;
    let mut state_dir: Option<PathBuf> = None;
    let mut policy_path: Option<PathBuf> = None;
    let mut i = 0;

    let separator = loop {
        match rest.get(i) {
            None => return Err(UsageError::MissingSeparator),
            Some(tok) if tok == "--" => break i,
            Some(tok) if tok == "--unattended" => {
                if unattended {
                    return Err(UsageError::DuplicateFlag("--unattended"));
                }
                unattended = true;
                i += 1;
            }
            Some(tok) if tok == "--state-dir" => {
                if state_dir.is_some() {
                    return Err(UsageError::DuplicateFlag("--state-dir"));
                }
                let value = rest.get(i + 1).ok_or(UsageError::MissingStateDirValue)?;
                if value == "--" {
                    return Err(UsageError::MissingStateDirValue);
                }
                state_dir = Some(PathBuf::from(value));
                i += 2;
            }
            Some(tok) if tok.starts_with("--state-dir=") => {
                if state_dir.is_some() {
                    return Err(UsageError::DuplicateFlag("--state-dir"));
                }
                let value = &tok["--state-dir=".len()..];
                if value.is_empty() {
                    return Err(UsageError::MissingStateDirValue);
                }
                state_dir = Some(PathBuf::from(value));
                i += 1;
            }
            Some(tok) if tok == "--policy" => {
                if policy_path.is_some() {
                    return Err(UsageError::DuplicateFlag("--policy"));
                }
                let value = rest.get(i + 1).ok_or(UsageError::MissingPolicyValue)?;
                if value == "--" {
                    return Err(UsageError::MissingPolicyValue);
                }
                policy_path = Some(PathBuf::from(value));
                i += 2;
            }
            Some(tok) if tok.starts_with("--policy=") => {
                if policy_path.is_some() {
                    return Err(UsageError::DuplicateFlag("--policy"));
                }
                let value = &tok["--policy=".len()..];
                if value.is_empty() {
                    return Err(UsageError::MissingPolicyValue);
                }
                policy_path = Some(PathBuf::from(value));
                i += 1;
            }
            Some(tok) => return Err(UsageError::UnknownFlag(tok.clone())),
        }
    };

    let command: Vec<String> = rest[separator + 1..].to_vec();
    if command.is_empty() {
        return Err(UsageError::EmptyCommand);
    }

    Ok(RunArgs {
        command,
        unattended,
        state_dir,
        policy_path,
    })
}

/// compute attendance (docs/design/cli.md section 3): attended iff both stdin and stderr are
/// terminals and `--unattended` was not given.
pub fn attendance(stdin_is_tty: bool, stderr_is_tty: bool, force_unattended: bool) -> Attendance {
    if !force_unattended && stdin_is_tty && stderr_is_tty {
        Attendance::Attended
    } else {
        Attendance::Unattended
    }
}

/// errors resolving the state root (docs/design/cli.md section 4).
#[derive(Debug, thiserror::Error)]
pub enum StateDirError {
    /// the resolved state root equals or lies beneath the workspace; a usage error, exit 2
    #[error(
        "leash: --state-dir '{state_root}' lies inside the workspace '{workspace}' \
         (the state root must be outside the workspace so the child cannot reach the trace)"
    )]
    InsideWorkspace {
        /// the resolved (canonicalized-prefix) state root
        state_root: PathBuf,
        /// the canonicalized workspace
        workspace: PathBuf,
    },
    /// canonicalizing the deepest existing ancestor of the candidate failed; a supervisor
    /// failure, not a usage error, because the ancestor exists and canonicalization should
    /// have succeeded
    #[error("failed to resolve state root: {0}")]
    Resolve(#[source] io::Error),
}

/// resolve the effective state root (docs/design/cli.md section 4).
///
/// `candidate` is the already-chosen path: either the `--state-dir` value or the XDG
/// default computed by the caller. if relative, it is joined onto `cwd`. the joined path is
/// canonicalized through its deepest existing ancestor (the root always exists, so this is
/// total), and the non-existing remainder is appended lexically. if the result equals or lies
/// beneath `workspace` (the canonicalized cwd, guaranteed by the caller), this returns
/// [`StateDirError::InsideWorkspace`], a usage-class error (exit 2).
pub fn resolve_state_root(
    cwd: &Path,
    workspace: &Path,
    candidate: &Path,
) -> Result<PathBuf, StateDirError> {
    let joined = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        cwd.join(candidate)
    };

    let resolved = canonicalize_deepest_ancestor(&joined).map_err(StateDirError::Resolve)?;

    if resolved == workspace || resolved.starts_with(workspace) {
        return Err(StateDirError::InsideWorkspace {
            state_root: resolved,
            workspace: workspace.to_path_buf(),
        });
    }

    Ok(resolved)
}

/// canonicalize `path` through its deepest existing ancestor, appending the non-existing
/// remainder lexically. the root always exists so this always finds some ancestor.
fn canonicalize_deepest_ancestor(path: &Path) -> io::Result<PathBuf> {
    if path.exists() {
        return path.canonicalize();
    }

    let mut existing = path;
    let mut remainder: Vec<&std::ffi::OsStr> = Vec::new();
    while let Some(parent) = existing.parent() {
        if let Some(name) = existing.file_name() {
            remainder.push(name);
        }
        existing = parent;
        if existing.exists() {
            break;
        }
    }

    let mut resolved = existing.canonicalize()?;
    for component in remainder.into_iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

/// exit code for a usage error or a reserved subcommand (cli.md section 6).
const EXIT_USAGE: u8 = 2;
/// exit code for a failure of leash itself, distinct from agent outcomes (FR-22).
const EXIT_SUPERVISOR_FAILURE: u8 = 125;

/// entry point for the binary; parses argv, computes the run's stamps, dispatches to the
/// session, and maps the outcome to the exit-code table of cli.md section 6.
pub fn run() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse(&args) {
        Ok(command) => command,
        Err(usage) => {
            eprintln!("{usage}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let run_args = match parsed {
        Command::Run(run_args) => run_args,
        Command::NotImplemented { message, .. } => {
            eprintln!("{message}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    // the workspace is the canonicalized cwd; a run that cannot name its own workspace
    // cannot reason about isolating the state root from it (cli.md section 4)
    let cwd = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("leash: cannot determine the working directory: {e}");
            return ExitCode::from(EXIT_SUPERVISOR_FAILURE);
        }
    };
    let workspace = match cwd.canonicalize() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("leash: cannot canonicalize the workspace: {e}");
            return ExitCode::from(EXIT_SUPERVISOR_FAILURE);
        }
    };

    let candidate = match &run_args.state_dir {
        Some(dir) => dir.clone(),
        None => {
            let xdg = std::env::var("XDG_STATE_HOME").ok();
            let home = std::env::var("HOME").ok();
            match crate::recorder::default_state_root(xdg.as_deref(), home.as_deref()) {
                Some(root) => root,
                None => {
                    eprintln!(
                        "leash: no state directory: set XDG_STATE_HOME or HOME, or pass --state-dir"
                    );
                    return ExitCode::from(EXIT_SUPERVISOR_FAILURE);
                }
            }
        }
    };
    let state_root = match resolve_state_root(&cwd, &workspace, &candidate) {
        Ok(root) => root,
        Err(e @ StateDirError::InsideWorkspace { .. }) => {
            // a usage-class refusal: the operator passed a state dir the run must not use
            eprintln!("{e}");
            return ExitCode::from(EXIT_USAGE);
        }
        Err(e) => {
            eprintln!("leash: {e}");
            return ExitCode::from(EXIT_SUPERVISOR_FAILURE);
        }
    };

    // SAFETY: isatty only queries the terminal state of fds 0 and 2, which exist for
    // the life of the process.
    let (stdin_tty, stderr_tty) = unsafe { (libc::isatty(0) == 1, libc::isatty(2) == 1) };
    let attendance = attendance(stdin_tty, stderr_tty, run_args.unattended);

    let mode = if run_args.policy_path.is_some() {
        crate::recorder::Mode::Enforce
    } else {
        crate::recorder::Mode::RecordOnly
    };

    dispatch_run(crate::supervisor::session::SessionSpec {
        argv: run_args.command,
        mode,
        attendance,
        state_root,
        workspace,
        policy_path: run_args.policy_path,
    })
}

/// run the session and map its outcome to the shell (cli.md section 6): the child's own
/// result passes through; any failure of leash itself is the reserved supervisor code.
#[cfg(target_os = "linux")]
fn dispatch_run(spec: crate::supervisor::session::SessionSpec) -> ExitCode {
    match crate::supervisor::session::run_session(spec) {
        Ok(outcome) => {
            let code = outcome.exit.shell_code();
            // shell_code is 0..=255 by construction (exit status byte, or 128 + signal)
            ExitCode::from(u8::try_from(code & 0xff).unwrap_or(EXIT_SUPERVISOR_FAILURE))
        }
        Err(e) => {
            eprintln!("leash: {e}");
            ExitCode::from(EXIT_SUPERVISOR_FAILURE)
        }
    }
}

/// on a non-linux host the session cannot exist; preflight would refuse, so refuse the
/// same way without pretending to start (supervisor failure, cli.md section 6).
#[cfg(not(target_os = "linux"))]
fn dispatch_run(_spec: crate::supervisor::session::SessionSpec) -> ExitCode {
    eprintln!("leash: leash supervises only on linux (kernel 5.19 or later, x86-64)");
    ExitCode::from(EXIT_SUPERVISOR_FAILURE)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // --- parse: happy paths ---

    #[test]
    fn parse_run_minimal() {
        let cmd = parse(&args(&["run", "--", "echo", "hi"])).unwrap();
        assert_eq!(
            cmd,
            Command::Run(RunArgs {
                command: vec!["echo".into(), "hi".into()],
                unattended: false,
                state_dir: None,
                policy_path: None,
            })
        );
    }

    #[test]
    fn parse_run_full_form_space_style() {
        let cmd = parse(&args(&[
            "run",
            "--unattended",
            "--state-dir",
            "/tmp/state",
            "--",
            "claude",
            "--dangerously-skip-permissions",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Run(RunArgs {
                command: vec!["claude".into(), "--dangerously-skip-permissions".into()],
                unattended: true,
                state_dir: Some(PathBuf::from("/tmp/state")),
                policy_path: None,
            })
        );
    }

    #[test]
    fn parse_run_full_form_equals_style() {
        let cmd = parse(&args(&[
            "run",
            "--state-dir=/tmp/state",
            "--unattended",
            "--",
            "echo",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Run(RunArgs {
                command: vec!["echo".into()],
                unattended: true,
                state_dir: Some(PathBuf::from("/tmp/state")),
                policy_path: None,
            })
        );
    }

    #[test]
    fn parse_run_accepts_policy_space_and_equals_forms() {
        let space = parse(&args(&[
            "run",
            "--policy",
            "/tmp/policy.toml",
            "--",
            "echo",
        ]))
        .unwrap();
        assert_eq!(
            space,
            Command::Run(RunArgs {
                command: vec!["echo".into()],
                unattended: false,
                state_dir: None,
                policy_path: Some(PathBuf::from("/tmp/policy.toml")),
            })
        );

        let equals = parse(&args(&["run", "--policy=/tmp/policy.toml", "--", "echo"])).unwrap();
        assert_eq!(
            equals,
            Command::Run(RunArgs {
                command: vec!["echo".into()],
                unattended: false,
                state_dir: None,
                policy_path: Some(PathBuf::from("/tmp/policy.toml")),
            })
        );
    }

    #[test]
    fn parse_run_verbatim_passthrough_never_parsed_as_flags() {
        let cmd = parse(&args(&[
            "run",
            "--",
            "rm",
            "-rf",
            "./build",
            "--unattended",
            "--policy",
            "child-policy.toml",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Run(RunArgs {
                command: vec![
                    "rm".into(),
                    "-rf".into(),
                    "./build".into(),
                    "--unattended".into(),
                    "--policy".into(),
                    "child-policy.toml".into(),
                ],
                unattended: false,
                state_dir: None,
                policy_path: None,
            })
        );
    }

    // --- parse: usage errors, one per grammar-table row ---

    #[test]
    fn parse_no_args_is_no_subcommand() {
        assert_eq!(parse(&args(&[])).unwrap_err(), UsageError::NoSubcommand);
    }

    #[test]
    fn parse_bare_option_first_is_no_subcommand() {
        assert_eq!(
            parse(&args(&["--unattended"])).unwrap_err(),
            UsageError::NoSubcommand
        );
    }

    #[test]
    fn parse_unknown_subcommand() {
        assert_eq!(
            parse(&args(&["frobnicate"])).unwrap_err(),
            UsageError::UnknownSubcommand("frobnicate".into())
        );
    }

    #[test]
    fn parse_unknown_flag_before_separator() {
        assert_eq!(
            parse(&args(&["run", "--bogus", "--", "echo"])).unwrap_err(),
            UsageError::UnknownFlag("--bogus".into())
        );
    }

    #[test]
    fn parse_run_without_separator() {
        assert_eq!(
            parse(&args(&["run", "echo", "hi"])).unwrap_err(),
            UsageError::MissingSeparator
        );
    }

    #[test]
    fn parse_run_with_no_flags_and_no_separator() {
        assert_eq!(
            parse(&args(&["run"])).unwrap_err(),
            UsageError::MissingSeparator
        );
    }

    #[test]
    fn parse_empty_command_after_separator() {
        assert_eq!(
            parse(&args(&["run", "--"])).unwrap_err(),
            UsageError::EmptyCommand
        );
    }

    #[test]
    fn parse_empty_command_after_separator_with_flags() {
        assert_eq!(
            parse(&args(&["run", "--unattended", "--"])).unwrap_err(),
            UsageError::EmptyCommand
        );
    }

    #[test]
    fn parse_duplicate_unattended() {
        assert_eq!(
            parse(&args(&[
                "run",
                "--unattended",
                "--unattended",
                "--",
                "echo"
            ]))
            .unwrap_err(),
            UsageError::DuplicateFlag("--unattended")
        );
    }

    #[test]
    fn parse_duplicate_policy() {
        assert_eq!(
            parse(&args(&[
                "run",
                "--policy",
                "a.toml",
                "--policy=b.toml",
                "--",
                "echo"
            ]))
            .unwrap_err(),
            UsageError::DuplicateFlag("--policy")
        );
    }

    #[test]
    fn parse_policy_missing_value() {
        assert_eq!(
            parse(&args(&["run", "--policy", "--", "echo"])).unwrap_err(),
            UsageError::MissingPolicyValue
        );
        assert_eq!(
            parse(&args(&["run", "--policy=", "--", "echo"])).unwrap_err(),
            UsageError::MissingPolicyValue
        );
    }

    #[test]
    fn parse_duplicate_state_dir() {
        assert_eq!(
            parse(&args(&[
                "run",
                "--state-dir",
                "/a",
                "--state-dir",
                "/b",
                "--",
                "echo"
            ]))
            .unwrap_err(),
            UsageError::DuplicateFlag("--state-dir")
        );
    }

    #[test]
    fn parse_duplicate_state_dir_mixed_styles() {
        assert_eq!(
            parse(&args(&[
                "run",
                "--state-dir=/a",
                "--state-dir",
                "/b",
                "--",
                "echo"
            ]))
            .unwrap_err(),
            UsageError::DuplicateFlag("--state-dir")
        );
    }

    #[test]
    fn parse_state_dir_missing_value_at_end() {
        assert_eq!(
            parse(&args(&["run", "--unattended", "--state-dir", "--"])).unwrap_err(),
            UsageError::MissingStateDirValue
        );
    }

    #[test]
    fn parse_state_dir_alone_with_no_separator_is_missing_separator() {
        assert_eq!(
            parse(&args(&["run", "--state-dir"])).unwrap_err(),
            UsageError::MissingSeparator
        );
    }

    #[test]
    fn parse_state_dir_immediately_before_separator() {
        assert_eq!(
            parse(&args(&["run", "--state-dir", "--", "echo"])).unwrap_err(),
            UsageError::MissingStateDirValue
        );
    }

    #[test]
    fn parse_state_dir_equals_empty_value() {
        assert_eq!(
            parse(&args(&["run", "--state-dir=", "--", "echo"])).unwrap_err(),
            UsageError::MissingStateDirValue
        );
    }

    // --- parse: reserved subcommands ---

    #[test]
    fn parse_diff_is_not_implemented() {
        let cmd = parse(&args(&["diff"])).unwrap();
        match cmd {
            Command::NotImplemented { name, message } => {
                assert_eq!(name, "diff");
                assert_eq!(
                    message,
                    "leash: 'diff' is not implemented yet (planned: time-travel milestone M3)"
                );
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn parse_rewind_is_not_implemented() {
        let cmd = parse(&args(&["rewind"])).unwrap();
        match cmd {
            Command::NotImplemented { name, message } => {
                assert_eq!(name, "rewind");
                assert_eq!(
                    message,
                    "leash: 'rewind' is not implemented yet (planned: time-travel milestone M3)"
                );
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn parse_runs_is_not_implemented() {
        let cmd = parse(&args(&["runs"])).unwrap();
        match cmd {
            Command::NotImplemented { name, message } => {
                assert_eq!(name, "runs");
                assert_eq!(
                    message,
                    "leash: 'runs' is not implemented yet (planned: FR-21 run management)"
                );
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    // --- attendance ---

    #[test]
    fn attendance_both_ttys_not_forced_is_attended() {
        assert_eq!(attendance(true, true, false), Attendance::Attended);
    }

    #[test]
    fn attendance_both_ttys_forced_unattended_is_unattended() {
        assert_eq!(attendance(true, true, true), Attendance::Unattended);
    }

    #[test]
    fn attendance_stdin_not_tty_is_unattended() {
        assert_eq!(attendance(false, true, false), Attendance::Unattended);
    }

    #[test]
    fn attendance_stderr_not_tty_is_unattended() {
        assert_eq!(attendance(true, false, false), Attendance::Unattended);
    }

    #[test]
    fn attendance_neither_tty_is_unattended() {
        assert_eq!(attendance(false, false, false), Attendance::Unattended);
    }

    #[test]
    fn attendance_neither_tty_forced_is_unattended() {
        assert_eq!(attendance(false, false, true), Attendance::Unattended);
    }

    #[test]
    fn attendance_stdin_tty_only_forced_is_unattended() {
        assert_eq!(attendance(true, false, true), Attendance::Unattended);
    }

    #[test]
    fn attendance_stderr_tty_only_forced_is_unattended() {
        assert_eq!(attendance(false, true, true), Attendance::Unattended);
    }

    // --- resolve_state_root ---

    #[test]
    fn resolve_state_root_candidate_equal_to_workspace_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().canonicalize().unwrap();
        let cwd = workspace.clone();

        let err = resolve_state_root(&cwd, &workspace, &workspace).unwrap_err();
        match err {
            StateDirError::InsideWorkspace {
                state_root,
                workspace: ws,
            } => {
                assert_eq!(state_root, workspace);
                assert_eq!(ws, workspace);
            }
            other => panic!("expected InsideWorkspace, got {other:?}"),
        }
    }

    #[test]
    fn resolve_state_root_candidate_inside_workspace_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().canonicalize().unwrap();
        let cwd = workspace.clone();
        let nested = workspace.join("state");
        std::fs::create_dir(&nested).unwrap();

        let err = resolve_state_root(&cwd, &workspace, &nested).unwrap_err();
        assert!(matches!(err, StateDirError::InsideWorkspace { .. }));
    }

    #[test]
    fn resolve_state_root_relative_candidate_under_workspace_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().canonicalize().unwrap();
        let cwd = workspace.clone();
        std::fs::create_dir(workspace.join("state")).unwrap();

        let candidate = PathBuf::from("state");
        let err = resolve_state_root(&cwd, &workspace, &candidate).unwrap_err();
        assert!(matches!(err, StateDirError::InsideWorkspace { .. }));
    }

    #[test]
    fn resolve_state_root_symlink_into_workspace_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().canonicalize().unwrap();
        let cwd = workspace.clone();
        let link = workspace.join("link-to-self");
        symlink(&workspace, &link).unwrap();

        let err = resolve_state_root(&cwd, &workspace, &link).unwrap_err();
        assert!(matches!(err, StateDirError::InsideWorkspace { .. }));
    }

    #[test]
    fn resolve_state_root_nonexisting_dir_outside_workspace_accepted() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let workspace_dir = root.join("workspace");
        std::fs::create_dir(&workspace_dir).unwrap();
        let workspace = workspace_dir.canonicalize().unwrap();
        let cwd = workspace.clone();

        let candidate = root.join("state-does-not-exist-yet");
        let resolved = resolve_state_root(&cwd, &workspace, &candidate).unwrap();
        assert_eq!(resolved, candidate);
    }

    #[test]
    fn resolve_state_root_nonexisting_multilevel_suffix_accepted() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let workspace_dir = root.join("workspace");
        std::fs::create_dir(&workspace_dir).unwrap();
        let workspace = workspace_dir.canonicalize().unwrap();
        let cwd = workspace.clone();

        let candidate = root.join("a/b/c/state");
        let resolved = resolve_state_root(&cwd, &workspace, &candidate).unwrap();
        assert_eq!(resolved, candidate);
    }
}
