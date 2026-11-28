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
use crate::rewind::{RewindError, RewindRequest, RewindTarget, run_rewind};
use crate::run_diff::{DiffRunError, RefError, RunRef, parse_run_ref, run_diff};

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
    /// the attended-ask timeout in seconds (FR-10); absent means the default of 60
    pub ask_timeout: Option<u64>,
}

/// the parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `leash run ...`
    Run(RunArgs),
    /// `leash --help` or `leash -h`: print usage to stdout, exit 0
    Help,
    /// `leash --version` or `leash -V`: print the version to stdout, exit 0
    Version,
    /// list or explicitly prune recorded runs
    Runs(RunsArgs),
    /// compare the filesystem effects of two runs or steps (FR-13)
    Diff(DiffArgs),
    /// restore a run's workspace to an earlier step (FR-12)
    Rewind(RewindArgs),
}

/// arguments of `leash runs` (FR-21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunsArgs {
    /// explicit ids to delete, or none to list
    pub prune: Option<Vec<String>>,
    /// state directory override
    pub state_dir: Option<PathBuf>,
}

/// arguments of `leash diff` (docs/design/cli.md section 1, FR-13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffArgs {
    /// the older side
    pub old: RunRef,
    /// the newer side
    pub new: RunRef,
    /// state directory override
    pub state_dir: Option<PathBuf>,
}

/// arguments of `leash rewind` (docs/design/cli.md section 1, FR-12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewindArgs {
    /// the run to rewind; a plain directory name
    pub run_id: String,
    /// the step to restore; absent means step 0 (unless `undo` is given)
    pub step: Option<u64>,
    /// restore the safety snapshot of an earlier rewind instead of a step
    pub undo: Option<u64>,
    /// a chain head or step digest the operator kept outside the store (lowercase hex)
    pub expect: Option<String>,
    /// skip the safety snapshot; the rewind then cannot be undone
    pub no_undo: bool,
    /// the workspace when the working directory is not it
    pub workspace: Option<PathBuf>,
    /// state directory override
    pub state_dir: Option<PathBuf>,
}

/// a malformed command line (docs/design/cli.md section 1). every variant exits 2 and prints
/// a message naming the mistake.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UsageError {
    /// `leash` invoked with no arguments, or a bare option before any subcommand other than
    /// the help and version options
    #[error("leash: no subcommand given (try 'leash run -- <command>')")]
    NoSubcommand,
    /// `--help`, `-h`, `--version`, or `-V` followed by further arguments
    #[error("leash: '{0}' takes no further arguments")]
    TrailingAfterOption(String),
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
    /// `--ask-timeout` is the last token before `--`, immediately followed by `--`, or empty
    #[error("leash: '--ask-timeout' is missing its value")]
    MissingAskTimeoutValue,
    /// `--ask-timeout` is not a whole number of seconds in 1..=3600
    #[error("leash: '--ask-timeout' must be a whole number of seconds in 1..=3600")]
    InvalidAskTimeoutValue,
    /// prune requires at least one run id
    #[error("leash: 'runs prune' requires at least one run id")]
    MissingPruneRunId,
    /// `diff` given fewer than two run arguments
    #[error("leash: 'diff' requires two runs: leash diff <run-id>[:<step>] <run-id>[:<step>]")]
    MissingDiffRun,
    /// a `diff` run id that is not a plain directory name
    #[error(
        "leash: invalid run id in {0:?}: it must be a plain name, not empty, '.', '..' or containing '/'"
    )]
    InvalidRunId(String),
    /// a `diff` step that is not a non-negative whole number
    #[error("leash: invalid step in {0:?}: expected a non-negative whole number after ':'")]
    InvalidStep(String),
    /// a positional argument `runs` does not accept
    #[error("leash: unexpected argument '{0}'")]
    UnexpectedArgument(String),
    /// `rewind` given no run id
    #[error("leash: 'rewind' requires a run id: leash rewind <run-id> [--step N]")]
    MissingRewindRun,
    /// a `rewind` flag that takes a value was given none
    #[error("leash: '{0}' is missing its value")]
    MissingValue(&'static str),
    /// `--step` or `--undo` that is not a non-negative whole number
    #[error("leash: invalid value {1:?} for '{0}': expected a non-negative whole number")]
    InvalidNumber(&'static str, String),
    /// `--expect` that is not a 64-digit hexadecimal sha256
    #[error("leash: invalid value {0:?} for '--expect': expected 64 hexadecimal digits")]
    InvalidDigest(String),
    /// two `rewind` flags that cannot be combined
    #[error("leash: '{0}' cannot be combined with '{1}'")]
    ConflictingFlags(&'static str, &'static str),
}

/// the text printed by `--help` (docs/design/cli.md section 1).
const HELP: &str = "\
leash: supervise an AI coding agent at the operating-system boundary

usage:
  leash run [--unattended] [--state-dir <dir>] [--policy <path>] [--ask-timeout <seconds>] -- <command...>

run flags:
  --unattended              treat the run as unattended even on a terminal
  --state-dir <dir>         state root for run traces (must be outside the workspace)
  --policy <path>           enforce this policy file (without it the run is record-only)
  --ask-timeout <seconds>   attended-ask timeout, 1 to 3600 (default 60)

everything after '--' is the command and is passed through verbatim.

  leash runs [--state-dir <dir>]   list recorded runs
  leash diff <run-id>[:<step>] <run-id>[:<step>] [--state-dir <dir>]
                            compare the filesystem effects of two runs or steps
                            (a missing :<step> means the run's final committed step)
  leash rewind <run-id> [--step N] [--expect <digest>] [--no-undo] [--workspace <dir>] [--state-dir <dir>]
  leash rewind <run-id> --undo <n> [--expect <digest>] [--no-undo] [--workspace <dir>] [--state-dir <dir>]
                            restore the workspace to step N of a finished snapshot run
                            (default step 0, before the agent started) after a safety
                            snapshot that '--undo <n>' restores; '--no-undo' skips it.
                            filesystem effects only: nothing sent off this machine is undone

reserved, not available yet: runs prune

options:
  -h, --help                print this help and exit
  -V, --version             print the version and exit
";

/// the line printed by `--version`.
fn version_line() -> String {
    format!("leash {}", env!("CARGO_PKG_VERSION"))
}

/// parse argv (excluding argv\[0\]) into a [`Command`] per docs/design/cli.md section 1.
pub fn parse(args: &[String]) -> Result<Command, UsageError> {
    let Some(first) = args.first() else {
        return Err(UsageError::NoSubcommand);
    };

    // help and version are top-level options, only valid alone as the first argument
    let top_level = match first.as_str() {
        "--help" | "-h" => Some(Command::Help),
        "--version" | "-V" => Some(Command::Version),
        _ => None,
    };
    if let Some(command) = top_level {
        return if args.len() == 1 {
            Ok(command)
        } else {
            Err(UsageError::TrailingAfterOption(first.clone()))
        };
    }

    if first.starts_with('-') {
        return Err(UsageError::NoSubcommand);
    }

    match first.as_str() {
        "run" => parse_run(&args[1..]).map(Command::Run),
        "diff" => parse_diff(&args[1..]).map(Command::Diff),
        "rewind" => parse_rewind(&args[1..]).map(Command::Rewind),
        "runs" => parse_runs(&args[1..]).map(Command::Runs),
        other => Err(UsageError::UnknownSubcommand(other.to_string())),
    }
}

/// does `token` spell `flag`, alone or as `flag=value`?
fn is_flag(token: &str, flag: &str) -> bool {
    token == flag
        || token
            .strip_prefix(flag)
            .is_some_and(|rest| rest.starts_with('='))
}

/// the value of a flag that takes one, in the space or the equals form. `i` indexes the
/// flag token and moves onto the value token in the space form.
fn flag_value<'a>(
    rest: &'a [String],
    i: &mut usize,
    flag: &'static str,
) -> Result<&'a str, UsageError> {
    let token = &rest[*i];
    if token == flag {
        *i += 1;
        rest.get(*i)
            .filter(|v| !v.is_empty())
            .map(String::as_str)
            .ok_or(UsageError::MissingValue(flag))
    } else {
        let value = &token[flag.len() + 1..];
        if value.is_empty() {
            Err(UsageError::MissingValue(flag))
        } else {
            Ok(value)
        }
    }
}

/// a plain decimal number: digits only, no sign, no whitespace, fits in a u64.
fn parse_number(flag: &'static str, value: &str) -> Result<u64, UsageError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(UsageError::InvalidNumber(flag, value.to_string()));
    }
    value
        .parse::<u64>()
        .map_err(|_| UsageError::InvalidNumber(flag, value.to_string()))
}

fn parse_rewind(rest: &[String]) -> Result<RewindArgs, UsageError> {
    let mut run_id: Option<String> = None;
    let mut step = None;
    let mut undo = None;
    let mut expect: Option<String> = None;
    let mut no_undo = false;
    let mut workspace: Option<PathBuf> = None;
    let mut state_dir: Option<PathBuf> = None;
    let mut i = 0;
    while i < rest.len() {
        let token = rest[i].as_str();
        if is_flag(token, "--step") {
            if step.is_some() {
                return Err(UsageError::DuplicateFlag("--step"));
            }
            step = Some(parse_number("--step", flag_value(rest, &mut i, "--step")?)?);
        } else if is_flag(token, "--undo") {
            if undo.is_some() {
                return Err(UsageError::DuplicateFlag("--undo"));
            }
            undo = Some(parse_number("--undo", flag_value(rest, &mut i, "--undo")?)?);
        } else if is_flag(token, "--expect") {
            if expect.is_some() {
                return Err(UsageError::DuplicateFlag("--expect"));
            }
            let value = flag_value(rest, &mut i, "--expect")?;
            if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(UsageError::InvalidDigest(value.to_string()));
            }
            expect = Some(value.to_ascii_lowercase());
        } else if is_flag(token, "--workspace") {
            if workspace.is_some() {
                return Err(UsageError::DuplicateFlag("--workspace"));
            }
            workspace = Some(PathBuf::from(flag_value(rest, &mut i, "--workspace")?));
        } else if is_flag(token, "--state-dir") {
            if state_dir.is_some() {
                return Err(UsageError::DuplicateFlag("--state-dir"));
            }
            state_dir = Some(PathBuf::from(flag_value(rest, &mut i, "--state-dir")?));
        } else if token == "--no-undo" {
            if no_undo {
                return Err(UsageError::DuplicateFlag("--no-undo"));
            }
            no_undo = true;
        } else if token.starts_with('-') {
            return Err(UsageError::UnknownFlag(token.to_string()));
        } else if run_id.is_some() {
            return Err(UsageError::UnexpectedArgument(token.to_string()));
        } else {
            if token.is_empty()
                || token == "."
                || token == ".."
                || token.contains('/')
                || token.contains('\0')
            {
                return Err(UsageError::InvalidRunId(token.to_string()));
            }
            run_id = Some(token.to_string());
        }
        i += 1;
    }
    let run_id = run_id.ok_or(UsageError::MissingRewindRun)?;
    if undo.is_some() && step.is_some() {
        return Err(UsageError::ConflictingFlags("--undo", "--step"));
    }
    Ok(RewindArgs {
        run_id,
        step,
        undo,
        expect,
        no_undo,
        workspace,
        state_dir,
    })
}

fn parse_diff(rest: &[String]) -> Result<DiffArgs, UsageError> {
    let mut state_dir = None;
    let mut refs: Vec<RunRef> = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        let token = &rest[i];
        if token == "--state-dir" || token.starts_with("--state-dir=") {
            if state_dir.is_some() {
                return Err(UsageError::DuplicateFlag("--state-dir"));
            }
            let value = if token == "--state-dir" {
                i += 1;
                rest.get(i)
                    .filter(|v| !v.is_empty() && !v.starts_with('-'))
                    .ok_or(UsageError::MissingStateDirValue)?
                    .as_str()
            } else {
                let value = &token["--state-dir=".len()..];
                if value.is_empty() {
                    return Err(UsageError::MissingStateDirValue);
                }
                value
            };
            state_dir = Some(PathBuf::from(value));
        } else if token.starts_with('-') {
            return Err(UsageError::UnknownFlag(token.clone()));
        } else if refs.len() == 2 {
            return Err(UsageError::UnexpectedArgument(token.clone()));
        } else {
            refs.push(parse_run_ref(token).map_err(|e| match e {
                RefError::BadRunId => UsageError::InvalidRunId(token.clone()),
                RefError::BadStep => UsageError::InvalidStep(token.clone()),
            })?);
        }
        i += 1;
    }
    let mut refs = refs.into_iter();
    match (refs.next(), refs.next()) {
        (Some(old), Some(new)) => Ok(DiffArgs {
            old,
            new,
            state_dir,
        }),
        _ => Err(UsageError::MissingDiffRun),
    }
}

fn parse_runs(rest: &[String]) -> Result<RunsArgs, UsageError> {
    let mut state_dir = None;
    let mut prune = None;
    let mut i = 0;
    while i < rest.len() {
        let token = &rest[i];
        if token == "--state-dir" || token.starts_with("--state-dir=") {
            if state_dir.is_some() {
                return Err(UsageError::DuplicateFlag("--state-dir"));
            }
            let value = if token == "--state-dir" {
                i += 1;
                rest.get(i)
                    .filter(|v| !v.is_empty() && !v.starts_with('-'))
                    .ok_or(UsageError::MissingStateDirValue)?
                    .as_str()
            } else {
                let value = &token["--state-dir=".len()..];
                if value.is_empty() {
                    return Err(UsageError::MissingStateDirValue);
                }
                value
            };
            state_dir = Some(PathBuf::from(value));
        } else if token.starts_with('-') {
            return Err(UsageError::UnknownFlag(token.clone()));
        } else if token == "prune" && prune.is_none() && i == 0 {
            prune = Some(Vec::new());
        } else if let Some(ids) = &mut prune {
            ids.push(token.clone());
        } else {
            return Err(UsageError::UnexpectedArgument(token.clone()));
        }
        i += 1;
    }
    if matches!(&prune, Some(ids) if ids.is_empty()) {
        return Err(UsageError::MissingPruneRunId);
    }
    Ok(RunsArgs { prune, state_dir })
}

/// parse the tokens after `run`.
fn parse_run(rest: &[String]) -> Result<RunArgs, UsageError> {
    if !rest.iter().any(|tok| tok == "--") {
        return Err(UsageError::MissingSeparator);
    }

    let mut unattended = false;
    let mut state_dir: Option<PathBuf> = None;
    let mut policy_path: Option<PathBuf> = None;
    let mut ask_timeout: Option<u64> = None;
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
            Some(tok) if tok == "--ask-timeout" => {
                if ask_timeout.is_some() {
                    return Err(UsageError::DuplicateFlag("--ask-timeout"));
                }
                let value = rest.get(i + 1).ok_or(UsageError::MissingAskTimeoutValue)?;
                if value == "--" {
                    return Err(UsageError::MissingAskTimeoutValue);
                }
                ask_timeout = Some(parse_ask_timeout(value)?);
                i += 2;
            }
            Some(tok) if tok.starts_with("--ask-timeout=") => {
                if ask_timeout.is_some() {
                    return Err(UsageError::DuplicateFlag("--ask-timeout"));
                }
                let value = &tok["--ask-timeout=".len()..];
                if value.is_empty() {
                    return Err(UsageError::MissingAskTimeoutValue);
                }
                ask_timeout = Some(parse_ask_timeout(value)?);
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
        ask_timeout,
    })
}

/// the `--ask-timeout` value: whole seconds in 1..=3600 (cli.md section 1). zero would
/// deny every ask on sight; the ceiling keeps the whole-tree stall (notify-loop.md
/// section 5) bounded by a span an operator can actually reason about.
fn parse_ask_timeout(value: &str) -> Result<u64, UsageError> {
    match value.parse::<u64>() {
        Ok(secs) if (1..=3600).contains(&secs) => Ok(secs),
        _ => Err(UsageError::InvalidAskTimeoutValue),
    }
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
        // handled before any platform check so they work on hosts that cannot supervise
        Command::Help => {
            print!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Command::Version => {
            println!("{}", version_line());
            return ExitCode::SUCCESS;
        }
        Command::Runs(args) => return dispatch_runs(args),
        Command::Diff(args) => return dispatch_diff(args),
        Command::Rewind(args) => return dispatch_rewind(args),
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

    let state_root_spelling = if candidate.is_absolute() {
        candidate
    } else {
        cwd.join(candidate)
    };
    dispatch_run(crate::supervisor::session::SessionSpec {
        argv: run_args.command,
        mode,
        attendance,
        state_root,
        state_root_spelling,
        workspace,
        policy_path: run_args.policy_path,
        ask_timeout: run_args
            .ask_timeout
            .map(std::time::Duration::from_secs)
            .unwrap_or(crate::supervisor::run::DEFAULT_ASK_TIMEOUT),
        // ADR-0024 decisions 4 to 6 are in place in the session (the implicit cgroup2 deny and
        // the metadata calls it needs, the Landlock overlap refusal, the ABI 3 floor). the
        // `--snapshots` flag that turns this on is added by the capture slice, so it stays off here.
        snapshot_integrity: false,
    })
}

fn dispatch_diff(args: DiffArgs) -> ExitCode {
    let state_root = match args.state_dir.or_else(|| {
        let xdg = std::env::var("XDG_STATE_HOME").ok();
        let home = std::env::var("HOME").ok();
        crate::recorder::default_state_root(xdg.as_deref(), home.as_deref())
    }) {
        Some(root) => root,
        None => {
            eprintln!("leash: no state directory: set XDG_STATE_HOME or HOME, or pass --state-dir");
            return ExitCode::from(EXIT_SUPERVISOR_FAILURE);
        }
    };
    match run_diff(&state_root, &args.old, &args.new) {
        Ok(report) => {
            print!("{report}");
            ExitCode::SUCCESS
        }
        Err(e @ DiffRunError::Usage(_)) => {
            eprintln!("{e}");
            ExitCode::from(EXIT_USAGE)
        }
        Err(e @ DiffRunError::Failure(_)) => {
            eprintln!("{e}");
            ExitCode::from(EXIT_SUPERVISOR_FAILURE)
        }
    }
}

/// resolve the workspace and state root of a rewind, run it, and map the outcome to the
/// exit codes of cli.md section 6: a request that names something that does not exist or
/// does not fit is 2, a failure or refusal at run time is 125.
fn dispatch_rewind(args: RewindArgs) -> ExitCode {
    use std::io::Write as _;

    let cwd = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("leash: cannot determine the working directory: {e}");
            return ExitCode::from(EXIT_SUPERVISOR_FAILURE);
        }
    };
    let (workspace_spelling, workspace_flag) = match &args.workspace {
        Some(dir) => (cwd.join(dir), true),
        None => (cwd.clone(), false),
    };
    let workspace = match workspace_spelling.canonicalize() {
        Ok(dir) => dir,
        Err(e) if workspace_flag => {
            eprintln!(
                "leash: cannot resolve the workspace {}: {e}",
                workspace_spelling.display()
            );
            return ExitCode::from(EXIT_USAGE);
        }
        Err(e) => {
            eprintln!("leash: cannot canonicalize the workspace: {e}");
            return ExitCode::from(EXIT_SUPERVISOR_FAILURE);
        }
    };
    let candidate = match args.state_dir.clone().or_else(|| {
        let xdg = std::env::var("XDG_STATE_HOME").ok();
        let home = std::env::var("HOME").ok();
        crate::recorder::default_state_root(xdg.as_deref(), home.as_deref())
    }) {
        Some(root) => root,
        None => {
            eprintln!("leash: no state directory: set XDG_STATE_HOME or HOME, or pass --state-dir");
            return ExitCode::from(EXIT_SUPERVISOR_FAILURE);
        }
    };
    let state_root = match resolve_state_root(&cwd, &workspace, &candidate) {
        Ok(root) => root,
        Err(e @ StateDirError::InsideWorkspace { .. }) => {
            eprintln!("{e}");
            return ExitCode::from(EXIT_USAGE);
        }
        Err(e) => {
            eprintln!("leash: {e}");
            return ExitCode::from(EXIT_SUPERVISOR_FAILURE);
        }
    };
    let request = RewindRequest {
        run_id: args.run_id,
        target: match args.undo {
            Some(n) => RewindTarget::Undo(n),
            None => RewindTarget::Step(args.step.unwrap_or(0)),
        },
        expect: args.expect,
        no_undo: args.no_undo,
        workspace,
        state_root,
    };
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    let result = run_rewind(&request, &mut stdout, &mut stderr);
    let _ = stdout.flush();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e @ RewindError::Usage(_)) => {
            let _ = writeln!(stderr, "{e}");
            ExitCode::from(EXIT_USAGE)
        }
        Err(e @ RewindError::Failure(_)) => {
            let _ = writeln!(stderr, "{e}");
            ExitCode::from(EXIT_SUPERVISOR_FAILURE)
        }
    }
}

fn dispatch_runs(args: RunsArgs) -> ExitCode {
    let state_root = match args.state_dir.or_else(|| {
        let xdg = std::env::var("XDG_STATE_HOME").ok();
        let home = std::env::var("HOME").ok();
        crate::recorder::default_state_root(xdg.as_deref(), home.as_deref())
    }) {
        Some(root) => root,
        None => {
            eprintln!("leash: no state directory: set XDG_STATE_HOME or HOME, or pass --state-dir");
            return ExitCode::from(EXIT_SUPERVISOR_FAILURE);
        }
    };
    if let Some(ids) = args.prune {
        return match crate::runs::prune(&state_root, &ids) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("leash: cannot prune runs: {e}");
                ExitCode::from(EXIT_SUPERVISOR_FAILURE)
            }
        };
    }
    match crate::runs::list(&state_root) {
        Ok(entries) => {
            for entry in entries {
                let id = entry.display_id();
                match entry.details {
                    Ok(details) => {
                        let mode = match details.meta.mode {
                            crate::recorder::Mode::RecordOnly => "record-only",
                            crate::recorder::Mode::Enforce => "enforce",
                        };
                        let exit = match details.exit {
                            Some(crate::runs::RunExit::Code(code)) => format!("exit {code}"),
                            Some(crate::runs::RunExit::Signal(signal)) => {
                                format!("signal {signal}")
                            }
                            None => "incomplete (no run_end)".to_string(),
                        };
                        println!(
                            "{}\t{}\t{}\t{:?}\t{}",
                            id, mode, details.meta.start_ts, details.meta.argv, exit
                        );
                    }
                    Err(e) => {
                        println!("{id}\tcorrupt or incomplete: {e}")
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("leash: cannot list runs: {e}");
            ExitCode::from(EXIT_SUPERVISOR_FAILURE)
        }
    }
}

/// map a completed or failed session to the shell exit code (cli.md section 6, FR-22):
/// the child's own exit or signal passes through; any supervisor failure is 125.
pub fn session_exit_code(
    result: Result<
        crate::supervisor::session::SessionOutcome,
        crate::supervisor::session::SessionError,
    >,
) -> ExitCode {
    match result {
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

/// run the session and map its outcome to the shell (cli.md section 6): the child's own
/// result passes through; any failure of leash itself is the reserved supervisor code.
#[cfg(target_os = "linux")]
fn dispatch_run(spec: crate::supervisor::session::SessionSpec) -> ExitCode {
    session_exit_code(crate::supervisor::session::run_session(spec))
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
                ask_timeout: None,
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
                ask_timeout: None,
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
                ask_timeout: None,
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
                ask_timeout: None,
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
                ask_timeout: None,
            })
        );
    }

    #[test]
    fn parse_run_accepts_ask_timeout_space_and_equals_forms() {
        for form in [
            args(&["run", "--ask-timeout", "30", "--", "echo"]),
            args(&["run", "--ask-timeout=30", "--", "echo"]),
        ] {
            let cmd = parse(&form).unwrap();
            assert_eq!(
                cmd,
                Command::Run(RunArgs {
                    command: vec!["echo".into()],
                    unattended: false,
                    state_dir: None,
                    policy_path: None,
                    ask_timeout: Some(30),
                })
            );
        }
    }

    #[test]
    fn parse_run_rejects_ask_timeout_errors() {
        // repeated
        assert_eq!(
            parse(&args(&[
                "run",
                "--ask-timeout",
                "30",
                "--ask-timeout=10",
                "--",
                "echo",
            ])),
            Err(UsageError::DuplicateFlag("--ask-timeout"))
        );
        // missing value: immediately followed by `--`, or empty after `=`
        assert_eq!(
            parse(&args(&["run", "--ask-timeout", "--", "echo"])),
            Err(UsageError::MissingAskTimeoutValue)
        );
        assert_eq!(
            parse(&args(&["run", "--ask-timeout=", "--", "echo"])),
            Err(UsageError::MissingAskTimeoutValue)
        );
        // invalid value: zero, past the ceiling, or not a whole number
        for bad in ["0", "3601", "abc", "-5", "1.5"] {
            assert_eq!(
                parse(&args(&["run", "--ask-timeout", bad, "--", "echo"])),
                Err(UsageError::InvalidAskTimeoutValue),
                "{bad} is invalid"
            );
        }
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
                ask_timeout: None,
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

    #[test]
    fn parse_help_and_version_options() {
        assert_eq!(parse(&args(&["--help"])).unwrap(), Command::Help);
        assert_eq!(parse(&args(&["-h"])).unwrap(), Command::Help);
        assert_eq!(parse(&args(&["--version"])).unwrap(), Command::Version);
        assert_eq!(parse(&args(&["-V"])).unwrap(), Command::Version);
    }

    #[test]
    fn parse_help_with_trailing_args_is_usage_error() {
        assert_eq!(
            parse(&args(&["--help", "extra"])).unwrap_err(),
            UsageError::TrailingAfterOption("--help".into())
        );
        assert_eq!(
            parse(&args(&["-V", "run"])).unwrap_err(),
            UsageError::TrailingAfterOption("-V".into())
        );
    }

    #[test]
    fn parse_other_bare_options_stay_no_subcommand() {
        for opt in ["--bogus", "-x", "--helpme", "-v"] {
            assert_eq!(
                parse(&args(&[opt])).unwrap_err(),
                UsageError::NoSubcommand,
                "{opt}"
            );
        }
    }

    #[test]
    fn parse_run_help_is_not_supported() {
        assert_eq!(
            parse(&args(&["run", "--help"])).unwrap_err(),
            UsageError::MissingSeparator
        );
        assert_eq!(
            parse(&args(&["run", "--help", "--", "echo"])).unwrap_err(),
            UsageError::UnknownFlag("--help".into())
        );
        // after the separator it is the child's argument, never parsed
        assert!(matches!(
            parse(&args(&["run", "--", "echo", "--help"])).unwrap(),
            Command::Run(_)
        ));
    }

    #[test]
    fn help_text_names_every_run_flag_and_option() {
        for needle in [
            "--unattended",
            "--state-dir",
            "--policy",
            "--ask-timeout",
            "-h, --help",
            "-V, --version",
            "leash rewind <run-id> [--step N] [--expect <digest>] [--no-undo]",
            "--undo <n>",
            "reserved, not available yet: runs prune",
            "leash diff <run-id>[:<step>] <run-id>[:<step>]",
        ] {
            assert!(HELP.contains(needle), "{needle}");
        }
        assert_eq!(
            version_line(),
            format!("leash {}", env!("CARGO_PKG_VERSION"))
        );
    }

    // --- parse: reserved subcommands ---

    fn rr(id: &str, step: Option<u64>) -> RunRef {
        RunRef {
            run_id: id.into(),
            step,
        }
    }

    #[test]
    fn parse_diff_valid_forms() {
        assert_eq!(
            parse(&args(&["diff", "a", "b"])).unwrap(),
            Command::Diff(DiffArgs {
                old: rr("a", None),
                new: rr("b", None),
                state_dir: None
            })
        );
        assert_eq!(
            parse(&args(&["diff", "a:0", "a:3", "--state-dir", "/s"])).unwrap(),
            Command::Diff(DiffArgs {
                old: rr("a", Some(0)),
                new: rr("a", Some(3)),
                state_dir: Some("/s".into())
            })
        );
        assert_eq!(
            parse(&args(&["diff", "--state-dir=/s", "a", "b:2"])).unwrap(),
            Command::Diff(DiffArgs {
                old: rr("a", None),
                new: rr("b", Some(2)),
                state_dir: Some("/s".into())
            })
        );
    }

    #[test]
    fn parse_diff_rejects_missing_and_extra_arguments() {
        for case in [
            &["diff"][..],
            &["diff", "a"],
            &["diff", "--state-dir=/s", "a"],
        ] {
            assert_eq!(parse(&args(case)), Err(UsageError::MissingDiffRun));
        }
        assert_eq!(
            parse(&args(&["diff", "a", "b", "c"])),
            Err(UsageError::UnexpectedArgument("c".into()))
        );
        assert_eq!(
            parse(&args(&["diff", "a", "b", "--nope"])),
            Err(UsageError::UnknownFlag("--nope".into()))
        );
        assert_eq!(
            parse(&args(&["diff", "a", "b", "--state-dir"])),
            Err(UsageError::MissingStateDirValue)
        );
        assert_eq!(
            parse(&args(&["diff", "a", "b", "--state-dir=a", "--state-dir=b"])),
            Err(UsageError::DuplicateFlag("--state-dir"))
        );
    }

    #[test]
    fn parse_diff_rejects_bad_run_ids_and_steps() {
        for bad in ["../x", "a/b", "..", ".", ":1", "/abs"] {
            assert_eq!(
                parse(&args(&["diff", bad, "b"])),
                Err(UsageError::InvalidRunId(bad.into())),
                "{bad}"
            );
        }
        for bad in ["a:x", "a:-1", "a:", "a:1:2"] {
            assert_eq!(
                parse(&args(&["diff", "b", bad])),
                Err(UsageError::InvalidStep(bad.into())),
                "{bad}"
            );
        }
    }

    fn rewind(v: &[&str]) -> Result<RewindArgs, UsageError> {
        let mut argv = vec!["rewind"];
        argv.extend_from_slice(v);
        match parse(&args(&argv))? {
            Command::Rewind(a) => Ok(a),
            other => panic!("expected Rewind, got {other:?}"),
        }
    }

    #[test]
    fn parse_rewind_minimal_and_full() {
        assert_eq!(
            rewind(&["r1"]).unwrap(),
            RewindArgs {
                run_id: "r1".into(),
                step: None,
                undo: None,
                expect: None,
                no_undo: false,
                workspace: None,
                state_dir: None,
            }
        );
        let digest = "AB".repeat(32);
        let full = rewind(&[
            "r1",
            "--step",
            "3",
            "--expect",
            &digest,
            "--no-undo",
            "--workspace=/w",
            "--state-dir",
            "/s",
        ])
        .unwrap();
        assert_eq!(full.step, Some(3));
        assert_eq!(
            full.expect,
            Some("ab".repeat(32)),
            "digests normalize to lowercase"
        );
        assert!(full.no_undo);
        assert_eq!(full.workspace, Some(PathBuf::from("/w")));
        assert_eq!(full.state_dir, Some(PathBuf::from("/s")));
        // flags may come before the run id, and the equals forms work
        let early = rewind(&["--step=0", "r1"]).unwrap();
        assert_eq!((early.run_id.as_str(), early.step), ("r1", Some(0)));
        assert_eq!(rewind(&["r1", "--undo", "2"]).unwrap().undo, Some(2));
        assert!(rewind(&["r1", "--undo=2", "--no-undo"]).is_ok());
    }

    #[test]
    fn parse_rewind_usage_errors() {
        assert_eq!(rewind(&[]), Err(UsageError::MissingRewindRun));
        assert_eq!(
            rewind(&["--no-undo"]),
            Err(UsageError::MissingRewindRun),
            "flags alone name no run"
        );
        for bad in ["", ".", "..", "a/b", "../x"] {
            assert_eq!(
                rewind(&[bad]),
                Err(UsageError::InvalidRunId(bad.into())),
                "{bad:?}"
            );
        }
        assert_eq!(
            rewind(&["r", "s"]),
            Err(UsageError::UnexpectedArgument("s".into()))
        );
        assert_eq!(
            rewind(&["r", "--force"]),
            Err(UsageError::UnknownFlag("--force".into()))
        );
        for bad in ["x", "-1", "+1", "1.5", " 1", "", "99999999999999999999"] {
            assert_eq!(
                rewind(&["r", "--step", bad]),
                if bad.is_empty() {
                    Err(UsageError::MissingValue("--step"))
                } else {
                    Err(UsageError::InvalidNumber("--step", bad.into()))
                },
                "--step {bad:?}"
            );
        }
        assert_eq!(
            rewind(&["r", "--undo", "x"]),
            Err(UsageError::InvalidNumber("--undo", "x".into()))
        );
        assert_eq!(
            rewind(&["r", "--step"]),
            Err(UsageError::MissingValue("--step"))
        );
        assert_eq!(
            rewind(&["r", "--step="]),
            Err(UsageError::MissingValue("--step"))
        );
        assert_eq!(
            rewind(&["r", "--workspace"]),
            Err(UsageError::MissingValue("--workspace"))
        );
        for bad in ["abc", &"g".repeat(64), &"a".repeat(63), &"a".repeat(65)] {
            assert_eq!(
                rewind(&["r", "--expect", bad]),
                Err(UsageError::InvalidDigest(bad.to_string())),
                "{bad:?}"
            );
        }
        let digest = "a".repeat(64);
        let expect_eq = format!("--expect={digest}");
        for flag in ["--step=1", "--workspace=/a", "--state-dir=/a", &expect_eq] {
            assert!(
                matches!(
                    rewind(&["r", flag, flag]),
                    Err(UsageError::DuplicateFlag(_))
                ),
                "{flag}"
            );
        }
        assert_eq!(
            rewind(&["r", "--no-undo", "--no-undo"]),
            Err(UsageError::DuplicateFlag("--no-undo"))
        );
        assert_eq!(
            rewind(&["r", "--undo", "1", "--step", "0"]),
            Err(UsageError::ConflictingFlags("--undo", "--step"))
        );
        // an undo is checked against the digest of its safety snapshot
        assert!(rewind(&["r", "--undo", "1", "--expect", &"a".repeat(64)]).is_ok());
    }

    #[test]
    fn parse_runs_list_and_prune() {
        assert_eq!(
            parse(&args(&["runs"])).unwrap(),
            Command::Runs(RunsArgs {
                prune: None,
                state_dir: None
            })
        );
        assert_eq!(
            parse(&args(&["runs", "--state-dir=/tmp/state"])).unwrap(),
            Command::Runs(RunsArgs {
                prune: None,
                state_dir: Some("/tmp/state".into())
            })
        );
        assert_eq!(
            parse(&args(&[
                "runs",
                "prune",
                "a",
                "b",
                "--state-dir",
                "/tmp/state"
            ]))
            .unwrap(),
            Command::Runs(RunsArgs {
                prune: Some(args(&["a", "b"])),
                state_dir: Some("/tmp/state".into())
            })
        );
    }

    #[test]
    fn parse_runs_rejects_bad_arguments() {
        assert_eq!(
            parse(&args(&["runs", "prune"])),
            Err(UsageError::MissingPruneRunId)
        );
        assert_eq!(
            parse(&args(&["runs", "--state-dir"])),
            Err(UsageError::MissingStateDirValue)
        );
        assert_eq!(
            parse(&args(&["runs", "--state-dir="])),
            Err(UsageError::MissingStateDirValue)
        );
        assert_eq!(
            parse(&args(&["runs", "--state-dir=a", "--state-dir=b"])),
            Err(UsageError::DuplicateFlag("--state-dir"))
        );
        assert_eq!(
            parse(&args(&["runs", "unexpected"])),
            Err(UsageError::UnexpectedArgument("unexpected".into()))
        );
        assert_eq!(
            parse(&args(&["runs", "--bogus"])),
            Err(UsageError::UnknownFlag("--bogus".into()))
        );
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
