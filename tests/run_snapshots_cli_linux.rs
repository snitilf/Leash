//! `leash run --snapshots` end to end (ADR-0024, docs/design/cli.md section 1), driven through
//! the real compiled binary: the run, what it prints at the end, `leash diff` over its steps,
//! and `leash rewind` using the command the run printed.
//!
//! the run tests need a delegated cgroup v2 and skip without one. `LEASH_REQUIRE_FREEZER=1`
//! turns the skip into a failure, which is how the CI cgroup job proves they ran. the usage
//! errors need no host support and always run.
//!
//! the temporary directories must not carry a default ACL, because capture refuses an entry
//! that has one: point `TMPDIR` at a directory without one when `/tmp` has them.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

const NOTICE: &str = "rewind reverses filesystem effects only; anything the agent sent off this machine is not undone";

fn leash_bin() -> &'static str {
    env!("CARGO_BIN_EXE_leash")
}

fn run_leash(args: &[&str], cwd: &Path) -> Output {
    Command::new(leash_bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// kind, mode, mtime and content (or target) of every path below `root`.
fn tree_state(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
        let mut names: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        names.sort();
        for path in names {
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let meta = fs::symlink_metadata(&path).unwrap();
            let kind = if meta.is_dir() {
                "dir".to_string()
            } else if meta.file_type().is_symlink() {
                format!("symlink -> {}", fs::read_link(&path).unwrap().display())
            } else if meta.is_file() {
                format!("file {:?}", fs::read(&path).unwrap())
            } else {
                "other".to_string()
            };
            out.insert(
                rel,
                format!(
                    "{kind} mode={:o} mtime={}.{}",
                    meta.mode() & 0o7777,
                    meta.mtime(),
                    meta.mtime_nsec()
                ),
            );
            if meta.is_dir() {
                walk(root, &path, out);
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// strip an inherited default ACL, which capture refuses.
fn strip_default_acl(path: &Path) {
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: c_path and the attribute name are NUL-terminated.
    let _ = unsafe { libc::removexattr(c_path.as_ptr(), c"system.posix_acl_default".as_ptr()) };
}

fn create_dir(path: &Path) {
    fs::create_dir(path).unwrap();
    strip_default_acl(path);
}

/// the policy the run tests use: read and execute anywhere, and write inside the workspace.
fn workspace_policy(ws: &Path) -> String {
    format!(
        "schema_version = 1\n\
         [[fs]]\npath=\"/**\"\nmode=[\"read\"]\naction=\"allow\"\n\
         [[exec]]\nbinary=\"/**\"\naction=\"allow\"\n\
         [[fs]]\npath={:?}\nmode=[\"read\",\"write\",\"create\",\"delete\"]\naction=\"allow\"\n",
        format!("{}/**", ws.display())
    )
}

/// a workspace with a nested file, an empty directory, a symlink and two modes.
fn populate(ws: &Path) {
    fs::write(ws.join("a.txt"), "one\n").unwrap();
    create_dir(&ws.join("sub"));
    fs::write(ws.join("sub/b.txt"), "two\n").unwrap();
    create_dir(&ws.join("empty"));
    symlink("a.txt", ws.join("link")).unwrap();
    fs::set_permissions(
        ws.join("a.txt"),
        std::os::unix::fs::PermissionsExt::from_mode(0o640),
    )
    .unwrap();
}

/// the agent: three bursts of edits with a pause longer than the 250 ms quiet window between
/// them, so each burst becomes its own step.
const AGENT: &str = "set -e; \
    echo changed > a.txt; sleep 0.7; \
    rm sub/b.txt; echo new > new.txt; sleep 0.7; \
    mkdir sub/deep; echo c > sub/deep/c.txt; chmod 600 a.txt; rm link; echo now a file > link; sleep 0.7; \
    mv new.txt renamed.txt; rmdir empty";

/// run the printed command the way the shell would, with `leash` on the path and from a
/// directory that is not the workspace.
fn run_printed(command: &str) -> Output {
    let bin_dir = tempfile::tempdir().unwrap();
    symlink(leash_bin(), bin_dir.path().join("leash")).unwrap();
    let path = format!(
        "{}:{}",
        bin_dir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let elsewhere = tempfile::tempdir().unwrap();
    Command::new("sh")
        .args(["-c", command])
        .env("PATH", path)
        .current_dir(elsewhere.path())
        .output()
        .unwrap()
}

fn is_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[test]
fn a_snapshot_run_is_diffed_and_rewound_with_what_it_printed() {
    if !common::delegated_cgroup_or_skip("snapshot_run_cli") {
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let ws_dir = tempfile::tempdir().unwrap();
    let ws = ws_dir.path().canonicalize().unwrap();
    strip_default_acl(&ws);
    populate(&ws);
    let original = tree_state(&ws);
    let policy = state.path().join("policy.toml");
    fs::write(&policy, workspace_policy(&ws)).unwrap();
    let state_arg = state.path().to_string_lossy().into_owned();
    let policy_arg = policy.to_string_lossy().into_owned();

    // the run
    let out = run_leash(
        &[
            "run",
            "--snapshots",
            "--state-dir",
            &state_arg,
            "--policy",
            &policy_arg,
            "--",
            "sh",
            "-c",
            AGENT,
        ],
        &ws,
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let after_run = tree_state(&ws);
    assert_ne!(after_run, original, "the agent changed the workspace");

    // what it printed: every step digest in order, the chain head, the run line and, last,
    // the command that undoes the run
    let err = stderr(&out);
    let lines: Vec<&str> = err.lines().collect();
    let printed_digests: Vec<(u64, String)> = lines
        .iter()
        .filter_map(|l| l.strip_prefix("leash: step "))
        .map(|rest| {
            let (n, digest) = rest.split_once(" snapshot ").expect(rest);
            (n.parse().unwrap(), digest.to_string())
        })
        .collect();
    let head = lines
        .iter()
        .find_map(|l| l.strip_prefix("leash: snapshot chain head "))
        .unwrap_or_else(|| panic!("no chain head line in: {err}"))
        .to_string();
    assert!(is_digest(&head), "{head}");
    let id = lines
        .iter()
        .find_map(|l| {
            l.strip_prefix("leash: run ")
                .and_then(|rest| rest.split_once(" recorded"))
                .map(|(id, _)| id.to_string())
        })
        .unwrap_or_else(|| panic!("no run line in: {err}"));
    let hint = *lines.last().unwrap();
    assert_eq!(
        hint,
        format!(
            "leash: to undo this run: leash rewind {id} --expect {head} --workspace {} --state-dir {}",
            ws.display(),
            state.path().canonicalize().unwrap().display()
        ),
        "the last line is the rewind command"
    );
    let position = |needle: &str| lines.iter().position(|l| l.contains(needle)).unwrap();
    assert!(position("step 0 snapshot") < position("snapshot chain head"));
    assert!(position("snapshot chain head") < position("recorded; report:"));
    assert!(position("recorded; report:") < lines.len() - 1);

    // the trace agrees: steps 0..=N, each with the digest that was printed, and a chain head
    let trace =
        fs::read_to_string(state.path().join("runs").join(&id).join("trace.jsonl")).unwrap();
    let events: Vec<Value> = trace
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let traced: Vec<(u64, String)> = events
        .iter()
        .filter(|e| e["type"] == "step")
        .map(|e| {
            (
                e["step"].as_u64().unwrap(),
                e["manifest_digest"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let final_step = traced.last().unwrap().0;
    assert!(
        final_step >= 3,
        "three bursts and the end make at least steps 0 to 3: {traced:?}"
    );
    assert_eq!(
        traced.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
        (0..=final_step).collect::<Vec<_>>(),
        "the steps are consecutive from 0"
    );
    assert_eq!(
        printed_digests, traced,
        "the printed digests are the trace's"
    );
    let end = events.iter().find(|e| e["type"] == "run_end").unwrap();
    assert_eq!(end["chain_head"].as_str().unwrap(), head);
    assert_eq!(end["final_step"].as_u64().unwrap(), final_step);

    // diff from the original to the end lists what the agent did
    let diff = run_leash(
        &["diff", &format!("{id}:0"), &id, "--state-dir", &state_arg],
        &ws,
    );
    assert_eq!(diff.status.code(), Some(0), "{}", stderr(&diff));
    let listing = stdout(&diff);
    for expected in [
        "M  a.txt",
        "D  sub/b.txt",
        "A  sub/deep/c.txt",
        "A  renamed.txt",
        "D  empty",
        "T  link (symlink -> file)",
    ] {
        assert!(
            listing.lines().any(|l| l == expected),
            "{expected:?} is listed:\n{listing}"
        );
    }
    assert!(!listing.contains("no differences"), "{listing}");

    // the printed command restores the original tree exactly: content, modes and mtimes
    let rewind = run_printed(&hint["leash: to undo this run: ".len()..]);
    assert_eq!(rewind.status.code(), Some(0), "{}", stderr(&rewind));
    assert!(
        stdout(&rewind).lines().any(|l| l == NOTICE),
        "{}",
        stdout(&rewind)
    );
    assert!(
        stdout(&rewind).contains(&format!("chain head: {head}")),
        "{}",
        stdout(&rewind)
    );
    assert!(
        !stderr(&rewind).contains("no --expect given"),
        "the printed command carries --expect: {}",
        stderr(&rewind)
    );
    assert_eq!(tree_state(&ws), original, "rewound to step 0");

    // and `--step` with `--expect` goes forward again to the end state
    let forward = run_leash(
        &[
            "rewind",
            &id,
            "--step",
            &final_step.to_string(),
            "--expect",
            &head,
            "--state-dir",
            &state_arg,
        ],
        &ws,
    );
    assert_eq!(forward.status.code(), Some(0), "{}", stderr(&forward));
    assert_eq!(tree_state(&ws), after_run, "rewound to the final step");
}

#[test]
fn a_snapshot_run_passes_the_childs_exit_code_through_and_still_prints_the_command() {
    if !common::delegated_cgroup_or_skip("snapshot_run_exit_code") {
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let ws_dir = tempfile::tempdir().unwrap();
    let ws = ws_dir.path().canonicalize().unwrap();
    strip_default_acl(&ws);
    populate(&ws);
    let original = tree_state(&ws);
    let policy = state.path().join("policy.toml");
    fs::write(&policy, workspace_policy(&ws)).unwrap();
    let out = run_leash(
        &[
            "run",
            "--snapshots",
            "--state-dir",
            &state.path().to_string_lossy(),
            "--policy",
            &policy.to_string_lossy(),
            "--",
            "sh",
            "-c",
            "echo oops > a.txt; exit 7",
        ],
        &ws,
    );
    assert_eq!(out.status.code(), Some(7), "{}", stderr(&out));
    let err = stderr(&out);
    let hint = err.lines().last().unwrap();
    assert!(
        hint.starts_with("leash: to undo this run: leash rewind "),
        "{err}"
    );
    let rewind = run_printed(&hint["leash: to undo this run: ".len()..]);
    assert_eq!(rewind.status.code(), Some(0), "{}", stderr(&rewind));
    assert_eq!(tree_state(&ws), original);
}

#[test]
fn a_run_without_snapshots_prints_no_rewind_command() {
    if !common::delegated_cgroup_or_skip("run_without_snapshots") {
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let ws_dir = tempfile::tempdir().unwrap();
    let ws = ws_dir.path().canonicalize().unwrap();
    let policy = state.path().join("policy.toml");
    fs::write(&policy, workspace_policy(&ws)).unwrap();
    let out = run_leash(
        &[
            "run",
            "--state-dir",
            &state.path().to_string_lossy(),
            "--policy",
            &policy.to_string_lossy(),
            "--",
            "true",
        ],
        &ws,
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(!err.contains("to undo this run"), "{err}");
    assert!(!err.contains("snapshot chain head"), "{err}");
}

// ---- refusals ----

#[test]
fn snapshots_without_a_policy_is_a_usage_error_and_creates_nothing() {
    // enforce mode only, so there is no way to ask for a record-only snapshot run
    let work = tempfile::tempdir().unwrap();
    let state = work.path().join("state");
    for args in [
        vec!["run", "--snapshots", "--", "true"],
        vec!["run", "--unattended", "--snapshots", "--", "true"],
    ] {
        let mut full = args.clone();
        let state_arg = state.to_string_lossy().into_owned();
        full.splice(1..1, ["--state-dir", state_arg.as_str()]);
        let out = run_leash(&full, work.path());
        assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
        let err = stderr(&out);
        assert!(
            err.contains("--snapshots") && err.contains("--policy"),
            "the message names both flags: {err}"
        );
        assert!(!state.exists(), "nothing was created: {}", state.display());
    }
}

#[test]
fn a_policy_that_can_write_the_state_root_refuses_before_any_run_directory() {
    if !common::delegated_cgroup_or_skip("snapshot_overlap_refusal") {
        return;
    }
    let work = tempfile::tempdir().unwrap();
    let root = work.path().canonicalize().unwrap();
    let ws = root.join("ws");
    create_dir(&ws);
    let state = root.join("state");
    fs::create_dir(&state).unwrap();
    let policy = root.join("policy.toml");
    fs::write(
        &policy,
        format!(
            "{}[[fs]]\npath={:?}\nmode=[\"read\",\"write\",\"create\",\"delete\"]\naction=\"allow\"\n",
            workspace_policy(&ws),
            format!("{}/**", state.display())
        ),
    )
    .unwrap();
    let out = run_leash(
        &[
            "run",
            "--snapshots",
            "--state-dir",
            &state.to_string_lossy(),
            "--policy",
            &policy.to_string_lossy(),
            "--",
            "true",
        ],
        &ws,
    );
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains("snapshot integrity refused") && err.contains("state root"),
        "{err}"
    );
    assert!(
        !state.join("runs").exists(),
        "no run directory was created: {:?}",
        fs::read_dir(&state).unwrap().collect::<Vec<_>>()
    );
}
