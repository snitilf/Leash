//! enforce mode denies the agent the state root (FR-3, FR-21; ADR-0024 decision 3).
//!
//! these run only on linux and drive the real compiled binary: a previous run is produced
//! first, then an enforce-mode agent (`sh -c`) tries to read, list, tamper with, move, and
//! plant files in the state root, both the previous run and the live one. the live run's
//! directory is handed to the agent through a workspace file once the harness sees the run
//! directory appear, so the agent never needs to list the runs directory to find it.
//!
//! layout of every test: `<root>/p/state` is the state root, `<root>/p/state-other` is a
//! sibling that shares its string prefix, `<root>/other` is an unrelated directory. the
//! policy allows everything under `<root>`, so any refusal on a path in the state root comes
//! from the implicit rule, not from a missing allow.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(30);
const IMPLICIT: &str = "implicit:state_root";

fn leash_exe() -> &'static str {
    env!("CARGO_BIN_EXE_leash")
}

struct Layout {
    root: tempfile::TempDir,
    ws: tempfile::TempDir,
    cfg: tempfile::TempDir,
}

impl Layout {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let layout = Self { root, ws, cfg };
        std::fs::create_dir_all(layout.state().parent().unwrap()).unwrap();
        std::fs::create_dir_all(layout.sibling()).unwrap();
        std::fs::create_dir_all(layout.other()).unwrap();
        std::fs::write(layout.sibling().join("f"), b"sibling-data").unwrap();
        std::fs::write(layout.ws.path().join("file"), b"ws-data").unwrap();
        layout
    }

    fn root(&self) -> PathBuf {
        self.root.path().canonicalize().unwrap()
    }
    fn parent(&self) -> PathBuf {
        self.root().join("p")
    }
    /// the state root is created by the first run; its parent exists from the start.
    fn state(&self) -> PathBuf {
        self.parent().join("state")
    }
    fn sibling(&self) -> PathBuf {
        self.parent().join("state-other")
    }
    fn other(&self) -> PathBuf {
        self.root().join("other")
    }
    fn ws(&self) -> PathBuf {
        self.ws.path().canonicalize().unwrap()
    }

    /// examples/policy.toml, optionally with write, create, and delete allowed under root.
    fn policy(&self, with_writes: bool) -> PathBuf {
        let mut text = include_str!("../examples/policy.toml").to_string();
        if with_writes {
            text.push_str(&format!(
                "\n[[fs]]\npath = \"{}/**\"\nmode = [\"read\", \"write\", \"create\", \"delete\"]\naction = \"allow\"\n",
                self.root().display()
            ));
        }
        let path = self.cfg.path().join("policy.toml");
        std::fs::write(&path, text).unwrap();
        path
    }

    /// one record-only run that leaves a finished previous run in the state root.
    fn previous_run(&self) -> PathBuf {
        let out = Command::new(leash_exe())
            .args(["run", "--unattended", "--state-dir"])
            .arg(self.state())
            .args(["--", "true"])
            .current_dir(self.ws())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        let runs = run_names(&self.state());
        assert_eq!(runs.len(), 1);
        self.state()
            .join("runs")
            .join(runs.into_iter().next().unwrap())
    }
}

fn run_names(state: &Path) -> BTreeSet<String> {
    match std::fs::read_dir(state.join("runs")) {
        Ok(rd) => rd
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => BTreeSet::new(),
    }
}

struct Finished {
    out: Output,
    live: PathBuf,
}

/// run an enforce agent script. the script receives `$1 ws`, `$2 state`, `$3 previous run`,
/// `$4 root`, and finds the live run directory in the file `$ws/live`.
fn run_enforce(layout: &Layout, policy: &Path, prev: &Path, script: &str) -> Finished {
    let known = run_names(&layout.state());
    let wrapped = format!(
        "WS=$1; STATE=$2; PREV=$3; ROOT=$4\n\
         while [ ! -s \"$WS/live\" ]; do sleep 0.05; done\n\
         LIVE=$(cat \"$WS/live\")\n\
         t() {{ if \"$@\" >>\"$WS/.o\" 2>&1; then echo \"OK $*\"; else echo \"DENIED $*\"; fi; }}\n\
         {script}\n"
    );
    let mut child = Command::new(leash_exe())
        .args(["run", "--unattended", "--state-dir"])
        .arg(layout.state())
        .arg("--policy")
        .arg(policy)
        .args(["--", "/bin/sh", "-c", &wrapped, "sh"])
        .arg(layout.ws())
        .arg(layout.state())
        .arg(prev)
        .arg(layout.root())
        .current_dir(layout.ws())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let mut live = None;
    loop {
        if live.is_none() {
            let now = run_names(&layout.state());
            if let Some(new) = now.difference(&known).next() {
                let dir = layout.state().join("runs").join(new);
                if dir.join("trace.jsonl").exists() {
                    let tmp = layout.ws().join("live.tmp");
                    std::fs::write(&tmp, dir.to_string_lossy().as_bytes()).unwrap();
                    std::fs::rename(&tmp, layout.ws().join("live")).unwrap();
                    live = Some(dir);
                }
            }
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if start.elapsed() > DEADLINE {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            panic!("leash exceeded the deadline: {out:?}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let out = child.wait_with_output().unwrap();
    Finished {
        out,
        live: live.expect("the live run directory appeared"),
    }
}

fn events(run_dir: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(run_dir.join("trace.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).expect("every trace line parses"))
        .collect()
}

fn implicit_denies(run_dir: &Path) -> Vec<serde_json::Value> {
    events(run_dir)
        .into_iter()
        .filter(|e| e["matched_rule"] == IMPLICIT && e["decision"] == "deny")
        .collect()
}

/// everything the agent's probes wrote to stdout and stderr.
fn probe_output(l: &Layout) -> String {
    std::fs::read_to_string(l.ws().join(".o")).unwrap_or_default()
}

fn stdout(f: &Finished) -> String {
    String::from_utf8_lossy(&f.out.stdout).into_owned()
}

fn assert_denied(text: &str, needle: &str) {
    assert!(
        text.lines()
            .any(|l| l.starts_with("DENIED ") && l.contains(needle)),
        "expected a DENIED line containing {needle:?} in:\n{text}"
    );
}

fn mentions(events: &[serde_json::Value], path: &Path) -> bool {
    let p = path.to_string_lossy();
    events
        .iter()
        .any(|e| e["fact"]["path"] == p.as_ref() || e["fact"]["dest"] == p.as_ref())
}

#[test]
fn enforce_agent_cannot_read_or_list_the_state_root_under_the_example_policy() {
    let l = Layout::new();
    let prev = l.previous_run();
    let f = run_enforce(
        &l,
        &l.policy(false),
        &prev,
        r#"
t cat "$WS/file"
t cat "$PREV/meta.json"
t cat "$PREV/trace.jsonl"
t cat "$LIVE/meta.json"
t cat "$LIVE/trace.jsonl"
t ls "$STATE"
t ls "$STATE/runs"
t ls "$PREV"
t ls "$LIVE"
cd "$STATE/runs" && t ls .
exit 0
"#,
    );
    let text = stdout(&f);
    assert!(text.contains("OK cat"), "workspace control read: {text}");
    for needle in [
        "meta.json",
        "trace.jsonl",
        &format!("ls {}", l.state().display()),
        &format!("ls {}/runs", l.state().display()),
        &format!("ls {}", prev.display()),
        &format!("ls {}", f.live.display()),
    ] {
        assert_denied(&text, needle);
    }
    assert_denied(&text, "ls .");
    assert!(
        !probe_output(&l).contains("\"type\""),
        "trace content must not reach the agent: {text}"
    );
    let denies = implicit_denies(&f.live);
    assert!(mentions(&denies, &prev.join("meta.json")), "{denies:#?}");
    assert!(
        mentions(&denies, &f.live.join("trace.jsonl")),
        "{denies:#?}"
    );
    assert!(mentions(&denies, &l.state().join("runs")), "{denies:#?}");
    let report = std::fs::read_to_string(f.live.join("report.txt")).unwrap();
    assert!(report.contains("denied"), "{report}");
}

#[test]
fn enforce_agent_cannot_tamper_with_the_state_root_even_with_write_grants() {
    let l = Layout::new();
    let prev = l.previous_run();
    let f = run_enforce(
        &l,
        &l.policy(true),
        &prev,
        r#"
echo ok > "$WS/ctl"
t sh -c 'echo x >> "$1"' sh "$LIVE/trace.jsonl"
t sh -c ': > "$1"' sh "$LIVE/trace.jsonl"
t truncate -s 0 "$LIVE/trace.jsonl"
t touch "$LIVE/planted"
t touch "$STATE/planted"
t mkdir "$STATE/d"
t rm "$LIVE/trace.jsonl"
t mv "$LIVE/trace.jsonl" "$ROOT/stolen"
t mv "$PREV" "$ROOT/moved"
t rm -rf "$PREV"
t mv "$ROOT/p" "$ROOT/p2"
t rmdir "$ROOT/p"
t mv -T "$ROOT/other" "$ROOT/p"
t mv "$STATE" "$ROOT/state2"
t rm -rf "$STATE"
t mv "$WS/file" "$STATE/x"
t ln "$WS/file" "$STATE/hl"
t ln "$LIVE/trace.jsonl" "$WS/leak"
t ln -s /etc/passwd "$STATE/sl"
t ln -s /etc/passwd "$LIVE/sl"
exit 0
"#,
    );
    let text = stdout(&f);
    assert!(f.out.status.success(), "{:?}", f.out);
    // the on-disk state is untouched
    assert!(prev.join("meta.json").exists() && prev.join("trace.jsonl").exists());
    for name in ["planted", "d", "x", "hl", "sl"] {
        assert!(!l.state().join(name).exists(), "{name} was planted");
        assert!(!f.live.join(name).exists(), "{name} was planted");
    }
    assert!(!l.root().join("stolen").exists());
    assert!(!l.root().join("moved").exists());
    assert!(!l.root().join("state2").exists());
    assert!(!l.root().join("p2").exists());
    assert!(!l.ws().join("leak").exists());
    assert!(l.other().exists(), "the unrelated directory was not moved");
    // the live trace is intact and parseable, and holds the denies under the implicit id
    let all = events(&f.live);
    assert_eq!(all[0]["type"], "run_start");
    let denies = implicit_denies(&f.live);
    for syscall in ["openat", "unlinkat", "linkat", "symlinkat", "mkdirat"] {
        assert!(
            denies.iter().any(|e| e["syscall"] == syscall),
            "no implicit deny for {syscall}: {denies:#?}"
        );
    }
    assert!(
        denies.iter().any(|e| e["syscall"]
            .as_str()
            .is_some_and(|s| s.starts_with("rename"))),
        "{denies:#?}"
    );
    // ancestor protection: moving or removing the state root's parent, and renaming over it
    let p = l.parent();
    assert!(
        denies
            .iter()
            .any(|e| e["fact"]["path"] == p.to_string_lossy().as_ref()
                && e["syscall"]
                    .as_str()
                    .is_some_and(|s| s.starts_with("rename"))),
        "rename of the parent is not denied by the implicit rule: {denies:#?}"
    );
    assert!(
        denies
            .iter()
            .any(|e| e["fact"]["dest"] == p.to_string_lossy().as_ref()),
        "rename onto the parent is not denied by the implicit rule: {denies:#?}"
    );
    assert!(
        denies
            .iter()
            .any(|e| e["fact"]["path"] == l.state().to_string_lossy().as_ref()),
        "{denies:#?}"
    );
    // the control write outside the state root worked
    assert_eq!(std::fs::read(l.ws().join("ctl")).unwrap(), b"ok\n");
    assert_denied(&text, "truncate -s 0");
    assert_denied(&text, "mv ");
}

#[test]
fn enforce_denies_a_symlink_that_resolves_into_the_state_root() {
    use std::os::unix::fs::symlink;
    let l = Layout::new();
    let prev = l.previous_run();
    let links = tempfile::tempdir().unwrap();
    let links_path = links.path().canonicalize().unwrap();
    symlink(prev.join("trace.jsonl"), links_path.join("trace")).unwrap();
    symlink(l.state(), links_path.join("dir")).unwrap();
    symlink(prev.join("trace.jsonl"), l.ws().join("inws")).unwrap();
    let script = format!(
        "t cat {l}/trace\nt ls {l}/dir\nt cat \"$WS/inws\"\nexit 0\n",
        l = links_path.display()
    );
    let f = run_enforce(&l, &l.policy(false), &prev, &script);
    let text = stdout(&f);
    assert_denied(&text, &format!("{}/trace", links_path.display()));
    assert_denied(&text, &format!("{}/dir", links_path.display()));
    assert_denied(&text, "inws");
    assert!(!probe_output(&l).contains("\"type\""));
    let denies = implicit_denies(&f.live);
    assert!(
        mentions(&denies, &prev.join("trace.jsonl")),
        "the decision is on the resolved identity: {denies:#?}"
    );
}

#[test]
fn enforce_allows_a_sibling_that_only_shares_a_string_prefix_with_the_state_root() {
    let l = Layout::new();
    let prev = l.previous_run();
    let f = run_enforce(
        &l,
        &l.policy(true),
        &prev,
        r#"
t cat "$ROOT/p/state-other/f"
t sh -c 'echo y > "$1"' sh "$ROOT/p/state-other/g"
t touch "$ROOT/other/h"
exit 0
"#,
    );
    let text = stdout(&f);
    assert!(text.contains("OK cat"), "{text}");
    assert!(!text.contains("DENIED"), "{text}");
    assert_eq!(std::fs::read(l.sibling().join("g")).unwrap(), b"y\n");
    assert!(l.other().join("h").exists());
    assert!(implicit_denies(&f.live).is_empty());
}

#[test]
fn record_only_mode_does_not_apply_the_implicit_rule() {
    let l = Layout::new();
    let prev = l.previous_run();
    let out = Command::new(leash_exe())
        .args(["run", "--unattended", "--state-dir"])
        .arg(l.state())
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(format!(
            "cat '{p}/meta.json' >/dev/null && : > '{p}/planted'",
            p = prev.display()
        ))
        .current_dir(l.ws())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(prev.join("planted").exists());
}
