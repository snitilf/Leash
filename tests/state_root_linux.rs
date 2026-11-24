//! enforce mode denies the agent the state root (FR-3, FR-21; ADR-0024 decision 3).
//!
//! these run only on linux and drive the real compiled binary: a previous run is produced
//! first, then an enforce-mode agent tries to read, list, tamper with, move, and plant files
//! in the state root, both the previous run and the live one. the live run's directory is
//! handed to the agent through a workspace file once the harness sees the run directory
//! appear, so the agent never needs to list the runs directory to find it.
//!
//! two kinds of agent: `sh -c` scripts whose probes are named (`p NAME cmd...`), and this
//! test binary re-exec'd (`agent_probes`, the pattern of notify_linux.rs) for syscalls a
//! shell cannot make. every probe is asserted on its own: the agent reports `DENIED name`,
//! and the trace holds a deny event for that probe with the expected syscall, path and
//! `matched_rule`, so one failing probe cannot hide behind another.
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
const PROC_RULE: &str = "implicit:supervisor_proc";

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
        std::fs::create_dir_all(layout.links()).unwrap();
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
    /// a directory for symlinks the agent is allowed to write in.
    fn links(&self) -> PathBuf {
        self.root().join("links")
    }
    fn ws(&self) -> PathBuf {
        self.ws.path().canonicalize().unwrap()
    }

    /// examples/policy.toml, optionally with write, create, and delete allowed under root,
    /// and any extra policy text appended.
    fn policy_with(&self, with_writes: bool, extra: &str) -> PathBuf {
        let mut text = include_str!("../examples/policy.toml").to_string();
        if with_writes {
            text.push_str(&format!(
                "\n[[fs]]\npath = \"{}/**\"\nmode = [\"read\", \"write\", \"create\", \"delete\"]\naction = \"allow\"\n",
                self.root().display()
            ));
        }
        text.push_str(extra);
        let path = self.cfg.path().join("policy.toml");
        std::fs::write(&path, text).unwrap();
        path
    }

    fn policy(&self, with_writes: bool) -> PathBuf {
        self.policy_with(with_writes, "")
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

/// what a hook sees while the agent is parked: the supervisor, the live run, the workspace.
struct HookCtx {
    leash_pid: u32,
    ws: PathBuf,
}

/// optional knobs of one enforce run.
#[derive(Default)]
struct Opts<'a> {
    /// the `--state-dir` argument, when it is not the plain state root.
    state_arg: Option<PathBuf>,
    /// runs once while the agent is parked after the live run appeared; the agent resumes
    /// when it returns, and can read what the hook wrote to `$WS/pids`.
    hook: Option<&'a dyn Fn(&HookCtx)>,
}

/// run an enforce agent script. the script receives `$1 ws`, `$2 state`, `$3 previous run`,
/// `$4 root`, and finds the live run directory in the file `$ws/live`. `t cmd` and
/// `p NAME cmd` print `OK` or `DENIED` for the command.
fn run_enforce(layout: &Layout, policy: &Path, prev: &Path, script: &str) -> Finished {
    run_enforce_with(layout, &Opts::default(), policy, prev, script)
}

fn run_enforce_with(
    layout: &Layout,
    opts: &Opts<'_>,
    policy: &Path,
    prev: &Path,
    script: &str,
) -> Finished {
    let known = run_names(&layout.state());
    let park = if opts.hook.is_some() {
        "echo up > \"$WS/up\"\nwhile [ ! -e \"$WS/go\" ]; do sleep 0.05; done\n"
    } else {
        ""
    };
    let wrapped = format!(
        "WS=$1; STATE=$2; PREV=$3; ROOT=$4\n\
         while [ ! -s \"$WS/live\" ]; do sleep 0.05; done\n\
         LIVE=$(cat \"$WS/live\")\n\
         t() {{ if \"$@\" >>\"$WS/.o\" 2>&1; then echo \"OK $*\"; else echo \"DENIED $*\"; fi; }}\n\
         p() {{ n=$1; shift; if \"$@\" >>\"$WS/.o\" 2>&1; then echo \"OK $n\"; else echo \"DENIED $n\"; fi; }}\n\
         {park}{script}\n"
    );
    let child = Command::new(leash_exe())
        .args(["run", "--unattended", "--state-dir"])
        .arg(opts.state_arg.clone().unwrap_or_else(|| layout.state()))
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
    drive(layout, opts, known, child)
}

/// wait for the live run directory, hand it to the agent, run the hook, wait for the exit.
fn drive(
    layout: &Layout,
    opts: &Opts<'_>,
    known: BTreeSet<String>,
    mut child: std::process::Child,
) -> Finished {
    let start = Instant::now();
    let mut live = None;
    let mut hooked = opts.hook.is_none();
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
        if !hooked && layout.ws().join("up").exists() {
            let ctx = HookCtx {
                leash_pid: child.id(),
                ws: layout.ws(),
            };
            (opts.hook.unwrap())(&ctx);
            std::fs::write(layout.ws().join("go"), b"go").unwrap();
            hooked = true;
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

/// one probe and what the trace must say about it: a deny event whose syscall starts with
/// one of `syscalls`, whose fact `field` is `value`, decided by `rule`.
struct Probe {
    name: &'static str,
    syscalls: &'static [&'static str],
    field: &'static str,
    value: PathBuf,
    rule: &'static str,
}

fn probe(
    name: &'static str,
    syscalls: &'static [&'static str],
    field: &'static str,
    value: impl Into<PathBuf>,
) -> Probe {
    Probe {
        name,
        syscalls,
        field,
        value: value.into(),
        rule: IMPLICIT,
    }
}

/// assert every probe on its own: the agent saw the denial and the trace recorded it with
/// the expected syscall, path and rule.
fn assert_probes(text: &str, run_dir: &Path, probes: &[Probe]) {
    let all = events(run_dir);
    for p in probes {
        assert!(
            text.lines().any(|l| l == format!("DENIED {}", p.name)),
            "probe {} was not denied for the agent in:\n{text}",
            p.name
        );
        let value = p.value.to_string_lossy();
        let found = all.iter().any(|e| {
            e["decision"] == "deny"
                && e["matched_rule"] == p.rule
                && e["syscall"]
                    .as_str()
                    .is_some_and(|s| p.syscalls.iter().any(|prefix| s.starts_with(prefix)))
                && e["fact"][p.field] == value.as_ref()
        });
        assert!(
            found,
            "probe {}: no deny event {:?} with {}={} decided by {}; denies seen: {:#?}",
            p.name,
            p.syscalls,
            p.field,
            value,
            p.rule,
            all.iter()
                .filter(|e| e["decision"] == "deny")
                .collect::<Vec<_>>()
        );
    }
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
p append sh -c 'echo x >> "$1"' sh "$LIVE/trace.jsonl"
p redirect_truncate sh -c ': > "$1"' sh "$LIVE/trace.jsonl"
p truncate_cmd truncate -s 0 "$LIVE/trace.jsonl"
p touch_live touch "$LIVE/planted"
p touch_state touch "$STATE/planted"
p mkdir_state mkdir "$STATE/d"
p rm_trace rm "$LIVE/trace.jsonl"
p rmdir_prev rmdir "$PREV"
p rmdir_state rmdir "$STATE"
p mv_trace mv "$LIVE/trace.jsonl" "$ROOT/stolen"
p mv_prev mv "$PREV" "$ROOT/moved"
p mv_state mv "$STATE" "$ROOT/state2"
p mv_parent mv "$ROOT/p" "$ROOT/p2"
p mv_into_state mv "$WS/file" "$STATE/x"
p ln_into_state ln "$WS/file" "$STATE/hl"
p ln_from_state ln "$LIVE/trace.jsonl" "$WS/leak"
p symlink_state ln -s /etc/passwd "$STATE/sl"
p symlink_live ln -s /etc/passwd "$LIVE/sl"
# these two fail with ENOTEMPTY in the kernel anyway, so the only thing they can prove is
# the recorded decision: the rule runs before the kernel is asked
p rmdir_parent rmdir "$ROOT/p"
p mv_over_parent mv -T "$ROOT/other" "$ROOT/p"
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
    // the live trace is intact and parseable
    assert_eq!(events(&f.live)[0]["type"], "run_start");
    // the control write outside the state root worked
    assert_eq!(std::fs::read(l.ws().join("ctl")).unwrap(), b"ok\n");
    let live = &f.live;
    assert_probes(
        &text,
        live,
        &[
            probe("append", &["open"], "path", live.join("trace.jsonl")),
            probe(
                "redirect_truncate",
                &["open"],
                "path",
                live.join("trace.jsonl"),
            ),
            probe(
                "truncate_cmd",
                &["open", "truncate"],
                "path",
                live.join("trace.jsonl"),
            ),
            probe("touch_live", &["open"], "path", live.join("planted")),
            probe("touch_state", &["open"], "path", l.state().join("planted")),
            probe("mkdir_state", &["mkdir"], "path", l.state().join("d")),
            probe("rm_trace", &["unlink"], "path", live.join("trace.jsonl")),
            probe("rmdir_prev", &["rmdir", "unlink"], "path", prev.clone()),
            probe("rmdir_state", &["rmdir", "unlink"], "path", l.state()),
            probe("mv_trace", &["rename"], "path", live.join("trace.jsonl")),
            probe("mv_prev", &["rename"], "path", prev.clone()),
            probe("mv_state", &["rename"], "path", l.state()),
            probe("mv_parent", &["rename"], "path", l.parent()),
            probe("mv_into_state", &["rename"], "dest", l.state().join("x")),
            probe("ln_into_state", &["link"], "dest", l.state().join("hl")),
            probe("ln_from_state", &["link"], "path", live.join("trace.jsonl")),
            probe("symlink_state", &["symlink"], "dest", l.state().join("sl")),
            probe("symlink_live", &["symlink"], "dest", live.join("sl")),
            probe("rmdir_parent", &["rmdir", "unlink"], "path", l.parent()),
            probe("mv_over_parent", &["rename"], "dest", l.parent()),
        ],
    );
    let report = std::fs::read_to_string(f.live.join("report.txt")).unwrap();
    assert!(report.contains("denied"), "{report}");
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
        "p via_file_link cat {l}/trace\n\
         p via_dir_link ls {l}/dir\n\
         p via_ws_link cat \"$WS/inws\"\n\
         exit 0\n",
        l = links_path.display()
    );
    let f = run_enforce(&l, &l.policy(false), &prev, &script);
    let text = stdout(&f);
    assert!(
        !probe_output(&l).contains("\"type\""),
        "trace content must not reach the agent: {text}"
    );
    // each of the three probes is decided on the resolved identity, not the spelling
    assert_probes(
        &text,
        &f.live,
        &[
            probe("via_file_link", &["open"], "path", prev.join("trace.jsonl")),
            probe("via_dir_link", &["open"], "path", l.state()),
            probe("via_ws_link", &["open"], "path", prev.join("trace.jsonl")),
        ],
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

/// the state root reached through a symlinked `--state-dir`: the agent has a write grant on
/// the link's parent, and must still not be able to rename, replace or remove the link, which
/// would redirect the operator's own spelling of the state root.
#[test]
fn enforce_protects_the_symlink_the_state_dir_was_spelled_through() {
    use std::os::unix::fs::symlink;
    let l = Layout::new();
    let prev = l.previous_run();
    let link = l.links().join("sd");
    symlink(l.state(), &link).unwrap();
    std::fs::write(l.links().join("decoy"), b"decoy").unwrap();
    let opts = Opts {
        state_arg: Some(link.clone()),
        hook: None,
    };
    let script = format!(
        "p mv_hop mv {link} \"$ROOT/links/moved\"\n\
         p replace_hop mv -T \"$ROOT/links/decoy\" {link}\n\
         p rm_hop rm {link}\n\
         p ln_force_hop ln -sfn /nonexistent {link}\n\
         p mv_links_dir mv \"$ROOT/links\" \"$ROOT/links2\"\n\
         exit 0\n",
        link = link.display()
    );
    let f = run_enforce_with(&l, &opts, &l.policy(true), &prev, &script);
    let text = stdout(&f);
    assert!(f.out.status.success(), "{:?}", f.out);
    assert_eq!(std::fs::read_link(&link).unwrap(), l.state());
    assert_eq!(std::fs::read(l.links().join("decoy")).unwrap(), b"decoy");
    assert!(!l.links().join("moved").exists());
    assert!(!l.root().join("links2").exists());
    assert_probes(
        &text,
        &f.live,
        &[
            probe("mv_hop", &["rename"], "path", link.clone()),
            probe("replace_hop", &["rename"], "dest", link.clone()),
            probe("rm_hop", &["unlink"], "path", link.clone()),
            probe("ln_force_hop", &["unlink"], "path", link.clone()),
            probe("mv_links_dir", &["rename"], "path", l.links()),
        ],
    );
}

fn ppid_of(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // the command name is parenthesised and may contain spaces; ppid is the second field after it
    let after = stat.rsplit_once(')')?.1;
    after.split_whitespace().nth(1)?.parse().ok()
}

fn children_of(parent: u32) -> Vec<u32> {
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| ppid_of(*pid) == Some(parent))
        .collect()
}

fn comm_of(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// what every descriptor of `pid` points at. panics when the table cannot be read, so a
/// check never passes by seeing nothing.
fn fd_targets(pid: u32) -> Vec<String> {
    let dir = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap_or_else(|e| panic!("cannot read /proc/{pid}/fd: {e}"));
    dir.filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .map(|t| t.to_string_lossy().into_owned())
        .collect()
}

/// the broker is a forked copy of the supervisor, so it inherited the live trace descriptor
/// unless it closed it. and neither process's `/proc/<pid>` tree may be reached by the agent,
/// whatever it is granted: `mem` there is the supervisor's memory.
#[test]
fn broker_holds_no_trace_descriptor_and_the_supervisor_proc_tree_is_denied() {
    let l = Layout::new();
    let prev = l.previous_run();
    let pids = std::sync::Mutex::new(None::<(u32, u32)>);
    let hook = |ctx: &HookCtx| {
        let kids = children_of(ctx.leash_pid);
        let broker = kids
            .iter()
            .copied()
            .find(|pid| comm_of(*pid) == "leash")
            .unwrap_or_else(|| panic!("no broker among {kids:?}"));
        // the supervisor holds the trace, which proves the check below can see one
        let sup = fd_targets(ctx.leash_pid);
        assert!(
            sup.iter().any(|t| t.ends_with("/trace.jsonl")),
            "the supervisor's own descriptors show no trace: {sup:?}"
        );
        let held = fd_targets(broker);
        assert!(
            held.len() >= 4,
            "the broker keeps stdio and its socket at least: {held:?}"
        );
        assert!(
            held.iter().all(|t| !t.contains("trace.jsonl")),
            "the broker inherited the live trace: {held:?}"
        );
        assert!(
            held.iter().all(|t| !t.contains("/runs/")),
            "the broker inherited a run directory descriptor: {held:?}"
        );
        std::fs::write(
            ctx.ws.join("pids"),
            format!("{} {}\n", ctx.leash_pid, broker),
        )
        .unwrap();
        *pids.lock().unwrap() = Some((ctx.leash_pid, broker));
    };
    let opts = Opts {
        state_arg: None,
        hook: Some(&hook),
    };
    let policy = l.policy_with(
        true,
        "\n[[fs]]\npath = \"/proc/**\"\nmode = [\"read\", \"write\"]\naction = \"allow\"\n",
    );
    let f = run_enforce_with(
        &l,
        &opts,
        &policy,
        &prev,
        r#"
read SUP BROKER < "$WS/pids"
p sup_mem_read sh -c ': < /proc/$1/mem' sh "$SUP"
p sup_mem_write sh -c ': >> /proc/$1/mem' sh "$SUP"
p sup_fd_dir ls "/proc/$SUP/fd"
p broker_mem_read sh -c ': < /proc/$1/mem' sh "$BROKER"
p broker_mem_write sh -c ': >> /proc/$1/mem' sh "$BROKER"
p broker_task_dir ls "/proc/$BROKER/task"
exit 0
"#,
    );
    let text = stdout(&f);
    let (sup, broker) = pids.lock().unwrap().expect("the hook ran");
    let denial = |name, syscalls, pid: u32, tail: &str| Probe {
        name,
        syscalls,
        field: "path",
        value: PathBuf::from(format!("/proc/{pid}/{tail}")),
        rule: PROC_RULE,
    };
    assert_probes(
        &text,
        &f.live,
        &[
            denial("sup_mem_read", &["open"], sup, "mem"),
            denial("sup_mem_write", &["open"], sup, "mem"),
            denial("sup_fd_dir", &["open"], sup, "fd"),
            denial("broker_mem_read", &["open"], broker, "mem"),
            denial("broker_mem_write", &["open"], broker, "mem"),
            denial("broker_task_dir", &["open"], broker, "task"),
        ],
    );
}

/// raw-syscall probes a shell cannot make, run as the agent of the next test.
#[test]
fn agent_probes() {
    use std::ffi::CString;
    if std::env::var_os("LEASH_SR_AGENT").is_none() {
        return;
    }
    let env = |k: &str| std::env::var(k).unwrap();
    let c = |s: &str| CString::new(s).unwrap();
    let report = |name: &str, rc: i64| {
        println!("{} {name}", if rc < 0 { "DENIED" } else { "OK" });
    };
    let (parent, state, prev) = (env("SR_PARENT"), env("SR_STATE"), env("SR_PREV"));
    // the live run directory is handed over through the workspace once the run starts
    let ws = env("SR_WS");
    let live = loop {
        match std::fs::read_to_string(format!("{ws}/live")) {
            Ok(text) if !text.is_empty() => break text,
            _ => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    };
    let (root, link) = (env("SR_ROOT"), env("SR_LINK"));
    // SAFETY: every call below passes nul-terminated paths this function owns and checks
    // the return value; none of them takes a pointer the kernel writes through.
    unsafe {
        let (uid, gid) = (libc::getuid(), libc::getgid());
        report("chmod_parent", libc::chmod(c(&parent).as_ptr(), 0).into());
        report("chmod_state", libc::chmod(c(&state).as_ptr(), 0).into());
        report(
            "chown_parent",
            libc::chown(c(&parent).as_ptr(), uid, gid).into(),
        );
        report(
            "chown_state",
            libc::chown(c(&state).as_ptr(), uid, gid).into(),
        );

        // an O_PATH handle on a file in the root
        let fd = libc::open(
            c(&format!("{prev}/trace.jsonl")).as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC,
        );
        report("opath_open", fd.into());

        // a directory handle on an ancestor is allowed (control); a relative open through it
        // that lands in the root is not, and a sibling through it still is
        let dirfd = libc::open(
            c(&parent).as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        );
        report("ctl_ancestor_dirfd", dirfd.into());
        let rel = prev
            .strip_prefix(&format!("{parent}/"))
            .unwrap()
            .to_string();
        let fd = libc::openat(
            dirfd,
            c(&format!("{rel}/meta.json")).as_ptr(),
            libc::O_RDONLY,
        );
        report("dirfd_openat", fd.into());
        let fd = libc::openat(dirfd, c("state-other/f").as_ptr(), libc::O_RDONLY);
        report("ctl_dirfd_sibling", fd.into());

        // `..` out of an unrelated directory and back into the root
        let live_name = live.rsplit('/').next().unwrap().to_string();
        let fd = libc::open(
            c(&format!(
                "{root}/other/../p/state/runs/{live_name}/meta.json"
            ))
            .as_ptr(),
            libc::O_RDONLY,
        );
        report("dotdot_open", fd.into());

        // RENAME_EXCHANGE swaps the two names, so on the ancestor it would replace it
        const EXCHANGE: libc::c_uint = 2;
        let other = format!("{root}/other");
        let rc = libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            c(&parent).as_ptr(),
            libc::AT_FDCWD,
            c(&other).as_ptr(),
            EXCHANGE,
        );
        report("exchange_source", rc);
        let rc = libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            c(&other).as_ptr(),
            libc::AT_FDCWD,
            c(&parent).as_ptr(),
            EXCHANGE,
        );
        report("exchange_dest", rc);

        // exec last: a success would replace this process
        let arg0 = c("x");
        let argv = [arg0.as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null::<libc::c_char>()];
        for (name, path) in [
            ("exec_spelled", format!("{state}/exe.sh")),
            ("exec_symlink", format!("{link}/exe.sh")),
            ("exec_dotdot", format!("{root}/other/../p/state/exe.sh")),
        ] {
            report(
                name,
                libc::execve(c(&path).as_ptr(), argv.as_ptr(), envp.as_ptr()).into(),
            );
        }
    }
}

/// metadata changes on the root and an ancestor, O_PATH and dirfd-relative opens, `..`
/// traversal, RENAME_EXCHANGE on an ancestor, and exec by three spellings, all under a policy
/// that grants everything under the root: each must be denied by the implicit rule alone.
#[test]
fn enforce_denies_metadata_handle_traversal_exchange_and_exec_probes() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let l = Layout::new();
    let prev = l.previous_run();
    let exe = l.state().join("exe.sh");
    std::fs::write(
        &exe,
        format!("#!/bin/sh\ntouch '{}/exec-ran'\n", l.ws().display()),
    )
    .unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    symlink(l.state(), l.links().join("stlink")).unwrap();
    let parent_mode = std::fs::metadata(l.parent()).unwrap().permissions().mode();
    let state_mode = std::fs::metadata(l.state()).unwrap().permissions().mode();

    let known = run_names(&l.state());
    let agent = std::env::current_exe().unwrap();
    let child = Command::new(leash_exe())
        .args(["run", "--unattended", "--state-dir"])
        .arg(l.state())
        .arg("--policy")
        .arg(l.policy(true))
        .arg("--")
        .arg(&agent)
        .args(["--exact", "agent_probes", "--nocapture"])
        .env("LEASH_SR_AGENT", "1")
        .env("SR_PARENT", l.parent())
        .env("SR_STATE", l.state())
        .env("SR_PREV", &prev)
        .env("SR_ROOT", l.root())
        .env("SR_LINK", l.links().join("stlink"))
        .env("SR_WS", l.ws())
        .current_dir(l.ws())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let f = drive(&l, &Opts::default(), known, child);
    let text = stdout(&f);
    assert!(
        text.lines().any(|n| n == "OK ctl_ancestor_dirfd")
            && text.lines().any(|n| n == "OK ctl_dirfd_sibling"),
        "the control probes must succeed: {text}"
    );

    // nothing the probes attempted took effect
    assert_eq!(
        std::fs::metadata(l.parent()).unwrap().permissions().mode(),
        parent_mode
    );
    assert_eq!(
        std::fs::metadata(l.state()).unwrap().permissions().mode(),
        state_mode
    );
    assert!(l.state().exists() && l.sibling().exists() && !l.other().join("state").exists());
    assert!(!l.ws().join("exec-ran").exists(), "the exec ran: {text}");

    assert_probes(
        &text,
        &f.live,
        &[
            probe("chmod_parent", &["chmod", "fchmodat"], "path", l.parent()),
            probe("chmod_state", &["chmod", "fchmodat"], "path", l.state()),
            probe(
                "chown_parent",
                &["chown", "fchownat", "lchown"],
                "path",
                l.parent(),
            ),
            probe(
                "chown_state",
                &["chown", "fchownat", "lchown"],
                "path",
                l.state(),
            ),
            probe("opath_open", &["open"], "path", prev.join("trace.jsonl")),
            probe("dirfd_openat", &["open"], "path", prev.join("meta.json")),
            probe("dotdot_open", &["open"], "path", f.live.join("meta.json")),
            probe("exchange_source", &["rename"], "path", l.parent()),
            probe("exchange_dest", &["rename"], "dest", l.parent()),
            probe("exec_spelled", &["exec"], "binary", exe.clone()),
            probe(
                "exec_symlink",
                &["exec"],
                "binary",
                l.links().join("stlink/exe.sh"),
            ),
            probe(
                "exec_dotdot",
                &["exec"],
                "binary",
                l.root().join("other/../p/state/exe.sh"),
            ),
        ],
    );
    let report = std::fs::read_to_string(f.live.join("report.txt")).unwrap();
    assert!(
        report.contains("denied"),
        "the report still renders: {report}"
    );
}
