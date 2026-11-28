//! the protection of a snapshot-integrity enforce run (ADR-0024 decisions 4, 5 and 6): the
//! implicit deny of every cgroup2 mount, the refusal of a policy whose Landlock grants could
//! change the state root or a cgroup2 mount, and the refusal of a host whose Landlock ABI is
//! below 3.
//!
//! the tests that run an agent need a delegated cgroup v2 (see `run_cgroup_linux.rs` for how
//! to make one); without one they skip and say why, and with `LEASH_REQUIRE_FREEZER=1` they
//! fail instead. the refusal tests run before any cgroup is touched, so they need none.
//! every test forks, so all of them serialize under one lock.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use leash::recorder::{Attendance, Mode};
use leash::supervisor::cgroup_mounts::CgroupMounts;
use leash::supervisor::preflight;
use leash::supervisor::session::{
    ExitDisposition, SessionError, SessionHooks, SessionSpec, run_session, run_session_with_hooks,
};

static SPAWN_LOCK: Mutex<()> = Mutex::new(());

fn spawn_lock() -> MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

const POLICY: &str = "schema_version = 1\n\
    [[fs]]\npath=\"/**\"\nmode=[\"read\"]\naction=\"allow\"\n\
    [[exec]]\nbinary=\"/**\"\naction=\"allow\"\n";

const CGROUP_RULE: &str = "implicit:cgroup";
const OVERLAP_RESIDUAL: &str = "landlock:snapshot_store_read_overlap";

/// the first cgroup2 mount of this mount namespace, as the supervisor reads it.
fn mount() -> PathBuf {
    CgroupMounts::from_proc_self()
        .unwrap()
        .paths()
        .first()
        .cloned()
        .expect("this host has a cgroup2 mount")
}

/// the supervisor's own cgroup directory, the parent of every run cgroup.
fn parent_cgroup_dir() -> PathBuf {
    let own = std::fs::read_to_string("/proc/self/cgroup")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .unwrap()
        .to_string();
    mount().join(own.trim_start_matches('/'))
}

struct Session {
    /// keeps the state root's directory alive; the root itself is `state_dir`, which may
    /// be nested inside it
    _state_guard: tempfile::TempDir,
    state_dir: PathBuf,
    ws: tempfile::TempDir,
    snapshot: bool,
}

impl Session {
    fn new() -> Self {
        Self::with_state(tempfile::tempdir().unwrap())
    }

    fn with_state(state: tempfile::TempDir) -> Self {
        let dir = state.path().to_path_buf();
        Self::nested(state, dir)
    }

    /// a state root `dir` somewhere beneath `guard`, which must already exist.
    fn nested(guard: tempfile::TempDir, dir: PathBuf) -> Self {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("policy.toml"), POLICY).unwrap();
        Self {
            _state_guard: guard,
            state_dir: dir,
            ws: tempfile::tempdir().unwrap(),
            snapshot: true,
        }
    }

    /// the same session without snapshot integrity, as a plain enforce run.
    fn plain() -> Self {
        Self {
            snapshot: false,
            ..Self::new()
        }
    }

    fn write_policy(&self, policy: &str) {
        std::fs::write(self.state_dir.join("policy.toml"), policy).unwrap();
    }

    fn ws(&self) -> PathBuf {
        self.ws.path().to_path_buf()
    }

    fn spec(&self, argv: &[&str]) -> SessionSpec {
        SessionSpec {
            argv: argv.iter().map(ToString::to_string).collect(),
            mode: Mode::Enforce,
            attendance: Attendance::Unattended,
            state_root: self.state_dir.to_path_buf(),
            state_root_spelling: self.state_dir.to_path_buf(),
            workspace: self.ws.path().to_path_buf(),
            policy_path: Some(self.state_dir.join("policy.toml")),
            ask_timeout: Duration::from_secs(60),
            snapshot_integrity: self.snapshot,
        }
    }

    fn run(&self, argv: &[&str]) -> Result<Run, SessionError> {
        finish(run_session(self.spec(argv))?)
    }

    fn python(&self, script: &str) -> Result<Run, SessionError> {
        self.run(&["/usr/bin/python3", "-c", script])
    }

    /// no run directory was created, which is what "refused before spawn" means here.
    fn assert_no_run_directory(&self) {
        assert!(
            !self.state_dir.join("runs").exists(),
            "a refused run must not create a run directory"
        );
    }
}

struct Run {
    exit: ExitDisposition,
    events: Vec<serde_json::Value>,
}

fn finish(outcome: leash::supervisor::session::SessionOutcome) -> Result<Run, SessionError> {
    let events = std::fs::read_to_string(outcome.run_path.join("trace.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    Ok(Run {
        exit: outcome.exit,
        events,
    })
}

impl Run {
    fn assert_exit_zero(&self) {
        assert!(
            matches!(self.exit, ExitDisposition::Exited(0)),
            "the agent script asserts its own expectations: {:?}",
            self.exit
        );
    }

    fn run_cgroup(&self) -> PathBuf {
        PathBuf::from(self.events[0]["run_cgroup"].as_str().unwrap())
    }

    fn residuals(&self) -> Vec<String> {
        self.events[0]["landlock_residuals"]
            .as_array()
            .map(|a| a.iter().map(|v| v.as_str().unwrap().to_string()).collect())
            .unwrap_or_default()
    }

    fn rule_events(&self, rule: &str) -> Vec<&serde_json::Value> {
        self.events
            .iter()
            .filter(|e| e["matched_rule"] == rule)
            .collect()
    }

    /// is there a deny decided by `rule` for a syscall starting with one of `syscalls`,
    /// whose fact `field` is `value`?
    fn has_deny(&self, rule: &str, syscalls: &[&str], field: &str, value: &Path) -> bool {
        let value = value.to_string_lossy();
        self.events.iter().any(|e| {
            e["decision"] == "deny"
                && e["matched_rule"] == rule
                && e["syscall"]
                    .as_str()
                    .is_some_and(|s| syscalls.iter().any(|prefix| s.starts_with(prefix)))
                && e["fact"][field] == value.as_ref()
        })
    }

    fn denies_seen(&self) -> Vec<&serde_json::Value> {
        self.events
            .iter()
            .filter(|e| e["decision"] == "deny")
            .collect()
    }
}

/// python that runs in the agent and defines `mount`, `own` (its run cgroup directory),
/// `parent` (the supervisor's cgroup directory) and `denied(fn, what)`, which passes only
/// when the call fails with the EACCES the supervisor answers a denial with.
fn agent_prelude() -> String {
    format!(
        "import errno, os\n\
         mount = {mount:?}\n\
         parent = {parent:?}\n\
         me = open('/proc/%d/cgroup' % os.getpid()).read().split('0::')[1].strip()\n\
         own = (mount + '/' + me.lstrip('/')).rstrip('/')\n\
         def denied(fn, what):\n\
         \x20   try:\n\
         \x20       fn()\n\
         \x20   except OSError as e:\n\
         \x20       assert e.errno == errno.EACCES, (what, e)\n\
         \x20       return\n\
         \x20   raise SystemExit('was allowed: ' + what)\n",
        mount = mount().to_string_lossy(),
        parent = parent_cgroup_dir().to_string_lossy(),
    )
}

fn delegated(test: &str) -> bool {
    common::delegated_cgroup_or_skip(test)
}

// --- decision 4: the implicit cgroup2 deny ---

#[test]
fn the_agent_cannot_open_list_or_stat_open_anything_under_the_cgroup_mount() {
    let _guard = spawn_lock();
    if !delegated("cgroup_reads") {
        return;
    }
    let session = Session::new();
    let script = format!(
        "{}\
         files = [d + '/' + n for d in (own, parent) for n in ('cgroup.procs', 'cgroup.freeze', 'cgroup.kill')]\n\
         for p in files:\n\
         \x20   denied(lambda: os.close(os.open(p, os.O_RDONLY)), 'open ' + p)\n\
         \x20   denied(lambda: os.close(os.open(p, os.O_PATH)), 'stat-open ' + p)\n\
         for d in (own, parent, mount):\n\
         \x20   denied(lambda: os.listdir(d), 'list ' + d)\n\
         \x20   denied(lambda: os.close(os.open(d, os.O_PATH | os.O_DIRECTORY)), 'stat-open ' + d)\n",
        agent_prelude()
    );
    let run = session.python(&script).unwrap();
    run.assert_exit_zero();

    let own = run.run_cgroup();
    let parent = parent_cgroup_dir();
    for dir in [&own, &parent] {
        for name in ["cgroup.procs", "cgroup.freeze", "cgroup.kill"] {
            let path = dir.join(name);
            assert!(
                run.has_deny(CGROUP_RULE, &["open"], "path", &path),
                "no {CGROUP_RULE} deny for {}: {:#?}",
                path.display(),
                run.denies_seen()
            );
        }
    }
    for dir in [own, parent, mount()] {
        assert!(
            run.has_deny(CGROUP_RULE, &["open"], "path", &dir),
            "no {CGROUP_RULE} deny for {}: {:#?}",
            dir.display(),
            run.denies_seen()
        );
    }
}

#[test]
fn the_agent_cannot_move_or_alter_an_ancestor_of_the_cgroup_mount() {
    let _guard = spawn_lock();
    if !delegated("cgroup_ancestors") {
        return;
    }
    let session = Session::new();
    std::fs::write(session.ws().join("f"), b"x").unwrap();
    let ancestor = mount().parent().unwrap().to_path_buf();
    let script = format!(
        "{}\
         anc = {ancestor:?}\n\
         ws = {ws:?}\n\
         denied(lambda: os.chmod(anc, 0o755), 'chmod ancestor')\n\
         denied(lambda: os.rename(anc, anc + '-moved'), 'rename ancestor')\n\
         denied(lambda: os.rename(ws + '/f', anc), 'rename onto ancestor')\n\
         denied(lambda: os.rmdir(anc), 'rmdir ancestor')\n",
        agent_prelude(),
        ancestor = ancestor.to_string_lossy(),
        ws = session.ws().to_string_lossy(),
    );
    let run = session.python(&script).unwrap();
    run.assert_exit_zero();
    assert!(run.has_deny(CGROUP_RULE, &["chmod", "fchmodat"], "path", &ancestor));
    assert!(run.has_deny(CGROUP_RULE, &["rename"], "path", &ancestor));
    assert!(run.has_deny(CGROUP_RULE, &["rename"], "dest", &ancestor));
    assert!(run.has_deny(CGROUP_RULE, &["rmdir", "unlinkat"], "path", &ancestor));
    assert!(session.ws().join("f").exists(), "the file was not moved");
}

/// one escape test per operation the agent could use to change the run cgroup's metadata or
/// plant a sibling run cgroup: `statement` runs in the agent and must be denied, and the trace
/// must hold a deny for `syscalls` on the path `expected` names, decided by `implicit:cgroup`.
fn escape(test: &str, statement: &str, syscalls: &[&str], expected: impl Fn(&Run) -> PathBuf) {
    let _guard = spawn_lock();
    if !delegated(test) {
        return;
    }
    let session = Session::new();
    let script = format!("{}{statement}", agent_prelude());
    let run = session.python(&script).unwrap();
    run.assert_exit_zero();
    let path = expected(&run);
    assert!(
        run.has_deny(CGROUP_RULE, syscalls, "path", &path),
        "{test}: no {CGROUP_RULE} deny {syscalls:?} for {}; denies seen: {:#?}",
        path.display(),
        run.denies_seen()
    );
}

#[test]
fn mkdir_of_a_fake_run_cgroup_sibling_is_denied() {
    // the parent cgroup is where Leash's stale cleanup looks for dead runs, so a planted
    // leash-<id> directory there holding same-uid processes would be killed by a later run
    escape(
        "mkdir_fake_sibling",
        "fake = parent + '/leash-20200101T000000Z-deadbeef'\n\
         denied(lambda: os.mkdir(fake), 'mkdir ' + fake)\n",
        &["mkdir"],
        |_| parent_cgroup_dir().join("leash-20200101T000000Z-deadbeef"),
    );
}

#[test]
fn rmdir_of_the_run_cgroup_is_denied() {
    escape(
        "rmdir_run_cgroup",
        "denied(lambda: os.rmdir(own), 'rmdir ' + own)\n",
        &["rmdir", "unlinkat"],
        Run::run_cgroup,
    );
}

#[test]
fn chmod_of_a_cgroup_control_file_is_denied() {
    escape(
        "chmod_control_file",
        "denied(lambda: os.chmod(own + '/cgroup.procs', 0o666), 'chmod')\n",
        &["chmod", "fchmodat"],
        |run| run.run_cgroup().join("cgroup.procs"),
    );
}

#[test]
fn chown_of_the_run_cgroup_is_denied() {
    escape(
        "chown_run_cgroup",
        "denied(lambda: os.chown(own, os.getuid(), os.getgid()), 'chown')\n",
        &["chown", "fchownat"],
        Run::run_cgroup,
    );
}

#[test]
fn setxattr_of_the_run_lock_is_denied() {
    escape(
        "setxattr_run_lock",
        "denied(lambda: os.setxattr(own, 'user.leash.lock', b'0:0'), 'setxattr')\n",
        &["setxattr"],
        Run::run_cgroup,
    );
}

#[test]
fn removexattr_of_the_run_lock_is_denied() {
    escape(
        "removexattr_run_lock",
        "denied(lambda: os.removexattr(own, 'user.leash.lock'), 'removexattr')\n",
        &["removexattr"],
        Run::run_cgroup,
    );
}

/// python that defines `sc(number, *args)`, a raw `syscall(2)` returning `(rc, errno)`.
/// integers go as `long`, pointers as they are.
const RAW_SYSCALL: &str = r#"
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
def sc(number, *args):
    conv = [a if isinstance(a, (ctypes.c_void_p, ctypes.c_char_p)) else ctypes.c_long(a) for a in args]
    ctypes.set_errno(0)
    rc = libc.syscall(ctypes.c_long(number), *conv)
    return rc, ctypes.get_errno()
"#;

/// unmounts a mount the test made, whatever the test does after.
struct Unmount(PathBuf);

impl Drop for Unmount {
    fn drop(&mut self) {
        let _ = std::process::Command::new("sudo")
            .args(["-n", "umount"])
            .arg(&self.0)
            .status();
    }
}

fn sudo_works() -> bool {
    std::process::Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
fn a_cgroup2_mount_made_after_the_run_started_is_denied_by_its_filesystem_type() {
    // the mounts are read once, before the child exists, so a cgroup2 mount made later is
    // unknown to the path rule. the handle the broker opens still says what filesystem it is
    // on, and a cgroup2 magic is denied whatever the path
    let _guard = spawn_lock();
    if !delegated("late_cgroup_mount") {
        return;
    }
    if !sudo_works() {
        assert!(
            std::env::var("LEASH_REQUIRE_FREEZER").as_deref() != Ok("1"),
            "LEASH_REQUIRE_FREEZER=1 but passwordless sudo is not available"
        );
        eprintln!("skipping late_cgroup_mount: no passwordless sudo to mount with");
        return;
    }
    let session = Session::new();
    let late = tempfile::tempdir().unwrap();
    let ready = session.ws().join("ready");
    let go = session.ws().join("go");
    let mounter = {
        let (ready, go, point) = (ready.clone(), go.clone(), late.path().to_path_buf());
        std::thread::spawn(move || {
            for _ in 0..600 {
                if ready.exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let mounted = std::process::Command::new("sudo")
                .args(["-n", "mount", "-t", "cgroup2", "none"])
                .arg(&point)
                .status()
                .is_ok_and(|s| s.success());
            std::fs::write(&go, if mounted { "mounted" } else { "failed" }).unwrap();
            mounted
        })
    };
    let _unmount = Unmount(late.path().to_path_buf());
    let script = format!(
        "{}{}",
        agent_prelude(),
        r#"
import time
open(@WS@ + '/ready', 'w').close()
for _ in range(600):
    if os.path.exists(@WS@ + '/go') and open(@WS@ + '/go').read():
        break
    time.sleep(0.1)
if open(@WS@ + '/go').read() != 'mounted':
    raise SystemExit(77)
denied(lambda: os.close(os.open(@LATE@ + '/cgroup.controllers', os.O_RDONLY)), 'open')
denied(lambda: os.listdir(@LATE@), 'list')
"#
        .replace("@WS@", &format!("{:?}", session.ws().to_string_lossy()))
        .replace("@LATE@", &format!("{:?}", late.path().to_string_lossy()))
    );
    let run = session.python(&script).unwrap();
    let mounted = mounter.join().unwrap();
    if !mounted {
        assert!(
            std::env::var("LEASH_REQUIRE_FREEZER").as_deref() != Ok("1"),
            "LEASH_REQUIRE_FREEZER=1 but the cgroup2 mount could not be made"
        );
        eprintln!("skipping late_cgroup_mount: mount -t cgroup2 failed here");
        return;
    }
    run.assert_exit_zero();
    let file = late.path().join("cgroup.controllers");
    assert!(
        run.has_deny(CGROUP_RULE, &["open"], "path", &file),
        "no {CGROUP_RULE} deny for {}: {:#?}",
        file.display(),
        run.denies_seen()
    );
}

#[test]
fn the_path_attribute_calls_that_libc_does_not_know_yet_are_answered_enosys_and_recorded() {
    // setxattrat (463), removexattrat (466) and file_setattr (469) name a path and need no
    // open, so an agent could set `user.leash.lock` on its run cgroup with one of them on a
    // kernel new enough. this host's kernel may predate them, which answers ENOSYS by itself,
    // so the trace event is what proves Leash intercepted the call before the kernel did
    let _guard = spawn_lock();
    if !delegated("xattrat_enosys") {
        return;
    }
    let session = Session::new();
    let script = format!(
        "{}{RAW_SYSCALL}{}",
        agent_prelude(),
        r#"
AT_FDCWD = -100
target = ctypes.c_char_p(own.encode())
name = ctypes.c_char_p(b'user.leash.lock')
args = ctypes.create_string_buffer(16)
attr = ctypes.create_string_buffer(32)
args_p = ctypes.cast(args, ctypes.c_void_p)
attr_p = ctypes.cast(attr, ctypes.c_void_p)
calls = {
    463: (AT_FDCWD, target, 0, name, args_p, 16),
    466: (AT_FDCWD, target, 0, name),
    469: (AT_FDCWD, target, attr_p, 32, 0),
}
for number, call in calls.items():
    rc, err = sc(number, *call)
    assert rc == -1 and err == errno.ENOSYS, (number, rc, err)
"#
    );
    let run = session.python(&script).unwrap();
    run.assert_exit_zero();
    for name in ["setxattrat", "removexattrat", "file_setattr"] {
        let seen: Vec<_> = run
            .rule_events("snapshot:xattrat")
            .into_iter()
            .filter(|e| e["syscall"] == name)
            .collect();
        assert_eq!(seen.len(), 1, "{name} recorded once: {:#?}", run.events);
        assert_eq!(seen[0]["decision"], "deny", "{name}");
    }
}

#[test]
fn utimensat_of_a_cgroup_control_file_is_denied() {
    escape(
        "utimensat_control_file",
        "denied(lambda: os.utime(own + '/cgroup.procs', (1, 1)), 'utime')\n",
        &["utimensat", "utimes", "utime", "futimesat"],
        |run| run.run_cgroup().join("cgroup.procs"),
    );
}

#[test]
fn the_same_metadata_calls_on_a_workspace_file_are_allowed_and_recorded() {
    let _guard = spawn_lock();
    if !delegated("metadata_in_workspace") {
        return;
    }
    let session = Session::new();
    let file = session.ws().join("f");
    std::fs::write(&file, b"x").unwrap();
    let script = format!(
        "import errno, os\n\
         f = {file:?}\n\
         os.chmod(f, 0o600)\n\
         os.chown(f, os.getuid(), os.getgid())\n\
         os.utime(f, (5, 7))\n\
         assert os.stat(f).st_mtime == 7\n\
         assert os.stat(f).st_mode & 0o777 == 0o600\n\
         fd = os.open(f, os.O_RDWR)\n\
         os.fchmod(fd, 0o640)\n\
         os.utime(fd, (9, 11))\n\
         assert os.stat(f).st_mtime == 11\n\
         assert os.stat(f).st_mode & 0o777 == 0o640\n\
         try:\n\
         \x20   os.setxattr(f, 'user.leash.test', b'1')\n\
         \x20   os.removexattr(f, 'user.leash.test')\n\
         except OSError as e:\n\
         \x20   assert e.errno == errno.ENOTSUP, e\n",
        file = file.to_string_lossy(),
    );
    let run = session.python(&script).unwrap();
    run.assert_exit_zero();
    assert!(
        run.rule_events(CGROUP_RULE).is_empty(),
        "nothing outside the cgroup mount is denied by it"
    );
    for syscalls in [
        &["chmod", "fchmodat"][..],
        &["chown", "fchownat"],
        &["utimensat"],
        &["fchmod"],
        &["setxattr"],
    ] {
        assert!(
            run.events.iter().any(|e| e["decision"] == "allow"
                && e["syscall"]
                    .as_str()
                    .is_some_and(|s| syscalls.iter().any(|p| s.starts_with(p)))
                && e["fact"]["path"] == file.to_string_lossy().as_ref()),
            "no allow event for {syscalls:?}: {:#?}",
            run.events
        );
    }
}

/// python run in the agent over a workspace `ws`: every path and descriptor form of the
/// metadata calls, on a regular file, a symlink to it and a directory, each followed by a
/// check of the effect on disk. the calls go through `syscall(2)` where libc has no wrapper
/// or picks another number, so each number the filter traps is the one exercised.
const METADATA_EFFECTS: &str = r#"
import ctypes, errno, os, stat
libc = ctypes.CDLL(None, use_errno=True)
def sc(number, *args):
    conv = [a if isinstance(a, (ctypes.c_void_p, ctypes.c_char_p)) else ctypes.c_long(a) for a in args]
    ctypes.set_errno(0)
    rc = libc.syscall(ctypes.c_long(number), *conv)
    return rc, ctypes.get_errno()
def cs(text):
    return ctypes.c_char_p(text.encode())
def ptr(array):
    return ctypes.cast(array, ctypes.c_void_p)
def ok(result, what):
    assert result == (0, 0), (what, result, errno.errorcode.get(result[1]))
def fails(result, err, what):
    assert result == (-1, err), (what, result, errno.errorcode.get(result[1]))

AT_FDCWD, NOFOLLOW, EMPTY = -100, 0x100, 0x1000
ws = @WS@
f, link, d = ws + '/f', ws + '/l', ws + '/d'
open(f, 'w').write('x')
os.symlink('f', link)
os.mkdir(d)
uid, gid = os.getuid(), os.getgid()
dfd = os.open(ws, os.O_RDONLY | os.O_DIRECTORY)
fd = os.open(f, os.O_RDWR)

# utime(132), utimes(235), futimesat(261) on a path, then on a name beneath a directory fd
ok(sc(132, cs(f), ptr((ctypes.c_long * 2)(100, 200))), 'utime')
assert (os.stat(f).st_atime, os.stat(f).st_mtime) == (100, 200)
ok(sc(235, cs(f), ptr((ctypes.c_long * 4)(300, 0, 400, 500000))), 'utimes')
assert (os.stat(f).st_atime, os.stat(f).st_mtime) == (300, 400.5)
ok(sc(261, dfd, cs('f'), ptr((ctypes.c_long * 4)(500, 0, 600, 250000))), 'futimesat dirfd')
assert (os.stat(f).st_atime, os.stat(f).st_mtime) == (500, 600.25)
ok(sc(132, cs(f), 0), 'utime now')
assert os.stat(f).st_mtime > 1e9
# futimesat with a null path is futimes on the descriptor
ok(sc(261, fd, 0, ptr((ctypes.c_long * 4)(700, 0, 800, 0))), 'futimesat null path')
assert os.stat(f).st_mtime == 800

# utimensat: follow, no-follow on a symlink, on a directory, by AT_EMPTY_PATH, and futimens
ok(sc(280, AT_FDCWD, cs(f), ptr((ctypes.c_long * 4)(1, 0, 2, 0)), 0), 'utimensat')
assert os.stat(f).st_mtime == 2
ok(sc(280, AT_FDCWD, cs(link), ptr((ctypes.c_long * 4)(3, 0, 4, 0)), NOFOLLOW), 'utimensat nofollow')
assert os.lstat(link).st_mtime == 4 and os.stat(f).st_mtime == 2, 'the link, not its target'
ok(sc(280, AT_FDCWD, cs(link), ptr((ctypes.c_long * 4)(5, 0, 6, 0)), 0), 'utimensat follow link')
assert os.stat(f).st_mtime == 6 and os.lstat(link).st_mtime == 4, 'the target, not the link'
os.utime(link, (7, 8), follow_symlinks=False)
assert os.lstat(link).st_mtime == 8 and os.stat(f).st_mtime == 6
os.utime(link, (9, 10))
assert os.stat(f).st_mtime == 10 and os.lstat(link).st_mtime == 8
ok(sc(280, dfd, cs('d'), ptr((ctypes.c_long * 4)(11, 0, 12, 0)), NOFOLLOW), 'utimensat dir')
assert os.stat(d).st_mtime == 12
ok(sc(280, fd, cs(''), ptr((ctypes.c_long * 4)(13, 0, 14, 0)), EMPTY), 'utimensat AT_EMPTY_PATH')
assert os.stat(f).st_mtime == 14
os.utime(fd, (15, 16))
assert os.stat(f).st_mtime == 16
ok(sc(280, AT_FDCWD, cs(f), ptr((ctypes.c_long * 4)(17, 0, 18, 0)), EMPTY), 'utimensat EMPTY ignored')
assert os.stat(f).st_mtime == 18
# UTIME_OMIT leaves one of the two alone
ok(sc(280, AT_FDCWD, cs(f), ptr((ctypes.c_long * 4)(0, (1 << 30) - 2, 20, 0)), 0), 'utimensat omit')
assert (os.stat(f).st_atime, os.stat(f).st_mtime) == (17, 20)

# chmod: fchmodat2(452) follow, no-follow on a file, no-follow on a symlink, AT_EMPTY_PATH; fchmod
ok(sc(452, AT_FDCWD, cs(f), 0o640, 0), 'fchmodat2')
assert stat.S_IMODE(os.stat(f).st_mode) == 0o640
ok(sc(452, AT_FDCWD, cs(f), 0o600, NOFOLLOW), 'fchmodat2 nofollow file')
assert stat.S_IMODE(os.stat(f).st_mode) == 0o600
link_mode = stat.S_IMODE(os.lstat(link).st_mode)
fails(sc(452, AT_FDCWD, cs(link), 0o640, NOFOLLOW), errno.EOPNOTSUPP, 'fchmodat2 nofollow symlink')
assert stat.S_IMODE(os.lstat(link).st_mode) == link_mode and stat.S_IMODE(os.stat(f).st_mode) == 0o600
ok(sc(452, AT_FDCWD, cs(link), 0o644, 0), 'fchmodat2 follows the symlink')
assert stat.S_IMODE(os.stat(f).st_mode) == 0o644
ok(sc(452, fd, cs(''), 0o664, EMPTY), 'fchmodat2 AT_EMPTY_PATH')
assert stat.S_IMODE(os.stat(f).st_mode) == 0o664
ok(sc(452, dfd, cs('d'), 0o750, 0), 'fchmodat2 dirfd')
assert stat.S_IMODE(os.stat(d).st_mode) == 0o750
ok(sc(91, fd, 0o600), 'fchmod')
assert stat.S_IMODE(os.stat(f).st_mode) == 0o600
os.chmod(link, 0o640)
assert stat.S_IMODE(os.stat(f).st_mode) == 0o640
os.chmod(f, 0o600, follow_symlinks=True)

# chown to a group the user belongs to, so the change is visible when there is one
others = [g for g in os.getgroups() if g != gid]
target_gid = others[0] if others else gid
ok(sc(94, cs(f), uid, target_gid), 'lchown file')
assert os.stat(f).st_gid == target_gid
ok(sc(94, cs(link), uid, gid), 'lchown symlink')
assert os.lstat(link).st_gid == gid and os.stat(f).st_gid == target_gid, 'the link, not its target'
if others:
    ok(sc(94, cs(link), uid, target_gid), 'lchown symlink to another group')
    assert os.lstat(link).st_gid == target_gid
os.chown(link, uid, gid, follow_symlinks=False)
os.chown(link, uid, gid)
assert os.stat(f).st_gid == gid, 'chown follows the link to the file'
ok(sc(93, fd, uid, target_gid), 'fchown')
assert os.stat(f).st_gid == target_gid
ok(sc(93, fd, uid, gid), 'fchown back')
assert os.stat(f).st_gid == gid

# extended attributes: path forms, no-follow forms and descriptor forms
try:
    os.setxattr(f, 'user.leash.probe', b'p')
    os.removexattr(f, 'user.leash.probe')
    xattrs = True
except OSError as e:
    assert e.errno == errno.ENOTSUP, e
    xattrs = False
if xattrs:
    value = ctypes.create_string_buffer(b'v1')
    ok(sc(188, cs(f), cs('user.leash.a'), ptr(value), 2, 0), 'setxattr')
    assert os.getxattr(f, 'user.leash.a') == b'v1'
    ok(sc(188, cs(link), cs('user.leash.b'), ptr(value), 2, 0), 'setxattr through the link')
    assert os.getxattr(f, 'user.leash.b') == b'v1', 'setxattr follows the symlink'
    ok(sc(189, cs(f), cs('user.leash.c'), ptr(value), 2, 0), 'lsetxattr file')
    assert os.getxattr(f, 'user.leash.c') == b'v1'
    fails(sc(189, cs(link), cs('user.leash.d'), ptr(value), 2, 0), errno.EPERM, 'lsetxattr symlink')
    assert 'user.leash.d' not in os.listxattr(f), 'no-follow never reaches the target'
    fails(sc(188, cs(f), cs('user.leash.a'), ptr(value), 2, 1), errno.EEXIST, 'XATTR_CREATE of an existing name')
    ok(sc(188, cs(f), cs('user.leash.a'), ptr(ctypes.create_string_buffer(b'v2')), 2, 2), 'XATTR_REPLACE')
    assert os.getxattr(f, 'user.leash.a') == b'v2'
    ok(sc(190, fd, cs('user.leash.e'), ptr(value), 2, 0), 'fsetxattr')
    assert os.getxattr(f, 'user.leash.e') == b'v1'
    ok(sc(197, cs(f), cs('user.leash.a')), 'removexattr')
    assert 'user.leash.a' not in os.listxattr(f)
    ok(sc(198, cs(f), cs('user.leash.c')), 'lremovexattr file')
    assert 'user.leash.c' not in os.listxattr(f)
    fails(sc(198, cs(link), cs('user.leash.b')), errno.EPERM, 'lremovexattr symlink')
    assert 'user.leash.b' in os.listxattr(f)
    ok(sc(199, fd, cs('user.leash.e')), 'fremovexattr')
    assert 'user.leash.e' not in os.listxattr(f)
    ok(sc(197, cs(link), cs('user.leash.b')), 'removexattr through the link')
    assert os.listxattr(f) == []
    fails(sc(197, cs(f), cs('user.leash.nothing')), errno.ENODATA, 'removexattr of a missing name')
"#;

/// every syscall name the effects script reaches, which must each leave an allow event.
const METADATA_SYSCALLS: [&str; 14] = [
    "utime",
    "utimes",
    "futimesat",
    "utimensat",
    "fchmodat2",
    "fchmod",
    "lchown",
    "fchown",
    "chmod",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "lremovexattr",
    "fremovexattr",
];

#[test]
fn every_path_and_descriptor_form_of_the_metadata_calls_takes_effect_in_the_workspace() {
    let _guard = spawn_lock();
    if !delegated("metadata_effects") {
        return;
    }
    let session = Session::new();
    let ws = session.ws();
    let script = METADATA_EFFECTS.replace("@WS@", &format!("{:?}", ws.to_string_lossy()));
    let run = session.python(&script).unwrap();
    run.assert_exit_zero();
    assert!(
        run.denies_seen().is_empty(),
        "nothing in the workspace is denied: {:#?}",
        run.denies_seen()
    );
    let file = ws.join("f");
    let link = ws.join("l");
    let dir = ws.join("d");
    for syscall in METADATA_SYSCALLS {
        assert!(
            run.events
                .iter()
                .any(|e| e["decision"] == "allow" && e["syscall"] == syscall),
            "no allow event for {syscall}"
        );
    }
    // the no-follow forms are decided on the symlink itself, the following forms on its target
    for (syscall, path) in [
        ("utimensat", &link),
        ("utimensat", &file),
        ("utimensat", &dir),
        ("lchown", &link),
        ("lchown", &file),
        ("fchmodat2", &link),
        ("fchmodat2", &file),
        ("fchmodat2", &dir),
        ("lsetxattr", &link),
        ("lremovexattr", &link),
        ("fchown", &file),
        ("fchmod", &file),
        ("fsetxattr", &file),
        ("fremovexattr", &file),
    ] {
        if !path.exists() && !path.is_symlink() {
            continue;
        }
        let xattr_call = syscall.contains("xattr");
        let has_xattr = run.events.iter().any(|e| e["syscall"] == "setxattr");
        if xattr_call && !has_xattr {
            continue;
        }
        assert!(
            run.events.iter().any(|e| e["decision"] == "allow"
                && e["syscall"] == syscall
                && e["fact"]["path"] == path.to_string_lossy().as_ref()),
            "no allow event for {syscall} on {}: {:#?}",
            path.display(),
            run.events
                .iter()
                .filter(|e| e["syscall"] == syscall)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn an_invalid_metadata_operand_is_answered_like_the_kernel_and_recorded_as_such() {
    let _guard = spawn_lock();
    if !delegated("unsupported_operand") {
        return;
    }
    let session = Session::new();
    let ws = session.ws();
    std::fs::write(ws.join("f"), b"x").unwrap();
    let script = format!(
        "{RAW_SYSCALL}{}",
        r#"
import errno, os
AT_FDCWD = -100
f = @WS@ + '/f'
big = ctypes.create_string_buffer(70000)
name = ctypes.c_char_p(b'user.leash.big')
path = ctypes.c_char_p(f.encode())
def check(result, err, what):
    assert result == (-1, err), (what, result, errno.errorcode.get(result[1]))
check(sc(188, path, name, ctypes.cast(big, ctypes.c_void_p), 70000, 0), errno.E2BIG, 'setxattr over the limit')
check(sc(189, path, name, ctypes.cast(big, ctypes.c_void_p), 65537, 0), errno.E2BIG, 'lsetxattr over the limit')
check(sc(452, AT_FDCWD, path, 0o600, 0x2000), errno.EINVAL, 'fchmodat2 with an unknown flag')
check(sc(280, AT_FDCWD, path, 0, 0x4000), errno.EINVAL, 'utimensat with an unknown flag')
"#
        .replace("@WS@", &format!("{:?}", ws.to_string_lossy()))
    );
    let run = session.python(&script).unwrap();
    run.assert_exit_zero();
    assert!(
        run.rule_events("failsafe:memory_read").is_empty(),
        "an invalid operand is not a failed memory read: {:#?}",
        run.events
    );
    let seen = run.rule_events("failsafe:unsupported_operand");
    assert_eq!(seen.len(), 4, "{seen:#?}");
    for (syscall, errno) in [
        ("setxattr", "E2BIG"),
        ("lsetxattr", "E2BIG"),
        ("fchmodat2", "EINVAL"),
        ("utimensat", "EINVAL"),
    ] {
        assert!(
            seen.iter()
                .any(|e| e["syscall"] == syscall && e["errno"] == errno && e["decision"] == "deny"),
            "no {syscall} {errno}: {seen:#?}"
        );
    }
}

#[test]
fn tar_extracts_and_cp_copies_a_tree_with_links_and_times_in_a_snapshot_run() {
    let _guard = spawn_lock();
    if !delegated("tar_and_cp") {
        return;
    }
    let session = Session::new();
    let ws = session.ws();
    let src = ws.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha").unwrap();
    std::fs::write(src.join("sub/b.txt"), b"beta").unwrap();
    std::os::unix::fs::symlink("a.txt", src.join("link")).unwrap();
    std::os::unix::fs::symlink("sub", src.join("dirlink")).unwrap();
    let stamp = |path: &str, when: &str| {
        let status = std::process::Command::new("touch")
            .args(["-h", "-d", when, path])
            .status()
            .unwrap();
        assert!(status.success());
    };
    for (rel, when) in [
        ("a.txt", "2001-02-03 04:05:06"),
        ("sub/b.txt", "2002-03-04 05:06:07"),
        ("link", "2003-04-05 06:07:08"),
        ("dirlink", "2004-05-06 07:08:09"),
        ("sub", "2005-06-07 08:09:10"),
    ] {
        stamp(src.join(rel).to_str().unwrap(), when);
    }
    let archive = ws.join("a.tar");
    let status = std::process::Command::new("tar")
        .args(["-cf"])
        .arg(&archive)
        .arg("-C")
        .arg(&src)
        .arg(".")
        .status()
        .unwrap();
    assert!(status.success());
    std::fs::create_dir(ws.join("extracted")).unwrap();
    let script = format!(
        "cd {ws} && /usr/bin/tar -xf {tar} -C {ws}/extracted && /usr/bin/cp -a {src} {ws}/copied",
        ws = ws.display(),
        tar = archive.display(),
        src = src.display(),
    );
    let run = session.run(&["/bin/sh", "-c", &script]).unwrap();
    run.assert_exit_zero();
    assert!(
        run.denies_seen().is_empty(),
        "no denial inside the workspace: {:#?}",
        run.denies_seen()
    );
    let mtime = |path: PathBuf| {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path).unwrap().mtime()
    };
    for tree in ["extracted", "copied"] {
        let root = ws.join(tree);
        let rel = |name: &str| root.join(name);
        assert_eq!(
            std::fs::read_link(rel("link")).unwrap(),
            Path::new("a.txt"),
            "{tree}: the symlink survives"
        );
        assert_eq!(std::fs::read(rel("sub/b.txt")).unwrap(), b"beta");
        for name in ["a.txt", "sub/b.txt", "link", "dirlink", "sub"] {
            assert_eq!(
                mtime(rel(name)),
                mtime(src.join(name)),
                "{tree}: the time of {name} is kept, on the link itself for a symlink"
            );
        }
    }
    assert!(
        run.events
            .iter()
            .any(|e| e["syscall"] == "utimensat" && e["decision"] == "allow"),
        "the time restoration went through the mediated utimensat"
    );
}

// --- decision 5: the overlap refusal ---

/// the refusal's text, asserting it is the overlap refusal and not another failure.
fn overlap_refusal(result: Result<Run, SessionError>) -> String {
    match result {
        Err(error @ SessionError::SnapshotGrantOverlap(_)) => error.to_string(),
        Err(other) => panic!("expected the overlap refusal, got: {other}"),
        Ok(_) => panic!("the run must be refused before spawn"),
    }
}

#[test]
fn a_home_write_grant_that_covers_the_state_root_is_refused_before_any_run_directory() {
    let _guard = spawn_lock();
    let home = std::env::var("HOME").expect("HOME is set");
    let state = tempfile::tempdir_in(&home).unwrap();
    let state_path = state.path().to_path_buf();
    let session = Session::with_state(state);
    session.write_policy(&format!(
        "{POLICY}[[fs]]\npath=\"~/**\"\nmode=[\"read\", \"write\"]\naction=\"allow\"\n"
    ));
    let message = overlap_refusal(session.run(&["/bin/true"]));
    assert!(message.contains("rule fs.2"), "names the rule: {message}");
    assert!(
        message.contains(&format!("beneath \"{home}\"")),
        "names the grant path: {message}"
    );
    assert!(message.contains("write"), "names the right: {message}");
    assert!(
        message.contains(&format!("state root \"{}\"", state_path.display())),
        "names the state root: {message}"
    );
    session.assert_no_run_directory();
}

#[test]
fn a_write_grant_over_sys_is_refused_for_the_cgroup_mount_it_covers() {
    let _guard = spawn_lock();
    for (mode, right) in [
        ("write", "write, truncate"),
        ("create", "make, refer"),
        ("delete", "truncate, remove, refer"),
    ] {
        let session = Session::new();
        session.write_policy(&format!(
            "{POLICY}[[fs]]\npath=\"/sys/**\"\nmode=[\"{mode}\"]\naction=\"allow\"\n"
        ));
        let message = overlap_refusal(session.run(&["/bin/true"]));
        assert!(message.contains("rule fs.2"), "{mode}: {message}");
        assert!(message.contains("beneath \"/sys\""), "{mode}: {message}");
        assert!(message.contains(right), "{mode}: {message}");
        assert!(
            message.contains(&format!("cgroup2 mount \"{}\"", mount().display())),
            "{mode}: {message}"
        );
        session.assert_no_run_directory();
    }
}

#[test]
fn a_grant_beneath_the_state_root_or_a_mount_is_refused_like_one_above_it() {
    let _guard = spawn_lock();
    let session = Session::new();
    let state = session.state_dir.clone().to_path_buf();
    for (glob, what) in [
        (format!("{}/runs/**", state.display()), "state root"),
        (format!("{}/**", mount().display()), "cgroup2 mount"),
    ] {
        session.write_policy(&format!(
            "{POLICY}[[fs]]\npath=\"{glob}\"\nmode=[\"read\", \"write\"]\naction=\"allow\"\n"
        ));
        let message = overlap_refusal(session.run(&["/bin/true"]));
        assert!(message.contains(what), "{glob}: {message}");
        session.assert_no_run_directory();
    }
}

#[test]
fn a_write_grant_on_a_missing_path_is_refused_when_landlock_anchors_it_over_the_state_root() {
    // Landlock cannot open a path that does not exist, so it anchors the grant at the deepest
    // existing ancestor and the rights land there. `<tmp>/p/missing/**` therefore grants write
    // on `<tmp>/p`, which holds the state root `<tmp>/p/leash`
    let _guard = spawn_lock();
    let tmp = tempfile::tempdir().unwrap();
    let parent = tmp.path().join("p");
    let session = Session::nested(tmp, parent.join("leash"));
    let missing = parent.join("missing");
    assert!(!missing.exists());
    session.write_policy(&format!(
        "{POLICY}[[fs]]\npath=\"{}/**\"\nmode=[\"write\"]\naction=\"allow\"\n",
        missing.display()
    ));
    let message = overlap_refusal(session.run(&["/bin/true"]));
    assert!(message.contains("rule fs.2"), "names the rule: {message}");
    assert!(
        message.contains(&format!("beneath \"{}\"", missing.display())),
        "names the grant as the policy spelled it: {message}"
    );
    assert!(
        message.contains(&format!("anchors it at \"{}\"", parent.display())),
        "names where Landlock really anchors it: {message}"
    );
    assert!(
        message.contains(&format!("state root \"{}\"", session.state_dir.display())),
        "names the state root: {message}"
    );
    session.assert_no_run_directory();
}

#[test]
fn a_write_grant_on_a_missing_top_level_path_is_anchored_at_the_root_and_refused() {
    let _guard = spawn_lock();
    let missing = "/leash-no-such-top-level-dir";
    assert!(!Path::new(missing).exists());
    let session = Session::new();
    session.write_policy(&format!(
        "{POLICY}[[fs]]\npath=\"{missing}/**\"\nmode=[\"write\"]\naction=\"allow\"\n"
    ));
    let message = overlap_refusal(session.run(&["/bin/true"]));
    assert!(message.contains("rule fs.2"), "{message}");
    assert!(message.contains("anchors it at \"/\""), "{message}");
    session.assert_no_run_directory();
}

#[test]
fn a_write_grant_on_a_missing_path_anchored_elsewhere_is_not_refused() {
    let _guard = spawn_lock();
    if !delegated("missing_grant_elsewhere") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let other = tmp.path().join("q");
    std::fs::create_dir(&other).unwrap();
    let session = Session::new();
    session.write_policy(&format!(
        "{POLICY}[[fs]]\npath=\"{}/missing/**\"\nmode=[\"write\"]\naction=\"allow\"\n",
        other.display()
    ));
    let run = session.run(&["/bin/true"]).unwrap();
    run.assert_exit_zero();
}

#[test]
fn a_workspace_that_is_beneath_the_state_root_is_refused_under_the_base_rule() {
    let _guard = spawn_lock();
    let state = tempfile::tempdir().unwrap();
    std::fs::write(state.path().join("policy.toml"), POLICY).unwrap();
    let ws = state.path().join("workspace");
    std::fs::create_dir(&ws).unwrap();
    let other = Session::new();
    let mut spec = other.spec(&["/bin/true"]);
    spec.state_root = state.path().to_path_buf();
    spec.state_root_spelling = state.path().to_path_buf();
    spec.policy_path = Some(state.path().join("policy.toml"));
    spec.workspace = ws;
    let message = overlap_refusal(run_session(spec).and_then(finish));
    assert!(message.contains("rule base:workspace"), "{message}");
    assert!(!state.path().join("runs").exists());
}

#[test]
fn the_cgroup_grant_the_overlap_test_documents_is_refused_before_spawn() {
    let _guard = spawn_lock();
    let session = Session::new();
    session.write_policy(&format!(
        "{POLICY}[[fs]]\npath=\"/sys/fs/cgroup/**\"\nmode=[\"read\", \"write\"]\naction=\"allow\"\n"
    ));
    overlap_refusal(session.run(&["/bin/true"]));
    session.assert_no_run_directory();
}

#[test]
fn a_read_only_policy_runs_and_stamps_the_single_layer_residual() {
    let _guard = spawn_lock();
    if !delegated("read_overlap_residual") {
        return;
    }
    let session = Session::new();
    let run = session.run(&["/bin/true"]).unwrap();
    run.assert_exit_zero();
    let residuals = run.residuals();
    assert_eq!(
        residuals
            .iter()
            .filter(|r| r.as_str() == OVERLAP_RESIDUAL)
            .count(),
        1,
        "stamped exactly once: {residuals:?}"
    );
}

// --- decision 6: the Landlock ABI ---

#[test]
fn a_host_with_landlock_abi_2_is_refused_before_spawn() {
    let _guard = spawn_lock();
    let session = Session::new();
    let abi_2 = || -> Result<preflight::Capabilities, preflight::PreflightError> {
        let mut caps = preflight::probe()?;
        caps.landlock_abi = 2;
        Ok(caps)
    };
    let result = run_session_with_hooks(
        session.spec(&["/bin/true"]),
        SessionHooks {
            capabilities: &abi_2,
            ..SessionHooks::default()
        },
    );
    match result {
        Err(
            error @ SessionError::SnapshotLandlockAbi {
                abi: 2,
                required: 3,
            },
        ) => {
            let text = error.to_string();
            assert!(text.contains("ABI 2") && text.contains("ABI 3"), "{text}");
        }
        other => panic!("expected the ABI refusal, got {other:?}"),
    }
    session.assert_no_run_directory();

    // the same host without snapshot integrity is not refused on ABI 2
    let plain = Session::plain();
    let result = run_session_with_hooks(
        plain.spec(&["/bin/true"]),
        SessionHooks {
            capabilities: &abi_2,
            ..SessionHooks::default()
        },
    );
    assert!(result.is_ok(), "{:?}", result.err());
}

// --- other runs are unchanged ---

const READ_CONTROLLERS: &str = "import os\n\
    mount = {mount:?}\n\
    data = open(mount + '/cgroup.controllers').read()\n\
    assert isinstance(data, str)\n\
    f = {file:?}\n\
    os.utime(f, (5, 7))\n\
    os.chmod(f, 0o600)\n";

#[test]
fn a_non_snapshot_enforce_run_is_unchanged() {
    let _guard = spawn_lock();
    let session = Session::plain();
    let file = session.ws().join("f");
    std::fs::write(&file, b"x").unwrap();
    // a write grant over a cgroup2 mount is the operator's business without snapshots
    session.write_policy(&format!(
        "{POLICY}[[fs]]\npath=\"/sys/**\"\nmode=[\"write\"]\naction=\"allow\"\n"
    ));
    let script = READ_CONTROLLERS
        .replace("{mount:?}", &format!("{:?}", mount().to_string_lossy()))
        .replace("{file:?}", &format!("{:?}", file.to_string_lossy()));
    let run = session.python(&script).unwrap();
    run.assert_exit_zero();
    assert!(run.rule_events(CGROUP_RULE).is_empty());
    assert!(!run.residuals().contains(&OVERLAP_RESIDUAL.to_string()));
    assert!(
        run.events[0]["run_cgroup"].is_null(),
        "no run cgroup without snapshots"
    );
    let metadata = |e: &&serde_json::Value| {
        e["syscall"]
            .as_str()
            .is_some_and(|s| s.starts_with("utime") || s.contains("xattr"))
    };
    assert_eq!(
        run.events.iter().filter(metadata).count(),
        0,
        "the metadata calls are not trapped without snapshots"
    );
    let controllers = mount().join("cgroup.controllers");
    assert!(
        run.events.iter().any(|e| e["decision"] == "allow"
            && e["fact"]["path"] == controllers.to_string_lossy().as_ref()),
        "the cgroup file is read under the ordinary policy: {:#?}",
        run.events
    );
}

#[test]
fn a_record_only_run_is_unchanged() {
    let _guard = spawn_lock();
    let session = Session::plain();
    let file = session.ws().join("f");
    std::fs::write(&file, b"x").unwrap();
    let mut spec = session.spec(&["/usr/bin/python3", "-c", ""]);
    let script = READ_CONTROLLERS
        .replace("{mount:?}", &format!("{:?}", mount().to_string_lossy()))
        .replace("{file:?}", &format!("{:?}", file.to_string_lossy()));
    spec.argv = vec!["/usr/bin/python3".into(), "-c".into(), script];
    spec.mode = Mode::RecordOnly;
    spec.policy_path = None;
    let run = finish(run_session(spec).unwrap()).unwrap();
    run.assert_exit_zero();
    assert!(run.rule_events(CGROUP_RULE).is_empty());
    assert!(run.events[0]["landlock_residuals"].is_null());
    assert!(run.events[0]["run_cgroup"].is_null());
    assert!(
        !run.events.iter().any(|e| e["syscall"]
            .as_str()
            .is_some_and(|s| s.starts_with("utime") || s.contains("xattr"))),
        "the metadata calls are not trapped in record-only"
    );
}
