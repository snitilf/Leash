//! the snapshot capture barrier of a snapshot run (ADR-0024 decisions 10 to 14 and 16;
//! docs/design/snapshot.md section 2).
//!
//! these tests drive whole sessions with `snapshot_integrity` set, so each needs a delegated
//! cgroup v2: a cgroup this process may create children in, with working `cgroup.freeze` and
//! `cgroup.kill`. without one they skip and say why. with `LEASH_REQUIRE_FREEZER=1` they fail
//! instead, which is how the CI leg that provisions a delegated cgroup proves they ran. to run
//! them locally, as root create a cgroup, chown it to the test user, move the test shell into
//! it, and run `cargo test` from that shell:
//!
//! ```sh
//! sudo mkdir /sys/fs/cgroup/leash-dev && sudo chown -R $USER /sys/fs/cgroup/leash-dev
//! echo $$ | sudo tee /sys/fs/cgroup/leash-dev/cgroup.procs
//! LEASH_REQUIRE_FREEZER=1 cargo test --test capture_barrier_linux -- --nocapture
//! ```
//!
//! the agent scripts are orchestrated from outside the sandbox: an agent waits for files in a
//! control directory (read through the `/**` read grant), and a helper thread releases it once
//! a step's manifest is published. nothing outside the agent writes into the workspace while a
//! capture can run. every test forks, so all of them serialize under one lock.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use leash::cli::session_exit_code;
use leash::recorder::{AskResolution, Attendance, CapturePhase, Mode};
use leash::snapshot::restore::recompute_chain;
use leash::snapshot::store::{EntryKind, Limits, committed_steps, load_manifest, verify_object};
use leash::supervisor::barrier::BarrierOps;
use leash::supervisor::cgroup::Cgroup;
use leash::supervisor::run::RunError;
use leash::supervisor::session::{
    ExitDisposition, SessionError, SessionHooks, SessionOutcome, SessionSpec,
    run_session_with_hooks,
};
use leash::supervisor::workspace_lock::WorkspaceLockError;
use serde_json::Value;

static SPAWN_LOCK: Mutex<()> = Mutex::new(());

fn spawn_lock() -> MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

const POLICY_BASE: &str = "schema_version = 1\n\
    [[fs]]\npath=\"/**\"\nmode=[\"read\"]\naction=\"allow\"\n\
    [[exec]]\nbinary=\"/**\"\naction=\"allow\"\n";

/// what every agent script starts with: the workspace, the control directory, a wait for a
/// control file, and a file write the supervisor sees as one mediated create-and-write.
const PRELUDE: &str = "import os, time, sys, struct, threading, mmap, ctypes\n\
WS = {ws}\n\
CTL = {ctl}\n\
def wait(n):\n\
\x20   while not os.path.exists(CTL + '/' + n):\n\
\x20       time.sleep(0.005)\n\
def put(name, data=''):\n\
\x20   with open(WS + '/' + name, 'w') as f:\n\
\x20       f.write(data)\n";

struct Harness {
    state: tempfile::TempDir,
    _ws: tempfile::TempDir,
    _ctl: tempfile::TempDir,
    ws: PathBuf,
    ctl: PathBuf,
}

impl Harness {
    fn new(initial: &[(&str, &str)]) -> Self {
        let state = tempfile::tempdir().unwrap();
        let ws_dir = tempfile::tempdir().unwrap();
        let ctl_dir = tempfile::tempdir().unwrap();
        let ws = ws_dir.path().canonicalize().unwrap();
        let ctl = ctl_dir.path().canonicalize().unwrap();
        for (name, data) in initial {
            std::fs::write(ws.join(name), data).unwrap();
        }
        let harness = Self {
            state,
            _ws: ws_dir,
            _ctl: ctl_dir,
            ws,
            ctl,
        };
        harness.write_policy(&format!(
            "{POLICY_BASE}[[fs]]\npath={:?}\nmode=[\"read\",\"write\",\"create\",\"delete\"]\naction=\"allow\"\n",
            format!("{}/**", harness.ws.display())
        ));
        harness
    }

    fn write_policy(&self, policy: &str) {
        std::fs::write(self.state.path().join("policy.toml"), policy).unwrap();
    }

    fn spec(&self, body: &str) -> SessionSpec {
        let prelude = PRELUDE
            .replace("{ws}", &format!("{:?}", self.ws.display().to_string()))
            .replace("{ctl}", &format!("{:?}", self.ctl.display().to_string()));
        SessionSpec {
            argv: vec![
                "/usr/bin/python3".into(),
                "-c".into(),
                format!("{prelude}{body}"),
            ],
            mode: Mode::Enforce,
            attendance: Attendance::Unattended,
            state_root: self.state.path().to_path_buf(),
            state_root_spelling: self.state.path().to_path_buf(),
            workspace: self.ws.clone(),
            policy_path: Some(self.state.path().join("policy.toml")),
            ask_timeout: Duration::from_secs(60),
            snapshot_integrity: true,
        }
    }

    fn run(&self, body: &str) -> Result<SessionOutcome, SessionError> {
        self.run_with(body, SessionHooks::default())
    }

    fn run_with(
        &self,
        body: &str,
        hooks: SessionHooks<'_>,
    ) -> Result<SessionOutcome, SessionError> {
        run_session_with_hooks(self.spec(body), hooks)
    }

    /// the one run directory under the state root, once it exists.
    fn run_dir(&self) -> Option<PathBuf> {
        first_run(self.state.path())
    }

    /// release the agent's `go` files as the named steps publish.
    fn release(&self, plan: &[(u64, &'static str)]) -> JoinHandle<()> {
        let state = self.state.path().to_path_buf();
        let ctl = self.ctl.clone();
        let plan = plan.to_vec();
        std::thread::spawn(move || {
            for (step, name) in plan {
                let deadline = Instant::now() + Duration::from_secs(60);
                loop {
                    if first_run(&state).is_some_and(|run| manifest_path(&run, step).exists()) {
                        break;
                    }
                    if Instant::now() >= deadline {
                        let denied: Vec<String> = first_run(&state)
                            .map(|run| events_of(&run))
                            .unwrap_or_default()
                            .iter()
                            .filter(|e| e["decision"] == "deny")
                            .map(Value::to_string)
                            .collect();
                        panic!("step {step} was never published; denied events: {denied:#?}");
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                std::fs::write(ctl.join(name), "1").unwrap();
            }
        })
    }

    fn read_ws(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.ws.join(name)).unwrap()
    }
}

fn first_run(state: &Path) -> Option<PathBuf> {
    std::fs::read_dir(state.join("runs"))
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .min()
}

fn manifest_path(run: &Path, step: u64) -> PathBuf {
    run.join("snapshots/manifests")
        .join(format!("step-{step:06}.json"))
}

fn events_of(run: &Path) -> Vec<Value> {
    std::fs::read_to_string(run.join("trace.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn of_type<'a>(events: &'a [Value], kind: &str) -> Vec<&'a Value> {
    events.iter().filter(|e| e["type"] == kind).collect()
}

fn open_store(run: &Path) -> File {
    File::open(run.join("snapshots")).unwrap()
}

/// the regular files of the snapshot at `step`, path to content, every object verified.
fn files_at(store: &File, step: u64) -> BTreeMap<String, Vec<u8>> {
    let (manifest, _) = load_manifest(store, step).unwrap();
    manifest
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::File)
        .map(|e| {
            let mut file = verify_object(store, e.sha256.as_deref().unwrap()).unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            (e.path.clone(), bytes)
        })
        .collect()
}

fn tree(pairs: &[(&str, &str)]) -> BTreeMap<String, Vec<u8>> {
    pairs
        .iter()
        .map(|(name, data)| ((*name).to_string(), data.as_bytes().to_vec()))
        .collect()
}

fn step_numbers(events: &[Value]) -> Vec<u64> {
    of_type(events, "step")
        .iter()
        .map(|e| e["step"].as_u64().unwrap())
        .collect()
}

/// the digests, chain head and ordering every successful snapshot run must show.
fn assert_digests_and_chain(run: &Path, events: &[Value]) {
    let store = open_store(run);
    let steps = of_type(events, "step");
    assert!(
        steps.len() >= 2,
        "step 0 and the final step exist: {events:?}"
    );
    for event in &steps {
        let step = event["step"].as_u64().unwrap();
        let (_, digest) = load_manifest(&store, step).unwrap();
        assert_eq!(
            event["manifest_digest"], digest,
            "the step event of {step} carries the store's manifest digest"
        );
    }
    assert_eq!(step_numbers(events), committed_steps(&store).unwrap());
    assert_eq!(step_numbers(events)[0], 0, "step 0 is the first step event");
    let chain = recompute_chain(&store).unwrap();
    let end = of_type(events, "run_end");
    assert_eq!(end.len(), 1);
    assert_eq!(end[0]["chain_head"], chain.head);
    assert_eq!(
        end[0]["final_step"],
        *step_numbers(events).last().unwrap(),
        "run_end names the final committed step"
    );
}

fn pauses(events: &[Value]) -> Vec<u64> {
    of_type(events, "step")
        .iter()
        .map(|e| e["capture_pause_us"].as_u64().unwrap())
        .collect()
}

/// the shape every abort-closed run must show: exit 125, a recorded failure naming the phase,
/// no run_end, no report, the whole cgroup killed and removed, and the failed boundary has no
/// step event.
fn assert_aborted_closed(
    harness: &Harness,
    result: Result<SessionOutcome, SessionError>,
    step: u64,
    phase: CapturePhase,
) -> Vec<Value> {
    match &result {
        Err(SessionError::Run(RunError::Barrier {
            step: failed_step,
            phase: failed_phase,
            ..
        })) => {
            assert_eq!(*failed_step, step, "{result:?}");
            assert_eq!(*failed_phase, phase, "{result:?}");
        }
        other => panic!("expected an aborted boundary, got {other:?}"),
    }
    assert_eq!(session_exit_code(result), ExitCode::from(125));
    let run = harness.run_dir().expect("the run directory exists");
    let events = events_of(&run);
    let failed = of_type(&events, "capture_failed");
    assert_eq!(failed.len(), 1, "{events:?}");
    assert_eq!(failed[0]["step"], step);
    assert_eq!(
        failed[0]["phase"],
        serde_json::to_value(phase).unwrap(),
        "{failed:?}"
    );
    assert!(failed[0]["error"].as_str().is_some_and(|e| !e.is_empty()));
    assert!(
        of_type(&events, "run_end").is_empty(),
        "an aborted run never stamps run_end: {events:?}"
    );
    assert!(!run.join("report.txt").exists());
    let kills = of_type(&events, "cgroup_kill");
    assert_eq!(kills.len(), 1, "{events:?}");
    assert_eq!(kills[0]["reason"], "abort");
    let cgroup = PathBuf::from(events[0]["run_cgroup"].as_str().unwrap());
    assert!(
        !cgroup.exists(),
        "the whole run cgroup was killed and removed"
    );
    events
}

/// the agent writes its pid to the workspace first thing; this asserts it is gone.
fn assert_agent_dead(harness: &Harness) {
    let pid: i32 = String::from_utf8(harness.read_ws("agent.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // SAFETY: signal 0 only checks whether the pid exists.
    let alive = unsafe { libc::kill(pid, 0) } == 0;
    assert!(!alive, "agent {pid} must be killed with its cgroup");
}

const WRITE_PID: &str = "put('agent.pid', str(os.getpid()))\n";

// ---------------------------------------------------------------------------------------
// the write pattern: steps, the window and the minimum interval
// ---------------------------------------------------------------------------------------

#[test]
fn a_write_pattern_yields_the_expected_steps_and_each_manifest_matches_its_moment() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("write_pattern") {
        return;
    }
    let harness = Harness::new(&[("base.txt", "base")]);
    // a burst inside the 250 ms window is one step. a second burst 0.45 s later is past the
    // window but inside the 1 s minimum interval, so it joins the same step. a gap beyond the
    // window and the interval splits. each go file is released once the step it follows is
    // published, so the timings below are relative to the previous boundary.
    let releaser = harness.release(&[(1, "go1"), (2, "go2"), (4, "go3")]);
    let outcome = harness
        .run(
            "put('a1', '1'); time.sleep(0.05); put('a2', '2'); time.sleep(0.05); put('a3', '3')\n\
             wait('go1')\n\
             put('b1', '1'); time.sleep(0.45); put('b2', '2')\n\
             wait('go2')\n\
             put('c1', '1'); time.sleep(1.5); put('d1', '1')\n\
             wait('go3')\n",
        )
        .unwrap();
    releaser.join().unwrap();
    assert!(matches!(outcome.exit, ExitDisposition::Exited(0)));

    let events = events_of(&outcome.run_path);
    assert_eq!(step_numbers(&events), vec![0, 1, 2, 3, 4, 5], "{events:?}");
    let store = open_store(&outcome.run_path);
    let step0 = [("base.txt", "base")];
    let step1 = [("base.txt", "base"), ("a1", "1"), ("a2", "2"), ("a3", "3")];
    let step2 = [
        ("base.txt", "base"),
        ("a1", "1"),
        ("a2", "2"),
        ("a3", "3"),
        ("b1", "1"),
        ("b2", "2"),
    ];
    let step3 = [
        ("base.txt", "base"),
        ("a1", "1"),
        ("a2", "2"),
        ("a3", "3"),
        ("b1", "1"),
        ("b2", "2"),
        ("c1", "1"),
    ];
    let step4 = [
        ("base.txt", "base"),
        ("a1", "1"),
        ("a2", "2"),
        ("a3", "3"),
        ("b1", "1"),
        ("b2", "2"),
        ("c1", "1"),
        ("d1", "1"),
    ];
    for (step, expected) in [
        (0, &step0[..]),
        (1, &step1[..]),
        (2, &step2[..]),
        (3, &step3[..]),
        (4, &step4[..]),
        (5, &step4[..]),
    ] {
        let expected = tree(expected);
        assert_eq!(
            files_at(&store, step),
            expected,
            "the manifest of step {step} matches the workspace at that point"
        );
    }

    assert_digests_and_chain(&outcome.run_path, &events);
    let pauses = pauses(&events);
    assert_eq!(pauses[0], 0, "no agent runs at step 0");
    assert_eq!(pauses[5], 0, "no agent runs at the final step");
    assert!(
        pauses[1..5].iter().all(|p| *p > 0),
        "every boundary froze the agent: {pauses:?}"
    );
    eprintln!("MEASURED capture pauses (us) per step: {pauses:?}");
}

// ---------------------------------------------------------------------------------------
// consistency: writes that tick no mediated event
// ---------------------------------------------------------------------------------------

#[test]
fn a_persistent_fd_writer_is_never_captured_torn() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("persistent_fd") {
        return;
    }
    let harness = Harness::new(&[]);
    let releaser = harness.release(&[(1, "go1"), (2, "go2"), (3, "go3")]);
    // the writer thread appends 4 KiB records through one descriptor with no further mediated
    // event, 1000 times a second. only the marker files propose boundaries.
    let outcome = harness
        .run(
            "fd = os.open(WS + '/log', os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)\n\
             stop = False\n\
             def writer():\n\
             \x20   n = 0\n\
             \x20   while not stop:\n\
             \x20       os.write(fd, struct.pack('<Q', n) * 512)\n\
             \x20       n += 1\n\
             \x20       time.sleep(0.001)\n\
             t = threading.Thread(target=writer)\n\
             t.start()\n\
             put('m0')\n\
             wait('go1')\n\
             put('m1')\n\
             wait('go2')\n\
             put('m2')\n\
             wait('go3')\n\
             stop = True\n\
             t.join()\n",
        )
        .unwrap();
    releaser.join().unwrap();
    assert!(matches!(outcome.exit, ExitDisposition::Exited(0)));

    let events = events_of(&outcome.run_path);
    let store = open_store(&outcome.run_path);
    let steps = step_numbers(&events);
    assert!(steps.len() >= 5, "{steps:?}");
    let mut previous: Vec<u8> = Vec::new();
    for step in steps {
        let log = files_at(&store, step).remove("log").unwrap_or_default();
        assert_eq!(
            log.len() % 4096,
            0,
            "step {step}: a whole number of records"
        );
        for (i, record) in log.chunks(4096).enumerate() {
            let expected = (i as u64).to_le_bytes();
            assert!(
                record.chunks(8).all(|word| word == expected),
                "step {step}: record {i} is torn"
            );
        }
        assert!(
            log.starts_with(&previous),
            "step {step}: the log only ever grows by appending"
        );
        previous = log;
    }
    assert!(
        previous.len() >= 4096 * 100,
        "the writer ran across the boundaries: {} bytes",
        previous.len()
    );
    assert_digests_and_chain(&outcome.run_path, &events);
}

#[test]
fn a_shared_mmap_writer_is_never_captured_torn() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("shared_mmap") {
        return;
    }
    let harness = Harness::new(&[]);
    let releaser = harness.release(&[(1, "go1"), (2, "go2"), (3, "go3")]);
    // the writer fills a MAP_SHARED file with the 8-byte word i+1 at offset 8*i, one aligned
    // store per word, in order. nothing about it reaches the supervisor. a capture at a frozen
    // moment sees words 1..k and then zeros, never a gap or a half-written word. a
    // multi-word record is an application transaction and stays outside the contract
    // (snapshot.md section 1).
    let outcome = harness
        .run(
            "N = 100000\n\
             fd = os.open(WS + '/map', os.O_RDWR | os.O_CREAT, 0o644)\n\
             os.ftruncate(fd, 8 * N)\n\
             mm = mmap.mmap(fd, 8 * N, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)\n\
             words = (ctypes.c_uint64 * N).from_buffer(mm)\n\
             stop = False\n\
             def writer():\n\
             \x20   for i in range(N):\n\
             \x20       if stop:\n\
             \x20           break\n\
             \x20       words[i] = i + 1\n\
             \x20       time.sleep(0.001)\n\
             t = threading.Thread(target=writer)\n\
             t.start()\n\
             put('m0')\n\
             wait('go1')\n\
             put('m1')\n\
             wait('go2')\n\
             put('m2')\n\
             wait('go3')\n\
             stop = True\n\
             t.join()\n",
        )
        .unwrap();
    releaser.join().unwrap();
    assert!(matches!(outcome.exit, ExitDisposition::Exited(0)));

    let events = events_of(&outcome.run_path);
    let store = open_store(&outcome.run_path);
    let mut previous_fill = 0usize;
    for step in step_numbers(&events) {
        let map = files_at(&store, step).remove("map").unwrap_or_default();
        if map.is_empty() {
            continue; // step 0 predates the file
        }
        assert_eq!(map.len(), 8 * 100_000);
        let words: Vec<u64> = map
            .chunks(8)
            .map(|w| u64::from_le_bytes(w.try_into().unwrap()))
            .collect();
        let filled = words.iter().take_while(|w| **w != 0).count();
        for (i, word) in words[..filled].iter().enumerate() {
            assert_eq!(*word, i as u64 + 1, "step {step}: word {i} is torn");
        }
        assert!(
            words[filled..].iter().all(|w| *w == 0),
            "step {step}: a store landed beyond a gap"
        );
        assert!(filled >= previous_fill, "step {step}: the fill only grows");
        previous_fill = filled;
    }
    assert!(
        previous_fill >= 500,
        "the writer ran across the boundaries: {previous_fill} words"
    );
    assert_digests_and_chain(&outcome.run_path, &events);
}

// ---------------------------------------------------------------------------------------
// descendants and orphans
// ---------------------------------------------------------------------------------------

/// live file sizes just after a freeze, again 30 ms later, and the cgroup's member count.
type FrozenSample = (Vec<u64>, Vec<u64>, usize);

const WRITER_PROC: &str = "def writer_proc(name):\n\
\x20   fd = os.open(WS + '/' + name, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)\n\
\x20   n = 0\n\
\x20   while True:\n\
\x20       os.write(fd, struct.pack('<Q', n) * 8)\n\
\x20       n += 1\n\
\x20       time.sleep(0.001)\n";

#[test]
fn descendants_and_an_orphan_are_frozen_at_a_boundary_and_killed_at_root_exit() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("descendants_frozen") {
        return;
    }
    let harness = Harness::new(&[]);
    let releaser = harness.release(&[(1, "go1"), (2, "go2")]);
    let files = ["w_child", "w_grand", "w_orphan"];
    let sizes = |ws: &Path| -> Vec<u64> {
        files
            .iter()
            .map(|f| std::fs::metadata(ws.join(f)).map_or(0, |m| m.len()))
            .collect()
    };
    let frozen_samples: Mutex<Vec<FrozenSample>> = Mutex::new(Vec::new());
    let checks = AtomicU64::new(0);
    let ws = harness.ws.clone();
    let state = harness.state.path().to_path_buf();
    // after the freeze: the live files do not move for 30 ms (the writers append every ms), and
    // the cgroup lists every member. after the capture: the live sizes still equal the
    // snapshot's, so the capture saw the frozen moment.
    let freeze = |group: &Cgroup, timeout: Duration| -> std::io::Result<()> {
        group.set_frozen(true, timeout)?;
        let before = sizes(&ws);
        std::thread::sleep(Duration::from_millis(30));
        let after = sizes(&ws);
        let members = group.members()?.len();
        frozen_samples
            .lock()
            .unwrap()
            .push((before, after, members));
        Ok(())
    };
    let is_frozen = |group: &Cgroup| -> std::io::Result<bool> {
        let step = checks.fetch_add(1, Ordering::SeqCst) + 1;
        let run = first_run(&state).unwrap();
        let store = open_store(&run);
        let (manifest, _) = load_manifest(&store, step).unwrap();
        for file in files {
            let live = std::fs::metadata(ws.join(file)).map_or(0, |m| m.len());
            let captured = manifest
                .entries
                .iter()
                .find(|e| e.path == file)
                .and_then(|e| e.size)
                .unwrap_or(0);
            assert_eq!(
                live, captured,
                "step {step}: {file} moved after its capture"
            );
        }
        group.is_frozen()
    };
    let hooks = SessionHooks {
        barrier: BarrierOps {
            freeze: &freeze,
            is_frozen: &is_frozen,
            ..BarrierOps::default()
        },
        ..SessionHooks::default()
    };
    let outcome = harness
        .run_with(
            &format!(
                "{WRITER_PROC}\
                 put('root.pid', str(os.getpid()))\n\
                 c = os.fork()\n\
                 if c == 0:\n\
                 \x20   put('child.pid', str(os.getpid()))\n\
                 \x20   g = os.fork()\n\
                 \x20   if g == 0:\n\
                 \x20       put('grand.pid', str(os.getpid()))\n\
                 \x20       writer_proc('w_grand')\n\
                 \x20   writer_proc('w_child')\n\
                 o = os.fork()\n\
                 if o == 0:\n\
                 \x20   og = os.fork()\n\
                 \x20   if og == 0:\n\
                 \x20       put('orphan.pid', str(os.getpid()))\n\
                 \x20       writer_proc('w_orphan')\n\
                 \x20   os._exit(0)\n\
                 while not all(os.path.exists(WS + '/' + f) for f in ('child.pid', 'grand.pid', 'orphan.pid')):\n\
                 \x20   time.sleep(0.005)\n\
                 time.sleep(0.2)\n\
                 put('m0')\n\
                 wait('go1')\n\
                 put('m1')\n\
                 wait('go2')\n"
            ),
            hooks,
        )
        .unwrap();
    releaser.join().unwrap();
    assert!(matches!(outcome.exit, ExitDisposition::Exited(0)));

    let samples = frozen_samples.lock().unwrap();
    assert!(samples.len() >= 2, "two boundaries ran: {}", samples.len());
    for (before, after, members) in samples.iter() {
        assert_eq!(before, after, "no writer moved while the cgroup was frozen");
        assert!(
            before.iter().all(|s| *s > 0),
            "every writer had run: {before:?}"
        );
        assert!(
            *members >= 4,
            "root, child, grandchild and the orphan are all in the cgroup: {members}"
        );
    }

    let events = events_of(&outcome.run_path);
    // the root exited with writers alive: the cgroup was killed, then the final capture ran
    let kills = of_type(&events, "cgroup_kill");
    assert_eq!(kills.len(), 1);
    assert_eq!(kills[0]["reason"], "run_end");
    assert!(kills[0]["processes"].as_u64().unwrap() >= 3);
    let kill_seq = kills[0]["seq"].as_u64().unwrap();
    let steps = of_type(&events, "step");
    let final_event = steps.last().unwrap();
    assert!(
        final_event["seq"].as_u64().unwrap() > kill_seq,
        "the final capture follows the kill and populated 0"
    );
    assert!(of_type(&events, "run_end")[0]["seq"].as_u64().unwrap() > kill_seq);
    for pid_file in ["root", "child", "grand", "orphan"] {
        let pid: i32 = String::from_utf8(harness.read_ws(&format!("{pid_file}.pid")))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // SAFETY: signal 0 only checks whether the pid exists.
        assert_ne!(
            unsafe { libc::kill(pid, 0) },
            0,
            "{pid_file} {pid} survived"
        );
    }
    // nothing writes after the run: the final snapshot holds the files' last bytes
    let final_step = final_event["step"].as_u64().unwrap();
    let store = open_store(&outcome.run_path);
    let final_files = files_at(&store, final_step);
    std::thread::sleep(Duration::from_millis(100));
    for file in files {
        assert_eq!(
            final_files[file],
            harness.read_ws(file),
            "{file}: the final capture matches the workspace after the run"
        );
    }
    assert_digests_and_chain(&outcome.run_path, &events);
}

// ---------------------------------------------------------------------------------------
// the order of the barrier, and the loop that never receives across it
// ---------------------------------------------------------------------------------------

#[test]
fn the_barrier_runs_in_adr_order_and_no_notification_is_recorded_across_it() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("barrier_order") {
        return;
    }
    let harness = Harness::new(&[("base.txt", "base")]);
    let releaser = harness.release(&[(1, "go1"), (2, "go2"), (3, "go3")]);
    let state = harness.state.path().to_path_buf();
    let boundary = AtomicU64::new(0);
    let log: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let lines_at_freeze = AtomicU64::new(0);
    let line_count = |run: &Path| events_of(run).len() as u64;
    let step_events = |run: &Path| of_type(&events_of(run), "step").len() as u64;
    let freeze = |group: &Cgroup, timeout: Duration| -> std::io::Result<()> {
        let step = boundary.fetch_add(1, Ordering::SeqCst) + 1;
        let run = first_run(&state).unwrap();
        assert!(
            !manifest_path(&run, step).exists(),
            "nothing is captured before the freeze"
        );
        assert_eq!(step_events(&run), step, "steps 0..{step} are committed");
        lines_at_freeze.store(line_count(&run), Ordering::SeqCst);
        log.lock().unwrap().push(format!("freeze {step}"));
        group.set_frozen(true, timeout)
    };
    let is_frozen = |group: &Cgroup| -> std::io::Result<bool> {
        let step = boundary.load(Ordering::SeqCst);
        let run = first_run(&state).unwrap();
        assert!(
            manifest_path(&run, step).exists(),
            "the capture is published before the re-check"
        );
        assert_eq!(
            step_events(&run),
            step,
            "the step event follows the re-check"
        );
        log.lock().unwrap().push(format!("frozen? {step}"));
        group.is_frozen()
    };
    let thaw = |group: &Cgroup, timeout: Duration| -> std::io::Result<()> {
        let step = boundary.load(Ordering::SeqCst);
        let run = first_run(&state).unwrap();
        assert_eq!(
            step_events(&run),
            step + 1,
            "the step event is durable before the thaw"
        );
        assert_eq!(
            line_count(&run),
            lines_at_freeze.load(Ordering::SeqCst) + 1,
            "between freeze and thaw the trace gained only the step event: no notification was received"
        );
        log.lock().unwrap().push(format!("thaw {step}"));
        group.set_frozen(false, timeout)
    };
    let hooks = SessionHooks {
        barrier: BarrierOps {
            freeze: &freeze,
            is_frozen: &is_frozen,
            thaw: &thaw,
            ..BarrierOps::default()
        },
        ..SessionHooks::default()
    };
    // a hammer thread issues mediated opens as fast as it can all through the run, so at every
    // freeze some notifications are unreceived. each is interrupted by the freeze and restarts
    // after the thaw (measurement 0003 question 2); the run must neither hang nor lose one.
    let outcome = harness
        .run_with(
            "stop = False\n\
             def hammer():\n\
             \x20   while not stop:\n\
             \x20       try:\n\
             \x20           open(WS + '/base.txt', 'rb').close()\n\
             \x20       except OSError:\n\
             \x20           pass\n\
             \x20       time.sleep(0.0005)\n\
             t = threading.Thread(target=hammer)\n\
             t.start()\n\
             put('m0')\n\
             wait('go1')\n\
             put('m1')\n\
             wait('go2')\n\
             put('m2')\n\
             wait('go3')\n\
             stop = True\n\
             t.join()\n",
            hooks,
        )
        .unwrap();
    releaser.join().unwrap();
    assert!(matches!(outcome.exit, ExitDisposition::Exited(0)));
    let log = log.lock().unwrap();
    assert_eq!(
        log.iter().map(String::as_str).collect::<Vec<_>>(),
        [
            "freeze 1",
            "frozen? 1",
            "thaw 1",
            "freeze 2",
            "frozen? 2",
            "thaw 2",
            "freeze 3",
            "frozen? 3",
            "thaw 3"
        ]
    );
    let events = events_of(&outcome.run_path);
    let opens = events
        .iter()
        .filter(|e| {
            e["type"] == "syscall"
                && e["fact"]["path"]
                    .as_str()
                    .is_some_and(|p| p.ends_with("base.txt"))
        })
        .count();
    assert!(
        opens > 100,
        "the hammer ran throughout: {opens} opens recorded"
    );
    assert_digests_and_chain(&outcome.run_path, &events);
}

#[test]
fn a_boundary_waits_for_the_ask_prompt_in_flight_and_never_interrupts_it() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("ask_pending") {
        return;
    }
    let harness = Harness::new(&[("trigger-ask", "ask")]);
    let trigger = harness.ws.join("trigger-ask");
    harness.write_policy(&format!(
        "schema_version = 1\n\
         [[fs]]\npath={:?}\nmode=[\"read\"]\naction=\"ask\"\n\
         [[fs]]\npath={:?}\nmode=[\"read\",\"write\",\"create\",\"delete\"]\naction=\"allow\"\n\
         [[fs]]\npath=\"/**\"\nmode=[\"read\"]\naction=\"allow\"\n\
         [[exec]]\nbinary=\"/**\"\naction=\"allow\"\n",
        trigger.display().to_string(),
        format!("{}/**", harness.ws.display()),
    ));
    let prompt_end_ms = AtomicU64::new(0);
    let prompter = |_asks: &[leash::supervisor::ask::PendingAsk], _t: Duration| {
        // longer than the window and the minimum interval together: a boundary is due while
        // the prompt is open, and must wait for it
        std::thread::sleep(Duration::from_millis(1800));
        prompt_end_ms.store(now_ms(), Ordering::SeqCst);
        AskResolution::Approved
    };
    let mut spec = harness.spec(
        "put('m0')\n\
         open(WS + '/trigger-ask').read()\n\
         time.sleep(0.3)\n",
    );
    spec.attendance = Attendance::Attended;
    let outcome = run_session_with_hooks(
        spec,
        SessionHooks {
            prompter: &prompter,
            ..SessionHooks::default()
        },
    )
    .unwrap();
    assert!(matches!(outcome.exit, ExitDisposition::Exited(0)));
    let events = events_of(&outcome.run_path);
    let ask = events
        .iter()
        .find(|e| e["type"] == "syscall" && e["decision"] == "ask")
        .expect("the ask was recorded");
    let step1 = events
        .iter()
        .find(|e| e["type"] == "step" && e["step"] == 1)
        .expect("the mutation closed a step");
    assert!(
        step1["seq"].as_u64().unwrap() > ask["seq"].as_u64().unwrap(),
        "the boundary came after the prompt resolved"
    );
    assert!(
        step1["ts"].as_u64().unwrap() >= prompt_end_ms.load(Ordering::SeqCst),
        "no boundary committed while the prompt was open"
    );
    assert_digests_and_chain(&outcome.run_path, &events);
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// ---------------------------------------------------------------------------------------
// every failure aborts closed
// ---------------------------------------------------------------------------------------

fn failing_freeze(_: &Cgroup, _: Duration) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "cgroup frozen did not reach 1",
    ))
}

#[test]
fn a_freeze_that_does_not_complete_aborts_closed_and_kills_the_whole_cgroup() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("freeze_timeout") {
        return;
    }
    let harness = Harness::new(&[]);
    let started = Instant::now();
    // the freeze is simulated: an agent cannot install its own SECCOMP_RET_USER_NOTIF listener
    // under Leash's (see the next test), so no agent can wedge a freeze on a real kernel
    let result = harness.run_with(
        &format!(
            "{WRITE_PID}\
             sleep_child = os.fork()\n\
             if sleep_child == 0:\n\
             \x20   time.sleep(60)\n\
             \x20   os._exit(0)\n\
             put('m0')\n\
             time.sleep(60)\n"
        ),
        SessionHooks {
            barrier: BarrierOps {
                freeze: &failing_freeze,
                ..BarrierOps::default()
            },
            ..SessionHooks::default()
        },
    );
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the abort kills the sleeping tree instead of waiting for it"
    );
    let events = assert_aborted_closed(&harness, result, 1, CapturePhase::Freeze);
    assert_eq!(
        step_numbers(&events),
        vec![0],
        "no step event for the failed boundary"
    );
    assert_agent_dead(&harness);
    assert!(
        !manifest_path(&harness.run_dir().unwrap(), 1).exists(),
        "nothing was captured"
    );
}

#[test]
fn an_agent_cannot_install_its_own_notify_listener_under_leashs() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("nested_listener") {
        return;
    }
    let harness = Harness::new(&[]);
    // the kernel allows one listener per filter chain, and Leash's is already in the agent's
    // chain, so SECCOMP_FILTER_FLAG_NEW_LISTENER fails with EBUSY. the filter would trap only
    // getpriority, so a kernel that accepted it could not hang the agent
    let outcome = harness
        .run(
            "import errno\n\
             libc = ctypes.CDLL(None, use_errno=True)\n\
             class Insn(ctypes.Structure):\n\
             \x20   _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte), ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]\n\
             class Prog(ctypes.Structure):\n\
             \x20   _fields_ = [('len', ctypes.c_ushort), ('filter', ctypes.POINTER(Insn))]\n\
             insns = (Insn * 4)(Insn(0x20, 0, 0, 0), Insn(0x15, 0, 1, 140), Insn(0x06, 0, 0, 0x7fc00000), Insn(0x06, 0, 0, 0x7fff0000))\n\
             prog = Prog(4, insns)\n\
             rc = libc.syscall(317, 1, 1 << 3, ctypes.byref(prog))\n\
             err = ctypes.get_errno()\n\
             print('NEW_LISTENER rc=%d errno=%d' % (rc, err), file=sys.stderr)\n\
             sys.exit(0 if rc == -1 and err == errno.EBUSY else (3 if rc >= 0 else 4))\n",
        )
        .unwrap();
    assert!(
        matches!(outcome.exit, ExitDisposition::Exited(0)),
        "a nested NEW_LISTENER must fail with EBUSY: {:?}",
        outcome.exit
    );
}

#[test]
fn a_capture_the_store_refuses_aborts_closed_and_records_the_failure() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("capture_refused") {
        return;
    }
    let harness = Harness::new(&[]);
    // a fifo is an entry capture refuses; the agent plants one between mediated writes
    let result = harness.run(&format!(
        "{WRITE_PID}\
         put('m0')\n\
         os.mkfifo(WS + '/pipe')\n\
         time.sleep(60)\n"
    ));
    let events = assert_aborted_closed(&harness, result, 1, CapturePhase::Capture);
    assert_eq!(
        step_numbers(&events),
        vec![0],
        "no step event for the failed boundary"
    );
    let failed = of_type(&events, "capture_failed");
    assert!(
        failed[0]["error"].as_str().unwrap().contains("pipe"),
        "the error names the entry: {failed:?}"
    );
    assert_agent_dead(&harness);
    assert!(
        !manifest_path(&harness.run_dir().unwrap(), 1).exists(),
        "a refused capture publishes nothing"
    );
}

#[test]
fn a_capture_limit_hit_aborts_closed() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("capture_limit") {
        return;
    }
    let harness = Harness::new(&[("base.txt", "base")]);
    let result = harness.run_with(
        &format!(
            "{WRITE_PID}\
             for i in range(6):\n\
             \x20   put('f%d' % i)\n\
             time.sleep(60)\n"
        ),
        SessionHooks {
            limits: Limits {
                max_entries: 4,
                ..Limits::default()
            },
            ..SessionHooks::default()
        },
    );
    let events = assert_aborted_closed(&harness, result, 1, CapturePhase::Capture);
    assert_eq!(step_numbers(&events), vec![0]);
    assert!(
        of_type(&events, "capture_failed")[0]["error"]
            .as_str()
            .unwrap()
            .contains("limit"),
        "{events:?}"
    );
    assert_agent_dead(&harness);
}

#[test]
fn a_limit_hit_by_the_initial_capture_refuses_the_run_before_any_agent_exists() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("initial_capture_limit") {
        return;
    }
    let harness = Harness::new(&[("a", "1"), ("b", "2"), ("c", "3")]);
    let result = harness.run_with(
        &format!("{WRITE_PID}time.sleep(60)\n"),
        SessionHooks {
            limits: Limits {
                max_entries: 2,
                ..Limits::default()
            },
            ..SessionHooks::default()
        },
    );
    match &result {
        Err(SessionError::Run(RunError::Barrier { step: 0, phase, .. })) => {
            assert_eq!(*phase, CapturePhase::Capture);
        }
        other => panic!("expected a refused step 0, got {other:?}"),
    }
    assert_eq!(session_exit_code(result), ExitCode::from(125));
    let run = harness.run_dir().unwrap();
    let events = events_of(&run);
    assert_eq!(of_type(&events, "capture_failed").len(), 1);
    assert!(of_type(&events, "step").is_empty());
    assert!(of_type(&events, "run_end").is_empty());
    assert!(!harness.ws.join("agent.pid").exists(), "no agent ever ran");
    let cgroup = PathBuf::from(events[0]["run_cgroup"].as_str().unwrap());
    assert!(!cgroup.exists(), "the run cgroup was removed");
}

#[test]
fn a_cgroup_that_thaws_during_the_capture_aborts_closed_and_leaves_an_orphan_manifest() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("frozen_dropped") {
        return;
    }
    let harness = Harness::new(&[]);
    let result = harness.run_with(
        &format!("{WRITE_PID}put('m0')\ntime.sleep(60)\n"),
        SessionHooks {
            barrier: BarrierOps {
                is_frozen: &|_| Ok(false),
                ..BarrierOps::default()
            },
            ..SessionHooks::default()
        },
    );
    let events = assert_aborted_closed(&harness, result, 1, CapturePhase::FrozenCheck);
    assert_eq!(
        step_numbers(&events),
        vec![0],
        "no step event for the failed boundary"
    );
    // the manifest was published before the re-check: it is an orphan, never a committed step
    let run = harness.run_dir().unwrap();
    assert_eq!(committed_steps(&open_store(&run)).unwrap(), vec![0, 1]);
    assert_agent_dead(&harness);
}

#[test]
fn a_thaw_that_does_not_complete_aborts_closed_after_the_step_is_committed() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("thaw_timeout") {
        return;
    }
    let harness = Harness::new(&[]);
    let result = harness.run_with(
        &format!("{WRITE_PID}put('m0')\ntime.sleep(60)\n"),
        SessionHooks {
            barrier: BarrierOps {
                thaw: &|_, _| {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "cgroup frozen did not reach 0",
                    ))
                },
                ..BarrierOps::default()
            },
            ..SessionHooks::default()
        },
    );
    let events = assert_aborted_closed(&harness, result, 1, CapturePhase::Thaw);
    // the step event was durable before the thaw was tried: the step is committed, the run is
    // not. the agent was still frozen when the cgroup was killed
    assert_eq!(step_numbers(&events), vec![0, 1]);
    assert_agent_dead(&harness);
}

// ---------------------------------------------------------------------------------------
// the workspace lock
// ---------------------------------------------------------------------------------------

#[test]
fn a_second_run_on_a_locked_workspace_is_refused_before_it_spawns() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("workspace_lock") {
        return;
    }
    let harness = Harness::new(&[]);
    let state = harness.state.path().to_path_buf();
    let spec = harness.spec("put('up'); wait('release')\n");
    let first = std::thread::spawn(move || run_session_with_hooks(spec, SessionHooks::default()));
    let deadline = Instant::now() + Duration::from_secs(20);
    while !harness.ws.join("up").exists() {
        assert!(Instant::now() < deadline, "the first run never started");
        std::thread::sleep(Duration::from_millis(10));
    }
    let runs_before = std::fs::read_dir(state.join("runs")).unwrap().count();

    let second = harness.run("put('second-agent-ran')\n");
    match &second {
        Err(SessionError::WorkspaceLock(WorkspaceLockError::Held(_))) => {}
        other => panic!("expected a refused second run, got {other:?}"),
    }
    assert!(
        second
            .unwrap_err()
            .to_string()
            .contains("another leash run or rewind owns this workspace")
    );
    assert!(!harness.ws.join("second-agent-ran").exists());
    assert_eq!(
        std::fs::read_dir(state.join("runs")).unwrap().count(),
        runs_before,
        "the refused run created no run directory"
    );

    std::fs::write(harness.ctl.join("release"), "1").unwrap();
    let outcome = first.join().unwrap().unwrap();
    assert!(matches!(outcome.exit, ExitDisposition::Exited(0)));
    // the lock is released with the run: the workspace can be run again
    std::fs::remove_file(harness.ws.join("up")).unwrap();
    let third = harness.run("put('third')\n").unwrap();
    assert!(matches!(third.exit, ExitDisposition::Exited(0)));
}

// ---------------------------------------------------------------------------------------
// digests on stderr
// ---------------------------------------------------------------------------------------

/// the body of the child process the next test spawns: it runs one snapshot session and lets
/// its stderr be read. without the env vars it is a no-op, so a normal test run skips it.
#[test]
fn stderr_child() {
    let (Ok(state), Ok(ws), Ok(ctl)) = (
        std::env::var("LEASH_BARRIER_STATE"),
        std::env::var("LEASH_BARRIER_WS"),
        std::env::var("LEASH_BARRIER_CTL"),
    ) else {
        return;
    };
    let (state, ws, ctl) = (PathBuf::from(state), PathBuf::from(ws), PathBuf::from(ctl));
    let prelude = PRELUDE
        .replace("{ws}", &format!("{:?}", ws.display().to_string()))
        .replace("{ctl}", &format!("{:?}", ctl.display().to_string()));
    let spec = SessionSpec {
        argv: vec![
            "/usr/bin/python3".into(),
            "-c".into(),
            format!("{prelude}put('a1', '1')\ntime.sleep(1.6)\nput('b1', '2')\ntime.sleep(1.6)\n"),
        ],
        mode: Mode::Enforce,
        attendance: Attendance::Unattended,
        state_root: state.clone(),
        state_root_spelling: state.clone(),
        workspace: ws,
        policy_path: Some(state.join("policy.toml")),
        ask_timeout: Duration::from_secs(60),
        snapshot_integrity: true,
    };
    let outcome = run_session_with_hooks(spec, SessionHooks::default()).unwrap();
    assert!(matches!(outcome.exit, ExitDisposition::Exited(0)));
}

#[test]
fn each_digest_is_printed_as_its_step_commits_and_run_end_carries_the_chain_head() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("stderr_digests") {
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let ws = tempfile::tempdir().unwrap();
    let ctl = tempfile::tempdir().unwrap();
    let ws_path = ws.path().canonicalize().unwrap();
    std::fs::write(
        state.path().join("policy.toml"),
        format!(
            "{POLICY_BASE}[[fs]]\npath={:?}\nmode=[\"read\",\"write\",\"create\",\"delete\"]\naction=\"allow\"\n",
            format!("{}/**", ws_path.display())
        ),
    )
    .unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["stderr_child", "--exact", "--nocapture"])
        .env("LEASH_BARRIER_STATE", state.path())
        .env("LEASH_BARRIER_WS", &ws_path)
        .env("LEASH_BARRIER_CTL", ctl.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    let run = first_run(state.path()).unwrap();
    let events = events_of(&run);
    assert_digests_and_chain(&run, &events);
    let store = open_store(&run);
    let chain = recompute_chain(&store).unwrap();
    assert!(chain.digests.len() >= 3, "{:?}", chain.digests);
    for (step, digest) in &chain.digests {
        assert!(
            stderr
                .lines()
                .any(|l| l == format!("leash: step {step} snapshot {digest}")),
            "stderr shows step {step}'s digest:\n{stderr}"
        );
    }
    assert!(
        stderr
            .lines()
            .any(|l| l == format!("leash: snapshot chain head {}", chain.head)),
        "stderr shows the chain head:\n{stderr}"
    );
    // the digest line precedes the next step's line: they print as each step commits
    let order: Vec<usize> = chain
        .digests
        .iter()
        .map(|(step, digest)| {
            stderr
                .find(&format!("leash: step {step} snapshot {digest}"))
                .unwrap()
        })
        .collect();
    assert!(order.windows(2).all(|w| w[0] < w[1]));
}

// ---------------------------------------------------------------------------------------
// a run that does not snapshot is unchanged
// ---------------------------------------------------------------------------------------

#[test]
fn a_non_snapshot_enforce_run_takes_no_snapshots_and_keeps_its_trace_shape() {
    let _guard = spawn_lock();
    let harness = Harness::new(&[("base.txt", "base")]);
    let mut spec = harness.spec("put('a1', '1')\ntime.sleep(1.5)\nput('a2', '2')\n");
    spec.snapshot_integrity = false;
    let outcome = run_session_with_hooks(spec, SessionHooks::default()).unwrap();
    assert!(matches!(outcome.exit, ExitDisposition::Exited(0)));

    let events = events_of(&outcome.run_path);
    for event in &events {
        let kind = event["type"].as_str().unwrap();
        assert!(
            matches!(kind, "run_start" | "syscall" | "run_end"),
            "a non-snapshot run writes only run_start, syscall and run_end: {event}"
        );
    }
    assert!(events[0].get("run_cgroup").is_none());
    let end = of_type(&events, "run_end");
    assert_eq!(end.len(), 1);
    assert_eq!(end[0]["final_step"], 0);
    assert!(end[0].get("chain_head").is_none());
    assert_eq!(
        std::fs::read_dir(outcome.run_path.join("snapshots"))
            .unwrap()
            .count(),
        0,
        "nothing was stored"
    );
    assert!(
        !harness.state.path().join("locks").exists(),
        "no workspace lock was taken"
    );
    assert_eq!(harness.read_ws("a1"), b"1");
}
