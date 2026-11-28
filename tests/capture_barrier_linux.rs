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
use leash::recorder::{AskResolution, Attendance, CapturePhase, FailNthSync, Mode};
use leash::snapshot::restore::recompute_chain;
use leash::snapshot::store::{
    EntryKind, Limits, StoreError, committed_steps_from_trace, load_manifest, published_steps,
    verify_object,
};
use leash::supervisor::barrier::BarrierOps;
use leash::supervisor::cgroup::Cgroup;
use leash::supervisor::run::RunError;
use leash::supervisor::session::{
    ExitDisposition, SessionError, SessionHooks, SessionOutcome, SessionSpec,
    run_session_with_hooks, run_session_with_trace_sink,
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
def wait_ws(n):\n\
\x20   while not os.path.exists(WS + '/' + n):\n\
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

/// the committed steps of a run as `leash diff` and rewind read them: from the trace.
fn committed_of(run: &Path) -> Vec<u64> {
    committed_steps_from_trace(&File::open(run).unwrap()).unwrap()
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
    assert_eq!(step_numbers(events), published_steps(&store).unwrap());
    assert_eq!(step_numbers(events), committed_of(run));
    assert_eq!(step_numbers(events)[0], 0, "step 0 is the first step event");
    let chain = recompute_chain(&store, &committed_of(run)).unwrap();
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

/// the two writers that tick no mediated event after setup. each stores the counter `i` in the
/// last unit of its file and then in the first, forever, from a forked process, so the file is
/// never inconsistent in a way the supervisor could see by watching events.
///
/// a capture of a frozen tree reads a moment at which the writer is stopped between or
/// after its two stores, so `tail - head` is 0 or 1. a copy of a running tree reads the head,
/// keeps reading while the writer advances, and reads the tail much later: the difference is
/// the number of iterations that ran meanwhile, in the tens of thousands for these sizes. the
/// negative-control tests below prove that difference shows, so these positive tests can fail.
#[derive(Clone, Copy)]
enum Workload {
    /// a `MAP_SHARED` file of 1 Mi words, stored through the mapping.
    SharedMap,
    /// a file of 2048 records of 4 KiB, written with `pwrite` through one descriptor.
    PersistentFd,
}

impl Workload {
    fn name(self) -> &'static str {
        match self {
            Self::SharedMap => "map",
            Self::PersistentFd => "log",
        }
    }

    /// the agent code that creates the file, forks the writer and returns in the parent.
    fn setup(self) -> &'static str {
        match self {
            Self::SharedMap => {
                r#"
N = 1 << 20
fd = os.open(WS + '/map', os.O_RDWR | os.O_CREAT, 0o644)
os.ftruncate(fd, 8 * N)
mm = mmap.mmap(fd, 8 * N, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
words = (ctypes.c_uint64 * N).from_buffer(mm)
if os.fork() == 0:
    i = 0
    while True:
        i += 1
        words[N - 1] = i
        words[0] = i
"#
            }
            Self::PersistentFd => {
                r#"
R = 4096
NREC = 2048
fd = os.open(WS + '/log', os.O_RDWR | os.O_CREAT, 0o644)
os.ftruncate(fd, R * NREC)
if os.fork() == 0:
    i = 0
    while True:
        i += 1
        rec = struct.pack('<Q', i) * 512
        os.pwrite(fd, rec, R * (NREC - 1))
        os.pwrite(fd, rec, 0)
"#
            }
        }
    }

    /// bytes per unit: a word, or a record.
    fn unit(self) -> usize {
        match self {
            Self::SharedMap => 8,
            Self::PersistentFd => 4096,
        }
    }

    fn file_len(self) -> usize {
        match self {
            Self::SharedMap => 8 << 20,
            Self::PersistentFd => 4096 * 2048,
        }
    }

    /// the counters in the first and last unit of the captured file, or an error naming a
    /// unit that is not one counter repeated (a torn record).
    fn ends(self, bytes: &[u8]) -> Result<(u64, u64), String> {
        assert_eq!(bytes.len(), self.file_len(), "the file keeps its size");
        let unit = self.unit();
        let read = |chunk: &[u8]| -> Result<u64, String> {
            if chunk.chunks(8).all(|w| w == &chunk[..8]) {
                Ok(u64::from_le_bytes(chunk[..8].try_into().unwrap()))
            } else {
                Err(format!("a unit is torn: {:?}", &chunk[..16]))
            }
        };
        let head = read(&bytes[..unit])?;
        let tail = read(&bytes[bytes.len() - unit..])?;
        Ok((head, tail))
    }

    /// everything between the first and the last unit is still zero: nothing else wrote.
    fn middle_is_untouched(self, bytes: &[u8]) -> bool {
        let unit = self.unit();
        bytes[unit..bytes.len() - unit].iter().all(|b| *b == 0)
    }

    /// the whole agent program: the setup, then `tail`.
    fn body(self, tail: &str) -> String {
        format!("{}{tail}", self.setup())
    }
}

/// a freeze or thaw that does nothing: with `is_frozen` always satisfied, the barrier captures a
/// running tree while believing it is frozen. this is the negative control of the consistency
/// tests, a test of the tests and not of any production path.
fn noop_freeze(_: &Cgroup, _: Duration) -> std::io::Result<()> {
    Ok(())
}

fn assert_captured_consistently(workload: Workload, run: &Path, events: &[Value]) {
    let store = open_store(run);
    let mut previous_head = 0u64;
    let mut seen = 0;
    for step in step_numbers(events) {
        let Some(bytes) = files_at(&store, step).remove(workload.name()) else {
            continue; // step 0 predates the file
        };
        seen += 1;
        let (head, tail) = workload
            .ends(&bytes)
            .unwrap_or_else(|e| panic!("step {step}: {e}"));
        assert!(
            tail == head || tail == head + 1,
            "step {step}: head {head} and tail {tail} differ by more than one iteration, so the file was read while its writer ran"
        );
        assert!(
            workload.middle_is_untouched(&bytes),
            "step {step}: a store landed between the first and the last unit"
        );
        assert!(
            head >= previous_head,
            "step {step}: the counter only grows ({head} after {previous_head})"
        );
        previous_head = head;
    }
    assert!(seen >= 3, "boundaries captured the file: {seen}");
    assert!(
        previous_head >= 10_000,
        "the writer ran across the boundaries: counter {previous_head}"
    );
}

fn run_consistency_test(workload: Workload, name: &str) {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip(name) {
        return;
    }
    let harness = Harness::new(&[]);
    let releaser = harness.release(&[(1, "go1"), (2, "go2"), (3, "go3")]);
    // only the marker files propose boundaries: the writer ticks no mediated event after its
    // setup, and the root waits for each step to publish before it makes the next marker
    let outcome = harness
        .run(
            &workload
                .body("put('m0')\nwait('go1')\nput('m1')\nwait('go2')\nput('m2')\nwait('go3')\n"),
        )
        .unwrap();
    releaser.join().unwrap();
    assert!(matches!(outcome.exit, ExitDisposition::Exited(0)));
    let events = events_of(&outcome.run_path);
    assert_captured_consistently(workload, &outcome.run_path, &events);
    assert_digests_and_chain(&outcome.run_path, &events);
}

#[test]
fn a_persistent_fd_writer_is_never_captured_ahead_of_itself() {
    run_consistency_test(Workload::PersistentFd, "persistent_fd");
}

#[test]
fn a_shared_mmap_writer_is_never_captured_ahead_of_itself() {
    run_consistency_test(Workload::SharedMap, "shared_mmap");
}

/// how many sessions each negative control runs. every one must show the failure.
const NEGATIVE_CONTROL_RUNS: usize = 4;

/// what an unfrozen capture of a running writer showed.
#[derive(Debug)]
enum Unfrozen {
    /// the store refused the capture because the file changed under it (`capture_failed`).
    CaptureFailed,
    /// the capture was published, and its first and last units differ by this much.
    Drift(u64),
}

/// run the workload with the freezer disabled and report what the mid-run capture shows.
fn negative_control_run(workload: Workload, name: &str) -> Unfrozen {
    let harness = Harness::new(&[]);
    let ctl = harness.ctl.clone();
    // the re-check runs after the capture and before publication: releasing the agent there
    // ends the run right after the boundary, with no sleep to tune
    let release = move |_: &Cgroup| -> std::io::Result<bool> {
        std::fs::write(ctl.join("go1"), "1")?;
        Ok(true)
    };
    let result = harness.run_with(
        &workload.body("put('m0')\nwait('go1')\n"),
        SessionHooks {
            barrier: BarrierOps {
                freeze: &noop_freeze,
                thaw: &noop_freeze,
                is_frozen: &release,
                ..BarrierOps::default()
            },
            ..SessionHooks::default()
        },
    );
    match result {
        Err(SessionError::Run(RunError::Barrier {
            phase: CapturePhase::Capture,
            ..
        })) => {
            let run = harness.run_dir().unwrap();
            assert_eq!(of_type(&events_of(&run), "capture_failed").len(), 1);
            Unfrozen::CaptureFailed
        }
        Ok(outcome) => {
            let events = events_of(&outcome.run_path);
            let store = open_store(&outcome.run_path);
            let steps = step_numbers(&events);
            // the last step is taken after the kill, so only the mid-run steps can drift
            let mid_run = &steps[1..steps.len() - 1];
            assert!(!mid_run.is_empty(), "{name}: a boundary ran mid-run");
            let mut worst = 0u64;
            for step in mid_run {
                let bytes = files_at(&store, *step).remove(workload.name()).unwrap();
                worst = worst.max(match workload.ends(&bytes) {
                    Ok((head, tail)) => tail.abs_diff(head),
                    // a torn unit is also a copy of a running writer
                    Err(_) => u64::MAX,
                });
            }
            Unfrozen::Drift(worst)
        }
        other => panic!("{name}: unexpected result {other:?}"),
    }
}

fn run_negative_control(workload: Workload, name: &str) {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip(name) {
        return;
    }
    for run in 1..=NEGATIVE_CONTROL_RUNS {
        let observed = negative_control_run(workload, name);
        eprintln!("NEGATIVE-CONTROL {name} run {run}: {observed:?}");
        if let Unfrozen::Drift(drift) = observed {
            assert!(
                drift > 1,
                "{name} run {run}: an unfrozen capture of a running writer showed head and tail within one iteration, so the positive test could not have failed"
            );
        }
    }
}

#[test]
fn negative_control_an_unfrozen_capture_of_a_persistent_fd_writer_shows_drift() {
    run_negative_control(Workload::PersistentFd, "persistent_fd_control");
}

#[test]
fn negative_control_an_unfrozen_capture_of_a_shared_mmap_writer_shows_drift() {
    run_negative_control(Workload::SharedMap, "shared_mmap_control");
}

// ---------------------------------------------------------------------------------------
// descendants and orphans
// ---------------------------------------------------------------------------------------

/// live file sizes just after a freeze, again 30 ms later, and the cgroup's member count.
type FrozenSample = (Vec<u64>, Vec<u64>, usize);

/// a process that opens `name` once (one mediated event) and then appends 64-byte records
/// every millisecond through that descriptor, touching nothing the supervisor mediates. when
/// `ready` is given it announces itself with a file first.
const WRITER_PROC: &str = "def writer_proc(name, ready=None):\n\
\x20   fd = os.open(WS + '/' + name, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)\n\
\x20   if ready:\n\
\x20       put(ready)\n\
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
    let rechecks: Mutex<Vec<Vec<u64>>> = Mutex::new(Vec::new());
    let ws = harness.ws.clone();
    // after the freeze: the live files do not move for 30 ms (the writers append every ms), and
    // the cgroup lists every member. at the re-check, which runs after the capture and before
    // the manifest is published, the live sizes are recorded: the test compares them with the
    // published snapshot once the run is over, so the capture saw the frozen moment.
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
        rechecks.lock().unwrap().push(sizes(&ws));
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
                 \x20       writer_proc('w_orphan', 'orphan.ready')\n\
                 \x20   wait_ws('orphan.ready')\n\
                 \x20   os._exit(0)\n\
                 for f in ('child.pid', 'grand.pid', 'orphan.ready'):\n\
                 \x20   wait_ws(f)\n\
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
    let rechecks = rechecks.lock().unwrap();
    assert_eq!(
        rechecks.len(),
        samples.len(),
        "every boundary re-checked once"
    );
    let store = open_store(&outcome.run_path);
    for (i, (_, after, _)) in samples.iter().enumerate() {
        let step = i as u64 + 1;
        assert_eq!(
            &rechecks[i], after,
            "step {step}: the live files moved between the freeze and the re-check"
        );
        let (manifest, _) = load_manifest(&store, step).unwrap();
        for (file, live) in files.iter().zip(&rechecks[i]) {
            let captured = manifest
                .entries
                .iter()
                .find(|e| e.path == *file)
                .and_then(|e| e.size)
                .unwrap_or(0);
            assert_eq!(
                *live, captured,
                "step {step}: {file} moved after its capture"
            );
        }
    }
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
            !manifest_path(&run, step).exists(),
            "the re-check runs before the manifest is published (ADR-0024 decision 10)"
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
        assert!(
            manifest_path(&run, step).exists(),
            "the manifest is published before the thaw"
        );
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
fn a_cgroup_that_thaws_during_the_capture_aborts_closed_and_publishes_no_manifest() {
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
    // the re-check runs before the manifest is published (ADR-0024 decision 10), so the failed
    // boundary leaves no manifest at all: not an orphan, nothing
    let run = harness.run_dir().unwrap();
    assert!(
        !manifest_path(&run, 1).exists(),
        "a failed frozen re-check publishes no manifest"
    );
    assert_eq!(published_steps(&open_store(&run)).unwrap(), vec![0]);
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

#[test]
fn a_step_event_that_cannot_be_made_durable_leaves_the_tree_frozen_until_killed() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("step_event_sync") {
        return;
    }
    let harness = Harness::new(&[]);
    let thaws = AtomicU64::new(0);
    let thaw = |group: &Cgroup, timeout: Duration| -> std::io::Result<()> {
        thaws.fetch_add(1, Ordering::SeqCst);
        group.set_frozen(false, timeout)
    };
    // the trace syncs three times before the agent can be affected: run_start, the step 0
    // event, and then the event of step 1, which is the one that fails. the event reaches the
    // file and never becomes durable
    let result = run_session_with_trace_sink(
        harness.spec(&format!("{WRITE_PID}put('m0')\ntime.sleep(60)\n")),
        SessionHooks {
            barrier: BarrierOps {
                thaw: &thaw,
                ..BarrierOps::default()
            },
            ..SessionHooks::default()
        },
        |file| FailNthSync::new(file, 3),
    );
    let events = assert_aborted_closed(&harness, result, 1, CapturePhase::StepEvent);
    assert_eq!(
        thaws.load(Ordering::SeqCst),
        0,
        "the tree was never thawed: it stayed frozen until the cgroup kill"
    );
    assert_agent_dead(&harness);
    assert_eq!(
        step_numbers(&events),
        vec![0, 1],
        "the event of step 1 was written to the file"
    );
    let run = harness.run_dir().unwrap();
    let store = open_store(&run);
    assert_eq!(
        published_steps(&store).unwrap(),
        vec![0, 1],
        "the manifest of step 1 was published: an orphan"
    );
    assert_eq!(
        committed_of(&run),
        vec![0],
        "step 1 is not committed, because its event is followed by capture_failed for it"
    );
    let chain = recompute_chain(&store, &committed_of(&run)).unwrap();
    assert_eq!(chain.digests.len(), 1, "the orphan is not in the chain");
}

#[test]
fn a_publish_the_store_refuses_at_a_boundary_aborts_closed() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("publish_refused") {
        return;
    }
    let harness = Harness::new(&[]);
    let state = harness.state.path().to_path_buf();
    let thaws = AtomicU64::new(0);
    let thaw = |group: &Cgroup, timeout: Duration| -> std::io::Result<()> {
        thaws.fetch_add(1, Ordering::SeqCst);
        group.set_frozen(false, timeout)
    };
    // the frozen re-check runs after the whole tree is captured and immediately before the
    // manifest is renamed into place. a manifest that appears at that moment makes the store
    // refuse the publication, after its objects and staged manifest exist
    let plant = |group: &Cgroup| -> std::io::Result<bool> {
        let run = first_run(&state).unwrap();
        std::fs::write(manifest_path(&run, 1), "planted")?;
        group.is_frozen()
    };
    let result = harness.run_with(
        &format!("{WRITE_PID}put('m0')\ntime.sleep(60)\n"),
        SessionHooks {
            barrier: BarrierOps {
                is_frozen: &plant,
                thaw: &thaw,
                ..BarrierOps::default()
            },
            ..SessionHooks::default()
        },
    );
    let events = assert_aborted_closed(&harness, result, 1, CapturePhase::Capture);
    assert_eq!(step_numbers(&events), vec![0], "no step event for step 1");
    assert!(
        of_type(&events, "capture_failed")[0]["error"]
            .as_str()
            .unwrap()
            .contains("already exists"),
        "{events:?}"
    );
    assert_eq!(thaws.load(Ordering::SeqCst), 0, "the tree stayed frozen");
    assert_agent_dead(&harness);
    let run = harness.run_dir().unwrap();
    assert_eq!(
        std::fs::read(manifest_path(&run, 1)).unwrap(),
        b"planted",
        "the store did not replace what was there"
    );
    assert_eq!(
        std::fs::read_dir(run.join("snapshots/staging"))
            .unwrap()
            .count(),
        0,
        "the staged manifest of the refused publication was removed"
    );
    assert_eq!(committed_of(&run), vec![0]);
}

#[test]
fn a_chain_head_that_cannot_be_computed_after_the_final_commit_is_recorded_and_aborts_closed() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("chain_head_error") {
        return;
    }
    let harness = Harness::new(&[]);
    let broken = |_: &[(u64, String)]| -> Result<String, StoreError> {
        Err(StoreError::InvalidChain {
            reason: "injected chain failure".into(),
        })
    };
    let result = harness.run_with(
        "put('a1', '1')\n",
        SessionHooks {
            chain_head: &broken,
            ..SessionHooks::default()
        },
    );
    match &result {
        Err(SessionError::Run(RunError::ChainHead(_))) => {}
        other => panic!("expected a chain head failure, got {other:?}"),
    }
    assert_eq!(session_exit_code(result), ExitCode::from(125));
    let run = harness.run_dir().unwrap();
    let events = events_of(&run);
    let final_step = *step_numbers(&events).last().unwrap();
    assert!(final_step >= 1, "the final step was committed: {events:?}");
    assert_eq!(committed_of(&run).last(), Some(&final_step));
    let failed = of_type(&events, "capture_failed");
    assert_eq!(failed.len(), 1, "the failure is recorded: {events:?}");
    assert_eq!(failed[0]["phase"], "chain_head");
    assert_eq!(failed[0]["step"], final_step);
    assert!(
        failed[0]["error"]
            .as_str()
            .unwrap()
            .contains("injected chain failure")
    );
    let final_seq = of_type(&events, "step").last().unwrap()["seq"]
        .as_u64()
        .unwrap();
    assert!(failed[0]["seq"].as_u64().unwrap() > final_seq);
    assert!(
        of_type(&events, "run_end").is_empty(),
        "no run_end without a chain head: {events:?}"
    );
    assert!(!run.join("report.txt").exists());
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

#[test]
fn a_second_run_with_a_different_state_dir_on_a_locked_workspace_is_refused_before_it_spawns() {
    let _guard = spawn_lock();
    if !common::delegated_cgroup_or_skip("workspace_lock_other_state") {
        return;
    }
    let harness = Harness::new(&[]);
    let spec = harness.spec("put('up'); wait('release')\n");
    let first = std::thread::spawn(move || run_session_with_hooks(spec, SessionHooks::default()));
    let deadline = Instant::now() + Duration::from_secs(20);
    while !harness.ws.join("up").exists() {
        assert!(Instant::now() < deadline, "the first run never started");
        std::thread::sleep(Duration::from_millis(10));
    }

    // the second run names the same workspace under another state directory, so the lock file
    // under its state root is a different file: only a lock on the workspace directory itself
    // can stop it
    let other_state = tempfile::tempdir().unwrap();
    std::fs::copy(
        harness.state.path().join("policy.toml"),
        other_state.path().join("policy.toml"),
    )
    .unwrap();
    let mut spec = harness.spec("put('second-agent-ran')\n");
    spec.state_root = other_state.path().to_path_buf();
    spec.state_root_spelling = other_state.path().to_path_buf();
    spec.policy_path = Some(other_state.path().join("policy.toml"));
    let second = run_session_with_hooks(spec, SessionHooks::default());
    match &second {
        Err(SessionError::WorkspaceLock(WorkspaceLockError::Held(_))) => {}
        other => panic!("expected a refused second run, got {other:?}"),
    }
    assert!(!harness.ws.join("second-agent-ran").exists());
    assert!(
        !other_state.path().join("runs").exists(),
        "the refused run created no run directory under the other state root"
    );

    std::fs::write(harness.ctl.join("release"), "1").unwrap();
    let outcome = first.join().unwrap().unwrap();
    assert!(matches!(outcome.exit, ExitDisposition::Exited(0)));
    // the lock goes with the run: the other state directory can now run the workspace
    std::fs::remove_file(harness.ws.join("up")).unwrap();
    let mut spec = harness.spec("put('third')\n");
    spec.state_root = other_state.path().to_path_buf();
    spec.state_root_spelling = other_state.path().to_path_buf();
    spec.policy_path = Some(other_state.path().join("policy.toml"));
    let third = run_session_with_hooks(spec, SessionHooks::default()).unwrap();
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
    let chain = recompute_chain(&store, &committed_of(&run)).unwrap();
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
