//! NFR-2 record-only overhead harness (docs/measurements/0001-m1-overhead.md, issue #5).
//!
//! custom main, `harness = false`, no criterion. the whole kernel-touching body is linux
//! only; on any other host `main` says so and exits 0, so the file stays buildable and
//! clippy-clean everywhere. ci never runs benches and no number here gates ci.
//!
//! modes (argv after the bench name):
//!   micro [class]            drive the microbenchmark, bare vs `leash run --`, per class
//!   macro <script.sh>        drive the end-to-end workload, bare vs `leash run --`
//!   gaps  <trace.jsonl>      mine the inter-mutating-event gap distribution (FR-17)
//!   --child <class> <N> <results-path> <workdir>   internal: the timed inner loop
//!
//! the pure analysis (quantiles, gap mining) lives in `leash::measure` and is unit-tested
//! by `cargo test`; this file is the linux-only driver and the timed child around it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(not(target_os = "linux"))]
fn main() {
    println!(
        "leash benches are linux-only; nothing to run on {}",
        std::env::consts::OS
    );
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use leash::measure::{Quantiles, gap_report, quantiles};

    // the four micro classes and their loop sizes (measurements/0001 section 2.1). fs
    // classes run 10000 iterations, exec 500 (fork+exec is far heavier per iteration).
    const CLASSES: &[&str] = &["open_read", "open_write", "mutate", "exec"];
    const N_FS: usize = 10_000;
    const N_EXEC: usize = 500;

    // distinctive workspace filenames so the trap-completeness gate can pick our own
    // syscalls out of the trace by path, ignoring the child's libc/loader opens.
    const READ_FILE: &str = "leash_bench_open_read.dat";
    const WRITE_FILE: &str = "leash_bench_open_write.dat";
    const MUTATE_A: &str = "leash_bench_mutate_a.dat";
    const MUTATE_B: &str = "leash_bench_mutate_b.dat";
    const EXEC_BIN: &str = "/bin/true";

    const REPS: usize = 3;
    const MICRO_DEADLINE: Duration = Duration::from_secs(90);
    const MACRO_DEADLINE: Duration = Duration::from_secs(300);
    const MACRO_REPS: usize = 5;

    pub fn main() {
        // cargo bench passes a --bench flag to harness = false targets; drop it so
        // positional parsing sees only our own arguments.
        let args: Vec<String> = std::env::args().filter(|a| a != "--bench").collect();
        match args.get(1).map(String::as_str) {
            Some("--child") => run_child(&args),
            Some("micro") => run_micro(args.get(2).map(String::as_str)),
            Some("macro") => run_macro(args.get(2).map(String::as_str)),
            Some("gaps") => run_gaps(args.get(2).map(String::as_str)),
            other => {
                eprintln!(
                    "usage: overhead <micro [class] | macro <script.sh> | gaps <trace.jsonl>>\n\
                     (got {other:?})"
                );
                std::process::exit(2);
            }
        }
    }

    fn n_for(class: &str) -> usize {
        if class == "exec" { N_EXEC } else { N_FS }
    }

    // ---------------------------------------------------------------------------
    // child mode: the timed inner loop. re-exec'd by the driver both bare and under
    // leash, so the measurement excludes leash startup and teardown (only the loop is
    // timed). same self-re-exec shape as tests/spawn_linux.rs, adapted to a bench.
    // ---------------------------------------------------------------------------

    fn run_child(args: &[String]) {
        // --child <class> <N> <results-path> <workdir>
        let class = args.get(2).cloned().unwrap_or_default();
        let n: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
        let results = PathBuf::from(args.get(4).cloned().unwrap_or_default());
        let workdir = PathBuf::from(args.get(5).cloned().unwrap_or_default());

        if let Err(e) = std::env::set_current_dir(&workdir) {
            eprintln!("child: cannot enter workdir {}: {e}", workdir.display());
            std::process::exit(3);
        }

        let samples = match class.as_str() {
            "open_read" => loop_open_read(n),
            "open_write" => loop_open_write(n),
            "mutate" => loop_mutate(n),
            "exec" => loop_exec(n),
            other => {
                eprintln!("child: unknown class {other:?}");
                std::process::exit(4);
            }
        };

        // discard the first 5 percent as warmup, then summarize what remains.
        let warmup = (samples.len() * 5) / 100;
        let measured = &samples[warmup.min(samples.len())..];
        let Some(q) = quantiles(measured) else {
            eprintln!("child: no measured samples for {class}");
            std::process::exit(5);
        };

        let out = serde_json::json!({
            "class": class,
            "n": n,
            "measured": q.count,
            "min": q.min,
            "p50": q.p50,
            "p90": q.p90,
            "p99": q.p99,
            "max": q.max,
        });
        if let Err(e) = std::fs::write(&results, serde_json::to_vec(&out).unwrap()) {
            eprintln!("child: cannot write results {}: {e}", results.display());
            std::process::exit(6);
        }
    }

    fn loop_open_read(n: usize) -> Vec<u64> {
        let path = CString::new(READ_FILE).unwrap();
        // pre-create the file the loop opens read-only.
        {
            // SAFETY: open with a borrowed nul-terminated path we own; create the target
            // for the read loop and close it immediately.
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o644) };
            if fd >= 0 {
                // SAFETY: close a fd we just opened and own.
                unsafe { libc::close(fd) };
            }
        }
        let mut samples = Vec::with_capacity(n);
        for _ in 0..n {
            let t = Instant::now();
            // SAFETY: open the pre-created path read-only and close it; the path outlives
            // the call and the returned fd is closed on every branch.
            unsafe {
                let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
                if fd >= 0 {
                    libc::close(fd);
                }
            }
            samples.push(t.elapsed().as_nanos() as u64);
        }
        samples
    }

    fn loop_open_write(n: usize) -> Vec<u64> {
        let path = CString::new(WRITE_FILE).unwrap();
        let mut samples = Vec::with_capacity(n);
        for _ in 0..n {
            let t = Instant::now();
            // SAFETY: open the path for write (creating it the first time) and close it;
            // the path outlives the call and the fd is closed on every branch.
            unsafe {
                let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o644);
                if fd >= 0 {
                    libc::close(fd);
                }
            }
            samples.push(t.elapsed().as_nanos() as u64);
        }
        samples
    }

    fn loop_mutate(n: usize) -> Vec<u64> {
        let a = CString::new(MUTATE_A).unwrap();
        let b = CString::new(MUTATE_B).unwrap();
        // pre-create A so the first rename has something to move.
        {
            // SAFETY: create the initial mutate file and close it.
            let fd = unsafe { libc::open(a.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o644) };
            if fd >= 0 {
                // SAFETY: close a fd we own.
                unsafe { libc::close(fd) };
            }
        }
        let mut samples = Vec::with_capacity(n);
        for _ in 0..n {
            let t = Instant::now();
            // SAFETY: rename between two paths we own; both outlive the calls. the pair
            // leaves the tree as it found it, so the next iteration starts from A again.
            unsafe {
                libc::rename(a.as_ptr(), b.as_ptr());
                libc::rename(b.as_ptr(), a.as_ptr());
            }
            samples.push(t.elapsed().as_nanos() as u64);
        }
        samples
    }

    fn loop_exec(n: usize) -> Vec<u64> {
        let mut samples = Vec::with_capacity(n);
        for _ in 0..n {
            let t = Instant::now();
            // Command is fork + execvp + waitpid; only the execve is mediated. timing
            // wraps the whole spawn and wait, which is the exec class's cost.
            let status = Command::new(EXEC_BIN)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            samples.push(t.elapsed().as_nanos() as u64);
            if status.map(|s| !s.success()).unwrap_or(true) {
                eprintln!("child: {EXEC_BIN} did not exit 0");
                std::process::exit(7);
            }
        }
        samples
    }

    // ---------------------------------------------------------------------------
    // driver: run each class bare and under `leash run --`, gate on trap completeness.
    // ---------------------------------------------------------------------------

    fn run_micro(only: Option<&str>) {
        let bench = self_exe();
        let leash = leash_exe();
        println!("leash overhead micro (measurements/0001 section 2.1)");
        println!("bench exe: {}", bench.display());
        println!("leash exe: {}", leash.display());

        // self-check first: bare vs bare must be indistinguishable from noise before any
        // leash number is read (section 2.1 validity gates).
        let sc_a = one_rep_bare(&bench, "open_read", N_FS);
        let sc_b = one_rep_bare(&bench, "open_read", N_FS);
        match (sc_a, sc_b) {
            (Some(a), Some(b)) => {
                let delta = a.p50 as i64 - b.p50 as i64;
                println!(
                    "\nself-check (open_read bare vs bare): p50 {} ns vs {} ns, delta {delta} ns",
                    a.p50, b.p50
                );
                println!(
                    "  read the leash numbers only if this delta is small relative to the leash delta below."
                );
            }
            _ => println!(
                "\nself-check: a bare rep produced no results; investigate before trusting leash numbers"
            ),
        }

        let classes: Vec<&str> = match only {
            Some(c) if CLASSES.contains(&c) => vec![c],
            Some(c) => {
                eprintln!("unknown class {c:?}; classes: {CLASSES:?}");
                std::process::exit(2);
            }
            None => CLASSES.to_vec(),
        };

        let mut records = Vec::new();
        println!(
            "\n{:<12} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
            "class", "bare p50", "leash p50", "d p50", "bare p99", "leash p99", "d p99"
        );
        for class in classes {
            let n = n_for(class);
            let bare: Vec<Quantiles> = (0..REPS)
                .filter_map(|_| one_rep_bare(&bench, class, n))
                .collect();
            let mut leash_ok = Vec::new();
            let mut voids = 0usize;
            for _ in 0..REPS {
                match one_rep_leash(&bench, &leash, class, n) {
                    LeashRep::Ok(q) => leash_ok.push(q),
                    LeashRep::Void(reason) => {
                        voids += 1;
                        println!("  VOID leash rep for {class}: {reason}");
                    }
                }
            }
            let bp50 = median_of(&bare, |q| q.p50);
            let bp99 = median_of(&bare, |q| q.p99);
            let lp50 = median_of(&leash_ok, |q| q.p50);
            let lp99 = median_of(&leash_ok, |q| q.p99);
            let cell = |v: Option<u64>| v.map_or("-".to_string(), |x| x.to_string());
            let delta = |b: Option<u64>, l: Option<u64>| match (b, l) {
                (Some(b), Some(l)) => (l as i64 - b as i64).to_string(),
                _ => "-".to_string(),
            };
            println!(
                "{:<12} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
                class,
                cell(bp50),
                cell(lp50),
                delta(bp50, lp50),
                cell(bp99),
                cell(lp99),
                delta(bp99, lp99),
            );
            records.push(serde_json::json!({
                "class": class,
                "n": n,
                "bare": bare.iter().map(quantiles_json).collect::<Vec<_>>(),
                "leash": leash_ok.iter().map(quantiles_json).collect::<Vec<_>>(),
                "voids": voids,
            }));
        }

        let out = serde_json::json!({
            "kind": "micro",
            "reps": REPS,
            "classes": records,
        });
        let path = write_results("micro", &out);
        println!(
            "\nnote: all numbers are ns and come from this box only; a result without\n\
                  its box, kernel, cpu, and commit is meaningless (measurements/0001 section 3)."
        );
        println!("results: {}", path.display());
    }

    enum LeashRep {
        Ok(Quantiles),
        Void(String),
    }

    fn one_rep_bare(bench: &Path, class: &str, n: usize) -> Option<Quantiles> {
        let ws = tempdir();
        let results = ws.path().join("results.json");
        let mut cmd = Command::new(bench);
        cmd.args([
            "--child",
            class,
            &n.to_string(),
            results.to_str().unwrap(),
            ws.path().to_str().unwrap(),
        ])
        .current_dir(ws.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
        let outcome = run_deadline(cmd, MICRO_DEADLINE);
        if outcome.timed_out {
            println!("  bare rep for {class} timed out and was killed");
            return None;
        }
        read_quantiles(&results)
    }

    fn one_rep_leash(bench: &Path, leash: &Path, class: &str, n: usize) -> LeashRep {
        let ws = tempdir();
        let state = tempdir();
        let results = ws.path().join("results.json");
        let mut cmd = Command::new(leash);
        cmd.args([
            "run",
            "--unattended",
            "--state-dir",
            state.path().to_str().unwrap(),
            "--",
            bench.to_str().unwrap(),
            "--child",
            class,
            &n.to_string(),
            results.to_str().unwrap(),
            ws.path().to_str().unwrap(),
        ])
        .current_dir(ws.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
        let outcome = run_deadline(cmd, MICRO_DEADLINE);
        if outcome.timed_out {
            return LeashRep::Void(format!(
                "leash timed out and was killed; stderr: {}",
                outcome.stderr
            ));
        }
        if outcome.status != Some(0) {
            return LeashRep::Void(format!(
                "leash exited {:?}; stderr: {}",
                outcome.status, outcome.stderr
            ));
        }
        let Some(q) = read_quantiles(&results) else {
            return LeashRep::Void("the child wrote no results file".to_string());
        };

        // trap-completeness gate: every iteration must appear in the trace, or the rep is
        // void. count this class's own syscall events by path/binary and compare to the
        // expected total (section 2.1).
        let Some(trace_path) = find_trace(state.path()) else {
            return LeashRep::Void(
                "no run directory / trace.jsonl under the state dir".to_string(),
            );
        };
        let trace = std::fs::read_to_string(&trace_path).unwrap_or_default();
        let counted = count_class_events(&trace, class);
        let expected = expected_events(class, n);
        if counted != expected {
            return LeashRep::Void(format!(
                "trap incomplete: {counted} {class} events in the trace, expected {expected}"
            ));
        }
        LeashRep::Ok(q)
    }

    // events per iteration: the mutate loop issues two renames, the rest one call each.
    fn expected_events(class: &str, n: usize) -> usize {
        if class == "mutate" { 2 * n } else { n }
    }

    fn count_class_events(trace: &str, class: &str) -> usize {
        trace
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line.trim()).ok())
            .filter(|ev| ev.get("type").and_then(serde_json::Value::as_str) == Some("syscall"))
            .filter(|ev| event_matches_class(ev, class))
            .count()
    }

    fn event_matches_class(ev: &serde_json::Value, class: &str) -> bool {
        let syscall = ev
            .get("syscall")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let fact = match ev.get("fact") {
            Some(f) => f,
            None => return false,
        };
        let path = fact
            .get("path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let dest = fact
            .get("dest")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let access = fact.get("access").and_then(serde_json::Value::as_array);
        let has = |kind: &str| access.is_some_and(|a| a.iter().any(|v| v.as_str() == Some(kind)));
        let is_open = matches!(syscall, "open" | "openat" | "openat2" | "creat");
        match class {
            "open_read" => is_open && path.ends_with(READ_FILE) && has("read"),
            "open_write" => is_open && path.ends_with(WRITE_FILE) && has("write"),
            "mutate" => {
                matches!(syscall, "rename" | "renameat" | "renameat2")
                    && (path.ends_with(MUTATE_A)
                        || path.ends_with(MUTATE_B)
                        || dest.ends_with(MUTATE_A)
                        || dest.ends_with(MUTATE_B))
            }
            "exec" => {
                matches!(syscall, "execve" | "execveat")
                    && fact
                        .get("binary")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|b| b.ends_with(EXEC_BIN))
            }
            _ => false,
        }
    }

    // ---------------------------------------------------------------------------
    // macro mode: end-to-end wall clock, leash on vs off, 5 alternating reps.
    // ---------------------------------------------------------------------------

    fn run_macro(script: Option<&str>) {
        let Some(script) = script else {
            eprintln!("macro: needs a path to the workload script (benches/workloads/macro.sh)");
            std::process::exit(2);
        };
        let script = match std::fs::canonicalize(script) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("macro: cannot resolve script {script}: {e}");
                std::process::exit(2);
            }
        };
        let leash = leash_exe();
        println!("leash overhead macro (measurements/0001 section 2.2)");
        println!("script: {}", script.display());

        let mut bare = Vec::new();
        let mut on = Vec::new();
        for rep in 0..MACRO_REPS {
            if let Some(d) = macro_rep(&script, None) {
                bare.push(d);
            } else {
                println!("  macro bare rep {rep} timed out and was killed");
            }
            if let Some(d) = macro_rep(&script, Some(&leash)) {
                on.push(d);
            } else {
                println!("  macro leash rep {rep} timed out and was killed");
            }
        }

        report_wall("bare", &bare);
        report_wall("leash", &on);
        let out = serde_json::json!({
            "kind": "macro",
            "reps": MACRO_REPS,
            "bare_ms": bare.iter().map(|d| d.as_millis() as u64).collect::<Vec<_>>(),
            "leash_ms": on.iter().map(|d| d.as_millis() as u64).collect::<Vec<_>>(),
        });
        let path = write_results("macro", &out);
        println!("results: {}", path.display());
    }

    // one macro rep in a fresh workspace; returns the wall-clock duration, or None if the
    // run was killed on the deadline.
    fn macro_rep(script: &Path, leash: Option<&Path>) -> Option<Duration> {
        let ws = tempdir();
        let workdir = ws.path().join("work");
        std::fs::create_dir_all(&workdir).unwrap();
        let mut cmd = match leash {
            Some(leash) => {
                let state = tempdir();
                let state_path = state.path().to_path_buf();
                // keep the state dir alive for the whole run by leaking the handle: a
                // bench process is short-lived and this avoids a drop-order dance.
                std::mem::forget(state);
                let mut c = Command::new(leash);
                c.args([
                    "run",
                    "--unattended",
                    "--state-dir",
                    state_path.to_str().unwrap(),
                    "--",
                    "sh",
                    script.to_str().unwrap(),
                    workdir.to_str().unwrap(),
                ]);
                c
            }
            None => {
                let mut c = Command::new("sh");
                c.arg(script).arg(&workdir);
                c
            }
        };
        cmd.current_dir(ws.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let start = Instant::now();
        let outcome = run_deadline(cmd, MACRO_DEADLINE);
        let elapsed = start.elapsed();
        if outcome.timed_out {
            return None;
        }
        if outcome.status != Some(0) {
            println!(
                "  macro rep exited {:?}; stderr: {}",
                outcome.status, outcome.stderr
            );
        }
        Some(elapsed)
    }

    fn report_wall(label: &str, times: &[Duration]) {
        if times.is_empty() {
            println!("{label}: no successful reps");
            return;
        }
        let mut ms: Vec<u64> = times.iter().map(|d| d.as_millis() as u64).collect();
        ms.sort_unstable();
        let median = ms[ms.len() / 2];
        let spread = ms[ms.len() - 1] - ms[0];
        println!(
            "{label}: median {median} ms, spread {spread} ms (min {} .. max {}), n={}",
            ms[0],
            ms[ms.len() - 1],
            ms.len()
        );
    }

    // ---------------------------------------------------------------------------
    // gaps mode: mine the inter-mutating-event gap distribution (FR-17).
    // ---------------------------------------------------------------------------

    fn run_gaps(trace_path: Option<&str>) {
        let Some(trace_path) = trace_path else {
            eprintln!("gaps: needs a path to a trace.jsonl");
            std::process::exit(2);
        };
        let trace = match std::fs::read_to_string(trace_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("gaps: cannot read {trace_path}: {e}");
                std::process::exit(2);
            }
        };
        let report = gap_report(&trace);
        println!("gap analysis of {trace_path} (measurements/0001 section 2.3)");
        println!(
            "mutating events: {}, gaps: {}",
            report.event_count, report.gap_count
        );
        match report.quantiles {
            Some(q) => println!(
                "gap ms  min {} p50 {} p90 {} p99 {} max {}",
                q.min, q.p50, q.p90, q.p99, q.max
            ),
            None => println!("gap ms  (fewer than two mutating events; no gaps)"),
        }
        println!("histogram (inclusive upper bound in ms -> count):");
        for bucket in &report.histogram {
            let label = bucket
                .upper_ms_inclusive
                .map_or_else(|| "> last".to_string(), |ms| format!("<= {ms}"));
            if bucket.count > 0 {
                println!("  {label:>8}  {}", bucket.count);
            }
        }
        let out = serde_json::to_value(&report).unwrap();
        let path = write_results("gaps", &out);
        println!("results: {}", path.display());
    }

    // ---------------------------------------------------------------------------
    // shared helpers
    // ---------------------------------------------------------------------------

    struct Outcome {
        status: Option<i32>,
        stderr: String,
        timed_out: bool,
    }

    // spawn and wait with a deadline; SIGKILL the process if it outlives the budget so a
    // wedged leash child cannot hang the bench forever (adapted from tests/cli_linux.rs).
    fn run_deadline(mut cmd: Command, deadline: Duration) -> Outcome {
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return Outcome {
                    status: None,
                    stderr: format!("spawn failed: {e}"),
                    timed_out: false,
                };
            }
        };
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let out = child.wait_with_output();
                    let stderr = out
                        .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
                        .unwrap_or_default();
                    return Outcome {
                        status: status.code(),
                        stderr,
                        timed_out: false,
                    };
                }
                Ok(None) if start.elapsed() > deadline => {
                    let _ = child.kill();
                    let out = child.wait_with_output();
                    let stderr = out
                        .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
                        .unwrap_or_default();
                    return Outcome {
                        status: None,
                        stderr,
                        timed_out: true,
                    };
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(25)),
                Err(e) => {
                    return Outcome {
                        status: None,
                        stderr: format!("wait failed: {e}"),
                        timed_out: false,
                    };
                }
            }
        }
    }

    fn read_quantiles(results: &Path) -> Option<Quantiles> {
        let text = std::fs::read_to_string(results).ok()?;
        let v: serde_json::Value = serde_json::from_str(&text).ok()?;
        Some(Quantiles {
            count: v.get("measured")?.as_u64()? as usize,
            min: v.get("min")?.as_u64()?,
            p50: v.get("p50")?.as_u64()?,
            p90: v.get("p90")?.as_u64()?,
            p99: v.get("p99")?.as_u64()?,
            max: v.get("max")?.as_u64()?,
        })
    }

    fn quantiles_json(q: &Quantiles) -> serde_json::Value {
        serde_json::json!({
            "count": q.count,
            "min": q.min,
            "p50": q.p50,
            "p90": q.p90,
            "p99": q.p99,
            "max": q.max,
        })
    }

    fn median_of(reps: &[Quantiles], f: impl Fn(&Quantiles) -> u64) -> Option<u64> {
        if reps.is_empty() {
            return None;
        }
        let mut v: Vec<u64> = reps.iter().map(f).collect();
        v.sort_unstable();
        Some(v[v.len() / 2])
    }

    // the single run directory's trace.jsonl under <state>/runs/<run-id>/ (trace.md
    // section 1). the driver gives each leash rep a fresh state dir, so there is one.
    fn find_trace(state: &Path) -> Option<PathBuf> {
        let mut entries = std::fs::read_dir(state.join("runs")).ok()?;
        let run = entries.next()?.ok()?.path();
        let trace = run.join("trace.jsonl");
        trace.is_file().then_some(trace)
    }

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn self_exe() -> PathBuf {
        std::env::current_exe().expect("current_exe")
    }

    // locate the compiled leash binary. cargo sets CARGO_BIN_EXE_leash for bench targets,
    // which is the reliable path; if it is somehow absent, fall back to a sibling of the
    // bench binary (the bench lives in target/<profile>/deps, leash in target/<profile>).
    fn leash_exe() -> PathBuf {
        if let Some(p) = option_env!("CARGO_BIN_EXE_leash") {
            return PathBuf::from(p);
        }
        let bench = self_exe();
        for ancestor in bench.ancestors().skip(1).take(4) {
            let candidate = ancestor.join("leash");
            if candidate.is_file() {
                return candidate;
            }
        }
        eprintln!(
            "cannot locate the leash binary (no CARGO_BIN_EXE_leash, no sibling of {}); \
             run via `cargo bench --bench overhead`",
            bench.display()
        );
        std::process::exit(2);
    }

    fn write_results(kind: &str, value: &serde_json::Value) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("leash-overhead-{kind}-{stamp}.json"));
        let bytes = serde_json::to_vec_pretty(value).unwrap();
        if let Err(e) = std::fs::write(&path, bytes) {
            eprintln!("cannot write results {}: {e}", path.display());
        }
        path
    }
}
