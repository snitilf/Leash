//! the trace writer and session report (docs/design/trace.md).
//!
//! assumptions: this module is the single writer of the trace (I2, ADR-0002); no other
//! module holds the file. events are append-only in decision order; a write failure is
//! surfaced to the caller so the pending action denies and the run aborts (case E), never
//! swallowed. the child cannot reach the state directory in enforce mode; in record-only
//! that protection is filesystem permissions and is a named residual, not a claim.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;

// the human-readable session report, derived from the trace (trace.md section 6).
pub mod report;

/// the trace schema version, stamped into `run_start` and `meta.json` so a reader can
/// decode without guessing (trace.md section 2). renames bump this.
pub const TRACE_SCHEMA_VERSION: u32 = 1;

/// errors from the recorder. every one of these is fatal to the pending action:
/// the caller denies and aborts rather than continue unrecorded (I3, case E).
#[derive(Debug, thiserror::Error)]
pub enum RecorderError {
    /// the clock reports a time before the unix epoch; nothing sane can be stamped
    #[error("system clock is before the unix epoch")]
    ClockBeforeEpoch,
    /// the os random source failed; run-ids would collide silently without it
    #[error("os random source failed: {0}")]
    Random(String),
    /// an event failed to serialize; the action it describes must not proceed
    #[error("event serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    /// the trace could not be written; the action it describes must not proceed
    #[error("trace write failed: {0}")]
    Write(#[source] io::Error),
    /// the per-run directory could not be established; the run does not start
    #[error("run directory setup failed: {0}")]
    Setup(#[source] io::Error),
}

/// the run mode (ADR-0010), stamped into the trace and named in the report (FR-19).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// camera: everything allowed and recorded, would-denies flagged
    RecordOnly,
    /// bouncer: deny-by-default per the policy
    Enforce,
}

/// whether an operator is present to answer asks (FR-20); stamped into the trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Attendance {
    /// a controlling terminal is present; asks prompt
    Attended,
    /// no terminal or explicitly requested; asks deny immediately
    Unattended,
}

/// the snapshot mechanism preflight selected (ADR-0009), stamped with its reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotMechanism {
    /// overlayfs write layer
    Overlay,
    /// plain per-step copy fallback
    Copy,
}

/// run-start facts, written to `meta.json` and repeated in the `run_start` event so the
/// stream is self-contained (trace.md sections 1-2).
#[derive(Debug, Clone, Serialize)]
pub struct RunMeta {
    /// trace schema version (TRACE_SCHEMA_VERSION)
    pub schema_version: u32,
    /// record_only or enforce
    pub mode: Mode,
    /// attended or unattended
    pub attendance: Attendance,
    /// digest of the loaded policy file, absent in a policy-less record-only run
    pub policy_digest: Option<String>,
    /// kernel release string from preflight
    pub kernel: String,
    /// probed landlock abi, absent in record-only (no ruleset applied)
    pub landlock_abi: Option<u32>,
    /// mechanism preflight selected
    pub snapshot_mechanism: SnapshotMechanism,
    /// why preflight selected it (e.g. host restricts unprivileged userns)
    pub snapshot_reason: String,
    /// the supervised command line
    pub argv: Vec<String>,
    /// workspace root
    pub workspace: PathBuf,
    /// run start, unix epoch milliseconds utc
    pub start_ts: u64,
}

/// one trace event: the shared envelope plus a type-specific body (trace.md section 2).
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    /// monotonic sequence number; the authoritative order (decision order, ADR-0011)
    pub seq: u64,
    /// supervisor wall clock at the moment of decision, unix epoch milliseconds utc
    pub ts: u64,
    /// the type-specific body, flattened with its `type` tag
    #[serde(flatten)]
    pub body: EventBody,
}

/// the type-specific part of an event.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventBody {
    /// run-start facts, same as meta.json
    RunStart(RunMeta),
    /// one mediated syscall and its decision
    Syscall(SyscallEvent),
    /// a step boundary (FR-17)
    Step {
        /// the step index this boundary closes
        step: u64,
    },
    /// end of run
    RunEnd {
        /// child tree exit code, if it exited
        exit_code: Option<i32>,
        /// terminating signal, if killed
        signal: Option<i32>,
        /// index of the final step
        final_step: u64,
    },
}

/// a mediated syscall event (trace.md section 2).
#[derive(Debug, Clone, Serialize)]
pub struct SyscallEvent {
    /// the child pid that trapped
    pub pid: u32,
    /// syscall name
    pub syscall: String,
    /// the kernel-trusted typed fact the decision was made on (I4)
    pub fact: Fact,
    /// the decision
    pub decision: Decision,
    /// how an ask resolved; present exactly when decision is ask
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ask_resolution: Option<AskResolution>,
    /// id of the policy rule that decided, or the base rule
    pub matched_rule: String,
    /// present in record-only when a present policy would have denied (ADR-0010)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub would_deny: Option<bool>,
}

/// the typed fact a decision was made on: resolved path, host and port, or binary,
/// plus access mode (trace.md section 2).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "family", rename_all = "snake_case")]
pub enum Fact {
    /// a filesystem decision
    Fs {
        /// the resolved path the decision used
        path: PathBuf,
        /// requested access, e.g. read, write, create, delete
        access: Vec<FsAccess>,
        /// the second path of a two-path operation (rename, link, symlink); absent otherwise
        #[serde(skip_serializing_if = "Option::is_none")]
        dest: Option<PathBuf>,
    },
    /// a network decision
    Net {
        /// destination host as decided (address, or name for a hostname rule)
        host: String,
        /// destination port
        port: u16,
    },
    /// an execution decision
    Exec {
        /// the resolved binary path
        binary: PathBuf,
    },
    /// a decision made without a trusted typed fact: the denied-and-recorded set
    /// (syscalls.md section 5) and a case-c deny where the pointer argument could not be
    /// read within its cap. the envelope's syscall field names the call.
    Raw {},
}

/// filesystem access kinds, matching the policy vocabulary (policy.md section 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FsAccess {
    /// open for reading
    Read,
    /// open for writing, or a metadata write
    Write,
    /// create a new entry
    Create,
    /// remove an entry
    Delete,
}

/// a decision over a mediated syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// the action proceeds
    Allow,
    /// the action is refused
    Deny,
    /// the operator was asked; see ask_resolution
    Ask,
}

/// how an ask resolved (FR-10, FR-20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AskResolution {
    /// operator approved
    Approved,
    /// operator denied
    Denied,
    /// the timeout fired; timeout-to-deny
    TimedOut,
}

/// where trace bytes go. `File` is the real sink; tests substitute one that records.
pub trait TraceSink: Write {
    /// force written bytes to durable storage (fsync for a file)
    fn sync(&mut self) -> io::Result<()>;
}

impl TraceSink for File {
    fn sync(&mut self) -> io::Result<()> {
        self.sync_data()
    }
}

/// the single writer of `trace.jsonl` (I2). append-only, decision order, one json object
/// per line. a write failure is returned, never swallowed: the caller denies the pending
/// action and aborts the run (notify-loop.md case E).
pub struct TraceWriter<S: TraceSink> {
    sink: S,
    next_seq: u64,
}

impl<S: TraceSink> TraceWriter<S> {
    /// wrap a sink; the first event gets seq 0.
    pub fn new(sink: S) -> Self {
        Self { sink, next_seq: 0 }
    }

    /// append one event, assigning the next sequence number. returns the seq on success.
    /// on any error the event did not land and the writer must not be used again.
    pub fn append(&mut self, ts: u64, body: EventBody) -> Result<u64, RecorderError> {
        let seq = self.next_seq;
        let mut line = serde_json::to_vec(&Event { seq, ts, body })?;
        line.push(b'\n');
        self.sink.write_all(&line).map_err(RecorderError::Write)?;
        self.next_seq = seq + 1;
        Ok(seq)
    }

    /// flush and fsync; called at step boundaries and run end (trace.md section 4).
    pub fn sync(&mut self) -> Result<(), RecorderError> {
        self.sink.flush().map_err(RecorderError::Write)?;
        self.sink.sync().map_err(RecorderError::Write)
    }

    /// give the sink back (used by tests to inspect what was written).
    pub fn into_inner(self) -> S {
        self.sink
    }
}

/// a per-run directory under the state root (trace.md section 1, FR-21).
pub struct RunDir {
    /// the run id (directory name)
    pub id: String,
    /// absolute path of the run directory
    pub path: PathBuf,
}

impl RunDir {
    /// create `<state_root>/runs/<run-id>/` with its `snapshots/` subdirectory and write
    /// `meta.json`. refuses to reuse an existing directory (run-ids are unique).
    pub fn create(
        state_root: &Path,
        meta: &RunMeta,
        now: SystemTime,
    ) -> Result<RunDir, RecorderError> {
        let id = generate_run_id(now)?;
        let runs = state_root.join("runs");
        std::fs::create_dir_all(&runs).map_err(RecorderError::Setup)?;

        let path = runs.join(&id);
        // create_dir (not create_dir_all) so an existing directory is an error:
        // run-ids are unique and a reused directory would mix two runs' evidence
        std::fs::create_dir(&path).map_err(RecorderError::Setup)?;
        std::fs::create_dir(path.join("snapshots")).map_err(RecorderError::Setup)?;

        let bytes = serde_json::to_vec_pretty(meta)?;
        let mut file = File::create_new(path.join("meta.json")).map_err(RecorderError::Setup)?;
        file.write_all(&bytes).map_err(RecorderError::Setup)?;
        file.sync_data().map_err(RecorderError::Setup)?;

        Ok(RunDir { id, path })
    }

    /// open `trace.jsonl` for appending; fails if it already exists (single writer, I2).
    pub fn trace_writer(&self) -> Result<TraceWriter<File>, RecorderError> {
        let file = File::create_new(self.path.join("trace.jsonl")).map_err(RecorderError::Setup)?;
        Ok(TraceWriter::new(file))
    }
}

/// resolve the default state root per xdg (FR-21): `$XDG_STATE_HOME/leash`, else
/// `$HOME/.local/state/leash`. pure so it is testable; the cli passes real env values.
pub fn default_state_root(xdg_state_home: Option<&str>, home: Option<&str>) -> Option<PathBuf> {
    match (xdg_state_home, home) {
        (Some(xdg), _) if !xdg.is_empty() => Some(Path::new(xdg).join("leash")),
        (_, Some(home)) if !home.is_empty() => Some(Path::new(home).join(".local/state/leash")),
        _ => None,
    }
}

/// generate a run id per trace.md section 1: a compact utc timestamp, a hyphen, and six
/// random base32 characters, e.g. `20260708T183005Z-7k3m9q`. sorts by start time in a
/// directory listing, unique without coordination, one safe path component.
pub fn generate_run_id(now: SystemTime) -> Result<String, RecorderError> {
    let secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| RecorderError::ClockBeforeEpoch)?
        .as_secs();

    let mut raw = [0u8; 4];
    getrandom::fill(&mut raw).map_err(|e| RecorderError::Random(e.to_string()))?;
    // rfc 4648 base32 alphabet, lowercased; 6 chars consume 30 of the 32 random bits
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let bits = u32::from_le_bytes(raw);
    let suffix: String = (0..6)
        .map(|i| ALPHABET[((bits >> (5 * i)) & 0x1f) as usize] as char)
        .collect();

    Ok(format!("{}-{}", format_utc_compact(secs), suffix))
}

/// format an epoch-seconds value as `YYYYMMDDTHHMMSSZ`, always utc.
fn format_utc_compact(epoch_secs: u64) -> String {
    let days = epoch_secs / 86_400;
    let rem = epoch_secs % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// gregorian date from days since 1970-01-01 (howard hinnant's civil_from_days).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // year of era [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // month index, march-based [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(epoch_secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(epoch_secs)
    }

    // golden values computed independently (python datetime, utc)
    #[test]
    fn run_id_timestamp_matches_known_utc_dates() {
        for (secs, stamp) in [
            (0, "19700101T000000Z"),
            (946_684_799, "19991231T235959Z"),
            (951_827_696, "20000229T123456Z"),
            (1_783_535_405, "20260708T183005Z"),
            (4_102_444_800, "21000101T000000Z"),
        ] {
            let id = generate_run_id(at(secs)).unwrap();
            assert_eq!(&id[..16], stamp, "timestamp part for epoch {secs}");
        }
    }

    #[test]
    fn run_id_has_documented_shape() {
        let id = generate_run_id(at(1_783_535_405)).unwrap();
        // 16-char stamp, hyphen, 6 chars of lowercase base32
        assert_eq!(id.len(), 23);
        assert_eq!(id.as_bytes()[16], b'-');
        let suffix = &id[17..];
        assert!(
            suffix.chars().all(|c| matches!(c, 'a'..='z' | '2'..='7')),
            "suffix {suffix:?} not lowercase base32"
        );
    }

    #[test]
    fn run_ids_sort_by_start_time() {
        let earlier = generate_run_id(at(1_783_535_405)).unwrap();
        let later = generate_run_id(at(1_783_535_406)).unwrap();
        assert!(earlier < later);
    }

    #[test]
    fn run_ids_are_unique_at_the_same_instant() {
        let a = generate_run_id(at(1_783_535_405)).unwrap();
        let b = generate_run_id(at(1_783_535_405)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn run_id_is_a_single_safe_path_component() {
        let id = generate_run_id(at(1_783_535_405)).unwrap();
        assert!(!id.contains(['/', '\\', '\0', '.']));
    }

    // --- event schema: golden shapes from trace.md section 2 ---

    use serde_json::{Value, json};

    fn sample_meta() -> RunMeta {
        RunMeta {
            schema_version: TRACE_SCHEMA_VERSION,
            mode: Mode::RecordOnly,
            attendance: Attendance::Attended,
            policy_digest: None,
            kernel: "6.8.0-124-generic".into(),
            landlock_abi: None,
            snapshot_mechanism: SnapshotMechanism::Overlay,
            snapshot_reason: "privileged overlay mount available".into(),
            argv: vec!["claude".into(), "--dangerously-skip-permissions".into()],
            workspace: "/home/op/project".into(),
            start_ts: 1_783_535_405_000,
        }
    }

    fn as_value(event: &Event) -> Value {
        serde_json::to_value(event).unwrap()
    }

    #[test]
    fn syscall_event_serializes_to_documented_shape() {
        let event = Event {
            seq: 3,
            ts: 1_783_535_405_123,
            body: EventBody::Syscall(SyscallEvent {
                pid: 4242,
                syscall: "openat".into(),
                fact: Fact::Fs {
                    path: "/home/op/project/src/main.rs".into(),
                    access: vec![FsAccess::Read],
                    dest: None,
                },
                decision: Decision::Allow,
                ask_resolution: None,
                matched_rule: "base:workspace".into(),
                would_deny: None,
            }),
        };
        assert_eq!(
            as_value(&event),
            json!({
                "seq": 3,
                "ts": 1_783_535_405_123u64,
                "type": "syscall",
                "pid": 4242,
                "syscall": "openat",
                "fact": {
                    "family": "fs",
                    "path": "/home/op/project/src/main.rs",
                    "access": ["read"]
                },
                "decision": "allow",
                "matched_rule": "base:workspace"
            })
        );
    }

    #[test]
    fn two_path_fact_carries_dest_and_single_path_omits_it() {
        let event = Event {
            seq: 4,
            ts: 1_783_535_405_200,
            body: EventBody::Syscall(SyscallEvent {
                pid: 4242,
                syscall: "rename".into(),
                fact: Fact::Fs {
                    path: "/home/op/project/a.txt".into(),
                    access: vec![FsAccess::Write],
                    dest: Some("/home/op/project/b.txt".into()),
                },
                decision: Decision::Allow,
                ask_resolution: None,
                matched_rule: "base:record_only".into(),
                would_deny: None,
            }),
        };
        assert_eq!(
            as_value(&event)["fact"],
            json!({
                "family": "fs",
                "path": "/home/op/project/a.txt",
                "access": ["write"],
                "dest": "/home/op/project/b.txt"
            })
        );
    }

    #[test]
    fn raw_fact_serializes_to_family_only() {
        let event = Event {
            seq: 5,
            ts: 1_783_535_405_300,
            body: EventBody::Syscall(SyscallEvent {
                pid: 4242,
                syscall: "io_uring_setup".into(),
                fact: Fact::Raw {},
                decision: Decision::Deny,
                ask_resolution: None,
                matched_rule: "sr4:io_uring".into(),
                would_deny: None,
            }),
        };
        assert_eq!(as_value(&event)["fact"], json!({ "family": "raw" }));
        assert_eq!(as_value(&event)["decision"], "deny");
        assert_eq!(as_value(&event)["syscall"], "io_uring_setup");
    }

    #[test]
    fn ask_and_would_deny_fields_appear_only_when_present() {
        let event = Event {
            seq: 9,
            ts: 1_783_535_406_000,
            body: EventBody::Syscall(SyscallEvent {
                pid: 4242,
                syscall: "connect".into(),
                fact: Fact::Net {
                    host: "203.0.113.7".into(),
                    port: 443,
                },
                decision: Decision::Ask,
                ask_resolution: Some(AskResolution::TimedOut),
                matched_rule: "net.2".into(),
                would_deny: Some(true),
            }),
        };
        assert_eq!(
            as_value(&event),
            json!({
                "seq": 9,
                "ts": 1_783_535_406_000u64,
                "type": "syscall",
                "pid": 4242,
                "syscall": "connect",
                "fact": { "family": "net", "host": "203.0.113.7", "port": 443 },
                "decision": "ask",
                "ask_resolution": "timed_out",
                "matched_rule": "net.2",
                "would_deny": true
            })
        );
    }

    #[test]
    fn lifecycle_events_serialize_to_documented_shapes() {
        let start = Event {
            seq: 0,
            ts: 1_783_535_405_000,
            body: EventBody::RunStart(sample_meta()),
        };
        let started = as_value(&start);
        assert_eq!(started["type"], "run_start");
        assert_eq!(started["schema_version"], 1);
        assert_eq!(started["mode"], "record_only");
        assert_eq!(started["attendance"], "attended");
        assert_eq!(started["snapshot_mechanism"], "overlay");

        let step = Event {
            seq: 7,
            ts: 1_783_535_405_500,
            body: EventBody::Step { step: 2 },
        };
        assert_eq!(
            as_value(&step),
            json!({ "seq": 7, "ts": 1_783_535_405_500u64, "type": "step", "step": 2 })
        );

        let end = Event {
            seq: 11,
            ts: 1_783_535_407_000,
            body: EventBody::RunEnd {
                exit_code: Some(0),
                signal: None,
                final_step: 3,
            },
        };
        let ended = as_value(&end);
        assert_eq!(ended["type"], "run_end");
        assert_eq!(ended["exit_code"], 0);
        assert_eq!(ended["final_step"], 3);
    }

    // --- trace writer: order, failure surfacing, sync ---

    /// a sink that records what happens to it, and can be told to fail
    #[derive(Default)]
    struct FakeSink {
        bytes: Vec<u8>,
        syncs_at: Vec<usize>, // byte length at each sync call
        fail_writes: bool,
    }

    impl Write for FakeSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.fail_writes {
                return Err(io::Error::other("disk gone"));
            }
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl TraceSink for FakeSink {
        fn sync(&mut self) -> io::Result<()> {
            if self.fail_writes {
                return Err(io::Error::other("disk gone"));
            }
            self.syncs_at.push(self.bytes.len());
            Ok(())
        }
    }

    fn step_body(step: u64) -> EventBody {
        EventBody::Step { step }
    }

    #[test]
    fn writer_appends_one_json_line_per_event_in_seq_order() {
        let mut writer = TraceWriter::new(FakeSink::default());
        assert_eq!(writer.append(1_000, step_body(0)).unwrap(), 0);
        assert_eq!(writer.append(2_000, step_body(1)).unwrap(), 1);

        let sink = writer.into_inner();
        let text = String::from_utf8(sink.bytes).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(
            text.ends_with('\n'),
            "every event line is newline-terminated"
        );
        for (i, line) in lines.iter().enumerate() {
            let v: Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["seq"], i as u64, "seq is monotonic from 0");
        }
    }

    #[test]
    fn writer_surfaces_a_failed_write_as_an_error() {
        let mut writer = TraceWriter::new(FakeSink {
            fail_writes: true,
            ..FakeSink::default()
        });
        let err = writer.append(1_000, step_body(0));
        assert!(
            matches!(err, Err(RecorderError::Write(_))),
            "a failed trace write must surface, never be swallowed (case E)"
        );
    }

    #[test]
    fn sync_flushes_written_events_to_the_sink() {
        let mut writer = TraceWriter::new(FakeSink::default());
        writer.append(1_000, step_body(0)).unwrap();
        writer.sync().unwrap();
        let sink = writer.into_inner();
        assert_eq!(sink.syncs_at.len(), 1);
        assert_eq!(
            sink.syncs_at[0],
            sink.bytes.len(),
            "sync happens after the step event's bytes reached the sink"
        );
    }

    // --- run directory ---

    use std::fs;

    #[test]
    fn run_dir_creates_documented_layout_and_meta() {
        let root = tempfile::tempdir().unwrap();
        let dir = RunDir::create(root.path(), &sample_meta(), at(1_783_535_405)).unwrap();

        assert!(dir.path.starts_with(root.path().join("runs")));
        assert_eq!(dir.path.file_name().unwrap().to_str().unwrap(), dir.id);
        assert!(dir.path.join("snapshots").is_dir());

        let meta: Value =
            serde_json::from_str(&fs::read_to_string(dir.path.join("meta.json")).unwrap()).unwrap();
        assert_eq!(meta["schema_version"], 1);
        assert_eq!(meta["mode"], "record_only");
        assert_eq!(meta["workspace"], "/home/op/project");
    }

    #[test]
    fn run_dir_trace_writer_writes_into_the_run_directory() {
        let root = tempfile::tempdir().unwrap();
        let dir = RunDir::create(root.path(), &sample_meta(), at(1_783_535_405)).unwrap();
        let mut writer = dir.trace_writer().unwrap();
        writer.append(1_000, step_body(0)).unwrap();
        writer.sync().unwrap();

        let text = fs::read_to_string(dir.path.join("trace.jsonl")).unwrap();
        let v: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(v["type"], "step");
    }

    #[test]
    fn run_dir_refuses_a_second_trace_writer() {
        let root = tempfile::tempdir().unwrap();
        let dir = RunDir::create(root.path(), &sample_meta(), at(1_783_535_405)).unwrap();
        let _first = dir.trace_writer().unwrap();
        assert!(
            dir.trace_writer().is_err(),
            "the trace has exactly one writer (I2)"
        );
    }

    // --- xdg state root resolution ---

    #[test]
    fn state_root_prefers_xdg_state_home_then_home() {
        assert_eq!(
            default_state_root(Some("/xdg/state"), Some("/home/op")),
            Some(PathBuf::from("/xdg/state/leash"))
        );
        assert_eq!(
            default_state_root(None, Some("/home/op")),
            Some(PathBuf::from("/home/op/.local/state/leash"))
        );
        assert_eq!(default_state_root(None, None), None);
    }
}
