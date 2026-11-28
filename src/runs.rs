//! operator-directed run listing and deletion (FR-21).
//!
//! the state root is operator supplied. run ids must be single path components and
//! pruning is unavailable until exact-target deletion is safe under concurrent changes.

use std::fs;
use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::recorder::{RunMeta, TRACE_SCHEMA_VERSION, report::render_report};

/// the largest meta.json the listing will read. a real one is well under 4 KiB.
pub const META_READ_CAP: u64 = 64 * 1024;

/// the largest trace.jsonl the listing will read, so a huge or endless file cannot
/// exhaust memory. a larger trace is listed as unreadable, never truncated silently.
pub const TRACE_READ_CAP: u64 = 256 * 1024 * 1024;

/// One run directory and the result of reading its recorded facts.
#[derive(Debug)]
pub struct RunEntry {
    /// Directory name; a name that is not valid utf-8 is kept in its escaped debug form
    /// so two such names never collapse into one id.
    pub id: String,
    /// Recorded facts, or a diagnostic for an incomplete or corrupt run.
    pub details: Result<RunDetails, String>,
}

impl RunEntry {
    /// the id as it is safe to print on a terminal: an id made only of printable ascii
    /// prints as is, anything else (control bytes, escapes, newlines) prints escaped.
    pub fn display_id(&self) -> String {
        if !self.id.is_empty() && self.id.chars().all(|c| c.is_ascii_graphic()) {
            self.id.clone()
        } else {
            format!("{:?}", self.id)
        }
    }
}

/// Facts needed to display a run.
#[derive(Debug)]
pub struct RunDetails {
    /// Run start metadata.
    pub meta: RunMeta,
    /// Exit outcome, absent when no run_end was recorded.
    pub exit: Option<RunExit>,
}

/// The child command's recorded outcome.
#[derive(Debug, PartialEq, Eq)]
pub enum RunExit {
    /// The command exited with this status.
    Code(i64),
    /// The command was terminated by this signal.
    Signal(i64),
}

/// List every directory in the runs directory, including unreadable or incomplete runs.
/// A missing runs directory is an empty listing. Entries are sorted by id.
pub fn list(state_root: &Path) -> io::Result<Vec<RunEntry>> {
    let entries = match fs::read_dir(state_root.join("runs")) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut runs = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let id = match name.to_str() {
            Some(id) => id.to_owned(),
            None => format!("{name:?}"),
        };
        // file_type does not follow symlinks, so a symlinked run directory is skipped
        let details = match entry.file_type() {
            Ok(kind) if kind.is_dir() => read_details(&entry.path()),
            Ok(_) => continue,
            Err(e) => Err(format!("cannot stat entry: {e}")),
        };
        runs.push(RunEntry { id, details });
    }
    runs.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(runs)
}

/// read one file of a run directory without trusting it: never follow a symlink, never
/// block on a fifo, accept only a regular file, and stop at `cap` bytes.
fn read_capped(path: &Path, cap: u64) -> io::Result<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    if meta.len() > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("larger than the {cap}-byte read limit"),
        ));
    }
    let mut bytes = Vec::new();
    // the file can still grow after the size check, so the read itself is capped too
    file.take(cap + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("larger than the {cap}-byte read limit"),
        ));
    }
    Ok(bytes)
}

fn read_details(path: &Path) -> Result<RunDetails, String> {
    let meta_bytes = read_capped(&path.join("meta.json"), META_READ_CAP)
        .map_err(|e| format!("meta.json: {e}"))?;
    let meta: RunMeta =
        serde_json::from_slice(&meta_bytes).map_err(|e| format!("meta.json: {e}"))?;
    if meta.schema_version != TRACE_SCHEMA_VERSION {
        return Err(format!(
            "meta.json: unsupported schema version {}",
            meta.schema_version
        ));
    }
    let trace_bytes = read_capped(&path.join("trace.jsonl"), TRACE_READ_CAP)
        .map_err(|e| format!("trace.jsonl: {e}"))?;
    let trace = String::from_utf8(trace_bytes).map_err(|e| format!("trace.jsonl: {e}"))?;
    render_report(&trace).map_err(|e| format!("trace.jsonl: {e}"))?;
    let expected_meta = serde_json::to_value(&meta).map_err(|e| format!("meta.json: {e}"))?;
    let mut exit = None;
    let mut started = false;
    let mut ended = false;
    let mut next_seq = 0u64;
    for line in BufReader::new(trace.as_bytes()).lines() {
        let line = line.map_err(|e| format!("trace.jsonl: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let event: serde_json::Value =
            serde_json::from_str(&line).map_err(|e| format!("trace.jsonl: {e}"))?;
        if event["seq"].as_u64() != Some(next_seq) || ended {
            return Err("trace.jsonl: invalid event order".into());
        }
        next_seq = next_seq
            .checked_add(1)
            .ok_or("trace.jsonl: sequence overflow")?;
        match event["type"].as_str() {
            Some("run_start") => {
                if started || next_seq != 1 {
                    return Err("trace.jsonl: misplaced run_start".into());
                }
                let object = expected_meta
                    .as_object()
                    .ok_or("meta.json: invalid metadata")?;
                if object
                    .iter()
                    .any(|(key, value)| event.get(key) != Some(value))
                {
                    return Err("trace.jsonl: run_start disagrees with meta.json".into());
                }
                started = true;
            }
            Some("run_end") => {
                ended = true;
                exit = event["exit_code"]
                    .as_i64()
                    .map(RunExit::Code)
                    .or_else(|| event["signal"].as_i64().map(RunExit::Signal));
            }
            _ => {}
        }
    }
    Ok(RunDetails { meta, exit })
}

/// Pruning is unavailable until deletion can be bound to the selected directory.
/// No run data is deleted by this function.
pub fn prune(_state_root: &Path, _ids: &[String]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "run pruning is unavailable: safe deletion under concurrent changes is not implemented",
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::recorder::{Attendance, Mode, RunDir, SnapshotMechanism, TRACE_SCHEMA_VERSION};
    use std::time::{Duration, SystemTime};

    fn make_run(root: &Path, seconds: u64) -> RunDir {
        let meta = RunMeta {
            schema_version: TRACE_SCHEMA_VERSION,
            mode: Mode::RecordOnly,
            attendance: Attendance::Unattended,
            policy_digest: None,
            kernel: "test".into(),
            landlock_abi: None,
            landlock_residuals: None,
            snapshot_mechanism: SnapshotMechanism::Copy,
            snapshot_reason: "test".into(),
            argv: vec!["echo".into(), "hello".into()],
            workspace: "/workspace".into(),
            start_ts: seconds * 1000,
            run_cgroup: None,
        };
        let dir = RunDir::create(
            root,
            &meta,
            SystemTime::UNIX_EPOCH + Duration::from_secs(seconds),
        )
        .unwrap();
        let mut start = serde_json::to_value(&meta).unwrap();
        start["seq"] = 0.into();
        start["ts"] = (seconds * 1000).into();
        start["type"] = "run_start".into();
        fs::write(dir.path.join("trace.jsonl"), format!("{start}\n{{\"seq\":1,\"ts\":1,\"type\":\"run_end\",\"exit_code\":3,\"signal\":null}}\n")).unwrap();
        dir
    }

    #[test]
    fn lists_recorded_facts_and_reports_damaged_runs() {
        let root = tempfile::tempdir().unwrap();
        let run = make_run(root.path(), 100);
        fs::create_dir(root.path().join("runs/broken")).unwrap();
        let entries = list(root.path()).unwrap();
        assert_eq!(entries.len(), 2);
        let good = entries
            .iter()
            .find(|e| e.id == run.id)
            .unwrap()
            .details
            .as_ref()
            .unwrap();
        assert_eq!(good.meta.argv, ["echo", "hello"]);
        assert_eq!(good.meta.start_ts, 100_000);
        assert_eq!(good.exit, Some(RunExit::Code(3)));
        assert!(
            entries
                .iter()
                .find(|e| e.id == "broken")
                .unwrap()
                .details
                .is_err()
        );
        fs::write(run.path.join("trace.jsonl"), "bad json\n").unwrap();
        assert!(
            list(root.path())
                .unwrap()
                .iter()
                .find(|e| e.id == run.id)
                .unwrap()
                .details
                .is_err()
        );
    }

    #[test]
    fn missing_end_is_visible_and_missing_root_is_empty() {
        let root = tempfile::tempdir().unwrap();
        assert!(list(root.path()).unwrap().is_empty());
        let run = make_run(root.path(), 100);
        let trace = fs::read_to_string(run.path.join("trace.jsonl")).unwrap();
        fs::write(
            run.path.join("trace.jsonl"),
            format!("{}\n", trace.lines().next().unwrap()),
        )
        .unwrap();
        assert_eq!(
            list(root.path()).unwrap()[0].details.as_ref().unwrap().exit,
            None
        );
    }

    #[test]
    fn metadata_mismatch_and_unsupported_schema_are_reported() {
        let root = tempfile::tempdir().unwrap();
        let run = make_run(root.path(), 100);
        let path = run.path.join("meta.json");
        let mut meta: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        meta["argv"] = serde_json::json!(["other"]);
        fs::write(&path, serde_json::to_vec(&meta).unwrap()).unwrap();
        assert!(
            list(root.path()).unwrap()[0]
                .details
                .as_ref()
                .unwrap_err()
                .contains("disagrees")
        );
        meta["schema_version"] = 999.into();
        fs::write(path, serde_json::to_vec(&meta).unwrap()).unwrap();
        assert!(
            list(root.path()).unwrap()[0]
                .details
                .as_ref()
                .unwrap_err()
                .contains("unsupported schema")
        );
    }

    fn details_err(root: &Path, id: &str) -> String {
        list(root)
            .unwrap()
            .into_iter()
            .find(|e| e.id == id)
            .unwrap()
            .details
            .unwrap_err()
    }

    #[test]
    fn hostile_run_files_are_reported_not_followed_or_blocked_on() {
        let root = tempfile::tempdir().unwrap();

        // a symlinked meta.json is refused, never followed (here at an endless device)
        let run = make_run(root.path(), 100);
        fs::remove_file(run.path.join("meta.json")).unwrap();
        std::os::unix::fs::symlink("/dev/zero", run.path.join("meta.json")).unwrap();
        assert!(details_err(root.path(), &run.id).starts_with("meta.json"));

        // a fifo in place of the trace must not block the listing
        let run = make_run(root.path(), 200);
        let trace = run.path.join("trace.jsonl");
        fs::remove_file(&trace).unwrap();
        let c_path = std::ffi::CString::new(trace.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: mkfifo reads the nul-terminated path we own.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert!(details_err(root.path(), &run.id).contains("not a regular file"));

        // an oversized meta.json is refused before it is read
        let run = make_run(root.path(), 300);
        let file = fs::File::create(run.path.join("meta.json")).unwrap();
        file.set_len(META_READ_CAP + 1).unwrap();
        assert!(details_err(root.path(), &run.id).contains("read limit"));
    }

    #[test]
    fn unprintable_ids_are_escaped_for_display() {
        let plain = RunEntry {
            id: "20261123T234345Z-rdzo2f".into(),
            details: Err(String::new()),
        };
        assert_eq!(plain.display_id(), "20261123T234345Z-rdzo2f");
        let hostile = RunEntry {
            id: "evil\u{1b}[2J\nfake".into(),
            details: Err(String::new()),
        };
        let shown = hostile.display_id();
        assert!(
            !shown.contains('\u{1b}') && !shown.contains('\n'),
            "{shown}"
        );
    }

    #[test]
    fn pruning_refuses_without_deleting_any_runs() {
        let root = tempfile::tempdir().unwrap();
        let a = make_run(root.path(), 100);
        let b = make_run(root.path(), 101);
        let error = prune(root.path(), std::slice::from_ref(&a.id)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(a.path.exists());
        assert!(b.path.exists());
    }
}
