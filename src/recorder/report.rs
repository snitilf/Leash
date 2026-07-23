//! the human-readable session report, rendered from the trace (docs/design/trace.md
//! section 6).
//!
//! assumptions: pure text in, text out. no filesystem access and no clock reads happen
//! here; the caller (`supervisor::session`) owns writing `report.txt` and fsyncing it.
//! only the supervisor ever writes a trace (I2), so a well-formed trace should carry at
//! most one `run_start` and one `run_end`, but this reader does not trust that: it keeps
//! the first of each rather than silently preferring the last, and still validates every
//! occurrence's fields so a malformed later event is not swallowed. an unrecognized
//! `type` is skipped for forward compatibility (a newer supervisor's trace should not
//! break an older report renderer). the report's section coverage matches the
//! notify-loop slice that produced the trace: `fs`, `exec`, and `net` facts are rendered
//! from whatever the trace actually carries, and network gets a named-unobserved
//! sentence when no net facts are present, never a silent "nothing happened" reading.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

/// errors from rendering a session report. a malformed or invalid trace is refused
/// rather than partially summarized, because a report must not silently drop evidence.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    /// a trace line is not syntactically valid json
    #[error("trace line {line} is not valid json: {source}")]
    Malformed {
        /// 1-based line number in the trace
        line: usize,
        /// the underlying parse error
        #[source]
        source: serde_json::Error,
    },
    /// a line parsed as json but a recognized event's shape does not match the schema
    #[error("trace line {line}: recognized event is missing or mistypes field '{field}'")]
    InvalidEvent {
        /// 1-based line number in the trace
        line: usize,
        /// the field that was missing or the wrong type
        field: &'static str,
    },
    /// the trace has no `run_start` event, so the report has nothing to name the run
    #[error("the trace has no run_start event")]
    MissingRunStart,
}

/// how a run ended, resolved once so the render step never has to reason about an
/// impossible exit_code/signal combination (both validated absent is rejected earlier).
enum ExitOutcome {
    /// the child tree exited with this status
    Code(i64),
    /// the child tree was killed by this signal
    Signal(i64),
}

/// accumulated per-path filesystem activity: the union of access modes requested and
/// the set of decisions observed at that path, across every syscall event that named it.
#[derive(Default)]
struct FileActivity {
    access: BTreeSet<String>,
    decisions: BTreeSet<String>,
}

/// render `trace.jsonl` into the session report text (docs/design/trace.md section 6).
///
/// each non-empty line is one json event. lines are processed in file order, which is
/// decision order (ADR-0011) because the supervisor is the trace's single writer. the
/// function is pure: given the same trace text it always returns the same report text.
pub fn render_report(trace_jsonl: &str) -> Result<String, ReportError> {
    let mut mode: Option<String> = None;
    let mut argv: Option<Vec<String>> = None;
    let mut workspace: Option<String> = None;
    let mut exit_outcome: Option<ExitOutcome> = None;
    let mut have_run_end = false;

    let mut files: BTreeMap<String, FileActivity> = BTreeMap::new();
    let mut processes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut process_creations: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut cross_process: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut network: BTreeMap<(String, i64), BTreeSet<String>> = BTreeMap::new();
    let mut denied_raw: BTreeSet<(String, String)> = BTreeSet::new();

    for (idx, raw_line) in trace_jsonl.lines().enumerate() {
        let line = idx + 1;
        if raw_line.trim().is_empty() {
            continue;
        }

        let value: Value = serde_json::from_str(raw_line)
            .map_err(|source| ReportError::Malformed { line, source })?;

        require_number(&value, "seq", line)?;
        require_number(&value, "ts", line)?;
        let event_type = require_str(&value, "type", line)?.to_string();

        match event_type.as_str() {
            "run_start" => {
                let parsed_mode = require_str(&value, "mode", line)?.to_string();
                if parsed_mode != "record_only" && parsed_mode != "enforce" {
                    return Err(ReportError::InvalidEvent {
                        line,
                        field: "mode",
                    });
                }
                let parsed_argv = parse_argv(&value, line)?;
                let parsed_workspace = require_str(&value, "workspace", line)?.to_string();

                if mode.is_none() {
                    mode = Some(parsed_mode);
                    argv = Some(parsed_argv);
                    workspace = Some(parsed_workspace);
                }
            }
            "syscall" => {
                let syscall = require_str(&value, "syscall", line)?.to_string();
                let decision = require_str(&value, "decision", line)?.to_string();
                let matched_rule = require_str(&value, "matched_rule", line)?.to_string();
                let fact = value.get("fact").and_then(Value::as_object).ok_or(
                    ReportError::InvalidEvent {
                        line,
                        field: "fact",
                    },
                )?;
                let family = fact.get("family").and_then(Value::as_str).ok_or(
                    ReportError::InvalidEvent {
                        line,
                        field: "family",
                    },
                )?;

                let display = display_decision(&decision);

                match family {
                    "fs" => {
                        let path = fact
                            .get("path")
                            .and_then(Value::as_str)
                            .ok_or(ReportError::InvalidEvent {
                                line,
                                field: "path",
                            })?
                            .to_string();
                        let access = parse_access(fact, line)?;
                        let entry = files.entry(path).or_default();
                        entry.access.extend(access);
                        entry.decisions.insert(display);
                    }
                    "exec" => {
                        let binary = fact
                            .get("binary")
                            .and_then(Value::as_str)
                            .ok_or(ReportError::InvalidEvent {
                                line,
                                field: "binary",
                            })?
                            .to_string();
                        processes.entry(binary).or_default().insert(display);
                    }
                    "net" => {
                        let host = fact
                            .get("host")
                            .and_then(Value::as_str)
                            .ok_or(ReportError::InvalidEvent {
                                line,
                                field: "host",
                            })?
                            .to_string();
                        let port = fact.get("port").and_then(Value::as_i64).ok_or(
                            ReportError::InvalidEvent {
                                line,
                                field: "port",
                            },
                        )?;
                        network.entry((host, port)).or_default().insert(display);
                    }
                    "process" => {
                        process_creations
                            .entry(syscall)
                            .or_default()
                            .insert(display);
                    }
                    "cross_process" => {
                        let target = fact
                            .get("target_pid")
                            .and_then(Value::as_i64)
                            .map_or_else(|| "unknown".to_string(), |pid| pid.to_string());
                        cross_process
                            .entry(format!("{syscall} target={target}"))
                            .or_default()
                            .insert(display);
                    }
                    "raw" => {
                        if decision == "deny" {
                            denied_raw.insert((syscall, matched_rule));
                        }
                    }
                    _ => {
                        return Err(ReportError::InvalidEvent {
                            line,
                            field: "family",
                        });
                    }
                }
            }
            "run_end" => {
                let code = optional_number(&value, "exit_code", line)?;
                let signal = optional_number(&value, "signal", line)?;
                let outcome = match (code, signal) {
                    (Some(n), _) => ExitOutcome::Code(n),
                    (None, Some(s)) => ExitOutcome::Signal(s),
                    (None, None) => {
                        return Err(ReportError::InvalidEvent {
                            line,
                            field: "exit_code",
                        });
                    }
                };
                if !have_run_end {
                    exit_outcome = Some(outcome);
                    have_run_end = true;
                }
            }
            "step" => {
                // step boundaries carry no report content (trace.md section 6)
            }
            _ => {
                // unrecognized types are skipped for forward compatibility
            }
        }
    }

    let mode = mode.ok_or(ReportError::MissingRunStart)?;
    let argv = argv.unwrap_or_default();
    let workspace = workspace.unwrap_or_default();

    Ok(format_report(
        &mode,
        &argv,
        &workspace,
        exit_outcome.as_ref(),
        have_run_end,
        &files,
        &processes,
        &process_creations,
        &cross_process,
        &network,
        &denied_raw,
    ))
}

/// assemble the final report text from the accumulated trace data.
#[allow(clippy::too_many_arguments)]
fn format_report(
    mode: &str,
    argv: &[String],
    workspace: &str,
    exit_outcome: Option<&ExitOutcome>,
    have_run_end: bool,
    files: &BTreeMap<String, FileActivity>,
    processes: &BTreeMap<String, BTreeSet<String>>,
    process_creations: &BTreeMap<String, BTreeSet<String>>,
    cross_process: &BTreeMap<String, BTreeSet<String>>,
    network: &BTreeMap<(String, i64), BTreeSet<String>>,
    denied_raw: &BTreeSet<(String, String)>,
) -> String {
    let mode_line = if mode == "enforce" {
        "enforce".to_string()
    } else {
        // FR-19 and SR-4: record-only enforces no policy, but the denied-and-recorded set
        // is refused in this mode too, so the line must not claim every action was allowed.
        "record-only (no policy was enforced; only un-mediated I/O paths were denied, per SR-4)"
            .to_string()
    };

    let exit_line = if !have_run_end {
        "unknown (no run_end was recorded; the supervisor failed before stamping one)".to_string()
    } else {
        match exit_outcome {
            Some(ExitOutcome::Code(n)) => format!("code {n}"),
            Some(ExitOutcome::Signal(s)) => format!("killed by signal {s}"),
            None => "unknown (no run_end was recorded; the supervisor failed before stamping one)"
                .to_string(),
        }
    };

    let mut out = String::new();
    out.push_str("leash session report\n");
    out.push_str(&format!("mode: {mode_line}\n"));
    out.push_str(&format!("command: {}\n", argv.join(" ")));
    out.push_str(&format!("workspace: {workspace}\n"));
    out.push_str(&format!("exit: {exit_line}\n"));
    out.push('\n');

    out.push_str(&format!("files touched ({}):\n", files.len()));
    if files.is_empty() {
        out.push_str("  none recorded\n");
    } else {
        for (path, activity) in files {
            let access = activity
                .access
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            let decisions = activity
                .decisions
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("  {path}  [{access}]  {decisions}\n"));
        }
    }
    out.push('\n');

    out.push_str("processes spawned (from observed execve and execveat events):\n");
    if processes.is_empty() {
        out.push_str("  none recorded\n");
    } else {
        for (binary, decisions) in processes {
            let decisions = decisions.iter().cloned().collect::<Vec<_>>().join(", ");
            out.push_str(&format!("  {binary}  {decisions}\n"));
        }
    }
    out.push('\n');

    out.push_str("process creation:\n");
    if process_creations.is_empty() {
        out.push_str("  none recorded\n");
    } else {
        for (syscall, decisions) in process_creations {
            let decisions = decisions.iter().cloned().collect::<Vec<_>>().join(", ");
            out.push_str(&format!("  {syscall}  {decisions}\n"));
        }
    }
    out.push('\n');

    out.push_str("cross-process control:\n");
    if cross_process.is_empty() {
        out.push_str("  none recorded\n");
    } else {
        for (target, decisions) in cross_process {
            let decisions = decisions.iter().cloned().collect::<Vec<_>>().join(", ");
            out.push_str(&format!("  {target}  {decisions}\n"));
        }
    }
    out.push('\n');

    out.push_str("network connections:\n");
    if network.is_empty() {
        out.push_str("  none recorded\n");
    } else {
        for ((host, port), decisions) in network {
            let decisions = decisions.iter().cloned().collect::<Vec<_>>().join(", ");
            out.push_str(&format!("  {host}:{port}  {decisions}\n"));
        }
    }
    out.push('\n');

    out.push_str("denied without a typed fact:\n");
    if denied_raw.is_empty() {
        out.push_str("  none\n");
    } else {
        for (syscall, matched_rule) in denied_raw {
            out.push_str(&format!("  {syscall}  ({matched_rule})\n"));
        }
    }

    out
}

/// "allow" -> "allowed", "deny" -> "denied"; anything else passes through unnormalized
/// rather than inventing a display form for a decision this slice does not yet emit
/// (e.g. "ask").
fn display_decision(raw: &str) -> String {
    match raw {
        "allow" => "allowed".to_string(),
        "deny" => "denied".to_string(),
        other => other.to_string(),
    }
}

/// require a field to be present and a json string; used for every mandatory string
/// field across event bodies.
fn require_str<'a>(
    value: &'a Value,
    field: &'static str,
    line: usize,
) -> Result<&'a str, ReportError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ReportError::InvalidEvent { line, field })
}

/// require a field to be present and a json number; the envelope's `seq` and `ts`.
fn require_number(value: &Value, field: &'static str, line: usize) -> Result<(), ReportError> {
    match value.get(field) {
        Some(v) if v.is_number() => Ok(()),
        _ => Err(ReportError::InvalidEvent { line, field }),
    }
}

/// a field that is a json number, `null`, or absent; `run_end`'s exit_code and signal.
fn optional_number(
    value: &Value,
    field: &'static str,
    line: usize,
) -> Result<Option<i64>, ReportError> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_i64()
            .map(Some)
            .ok_or(ReportError::InvalidEvent { line, field }),
    }
}

/// `run_start`'s `argv`: a required json array of strings.
fn parse_argv(value: &Value, line: usize) -> Result<Vec<String>, ReportError> {
    let items = value
        .get("argv")
        .and_then(Value::as_array)
        .ok_or(ReportError::InvalidEvent {
            line,
            field: "argv",
        })?;
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or(ReportError::InvalidEvent {
                    line,
                    field: "argv",
                })
        })
        .collect()
}

/// an `fs` fact's optional `access`: a json array of strings when present, absent when not.
fn parse_access(
    fact: &serde_json::Map<String, Value>,
    line: usize,
) -> Result<Vec<String>, ReportError> {
    match fact.get("access") {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_string)
                    .ok_or(ReportError::InvalidEvent {
                        line,
                        field: "access",
                    })
            })
            .collect(),
        Some(_) => Err(ReportError::InvalidEvent {
            line,
            field: "access",
        }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn syscall_line(
        seq: u64,
        syscall: &str,
        decision: &str,
        fact: &str,
        matched_rule: &str,
    ) -> String {
        format!(
            r#"{{"seq":{seq},"ts":1000,"type":"syscall","pid":1,"syscall":"{syscall}","decision":"{decision}","fact":{fact},"matched_rule":"{matched_rule}"}}"#
        )
    }

    fn run_start_line(mode: &str, argv: &str, workspace: &str) -> String {
        format!(
            r#"{{"seq":0,"ts":100,"type":"run_start","mode":"{mode}","argv":{argv},"workspace":"{workspace}"}}"#
        )
    }

    fn run_end_line(seq: u64, exit_code: &str, signal: &str) -> String {
        format!(
            r#"{{"seq":{seq},"ts":9000,"type":"run_end","exit_code":{exit_code},"signal":{signal}}}"#
        )
    }

    #[test]
    fn report_matches_golden_text() {
        let trace = [
            run_start_line("record_only", r#"["claude","-p"]"#, "/w"),
            syscall_line(
                1,
                "openat",
                "allow",
                r#"{"family":"fs","path":"/w/src/main.rs","access":["read"]}"#,
                "base:record_only",
            ),
            syscall_line(
                2,
                "openat",
                "allow",
                r#"{"family":"fs","path":"/w/src/main.rs","access":["write"]}"#,
                "base:record_only",
            ),
            syscall_line(
                3,
                "openat",
                "allow",
                r#"{"family":"fs","path":"/w/README.md","access":["read"]}"#,
                "base:record_only",
            ),
            syscall_line(
                4,
                "execve",
                "allow",
                r#"{"family":"exec","binary":"/usr/bin/node"}"#,
                "base:record_only",
            ),
            syscall_line(
                5,
                "io_uring_setup",
                "deny",
                r#"{"family":"raw"}"#,
                "sr4:io_uring",
            ),
            run_end_line(6, "0", "null"),
        ]
        .join("\n");

        let report = render_report(&trace).unwrap();
        let golden = [
            "leash session report",
            "mode: record-only (no policy was enforced; only un-mediated I/O paths were denied, per SR-4)",
            "command: claude -p",
            "workspace: /w",
            "exit: code 0",
            "",
            "files touched (2):",
            "  /w/README.md  [read]  allowed",
            "  /w/src/main.rs  [read, write]  allowed",
            "",
            "processes spawned (from observed execve and execveat events):",
            "  /usr/bin/node  allowed",
            "",
            "process creation:",
            "  none recorded",
            "",
            "cross-process control:",
            "  none recorded",
            "",
            "network connections:",
            "  none recorded",
            "",
            "denied without a typed fact:",
            "  io_uring_setup  (sr4:io_uring)",
            "",
        ]
        .join("\n");
        assert_eq!(report, golden);
    }

    #[test]
    fn record_only_report_uses_no_enforcement_language() {
        let trace = run_start_line("record_only", "[]", "/w");
        let report = render_report(&trace).unwrap();
        assert!(report.contains("no policy was enforced"));
        assert!(!report.contains("enforce mode"));
        assert!(!report.contains("blocked"));
        assert!(!report.contains("policy denied"));
    }

    #[test]
    fn rendering_is_deterministic() {
        let trace = [
            run_start_line("record_only", r#"["claude"]"#, "/w"),
            syscall_line(
                1,
                "openat",
                "allow",
                r#"{"family":"fs","path":"/w/a.txt","access":["read"]}"#,
                "base:record_only",
            ),
        ]
        .join("\n");

        let first = render_report(&trace).unwrap();
        let second = render_report(&trace).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn unknown_event_types_are_skipped() {
        let trace = [
            run_start_line("record_only", "[]", "/w"),
            r#"{"seq":1,"ts":100,"type":"future_thing","whatever":true}"#.to_string(),
        ]
        .join("\n");

        let report = render_report(&trace);
        assert!(report.is_ok());
    }

    #[test]
    fn malformed_line_is_an_error() {
        let trace = [
            run_start_line("record_only", "[]", "/w"),
            "{not json".to_string(),
        ]
        .join("\n");

        let err = render_report(&trace).unwrap_err();
        assert!(matches!(err, ReportError::Malformed { line: 2, .. }));
    }

    #[test]
    fn missing_run_start_is_an_error() {
        let trace = syscall_line(
            0,
            "openat",
            "allow",
            r#"{"family":"fs","path":"/w/a.txt","access":["read"]}"#,
            "base:record_only",
        );

        let err = render_report(&trace).unwrap_err();
        assert!(matches!(err, ReportError::MissingRunStart));
    }

    #[test]
    fn syscall_missing_decision_is_invalid() {
        let trace = [
            run_start_line("record_only", "[]", "/w"),
            r#"{"seq":1,"ts":100,"type":"syscall","pid":1,"syscall":"openat","fact":{"family":"fs","path":"/w/a.txt"},"matched_rule":"base:record_only"}"#
                .to_string(),
        ]
        .join("\n");

        let err = render_report(&trace).unwrap_err();
        assert!(matches!(
            err,
            ReportError::InvalidEvent {
                line: 2,
                field: "decision"
            }
        ));
    }

    #[test]
    fn fs_fact_missing_path_is_invalid() {
        let trace = [
            run_start_line("record_only", "[]", "/w"),
            syscall_line(
                1,
                "openat",
                "allow",
                r#"{"family":"fs","access":["read"]}"#,
                "base:record_only",
            ),
        ]
        .join("\n");

        let err = render_report(&trace).unwrap_err();
        assert!(matches!(
            err,
            ReportError::InvalidEvent {
                line: 2,
                field: "path"
            }
        ));
    }

    #[test]
    fn run_start_missing_mode_is_invalid() {
        let trace = r#"{"seq":0,"ts":100,"type":"run_start","argv":[],"workspace":"/w"}"#;

        let err = render_report(trace).unwrap_err();
        assert!(matches!(
            err,
            ReportError::InvalidEvent {
                line: 1,
                field: "mode"
            }
        ));
    }

    #[test]
    fn raw_allow_does_not_reach_the_denied_section() {
        let trace = [
            run_start_line("record_only", "[]", "/w"),
            syscall_line(
                1,
                "some_syscall",
                "allow",
                r#"{"family":"raw"}"#,
                "base:record_only",
            ),
        ]
        .join("\n");

        let report = render_report(&trace).unwrap();
        assert!(report.contains("denied without a typed fact:\n  none\n"));
    }

    #[test]
    fn signal_death_renders_killed_by_signal() {
        let trace = [
            run_start_line("record_only", "[]", "/w"),
            run_end_line(1, "null", "9"),
        ]
        .join("\n");

        let report = render_report(&trace).unwrap();
        assert!(report.contains("exit: killed by signal 9\n"));
    }

    #[test]
    fn missing_run_end_renders_unknown() {
        let trace = run_start_line("record_only", "[]", "/w");

        let report = render_report(&trace).unwrap();
        assert!(report.contains(
            "exit: unknown (no run_end was recorded; the supervisor failed before stamping one)\n"
        ));
    }

    #[test]
    fn net_allow_renders_host_port_and_drops_placeholder() {
        let trace = [
            run_start_line("record_only", "[]", "/w"),
            syscall_line(
                1,
                "connect",
                "allow",
                r#"{"family":"net","host":"203.0.113.7","port":443}"#,
                "net.1",
            ),
        ]
        .join("\n");

        let report = render_report(&trace).unwrap();
        assert!(report.contains("  203.0.113.7:443  allowed\n"));
        assert!(!report.contains("not implemented"));
    }
}
