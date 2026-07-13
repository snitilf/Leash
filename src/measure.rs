//! measurement and trace-analysis helpers for the NFR-2 overhead harness
//! (`benches/overhead.rs`, docs/measurements/0001-m1-overhead.md).
//!
//! this module is pure and side-effect-free. it computes quantiles over raw timing
//! samples (the micro method) and mines a trace for the inter-mutating-event gap
//! distribution the coalescing-window decision needs (the gap method, FR-17,
//! snapshot.md section 1). it lives in the library, not the bench binary, so the logic
//! is exercised by `cargo test` on any host, not only when a linux bench builds. nothing
//! here touches the kernel or the clock: the bench owns all of that and hands raw data in.

use serde::Serialize;

/// nearest-rank quantiles over a set of samples. the unit is the caller's (nanoseconds
/// for the micro method, milliseconds for gaps); this only sorts and indexes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Quantiles {
    /// number of samples the quantiles were computed over
    pub count: usize,
    /// smallest sample
    pub min: u64,
    /// 50th percentile (median)
    pub p50: u64,
    /// 90th percentile
    pub p90: u64,
    /// 99th percentile
    pub p99: u64,
    /// largest sample
    pub max: u64,
}

/// quantiles over `samples`, or `None` when there is nothing to summarize. computed on a
/// sorted copy; the input is not mutated.
pub fn quantiles(samples: &[u64]) -> Option<Quantiles> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    Some(Quantiles {
        count: sorted.len(),
        min: sorted[0],
        p50: percentile(&sorted, 50),
        p90: percentile(&sorted, 90),
        p99: percentile(&sorted, 99),
        max: sorted[sorted.len() - 1],
    })
}

// nearest-rank percentile on a non-empty sorted slice. `p` is a whole percent in 1..=100.
// rank = ceil(p/100 * n), clamped into the slice, so p100 is the max and small n never
// indexes out of range. no interpolation: the reported value is always a real sample.
fn percentile(sorted: &[u64], p: u64) -> u64 {
    let n = sorted.len();
    let rank = ((p as f64 / 100.0) * n as f64).ceil() as usize;
    let idx = rank.clamp(1, n) - 1;
    sorted[idx]
}

/// is this parsed trace event a mutating filesystem event, i.e. part of the step clock's
/// mutating set (snapshot.md section 1: open-for-write plus the mutation family create,
/// rename, unlink, mkdir, link, symlink, truncate)?
///
/// the recorder encodes every one of those as an `fs` fact whose `access` set contains
/// write, create, or delete; a read-only open carries only `read` and is excluded
/// (trace.md section 2, src/supervisor/fact.rs). we key off the recorded access mode
/// rather than a syscall-name allowlist, so the filter tracks exactly what the recorder
/// emits: a metadata write (chmod/chown, recorded as a write) counts as mutating too,
/// which matches the step-clock intent that any path-mutating event ticks the clock.
pub fn is_mutating_event(event: &serde_json::Value) -> bool {
    if event.get("type").and_then(serde_json::Value::as_str) != Some("syscall") {
        return false;
    }
    let Some(fact) = event.get("fact") else {
        return false;
    };
    if fact.get("family").and_then(serde_json::Value::as_str) != Some("fs") {
        return false;
    }
    let Some(access) = fact.get("access").and_then(serde_json::Value::as_array) else {
        return false;
    };
    access
        .iter()
        .any(|a| matches!(a.as_str(), Some("write") | Some("create") | Some("delete")))
}

/// timestamps (ms, `Event.ts`) of the mutating events in a `trace.jsonl` body, ordered by
/// `seq` (the authoritative decision order, ADR-0011). blank lines and lines that do not
/// parse as a json object are skipped, so a partially written trace still yields its
/// readable prefix. an event missing `seq` or `ts` is dropped.
pub fn mutating_event_timestamps(trace: &str) -> Vec<u64> {
    let mut events: Vec<(u64, u64)> = Vec::new();
    for line in trace.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if !is_mutating_event(&value) {
            continue;
        }
        let seq = value.get("seq").and_then(serde_json::Value::as_u64);
        let ts = value.get("ts").and_then(serde_json::Value::as_u64);
        if let (Some(seq), Some(ts)) = (seq, ts) {
            events.push((seq, ts));
        }
    }
    events.sort_by_key(|&(seq, _)| seq);
    events.into_iter().map(|(_, ts)| ts).collect()
}

/// consecutive gaps between ordered timestamps. `saturating_sub` guards against a
/// non-monotonic pair (which the seq ordering should prevent) collapsing to a huge value.
pub fn consecutive_gaps(timestamps: &[u64]) -> Vec<u64> {
    timestamps
        .windows(2)
        .map(|w| w[1].saturating_sub(w[0]))
        .collect()
}

// inclusive upper bounds (ms) for the gap histogram. the window decision lives in the
// tens-of-ms-to-seconds range (measurements/0001 section 2.3), so the edges cluster there.
// Event.ts is unix-epoch ms, so sub-ms intra-burst gaps land in the first (<=0 ms) bucket.
const GAP_BUCKET_EDGES_MS: &[u64] = &[
    0, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000,
];

/// one histogram bucket: all gaps `g` with `prev_edge < g <= upper_ms_inclusive`. the
/// final overflow bucket carries `None` and holds every gap larger than the last edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GapBucket {
    /// inclusive upper bound in ms, or `None` for the overflow bucket
    pub upper_ms_inclusive: Option<u64>,
    /// how many gaps fell in this bucket
    pub count: usize,
}

/// bucket `gaps` (ms) into the fixed edge set plus a trailing overflow bucket.
pub fn gap_histogram(gaps: &[u64]) -> Vec<GapBucket> {
    let mut counts = vec![0usize; GAP_BUCKET_EDGES_MS.len() + 1];
    for &g in gaps {
        let idx = GAP_BUCKET_EDGES_MS
            .iter()
            .position(|&edge| g <= edge)
            .unwrap_or(GAP_BUCKET_EDGES_MS.len());
        counts[idx] += 1;
    }
    counts
        .into_iter()
        .enumerate()
        .map(|(i, count)| GapBucket {
            upper_ms_inclusive: GAP_BUCKET_EDGES_MS.get(i).copied(),
            count,
        })
        .collect()
}

/// the gap distribution mined from one `trace.jsonl` body: the mutating-event count, the
/// number of consecutive gaps, their quantiles, and a histogram. this is the data the
/// coalescing-window decision needs (measurements/0001 section 2.3).
#[derive(Debug, Clone, Serialize)]
pub struct GapReport {
    /// number of mutating events found
    pub event_count: usize,
    /// number of consecutive gaps (event_count - 1, or 0)
    pub gap_count: usize,
    /// quantiles of the gaps (ms), or `None` when there are fewer than two events
    pub quantiles: Option<Quantiles>,
    /// gap histogram over the fixed ms buckets
    pub histogram: Vec<GapBucket>,
}

/// build the gap report from a `trace.jsonl` body.
pub fn gap_report(trace: &str) -> GapReport {
    let timestamps = mutating_event_timestamps(trace);
    let gaps = consecutive_gaps(&timestamps);
    GapReport {
        event_count: timestamps.len(),
        gap_count: gaps.len(),
        quantiles: quantiles(&gaps),
        histogram: gap_histogram(&gaps),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn quantiles_of_one_through_ten() {
        let samples: Vec<u64> = (1..=10).collect();
        let q = quantiles(&samples).unwrap();
        assert_eq!(q.count, 10);
        assert_eq!(q.min, 1);
        // nearest-rank: p50 -> rank ceil(5.0)=5 -> sorted[4]
        assert_eq!(q.p50, 5);
        // p90 -> rank ceil(9.0)=9 -> sorted[8]
        assert_eq!(q.p90, 9);
        // p99 -> rank ceil(9.9)=10 -> sorted[9]
        assert_eq!(q.p99, 10);
        assert_eq!(q.max, 10);
    }

    #[test]
    fn quantiles_are_order_independent() {
        let a = quantiles(&[9, 1, 7, 3, 5]).unwrap();
        let b = quantiles(&[1, 3, 5, 7, 9]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn quantiles_single_sample_is_flat() {
        let q = quantiles(&[42]).unwrap();
        assert_eq!(
            q,
            Quantiles {
                count: 1,
                min: 42,
                p50: 42,
                p90: 42,
                p99: 42,
                max: 42
            }
        );
    }

    #[test]
    fn quantiles_empty_is_none() {
        assert!(quantiles(&[]).is_none());
    }

    #[test]
    fn consecutive_gaps_are_differences() {
        assert_eq!(consecutive_gaps(&[10, 15, 15, 40]), vec![5, 0, 25]);
        assert!(consecutive_gaps(&[7]).is_empty());
        assert!(consecutive_gaps(&[]).is_empty());
    }

    // realistic trace lines in the recorder's shape (trace.md section 2, src/recorder.rs):
    // seq/ts envelope, flattened type, fs facts with an access set. dest/would_deny are
    // omitted when absent, exactly as the serializer emits them.
    const TRACE: &str = r#"
{"seq":0,"ts":1000,"type":"run_start","mode":"record_only","argv":["/bin/sh"]}
{"seq":1,"ts":1000,"type":"syscall","pid":100,"syscall":"openat","fact":{"family":"fs","path":"/w/read.txt","access":["read"]},"decision":"allow","matched_rule":"base:record_only"}
{"seq":2,"ts":1002,"type":"syscall","pid":100,"syscall":"openat","fact":{"family":"fs","path":"/w/out.txt","access":["write","create"]},"decision":"allow","matched_rule":"base:record_only"}
{"seq":3,"ts":1050,"type":"syscall","pid":100,"syscall":"rename","fact":{"family":"fs","path":"/w/a","access":["write"],"dest":"/w/b"},"decision":"allow","matched_rule":"base:record_only"}
{"seq":4,"ts":1051,"type":"syscall","pid":100,"syscall":"unlink","fact":{"family":"fs","path":"/w/gone","access":["delete"]},"decision":"allow","matched_rule":"base:record_only"}
{"seq":5,"ts":1060,"type":"syscall","pid":100,"syscall":"execve","fact":{"family":"exec","binary":"/bin/true"},"decision":"allow","matched_rule":"base:record_only"}
{"seq":6,"ts":1200,"type":"step","step":0}
{"seq":7,"ts":1300,"type":"run_end","exit_code":0,"signal":null,"final_step":1}
"#;

    #[test]
    fn filter_keeps_only_mutating_fs_events() {
        let ts = mutating_event_timestamps(TRACE);
        // the write-open (1002), the rename (1050), and the unlink (1051): the read-open,
        // the execve, the step, run_start and run_end are all excluded.
        assert_eq!(ts, vec![1002, 1050, 1051]);
    }

    #[test]
    fn gap_report_over_realistic_trace() {
        let report = gap_report(TRACE);
        assert_eq!(report.event_count, 3);
        assert_eq!(report.gap_count, 2);
        // gaps: 1050-1002=48, 1051-1050=1
        let q = report.quantiles.unwrap();
        assert_eq!(q.min, 1);
        assert_eq!(q.max, 48);
        // one gap (1) in the <=1 ms bucket, one gap (48) in the <=50 ms bucket
        let one_ms = report
            .histogram
            .iter()
            .find(|b| b.upper_ms_inclusive == Some(1))
            .unwrap();
        assert_eq!(one_ms.count, 1);
        let fifty_ms = report
            .histogram
            .iter()
            .find(|b| b.upper_ms_inclusive == Some(50))
            .unwrap();
        assert_eq!(fifty_ms.count, 1);
        let total: usize = report.histogram.iter().map(|b| b.count).sum();
        assert_eq!(total, report.gap_count);
    }

    #[test]
    fn empty_trace_reports_nothing() {
        let report = gap_report("");
        assert_eq!(report.event_count, 0);
        assert_eq!(report.gap_count, 0);
        assert!(report.quantiles.is_none());
        assert_eq!(report.histogram.iter().map(|b| b.count).sum::<usize>(), 0);
    }

    #[test]
    fn single_mutating_event_has_no_gaps() {
        let trace = r#"{"seq":0,"ts":5,"type":"syscall","pid":1,"syscall":"openat","fact":{"family":"fs","path":"/w/x","access":["write"]},"decision":"allow","matched_rule":"base:record_only"}"#;
        let report = gap_report(trace);
        assert_eq!(report.event_count, 1);
        assert_eq!(report.gap_count, 0);
        assert!(report.quantiles.is_none());
    }

    #[test]
    fn out_of_file_order_is_sorted_by_seq() {
        // two mutating events written out of seq order; the gap must use seq order.
        let trace = r#"
{"seq":2,"ts":200,"type":"syscall","pid":1,"syscall":"rename","fact":{"family":"fs","path":"/w/a","access":["write"],"dest":"/w/b"},"decision":"allow","matched_rule":"base:record_only"}
{"seq":1,"ts":100,"type":"syscall","pid":1,"syscall":"openat","fact":{"family":"fs","path":"/w/o","access":["write"]},"decision":"allow","matched_rule":"base:record_only"}
"#;
        let ts = mutating_event_timestamps(trace);
        assert_eq!(ts, vec![100, 200]);
    }

    #[test]
    fn non_json_lines_are_skipped() {
        let trace = "not json\n{bad\n{\"seq\":0,\"ts\":5,\"type\":\"syscall\",\"pid\":1,\"syscall\":\"openat\",\"fact\":{\"family\":\"fs\",\"path\":\"/w/x\",\"access\":[\"write\"]},\"decision\":\"allow\",\"matched_rule\":\"base:record_only\"}";
        assert_eq!(mutating_event_timestamps(trace), vec![5]);
    }
}
