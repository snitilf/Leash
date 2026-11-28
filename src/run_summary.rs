//! what a snapshot run tells the operator when it ends (docs/design/cli.md section 5).
//!
//! assumptions: the trace text was written by this supervisor a moment ago, so a line that
//! does not parse is skipped rather than trusted. nothing here decides anything; it only
//! formats values the run already committed, so the operator can keep the chain head outside
//! the state root and hand it back to `leash rewind --expect`.

use std::path::Path;

use crate::rewind::shell_quote;

/// one line per committed step digest of a finished snapshot run, in step order, as
/// `leash: step <n> digest: <64 hex>`. the digests are the ones the step events carry.
pub fn step_digest_lines(trace: &str) -> Vec<String> {
    trace
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|event| event["type"] == "step")
        .filter_map(|event| {
            let step = event["step"].as_u64()?;
            let digest = event["manifest_digest"].as_str()?;
            Some(format!("leash: step {step} digest: {digest}"))
        })
        .collect()
}

/// the last line of a finished snapshot run: the command that rewinds it, checked against
/// the chain head the run just printed. the workspace and state directory are spelled out so
/// the command works from any directory and for a non-default state root, and every value
/// is shell-quoted so the line can be pasted.
pub fn rewind_hint(run_id: &str, chain_head: &str, workspace: &Path, state_root: &Path) -> String {
    format!(
        "leash: to undo this run: leash rewind {} --expect {chain_head} --workspace {} --state-dir {}",
        shell_quote(run_id),
        shell_quote(&workspace.to_string_lossy()),
        shell_quote(&state_root.to_string_lossy()),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const D0: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const D1: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn step_digests_come_from_the_step_events_in_order() {
        let trace = format!(
            "{{\"seq\":0,\"ts\":1,\"type\":\"run_start\"}}\n\
             {{\"seq\":1,\"ts\":2,\"type\":\"step\",\"step\":0,\"manifest_digest\":\"{D0}\",\"capture_pause_us\":0}}\n\
             {{\"seq\":2,\"ts\":3,\"type\":\"syscall\",\"step\":9}}\n\
             {{\"seq\":3,\"ts\":4,\"type\":\"step\",\"step\":1,\"manifest_digest\":\"{D1}\",\"capture_pause_us\":7}}\n"
        );
        assert_eq!(
            step_digest_lines(&trace),
            vec![
                format!("leash: step 0 digest: {D0}"),
                format!("leash: step 1 digest: {D1}")
            ]
        );
    }

    #[test]
    fn a_step_without_a_digest_and_a_torn_line_are_skipped() {
        let trace = format!(
            "{{\"type\":\"step\",\"step\":0}}\nnot json\n\
             {{\"type\":\"step\",\"step\":1,\"manifest_digest\":\"{D1}\"}}\n{{\"type\":\"step\""
        );
        assert_eq!(
            step_digest_lines(&trace),
            vec![format!("leash: step 1 digest: {D1}")]
        );
    }

    #[test]
    fn a_trace_without_steps_has_no_digest_lines() {
        assert!(step_digest_lines("").is_empty());
        assert!(step_digest_lines("{\"type\":\"run_end\"}\n").is_empty());
    }

    #[test]
    fn the_hint_names_the_run_the_head_the_workspace_and_the_state_root() {
        assert_eq!(
            rewind_hint(
                "20260101T000000Z-abc123",
                D1,
                Path::new("/work/my repo"),
                Path::new("/state")
            ),
            format!(
                "leash: to undo this run: leash rewind 20260101T000000Z-abc123 --expect {D1} --workspace '/work/my repo' --state-dir /state"
            )
        );
    }

    #[test]
    fn the_hint_cannot_carry_a_line_break_from_a_path() {
        let hint = rewind_hint("id", D0, Path::new("/a\nb"), Path::new("/s"));
        assert!(!hint.contains('\n'), "{hint:?}");
    }
}
