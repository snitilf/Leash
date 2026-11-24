//! `leash diff`: open two runs' snapshot stores and compare a step of each (FR-13).
//!
//! assumptions: the state root is operator supplied, but everything beneath it is
//! untrusted input (a hostile run can leave anything in its directory). every component
//! below the state root is opened with `O_NOFOLLOW | O_DIRECTORY` relative to its parent
//! descriptor, so a symlinked `runs`, run directory or `snapshots` is refused. manifests
//! are read and validated by `snapshot::store`.

use std::path::Path;

/// a run id and optional step naming one side of a diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRef {
    /// the run directory name; validated by [`parse_run_ref`].
    pub run_id: String,
    /// the step number; absent means the final committed step.
    pub step: Option<u64>,
}

/// why a diff could not be produced.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum DiffRunError {
    /// the request names something that does not exist: unknown run, no snapshots, or
    /// unknown step. a usage error (exit 2).
    #[error("leash: {0}")]
    Usage(String),
    /// the store exists but cannot be read or fails validation. a failure of leash (125).
    #[error("leash: {0}")]
    Failure(String),
}

/// why a `<run-id>[:<step>]` argument is malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefError {
    /// the run id is empty, `.`, `..`, or contains `/` or NUL.
    BadRunId,
    /// the step is not a plain decimal u64.
    BadStep,
}

/// parse `<run-id>` or `<run-id>:<step>`. the run id must be a plain directory name:
/// non-empty, not `.` or `..`, no `/`, no NUL. the step is plain decimal digits.
pub fn parse_run_ref(token: &str) -> Result<RunRef, RefError> {
    let (id, step) = match token.split_once(':') {
        Some((id, step)) => (id, Some(step)),
        None => (token, None),
    };
    if id.is_empty() || id == "." || id == ".." || id.contains('/') || id.contains('\0') {
        return Err(RefError::BadRunId);
    }
    let step = match step {
        None => None,
        Some(s) => {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return Err(RefError::BadStep);
            }
            Some(s.parse::<u64>().map_err(|_| RefError::BadStep)?)
        }
    };
    Ok(RunRef {
        run_id: id.to_string(),
        step,
    })
}

/// compare the two named steps and return the rendered report.
#[cfg(target_os = "linux")]
pub fn run_diff(state_root: &Path, old: &RunRef, new: &RunRef) -> Result<String, DiffRunError> {
    let (old_manifest, new_manifest) = (load_side(state_root, old)?, load_side(state_root, new)?);
    let changes = crate::snapshot::diff::diff(&old_manifest, &new_manifest);
    Ok(crate::snapshot::diff::render(&changes))
}

/// snapshot stores are produced and read only on linux.
#[cfg(not(target_os = "linux"))]
pub fn run_diff(_state_root: &Path, _old: &RunRef, _new: &RunRef) -> Result<String, DiffRunError> {
    Err(DiffRunError::Failure(
        "diff reads snapshot stores, which only linux produces (kernel 5.19 or later)".into(),
    ))
}

#[cfg(target_os = "linux")]
fn open_dir_at(
    parent: Option<&std::fs::File>,
    path: &std::ffi::CStr,
    follow: bool,
) -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let mut flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    if !follow {
        flags |= libc::O_NOFOLLOW;
    }
    let dirfd = parent.map_or(libc::AT_FDCWD, |p| p.as_raw_fd());
    // SAFETY: dirfd is a live descriptor or AT_FDCWD and path is NUL-terminated; the
    // returned descriptor is owned by the File constructed from it.
    let fd = unsafe { libc::openat(dirfd, path.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh descriptor this function owns.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn load_side(
    state_root: &Path,
    side: &RunRef,
) -> Result<crate::snapshot::store::Manifest, DiffRunError> {
    use crate::snapshot::store::{committed_steps, load_manifest};
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let label = crate::snapshot::diff::display_path(&side.run_id);
    let usage = |msg: String| DiffRunError::Usage(msg);
    let no_store = || usage(format!("run '{label}' has no snapshots"));

    let root_c = CString::new(state_root.as_os_str().as_bytes())
        .map_err(|_| DiffRunError::Failure("state directory contains a NUL byte".into()))?;
    let root = open_dir_at(None, &root_c, true).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            usage(format!("unknown run '{label}' (no state directory)"))
        } else {
            DiffRunError::Failure(format!("cannot open state directory: {e}"))
        }
    })?;
    // a missing runs directory or run directory is an unknown run; a symlink or other
    // non-directory in either place is treated the same, never followed
    let unknown = || usage(format!("unknown run '{label}'"));
    let runs = open_dir_at(Some(&root), c"runs", false).map_err(|_| unknown())?;
    let id_c = CString::new(side.run_id.as_str()).map_err(|_| unknown())?;
    let run_dir = open_dir_at(Some(&runs), &id_c, false).map_err(|_| unknown())?;
    let store = open_dir_at(Some(&run_dir), c"snapshots", false).map_err(|_| no_store())?;

    let steps = committed_steps(&store)
        .map_err(|e| DiffRunError::Failure(format!("run '{label}': {e}")))?;
    let step = match side.step {
        Some(s) if steps.contains(&s) => s,
        Some(s) => {
            return Err(usage(format!(
                "run '{label}' has no committed step {s} (committed: {})",
                join_steps(&steps)
            )));
        }
        None => *steps.last().ok_or_else(no_store)?,
    };
    let (manifest, _digest) = load_manifest(&store, step)
        .map_err(|e| DiffRunError::Failure(format!("run '{label}' step {step}: {e}")))?;
    Ok(manifest)
}

#[cfg(target_os = "linux")]
fn join_steps(steps: &[u64]) -> String {
    if steps.is_empty() {
        return "none".into();
    }
    steps
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_id_and_optional_step() {
        assert_eq!(
            parse_run_ref("20260101T000000Z-ab12").unwrap(),
            RunRef {
                run_id: "20260101T000000Z-ab12".into(),
                step: None
            }
        );
        assert_eq!(
            parse_run_ref("r:0").unwrap(),
            RunRef {
                run_id: "r".into(),
                step: Some(0)
            }
        );
        assert_eq!(parse_run_ref("r:007").unwrap().step, Some(7));
    }

    #[test]
    fn rejects_bad_ids_and_steps() {
        for bad in ["", ".", "..", "../x", "a/b", "/abs", ":3", "a\0b", "../x:1"] {
            assert_eq!(parse_run_ref(bad), Err(RefError::BadRunId), "{bad:?}");
        }
        for bad in [
            "r:",
            "r:x",
            "r:-1",
            "r:+1",
            "r:1:2",
            "r:1.5",
            "r: 1",
            "r:99999999999999999999",
        ] {
            assert_eq!(parse_run_ref(bad), Err(RefError::BadStep), "{bad:?}");
        }
    }
}
