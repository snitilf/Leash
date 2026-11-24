//! workspace snapshots, rewind, and diff (docs/design/snapshot.md, ADR-0009).
//!
//! assumptions: nothing in this module sits on the decision loop's hot path. the upper
//! layer has overlay semantics (whiteouts, opaque markers, copy-up), and every reader in
//! here must interpret them, never treat the layer as a plain tree. the copy fallback
//! must stay observably equivalent to the overlay; behavior only one mechanism exhibits
//! is a bug in one of them.
//!
//! the workspace belongs to a hostile child between captures (SR-1): a tree can contain
//! symlinks pointing anywhere. symlinks are copied and restored as links, verbatim,
//! but path-based traversal is not safe against concurrent replacement. sockets and device nodes cannot be reproduced by an
//! unprivileged restore, so capture refuses them closed (UnsupportedEntry) rather than
//! silently snapshotting an incomplete tree.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// content-addressed exact snapshot store (ADR-0022).
pub mod store;

/// pure comparison of two snapshot manifests (FR-13).
pub mod diff;

/// rewind restore engine: plan and apply a stored manifest onto the workspace (ADR-0024).
#[cfg(target_os = "linux")]
pub mod restore;

/// errors from snapshot capture and restore.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// an io failure, with the operation and the path it touched
    #[error("{op} failed for {}: {source}", .path.display())]
    Io {
        /// what was being attempted (read, write, remove, ...)
        op: &'static str,
        /// the path the operation touched
        path: PathBuf,
        /// the underlying io error
        #[source]
        source: io::Error,
    },
    /// an entry kind the copy mechanism cannot reproduce (snapshot.md section 3)
    #[error(
        "unsupported entry at {}: only files, directories, symlinks, and fifos are captured",
        .0.display()
    )]
    UnsupportedEntry(PathBuf),
    /// a tree root must be a directory, not a symlink or another entry
    #[error("tree root {} is not a directory", .0.display())]
    InvalidRoot(PathBuf),
    /// capture refuses to clobber an existing destination
    #[error("capture destination {} already exists", .0.display())]
    DestinationExists(PathBuf),
}

fn io_err<'a>(op: &'static str, path: &'a Path) -> impl FnOnce(io::Error) -> SnapshotError + 'a {
    move |source| SnapshotError::Io {
        op,
        path: path.to_path_buf(),
        source,
    }
}

/// strip the tree root off a path produced by walking that root. joining can never
/// escape the root, so a failure here is a bug, reported as an io-class error rather
/// than a panic.
fn rel_of<'a>(root: &Path, path: &'a Path) -> Result<&'a Path, SnapshotError> {
    path.strip_prefix(root).map_err(|_| SnapshotError::Io {
        op: "relativize",
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "path escaped its tree root"),
    })
}

/// the coalescing window (snapshot.md section 1): a step boundary falls when mutating
/// mediated events go quiet for longer than this. measured from the M1 trace (25x over
/// the worst observed in-burst gap, far below agent think time); FR-17 via ADR-0006.
pub const STEP_WINDOW: Duration = Duration::from_millis(250);

/// step detection (FR-17, snapshot.md section 1). a pure state machine fed by the run
/// loop: the loop reports every mutating mediated event, asks for the wakeup deadline,
/// and polls for boundaries. boundary 0 is run start and is emitted by the caller, so
/// indices handed out here start at 1. two properties are fixed regardless of the
/// window: a boundary never falls inside a burst, and run end is always a boundary.
pub struct StepClock {
    window: Duration,
    last_mutation: Option<Instant>,
    /// the open step has seen a mutation since the last boundary
    pending: bool,
    /// the index the next boundary closes
    next_index: u64,
}

impl StepClock {
    /// a clock with the given coalescing window; tests inject smaller windows.
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            last_mutation: None,
            pending: false,
            next_index: 1,
        }
    }

    /// report one mutating mediated event at `at`.
    pub fn on_mutation(&mut self, at: Instant) {
        self.pending = true;
        self.last_mutation = Some(at);
    }

    /// close a boundary if activity has quiesced for the window. returns the index of
    /// the step this boundary closes.
    pub fn poll(&mut self, now: Instant) -> Option<u64> {
        let last = self.last_mutation?;
        if !self.pending || now.duration_since(last) < self.window {
            return None;
        }
        self.pending = false;
        let index = self.next_index;
        self.next_index += 1;
        Some(index)
    }

    /// when the run loop must wake to close a pending boundary, if any.
    pub fn deadline(&self) -> Option<Instant> {
        if self.pending {
            self.last_mutation.map(|last| last + self.window)
        } else {
            None
        }
    }

    /// run end is always a boundary, mutations or not: returns the final step index.
    pub fn finish(&mut self) -> u64 {
        self.pending = false;
        let index = self.next_index;
        self.next_index += 1;
        index
    }
}

/// where the run loop sends step boundaries (FR-11): capture the current workspace
/// state as the snapshot for the step being closed. the session implements this over
/// the run directory; a capture failure stops the run fail-closed (snapshot.md
/// section 6), because a recorded boundary without its snapshot would be a lie.
pub trait BoundaryCapture {
    /// capture the workspace state as the snapshot for `step`
    fn capture(&self, step: u64) -> Result<(), SnapshotError>;
}

/// the directory name of one step's snapshot inside a run's `snapshots/` directory.
/// zero-padded so lexical order matches step order.
pub fn step_snapshot_name(step: u64) -> String {
    format!("step-{step:06}")
}

/// the reproducible kinds of tree entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
    Symlink,
    Fifo,
}

fn kind_of(md: &fs::Metadata) -> Result<Kind, PathBuf> {
    let ft = md.file_type();
    if ft.is_file() {
        Ok(Kind::File)
    } else if ft.is_dir() {
        Ok(Kind::Dir)
    } else if ft.is_symlink() {
        Ok(Kind::Symlink)
    } else if ft.is_fifo() {
        Ok(Kind::Fifo)
    } else {
        Err(PathBuf::new())
    }
}

/// copy mechanism (snapshot.md section 3): capture an exact tree copy of `workspace`
/// into `dest`, which must not exist yet. files keep content and permission bits,
/// directories keep permission bits (including empty directories), symlinks are copied
/// as links and never followed. any other entry kind fails the capture closed.
pub fn capture_copy(workspace: &Path, dest: &Path) -> Result<(), SnapshotError> {
    if dest.symlink_metadata().is_ok() {
        return Err(SnapshotError::DestinationExists(dest.to_path_buf()));
    }
    let root_md = workspace
        .symlink_metadata()
        .map_err(io_err("stat workspace", workspace))?;
    if !root_md.file_type().is_dir() {
        return Err(SnapshotError::InvalidRoot(workspace.to_path_buf()));
    }
    fs::create_dir_all(dest).map_err(io_err("create capture dir", dest))?;

    // dir modes are applied only after the whole tree is placed: a read-only directory
    // would otherwise reject its own children mid-capture.
    let mut dir_modes: Vec<(PathBuf, u32)> = Vec::new();
    dir_modes.push((dest.to_path_buf(), root_md.permissions().mode()));

    let mut links = BTreeMap::new();
    let mut stack = vec![(workspace.to_path_buf(), dest.to_path_buf())];
    while let Some((src_dir, dst_dir)) = stack.pop() {
        let entries = fs::read_dir(&src_dir).map_err(io_err("read dir", &src_dir))?;
        for entry in entries {
            let entry = entry.map_err(io_err("read dir entry", &src_dir))?;
            // DirEntry::metadata does not traverse symlinks; exactly what a hostile
            // tree requires.
            let md = entry
                .metadata()
                .map_err(io_err("stat entry", &entry.path()))?;
            let dst = dst_dir.join(entry.file_name());
            place_entry(
                &entry.path(),
                &dst,
                &md,
                &mut stack,
                &mut dir_modes,
                &mut links,
            )?;
        }
    }
    apply_dir_modes(&dir_modes)?;
    Ok(())
}

/// place one entry of a captured tree at `dst`. shared by capture (src is the live
/// workspace) and restore (src is the snapshot).
fn place_entry(
    src: &Path,
    dst: &Path,
    md: &fs::Metadata,
    dirs: &mut Vec<(PathBuf, PathBuf)>,
    dir_modes: &mut Vec<(PathBuf, u32)>,
    links: &mut BTreeMap<(u64, u64), PathBuf>,
) -> Result<(), SnapshotError> {
    match kind_of(md).map_err(|_| SnapshotError::UnsupportedEntry(src.to_path_buf()))? {
        Kind::File => {
            let key = (md.dev(), md.ino());
            if let Some(first) = links.get(&key) {
                fs::hard_link(first, dst).map_err(io_err("link file", dst))?;
            } else {
                fs::copy(src, dst).map_err(io_err("copy file", src))?;
                links.insert(key, dst.to_path_buf());
            }
        }
        Kind::Dir => {
            fs::create_dir(dst).map_err(io_err("create dir", dst))?;
            dir_modes.push((dst.to_path_buf(), md.permissions().mode()));
            dirs.push((src.to_path_buf(), dst.to_path_buf()));
        }
        Kind::Symlink => {
            let target = fs::read_link(src).map_err(io_err("read symlink", src))?;
            std::os::unix::fs::symlink(&target, dst).map_err(io_err("create symlink", dst))?;
        }
        Kind::Fifo => {
            create_fifo(dst, md.permissions().mode())?;
        }
    }
    Ok(())
}

fn create_fifo(path: &Path, mode: u32) -> Result<(), SnapshotError> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| SnapshotError::UnsupportedEntry(path.to_path_buf()))?;
    // SAFETY: c_path is a valid nul-terminated path we own; mkfifo only creates the node.
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), (mode & 0o7777) as libc::mode_t) };
    if rc != 0 {
        return Err(io_err("create fifo", path)(io::Error::last_os_error()));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o7777))
        .map_err(io_err("set fifo permissions", path))?;
    Ok(())
}

fn apply_dir_modes(dir_modes: &[(PathBuf, u32)]) -> Result<(), SnapshotError> {
    for (path, mode) in dir_modes.iter().rev() {
        fs::set_permissions(path, fs::Permissions::from_mode(*mode))
            .map_err(io_err("set dir permissions", path))?;
    }
    Ok(())
}

/// remove whatever is at `path`, never following symlinks. a symlink to a directory is
/// removed as a link, not descended into.
fn remove_entry(path: &Path, md: &fs::Metadata) -> Result<(), SnapshotError> {
    if md.file_type().is_dir() {
        // remove_dir_all does not traverse symlinks; it removes a symlinked dir as a link.
        fs::remove_dir_all(path).map_err(io_err("remove dir", path))
    } else {
        fs::remove_file(path).map_err(io_err("remove entry", path))
    }
}

/// restore (FR-12): make `workspace` match `snapshot` exactly. entries the run added are
/// removed, entries it deleted or modified are brought back, symlinks are restored as
/// links. this path-based implementation does not protect against concurrent entry
/// replacement and must not be used with an untrusted concurrent writer.
pub fn restore_copy(snapshot: &Path, workspace: &Path) -> Result<(), SnapshotError> {
    let snapshot_md = snapshot
        .symlink_metadata()
        .map_err(io_err("stat snapshot", snapshot))?;
    if !snapshot_md.file_type().is_dir() {
        return Err(SnapshotError::InvalidRoot(snapshot.to_path_buf()));
    }
    match workspace.symlink_metadata() {
        Ok(md) if md.file_type().is_dir() => {}
        Ok(_) => return Err(SnapshotError::InvalidRoot(workspace.to_path_buf())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(workspace).map_err(io_err("create workspace", workspace))?;
        }
        Err(e) => return Err(io_err("stat workspace", workspace)(e)),
    }

    // pass 1: remove workspace entries the snapshot does not have. a missing directory
    // takes its whole subtree with it, so removal never needs child-before-parent order.
    let mut stack = vec![workspace.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).map_err(io_err("read dir", &dir))?;
        for entry in entries {
            let entry = entry.map_err(io_err("read dir entry", &dir))?;
            let path = entry.path();
            let rel = rel_of(workspace, &path)?;
            let in_snapshot = snapshot.join(rel);
            let md = entry.metadata().map_err(io_err("stat entry", &path))?;
            match in_snapshot.symlink_metadata() {
                Ok(snapshot_md) => {
                    if md.file_type().is_dir() && snapshot_md.file_type().is_dir() {
                        stack.push(path);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => remove_entry(&path, &md)?,
                Err(e) => return Err(io_err("stat snapshot entry", &in_snapshot)(e)),
            }
        }
    }

    // pass 2: place every snapshot entry, replacing whatever type sits there now.
    let mut dir_modes: Vec<(PathBuf, u32)> = Vec::new();
    let root_md = snapshot
        .symlink_metadata()
        .map_err(io_err("stat snapshot", snapshot))?;
    dir_modes.push((workspace.to_path_buf(), root_md.permissions().mode()));

    let mut links = BTreeMap::new();
    let mut stack = vec![(snapshot.to_path_buf(), workspace.to_path_buf())];
    while let Some((src_dir, dst_dir)) = stack.pop() {
        let entries = fs::read_dir(&src_dir).map_err(io_err("read dir", &src_dir))?;
        for entry in entries {
            let entry = entry.map_err(io_err("read dir entry", &src_dir))?;
            let src = entry.path();
            let dst = dst_dir.join(entry.file_name());
            let md = entry.metadata().map_err(io_err("stat entry", &src))?;
            if let Ok(dst_md) = dst.symlink_metadata() {
                let same = match (kind_of(&md), kind_of(&dst_md)) {
                    (Ok(Kind::Dir), Ok(Kind::Dir)) => true,
                    (Ok(Kind::File), Ok(Kind::File)) => false,
                    (Ok(Kind::Symlink), Ok(Kind::Symlink)) => {
                        fs::read_link(&dst).ok() == fs::read_link(&src).ok()
                    }
                    (Ok(Kind::Fifo), Ok(Kind::Fifo)) => false,
                    _ => false,
                };
                if same {
                    if md.file_type().is_dir() {
                        dir_modes.push((dst.clone(), md.permissions().mode()));
                        stack.push((src, dst));
                    }
                    continue;
                }
                remove_entry(&dst, &dst_md)?;
            }
            place_entry(&src, &dst, &md, &mut stack, &mut dir_modes, &mut links)?;
        }
    }
    apply_dir_modes(&dir_modes)?;
    Ok(())
}

/// one indexed tree entry, with enough content identity to compare two trees without
/// trusting mtimes. used by the rewind dirty-workspace guard and by the tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// a regular file: length, permission bits, content digest
    File {
        /// file length in bytes
        len: u64,
        /// permission bits
        mode: u32,
        /// sha-256 of the content
        digest: [u8; 32],
    },
    /// a directory, by permission bits
    Dir {
        /// permission bits
        mode: u32,
    },
    /// a symlink, by its verbatim target
    Symlink {
        /// the link target, as stored
        target: PathBuf,
    },
    /// a fifo, by permission bits
    Fifo {
        /// permission bits
        mode: u32,
    },
}

/// index a tree into relative-path entries. never follows symlinks.
pub fn index_tree(root: &Path) -> Result<BTreeMap<PathBuf, Entry>, SnapshotError> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).map_err(io_err("read dir", &dir))?;
        for entry in entries {
            let entry = entry.map_err(io_err("read dir entry", &dir))?;
            let path = entry.path();
            let rel = rel_of(root, &path)?.to_path_buf();
            let md = entry.metadata().map_err(io_err("stat entry", &path))?;
            let mode = md.permissions().mode() & 0o7777;
            let entry =
                match kind_of(&md).map_err(|_| SnapshotError::UnsupportedEntry(path.clone()))? {
                    Kind::File => {
                        use sha2::Digest;
                        let mut file = fs::File::open(&path).map_err(io_err("open file", &path))?;
                        let mut digest = sha2::Sha256::new();
                        io::copy(&mut file, &mut digest).map_err(io_err("read file", &path))?;
                        Entry::File {
                            len: md.len(),
                            mode,
                            digest: digest.finalize().into(),
                        }
                    }
                    Kind::Dir => {
                        stack.push(path);
                        Entry::Dir { mode }
                    }
                    Kind::Symlink => Entry::Symlink {
                        target: fs::read_link(&path).map_err(io_err("read symlink", &path))?,
                    },
                    Kind::Fifo => Entry::Fifo { mode },
                };
            out.insert(rel, entry);
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Fixture {
        root: tempfile::TempDir,
    }

    impl Fixture {
        /// a mixed tree: a mode-pinned file, a nested dir, an empty dir, a symlink
        /// pointing outside the tree, and a fifo.
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let ws = root.path().join("ws");
            fs::create_dir_all(ws.join("src/nested")).unwrap();
            fs::create_dir(ws.join("empty-dir")).unwrap();
            fs::write(ws.join("README.md"), "hello workspace").unwrap();
            fs::set_permissions(ws.join("README.md"), fs::Permissions::from_mode(0o640)).unwrap();
            fs::write(ws.join("src/main.rs"), "fn main() {}\n").unwrap();
            fs::write(ws.join("src/nested/deep.txt"), "deep").unwrap();
            // a symlink pointing outside the tree: capture must keep it a link.
            let outside = root.path().join("outside-secret.txt");
            fs::write(&outside, "not part of the workspace").unwrap();
            symlink(&outside, ws.join("link-out")).unwrap();
            Self { root }
        }

        fn ws(&self) -> PathBuf {
            self.root.path().join("ws")
        }
    }

    #[test]
    fn a_burst_closes_as_one_step_at_quiescence() {
        let t0 = Instant::now();
        let mut clock = StepClock::new(STEP_WINDOW);
        // a burst with gaps well under the window: no boundary inside it
        for ms in [0, 40, 120, 200] {
            clock.on_mutation(t0 + Duration::from_millis(ms));
            assert_eq!(clock.poll(t0 + Duration::from_millis(ms)), None);
        }
        assert_eq!(
            clock.deadline(),
            Some(t0 + Duration::from_millis(200) + STEP_WINDOW)
        );
        // quiet for the window: the boundary closes step 1
        assert_eq!(
            clock.poll(t0 + Duration::from_millis(200) + STEP_WINDOW),
            Some(1)
        );
        assert_eq!(clock.deadline(), None);
        assert_eq!(clock.poll(t0 + Duration::from_secs(60)), None);
    }

    #[test]
    fn bursts_separated_by_quiet_become_separate_steps() {
        let t0 = Instant::now();
        let mut clock = StepClock::new(STEP_WINDOW);
        clock.on_mutation(t0);
        assert_eq!(clock.poll(t0 + STEP_WINDOW), Some(1));
        clock.on_mutation(t0 + Duration::from_secs(5));
        assert_eq!(
            clock.poll(t0 + Duration::from_secs(5) + STEP_WINDOW),
            Some(2)
        );
    }

    #[test]
    fn a_run_with_no_mutations_still_ends_on_a_boundary() {
        let t0 = Instant::now();
        let mut clock = StepClock::new(STEP_WINDOW);
        assert_eq!(clock.poll(t0 + Duration::from_secs(3600)), None);
        assert_eq!(clock.finish(), 1, "run end is always a boundary");
    }

    #[test]
    fn run_end_closes_a_step_even_mid_burst() {
        let t0 = Instant::now();
        let mut clock = StepClock::new(STEP_WINDOW);
        clock.on_mutation(t0);
        assert_eq!(clock.finish(), 1);
    }

    #[test]
    fn step_indices_are_monotonic_across_boundaries_and_run_end() {
        let t0 = Instant::now();
        let mut clock = StepClock::new(STEP_WINDOW);
        for burst in 0..3 {
            let at = t0 + Duration::from_secs(burst * 10);
            clock.on_mutation(at);
            assert_eq!(clock.poll(at + STEP_WINDOW), Some(burst + 1));
        }
        assert_eq!(clock.finish(), 4);
    }

    #[test]
    fn capture_preserves_a_mixed_tree_exactly() {
        let fx = Fixture::new();
        let dest = fx.root.path().join("snap");
        capture_copy(&fx.ws(), &dest).unwrap();

        assert_eq!(
            fs::read(dest.join("README.md")).unwrap(),
            b"hello workspace"
        );
        assert_eq!(
            fs::symlink_metadata(dest.join("README.md"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o640
        );
        assert!(dest.join("empty-dir").is_dir());
        assert_eq!(
            fs::read_dir(dest.join("empty-dir")).unwrap().count(),
            0,
            "empty directory must stay empty"
        );
        let link = fs::symlink_metadata(dest.join("link-out")).unwrap();
        assert!(link.file_type().is_symlink(), "link copied as a link");
        assert_eq!(
            fs::read_link(dest.join("link-out")).unwrap(),
            fx.root.path().join("outside-secret.txt")
        );
        assert_eq!(index_tree(&fx.ws()).unwrap(), index_tree(&dest).unwrap());
    }

    #[test]
    fn restore_makes_the_workspace_match_the_snapshot_exactly() {
        let fx = Fixture::new();
        let snap = fx.root.path().join("snap");
        capture_copy(&fx.ws(), &snap).unwrap();

        // the run mutates the tree: delete, modify, add, re-target a link, lose a dir.
        fs::remove_file(fx.ws().join("src/main.rs")).unwrap();
        fs::write(fx.ws().join("README.md"), "rewritten by the agent").unwrap();
        fs::write(fx.ws().join("new-file.txt"), "new").unwrap();
        fs::remove_dir_all(fx.ws().join("empty-dir")).unwrap();
        fs::remove_file(fx.ws().join("link-out")).unwrap();
        symlink("/tmp", fx.ws().join("link-out")).unwrap();

        restore_copy(&snap, &fx.ws()).unwrap();
        assert_eq!(index_tree(&snap).unwrap(), index_tree(&fx.ws()).unwrap());
        assert_eq!(
            fs::read(fx.ws().join("README.md")).unwrap(),
            b"hello workspace"
        );
        assert!(fx.ws().join("empty-dir").is_dir());
    }

    #[test]
    fn restore_recreates_a_missing_workspace_root() {
        let fx = Fixture::new();
        let snap = fx.root.path().join("snap");
        capture_copy(&fx.ws(), &snap).unwrap();
        fs::remove_dir_all(fx.ws()).unwrap();

        restore_copy(&snap, &fx.ws()).unwrap();
        assert_eq!(index_tree(&snap).unwrap(), index_tree(&fx.ws()).unwrap());
    }

    #[test]
    fn capture_refuses_to_clobber_an_existing_destination() {
        let fx = Fixture::new();
        let dest = fx.root.path().join("snap");
        fs::create_dir(&dest).unwrap();
        assert!(matches!(
            capture_copy(&fx.ws(), &dest),
            Err(SnapshotError::DestinationExists(_))
        ));
        // nothing was written into the existing dir
        assert_eq!(fs::read_dir(&dest).unwrap().count(), 0);
    }

    #[test]
    fn a_symlink_is_captured_as_a_link_never_followed() {
        let fx = Fixture::new();
        let dest = fx.root.path().join("snap");
        capture_copy(&fx.ws(), &dest).unwrap();
        match &index_tree(&dest).unwrap()[Path::new("link-out")] {
            Entry::Symlink { target } => {
                assert_eq!(target, &fx.root.path().join("outside-secret.txt"))
            }
            other => panic!("link-out must index as a symlink, got {other:?}"),
        }
        // the secret content exists only outside the capture
        assert!(!dest.join("outside-secret.txt").exists());
    }

    #[test]
    fn type_changes_between_snapshot_and_workspace_are_restored() {
        let fx = Fixture::new();
        let snap = fx.root.path().join("snap");
        capture_copy(&fx.ws(), &snap).unwrap();

        // file becomes a dir, dir becomes a symlink, symlink becomes a file.
        fs::remove_file(fx.ws().join("README.md")).unwrap();
        fs::create_dir(fx.ws().join("README.md")).unwrap();
        fs::remove_dir_all(fx.ws().join("src")).unwrap();
        symlink("/tmp", fx.ws().join("src")).unwrap();
        fs::remove_file(fx.ws().join("link-out")).unwrap();
        fs::write(fx.ws().join("link-out"), "now a file").unwrap();

        restore_copy(&snap, &fx.ws()).unwrap();
        assert_eq!(index_tree(&snap).unwrap(), index_tree(&fx.ws()).unwrap());
        assert!(fx.ws().join("README.md").is_file());
        assert!(fx.ws().join("src").is_dir());
        assert!(
            fs::symlink_metadata(fx.ws().join("link-out"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn hard_links_survive_capture_and_restore() {
        let fx = Fixture::new();
        fs::hard_link(fx.ws().join("README.md"), fx.ws().join("linked")).unwrap();
        let snap = fx.root.path().join("snap");
        capture_copy(&fx.ws(), &snap).unwrap();
        assert_eq!(
            fs::metadata(snap.join("README.md")).unwrap().ino(),
            fs::metadata(snap.join("linked")).unwrap().ino()
        );
        fs::remove_file(fx.ws().join("linked")).unwrap();
        restore_copy(&snap, &fx.ws()).unwrap();
        assert_eq!(
            fs::metadata(fx.ws().join("README.md")).unwrap().ino(),
            fs::metadata(fx.ws().join("linked")).unwrap().ino()
        );
    }

    #[test]
    fn restore_rejects_a_symlink_workspace_root() {
        let fx = Fixture::new();
        let snap = fx.root.path().join("snap");
        capture_copy(&fx.ws(), &snap).unwrap();
        let outside = fx.root.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), "safe").unwrap();
        let link = fx.root.path().join("workspace-link");
        symlink(&outside, &link).unwrap();
        assert!(matches!(
            restore_copy(&snap, &link),
            Err(SnapshotError::InvalidRoot(_))
        ));
        assert_eq!(fs::read(outside.join("keep")).unwrap(), b"safe");
    }

    #[test]
    fn restore_replaces_fifo_with_snapshot_mode() {
        let fx = Fixture::new();
        let fifo = fx.ws().join("pipe");
        create_fifo(&fifo, 0o600).unwrap();
        let snap = fx.root.path().join("snap");
        capture_copy(&fx.ws(), &snap).unwrap();
        fs::set_permissions(&fifo, fs::Permissions::from_mode(0o644)).unwrap();
        restore_copy(&snap, &fx.ws()).unwrap();
        assert_eq!(
            fs::symlink_metadata(fifo).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }

    #[test]
    fn unsupported_entries_fail_capture_closed() {
        let fx = Fixture::new();
        // a bound unix socket sits in the workspace; it cannot be reproduced.
        let _listener =
            std::os::unix::net::UnixListener::bind(fx.ws().join("daemon.sock")).unwrap();
        let dest = fx.root.path().join("snap");
        assert!(matches!(
            capture_copy(&fx.ws(), &dest),
            Err(SnapshotError::UnsupportedEntry(_))
        ));
    }

    #[test]
    fn fifos_round_trip_through_capture_and_restore() {
        let fx = Fixture::new();
        let fifo = fx.ws().join("pipe");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: c_path is a valid nul-terminated path inside a temp dir we own.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(rc, 0);

        let snap = fx.root.path().join("snap");
        capture_copy(&fx.ws(), &snap).unwrap();
        fs::remove_file(&fifo).unwrap();
        restore_copy(&snap, &fx.ws()).unwrap();

        assert!(
            fx.ws()
                .join("pipe")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_fifo()
        );
        assert_eq!(index_tree(&snap).unwrap(), index_tree(&fx.ws()).unwrap());
    }

    #[test]
    fn the_index_sees_content_changes_not_just_names() {
        let fx = Fixture::new();
        let before = index_tree(&fx.ws()).unwrap();
        fs::write(fx.ws().join("README.md"), "same name, new content").unwrap();
        let after = index_tree(&fx.ws()).unwrap();
        assert_ne!(before, after);
        assert_eq!(before.len(), after.len(), "no entry added or removed");
    }
}
