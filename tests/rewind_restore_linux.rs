//! linux integration tests for the rewind restore engine (`leash::snapshot::restore`,
//! ADR-0024 rules 16-22). every test starts from a real capture.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::Path;

use leash::snapshot::restore::{
    ChangeAction, RestoreContext, RestoreError, RestoreOp, apply, apply_with_context, chain_head,
    current_manifest, plan, recompute_chain, scan_current,
};
use leash::snapshot::store::{EntryKind, Limits, Manifest, StoreError, capture, load_manifest};

fn open_dir(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .unwrap()
}

/// create a directory. it keeps whatever default ACL its parent hands down (a `/tmp` with
/// default ACLs does), because capture and restore now carry ACLs.
fn create_dir(path: &Path) {
    fs::create_dir(path).unwrap();
}

fn set_mtime(path: &Path, sec: i64, nsec: i64) {
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let times = [libc::timespec {
        tv_sec: sec,
        tv_nsec: nsec,
    }; 2];
    // SAFETY: c_path is NUL-terminated and times points to a valid 2-element array.
    let rc = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    assert_eq!(
        rc,
        0,
        "utimensat failed: {}",
        std::io::Error::last_os_error()
    );
}

struct Fixture {
    tmp: tempfile::TempDir,
    ws: std::path::PathBuf,
    store_path: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("ws");
        let store_path = tmp.path().join("store");
        create_dir(&ws);
        fs::create_dir(&store_path).unwrap();
        Self {
            tmp,
            ws,
            store_path,
        }
    }

    fn ws_fd(&self) -> File {
        open_dir(&self.ws)
    }

    fn store_fd(&self) -> File {
        open_dir(&self.store_path)
    }

    fn outside(&self, name: &str) -> std::path::PathBuf {
        self.tmp.path().join(name)
    }

    fn capture(&self, step: u64) -> Manifest {
        capture(&self.ws_fd(), &self.store_fd(), step, &Limits::default()).unwrap();
        load_manifest(&self.store_fd(), step).unwrap().0
    }
}

fn digest(c: char) -> String {
    c.to_string().repeat(64)
}

#[test]
fn chain_head_is_deterministic_and_digest_sensitive() {
    let a = vec![(0u64, digest('a')), (1, digest('b'))];
    assert_eq!(chain_head(&a).unwrap(), chain_head(&a.clone()).unwrap());
    let swapped = vec![(0u64, digest('b')), (1, digest('a'))];
    assert_ne!(chain_head(&a).unwrap(), chain_head(&swapped).unwrap());
    assert_ne!(chain_head(&a).unwrap(), chain_head(&a[..1]).unwrap());
}

#[test]
fn chain_head_rejects_non_ascending_steps_and_malformed_digests() {
    for steps in [[1u64, 0], [0, 0], [3, 3]] {
        let d = vec![(steps[0], digest('a')), (steps[1], digest('b'))];
        let err = chain_head(&d).unwrap_err();
        assert!(matches!(err, StoreError::InvalidChain { .. }), "{err}");
    }
    for bad in [
        "".to_owned(),
        "abc".to_owned(),
        digest('A'),
        digest('g'),
        format!("{}0", digest('a')),
        format!("{}\n", digest('a')),
    ] {
        let err = chain_head(&[(0, bad.clone())]).unwrap_err();
        assert!(matches!(err, StoreError::InvalidChain { .. }), "{bad:?}");
    }
    assert!(chain_head(&[]).is_ok());
}

#[test]
fn chain_head_hashes_the_documented_line_format() {
    use sha2::{Digest, Sha256};
    let d = vec![(0u64, digest('a')), (12, digest('b'))];
    let text = format!("0:{}\n12:{}\n", digest('a'), digest('b'));
    let expected: String = Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(chain_head(&d).unwrap(), expected);
}

/// the digests of the first `steps` manifests already in the store.
fn capture_chain_digests_of(fx: &Fixture, steps: u64) -> Vec<(u64, String)> {
    (0..steps)
        .map(|step| {
            let (_, digest) = load_manifest(&fx.store_fd(), step).unwrap();
            (step, digest)
        })
        .collect()
}

fn capture_chain(fx: &Fixture, steps: u64) -> Vec<(u64, String)> {
    fs::write(fx.ws.join("a"), b"one").unwrap();
    let mut digests = Vec::new();
    for step in 0..steps {
        let p = capture(&fx.ws_fd(), &fx.store_fd(), step, &Limits::default()).unwrap();
        digests.push((step, p.manifest_digest));
        fs::write(fx.ws.join("a"), format!("v{step}")).unwrap();
    }
    digests
}

/// the committed step list of a run that committed steps `0..steps`.
fn committed(steps: u64) -> Vec<u64> {
    (0..steps).collect()
}

#[test]
fn recompute_chain_matches_digests_returned_by_capture() {
    let fx = Fixture::new();
    let digests = capture_chain(&fx, 3);
    let chain = recompute_chain(&fx.store_fd(), &committed(3)).unwrap();
    assert_eq!(chain.head, chain_head(&digests).unwrap());
    assert_eq!(chain.digests, digests);
    assert_eq!(chain.digest(1), Some(digests[1].1.as_str()));
    assert_eq!(chain.digest(3), None);
}

#[test]
fn recompute_chain_uses_bytes_on_disk_not_a_trace() {
    let fx = Fixture::new();
    let digests = capture_chain(&fx, 1);
    let honest = chain_head(&digests).unwrap();
    let path = fx.store_path.join("manifests/step-000000.json");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut bytes = fs::read(&path).unwrap();
    bytes.push(b'\n');
    fs::write(&path, bytes).unwrap();
    assert_ne!(
        recompute_chain(&fx.store_fd(), &committed(1)).unwrap().head,
        honest
    );
}

#[test]
fn a_committed_step_whose_manifest_was_deleted_is_an_error() {
    let fx = Fixture::new();
    capture_chain(&fx, 3);
    fs::remove_file(fx.store_path.join("manifests/step-000002.json")).unwrap();
    let err = recompute_chain(&fx.store_fd(), &committed(3)).unwrap_err();
    assert!(
        matches!(&err, StoreError::Io { path, .. } if path.contains("step-000002")),
        "{err}"
    );
    // the same store with step 2 not committed is a shorter, valid chain
    let digests = capture_chain_digests_of(&fx, 2);
    let after = recompute_chain(&fx.store_fd(), &committed(2)).unwrap();
    assert_eq!(after.head, chain_head(&digests).unwrap());
    assert_eq!(after.digest(2), None);
}

#[test]
fn a_committed_list_with_a_gap_names_the_missing_step() {
    let fx = Fixture::new();
    capture_chain(&fx, 3);
    let err = recompute_chain(&fx.store_fd(), &[0, 2]).unwrap_err();
    assert!(
        matches!(&err, StoreError::InvalidChain { reason } if reason.contains("step 1 is missing")),
        "{err}"
    );
}

#[test]
fn a_committed_list_that_starts_after_step_zero_names_step_zero() {
    let fx = Fixture::new();
    capture_chain(&fx, 2);
    let err = recompute_chain(&fx.store_fd(), &[1]).unwrap_err();
    assert!(
        matches!(&err, StoreError::InvalidChain { reason } if reason.contains("step 0 is missing")),
        "{err}"
    );
}

#[test]
fn an_orphan_manifest_is_not_in_the_chain() {
    let fx = Fixture::new();
    let digests = capture_chain(&fx, 2);
    let honest = chain_head(&digests).unwrap();
    // step 2 is published but its step event never became durable: it is not committed
    capture(&fx.ws_fd(), &fx.store_fd(), 2, &Limits::default()).unwrap();
    assert_eq!(
        recompute_chain(&fx.store_fd(), &committed(2)).unwrap().head,
        honest,
        "the chain over the committed steps ignores the orphan"
    );
    assert_ne!(
        recompute_chain(&fx.store_fd(), &committed(3)).unwrap().head,
        honest,
        "counting the orphan as committed would change the head"
    );
}

#[test]
fn current_manifest_captures_into_the_scratch_store() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("a"), b"one").unwrap();
    let scratch = fx.outside("scratch");
    fs::create_dir(&scratch).unwrap();
    let m = current_manifest(&fx.ws_fd(), &open_dir(&scratch), 7, &Limits::default()).unwrap();
    assert_eq!(m.step, 7);
    assert_eq!(m.entries.len(), 1);
}

#[test]
fn identical_manifests_plan_nothing() {
    let fx = Fixture::new();
    create_dir(&fx.ws.join("d"));
    fs::write(fx.ws.join("d/f"), b"x").unwrap();
    symlink("d/f", fx.ws.join("l")).unwrap();
    let m = fx.capture(0);
    let p = plan(&m, &m);
    assert!(p.is_empty());
    assert!(p.summary().is_empty());
}

#[test]
fn plan_orders_removals_deepest_first_and_mkdirs_shallowest_first() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("keep"), b"k").unwrap();
    let base = fx.capture(0);
    create_dir(&fx.ws.join("a"));
    create_dir(&fx.ws.join("a/b"));
    fs::write(fx.ws.join("a/b/f"), b"f").unwrap();
    let grown = fx.capture(1);

    let p = plan(&grown, &base);
    let removed: Vec<&str> = p
        .ops
        .iter()
        .filter_map(|op| match op {
            RestoreOp::Remove { path, .. } => Some(path.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(removed, ["a/b/f", "a/b", "a"]);

    let p = plan(&base, &grown);
    let mkdirs: Vec<&str> = p
        .ops
        .iter()
        .filter_map(|op| match op {
            RestoreOp::Mkdir { path } => Some(path.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(mkdirs, ["a", "a/b"]);
    assert!(p.ops.contains(&RestoreOp::WriteFile {
        path: "a/b/f".into()
    }));
    let finalize: Vec<&str> = p.finalize_dirs.iter().map(|d| d.path.as_str()).collect();
    assert_eq!(finalize, ["a/b", "a"]);
}

#[test]
fn plan_distinguishes_content_metadata_symlink_and_link_changes() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("content"), b"old").unwrap();
    fs::write(fx.ws.join("meta"), b"same").unwrap();
    fs::write(fx.ws.join("pair-a"), b"pair").unwrap();
    fs::hard_link(fx.ws.join("pair-a"), fx.ws.join("pair-b")).unwrap();
    symlink("one", fx.ws.join("lnk")).unwrap();
    let base = fx.capture(0);

    fs::write(fx.ws.join("content"), b"new").unwrap();
    fs::set_permissions(fx.ws.join("meta"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(fx.ws.join("pair-b")).unwrap();
    fs::write(fx.ws.join("pair-b"), b"pair").unwrap();
    fs::remove_file(fx.ws.join("lnk")).unwrap();
    symlink("two", fx.ws.join("lnk")).unwrap();
    let now = fx.capture(1);

    let p = plan(&now, &base);
    assert!(p.ops.contains(&RestoreOp::WriteFile {
        path: "content".into()
    }));
    assert!(p.ops.contains(&RestoreOp::Symlink { path: "lnk".into() }));
    // the broken link group is rebuilt: first member written, second linked from it
    assert!(p.ops.contains(&RestoreOp::WriteFile {
        path: "pair-a".into()
    }));
    assert!(p.ops.contains(&RestoreOp::LinkFile {
        path: "pair-b".into(),
        source: "pair-a".into()
    }));
    let meta = p
        .ops
        .iter()
        .find_map(|op| match op {
            RestoreOp::SetMetadata { path, change } if path == "meta" => Some(*change),
            _ => None,
        })
        .unwrap();
    assert!(meta.mode);
    assert!(!meta.owner);

    let s = p.summary();
    assert_eq!(s.files_written, 2);
    assert_eq!(s.hard_links, 1);
    assert_eq!(s.symlinks, 1);
    assert!(
        s.changes
            .iter()
            .any(|c| c.action == ChangeAction::Metadata && c.path == "meta")
    );
    let text = s.to_string();
    assert!(text.contains("write content"), "{text}");
}

#[test]
fn plan_turns_a_kind_change_into_remove_then_create() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("x"), b"file").unwrap();
    create_dir(&fx.ws.join("y"));
    fs::write(fx.ws.join("y/inner"), b"i").unwrap();
    let base = fx.capture(0);
    fs::remove_file(fx.ws.join("x")).unwrap();
    create_dir(&fx.ws.join("x"));
    fs::remove_file(fx.ws.join("y/inner")).unwrap();
    fs::remove_dir(fx.ws.join("y")).unwrap();
    fs::write(fx.ws.join("y"), b"now a file").unwrap();
    set_mtime(&fx.ws.join("y"), 1, 0);
    let now = fx.capture(1);

    let p = plan(&now, &base);
    let pos = |needle: &RestoreOp| p.ops.iter().position(|op| op == needle).unwrap();
    let rm_x = pos(&RestoreOp::Remove {
        path: "x".into(),
        kind: EntryKind::Dir,
    });
    let write_x = pos(&RestoreOp::WriteFile { path: "x".into() });
    assert!(rm_x < write_x);
    let rm_y = pos(&RestoreOp::Remove {
        path: "y".into(),
        kind: EntryKind::File,
    });
    let mkdir_y = pos(&RestoreOp::Mkdir { path: "y".into() });
    assert!(rm_y < mkdir_y);
    assert!(
        mkdir_y
            < pos(&RestoreOp::WriteFile {
                path: "y/inner".into()
            })
    );
}

fn is_root() -> bool {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// under root, assert that `apply` refuses and return true so the caller skips the rest.
/// as a normal user this does nothing and returns false.
fn root_refused(fx: &Fixture, target: &Manifest) -> bool {
    if !is_root() {
        return false;
    }
    let err = apply(&fx.ws_fd(), &fx.store_fd(), target, &plan(target, target)).unwrap_err();
    assert!(matches!(err, RestoreError::RunningAsRoot), "{err}");
    skipped_as_root();
    true
}

/// a test that cannot run as root says so, and fails under `LEASH_REQUIRE_XATTR=1` (set in
/// CI), so a root run cannot pass the xattr and ACL restore tests by skipping them.
fn skipped_as_root() {
    assert!(
        std::env::var("LEASH_REQUIRE_XATTR").as_deref() != Ok("1"),
        "LEASH_REQUIRE_XATTR=1 but this runs as root, and restore refuses root, so the test would be skipped"
    );
    eprintln!("SKIPPED restore coverage: running as root, which restore refuses");
}

/// like `root_refused` for a test that has not built its target yet: under root it captures
/// a probe workspace and asserts the refusal, as a normal user it does nothing.
fn root_guard(fx: &Fixture) -> bool {
    if !is_root() {
        return false;
    }
    fs::write(fx.ws.join("probe"), b"probe").unwrap();
    let target = fx.capture(0);
    root_refused(fx, &target)
}

const HOSTILE_NAME: &str = "evil\nA  fake-line \u{1b}[2Jname";

fn assert_one_line_escaped(text: &str) {
    assert!(!text.contains('\u{1b}'), "raw escape in {text:?}");
    assert!(!text.contains("\nA  fake-line"), "spoofed line in {text:?}");
}

#[test]
fn the_change_summary_escapes_hostile_paths_on_one_line() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("keep"), b"k").unwrap();
    let base = fx.capture(0);
    fs::write(fx.ws.join(HOSTILE_NAME), b"x").unwrap();
    fs::hard_link(fx.ws.join(HOSTILE_NAME), fx.ws.join("peer")).unwrap();
    let now = fx.capture(1);

    // removal of the hostile names, and their creation including a link detail
    for (from, to) in [(&now, &base), (&base, &now)] {
        let summary = plan(from, to).summary();
        let text = summary.to_string();
        assert_one_line_escaped(&text);
        assert!(text.contains("\\n"), "{text:?}");
        // header line plus one line per change, nothing injected
        assert_eq!(text.lines().count(), summary.changes.len() + 1, "{text:?}");
    }
}

#[test]
fn restore_errors_escape_hostile_paths() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("keep"), b"k").unwrap();
    let base = fx.capture(0);
    if root_refused(&fx, &base) {
        return;
    }
    let mut p = plan(&base, &base);
    p.ops.push(RestoreOp::SetMetadata {
        path: HOSTILE_NAME.into(),
        change: Default::default(),
    });
    let err = apply(&fx.ws_fd(), &fx.store_fd(), &base, &p).unwrap_err();
    let text = err.to_string();
    assert!(matches!(err, RestoreError::InvalidPlan { .. }), "{text}");
    assert_one_line_escaped(&text);
    assert!(text.contains("\\n"), "{text:?}");
}

/// set a user xattr. returns false, after saying why, only when the filesystem does not
/// support user xattrs; `LEASH_REQUIRE_XATTR=1` (set in CI) turns that into a failure so the
/// xattr paths cannot go untested unnoticed.
fn try_set_user_xattr(path: &Path, name: &str, value: &[u8]) -> bool {
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let c_name = CString::new(name).unwrap();
    // SAFETY: c_path and c_name are NUL-terminated and value is a valid byte slice.
    let rc = unsafe {
        libc::setxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if rc == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error();
    assert!(
        matches!(err.raw_os_error(), Some(libc::EOPNOTSUPP | libc::ENOSYS)),
        "unexpected setxattr failure: {err}"
    );
    assert!(
        std::env::var("LEASH_REQUIRE_XATTR").as_deref() != Ok("1"),
        "LEASH_REQUIRE_XATTR=1 but {} does not support user xattrs: {err}",
        path.display()
    );
    eprintln!(
        "SKIPPED xattr coverage: {} does not support user xattrs ({err}); set LEASH_REQUIRE_XATTR=1 to fail instead",
        path.display()
    );
    false
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// names of the entries directly inside `dir`, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn round_trip_restores_the_captured_workspace_exactly() {
    let fx = Fixture::new();
    if root_guard(&fx) {
        return;
    }
    let ws = &fx.ws;

    fs::write(ws.join("a.txt"), b"hello").unwrap();
    set_mtime(&ws.join("a.txt"), 1_700_000_000, 123_456_789);
    let xattrs = try_set_user_xattr(&ws.join("a.txt"), "user.x", b"1");
    fs::write(ws.join("exec.sh"), b"#!/bin/sh\n").unwrap();
    chmod(&ws.join("exec.sh"), 0o755);
    set_mtime(&ws.join("exec.sh"), 1_700_000_001, 0);
    fs::write(ws.join("setuid"), b"s").unwrap();
    chmod(&ws.join("setuid"), 0o4755);
    set_mtime(&ws.join("setuid"), 1_700_000_002, 5);
    create_dir(&ws.join("d"));
    fs::write(ws.join("d/inner.txt"), b"inner").unwrap();
    create_dir(&ws.join("d/deep"));
    fs::write(ws.join("d/deep/x.txt"), b"deep").unwrap();
    chmod(&ws.join("d"), 0o750);
    create_dir(&ws.join("empty"));
    create_dir(&ws.join("ro"));
    fs::write(ws.join("ro/f"), b"readonly").unwrap();
    chmod(&ws.join("ro/f"), 0o400);
    chmod(&ws.join("ro"), 0o500);
    fs::write(ws.join("filetodir"), b"was a file").unwrap();
    create_dir(&ws.join("dirtofile"));
    fs::write(ws.join("dirtofile/child"), b"c").unwrap();
    symlink("a.txt", ws.join("lnk")).unwrap();
    set_mtime(&ws.join("lnk"), 1_700_000_003, 7);
    fs::write(ws.join("h1"), b"linked").unwrap();
    fs::hard_link(ws.join("h1"), ws.join("h2")).unwrap();
    fs::write(ws.join("solo"), b"solo").unwrap();
    // pin every mtime so the comparison is not about wall-clock luck
    for (i, name) in [
        "h1",
        "solo",
        "d/inner.txt",
        "d/deep/x.txt",
        "ro/f",
        "filetodir",
    ]
    .iter()
    .enumerate()
    {
        set_mtime(&ws.join(name), 1_600_000_000 + i as i64, 11);
    }
    for (i, name) in ["d/deep", "d", "empty", "dirtofile/child", "dirtofile", "ro"]
        .iter()
        .enumerate()
    {
        set_mtime(&ws.join(name), 1_500_000_000 + i as i64, 22);
    }
    let base = fx.capture(0);

    // mutate: edit, add, delete, modes, mtimes, kind swaps, link changes, xattrs
    fs::write(ws.join("a.txt"), b"hello, edited").unwrap();
    set_mtime(&ws.join("a.txt"), 1_800_000_000, 1);
    if xattrs {
        try_set_user_xattr(&ws.join("a.txt"), "user.x", b"2");
        try_set_user_xattr(&ws.join("a.txt"), "user.y", b"extra");
        try_set_user_xattr(&ws.join("d"), "user.dir", b"d");
    }
    chmod(&ws.join("exec.sh"), 0o600);
    set_mtime(&ws.join("setuid"), 1_800_000_001, 0);
    fs::write(ws.join("added.txt"), b"added").unwrap();
    create_dir(&ws.join("newdir"));
    fs::write(ws.join("newdir/n"), b"n").unwrap();
    fs::remove_file(ws.join("d/inner.txt")).unwrap();
    fs::remove_file(ws.join("d/deep/x.txt")).unwrap();
    fs::remove_dir(ws.join("d/deep")).unwrap();
    chmod(&ws.join("ro"), 0o700);
    fs::write(ws.join("ro/new"), b"new in ro").unwrap();
    chmod(&ws.join("ro"), 0o500);
    fs::remove_file(ws.join("filetodir")).unwrap();
    create_dir(&ws.join("filetodir"));
    fs::write(ws.join("filetodir/inside"), b"i").unwrap();
    fs::remove_file(ws.join("dirtofile/child")).unwrap();
    fs::remove_dir(ws.join("dirtofile")).unwrap();
    fs::write(ws.join("dirtofile"), b"now a file").unwrap();
    fs::remove_file(ws.join("lnk")).unwrap();
    symlink("added.txt", ws.join("lnk")).unwrap();
    fs::remove_file(ws.join("h2")).unwrap();
    fs::write(ws.join("h2"), b"linked").unwrap();
    fs::hard_link(ws.join("solo"), ws.join("solo-link")).unwrap();
    set_mtime(&ws.join("empty"), 1_900_000_000, 0);
    let now = fx.capture(1);
    assert_ne!(now.entries, base.entries);

    let p = plan(&now, &base);
    assert!(!p.summary().is_empty());
    let stats = apply(&fx.ws_fd(), &fx.store_fd(), &base, &p).unwrap();
    assert!(stats.files_written > 0 && stats.removed > 0 && stats.hard_links > 0);

    let after = fx.capture(2);
    assert_eq!(after.entries, base.entries);
    assert!(plan(&after, &base).is_empty());
    assert_eq!(fs::read(ws.join("a.txt")).unwrap(), b"hello");
    assert_eq!(fs::read_link(ws.join("lnk")).unwrap(), Path::new("a.txt"));
    assert!(!names(ws).iter().any(|n| n.starts_with(".leash-restore")));

    chmod(&ws.join("ro"), 0o700);
}

#[test]
fn hostile_manifest_paths_are_refused_before_any_write() {
    let fx = Fixture::new();
    if root_guard(&fx) {
        return;
    }
    fs::write(fx.ws.join("keep"), b"keep").unwrap();
    let base = fx.capture(0);
    fs::write(fx.ws.join("extra"), b"extra").unwrap();
    let now = fx.capture(1);

    for bad in ["../escape", "/abs/escape", "a/../../escape", "a//b", "./x"] {
        let mut forged = base.clone();
        forged.entries[0].path = bad.to_owned();
        // the step matches the file it is loaded from, so only the path can be at fault
        forged.step = 9;
        // as a stored manifest: refused when loaded, naming the bad path
        let json = serde_json::to_vec(&forged).unwrap();
        let mpath = fx.store_path.join("manifests/step-000009.json");
        fs::write(&mpath, &json).unwrap();
        let err = load_manifest(&fx.store_fd(), 9).unwrap_err();
        assert!(
            matches!(&err, StoreError::InvalidManifest { reason }
                if reason.contains(&format!("{bad:?}")) && !reason.contains("step")),
            "{bad}: {err}"
        );
        fs::remove_file(&mpath).unwrap();

        // as an in-memory target: refused by apply before it touches the workspace
        let p = plan(&now, &forged);
        let err = apply(&fx.ws_fd(), &fx.store_fd(), &forged, &p).unwrap_err();
        assert!(
            matches!(&err, RestoreError::Store(StoreError::InvalidManifest { reason })
                if reason.contains(&format!("{bad:?}"))),
            "{bad}: {err}"
        );
        assert_eq!(names(&fx.ws), ["extra", "keep"]);
        assert!(!fx.outside("escape").exists());
    }
}

#[test]
fn a_plan_path_that_escapes_is_refused_before_any_write() {
    let fx = Fixture::new();
    if root_guard(&fx) {
        return;
    }
    fs::write(fx.ws.join("keep"), b"keep").unwrap();
    let base = fx.capture(0);
    fs::write(fx.outside("victim"), b"victim").unwrap();
    let mut p = plan(&base, &base);
    p.ops.push(RestoreOp::Remove {
        path: "../victim".into(),
        kind: EntryKind::File,
    });
    let err = apply(&fx.ws_fd(), &fx.store_fd(), &base, &p).unwrap_err();
    assert!(matches!(err, RestoreError::Store(_)), "{err}");
    assert_eq!(fs::read(fx.outside("victim")).unwrap(), b"victim");
}

#[test]
fn a_tampered_object_fails_before_the_destination_is_replaced() {
    let fx = Fixture::new();
    if root_guard(&fx) {
        return;
    }
    fs::write(fx.ws.join("f"), b"original").unwrap();
    fs::write(fx.ws.join("g"), b"gee").unwrap();
    let base = fx.capture(0);
    fs::write(fx.ws.join("f"), b"changed").unwrap();
    let now = fx.capture(1);

    let sha = base
        .entries
        .iter()
        .find(|e| e.path == "f")
        .unwrap()
        .sha256
        .clone()
        .unwrap();
    let object = fx.store_path.join(format!("objects/{}/{sha}", &sha[..2]));
    chmod(&object, 0o600);
    fs::write(&object, b"evil bytes").unwrap();

    let p = plan(&now, &base);
    let err = apply(&fx.ws_fd(), &fx.store_fd(), &base, &p).unwrap_err();
    assert!(
        matches!(err, RestoreError::Store(StoreError::ObjectCorrupt { .. })),
        "{err}"
    );
    assert_eq!(fs::read(fx.ws.join("f")).unwrap(), b"changed");
    assert_eq!(names(&fx.ws), ["f", "g"]);
}

#[test]
fn a_forged_size_fails_during_the_copy_and_leaves_no_temp_entries() {
    let fx = Fixture::new();
    if root_guard(&fx) {
        return;
    }
    fs::write(fx.ws.join("f"), b"original").unwrap();
    fs::write(fx.ws.join("g"), b"gee").unwrap();
    let base = fx.capture(0);
    fs::write(fx.ws.join("f"), b"changed").unwrap();
    let now = fx.capture(1);

    // the object is intact and hashes right; only the manifest's size is wrong, so the
    // failure comes from the copy, after the temporary file exists
    let mut forged = base.clone();
    for e in &mut forged.entries {
        if e.path == "f" {
            e.size = e.size.map(|s| s + 1);
        }
    }
    forged.totals.total_bytes += 1;
    let p = plan(&now, &forged);
    assert!(p.ops.contains(&RestoreOp::WriteFile { path: "f".into() }));
    let err = apply(&fx.ws_fd(), &fx.store_fd(), &forged, &p).unwrap_err();
    assert!(
        matches!(&err, RestoreError::SizeMismatch { path, expected: 9, actual: 8 } if path == "f"),
        "{err}"
    );
    assert_eq!(fs::read(fx.ws.join("f")).unwrap(), b"changed");
    assert_eq!(names(&fx.ws), ["f", "g"]);
}

#[test]
fn a_directory_swapped_for_a_symlink_after_planning_is_not_followed() {
    let fx = Fixture::new();
    if root_guard(&fx) {
        return;
    }
    create_dir(&fx.ws.join("sub"));
    fs::write(fx.ws.join("sub/file"), b"orig").unwrap();
    let base = fx.capture(0);
    fs::write(fx.ws.join("sub/file"), b"mod").unwrap();
    let now = fx.capture(1);
    let p = plan(&now, &base);

    let outside = fx.outside("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("file"), b"outside").unwrap();
    fs::remove_file(fx.ws.join("sub/file")).unwrap();
    fs::remove_dir(fx.ws.join("sub")).unwrap();
    symlink(&outside, fx.ws.join("sub")).unwrap();

    let err = apply(&fx.ws_fd(), &fx.store_fd(), &base, &p).unwrap_err();
    assert!(matches!(err, RestoreError::UnsafePath { .. }), "{err}");
    assert_eq!(fs::read(outside.join("file")).unwrap(), b"outside");
    assert_eq!(names(&outside), ["file"]);
    assert!(
        fs::symlink_metadata(fx.ws.join("sub"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn an_outside_hard_link_is_never_written_through() {
    let fx = Fixture::new();
    if root_guard(&fx) {
        return;
    }
    fs::write(fx.ws.join("f"), b"orig").unwrap();
    let outside = fx.outside("outside-link");
    fs::hard_link(fx.ws.join("f"), &outside).unwrap();
    let base = fx.capture(0);
    // the agent edits through the shared inode, so the outside name changes too
    fs::write(fx.ws.join("f"), b"evil").unwrap();
    assert_eq!(fs::read(&outside).unwrap(), b"evil");
    let now = fx.capture(1);

    let p = plan(&now, &base);
    apply(&fx.ws_fd(), &fx.store_fd(), &base, &p).unwrap();
    assert_eq!(fs::read(fx.ws.join("f")).unwrap(), b"orig");
    assert_eq!(fs::read(&outside).unwrap(), b"evil");
}

#[test]
fn root_is_refused_through_the_context_seam() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("f"), b"orig").unwrap();
    let base = fx.capture(0);
    fs::write(fx.ws.join("f"), b"changed").unwrap();
    let now = fx.capture(1);
    let p = plan(&now, &base);
    let ctx = RestoreContext {
        euid: 0,
        egid: 0,
        groups: vec![],
    };
    let err = apply_with_context(&fx.ws_fd(), &fx.store_fd(), &base, &p, &ctx).unwrap_err();
    assert!(matches!(err, RestoreError::RunningAsRoot), "{err}");
    assert_eq!(fs::read(fx.ws.join("f")).unwrap(), b"changed");
}

#[test]
fn an_owner_this_process_cannot_create_fails_in_preflight_naming_the_path() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("f"), b"orig").unwrap();
    fs::write(fx.ws.join("extra"), b"extra").unwrap();
    let base = fx.capture(0);
    fs::remove_file(fx.ws.join("extra")).unwrap();
    fs::write(fx.ws.join("f"), b"changed").unwrap();
    fs::write(fx.ws.join("later"), b"later").unwrap();
    let now = fx.capture(1);

    let me = RestoreContext::from_process().unwrap();
    // pretend the process is someone else, so the manifest owner is out of reach
    let ctx = RestoreContext {
        euid: me.euid.wrapping_add(1).max(1),
        egid: me.egid,
        groups: me.groups.clone(),
    };
    let p = plan(&now, &base);
    let err = apply_with_context(&fx.ws_fd(), &fx.store_fd(), &base, &p, &ctx).unwrap_err();
    match err {
        RestoreError::Ownership { path, .. } => assert!(path == "f" || path == "extra", "{path}"),
        other => panic!("expected an ownership error, got {other}"),
    }
    // nothing was written, not even the removal that comes first in the plan
    assert_eq!(names(&fx.ws), ["f", "later"]);
    assert_eq!(fs::read(fx.ws.join("f")).unwrap(), b"changed");
}

// ---- hard links outside the workspace, ownership preflight, leftovers, deep trees ----

fn mtime_of(path: &Path) -> (i64, i64) {
    use std::os::unix::fs::MetadataExt;
    let m = fs::symlink_metadata(path).unwrap();
    (m.mtime(), m.mtime_nsec())
}

fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

fn ino_of(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    fs::symlink_metadata(path).unwrap().ino()
}

fn nlink_of(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    fs::symlink_metadata(path).unwrap().nlink()
}

#[test]
fn a_metadata_only_restore_never_writes_through_an_outside_hard_link() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("f"), b"orig").unwrap();
    chmod(&fx.ws.join("f"), 0o644);
    set_mtime(&fx.ws.join("f"), 1_600_000_000, 5);
    let outside = fx.outside("outside-link");
    fs::hard_link(fx.ws.join("f"), &outside).unwrap();
    let base = fx.capture(0);
    if root_refused(&fx, &base) {
        return;
    }
    // the agent changes only metadata, through the shared inode, so the outside name
    // changes too
    chmod(&fx.ws.join("f"), 0o600);
    set_mtime(&fx.ws.join("f"), 1_700_000_000, 9);
    let now = fx.capture(1);

    let p = plan(&now, &base);
    assert!(
        p.ops
            .iter()
            .any(|op| matches!(op, RestoreOp::SetMetadata { path, .. } if path == "f"))
    );
    assert!(
        !p.ops
            .iter()
            .any(|op| matches!(op, RestoreOp::WriteFile { .. }))
    );
    apply(&fx.ws_fd(), &fx.store_fd(), &base, &p).unwrap();

    assert_eq!(fs::read(fx.ws.join("f")).unwrap(), b"orig");
    assert_eq!(mode_of(&fx.ws.join("f")), 0o644);
    assert_eq!(mtime_of(&fx.ws.join("f")), (1_600_000_000, 5));
    // the outside name keeps exactly what the agent left it
    assert_eq!(mode_of(&outside), 0o600);
    assert_eq!(mtime_of(&outside), (1_700_000_000, 9));
    assert_ne!(ino_of(&fx.ws.join("f")), ino_of(&outside));
    assert!(plan(&fx.capture(2), &base).is_empty());
}

#[test]
fn a_metadata_only_restore_relinks_the_group_off_an_outside_hard_link() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("a"), b"pair").unwrap();
    fs::hard_link(fx.ws.join("a"), fx.ws.join("b")).unwrap();
    chmod(&fx.ws.join("a"), 0o644);
    set_mtime(&fx.ws.join("a"), 1_600_000_000, 5);
    let outside = fx.outside("outside-link");
    fs::hard_link(fx.ws.join("a"), &outside).unwrap();
    let base = fx.capture(0);
    if root_refused(&fx, &base) {
        return;
    }
    chmod(&fx.ws.join("a"), 0o600);
    set_mtime(&fx.ws.join("a"), 1_700_000_000, 9);
    let now = fx.capture(1);

    let p = plan(&now, &base);
    apply(&fx.ws_fd(), &fx.store_fd(), &base, &p).unwrap();

    // both workspace names still share one inode, which is no longer the outside one
    assert_eq!(ino_of(&fx.ws.join("a")), ino_of(&fx.ws.join("b")));
    assert_eq!(nlink_of(&fx.ws.join("a")), 2);
    assert_ne!(ino_of(&fx.ws.join("a")), ino_of(&outside));
    assert_eq!(mode_of(&fx.ws.join("b")), 0o644);
    assert_eq!(mtime_of(&fx.ws.join("b")), (1_600_000_000, 5));
    assert_eq!(mode_of(&outside), 0o600);
    assert_eq!(mtime_of(&outside), (1_700_000_000, 9));
    let after = fx.capture(2);
    assert_eq!(after.entries, base.entries);
}

#[test]
fn a_symlink_metadata_fix_never_touches_an_outside_hard_link_of_the_symlink() {
    let fx = Fixture::new();
    symlink("target", fx.ws.join("lnk")).unwrap();
    set_mtime(&fx.ws.join("lnk"), 1_600_000_000, 5);
    let outside = fx.outside("outside-lnk");
    fs::hard_link(fx.ws.join("lnk"), &outside).unwrap();
    let base = fx.capture(0);
    if root_refused(&fx, &base) {
        return;
    }
    set_mtime(&fx.ws.join("lnk"), 1_700_000_000, 9);
    let now = fx.capture(1);

    let p = plan(&now, &base);
    assert!(
        p.ops
            .iter()
            .any(|op| matches!(op, RestoreOp::SetMetadata { path, .. } if path == "lnk"))
    );
    apply(&fx.ws_fd(), &fx.store_fd(), &base, &p).unwrap();

    assert_eq!(
        fs::read_link(fx.ws.join("lnk")).unwrap(),
        Path::new("target")
    );
    assert_eq!(mtime_of(&fx.ws.join("lnk")), (1_600_000_000, 5));
    assert_eq!(mtime_of(&outside), (1_700_000_000, 9));
    assert_ne!(ino_of(&fx.ws.join("lnk")), ino_of(&outside));
}

#[test]
fn metadata_of_an_entry_owned_by_someone_else_fails_in_preflight() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("g"), b"gee").unwrap();
    create_dir(&fx.ws.join("d"));
    fs::write(fx.ws.join("d/inner"), b"i").unwrap();
    let g_mode = mode_of(&fx.ws.join("g"));
    let base = fx.capture(0);
    if root_refused(&fx, &base) {
        return;
    }
    let me = RestoreContext::from_process().unwrap();
    // pretend to be another uid; only metadata differs, and the owner does not change
    let ctx = RestoreContext {
        euid: me.euid.wrapping_add(1).max(1),
        egid: me.egid,
        groups: me.groups.clone(),
    };

    chmod(&fx.ws.join("g"), 0o600);
    let now = fx.capture(1);
    let p = plan(&now, &base);
    let err = apply_with_context(&fx.ws_fd(), &fx.store_fd(), &base, &p, &ctx).unwrap_err();
    assert!(
        matches!(&err, RestoreError::NotOwner { path, .. } if path == "g"),
        "{err}"
    );
    assert_eq!(mode_of(&fx.ws.join("g")), 0o600);

    // an existing directory whose mtime alone differs is checked the same way
    chmod(&fx.ws.join("g"), g_mode);
    set_mtime(&fx.ws.join("d"), 1_700_000_000, 1);
    let now = fx.capture(2);
    let p = plan(&now, &base);
    let err = apply_with_context(&fx.ws_fd(), &fx.store_fd(), &base, &p, &ctx).unwrap_err();
    assert!(
        matches!(&err, RestoreError::NotOwner { path, .. } if path == "d"),
        "{err}"
    );
    assert_eq!(mtime_of(&fx.ws.join("d")), (1_700_000_000, 1));
}

#[test]
fn a_contents_change_in_a_directory_owned_by_someone_else_fails_in_preflight() {
    let fx = Fixture::new();
    create_dir(&fx.ws.join("d"));
    fs::write(fx.ws.join("d/inner"), b"i").unwrap();
    let base = fx.capture(0);
    if root_refused(&fx, &base) {
        return;
    }
    fs::write(fx.ws.join("d/extra"), b"x").unwrap();
    let now = fx.capture(1);
    let p = plan(&now, &base);
    // the directory is in the plan only because its contents change; as another uid the
    // final mode and mtime pass could not run, so nothing may be removed first
    let me = RestoreContext::from_process().unwrap();
    let ctx = RestoreContext {
        euid: me.euid.wrapping_add(1).max(1),
        egid: me.egid,
        groups: me.groups.clone(),
    };
    let err = apply_with_context(&fx.ws_fd(), &fx.store_fd(), &base, &p, &ctx).unwrap_err();
    assert!(matches!(err, RestoreError::NotOwner { .. }), "{err}");
    assert_eq!(names(&fx.ws.join("d")), ["extra", "inner"]);
}

#[test]
fn leftover_temp_names_in_touched_directories_are_removed_before_applying() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("f"), b"orig").unwrap();
    create_dir(&fx.ws.join("d"));
    fs::write(fx.ws.join("d/g"), b"gee").unwrap();
    create_dir(&fx.ws.join("untouched"));
    fs::write(fx.ws.join("untouched/h"), b"h").unwrap();
    // a snapshot can legitimately contain a file with the temp prefix, which must stay
    fs::write(fx.ws.join(".leash-restore-kept"), b"mine").unwrap();
    let base = fx.capture(0);
    if root_refused(&fx, &base) {
        return;
    }
    fs::write(fx.ws.join("f"), b"changed").unwrap();
    fs::write(fx.ws.join("d/g"), b"changed").unwrap();
    let now = fx.capture(1);

    // a killed apply left these behind after the plan was computed
    fs::write(fx.ws.join(".leash-restore-dead"), b"partial").unwrap();
    symlink("/nonexistent", fx.ws.join("d/.leash-restore-dead2")).unwrap();
    fs::write(fx.ws.join("untouched/.leash-restore-dead3"), b"partial").unwrap();

    let p = plan(&now, &base);
    apply(&fx.ws_fd(), &fx.store_fd(), &base, &p).unwrap();
    assert_eq!(
        names(&fx.ws),
        [".leash-restore-kept", "d", "f", "untouched"]
    );
    assert_eq!(names(&fx.ws.join("d")), ["g"]);
    // a directory the plan does not touch is left alone
    assert_eq!(
        names(&fx.ws.join("untouched")),
        [".leash-restore-dead3", "h"]
    );
    assert_eq!(
        fs::read(fx.ws.join(".leash-restore-kept")).unwrap(),
        b"mine"
    );
}

#[test]
fn a_real_root_is_refused_even_when_the_context_claims_another_uid() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("f"), b"orig").unwrap();
    let base = fx.capture(0);
    fs::write(fx.ws.join("f"), b"changed").unwrap();
    let now = fx.capture(1);
    let me = RestoreContext::from_process().unwrap();
    let ctx = RestoreContext {
        euid: me.euid.max(1000),
        egid: me.egid,
        groups: me.groups.clone(),
    };
    let result = apply_with_context(&fx.ws_fd(), &fx.store_fd(), &base, &plan(&now, &base), &ctx);
    if is_root() {
        assert!(matches!(result, Err(RestoreError::RunningAsRoot)));
        assert_eq!(fs::read(fx.ws.join("f")).unwrap(), b"changed");
    } else {
        // not root, so only the seam is exercised and this context may fail on ownership
        assert!(!matches!(result, Err(RestoreError::RunningAsRoot)));
    }
}

fn deep_names(levels: usize) -> Vec<String> {
    (0..levels)
        .map(|i| format!("{i:02}{}", "d".repeat(98)))
        .collect()
}

/// open (creating when `create`) the directory chain `names` one `openat` at a time, so
/// the full path is never handed to the kernel at once.
fn deep_dir(ws: &File, names: &[String], create: bool) -> File {
    use std::os::fd::{AsRawFd, FromRawFd};
    let mut cur = ws.try_clone().unwrap();
    for name in names {
        let c_name = CString::new(name.as_str()).unwrap();
        if create {
            // SAFETY: cur is a live directory descriptor and c_name is NUL-terminated.
            let rc = unsafe { libc::mkdirat(cur.as_raw_fd(), c_name.as_ptr(), 0o755) };
            assert!(
                rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST),
                "mkdirat: {}",
                std::io::Error::last_os_error()
            );
        }
        // SAFETY: as above; O_DIRECTORY | O_NOFOLLOW opens a real directory.
        let fd = unsafe {
            libc::openat(
                cur.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        assert!(fd >= 0, "openat: {}", std::io::Error::last_os_error());
        // SAFETY: openat returned a fresh descriptor that nothing else owns.
        cur = unsafe { File::from_raw_fd(fd) };
    }
    cur
}

fn write_deep(ws: &File, names: &[String], file: &str, content: &[u8]) {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    let dir = deep_dir(ws, names, true);
    let c_file = CString::new(file).unwrap();
    // SAFETY: dir is a live directory descriptor and c_file is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c_file.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
            0o644 as libc::c_uint,
        )
    };
    assert!(fd >= 0, "openat: {}", std::io::Error::last_os_error());
    // SAFETY: openat returned a fresh descriptor that nothing else owns.
    let mut f = unsafe { File::from_raw_fd(fd) };
    f.write_all(content).unwrap();
}

fn read_deep(ws: &File, names: &[String], file: &str) -> Option<Vec<u8>> {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    let dir = deep_dir(ws, names, false);
    let c_file = CString::new(file).unwrap();
    // SAFETY: dir is a live directory descriptor and c_file is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c_file.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: openat returned a fresh descriptor that nothing else owns.
    let mut f = unsafe { File::from_raw_fd(fd) };
    let mut out = Vec::new();
    f.read_to_end(&mut out).unwrap();
    Some(out)
}

#[test]
fn a_tree_deeper_than_path_max_is_restored() {
    let fx = Fixture::new();
    let names = deep_names(50);
    write_deep(&fx.ws_fd(), &names, "f", b"orig");
    write_deep(&fx.ws_fd(), &names[..30], "mid", b"mid");
    let base = fx.capture(0);
    let longest = base.entries.iter().map(|e| e.path.len()).max().unwrap();
    assert!(longest > 4096, "tree is only {longest} bytes deep");
    if root_refused(&fx, &base) {
        return;
    }
    write_deep(&fx.ws_fd(), &names, "f", b"changed");
    write_deep(&fx.ws_fd(), &names, "extra", b"x");
    write_deep(&fx.ws_fd(), &names[..30], "mid", b"changed");
    let now = fx.capture(1);

    let p = plan(&now, &base);
    apply(&fx.ws_fd(), &fx.store_fd(), &base, &p).unwrap();
    assert_eq!(read_deep(&fx.ws_fd(), &names, "f").unwrap(), b"orig");
    assert_eq!(read_deep(&fx.ws_fd(), &names[..30], "mid").unwrap(), b"mid");
    assert_eq!(read_deep(&fx.ws_fd(), &names, "extra"), None);
    assert_eq!(fx.capture(2).entries, base.entries);
}

// ---- scan_current: the planning input when the safety snapshot is skipped ----

fn count_store_files(dir: &Path) -> usize {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            if p.is_dir() { count_store_files(&p) } else { 1 }
        })
        .sum()
}

#[test]
fn scan_current_matches_capture_when_nothing_is_refused() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("a"), b"pair").unwrap();
    fs::hard_link(fx.ws.join("a"), fx.ws.join("b")).unwrap();
    create_dir(&fx.ws.join("d"));
    fs::write(fx.ws.join("d/empty"), b"").unwrap();
    symlink("a", fx.ws.join("lnk")).unwrap();
    chmod(&fx.ws.join("d/empty"), 0o4755);
    // the group shares one inode, so both names carry the attribute
    let _ = try_set_user_xattr(&fx.ws.join("a"), "user.k", b"v");
    let captured = fx.capture(0);
    let (scanned, refused) = scan_current(&fx.ws_fd(), &Limits::default()).unwrap();
    assert!(refused.is_empty(), "{refused:?}");
    assert_eq!(scanned.entries, captured.entries);
    assert_eq!(scanned.totals, captured.totals);
}

#[test]
fn a_no_undo_scan_stores_nothing_and_plans_around_entries_capture_refuses() {
    use std::os::unix::net::UnixListener;
    let fx = Fixture::new();
    fs::write(fx.ws.join("keep"), b"keep").unwrap();
    fs::write(fx.ws.join("secret"), b"secret").unwrap();
    let base = fx.capture(0);
    if root_refused(&fx, &base) {
        return;
    }
    // the agent plants entries that capture refuses and edits what is already there
    let _listener = UnixListener::bind(fx.ws.join("sock")).unwrap();
    fs::write(fx.ws.join("huge"), vec![7u8; 64]).unwrap();
    fs::write(fx.ws.join("keep"), b"edited").unwrap();
    chmod(&fx.ws.join("secret"), 0o000);
    // capture refuses this workspace outright (the unreadable file, then the socket)
    assert!(capture(&fx.ws_fd(), &fx.store_fd(), 1, &Limits::default()).is_err());

    let before = count_store_files(&fx.store_path);
    let limits = Limits {
        max_file_size: 16,
        ..Limits::default()
    };
    let (current, refused) = scan_current(&fx.ws_fd(), &limits).unwrap();
    let refused_paths: Vec<&str> = refused.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(refused_paths, ["huge", "secret", "sock"], "{refused:?}");
    // scanning writes no object and no manifest
    assert_eq!(count_store_files(&fx.store_path), before);

    let p = plan(&current, &base);
    assert!(p.ops.contains(&RestoreOp::Remove {
        path: "sock".into(),
        kind: EntryKind::File
    }));
    assert!(p.ops.contains(&RestoreOp::Remove {
        path: "huge".into(),
        kind: EntryKind::File
    }));
    // the unreadable file is rewritten from the target
    assert!(p.ops.contains(&RestoreOp::WriteFile {
        path: "secret".into()
    }));
    apply(&fx.ws_fd(), &fx.store_fd(), &base, &p).unwrap();

    assert_eq!(names(&fx.ws), ["keep", "secret"]);
    assert_eq!(fs::read(fx.ws.join("keep")).unwrap(), b"keep");
    assert_eq!(fs::read(fx.ws.join("secret")).unwrap(), b"secret");
    assert_eq!(fx.capture(2).entries, base.entries);
}

#[test]
fn a_scan_lists_an_unreadable_directory_instead_of_failing() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("keep"), b"keep").unwrap();
    let base = fx.capture(0);
    if root_refused(&fx, &base) {
        return;
    }
    create_dir(&fx.ws.join("locked"));
    fs::write(fx.ws.join("locked/inner"), b"i").unwrap();
    chmod(&fx.ws.join("locked"), 0o000);
    let (current, refused) = scan_current(&fx.ws_fd(), &Limits::default()).unwrap();
    chmod(&fx.ws.join("locked"), 0o700);
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0].path, "locked");
    assert!(
        current
            .entries
            .iter()
            .any(|e| e.path == "locked" && e.kind == EntryKind::Dir)
    );
}

// ---- ownership, final-component swaps, recovery ----

#[test]
fn a_gid_outside_the_callers_groups_is_refused_in_preflight() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("f"), b"orig").unwrap();
    fs::write(fx.ws.join("later"), b"later").unwrap();
    let base = fx.capture(0);
    if root_refused(&fx, &base) {
        return;
    }
    fs::remove_file(fx.ws.join("later")).unwrap();
    fs::write(fx.ws.join("f"), b"changed").unwrap();
    let now = fx.capture(1);

    let me = RestoreContext::from_process().unwrap();
    // same uid, but the manifest group is neither the primary nor a supplementary group
    let ctx = RestoreContext {
        euid: me.euid,
        egid: me.egid.wrapping_add(7),
        groups: vec![],
    };
    let p = plan(&now, &base);
    let err = apply_with_context(&fx.ws_fd(), &fx.store_fd(), &base, &p, &ctx).unwrap_err();
    assert!(matches!(err, RestoreError::Ownership { .. }), "{err}");
    // nothing was written, not even the removal that comes first in the plan
    assert_eq!(names(&fx.ws), ["f"]);
    assert_eq!(fs::read(fx.ws.join("f")).unwrap(), b"changed");
}

#[test]
fn fchown_to_the_callers_own_supplementary_group_succeeds() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("f"), b"orig").unwrap();
    let base = fx.capture(0);
    if root_refused(&fx, &base) {
        return;
    }
    let me = RestoreContext::from_process().unwrap();
    let Some(other) = me.groups.iter().copied().find(|g| *g != me.egid) else {
        eprintln!(
            "SKIPPED fchown coverage: the caller has no supplementary group besides gid {}",
            me.egid
        );
        return;
    };
    // the agent regroups the file to another group of the same user; restoring it is an
    // fchown to an owner the caller may create
    let c_path = CString::new(fx.ws.join("f").as_os_str().as_bytes()).unwrap();
    // SAFETY: c_path is NUL-terminated; uid -1 leaves the owner unchanged.
    let rc = unsafe { libc::chown(c_path.as_ptr(), u32::MAX, other) };
    assert_eq!(rc, 0, "chown: {}", std::io::Error::last_os_error());
    let now = fx.capture(1);
    let p = plan(&now, &base);
    assert!(p.ops.iter().any(|op| matches!(
        op,
        RestoreOp::SetMetadata { path, change } if path == "f" && change.owner
    )));
    apply(&fx.ws_fd(), &fx.store_fd(), &base, &p).unwrap();
    assert_eq!(fx.capture(2).entries, base.entries);
}

#[test]
fn a_destination_swapped_for_a_symlink_is_replaced_not_followed() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("f"), b"orig").unwrap();
    fs::write(fx.ws.join("m"), b"meta").unwrap();
    let base = fx.capture(0);
    if root_refused(&fx, &base) {
        return;
    }
    fs::write(fx.ws.join("f"), b"changed").unwrap();
    chmod(&fx.ws.join("m"), 0o600);
    let now = fx.capture(1);
    let p = plan(&now, &base);
    // f is rewritten, m only has its mode fixed in place
    assert!(p.ops.contains(&RestoreOp::WriteFile { path: "f".into() }));
    assert!(
        p.ops
            .iter()
            .any(|op| matches!(op, RestoreOp::SetMetadata { path, .. } if path == "m"))
    );

    // between plan and apply the agent swaps both final components for symlinks to a file
    // outside the workspace
    let outside = fx.outside("outside-target");
    fs::write(&outside, b"outside").unwrap();
    chmod(&outside, 0o640);
    for name in ["f", "m"] {
        fs::remove_file(fx.ws.join(name)).unwrap();
        symlink(&outside, fx.ws.join(name)).unwrap();
    }

    // f is renamed over, so the symlink is replaced by the restored file. m is opened with
    // O_NOFOLLOW, so the in-place fix fails instead of chmodding the outside file.
    let err = apply(&fx.ws_fd(), &fx.store_fd(), &base, &p).unwrap_err();
    assert!(
        matches!(&err, RestoreError::Io { op: "openat", path, .. } if path == "m"),
        "{err}"
    );
    assert!(
        !fs::symlink_metadata(fx.ws.join("f"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(fx.ws.join("f")).unwrap(), b"orig");
    assert!(
        fs::symlink_metadata(fx.ws.join("m"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&outside).unwrap(), b"outside");
    assert_eq!(mode_of(&outside), 0o640);
}

#[test]
fn a_failed_apply_is_undone_by_restoring_the_safety_snapshot() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("a"), b"a-old").unwrap();
    create_dir(&fx.ws.join("d"));
    fs::write(fx.ws.join("d/inner"), b"inner-old").unwrap();
    fs::write(fx.ws.join("zz"), b"zz-old").unwrap();
    set_mtime(&fx.ws.join("a"), 1_600_000_000, 1);
    set_mtime(&fx.ws.join("d/inner"), 1_600_000_001, 2);
    set_mtime(&fx.ws.join("d"), 1_600_000_002, 3);
    set_mtime(&fx.ws.join("zz"), 1_600_000_003, 4);
    let base = fx.capture(0);
    if root_refused(&fx, &base) {
        return;
    }
    // the workspace the user has when they rewind
    fs::write(fx.ws.join("a"), b"a-new").unwrap();
    fs::write(fx.ws.join("d/inner"), b"inner-new").unwrap();
    fs::remove_file(fx.ws.join("zz")).unwrap();
    fs::write(fx.ws.join("zz"), b"zz-new!").unwrap();
    fs::write(fx.ws.join("added"), b"added").unwrap();
    chmod(&fx.ws.join("a"), 0o600);

    // 1. the safety snapshot, in a scratch store
    let scratch_path = fx.outside("safety-store");
    fs::create_dir(&scratch_path).unwrap();
    let scratch = open_dir(&scratch_path);
    let safety = current_manifest(&fx.ws_fd(), &scratch, 1, &Limits::default()).unwrap();

    // 2. an apply that fails on its last file: its manifest size is wrong
    let mut forged = base.clone();
    for e in &mut forged.entries {
        if e.path == "zz" {
            e.size = e.size.map(|s| s + 1);
        }
    }
    forged.totals.total_bytes += 1;
    let p = plan(&safety, &forged);
    let err = apply(&fx.ws_fd(), &fx.store_fd(), &forged, &p).unwrap_err();
    assert!(matches!(err, RestoreError::SizeMismatch { .. }), "{err}");
    // the workspace is partially restored: earlier operations ran
    assert_eq!(fs::read(fx.ws.join("a")).unwrap(), b"a-old");
    assert!(!fx.ws.join("added").exists());
    assert_eq!(fs::read(fx.ws.join("zz")).unwrap(), b"zz-new!");

    // 3. restore the safety snapshot from the scratch store
    let partial =
        current_manifest(&fx.ws_fd(), &open_dir(&scratch_path), 2, &Limits::default()).unwrap();
    let undo = plan(&partial, &safety);
    apply(&fx.ws_fd(), &scratch, &safety, &undo).unwrap();
    let after =
        current_manifest(&fx.ws_fd(), &open_dir(&scratch_path), 3, &Limits::default()).unwrap();
    assert_eq!(after.entries, safety.entries);
    assert_eq!(fs::read(fx.ws.join("a")).unwrap(), b"a-new");
    assert_eq!(fs::read(fx.ws.join("added")).unwrap(), b"added");
    assert_eq!(fs::read(fx.ws.join("zz")).unwrap(), b"zz-new!");
}

// ---- POSIX ACLs ----

const ACCESS: &str = "system.posix_acl_access";
const DEFAULT: &str = "system.posix_acl_default";
const NAMED_UID: u32 = 4242;
const OTHER_UID: u32 = 4243;

/// a POSIX ACL xattr value: `(tag, perm, id)` entries behind the version 2 header.
fn acl_blob(entries: &[(u16, u16, u32)]) -> Vec<u8> {
    let mut out = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in entries {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&perm.to_le_bytes());
        out.extend_from_slice(&id.to_le_bytes());
    }
    out
}

/// owner, one named user, group, mask and other, in the order the kernel stores them.
fn ext_acl(owner: u16, user: (u32, u16), group: u16, mask: u16, other: u16) -> Vec<u8> {
    acl_blob(&[
        (0x01, owner, u32::MAX),
        (0x02, user.1, user.0),
        (0x04, group, u32::MAX),
        (0x10, mask, u32::MAX),
        (0x20, other, u32::MAX),
    ])
}

/// set an ACL attribute. returns false, after saying why, only when the filesystem does not
/// support ACLs; `LEASH_REQUIRE_XATTR=1` turns that into a failure.
fn try_set_acl(path: &Path, name: &str, value: &[u8]) -> bool {
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let c_name = CString::new(name).unwrap();
    // SAFETY: c_path and c_name are NUL-terminated and value is a valid byte slice.
    let rc = unsafe {
        libc::setxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if rc == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error();
    assert!(
        matches!(err.raw_os_error(), Some(libc::EOPNOTSUPP | libc::ENOSYS)),
        "unexpected setxattr failure on {}: {err}",
        path.display()
    );
    assert!(
        std::env::var("LEASH_REQUIRE_XATTR").as_deref() != Ok("1"),
        "LEASH_REQUIRE_XATTR=1 but {} does not support ACLs: {err}",
        path.display()
    );
    eprintln!(
        "SKIPPED ACL coverage: {} does not support ACLs ({err}); set LEASH_REQUIRE_XATTR=1 to fail instead",
        path.display()
    );
    false
}

fn remove_acl(path: &Path, name: &str) {
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let c_name = CString::new(name).unwrap();
    // SAFETY: c_path and c_name are NUL-terminated.
    let rc = unsafe { libc::removexattr(c_path.as_ptr(), c_name.as_ptr()) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        assert_eq!(err.raw_os_error(), Some(libc::ENODATA), "{err}");
    }
}

fn get_xattr(path: &Path, name: &str) -> Option<Vec<u8>> {
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let c_name = CString::new(name).unwrap();
    let mut buf = vec![0u8; 4096];
    // SAFETY: c_path and c_name are NUL-terminated and buf has `buf.len()` writable bytes.
    let n = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n < 0 {
        let err = std::io::Error::last_os_error();
        assert_eq!(err.raw_os_error(), Some(libc::ENODATA), "{err}");
        return None;
    }
    buf.truncate(n as usize);
    Some(buf)
}

/// the mode and both raw ACL values of an entry, the state restore must reproduce exactly.
type AclState = (u32, Option<Vec<u8>>, Option<Vec<u8>>);

fn acl_state(path: &Path) -> AclState {
    (
        mode_of(path),
        get_xattr(path, ACCESS),
        get_xattr(path, DEFAULT),
    )
}

#[test]
fn acls_and_modes_survive_a_round_trip_exactly() {
    let fx = Fixture::new();
    if root_guard(&fx) {
        return;
    }
    let ws = &fx.ws;
    fs::write(ws.join("f"), b"file").unwrap();
    if !try_set_acl(&ws.join("f"), ACCESS, &ext_acl(6, (NAMED_UID, 4), 4, 4, 0)) {
        return;
    }
    fs::write(ws.join("g"), b"gone and back").unwrap();
    assert!(try_set_acl(
        &ws.join("g"),
        ACCESS,
        &ext_acl(6, (NAMED_UID, 6), 4, 6, 4)
    ));
    fs::write(ws.join("plain"), b"no acl").unwrap();
    create_dir(&ws.join("d"));
    assert!(try_set_acl(
        &ws.join("d"),
        ACCESS,
        &ext_acl(7, (NAMED_UID, 5), 5, 5, 0)
    ));
    assert!(try_set_acl(
        &ws.join("d"),
        DEFAULT,
        &ext_acl(7, (NAMED_UID, 7), 5, 7, 0)
    ));
    // created under the default ACL of `d`, so it inherits an access ACL
    fs::write(ws.join("d/inner"), b"inner").unwrap();
    create_dir(&ws.join("d/sub"));
    create_dir(&ws.join("gone-dir"));
    assert!(try_set_acl(
        &ws.join("gone-dir"),
        DEFAULT,
        &acl_blob(&[
            (0x01, 7, u32::MAX),
            (0x04, 5, u32::MAX),
            (0x20, 0, u32::MAX)
        ])
    ));
    // pin the directory mtimes the creations above moved
    for (i, name) in ["d/sub", "d", "gone-dir"].iter().enumerate() {
        set_mtime(&ws.join(name), 1_500_000_000 + i as i64, 0);
    }

    let paths = ["f", "g", "plain", "d", "d/inner", "d/sub", "gone-dir"];
    let before: Vec<AclState> = paths.iter().map(|p| acl_state(&ws.join(p))).collect();
    assert!(before[0].1.is_some() && before[3].1.is_some() && before[3].2.is_some());
    assert!(before[4].1.is_some(), "d/inner inherited an access ACL");
    let base = fx.capture(0);
    for (path, state) in paths.iter().zip(&before) {
        let entry = base.entries.iter().find(|e| e.path == *path).unwrap();
        let hex = |v: &Option<Vec<u8>>| {
            v.as_ref()
                .map(|b| b.iter().map(|x| format!("{x:02x}")).collect::<String>())
        };
        assert_eq!(entry.xattrs.get(ACCESS), hex(&state.1).as_ref(), "{path}");
        assert_eq!(entry.xattrs.get(DEFAULT), hex(&state.2).as_ref(), "{path}");
        assert_eq!(entry.mode, state.0, "{path}");
    }

    // mutate every way an ACL can move: new value, chmod rewriting the mask, removal,
    // adding one where there was none, and entries replaced by new inodes
    assert!(try_set_acl(
        &ws.join("f"),
        ACCESS,
        &ext_acl(6, (OTHER_UID, 6), 6, 6, 0)
    ));
    chmod(&ws.join("f"), 0o604);
    chmod(&ws.join("g"), 0o600);
    remove_acl(&ws.join("d"), DEFAULT);
    assert!(try_set_acl(
        &ws.join("d"),
        ACCESS,
        &ext_acl(7, (OTHER_UID, 7), 7, 7, 5)
    ));
    remove_acl(&ws.join("d/inner"), ACCESS);
    assert!(try_set_acl(
        &ws.join("plain"),
        ACCESS,
        &ext_acl(6, (NAMED_UID, 4), 4, 4, 4)
    ));
    fs::remove_file(ws.join("g")).unwrap();
    fs::write(ws.join("g"), b"gone and back").unwrap();
    fs::remove_dir(ws.join("d/sub")).unwrap();
    fs::remove_dir(ws.join("gone-dir")).unwrap();
    let now = fx.capture(1);
    assert_ne!(now.entries, base.entries);

    let p = plan(&now, &base);
    apply(&fx.ws_fd(), &fx.store_fd(), &base, &p).unwrap();

    for (path, state) in paths.iter().zip(&before) {
        assert_eq!(&acl_state(&ws.join(path)), state, "{path}");
    }
    let after = fx.capture(2);
    assert_eq!(after.entries, base.entries);
    assert!(plan(&after, &base).is_empty());
}

#[test]
fn a_restored_entry_does_not_keep_an_acl_inherited_from_its_parent() {
    let fx = Fixture::new();
    if root_guard(&fx) {
        return;
    }
    let ws = &fx.ws;
    fs::write(ws.join("plain"), b"plain").unwrap();
    create_dir(&ws.join("sub"));
    fs::write(ws.join("sub/child"), b"child").unwrap();
    // the target has no ACL anywhere
    remove_acl(&ws.join("sub"), DEFAULT);
    for p in ["plain", "sub", "sub/child"] {
        remove_acl(&ws.join(p), ACCESS);
    }
    chmod(&ws.join("plain"), 0o640);
    chmod(&ws.join("sub"), 0o750);
    chmod(&ws.join("sub/child"), 0o600);
    for (i, name) in ["plain", "sub/child", "sub"].iter().enumerate() {
        set_mtime(&ws.join(name), 1_600_000_000 + i as i64, 0);
    }
    let base = fx.capture(0);
    assert!(base.entries.iter().all(|e| e.xattrs.is_empty()));

    // from now on everything created in the workspace root inherits a named-user ACL
    if !try_set_acl(ws, DEFAULT, &ext_acl(7, (NAMED_UID, 7), 5, 7, 0)) {
        return;
    }
    fs::remove_file(ws.join("plain")).unwrap();
    fs::remove_file(ws.join("sub/child")).unwrap();
    fs::remove_dir(ws.join("sub")).unwrap();

    let now = fx.capture(1);
    let p = plan(&now, &base);
    apply(&fx.ws_fd(), &fx.store_fd(), &base, &p).unwrap();

    for path in ["plain", "sub", "sub/child"] {
        let (_, access, default) = acl_state(&ws.join(path));
        assert_eq!(
            (access, default),
            (None, None),
            "{path} kept an inherited ACL"
        );
    }
    let after = fx.capture(2);
    assert_eq!(after.entries, base.entries);
}

#[test]
fn a_malformed_acl_in_a_forged_manifest_is_refused_before_any_write() {
    let fx = Fixture::new();
    if root_guard(&fx) {
        return;
    }
    let ws = &fx.ws;
    fs::write(ws.join("f"), b"file").unwrap();
    if !try_set_acl(&ws.join("f"), ACCESS, &ext_acl(6, (NAMED_UID, 4), 4, 4, 0)) {
        return;
    }
    fs::write(ws.join("victim"), b"victim").unwrap();
    create_dir(&ws.join("d"));
    let base = fx.capture(0);
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let good = ext_acl(6, (NAMED_UID, 4), 4, 4, 0);
    let mut wrong_version = good.clone();
    wrong_version[0] = 1;
    let forgeries: Vec<(&str, &str, String)> = vec![
        ("f", ACCESS, hex(&wrong_version)),
        ("f", ACCESS, hex(&good[..good.len() - 1])),
        ("f", ACCESS, hex(&acl_blob(&[(0x01, 6, u32::MAX)]))),
        // well formed, but its owner and mask disagree with the mode 0640
        ("f", ACCESS, hex(&ext_acl(7, (NAMED_UID, 7), 7, 7, 7))),
        // a default ACL belongs to directories
        ("f", DEFAULT, hex(&good)),
        ("d", DEFAULT, "nothex".to_owned()),
    ];

    fs::remove_file(ws.join("victim")).unwrap();
    let now = fx.capture(1);
    for (path, name, value) in forgeries {
        let mut forged = base.clone();
        for e in &mut forged.entries {
            if e.path == path {
                e.xattrs.insert(name.to_owned(), value.clone());
            }
        }
        let p = plan(&now, &forged);
        let err = apply(&fx.ws_fd(), &fx.store_fd(), &forged, &p).unwrap_err();
        assert!(
            matches!(err, RestoreError::Store(StoreError::InvalidManifest { .. })),
            "{path} {name}: {err}"
        );
        // the removal the plan starts with did not run, and nothing was written
        assert!(!ws.join("victim").exists(), "{path} {name}");
        assert_eq!(names(ws), ["d", "f"], "{path} {name}");
    }
}

#[test]
fn an_acl_only_change_on_an_entry_owned_by_someone_else_fails_in_preflight() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("f"), b"file").unwrap();
    if !try_set_acl(
        &fx.ws.join("f"),
        ACCESS,
        &ext_acl(6, (NAMED_UID, 4), 4, 4, 0),
    ) {
        return;
    }
    let base = fx.capture(0);
    if root_refused(&fx, &base) {
        return;
    }
    let me = RestoreContext::from_process().unwrap();
    let ctx = RestoreContext {
        euid: me.euid.wrapping_add(1).max(1),
        egid: me.egid,
        groups: me.groups.clone(),
    };
    // same mode, same everything else: only the named user of the ACL differs
    let changed = ext_acl(6, (OTHER_UID, 4), 4, 4, 0);
    assert!(try_set_acl(&fx.ws.join("f"), ACCESS, &changed));
    let now = fx.capture(1);
    let p = plan(&now, &base);
    assert!(!p.is_empty());
    let err = apply_with_context(&fx.ws_fd(), &fx.store_fd(), &base, &p, &ctx).unwrap_err();
    assert!(
        matches!(&err, RestoreError::NotOwner { path, .. } if path == "f"),
        "{err}"
    );
    assert_eq!(get_xattr(&fx.ws.join("f"), ACCESS), Some(changed));
}

#[test]
fn the_change_summary_names_an_acl_change_apart_from_user_xattrs() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("f"), b"file").unwrap();
    fs::write(fx.ws.join("u"), b"user").unwrap();
    if !try_set_acl(
        &fx.ws.join("f"),
        ACCESS,
        &ext_acl(6, (NAMED_UID, 4), 4, 4, 0),
    ) {
        return;
    }
    let user_xattrs = try_set_user_xattr(&fx.ws.join("u"), "user.x", b"1");
    let base = fx.capture(0);
    // only the named user of the ACL differs, so the mode is the same
    assert!(try_set_acl(
        &fx.ws.join("f"),
        ACCESS,
        &ext_acl(6, (OTHER_UID, 4), 4, 4, 0)
    ));
    if user_xattrs {
        assert!(try_set_user_xattr(&fx.ws.join("u"), "user.x", b"2"));
    }
    let now = fx.capture(1);
    let p = plan(&now, &base);
    let change_of = |path: &str| {
        p.ops
            .iter()
            .find_map(|op| match op {
                RestoreOp::SetMetadata { path: p, change } if p == path => Some(*change),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no metadata change for {path}"))
    };
    let f = change_of("f");
    assert!(f.acl && !f.xattrs && !f.mode, "{f:?}");
    if user_xattrs {
        let u = change_of("u");
        assert!(u.xattrs && !u.acl, "{u:?}");
    }
    let summary = p.summary();
    let detail = |path: &str| {
        summary
            .changes
            .iter()
            .find(|c| c.action == ChangeAction::Metadata && c.path == path)
            .unwrap()
            .detail
            .clone()
    };
    assert_eq!(detail("f"), "acl");
    if user_xattrs {
        assert_eq!(detail("u"), "xattrs");
    }
    assert!(summary.to_string().contains("(acl)"), "{summary}");
}

#[test]
fn setgid_with_an_access_acl_and_a_default_acl_round_trip() {
    let fx = Fixture::new();
    if root_guard(&fx) {
        return;
    }
    let ws = &fx.ws;
    fs::write(ws.join("f"), b"file").unwrap();
    if !try_set_acl(&ws.join("f"), ACCESS, &ext_acl(6, (NAMED_UID, 4), 4, 4, 0)) {
        return;
    }
    chmod(&ws.join("f"), 0o2640);
    create_dir(&ws.join("d"));
    assert!(try_set_acl(
        &ws.join("d"),
        ACCESS,
        &ext_acl(7, (NAMED_UID, 5), 5, 5, 0)
    ));
    assert!(try_set_acl(
        &ws.join("d"),
        DEFAULT,
        &ext_acl(7, (NAMED_UID, 5), 5, 5, 0)
    ));
    chmod(&ws.join("d"), 0o3750);
    set_mtime(&ws.join("d"), 1_500_000_000, 0);
    let before = [acl_state(&ws.join("f")), acl_state(&ws.join("d"))];
    assert_eq!(before[0].0, 0o2640);
    assert_eq!(before[1].0, 0o3750);
    let base = fx.capture(0);

    assert!(try_set_acl(
        &ws.join("f"),
        ACCESS,
        &ext_acl(6, (OTHER_UID, 6), 6, 6, 4)
    ));
    chmod(&ws.join("f"), 0o600);
    chmod(&ws.join("d"), 0o700);
    remove_acl(&ws.join("d"), DEFAULT);
    let now = fx.capture(1);
    apply(&fx.ws_fd(), &fx.store_fd(), &base, &plan(&now, &base)).unwrap();

    assert_eq!(acl_state(&ws.join("f")), before[0]);
    assert_eq!(acl_state(&ws.join("d")), before[1]);
    assert_eq!(fx.capture(2).entries, base.entries);
}
