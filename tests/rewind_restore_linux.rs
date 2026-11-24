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
    current_manifest, plan, recompute_chain,
};
use leash::snapshot::store::{EntryKind, Limits, Manifest, StoreError, capture, load_manifest};

fn open_dir(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .unwrap()
}

/// create a directory and strip inherited default acls so capture does not refuse it.
fn create_dir(path: &Path) {
    fs::create_dir(path).unwrap();
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: c_path and the static attribute name are NUL-terminated.
    let _ = unsafe { libc::removexattr(c_path.as_ptr(), c"system.posix_acl_default".as_ptr()) };
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

#[test]
fn recompute_chain_matches_digests_returned_by_capture() {
    let fx = Fixture::new();
    let digests = capture_chain(&fx, 3);
    let chain = recompute_chain(&fx.store_fd()).unwrap();
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
    assert_ne!(recompute_chain(&fx.store_fd()).unwrap().head, honest);
}

#[test]
fn a_deleted_last_manifest_changes_the_head() {
    let fx = Fixture::new();
    let digests = capture_chain(&fx, 3);
    let honest = chain_head(&digests).unwrap();
    fs::remove_file(fx.store_path.join("manifests/step-000002.json")).unwrap();
    let after = recompute_chain(&fx.store_fd()).unwrap();
    assert_ne!(after.head, honest);
    assert_eq!(after.digest(2), None);
}

#[test]
fn a_deleted_middle_manifest_is_a_gap_naming_the_missing_step() {
    let fx = Fixture::new();
    capture_chain(&fx, 3);
    fs::remove_file(fx.store_path.join("manifests/step-000001.json")).unwrap();
    let err = recompute_chain(&fx.store_fd()).unwrap_err();
    assert!(
        matches!(&err, StoreError::InvalidChain { reason } if reason.contains("step 1 is missing")),
        "{err}"
    );
}

#[test]
fn a_chain_that_starts_after_step_zero_names_step_zero() {
    let fx = Fixture::new();
    capture_chain(&fx, 2);
    fs::remove_file(fx.store_path.join("manifests/step-000000.json")).unwrap();
    let err = recompute_chain(&fx.store_fd()).unwrap_err();
    assert!(
        matches!(&err, StoreError::InvalidChain { reason } if reason.contains("step 0 is missing")),
        "{err}"
    );
}

#[test]
fn an_extra_manifest_changes_the_head() {
    let fx = Fixture::new();
    let digests = capture_chain(&fx, 2);
    let honest = chain_head(&digests).unwrap();
    capture(&fx.ws_fd(), &fx.store_fd(), 2, &Limits::default()).unwrap();
    assert_ne!(recompute_chain(&fx.store_fd()).unwrap().head, honest);
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
    if is_root() {
        return;
    }
    let fx = Fixture::new();
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
    if is_root() {
        return;
    }
    let fx = Fixture::new();
    fs::write(fx.ws.join("keep"), b"keep").unwrap();
    let base = fx.capture(0);
    fs::write(fx.ws.join("extra"), b"extra").unwrap();
    let now = fx.capture(1);

    for bad in ["../escape", "/abs/escape", "a/../../escape", "a//b", "./x"] {
        let mut forged = base.clone();
        forged.entries[0].path = bad.to_owned();
        // as a stored manifest: refused when loaded
        let json = serde_json::to_vec(&forged).unwrap();
        let mpath = fx.store_path.join("manifests/step-000009.json");
        fs::write(&mpath, &json).unwrap();
        let err = load_manifest(&fx.store_fd(), 9).unwrap_err();
        assert!(
            matches!(err, StoreError::InvalidManifest { .. }),
            "{bad}: {err}"
        );
        fs::remove_file(&mpath).unwrap();

        // as an in-memory target: refused by apply before it touches the workspace
        let p = plan(&now, &forged);
        let err = apply(&fx.ws_fd(), &fx.store_fd(), &forged, &p).unwrap_err();
        assert!(
            matches!(err, RestoreError::Store(StoreError::InvalidManifest { .. })),
            "{bad}: {err}"
        );
        assert_eq!(names(&fx.ws), ["extra", "keep"]);
        assert!(!fx.outside("escape").exists());
    }
}

#[test]
fn a_plan_path_that_escapes_is_refused_before_any_write() {
    if is_root() {
        return;
    }
    let fx = Fixture::new();
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
    if is_root() {
        return;
    }
    let fx = Fixture::new();
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
fn a_directory_swapped_for_a_symlink_after_planning_is_not_followed() {
    if is_root() {
        return;
    }
    let fx = Fixture::new();
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
    if is_root() {
        return;
    }
    let fx = Fixture::new();
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
