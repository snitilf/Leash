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
    ChangeAction, RestoreOp, chain_head, current_manifest, plan, recompute_chain,
};
use leash::snapshot::store::{EntryKind, Limits, Manifest, capture, load_manifest};

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
fn chain_head_is_deterministic_and_order_sensitive() {
    let a = vec![(0u64, digest('a')), (1, digest('b'))];
    assert_eq!(chain_head(&a), chain_head(&a.clone()));
    let swapped = vec![(0u64, digest('b')), (1, digest('a'))];
    assert_ne!(chain_head(&a), chain_head(&swapped));
    let reversed = vec![(1u64, digest('b')), (0, digest('a'))];
    assert_ne!(chain_head(&a), chain_head(&reversed));
    assert_ne!(chain_head(&a), chain_head(&a[..1]));
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
    assert_eq!(chain_head(&d), expected);
}

#[test]
fn recompute_chain_matches_digests_returned_by_capture() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("a"), b"one").unwrap();
    let mut digests = Vec::new();
    for step in 0..3u64 {
        let p = capture(&fx.ws_fd(), &fx.store_fd(), step, &Limits::default()).unwrap();
        digests.push((step, p.manifest_digest));
        fs::write(fx.ws.join("a"), format!("v{step}")).unwrap();
    }
    assert_eq!(
        recompute_chain(&fx.store_fd()).unwrap(),
        chain_head(&digests)
    );
}

#[test]
fn recompute_chain_uses_bytes_on_disk_not_a_trace() {
    let fx = Fixture::new();
    fs::write(fx.ws.join("a"), b"one").unwrap();
    let p = capture(&fx.ws_fd(), &fx.store_fd(), 0, &Limits::default()).unwrap();
    let honest = chain_head(&[(0, p.manifest_digest)]);
    let path = fx.store_path.join("manifests/step-000000.json");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut bytes = fs::read(&path).unwrap();
    bytes.push(b'\n');
    fs::write(&path, bytes).unwrap();
    assert_ne!(recompute_chain(&fx.store_fd()).unwrap(), honest);
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
