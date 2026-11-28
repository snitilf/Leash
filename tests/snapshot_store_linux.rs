//! linux integration tests for the content-addressed exact snapshot store
//! (`leash::snapshot::store`, ADR-0022).

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::{CString, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::Path;

use leash::snapshot::store::{
    DEFAULT_MAX_FILE_SIZE, EntryKind, Limits, StoreError, capture, capture_gated, load_manifest,
    published_steps, verify_object,
};

fn open_dir(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .unwrap()
}

/// create a test workspace directory and strip any inherited `system.posix_acl_default`
/// from `/tmp` so newly created subdirectories inside the test fixture do not inherit
/// host-level default ACLs (which `capture` intentionally refuses as unsupported metadata).
fn create_workspace_dir(path: &Path) {
    fs::create_dir(path).unwrap();
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: c_path and the static attribute name are NUL-terminated.
    let _ = unsafe { libc::removexattr(c_path.as_ptr(), c"system.posix_acl_default".as_ptr()) };
}

fn set_mtime(path: &Path, sec: i64, nsec: i64) {
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let times = [
        libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        },
        libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        },
    ];
    // SAFETY: c_path is NUL-terminated and times points to a valid 2-element array.
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
    assert_eq!(
        rc,
        0,
        "utimensat failed: {}",
        std::io::Error::last_os_error()
    );
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
        true
    } else {
        let err = std::io::Error::last_os_error();
        if matches!(err.raw_os_error(), Some(libc::EOPNOTSUPP | libc::ENOSYS)) {
            false
        } else {
            panic!("unexpected setxattr failure: {err}");
        }
    }
}

#[test]
fn exact_round_trip_preserves_content_metadata_symlink_empty_dir_and_xattr() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join("ws");
    let store_path = tmp.path().join("store");
    create_workspace_dir(&ws_path);
    fs::create_dir(&store_path).unwrap();

    let hello_path = ws_path.join("hello.txt");
    let content = b"hello exact snapshot\n";
    fs::write(&hello_path, content).unwrap();
    // setuid bit on a file we own (0o4750)
    fs::set_permissions(&hello_path, fs::Permissions::from_mode(0o4750)).unwrap();
    let expected_sec = 1_700_000_123i64;
    let expected_nsec = 456_789_000i64;
    set_mtime(&hello_path, expected_sec, expected_nsec);
    let xattr_supported = try_set_user_xattr(&hello_path, "user.leash.test", b"\x00\xffhi");

    fs::create_dir(ws_path.join("empty")).unwrap();
    fs::create_dir(ws_path.join("sub")).unwrap();
    fs::write(ws_path.join("sub/nested.bin"), b"\x01\x02\x03\x04").unwrap();
    symlink("sub/nested.bin", ws_path.join("rel-link")).unwrap();

    let ws_meta = fs::symlink_metadata(&hello_path).unwrap();
    let ws_fd = open_dir(&ws_path);
    let store_fd = open_dir(&store_path);

    let published = capture(&ws_fd, &store_fd, 0, &Limits::default()).unwrap();
    assert_eq!(published.stats.files, 2);
    assert_eq!(published.stats.dirs, 2);
    assert_eq!(published.stats.symlinks, 1);
    assert_eq!(published.stats.entries, 5);
    assert_eq!(published.stats.new_objects, 2);
    assert_eq!(published.stats.reused_objects, 0);
    assert_eq!(published.stats.total_bytes, (content.len() + 4) as u64);
    assert_eq!(published.stats.store_growth, (content.len() + 4) as u64);

    assert_eq!(published_steps(&store_fd).unwrap(), vec![0]);

    let (manifest, digest) = load_manifest(&store_fd, 0).unwrap();
    assert_eq!(digest, published.manifest_digest);
    assert_eq!(manifest.step, 0);
    assert_eq!(manifest.entries.len(), 5);

    let hello = manifest
        .entries
        .iter()
        .find(|e| e.path == "hello.txt")
        .unwrap();
    assert_eq!(hello.kind, EntryKind::File);
    assert_eq!(hello.mode, 0o4750);
    assert_eq!(hello.uid, ws_meta.uid());
    assert_eq!(hello.gid, ws_meta.gid());
    assert_eq!(hello.mtime_sec, expected_sec);
    assert_eq!(hello.mtime_nsec, expected_nsec);
    assert_eq!(hello.size, Some(content.len() as u64));
    if xattr_supported {
        assert_eq!(
            hello.xattrs.get("user.leash.test").map(String::as_str),
            Some("00ff6869")
        );
    }
    // if user xattrs are unsupported on the test filesystem (EOPNOTSUPP), only the
    // xattr assertion above is skipped.

    let sha = hello.sha256.as_deref().unwrap();
    let mut obj = verify_object(&store_fd, sha).unwrap();
    let mut got = Vec::new();
    obj.read_to_end(&mut got).unwrap();
    assert_eq!(got, content);

    // stored objects and manifests are mode 0400
    let obj_path = store_path.join("objects").join(&sha[..2]).join(sha);
    assert_eq!(
        fs::symlink_metadata(&obj_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o400
    );
    let manifest_path = store_path.join("manifests/step-000000.json");
    assert_eq!(
        fs::symlink_metadata(&manifest_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o400
    );

    let empty = manifest.entries.iter().find(|e| e.path == "empty").unwrap();
    assert_eq!(empty.kind, EntryKind::Dir);

    let link = manifest
        .entries
        .iter()
        .find(|e| e.path == "rel-link")
        .unwrap();
    assert_eq!(link.kind, EntryKind::Symlink);
    assert_eq!(link.target.as_deref(), Some("sub/nested.bin"));
}

#[test]
fn hard_links_are_stored_once_with_shared_link_group() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join("ws");
    let store_path = tmp.path().join("store");
    create_workspace_dir(&ws_path);
    fs::create_dir(&store_path).unwrap();

    fs::write(ws_path.join("a.txt"), b"shared inode content").unwrap();
    fs::hard_link(ws_path.join("a.txt"), ws_path.join("b.txt")).unwrap();
    fs::create_dir(ws_path.join("sub")).unwrap();
    fs::hard_link(ws_path.join("a.txt"), ws_path.join("sub/c.txt")).unwrap();
    fs::write(ws_path.join("unique.txt"), b"different content").unwrap();

    let ws_fd = open_dir(&ws_path);
    let store_fd = open_dir(&store_path);

    let published = capture(&ws_fd, &store_fd, 1, &Limits::default()).unwrap();
    assert_eq!(published.stats.files, 4);
    assert_eq!(published.stats.new_objects, 2);
    assert_eq!(published.stats.reused_objects, 2);

    let (manifest, _) = load_manifest(&store_fd, 1).unwrap();
    let a = manifest.entries.iter().find(|e| e.path == "a.txt").unwrap();
    let b = manifest.entries.iter().find(|e| e.path == "b.txt").unwrap();
    let c = manifest
        .entries
        .iter()
        .find(|e| e.path == "sub/c.txt")
        .unwrap();
    let u = manifest
        .entries
        .iter()
        .find(|e| e.path == "unique.txt")
        .unwrap();

    assert_eq!(a.link_group, Some(1));
    assert_eq!(b.link_group, Some(1));
    assert_eq!(c.link_group, Some(1));
    assert_eq!(a.sha256, b.sha256);
    assert_eq!(a.sha256, c.sha256);
    assert_eq!(u.link_group, None);
}

#[test]
fn symlink_pointing_outside_workspace_is_recorded_and_not_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join("ws");
    let store_path = tmp.path().join("store");
    let outside_dir = tmp.path().join("outside");
    create_workspace_dir(&ws_path);
    fs::create_dir(&store_path).unwrap();
    fs::create_dir(&outside_dir).unwrap();

    let outside_file = outside_dir.join("secret.txt");
    fs::write(&outside_file, b"do not copy me").unwrap();
    symlink(&outside_file, ws_path.join("link-file")).unwrap();
    symlink(&outside_dir, ws_path.join("link-dir")).unwrap();

    let ws_fd = open_dir(&ws_path);
    let store_fd = open_dir(&store_path);

    let published = capture(&ws_fd, &store_fd, 0, &Limits::default()).unwrap();
    assert_eq!(published.stats.symlinks, 2);
    assert_eq!(published.stats.files, 0);
    assert_eq!(published.stats.dirs, 0);
    assert_eq!(published.stats.new_objects, 0);

    let (manifest, _) = load_manifest(&store_fd, 0).unwrap();
    let lf = manifest
        .entries
        .iter()
        .find(|e| e.path == "link-file")
        .unwrap();
    let ld = manifest
        .entries
        .iter()
        .find(|e| e.path == "link-dir")
        .unwrap();
    assert_eq!(lf.kind, EntryKind::Symlink);
    assert_eq!(lf.target.as_deref(), outside_file.to_str());
    assert_eq!(ld.kind, EntryKind::Symlink);
    assert_eq!(ld.target.as_deref(), outside_dir.to_str());
}

#[test]
fn fifo_and_unix_socket_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_fifo = tmp.path().join("ws-fifo");
    let ws_sock = tmp.path().join("ws-sock");
    let store_path = tmp.path().join("store");
    create_workspace_dir(&ws_fifo);
    create_workspace_dir(&ws_sock);
    fs::create_dir(&store_path).unwrap();

    let fifo_path = ws_fifo.join("pipe");
    let c_fifo = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
    // SAFETY: c_fifo is NUL-terminated inside a temp directory we own.
    assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);

    let store_fd = open_dir(&store_path);
    let err = capture(&open_dir(&ws_fifo), &store_fd, 0, &Limits::default()).unwrap_err();
    assert!(
        matches!(err, StoreError::UnsupportedEntry { kind: "fifo", .. }),
        "expected fifo refusal, got {err:?}"
    );

    let _listener = UnixListener::bind(ws_sock.join("agent.sock")).unwrap();
    let err = capture(&open_dir(&ws_sock), &store_fd, 0, &Limits::default()).unwrap_err();
    assert!(
        matches!(err, StoreError::UnsupportedEntry { kind: "socket", .. }),
        "expected socket refusal, got {err:?}"
    );
    assert!(published_steps(&store_fd).unwrap().is_empty());
}

#[test]
fn non_utf8_filename_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join("ws");
    let store_path = tmp.path().join("store");
    create_workspace_dir(&ws_path);
    fs::create_dir(&store_path).unwrap();

    let bad_name = OsStr::from_bytes(b"bad-\xff-file.txt");
    fs::write(ws_path.join(bad_name), b"nope").unwrap();

    let err = capture(
        &open_dir(&ws_path),
        &open_dir(&store_path),
        0,
        &Limits::default(),
    )
    .unwrap_err();
    assert!(
        matches!(err, StoreError::UnsupportedName { .. }),
        "expected UnsupportedName, got {err:?}"
    );
}

#[test]
fn sparse_2gib_file_is_refused_by_max_file_size_without_reading() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join("ws");
    let store_path = tmp.path().join("store");
    create_workspace_dir(&ws_path);
    fs::create_dir(&store_path).unwrap();

    let two_gib: u64 = 2 * 1024 * 1024 * 1024;
    let sparse = File::create(ws_path.join("huge.bin")).unwrap();
    sparse.set_len(two_gib).unwrap();
    drop(sparse);

    let err = capture(
        &open_dir(&ws_path),
        &open_dir(&store_path),
        0,
        &Limits::default(),
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            StoreError::FileSizeLimitExceeded {
                size,
                limit,
                ..
            } if size == two_gib && limit == DEFAULT_MAX_FILE_SIZE
        ),
        "expected FileSizeLimitExceeded, got {err:?}"
    );
}

#[test]
fn max_entries_and_max_store_growth_are_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join("ws");
    let store_a = tmp.path().join("store-a");
    let store_b = tmp.path().join("store-b");
    create_workspace_dir(&ws_path);
    fs::create_dir(&store_a).unwrap();
    fs::create_dir(&store_b).unwrap();

    fs::write(ws_path.join("a.txt"), b"0123456789").unwrap();
    fs::write(ws_path.join("b.txt"), b"abcdefghij").unwrap();
    fs::write(ws_path.join("c.txt"), b"klmnopqrst").unwrap();

    let ws_fd = open_dir(&ws_path);

    let entry_limits = Limits {
        max_entries: 2,
        ..Limits::default()
    };
    let err = capture(&ws_fd, &open_dir(&store_a), 0, &entry_limits).unwrap_err();
    assert!(
        matches!(err, StoreError::EntryLimitExceeded { limit: 2 }),
        "expected EntryLimitExceeded, got {err:?}"
    );

    let growth_limits = Limits {
        max_store_growth: 15,
        ..Limits::default()
    };
    let err = capture(&ws_fd, &open_dir(&store_b), 0, &growth_limits).unwrap_err();
    assert!(
        matches!(err, StoreError::StoreGrowthLimitExceeded { limit: 15, .. }),
        "expected StoreGrowthLimitExceeded, got {err:?}"
    );
}

#[test]
fn second_capture_of_unchanged_tree_writes_zero_new_objects() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join("ws");
    let store_path = tmp.path().join("store");
    create_workspace_dir(&ws_path);
    fs::create_dir(&store_path).unwrap();

    fs::write(ws_path.join("one.txt"), b"alpha").unwrap();
    fs::write(ws_path.join("two.txt"), b"beta").unwrap();

    let ws_fd = open_dir(&ws_path);
    let store_fd = open_dir(&store_path);

    let first = capture(&ws_fd, &store_fd, 0, &Limits::default()).unwrap();
    assert_eq!(first.stats.new_objects, 2);
    assert_eq!(first.stats.reused_objects, 0);
    assert_eq!(first.stats.store_growth, 9);

    let second = capture(&ws_fd, &store_fd, 1, &Limits::default()).unwrap();
    assert_eq!(second.stats.new_objects, 0);
    assert_eq!(second.stats.reused_objects, 2);
    assert_eq!(second.stats.store_growth, 0);
    assert_eq!(published_steps(&store_fd).unwrap(), vec![0, 1]);
}

#[test]
fn manifest_bytes_are_identical_across_two_stores_for_same_tree_and_step() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join("ws");
    let store_a = tmp.path().join("store-a");
    let store_b = tmp.path().join("store-b");
    create_workspace_dir(&ws_path);
    fs::create_dir(&store_a).unwrap();
    fs::create_dir(&store_b).unwrap();

    fs::create_dir(ws_path.join("dir")).unwrap();
    fs::write(ws_path.join("dir/z.txt"), b"zzz").unwrap();
    fs::write(ws_path.join("a.txt"), b"aaa").unwrap();
    fs::hard_link(ws_path.join("a.txt"), ws_path.join("a-link.txt")).unwrap();
    symlink("dir/z.txt", ws_path.join("l")).unwrap();

    let ws_fd = open_dir(&ws_path);
    let pub_a = capture(&ws_fd, &open_dir(&store_a), 7, &Limits::default()).unwrap();
    let pub_b = capture(&ws_fd, &open_dir(&store_b), 7, &Limits::default()).unwrap();

    assert_eq!(pub_a.manifest_digest, pub_b.manifest_digest);
    let bytes_a = fs::read(store_a.join("manifests/step-000007.json")).unwrap();
    let bytes_b = fs::read(store_b.join("manifests/step-000007.json")).unwrap();
    assert_eq!(bytes_a, bytes_b);
}

#[test]
fn tampered_object_fails_verify_object() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join("ws");
    let store_path = tmp.path().join("store");
    create_workspace_dir(&ws_path);
    fs::create_dir(&store_path).unwrap();

    fs::write(ws_path.join("data.txt"), b"integrity matters").unwrap();
    let store_fd = open_dir(&store_path);
    capture(&open_dir(&ws_path), &store_fd, 0, &Limits::default()).unwrap();

    let (manifest, _) = load_manifest(&store_fd, 0).unwrap();
    let sha = manifest.entries[0].sha256.as_deref().unwrap();
    let obj_path = store_path.join("objects").join(&sha[..2]).join(sha);

    fs::set_permissions(&obj_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&obj_path, b"integrity TAMPERED").unwrap();
    fs::set_permissions(&obj_path, fs::Permissions::from_mode(0o400)).unwrap();

    let err = verify_object(&store_fd, sha).unwrap_err();
    assert!(
        matches!(err, StoreError::ObjectCorrupt { .. }),
        "expected ObjectCorrupt, got {err:?}"
    );
}

#[test]
fn symlinked_object_file_fails_verify_object() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join("ws");
    let store_path = tmp.path().join("store");
    create_workspace_dir(&ws_path);
    fs::create_dir(&store_path).unwrap();

    let payload = b"genuine content";
    fs::write(ws_path.join("data.txt"), payload).unwrap();
    let store_fd = open_dir(&store_path);
    capture(&open_dir(&ws_path), &store_fd, 0, &Limits::default()).unwrap();

    let (manifest, _) = load_manifest(&store_fd, 0).unwrap();
    let sha = manifest.entries[0].sha256.as_deref().unwrap();
    let obj_path = store_path.join("objects").join(&sha[..2]).join(sha);

    let external = tmp.path().join("external-copy");
    fs::write(&external, payload).unwrap();
    fs::remove_file(&obj_path).unwrap();
    symlink(&external, &obj_path).unwrap();

    let err = verify_object(&store_fd, sha).unwrap_err();
    assert!(
        matches!(err, StoreError::InvalidObject { .. }),
        "expected InvalidObject, got {err:?}"
    );
}

#[test]
fn capturing_same_step_twice_returns_manifest_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join("ws");
    let store_path = tmp.path().join("store");
    create_workspace_dir(&ws_path);
    fs::create_dir(&store_path).unwrap();
    fs::write(ws_path.join("a.txt"), b"hello").unwrap();

    let ws_fd = open_dir(&ws_path);
    let store_fd = open_dir(&store_path);

    capture(&ws_fd, &store_fd, 3, &Limits::default()).unwrap();
    let err = capture(&ws_fd, &store_fd, 3, &Limits::default()).unwrap_err();
    assert!(
        matches!(err, StoreError::ManifestExists { step: 3 }),
        "expected ManifestExists, got {err:?}"
    );
}

#[test]
fn failed_capture_leaves_published_steps_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join("ws");
    let store_path = tmp.path().join("store");
    create_workspace_dir(&ws_path);
    fs::create_dir(&store_path).unwrap();
    fs::write(ws_path.join("ok.txt"), b"ok").unwrap();

    let ws_fd = open_dir(&ws_path);
    let store_fd = open_dir(&store_path);

    capture(&ws_fd, &store_fd, 0, &Limits::default()).unwrap();
    assert_eq!(published_steps(&store_fd).unwrap(), vec![0]);

    let fifo_path = ws_path.join("bad-fifo");
    let c_fifo = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
    // SAFETY: c_fifo is NUL-terminated inside a temp directory we own.
    assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);

    let err = capture(&ws_fd, &store_fd, 1, &Limits::default()).unwrap_err();
    assert!(matches!(err, StoreError::UnsupportedEntry { .. }));
    assert_eq!(published_steps(&store_fd).unwrap(), vec![0]);
}

#[test]
fn a_before_publish_check_runs_after_the_objects_and_before_the_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join("ws");
    let store_path = tmp.path().join("store");
    create_workspace_dir(&ws_path);
    fs::create_dir(&store_path).unwrap();
    fs::write(ws_path.join("a.txt"), b"alpha").unwrap();
    let ws_fd = open_dir(&ws_path);
    let store_fd = open_dir(&store_path);

    let mut calls = 0;
    let published = capture_gated(&ws_fd, &store_fd, 0, &Limits::default(), &mut || {
        calls += 1;
        assert!(
            !store_path.join("manifests/step-000000.json").exists(),
            "no manifest exists when the check runs"
        );
        let objects = fs::read_dir(store_path.join("objects")).unwrap().count();
        assert!(objects > 0, "the objects are already placed");
        Ok(())
    })
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(published_steps(&store_fd).unwrap(), vec![0]);
    assert_eq!(
        load_manifest(&store_fd, 0).unwrap().1,
        published.manifest_digest
    );
}

#[test]
fn a_refused_before_publish_check_publishes_no_manifest_and_leaves_no_staging_file() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join("ws");
    let store_path = tmp.path().join("store");
    create_workspace_dir(&ws_path);
    fs::create_dir(&store_path).unwrap();
    fs::write(ws_path.join("a.txt"), b"alpha").unwrap();
    let ws_fd = open_dir(&ws_path);
    let store_fd = open_dir(&store_path);

    let err = capture_gated(&ws_fd, &store_fd, 0, &Limits::default(), &mut || {
        Err(StoreError::PublishRefused {
            reason: "thawed".into(),
        })
    })
    .unwrap_err();
    assert!(
        matches!(err, StoreError::PublishRefused { ref reason } if reason == "thawed"),
        "{err:?}"
    );
    assert!(published_steps(&store_fd).unwrap().is_empty());
    assert!(!store_path.join("manifests/step-000000.json").exists());
    assert_eq!(
        fs::read_dir(store_path.join("staging")).unwrap().count(),
        0,
        "the staged manifest was removed"
    );
    // the refused step can be captured again: nothing was left behind to collide with
    capture(&ws_fd, &store_fd, 0, &Limits::default()).unwrap();
    assert_eq!(published_steps(&store_fd).unwrap(), vec![0]);
}
