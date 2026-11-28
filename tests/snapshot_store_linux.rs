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
    DEFAULT_MAX_FILE_SIZE, EntryKind, Limits, StoreError, TRACE_LINE_CAP, TRACE_STEP_CAP, capture,
    capture_gated, committed_steps_from_trace, load_manifest, published_steps, read_trace,
    read_trace_capped, verify_object,
};

fn open_dir(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .unwrap()
}

/// create a test workspace directory. it keeps any default ACL its parent hands down, as a
/// `/tmp` with default ACLs does, because `capture` records ACLs.
fn create_workspace_dir(path: &Path) {
    fs::create_dir(path).unwrap();
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

const ACL_ACCESS: &str = "system.posix_acl_access";
const ACL_DEFAULT: &str = "system.posix_acl_default";

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

/// raw `setxattr`; returns the error instead of panicking so callers can decide.
fn set_xattr_raw(path: &Path, name: &str, value: &[u8]) -> std::io::Result<()> {
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
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn get_xattr_raw(path: &Path, name: &str) -> Option<Vec<u8>> {
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// whether this filesystem takes ACLs; an unsupported one skips the test and says so, unless
/// `LEASH_REQUIRE_XATTR=1`, which turns the skip into a failure.
fn acl_supported(path: &Path, probe: &[u8]) -> bool {
    match set_xattr_raw(path, ACL_DEFAULT, probe) {
        Ok(()) => true,
        Err(err) => {
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
    }
}

#[test]
fn a_workspace_under_a_default_acl_is_captured_with_its_acl_values() {
    let tmp = tempfile::tempdir().unwrap();
    let parent = tmp.path().join("parent");
    let store_path = tmp.path().join("store");
    fs::create_dir(&parent).unwrap();
    fs::create_dir(&store_path).unwrap();
    // setfacl -d -m u::rwx,u:4242:rwx,g::r-x,m::rwx,o::--- on the parent
    let default = acl_blob(&[
        (0x01, 7, u32::MAX),
        (0x02, 7, 4242),
        (0x04, 5, u32::MAX),
        (0x10, 7, u32::MAX),
        (0x20, 0, u32::MAX),
    ]);
    if !acl_supported(&parent, &default) {
        return;
    }
    // the workspace and everything made in it inherits from the parent
    let ws_path = parent.join("ws");
    fs::create_dir(&ws_path).unwrap();
    fs::write(ws_path.join("file"), b"data").unwrap();
    fs::create_dir(ws_path.join("dir")).unwrap();
    fs::write(ws_path.join("dir/inner"), b"inner").unwrap();

    let ws_fd = open_dir(&ws_path);
    let store_fd = open_dir(&store_path);
    capture(&ws_fd, &store_fd, 0, &Limits::default()).unwrap();
    let (manifest, _) = load_manifest(&store_fd, 0).unwrap();

    let entry = |p: &str| manifest.entries.iter().find(|e| e.path == p).unwrap();
    for p in ["file", "dir", "dir/inner"] {
        let access = get_xattr_raw(&ws_path.join(p), ACL_ACCESS)
            .unwrap_or_else(|| panic!("{p} inherited no access ACL"));
        assert_eq!(
            entry(p).xattrs.get(ACL_ACCESS).map(String::as_str),
            Some(hex(&access).as_str()),
            "{p}"
        );
        assert_eq!(
            entry(p).mode,
            fs::metadata(ws_path.join(p)).unwrap().mode() & 0o7777
        );
    }
    assert_eq!(
        entry("dir").xattrs.get(ACL_DEFAULT).map(String::as_str),
        Some(hex(&default).as_str())
    );
    assert!(!entry("file").xattrs.contains_key(ACL_DEFAULT));
    assert!(!entry("dir/inner").xattrs.contains_key(ACL_DEFAULT));
}

#[test]
fn a_workspace_under_the_default_tmp_is_captured() {
    // whatever default ACL the host's /tmp carries is inherited by the workspace and the
    // directories in it; capture must accept it rather than refuse the whole workspace
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    let ws_path = tmp.path().join("ws");
    let store_path = tmp.path().join("store");
    fs::create_dir(&ws_path).unwrap();
    fs::create_dir(&store_path).unwrap();
    fs::create_dir(ws_path.join("dir")).unwrap();
    fs::write(ws_path.join("dir/f"), b"x").unwrap();
    let ws_fd = open_dir(&ws_path);
    let store_fd = open_dir(&store_path);
    capture(&ws_fd, &store_fd, 0, &Limits::default()).unwrap();
    let (manifest, _) = load_manifest(&store_fd, 0).unwrap();
    let dir = manifest.entries.iter().find(|e| e.path == "dir").unwrap();
    assert_eq!(
        dir.xattrs.get(ACL_DEFAULT).map(String::as_str),
        get_xattr_raw(&ws_path.join("dir"), ACL_DEFAULT)
            .map(|v| hex(&v))
            .as_deref()
    );
}

#[test]
fn a_trusted_xattr_is_still_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join("ws");
    let store_path = tmp.path().join("store");
    create_workspace_dir(&ws_path);
    fs::create_dir(&store_path).unwrap();
    fs::write(ws_path.join("f"), b"x").unwrap();
    match set_xattr_raw(&ws_path.join("f"), "trusted.leash.test", b"v") {
        Ok(()) => {}
        Err(err) if matches!(err.raw_os_error(), Some(libc::EPERM | libc::EACCES)) => {
            eprintln!("SKIPPED trusted.* refusal: setting it needs CAP_SYS_ADMIN ({err})");
            return;
        }
        Err(err) if matches!(err.raw_os_error(), Some(libc::EOPNOTSUPP | libc::ENOSYS)) => {
            eprintln!("SKIPPED trusted.* refusal: not supported here ({err})");
            return;
        }
        Err(err) => panic!("unexpected setxattr failure: {err}"),
    }
    let ws_fd = open_dir(&ws_path);
    let store_fd = open_dir(&store_path);
    let err = capture(&ws_fd, &store_fd, 0, &Limits::default()).unwrap_err();
    assert!(
        matches!(&err, StoreError::UnsupportedMetadata { attr, .. } if attr == "trusted.leash.test"),
        "{err}"
    );
    assert!(published_steps(&store_fd).unwrap().is_empty());
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

/// every regular file of the published manifest `step` has its object in the store, intact.
fn assert_every_object_of(store_fd: &File, step: u64) {
    let (manifest, _) = load_manifest(store_fd, step).unwrap();
    for entry in &manifest.entries {
        if let Some(sha) = entry.sha256.as_deref() {
            verify_object(store_fd, sha)
                .unwrap_or_else(|e| panic!("manifest {step}: object {sha} of {}: {e}", entry.path));
        }
    }
}

#[test]
fn an_object_already_in_the_store_is_not_written_again() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join("ws");
    let store_path = tmp.path().join("store");
    create_workspace_dir(&ws_path);
    fs::create_dir(&store_path).unwrap();
    fs::write(ws_path.join("one.txt"), b"alpha").unwrap();
    let ws_fd = open_dir(&ws_path);
    let store_fd = open_dir(&store_path);

    capture(&ws_fd, &store_fd, 0, &Limits::default()).unwrap();
    let (manifest, _) = load_manifest(&store_fd, 0).unwrap();
    let sha = manifest.entries[0].sha256.clone().unwrap();
    let object = store_path.join("objects").join(&sha[..2]).join(&sha);
    let inode = fs::metadata(&object).unwrap().ino();

    capture(&ws_fd, &store_fd, 1, &Limits::default()).unwrap();
    assert_eq!(
        fs::metadata(&object).unwrap().ino(),
        inode,
        "the object was left alone"
    );
    assert_eq!(
        fs::read_dir(store_path.join("staging")).unwrap().count(),
        0,
        "nothing was staged for it"
    );
}

#[test]
fn an_object_lost_from_the_store_is_stored_again_before_the_next_manifest_names_it() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join("ws");
    let store_path = tmp.path().join("store");
    create_workspace_dir(&ws_path);
    fs::create_dir(&store_path).unwrap();
    fs::write(ws_path.join("one.txt"), b"alpha").unwrap();
    fs::write(ws_path.join("two.txt"), b"beta").unwrap();
    let ws_fd = open_dir(&ws_path);
    let store_fd = open_dir(&store_path);

    capture(&ws_fd, &store_fd, 0, &Limits::default()).unwrap();
    let (manifest, _) = load_manifest(&store_fd, 0).unwrap();
    let sha = manifest.entries[0].sha256.clone().unwrap();
    let object = store_path.join("objects").join(&sha[..2]).join(&sha);
    fs::remove_file(&object).unwrap();

    let again = capture(&ws_fd, &store_fd, 1, &Limits::default()).unwrap();
    assert_eq!(
        again.stats.new_objects, 1,
        "only the lost object is written"
    );
    assert_eq!(again.stats.reused_objects, 1);
    assert_every_object_of(&store_fd, 1);
}

#[test]
fn a_capture_that_fails_after_storing_objects_publishes_nothing_and_the_retry_has_every_object() {
    let tmp = tempfile::tempdir().unwrap();
    let ws_path = tmp.path().join("ws");
    let store_path = tmp.path().join("store");
    create_workspace_dir(&ws_path);
    fs::create_dir(&store_path).unwrap();
    fs::write(ws_path.join("a.txt"), b"first").unwrap();
    fs::write(ws_path.join("z.txt"), b"last").unwrap();
    let fifo = ws_path.join("m-fifo");
    let c_fifo = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: c_fifo is NUL-terminated inside a temp directory we own.
    assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);
    let ws_fd = open_dir(&ws_path);
    let store_fd = open_dir(&store_path);

    // the refusal falls in the middle of the walk, after some objects were stored
    let err = capture(&ws_fd, &store_fd, 0, &Limits::default()).unwrap_err();
    assert!(
        matches!(err, StoreError::UnsupportedEntry { .. }),
        "{err:?}"
    );
    assert_eq!(published_steps(&store_fd).unwrap(), Vec::<u64>::new());
    assert_eq!(
        fs::read_dir(store_path.join("staging")).unwrap().count(),
        0,
        "no staged file survives the failure"
    );

    fs::remove_file(&fifo).unwrap();
    capture(&ws_fd, &store_fd, 0, &Limits::default()).unwrap();
    assert_every_object_of(&store_fd, 0);
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

// ---------------------------------------------------------------------------------------
// the committed steps of a run come from its trace, not from the manifests on disk
// ---------------------------------------------------------------------------------------

fn step_line(seq: u64, step: u64) -> String {
    format!(
        r#"{{"seq":{seq},"ts":1,"type":"step","step":{step},"manifest_digest":"{}"}}"#,
        "ab".repeat(32)
    )
}

fn failed_line(seq: u64, step: u64, phase: &str) -> String {
    format!(
        r#"{{"seq":{seq},"ts":1,"type":"capture_failed","step":{step},"phase":"{phase}","error":"x"}}"#
    )
}

fn trace_dir(lines: &[String]) -> (tempfile::TempDir, File) {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("trace.jsonl"), lines.join("\n") + "\n").unwrap();
    let handle = open_dir(dir.path());
    (dir, handle)
}

#[test]
fn committed_steps_are_the_step_events_in_the_trace() {
    let (_dir, run) = trace_dir(&[
        r#"{"seq":0,"ts":1,"type":"run_start"}"#.into(),
        step_line(1, 0),
        r#"{"seq":2,"ts":1,"type":"syscall","decision":"allow"}"#.into(),
        step_line(3, 1),
        step_line(4, 2),
    ]);
    assert_eq!(committed_steps_from_trace(&run).unwrap(), vec![0, 1, 2]);
}

#[test]
fn an_orphan_manifest_is_published_but_not_committed() {
    let tmp = tempfile::tempdir().unwrap();
    let run_path = tmp.path().join("run");
    let ws_path = tmp.path().join("ws");
    fs::create_dir(&run_path).unwrap();
    fs::create_dir(run_path.join("snapshots")).unwrap();
    create_workspace_dir(&ws_path);
    let store_fd = open_dir(&run_path.join("snapshots"));
    let ws_fd = open_dir(&ws_path);
    capture(&ws_fd, &store_fd, 0, &Limits::default()).unwrap();
    capture(&ws_fd, &store_fd, 1, &Limits::default()).unwrap();
    // step 1's event never became durable
    fs::write(
        run_path.join("trace.jsonl"),
        [step_line(0, 0), failed_line(1, 1, "step_event")].join("\n") + "\n",
    )
    .unwrap();
    let run = open_dir(&run_path);
    assert_eq!(published_steps(&store_fd).unwrap(), vec![0, 1]);
    assert_eq!(committed_steps_from_trace(&run).unwrap(), vec![0]);
}

#[test]
fn only_a_step_event_failure_for_the_same_step_uncommits_it() {
    // thaw, capture, frozen_check and freeze failures leave the committed set alone: after a
    // thaw failure the step event was already durable, and the others never wrote one
    for phase in ["thaw", "capture", "frozen_check", "freeze"] {
        let (_dir, run) = trace_dir(&[step_line(0, 0), step_line(1, 1), failed_line(2, 1, phase)]);
        assert_eq!(
            committed_steps_from_trace(&run).unwrap(),
            vec![0, 1],
            "{phase}"
        );
    }
    // a step_event failure for a different step changes nothing either
    let (_dir, run) = trace_dir(&[
        step_line(0, 0),
        step_line(1, 1),
        failed_line(2, 2, "step_event"),
    ]);
    assert_eq!(committed_steps_from_trace(&run).unwrap(), vec![0, 1]);
    // and one for the step just written removes exactly that step
    let (_dir, run) = trace_dir(&[
        step_line(0, 0),
        step_line(1, 1),
        failed_line(2, 1, "step_event"),
    ]);
    assert_eq!(committed_steps_from_trace(&run).unwrap(), vec![0]);
}

#[test]
fn text_an_agent_controls_cannot_forge_a_step_event() {
    // a syscall event whose recorded path spells a step event: JSON escapes its quotes
    let forged = serde_json::json!({
        "seq": 1, "ts": 1, "type": "syscall",
        "fact": {"path": r#"x","type":"step","step":9,"y":""#},
    })
    .to_string();
    let (_dir, run) = trace_dir(&[step_line(0, 0), forged]);
    assert_eq!(committed_steps_from_trace(&run).unwrap(), vec![0]);
}

#[test]
fn a_final_line_torn_by_a_crash_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let mut text = [step_line(0, 0), step_line(1, 1)].join("\n");
    text.push('\n');
    text.push_str(r#"{"seq":2,"ts":1,"type":"step","step":2"#);
    fs::write(dir.path().join("trace.jsonl"), text).unwrap();
    assert_eq!(
        committed_steps_from_trace(&open_dir(dir.path())).unwrap(),
        vec![0, 1]
    );
}

#[test]
fn a_malformed_or_non_ascending_step_event_is_an_invalid_trace() {
    for lines in [
        vec![
            step_line(0, 0),
            r#"{"seq":1,"type":"step","step":"one"}"#.to_string(),
        ],
        vec![step_line(0, 0), r#"{"seq":1,"type":"step"}"#.to_string()],
        vec![step_line(0, 1), step_line(1, 1)],
        vec![step_line(0, 2), step_line(1, 1)],
        vec![
            step_line(0, 0),
            r#"{"type":"step","step":1 not json"#.to_string(),
        ],
    ] {
        let (_dir, run) = trace_dir(&lines);
        let err = committed_steps_from_trace(&run).unwrap_err();
        assert!(
            matches!(err, StoreError::InvalidTrace { .. }),
            "{lines:?}: {err:?}"
        );
    }
}

#[test]
fn a_symlinked_or_special_trace_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    fs::write(&real, step_line(0, 0) + "\n").unwrap();
    symlink(&real, dir.path().join("trace.jsonl")).unwrap();
    let err = committed_steps_from_trace(&open_dir(dir.path())).unwrap_err();
    assert!(
        matches!(&err, StoreError::InvalidTrace { reason } if reason.contains("symlink")),
        "{err:?}"
    );

    let fifo_dir = tempfile::tempdir().unwrap();
    let fifo = CString::new(fifo_dir.path().join("trace.jsonl").as_os_str().as_bytes()).unwrap();
    // SAFETY: fifo is NUL-terminated inside a directory this test owns.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let err = committed_steps_from_trace(&open_dir(fifo_dir.path())).unwrap_err();
    assert!(
        matches!(&err, StoreError::InvalidTrace { reason } if reason.contains("not a regular file")),
        "{err:?}"
    );
}

#[test]
fn a_large_trace_is_read_to_its_end_because_it_grows_with_agent_activity() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let mut out = std::io::BufWriter::new(File::create(dir.path().join("trace.jsonl")).unwrap());
    // the filler lines are under the line cap, and together they are far larger than any
    // fixed size cap a long run's trace could be held to: 64 MiB of syscall events between
    // two steps
    let filler = format!(
        r#"{{"seq":1,"ts":1,"type":"syscall","decision":"allow","path":"{}"}}"#,
        "p".repeat(900)
    );
    writeln!(out, "{}", step_line(0, 0)).unwrap();
    for _ in 0..(64 * 1024 * 1024 / (filler.len() + 1)) {
        writeln!(out, "{filler}").unwrap();
    }
    writeln!(out, "{}", step_line(1, 1)).unwrap();
    out.flush().unwrap();
    drop(out);
    assert!(fs::metadata(dir.path().join("trace.jsonl")).unwrap().len() > 60 * 1024 * 1024);
    assert_eq!(
        committed_steps_from_trace(&open_dir(dir.path())).unwrap(),
        [0, 1]
    );
}

#[test]
fn a_line_over_the_line_cap_is_refused() {
    let long = tempfile::tempdir().unwrap();
    let mut text = "x".repeat(TRACE_LINE_CAP + 10);
    text.push('\n');
    fs::write(long.path().join("trace.jsonl"), text).unwrap();
    let err = committed_steps_from_trace(&open_dir(long.path())).unwrap_err();
    assert!(
        matches!(&err, StoreError::InvalidTrace { reason } if reason.contains("longer than")),
        "{err:?}"
    );
}

#[test]
fn more_step_events_than_the_step_cap_are_refused() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let mut out = std::io::BufWriter::new(File::create(dir.path().join("trace.jsonl")).unwrap());
    for step in 0..=TRACE_STEP_CAP {
        writeln!(out, r#"{{"type":"step","step":{step}}}"#).unwrap();
    }
    out.flush().unwrap();
    drop(out);
    let err = committed_steps_from_trace(&open_dir(dir.path())).unwrap_err();
    assert!(
        matches!(&err, StoreError::InvalidTrace { reason } if reason.contains("step events")),
        "{err:?}"
    );
}

#[test]
fn a_missing_trace_is_a_not_found_error() {
    let dir = tempfile::tempdir().unwrap();
    let err = committed_steps_from_trace(&open_dir(dir.path())).unwrap_err();
    assert!(
        matches!(&err, StoreError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------------------------
// one streaming, capped pass over the trace: committed steps, digests and run_start
// ---------------------------------------------------------------------------------------

fn start_line(workspace: &str) -> String {
    format!(
        r#"{{"seq":0,"ts":1,"type":"run_start","workspace":"{workspace}","run_cgroup":"/cg/leash-x"}}"#
    )
}

#[test]
fn read_trace_returns_the_committed_steps_their_digests_and_the_run_start() {
    let (_dir, run) = trace_dir(&[
        start_line("/w"),
        step_line(1, 0),
        r#"{"seq":2,"ts":1,"type":"syscall","decision":"allow"}"#.into(),
        step_line(3, 1),
        r#"{"seq":4,"ts":1,"type":"step","step":2}"#.into(),
    ]);
    let trace = read_trace(&run).unwrap();
    assert_eq!(trace.committed, vec![0, 1, 2]);
    assert_eq!(trace.events, 5);
    assert_eq!(
        trace.digests.keys().copied().collect::<Vec<_>>(),
        vec![0, 1],
        "a step event without a digest binds no snapshot"
    );
    assert_eq!(trace.digests[&0], "ab".repeat(32));
    let start = trace.run_start.unwrap();
    assert_eq!(start.workspace.as_deref(), Some(Path::new("/w")));
    assert_eq!(start.run_cgroup.as_deref(), Some(Path::new("/cg/leash-x")));
    // the one parser: the committed list is the committed list of read_trace
    assert_eq!(committed_steps_from_trace(&run).unwrap(), vec![0, 1, 2]);
}

#[test]
fn a_step_event_that_failed_to_commit_takes_its_digest_with_it() {
    let (_dir, run) = trace_dir(&[
        start_line("/w"),
        step_line(1, 0),
        step_line(2, 1),
        failed_line(3, 1, "step_event"),
    ]);
    let trace = read_trace(&run).unwrap();
    assert_eq!(trace.committed, vec![0]);
    assert_eq!(trace.digests.keys().copied().collect::<Vec<_>>(), vec![0]);
}

#[test]
fn a_trace_that_does_not_start_with_run_start_reports_none() {
    let (_dir, run) = trace_dir(&[step_line(0, 0)]);
    let trace = read_trace(&run).unwrap();
    assert!(trace.run_start.is_none());
    assert_eq!(trace.events, 1);
}

#[test]
fn an_empty_line_a_second_run_start_and_a_bad_digest_are_invalid() {
    for (lines, needle) in [
        (
            vec![start_line("/w"), String::new(), step_line(2, 0)],
            "empty",
        ),
        (vec![start_line("/w"), start_line("/w")], "second run_start"),
        (
            vec![
                start_line("/w"),
                format!(
                    r#"{{"seq":1,"type":"step","step":0,"manifest_digest":"{}"}}"#,
                    "AB".repeat(32)
                ),
            ],
            "64 lowercase hex",
        ),
        (
            vec![
                start_line("/w"),
                r#"{"seq":1,"type":"step","step":0,"manifest_digest":"abc"}"#.into(),
            ],
            "64 lowercase hex",
        ),
    ] {
        let (_dir, run) = trace_dir(&lines);
        let err = read_trace(&run).unwrap_err();
        assert!(
            matches!(&err, StoreError::InvalidTrace { reason } if reason.contains(needle)),
            "{lines:?}: {err:?}"
        );
    }
}

#[test]
fn a_trace_of_only_newlines_is_refused_at_its_first_line() {
    // the recorder never writes an empty line, so a file of newlines is refused at once
    // instead of being split into millions of lines
    let dir = tempfile::tempdir().unwrap();
    let size = 8 * 1024 * 1024;
    fs::write(dir.path().join("trace.jsonl"), vec![b'\n'; size]).unwrap();
    let err = read_trace(&open_dir(dir.path())).unwrap_err();
    assert!(
        matches!(&err, StoreError::InvalidTrace { reason } if reason.contains("line 1 is empty")),
        "{err:?}"
    );
    // with the line cap lowered, the answer is the same
    let err = read_trace_capped(&open_dir(dir.path()), 1024).unwrap_err();
    assert!(
        matches!(&err, StoreError::InvalidTrace { reason } if reason.contains("line 1 is empty")),
        "{err:?}"
    );
}

#[test]
fn one_oversized_line_is_refused_without_buffering_it() {
    let dir = tempfile::tempdir().unwrap();
    // no newline at all: the line is cut at the line cap, not read to its end
    let size = 4 * 1024 * 1024;
    fs::write(dir.path().join("trace.jsonl"), vec![b'x'; size]).unwrap();
    let err = read_trace_capped(&open_dir(dir.path()), 64 * 1024).unwrap_err();
    assert!(
        matches!(&err, StoreError::InvalidTrace { reason } if reason.contains("longer than 65536")),
        "{err:?}"
    );
}
