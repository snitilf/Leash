//! Linux kernel-mechanics probes for ADR-0020.
//!
//! These tests deliberately exercise raw kernel behavior before the production broker
//! protocol depends on it: Landlock confinement of a sibling broker process, fd return
//! through SCM_RIGHTS, and socket-state preservation through pidfd_getfd.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::CString;
use std::io::Read;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use leash::policy::{ExpandContext, Policy};
use leash::sandbox::landlock;
use leash::supervisor::broker::{
    Broker, BrokerResult, BrokerResultOrPath, MutationOperation, NetworkOperation, PreparedPath,
};

static FORK_LOCK: Mutex<()> = Mutex::new(());

fn fork_guard() -> MutexGuard<'static, ()> {
    FORK_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn prepare_path(
    broker: &mut Broker,
    path: &Path,
    follow: bool,
    allow_missing: bool,
) -> PreparedPath {
    match broker.prepare_path(path, follow, allow_missing).unwrap() {
        BrokerResultOrPath::Path(path) => path,
        other => panic!("expected prepared path, got {other:?}"),
    }
}

#[test]
fn confined_broker_returns_allowed_fd_and_cannot_open_outside_hull() {
    let _guard = fork_guard();
    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let allowed_path = workspace.path().join("allowed.txt");
    let denied_path = outside.path().join("denied.txt");
    std::fs::write(&allowed_path, b"broker-ok").unwrap();
    std::fs::write(&denied_path, b"must-not-open").unwrap();

    let policy = Policy::parse(
        "schema_version = 1\n",
        &ExpandContext {
            workspace: workspace.path().to_str().unwrap(),
            home: "/tmp",
        },
    )
    .unwrap();
    let ruleset = landlock::build_ruleset(&landlock::derive_hull(&policy, 4)).unwrap();
    let allowed_c = CString::new(allowed_path.as_os_str().as_encoded_bytes()).unwrap();
    let denied_c = CString::new(denied_path.as_os_str().as_encoded_bytes()).unwrap();
    let (parent_sock, child_sock) = seqpacket_pair();

    // SAFETY: the child branch uses only async-signal-safe syscalls before _exit.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
    if pid == 0 {
        drop(parent_sock);
        // SAFETY: prctl and Landlock take scalar arguments owned by this child.
        let no_new_privs = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if no_new_privs != 0 {
            unsafe { libc::_exit(10) };
        }
        // SAFETY: the inherited fd is a live Landlock ruleset.
        if !unsafe { landlock::restrict_self(ruleset.as_raw_fd()) } {
            unsafe { libc::_exit(11) };
        }
        // SAFETY: both C strings are inherited immutable storage.
        let allowed_fd =
            unsafe { libc::open(allowed_c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if allowed_fd < 0 {
            unsafe { libc::_exit(12) };
        }
        if send_fd(child_sock.as_raw_fd(), allowed_fd).is_err() {
            unsafe { libc::_exit(13) };
        }
        // SAFETY: the fd was opened above and is no longer needed in the child.
        unsafe { libc::close(allowed_fd) };

        // SAFETY: the path storage is valid and Landlock must reject this open.
        let denied_fd = unsafe { libc::open(denied_c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if denied_fd >= 0 {
            unsafe {
                libc::close(denied_fd);
                libc::_exit(14);
            }
        }
        let errno = std::io::Error::last_os_error().raw_os_error();
        unsafe {
            libc::_exit(if matches!(errno, Some(libc::EACCES | libc::EPERM)) {
                0
            } else {
                15
            });
        }
    }

    drop(child_sock);
    let mut returned = recv_fd(parent_sock.as_raw_fd()).expect("broker returns an fd");
    let mut contents = String::new();
    returned.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "broker-ok");
    assert_eq!(wait_exit(pid), 0);
}

#[test]
fn pidfd_duplicate_operates_on_the_childs_socket_object() {
    let _guard = fork_guard();
    let (parent_control, child_control) = seqpacket_pair();

    // SAFETY: the child branch uses only socket IPC and _exit.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
    if pid == 0 {
        drop(parent_control);
        // SAFETY: socket returns a new fd or -1.
        let socket =
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if socket < 0 {
            unsafe { libc::_exit(20) };
        }
        let bytes = socket.to_ne_bytes();
        // SAFETY: send reads the four-byte local array.
        if unsafe {
            libc::send(
                child_control.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
            )
        } != bytes.len() as isize
        {
            unsafe { libc::_exit(21) };
        }
        let mut ack = 0u8;
        // SAFETY: recv writes one byte to the local ack.
        let received =
            unsafe { libc::recv(child_control.as_raw_fd(), (&raw mut ack).cast(), 1, 0) };
        unsafe {
            libc::close(socket);
            libc::_exit(if received == 1 { 0 } else { 22 });
        }
    }

    drop(child_control);
    let mut child_fd_bytes = [0u8; size_of::<RawFd>()];
    recv_exact(parent_control.as_raw_fd(), &mut child_fd_bytes);
    let child_fd = RawFd::from_ne_bytes(child_fd_bytes);

    // SAFETY: pidfd_open takes a live child pid and zero flags.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(
        pidfd >= 0,
        "pidfd_open: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: pidfd names our child and child_fd is the fd number it reported.
    let duplicate = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, child_fd, 0) };
    // SAFETY: pidfd is no longer needed after duplication.
    unsafe { libc::close(pidfd as RawFd) };
    assert!(
        duplicate >= 0,
        "pidfd_getfd: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: pidfd_getfd returned a new owned descriptor.
    let duplicate = unsafe { OwnedFd::from_raw_fd(duplicate as RawFd) };

    let receiver = udp_receiver();
    let address = receiver_address(&receiver);
    // SAFETY: connect applies to the duplicated socket and reads the local sockaddr.
    let connected = unsafe {
        libc::connect(
            duplicate.as_raw_fd(),
            (&raw const address).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    assert_eq!(
        connected,
        0,
        "connect duplicate: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: send reads the local payload and uses the connected duplicate.
    let sent = unsafe {
        libc::send(
            duplicate.as_raw_fd(),
            b"pidfd-ok".as_ptr().cast(),
            b"pidfd-ok".len(),
            0,
        )
    };
    assert_eq!(sent, b"pidfd-ok".len() as isize);

    let mut payload = [0u8; 32];
    // SAFETY: recv writes into the local payload buffer.
    let received = unsafe {
        libc::recv(
            receiver.as_raw_fd(),
            payload.as_mut_ptr().cast(),
            payload.len(),
            0,
        )
    };
    assert_eq!(&payload[..received as usize], b"pidfd-ok");

    // SAFETY: send reads one local byte and releases the child.
    assert_eq!(
        unsafe { libc::send(parent_control.as_raw_fd(), b"x".as_ptr().cast(), 1, 0) },
        1
    );
    assert_eq!(wait_exit(pid), 0);
}

#[test]
fn production_broker_prepares_and_commits_an_allowed_open() {
    let _guard = fork_guard();
    let workspace = tempfile::tempdir().unwrap();
    let allowed_path = workspace.path().join("allowed.txt");
    std::fs::write(&allowed_path, b"prepared-open").unwrap();
    let policy = Policy::parse(
        "schema_version = 1\n",
        &ExpandContext {
            workspace: workspace.path().to_str().unwrap(),
            home: "/tmp",
        },
    )
    .unwrap();
    let prepared_ruleset = landlock::prepare_ruleset(&landlock::derive_hull(&policy, 4)).unwrap();
    let mut broker = Broker::spawn(&prepared_ruleset, workspace.path()).unwrap();
    let prepared = match broker.prepare_path(&allowed_path, true, false).unwrap() {
        BrokerResultOrPath::Path(path) => path,
        other => panic!("expected prepared path, got {other:?}"),
    };
    assert_eq!(prepared.identity(), allowed_path);
    let mut returned = match broker
        .commit_open(prepared, libc::O_RDONLY as u64, 0)
        .unwrap()
    {
        BrokerResult::Fd(fd) => std::fs::File::from(fd),
        other => panic!("expected returned fd, got {other:?}"),
    };
    let mut contents = String::new();
    returned.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "prepared-open");
}

/// the broker is a forked copy of the supervisor and must drop every descriptor it does not
/// need, the live trace above all. a real run's supervisor and broker are non-dumpable, so
/// their `/proc/<pid>/fd` is unreadable from outside; this test process is dumpable, which
/// lets it read the broker's table directly and see exactly what the production
/// `Broker::spawn` leaves open after its handshake.
#[test]
fn broker_closes_inherited_descriptors_it_does_not_need() {
    let _guard = fork_guard();
    let workspace = tempfile::tempdir().unwrap();
    let run_dir = tempfile::tempdir().unwrap();
    // stand-ins for what the supervisor holds when it forks: the live trace, a run directory
    // handle, and a spare descriptor (the fork keeps all of them)
    let trace = std::fs::File::create(run_dir.path().join("trace.jsonl")).unwrap();
    let run_handle = std::fs::File::open(run_dir.path()).unwrap();
    let spare = std::fs::File::open("/dev/null").unwrap();
    let policy = Policy::parse(
        "schema_version = 1\n",
        &ExpandContext {
            workspace: workspace.path().to_str().unwrap(),
            home: "/tmp",
        },
    )
    .unwrap();
    let prepared_ruleset = landlock::prepare_ruleset(&landlock::derive_hull(&policy, 4)).unwrap();
    let broker = Broker::spawn(&prepared_ruleset, workspace.path()).unwrap();

    // dumpable here, so the table is readable; a failed read must fail the test, never pass it
    let fd_dir = format!("/proc/{}/fd", broker.pid());
    let held: Vec<(i32, String)> = std::fs::read_dir(&fd_dir)
        .unwrap_or_else(|e| panic!("cannot read {fd_dir}: {e}"))
        .map(|entry| {
            let entry = entry.unwrap();
            let fd = entry.file_name().to_str().unwrap().parse::<i32>().unwrap();
            let target = std::fs::read_link(entry.path()).ok();
            (
                fd,
                target.map_or_else(String::new, |t| t.to_string_lossy().into_owned()),
            )
        })
        .collect();
    assert!(
        held.len() >= 4,
        "the broker keeps stdio and its socket at least: {held:?}"
    );
    for stand_in in [trace.as_raw_fd(), run_handle.as_raw_fd(), spare.as_raw_fd()] {
        assert!(
            held.iter().all(|(fd, _)| *fd != stand_in),
            "the broker still holds inherited descriptor {stand_in}: {held:?}"
        );
    }
    let run_prefix = run_dir.path().to_str().unwrap();
    assert!(
        held.iter()
            .all(|(_, t)| !t.contains("trace.jsonl") && !t.starts_with(run_prefix)),
        "the broker holds the trace or a run directory: {held:?}"
    );
}

#[test]
fn production_broker_preserves_o_path_directory_validation() {
    let _guard = fork_guard();
    let workspace = tempfile::tempdir().unwrap();
    let file = workspace.path().join("regular-file");
    std::fs::write(&file, b"data").unwrap();
    let policy = Policy::parse(
        "schema_version = 1\n",
        &ExpandContext {
            workspace: workspace.path().to_str().unwrap(),
            home: "/tmp",
        },
    )
    .unwrap();
    let prepared_ruleset = landlock::prepare_ruleset(&landlock::derive_hull(&policy, 4)).unwrap();
    let mut broker = Broker::spawn(&prepared_ruleset, workspace.path()).unwrap();
    let prepared = match broker.prepare_path(&file, true, false).unwrap() {
        BrokerResultOrPath::Path(path) => path,
        other => panic!("expected prepared path, got {other:?}"),
    };
    match broker
        .commit_open(
            prepared,
            u64::try_from(libc::O_PATH | libc::O_DIRECTORY).unwrap(),
            0,
        )
        .unwrap()
    {
        BrokerResult::Errno(errno) => assert_eq!(errno, libc::ENOTDIR),
        other => panic!("expected ENOTDIR, got {other:?}"),
    }
}

/// issue #53: SECCOMP_IOCTL_NOTIF_ADDFD refuses an O_PATH source descriptor (the kernel's
/// fget rejects FMODE_PATH files with EBADF), so the broker answers an O_PATH open with a
/// read-only descriptor on the same pinned object instead. a kind it cannot reopen safely
/// is refused with EOPNOTSUPP. whether the agent's descriptor is close-on-exec is set by
/// the ADDFD, not this descriptor, and is covered end to end in cli_linux.
#[test]
fn production_broker_realizes_o_path_as_a_read_only_descriptor() {
    use std::os::unix::fs::{MetadataExt, symlink};

    let _guard = fork_guard();
    let workspace = tempfile::tempdir().unwrap();
    let dir = workspace.path().join("dir");
    std::fs::create_dir(&dir).unwrap();
    let file = workspace.path().join("regular-file");
    std::fs::write(&file, b"data").unwrap();
    let link = workspace.path().join("link-to-file");
    // relative, so the workspace anchor (RESOLVE_BENEATH) can follow it
    symlink("regular-file", &link).unwrap();
    let fifo = workspace.path().join("fifo");
    let fifo_c = CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: fifo_c is a valid nul-terminated path.
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
    let socket = workspace.path().join("socket");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    // the hull must reach /dev/null for the device case to get past path preparation
    let policy = Policy::parse(
        "schema_version = 1\n\
         [[fs]]\npath=\"/dev/null\"\nmode=[\"read\"]\naction=\"allow\"\n",
        &ExpandContext {
            workspace: workspace.path().to_str().unwrap(),
            home: "/tmp",
        },
    )
    .unwrap();
    let prepared_ruleset = landlock::prepare_ruleset(&landlock::derive_hull(&policy, 4)).unwrap();
    let mut broker = Broker::spawn(&prepared_ruleset, workspace.path()).unwrap();
    let o_path = u64::try_from(libc::O_PATH | libc::O_CLOEXEC).unwrap();
    let o_nofollow = u64::try_from(libc::O_NOFOLLOW).unwrap();
    let mut open = |path: &Path, flags: u64| {
        let prepared = prepare_path(&mut broker, path, flags & o_nofollow == 0, false);
        broker.commit_open(prepared, flags, 0).unwrap()
    };

    for (path, flags) in [
        (&dir, o_path | u64::try_from(libc::O_DIRECTORY).unwrap()),
        (&dir, o_path),
        (&file, o_path),
        // without O_NOFOLLOW the link is followed to the regular file
        (&link, o_path),
    ] {
        let BrokerResult::Fd(fd) = open(path, flags) else {
            panic!("O_PATH open of {path:?} must yield a descriptor");
        };
        // SAFETY: fd is a live descriptor.
        let status = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        assert!(status >= 0);
        assert_eq!(status & libc::O_PATH, 0, "must not be an O_PATH file");
        assert_eq!(status & libc::O_ACCMODE, libc::O_RDONLY);
        // the substitute is the very object the policy judged, not a re-resolved path
        let mut stat: libc::stat = unsafe { zeroed() };
        // SAFETY: fd is live and stat points to writable local storage.
        assert_eq!(unsafe { libc::fstat(fd.as_raw_fd(), &raw mut stat) }, 0);
        let expected = std::fs::metadata(path).unwrap();
        assert_eq!(
            (stat.st_dev, stat.st_ino),
            (expected.dev(), expected.ino()),
            "{path:?}"
        );
    }

    // a kind whose read-only open can block, has side effects, or cannot be reopened
    // without following a symlink is refused, not opened
    let dev_null = Path::new("/dev/null");
    for (path, flags, kind) in [
        (&link, o_path | o_nofollow, "symlink under O_NOFOLLOW"),
        (&fifo, o_path, "fifo"),
        (&socket, o_path, "unix socket"),
        (&dev_null.to_path_buf(), o_path, "character device"),
    ] {
        match open(path, flags) {
            BrokerResult::Errno(errno) => assert_eq!(errno, libc::EOPNOTSUPP, "{kind}"),
            other => panic!("expected EOPNOTSUPP for a {kind}, got {other:?}"),
        }
    }

    // O_PATH honors only O_DIRECTORY, O_NOFOLLOW, and O_CLOEXEC: a stray O_CREAT creates
    // nothing and O_TRUNC truncates nothing
    let missing = workspace.path().join("missing");
    match broker.prepare_path(&missing, true, true).unwrap() {
        BrokerResultOrPath::Path(prepared) => {
            let flags = o_path | u64::try_from(libc::O_CREAT | libc::O_WRONLY).unwrap();
            match broker.commit_open(prepared, flags, 0o600).unwrap() {
                BrokerResult::Errno(errno) => assert_eq!(errno, libc::ENOENT),
                other => panic!("expected ENOENT, got {other:?}"),
            }
        }
        other => panic!("expected prepared path, got {other:?}"),
    }
    assert!(!missing.exists(), "O_PATH | O_CREAT must not create");
    let prepared = prepare_path(&mut broker, &file, true, false);
    let flags = o_path | u64::try_from(libc::O_TRUNC | libc::O_WRONLY).unwrap();
    assert!(matches!(
        broker.commit_open(prepared, flags, 0).unwrap(),
        BrokerResult::Fd(_)
    ));
    assert_eq!(std::fs::read(&file).unwrap(), b"data", "O_TRUNC is ignored");
}

#[test]
fn production_broker_realizes_the_filesystem_mutation_family() {
    let _guard = fork_guard();
    let workspace = tempfile::tempdir().unwrap();
    let source = workspace.path().join("source");
    let hard_link = workspace.path().join("hard-link");
    let renamed = workspace.path().join("renamed");
    let directory = workspace.path().join("directory");
    let symbolic = workspace.path().join("symbolic");
    std::fs::write(&source, b"source-data").unwrap();
    let policy = Policy::parse(
        "schema_version = 1\n",
        &ExpandContext {
            workspace: workspace.path().to_str().unwrap(),
            home: "/tmp",
        },
    )
    .unwrap();
    let prepared_ruleset = landlock::prepare_ruleset(&landlock::derive_hull(&policy, 4)).unwrap();
    let mut broker = Broker::spawn(&prepared_ruleset, workspace.path()).unwrap();

    let prepared = prepare_path(&mut broker, &source, true, false);
    let result = broker
        .commit_mutation(prepared, None, MutationOperation::Truncate { length: 6 })
        .unwrap();
    assert!(matches!(result, BrokerResult::Value(0)));
    assert_eq!(std::fs::read(&source).unwrap(), b"source");

    let prepared = prepare_path(&mut broker, &directory, false, true);
    let result = broker
        .commit_mutation(prepared, None, MutationOperation::Mkdir { mode: 0o700 })
        .unwrap();
    assert!(matches!(result, BrokerResult::Value(0)));
    assert!(directory.is_dir());

    let prepared = prepare_path(&mut broker, &symbolic, false, true);
    let result = broker
        .commit_mutation(
            prepared,
            None,
            MutationOperation::Symlink {
                target: b"source".to_vec(),
            },
        )
        .unwrap();
    assert!(matches!(result, BrokerResult::Value(0)));
    assert_eq!(std::fs::read_link(&symbolic).unwrap(), Path::new("source"));

    let source_prepared = prepare_path(&mut broker, &source, false, false);
    let link_prepared = prepare_path(&mut broker, &hard_link, false, true);
    let result = broker
        .commit_mutation(
            source_prepared,
            Some(link_prepared),
            MutationOperation::Link { flags: 0 },
        )
        .unwrap();
    assert!(matches!(result, BrokerResult::Value(0)));
    assert_eq!(std::fs::read(&hard_link).unwrap(), b"source");

    let source_prepared = prepare_path(&mut broker, &source, false, false);
    let renamed_prepared = prepare_path(&mut broker, &renamed, false, true);
    let result = broker
        .commit_mutation(
            source_prepared,
            Some(renamed_prepared),
            MutationOperation::Rename { flags: 0 },
        )
        .unwrap();
    assert!(matches!(result, BrokerResult::Value(0)));
    assert!(!source.exists());
    assert_eq!(std::fs::read(&renamed).unwrap(), b"source");

    let exchange = workspace.path().join("exchange");
    std::fs::write(&exchange, b"exchange").unwrap();
    let renamed_prepared = prepare_path(&mut broker, &renamed, false, false);
    let exchange_prepared = prepare_path(&mut broker, &exchange, false, false);
    let result = broker
        .commit_mutation(
            renamed_prepared,
            Some(exchange_prepared),
            MutationOperation::Rename { flags: 2 },
        )
        .unwrap();
    assert!(matches!(result, BrokerResult::Value(0)));
    assert_eq!(std::fs::read(&renamed).unwrap(), b"exchange");
    assert_eq!(std::fs::read(&exchange).unwrap(), b"source");

    for operation in [
        MutationOperation::Chmod { mode: 0o600 },
        MutationOperation::Chown {
            uid: u32::MAX,
            gid: u32::MAX,
            flags: 0,
        },
    ] {
        let prepared = prepare_path(&mut broker, &renamed, true, false);
        let result = broker.commit_mutation(prepared, None, operation).unwrap();
        assert!(matches!(result, BrokerResult::Value(0)));
    }

    let prepared = prepare_path(&mut broker, &hard_link, false, false);
    let result = broker
        .commit_mutation(prepared, None, MutationOperation::Unlink { flags: 0 })
        .unwrap();
    assert!(matches!(result, BrokerResult::Value(0)));
    assert!(!hard_link.exists());
}

#[test]
fn production_broker_rejects_a_path_outside_every_anchor() {
    let _guard = fork_guard();
    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside_path = outside.path().join("outside.txt");
    std::fs::write(&outside_path, b"outside").unwrap();
    let policy = Policy::parse(
        "schema_version = 1\n",
        &ExpandContext {
            workspace: workspace.path().to_str().unwrap(),
            home: "/tmp",
        },
    )
    .unwrap();
    let prepared_ruleset = landlock::prepare_ruleset(&landlock::derive_hull(&policy, 4)).unwrap();
    let mut broker = Broker::spawn(&prepared_ruleset, workspace.path()).unwrap();
    match broker.prepare_path(&outside_path, true, false).unwrap() {
        BrokerResultOrPath::Result(BrokerResult::Errno(errno)) => {
            assert_eq!(errno, libc::EACCES)
        }
        other => panic!("expected EACCES, got {other:?}"),
    }
}

#[test]
fn prepared_open_is_pinned_across_a_symlink_swap() {
    let _guard = fork_guard();
    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let requested = workspace.path().join("requested.txt");
    let pinned = workspace.path().join("pinned.txt");
    let protected = outside.path().join("protected.txt");
    std::fs::write(&requested, b"original").unwrap();
    std::fs::write(&protected, b"protected").unwrap();
    let policy = Policy::parse(
        "schema_version = 1\n",
        &ExpandContext {
            workspace: workspace.path().to_str().unwrap(),
            home: "/tmp",
        },
    )
    .unwrap();
    let prepared_ruleset = landlock::prepare_ruleset(&landlock::derive_hull(&policy, 4)).unwrap();
    let mut broker = Broker::spawn(&prepared_ruleset, workspace.path()).unwrap();
    let prepared = match broker.prepare_path(&requested, true, false).unwrap() {
        BrokerResultOrPath::Path(path) => path,
        other => panic!("expected prepared path, got {other:?}"),
    };

    std::fs::rename(&requested, &pinned).unwrap();
    std::os::unix::fs::symlink(&protected, &requested).unwrap();
    let returned = match broker
        .commit_open(prepared, (libc::O_WRONLY | libc::O_TRUNC) as u64, 0)
        .unwrap()
    {
        BrokerResult::Fd(fd) => fd,
        other => panic!("expected returned fd, got {other:?}"),
    };
    drop(returned);

    assert_eq!(std::fs::read(&pinned).unwrap(), b"");
    assert_eq!(std::fs::read(&protected).unwrap(), b"protected");
}

#[test]
fn production_broker_sends_the_copied_udp_payload() {
    let _guard = fork_guard();
    let workspace = tempfile::tempdir().unwrap();
    let receiver = udp_receiver();
    let address = receiver_address(&receiver);
    let policy = Policy::parse(
        "schema_version = 1\n",
        &ExpandContext {
            workspace: workspace.path().to_str().unwrap(),
            home: "/tmp",
        },
    )
    .unwrap();
    let prepared_ruleset = landlock::prepare_ruleset(&landlock::derive_hull(&policy, 4)).unwrap();
    let mut broker = Broker::spawn(&prepared_ruleset, workspace.path()).unwrap();
    // SAFETY: socket returns a newly owned descriptor or -1.
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    assert!(socket >= 0, "socket: {}", std::io::Error::last_os_error());
    // SAFETY: socket returned a new owned descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };
    // SAFETY: sockaddr_in is plain initialized storage and the slice does not outlive it.
    let address_bytes = unsafe {
        std::slice::from_raw_parts(
            (&raw const address).cast::<u8>(),
            size_of::<libc::sockaddr_in>(),
        )
    }
    .to_vec();
    let result = broker
        .network(
            NetworkOperation::SendTo,
            socket,
            address_bytes,
            b"broker-sendto".to_vec(),
            0,
        )
        .unwrap();
    assert!(matches!(
        result,
        BrokerResult::Value(value) if value == b"broker-sendto".len() as i64
    ));

    let mut payload = [0u8; 32];
    // SAFETY: recv writes into the local payload buffer.
    let received = unsafe {
        libc::recv(
            receiver.as_raw_fd(),
            payload.as_mut_ptr().cast(),
            payload.len(),
            0,
        )
    };
    assert_eq!(&payload[..received as usize], b"broker-sendto");
}

fn seqpacket_pair() -> (OwnedFd, OwnedFd) {
    let mut pair = [-1; 2];
    // SAFETY: socketpair writes two owned descriptors into pair.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    };
    assert_eq!(rc, 0, "socketpair: {}", std::io::Error::last_os_error());
    // SAFETY: socketpair returned two distinct owned descriptors.
    unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) }
}

fn send_fd(socket: RawFd, fd: RawFd) -> std::io::Result<()> {
    let mut byte = b'f';
    let mut iov = libc::iovec {
        iov_base: (&raw mut byte).cast(),
        iov_len: 1,
    };
    let mut control = [0u8; 64];
    // SAFETY: zeroed msghdr is initialized with valid iovec and control storage below.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    // SAFETY: the control buffer is aligned enough for cmsghdr on supported Linux targets,
    // and CMSG_* operates within the buffer sized above.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null() {
            return Err(std::io::Error::other("SCM_RIGHTS header did not fit"));
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize;
        libc::CMSG_DATA(header).cast::<RawFd>().write(fd);
        message.msg_controllen = (*header).cmsg_len;
        if libc::sendmsg(socket, &message, 0) == 1 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

fn recv_fd(socket: RawFd) -> std::io::Result<std::fs::File> {
    let mut byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: (&raw mut byte).cast(),
        iov_len: 1,
    };
    let mut control = [0u8; 64];
    // SAFETY: zeroed msghdr is initialized with valid writable storage below.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    // SAFETY: recvmsg writes only into the declared iovec and control storage.
    if unsafe { libc::recvmsg(socket, &raw mut message, 0) } != 1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a successful broker message must contain one SCM_RIGHTS descriptor.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null()
            || (*header).cmsg_level != libc::SOL_SOCKET
            || (*header).cmsg_type != libc::SCM_RIGHTS
        {
            return Err(std::io::Error::other("missing SCM_RIGHTS descriptor"));
        }
        let fd = libc::CMSG_DATA(header).cast::<RawFd>().read();
        Ok(std::fs::File::from_raw_fd(fd))
    }
}

fn recv_exact(socket: RawFd, bytes: &mut [u8]) {
    let mut received = 0;
    while received < bytes.len() {
        // SAFETY: recv writes only into the remaining writable slice.
        let rc = unsafe {
            libc::recv(
                socket,
                bytes[received..].as_mut_ptr().cast(),
                bytes.len() - received,
                0,
            )
        };
        assert!(rc > 0, "recv: {}", std::io::Error::last_os_error());
        received += rc as usize;
    }
}

fn udp_receiver() -> OwnedFd {
    // SAFETY: socket returns a new fd or -1.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0, "socket: {}", std::io::Error::last_os_error());
    // SAFETY: fd is newly owned.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: bind reads the local sockaddr.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&raw const address).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "bind: {}", std::io::Error::last_os_error());
    fd
}

fn receiver_address(fd: &OwnedFd) -> libc::sockaddr_in {
    // SAFETY: zeroed sockaddr_in is valid output storage for getsockname.
    let mut address: libc::sockaddr_in = unsafe { zeroed() };
    let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: getsockname writes the bound address and updates len.
    let rc = unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            (&raw mut address).cast::<libc::sockaddr>(),
            &raw mut len,
        )
    };
    assert_eq!(rc, 0, "getsockname: {}", std::io::Error::last_os_error());
    address
}

fn wait_exit(pid: libc::pid_t) -> i32 {
    let mut status = 0;
    // SAFETY: waitpid writes the status of the child process.
    assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
    assert!(libc::WIFEXITED(status), "child status {status}");
    libc::WEXITSTATUS(status)
}
