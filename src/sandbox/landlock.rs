//! Landlock ruleset derivation and raw syscall wrappers.
//!
//! The pure half derives the coarse kernel hull from the validated policy: workspace base
//! plus every allow/ask filesystem and exec rule, with deny rules deliberately ignored.
//! The Linux half builds a ruleset fd in the parent, then the child applies that fd with
//! a single `landlock_restrict_self` syscall after the seccomp notify handshake and before
//! `execve`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::policy::{Action, FsMode, Policy};

/// Residual stamped for the host dimension of TCP egress, which Landlock cannot express.
pub const RESIDUAL_TCP_HOST: &str = "landlock:tcp_host";
/// Residual stamped when the policy uses truncation but the running ABI lacks FS_TRUNCATE.
pub const RESIDUAL_FS_TRUNCATE: &str = "landlock:fs_truncate_abi_lt_3";
/// Residual stamped when the policy uses network rules but the running ABI lacks net ports.
pub const RESIDUAL_TCP_PORT: &str = "landlock:tcp_port_abi_lt_4";

/// Residual stamped when a snapshot run's policy grants read (or execute) beneath, or over,
/// the state root or a cgroup2 mount. Landlock grants never subtract, so only the seccomp
/// layer denies those reads (ADR-0024 decision 5).
pub const RESIDUAL_SNAPSHOT_STORE_READ_OVERLAP: &str = "landlock:snapshot_store_read_overlap";

/// the Landlock ABI a snapshot run needs so path truncation is in the backstop (ADR-0024
/// decision 6).
pub const SNAPSHOT_MIN_ABI: u32 = ABI_TRUNCATE;

const ABI_TRUNCATE: u32 = 3;
const ABI_NET: u32 = 4;

/// Filesystem rights supported at the ABI-2 floor.
pub const ACCESS_FS_EXECUTE: u64 = 1 << 0;
const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const ACCESS_FS_READ_FILE: u64 = 1 << 2;
const ACCESS_FS_READ_DIR: u64 = 1 << 3;
const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const ACCESS_FS_REFER: u64 = 1 << 13;
const ACCESS_FS_TRUNCATE: u64 = 1 << 14;

/// TCP rights introduced by Landlock ABI 4.
pub const ACCESS_NET_BIND_TCP: u64 = 1 << 0;
const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

const FS_READ_RIGHTS: u64 = ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR;
const FS_WRITE_RIGHTS: u64 = ACCESS_FS_WRITE_FILE | ACCESS_FS_TRUNCATE;
const FS_CREATE_RIGHTS: u64 = ACCESS_FS_MAKE_CHAR
    | ACCESS_FS_MAKE_DIR
    | ACCESS_FS_MAKE_REG
    | ACCESS_FS_MAKE_SOCK
    | ACCESS_FS_MAKE_FIFO
    | ACCESS_FS_MAKE_BLOCK
    | ACCESS_FS_MAKE_SYM
    | ACCESS_FS_REFER;
const FS_DELETE_RIGHTS: u64 =
    ACCESS_FS_REMOVE_DIR | ACCESS_FS_REMOVE_FILE | ACCESS_FS_REFER | ACCESS_FS_TRUNCATE;

/// rights that are only meaningful beneath a directory. the kernel rejects
/// landlock_add_rule with EINVAL when the anchor's file type does not match the rights,
/// so a grant rooted at a plain file must drop these (an exact-path read rule derives
/// READ_FILE | READ_DIR, and the READ_DIR half is meaningless on a file).
#[cfg(any(target_os = "linux", test))]
const FS_DIRECTORY_ONLY_RIGHTS: u64 = ACCESS_FS_READ_DIR
    | ACCESS_FS_REMOVE_DIR
    | ACCESS_FS_MAKE_CHAR
    | ACCESS_FS_MAKE_DIR
    | ACCESS_FS_MAKE_REG
    | ACCESS_FS_MAKE_SOCK
    | ACCESS_FS_MAKE_FIFO
    | ACCESS_FS_MAKE_BLOCK
    | ACCESS_FS_MAKE_SYM
    | ACCESS_FS_REFER;

/// the rights a grant keeps for its anchor's actual file type. masking never widens a
/// grant, so the hull stays a superset of what the policy permits (policy.md section 6).
#[cfg(any(target_os = "linux", test))]
fn anchor_rights(rights: u64, is_directory: bool) -> u64 {
    if is_directory {
        rights
    } else {
        rights & !FS_DIRECTORY_ONLY_RIGHTS
    }
}

/// every right that changes a file tree: write, truncate, make (any `MAKE_*`), remove and
/// refer. a snapshot run refuses a grant holding any of them over the state root or a
/// cgroup2 mount (ADR-0024 decision 5).
const FS_MUTATING_RIGHTS: u64 = ACCESS_FS_WRITE_FILE
    | ACCESS_FS_TRUNCATE
    | ACCESS_FS_REMOVE_DIR
    | ACCESS_FS_REMOVE_FILE
    | FS_CREATE_RIGHTS;

/// the names of the mutating rights in `rights`, as the refusal message spells them.
pub fn mutating_right_names(rights: u64) -> Vec<&'static str> {
    [
        (ACCESS_FS_WRITE_FILE, "write"),
        (ACCESS_FS_TRUNCATE, "truncate"),
        (FS_CREATE_RIGHTS & !ACCESS_FS_REFER, "make"),
        (ACCESS_FS_REMOVE_DIR | ACCESS_FS_REMOVE_FILE, "remove"),
        (ACCESS_FS_REFER, "refer"),
    ]
    .into_iter()
    .filter(|(mask, _)| rights & mask != 0)
    .map(|(_, name)| name)
    .collect()
}

/// what a snapshot run keeps the agent away from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    /// the state root, which holds the retained snapshots and the trace
    StateRoot,
    /// a cgroup2 mount, which holds the run cgroup's control plane
    CgroupMount,
}

impl StoreKind {
    /// how a refusal message names it.
    pub fn describe(self) -> &'static str {
        match self {
            StoreKind::StateRoot => "state root",
            StoreKind::CgroupMount => "cgroup2 mount",
        }
    }
}

/// a resolved absolute path a snapshot run protects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedStore {
    /// which kind of path this is
    pub kind: StoreKind,
    /// its resolved absolute path
    pub path: PathBuf,
}

/// how a grant's hierarchy relates to a protected path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlapRelation {
    /// the grant root is the protected path
    Same,
    /// the grant root is an ancestor of the protected path, so the grant covers it
    GrantCoversStore,
    /// the grant root lies beneath the protected path
    GrantInsideStore,
}

impl OverlapRelation {
    /// how a refusal message states the relation of the grant to the protected path.
    pub fn describe(self) -> &'static str {
        match self {
            OverlapRelation::Same => "is the",
            OverlapRelation::GrantCoversStore => "is an ancestor of the",
            OverlapRelation::GrantInsideStore => "lies beneath the",
        }
    }
}

/// one grant that overlaps a protected path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreOverlap {
    /// the grant's hierarchy root as the policy spelled it
    pub grant_root: PathBuf,
    /// every right the grant holds
    pub rights: u64,
    /// the protected path it overlaps
    pub store: ProtectedStore,
    /// how the two relate
    pub relation: OverlapRelation,
}

impl StoreOverlap {
    /// the mutating rights of the grant, which are what make this overlap a refusal.
    pub fn mutating_rights(&self) -> u64 {
        self.rights & FS_MUTATING_RIGHTS
    }
}

/// the overlaps of a hull with the protected paths, split by whether the grant can mutate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoreOverlaps {
    /// grants with write, truncate, make, remove or refer rights: the run is refused
    pub mutating: Vec<StoreOverlap>,
    /// grants with only read or execute rights: allowed, stamped as a residual
    pub read_only: Vec<StoreOverlap>,
}

/// find every grant of `hull` that overlaps one of `stores`, as an ancestor or a descendant
/// (ADR-0024 decision 5). `canonical` resolves a grant root the way the kernel will when the
/// grant is anchored; the comparison is by path component, never by string prefix.
pub fn snapshot_store_overlaps(
    hull: &LandlockHull,
    stores: &[ProtectedStore],
    canonical: &dyn Fn(&Path) -> PathBuf,
) -> StoreOverlaps {
    let mut found = StoreOverlaps::default();
    for grant in &hull.fs {
        let root = canonical(&grant.root);
        for store in stores {
            let relation = if root == store.path {
                OverlapRelation::Same
            } else if store.path.starts_with(&root) {
                OverlapRelation::GrantCoversStore
            } else if root.starts_with(&store.path) {
                OverlapRelation::GrantInsideStore
            } else {
                continue;
            };
            let overlap = StoreOverlap {
                grant_root: grant.root.clone(),
                rights: grant.allowed_access,
                store: store.clone(),
                relation,
            };
            if overlap.mutating_rights() != 0 {
                found.mutating.push(overlap);
            } else {
                found.read_only.push(overlap);
            }
        }
    }
    found
}

/// which part of the policy produced a grant at `root` with a mutating right: the workspace
/// base (`base:workspace`) and every allow or ask filesystem rule (`fs.N`) whose hierarchy
/// root is `root` and whose modes give one. used to name the rule in a refusal.
pub fn mutating_grant_origins(policy: &Policy, root: &Path, abi: u32) -> Vec<String> {
    let mut origins = Vec::new();
    if Path::new(&policy.workspace) == root {
        origins.push("base:workspace".to_string());
    }
    for (index, rule) in policy.fs.iter().enumerate() {
        if matches!(rule.action, Action::Allow | Action::Ask)
            && hierarchy_root_from_glob(rule.path.as_str()) == root
            && fs_modes_to_rights(&rule.mode, abi) & FS_MUTATING_RIGHTS != 0
        {
            origins.push(format!("fs.{}", index + 1));
        }
    }
    origins
}

/// A derived Landlock hull, before Linux fds are opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandlockHull {
    /// filesystem hierarchy roots and the access rights granted under each
    pub fs: Vec<FsGrant>,
    /// TCP port grants, or all ports if a policy rule omits `port`
    pub net: NetGrant,
    /// rights the ruleset asks the kernel to handle for filesystem operations
    pub handled_access_fs: u64,
    /// rights the ruleset asks the kernel to handle for network operations
    pub handled_access_net: u64,
    /// named residuals left by the running ABI or by unexpressible dimensions
    pub residuals: Vec<String>,
}

/// A filesystem hierarchy root and its Landlock rights.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsGrant {
    /// lexical hierarchy root derived from the expanded policy glob
    pub root: PathBuf,
    /// Landlock filesystem access bits granted beneath `root`
    pub allowed_access: u64,
}

/// Network port grants for the ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetGrant {
    /// no ports are allowed
    None,
    /// every TCP port is allowed
    All,
    /// these TCP ports are allowed
    Ports(Vec<u16>),
}

/// Derive the coarse Landlock hull from a validated policy.
///
/// Deny rules never subtract from the hull. The seccomp policy layer narrows within the
/// Landlock hull, so this derivation includes every allow and ask that could become an
/// allow, plus the built-in workspace base filesystem allow.
pub fn derive_hull(policy: &Policy, abi: u32) -> LandlockHull {
    let mut fs = BTreeMap::<PathBuf, u64>::new();
    add_fs_grant(
        &mut fs,
        PathBuf::from(&policy.workspace),
        fs_modes_to_rights(
            &[FsMode::Read, FsMode::Write, FsMode::Create, FsMode::Delete],
            abi,
        ),
    );

    for rule in &policy.fs {
        if matches!(rule.action, Action::Allow | Action::Ask) {
            add_fs_grant(
                &mut fs,
                hierarchy_root_from_glob(rule.path.as_str()),
                fs_modes_to_rights(&rule.mode, abi),
            );
        }
    }

    for rule in &policy.exec {
        if matches!(rule.action, Action::Allow | Action::Ask) {
            add_fs_grant(
                &mut fs,
                hierarchy_root_from_glob(rule.binary.as_str()),
                ACCESS_FS_EXECUTE,
            );
        }
    }

    let net = derive_net_grant(policy);
    let mut residuals = vec![RESIDUAL_TCP_HOST.to_string()];
    if policy_uses_truncate(policy) && abi < ABI_TRUNCATE {
        residuals.push(RESIDUAL_FS_TRUNCATE.to_string());
    }
    if !policy.net.is_empty() && abi < ABI_NET {
        residuals.push(RESIDUAL_TCP_PORT.to_string());
    }

    let handled_access_fs = handled_fs_rights(abi);
    let handled_access_net = if abi >= ABI_NET {
        ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP
    } else {
        0
    };

    LandlockHull {
        fs: fs
            .into_iter()
            .map(|(root, allowed_access)| FsGrant {
                root,
                allowed_access,
            })
            .collect(),
        net,
        handled_access_fs,
        handled_access_net,
        residuals,
    }
}

fn add_fs_grant(fs: &mut BTreeMap<PathBuf, u64>, root: PathBuf, rights: u64) {
    fs.entry(root)
        .and_modify(|existing| *existing |= rights)
        .or_insert(rights);
}

fn fs_modes_to_rights(modes: &[FsMode], abi: u32) -> u64 {
    let mut rights = 0;
    for mode in modes {
        rights |= match mode {
            FsMode::Read => FS_READ_RIGHTS,
            FsMode::Write => FS_WRITE_RIGHTS,
            FsMode::Create => FS_CREATE_RIGHTS,
            FsMode::Delete => FS_DELETE_RIGHTS,
        };
    }
    rights & handled_fs_rights(abi)
}

fn handled_fs_rights(abi: u32) -> u64 {
    let mut rights = ACCESS_FS_EXECUTE
        | ACCESS_FS_WRITE_FILE
        | ACCESS_FS_READ_FILE
        | ACCESS_FS_READ_DIR
        | ACCESS_FS_REMOVE_DIR
        | ACCESS_FS_REMOVE_FILE
        | ACCESS_FS_MAKE_CHAR
        | ACCESS_FS_MAKE_DIR
        | ACCESS_FS_MAKE_REG
        | ACCESS_FS_MAKE_SOCK
        | ACCESS_FS_MAKE_FIFO
        | ACCESS_FS_MAKE_BLOCK
        | ACCESS_FS_MAKE_SYM
        | ACCESS_FS_REFER;
    if abi >= ABI_TRUNCATE {
        rights |= ACCESS_FS_TRUNCATE;
    }
    rights
}

fn derive_net_grant(policy: &Policy) -> NetGrant {
    let mut ports = BTreeSet::new();
    for rule in &policy.net {
        if !matches!(rule.action, Action::Allow | Action::Ask) {
            continue;
        }
        let Some(port) = rule.port else {
            return NetGrant::All;
        };
        ports.insert(port);
    }
    if ports.is_empty() {
        NetGrant::None
    } else {
        NetGrant::Ports(ports.into_iter().collect())
    }
}

fn policy_uses_truncate(policy: &Policy) -> bool {
    policy
        .fs
        .iter()
        .any(|rule| rule.mode.contains(&FsMode::Write))
}

fn hierarchy_root_from_glob(pattern: &str) -> PathBuf {
    let first_meta = pattern.find(['*', '?']).unwrap_or(pattern.len());
    let literal = &pattern[..first_meta];
    if first_meta == pattern.len() {
        return PathBuf::from(literal);
    }
    if literal.ends_with('/') {
        let root = literal.trim_end_matches('/');
        return PathBuf::from(if root.is_empty() { "/" } else { root });
    }
    let root = literal;
    if root.is_empty() {
        return PathBuf::from("/");
    }
    let root = match root.rfind('/') {
        Some(0) => "/",
        Some(i) => &root[..i],
        None => ".",
    };
    PathBuf::from(root)
}

/// Errors while constructing or applying a Landlock ruleset.
#[derive(Debug, thiserror::Error)]
pub enum LandlockError {
    /// a path had an interior nul byte and could not be passed to the kernel
    #[error("Landlock path contains a nul byte: {0}")]
    PathNul(String),
    /// an allowed hierarchy could not be opened by the supervisor
    #[error("could not open Landlock hierarchy \"{path}\": {source}")]
    OpenHierarchy {
        /// hierarchy path
        path: PathBuf,
        /// syscall error
        #[source]
        source: std::io::Error,
    },
    /// the ruleset fd could not be created
    #[error("landlock_create_ruleset failed: {0}")]
    Create(std::io::Error),
    /// a rule could not be added to the ruleset fd
    #[error("landlock_add_rule failed for \"{path}\": {source}")]
    AddRule {
        /// hierarchy path, or tcp:<port> for a net rule
        path: String,
        /// syscall error
        #[source]
        source: std::io::Error,
    },
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CString;
    use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
    use std::path::Path;

    /// One authoritative policy hierarchy opened before either enforcing task starts.
    #[derive(Debug)]
    pub struct RootAnchor {
        root: PathBuf,
        allowed_access: u64,
        fd: OwnedFd,
    }

    impl RootAnchor {
        /// Canonical path represented by this anchor.
        pub fn root(&self) -> &Path {
            &self.root
        }

        /// Landlock rights granted beneath this anchor.
        pub fn allowed_access(&self) -> u64 {
            self.allowed_access
        }

        /// Descriptor inherited by the confined broker.
        pub fn as_fd(&self) -> BorrowedFd<'_> {
            self.fd.as_fd()
        }
    }

    /// Ruleset plus the exact hierarchy descriptors from which it was built.
    #[derive(Debug)]
    pub struct PreparedRuleset {
        ruleset: OwnedFd,
        anchors: Vec<RootAnchor>,
    }

    impl PreparedRuleset {
        /// Ruleset descriptor applied to the broker and agent.
        pub fn ruleset_fd(&self) -> BorrowedFd<'_> {
            self.ruleset.as_fd()
        }

        /// Authoritative path anchors inherited by the broker.
        pub fn anchors(&self) -> &[RootAnchor] {
            &self.anchors
        }

        /// Split the prepared object when ownership of both parts is needed.
        pub fn into_parts(self) -> (OwnedFd, Vec<RootAnchor>) {
            (self.ruleset, self.anchors)
        }
    }

    #[cfg(test)]
    pub(super) const CREATE_RULESET_VERSION: libc::c_ulong = 1 << 0;
    pub const RULE_PATH_BENEATH: libc::c_int = 1;
    pub const RULE_NET_PORT: libc::c_int = 2;

    #[repr(C)]
    pub(super) struct RulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
    }

    #[repr(C)]
    pub(super) struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    #[repr(C)]
    pub(super) struct NetPortAttr {
        allowed_access: u64,
        port: u64,
    }

    /// Build a Landlock ruleset fd in the parent.
    pub fn build_ruleset(hull: &LandlockHull) -> Result<OwnedFd, LandlockError> {
        Ok(prepare_ruleset(hull)?.ruleset)
    }

    /// Open every hierarchy once and build Landlock from those retained descriptors.
    pub fn prepare_ruleset(hull: &LandlockHull) -> Result<PreparedRuleset, LandlockError> {
        let anchors = open_anchors(&hull.fs)?;
        let attr = RulesetAttr {
            handled_access_fs: hull.handled_access_fs,
            handled_access_net: hull.handled_access_net,
        };
        let size = if hull.handled_access_net == 0 {
            size_of::<u64>()
        } else {
            size_of::<RulesetAttr>()
        };
        // SAFETY: landlock_create_ruleset reads `attr` for `size` bytes and returns an fd
        // or -1. The fd is owned by this process on success.
        let fd =
            unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, &raw const attr, size, 0) };
        if fd < 0 {
            return Err(LandlockError::Create(std::io::Error::last_os_error()));
        }
        // SAFETY: the syscall returned a new ruleset fd owned by this process.
        let ruleset = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };

        for anchor in &anchors {
            // an anchor whose rights were fully masked by its file type (e.g. a
            // create-only rule on an exact file path) grants nothing; skipping it is
            // the same ruleset with one fewer no-op rule
            if anchor.allowed_access != 0 {
                add_path_rule(&ruleset, anchor)?;
            }
        }
        if hull.handled_access_net != 0 {
            add_net_rules(&ruleset, &hull.net)?;
        }

        Ok(PreparedRuleset { ruleset, anchors })
    }

    fn open_anchors(grants: &[FsGrant]) -> Result<Vec<RootAnchor>, LandlockError> {
        grants.iter().map(open_anchor).collect()
    }

    fn open_anchor(grant: &FsGrant) -> Result<RootAnchor, LandlockError> {
        let resolved = deepest_existing_ancestor(&grant.root).map_err(|source| {
            LandlockError::OpenHierarchy {
                path: grant.root.clone(),
                source,
            }
        })?;
        let c_path = CString::new(resolved.as_os_str().as_encoded_bytes())
            .map_err(|_| LandlockError::PathNul(resolved.display().to_string()))?;
        // SAFETY: open reads a nul-terminated path and returns a new fd or -1.
        let parent_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if parent_fd < 0 {
            return Err(LandlockError::OpenHierarchy {
                path: resolved,
                source: std::io::Error::last_os_error(),
            });
        }
        // SAFETY: open returned a new descriptor owned by this process.
        let fd = unsafe { OwnedFd::from_raw_fd(parent_fd) };
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: stat is a valid out-buffer and fd is a valid open descriptor; fstat
        // works on O_PATH descriptors.
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } < 0 {
            return Err(LandlockError::OpenHierarchy {
                path: resolved,
                source: std::io::Error::last_os_error(),
            });
        }
        let allowed_access = anchor_rights(
            grant.allowed_access,
            stat.st_mode & libc::S_IFMT == libc::S_IFDIR,
        );
        Ok(RootAnchor {
            root: resolved,
            allowed_access,
            fd,
        })
    }

    fn add_path_rule(ruleset: &OwnedFd, anchor: &RootAnchor) -> Result<(), LandlockError> {
        let attr = PathBeneathAttr {
            allowed_access: anchor.allowed_access,
            parent_fd: anchor.fd.as_raw_fd(),
        };
        // SAFETY: landlock_add_rule reads `attr`, borrowing the retained anchor fd.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset.as_raw_fd(),
                RULE_PATH_BENEATH,
                &raw const attr,
                0,
            )
        };
        if rc != 0 {
            return Err(LandlockError::AddRule {
                path: anchor.root.display().to_string(),
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    fn add_net_rules(ruleset: &OwnedFd, net: &NetGrant) -> Result<(), LandlockError> {
        match net {
            NetGrant::None => Ok(()),
            NetGrant::All => {
                for port in 1..=u16::MAX {
                    add_net_rule(ruleset, port)?;
                }
                Ok(())
            }
            NetGrant::Ports(ports) => {
                for &port in ports {
                    add_net_rule(ruleset, port)?;
                }
                Ok(())
            }
        }
    }

    fn add_net_rule(ruleset: &OwnedFd, port: u16) -> Result<(), LandlockError> {
        let attr = NetPortAttr {
            allowed_access: ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP,
            port: u64::from(port),
        };
        // SAFETY: landlock_add_rule reads `attr` for the duration of the call.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset.as_raw_fd(),
                RULE_NET_PORT,
                &raw const attr,
                0,
            )
        };
        if rc != 0 {
            return Err(LandlockError::AddRule {
                path: format!("tcp:{port}"),
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    fn deepest_existing_ancestor(path: &Path) -> std::io::Result<PathBuf> {
        if path.exists() {
            return path.canonicalize();
        }

        let mut existing = path;
        while let Some(parent) = existing.parent() {
            existing = parent;
            if existing.exists() {
                break;
            }
        }

        existing.canonicalize()
    }

    use std::os::fd::AsRawFd;
}

#[cfg(target_os = "linux")]
pub use linux::build_ruleset;
#[cfg(target_os = "linux")]
pub use linux::{PreparedRuleset, RootAnchor, prepare_ruleset};

/// Apply a parent-built Landlock ruleset to the current process.
///
/// # Safety
/// Must be called only in the post-fork child with a valid ruleset fd inherited from the
/// parent. It performs one raw syscall and allocates nothing.
#[cfg(target_os = "linux")]
pub unsafe fn restrict_self(ruleset_fd: std::os::fd::RawFd) -> bool {
    // SAFETY: landlock_restrict_self takes scalar arguments and restricts only the current
    // process. The caller guarantees `ruleset_fd` names a Landlock ruleset.
    unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0) == 0 }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::policy::{ExpandContext, Policy};
    use std::path::Path;

    const WORKSPACE: &str = "/home/op/project";

    fn policy(text: &str) -> Policy {
        Policy::parse(
            text,
            &ExpandContext {
                workspace: WORKSPACE,
                home: "/home/op",
            },
        )
        .unwrap()
    }

    fn grant<'a>(hull: &'a LandlockHull, path: &str) -> &'a FsGrant {
        hull.fs.iter().find(|g| g.root == Path::new(path)).unwrap()
    }

    #[test]
    fn empty_policy_derives_workspace_only_fs_hull() {
        let p = policy("schema_version = 1\n");
        let hull = derive_hull(&p, 4);
        assert_eq!(hull.fs.len(), 1);
        assert_eq!(hull.fs[0].root, Path::new(WORKSPACE));
        assert!(matches!(hull.net, NetGrant::None));
    }

    #[test]
    fn allow_and_ask_rules_are_included_and_deny_does_not_subtract() {
        let p = policy(
            "schema_version = 1\n\
             [[fs]]\npath=\"/etc/**\"\nmode=[\"read\"]\naction=\"allow\"\n\
             [[fs]]\npath=\"/var/tmp/**\"\nmode=[\"write\"]\naction=\"ask\"\n\
             [[fs]]\npath=\"/etc/shadow\"\nmode=[\"read\"]\naction=\"deny\"\n",
        );
        let hull = derive_hull(&p, 4);
        assert!(hull.fs.iter().any(|g| g.root == Path::new(WORKSPACE)));
        assert!(hull.fs.iter().any(|g| g.root == Path::new("/etc")));
        assert!(hull.fs.iter().any(|g| g.root == Path::new("/var/tmp")));
        assert!(!hull.fs.iter().any(|g| g.root == Path::new("/etc/shadow")));
    }

    #[test]
    fn fs_modes_map_to_landlock_rights() {
        let p = policy(
            "schema_version = 1\n\
             [[fs]]\npath=\"/data/read/**\"\nmode=[\"read\"]\naction=\"allow\"\n\
             [[fs]]\npath=\"/data/write/**\"\nmode=[\"write\"]\naction=\"allow\"\n\
             [[fs]]\npath=\"/data/create/**\"\nmode=[\"create\"]\naction=\"allow\"\n\
             [[fs]]\npath=\"/data/delete/**\"\nmode=[\"delete\"]\naction=\"allow\"\n",
        );
        let hull = derive_hull(&p, 4);
        assert_eq!(
            grant(&hull, "/data/read").allowed_access & FS_READ_RIGHTS,
            FS_READ_RIGHTS
        );
        assert_eq!(
            grant(&hull, "/data/write").allowed_access & FS_WRITE_RIGHTS,
            FS_WRITE_RIGHTS
        );
        assert_eq!(
            grant(&hull, "/data/create").allowed_access & FS_CREATE_RIGHTS,
            FS_CREATE_RIGHTS
        );
        assert_eq!(
            grant(&hull, "/data/delete").allowed_access & FS_DELETE_RIGHTS,
            FS_DELETE_RIGHTS
        );
    }

    fn hull_of(text: &str, abi: u32) -> (Policy, LandlockHull) {
        let p = policy(text);
        let hull = derive_hull(&p, abi);
        (p, hull)
    }

    fn stores() -> Vec<ProtectedStore> {
        vec![
            ProtectedStore {
                kind: StoreKind::StateRoot,
                path: "/home/op/.local/state/leash".into(),
            },
            ProtectedStore {
                kind: StoreKind::CgroupMount,
                path: "/sys/fs/cgroup".into(),
            },
        ]
    }

    fn overlaps(text: &str) -> StoreOverlaps {
        let (_, hull) = hull_of(text, 4);
        snapshot_store_overlaps(&hull, &stores(), &|p| p.to_path_buf())
    }

    #[test]
    fn a_write_grant_over_the_state_root_or_a_cgroup_mount_is_a_mutating_overlap() {
        for (glob, mode, kind, relation) in [
            (
                "/home/op/**",
                "write",
                StoreKind::StateRoot,
                OverlapRelation::GrantCoversStore,
            ),
            (
                "/**",
                "create",
                StoreKind::CgroupMount,
                OverlapRelation::GrantCoversStore,
            ),
            (
                "/sys/**",
                "delete",
                StoreKind::CgroupMount,
                OverlapRelation::GrantCoversStore,
            ),
            (
                "/sys/fs/cgroup/**",
                "write",
                StoreKind::CgroupMount,
                OverlapRelation::Same,
            ),
            (
                "/sys/fs/cgroup/leash/cgroup.procs",
                "write",
                StoreKind::CgroupMount,
                OverlapRelation::GrantInsideStore,
            ),
            (
                "/home/op/.local/state/leash/runs/**",
                "create",
                StoreKind::StateRoot,
                OverlapRelation::GrantInsideStore,
            ),
        ] {
            let found = overlaps(&format!(
                "schema_version = 1\n[[fs]]\npath=\"{glob}\"\nmode=[\"{mode}\"]\naction=\"allow\"\n"
            ));
            assert!(
                found
                    .mutating
                    .iter()
                    .any(|o| o.store.kind == kind && o.relation == relation),
                "{glob} {mode}: {found:?}"
            );
        }
    }

    #[test]
    fn every_mutating_right_alone_makes_an_overlap_a_refusal() {
        for mode in ["write", "create", "delete"] {
            let found = overlaps(&format!(
                "schema_version = 1\n[[fs]]\npath=\"/sys/**\"\nmode=[\"{mode}\"]\naction=\"ask\"\n"
            ));
            assert!(!found.mutating.is_empty(), "{mode}");
            assert!(found.read_only.is_empty(), "{mode}");
        }
    }

    #[test]
    fn a_read_or_exec_grant_is_a_read_only_overlap() {
        let found = overlaps(
            "schema_version = 1\n\
             [[fs]]\npath=\"/**\"\nmode=[\"read\"]\naction=\"allow\"\n\
             [[exec]]\nbinary=\"/sys/**\"\naction=\"allow\"\n",
        );
        assert!(found.mutating.is_empty(), "{found:?}");
        // "/" covers both protected paths, "/sys" covers the mount
        assert_eq!(found.read_only.len(), 3, "{found:?}");
    }

    #[test]
    fn a_deny_rule_and_unrelated_paths_overlap_nothing() {
        let found = overlaps(
            "schema_version = 1\n\
             [[fs]]\npath=\"/sys/fs/cgroup/**\"\nmode=[\"write\"]\naction=\"deny\"\n\
             [[fs]]\npath=\"/home/op/other/**\"\nmode=[\"write\"]\naction=\"allow\"\n\
             [[fs]]\npath=\"/sys/fs/cgroup2/**\"\nmode=[\"write\"]\naction=\"allow\"\n\
             [[fs]]\npath=\"/home/op/.local/state/leash2/**\"\nmode=[\"write\"]\naction=\"allow\"\n",
        );
        assert_eq!(found, StoreOverlaps::default());
    }

    #[test]
    fn grant_roots_are_compared_after_canonicalization() {
        let (_, hull) = hull_of(
            "schema_version = 1\n[[fs]]\npath=\"/link/**\"\nmode=[\"write\"]\naction=\"allow\"\n",
            4,
        );
        let canon = |p: &Path| {
            if p == Path::new("/link") {
                PathBuf::from("/sys/fs")
            } else {
                p.to_path_buf()
            }
        };
        let found = snapshot_store_overlaps(&hull, &stores(), &canon);
        assert_eq!(found.mutating.len(), 1, "{found:?}");
        assert_eq!(found.mutating[0].grant_root, Path::new("/link"));
        assert_eq!(found.mutating[0].store.kind, StoreKind::CgroupMount);
    }

    #[test]
    fn the_workspace_base_grant_is_checked_like_any_other() {
        let (_, hull) = hull_of("schema_version = 1\n", 4);
        let inside_workspace = [ProtectedStore {
            kind: StoreKind::StateRoot,
            path: "/home/op/project/state".into(),
        }];
        let found = snapshot_store_overlaps(&hull, &inside_workspace, &|p| p.to_path_buf());
        assert_eq!(found.mutating.len(), 1);
        assert_eq!(
            found.mutating[0].relation,
            OverlapRelation::GrantCoversStore
        );
    }

    #[test]
    fn mutating_right_names_follow_the_adr_vocabulary() {
        assert_eq!(
            mutating_right_names(FS_READ_RIGHTS | ACCESS_FS_EXECUTE),
            Vec::<&str>::new()
        );
        assert_eq!(
            mutating_right_names(FS_WRITE_RIGHTS),
            vec!["write", "truncate"]
        );
        assert_eq!(
            mutating_right_names(FS_CREATE_RIGHTS),
            vec!["make", "refer"]
        );
        assert_eq!(
            mutating_right_names(FS_DELETE_RIGHTS),
            vec!["truncate", "remove", "refer"]
        );
    }

    #[test]
    fn grant_origins_name_the_rules_that_gave_the_mutating_right() {
        let (p, _) = hull_of(
            "schema_version = 1\n\
             [[fs]]\npath=\"/sys/**\"\nmode=[\"read\"]\naction=\"allow\"\n\
             [[fs]]\npath=\"/sys/**\"\nmode=[\"write\"]\naction=\"ask\"\n\
             [[fs]]\npath=\"/sys/**\"\nmode=[\"delete\"]\naction=\"deny\"\n",
            4,
        );
        assert_eq!(
            mutating_grant_origins(&p, Path::new("/sys"), 4),
            vec!["fs.2".to_string()]
        );
        assert_eq!(
            mutating_grant_origins(&p, Path::new(WORKSPACE), 4),
            vec!["base:workspace".to_string()]
        );
    }

    #[test]
    fn exec_rules_map_to_execute_right() {
        let p = policy(
            "schema_version = 1\n\
             [[exec]]\nbinary=\"/usr/bin/git\"\naction=\"allow\"\n",
        );
        let hull = derive_hull(&p, 4);
        assert_eq!(
            grant(&hull, "/usr/bin/git").allowed_access & ACCESS_FS_EXECUTE,
            ACCESS_FS_EXECUTE
        );
    }

    #[test]
    fn anchor_rights_drops_directory_only_rights_for_a_file_anchor() {
        // a directory anchor keeps everything
        assert_eq!(anchor_rights(FS_READ_RIGHTS, true), FS_READ_RIGHTS);
        assert_eq!(anchor_rights(FS_CREATE_RIGHTS, true), FS_CREATE_RIGHTS);
        // a file anchor keeps the file-meaningful rights and drops the directory half
        assert_eq!(anchor_rights(FS_READ_RIGHTS, false), ACCESS_FS_READ_FILE);
        assert_eq!(anchor_rights(FS_WRITE_RIGHTS, false), FS_WRITE_RIGHTS);
        assert_eq!(
            anchor_rights(FS_DELETE_RIGHTS, false),
            ACCESS_FS_REMOVE_FILE | ACCESS_FS_TRUNCATE
        );
        // a create-only grant is fully masked on a file: the caller skips the no-op rule
        assert_eq!(anchor_rights(FS_CREATE_RIGHTS, false), 0);
    }

    #[test]
    fn abi_masks_rights_and_names_residuals() {
        let p = policy(
            "schema_version = 1\n\
             [[fs]]\npath=\"/tmp/**\"\nmode=[\"write\"]\naction=\"allow\"\n\
             [[net]]\nhost=\"api.example.com\"\nport=443\naction=\"allow\"\n",
        );
        let abi2 = derive_hull(&p, 2);
        assert_eq!(abi2.handled_access_fs & ACCESS_FS_TRUNCATE, 0);
        assert_eq!(abi2.handled_access_net, 0);
        assert!(abi2.residuals.contains(&RESIDUAL_TCP_HOST.to_string()));
        assert!(abi2.residuals.contains(&RESIDUAL_FS_TRUNCATE.to_string()));
        assert!(abi2.residuals.contains(&RESIDUAL_TCP_PORT.to_string()));

        let abi3 = derive_hull(&p, 3);
        assert_ne!(abi3.handled_access_fs & ACCESS_FS_TRUNCATE, 0);
        assert_eq!(abi3.handled_access_net, 0);
        assert!(!abi3.residuals.contains(&RESIDUAL_FS_TRUNCATE.to_string()));
        assert!(abi3.residuals.contains(&RESIDUAL_TCP_PORT.to_string()));

        let abi4 = derive_hull(&p, 4);
        assert_ne!(abi4.handled_access_fs & ACCESS_FS_TRUNCATE, 0);
        assert_eq!(
            abi4.handled_access_net,
            ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP
        );
        assert!(!abi4.residuals.contains(&RESIDUAL_TCP_PORT.to_string()));
    }

    #[test]
    fn net_allow_and_ask_ports_are_included_and_deny_is_ignored() {
        let p = policy(
            "schema_version = 1\n\
             [[net]]\nhost=\"a.example.com\"\nport=443\naction=\"allow\"\n\
             [[net]]\nhost=\"b.example.com\"\nport=8443\naction=\"ask\"\n\
             [[net]]\nhost=\"c.example.com\"\nport=22\naction=\"deny\"\n",
        );
        let hull = derive_hull(&p, 4);
        assert_eq!(hull.net, NetGrant::Ports(vec![443, 8443]));
    }

    #[test]
    fn portless_net_allow_derives_all_ports() {
        let p = policy("schema_version = 1\n[[net]]\nhost=\"*\"\naction=\"ask\"\n");
        assert_eq!(derive_hull(&p, 4).net, NetGrant::All);
    }

    #[test]
    fn glob_roots_are_lexical_hierarchy_roots() {
        assert_eq!(hierarchy_root_from_glob("/etc/**"), Path::new("/etc"));
        assert_eq!(
            hierarchy_root_from_glob("/var/log/*.log"),
            Path::new("/var/log")
        );
        assert_eq!(
            hierarchy_root_from_glob("/usr/bin/git"),
            Path::new("/usr/bin/git")
        );
        assert_eq!(
            hierarchy_root_from_glob("relative/*"),
            Path::new("relative")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_raw_abi_constants_and_layouts_match_the_kernel_contract() {
        assert_eq!(linux::CREATE_RULESET_VERSION, 1);
        assert_eq!(linux::RULE_PATH_BENEATH, 1);
        assert_eq!(linux::RULE_NET_PORT, 2);
        assert_eq!(size_of::<linux::RulesetAttr>(), 16);
        assert_eq!(size_of::<linux::PathBeneathAttr>(), 16);
        assert_eq!(size_of::<linux::NetPortAttr>(), 16);
        assert_eq!(ACCESS_FS_EXECUTE, 1);
        assert_eq!(ACCESS_FS_TRUNCATE, 1 << 14);
        assert_eq!(ACCESS_NET_BIND_TCP, 1);
        assert_eq!(ACCESS_NET_CONNECT_TCP, 1 << 1);
    }
}
