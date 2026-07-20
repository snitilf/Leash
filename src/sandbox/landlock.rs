//! Landlock ruleset derivation and raw syscall wrappers.
//!
//! The pure half derives the coarse kernel hull from the validated policy: workspace base
//! plus every allow/ask filesystem and exec rule, with deny rules deliberately ignored.
//! The Linux half builds a ruleset fd in the parent, then the child applies that fd with
//! a single `landlock_restrict_self` syscall after the seccomp notify handshake and before
//! `execve`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crate::policy::{Action, FsMode, Policy};

/// Residual stamped for the host dimension of TCP egress, which Landlock cannot express.
pub const RESIDUAL_TCP_HOST: &str = "landlock:tcp_host";
/// Residual stamped when the policy uses truncation but the running ABI lacks FS_TRUNCATE.
pub const RESIDUAL_FS_TRUNCATE: &str = "landlock:fs_truncate_abi_lt_3";
/// Residual stamped when the policy uses network rules but the running ABI lacks net ports.
pub const RESIDUAL_TCP_PORT: &str = "landlock:tcp_port_abi_lt_4";

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
    use std::os::fd::{FromRawFd, OwnedFd, RawFd};
    use std::path::Path;

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

        for grant in &hull.fs {
            add_path_rule(&ruleset, grant)?;
        }
        if hull.handled_access_net != 0 {
            add_net_rules(&ruleset, &hull.net)?;
        }

        Ok(ruleset)
    }

    fn add_path_rule(ruleset: &OwnedFd, grant: &FsGrant) -> Result<(), LandlockError> {
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
        let attr = PathBeneathAttr {
            allowed_access: grant.allowed_access,
            parent_fd,
        };
        // SAFETY: landlock_add_rule reads `attr`, borrowing parent_fd only for the call.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset.as_raw_fd(),
                RULE_PATH_BENEATH,
                &raw const attr,
                0,
            )
        };
        // SAFETY: parent_fd was opened above and is no longer needed after add_rule.
        unsafe { libc::close(parent_fd) };
        if rc != 0 {
            return Err(LandlockError::AddRule {
                path: resolved.display().to_string(),
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
