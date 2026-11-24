//! the implicit state-root deny of an enforce run (FR-3, FR-21, ADR-0024 decision 3).
//!
//! assumptions: the root is canonicalized once, before the child exists, so every comparison
//! below is between two resolved absolute paths. the fs facts this is asked about in enforce
//! mode carry the identity read back from the opened handle (ADR-0023), so a symlink that
//! leads into the root is judged on where it landed, not on how it was spelled. comparison is
//! by path component, never by string prefix: `/a/state2` is not beneath `/a/state`.
//!
//! the rule is evaluated before every policy rule and cannot be allowed by one. Landlock
//! cannot subtract a subtree from a grant, so this is the only layer that can deny reads and
//! the only one that can deny writes under an overlapping policy grant.
//!
//! the same module holds the sibling `implicit:supervisor_proc` rule: no path under
//! `/proc/<pid>/` of the supervisor or its broker may be reached, because `mem`, `fd/*` and
//! `environ` there would hand the agent the live trace and the supervisor's memory.

use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::recorder::FsAccess;

/// how many symlinks one spelled path may traverse before it is refused, as the kernel does.
const MAX_SYMLINK_HOPS: usize = 40;

/// the resolved state root of the run, the subject of the implicit deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateRoot {
    root: PathBuf,
    /// every symlink the operator's spelling of the root traversed, each as the canonical
    /// parent plus the link's own name. the agent must not be able to rename or replace one,
    /// because that would redirect the operator's own spelling away from the real root.
    links: Vec<PathBuf>,
    /// the processes whose `/proc/<pid>` tree is denied: the supervisor and its broker.
    proc_pids: Vec<u32>,
}

impl StateRoot {
    /// resolve the operator-spelled `spelled` path through every symlink, once, recording
    /// each symlink hop on the way. the directory must exist. a relative spelling is joined
    /// onto the current directory.
    pub fn resolve(spelled: &Path) -> io::Result<Self> {
        let absolute = if spelled.is_absolute() {
            spelled.to_path_buf()
        } else {
            std::env::current_dir()?.join(spelled)
        };
        let root = absolute.canonicalize()?;
        let links = symlink_hops(&absolute)?;
        Self::build(root, links)
    }

    /// wrap an already-resolved absolute path. a relative path is refused: a relative root
    /// could never match a resolved fact path, which would silently disable the rule. so is
    /// a path that is not valid UTF-8: fact paths are compared as text, and a lossy identity
    /// would never match it.
    pub fn from_resolved(root: PathBuf) -> io::Result<Self> {
        Self::build(root, Vec::new())
    }

    fn build(root: PathBuf, links: Vec<PathBuf>) -> io::Result<Self> {
        if !root.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the state root must be an absolute resolved path",
            ));
        }
        for path in std::iter::once(&root).chain(links.iter()) {
            if path.to_str().is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "the state root path {} is not valid UTF-8, so the implicit deny \
                         could not match it; choose a state directory with a UTF-8 path",
                        path.display()
                    ),
                ));
            }
        }
        Ok(Self {
            root,
            links,
            proc_pids: Vec::new(),
        })
    }

    /// name the processes whose `/proc/<pid>` tree is denied (the supervisor and its broker).
    pub fn with_supervisor_pids(mut self, pids: impl IntoIterator<Item = u32>) -> Self {
        self.proc_pids = pids.into_iter().collect();
        self
    }

    /// the resolved root.
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// the symlink hops of the operator's spelling, each canonical parent plus link name.
    pub fn links(&self) -> &[PathBuf] {
        &self.links
    }

    /// is `path` the root or beneath it?
    pub fn contains(&self, path: &Path) -> bool {
        path.starts_with(&self.root)
    }

    /// is `path` a node whose removal, replacement or modification would move, redirect or
    /// change the root: a strict ancestor of the root, a symlink hop of its spelling, or an
    /// ancestor of such a hop?
    pub fn is_protected_node(&self, path: &Path) -> bool {
        path != self.root
            && (self.root.starts_with(path) || self.links.iter().any(|l| l.starts_with(path)))
    }

    /// does the implicit rule deny this filesystem access?
    ///
    /// every access to the root or beneath it is denied. a protected node (an ancestor of
    /// the root, a symlink hop of its spelling, or an ancestor of a hop) is denied when the
    /// access would remove, replace or alter it: a `delete`, any access to the destination
    /// operand of a rename or link (`destination`), or a `write` on its own identity, which
    /// only chmod, chown and truncate of the directory itself produce. reading or listing a
    /// protected node, and creating beside the root, stay with the policy.
    pub fn denies_fs(&self, path: &Path, access: &[FsAccess], destination: bool) -> bool {
        if self.contains(path) {
            return true;
        }
        self.is_protected_node(path)
            && (destination
                || access.contains(&FsAccess::Delete)
                || access.contains(&FsAccess::Write))
    }

    /// does the implicit rule deny executing this binary?
    ///
    /// exec is decided on the path as spelled, on its lexical normalization (`..` folded),
    /// and on the supervisor's resolution of it through symlinks, and denied when any of
    /// them is the root or beneath it. the check runs at trap time against a path, not an
    /// opened handle, so a swap after the check is a named residual (escapes.md section 4).
    pub fn denies_exec(&self, binary: &Path) -> bool {
        if self.contains(binary) {
            return true;
        }
        if !binary.is_absolute() {
            return false;
        }
        self.contains(&normalize_lexically(binary)) || self.contains(&resolve_leniently(binary))
    }

    /// is `path` the `/proc` tree of the supervisor or its broker (`/proc/<pid>` and
    /// everything beneath it, `task/*` included)?
    pub fn denies_proc(&self, path: &Path) -> bool {
        self.proc_pids
            .iter()
            .any(|pid| path.starts_with(format!("/proc/{pid}")))
    }
}

/// fold `.` and `..` out of an absolute path without touching the filesystem.
fn normalize_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => out.push(name),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    out
}

/// resolve through symlinks as far as the path exists, then append the rest lexically, so a
/// not-yet-existing binary under a symlinked directory still resolves.
fn resolve_leniently(path: &Path) -> PathBuf {
    if let Ok(resolved) = path.canonicalize() {
        return resolved;
    }
    let mut existing = normalize_lexically(path);
    let mut tail: Vec<OsString> = Vec::new();
    loop {
        if let Ok(resolved) = existing.canonicalize() {
            let mut out = resolved;
            out.extend(tail.iter().rev());
            return out;
        }
        match (existing.file_name().map(OsString::from), existing.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name);
                existing = parent.to_path_buf();
            }
            _ => return normalize_lexically(path),
        }
    }
}

/// walk the absolute `spelled` path component by component, resolving as the kernel would,
/// and return every symlink it traversed as canonical parent plus link name. components that
/// do not exist yet are followed lexically.
fn symlink_hops(spelled: &Path) -> io::Result<Vec<PathBuf>> {
    let mut current = PathBuf::from("/");
    let mut pending: Vec<OsString> = components_of(spelled);
    let mut hops = Vec::new();
    while let Some(component) = pending.pop() {
        if component == ".." {
            current.pop();
            continue;
        }
        let next = current.join(&component);
        match std::fs::symlink_metadata(&next) {
            Ok(meta) if meta.file_type().is_symlink() => {
                if hops.len() >= MAX_SYMLINK_HOPS {
                    return Err(io::Error::from_raw_os_error(libc::ELOOP));
                }
                let target = std::fs::read_link(&next)?;
                hops.push(next);
                if target.is_absolute() {
                    current = PathBuf::from("/");
                }
                pending.extend(components_of(&target));
            }
            Ok(_) => current = next,
            Err(e) if e.kind() == io::ErrorKind::NotFound => current = next,
            Err(e) => return Err(e),
        }
    }
    Ok(hops)
}

/// the components of `path` that name something, in reverse so a stack pops them in order.
fn components_of(path: &Path) -> Vec<OsString> {
    path.components()
        .rev()
        .filter_map(|c| match c {
            Component::Normal(name) => Some(name.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn root() -> StateRoot {
        StateRoot::from_resolved("/home/u/.local/state/leash".into()).unwrap()
    }

    const EVERY_ACCESS: [FsAccess; 4] = [
        FsAccess::Read,
        FsAccess::Write,
        FsAccess::Create,
        FsAccess::Delete,
    ];

    #[test]
    fn the_root_and_everything_beneath_it_is_denied_for_every_access() {
        for path in [
            "/home/u/.local/state/leash",
            "/home/u/.local/state/leash/runs",
            "/home/u/.local/state/leash/runs/r1/trace.jsonl",
        ] {
            for access in EVERY_ACCESS {
                assert!(
                    root().denies_fs(Path::new(path), &[access], false),
                    "{path} {access:?}"
                );
            }
            assert!(root().denies_exec(Path::new(path)));
        }
    }

    #[test]
    fn a_sibling_sharing_a_string_prefix_is_not_beneath_the_root() {
        for path in [
            "/home/u/.local/state/leash2",
            "/home/u/.local/state/leash-other/f",
            "/home/u/.local/state/lea",
        ] {
            for access in EVERY_ACCESS {
                assert!(
                    !root().denies_fs(Path::new(path), &[access], false),
                    "{path} {access:?}"
                );
            }
        }
    }

    #[test]
    fn removing_replacing_or_altering_an_ancestor_is_denied() {
        for ancestor in [
            "/home/u/.local/state",
            "/home/u/.local",
            "/home/u",
            "/home",
            "/",
        ] {
            let p = Path::new(ancestor);
            assert!(
                root().denies_fs(p, &[FsAccess::Delete], false),
                "{ancestor}"
            );
            assert!(
                root().denies_fs(p, &[FsAccess::Create], true),
                "{ancestor} as a destination"
            );
            assert!(
                root().denies_fs(p, &[FsAccess::Delete, FsAccess::Create], true),
                "{ancestor} as an exchange destination"
            );
            assert!(
                root().denies_fs(p, &[FsAccess::Write], false),
                "{ancestor} chmod, chown or truncate of the directory itself"
            );
        }
    }

    #[test]
    fn reading_or_creating_in_an_ancestor_is_left_to_policy() {
        let p = Path::new("/home/u/.local");
        assert!(!root().denies_fs(p, &[FsAccess::Read], false));
        assert!(!root().denies_fs(p, &[FsAccess::Create], false));
    }

    #[test]
    fn unrelated_paths_are_not_denied() {
        let p = Path::new("/home/u/project/.local");
        for access in EVERY_ACCESS {
            assert!(!root().denies_fs(p, &[access], true));
        }
        assert!(!root().denies_exec(Path::new("/usr/bin/true")));
    }

    #[test]
    fn a_relative_root_is_refused() {
        assert!(StateRoot::from_resolved("state".into()).is_err());
    }

    #[test]
    fn a_root_that_is_not_utf8_is_refused() {
        use std::os::unix::ffi::OsStringExt;
        let bytes = b"/home/u/state-\xff".to_vec();
        let err = StateRoot::from_resolved(PathBuf::from(OsString::from_vec(bytes))).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("UTF-8"), "{err}");
    }

    #[test]
    fn resolve_follows_symlinks_once_and_records_each_hop() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let real = base.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let outer = base.join("outer");
        std::os::unix::fs::symlink("link", &outer).unwrap();

        let resolved = StateRoot::resolve(&outer).unwrap();
        assert_eq!(resolved.path(), real);
        assert_eq!(resolved.links(), &[outer.clone(), link.clone()]);
        assert!(StateRoot::resolve(&base.join("missing")).is_err());

        // a hop and its ancestors are protected like the root's own ancestors
        assert!(resolved.denies_fs(&link, &[FsAccess::Delete], false));
        assert!(resolved.denies_fs(&outer, &[FsAccess::Create], true));
        assert!(resolved.denies_fs(&base, &[FsAccess::Delete], false));
        assert!(!resolved.denies_fs(&link, &[FsAccess::Read], false));
    }

    #[test]
    fn a_dotdot_through_a_symlink_is_resolved_as_the_kernel_does() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        std::fs::create_dir_all(base.join("a/deep")).unwrap();
        std::fs::create_dir(base.join("state")).unwrap();
        std::os::unix::fs::symlink(base.join("a/deep"), base.join("hop")).unwrap();
        // hop/../../state is a/deep/../../state, that is base/state
        let resolved = StateRoot::resolve(&base.join("hop/../../state")).unwrap();
        assert_eq!(resolved.path(), base.join("state"));
        assert_eq!(resolved.links(), &[base.join("hop")]);
    }

    #[test]
    fn exec_is_decided_on_the_lexical_and_the_resolved_spelling() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let state = base.join("state");
        std::fs::create_dir_all(state.join("bin")).unwrap();
        std::fs::create_dir(base.join("other")).unwrap();
        std::os::unix::fs::symlink(&state, base.join("link")).unwrap();
        let root = StateRoot::resolve(&state).unwrap();

        assert!(root.denies_exec(&state.join("bin/x")));
        // `..` folded lexically
        assert!(root.denies_exec(&base.join("other/../state/bin/x")));
        // through a symlink, existing or not yet created
        assert!(root.denies_exec(&base.join("link/bin/x")));
        assert!(root.denies_exec(&base.join("link/not-yet/x")));
        assert!(!root.denies_exec(&base.join("other/x")));
        assert!(!root.denies_exec(Path::new("relative/x")));
    }

    #[test]
    fn the_proc_tree_of_the_named_pids_is_denied() {
        let r = root().with_supervisor_pids([100, 200]);
        for path in [
            "/proc/100",
            "/proc/100/mem",
            "/proc/100/fd/3",
            "/proc/200/task/201/mem",
        ] {
            assert!(r.denies_proc(Path::new(path)), "{path}");
        }
        for path in ["/proc/1000/mem", "/proc/10", "/proc/self/mem", "/proc"] {
            assert!(!r.denies_proc(Path::new(path)), "{path}");
        }
        assert!(!root().denies_proc(Path::new("/proc/100/mem")));
    }
}
