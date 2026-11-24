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

use std::io;
use std::path::{Path, PathBuf};

use crate::recorder::FsAccess;

/// the resolved state root of the run, the subject of the implicit deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateRoot {
    root: PathBuf,
}

impl StateRoot {
    /// resolve `path` through every symlink, once. the directory must exist.
    pub fn resolve(path: &Path) -> io::Result<Self> {
        Self::from_resolved(path.canonicalize()?)
    }

    /// wrap an already-resolved absolute path. a relative path is refused: a relative root
    /// could never match a resolved fact path, which would silently disable the rule.
    pub fn from_resolved(root: PathBuf) -> io::Result<Self> {
        if !root.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the state root must be an absolute resolved path",
            ));
        }
        Ok(Self { root })
    }

    /// the resolved root.
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// is `path` the root or beneath it?
    pub fn contains(&self, path: &Path) -> bool {
        path.starts_with(&self.root)
    }

    /// is `path` a strict ancestor of the root? moving or removing one moves or removes the
    /// root with it.
    pub fn is_strict_ancestor(&self, path: &Path) -> bool {
        path != self.root && self.root.starts_with(path)
    }

    /// does the implicit rule deny this filesystem access?
    ///
    /// every access to the root or beneath it is denied. an ancestor of the root is denied
    /// only when the access would remove or replace it: a `delete`, or any access to the
    /// destination operand of a rename or link (`destination`). reading or listing an
    /// ancestor, and creating beside the root, stay with the policy.
    pub fn denies_fs(&self, path: &Path, access: &[FsAccess], destination: bool) -> bool {
        if self.contains(path) {
            return true;
        }
        self.is_strict_ancestor(path) && (destination || access.contains(&FsAccess::Delete))
    }

    /// does the implicit rule deny executing this binary?
    pub fn denies_exec(&self, binary: &Path) -> bool {
        self.contains(binary)
    }
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
    fn removing_or_replacing_an_ancestor_is_denied() {
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
        }
    }

    #[test]
    fn reading_or_creating_in_an_ancestor_is_left_to_policy() {
        let p = Path::new("/home/u/.local");
        assert!(!root().denies_fs(p, &[FsAccess::Read], false));
        assert!(!root().denies_fs(p, &[FsAccess::Write], false));
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
    fn resolve_follows_symlinks_once() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let resolved = StateRoot::resolve(&link).unwrap();
        assert_eq!(resolved.path(), real.canonicalize().unwrap());
        assert!(StateRoot::resolve(&dir.path().join("missing")).is_err());
    }
}
