//! pure comparison of two snapshot manifests (FR-13, docs/design/cli.md `diff`).
//!
//! assumptions: both manifests were validated by `store::validate_manifest` (unique
//! relative paths, files carry sha256 and size, symlinks carry a target). nothing here
//! touches the filesystem, so the same code serves the copy and overlay mechanisms.
//! a manifest is a reconstructed visible state: a deletion is simply a missing path.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::store::{EntryKind, Manifest, ManifestEntry};

/// one difference between an old and a new manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// a path present only in the new manifest.
    Added {
        /// relative path.
        path: String,
        /// kind of the new entry.
        kind: EntryKind,
    },
    /// a path present only in the old manifest.
    Removed {
        /// relative path.
        path: String,
        /// kind of the old entry.
        kind: EntryKind,
    },
    /// a regular file whose content changed (sha256 or size), or a symlink whose target
    /// changed.
    Modified {
        /// relative path.
        path: String,
    },
    /// the entry kind at a path changed.
    KindChanged {
        /// relative path.
        path: String,
        /// old kind.
        from: EntryKind,
        /// new kind.
        to: EntryKind,
    },
    /// only metadata changed.
    MetadataChanged {
        /// relative path.
        path: String,
        /// changed fields, in the fixed order mode, uid, gid, mtime, xattrs, acl.
        fields: Vec<&'static str>,
    },
    /// a regular file removed at `from` and added at `to` with identical content.
    Renamed {
        /// old path.
        from: String,
        /// new path.
        to: String,
    },
    /// only the hard-link grouping of a file with unchanged content changed.
    LinkChanged {
        /// relative path.
        path: String,
    },
}

impl Change {
    /// the path the change is sorted by (`from` for a rename).
    pub fn sort_path(&self) -> &str {
        match self {
            Change::Added { path, .. }
            | Change::Removed { path, .. }
            | Change::Modified { path }
            | Change::KindChanged { path, .. }
            | Change::MetadataChanged { path, .. }
            | Change::LinkChanged { path } => path,
            Change::Renamed { from, .. } => from,
        }
    }

    /// tie-break when one path carries two changes (content and metadata, or metadata
    /// and link grouping).
    fn rank(&self) -> u8 {
        match self {
            Change::Removed { .. } | Change::Renamed { .. } => 0,
            Change::Added { .. } => 1,
            Change::KindChanged { .. } => 2,
            Change::Modified { .. } => 3,
            Change::MetadataChanged { .. } => 4,
            Change::LinkChanged { .. } => 5,
        }
    }
}

/// compare two manifests. output is sorted by path (a rename by its `from`), and a
/// manifest compared with itself yields no changes.
///
/// a file whose content changed reports `Modified` and, separately, any mode, uid, gid,
/// xattr or ACL change; its mtime is expected to move and is not reported. hard links are
/// treated as one object: names sharing an inode that gain new content are each
/// `Modified`, never renamed. `LinkChanged` considers only names present in both
/// manifests, so adding or removing one name does not flag its surviving siblings.
pub fn diff(old: &Manifest, new: &Manifest) -> Vec<Change> {
    let old_by: BTreeMap<&str, &ManifestEntry> =
        old.entries.iter().map(|e| (e.path.as_str(), e)).collect();
    let new_by: BTreeMap<&str, &ManifestEntry> =
        new.entries.iter().map(|e| (e.path.as_str(), e)).collect();

    let old_groups = link_signatures(&old_by, &new_by);
    let new_groups = link_signatures(&new_by, &old_by);

    let mut changes = Vec::new();
    let mut removed_files: Vec<&ManifestEntry> = Vec::new();
    let mut added_files: Vec<&ManifestEntry> = Vec::new();

    for (path, o) in &old_by {
        match new_by.get(path) {
            None => {
                if o.kind == EntryKind::File {
                    removed_files.push(o);
                } else {
                    changes.push(Change::Removed {
                        path: (*path).to_string(),
                        kind: o.kind,
                    });
                }
            }
            Some(n) => compare_present(
                o,
                n,
                old_groups.get(path),
                new_groups.get(path),
                &mut changes,
            ),
        }
    }
    for (path, n) in &new_by {
        if !old_by.contains_key(path) {
            if n.kind == EntryKind::File {
                added_files.push(n);
            } else {
                changes.push(Change::Added {
                    path: (*path).to_string(),
                    kind: n.kind,
                });
            }
        }
    }

    pair_renames(&removed_files, &added_files, &mut changes);

    changes.sort_by(|a, b| {
        a.sort_path()
            .cmp(b.sort_path())
            .then(a.rank().cmp(&b.rank()))
    });
    changes
}

/// for every regular file in `side`, the sorted names of its link group that also exist
/// as regular files in `other`; absent when the file has no such sibling.
fn link_signatures<'a>(
    side: &BTreeMap<&'a str, &'a ManifestEntry>,
    other: &BTreeMap<&'a str, &'a ManifestEntry>,
) -> HashMap<&'a str, Vec<&'a str>> {
    let mut groups: BTreeMap<u64, Vec<&'a str>> = BTreeMap::new();
    for (path, e) in side {
        if let (EntryKind::File, Some(g)) = (e.kind, e.link_group)
            && other.get(path).is_some_and(|o| o.kind == EntryKind::File)
        {
            groups.entry(g).or_default().push(path);
        }
    }
    let mut out = HashMap::new();
    for members in groups.into_values() {
        if members.len() > 1 {
            for m in &members {
                out.insert(*m, members.clone());
            }
        }
    }
    out
}

fn compare_present(
    o: &ManifestEntry,
    n: &ManifestEntry,
    old_group: Option<&Vec<&str>>,
    new_group: Option<&Vec<&str>>,
    out: &mut Vec<Change>,
) {
    if o.kind != n.kind {
        out.push(Change::KindChanged {
            path: n.path.clone(),
            from: o.kind,
            to: n.kind,
        });
        return;
    }
    let content_changed = match o.kind {
        EntryKind::File => o.sha256 != n.sha256 || o.size != n.size,
        EntryKind::Symlink => o.target != n.target,
        EntryKind::Dir => false,
    };
    if content_changed {
        out.push(Change::Modified {
            path: n.path.clone(),
        });
    }

    let mut fields = Vec::new();
    if o.mode != n.mode {
        fields.push("mode");
    }
    if o.uid != n.uid {
        fields.push("uid");
    }
    if o.gid != n.gid {
        fields.push("gid");
    }
    if !content_changed && (o.mtime_sec, o.mtime_nsec) != (n.mtime_sec, n.mtime_nsec) {
        fields.push("mtime");
    }
    // the ACLs live in the same map as the user xattrs but read as their own field
    fn split(e: &ManifestEntry) -> (BTreeMap<&String, &String>, BTreeMap<&String, &String>) {
        let (acl, user) = e
            .xattrs
            .iter()
            .partition(|(name, _)| super::acl::is_acl_name(name));
        (user, acl)
    }
    let ((old_user, old_acl), (new_user, new_acl)) = (split(o), split(n));
    if old_user != new_user {
        fields.push("xattrs");
    }
    if old_acl != new_acl {
        fields.push("acl");
    }
    if !fields.is_empty() {
        out.push(Change::MetadataChanged {
            path: n.path.clone(),
            fields,
        });
    }

    if !content_changed && o.kind == EntryKind::File && old_group != new_group {
        out.push(Change::LinkChanged {
            path: n.path.clone(),
        });
    }
}

/// pair removed and added regular files of identical content one to one. candidates
/// sharing a hash and size pair in sorted path order; leftovers stay Removed or Added.
/// both slices arrive in sorted path order.
fn pair_renames(removed: &[&ManifestEntry], added: &[&ManifestEntry], out: &mut Vec<Change>) {
    type Key<'a> = (&'a str, u64);
    fn key(e: &ManifestEntry) -> Option<Key<'_>> {
        Some((e.sha256.as_deref()?, e.size?))
    }
    let mut adds: HashMap<Key<'_>, Vec<&str>> = HashMap::new();
    for a in added {
        if let Some(k) = key(a) {
            adds.entry(k).or_default().push(a.path.as_str());
        }
    }
    let mut cursor: HashMap<Key<'_>, usize> = HashMap::new();
    let mut used: BTreeSet<&str> = BTreeSet::new();
    for r in removed {
        let paired = key(r).and_then(|k| {
            let bucket = adds.get(&k)?;
            let idx = cursor.entry(k).or_insert(0);
            let to = *bucket.get(*idx)?;
            *idx += 1;
            Some(to)
        });
        match paired {
            Some(to) => {
                used.insert(to);
                out.push(Change::Renamed {
                    from: r.path.clone(),
                    to: to.to_string(),
                });
            }
            None => out.push(Change::Removed {
                path: r.path.clone(),
                kind: r.kind,
            }),
        }
    }
    for a in added {
        if !used.contains(a.path.as_str()) {
            out.push(Change::Added {
                path: a.path.clone(),
                kind: a.kind,
            });
        }
    }
}

fn kind_name(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::File => "file",
        EntryKind::Dir => "dir",
        EntryKind::Symlink => "symlink",
    }
}

/// a path as safe to print: printed as is unless it holds a control character, in which
/// case the quoted, escaped debug form (the same rule `leash runs` uses for ids).
pub fn display_path(path: &str) -> String {
    if path.chars().any(char::is_control) {
        format!("{path:?}")
    } else {
        path.to_string()
    }
}

/// render changes as stable greppable lines followed by a summary line, or
/// `no differences` for an empty list. every line ends with a newline.
///
/// ```text
/// A  path                      added
/// D  path                      removed
/// M  path                      content changed
/// R  old -> new                renamed
/// T  path (file -> dir)        kind changed
/// m  path (mode, mtime)        metadata changed
/// L  path                      hard-link grouping changed
/// ```
pub fn render(changes: &[Change]) -> String {
    if changes.is_empty() {
        return "no differences\n".to_string();
    }
    let mut out = String::new();
    let (mut a, mut d, mut m, mut r, mut t, mut md, mut l) = (0, 0, 0, 0, 0, 0, 0);
    for c in changes {
        match c {
            Change::Added { path, .. } => {
                a += 1;
                out.push_str(&format!("A  {}\n", display_path(path)));
            }
            Change::Removed { path, .. } => {
                d += 1;
                out.push_str(&format!("D  {}\n", display_path(path)));
            }
            Change::Modified { path } => {
                m += 1;
                out.push_str(&format!("M  {}\n", display_path(path)));
            }
            Change::Renamed { from, to } => {
                r += 1;
                out.push_str(&format!(
                    "R  {} -> {}\n",
                    display_path(from),
                    display_path(to)
                ));
            }
            Change::KindChanged { path, from, to } => {
                t += 1;
                out.push_str(&format!(
                    "T  {} ({} -> {})\n",
                    display_path(path),
                    kind_name(*from),
                    kind_name(*to)
                ));
            }
            Change::MetadataChanged { path, fields } => {
                md += 1;
                out.push_str(&format!(
                    "m  {} ({})\n",
                    display_path(path),
                    fields.join(", ")
                ));
            }
            Change::LinkChanged { path } => {
                l += 1;
                out.push_str(&format!("L  {}\n", display_path(path)));
            }
        }
    }
    let parts: Vec<String> = [
        (a, "added"),
        (d, "removed"),
        (m, "modified"),
        (r, "renamed"),
        (t, "type changed"),
        (md, "metadata changed"),
        (l, "link changed"),
    ]
    .into_iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, label)| format!("{n} {label}"))
    .collect();
    out.push_str(&parts.join(", "));
    out.push('\n');
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::snapshot::store::ManifestTotals;

    fn man(entries: Vec<ManifestEntry>) -> Manifest {
        Manifest {
            schema_version: 1,
            step: 0,
            totals: ManifestTotals {
                entries: 0,
                files: 0,
                dirs: 0,
                symlinks: 0,
                total_bytes: 0,
            },
            entries,
        }
    }

    fn base(path: &str, kind: EntryKind) -> ManifestEntry {
        ManifestEntry {
            path: path.into(),
            kind,
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            mtime_sec: 10,
            mtime_nsec: 0,
            size: None,
            sha256: None,
            target: None,
            link_group: None,
            xattrs: BTreeMap::new(),
        }
    }

    fn file(path: &str, content: &str) -> ManifestEntry {
        let mut e = base(path, EntryKind::File);
        e.size = Some(content.len() as u64);
        let hex: String = content.bytes().map(|b| format!("{b:02x}")).collect();
        e.sha256 = Some(format!("{hex:0>64}"));
        e
    }

    fn dir(path: &str) -> ManifestEntry {
        base(path, EntryKind::Dir)
    }

    fn link(path: &str, target: &str) -> ManifestEntry {
        let mut e = base(path, EntryKind::Symlink);
        e.target = Some(target.into());
        e
    }

    fn grouped(mut e: ManifestEntry, g: u64) -> ManifestEntry {
        e.link_group = Some(g);
        e
    }

    fn added(path: &str, kind: EntryKind) -> Change {
        Change::Added {
            path: path.into(),
            kind,
        }
    }

    fn removed(path: &str, kind: EntryKind) -> Change {
        Change::Removed {
            path: path.into(),
            kind,
        }
    }

    fn modified(path: &str) -> Change {
        Change::Modified { path: path.into() }
    }

    fn renamed(from: &str, to: &str) -> Change {
        Change::Renamed {
            from: from.into(),
            to: to.into(),
        }
    }

    fn linked(path: &str) -> Change {
        Change::LinkChanged { path: path.into() }
    }

    #[test]
    fn self_diff_is_empty() {
        let m = man(vec![
            dir("d"),
            file("d/a", "x"),
            link("l", "d/a"),
            grouped(file("h1", "z"), 1),
            grouped(file("h2", "z"), 1),
        ]);
        assert!(diff(&m, &m).is_empty());
        assert_eq!(render(&[]), "no differences\n");
    }

    #[test]
    fn added_and_removed_each_kind() {
        let old = man(vec![dir("gone"), link("oldl", "t")]);
        let new = man(vec![dir("new"), file("f", "1"), link("newl", "t")]);
        assert_eq!(
            diff(&old, &new),
            vec![
                added("f", EntryKind::File),
                removed("gone", EntryKind::Dir),
                added("new", EntryKind::Dir),
                added("newl", EntryKind::Symlink),
                removed("oldl", EntryKind::Symlink),
            ]
        );
    }

    #[test]
    fn directory_removal_reports_dir_and_every_child() {
        let old = man(vec![
            dir("d"),
            dir("d/s"),
            file("d/s/x", "a"),
            file("d/y", "b"),
        ]);
        let new = man(vec![]);
        let paths: Vec<_> = diff(&old, &new)
            .iter()
            .map(|c| c.sort_path().to_string())
            .collect();
        assert_eq!(paths, ["d", "d/s", "d/s/x", "d/y"]);
    }

    #[test]
    fn content_change_by_hash_or_size_is_modified_without_mtime_noise() {
        let old = man(vec![file("a", "one"), file("b", "same")]);
        let mut a2 = file("a", "two");
        a2.mtime_sec = 99;
        let mut b2 = file("b", "same");
        b2.sha256 = Some("f".repeat(64));
        let new = man(vec![a2, b2]);
        assert_eq!(diff(&old, &new), vec![modified("a"), modified("b")]);
        // same hash, different size
        let mut s = file("a", "one");
        s.size = Some(99);
        assert_eq!(
            diff(&man(vec![file("a", "one")]), &man(vec![s])),
            vec![modified("a")]
        );
    }

    #[test]
    fn an_acl_change_is_labelled_acl_and_not_xattrs() {
        let old = man(vec![file("a", "x"), dir("d")]);
        let mut a = file("a", "x");
        a.xattrs
            .insert("system.posix_acl_access".into(), "02".into());
        let mut d = dir("d");
        d.xattrs
            .insert("system.posix_acl_default".into(), "02".into());
        d.xattrs.insert("user.k".into(), "00".into());
        assert_eq!(
            diff(&old, &man(vec![a, d])),
            vec![
                Change::MetadataChanged {
                    path: "a".into(),
                    fields: vec!["acl"]
                },
                Change::MetadataChanged {
                    path: "d".into(),
                    fields: vec!["xattrs", "acl"]
                },
            ]
        );
        // an ACL that did not change is not reported when only a user xattr did
        let mut with_acl = file("a", "x");
        with_acl
            .xattrs
            .insert("system.posix_acl_access".into(), "02".into());
        let mut both = with_acl.clone();
        both.xattrs.insert("user.k".into(), "00".into());
        assert_eq!(
            diff(&man(vec![with_acl]), &man(vec![both])),
            vec![Change::MetadataChanged {
                path: "a".into(),
                fields: vec!["xattrs"]
            }]
        );
    }

    #[test]
    fn metadata_fields_reported_in_fixed_order() {
        let old = man(vec![file("a", "x"), dir("d")]);
        let mut a = file("a", "x");
        a.mode = 0o755;
        a.uid = 1;
        a.gid = 2;
        a.mtime_nsec = 5;
        a.xattrs.insert("user.k".into(), "00".into());
        let mut d = dir("d");
        d.mtime_sec = 11;
        assert_eq!(
            diff(&old, &man(vec![a, d])),
            vec![
                Change::MetadataChanged {
                    path: "a".into(),
                    fields: vec!["mode", "uid", "gid", "mtime", "xattrs"]
                },
                Change::MetadataChanged {
                    path: "d".into(),
                    fields: vec!["mtime"]
                },
            ]
        );
    }

    #[test]
    fn mode_change_alongside_content_change_reports_both() {
        let mut a = file("a", "two");
        a.mode = 0o755;
        assert_eq!(
            diff(&man(vec![file("a", "one")]), &man(vec![a])),
            vec![
                modified("a"),
                Change::MetadataChanged {
                    path: "a".into(),
                    fields: vec!["mode"]
                }
            ]
        );
    }

    #[test]
    fn symlink_target_change_is_modified() {
        let old = man(vec![link("l", "a")]);
        let new = man(vec![link("l", "b")]);
        assert_eq!(diff(&old, &new), vec![modified("l")]);
    }

    #[test]
    fn kind_change_in_each_direction() {
        let old = man(vec![file("p", "x"), dir("q"), link("r", "t")]);
        let new = man(vec![dir("p"), link("q", "t"), file("r", "x")]);
        assert_eq!(
            diff(&old, &new),
            vec![
                Change::KindChanged {
                    path: "p".into(),
                    from: EntryKind::File,
                    to: EntryKind::Dir
                },
                Change::KindChanged {
                    path: "q".into(),
                    from: EntryKind::Dir,
                    to: EntryKind::Symlink
                },
                Change::KindChanged {
                    path: "r".into(),
                    from: EntryKind::Symlink,
                    to: EntryKind::File
                },
            ]
        );
    }

    #[test]
    fn simple_rename() {
        let old = man(vec![file("a", "x")]);
        let new = man(vec![file("b", "x")]);
        assert_eq!(diff(&old, &new), vec![renamed("a", "b")]);
    }

    #[test]
    fn rename_needs_same_hash_and_size_and_regular_file() {
        let old = man(vec![file("a", "x"), link("l", "t"), dir("d")]);
        let new = man(vec![file("b", "y"), link("m", "t"), dir("e")]);
        let ch = diff(&old, &new);
        assert!(ch.iter().all(|c| !matches!(c, Change::Renamed { .. })));
        assert_eq!(ch.len(), 6);
    }

    #[test]
    fn rename_pairs_duplicates_in_sorted_order_and_leaves_leftovers() {
        let old = man(vec![file("a3", "x"), file("a1", "x"), file("a2", "x")]);
        let new = man(vec![file("b2", "x"), file("b1", "x")]);
        assert_eq!(
            diff(&old, &new),
            vec![
                renamed("a1", "b1"),
                renamed("a2", "b2"),
                removed("a3", EntryKind::File),
            ]
        );
        // more adds than removes
        let old = man(vec![file("a", "x")]);
        let new = man(vec![file("b", "x"), file("c", "x")]);
        assert_eq!(
            diff(&old, &new),
            vec![renamed("a", "b"), added("c", EntryKind::File)]
        );
    }

    #[test]
    fn rename_is_deterministic_under_entry_order() {
        let a = man(vec![file("x1", "c"), file("x2", "c")]);
        let b = man(vec![file("y2", "c"), file("y1", "c")]);
        let mut a_rev = a.clone();
        a_rev.entries.reverse();
        assert_eq!(diff(&a, &b), diff(&a_rev, &b));
        assert_eq!(diff(&a, &b), vec![renamed("x1", "y1"), renamed("x2", "y2")]);
    }

    #[test]
    fn linked_names_with_new_content_are_modified_not_renamed() {
        let old = man(vec![
            grouped(file("a", "old"), 1),
            grouped(file("b", "old"), 1),
        ]);
        let new = man(vec![
            grouped(file("a", "new"), 7),
            grouped(file("b", "new"), 7),
        ]);
        assert_eq!(diff(&old, &new), vec![modified("a"), modified("b")]);
    }

    #[test]
    fn link_group_ids_are_not_compared_only_membership() {
        let old = man(vec![grouped(file("a", "x"), 1), grouped(file("b", "x"), 1)]);
        let new = man(vec![
            grouped(file("a", "x"), 42),
            grouped(file("b", "x"), 42),
        ]);
        assert!(diff(&old, &new).is_empty());
    }

    #[test]
    fn joining_and_leaving_a_link_group() {
        let sep = man(vec![file("a", "x"), file("b", "x")]);
        let joined = man(vec![grouped(file("a", "x"), 1), grouped(file("b", "x"), 1)]);
        let expect = vec![linked("a"), linked("b")];
        assert_eq!(diff(&sep, &joined), expect);
        assert_eq!(diff(&joined, &sep), expect);
    }

    #[test]
    fn one_name_leaving_a_three_way_group_flags_all_three() {
        let old = man(vec![
            grouped(file("a", "x"), 1),
            grouped(file("b", "x"), 1),
            grouped(file("c", "x"), 1),
        ]);
        let new = man(vec![
            grouped(file("a", "x"), 1),
            grouped(file("b", "x"), 1),
            file("c", "x"),
        ]);
        assert_eq!(
            diff(&old, &new),
            vec![linked("a"), linked("b"), linked("c")]
        );
    }

    #[test]
    fn removing_one_link_name_does_not_flag_the_survivor() {
        let old = man(vec![grouped(file("a", "x"), 1), grouped(file("b", "x"), 1)]);
        let new = man(vec![file("a", "x")]);
        assert_eq!(diff(&old, &new), vec![removed("b", EntryKind::File)]);
    }

    #[test]
    fn output_sorted_by_path_with_rename_by_from() {
        let old = man(vec![file("z", "x"), file("m", "m"), dir("b")]);
        let new = man(vec![file("a", "x"), file("m", "n"), dir("b"), dir("c")]);
        let ch = diff(&old, &new);
        let order: Vec<_> = ch.iter().map(|c| c.sort_path()).collect();
        assert_eq!(order, ["c", "m", "z"]);
        assert_eq!(ch[2], renamed("z", "a"));
    }

    #[test]
    fn render_lines_and_summary() {
        let changes = vec![
            added("a", EntryKind::File),
            removed("b", EntryKind::Dir),
            modified("c"),
            renamed("d", "e"),
            Change::KindChanged {
                path: "f".into(),
                from: EntryKind::File,
                to: EntryKind::Dir,
            },
            Change::MetadataChanged {
                path: "g".into(),
                fields: vec!["mode", "mtime"],
            },
            linked("h"),
        ];
        assert_eq!(
            render(&changes),
            "A  a\nD  b\nM  c\nR  d -> e\nT  f (file -> dir)\nm  g (mode, mtime)\nL  h\n\
             1 added, 1 removed, 1 modified, 1 renamed, 1 type changed, 1 metadata changed, 1 link changed\n"
        );
    }

    #[test]
    fn render_summary_omits_zero_categories() {
        assert_eq!(render(&[modified("a")]), "M  a\n1 modified\n");
    }

    #[test]
    fn render_escapes_control_characters() {
        let out = render(&[added("a\nD  fake", EntryKind::File)]);
        assert_eq!(out, "A  \"a\\nD  fake\"\n1 added\n");
        assert_eq!(display_path("plain name é"), "plain name é");
        assert_eq!(display_path("\u{1b}[31m"), "\"\\u{1b}[31m\"");
    }
}
