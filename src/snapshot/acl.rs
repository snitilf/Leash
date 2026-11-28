//! POSIX ACL xattr blobs as the snapshot store sees them.
//!
//! assumptions: the store treats an ACL as an opaque value, recorded and restored byte for
//! byte under its xattr name. this module only decides whether a value is a well-formed
//! blob for the kernel's `system.posix_acl_*` format, so a malformed or forged value is
//! refused explicitly instead of being handed to `fsetxattr`.

/// xattr name of the access ACL of a file or directory.
pub const ACCESS: &str = "system.posix_acl_access";

/// xattr name of the default ACL of a directory.
pub const DEFAULT: &str = "system.posix_acl_default";

/// header of the xattr format (`POSIX_ACL_XATTR_VERSION`), little endian.
const VERSION: u32 = 2;

/// size of the header and of each entry (`tag: u16`, `perm: u16`, `id: u32`).
const WORD: usize = 4;
const ENTRY: usize = 8;

const TAG_USER_OBJ: u16 = 0x01;
const TAG_USER: u16 = 0x02;
const TAG_GROUP_OBJ: u16 = 0x04;
const TAG_GROUP: u16 = 0x08;
const TAG_MASK: u16 = 0x10;
const TAG_OTHER: u16 = 0x20;

/// the id the kernel writes for entries that do not name a user or group.
const UNDEFINED_ID: u32 = u32::MAX;

/// whether `name` is one of the two ACL xattr names the store records.
pub fn is_acl_name(name: &str) -> bool {
    name == ACCESS || name == DEFAULT
}

struct Entry {
    tag: u16,
    perm: u16,
    id: u32,
}

fn entries(blob: &[u8]) -> Result<Vec<Entry>, &'static str> {
    let header = blob.get(..WORD).ok_or("shorter than the version header")?;
    if u32::from_le_bytes([header[0], header[1], header[2], header[3]]) != VERSION {
        return Err("version header is not 2");
    }
    let body = &blob[WORD..];
    if body.is_empty() {
        return Err("no entries");
    }
    if !body.len().is_multiple_of(ENTRY) {
        return Err("length is not a whole number of 8-byte entries");
    }
    Ok(body
        .chunks_exact(ENTRY)
        .map(|c| Entry {
            tag: u16::from_le_bytes([c[0], c[1]]),
            perm: u16::from_le_bytes([c[2], c[3]]),
            id: u32::from_le_bytes([c[4], c[5], c[6], c[7]]),
        })
        .collect())
}

/// where the entries must be in the sequence the kernel requires of a valid ACL.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    UserObj,
    User,
    Group,
    Other,
    Done,
}

/// check that `blob` is a well-formed POSIX ACL xattr value and return what is wrong if not.
///
/// this is the kernel's `posix_acl_valid` sequence (owner, named users, group, named groups,
/// optional mask, other, each tag in that order) over the little-endian xattr encoding, with
/// two stricter rules that hold for every value the kernel returns: an entry that names no
/// user or group carries the undefined id, and a named entry carries a real one.
pub fn validate_blob(blob: &[u8]) -> Result<(), &'static str> {
    const ORDER: &str = "entries are missing, repeated or out of order";
    let mut state = State::UserObj;
    let mut needs_mask = false;
    for e in entries(blob)? {
        if e.perm & !0o7 != 0 {
            return Err("permission bits outside rwx");
        }
        match e.tag {
            TAG_USER_OBJ | TAG_GROUP_OBJ | TAG_MASK | TAG_OTHER if e.id != UNDEFINED_ID => {
                return Err("an entry that names no user or group carries an id");
            }
            TAG_USER | TAG_GROUP if e.id == UNDEFINED_ID => {
                return Err("a named entry carries the undefined id");
            }
            TAG_USER_OBJ | TAG_USER | TAG_GROUP_OBJ | TAG_GROUP | TAG_MASK | TAG_OTHER => {}
            _ => return Err("unknown entry tag"),
        }
        needs_mask |= matches!(e.tag, TAG_USER | TAG_GROUP);
        state = match (e.tag, state) {
            (TAG_USER_OBJ, State::UserObj) | (TAG_USER, State::User) => State::User,
            (TAG_GROUP_OBJ, State::User) | (TAG_GROUP, State::Group) => State::Group,
            (TAG_MASK, State::Group) => State::Other,
            (TAG_OTHER, State::Other) => State::Done,
            (TAG_OTHER, State::Group) if !needs_mask => State::Done,
            _ => return Err(ORDER),
        };
    }
    if state == State::Done {
        Ok(())
    } else {
        Err(ORDER)
    }
}

/// check that the access ACL `blob` agrees with the permission bits `mode`.
///
/// the kernel keeps the owner, mask (or group when there is no mask) and other entries of an
/// access ACL equal to the owner, group and other bits of the mode. a value that disagrees
/// cannot be restored exactly, because setting the mode rewrites those entries.
pub fn check_mode(blob: &[u8], mode: u32) -> Result<(), &'static str> {
    validate_blob(blob)?;
    let (mut owner, mut group, mut mask, mut other) = (None, None, None, None);
    for e in entries(blob)? {
        let perm = u32::from(e.perm);
        match e.tag {
            TAG_USER_OBJ => owner = Some(perm),
            TAG_GROUP_OBJ => group = Some(perm),
            TAG_MASK => mask = Some(perm),
            TAG_OTHER => other = Some(perm),
            _ => {}
        }
    }
    if owner == Some((mode >> 6) & 0o7)
        && mask.or(group) == Some((mode >> 3) & 0o7)
        && other == Some(mode & 0o7)
    {
        Ok(())
    } else {
        Err("owner, mask and other entries disagree with the mode bits")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_OBJ: u16 = 0x01;
    const USER: u16 = 0x02;
    const GROUP_OBJ: u16 = 0x04;
    const GROUP: u16 = 0x08;
    const MASK: u16 = 0x10;
    const OTHER: u16 = 0x20;
    const UNDEF: u32 = u32::MAX;

    fn blob(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut out = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in entries {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&perm.to_le_bytes());
            out.extend_from_slice(&id.to_le_bytes());
        }
        out
    }

    /// rwx for the owner, r-x for a named user and the mask, r-- for the group, nothing else.
    fn extended() -> Vec<u8> {
        blob(&[
            (USER_OBJ, 7, UNDEF),
            (USER, 5, 1000),
            (GROUP_OBJ, 4, UNDEF),
            (MASK, 5, UNDEF),
            (OTHER, 0, UNDEF),
        ])
    }

    #[test]
    fn names_are_exactly_the_two_posix_acl_attributes() {
        assert!(is_acl_name("system.posix_acl_access"));
        assert!(is_acl_name("system.posix_acl_default"));
        assert!(!is_acl_name("system.posix_acl"));
        assert!(!is_acl_name("system.posix_acl_access2"));
        assert!(!is_acl_name("system.other"));
        assert!(!is_acl_name("user.system.posix_acl_access"));
        assert!(!is_acl_name("trusted.posix_acl_access"));
    }

    #[test]
    fn a_kernel_shaped_acl_is_valid() {
        assert_eq!(validate_blob(&extended()), Ok(()));
        let with_group = blob(&[
            (USER_OBJ, 7, UNDEF),
            (GROUP_OBJ, 5, UNDEF),
            (GROUP, 6, 20),
            (MASK, 7, UNDEF),
            (OTHER, 5, UNDEF),
        ]);
        assert_eq!(validate_blob(&with_group), Ok(()));
        // a default ACL may be the bare three entries
        let bare = blob(&[(USER_OBJ, 7, UNDEF), (GROUP_OBJ, 5, UNDEF), (OTHER, 0, UNDEF)]);
        assert_eq!(validate_blob(&bare), Ok(()));
    }

    #[test]
    fn a_wrong_header_or_length_is_refused() {
        assert!(validate_blob(&[]).is_err());
        assert!(validate_blob(&[2, 0, 0]).is_err());
        let mut v1 = extended();
        v1[0] = 1;
        assert!(validate_blob(&v1).is_err());
        let mut v3 = extended();
        v3[0] = 3;
        assert!(validate_blob(&v3).is_err());
        let mut high = extended();
        high[3] = 1;
        assert!(validate_blob(&high).is_err());
        let mut torn = extended();
        torn.pop();
        assert!(validate_blob(&torn).is_err());
        let mut long = extended();
        long.push(0);
        assert!(validate_blob(&long).is_err());
        // header only: no entries
        assert!(validate_blob(&2u32.to_le_bytes()).is_err());
    }

    #[test]
    fn an_unknown_tag_or_permission_bit_is_refused() {
        for tag in [0u16, 0x03, 0x40, 0x30, 0x100] {
            let b = blob(&[(USER_OBJ, 7, UNDEF), (tag, 0, UNDEF), (OTHER, 0, UNDEF)]);
            assert!(validate_blob(&b).is_err(), "tag {tag:#x}");
        }
        let b = blob(&[(USER_OBJ, 8, UNDEF), (GROUP_OBJ, 4, UNDEF), (OTHER, 0, UNDEF)]);
        assert!(validate_blob(&b).is_err());
    }

    #[test]
    fn a_missing_duplicated_or_misordered_entry_is_refused() {
        let missing_other = blob(&[(USER_OBJ, 7, UNDEF), (GROUP_OBJ, 4, UNDEF)]);
        assert!(validate_blob(&missing_other).is_err());
        let missing_user = blob(&[(GROUP_OBJ, 4, UNDEF), (OTHER, 0, UNDEF)]);
        assert!(validate_blob(&missing_user).is_err());
        let two_owners = blob(&[
            (USER_OBJ, 7, UNDEF),
            (USER_OBJ, 7, UNDEF),
            (GROUP_OBJ, 4, UNDEF),
            (OTHER, 0, UNDEF),
        ]);
        assert!(validate_blob(&two_owners).is_err());
        let misordered = blob(&[(USER_OBJ, 7, UNDEF), (OTHER, 0, UNDEF), (GROUP_OBJ, 4, UNDEF)]);
        assert!(validate_blob(&misordered).is_err());
        // a named user needs a mask
        let no_mask = blob(&[
            (USER_OBJ, 7, UNDEF),
            (USER, 5, 1000),
            (GROUP_OBJ, 4, UNDEF),
            (OTHER, 0, UNDEF),
        ]);
        assert!(validate_blob(&no_mask).is_err());
        // a mask without a named entry is also not a shape the kernel produces
        let lone_mask = blob(&[
            (USER_OBJ, 7, UNDEF),
            (GROUP_OBJ, 4, UNDEF),
            (MASK, 4, UNDEF),
            (OTHER, 0, UNDEF),
        ]);
        assert_eq!(validate_blob(&lone_mask), Ok(()));
        let two_masks = blob(&[
            (USER_OBJ, 7, UNDEF),
            (USER, 5, 1000),
            (GROUP_OBJ, 4, UNDEF),
            (MASK, 5, UNDEF),
            (MASK, 5, UNDEF),
            (OTHER, 0, UNDEF),
        ]);
        assert!(validate_blob(&two_masks).is_err());
        // a named user after the group entries
        let late_user = blob(&[
            (USER_OBJ, 7, UNDEF),
            (GROUP_OBJ, 4, UNDEF),
            (USER, 5, 1000),
            (MASK, 5, UNDEF),
            (OTHER, 0, UNDEF),
        ]);
        assert!(validate_blob(&late_user).is_err());
    }

    #[test]
    fn an_id_on_an_unnamed_entry_is_refused() {
        let b = blob(&[(USER_OBJ, 7, 0), (GROUP_OBJ, 4, UNDEF), (OTHER, 0, UNDEF)]);
        assert!(validate_blob(&b).is_err());
        let b = blob(&[(USER_OBJ, 7, UNDEF), (GROUP_OBJ, 4, UNDEF), (OTHER, 0, 1000)]);
        assert!(validate_blob(&b).is_err());
    }

    #[test]
    fn a_named_entry_needs_a_real_id() {
        let b = blob(&[
            (USER_OBJ, 7, UNDEF),
            (USER, 5, UNDEF),
            (GROUP_OBJ, 4, UNDEF),
            (MASK, 5, UNDEF),
            (OTHER, 0, UNDEF),
        ]);
        assert!(validate_blob(&b).is_err());
    }

    #[test]
    fn the_mode_must_agree_with_the_access_acl() {
        // owner rwx, mask r-x, other ---
        assert_eq!(check_mode(&extended(), 0o750), Ok(()));
        // setuid and friends are not part of the ACL
        assert_eq!(check_mode(&extended(), 0o4750), Ok(()));
        assert!(check_mode(&extended(), 0o700).is_err());
        assert!(check_mode(&extended(), 0o740).is_err());
        assert!(check_mode(&extended(), 0o751).is_err());
        // without a mask the group entry stands in for it
        let bare = blob(&[(USER_OBJ, 6, UNDEF), (GROUP_OBJ, 4, UNDEF), (OTHER, 0, UNDEF)]);
        assert_eq!(check_mode(&bare, 0o640), Ok(()));
        assert!(check_mode(&bare, 0o660).is_err());
    }
}
