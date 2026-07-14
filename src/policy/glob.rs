//! the hand-rolled glob matcher for policy path and binary rules (policy.md section 2.1).
//!
//! assumptions: the syntax is deliberately small and total (ADR-0018) so a rule can only
//! mean exactly what the spec says. the only metacharacters are `*` (matches within one
//! path component), `**` (matches across components), and `?` (matches a single
//! non-separator character). there are no character classes, no brace expansion, and no
//! negation; every other character, including `[`, `{`, and `!`, is a literal. a glob is
//! anchored: it must match the whole path, never a substring. matching is pure, allocates
//! only small temporaries, and never panics.

use std::fmt;

/// a compiled, validated glob. build one with [`Glob::compile`]; match with
/// [`Glob::is_match`]. compilation is where malformed patterns are rejected, so a `Glob`
/// value is always a pattern the matcher can evaluate totally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Glob {
    raw: String,
    segments: Vec<Segment>,
}

/// one `/`-delimited piece of a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// the `**` segment: matches zero or more whole path components
    DoubleStar,
    /// a normal segment matched against exactly one path component
    Pattern(Vec<Unit>),
}

/// one matchable unit inside a normal segment.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Unit {
    /// a literal character
    Literal(char),
    /// `*`: zero or more characters within the component
    Star,
    /// `?`: exactly one character within the component
    Question,
}

/// why a pattern is not a valid version-1 glob.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GlobError {
    /// the pattern is the empty string; a rule that matches nothing useful is a mistake
    #[error("pattern is empty")]
    Empty,
    /// three or more `*` in a row; only `*` and `**` exist in version 1
    #[error("a run of three or more '*' has no meaning in version 1")]
    TooManyStars,
    /// `**` that is not a whole path component (e.g. `a**` or `**b`); `**` must stand alone
    /// between separators, as in `a/**/b`
    #[error("'**' must be a whole path component, bounded by '/' or the ends of the pattern")]
    MalformedDoubleStar,
    /// a character-class bracket (`[` `]`), a brace (`{` `}`), or a leading `!` negation.
    /// these are load-time rejections, not literals: a rule written expecting them would
    /// silently under-match, and in a deny rule that is a boundary the operator believes
    /// exists and does not (policy.md section 2.1, decision of 2026-07-13)
    #[error("schema version 1 has no character classes, braces, or negation")]
    UnsupportedSyntax,
}

impl Glob {
    /// compile and validate a pattern. rejects an empty pattern, a run of three or more
    /// `*`, and a `**` that is not a standalone path component (policy.md section 2.1).
    pub fn compile(raw: &str) -> Result<Glob, GlobError> {
        if raw.is_empty() {
            return Err(GlobError::Empty);
        }

        // classes, braces, and a leading negation are rejected outright: version 1 has no
        // such syntax, and treating them as literals would silently under-match a rule.
        if raw.contains(['[', ']', '{', '}']) || raw.starts_with('!') {
            return Err(GlobError::UnsupportedSyntax);
        }

        let chars: Vec<char> = raw.chars().collect();
        // walk the star runs once and reject anything that is not exactly `*` or a
        // standalone `**`. a run of two must have a separator or a string boundary on both
        // sides, which is what makes it a whole path component.
        let mut i = 0;
        while i < chars.len() {
            if chars[i] != '*' {
                i += 1;
                continue;
            }
            let start = i;
            while i < chars.len() && chars[i] == '*' {
                i += 1;
            }
            let run = i - start;
            if run > 2 {
                return Err(GlobError::TooManyStars);
            }
            if run == 2 {
                let before_ok = start == 0 || chars[start - 1] == '/';
                let after_ok = i == chars.len() || chars[i] == '/';
                if !before_ok || !after_ok {
                    return Err(GlobError::MalformedDoubleStar);
                }
            }
        }

        // the run check guarantees the only `**` left is a standalone segment, so splitting
        // on '/' and treating a bare "**" as DoubleStar is unambiguous.
        let segments = raw
            .split('/')
            .map(|seg| {
                if seg == "**" {
                    Segment::DoubleStar
                } else {
                    Segment::Pattern(
                        seg.chars()
                            .map(|c| match c {
                                '*' => Unit::Star,
                                '?' => Unit::Question,
                                other => Unit::Literal(other),
                            })
                            .collect(),
                    )
                }
            })
            .collect();

        Ok(Glob {
            raw: raw.to_string(),
            segments,
        })
    }

    /// the original pattern text, for reporting and diagnostics.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// does this pattern match the whole of `path`? the match is anchored: the entire path
    /// must be consumed, never just a prefix or substring.
    pub fn is_match(&self, path: &str) -> bool {
        let text: Vec<&str> = path.split('/').collect();
        match_segments(&self.segments, &text)
    }
}

impl fmt::Display for Glob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

/// match a pattern's segments against a path's components. `**` acts like a wildcard over
/// whole components: the loop backtracks to the last `**` on a mismatch, which lets a
/// single `**` match zero or more components. this is the classic linear wildcard match
/// lifted from characters to path components, so it is total and needs no recursion.
fn match_segments(pattern: &[Segment], text: &[&str]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0;

    while ti < text.len() {
        if pi < pattern.len() {
            match &pattern[pi] {
                Segment::DoubleStar => {
                    // remember this `**` and provisionally let it consume nothing
                    star_pi = Some(pi);
                    star_ti = ti;
                    pi += 1;
                    continue;
                }
                Segment::Pattern(units) => {
                    if units_match(units, text[ti]) {
                        pi += 1;
                        ti += 1;
                        continue;
                    }
                }
            }
        }
        // a mismatch or an exhausted pattern: give the last `**` one more component
        match star_pi {
            Some(spi) => {
                pi = spi + 1;
                star_ti += 1;
                ti = star_ti;
            }
            None => return false,
        }
    }

    // trailing `**` segments can each match zero remaining components
    while pi < pattern.len() && matches!(pattern[pi], Segment::DoubleStar) {
        pi += 1;
    }
    pi == pattern.len()
}

/// match a single normal segment's units against one path component. same linear-wildcard
/// shape as [`match_segments`]: `*` backtracks, `?` consumes exactly one character, a
/// literal must match. no `/` can appear here because the caller already split on it.
fn units_match(units: &[Unit], component: &str) -> bool {
    let text: Vec<char> = component.chars().collect();
    let mut ui = 0;
    let mut ti = 0;
    let mut star_ui: Option<usize> = None;
    let mut star_ti = 0;

    while ti < text.len() {
        if ui < units.len() {
            match units[ui] {
                Unit::Literal(c) => {
                    if text[ti] == c {
                        ui += 1;
                        ti += 1;
                        continue;
                    }
                }
                Unit::Question => {
                    ui += 1;
                    ti += 1;
                    continue;
                }
                Unit::Star => {
                    star_ui = Some(ui);
                    star_ti = ti;
                    ui += 1;
                    continue;
                }
            }
        }
        match star_ui {
            Some(sui) => {
                ui = sui + 1;
                star_ti += 1;
                ti = star_ti;
            }
            None => return false,
        }
    }

    while ui < units.len() && matches!(units[ui], Unit::Star) {
        ui += 1;
    }
    ui == units.len()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // --- compilation: what is and is not a valid version-1 glob ---

    #[test]
    fn compile_rejects_the_empty_pattern() {
        assert_eq!(Glob::compile(""), Err(GlobError::Empty));
    }

    #[test]
    fn compile_rejects_three_or_more_stars() {
        assert_eq!(Glob::compile("a/***/b"), Err(GlobError::TooManyStars));
        assert_eq!(Glob::compile("***"), Err(GlobError::TooManyStars));
    }

    #[test]
    fn compile_rejects_double_star_that_is_not_a_whole_component() {
        for bad in ["a**", "**b", "a**b", "x/a**/y", "x/**b/y"] {
            assert_eq!(
                Glob::compile(bad),
                Err(GlobError::MalformedDoubleStar),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn compile_accepts_standalone_double_star_everywhere() {
        for good in ["**", "**/b", "a/**", "a/**/b", "/**", "/**/x"] {
            assert!(Glob::compile(good).is_ok(), "expected {good:?} to compile");
        }
    }

    #[test]
    fn compile_rejects_class_brace_and_leading_negation() {
        // version 1 has no classes, braces, or negation; these are load-time rejections
        for bad in ["/a/[xy]", "a]b", "/a/{x,y}", "a}b", "!/etc/passwd", "!*.rs"] {
            assert_eq!(
                Glob::compile(bad),
                Err(GlobError::UnsupportedSyntax),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn compile_accepts_a_non_leading_bang_as_a_literal() {
        // only a leading '!' is negation; elsewhere it is an ordinary path character
        let g = Glob::compile("/a/b!c").unwrap();
        assert!(g.is_match("/a/b!c"));
        assert!(!g.is_match("/a/bc"));
    }

    // --- matching: an exhaustive table over every metacharacter and corner case ---

    #[test]
    fn match_table() {
        // (pattern, path, expected)
        let cases: &[(&str, &str, bool)] = &[
            // plain literals, anchored (full match, never substring)
            ("/etc/passwd", "/etc/passwd", true),
            ("/etc/passwd", "/etc/passwd.bak", false),
            ("/etc/passwd", "/etc/passwd/x", false),
            ("passwd", "/etc/passwd", false),
            ("/etc", "/etc/passwd", false),
            // single star stays within one component
            ("/etc/*", "/etc/passwd", true),
            ("/etc/*", "/etc/", true),
            ("/etc/*", "/etc/ssh/sshd_config", false),
            ("/a/*/c", "/a/b/c", true),
            ("/a/*/c", "/a/c", false),
            ("/a/*/c", "/a/b/d/c", false),
            // star matches an empty run
            ("/a/*b", "/a/b", true),
            ("/a/b*", "/a/b", true),
            ("*", "abc", true),
            ("*", "", true),
            ("*", "a/b", false),
            // question matches exactly one non-separator character
            ("/a?c", "/a/c", false),
            ("a?c", "abc", true),
            ("a?c", "ac", false),
            ("a?c", "abbc", false),
            ("?", "a", true),
            ("?", "", false),
            ("?", "/", false),
            // double star crosses components, including zero
            ("**", "", true),
            ("**", "a", true),
            ("**", "a/b/c", true),
            ("/**", "/", true),
            ("/**", "/a", true),
            ("/**", "/a/b/c", true),
            ("a/**", "a", true),
            ("a/**", "a/b", true),
            ("a/**", "a/b/c", true),
            ("a/**", "ab", false),
            ("**/b", "b", true),
            ("**/b", "a/b", true),
            ("**/b", "a/x/b", true),
            ("**/b", "a/b/c", false),
            ("a/**/b", "a/b", true),
            ("a/**/b", "a/x/b", true),
            ("a/**/b", "a/x/y/b", true),
            ("a/**/b", "a/b/c", false),
            ("a/**/b", "x/a/b", false),
            // adjacent single metacharacters
            ("a*?", "ab", true),
            ("a*?", "a", false),
            ("a?*", "abc", true),
            ("??", "ab", true),
            ("??", "a", false),
            ("*/*", "a/b", true),
            ("*/*", "a", false),
            // realistic policy shapes
            ("/home/op/project/**", "/home/op/project/src/main.rs", true),
            ("/home/op/project/**", "/home/op/other/x", false),
            ("/home/op/.ssh/**", "/home/op/.ssh/id_ed25519", true),
            ("/usr/bin/*", "/usr/bin/git", true),
            ("/usr/bin/*", "/usr/local/bin/git", false),
        ];

        for &(pattern, path, expected) in cases {
            let g = Glob::compile(pattern).unwrap();
            assert_eq!(
                g.is_match(path),
                expected,
                "pattern {pattern:?} against {path:?}"
            );
        }
    }

    #[test]
    fn trailing_slash_in_pattern_needs_a_trailing_component() {
        let g = Glob::compile("foo/").unwrap();
        assert!(!g.is_match("foo"));
        // "foo/" splits into ["foo", ""], so it matches a path with an empty last component
        assert!(g.is_match("foo/"));
    }
}
