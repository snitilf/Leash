//! policy parsing and evaluation (docs/design/policy.md).
//!
//! assumptions: the engine is pure and total. facts in, decision plus matched-rule id out,
//! no io, no child memory access, no panic path (NFR-6, ADR-0004). the typed fact it
//! receives is kernel-trusted; validating that is the notify loop's job, not ours.
//! rejection is total and upfront: a policy loads whole or not at all (FR-18).
//!
//! this module owns loading: it turns an operator's TOML file into the typed, validated
//! [`Policy`] below, or rejects the whole file with a [`PolicyError`] naming what is wrong
//! and where. the fact-to-decision evaluator is a later slice; the glob and host matchers
//! it will build on live in [`glob`] and [`host`] and are exercised here at load time.

use std::io;
use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

pub mod engine;
pub mod glob;
pub mod host;

pub use engine::{Evaluation, Family, MatchId, Request};
pub use glob::{Glob, GlobError};
pub use host::{HostError, HostRule};

/// the only policy schema version this build understands (policy.md section 2). a new
/// predicate or a changed vocabulary is a new version and a security-relevant change
/// (ADR-0004); a file that declares anything else is rejected.
pub const SCHEMA_VERSION: u32 = 1;

/// a loaded, fully validated policy. every glob is compiled, every host is parsed, every
/// action and mode is known. order within each table is significant (policy.md section 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// the declared schema version; always [`SCHEMA_VERSION`] for a value that exists
    pub schema_version: u32,
    /// the workspace root this policy was expanded against, absolute. the built-in
    /// workspace base allow (policy.md section 1) is evaluated against it.
    pub workspace: String,
    /// filesystem rules, in file order
    pub fs: Vec<FsRule>,
    /// network rules, in file order
    pub net: Vec<NetRule>,
    /// executable rules, in file order
    pub exec: Vec<ExecRule>,
}

/// a policy loaded from disk plus the digest of the exact file bytes that were validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedPolicy {
    /// the typed, fully validated policy
    pub policy: Policy,
    /// lowercase hex SHA-256 digest of the loaded TOML bytes
    pub digest: String,
}

/// the substitutions applied to a glob before it is compiled (policy.md section 2.1).
/// `{workspace}` and `~` are expanded to absolute paths so the compiled glob is anchored
/// to a full resolved path. both are the caller's job to supply as absolute.
#[derive(Debug, Clone, Copy)]
pub struct ExpandContext<'a> {
    /// the run's workspace root, absolute; substituted for a leading `{workspace}`
    pub workspace: &'a str,
    /// the operating user's home directory, absolute; substituted for a leading `~`
    pub home: &'a str,
}

/// why a glob's `{workspace}` or `~` substitution failed. both are load-time rejections
/// (fail closed): the doc fixes these tokens as leading components only, so a token that
/// appears anywhere else is a mistake, not a literal (decision of 2026-07-13, flagged as
/// the doc was silent on mid-pattern use).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExpandError {
    /// `{workspace}` appeared somewhere other than as the whole leading path component
    #[error("'{{workspace}}' is valid only as the leading path component")]
    MisplacedWorkspace,
    /// a `~` at the start was not a bare `~` or a `~/` prefix (e.g. the `~user` form)
    #[error("'~' expands only as a leading '~' or '~/'")]
    MisplacedTilde,
}

/// a filesystem rule: a glob over the resolved path, a nonempty set of access modes, and
/// an action (policy.md section 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsRule {
    /// the path glob, anchored to the full resolved path
    pub path: Glob,
    /// the access modes this rule governs; never empty
    pub mode: Vec<FsMode>,
    /// the decision when this rule is the first match
    pub action: Action,
}

/// a network rule: a host, an optional port, and an action (policy.md section 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetRule {
    /// the host this rule matches
    pub host: HostRule,
    /// the destination port, or none to match any port (a hostless port is linted, not
    /// rejected, per policy.md section 5)
    pub port: Option<u16>,
    /// the decision when this rule is the first match
    pub action: Action,
}

/// an executable rule: a glob over the resolved binary path and an action. the exec table
/// is the sole spelling for execution control (policy.md section 2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRule {
    /// the binary-path glob, anchored to the full resolved path
    pub binary: Glob,
    /// the decision when this rule is the first match
    pub action: Action,
}

/// the decision a matched rule carries (policy.md section 2). an unknown value in the file
/// is a rejection, never a default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// the action proceeds
    Allow,
    /// the action is refused
    Deny,
    /// the operator is asked (FR-10, FR-20)
    Ask,
}

/// the filesystem access modes a rule can govern (policy.md section 2). matches the trace's
/// access vocabulary; a metadata syscall maps to `write`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsMode {
    /// open for reading
    Read,
    /// open for writing, or a metadata write
    Write,
    /// create a new entry
    Create,
    /// remove an entry
    Delete,
}

/// why a policy file was rejected. rejection is total: any one of these fails the whole
/// load, and the run does not begin (FR-18, policy.md section 4). each variant names what
/// is wrong and where.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// the file could not be read from disk
    #[error("could not read policy file \"{path}\": {source}")]
    Read {
        /// the path that could not be read
        path: String,
        /// the underlying io error
        #[source]
        source: io::Error,
    },
    /// the TOML did not parse, a required field was missing, or an unknown key, action, or
    /// mode was present. the toml error carries the location.
    #[error("policy is not valid TOML: {0}")]
    Toml(#[from] toml::de::Error),
    /// the declared schema_version is not the one this build supports
    #[error("unsupported schema_version {found}; this build supports version {supported}")]
    SchemaVersion {
        /// the version the file declared
        found: u32,
        /// the version this build supports
        supported: u32,
    },
    /// an fs rule declared an empty mode set; it can never match anything
    #[error("fs rule {index}: mode set is empty; list at least one of read, write, create, delete")]
    EmptyMode {
        /// the 1-based rule position within the fs table
        index: usize,
    },
    /// a path or binary glob was malformed
    #[error("{family} rule {index}: invalid glob \"{pattern}\": {source}")]
    Glob {
        /// which table the rule is in: "fs" or "exec"
        family: &'static str,
        /// the 1-based rule position within that table
        index: usize,
        /// the offending pattern
        pattern: String,
        /// why it was rejected
        #[source]
        source: GlobError,
    },
    /// a net rule's host was not a valid shape
    #[error("net rule {index}: invalid host \"{host}\": {source}")]
    Host {
        /// the 1-based rule position within the net table
        index: usize,
        /// the offending host string
        host: String,
        /// why it was rejected
        #[source]
        source: HostError,
    },
    /// a net rule named port 0, which no connection can target
    #[error("net rule {index}: port 0 is not a valid destination port")]
    ZeroPort {
        /// the 1-based rule position within the net table
        index: usize,
    },
    /// a path or binary glob used `{workspace}` or `~` in a position where it cannot be
    /// expanded
    #[error("{family} rule {index}: cannot expand \"{pattern}\": {source}")]
    Expand {
        /// which table the rule is in: "fs" or "exec"
        family: &'static str,
        /// the 1-based rule position within that table
        index: usize,
        /// the offending pattern, as written
        pattern: String,
        /// why expansion failed
        #[source]
        source: ExpandError,
    },
}

impl Policy {
    /// parse and validate a policy from TOML text, expanding globs against `ctx`. returns
    /// the typed policy or the first reason the file is rejected; there is no partial load
    /// (policy.md section 4).
    pub fn parse(text: &str, ctx: &ExpandContext) -> Result<Policy, PolicyError> {
        let raw: RawPolicy = toml::from_str(text)?;

        if raw.schema_version != SCHEMA_VERSION {
            return Err(PolicyError::SchemaVersion {
                found: raw.schema_version,
                supported: SCHEMA_VERSION,
            });
        }

        let mut fs = Vec::with_capacity(raw.fs.len());
        for (i, rule) in raw.fs.into_iter().enumerate() {
            let index = i + 1;
            if rule.mode.is_empty() {
                return Err(PolicyError::EmptyMode { index });
            }
            let path = compile_glob("fs", index, &rule.path, ctx)?;
            fs.push(FsRule {
                path,
                mode: rule.mode,
                action: rule.action,
            });
        }

        let mut net = Vec::with_capacity(raw.net.len());
        for (i, rule) in raw.net.into_iter().enumerate() {
            let index = i + 1;
            if rule.port == Some(0) {
                return Err(PolicyError::ZeroPort { index });
            }
            let host = HostRule::parse(&rule.host).map_err(|source| PolicyError::Host {
                index,
                host: rule.host.clone(),
                source,
            })?;
            net.push(NetRule {
                host,
                port: rule.port,
                action: rule.action,
            });
        }

        let mut exec = Vec::with_capacity(raw.exec.len());
        for (i, rule) in raw.exec.into_iter().enumerate() {
            let index = i + 1;
            let binary = compile_glob("exec", index, &rule.binary, ctx)?;
            exec.push(ExecRule {
                binary,
                action: rule.action,
            });
        }

        Ok(Policy {
            schema_version: raw.schema_version,
            workspace: ctx.workspace.to_string(),
            fs,
            net,
            exec,
        })
    }

    /// read a policy file and parse it. a read failure and a parse failure are both total
    /// rejections; the caller aborts the run either way (policy.md section 4).
    pub fn load(path: &Path, ctx: &ExpandContext) -> Result<Policy, PolicyError> {
        Self::load_with_digest(path, ctx).map(|loaded| loaded.policy)
    }

    /// read a policy file, parse it, and return the exact-byte digest stamped into run
    /// metadata. the digest is computed before parsing but returned only for a valid policy,
    /// so metadata never describes a partially loaded file.
    pub fn load_with_digest(path: &Path, ctx: &ExpandContext) -> Result<LoadedPolicy, PolicyError> {
        let text = std::fs::read_to_string(path).map_err(|source| PolicyError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let digest = hex_sha256(text.as_bytes());
        let policy = Policy::parse(&text, ctx)?;
        Ok(LoadedPolicy { policy, digest })
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// expand a glob's `{workspace}` / `~` tokens, then compile it, tagging any error with the
/// table and 1-based rule position so a rejection names what and where (policy.md
/// section 4). the pattern reported is the original text, as the operator wrote it.
fn compile_glob(
    family: &'static str,
    index: usize,
    raw: &str,
    ctx: &ExpandContext,
) -> Result<Glob, PolicyError> {
    let expanded = expand(raw, ctx).map_err(|source| PolicyError::Expand {
        family,
        index,
        pattern: raw.to_string(),
        source,
    })?;
    Glob::compile(&expanded).map_err(|source| PolicyError::Glob {
        family,
        index,
        pattern: raw.to_string(),
        source,
    })
}

/// expand a single glob string's leading `{workspace}` and `~` tokens (policy.md
/// section 2.1). both are recognized only as the whole leading path component; anywhere
/// else is a rejection. a `~` that is not at the start is an ordinary character.
fn expand(raw: &str, ctx: &ExpandContext) -> Result<String, ExpandError> {
    const WS: &str = "{workspace}";
    let after_ws = if raw == WS {
        ctx.workspace.to_string()
    } else if let Some(rest) = raw.strip_prefix("{workspace}/") {
        format!("{}/{}", ctx.workspace, rest)
    } else if raw.contains(WS) {
        return Err(ExpandError::MisplacedWorkspace);
    } else {
        raw.to_string()
    };

    let expanded = if after_ws == "~" {
        ctx.home.to_string()
    } else if let Some(rest) = after_ws.strip_prefix("~/") {
        format!("{}/{}", ctx.home, rest)
    } else if after_ws.starts_with('~') {
        return Err(ExpandError::MisplacedTilde);
    } else {
        after_ws
    };

    Ok(expanded)
}

// the raw shape as it sits in the file, before validation. deny_unknown_fields turns an
// unknown key into a parse-time rejection, and the typed enums reject an unknown action or
// mode, so those rejection classes fall out of serde (ADR-0018). the remaining checks
// (schema version, empty mode set, glob and host syntax, port range) run in `parse`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    schema_version: u32,
    #[serde(default)]
    fs: Vec<RawFsRule>,
    #[serde(default)]
    net: Vec<RawNetRule>,
    #[serde(default)]
    exec: Vec<RawExecRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFsRule {
    path: String,
    mode: Vec<FsMode>,
    action: Action,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNetRule {
    host: String,
    port: Option<u16>,
    action: Action,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExecRule {
    binary: String,
    action: Action,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // the fixed expansion context used across the load tests. the workspace and home are
    // absolute, as the caller must supply them.
    fn ctx() -> ExpandContext<'static> {
        ExpandContext {
            workspace: "/home/op/project",
            home: "/home/op",
        }
    }

    fn parse(text: &str) -> Result<Policy, PolicyError> {
        Policy::parse(text, &ctx())
    }

    fn digest_of(text: &str) -> String {
        hex_sha256(text.as_bytes())
    }

    // the full example from policy.md section 1, which must load clean and produce the
    // documented structure once its tokens are expanded.
    const VALID: &str = r#"
schema_version = 1

[[fs]]
path   = "~/.ssh/**"
mode   = ["read", "write"]
action = "deny"

[[fs]]
path   = "{workspace}/**"
mode   = ["read", "write", "create", "delete"]
action = "allow"

[[net]]
host   = "api.anthropic.com"
port   = 443
action = "allow"

[[net]]
host   = "*"
action = "ask"

[[exec]]
binary = "/usr/bin/git"
action = "allow"
"#;

    #[test]
    fn parses_the_documented_example() {
        let p = parse(VALID).unwrap();
        assert_eq!(p.schema_version, 1);
        assert_eq!(p.workspace, "/home/op/project");

        assert_eq!(p.fs.len(), 2);
        // ~ and {workspace} are expanded before the glob is compiled
        assert_eq!(p.fs[0].path.as_str(), "/home/op/.ssh/**");
        assert_eq!(p.fs[0].mode, vec![FsMode::Read, FsMode::Write]);
        assert_eq!(p.fs[0].action, Action::Deny);
        assert_eq!(p.fs[1].path.as_str(), "/home/op/project/**");
        assert_eq!(
            p.fs[1].mode,
            vec![FsMode::Read, FsMode::Write, FsMode::Create, FsMode::Delete]
        );
        assert_eq!(p.fs[1].action, Action::Allow);

        assert_eq!(p.net.len(), 2);
        assert_eq!(p.net[0].host, HostRule::Exact("api.anthropic.com".into()));
        assert_eq!(p.net[0].port, Some(443));
        assert_eq!(p.net[0].action, Action::Allow);
        assert_eq!(p.net[1].host, HostRule::Any);
        assert_eq!(p.net[1].port, None);
        assert_eq!(p.net[1].action, Action::Ask);

        assert_eq!(p.exec.len(), 1);
        assert_eq!(p.exec[0].binary.as_str(), "/usr/bin/git");
        assert_eq!(p.exec[0].action, Action::Allow);
    }

    #[test]
    fn empty_tables_are_allowed() {
        // a policy with only a schema version is valid; the base allow still lets the agent
        // work in its workspace (policy.md section 1). all tables default to empty.
        let p = parse("schema_version = 1\n").unwrap();
        assert!(p.fs.is_empty() && p.net.is_empty() && p.exec.is_empty());
    }

    #[test]
    fn load_with_digest_returns_the_validated_file_digest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, VALID).unwrap();
        let loaded = Policy::load_with_digest(&path, &ctx()).unwrap();
        assert_eq!(loaded.digest, digest_of(VALID));
        assert_eq!(loaded.policy.schema_version, 1);
    }

    #[test]
    fn rejects_non_toml() {
        assert!(matches!(
            parse("this is not = = toml"),
            Err(PolicyError::Toml(_))
        ));
    }

    #[test]
    fn rejects_missing_schema_version() {
        // serde reports the missing required field as a toml error
        assert!(matches!(
            parse("[[fs]]\npath=\"/x\"\nmode=[\"read\"]\naction=\"allow\"\n"),
            Err(PolicyError::Toml(_))
        ));
    }

    #[test]
    fn rejects_wrong_schema_version() {
        let err = parse("schema_version = 2\n").unwrap_err();
        assert!(matches!(
            err,
            PolicyError::SchemaVersion {
                found: 2,
                supported: 1
            }
        ));
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        assert!(matches!(
            parse("schema_version = 1\nbogus = true\n"),
            Err(PolicyError::Toml(_))
        ));
    }

    #[test]
    fn rejects_unknown_rule_key() {
        let src =
            "schema_version = 1\n[[fs]]\npath=\"/x\"\nmode=[\"read\"]\naction=\"allow\"\nextra=1\n";
        assert!(matches!(parse(src), Err(PolicyError::Toml(_))));
    }

    #[test]
    fn rejects_unknown_action() {
        let src = "schema_version = 1\n[[fs]]\npath=\"/x\"\nmode=[\"read\"]\naction=\"warn\"\n";
        assert!(matches!(parse(src), Err(PolicyError::Toml(_))));
    }

    #[test]
    fn rejects_unknown_mode() {
        let src = "schema_version = 1\n[[fs]]\npath=\"/x\"\nmode=[\"execute\"]\naction=\"allow\"\n";
        assert!(matches!(parse(src), Err(PolicyError::Toml(_))));
    }

    #[test]
    fn rejects_empty_mode_set() {
        let src = "schema_version = 1\n[[fs]]\npath=\"/x\"\nmode=[]\naction=\"allow\"\n";
        assert!(matches!(
            parse(src),
            Err(PolicyError::EmptyMode { index: 1 })
        ));
    }

    #[test]
    fn rejects_out_of_range_port() {
        let src = "schema_version = 1\n[[net]]\nhost=\"x.com\"\nport=70000\naction=\"allow\"\n";
        // 70000 does not fit u16, so serde rejects it at parse time
        assert!(matches!(parse(src), Err(PolicyError::Toml(_))));
    }

    #[test]
    fn rejects_zero_port() {
        let src = "schema_version = 1\n[[net]]\nhost=\"x.com\"\nport=0\naction=\"allow\"\n";
        assert!(matches!(
            parse(src),
            Err(PolicyError::ZeroPort { index: 1 })
        ));
    }

    #[test]
    fn rejects_malformed_glob_and_names_the_rule() {
        let src = "schema_version = 1\n[[fs]]\npath=\"/x\"\nmode=[\"read\"]\naction=\"allow\"\n[[fs]]\npath=\"a**b\"\nmode=[\"read\"]\naction=\"allow\"\n";
        let err = parse(src).unwrap_err();
        assert!(matches!(
            err,
            PolicyError::Glob {
                family: "fs",
                index: 2,
                ..
            }
        ));
    }

    #[test]
    fn rejects_malformed_exec_glob() {
        let src = "schema_version = 1\n[[exec]]\nbinary=\"***\"\naction=\"allow\"\n";
        assert!(matches!(
            parse(src),
            Err(PolicyError::Glob {
                family: "exec",
                index: 1,
                ..
            })
        ));
    }

    #[test]
    fn rejects_malformed_host_and_names_the_rule() {
        let src = "schema_version = 1\n[[net]]\nhost=\"bad_host\"\naction=\"allow\"\n";
        let err = parse(src).unwrap_err();
        assert!(matches!(err, PolicyError::Host { index: 1, .. }));
    }

    #[test]
    fn missing_port_is_allowed_and_left_none() {
        let src = "schema_version = 1\n[[net]]\nhost=\"x.com\"\naction=\"deny\"\n";
        let p = parse(src).unwrap();
        assert_eq!(p.net[0].port, None);
    }

    #[test]
    fn rejects_brace_glob_as_unsupported_syntax() {
        // a stray brace that is not the {workspace} token is rejected, not treated literally
        let src =
            "schema_version = 1\n[[fs]]\npath=\"/a/x[yz]\"\nmode=[\"read\"]\naction=\"allow\"\n";
        assert!(matches!(
            parse(src),
            Err(PolicyError::Glob {
                family: "fs",
                index: 1,
                source: GlobError::UnsupportedSyntax,
                ..
            })
        ));
    }

    // --- {workspace} and ~ expansion ---

    #[test]
    fn expands_leading_workspace_and_tilde_tokens() {
        assert_eq!(expand("{workspace}", &ctx()).unwrap(), "/home/op/project");
        assert_eq!(
            expand("{workspace}/src/**", &ctx()).unwrap(),
            "/home/op/project/src/**"
        );
        assert_eq!(expand("~", &ctx()).unwrap(), "/home/op");
        assert_eq!(
            expand("~/.ssh/id_ed25519", &ctx()).unwrap(),
            "/home/op/.ssh/id_ed25519"
        );
        // no token: passed through unchanged
        assert_eq!(expand("/usr/bin/git", &ctx()).unwrap(), "/usr/bin/git");
        // a non-leading ~ is an ordinary character
        assert_eq!(expand("/a/b~c", &ctx()).unwrap(), "/a/b~c");
    }

    #[test]
    fn rejects_misplaced_workspace_and_tilde_tokens() {
        assert_eq!(
            expand("/etc/{workspace}", &ctx()),
            Err(ExpandError::MisplacedWorkspace)
        );
        assert_eq!(
            expand("{workspace}extra", &ctx()),
            Err(ExpandError::MisplacedWorkspace)
        );
        assert_eq!(expand("~user/x", &ctx()), Err(ExpandError::MisplacedTilde));
    }

    #[test]
    fn misplaced_token_is_a_load_time_rejection_naming_the_rule() {
        let src = "schema_version = 1\n[[fs]]\npath=\"/etc/{workspace}\"\nmode=[\"read\"]\naction=\"allow\"\n";
        assert!(matches!(
            parse(src),
            Err(PolicyError::Expand {
                family: "fs",
                index: 1,
                source: ExpandError::MisplacedWorkspace,
                ..
            })
        ));
    }
}
