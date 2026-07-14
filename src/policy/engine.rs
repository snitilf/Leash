//! the policy evaluator: a fact in, a decision plus matched-rule id out (policy.md
//! section 3).
//!
//! assumptions: this is the pure, total core the doc requires. no io, no child memory
//! read, no panic path (NFR-6, ADR-0004, I4). it takes an already-resolved request built
//! from the kernel-trusted typed fact and returns the same decision regardless of run
//! mode; the mode governs only the base decision for an unmatched request, whether the
//! decision is enforced, and whether a would-deny is flagged (ADR-0010). ask resolution
//! (prompting, timeout-to-deny) is the supervisor's job, not the engine's.
//!
//! net seam: the engine matches address-family host rules against a destination `IpAddr`
//! and name rules against an optional destination hostname the caller supplies. resolving
//! a rule's hostname against live DNS is the supervisor's job (policy.md section 2.2); the
//! net fact side of that seam does not exist yet in `src/supervisor/fact.rs` (only the fs
//! table does), so the [`Request::Net`] shape here is the deliberate contract for it.

use std::fmt;
use std::net::IpAddr;

use crate::recorder::{Decision, FsAccess, Mode};

use super::{Action, FsMode, NetRule, Policy};

/// a request to evaluate, built from a mediated syscall's typed fact. the fs access set is
/// the trace vocabulary the notify loop produces ([`FsAccess`]); a rule's `mode` set is the
/// policy vocabulary ([`FsMode`]). borrowed so evaluation allocates nothing.
#[derive(Debug, Clone, Copy)]
pub enum Request<'a> {
    /// a filesystem decision: the resolved path and the requested access set
    Fs {
        /// the resolved absolute path the decision is made on
        path: &'a str,
        /// the access the syscall requests; the rule must cover at least one of these
        access: &'a [FsAccess],
    },
    /// a network decision: the destination address, an optional resolved hostname, and port
    Net {
        /// the destination address from the child's sockaddr
        ip: IpAddr,
        /// a hostname the supervisor has associated with this destination, if any; name
        /// rules match against it, address rules ignore it
        hostname: Option<&'a str>,
        /// the destination port
        port: u16,
    },
    /// an execution decision: the resolved binary path
    Exec {
        /// the resolved absolute binary path
        binary: &'a str,
    },
}

/// which table a rule lives in, for a matched-rule id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// the `fs` table
    Fs,
    /// the `net` table
    Net,
    /// the `exec` table
    Exec,
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Family::Fs => "fs",
            Family::Net => "net",
            Family::Exec => "exec",
        })
    }
}

/// what decided a request. renders to the matched-rule id the recorder stamps into an
/// event (trace.md section 2): `fs.1`, `net.2`, `base:workspace`, `base:enforce`,
/// `base:record_only`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchId {
    /// a rule in a table matched; index is 1-based, matching the operator's file view
    Rule {
        /// which table
        family: Family,
        /// the 1-based rule position
        index: usize,
    },
    /// the built-in workspace base allow (policy.md section 1)
    WorkspaceBaseAllow,
    /// nothing matched and the run is enforcing: deny-by-default (FR-19)
    BaseEnforce,
    /// nothing matched and the run is record-only: the base allow (ADR-0010)
    BaseRecordOnly,
}

impl fmt::Display for MatchId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MatchId::Rule { family, index } => write!(f, "{family}.{index}"),
            MatchId::WorkspaceBaseAllow => f.write_str("base:workspace"),
            MatchId::BaseEnforce => f.write_str("base:enforce"),
            MatchId::BaseRecordOnly => f.write_str("base:record_only"),
        }
    }
}

/// the result of evaluating a request: the effective decision, what decided it, and, in
/// record-only, whether a present policy would have denied (ADR-0010).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evaluation {
    /// the effective decision. in enforce this is the policy verdict; in record-only it is
    /// always allow, because record-only enforces nothing (ADR-0017)
    pub decision: Decision,
    /// the rule or base decision that produced this evaluation
    pub matched: MatchId,
    /// `Some(true)` when the run is record-only and the policy verdict would have denied;
    /// `None` otherwise, so the recorder flags only a would-deny (never a would-allow)
    pub would_deny: Option<bool>,
}

impl Policy {
    /// evaluate a request against this policy in the given mode. pure and total: the same
    /// policy verdict is computed in both modes; the mode selects the base decision for an
    /// unmatched request, whether the verdict is enforced, and whether a would-deny is
    /// flagged (policy.md section 3, ADR-0010).
    pub fn evaluate(&self, request: &Request, mode: Mode) -> Evaluation {
        let (verdict, matched) = match self.first_match(request) {
            Some((action, id)) => (action, id),
            None => {
                // no rule matched (and, for fs, the path is outside the workspace): the
                // inherent verdict is deny-by-default. the marker records which base applied.
                let marker = match mode {
                    Mode::Enforce => MatchId::BaseEnforce,
                    Mode::RecordOnly => MatchId::BaseRecordOnly,
                };
                (Action::Deny, marker)
            }
        };

        match mode {
            Mode::Enforce => Evaluation {
                decision: verdict.into(),
                matched,
                would_deny: None,
            },
            Mode::RecordOnly => Evaluation {
                // record-only enforces nothing; every access is allowed and the verdict is
                // recorded as a would-deny when it would have denied (ADR-0010, ADR-0017).
                decision: Decision::Allow,
                matched,
                would_deny: if verdict == Action::Deny {
                    Some(true)
                } else {
                    None
                },
            },
        }
    }

    /// walk the table for the request's family and return the first matching rule's action
    /// and id. for fs, an unmatched in-workspace access falls to the workspace base allow.
    /// `None` means nothing matched and the caller applies the base decision.
    fn first_match(&self, request: &Request) -> Option<(Action, MatchId)> {
        match request {
            Request::Fs { path, access } => {
                for (i, rule) in self.fs.iter().enumerate() {
                    if rule.path.is_match(path) && mode_intersects(&rule.mode, access) {
                        return Some((
                            rule.action,
                            MatchId::Rule {
                                family: Family::Fs,
                                index: i + 1,
                            },
                        ));
                    }
                }
                if path_under_workspace(&self.workspace, path) {
                    return Some((Action::Allow, MatchId::WorkspaceBaseAllow));
                }
                None
            }
            Request::Net { ip, hostname, port } => {
                for (i, rule) in self.net.iter().enumerate() {
                    if net_matches(rule, *ip, *hostname, *port) {
                        return Some((
                            rule.action,
                            MatchId::Rule {
                                family: Family::Net,
                                index: i + 1,
                            },
                        ));
                    }
                }
                None
            }
            Request::Exec { binary } => {
                for (i, rule) in self.exec.iter().enumerate() {
                    if rule.binary.is_match(binary) {
                        return Some((
                            rule.action,
                            MatchId::Rule {
                                family: Family::Exec,
                                index: i + 1,
                            },
                        ));
                    }
                }
                None
            }
        }
    }
}

impl From<Action> for Decision {
    fn from(action: Action) -> Decision {
        match action {
            Action::Allow => Decision::Allow,
            Action::Deny => Decision::Deny,
            Action::Ask => Decision::Ask,
        }
    }
}

impl FsMode {
    /// does this rule mode govern a requested access? the two enums are the same vocabulary
    /// at two layers (policy rule vs kernel-trusted fact); this is the bridge between them.
    fn covers(self, access: FsAccess) -> bool {
        matches!(
            (self, access),
            (FsMode::Read, FsAccess::Read)
                | (FsMode::Write, FsAccess::Write)
                | (FsMode::Create, FsAccess::Create)
                | (FsMode::Delete, FsAccess::Delete)
        )
    }
}

/// a fs rule matches when its mode set intersects the requested access set (policy.md
/// section 2): at least one requested access is governed by at least one of the rule's modes.
fn mode_intersects(modes: &[FsMode], access: &[FsAccess]) -> bool {
    access.iter().any(|a| modes.iter().any(|m| m.covers(*a)))
}

/// a net rule matches when its port constraint holds (none matches any port) and its host
/// matches the destination: an address family against the ip, a name family against the
/// supplied hostname (policy.md section 2.2).
fn net_matches(rule: &NetRule, ip: IpAddr, hostname: Option<&str>, port: u16) -> bool {
    if let Some(p) = rule.port
        && p != port
    {
        return false;
    }
    rule.host.matches_ip(ip) || hostname.is_some_and(|h| rule.host.matches_hostname(h))
}

/// is a resolved fs path inside the workspace root? the workspace is granted a base allow
/// (policy.md section 1); an exact match or a path with the root as a `/`-bounded prefix
/// counts, so `/ws/x` is under `/ws` but `/ws-other` is not.
fn path_under_workspace(workspace: &str, path: &str) -> bool {
    path == workspace
        || (path.len() > workspace.len()
            && path.starts_with(workspace)
            && path.as_bytes()[workspace.len()] == b'/')
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::policy::ExpandContext;

    const WORKSPACE: &str = "/home/op/project";
    const HOME: &str = "/home/op";

    fn policy(text: &str) -> Policy {
        Policy::parse(
            text,
            &ExpandContext {
                workspace: WORKSPACE,
                home: HOME,
            },
        )
        .unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn eval_fs(p: &Policy, path: &str, access: &[FsAccess], mode: Mode) -> Evaluation {
        p.evaluate(&Request::Fs { path, access }, mode)
    }

    fn eval_net(
        p: &Policy,
        ip: IpAddr,
        hostname: Option<&str>,
        port: u16,
        mode: Mode,
    ) -> Evaluation {
        p.evaluate(&Request::Net { ip, hostname, port }, mode)
    }

    fn eval_exec(p: &Policy, binary: &str, mode: Mode) -> Evaluation {
        p.evaluate(&Request::Exec { binary }, mode)
    }

    // --- matched-rule id rendering, the seam to the recorder's matched_rule string ---

    #[test]
    fn match_ids_render_to_the_recorder_string() {
        assert_eq!(
            MatchId::Rule {
                family: Family::Fs,
                index: 1
            }
            .to_string(),
            "fs.1"
        );
        assert_eq!(
            MatchId::Rule {
                family: Family::Net,
                index: 2
            }
            .to_string(),
            "net.2"
        );
        assert_eq!(MatchId::WorkspaceBaseAllow.to_string(), "base:workspace");
        assert_eq!(MatchId::BaseEnforce.to_string(), "base:enforce");
        assert_eq!(MatchId::BaseRecordOnly.to_string(), "base:record_only");
    }

    // --- first-match ordering ---

    #[test]
    fn first_matching_rule_wins_and_a_broad_allow_shadows_a_later_deny() {
        // a broad allow placed above a specific deny shadows it (policy.md section 3)
        let p = policy(
            "schema_version = 1\n\
             [[fs]]\npath=\"/etc/**\"\nmode=[\"read\"]\naction=\"allow\"\n\
             [[fs]]\npath=\"/etc/shadow\"\nmode=[\"read\"]\naction=\"deny\"\n",
        );
        let e = eval_fs(&p, "/etc/shadow", &[FsAccess::Read], Mode::Enforce);
        assert_eq!(e.decision, Decision::Allow);
        assert_eq!(
            e.matched,
            MatchId::Rule {
                family: Family::Fs,
                index: 1
            }
        );
    }

    #[test]
    fn a_specific_deny_above_a_broad_allow_takes_effect() {
        let p = policy(
            "schema_version = 1\n\
             [[fs]]\npath=\"/etc/shadow\"\nmode=[\"read\"]\naction=\"deny\"\n\
             [[fs]]\npath=\"/etc/**\"\nmode=[\"read\"]\naction=\"allow\"\n",
        );
        let e = eval_fs(&p, "/etc/shadow", &[FsAccess::Read], Mode::Enforce);
        assert_eq!(e.decision, Decision::Deny);
        assert_eq!(
            e.matched,
            MatchId::Rule {
                family: Family::Fs,
                index: 1
            }
        );
    }

    // --- mode-set intersection ---

    #[test]
    fn fs_rule_matches_only_when_mode_set_intersects_requested_access() {
        // a write-only rule does not decide a pure read; it falls through to the base
        let p = policy(
            "schema_version = 1\n\
             [[fs]]\npath=\"/data/**\"\nmode=[\"write\"]\naction=\"deny\"\n",
        );
        // write is governed -> the deny rule matches
        let w = eval_fs(&p, "/data/x", &[FsAccess::Write], Mode::Enforce);
        assert_eq!(w.decision, Decision::Deny);
        assert_eq!(
            w.matched,
            MatchId::Rule {
                family: Family::Fs,
                index: 1
            }
        );
        // pure read is not governed -> falls through to deny-by-default (outside workspace)
        let r = eval_fs(&p, "/data/x", &[FsAccess::Read], Mode::Enforce);
        assert_eq!(r.decision, Decision::Deny);
        assert_eq!(r.matched, MatchId::BaseEnforce);
        // a read+write open intersects the write rule
        let rw = eval_fs(
            &p,
            "/data/x",
            &[FsAccess::Read, FsAccess::Write],
            Mode::Enforce,
        );
        assert_eq!(
            rw.matched,
            MatchId::Rule {
                family: Family::Fs,
                index: 1
            }
        );
    }

    // --- base decisions per mode ---

    #[test]
    fn unmatched_out_of_workspace_denies_in_enforce_and_would_deny_in_record_only() {
        let p = policy("schema_version = 1\n");
        let enforce = eval_fs(&p, "/etc/passwd", &[FsAccess::Read], Mode::Enforce);
        assert_eq!(enforce.decision, Decision::Deny);
        assert_eq!(enforce.matched, MatchId::BaseEnforce);
        assert_eq!(enforce.would_deny, None);

        let record = eval_fs(&p, "/etc/passwd", &[FsAccess::Read], Mode::RecordOnly);
        assert_eq!(record.decision, Decision::Allow);
        assert_eq!(record.matched, MatchId::BaseRecordOnly);
        assert_eq!(record.would_deny, Some(true));
    }

    // --- workspace base allow ---

    #[test]
    fn unmatched_in_workspace_access_is_allowed_in_both_modes() {
        let p = policy("schema_version = 1\n");
        for mode in [Mode::Enforce, Mode::RecordOnly] {
            let e = eval_fs(
                &p,
                "/home/op/project/src/main.rs",
                &[
                    FsAccess::Read,
                    FsAccess::Write,
                    FsAccess::Create,
                    FsAccess::Delete,
                ],
                mode,
            );
            assert_eq!(e.decision, Decision::Allow, "{mode:?}");
            assert_eq!(e.matched, MatchId::WorkspaceBaseAllow, "{mode:?}");
            assert_eq!(e.would_deny, None, "{mode:?}");
        }
        // the workspace root itself, and a sibling that only shares the prefix
        assert_eq!(
            eval_fs(&p, "/home/op/project", &[FsAccess::Read], Mode::Enforce).matched,
            MatchId::WorkspaceBaseAllow
        );
        assert_eq!(
            eval_fs(
                &p,
                "/home/op/project-other/x",
                &[FsAccess::Read],
                Mode::Enforce
            )
            .matched,
            MatchId::BaseEnforce
        );
    }

    #[test]
    fn an_earlier_deny_overrides_the_workspace_base_allow() {
        // a deny inside the workspace shadows the built-in base allow (policy.md section 1)
        let p = policy(
            "schema_version = 1\n\
             [[fs]]\npath=\"{workspace}/.git/**\"\nmode=[\"write\",\"create\",\"delete\"]\naction=\"deny\"\n",
        );
        let denied = eval_fs(
            &p,
            "/home/op/project/.git/config",
            &[FsAccess::Write],
            Mode::Enforce,
        );
        assert_eq!(denied.decision, Decision::Deny);
        assert_eq!(
            denied.matched,
            MatchId::Rule {
                family: Family::Fs,
                index: 1
            }
        );
        // a read elsewhere in the workspace still gets the base allow
        let allowed = eval_fs(
            &p,
            "/home/op/project/src/main.rs",
            &[FsAccess::Read],
            Mode::Enforce,
        );
        assert_eq!(allowed.matched, MatchId::WorkspaceBaseAllow);
    }

    // --- ask surfacing and would-deny flagging ---

    #[test]
    fn ask_surfaces_as_ask_in_enforce_and_as_allow_without_would_deny_in_record_only() {
        let p = policy("schema_version = 1\n[[net]]\nhost=\"*\"\naction=\"ask\"\n");
        let enforce = eval_net(&p, ip("1.2.3.4"), None, 443, Mode::Enforce);
        assert_eq!(enforce.decision, Decision::Ask);
        assert_eq!(enforce.would_deny, None);

        let record = eval_net(&p, ip("1.2.3.4"), None, 443, Mode::RecordOnly);
        // record-only realizes everything as allow; an ask is not a deny, so no would-deny
        assert_eq!(record.decision, Decision::Allow);
        assert_eq!(record.would_deny, None);
    }

    #[test]
    fn a_matched_deny_flags_would_deny_in_record_only_but_allows() {
        let p = policy("schema_version = 1\n[[exec]]\nbinary=\"/usr/bin/curl\"\naction=\"deny\"\n");
        let record = eval_exec(&p, "/usr/bin/curl", Mode::RecordOnly);
        assert_eq!(record.decision, Decision::Allow);
        assert_eq!(record.would_deny, Some(true));
        assert_eq!(
            record.matched,
            MatchId::Rule {
                family: Family::Exec,
                index: 1
            }
        );

        let enforce = eval_exec(&p, "/usr/bin/curl", Mode::Enforce);
        assert_eq!(enforce.decision, Decision::Deny);
        assert_eq!(enforce.would_deny, None);
    }

    // --- net matching primitives ---

    #[test]
    fn net_matches_on_ip_cidr_and_resolved_hostname() {
        let p = policy(
            "schema_version = 1\n\
             [[net]]\nhost=\"api.anthropic.com\"\nport=443\naction=\"allow\"\n\
             [[net]]\nhost=\"10.0.0.0/8\"\naction=\"deny\"\n\
             [[net]]\nhost=\"*\"\naction=\"ask\"\n",
        );
        // hostname rule matches only when the supervisor supplies the resolved name
        let named = eval_net(
            &p,
            ip("203.0.113.7"),
            Some("api.anthropic.com"),
            443,
            Mode::Enforce,
        );
        assert_eq!(named.decision, Decision::Allow);
        assert_eq!(
            named.matched,
            MatchId::Rule {
                family: Family::Net,
                index: 1
            }
        );
        // same ip and port but no resolved name: rule 1 cannot match, falls to the catch-all
        let unnamed = eval_net(&p, ip("203.0.113.7"), None, 443, Mode::Enforce);
        assert_eq!(unnamed.decision, Decision::Ask);
        assert_eq!(
            unnamed.matched,
            MatchId::Rule {
                family: Family::Net,
                index: 3
            }
        );
        // the hostname rule carries port 443; a different port cannot match it
        let wrong_port = eval_net(
            &p,
            ip("203.0.113.7"),
            Some("api.anthropic.com"),
            80,
            Mode::Enforce,
        );
        assert_eq!(
            wrong_port.matched,
            MatchId::Rule {
                family: Family::Net,
                index: 3
            }
        );
        // cidr rule matches an address in range
        let in_cidr = eval_net(&p, ip("10.1.2.3"), None, 22, Mode::Enforce);
        assert_eq!(in_cidr.decision, Decision::Deny);
        assert_eq!(
            in_cidr.matched,
            MatchId::Rule {
                family: Family::Net,
                index: 2
            }
        );
    }

    #[test]
    fn net_with_no_rule_hits_the_base_decision() {
        let p = policy("schema_version = 1\n");
        assert_eq!(
            eval_net(&p, ip("1.2.3.4"), None, 443, Mode::Enforce).decision,
            Decision::Deny
        );
        assert_eq!(
            eval_net(&p, ip("1.2.3.4"), None, 443, Mode::RecordOnly).would_deny,
            Some(true)
        );
    }

    // --- exec matching ---

    #[test]
    fn exec_matches_the_resolved_binary_glob() {
        let p = policy("schema_version = 1\n[[exec]]\nbinary=\"/usr/bin/*\"\naction=\"allow\"\n");
        assert_eq!(
            eval_exec(&p, "/usr/bin/git", Mode::Enforce).decision,
            Decision::Allow
        );
        // outside the glob, no rule matches -> deny-by-default in enforce
        assert_eq!(
            eval_exec(&p, "/usr/local/bin/git", Mode::Enforce).matched,
            MatchId::BaseEnforce
        );
    }
}
