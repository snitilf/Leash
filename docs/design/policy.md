# Policy

- Status: settled (slate 2 closed 2026-07-08)
- Governs: the policy file format, the predicate vocabulary, how a decision is evaluated from it, how
  it is rejected, and how the Landlock ruleset is derived from it.
- Cites: FR-6, FR-7, FR-18, FR-19; NFR-3, NFR-6; SR-3; ADR-0003, ADR-0004, ADR-0010, ADR-0013.
  Invariants I3, I4 are defined in [`architecture.md`](architecture.md).

The **policy** is declarative data (ADR-0004): the operator reads, diffs, and reviews one file, and a
pure engine evaluates it (NFR-6). This file fixes the schema and the evaluation model. The engine
consumes the typed fact built by the notify loop ([`notify-loop.md`](notify-loop.md)) and returns a
decision plus the matched-rule id, which the recorder stamps into the event ([`trace.md`](trace.md)).
Terms in **bold** are in [`../CONTEXT.md`](../CONTEXT.md).

## 1. File shape

A policy is a TOML file with an explicit schema-version field and three rule tables, one per
predicate family (FR-7, FR-18). Order within a table is significant (section 3).

```toml
schema_version = 1

# filesystem rules, evaluated top to bottom
[[fs]]
path   = "~/.ssh/**"
mode   = ["read", "write"]
action = "deny"

[[fs]]
path   = "{workspace}/**"
mode   = ["read", "write", "create", "delete"]
action = "allow"

# network rules
[[net]]
host   = "api.anthropic.com"
port   = 443
action = "allow"

[[net]]
host   = "*"
action = "ask"

# executable rules
[[exec]]
binary = "/usr/bin/git"
action = "allow"
```

`{workspace}` expands to the run's **workspace** root. The workspace is granted all four fs modes
(read, write, create, delete) as a built-in base allow before any rule is read, so a policy that
lists nothing still lets the agent work in its project; an agent editing a project creates and
deletes files constantly, and a stingier base would train operators to write broad allows. Rules
extend access beyond the workspace or carve restrictions inside it (a `deny` for
`{workspace}/.git/**` placed above the base allow). This section originally said "read and write";
the recorded decision of 2026-07-14 (slice 2 of #25 surfaced the conflict with section 3) pinned
the base allow to all four modes. This base allow is a deliberate, documented
part of the effective ruleset, not a hidden exception to deny-by-default: it is echoed in the
**session report** so the operator sees the full effective policy (FR-5, NFR-3), and a policy may
override it with an earlier `deny`.

## 2. Predicate vocabulary (versioned)

The vocabulary is fixed and tied to `schema_version`; a new predicate is a new schema version and a
security-relevant change (ADR-0004). Version 1 covers exactly what FR-7 requires:

| Family | Key(s) | Matches | Notes |
|---|---|---|---|
| `fs` | `path` (glob), `mode` (set) | filesystem decisions ([`syscalls.md`](syscalls.md) sections 3.1-3.2) | `mode` in `read`, `write`, `create`, `delete`; metadata syscalls map to `write` |
| `net` | `host`, `port` | `connect` / `bind` decisions | matching semantics in section 2.2 |
| `exec` | `binary` (glob) | `execve` / `execveat` decisions ([`syscalls.md`](syscalls.md) section 3.3) | the binary path, resolved; the sole execution control (section 2.3) |

Every rule carries `action` in `allow`, `deny`, `ask`. A rule with an unknown key, an unknown
`action`, an unknown `mode`, or an unknown `schema_version` is a rejection (section 4), never
ignored.

### 2.1 Glob syntax (fixed at slate 2)

`path` and `binary` are gitignore-style globs: `*` matches within one path component, `**` crosses
components, `?` matches a single character. A glob is anchored: after `{workspace}` and `~`
expansion it must match the entire resolved absolute path, never a substring. Schema version 1 has
no brace expansion and no character classes; a fuller matcher would be a new schema version.

Pinned by the recorded decisions of 2026-07-13 (slice 1 of #25 surfaced them; ADR-0018 governs the
matcher being hand-rolled):

- `?` matches a single character within a component; it never matches `/`.
- `**` is well-formed only as a whole path component (bounded by `/` or the ends of the pattern);
  `a**`, `**b`, `a**b`, and `***` are load-time rejections, per the strict gitignore rule.
- The characters `[`, `]`, `{`, `}`, and a leading `!` are load-time rejections, not literals.
  Version 1 has no classes, braces, or negation, and a rule written with that syntax in mind would
  otherwise silently under-match, which in a `deny` rule is a boundary the operator believes
  exists and does not. Accepting them later (as real classes, in a new schema version) stays
  backward compatible; the reverse would not.
- An empty glob is a load-time rejection.

### 2.2 Host matching (fixed at slate 2)

A `net` rule's `host` is one of: an exact hostname, a `*.suffix` wildcard, an exact IP address, or
a CIDR block. IP and CIDR rules match the destination address in the child's `sockaddr` directly.
A hostname rule is enforced by the supervisor resolving the rule's name itself at decision time
(with a short-lived cache) and matching the child's destination IP against the resolved set; the
child's own resolver is never consulted, so a lying DNS answer inside the child cannot widen the
allowlist. The residual this leaves (CDN address rotation, one IP serving several hosts) is named
in [`escapes.md`](escapes.md).

Pinned by the recorded decisions of 2026-07-13:

- The bare wildcard `host = "*"` is a fifth valid shape, the catch-all (the section 1 example
  already used it); it matches any destination.
- `*.suffix` matches strict subdomains only, the TLS-wildcard-certificate convention:
  `*.example.com` matches `api.example.com` and never `example.com`. Covering the apex takes one
  additional exact rule.
- Hostname matching is case-insensitive. Port 0 is a load-time rejection.
- An IPv4-mapped IPv6 destination (`::ffff:a.b.c.d`) is normalized to IPv4 before it is recorded or evaluated.
  This makes an IPv4 literal or CIDR rule apply consistently to the same destination reached through an IPv4 or dual-stack socket; native IPv6 destinations remain IPv6.

### 2.3 One execution control (fixed at slate 2)

The `exec` table is the only spelling for execution control; there is no `execute` value in
`fs.mode`. One syscall family, one table, one first-match answer: two vocabularies deciding the
same `execve` would reintroduce exactly the ordering ambiguity first-match-in-file-order exists to
remove.

## 3. Evaluation

The engine is pure and total (ADR-0004, NFR-6): a fact in, a decision plus matched-rule id out, no
IO, no child memory read (it sees only the kernel-trusted typed fact, I4), no panic path. It is
exhaustively unit-testable without a live child.

1. Select the table for the fact's family (`fs`, `net`, `exec`).
2. Walk the rules top to bottom. The first rule whose predicate matches the fact wins, and its
   `action` is the decision. First-match-in-file-order is chosen over most-specific-match because it
   is what a reader can evaluate by eye: the decision for any request is "the first line that
   matches", which is diffable and reviewable (NFR-3). The cost is that ordering carries meaning, so
   a broad `allow` placed above a specific `deny` shadows it; the linter (section 5) warns on a
   fully-shadowed rule.
3. If no rule matches, apply the base decision for the **mode** (ADR-0010): in **enforce**, deny
   (deny-by-default, FR-19); in **record-only**, allow. The built-in workspace base allow from
   section 1 participates as the lowest-priority `fs` allow, so an unmatched in-workspace access is
   allowed in both modes.

In **record-only** mode the engine still evaluates the policy and records what it *would* have
decided, flagging a would-deny in the trace and report (ADR-0010), but the action is always allowed.
The engine returns the same decision object in both modes; the mode governs whether the supervisor
enforces it or only records it, not what the engine computes.

## 4. Rejection is total and upfront

A policy that fails to parse, declares an unknown `schema_version`, or contains any unknown predicate
key, `action`, or `mode` is rejected before the run starts, and the run does not begin (FR-18). There
is no partial application: a policy is loaded whole or not at all. This is a fail-closed property
(I3), because a silently-half-applied policy would be a boundary the operator believes exists and does
not. Validation runs entirely before the child is spawned, in the preflight step
([`architecture.md`](architecture.md) section 5.1), so a bad policy fails the run at the command line,
never mid-run.

## 5. Linting (advisory, not enforcement)

Beyond rejection, the loader emits advisory warnings that do not stop the run: a rule shadowed
entirely by an earlier one, a `net` rule that names a host but no port, an `fs` rule whose glob
matches nothing under the reachable roots. These help the operator keep a policy honest and diffable
(NFR-3); they are warnings, not errors, because a shadowed or empty rule is not unsafe, only
confusing.

## 6. Landlock derivation

The Landlock ruleset is the kernel backstop in **enforce** mode (ADR-0003). In **record-only** no
ruleset is applied at all, because nothing is enforced (ADR-0010, [`architecture.md`](architecture.md)
section 5.1); the rest of this section describes the enforce-mode derivation. It is derived from the
same policy so the two enforcing layers cannot silently disagree. The derivation is a coarsening, and
its direction matters for correctness:

- Landlock must not deny what the policy allows or may allow. If the seccomp layer allows an access
  the Landlock ruleset forbids, the kernel blocks a legitimate action and the layers contradict. So
  the derived ruleset grants the **hull** of the policy's permits: every filesystem hierarchy that any
  `allow` or `ask` rule (plus the workspace base allow) could permit, at the path-hierarchy
  granularity Landlock speaks. `ask` is included because an approved ask becomes an allow, and a
  ruleset that excluded ask-able paths would block an approved action.
- The seccomp layer narrows within that hull. Landlock enforces "no filesystem access outside the
  union of granted hierarchies"; the fine-grained per-syscall, per-glob, per-mode decision is the
  seccomp layer's job. Defense in depth means the coarse floor holds even if the fine layer has a gap
  (SR-3), not that the two are redundant.
- Network derivation is limited by what Landlock can express: TCP `connect`/`bind` **ports** only,
  not hosts (see [`syscalls.md`](syscalls.md) section 3.5). The derived net ruleset grants the union
  of ports any `net` allow/ask rule permits; host enforcement stays in the seccomp layer. This is not
  a gap in defense-in-depth but the refined backstop rule of ADR-0013: a boundary is backstopped in
  every dimension the kernel can express (here, the port), and where it cannot (TCP host identity) the
  seccomp layer enforces it alone and the residual is named. It is why the host allowlist is the part
  of the policy the seccomp layer must get exactly right.
- `exec` derives the Landlock `FS_EXECUTE` right on the union of allowed binary paths, which is the
  enforcing control for program execution (`execve` cannot be injected, [`syscalls.md`](syscalls.md)
  section 3.3).

The derivation runs once, in preflight (enforce mode only), against the running Landlock ABI, with the
handled rights masked to it. Where the ABI cannot back a dimension the policy uses, the degrade table
in [`architecture.md`](architecture.md) section 5.1 governs: the seccomp layer enforces that dimension
and the missing backstop is stamped into the trace, rather than the run being refused (ADR-0013). The
only hard refusal is below the kernel floor (ADR-0012).

## 7. Parameters fixed at slate 2

- Glob syntax and anchoring: gitignore-style `*` / `**` / `?`, anchored to the full resolved path
  (section 2.1).
- Host matching: exact hostname, `*.suffix` wildcard, IP, and CIDR; hostname rules enforced by
  supervisor-side resolution against the connected address (section 2.2), with the
  name-versus-address gap named as a residual in [`escapes.md`](escapes.md).
- Execution control has one spelling, the `exec` table (section 2.3).

The [`README.md`](README.md) open-parameters table records these as closed.
