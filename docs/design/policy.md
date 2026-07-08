# Policy

- Status: draft, in review (slate 2)
- Governs: the policy file format, the predicate vocabulary, how a decision is evaluated from it, how
  it is rejected, and how the Landlock ruleset is derived from it.
- Cites: FR-6, FR-7, FR-18, FR-19; NFR-3, NFR-6; SR-3; ADR-0003, ADR-0004, ADR-0010. Invariants I3,
  I4 are defined in [`architecture.md`](architecture.md).

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

`{workspace}` expands to the run's **workspace** root. The workspace is granted read and write as a
built-in base allow before any rule is read, so a policy that lists nothing still lets the agent work
in its project; rules extend access beyond the workspace or carve restrictions inside it (a `deny`
for `{workspace}/.git/**` placed above the base allow).

## 2. Predicate vocabulary (versioned)

The vocabulary is fixed and tied to `schema_version`; a new predicate is a new schema version and a
security-relevant change (ADR-0004). Version 1 covers exactly what FR-7 requires:

| Family | Key(s) | Matches | Notes |
|---|---|---|---|
| `fs` | `path` (glob), `mode` (set) | filesystem decisions (section 3.1 of [`syscalls.md`](syscalls.md)) | `mode` in `read`, `write`, `create`, `delete`, `execute` |
| `net` | `host`, `port` | `connect` / `bind` decisions | host and port matching semantics are an open parameter, section 6 |
| `exec` | `binary` (glob) | `execve` / `execveat` decisions | the binary path, resolved |

Every rule carries `action` in `allow`, `deny`, `ask`. A rule with an unknown key, an unknown
`action`, an unknown `mode`, or an unknown `schema_version` is a rejection (section 4), never
ignored.

## 3. Evaluation

The engine is pure and total (ADR-0004, NFR-6): a fact in, a decision plus matched-rule id out, no
IO, no child memory, no panic path. It is exhaustively unit-testable without a live child.

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
never mid-execution.

## 5. Linting (advisory, not enforcement)

Beyond rejection, the loader emits advisory warnings that do not stop the run: a rule shadowed
entirely by an earlier one, a `net` rule that names a host but no port, an `fs` rule whose glob
matches nothing under the reachable roots. These help the operator keep a policy honest and diffable
(NFR-3); they are warnings, not errors, because a shadowed or empty rule is not unsafe, only
confusing.

## 6. Landlock derivation

The Landlock ruleset is the always-on kernel backstop (ADR-0003), and it is derived from the same
policy so the two layers cannot silently disagree. The derivation is a coarsening, and its direction
matters for correctness:

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
  of ports any `net` allow/ask rule permits; host enforcement stays in the seccomp layer, which is
  why the host allowlist is the part of the policy the seccomp layer must get exactly right.
- `exec` derives the Landlock `FS_EXECUTE` right on the union of allowed binary paths, which is the
  enforcing control for program execution (`execve` cannot be injected, [`syscalls.md`](syscalls.md)
  section 3.3).

The derivation runs once, in preflight, against the running Landlock ABI; when the ABI cannot back a
required dimension (network on ABI < 4), the degrade table in [`architecture.md`](architecture.md)
section 5.1 governs (refuse in enforce, warn-and-stamp in record-only).

## 7. Open parameters (resolved at slate 2)

- Glob syntax for `path` and `binary` (shell-style `**` vs a fuller matcher), and whether globs are
  anchored.
- Host matching for `net`: exact hostname, suffix wildcard, IP and CIDR, and how a DNS name is
  reconciled with the IP the child actually connects to (the name-versus-address gap is a real
  enforcement question, not a formatting one).
- Whether `mode = ["execute"]` on an `fs` rule and the `exec` table are two spellings of one control
  or kept distinct.

These are carried in the open-parameters table in [`README.md`](README.md) with their closing trigger.
