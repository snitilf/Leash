# Work Tracking Setup — GitHub Issues + Projects

How work is tracked on Leash, and how to stand the system up from scratch (you'll do this once, in the fresh repo). This is a **runbook**: follow it top to bottom and the tracking system is reproducible, not hand-assembled.

## Philosophy: two layers, never merged

| Layer | Lives in | Holds | Mutable? |
|---|---|---|---|
| **Knowledge** | `docs/` (spec, ADRs, `CONTEXT.md`) | *why* and *what must be true* | ADRs immutable; spec append-only IDs |
| **Work** | GitHub Issues / PRs | *what to do* and *its state* | fully mutable/ephemeral |

The docs are the deterministic brain and the source of truth. Issues are the execution log — flow, not truth. **Never put a decision in an issue and nowhere else**: if grilling an issue produces a decision, record it in the spec or an ADR, then the issue just references the ID.

## The traceability chain

```
ADR-0004  ──justifies──▶  FR-6 (spec)  ──implemented by──▶  Issue #12  ──closed by──▶  PR #13  ──cites──▶  FR-6
  (why)                     (what)                            (work)                   (change)
```

Every issue names the requirement ID(s) it implements. Every PR cites the same ID(s) and closes its issue. Review checks the diff against those IDs. This chain is what makes the project *fully tracked* — any line of code traces up to the requirement and the decision that justify it.

---

## One-time setup (run in the fresh repo)

Prerequisites: the repo exists on GitHub, and the `gh` CLI is installed and authenticated (`gh auth login`).

### Step 1 — Labels

A deliberately lean set. Four axes: **type**, **change-control tier** (how much scrutiny a change needs, 0 to 3), **area** (from the module map), and **status**. Plus `agent-ready` / `human-only` to route work between the operator and an agent.

```bash
# type
gh label create "type:feature"  -c "#1d76db" -d "New capability" --force
gh label create "type:bug"      -c "#d73a4a" -d "Something broken" --force
gh label create "type:security" -c "#b60205" -d "Touches an enforced control / threat model" --force
gh label create "type:spike"    -c "#5319e7" -d "Time-boxed investigation" --force
gh label create "type:docs"     -c "#0e8a16" -d "Spec/ADR/design/docs only" --force
gh label create "type:chore"    -c "#c5def5" -d "Tooling, CI, deps" --force

# change-control tier (0 cosmetic, 1 ordinary, 2 security-relevant, 3 architectural)
gh label create "tier:0" -c "#ededed" -d "Cosmetic" --force
gh label create "tier:1" -c "#c2e0c6" -d "Ordinary behavior" --force
gh label create "tier:2" -c "#fbca04" -d "Security-relevant" --force
gh label create "tier:3" -c "#e99695" -d "Architectural / boundary-relaxing" --force

# area (module map)
for a in policy supervisor recorder snapshot sandbox cli; do
  gh label create "area:$a" -c "#bfd4f2" -d "$a module" --force
done

# status / routing
gh label create "status:needs-decision" -c "#d876e3" -d "Blocked on a decision (grill it)" --force
gh label create "status:blocked"        -c "#000000" -d "Blocked on another issue" --force
gh label create "agent-ready"           -c "#0e8a16" -d "Self-contained; an agent can take it" --force
gh label create "human-only"            -c "#5319e7" -d "Requires human judgement/credentials; do not assign to an agent" --force
```

> **Why `human-only` exists:** some work (relaxing a security boundary — tier:3, anything touching real credentials/money in your pipeline, final release sign-off) must not be delegated to an agent. Labeling it keeps the agentic workflow safe by default.

### Step 2 — Milestones (= roadmap phases)

One milestone per roadmap phase.

```bash
gh api repos/:owner/:repo/milestones -f title="M0 · Spike"        -f description="Design/spec; supervisor spike" >/dev/null
gh api repos/:owner/:repo/milestones -f title="M1 · Recorder"     -f description="v0.1: record file/proc/net events" >/dev/null
gh api repos/:owner/:repo/milestones -f title="M2 · Enforcement"  -f description="Policy + Landlock + escape suite" >/dev/null
gh api repos/:owner/:repo/milestones -f title="M3 · Time travel"  -f description="Snapshot / rewind / diff / TUI" >/dev/null
gh api repos/:owner/:repo/milestones -f title="M4 · Depth"        -f description="Hardening, benchmarks, v1.0" >/dev/null
```

### Step 3 — Issue & PR templates

Create these files (they live in the repo, so they're versioned like everything else):

**`.github/ISSUE_TEMPLATE/work-item.md`**

```markdown
---
name: Work item
about: A vertical slice of work implementing one or more requirements
labels: []
---

## Requirement(s)
<!-- The spec ID(s) this implements, e.g. FR-6, NFR-9. Link to docs/spec/SPEC.md.
     If there is no governing requirement yet, this issue is `status:needs-decision`
     — grill it into the spec first. -->

## Outcome
<!-- One shippable behavior, from the operator's perspective. A vertical slice,
     not a micro-task. If it needs more than ~a few sessions, split it. -->

## Acceptance criteria
<!-- How we'll know it's done, by observation, not by reading the diff.
     For type:security, list the escape tests that MUST pass (NFR-5). -->
- [ ]

## Change-control tier
<!-- 0–3. Round up when unsure. -->

## Notes / dependencies
<!-- Blocking issues, relevant ADRs, design sections. -->
```

**`.github/pull_request_template.md`**

```markdown
## What & why
Implements: <!-- FR-x / NFR-x / ADR-xxxx -->
Closes: #<!-- issue number -->

## Change-control tier
<!-- 0–3. Tier ≥2 requires the security checklist below. -->

## Evidence
- [ ] Behavior verified by observation, not just "it compiles"
- [ ] Tests written first, at agreed seams

## Security checklist (tier ≥ 2)
- [ ] Escape-attempt tests pass for every control claimed (NFR-5)
- [ ] Fails closed on error/timeout (FR-9)
- [ ] Child cannot touch the log / decision path (ADR-0002)
- [ ] Every `unsafe` has a `// SAFETY:` note

## Docs
- [ ] Spec/ADR/CONTEXT.md updated if this changed a decision or a term
```

### Step 4 — Projects board

```bash
# Create a user/org project (v2). Adjust --owner to your GitHub handle.
gh project create --owner "@me" --title "Leash"
```

Then in the UI (one-time): add a **Board** view with columns **Backlog → Ready → In progress → In review → Done**, and enable the built-in workflows: *Item added to project → Backlog*, *PR merged → Done*, *Issue closed → Done*. Link the repo so new issues auto-add. A board is optional sugar over issues; skip it if you find it noise.

### Step 5 — Seed the initial backlog from the spec

Don't mass-create issues for unresolved work. Seed only what's real now:

1. One `type:docs` issue per **open question** (OQ-1…OQ-8) → label `status:needs-decision`, milestone **M0**. Closing it = grilling it into the spec.
2. Once the spec is settled, one `agent-ready` `type:feature` issue per **M1 (Recorder)** vertical slice, each citing its FR IDs.

```bash
# example: seed the open-question issues
gh issue create -t "Decide OQ-1: what is a \"step\"?" \
  -b "Resolve SPEC.md §11 OQ-1 with the operator; record as requirement/ADR." \
  -l "type:docs,status:needs-decision" -m "M0 · Spike"
# …repeat for OQ-2…OQ-8
```

---

## Conventions (the rules that keep it deterministic)

- **An issue is a vertical slice** — one shippable behavior citing requirement IDs — never a micro-task. No issue to rename a variable.
- **No work without a governing requirement.** If an issue has no FR/NFR/ADR to cite, it's `status:needs-decision` — resolve it into the spec first. This is the "no decision without a record" rule, enforced at the tracker.
- **Branch per issue**, PR closes it (`Closes #N`), PR cites the requirement IDs. Merge only when review passes on both axes (standards and spec).
- **Commits** are small and single-purpose; the message names the tier for tier ≥ 2.
- **Routing:** `agent-ready` = a self-contained slice a coding agent can take from the issue and open a PR for. `human-only` = tier:3, credential/money-touching, or release sign-off — you do these.
- **Settled investigations** get distilled from the closed bug issue into the project's investigation record (the curated "don't re-fight this" index). The issue is the raw thread; the record entry is the lesson.

## How the agentic loop runs

1. You file an `agent-ready` issue citing requirements.
2. Assign the agent (web: assign the issue / kick it off). It reads the issue and the governing docs → implements test-first → opens a PR citing the IDs.
3. CI and review run. You review the PR (especially the security checklist for tier ≥ 2).
4. Merge closes the issue and (via board automation) moves it to Done.
5. Anything that changed a decision is already in an ADR/spec because the PR checklist required it — so the deterministic brain stays current.

