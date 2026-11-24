# ADR-0023: The namespace-root anchor resolves with RESOLVE_IN_ROOT

- Status: accepted
- Date: 2026-11-23
- Tier: 2 (enforcement-path resolution)

## Context

ADR-0020's "namespace-root symlinks" amendment gave the `/` anchor `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`.
Its stated reason was that no ordinary symlink can escape above `/`, so layouts such as `/lib` pointing into `/usr/lib` keep working.
That reasoning holds only for relative symlinks.
The kernel's `RESOLVE_BENEATH` rejects every absolute symlink with `EXDEV` whatever the anchor is, because an absolute target restarts resolution at the process root, which is by definition not beneath the dirfd.
A real enforce run on Ubuntu 24.04 (kernel 6.8) under a `/**` read allow showed the result: `sh -c 'cat /etc/hostname'` makes glibc open `/usr/share/locale/locale.alias`, an absolute symlink to `/etc/locale.alias`, and the broker answered `EXDEV` for a path the policy allows.
The same class covers `/etc/localtime`, `/etc/alternatives/*` and `/usr/bin/editor`.

## Decision

For the namespace-root anchor only, the broker resolves with `RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS` instead of `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`.
The root dirfd for this anchor is the real `/`, so `RESOLVE_IN_ROOT` yields ordinary path semantics: absolute symlinks restart at `/`, and `..` at `/` stays at `/`.
Magic links stay refused.
The workspace anchor keeps `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`, so an absolute symlink leaving the workspace is still refused.
Narrower non-workspace anchors keep `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`.
This supersedes only the flag choice in ADR-0020's namespace-root amendment.

## Consequences

Policy is still evaluated against the final resolved path.
The prepared identity is read back from the opened handle (`/proc/self/fd` readlink), not from the requested string, so a symlink under `/tmp` that points at a path matched by a deny rule resolves to the denied path and is denied.
Landlock in the broker's domain remains the kernel backstop for the same final object.
The `/` anchor gains no reach it did not already have: it already covered every path.
It only stops refusing symlinks the policy allows.

## Alternatives considered

Dropping to `RESOLVE_NO_SYMLINKS` at `/` would break `/lib` and every distribution symlink.
Dropping all resolve flags would lose the magic-link refusal.
Leaving `RESOLVE_BENEATH` keeps the bug, so enforce mode cannot run ordinary programs under a broad read allow.
