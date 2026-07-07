# Design

*How* Leash is built. This layer is written after the specification is settled: a design that
commits to *how* before *what* builds the wrong thing precisely.

Status: **not started.** The spec is settled (v0.2), so the design phase can begin.

This directory will hold, at minimum:
- the module decomposition (`policy`, `supervisor`, `recorder`, `snapshot`, `sandbox`, `cli`);
- the mediated-syscall enumeration and how each is decided (FR-4);
- the notify-loop protocol and its fail-closed handling (FR-9);
- the snapshot/rewind mechanism (ADR-0009, FR-17);
- the policy schema (FR-18).

Each design choice cites the spec requirement it satisfies and, where it is a hard-to-reverse
trade-off, is accompanied by an ADR.
