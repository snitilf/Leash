# Design

*How* Leash is built. This layer is written **after** the specification's open questions (`../spec/SPEC.md` §11) are resolved — a design that commits to *how* before *what* is settled builds the wrong thing precisely.

Status: **not started.** The design phase begins once SPEC.md leaves DRAFT (open questions closed into requirements/ADRs).

When it begins, this directory will hold, at minimum:
- the module decomposition (matching the responsibilities named in the architecture contract: `policy`, `supervisor`, `recorder`, `snapshot`, `sandbox`, `cli`);
- the mediated-syscall enumeration and how each is decided;
- the notify-loop protocol and its fail-closed handling;
- the snapshot/rewind mechanism chosen in OQ-1/OQ-2;
- the policy schema chosen in OQ-3.

Each design choice cites the spec requirement it satisfies and, where it is a hard-to-reverse trade-off, is accompanied by an ADR.
