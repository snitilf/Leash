# ADR-0007: Implement in Rust

- Status: accepted
- Date: 2026-07-07

## Context

Leash is security-sensitive systems software that manipulates raw kernel interfaces (seccomp, Landlock, ioctl, `/proc`, overlayfs) and handles hostile input across a trust boundary. The language choice is hard to reverse once a codebase exists. Candidates: C, C++, Rust, Go.

## Decision

Implement Leash in **Rust**.

## Consequences

- Memory-safety by default removes an entire class of vulnerabilities that would be unacceptable in a security tool, while still permitting the low-level `unsafe`/FFI work the kernel interfaces require — confined and audited.
- Rust is the market-legible default for new systems tooling in 2026, which serves the project's portfolio purpose.
- There is a learning ramp (ownership, the borrow checker); it is a ramp on *syntax and discipline*, not on systems concepts, given the author's existing C/systems background.
- The MSRV and edition must be pinned and recorded, because they bound which target machines (Raspberry Pi, VPS) can build the tool.

## Alternatives considered

- **C.** Rejected: no memory safety in a security tool; every bug is a potential CVE. Signals less in a portfolio.
- **C++.** Rejected: memory-safety story weaker than Rust for new code; buys nothing here Rust does not.
- **Go.** Rejected: GC and a heavy runtime are a poor fit for a thin, low-latency syscall supervisor doing extensive FFI; the notify hot path wants predictable, runtime-light control.
