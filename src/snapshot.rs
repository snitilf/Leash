//! workspace snapshots, rewind, and diff (docs/design/snapshot.md, ADR-0009).
//!
//! assumptions: nothing in this module sits on the decision loop's hot path. the upper
//! layer has overlay semantics (whiteouts, opaque markers, copy-up), and every reader in
//! here must interpret them, never treat the layer as a plain tree. the copy fallback
//! must stay observably equivalent to the overlay; behavior only one mechanism exhibits
//! is a bug in one of them.
