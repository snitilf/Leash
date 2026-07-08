//! the trace writer and session report (docs/design/trace.md).
//!
//! assumptions: this module is the single writer of the trace (I2, ADR-0002); no other
//! module holds the file. events are append-only in decision order; a write failure is
//! surfaced to the caller so the pending action denies and the run aborts (case E), never
//! swallowed. the child cannot reach the state directory in enforce mode; in record-only
//! that protection is filesystem permissions and is a named residual, not a claim.
