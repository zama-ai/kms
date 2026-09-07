//! Tests storage side effects of migrations that replace or delete persisted material.
//!
//! Cases use populated fault-injecting RAM storage. They require migrations to preserve legacy
//! material until its replacement is durable and verified, leave unrelated entries unchanged,
//! and remain safe to retry after partial failure.

mod cases;
mod support;
