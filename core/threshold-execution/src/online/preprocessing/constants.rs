//! The DKG preprocessing batch-size and parallel-chunk constants previously
//! defined here now live in the crate-level [`crate::constants`] module so that
//! all tuning knobs (batch sizes, channel depth, rayon minimum chunk sizes) sit
//! in one place. Import them from `crate::constants` instead.
