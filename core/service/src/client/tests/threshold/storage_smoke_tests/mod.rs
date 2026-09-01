//! File-storage checks for the threshold epoch lifecycle.
//!
//! The tests run four KMS parties against one temporary material directory. They inspect the
//! files after lifecycle requests and restart the parties on the same directory. The second epoch
//! contains a small value at the real `FheKeyInfo/<epoch>/<key>` path. Cleanup does not deserialize
//! this file.

mod cases;
mod support;
