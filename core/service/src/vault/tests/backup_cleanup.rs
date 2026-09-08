//! Tests destructive cleanup of custodian backup entries.
//!
//! `purge_backup` covers current custodian backups and unencrypted vaults. The shared removal
//! fixture covers file, RAM, and mocked S3 storage. Fault cases use the same populated backup tree
//! to check partial erasure, unrelated custodian contexts, and retry behavior.

mod cases;
mod support;
