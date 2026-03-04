//! Heap profiling support using jemalloc.
//!
//! When the `heap-profiling` feature is enabled and `MALLOC_CONF` includes
//! `prof:true`, this module provides on-demand heap dumps.
//!
//! # Quick Start
//!
//! For the full Docker-based workflow (handles PIE/ASLR, symbol resolution,
//! and diff analysis automatically), see `profiling/README.md`.
//!
//! Manual (non-PIE binary) usage:
//!
//! 1. Build with: `cargo build -p kms --bin kms-server --profile heap-profiling -F heap-profiling`
//! 2. Run with env: `MALLOC_CONF=prof:true,lg_prof_sample:12 kms-server ...`
//!    (use `lg_prof_sample:19` for lower overhead — see `profiling/README.md`)
//! 3. Dump heap:    `kill -USR1 <pid>`
//! 4. Analyze:      `jeprof --svg kms-server /tmp/kms-heap/prof.0001.heap > heap.svg`
//! 5. Diff two dumps: `jeprof --base=prof.0001.heap --svg kms-server prof.0010.heap > diff.svg`

use std::sync::atomic::{AtomicUsize, Ordering};

const HEAP_DUMP_DIR: &str = "/tmp/kms-heap";

static DUMP_SEQ: AtomicUsize = AtomicUsize::new(0);

/// Dump a heap profile to `/tmp/kms-heap/prof.NNNN.heap`.
///
/// Creates the output directory if it does not already exist.
pub fn dump_heap_profile() -> Result<String, String> {
    // Ensure the output directory exists (idempotent)
    if let Err(e) = std::fs::create_dir_all(HEAP_DUMP_DIR) {
        eprintln!("[heap-profiling] WARNING: failed to create {HEAP_DUMP_DIR}: {e}");
    }

    let seq = DUMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let path_str = format!("{HEAP_DUMP_DIR}/prof.{seq:04}.heap");
    let path_c = format!("{path_str}\0");

    // jemalloc mallctl expects a pointer to the filename string
    let ptr = path_c.as_ptr() as *const std::ffi::c_char;
    // SAFETY: `ptr` points to a valid null-terminated C string (`path_c`) that
    // outlives this call. jemalloc's `prof.dump` mallctl expects a `const char *`
    // and `raw::write` passes `&ptr` as `newp`, matching the expected ABI.
    let result = unsafe { tikv_jemalloc_ctl::raw::write(b"prof.dump\0", ptr) };

    match result {
        Ok(()) => {
            eprintln!("[heap-profiling] Dumped to {path_str}");
            Ok(path_str)
        }
        Err(e) => {
            let msg = format!("jemalloc prof.dump failed: {e}. Is MALLOC_CONF=prof:true set?");
            eprintln!("[heap-profiling] ERROR: {msg}");
            Err(msg)
        }
    }
}

/// Install a SIGUSR1 handler that triggers heap profile dumps.
///
/// Call this once at startup. Then `kill -USR1 <pid>` to dump.
pub fn install_sigusr1_handler() {
    if let Err(e) = std::fs::create_dir_all(HEAP_DUMP_DIR) {
        eprintln!("[heap-profiling] WARNING: failed to create {HEAP_DUMP_DIR}: {e}");
    }

    // Spawn a background tokio task to listen for SIGUSR1
    tokio::spawn(async {
        let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
            .expect("Failed to register SIGUSR1 handler");

        eprintln!("[heap-profiling] Ready — send SIGUSR1 to dump heap profile to {HEAP_DUMP_DIR}/");

        loop {
            sig.recv().await;
            let _ = dump_heap_profile();
        }
    });
}
