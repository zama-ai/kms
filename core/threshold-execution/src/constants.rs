use const_format::concatcp;

cfg_if::cfg_if! {
    if #[cfg(feature = "non-wasm")] {
        /// log_2 of parameter B_{SwitchSquash}, always using the upper bound
        pub(crate) const LOG_B_SWITCH_SQUASH: u32 = 70;
        pub (crate) const B_SWITCH_SQUASH: u128 = 1 << LOG_B_SWITCH_SQUASH;

        /// maximum number of PRSS party sets (n choose t) before the precomputation aborts
        pub(crate) const PRSS_SIZE_MAX: usize = 2047;

        /// statistical security parameter in bits
        pub const STATSEC: u32 = 40;

        /// constants for key separation in PRSS/PRZS
        pub(crate) const PHI_XOR_CONSTANT: u8 = 2;
        pub(crate) const CHI_XOR_CONSTANT: u8 = 1;

        // ---- MPC tuning knobs ----
        //
        // Each value is configurable at runtime via an environment variable and
        // read once on first access (`LazyLock`). When the variable is unset or
        // cannot be parsed as a `usize`, the documented default is used.

        /// Reads a `usize` tuning value from environment variable `name`, falling
        /// back to `default` when unset or unparseable.
        fn env_usize(name: &str, default: usize) -> usize {
            let value = match std::env::var(name) {
                Ok(raw) => {
                    raw.trim().parse::<usize>().unwrap_or_else(|_| {
                        tracing::warn!(
                            "Invalid usize value {raw:?} for env var {name}; using default {default}"
                        );
                        default
                    })
                },
                Err(e) => {
                    tracing::warn!("Error reading env var {name}: {e:?}; using default {default}");
                    default
                },
            };
            tracing::info!("Using tuning value {value} from env var {name} ");
            value
        }

        /// Amount of triples generated in one batch by the orchestrator.
        /// Env: `MPC_DKG_BATCH_SIZE_TRIPLES` (default 10000).
        pub(crate) static BATCH_SIZE_TRIPLES: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| env_usize("MPC_DKG_BATCH_SIZE_TRIPLES", 10000));
        /// Amount of bits generated in one batch by the orchestrator.
        /// Env: `MPC_DKG_BATCH_SIZE_BITS` (default 10000).
        pub(crate) static BATCH_SIZE_BITS: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| env_usize("MPC_DKG_BATCH_SIZE_BITS", 10000));
        /// Number of batches that can be queued per producer thread in the
        /// orchestrator. A value of 2 enables double-buffering: a producer can
        /// prepare the next batch while the consumer drains the current one.
        /// Env: `MPC_DKG_CHANNEL_BUFFER_SIZE` (default 2).
        pub(crate) static CHANNEL_BUFFER_SIZE: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| env_usize("MPC_DKG_CHANNEL_BUFFER_SIZE", 2));
        /// Progress tracker reports every `TRACKER_LOG_PERCENTAGE` percent.
        /// Env: `MPC_DKG_TRACKER_LOG_PERCENTAGE` (default 5).
        pub static TRACKER_LOG_PERCENTAGE: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| env_usize("MPC_DKG_TRACKER_LOG_PERCENTAGE", 5));

        // ---- Minimum rayon chunk sizes (minimum items per parallel task) ----
        // Tuning knobs for the parallel preprocessing loops: large enough to
        // amortize rayon's split/join overhead and to avoid oversubscription
        // under the orchestrator's session-level parallelism, small enough to
        // still parallelize some tasks.
        // NOTE: These are starting points and should be benchmarked and adjusted as needed.

        /// Local partial decryption of noise-flooding decryption: requests of at most this many packed blocks
        /// run inline on the calling thread (a block is ~6 µs of IFMA work; waking the pool and warming
        /// the key table in another core's cache costs more than that — on a 16+-core EC2 instance eight
        /// blocks took 69 µs over four tasks against 44 µs inline, sixteen blocks were even).
        /// Env: `MPC_PDEC_INLINE_MAX_BLOCKS` (default 8).
        pub(crate) static PDEC_INLINE_MAX_BLOCKS: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| env_usize("MPC_PDEC_INLINE_MAX_BLOCKS", 8));
        /// Blocks per Rayon task of the local partial decryption above that size: small tasks keep the
        /// critical path short once the pool is awake (64 blocks: 82 µs in pairs on the same instance).
        /// Env: `MPC_PDEC_PAR_MIN_BLOCKS` (default 2).
        /// Panics on initialization if the configured size is zero.
        pub(crate) static PDEC_PAR_MIN_BLOCKS: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| {
                let blocks = env_usize("MPC_PDEC_PAR_MIN_BLOCKS", 2);
                assert!(blocks > 0, "MPC_PDEC_PAR_MIN_BLOCKS must be at least 1");
                blocks
            });
        /// TUniform noise assembly: very cheap per item (~`bound + 2` ring ops).
        /// Env: `MPC_DKG_TUNIFORM_PAR_MIN_CHUNK` (default 4096).
        pub(crate) static TUNIFORM_GEN_PAR_MIN_CHUNK: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| env_usize("MPC_DKG_TUNIFORM_PAR_MIN_CHUNK", 4096));
        /// PRSS / PRZS / mask batch generation: a few AES-PRF evaluations per item.
        /// Env: `MPC_PRSS_PAR_MIN_CHUNK` (default 1024).
        /// Panics on initialization if the configured size is zero.
        pub(crate) static PRSS_GEN_PAR_MIN_CHUNK: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| {
                let chunk = env_usize("MPC_PRSS_PAR_MIN_CHUNK", 1024);
                assert!(chunk > 0, "MPC_PRSS_PAR_MIN_CHUNK must be at least 1");
                chunk
            });
        /// d-value reconstruction in triple/square generation (nsmall offline) : heavy per item
        /// (a Shamir reconstruction).
        /// Env: `MPC_D_VALUE_RECONSTRUCTION_PAR_MIN_CHUNK` (default 256).
        pub(crate) static D_VALUE_RECONSTRUCTION_PAR_MIN_CHUNK: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| {
                env_usize("MPC_D_VALUE_RECONSTRUCTION_PAR_MIN_CHUNK", 256)
            });
        /// Robust-open reconstruction (`sharing::open`).
        /// Env: `MPC_ROBUST_OPEN_PAR_MIN_CHUNK` (default 256).
        pub(crate) static ROBUST_OPEN_RECONSTRUCTION_PAR_MIN_CHUNK: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| {
                env_usize("MPC_ROBUST_OPEN_PAR_MIN_CHUNK", 256)
            });
        /// Whether reconstructions try the optimistic path (interpolate from `degree + 1` shares, accept
        /// only if every share agrees; see `algebra::sharing::optimistic`) before the error-correcting
        /// decoder. Env: `MPC_RECONSTRUCT=decoder` disables it, for before/after benchmarks; anything else
        /// (or unset) enables it.
        pub static RECONSTRUCT_OPTIMISTIC: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
            let optimistic = std::env::var("MPC_RECONSTRUCT")
                .map(|v| v.trim() != "decoder")
                .unwrap_or(true);
            tracing::info!("Reconstruction: optimistic path {}", if optimistic { "on" } else { "off (MPC_RECONSTRUCT=decoder)" });
            optimistic
        });
    }
}

/// keygen directories (anchored to the workspace root so paths are stable
/// regardless of which crate's tests are running or what the CWD is).
/// threshold-execution lives at `core/threshold-execution/`, so `/../..` reaches the workspace root.
pub const TEMP_DIR: &str = concatcp!(env!("CARGO_MANIFEST_DIR"), "/../../temp");

pub const SMALL_TEST_KEY_PATH: &str = concatcp!(TEMP_DIR, "/small_test_keys.bin");
pub const REAL_KEY_PATH: &str = concatcp!(TEMP_DIR, "/default_keys.bin");
