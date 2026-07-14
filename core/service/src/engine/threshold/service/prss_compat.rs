//! Issue#3089: temporary request-ID gate for the PRSS-Mask counter-schedule fix (#663).
//!
//! PR #663 changed the counter schedule of the batched PRSS-Mask (`mask_next_vec`) to use
//! disjoint counter pairs. The schedule is consensus-critical: if some MPC parties run the
//! pre-fix schedule and others the fixed one, their mask shares diverge on every block after
//! the first of a batch, and decryption of multi-block ciphertexts degrades (version minority
//! <= t: silently error-corrected, consuming the whole fault budget) or fails (minority > t).
//!
//! To allow parties to upgrade asynchronously, the schedule is selected per request from the
//! raw request ID ("activation height" pattern): requests with an ID strictly below the
//! configured threshold run the legacy schedule (interoperable with unpatched peers), requests
//! at or above it run the fixed one. Public and user decryption request IDs come from separate
//! (monotonically increasing) gateway counters, hence one threshold per stream:
//!
//! - [`LEGACY_PRSS_BEFORE_PUBLIC_DECRYPT_ID_ENV`]
//! - [`LEGACY_PRSS_BEFORE_USER_DECRYPT_ID_ENV`]
//!
//! Values are decimal or 0x-prefixed hex integers (up to 256 bits), and are consensus
//! constants: all parties MUST configure identical values. Unset means the fixed PRSS schedule is
//! always used. A malformed value fails every gated request (loudly) rather than silently
//! picking a schedule.
//!
//! NOTE: the comparison must be done on the raw request ID interpreted as a big-endian
//! integer. Derived session IDs are hashes of it and carry no order.
//!
//! This module, the env vars and the legacy code path are temporary and should be removed
//! once both gateway counters have passed their thresholds fleet-wide.

use alloy_primitives::U256;
use kms_grpc::RequestId;
use std::sync::OnceLock;

/// Public decryption requests with an ID strictly below this value run the legacy PRSS-Mask
/// schedule.
pub const LEGACY_PRSS_BEFORE_PUBLIC_DECRYPT_ID_ENV: &str =
    "KMS_PRSS_LEGACY_MASK_BEFORE_PUBLIC_DECRYPT_ID";
/// User decryption requests with an ID strictly below this value run the legacy PRSS-Mask
/// schedule.
pub const LEGACY_PRSS_BEFORE_USER_DECRYPT_ID_ENV: &str =
    "KMS_PRSS_LEGACY_MASK_BEFORE_USER_DECRYPT_ID";

/// The two request streams gated by this module. They use separate gateway counters, so each
/// has its own activation threshold.
#[derive(Clone, Copy, Debug)]
pub(crate) enum DecryptKind {
    Public,
    User,
}

static LEGACY_BEFORE_PUBLIC: OnceLock<Result<Option<U256>, String>> = OnceLock::new();
static LEGACY_BEFORE_USER: OnceLock<Result<Option<U256>, String>> = OnceLock::new();

/// Parse a threshold value as decimal or 0x-prefixed hex.
fn parse_threshold(raw: &str) -> Result<U256, String> {
    let raw = raw.trim();
    let digits = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .map(|hex| (hex, 16))
        .unwrap_or((raw, 10));
    // U256::from_str_radix parses an empty string as 0; reject it explicitly instead, so that
    // an env var set to an empty value (e.g. by a templating mishap) fails loudly rather than
    // silently configuring a threshold of 0.
    if digits.0.is_empty() {
        return Err(format!(
            "expected a decimal or 0x-prefixed hex integer, got empty value {raw:?}"
        ));
    }
    U256::from_str_radix(digits.0, digits.1)
        .map_err(|e| format!("expected a decimal or 0x-prefixed hex integer, got {raw:?}: {e}"))
}

fn read_env_threshold(var: &str) -> Result<Option<U256>, String> {
    match std::env::var(var) {
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(format!("could not read {var}: {e}")),
        Ok(raw) => {
            let threshold = parse_threshold(&raw).map_err(|e| format!("invalid {var}: {e}"))?;
            tracing::info!(
                "{var} is set: requests with ID < {threshold} will use the legacy (pre-#663) PRSS-Mask schedule"
            );
            Ok(Some(threshold))
        }
    }
}

/// Pure comparison helper: true iff `req_id`, interpreted as a big-endian integer, is strictly
/// below `threshold`.
fn is_before(req_id: &RequestId, threshold: &U256) -> bool {
    // A RequestId is exactly 32 bytes, so the conversion cannot fail.
    U256::try_from_be_slice(req_id.as_bytes())
        .map(|id| id < *threshold)
        .unwrap_or(false)
}

/// Returns true iff the given request must use the legacy (pre-#663) overlapping PRSS-Mask
/// counter schedule, i.e. iff the env var for `kind` is set and the raw request ID is strictly
/// below it. Errors if the env var is set but malformed, failing the request rather than
/// silently choosing a schedule.
pub(crate) fn use_legacy_prss_mask(req_id: &RequestId, kind: DecryptKind) -> anyhow::Result<bool> {
    let (cell, var) = match kind {
        DecryptKind::Public => (
            &LEGACY_BEFORE_PUBLIC,
            LEGACY_PRSS_BEFORE_PUBLIC_DECRYPT_ID_ENV,
        ),
        DecryptKind::User => (&LEGACY_BEFORE_USER, LEGACY_PRSS_BEFORE_USER_DECRYPT_ID_ENV),
    };
    // In production the env var is read and parsed once and cached. Test builds first check
    // the scoped override (see [`test_override`]), which avoids mutating process environment
    // variables at runtime — that is unsafe with concurrently running threads and could
    // corrupt tests running in parallel.
    #[cfg(test)]
    let threshold = match test_prs_compat::get(kind) {
        Some(overridden) => overridden,
        None => cell
            .get_or_init(|| read_env_threshold(var))
            .clone()
            .map_err(|e| anyhow::anyhow!("{e}"))?,
    };
    #[cfg(not(test))]
    let threshold = cell
        .get_or_init(|| read_env_threshold(var))
        .clone()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(match threshold {
        None => false,
        Some(threshold) => {
            let legacy = is_before(req_id, &threshold);
            if legacy {
                #[cfg(test)]
                test_prs_compat::LEGACY_PRSS_DECISIONS
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tracing::info!(
                    "Using legacy (pre-#663) PRSS-Mask schedule for {kind:?} decryption request {req_id} (ID < {var}={threshold})"
                );
            }
            legacy
        }
    })
}

/// Scoped, test-only override of the activation thresholds. This replaces mutating the
/// process environment in tests: `std::env::set_var` is unsafe with concurrently running
/// threads (the tokio servers spawned by integration tests read the env), and a leaked env
/// var would corrupt other tests. The override only substitutes the *source* of the
/// threshold; everything downstream (comparison, counting, wiring) is the production code
/// path, and env parsing itself is covered by the unit tests below.
#[cfg(test)]
pub(crate) mod test_prs_compat {
    use super::DecryptKind;
    use alloy_primitives::U256;
    use std::sync::RwLock;

    /// Test-only counter of how many times the gate selected the legacy schedule, so integration
    /// tests can assert that the switch actually happened (decryption outcomes are identical under
    /// both schedules when all parties agree, so success alone cannot distinguish them).
    pub(crate) static LEGACY_PRSS_DECISIONS: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);

    static OVERRIDE_PUBLIC: RwLock<Option<Option<U256>>> = RwLock::new(None);
    static OVERRIDE_USER: RwLock<Option<Option<U256>>> = RwLock::new(None);

    fn cell(kind: DecryptKind) -> &'static RwLock<Option<Option<U256>>> {
        match kind {
            DecryptKind::Public => &OVERRIDE_PUBLIC,
            DecryptKind::User => &OVERRIDE_USER,
        }
    }

    pub(super) fn get(kind: DecryptKind) -> Option<Option<U256>> {
        *cell(kind).read().unwrap()
    }

    /// RAII guard that overrides the legacy-schedule activation threshold for one stream for
    /// the duration of a test and clears it on drop (including on panic/unwind).
    /// `Some(threshold)` behaves as if the env var were set to that value, `None` as unset.
    /// The override is process-global state: only use it in `#[serial]` tests.
    pub(crate) struct LegacyThresholdGuard {
        kind: DecryptKind,
    }

    impl LegacyThresholdGuard {
        pub(crate) fn set(kind: DecryptKind, threshold: Option<U256>) -> Self {
            *cell(kind).write().unwrap() = Some(threshold);
            Self { kind }
        }
    }

    impl Drop for LegacyThresholdGuard {
        fn drop(&mut self) {
            *cell(self.kind).write().unwrap() = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parse_decimal_and_hex_thresholds() {
        assert_eq!(parse_threshold("1234"), Ok(U256::from(1234u64)));
        assert_eq!(parse_threshold(" 1234 "), Ok(U256::from(1234u64)));
        assert_eq!(parse_threshold("0x10"), Ok(U256::from(16u64)));
        assert_eq!(parse_threshold("0X10"), Ok(U256::from(16u64)));
        assert!(parse_threshold("").is_err());
        assert!(parse_threshold("   ").is_err());
        assert!(parse_threshold("0x").is_err());
        assert!(parse_threshold("nonsense").is_err());
        assert!(parse_threshold("0xzz").is_err());
        assert!(parse_threshold("-3").is_err());
    }

    #[test]
    fn boundary_is_strictly_below() {
        // Request IDs are 32-byte big-endian values; build them from the numeric threshold.
        let threshold = U256::from(1000u64);
        let req_id_from =
            |v: u64| RequestId::from_str(&hex::encode(U256::from(v).to_be_bytes::<32>())).unwrap();

        assert!(is_before(&req_id_from(0), &threshold));
        assert!(is_before(&req_id_from(999), &threshold));
        // ID == threshold must already use the fixed schedule.
        assert!(!is_before(&req_id_from(1000), &threshold));
        assert!(!is_before(&req_id_from(1001), &threshold));
        // Random/hash-style (huge) IDs always get the fixed schedule.
        let huge = RequestId::from_str(&"ff".repeat(32)).unwrap();
        assert!(!is_before(&huge, &threshold));
    }
}
