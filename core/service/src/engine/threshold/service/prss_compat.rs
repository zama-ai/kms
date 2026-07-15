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
//! (monotonically increasing) gateway counters, hence one threshold per stream, configured in
//! the `[threshold]` section of the server configuration:
//!
//! - `legacy_prss_mask_before_public_decrypt_id`
//! - `legacy_prss_mask_before_user_decrypt_id`
//!
//! (see [`crate::conf::threshold::ThresholdPartyConf`]). Going through the configuration file
//! rather than dedicated env vars means the values also reach Nitro-enclave deployments, where
//! the pod environment does not propagate into the enclave but the TOML does (over vsock). On
//! non-enclave deployments they can still be overridden through the configuration env layer
//! (`KMS_CORE__THRESHOLD__LEGACY_PRSS_MASK_BEFORE_PUBLIC_DECRYPT_ID`, etc.).
//!
//! Values are decimal or 0x-prefixed hex integers (up to 256 bits), and are consensus
//! constants: all parties MUST configure identical values. The default of "0" means the fixed
//! PRSS schedule is always used (no request ID is strictly below 0). Malformed values fail at
//! config load / server startup, never silently.
//!
//! NOTE: the comparison must be done on the raw request ID interpreted as a big-endian
//! integer. Derived session IDs are hashes of it and carry no order.
//!
//! This module, the config fields and the legacy code path are temporary and should be removed
//! once both gateway counters have passed their thresholds fleet-wide.

use crate::conf::threshold::ThresholdPartyConf;
use alloy_primitives::U256;
use kms_grpc::RequestId;
use std::sync::OnceLock;

/// The two request streams gated by this module. They use separate gateway counters, so each
/// has its own activation threshold.
#[derive(Clone, Copy, Debug)]
pub(crate) enum DecryptKind {
    Public,
    User,
}

static LEGACY_BEFORE_PUBLIC: OnceLock<U256> = OnceLock::new();
static LEGACY_BEFORE_USER: OnceLock<U256> = OnceLock::new();

/// Parse a threshold value as decimal or 0x-prefixed hex.
pub(crate) fn parse_threshold(raw: &str) -> Result<U256, String> {
    let raw = raw.trim();
    let digits = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .map(|hex| (hex, 16))
        .unwrap_or((raw, 10));
    // U256::from_str_radix parses an empty string as 0; reject it explicitly instead, so that
    // a value emptied by a templating mishap fails loudly rather than silently configuring a
    // threshold of 0.
    if digits.0.is_empty() {
        return Err(format!(
            "expected a decimal or 0x-prefixed hex integer, got empty value {raw:?}"
        ));
    }
    U256::from_str_radix(digits.0, digits.1)
        .map_err(|e| format!("expected a decimal or 0x-prefixed hex integer, got {raw:?}: {e}"))
}

/// Initialize the activation thresholds from the threshold party configuration. Must be called
/// during threshold server startup, before any decryption request is served. Fails on
/// malformed values (also caught earlier by config validation) and on re-initialization with
/// conflicting values (which can only happen with multiple in-process servers, e.g. in tests —
/// those must all agree since the values are consensus constants anyway).
///
/// If never called (e.g. centralized KMS), or left at the config default of 0, the fixed
/// schedule is always used.
pub(crate) fn init_from_conf(conf: &ThresholdPartyConf) -> anyhow::Result<()> {
    let parse = |name: &str, raw: &str| -> anyhow::Result<U256> {
        parse_threshold(raw).map_err(|e| anyhow::anyhow!("invalid [threshold].{name}: {e}"))
    };
    let public = parse(
        "legacy_prss_mask_before_public_decrypt_id",
        &conf.legacy_prss_mask_before_public_decrypt_id,
    )?;
    let user = parse(
        "legacy_prss_mask_before_user_decrypt_id",
        &conf.legacy_prss_mask_before_user_decrypt_id,
    )?;

    set_or_check(&LEGACY_BEFORE_PUBLIC, public, "public decryption")?;
    set_or_check(&LEGACY_BEFORE_USER, user, "user decryption")?;

    if public != U256::ZERO || user != U256::ZERO {
        tracing::info!(
            "PRSS-Mask legacy schedule activation thresholds configured: requests with ID strictly below public={public} / user={user} will use the legacy (pre-#663) schedule"
        );
    }
    Ok(())
}

fn set_or_check(cell: &OnceLock<U256>, value: U256, name: &str) -> anyhow::Result<()> {
    match cell.set(value) {
        Ok(()) => Ok(()),
        // Already initialized: tolerate idempotent re-initialization with the identical value.
        // This happens whenever several threshold servers run in one process (the integration
        // test harness boots all parties in-process, so each party's startup calls
        // init_from_conf against the same process-global cell). Only a *different* value is a
        // real conflict — the thresholds are consensus constants.
        Err(rejected) => {
            let existing = cell
                .get()
                .expect("OnceLock::set failed, so it must be initialized");
            if *existing == rejected {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "conflicting re-initialization of the {name} PRSS-Mask schedule threshold: already set to {existing}, refusing {rejected}"
                ))
            }
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
/// counter schedule, i.e. iff an activation threshold is configured for `kind` and the raw
/// request ID is strictly below it.
///
/// This gate applies to *decryption* only. Other PRSS consumers — notably key generation and
/// resharing — are NOT gated and always run the fixed schedule, so they are only safe once the
/// whole fleet runs the fixed schedule. Consequently key generation must not be attempted while
/// the cluster is mixed-version; wait until every party is upgraded (QA/runbook note).
pub(crate) fn use_legacy_prss_mask(req_id: &RequestId, kind: DecryptKind) -> bool {
    let cell = match kind {
        DecryptKind::Public => &LEGACY_BEFORE_PUBLIC,
        DecryptKind::User => &LEGACY_BEFORE_USER,
    };
    // Test builds first check the scoped override (see [`test_prs_compat`]), so integration
    // tests can vary the threshold at runtime without touching the global configuration.
    #[cfg(test)]
    let threshold = test_prs_compat::get(kind).or_else(|| cell.get().copied());
    // Uninitialized (centralized KMS) means: fixed schedule (as does the config default of 0,
    // handled naturally by the strictly-below comparison).
    #[cfg(not(test))]
    let threshold = cell.get().copied();

    match threshold {
        None => false,
        Some(threshold) => {
            let legacy = is_before(req_id, &threshold);
            if legacy {
                #[cfg(test)]
                test_prs_compat::LEGACY_PRSS_DECISIONS
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tracing::info!(
                    "Using legacy (pre-#663) PRSS-Mask schedule for {kind:?} decryption request {req_id} (ID < {threshold})"
                );
            }
            legacy
        }
    }
}

/// Scoped, test-only override of the activation thresholds. This substitutes only the *source*
/// of the threshold; everything downstream (comparison, counting, wiring) is the production
/// code path, and config parsing itself is covered by the unit tests below. The override takes
/// precedence over values set by [`init_from_conf`] (in-process test servers initialize with
/// the default threshold of 0).
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

    static OVERRIDE_PUBLIC: RwLock<Option<U256>> = RwLock::new(None);
    static OVERRIDE_USER: RwLock<Option<U256>> = RwLock::new(None);

    fn cell(kind: DecryptKind) -> &'static RwLock<Option<U256>> {
        match kind {
            DecryptKind::Public => &OVERRIDE_PUBLIC,
            DecryptKind::User => &OVERRIDE_USER,
        }
    }

    pub(super) fn get(kind: DecryptKind) -> Option<U256> {
        *cell(kind).read().unwrap()
    }

    /// RAII guard that overrides the legacy-schedule activation threshold for one stream for
    /// the duration of a test and clears it on drop (including on panic/unwind). Behaves as if
    /// the config field were set to that value; a threshold of 0 behaves like the config
    /// default (fixed schedule always). The override is process-global state: only use it in
    /// `#[serial]` tests.
    pub(crate) struct LegacyThresholdGuard {
        kind: DecryptKind,
    }

    impl LegacyThresholdGuard {
        pub(crate) fn set(kind: DecryptKind, threshold: U256) -> Self {
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
