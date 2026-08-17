//! Memoization of the per-scheme signing keys derived from a root secret.

use super::{SigningSchemeType, UnifiedPrivateSigKey};
use std::sync::{Arc, OnceLock};
use strum::EnumCount;
use zeroize::Zeroize;

/// Per-scheme cache of signing keys derived from a root secret.
///
/// Deriving a key runs a KDF plus a (for ML-DSA, non-trivial) key expansion, so
/// each scheme's key is derived once and memoized here.
///
/// Which slots are ever filled depends on what the cache hangs off:
/// - a [`super::RootSigningSeed`] is the root of the whole key hierarchy and can
///   derive every scheme, so every slot may be filled;
/// - a [`super::ecdsa::PrivateSigKey`] signs ECDSA with itself, so its
///   [`SigningSchemeType::Ecdsa256k1`] slot always stays empty.
pub(super) struct DerivedKeyCache {
    /// One slot per [`SigningSchemeType`], indexed by `scheme as usize`.
    slots: Arc<[OnceLock<UnifiedPrivateSigKey>; SigningSchemeType::COUNT]>,
}

impl DerivedKeyCache {
    pub(super) fn slot(&self, scheme: SigningSchemeType) -> &OnceLock<UnifiedPrivateSigKey> {
        &self.slots[scheme as usize]
    }
}

impl Default for DerivedKeyCache {
    fn default() -> Self {
        Self {
            slots: Arc::new(std::array::from_fn(|_| OnceLock::new())),
        }
    }
}

// Warm clone: sharing the `Arc` is deliberate, so clones of a root secret share
// one warmed cache rather than each re-deriving.
impl Clone for DerivedKeyCache {
    fn clone(&self) -> Self {
        Self {
            slots: Arc::clone(&self.slots),
        }
    }
}

// Ignore the key cache when doing equality comparision.
// Instead we only care about the underlying root secret when comparing.
impl PartialEq for DerivedKeyCache {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}
impl Eq for DerivedKeyCache {}

// Never render cached secret-key material.
impl std::fmt::Debug for DerivedKeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DerivedKeyCache(..)")
    }
}

impl Zeroize for DerivedKeyCache {
    fn zeroize(&mut self) {
        // Drop this handle to the shared cache. If it is the last one, the slots
        // drop and each cached key wipes itself in place
        // (`UnifiedPrivateSigKey: ZeroizeOnDrop`); if other clones still share
        // the cache, the derived keys are wiped once the final clone drops. The
        // root secret itself is wiped in place regardless.
        *self = Self::default();
    }
}
