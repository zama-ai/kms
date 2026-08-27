use aes_prng::AesRng;
use rand::{RngCore, SeedableRng};
use std::sync::{Arc, OnceLock, Weak};
use tokio::sync::Mutex;

use crate::cryptography::attestation::{SecurityModule, SecurityModuleProxy};

static RNG_REGISTRY: OnceLock<RngRegistry> = OnceLock::new();

type RngRegistryEntry = (Option<Weak<SecurityModuleProxy>>, Weak<Mutex<AesRng>>);
pub(crate) struct RngRegistry(Mutex<Vec<RngRegistryEntry>>);

impl RngRegistry {
    fn empty() -> Self {
        Self(Mutex::new(Vec::new()))
    }

    /// The process-wide registry backing the public entry points
    /// [`Self::fresh_registered_rng`] and [`Self::refresh_all_rngs_in_registry`].
    fn global() -> &'static Self {
        RNG_REGISTRY.get_or_init(Self::empty)
    }

    /// This function panics if the OS entropy pool is not available or if the security module exists but fails to provide randomness.
    async fn fresh_seed(
        security_module: Option<Arc<SecurityModuleProxy>>,
    ) -> [u8; crate::consts::RND_SIZE] {
        // Pulls randomness from OS entropy pool.
        let mut seed = [0u8; crate::consts::RND_SIZE];
        if let Err(err) = getrandom::fill(seed.as_mut()) {
            panic!("getrandom failed: {}", err);
        }

        // Pulls randomness from the security module if available.
        if let Some(security_module) = security_module {
            match security_module.get_random(crate::consts::RND_SIZE).await {
                Ok(bytes) => {
                    if bytes.len() != crate::consts::RND_SIZE {
                        panic!(
                            "Security module returned {} bytes, expected {}",
                            bytes.len(),
                            crate::consts::RND_SIZE
                        );
                    }
                    // Mix in the randomness from the security module into the OS seed
                    for i in 0..crate::consts::RND_SIZE {
                        // Direct indexing as we just checked the size is correct
                        seed[i] ^= bytes[i];
                    }
                }
                Err(e) => {
                    panic!("Failed to get random bytes from security module: {}", e);
                }
            }
        };

        seed
    }

    /// Creates a new RNG seeded with randomness from the OS, the base RNG, and optionally a security module.
    /// Optionally takes an existing RNG to pull randomness from, which is used to ensure that the new RNG is not seeded with weak randomness.
    async fn fresh_rng(
        existing_rng: Option<Arc<Mutex<AesRng>>>,
        security_module: Option<Arc<SecurityModuleProxy>>,
    ) -> AesRng {
        let fresh_seed = Self::fresh_seed(security_module).await;

        let mut seed = [0u8; crate::consts::RND_SIZE];
        // Make a seperate scope for the rng so that it is dropped before the lock is released
        if let Some(existing_rng) = existing_rng {
            let mut existing_rng = existing_rng.lock().await;
            existing_rng.fill_bytes(seed.as_mut());
        }

        // Mix in all the randomness sources to create a new seed
        for i in 0..crate::consts::RND_SIZE {
            seed[i] ^= fresh_seed[i];
        }

        AesRng::from_seed(seed)
    }

    /// Create a freshly-seeded RNG and register it in *this* registry.
    async fn register_fresh_rng(
        &self,
        existing_rng: Option<Arc<Mutex<AesRng>>>,
        security_module: Option<Arc<SecurityModuleProxy>>,
    ) -> Arc<Mutex<AesRng>> {
        let rng = Self::fresh_rng(existing_rng, security_module.clone()).await;
        let rng = Arc::new(Mutex::new(rng));
        let mut registry = self.0.lock().await;
        registry.push((
            security_module.as_ref().map(Arc::downgrade),
            Arc::downgrade(&rng),
        ));
        rng
    }

    /// Reseed every live RNG in *this* registry in place, first pruning entries
    /// whose RNG has been dropped. Each RNG is reseeded from its own (per-entry)
    /// security module, falling back to OS-only entropy if that module is gone.
    async fn refresh_all(&self) {
        let mut registry = self.0.lock().await;
        registry.retain(|entry| entry.1.upgrade().is_some());
        for (weak_security_module, weak_rng) in registry.iter() {
            if let Some(rng) = weak_rng.upgrade() {
                let security_module = weak_security_module
                    .as_ref()
                    .and_then(|weak| weak.upgrade());
                let fresh_rng = Self::fresh_rng(Some(Arc::clone(&rng)), security_module).await;
                let mut rng_lock = rng.lock().await;
                *rng_lock = fresh_rng;
            }
        }
    }

    #[cfg(test)]
    async fn entry_count(&self) -> usize {
        self.0.lock().await.len()
    }

    /// Create a freshly-seeded RNG registered in the process-wide registry.
    pub(crate) async fn fresh_registered_rng(
        existing_rng: Option<Arc<Mutex<AesRng>>>,
        security_module: Option<Arc<SecurityModuleProxy>>,
    ) -> Arc<Mutex<AesRng>> {
        Self::global()
            .register_fresh_rng(existing_rng, security_module)
            .await
    }

    /// Reseed every live RNG in the process-wide registry (e.g. on epoch init).
    pub(crate) async fn refresh_all_rngs_in_registry() {
        Self::global().refresh_all().await
    }
}

#[cfg(test)]
mod tests {
    use super::RngRegistry;
    use aes_prng::AesRng;
    use rand::{RngCore, SeedableRng};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// Draw 16 bytes from an RNG handle, advancing its state.
    async fn draw(rng: &Arc<Mutex<AesRng>>) -> [u8; 16] {
        let mut out = [0u8; 16];
        let mut guard = rng.lock().await;
        guard.fill_bytes(&mut out);
        out
    }

    /// Pin an RNG handle to a deterministic seed so its output is reproducible.
    async fn set_seed(rng: &Arc<Mutex<AesRng>>, seed: u64) {
        let mut guard = rng.lock().await;
        *guard = AesRng::seed_from_u64(seed);
    }

    #[tokio::test]
    async fn fresh_seed_draws_fresh_os_entropy() {
        let a = RngRegistry::fresh_seed(None).await;
        let b = RngRegistry::fresh_seed(None).await;
        assert_ne!(a, b, "OS entropy must differ between calls");
        assert_ne!(
            a,
            [0u8; crate::consts::RND_SIZE],
            "a fresh seed must not be all zeros"
        );
    }

    #[tokio::test]
    async fn fresh_rng_always_injects_new_entropy() {
        // No predecessor RNG: seeded purely from OS entropy, so two calls diverge.
        let mut r1 = RngRegistry::fresh_rng(None, None).await;
        let mut r2 = RngRegistry::fresh_rng(None, None).await;
        let (mut a, mut b) = ([0u8; 16], [0u8; 16]);
        r1.fill_bytes(&mut a);
        r2.fill_bytes(&mut b);
        assert_ne!(a, b, "fresh_rng(None) must be OS-seeded and never repeat");

        // Even from an *identical* predecessor state, fresh_rng mixes in fresh OS
        // entropy, so the output is not a deterministic function of the predecessor.
        let existing = Arc::new(Mutex::new(AesRng::seed_from_u64(1234)));
        let mut r3 = RngRegistry::fresh_rng(Some(Arc::clone(&existing)), None).await;
        set_seed(&existing, 1234).await; // rewind predecessor to the same state
        let mut r4 = RngRegistry::fresh_rng(Some(Arc::clone(&existing)), None).await;
        let (mut c, mut d) = ([0u8; 16], [0u8; 16]);
        r3.fill_bytes(&mut c);
        r4.fill_bytes(&mut d);
        assert_ne!(
            c, d,
            "identical predecessor state must still yield fresh entropy"
        );
    }

    #[tokio::test]
    async fn register_fresh_rng_adds_one_entry_each() {
        let registry = RngRegistry::empty();
        assert_eq!(registry.entry_count().await, 0);

        let _r1 = registry.register_fresh_rng(None, None).await;
        assert_eq!(registry.entry_count().await, 1);

        let _r2 = registry.register_fresh_rng(None, None).await;
        assert_eq!(registry.entry_count().await, 2);
    }

    #[tokio::test]
    async fn refresh_all_reseeds_in_place_keeping_the_same_allocation() {
        let registry = RngRegistry::empty();
        let rng = registry.register_fresh_rng(None, None).await;

        set_seed(&rng, 777).await;
        let before = draw(&rng).await;
        set_seed(&rng, 777).await; // restore the known state for the refresh
        let ptr_before = Arc::as_ptr(&rng);

        registry.refresh_all().await;

        assert_ne!(draw(&rng).await, before, "refresh must reseed the RNG");
        // The refresh must mutate the RNG behind the *same* allocation, so the
        // registry's Weak keeps pointing at the refreshed RNG rather than a stale one.
        assert_eq!(
            Arc::as_ptr(&rng),
            ptr_before,
            "refresh must reseed in place, not replace the allocation"
        );
    }

    #[tokio::test]
    async fn refresh_all_reseeds_every_registered_rng() {
        let registry = RngRegistry::empty();
        let rngs = [
            registry.register_fresh_rng(None, None).await,
            registry.register_fresh_rng(None, None).await,
            registry.register_fresh_rng(None, None).await,
        ];
        let seeds = [10u64, 20, 30];

        let mut before = Vec::new();
        for (rng, s) in rngs.iter().zip(seeds) {
            set_seed(rng, s).await;
            before.push(draw(rng).await);
            set_seed(rng, s).await; // restore for the refresh
        }

        registry.refresh_all().await;

        for (idx, rng) in rngs.iter().enumerate() {
            assert_ne!(draw(rng).await, before[idx], "rng {idx} was not reseeded");
        }
    }

    #[tokio::test]
    async fn refresh_all_prunes_entries_for_dropped_rngs() {
        let registry = RngRegistry::empty();
        let keep1 = registry.register_fresh_rng(None, None).await;
        let drop_me = registry.register_fresh_rng(None, None).await;
        let keep2 = registry.register_fresh_rng(None, None).await;
        assert_eq!(registry.entry_count().await, 3);

        // Dropping the only strong ref leaves a dangling Weak in the registry...
        drop(drop_me);
        assert_eq!(
            registry.entry_count().await,
            3,
            "a dead Weak is retained until the next refresh"
        );

        // ...which refresh_all prunes.
        registry.refresh_all().await;
        assert_eq!(
            registry.entry_count().await,
            2,
            "refresh_all must prune the dropped RNG's entry"
        );

        // The survivors are still usable.
        let _ = draw(&keep1).await;
        let _ = draw(&keep2).await;
    }
}
