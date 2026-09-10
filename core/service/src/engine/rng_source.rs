//! Shared random seed source per KMS instance. Services clone its `Arc`; tasks own forked RNGs.
//!
//! Reseeding protects future forks after fresh entropy arrives. It does not refresh
//! existing children or provide backtracking resistance within a reseeding interval (i.e. one epoch).

use crate::cryptography::attestation::{SecurityModule, SecurityModuleProxy};
use aes_prng::AesRng;
use rand::{RngCore, SeedableRng};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

type Seed = <AesRng as SeedableRng>::Seed;

/// Identifies which entropy provider prevented source initialization or refresh.
#[derive(Debug, thiserror::Error)]
pub enum RngSourceError {
    #[error("OS entropy read failed: {0}")]
    Os(#[source] getrandom::Error),
    #[error("security module entropy read failed: {0}")]
    SecurityModule(#[source] anyhow::Error),
}

/// Supplies task seeds and accepts fresh entropy at protocol boundaries.
pub struct RngSource {
    rng: Mutex<AesRng>,
    // The vault and TLS code share ownership of this module.
    security_module: Option<Arc<SecurityModuleProxy>>,
}

impl RngSource {
    /// Seeds the source from the OS and the optional security module.
    pub fn new(security_module: Option<Arc<SecurityModuleProxy>>) -> Result<Self, RngSourceError> {
        let seed = Self::fresh_seed(security_module.as_deref())?;
        Ok(Self {
            rng: Mutex::new(AesRng::from_seed(*seed)),
            security_module,
        })
    }

    /// Wraps an existing RNG, including deterministic RNGs used by test fixtures.
    #[cfg(test)]
    pub(crate) fn from_rng(rng: AesRng) -> Self {
        Self {
            rng: Mutex::new(rng),
            security_module: None,
        }
    }

    /// Derives a separate AES key for a task without copying the parent state.
    pub(crate) fn fork_rng(&self) -> AesRng {
        let mut seed = Zeroizing::new(Seed::default());
        // Only infallible AES operations run under this lock; poisoning indicates an invariant bug.
        self.rng
            .lock()
            .expect("seed source mutex poisoned")
            .fill_bytes(seed.as_mut());
        AesRng::from_seed(*seed)
    }

    /// Mixes fresh entropy with parent output before replacing the parent.
    /// An entropy failure leaves the parent unchanged and returns an error.
    pub(crate) fn reseed(&self) -> Result<(), RngSourceError> {
        let result = Self::fresh_seed(self.security_module.as_deref())
            .map(|entropy| self.reseed_with(entropy));
        match &result {
            Ok(()) => tracing::info!(
                security_module = self.security_module.is_some(),
                "RNG source refreshed"
            ),
            Err(error) => tracing::warn!(
                %error,
                security_module = self.security_module.is_some(),
                "RNG source refresh failed"
            ),
        }
        result
    }

    fn fresh_seed(
        security_module: Option<&SecurityModuleProxy>,
    ) -> Result<Zeroizing<Seed>, RngSourceError> {
        let mut seed = Zeroizing::new(Seed::default());
        getrandom::fill(seed.as_mut()).map_err(RngSourceError::Os)?;
        if let Some(module) = security_module {
            let bytes: Zeroizing<Seed> = module
                .get_random_sync()
                .map_err(RngSourceError::SecurityModule)?;
            for (out, contribution) in seed.iter_mut().zip(bytes.iter()) {
                *out ^= contribution;
            }
        }
        Ok(seed)
    }

    // Tests can supply deterministic entropy without a global mock.
    fn reseed_with(&self, entropy: Zeroizing<Seed>) {
        let mut rng = self.rng.lock().expect("seed source mutex poisoned");
        let mut seed = Zeroizing::new(Seed::default());
        rng.fill_bytes(seed.as_mut());
        for (out, contribution) in seed.iter_mut().zip(entropy.iter()) {
            *out ^= contribution;
        }
        // Forking and replacement use the same lock, so each fork sees one complete state.
        *rng = AesRng::from_seed(*seed);
    }
}

/// Creates an independent OS-seeded source for service test fixtures.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn test_rng_source() -> Arc<RngSource> {
    Arc::new(RngSource::new(None).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draw(rng: &mut AesRng) -> Seed {
        let mut bytes = Seed::default();
        rng.fill_bytes(&mut bytes);
        bytes
    }

    #[test]
    fn forks_use_distinct_keys_and_advance_the_parent() {
        let source = RngSource::from_rng(AesRng::seed_from_u64(42));
        let mut expected_parent = AesRng::seed_from_u64(42);
        let mut expected_first = AesRng::from_seed(draw(&mut expected_parent));
        let mut expected_second = AesRng::from_seed(draw(&mut expected_parent));
        let first = draw(&mut source.fork_rng());
        let second = draw(&mut source.fork_rng());
        assert_eq!(first, draw(&mut expected_first));
        assert_eq!(second, draw(&mut expected_second));
        assert_ne!(first, second);
    }

    #[test]
    fn reseed_mixes_both_contributions_and_preserves_existing_children() {
        let source = Arc::new(RngSource::from_rng(AesRng::seed_from_u64(42)));
        let other_handle = Arc::clone(&source);
        let mut child = source.fork_rng();
        let mut child_before = child.clone();
        let mut expected_parent = AesRng::seed_from_u64(42);
        let _child_seed = draw(&mut expected_parent);
        let mut seed = draw(&mut expected_parent);
        for byte in &mut seed {
            *byte ^= 0xA5;
        }
        let mut expected_parent = AesRng::from_seed(seed);
        let mut expected_child = AesRng::from_seed(draw(&mut expected_parent));

        source.reseed_with(Zeroizing::new([0xA5; aes_prng::SEED_SIZE]));

        assert_eq!(
            draw(&mut other_handle.fork_rng()),
            draw(&mut expected_child)
        );
        assert_eq!(draw(&mut child), draw(&mut child_before));
    }

    #[test]
    fn independent_sources_do_not_share_refresh_state() {
        let first = RngSource::from_rng(AesRng::seed_from_u64(42));
        let second = RngSource::from_rng(AesRng::seed_from_u64(42));
        let untouched = RngSource::from_rng(AesRng::seed_from_u64(42));
        first.reseed_with(Zeroizing::new([1; aes_prng::SEED_SIZE]));
        assert_eq!(
            draw(&mut second.fork_rng()),
            draw(&mut untouched.fork_rng())
        );
    }

    #[test]
    fn os_entropy_initialization_and_refresh() {
        let source = RngSource::new(None).unwrap();
        let before = draw(&mut source.fork_rng());
        source.reseed().unwrap();
        assert_ne!(before, draw(&mut source.fork_rng()));
    }

    // Networking setup spawns a task even though the source operations are synchronous.
    #[tokio::test]
    async fn service_instances_and_session_maker_share_one_source() {
        use crate::cryptography::signatures::gen_sig_keys;
        use crate::engine::{base::BaseKmsStruct, threshold::service::session::SessionMaker};
        use kms_grpc::rpc_types::KMSType;
        use threshold_networking::grpc::{CoreToCoreNetworkConfig, GrpcNetworkingManager};
        use tokio::sync::RwLock;

        let (_, sk) = gen_sig_keys(&mut AesRng::seed_from_u64(7));
        let source = Arc::new(RngSource::from_rng(AesRng::seed_from_u64(42)));
        let base = BaseKmsStruct::new(KMSType::Threshold, sk, Arc::clone(&source));
        let sibling = base.new_instance();
        assert!(Arc::ptr_eq(&base.rng_source(), &sibling.rng_source()));
        let networking = Arc::new(RwLock::new(
            GrpcNetworkingManager::new(None, CoreToCoreNetworkConfig::default()).unwrap(),
        ));
        let sessions = SessionMaker::new_uninitialized(networking, None, base.rng_source());
        let mut before_refresh = AesRng::seed_from_u64(42);
        sessions.reseed_rng().unwrap();
        assert_ne!(
            draw(&mut source.rng.lock().unwrap()),
            draw(&mut before_refresh)
        );

        let mut expected_parent = source.rng.lock().unwrap().clone();
        let mut expected = AesRng::from_seed(draw(&mut expected_parent));
        assert_eq!(draw(&mut sibling.new_rng()), draw(&mut expected));
        let mut expected = AesRng::from_seed(draw(&mut expected_parent));
        assert_eq!(draw(&mut base.new_rng()), draw(&mut expected));
    }

    #[cfg(feature = "insecure")]
    #[test]
    fn mock_nitro_supplies_full_seeds_at_startup_and_refresh() {
        use crate::cryptography::attestation::make_security_module;

        let module = Arc::new(make_security_module(true).unwrap());
        let source = RngSource::new(Some(module)).unwrap();
        source.reseed().unwrap();
    }
}
