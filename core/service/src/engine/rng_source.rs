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

/// Shares one parent RNG across services and reseeds it on epoch changes.
pub struct RngSource {
    rng: Mutex<AesRng>,
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

    /// Uses a supplied RNG for deterministic tests.
    #[cfg(test)]
    pub(crate) fn from_rng(rng: AesRng) -> Self {
        Self {
            rng: Mutex::new(rng),
            security_module: None,
        }
    }

    /// Returns a task RNG seeded from the parent RNG's next output.
    pub(crate) fn fork_rng(&self) -> AesRng {
        let mut seed = Zeroizing::new(Seed::default());
        // Only infallible AES operations run under this lock; poisoning indicates an invariant bug.
        self.rng
            .lock()
            .expect("seed source mutex poisoned")
            .fill_bytes(seed.as_mut());
        AesRng::from_seed(*seed)
    }

    /// Reseeds the parent with its next output XORed with fresh OS and optional NSM entropy.
    /// An entropy failure leaves the parent unchanged and returns an error.
    pub(crate) fn reseed(&self) -> Result<(), RngSourceError> {
        let entropy = Self::fresh_seed(self.security_module.as_deref())?;
        let mut rng = self.rng.lock().expect("seed source mutex poisoned");
        let mut seed = Zeroizing::new(Seed::default());
        rng.fill_bytes(seed.as_mut());
        for (out, contribution) in seed.iter_mut().zip(entropy.iter()) {
            *out ^= contribution;
        }
        *rng = AesRng::from_seed(*seed);
        Ok(())
    }

    fn fresh_seed(nsm: Option<&SecurityModuleProxy>) -> Result<Zeroizing<Seed>, RngSourceError> {
        let mut seed = Zeroizing::new(Seed::default());
        getrandom::fill(seed.as_mut()).map_err(RngSourceError::Os)?;
        if let Some(nsm_module) = nsm {
            let bytes: Zeroizing<Seed> = nsm_module
                .get_random_sync()
                .map_err(RngSourceError::SecurityModule)?;
            for (out, contribution) in seed.iter_mut().zip(bytes.iter()) {
                *out ^= contribution;
            }
        }
        Ok(seed)
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

    #[test]
    fn forks_use_distinct_seeds_and_advance_the_parent() {
        let source = RngSource::from_rng(AesRng::seed_from_u64(42));
        let mut expected_parent = AesRng::seed_from_u64(42);
        let mut expected_first = AesRng::from_rng(&mut expected_parent).unwrap();
        let mut expected_second = AesRng::from_rng(&mut expected_parent).unwrap();
        let first = source.fork_rng().next_u64();
        let second = source.fork_rng().next_u64();
        assert_eq!(first, expected_first.next_u64());
        assert_eq!(second, expected_second.next_u64());
        assert_ne!(first, second);
    }

    #[test]
    fn reseed_changes_future_forks_and_preserves_existing_children() {
        let source = Arc::new(RngSource::from_rng(AesRng::seed_from_u64(42)));
        let other_handle = Arc::clone(&source);
        let mut child = source.fork_rng();
        let mut child_before = child.clone();
        let untouched = RngSource::from_rng(source.rng.lock().unwrap().clone());

        source.reseed().unwrap();

        assert_ne!(
            other_handle.fork_rng().next_u64(),
            untouched.fork_rng().next_u64()
        );
        assert_eq!(child.next_u64(), child_before.next_u64());
    }

    #[test]
    fn independent_sources_do_not_share_refresh_state() {
        let first = RngSource::from_rng(AesRng::seed_from_u64(42));
        let second = RngSource::from_rng(AesRng::seed_from_u64(42));
        let untouched = RngSource::from_rng(AesRng::seed_from_u64(42));
        first.reseed().unwrap();
        assert_eq!(
            second.fork_rng().next_u64(),
            untouched.fork_rng().next_u64()
        );
    }

    #[test]
    fn os_entropy_initialization_and_refresh() {
        let source = RngSource::new(None).unwrap();
        let before = source.fork_rng().next_u64();
        source.reseed().unwrap();
        assert_ne!(before, source.fork_rng().next_u64());
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
            source.rng.lock().unwrap().next_u64(),
            before_refresh.next_u64()
        );

        let mut expected_parent = source.rng.lock().unwrap().clone();
        let mut expected = AesRng::from_rng(&mut expected_parent).unwrap();
        assert_eq!(sibling.new_rng().next_u64(), expected.next_u64());
        let mut expected = AesRng::from_rng(&mut expected_parent).unwrap();
        assert_eq!(base.new_rng().next_u64(), expected.next_u64());
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
