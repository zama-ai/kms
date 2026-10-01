//! Shared random seed source per KMS instance. Services clone its `Arc`; tasks
//! own forked RNGs.
//!
//! The source keeps two independent parents, because a fork can never carry
//! more entropy than the parent it is drawn from. [`RngSource::fork_rng_128`]
//! serves the general case from a 128-bit-seeded `AesRng`.
//! [`RngSource::fork_rng_256`] serves custodian backup from a 256-bit-seeded
//! `ChaCha20Rng`.
//!
//! Reseeding protects future forks after fresh entropy arrives. It does not
//! refresh existing children or provide backtracking resistance within a
//! reseeding interval (i.e. one epoch).

use crate::cryptography::attestation::{SecurityModule, SecurityModuleProxy};
use aes_prng::AesRng;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

type Seed128 = <AesRng as SeedableRng>::Seed;
type Seed256 = <ChaCha20Rng as SeedableRng>::Seed;

/// Identifies which entropy provider prevented source initialization or refresh.
#[derive(Debug, thiserror::Error)]
pub enum RngSourceError {
    #[error("OS entropy read failed: {0}")]
    Os(#[source] getrandom::Error),
    #[error("security module entropy read failed: {0}")]
    SecurityModule(#[source] anyhow::Error),
}

/// One RNG of each width that [`RngSource`] serves.
///
/// Carrying the pair together stops a caller from supplying one width and defaulting the other,
/// which would silently fix the seed of whichever RNG it forgot.
#[cfg(test)]
pub(crate) struct TaskRngs {
    rng_128: AesRng,
    rng_256: ChaCha20Rng,
}

#[cfg(test)]
impl TaskRngs {
    /// Pairs two independently chosen RNGs.
    pub(crate) fn new(rng_128: AesRng, rng_256: ChaCha20Rng) -> Self {
        Self { rng_128, rng_256 }
    }

    /// Derives both RNGs from one seed, for tests that want a reproducible pair.
    pub(crate) fn insecure_seed_from_u64(seed: u64) -> Self {
        Self::new(
            AesRng::seed_from_u64(seed),
            ChaCha20Rng::seed_from_u64(seed),
        )
    }
}

/// Shares one parent RNG per width across services and reseeds them on epoch changes.
pub struct RngSource {
    rng_128: Mutex<AesRng>,
    rng_256: Mutex<ChaCha20Rng>,
    security_module: Option<Arc<SecurityModuleProxy>>,
}

impl RngSource {
    /// Seeds both parents from the OS and the optional security module.
    ///
    /// The two draws are independent, so neither parent bounds the other.
    pub fn new(security_module: Option<Arc<SecurityModuleProxy>>) -> Result<Self, RngSourceError> {
        let seed_128: Zeroizing<Seed128> = Self::fresh_seed(security_module.as_deref())?;
        let seed_256: Zeroizing<Seed256> = Self::fresh_seed(security_module.as_deref())?;
        Ok(Self {
            rng_128: Mutex::new(AesRng::from_seed(*seed_128)),
            rng_256: Mutex::new(ChaCha20Rng::from_seed(*seed_256)),
            security_module,
        })
    }

    /// Uses supplied RNGs for deterministic tests.
    ///
    /// Both parents come from the caller: defaulting one here would hide which stream a test
    /// actually depends on.
    #[cfg(test)]
    pub(crate) fn from_rngs(rngs: TaskRngs) -> Self {
        Self {
            rng_128: Mutex::new(rngs.rng_128),
            rng_256: Mutex::new(rngs.rng_256),
            security_module: None,
        }
    }

    /// Returns one fork of each width, so a caller cannot take one and forget the other.
    #[cfg(test)]
    pub(crate) fn fork_all(&self) -> TaskRngs {
        TaskRngs::new(self.fork_rng_128(), self.fork_rng_256())
    }

    /// Returns a RNG seeded from the parent RNG's next output.
    ///
    /// This is implemented using AES-128 in counter mode.
    pub(crate) fn fork_rng_128(&self) -> AesRng {
        Self::fork(&self.rng_128)
    }

    /// Returns a 256-bit RNG seeded from the parent RNG's next output.
    ///
    /// This is implemented using chacha20.
    pub(crate) fn fork_rng_256(&self) -> ChaCha20Rng {
        Self::fork(&self.rng_256)
    }

    /// Reseeds both parents with their next output XORed with fresh OS and optional NSM entropy.
    /// An entropy failure leaves both parents unchanged and returns an error.
    pub(crate) fn reseed(&self) -> Result<(), RngSourceError> {
        // Draw both contributions before touching either parent, so an entropy failure leaves the
        // source entirely unchanged.
        let entropy_128: Zeroizing<Seed128> = Self::fresh_seed(self.security_module.as_deref())?;
        let entropy_256: Zeroizing<Seed256> = Self::fresh_seed(self.security_module.as_deref())?;
        Self::mix_into(&self.rng_128, &entropy_128);
        Self::mix_into(&self.rng_256, &entropy_256);
        Ok(())
    }

    /// Reseeds a parent from its own next output XORed with `entropy`.
    fn mix_into<R, const N: usize>(parent: &Mutex<R>, entropy: &[u8; N])
    where
        R: RngCore + SeedableRng<Seed = [u8; N]>,
    {
        // Only infallible RNG operations run under this lock; poisoning indicates an invariant bug.
        let mut parent = parent.lock().expect("seed source mutex poisoned");
        let mut seed = Zeroizing::new([0u8; N]);
        parent.fill_bytes(seed.as_mut());
        for (out, contribution) in seed.iter_mut().zip(entropy.iter()) {
            *out ^= contribution;
        }
        *parent = R::from_seed(*seed);
    }

    /// Seeds a child of the same kind from the parent's next output.
    fn fork<R, const N: usize>(parent: &Mutex<R>) -> R
    where
        R: RngCore + SeedableRng<Seed = [u8; N]>,
    {
        let mut seed = Zeroizing::new([0u8; N]);
        // Only infallible RNG operations run under this lock; poisoning indicates an invariant bug.
        parent
            .lock()
            .expect("seed source mutex poisoned")
            .fill_bytes(seed.as_mut());
        R::from_seed(*seed)
    }

    fn fresh_seed<const N: usize>(
        nsm: Option<&SecurityModuleProxy>,
    ) -> Result<Zeroizing<[u8; N]>, RngSourceError> {
        let mut seed = Zeroizing::new([0u8; N]);
        getrandom::fill(seed.as_mut()).map_err(RngSourceError::Os)?;
        if let Some(nsm_module) = nsm {
            let bytes: Zeroizing<[u8; N]> = nsm_module
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
    fn the_wide_parent_is_seeded_over_256_bits() {
        assert_eq!(std::mem::size_of::<Seed128>(), 16);
        assert_eq!(std::mem::size_of::<Seed256>(), 32);
    }

    #[test]
    fn forks_use_distinct_seeds_and_advance_the_parent() {
        let source = RngSource::from_rngs(TaskRngs::new(
            AesRng::seed_from_u64(42),
            ChaCha20Rng::seed_from_u64(43),
        ));
        let mut expected_parent = AesRng::seed_from_u64(42);
        let mut expected_first = AesRng::from_rng(&mut expected_parent).unwrap();
        let mut expected_second = AesRng::from_rng(&mut expected_parent).unwrap();
        let first = source.fork_rng_128().next_u64();
        let second = source.fork_rng_128().next_u64();
        assert_eq!(first, expected_first.next_u64());
        assert_eq!(second, expected_second.next_u64());
        assert_ne!(first, second);
    }

    #[test]
    fn wide_forks_use_distinct_seeds_and_advance_the_wide_parent() {
        let source = RngSource::from_rngs(TaskRngs::new(
            AesRng::seed_from_u64(42),
            ChaCha20Rng::seed_from_u64(43),
        ));
        let mut expected_parent = ChaCha20Rng::seed_from_u64(43);
        let mut expected_first = ChaCha20Rng::from_rng(&mut expected_parent).unwrap();
        let mut expected_second = ChaCha20Rng::from_rng(&mut expected_parent).unwrap();
        let first = source.fork_rng_256().next_u64();
        let second = source.fork_rng_256().next_u64();
        assert_eq!(first, expected_first.next_u64());
        assert_eq!(second, expected_second.next_u64());
        assert_ne!(first, second);
    }

    #[test]
    fn the_two_parents_do_not_disturb_each_other() {
        let source = RngSource::from_rngs(TaskRngs::new(
            AesRng::seed_from_u64(42),
            ChaCha20Rng::seed_from_u64(43),
        ));
        // Draw from the wide parent first; the narrow forks must be unaffected by it.
        let _ = source.fork_rng_256();
        let mut expected_parent = AesRng::seed_from_u64(42);
        let mut expected = AesRng::from_rng(&mut expected_parent).unwrap();
        assert_eq!(source.fork_rng_128().next_u64(), expected.next_u64());
    }

    #[test]
    fn reseed_changes_future_forks_and_preserves_existing_children() {
        let source = Arc::new(RngSource::from_rngs(TaskRngs::new(
            AesRng::seed_from_u64(42),
            ChaCha20Rng::seed_from_u64(43),
        )));
        let other_handle = Arc::clone(&source);
        let mut child = source.fork_rng_128();
        let mut child_before = child.clone();
        let untouched = RngSource::from_rngs(TaskRngs::new(
            source.rng_128.lock().unwrap().clone(),
            source.rng_256.lock().unwrap().clone(),
        ));

        source.reseed().unwrap();

        assert_ne!(
            other_handle.fork_rng_128().next_u64(),
            untouched.fork_rng_128().next_u64()
        );
        assert_eq!(child.next_u64(), child_before.next_u64());
    }

    #[test]
    fn reseed_changes_future_wide_forks() {
        let source = RngSource::from_rngs(TaskRngs::new(
            AesRng::seed_from_u64(42),
            ChaCha20Rng::seed_from_u64(43),
        ));
        let before = source.fork_rng_256().next_u64();
        source.reseed().unwrap();
        assert_ne!(before, source.fork_rng_256().next_u64());
    }

    #[test]
    fn independent_sources_do_not_share_refresh_state() {
        let first = RngSource::from_rngs(TaskRngs::new(
            AesRng::seed_from_u64(42),
            ChaCha20Rng::seed_from_u64(43),
        ));
        let second = RngSource::from_rngs(TaskRngs::new(
            AesRng::seed_from_u64(42),
            ChaCha20Rng::seed_from_u64(43),
        ));
        let untouched = RngSource::from_rngs(TaskRngs::new(
            AesRng::seed_from_u64(42),
            ChaCha20Rng::seed_from_u64(43),
        ));
        first.reseed().unwrap();
        assert_eq!(
            second.fork_rng_128().next_u64(),
            untouched.fork_rng_128().next_u64()
        );
    }

    #[test]
    fn os_entropy_initialization_and_refresh() {
        let source = RngSource::new(None).unwrap();
        let before = source.fork_rng_128().next_u64();
        let before_wide = source.fork_rng_256().next_u64();
        source.reseed().unwrap();
        assert_ne!(before, source.fork_rng_128().next_u64());
        assert_ne!(before_wide, source.fork_rng_256().next_u64());
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
        let source = Arc::new(RngSource::from_rngs(TaskRngs::new(
            AesRng::seed_from_u64(42),
            ChaCha20Rng::seed_from_u64(43),
        )));
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
            source.rng_128.lock().unwrap().next_u64(),
            before_refresh.next_u64()
        );

        let mut expected_parent = source.rng_128.lock().unwrap().clone();
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
