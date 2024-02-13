use aes_prng::AesRng;
use rand::SeedableRng;
use rand_core::CryptoRngCore;
use tfhe::{
    core_crypto::prelude::{ActivatedRandomGenerator, SecretRandomGenerator},
    Seed,
};

/// Get a *secure* random number generator.
pub fn get_rng() -> impl CryptoRngCore {
    // TODO is this what we want, or do we want to use the 128 bits Seeder?
    AesRng::from_entropy()
}

/// Get a SecretRandomGenerator, for secret key generation based on a seed.
pub fn secret_rng_from_seed(seed: u128) -> SecretRandomGenerator<ActivatedRandomGenerator> {
    SecretRandomGenerator::<ActivatedRandomGenerator>::new(Seed(seed))
}

/// Sample a seed from a random number generator.
pub fn seed_from_rng<R: CryptoRngCore>(rng: &mut R) -> Seed {
    let mut seed: u128 = rng.next_u64() as u128;
    seed += (rng.next_u64() as u128) << 64;
    Seed(seed)
}
