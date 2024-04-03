use aes_prng::AesRng;
use rand::SeedableRng;
use rand::{CryptoRng, Rng};
use tfhe::{
    core_crypto::prelude::{ActivatedRandomGenerator, SecretRandomGenerator},
    Seed,
};

/// Get a *secure* random number generator.
pub fn get_rng() -> impl Rng + CryptoRng {
    // TODO is this what we want, or do we want to use the 128 bits Seeder?
    AesRng::from_entropy()
}

/// Get a SecretRandomGenerator, for secret key generation based on a seed.
pub fn secret_rng_from_seed(seed: u128) -> SecretRandomGenerator<ActivatedRandomGenerator> {
    SecretRandomGenerator::<ActivatedRandomGenerator>::new(Seed(seed))
}

/// Sample a seed from a random number generator.
pub fn seed_from_rng<R: Rng + CryptoRng>(rng: &mut R) -> Seed {
    let mut seed: u128 = rng.next_u64() as u128;
    seed += (rng.next_u64() as u128) << 64;
    Seed(seed)
}

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;
    use rand::{RngCore, SeedableRng};
    use tfhe::{
        core_crypto::entities::{LweSecretKey, LweSecretKeyOwned},
        integer::parameters::LweDimension,
    };

    use crate::execution::random::{get_rng, secret_rng_from_seed, seed_from_rng};

    #[test]
    fn indeterminism_of_rng() {
        let mut rng1 = get_rng();
        let mut rng2 = get_rng();
        assert_ne!(rng1.next_u64(), rng2.next_u64());
    }

    #[test]
    fn determinism_of_seed() {
        let mut rng1 = secret_rng_from_seed(42);
        let mut rng2 = secret_rng_from_seed(42);
        // let mut buf1 = [0_u8; 32];
        // let mut buf2 = [1_u8; 32];
        let lwe_secret_key_1: LweSecretKeyOwned<u64> =
            LweSecretKey::generate_new_binary(LweDimension(700), &mut rng1);
        let lwe_secret_key_2: LweSecretKeyOwned<u64> =
            LweSecretKey::generate_new_binary(LweDimension(700), &mut rng2);
        assert_eq!(lwe_secret_key_1, lwe_secret_key_2);
    }

    #[test]
    fn seed_of_rng() {
        let mut rng = AesRng::seed_from_u64(42);
        let seed1 = seed_from_rng(&mut rng);
        let seed2 = seed_from_rng(&mut rng);
        // Check sufficient expected size
        assert!(seed1.0 > (1_u128 << 100));
        // Check randomness
        assert_ne!(seed1, seed2);
    }
}
