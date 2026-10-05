//! AES-128 counter-mode random number generator for the `rand` traits.
//!
//! [`AesRng`] takes its bytes from the [`tfhe_csprng`] generator. For a given seed, its output is
//! equal to the output of the `aes-prng` crate (version 0.2.1). The backward-compatibility test
//! vectors and the keys that derive from a fixed seed depend on that stream.

use rand::{CryptoRng, Error, RngCore, SeedableRng};
use tfhe_csprng::generators::aes_ctr::{AesCtrParams, BYTES_PER_BATCH};
use tfhe_csprng::generators::{DefaultRandomGenerator, RandomGenerator};
use tfhe_csprng::seeders::{Seed, SeedKind};

// TODO(#3255): use a 256-bit seed when `tfhe-csprng` has an audited AES-256 generator.
/// Size in bytes of the seed of [`AesRng`].
pub const SEED_SIZE: usize = 16;

/// Random number generator that runs AES-128 in counter mode through [`DefaultRandomGenerator`].
pub struct AesRng {
    generator: DefaultRandomGenerator,
    // The generator is not `Clone`: a clone starts a generator from this seed at the same index.
    seed: Seed,
    // Number of bytes drawn from the current batch of `BYTES_PER_BATCH` bytes.
    used_bytes: usize,
}

impl AesRng {
    fn next_byte(&mut self) -> u8 {
        // A generator that starts from a `Seed` stops after 2^132 bytes, which no caller reaches.
        self.generator
            .next_byte()
            .expect("AES-CTR generator reached its output bound")
    }

    /// Returns the next `N` bytes, all from one batch.
    ///
    /// `aes-prng` does not read an integer across two batches. It moves to the next batch when
    /// the current one has at most `N` bytes left, and drops those bytes.
    fn next_in_batch<const N: usize>(&mut self) -> [u8; N] {
        if self.used_bytes >= BYTES_PER_BATCH - N {
            for _ in self.used_bytes..BYTES_PER_BATCH {
                self.next_byte();
            }
            self.used_bytes = 0;
        }
        self.used_bytes += N;
        std::array::from_fn(|_| self.next_byte())
    }
}

impl SeedableRng for AesRng {
    type Seed = [u8; SEED_SIZE];

    fn from_seed(seed: Self::Seed) -> Self {
        // The generator takes the little-endian bytes of a `Seed` as the AES key.
        let seed = Seed(u128::from_le_bytes(seed));
        Self {
            generator: DefaultRandomGenerator::new(seed),
            seed,
            used_bytes: 0,
        }
    }
}

impl RngCore for AesRng {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(self.next_in_batch())
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(self.next_in_batch())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            *byte = self.next_byte();
        }
        self.used_bytes = (self.used_bytes + dest.len()) % BYTES_PER_BATCH;
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for AesRng {}

impl Clone for AesRng {
    fn clone(&self) -> Self {
        let first_index = self
            .generator
            .next_table_index()
            // See `next_byte`: the generator does not reach its bound.
            .expect("AES-CTR generator reached its output bound");
        Self {
            generator: DefaultRandomGenerator::new(AesCtrParams {
                seed: SeedKind::Ctr(self.seed),
                first_index,
            }),
            seed: self.seed,
            used_bytes: self.used_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; SEED_SIZE] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    /// The first `len` bytes of the stream of [`SEED`].
    fn stream(len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        AesRng::from_seed(SEED).fill_bytes(&mut bytes);
        bytes
    }

    /// All expected values come from `aes-prng` 0.2.1.
    #[test]
    fn stream_matches_aes_prng() {
        let bytes = stream(136);
        assert_eq!(
            bytes[..16],
            [
                0xc6, 0xa1, 0x3b, 0x37, 0x87, 0x8f, 0x5b, 0x82, 0x6f, 0x4f, 0x81, 0x62, 0xa1, 0xc8,
                0xd8, 0x79
            ]
        );
        assert_eq!(
            bytes[120..],
            [
                0xf4, 0x51, 0xbb, 0xcd, 0x99, 0x1a, 0x30, 0xec, 0xc7, 0x0f, 0xc6, 0x2b, 0xc9, 0xb0,
                0x45, 0x94
            ]
        );

        // The `u64` draw 16 and the `u32` draw 32 are the first ones after a dropped batch tail.
        let mut rng = AesRng::seed_from_u64(42);
        let draws: Vec<u64> = (0..20).map(|_| rng.next_u64()).collect();
        assert_eq!(
            [draws[0], draws[14], draws[15], draws[19]],
            [
                0xa1d935921a33135e,
                0x2a3054e4b3989e45,
                0xa2078a1ccc08f33b,
                0x23fdc68deabea18d
            ]
        );
        let mut rng = AesRng::seed_from_u64(42);
        let draws: Vec<u32> = (0..33).map(|_| rng.next_u32()).collect();
        assert_eq!(
            [draws[0], draws[30], draws[31], draws[32]],
            [0x1a33135e, 0x579f6874, 0xcc08f33b, 0xa2078a1c]
        );
    }

    #[test]
    fn integer_draw_skips_short_batch_tail() {
        let bytes = stream(2 * BYTES_PER_BATCH);
        // (bytes drawn first, stream offset of the next `u64`, stream offset of the next `u32`)
        for (drawn, u64_offset, u32_offset) in [
            (0, 0, 0),
            (119, 119, 119),
            (120, 128, 120),
            (123, 128, 123),
            (124, 128, 128),
            (127, 128, 128),
            (128, 128, 128),
            (129, 129, 129),
        ] {
            let mut rng = AesRng::from_seed(SEED);
            rng.fill_bytes(&mut vec![0; drawn]);
            assert_eq!(
                rng.clone().next_u64().to_le_bytes(),
                bytes[u64_offset..u64_offset + 8],
                "u64 after {drawn} bytes"
            );
            assert_eq!(
                rng.next_u32().to_le_bytes(),
                bytes[u32_offset..u32_offset + 4],
                "u32 after {drawn} bytes"
            );
        }
    }

    #[test]
    fn clone_continues_the_same_stream() {
        let mut rng = AesRng::from_seed(SEED);
        rng.fill_bytes(&mut [0; 5]);
        rng.next_u32();
        let mut clone = rng.clone();

        let (mut expected, mut actual) = ([0u8; 300], [0u8; 300]);
        rng.fill_bytes(&mut expected);
        clone.fill_bytes(&mut actual);
        assert_eq!(expected, actual);
        assert_eq!(rng.next_u64(), clone.next_u64());
    }

    #[test]
    fn from_entropy_gives_distinct_streams() {
        assert_ne!(
            AesRng::from_entropy().next_u64(),
            AesRng::from_entropy().next_u64()
        );
    }
}
