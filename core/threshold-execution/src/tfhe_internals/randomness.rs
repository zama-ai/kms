use algebra::{galois_rings::common::ResiduePoly, structure_traits::BaseRing};

use itertools::Itertools;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use tfhe::{
    core_crypto::commons::{
        math::random::{CompressionSeed, RandomGenerable, RandomGenerator, Uniform},
        parameters::{GlweSize, LweCiphertextCount, LweSize},
        traits::ParallelByteRandomGenerator,
    },
    shortint::parameters::{DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize},
};
use tfhe_csprng::{
    generators::{ForkError, aes_ctr::AesCtrParams},
    seeders::{SeedKind, XofSeed},
};

use super::parameters::EncryptionType;

//Question:
//For now there's a single noise vector which should be filled with the values we want
//however different parts of the protocol require different noise distribution
//should have separate vectors for each distribution or is it fine to assume
//that we correctly filled the vector such that whenever we pop some noise
//it's has been sampled from the correct distribution?

///Structure to get randomness needed inside encryptions
///the mask is from seeded rng, seed is derived from MPC protocol
///for now the noise part is put into a vector in advance and poped when needed
pub struct MPCEncryptionRandomGenerator<
    Z: BaseRing,
    Gen: ParallelByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
> {
    pub mask: MPCMaskRandomGenerator<Gen>,
    pub noise: MPCNoiseRandomGenerator<Z, EXTENSION_DEGREE>,
}

#[derive(Default)]
pub struct MPCNoiseRandomGenerator<Z: BaseRing, const EXTENSION_DEGREE: usize> {
    pub vec: Vec<ResiduePoly<Z, EXTENSION_DEGREE>>,
}

pub struct MPCMaskRandomGenerator<Gen: ParallelByteRandomGenerator> {
    pub generator: RandomGenerator<Gen>,
    seed: SeedKind,
}

impl<Z: BaseRing, const EXTENSION_DEGREE: usize> MPCNoiseRandomGenerator<Z, EXTENSION_DEGREE> {
    pub(crate) fn random_noise_custom_mod(&mut self) -> ResiduePoly<Z, EXTENSION_DEGREE> {
        self.vec.pop().expect("Not enough noise in the RNG")
    }

    pub(crate) fn fork_bsk_to_ggsw(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> impl IndexedParallelIterator<Item = Self> {
        let noise_elements = noise_elements_per_ggsw(level, glwe_size, polynomial_size);
        self.fork(lwe_dimension.0, noise_elements)
    }

    pub(crate) fn fork_lwe_list_to_lwe(
        &mut self,
        lwe_count: LweCiphertextCount,
    ) -> impl IndexedParallelIterator<Item = Self> {
        let noise_elements = 1_usize;
        self.fork(lwe_count.0, noise_elements)
    }

    pub(crate) fn fork_ggsw_level_to_glwe(
        &mut self,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> impl IndexedParallelIterator<Item = Self> {
        let noise_elements = noise_elements_per_glwe(polynomial_size);
        self.fork(glwe_size.0, noise_elements)
    }

    pub(crate) fn fork_ggsw_to_ggsw_levels(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> impl IndexedParallelIterator<Item = Self> {
        let noise_elements = noise_elements_per_ggsw_level(glwe_size, polynomial_size);
        self.fork(level.0, noise_elements)
    }

    ///Note here that our noise_rng is really just a vector pre-loaded with shares of the noise
    ///so to fork we simply split the vector into chunks of correct size.
    ///
    /// This panics if [`self`] contains less than n_child * size_child elements
    pub(crate) fn fork(
        &mut self,
        n_child: usize,
        size_child: usize,
    ) -> impl IndexedParallelIterator<Item = Self> {
        // This can panic if the vector is not large enough
        let noise_vec = self.vec.drain(0..n_child * size_child).collect_vec();

        let noise_iter = noise_vec
            .into_iter()
            .chunks(size_child)
            .into_iter()
            .map(|chunk| chunk.collect())
            .collect_vec();

        noise_iter.into_par_iter().map(|vec| Self { vec })
    }
}

impl<Gen: ParallelByteRandomGenerator> MPCMaskRandomGenerator<Gen> {
    pub fn new_from_seed(seed: XofSeed) -> Self {
        Self {
            generator: RandomGenerator::<Gen>::new(seed.clone()),
            seed: SeedKind::Xof(seed),
        }
    }

    /// Snapshot of the XOF generator state suitable for storing on a
    /// `SeededLwe*`/`SeededGlwe*` type — captures the underlying seed and the
    /// generator's current `TableIndex`, so that a decompressor can
    /// deterministically reproduce the mask bytes that will be sampled next.
    ///
    /// Mirrors `tfhe::core_crypto::commons::generators::MaskRandomGenerator::current_compression_seed`.
    pub fn current_compression_seed(&self) -> CompressionSeed {
        CompressionSeed {
            inner: AesCtrParams {
                seed: self.seed.clone(),
                first_index: self
                    .generator
                    .next_table_index()
                    .expect("MPC mask generator exhausted"),
            },
        }
    }

    pub fn fill_slice_with_random_mask_custom_mod<Z: BaseRing>(
        &mut self,
        output_mask: &mut [Z],
        randomness_type: EncryptionType,
    ) {
        for element in output_mask.iter_mut() {
            let randomness = match randomness_type {
                EncryptionType::Bits64 => u64::generate_one(&mut self.generator, Uniform) as u128,
                EncryptionType::Bits128 => u128::generate_one(&mut self.generator, Uniform),
            };
            *element = Z::from_u128(randomness);
        }
    }

    pub(crate) fn fork_bsk_to_ggsw(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        encryption_type: EncryptionType,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_bytes = mask_bytes_per_ggsw(level, glwe_size, polynomial_size, encryption_type);
        self.try_fork(lwe_dimension.0, mask_bytes)
    }

    pub(crate) fn fork_lwe_list_to_lwe(
        &mut self,
        lwe_count: LweCiphertextCount,
        lwe_size: LweSize,
        encryption_type: EncryptionType,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_bytes = mask_bytes_per_lwe(lwe_size.to_lwe_dimension(), encryption_type);
        self.try_fork(lwe_count.0, mask_bytes)
    }

    pub(crate) fn fork_ggsw_level_to_glwe(
        &mut self,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        encryption_type: EncryptionType,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_bytes = mask_bytes_per_glwe(
            glwe_size.to_glwe_dimension(),
            polynomial_size,
            encryption_type,
        );
        self.try_fork(glwe_size.0, mask_bytes)
    }

    pub(crate) fn fork_ggsw_to_ggsw_levels(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        encryption_type: EncryptionType,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_bytes = mask_bytes_per_ggsw_level(glwe_size, polynomial_size, encryption_type);
        self.try_fork(level.0, mask_bytes)
    }

    pub(crate) fn try_fork(
        &mut self,
        n_child: usize,
        mask_bytes: usize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let seed = self.seed.clone();
        let mask_iter = self.generator.par_try_fork(n_child, mask_bytes)?;
        // We return a proper iterator.
        Ok(mask_iter.map(move |generator| Self {
            generator,
            seed: seed.clone(),
        }))
    }
}

impl<Z: BaseRing, Gen: ParallelByteRandomGenerator, const EXTENSION_DEGREE: usize>
    MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>
{
    pub(crate) fn new_from_seed(seed: XofSeed) -> Self {
        Self {
            mask: MPCMaskRandomGenerator::<Gen>::new_from_seed(seed),
            noise: Default::default(),
        }
    }

    pub fn current_compression_seed(&self) -> CompressionSeed {
        self.mask.current_compression_seed()
    }

    pub(crate) fn fill_noise(&mut self, fill_with: Vec<ResiduePoly<Z, EXTENSION_DEGREE>>) {
        self.noise = MPCNoiseRandomGenerator { vec: fill_with };
    }

    pub(crate) fn random_noise_custom_mod(&mut self) -> ResiduePoly<Z, EXTENSION_DEGREE> {
        self.noise.random_noise_custom_mod()
    }

    ///Use the seeded rng to fill the masks
    pub fn fill_slice_with_random_mask_custom_mod(
        &mut self,
        output_mask: &mut [Z],
        randomness_type: EncryptionType,
    ) {
        self.mask
            .fill_slice_with_random_mask_custom_mod(output_mask, randomness_type);
    }

    ///Pop the noise to fill the noise part
    pub fn unsigned_torus_slice_wrapping_add_random_noise_custom_mod_assign(
        &mut self,
        output_body: &mut [ResiduePoly<Z, EXTENSION_DEGREE>],
    ) {
        let noise_iter = self.noise.vec.drain(0..output_body.len());
        // zip_eq can panic but we expect the noise vector to be of the same size as the output body
        // because we drain exactly the expected amount of noise
        for (elem, noise) in output_body.iter_mut().zip_eq(noise_iter) {
            *elem += noise
        }
    }

    // We allow the following lints because we are fine with mutating the rng
    // since we only care about the protocol state and reproducibility when it executes correctly.
    #[allow(unknown_lints)]
    #[allow(non_local_effect_before_error_return)]
    pub fn fork_bsk_to_ggsw(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        encryption_type: EncryptionType,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_iter = self.mask.fork_bsk_to_ggsw(
            lwe_dimension,
            level,
            glwe_size,
            polynomial_size,
            encryption_type,
        )?;
        let noise_iter =
            self.noise
                .fork_bsk_to_ggsw(lwe_dimension, level, glwe_size, polynomial_size);
        Ok(map_to_encryption_generator(mask_iter, noise_iter))
    }

    // We allow the following lints because we are fine with mutating the rng
    // since we only care about the protocol state and reproducibility when it executes correctly.
    #[allow(unknown_lints)]
    #[allow(non_local_effect_before_error_return)]
    pub fn fork_lwe_list_to_lwe(
        &mut self,
        lwe_count: LweCiphertextCount,
        lwe_size: LweSize,
        encryption_type: EncryptionType,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_iter = self
            .mask
            .fork_lwe_list_to_lwe(lwe_count, lwe_size, encryption_type)?;
        let noise_iter = self.noise.fork_lwe_list_to_lwe(lwe_count);
        Ok(map_to_encryption_generator(mask_iter, noise_iter))
    }

    // We allow the following lints because we are fine with mutating the rng
    // since we only care about the protocol state and reproducibility when it executes correctly.
    #[allow(unknown_lints)]
    #[allow(non_local_effect_before_error_return)]
    pub fn fork_ggsw_level_to_glwe(
        &mut self,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        encryption_type: EncryptionType,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_iter =
            self.mask
                .fork_ggsw_level_to_glwe(glwe_size, polynomial_size, encryption_type)?;

        let noise_iter = self
            .noise
            .fork_ggsw_level_to_glwe(glwe_size, polynomial_size);
        Ok(map_to_encryption_generator(mask_iter, noise_iter))
    }

    // We allow the following lints because we are fine with mutating the rng
    // since we only care about the protocol state and reproducibility when it executes correctly.
    #[allow(unknown_lints)]
    #[allow(non_local_effect_before_error_return)]
    pub fn fork_ggsw_to_ggsw_levels(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        encryption_type: EncryptionType,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        let mask_iter = self.mask.fork_ggsw_to_ggsw_levels(
            level,
            glwe_size,
            polynomial_size,
            encryption_type,
        )?;

        let noise_iter = self
            .noise
            .fork_ggsw_to_ggsw_levels(level, glwe_size, polynomial_size);
        Ok(map_to_encryption_generator(mask_iter, noise_iter))
    }
}

/// Forks both generators into an iterator
/// `mask_iter` and `noise_iter` MUST have the same length
fn map_to_encryption_generator<
    Z: BaseRing,
    Gen: ParallelByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    mask_iter: impl IndexedParallelIterator<Item = MPCMaskRandomGenerator<Gen>>,
    noise_iter: impl IndexedParallelIterator<Item = MPCNoiseRandomGenerator<Z, EXTENSION_DEGREE>>,
) -> impl IndexedParallelIterator<Item = MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>> {
    // `zip_eq` may panic but this only occurs if preconditions are not met, which would be a bug in this file
    mask_iter
        .zip_eq(noise_iter)
        .map(|(mask, noise)| MPCEncryptionRandomGenerator { mask, noise })
}

fn mask_bytes_per_ggsw(
    level: DecompositionLevelCount,
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
    encryption_type: EncryptionType,
) -> usize {
    level.0 * mask_bytes_per_ggsw_level(glwe_size, poly_size, encryption_type)
}

///How many bytes to fill the mask part of a ggsw row
fn mask_bytes_per_ggsw_level(
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
    encryption_type: EncryptionType,
) -> usize {
    glwe_size.0 * mask_bytes_per_glwe(glwe_size.to_glwe_dimension(), poly_size, encryption_type)
}

///How many bytes to fill the mask part of an lwe encryption
fn mask_bytes_per_lwe(lwe_dimension: LweDimension, encryption_type: EncryptionType) -> usize {
    lwe_dimension.0 * mask_bytes_per_coef(encryption_type)
}

///How many bytes to fill the mask part of a glwe encryption
fn mask_bytes_per_glwe(
    glwe_dimension: GlweDimension,
    poly_size: PolynomialSize,
    encryption_type: EncryptionType,
) -> usize {
    glwe_dimension.0 * mask_bytes_per_polynomial(poly_size, encryption_type)
}

///How many bytes to fill a polynomial with coefs in Z
fn mask_bytes_per_polynomial(poly_size: PolynomialSize, encryption_type: EncryptionType) -> usize {
    poly_size.0 * mask_bytes_per_coef(encryption_type)
}

///How many bytes to fill an element in Z
fn mask_bytes_per_coef(encryption_type: EncryptionType) -> usize {
    match encryption_type {
        EncryptionType::Bits64 => 8,
        EncryptionType::Bits128 => 16,
    }
}

fn noise_elements_per_ggsw(
    level: DecompositionLevelCount,
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
) -> usize {
    level.0 * noise_elements_per_ggsw_level(glwe_size, poly_size)
}

fn noise_elements_per_ggsw_level(glwe_size: GlweSize, poly_size: PolynomialSize) -> usize {
    glwe_size.0 * noise_elements_per_glwe(poly_size)
}

fn noise_elements_per_glwe(poly_size: PolynomialSize) -> usize {
    noise_elements_per_polynomial(poly_size)
}

fn noise_elements_per_polynomial(poly_size: PolynomialSize) -> usize {
    poly_size.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::base_ring::Z64;
    use tfhe::core_crypto::commons::math::random::RandomGenerator;
    use tfhe_csprng::{
        generators::{SoftwareRandomGenerator, aes_ctr::TableIndex},
        seeders::{SeedKind, XofSeed},
    };

    /// Regression test for the tfhe-rs 1.6 `TableIndex` bug. Proves that the
    /// `CompressionSeed` snapshot captured *after* the XOF mask generator has
    /// already advanced past the start can be fed into a fresh tfhe-rs
    /// `RandomGenerator` (the same one stock decompression builds internally
    /// from `SeededLwe*::compression_seed()`) and will reproduce the exact
    /// mask bytes our generator produces next.
    ///
    /// The assertions `SeedKind::Xof` + `first_index != TableIndex::FIRST`
    /// are what make this test *specifically* guard the bug: the old code
    /// stored `SeedKind::Ctr(seed)` with `first_index = FIRST` on every key,
    /// so it passed the round-trip only for the first key in the stream.
    #[test]
    fn current_compression_seed_reproduces_advanced_xof_state() {
        let xof_seed = XofSeed::new_u128(0xdead_beef_cafe_f00d, *b"TEST_SNP");
        let mut ours = MPCMaskRandomGenerator::<SoftwareRandomGenerator>::new_from_seed(xof_seed);

        // Consume some bytes so the generator's TableIndex is past the start —
        // this simulates having generated an earlier key with the same shared
        // XOF generator, which is the scenario the old code got wrong.
        let mut throwaway = vec![Z64::default(); 256];
        ours.fill_slice_with_random_mask_custom_mod(&mut throwaway, EncryptionType::Bits64);

        let cs = ours.current_compression_seed();

        // Guard #1: seed kind must be Xof (matching how the key was written).
        assert!(
            matches!(cs.inner.seed, SeedKind::Xof(_)),
            "compression seed must use Xof variant, not Ctr"
        );
        // Guard #2: the snapshot must actually be past the start; otherwise
        // this test wouldn't exercise the TableIndex bug.
        assert_ne!(
            cs.inner.first_index,
            TableIndex::FIRST,
            "snapshot must be past TableIndex::FIRST or the test isn't guarding the bug"
        );

        // Core invariant: a fresh tfhe-rs RandomGenerator built from the
        // snapshot — identical to what stock decompression does when it reads
        // `SeededLwe*::compression_seed()` — must agree byte-for-byte with our
        // advanced generator on the next output.
        let mut reference = RandomGenerator::<SoftwareRandomGenerator>::new(cs);
        for i in 0..1024 {
            let ours_byte = ours.generator.generate_next();
            let ref_byte = reference.generate_next();
            assert_eq!(
                ours_byte, ref_byte,
                "divergence at byte {i}: ours={ours_byte} ref={ref_byte}"
            );
        }
    }

    /// Sanity-check the other direction: a fresh generator, snapshotted
    /// immediately, must produce `first_index = TableIndex::FIRST` so the
    /// top-level public-key path (which takes its compression seed right after
    /// `new_from_seed`) lines up with `CompressedXofKeySet`'s `XofSeedStart`.
    #[test]
    fn current_compression_seed_is_first_on_fresh_generator() {
        let xof_seed = XofSeed::new_u128(1, *b"TEST_SNP");
        let ours = MPCMaskRandomGenerator::<SoftwareRandomGenerator>::new_from_seed(xof_seed);
        let cs = ours.current_compression_seed();

        assert!(matches!(cs.inner.seed, SeedKind::Xof(_)));
        assert_eq!(cs.inner.first_index, TableIndex::FIRST);
    }
}
