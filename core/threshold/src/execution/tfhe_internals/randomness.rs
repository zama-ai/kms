use crate::{
    algebra::{residue_poly::ResiduePoly, structure_traits::BaseRing},
    error::error_handler::anyhow_error_and_log,
};

use concrete_csprng::generators::ForkError;
use itertools::Itertools;
use tfhe::{
    core_crypto::commons::{
        math::random::RandomGenerator,
        parameters::{GlweSize, LweCiphertextCount, LweSize},
        traits::ByteRandomGenerator,
    },
    shortint::parameters::{DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize},
    Seed,
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
pub struct MPCEncryptionRandomGenerator<Z: BaseRing, Gen: ByteRandomGenerator> {
    //TODO: Once XOF available from TFHE-RS, need to use it here and use the correct DSEP !!
    pub mask: MPCMaskRandomGenerator<Gen>,
    pub noise: MPCNoiseRandomGenerator<Z>,
}

#[derive(Default)]
pub struct MPCNoiseRandomGenerator<Z: BaseRing> {
    pub vec: Vec<ResiduePoly<Z>>,
}

pub struct MPCMaskRandomGenerator<Gen: ByteRandomGenerator> {
    pub gen: RandomGenerator<Gen>,
}

impl<Z: BaseRing> MPCNoiseRandomGenerator<Z> {
    pub(crate) fn random_noise_custom_mod(&mut self) -> ResiduePoly<Z> {
        self.vec.pop().expect("Not enough noise in the RNG")
    }

    pub(crate) fn fork_bsk_to_ggsw(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let noise_elements = noise_elements_per_ggsw(level, glwe_size, polynomial_size);
        self.try_fork(lwe_dimension.0, noise_elements)
    }

    pub(crate) fn fork_lwe_list_to_lwe(
        &mut self,
        lwe_count: LweCiphertextCount,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let noise_elements = 1_usize;
        self.try_fork(lwe_count.0, noise_elements)
    }

    pub(crate) fn fork_ggsw_level_to_glwe(
        &mut self,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let noise_elements = noise_elements_per_glwe(polynomial_size);
        self.try_fork(glwe_size.0, noise_elements)
    }

    pub(crate) fn fork_ggsw_to_ggsw_levels(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let noise_elements = noise_elements_per_ggsw_level(glwe_size, polynomial_size);
        self.try_fork(level.0, noise_elements)
    }

    ///Note here that our noise_rng is really just a vector pre-loaded with shares of the noise
    ///so to fork we simply split the vector into chunks of correct size
    pub(crate) fn try_fork(
        &mut self,
        n_child: usize,
        size_child: usize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let noise_vec = self.vec.drain(0..n_child * size_child).collect_vec();

        let noise_iter = noise_vec
            .into_iter()
            .chunks(size_child)
            .into_iter()
            .map(|chunk| chunk.collect())
            .collect_vec();

        Ok(noise_iter.into_iter().map(|vec| Self { vec }))
    }
}

impl<Gen: ByteRandomGenerator> MPCMaskRandomGenerator<Gen> {
    pub fn new_from_seed(seed: u128) -> Self {
        Self {
            gen: RandomGenerator::<Gen>::new(Seed(seed)),
        }
    }
    pub fn fill_slice_with_random_mask_custom_mod<Z: BaseRing>(
        &mut self,
        output_mask: &mut [Z],
        randomness_type: EncryptionType,
    ) {
        let num_bytes_needed = match randomness_type {
            EncryptionType::Bits64 => 8,
            EncryptionType::Bits128 => 16,
        };

        for element in output_mask.iter_mut() {
            for _ in 0..num_bytes_needed {
                *element = (*element << 8) + (Z::from_u128(self.gen.generate_next() as u128));
            }
        }
    }

    pub(crate) fn fork_bsk_to_ggsw<Z: BaseRing>(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_bytes = mask_bytes_per_ggsw::<Z>(level, glwe_size, polynomial_size);
        self.try_fork(lwe_dimension.0, mask_bytes)
    }

    pub(crate) fn fork_lwe_list_to_lwe<Z: BaseRing>(
        &mut self,
        lwe_count: LweCiphertextCount,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_bytes = mask_bytes_per_lwe::<Z>(lwe_size.to_lwe_dimension());
        self.try_fork(lwe_count.0, mask_bytes)
    }

    pub(crate) fn fork_ggsw_level_to_glwe<Z: BaseRing>(
        &mut self,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_bytes = mask_bytes_per_glwe::<Z>(glwe_size.to_glwe_dimension(), polynomial_size);
        self.try_fork(glwe_size.0, mask_bytes)
    }

    pub(crate) fn fork_ggsw_to_ggsw_levels<Z: BaseRing>(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_bytes = mask_bytes_per_ggsw_level::<Z>(glwe_size, polynomial_size);
        self.try_fork(level.0, mask_bytes)
    }

    pub(crate) fn try_fork(
        &mut self,
        n_child: usize,
        mask_bytes: usize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        // We try to fork the generators
        let mask_iter = self.gen.try_fork(n_child, mask_bytes)?;
        // We return a proper iterator.
        Ok(mask_iter.map(|gen| Self { gen }))
    }
}

impl<Z: BaseRing, Gen: ByteRandomGenerator> MPCEncryptionRandomGenerator<Z, Gen> {
    pub(crate) fn new_from_seed(seed: u128) -> Self {
        Self {
            mask: MPCMaskRandomGenerator::<Gen>::new_from_seed(seed),
            noise: Default::default(),
        }
    }

    pub(crate) fn fill_noise(&mut self, fill_with: Vec<ResiduePoly<Z>>) {
        self.noise = MPCNoiseRandomGenerator { vec: fill_with };
    }

    pub(crate) fn random_noise_custom_mod(&mut self) -> ResiduePoly<Z> {
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
        output_body: &mut [ResiduePoly<Z>],
    ) -> anyhow::Result<()> {
        for elem in output_body.iter_mut() {
            *elem += self
                .noise
                .vec
                .pop()
                .ok_or_else(|| anyhow_error_and_log("Not enough noise in store"))?;
        }
        //There shouldnt be any noise left in there
        debug_assert_eq!(self.noise.vec.len(), 0);
        Ok(())
    }

    pub fn fork_bsk_to_ggsw(
        &mut self,
        lwe_dimension: LweDimension,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_iter =
            self.mask
                .fork_bsk_to_ggsw::<Z>(lwe_dimension, level, glwe_size, polynomial_size)?;
        let noise_iter =
            self.noise
                .fork_bsk_to_ggsw(lwe_dimension, level, glwe_size, polynomial_size)?;
        Ok(map_to_encryption_generator(mask_iter, noise_iter))
    }
    pub fn fork_lwe_list_to_lwe(
        &mut self,
        lwe_count: LweCiphertextCount,
        lwe_size: LweSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_iter = self.mask.fork_lwe_list_to_lwe::<Z>(lwe_count, lwe_size)?;
        let noise_iter = self.noise.fork_lwe_list_to_lwe(lwe_count)?;
        Ok(map_to_encryption_generator(mask_iter, noise_iter))
    }

    pub fn fork_ggsw_level_to_glwe(
        &mut self,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_iter = self
            .mask
            .fork_ggsw_level_to_glwe::<Z>(glwe_size, polynomial_size)?;

        let noise_iter = self
            .noise
            .fork_ggsw_level_to_glwe(glwe_size, polynomial_size)?;
        Ok(map_to_encryption_generator(mask_iter, noise_iter))
    }

    pub fn fork_ggsw_to_ggsw_levels(
        &mut self,
        level: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        let mask_iter =
            self.mask
                .fork_ggsw_to_ggsw_levels::<Z>(level, glwe_size, polynomial_size)?;

        let noise_iter = self
            .noise
            .fork_ggsw_to_ggsw_levels(level, glwe_size, polynomial_size)?;
        Ok(map_to_encryption_generator(mask_iter, noise_iter))
    }
}

/// Forks both generators into an iterator
fn map_to_encryption_generator<Z: BaseRing, Gen: ByteRandomGenerator>(
    mask_iter: impl Iterator<Item = MPCMaskRandomGenerator<Gen>>,
    noise_iter: impl Iterator<Item = MPCNoiseRandomGenerator<Z>>,
) -> impl Iterator<Item = MPCEncryptionRandomGenerator<Z, Gen>> {
    // We return a proper iterator.
    mask_iter
        .zip(noise_iter)
        .map(|(mask, noise)| MPCEncryptionRandomGenerator { mask, noise })
}

fn mask_bytes_per_ggsw<Z: BaseRing>(
    level: DecompositionLevelCount,
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
) -> usize {
    level.0 * mask_bytes_per_ggsw_level::<Z>(glwe_size, poly_size)
}

///How many bytes to fill the mask part of a ggsw row
fn mask_bytes_per_ggsw_level<Z: BaseRing>(glwe_size: GlweSize, poly_size: PolynomialSize) -> usize {
    glwe_size.0 * mask_bytes_per_glwe::<Z>(glwe_size.to_glwe_dimension(), poly_size)
}

///How many bytes to fill the mask part of an lwe encryption
fn mask_bytes_per_lwe<Z: BaseRing>(lwe_dimension: LweDimension) -> usize {
    lwe_dimension.0 * mask_bytes_per_coef::<Z>()
}

///How many bytes to fill the mask part of a glwe encryption
fn mask_bytes_per_glwe<Z: BaseRing>(
    glwe_dimension: GlweDimension,
    poly_size: PolynomialSize,
) -> usize {
    glwe_dimension.0 * mask_bytes_per_polynomial::<Z>(poly_size)
}

///How many bytes to fill a polynomial with coefs in Z
fn mask_bytes_per_polynomial<Z: BaseRing>(poly_size: PolynomialSize) -> usize {
    poly_size.0 * mask_bytes_per_coef::<Z>()
}

//WARNING: IDK yet if it's a big deal, but we may be asking more bytes from our XOF than we actually need
//as we ask enough bytes to fill up a full element from the ring even if we actually require less
//e.g. if the sharing domain is Z128 but we are generating the Z64 key material.

///How many bytes to fill an element in Z
fn mask_bytes_per_coef<Z: BaseRing>() -> usize {
    Z::BIT_LENGTH / 8
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
