use std::ops::DerefMut;

use itertools::{EitherOrBoth, Itertools};
use tfhe::{
    core_crypto::{
        commons::{
            parameters::GlweSize,
            traits::{ContiguousEntityContainerMut, UnsignedInteger},
        },
        entities::LweBootstrapKeyOwned,
    },
    shortint::parameters::{
        CoreCiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, LweDimension,
        PolynomialSize,
    },
};

use crate::{
    algebra::{
        galois_rings::common::ResiduePoly,
        structure_traits::{BaseRing, ErrorCorrect},
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        online::triple::open_list, runtime::session::BaseSessionHandles, sharing::share::Share,
    },
};

use super::{ggsw_ciphertext::GgswCiphertextShare, parameters::EncryptionType};

//Note: We assume all the ggsw ctxt in the list have same parameters
#[derive(Clone)]
pub struct LweBootstrapKeyShare<Z: BaseRing, const EXTENSION_DEGREE: usize> {
    pub ggsw_list: Vec<GgswCiphertextShare<Z, EXTENSION_DEGREE>>,
}

impl<Z: BaseRing, const EXTENSION_DEGREE: usize> LweBootstrapKeyShare<Z, EXTENSION_DEGREE> {
    pub fn new(
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_lwe_dimension: LweDimension,
        encryption_type: EncryptionType,
    ) -> Self {
        Self {
            ggsw_list: vec![
                GgswCiphertextShare::new(
                    glwe_size,
                    polynomial_size,
                    decomp_base_log,
                    decomp_level_count,
                    encryption_type
                );
                input_lwe_dimension.0
            ],
        }
    }

    //Returns the lwe dimension of the input lwe secret key
    //which is equal to the number of ggsw ciphertext
    pub fn input_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.ggsw_list.len())
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.ggsw_list[0].decomposition_level_count()
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.ggsw_list[0].glwe_size()
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.ggsw_list[0].polynomial_size()
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.ggsw_list[0].decomposition_base_log()
    }

    pub fn encryption_type(&self) -> EncryptionType {
        self.ggsw_list[0].data[0].data[0].encryption_type
    }
}

impl<Z: BaseRing, const EXTENSION_DEGREE: usize> LweBootstrapKeyShare<Z, EXTENSION_DEGREE>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    pub async fn open_to_tfhers_type<Scalar: UnsignedInteger, S: BaseSessionHandles>(
        self,
        session: &S,
    ) -> anyhow::Result<LweBootstrapKeyOwned<Scalar>> {
        let encryption_type = self.encryption_type();
        match encryption_type {
            EncryptionType::Bits64 => debug_assert_eq!(Scalar::BITS, 64),
            EncryptionType::Bits128 => debug_assert_eq!(Scalar::BITS, 128),
        }

        let glwe_size = self.glwe_size();
        let glwe_dimension = glwe_size.to_glwe_dimension();
        let polynomial_size = self.polynomial_size();
        let decomp_base_log = self.decomposition_base_log();
        let decomp_level_count = self.decomposition_level_count();
        let input_lwe_dimension = self.input_lwe_dimension();

        let my_role = session.my_role();

        let num_masks = self.ggsw_list.len()
            * self.glwe_size().0
            * self.decomposition_level_count().0
            * self.glwe_size().to_glwe_dimension().0
            * self.polynomial_size().0;

        let num_bodies = self.ggsw_list.len()
            * self.glwe_size().0
            * self.decomposition_level_count().0
            * self.polynomial_size().0;

        let (mut masks, mut shared_bodies): (Vec<Z>, Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>) = (
            Vec::with_capacity(num_masks),
            Vec::with_capacity(num_bodies),
        );

        self.ggsw_list.into_iter().for_each(|ggsw| {
            ggsw.data.into_iter().for_each(|ggsw_level_matrix| {
                ggsw_level_matrix.data.into_iter().for_each(|glwe_ctxt| {
                    glwe_ctxt.mask.into_iter().for_each(|mask| masks.push(mask));
                    glwe_ctxt
                        .body
                        .into_iter()
                        .for_each(|glwe_body| shared_bodies.push(Share::new(my_role, glwe_body)));
                })
            })
        });

        let bodies: Vec<Z> = open_list(&shared_bodies, session)
            .await?
            .iter()
            .map(|v| v.to_scalar())
            .try_collect()?;

        let mut bootstrap_key = LweBootstrapKeyOwned::new(
            Scalar::ZERO,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            CoreCiphertextModulus::new_native(),
        );

        let glwe_ctxt_list = bootstrap_key.deref_mut();

        let mut glwe_index = 0;
        for mut ggsw_ctxt in glwe_ctxt_list.iter_mut() {
            let mut glwe_ctxts = ggsw_ctxt.as_mut_glwe_list();
            for mut glwe_ctxt in glwe_ctxts.iter_mut() {
                let (mut mask, mut body) = glwe_ctxt.get_mut_mask_and_body();
                let underlying_container = mask.as_mut();
                let mask_start_idx = glwe_index * polynomial_size.0 * glwe_dimension.0;
                let mask_end_idx = mask_start_idx + (polynomial_size.0 * glwe_dimension.0);
                for c_m in underlying_container
                    .iter_mut()
                    .zip_longest(masks.get(mask_start_idx..mask_end_idx).ok_or_else(|| anyhow_error_and_log(format!("masks of incorrect size, can't take subslice with start_idx {mask_start_idx}, end_idx {mask_end_idx}")))?.iter())
                {
                    if let EitherOrBoth::Both(c,m) = c_m {
                    //to_byte_vec puts bytes of m in little endianness (i.e. lsb first)
                    let m_byte_vec = m.to_byte_vec();
                    let m = m_byte_vec
                        .into_iter()
                        //rev to put the msb first
                        .rev()
                        .fold(Scalar::ZERO, |acc, byte| {
                            acc.wrapping_shl(8)
                                .wrapping_add(Scalar::cast_from(byte as u128))
                        });
                    *c = m
                    } else {
                        return Err(anyhow_error_and_log("zip error"));
                    }
                }

                let underlying_container = body.as_mut();
                let body_start_idx = glwe_index * polynomial_size.0;
                let body_end_idx = body_start_idx + polynomial_size.0;
                for c_m in underlying_container
                    .iter_mut()
                    .zip_longest(bodies.get(body_start_idx..body_end_idx).ok_or_else(|| anyhow_error_and_log(format!("bodies of incorrect size, can't take a subslice with start_idx {body_start_idx} amd end_idx {body_end_idx}")))?.iter())
                {
                    if let EitherOrBoth::Both(c,m) = c_m {
                    let m_byte_vec = m.to_byte_vec();
                    let m = m_byte_vec
                        .into_iter()
                        .rev()
                        .fold(Scalar::ZERO, |acc, byte| {
                            acc.wrapping_shl(8)
                                .wrapping_add(Scalar::cast_from(byte as u128))
                        });
                    *c = m
                    } else {
                        return Err(anyhow_error_and_log("zip error"));
                    }
                }
                glwe_index += 1;
            }
        }

        Ok(bootstrap_key)
    }
}
