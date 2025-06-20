use std::slice::IterMut;

use itertools::Itertools;
use tfhe::{
    boolean::prelude::{
        DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    },
    core_crypto::prelude::{
        CiphertextModulus, ContiguousEntityContainerMut, GlweSize, LwePackingKeyswitchKeyOwned,
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

use super::{glwe_ciphertext::GlweCiphertextShare, parameters::EncryptionType};

// Data structure to hold the shares of the Packing KS
// used for compression.
// The underlying data is a a vector of vectors of GlweCiphertextShare
// where for each input key bit we GLev encrypt it
pub struct LwePackingKeyswitchKeyShares<Z: BaseRing, const EXTENSION_DEGREE: usize> {
    data: Vec<Vec<GlweCiphertextShare<Z, EXTENSION_DEGREE>>>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
}

impl<Z: BaseRing, const EXTENSION_DEGREE: usize> LwePackingKeyswitchKeyShares<Z, EXTENSION_DEGREE> {
    pub fn output_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    pub fn iter_mut_levels(&mut self) -> IterMut<Vec<GlweCiphertextShare<Z, EXTENSION_DEGREE>>> {
        self.data.iter_mut()
    }

    pub fn new(
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_key_glwe_dimension: GlweDimension,
        output_key_polynomial_size: PolynomialSize,
    ) -> Self {
        Self {
            data: vec![
                vec![
                    GlweCiphertextShare::new(
                        output_key_polynomial_size,
                        output_key_glwe_dimension.0,
                        EncryptionType::Bits64
                    );
                    decomp_level_count.0
                ];
                input_key_lwe_dimension.0
            ],
            decomp_base_log,
            decomp_level_count,
            output_glwe_size: output_key_glwe_dimension.to_glwe_size(),
            output_polynomial_size: output_key_polynomial_size,
        }
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }
}

impl<Z: BaseRing, const EXTENSION_DEGREE: usize> LwePackingKeyswitchKeyShares<Z, EXTENSION_DEGREE>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    pub async fn open_to_tfhers_type<S: BaseSessionHandles>(
        self,
        session: &S,
    ) -> anyhow::Result<LwePackingKeyswitchKeyOwned<u64>> {
        let my_role = session.my_role();
        let input_key_lwe_dimension = LweDimension(self.data.len());
        let output_key_glwe_dimension = self.output_glwe_size.to_glwe_dimension();
        let output_key_polynomial_size = self.output_polynomial_size();

        let shared_bodies: Vec<_> = self
            .data
            .iter()
            .flat_map(|v1| {
                v1.iter()
                    .flat_map(|v2| v2.body.iter().map(|value| Share::new(my_role, *value)))
            })
            .collect();

        let bodies: Vec<Z> = open_list(&shared_bodies, session)
            .await?
            .iter()
            .map(|v| v.to_scalar())
            .try_collect()?;

        let masks: Vec<_> = self
            .data
            .into_iter()
            .flat_map(|v1| v1.into_iter().flat_map(|v2| v2.mask))
            .collect();

        let mut ksk = LwePackingKeyswitchKeyOwned::new(
            0_u64,
            self.decomp_base_log,
            self.decomp_level_count,
            input_key_lwe_dimension,
            output_key_glwe_dimension,
            output_key_polynomial_size,
            CiphertextModulus::new_native(),
        );

        let mut glwe_ciphertext_list = ksk.as_mut_glwe_ciphertext_list();
        let mut masks_iterator = masks.into_iter();
        let mut bodies_iterator = bodies.into_iter();

        for mut glwe_ciphertext in glwe_ciphertext_list.iter_mut() {
            let (mut mask, mut body) = glwe_ciphertext.get_mut_mask_and_body();

            let underlying_container = mask.as_mut();
            for c_m in underlying_container.iter_mut() {
                if let Some(m) = masks_iterator.next() {
                    let m_byte_vec = m.to_byte_vec();
                    let m = m_byte_vec.iter().rev().fold(0_u64, |acc, byte| {
                        acc.wrapping_shl(8).wrapping_add(*byte as u64)
                    });
                    *c_m = m;
                } else {
                    return Err(anyhow_error_and_log(
                        "Not enough masks to cast the compression key to tfhe-rs type",
                    ));
                }
            }

            let underlying_container = body.as_mut();
            for c_b in underlying_container.iter_mut() {
                let body_data = {
                    let tmp = if let Some(body) = bodies_iterator.next() {
                        body.to_byte_vec()
                    } else {
                        return Err(anyhow_error_and_log(
                            "Not enough bodies to cast the compression key to tfhe-rs type",
                        ));
                    };
                    // Below we perform recomposition to convert Vec<u8> to u64
                    tmp.iter().rev().fold(0_u64, |acc, byte| {
                        acc.wrapping_shl(8).wrapping_add(*byte as u64)
                    })
                };
                *(c_b) = body_data;
            }
        }

        Ok(ksk)
    }
}
