use itertools::Itertools;
use rand::{CryptoRng, Rng};
use tfhe::{
    core_crypto::{commons::parameters::LweSize, entities::LweKeyswitchKeyOwned},
    shortint::{
        parameters::{DecompositionBaseLog, DecompositionLevelCount, LweDimension},
        CiphertextModulus,
    },
};

use crate::{
    algebra::structure_traits::{BaseRing, ErrorCorrect},
    execution::{
        online::triple::open_list, runtime::session::BaseSessionHandles, sharing::share::Share,
    },
};

use super::lwe_ciphertext::{opened_lwe_masks_bodies_to_tfhers_u64, LweCiphertextShare};
use crate::algebra::galois_rings::common::ResiduePoly;

#[derive(Clone)]
pub struct LweKeySwitchKeyShare<Z: BaseRing, const EXTENSION_DEGREE: usize> {
    //data is a matrix of LweCiphertextShare where each line
    //corresponds to an input_key element and columns are the levels
    pub data: Vec<Vec<LweCiphertextShare<Z, EXTENSION_DEGREE>>>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_lwe_size: LweSize,
}

impl<Z: BaseRing, const EXTENSION_DEGREE: usize> LweKeySwitchKeyShare<Z, EXTENSION_DEGREE> {
    pub fn iter_mut_levels(
        &mut self,
    ) -> impl Iterator<Item = &mut Vec<LweCiphertextShare<Z, EXTENSION_DEGREE>>> {
        self.data.iter_mut()
    }

    pub fn new(
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_key_lwe_dimension: LweDimension,
    ) -> Self {
        Self {
            data: vec![
                vec![
                    LweCiphertextShare::new(output_key_lwe_dimension.to_lwe_size());
                    decomp_level_count.0
                ];
                input_key_lwe_dimension.0
            ],
            decomp_base_log,
            decomp_level_count,
            output_lwe_size: output_key_lwe_dimension.to_lwe_size(),
        }
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }
}

impl<Z: BaseRing, const EXTENSION_DEGREE: usize> LweKeySwitchKeyShare<Z, EXTENSION_DEGREE>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    pub async fn open_to_tfhers_type<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        self,
        session: &S,
    ) -> anyhow::Result<LweKeyswitchKeyOwned<u64>> {
        let my_role = session.my_role()?;
        let input_key_lwe_dimension = LweDimension(self.data.len());

        let shared_bodies: Vec<_> = self
            .data
            .iter()
            .flat_map(|v1| v1.iter().map(|v2| Share::new(my_role, v2.body)))
            .collect();
        let bodies: Vec<Z> = open_list(&shared_bodies, session)
            .await?
            .iter()
            .map(|v| v.to_scalar())
            .try_collect()?;

        let masks: Vec<_> = self
            .data
            .into_iter()
            .flat_map(|v1| v1.into_iter().map(|v2| v2.mask))
            .collect();

        let mut ksk = LweKeyswitchKeyOwned::new(
            0_u64,
            self.decomp_base_log,
            self.decomp_level_count,
            input_key_lwe_dimension,
            self.output_lwe_size.to_lwe_dimension(),
            CiphertextModulus::new_native(),
        );

        let mut lwe_ciphertext_list = ksk.as_mut_lwe_ciphertext_list();
        opened_lwe_masks_bodies_to_tfhers_u64(masks, bodies, &mut lwe_ciphertext_list)?;
        Ok(ksk)
    }
}
