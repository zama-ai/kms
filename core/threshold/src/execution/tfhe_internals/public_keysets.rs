use crate::execution::tfhe_internals::lwe_key::to_tfhe_hl_api_compact_public_key;
use crate::execution::tfhe_internals::parameters::DKGParams;
use serde::{Deserialize, Serialize};
use tfhe::core_crypto::algorithms::convert_standard_lwe_bootstrap_key_to_fourier_128;
use tfhe::core_crypto::entities::Fourier128LweBootstrapKey;
use tfhe::shortint::atomic_pattern::{AtomicPatternServerKey, StandardAtomicPatternServerKey};
use tfhe::shortint::list_compression::{
    CompressionKey, DecompressionKey, NoiseSquashingCompressionKey,
};
use tfhe::shortint::noise_squashing::NoiseSquashingKey;
use tfhe::shortint::server_key::ModulusSwitchConfiguration;
use tfhe::{
    core_crypto::{
        algorithms::par_convert_standard_lwe_bootstrap_key_to_fourier,
        entities::{FourierLweBootstrapKey, LweBootstrapKey, LweCompactPublicKey, LweKeyswitchKey},
    },
    shortint::{
        ciphertext::{MaxDegree, MaxNoiseLevel},
        server_key::ShortintBootstrappingKey,
    },
};

#[derive(Clone, Serialize, Deserialize)]
pub struct FhePubKeySet {
    pub public_key: tfhe::CompactPublicKey,
    pub server_key: tfhe::ServerKey,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct RawPubKeySet {
    pub lwe_public_key: LweCompactPublicKey<Vec<u64>>,
    pub ksk: LweKeyswitchKey<Vec<u64>>,
    pub pksk: Option<LweKeyswitchKey<Vec<u64>>>,
    pub bk: LweBootstrapKey<Vec<u64>>,
    pub bk_sns: Option<LweBootstrapKey<Vec<u128>>>,
    pub compression_keys: Option<(CompressionKey, DecompressionKey)>,
    pub msnrk: ModulusSwitchConfiguration<u64>,
    pub msnrk_sns: Option<ModulusSwitchConfiguration<u64>>,
    pub seed: u128,
    pub sns_compression_key: Option<NoiseSquashingCompressionKey>,
}

impl Eq for RawPubKeySet {}

impl RawPubKeySet {
    pub fn compute_tfhe_shortint_server_key(&self, params: DKGParams) -> tfhe::shortint::ServerKey {
        let regular_params = params.get_params_basics_handle();
        let max_value =
            regular_params.get_message_modulus().0 * regular_params.get_carry_modulus().0 - 1;

        // Creation of the bootstrapping key in the Fourier domain
        let mut fourier_bsk = FourierLweBootstrapKey::new(
            self.bk.input_lwe_dimension(),
            self.bk.glwe_size(),
            self.bk.polynomial_size(),
            self.bk.decomposition_base_log(),
            self.bk.decomposition_level_count(),
        );

        // Conversion to fourier domain
        // TODO add `modulus_switch_noise_reduction_key` to RawPubKeySet
        par_convert_standard_lwe_bootstrap_key_to_fourier(&self.bk, &mut fourier_bsk);

        let pk_bk = ShortintBootstrappingKey::Classic {
            bsk: fourier_bsk,
            modulus_switch_noise_reduction_key: self.msnrk.clone(),
        };

        let max_noise_level = MaxNoiseLevel::from_msg_carry_modulus(
            regular_params.get_message_modulus(),
            regular_params.get_carry_modulus(),
        );

        let atomic_pattern = StandardAtomicPatternServerKey::from_raw_parts(
            self.ksk.clone(),
            pk_bk,
            regular_params.pbs_order(),
        );

        tfhe::shortint::ServerKey::from_raw_parts(
            AtomicPatternServerKey::Standard(atomic_pattern),
            regular_params.get_message_modulus(),
            regular_params.get_carry_modulus(),
            MaxDegree::new(max_value),
            max_noise_level,
        )
    }

    pub fn compute_tfhe_hl_api_server_key(&self, params: DKGParams) -> tfhe::ServerKey {
        let shortint_key = self.compute_tfhe_shortint_server_key(params);
        let integer_key = tfhe::integer::ServerKey::from_raw_parts(shortint_key);

        let (compression_key, decompression_key) = self.compression_keys.as_ref().map_or_else(
            || (None, None),
            |(c_k, d_k)| {
                (
                    Some(
                        tfhe::integer::compression_keys::CompressionKey::from_raw_parts(
                            c_k.clone(),
                        ),
                    ),
                    Some(
                        tfhe::integer::compression_keys::DecompressionKey::from_raw_parts(
                            d_k.clone(),
                        ),
                    ),
                )
            },
        );
        let noise_squashing_key = match (&self.bk_sns, &self.msnrk_sns, params) {
            (Some(bk_sns), Some(msnrk_sns), DKGParams::WithSnS(sns_param)) => {
                let mut fourier_bk = Fourier128LweBootstrapKey::new(
                    bk_sns.input_lwe_dimension(),
                    bk_sns.glwe_size(),
                    bk_sns.polynomial_size(),
                    bk_sns.decomposition_base_log(),
                    bk_sns.decomposition_level_count(),
                );
                let sns_param = sns_param.sns_params;

                convert_standard_lwe_bootstrap_key_to_fourier_128(bk_sns, &mut fourier_bk);
                let key = NoiseSquashingKey::from_raw_parts(
                    fourier_bk,
                    msnrk_sns.clone(),
                    sns_param.message_modulus,
                    sns_param.carry_modulus,
                    sns_param.ciphertext_modulus,
                );
                Some(tfhe::integer::noise_squashing::NoiseSquashingKey::from_raw_parts(key))
            }
            _ => None,
        };

        if let Some(pksk) = &self.pksk {
            let shortint_pksk =
                tfhe::shortint::key_switching_key::KeySwitchingKeyMaterial::from_raw_parts(
                    pksk.clone(),
                    0,
                    params
                        .get_params_basics_handle()
                        .get_pksk_destination()
                        .unwrap(),
                );
            let integer_pksk =
                tfhe::integer::key_switching_key::KeySwitchingKeyMaterial::from_raw_parts(
                    shortint_pksk,
                );

            tfhe::ServerKey::from_raw_parts(
                integer_key,
                Some(integer_pksk),
                compression_key,
                decompression_key,
                noise_squashing_key,
                None, //TODO: Fill when we have compression keys for big ctxt
                tfhe::Tag::default(),
            )
        } else {
            tfhe::ServerKey::from_raw_parts(
                integer_key,
                None,
                compression_key,
                decompression_key,
                noise_squashing_key,
                None, //TODO: Fill when we have compression keys for big ctxt
                tfhe::Tag::default(),
            )
        }
    }

    pub fn compute_tfhe_hl_api_compact_public_key(
        &self,
        params: DKGParams,
    ) -> tfhe::CompactPublicKey {
        let params = params
            .get_params_basics_handle()
            .get_compact_pk_enc_params();

        to_tfhe_hl_api_compact_public_key(self.lwe_public_key.clone(), params)
    }

    pub fn to_pubkeyset(&self, params: DKGParams) -> FhePubKeySet {
        FhePubKeySet {
            public_key: self.compute_tfhe_hl_api_compact_public_key(params),
            server_key: self.compute_tfhe_hl_api_server_key(params),
        }
    }
}
