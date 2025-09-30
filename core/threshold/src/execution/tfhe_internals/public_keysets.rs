use crate::execution::endpoints::keygen::DSEP_KG;
use crate::execution::tfhe_internals::lwe_key::{
    to_tfhe_hl_api_compact_public_key, to_tfhe_hl_api_compressed_compact_public_key,
};
use crate::execution::tfhe_internals::parameters::DKGParams;
use serde::{Deserialize, Serialize};
use tfhe::core_crypto::algorithms::par_convert_standard_lwe_bootstrap_key_to_fourier_128;
use tfhe::core_crypto::entities::Fourier128LweBootstrapKey;
use tfhe::core_crypto::prelude::{
    SeededLweBootstrapKey, SeededLweCompactPublicKey, SeededLweKeyswitchKey,
};
use tfhe::shortint::atomic_pattern::compressed::{
    CompressedAtomicPatternServerKey, CompressedStandardAtomicPatternServerKey,
};
use tfhe::shortint::atomic_pattern::{AtomicPatternServerKey, StandardAtomicPatternServerKey};
use tfhe::shortint::list_compression::{
    CompressedCompressionKey, CompressedDecompressionKey, CompressedNoiseSquashingCompressionKey,
    CompressionKey, DecompressionKey, NoiseSquashingCompressionKey,
};
use tfhe::shortint::noise_squashing::{
    CompressedShortint128BootstrappingKey, NoiseSquashingKey, Shortint128BootstrappingKey,
};
use tfhe::shortint::server_key::{
    CompressedModulusSwitchConfiguration, ModulusSwitchConfiguration,
    ShortintCompressedBootstrappingKey,
};
use tfhe::shortint::EncryptionKeyChoice;
use tfhe::{
    core_crypto::{
        algorithms::par_convert_standard_lwe_bootstrap_key_to_fourier,
        entities::{FourierLweBootstrapKey, LweBootstrapKey, LweCompactPublicKey, LweKeyswitchKey},
    },
    shortint::{
        ciphertext::{MaxDegree, MaxNoiseLevel},
        server_key::ShortintBootstrappingKey,
    },
    xof_key_set::CompressedXofKeySet,
    XofSeed,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct FhePubKeySet {
    pub public_key: tfhe::CompactPublicKey,
    pub server_key: tfhe::ServerKey,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) enum ReRandomizationRawKeySwitchingKey {
    UseCPKEncryptionKSK,
    DedicatedKSK(LweKeyswitchKey<Vec<u64>>),
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
    pub sns_compression_key: Option<NoiseSquashingCompressionKey>,
    pub cpk_re_randomization_ksk: Option<ReRandomizationRawKeySwitchingKey>,
    pub seed: u128,
}

impl Eq for RawPubKeySet {}

impl RawPubKeySet {
    pub fn compute_tfhe_shortint_server_key(&self, params: DKGParams) -> tfhe::shortint::ServerKey {
        let regular_params = params.get_params_basics_handle();

        // Creation of the bootstrapping key in the Fourier domain
        let mut fourier_bsk = FourierLweBootstrapKey::new(
            self.bk.input_lwe_dimension(),
            self.bk.glwe_size(),
            self.bk.polynomial_size(),
            self.bk.decomposition_base_log(),
            self.bk.decomposition_level_count(),
        );

        // Conversion to fourier domain
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
            MaxDegree::from_msg_carry_modulus(
                regular_params.get_message_modulus(),
                regular_params.get_carry_modulus(),
            ),
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
        let (noise_squashing_key, noise_squashing_compression_key) =
            match (&self.bk_sns, &self.msnrk_sns, params) {
                (Some(bk_sns), Some(msnrk_sns), DKGParams::WithSnS(sns_param)) => {
                    let mut fourier_bk = Fourier128LweBootstrapKey::new(
                        bk_sns.input_lwe_dimension(),
                        bk_sns.glwe_size(),
                        bk_sns.polynomial_size(),
                        bk_sns.decomposition_base_log(),
                        bk_sns.decomposition_level_count(),
                    );
                    let sns_param = sns_param.sns_params;

                    par_convert_standard_lwe_bootstrap_key_to_fourier_128(bk_sns, &mut fourier_bk);
                    let key = NoiseSquashingKey::from_raw_parts(
                        Shortint128BootstrappingKey::Classic {
                            bsk: fourier_bk,
                            modulus_switch_noise_reduction_key: msnrk_sns.clone(),
                        },
                        sns_param.message_modulus(),
                        sns_param.carry_modulus(),
                        sns_param.ciphertext_modulus(),
                    );
                    let noise_squashing_key =
                        tfhe::integer::noise_squashing::NoiseSquashingKey::from_raw_parts(key);
                    match self.sns_compression_key.as_ref() {
                    Some(sns_compression_key) => (
                        Some(noise_squashing_key),
                        Some(
                            tfhe::integer::ciphertext::NoiseSquashingCompressionKey::from_raw_parts(
                                sns_compression_key.clone(),
                            ),
                        ),
                    ),
                    None => (Some(noise_squashing_key), None),
                }
                }
                _ => (None, None),
            };

        let integer_pksk = self.pksk.as_ref().map(|pksk| {
            let shortint_pksk =
                tfhe::shortint::key_switching_key::KeySwitchingKeyMaterial::from_raw_parts(
                    pksk.clone(),
                    params.get_params_basics_handle().pksk_rshift(),
                    params
                        .get_params_basics_handle()
                        .get_pksk_destination()
                        .unwrap(),
                );

            tfhe::integer::key_switching_key::KeySwitchingKeyMaterial::from_raw_parts(shortint_pksk)
        });

        let rerand_ksk =
            self.cpk_re_randomization_ksk
                .as_ref()
                .map(|rerand_ksk| match rerand_ksk {
                    ReRandomizationRawKeySwitchingKey::UseCPKEncryptionKSK => {
                        tfhe::ReRandomizationKeySwitchingKey::UseCPKEncryptionKSK
                    }
                    ReRandomizationRawKeySwitchingKey::DedicatedKSK(dedicated_rerand_ksk) => {
                        let shortint_rerand_ksk =
                        tfhe::shortint::key_switching_key::KeySwitchingKeyMaterial::from_raw_parts(
                            dedicated_rerand_ksk.clone(),
                            0,
                            EncryptionKeyChoice::Big,
                        );

                        let rerand_ksk =
                        tfhe::integer::key_switching_key::KeySwitchingKeyMaterial::from_raw_parts(
                            shortint_rerand_ksk,
                        );
                        tfhe::ReRandomizationKeySwitchingKey::DedicatedKSK(rerand_ksk)
                    }
                });

        tfhe::ServerKey::from_raw_parts(
            integer_key,
            integer_pksk,
            compression_key,
            decompression_key,
            noise_squashing_key,
            noise_squashing_compression_key,
            rerand_ksk,
            tfhe::Tag::default(),
        )
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

// NOTE: This is meant to be replaced by XofKeySet once introduced in TFHE-RS
// https://github.com/zama-ai/tfhe-rs/pull/2409
#[derive(Clone, Serialize, Deserialize)]
pub struct CompressedFhePubKeySet {
    pub public_key: tfhe::CompressedCompactPublicKey,
    pub server_key: tfhe::CompressedServerKey,
    pub seed: u128,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) enum CompressedReRandomizationRawKeySwitchingKey {
    UseCPKEncryptionKSK,
    DedicatedKSK(SeededLweKeyswitchKey<Vec<u64>>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RawCompressedPubKeySet {
    pub lwe_public_key: SeededLweCompactPublicKey<Vec<u64>>,
    pub ksk: SeededLweKeyswitchKey<Vec<u64>>,
    pub pksk: Option<SeededLweKeyswitchKey<Vec<u64>>>,
    pub bk: SeededLweBootstrapKey<Vec<u64>>,
    pub bk_sns: Option<SeededLweBootstrapKey<Vec<u128>>>,
    pub compression_keys: Option<(CompressedCompressionKey, CompressedDecompressionKey)>,
    pub msnrk: CompressedModulusSwitchConfiguration<u64>,
    pub msnrk_sns: Option<CompressedModulusSwitchConfiguration<u64>>,
    pub sns_compression_key: Option<CompressedNoiseSquashingCompressionKey>,
    pub cpk_re_randomization_ksk: Option<CompressedReRandomizationRawKeySwitchingKey>,
    pub seed: u128,
}

impl RawCompressedPubKeySet {
    pub fn compute_tfhe_hl_api_compressed_compact_public_key(
        &self,
        params: DKGParams,
    ) -> tfhe::CompressedCompactPublicKey {
        let params = params
            .get_params_basics_handle()
            .get_compact_pk_enc_params();
        to_tfhe_hl_api_compressed_compact_public_key(self.lwe_public_key.clone(), params)
    }

    pub fn compute_tfhe_shortint_compressed_server_key(
        &self,
        params: DKGParams,
    ) -> tfhe::shortint::CompressedServerKey {
        let regular_params = params.get_params_basics_handle();

        let pk_bk = ShortintCompressedBootstrappingKey::Classic {
            bsk: self.bk.clone(),
            modulus_switch_noise_reduction_key: self.msnrk.clone(),
        };

        let max_noise_level = MaxNoiseLevel::from_msg_carry_modulus(
            regular_params.get_message_modulus(),
            regular_params.get_carry_modulus(),
        );

        let atomic_pattern = CompressedStandardAtomicPatternServerKey::from_raw_parts(
            self.ksk.clone(),
            pk_bk,
            regular_params.pbs_order(),
        );

        tfhe::shortint::CompressedServerKey::from_raw_parts(
            CompressedAtomicPatternServerKey::Standard(atomic_pattern),
            regular_params.get_message_modulus(),
            regular_params.get_carry_modulus(),
            MaxDegree::from_msg_carry_modulus(
                regular_params.get_message_modulus(),
                regular_params.get_carry_modulus(),
            ),
            max_noise_level,
        )
    }

    pub fn compute_tfhe_hl_api_compressed_server_key(
        &self,
        params: DKGParams,
    ) -> tfhe::CompressedServerKey {
        let shortint_key = self.compute_tfhe_shortint_compressed_server_key(params);

        let cpk_key_switching_key_material = self.pksk.as_ref().map(|pksk| {
            tfhe::integer::key_switching_key::CompressedKeySwitchingKeyMaterial::from_raw_parts( tfhe::shortint::key_switching_key::CompressedKeySwitchingKeyMaterial::from_raw_parts(
                pksk.clone(),
                params.get_params_basics_handle().pksk_rshift(),
                params
                    .get_params_basics_handle()
                    .get_pksk_destination()
                    .unwrap(),
            ))
        });

        let (compression_key, decompression_key) = match self.compression_keys.as_ref() {
            Some((compression_key, decompression_key)) => (
                Some(compression_key.clone()),
                Some(decompression_key.clone()),
            ),
            None => (None, None),
        };

        let (noise_squashing_key, noise_squashing_compression_key) = match (
            self.bk_sns.as_ref(),
            self.msnrk_sns.as_ref(),
            params,
        ) {
            (Some(bk_sns), Some(msnrk_sns), DKGParams::WithSnS(params_with_sns)) => {
                let noise_squashing_key = Some(
                    tfhe::integer::noise_squashing::CompressedNoiseSquashingKey::from_raw_parts( tfhe::shortint::noise_squashing::CompressedNoiseSquashingKey::from_raw_parts(
                        CompressedShortint128BootstrappingKey::Classic{
                            bsk : bk_sns.clone(),
                            modulus_switch_noise_reduction_key: msnrk_sns.clone()
                        },
                        params_with_sns.sns_params.message_modulus(),
                        params_with_sns.sns_params.carry_modulus(),
                        params_with_sns.sns_params.ciphertext_modulus(),
                    )));
                match self.sns_compression_key.as_ref() {
                        Some(sns_compression_key) => (
                            noise_squashing_key,
                            Some(tfhe::integer::ciphertext::CompressedNoiseSquashingCompressionKey::from_raw_parts(
                                sns_compression_key.clone(),
                            )),
                        ),
                        None => (noise_squashing_key, None),
                    }
            }
            _ => (None, None),
        };

        let rerand_ksk =
            self.cpk_re_randomization_ksk
                .as_ref()
                .map(|rerand_ksk| match rerand_ksk {
                    CompressedReRandomizationRawKeySwitchingKey::UseCPKEncryptionKSK => {
                        tfhe::CompressedReRandomizationKeySwitchingKey::UseCPKEncryptionKSK
                    }
                    CompressedReRandomizationRawKeySwitchingKey::DedicatedKSK(dedicated_rerand_ksk) => {
                        let shortint_rerand_ksk =
                        tfhe::shortint::key_switching_key::CompressedKeySwitchingKeyMaterial::from_raw_parts(
                            dedicated_rerand_ksk.clone(),
                            0,
                            EncryptionKeyChoice::Big,
                        );

                        let rerand_ksk =
                        tfhe::integer::key_switching_key::CompressedKeySwitchingKeyMaterial::from_raw_parts(
                            shortint_rerand_ksk,
                        );
                        tfhe::CompressedReRandomizationKeySwitchingKey::DedicatedKSK(rerand_ksk)
                    }
                });

        tfhe::CompressedServerKey::from_raw_parts(
            tfhe::integer::CompressedServerKey::from_raw_parts(shortint_key),
            cpk_key_switching_key_material,
            compression_key.map(|compression_key| {
                tfhe::integer::compression_keys::CompressedCompressionKey::from_raw_parts(
                    compression_key,
                )
            }),
            decompression_key.map(|decompression_key| {
                tfhe::integer::compression_keys::CompressedDecompressionKey::from_raw_parts(
                    decompression_key,
                )
            }),
            noise_squashing_key,
            noise_squashing_compression_key,
            rerand_ksk,
            tfhe::Tag::default(),
        )
    }

    pub fn to_compressed_pubkeyset(&self, params: DKGParams) -> CompressedFhePubKeySet {
        let seed = self.seed;
        let public_key = self.compute_tfhe_hl_api_compressed_compact_public_key(params);
        let server_key = self.compute_tfhe_hl_api_compressed_server_key(params);

        CompressedFhePubKeySet {
            public_key,
            server_key,
            seed,
        }
    }
}

impl CompressedFhePubKeySet {
    // NOTE: This is meant to be replaced by CompressedXofKeySet::decompress once introduced in TFHE-RS
    // https://github.com/zama-ai/tfhe-rs/pull/2409
    #[allow(dead_code)]
    pub fn decompress(self) -> anyhow::Result<FhePubKeySet> {
        let xof_seed = XofSeed::new_u128(self.seed, DSEP_KG);
        let xof_key_set =
            CompressedXofKeySet::from_raw_parts(xof_seed, self.public_key, self.server_key)
                .decompress()?;

        let (public_key, server_key) = xof_key_set.into_raw_parts();
        Ok(FhePubKeySet {
            public_key,
            server_key,
        })
    }
}
