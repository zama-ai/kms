use tfhe::{
    integer::{
        ciphertext::{SquashedNoiseBooleanBlock, SquashedNoiseRadixCiphertext},
        RadixCiphertext,
    },
    shortint::ciphertext::SquashedNoiseCiphertext,
};

// Re-export the non-wasm module
#[cfg(feature = "non-wasm")]
pub use super::decryption_non_wasm::*;

#[derive(
    Copy,
    Clone,
    Default,
    serde::Serialize,
    serde::Deserialize,
    derive_more::Display,
    Debug,
    clap::ValueEnum,
)]
pub enum DecryptionMode {
    /// nSmall Noise Flooding, this is the default
    #[default]
    NoiseFloodSmall,
    /// nLarge Noise Flooding
    NoiseFloodLarge,
    /// nSmall Bit Decomposition
    BitDecSmall,
    /// nLarge Bit Decomposition
    BitDecLarge,
}

impl DecryptionMode {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            DecryptionMode::NoiseFloodSmall => "NoiseFloodSmall",
            DecryptionMode::NoiseFloodLarge => "NoiseFloodLarge",
            DecryptionMode::BitDecSmall => "BitDecSmall",
            DecryptionMode::BitDecLarge => "BitDecLarge",
        }
    }
}

#[derive(Clone)]
pub enum SnsRadixOrBoolCiphertext {
    Radix(SquashedNoiseRadixCiphertext),
    Bool(SquashedNoiseBooleanBlock),
    // eventually we'll need to add SignedRadix
}

impl SnsRadixOrBoolCiphertext {
    pub fn len(&self) -> usize {
        match self {
            SnsRadixOrBoolCiphertext::Radix(inner) => inner.packed_blocks().len(),
            SnsRadixOrBoolCiphertext::Bool(_) => 1,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn packed_blocks<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = &'a SquashedNoiseCiphertext> + 'a> {
        match self {
            SnsRadixOrBoolCiphertext::Radix(inner) => Box::new(inner.packed_blocks().iter()),
            SnsRadixOrBoolCiphertext::Bool(inner) => {
                Box::new(std::iter::once(inner.packed_blocks()))
            }
        }
    }

    pub fn packing_factor(&self) -> usize {
        match self {
            SnsRadixOrBoolCiphertext::Radix(inner) => {
                inner.original_block_count() / inner.packed_blocks().len()
            }
            SnsRadixOrBoolCiphertext::Bool(_inner) => 1,
        }
    }
}

pub enum LowLevelCiphertext {
    Big(SnsRadixOrBoolCiphertext),
    Small(RadixCiphertext),
}

impl LowLevelCiphertext {
    pub fn try_get_big_ct(self) -> anyhow::Result<SnsRadixOrBoolCiphertext> {
        match self {
            LowLevelCiphertext::Big(ct128) => Ok(ct128),
            LowLevelCiphertext::Small(_) => {
                anyhow::bail!("expected big ciphertext but got a small one")
            }
        }
    }
    pub fn try_get_small_ct(self) -> anyhow::Result<RadixCiphertext> {
        match self {
            LowLevelCiphertext::Big(_) => {
                anyhow::bail!("expected small ciphertext but got a big one")
            }
            LowLevelCiphertext::Small(ct64) => Ok(ct64),
        }
    }
}

#[cfg(test)]
mod tests {
    use tfhe::{
        prelude::{FheEncrypt, SquashNoise},
        shortint::ClassicPBSParameters,
        ClientKey, ConfigBuilder, FheBool, FheUint32, ServerKey,
    };

    use crate::{
        execution::tfhe_internals::parameters::DKGParams,
        tests::test_data_setup::tests::TEST_PARAMETERS,
    };

    use super::SnsRadixOrBoolCiphertext;

    #[test]
    fn test_packing_factor() {
        let block_param: ClassicPBSParameters = TEST_PARAMETERS
            .get_params_basics_handle()
            .to_classic_pbs_parameters();
        let sns_param = match TEST_PARAMETERS {
            DKGParams::WithoutSnS(_) => panic!("expected pbs params"),
            DKGParams::WithSnS(dkgparams_sn_s) => dkgparams_sn_s.sns_params,
        };
        let config = ConfigBuilder::with_custom_parameters(block_param)
            .enable_noise_squashing(sns_param)
            .build();
        let client_key = ClientKey::generate(config);
        let server_key = ServerKey::new(&client_key);
        tfhe::set_server_key(server_key);

        // test radix ct
        {
            let m = 3232u32;
            let ct = FheUint32::encrypt(m, &client_key);
            let ct_big = ct
                .squash_noise()
                .unwrap()
                .underlying_squashed_noise_ciphertext()
                .clone();

            let wrapped_ct_big = SnsRadixOrBoolCiphertext::Radix(ct_big);
            let msg_bits = sns_param.message_modulus.0.ilog2();
            let carry_bits = sns_param.carry_modulus.0.ilog2();
            assert_eq!(
                wrapped_ct_big.packing_factor() as u32,
                (msg_bits + carry_bits) / msg_bits
            );
        }

        // test binary
        {
            let m = true;
            let ct = FheBool::encrypt(m, &client_key);
            let ct_big = ct
                .squash_noise()
                .unwrap()
                .underlying_squashed_noise_ciphertext()
                .clone();

            let wrapped_ct_big = SnsRadixOrBoolCiphertext::Bool(ct_big);
            assert_eq!(wrapped_ct_big.packing_factor(), 1);
        }
    }
}
