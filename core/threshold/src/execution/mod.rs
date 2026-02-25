#[cfg(feature = "non-wasm")]
pub mod communication {
    pub mod broadcast;
    pub mod p2p;
}
pub mod constants;
pub mod runtime;

#[cfg(feature = "non-wasm")]
pub mod small_execution {
    pub mod agree_random;
    pub mod offline;
    pub mod prf;
    pub mod prss;
}
pub mod random;
pub mod endpoints {
    pub mod decryption;
    #[cfg(feature = "non-wasm")]
    pub mod reshare_sk;
    // We keep decryption_non_wasm a private module and reexport it in decryption.
    #[cfg(feature = "non-wasm")]
    mod decryption_non_wasm;
    #[cfg(feature = "non-wasm")]
    pub mod keygen;
    pub mod reconstruct;
}
#[cfg(feature = "non-wasm")]
pub mod large_execution {
    pub mod coinflip;
    pub mod constants;
    pub mod double_sharing;
    pub mod local_double_share;
    pub mod local_single_share;
    pub mod offline;
    pub mod share_dispute;
    pub mod single_sharing;
    pub mod vss;
}

#[cfg(feature = "non-wasm")]
pub mod online {
    pub mod bit_lift;
    pub mod bit_manipulation;
    pub mod gen_bits;
    pub mod preprocessing;
    pub mod reshare;
    pub mod secret_distributions;
    pub mod triple;
}

pub mod sharing {
    #[cfg(feature = "non-wasm")]
    pub mod constants;
    #[cfg(feature = "non-wasm")]
    pub mod input;
    #[cfg(feature = "non-wasm")]
    pub mod open;
    pub mod shamir;
    pub mod share;
}

pub mod tfhe_internals {
    #[cfg(feature = "non-wasm")]
    pub mod compression_decompression_key;
    #[cfg(feature = "non-wasm")]
    pub mod compression_decompression_key_generation;
    #[cfg(feature = "non-wasm")]
    pub mod ggsw_ciphertext;
    #[cfg(feature = "non-wasm")]
    pub mod glwe_ciphertext;
    #[cfg(feature = "non-wasm")]
    pub mod glwe_key;
    #[cfg(feature = "non-wasm")]
    pub mod lwe_bootstrap_key;
    #[cfg(feature = "non-wasm")]
    pub mod lwe_bootstrap_key_generation;
    #[cfg(feature = "non-wasm")]
    pub mod lwe_ciphertext;
    #[cfg(feature = "non-wasm")]
    pub mod lwe_key;
    #[cfg(feature = "non-wasm")]
    pub mod lwe_keyswitch_key;
    #[cfg(feature = "non-wasm")]
    pub mod lwe_keyswitch_key_generation;
    #[cfg(feature = "non-wasm")]
    pub mod lwe_packing_keyswitch_key;
    #[cfg(feature = "non-wasm")]
    pub mod lwe_packing_keyswitch_key_generation;
    #[cfg(feature = "non-wasm")]
    pub mod modulus_switch_noise_reduction_key_generation;
    pub mod parameters;
    #[cfg(feature = "non-wasm")]
    pub mod private_keysets;
    #[cfg(feature = "non-wasm")]
    pub mod public_keysets;
    #[cfg(feature = "non-wasm")]
    pub mod randomness;
    mod raw_parameters;
    #[cfg(feature = "non-wasm")]
    pub mod sns_compression_key;
    #[cfg(feature = "non-wasm")]
    pub mod sns_compression_key_generation;
    pub mod switch_and_squash;
    #[cfg(any(test, feature = "testing"))]
    pub mod test_feature;
    #[cfg(feature = "non-wasm")]
    pub mod utils;
}

pub mod config;

#[cfg(feature = "non-wasm")]
pub mod zk {
    pub mod ceremony;
    pub mod constants;
}

pub mod keyset_config;
