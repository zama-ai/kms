//! Local generation of FHE client keys.
//!
//! These helpers run on one node, without an MPC protocol. Tests, benchmarks and test fixtures
//! use them.

use tfhe::{ClientKey, Seed};
use threshold_execution::tfhe_internals::parameters::DKGParams;

pub fn generate_client_fhe_key(params: DKGParams, tag: tfhe::Tag, seed: Option<Seed>) -> ClientKey {
    use tfhe::prelude::Tagged;

    let config = params.to_tfhe_config();
    let mut client_key = match seed {
        Some(seed) => ClientKey::generate_with_seed(config, seed),
        None => ClientKey::generate(config),
    };
    *client_key.tag_mut() = tag;
    client_key
}

#[cfg(test)]
mod tests {
    use crate::consts::TEST_PARAM;

    #[test]
    fn sanity_check_sns_compression_test_params() {
        use tfhe::prelude::{FheDecrypt, FheEncrypt, SquashNoise};
        let params = TEST_PARAM;
        let cks = crate::util::key_setup::local_material::generate_client_fhe_key(
            params,
            tfhe::Tag::default(),
            None,
        );
        let sks = cks.generate_server_key();

        tfhe::set_server_key(sks);
        let pt = 12u32;
        let ct = tfhe::FheUint32::encrypt(pt, &cks);
        let large_ct = ct.squash_noise().unwrap();

        let compressed_large_ct = tfhe::CompressedSquashedNoiseCiphertextListBuilder::new()
            .push(large_ct)
            .build()
            .unwrap();
        let new_large_ct: tfhe::SquashedNoiseFheUint = compressed_large_ct.get(0).unwrap().unwrap();
        let actual_pt: u32 = new_large_ct.decrypt(&cks);
        assert_eq!(actual_pt, pt);
    }
}
