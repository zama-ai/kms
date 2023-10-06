use std::{collections::HashMap, sync::Arc};

use crate::{
    computation::SessionId,
    execution::{
        distributed::DistributedSession,
        party::{Identity, Role},
    },
    networking::local::LocalNetworkingProducer,
};

// returns a dummy session for a single party for testing/benchmark, given n and t and the party_id.
pub fn get_dummy_session_party_id(
    num_parties: usize,
    threshold: u8,
    party_id: usize,
) -> DistributedSession {
    let mut role_assignment = HashMap::new();
    assert!(party_id > 0);
    let my_id = Identity(format!("localhost:{}", 5000 + party_id - 1));

    for p in 0..num_parties {
        let id = Identity(format!("localhost:{}", 5000 + p));
        role_assignment.insert(Role((p + 1) as u64), id.clone());
    }

    let net_producer = LocalNetworkingProducer::from_ids(&[my_id.clone()]);
    DistributedSession::new(
        SessionId(1),
        role_assignment,
        Arc::new(net_producer.user_net(my_id.clone())),
        threshold,
        None,
        my_id.clone(),
    )
}

#[cfg(test)]
pub mod tests {

    use crate::{
        file_handling::read_element,
        lwe::{gen_key_set, Ciphertext64, KeySet, ThresholdLWEParameters},
        tests::test_data_setup::tests::{DEFAULT_SEED, TEST_KEY_PATH},
    };
    use aes_prng::AesRng;
    use rand::SeedableRng;

    // Deterministic key generation
    pub fn generate_keys(params: ThresholdLWEParameters) -> KeySet {
        let mut seeded_rng = AesRng::seed_from_u64(DEFAULT_SEED);
        gen_key_set(params, &mut seeded_rng)
    }

    // Deterministic cipher generation
    pub fn generate_cipher(_key_name: &str, message: u8) -> Ciphertext64 {
        let keys: KeySet = read_element(TEST_KEY_PATH.to_string()).unwrap();
        let mod_log = keys
            .pk
            .threshold_lwe_parameters
            .input_cipher_parameters
            .usable_message_modulus_log
            .0;
        if message >= 1 << mod_log {
            panic!("Message cannot be handled in a single block with current parameters!");
        }
        let mut seeded_rng = AesRng::seed_from_u64(444);
        keys.pk
            .encrypt_w_bitlimit(&mut seeded_rng, message, mod_log)
    }
}
