#[cfg(test)]
pub mod tests {
    use crate::execution::tfhe_internals::parameters::{
        DKGParams, BC_PARAMS_SAM_SNS, PARAMS_TEST_BK_SNS,
    };
    use crate::execution::tfhe_internals::test_feature::KeySet;
    use crate::file_handling::{read_element, write_element};
    use crate::tests::helper::tests::generate_keys;

    pub const DEFAULT_SEED: u64 = 1;

    // Very small parameters with very little noise, used in most tests to increase speed
    pub const TEST_PARAMETERS: DKGParams = PARAMS_TEST_BK_SNS;

    // TAKING BLOCKCHAIN PARAMS AS REFERENCE (Sept. 16 2024)
    // TODO MULTIPLE PEOPLE SHOULD VALIDATE THAT THESE ARE INDEED THE PARAMETERS WE SHOULD RUN WITH!!!
    pub const REAL_PARAMETERS: DKGParams = BC_PARAMS_SAM_SNS;

    pub fn ensure_keys_exist(path: &str, params: DKGParams) {
        match read_element::<KeySet>(path.to_string()) {
            Ok(_key_bytes) => (),
            Err(_e) => {
                let keys = generate_keys(params);
                write_element(path.to_string(), &keys).unwrap();
            }
        }
    }
}
