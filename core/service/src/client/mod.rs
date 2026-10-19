#[cfg(feature = "non-wasm")]
pub mod client_non_wasm;
pub mod client_wasm;
#[cfg(feature = "non-wasm")]
pub mod crs_gen;
#[cfg(feature = "non-wasm")]
pub mod custodian_context;
#[cfg(not(feature = "non-wasm"))]
pub mod js_api;
#[cfg(feature = "non-wasm")]
pub mod key_gen;
#[cfg(feature = "non-wasm")]
pub mod local_crypto;
#[cfg(feature = "non-wasm")]
pub mod mpc_context;
#[cfg(feature = "non-wasm")]
pub mod public_decryption;
#[cfg(any(test, feature = "testing"))]
#[cfg(feature = "non-wasm")]
pub mod test_tools;
#[cfg(feature = "non-wasm")]
pub mod user_decryption_non_wasm;
pub mod user_decryption_wasm;

#[cfg(test)]
pub(crate) mod tests {
    mod common;
    mod crs_gen_tests;
    mod custodian_backup_tests;
    mod custodian_context_tests;
    // CI runs tests prefixed with `nightly_` only on scheduled runs.
    // The remaining tests also run in regular CI.
    #[cfg(feature = "slow_tests")]
    mod extended_tests;
    mod key_gen_tests;
    mod misc_tests;
    mod mpc_context_tests;
    #[cfg(feature = "slow_tests")]
    mod mpc_epoch_tests;
    mod public_decryption_tests;
    mod restore_from_backup_tests;
    mod service_helpers;
    mod storage_smoke_tests;
    #[cfg(any(test, feature = "testing"))]
    mod testing_infra_tests;
    mod user_decryption_tests;
    use crate::engine::utils::make_extra_data;
    use kms_grpc::{ContextId, EpochId};

    fn ctx() -> ContextId {
        ContextId::from_bytes([0x11u8; 32])
    }

    fn ep() -> EpochId {
        EpochId::from_bytes([0x22u8; 32])
    }

    #[test]
    fn make_extra_data_v0_ignores_ids() {
        let out = make_extra_data(0, None, None).unwrap();
        assert_eq!(out, vec![0u8]);
        let out = make_extra_data(0, Some(&ctx()), Some(&ep())).unwrap();
        assert_eq!(out, vec![0u8]);
    }

    #[test]
    fn make_extra_data_v1_requires_context() {
        let out = make_extra_data(1, Some(&ctx()), None).unwrap();
        assert_eq!(out.len(), 33);
        assert_eq!(out[0], 1);
        assert_eq!(&out[1..], ctx().as_bytes());

        let err = make_extra_data(1, None, None).unwrap_err().to_string();
        assert!(err.contains("version 1 requires a context_id"), "{err}");
    }

    #[test]
    fn make_extra_data_v2_requires_both_ids() {
        let out = make_extra_data(2, Some(&ctx()), Some(&ep())).unwrap();
        assert_eq!(out.len(), 65);
        assert_eq!(out[0], 2);
        assert_eq!(&out[1..33], ctx().as_bytes());
        assert_eq!(&out[33..], ep().as_bytes());

        let err = make_extra_data(2, None, Some(&ep()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("version 2 requires a context_id"), "{err}");

        let err = make_extra_data(2, Some(&ctx()), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("version 2 requires an epoch_id"), "{err}");
    }

    #[test]
    fn make_extra_data_unknown_version_errors() {
        let err = make_extra_data(3, Some(&ctx()), Some(&ep()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown version 3"), "{err}");
    }
}
