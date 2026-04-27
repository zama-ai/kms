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
pub mod mpc_context;
#[cfg(feature = "non-wasm")]
pub mod public_decryption;
#[cfg(any(test, feature = "testing"))]
#[cfg(feature = "non-wasm")]
pub mod test_tools;
#[cfg(feature = "non-wasm")]
pub mod user_decryption_non_wasm;
pub mod user_decryption_wasm;

#[cfg(feature = "non-wasm")]
use kms_grpc::{ContextId, EpochId};

/// Highest `extra_data` version understood by [`make_extra_data`].
/// Must stay in sync with `sanity_check_extra_data` in `engine::utils`.
#[cfg(feature = "non-wasm")]
pub const MAX_EXTRA_DATA_VERSION: u8 = 2;

/// Build an `extra_data` payload for a gRPC request, matching the format the KMS core expects
/// (see `sanity_check_extra_data` in `engine::utils`). Layout:
/// - byte 0: version
/// - v0: no extra bytes
/// - v1: 32 bytes of context_id
/// - v2: 32 bytes of context_id followed by 32 bytes of epoch_id
///
/// Errors when `version` is above [`MAX_EXTRA_DATA_VERSION`], when v1 is requested without a
/// `context_id`, or when v2 is requested without both a `context_id` and an `epoch_id`.
#[cfg(feature = "non-wasm")]
pub(crate) fn make_extra_data(
    version: u8,
    context_id: Option<&ContextId>,
    epoch_id: Option<&EpochId>,
) -> anyhow::Result<Vec<u8>> {
    let mut extra_data = vec![version];
    match version {
        0 => {
            // no extra data
        }
        1 => {
            let ctx = context_id.ok_or_else(|| {
                anyhow::anyhow!("make_extra_data: version 1 requires a context_id")
            })?;
            extra_data.extend_from_slice(ctx.as_bytes());
        }
        2 => {
            let ctx = context_id.ok_or_else(|| {
                anyhow::anyhow!("make_extra_data: version 2 requires a context_id")
            })?;
            let ep = epoch_id.ok_or_else(|| {
                anyhow::anyhow!("make_extra_data: version 2 requires an epoch_id")
            })?;
            extra_data.extend_from_slice(ctx.as_bytes());
            extra_data.extend_from_slice(ep.as_bytes());
        }
        _ => {
            return Err(anyhow::anyhow!(
                "make_extra_data: unknown version {version}, highest supported is {MAX_EXTRA_DATA_VERSION}"
            ));
        }
    }
    Ok(extra_data)
}

#[allow(deprecated)]
#[cfg(test)]
pub(crate) mod tests {
    mod centralized;
    mod common;
    #[cfg(any(test, feature = "testing"))]
    mod testing_infra_tests;
    mod threshold;
    use super::make_extra_data;
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
