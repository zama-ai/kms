//! Validation of the input keyset of a secret key reshare.

use crate::{
    endpoints::reshare_sk::DedicatedOprfKeysPresent,
    tfhe_internals::{
        parameters::{DKGParams, DkgMode},
        private_keysets::{
            CompressionPrivateKeySharesEnum, GlweSecretKeyShareEnum, LweSecretKeyShareEnum,
            PrivateKeySet,
        },
    },
};
use algebra::{
    base_ring::{Z64, Z128},
    galois_rings::common::ResiduePoly,
    sharing::share::Share,
};
use error_utils::anyhow_error_and_log;
use tfhe::shortint::parameters::CompressionParameters;
use zeroize::Zeroize;

/// Share count of each component of a keyset being reshared, derived from the
/// DKG parameters and the dedicated key flags. `None` marks an absent optional
/// component.
#[derive(Debug)]
pub(super) struct ComponentSizes {
    pub(super) sns: Option<usize>,
    pub(super) lwe_compute: usize,
    pub(super) lwe_encryption: usize,
    pub(super) oprf: Option<usize>,
    pub(super) transciphering: Option<usize>,
    pub(super) glwe: usize,
    pub(super) compression: Option<usize>,
    pub(super) sns_compression: Option<usize>,
}

impl ComponentSizes {
    /// Returns an error when `dedicated_keys` claims a transciphering key that
    /// `parameters` cannot size.
    pub(super) fn new(
        parameters: DKGParams,
        dedicated_keys: DedicatedOprfKeysPresent,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            sns: parameters.sns().map(|p| p.glwe_sk_num_bits_sns()),
            lwe_compute: parameters.lwe_dimension().0,
            lwe_encryption: parameters.lwe_hat_dimension().0,
            oprf: dedicated_keys.oprf.then(|| parameters.lwe_dimension().0),
            transciphering: dedicated_keys
                .transciphering
                .then(|| {
                    parameters
                        .transciphering_lwe_dimension()
                        .ok_or_else(|| anyhow_error_and_log("transciphering key has no parameters"))
                        .map(|d| d.0)
                })
                .transpose()?,
            glwe: parameters.glwe_sk_num_bits(),
            compression: parameters
                .compression_decompression_params()
                .map(|_| parameters.compression_sk_num_bits()),
            sns_compression: parameters.sns().and_then(|p| {
                p.sns_compression_params()
                    .is_some()
                    .then(|| p.sns_compression_sk_num_bits())
            }),
        })
    }
}

/// Checks that `keyset` holds exactly the components in `sizes`, each in the
/// ring of the DKG mode and with the expected share count. Also checks that the
/// stored GLWE and compression metadata match `parameters`, because the
/// reshared keyset takes this metadata from `parameters`.
///
/// The reshare concatenates the components into one batch per ring and splits
/// the output by `sizes`. A component with a wrong length can offset another
/// one and keep the batch total correct, so only a check per component
/// detects it.
pub(super) fn check_input_keyset<const EXTENSION_DEGREE: usize>(
    keyset: &PrivateKeySet<EXTENSION_DEGREE>,
    parameters: DKGParams,
    sizes: &ComponentSizes,
) -> anyhow::Result<()> {
    let dkg_mode = parameters.dkg_mode();
    let lwe_len =
        |component: &str, key: &LweSecretKeyShareEnum<EXTENSION_DEGREE>| match (key, dkg_mode) {
            (LweSecretKeyShareEnum::Z64(key), DkgMode::Z64) => Ok(key.data.len()),
            (LweSecretKeyShareEnum::Z128(key), DkgMode::Z128) => Ok(key.data.len()),
            _ => Err(wrong_ring(component, dkg_mode)),
        };

    check_optional(
        "GLWE SnS key",
        keyset.glwe_secret_key_share_sns_as_lwe.as_ref(),
        sizes.sns,
        |key| Ok(key.data.len()),
    )?;
    check_len(
        "LWE compute key",
        lwe_len("LWE compute key", &keyset.lwe_compute_secret_key_share)?,
        sizes.lwe_compute,
    )?;
    check_len(
        "LWE encryption key",
        lwe_len(
            "LWE encryption key",
            &keyset.lwe_encryption_secret_key_share,
        )?,
        sizes.lwe_encryption,
    )?;
    check_optional(
        "OPRF key",
        keyset.oprf_secret_key_share.as_ref(),
        sizes.oprf,
        |key| lwe_len("OPRF key", key),
    )?;
    check_optional(
        "transciphering key",
        keyset.transciphering_secret_key_share.as_ref(),
        sizes.transciphering,
        |key| lwe_len("transciphering key", key),
    )?;

    let (glwe_len, glwe_polynomial_size) = match (&keyset.glwe_secret_key_share, dkg_mode) {
        (GlweSecretKeyShareEnum::Z64(key), DkgMode::Z64) => (key.data.len(), key.polynomial_size),
        (GlweSecretKeyShareEnum::Z128(key), DkgMode::Z128) => (key.data.len(), key.polynomial_size),
        _ => return Err(wrong_ring("GLWE compute key", dkg_mode)),
    };
    check_len("GLWE compute key", glwe_len, sizes.glwe)?;
    if glwe_polynomial_size != parameters.polynomial_size() {
        return Err(anyhow_error_and_log(format!(
            "Reshare input GLWE compute key has polynomial size {:?}, expected {:?}",
            glwe_polynomial_size,
            parameters.polynomial_size()
        )));
    }

    let compression = match &keyset.glwe_secret_key_share_compression {
        Some(CompressionPrivateKeySharesEnum::Z64(key)) if dkg_mode == DkgMode::Z64 => Some((
            key.post_packing_ks_key.data.len(),
            key.post_packing_ks_key.polynomial_size,
            key.params,
        )),
        Some(CompressionPrivateKeySharesEnum::Z128(key)) if dkg_mode == DkgMode::Z128 => Some((
            key.post_packing_ks_key.data.len(),
            key.post_packing_ks_key.polynomial_size,
            key.params,
        )),
        Some(_) => return Err(wrong_ring("GLWE compression key", dkg_mode)),
        None => None,
    };
    check_optional(
        "GLWE compression key",
        compression.as_ref(),
        sizes.compression,
        |(len, _, _)| Ok(*len),
    )?;
    if let (Some((_, polynomial_size, params)), Some(expected)) =
        (compression, parameters.compression_decompression_params())
    {
        let expected_polynomial_size = expected
            .raw_compression_parameters
            .packing_ks_polynomial_size;
        if polynomial_size != expected_polynomial_size {
            return Err(anyhow_error_and_log(format!(
                "Reshare input GLWE compression key has polynomial size {polynomial_size:?}, expected {expected_polynomial_size:?}"
            )));
        }
        let expected_params = CompressionParameters::Classic(expected.raw_compression_parameters);
        if params != expected_params {
            return Err(anyhow_error_and_log(format!(
                "Reshare input GLWE compression key has parameters {params:?}, expected {expected_params:?}"
            )));
        }
    }

    check_optional(
        "GLWE SnS compression key",
        keyset.glwe_sns_compression_key_as_lwe.as_ref(),
        sizes.sns_compression,
        |key| Ok(key.data.len()),
    )
}

fn wrong_ring(component: &str, dkg_mode: DkgMode) -> anyhow::Error {
    anyhow_error_and_log(format!(
        "Reshare input {component} is not in the ring of DKG mode {dkg_mode:?}"
    ))
}

fn check_len(component: &str, actual: usize, expected: usize) -> anyhow::Result<()> {
    if actual != expected {
        return Err(anyhow_error_and_log(format!(
            "Reshare input {component} has {actual} shares, expected {expected}"
        )));
    }
    Ok(())
}

/// Checks that an optional component is present exactly when `expected` is
/// `Some`, and that a present component has `expected` shares.
fn check_optional<K>(
    component: &str,
    key: Option<&K>,
    expected: Option<usize>,
    len: impl FnOnce(&K) -> anyhow::Result<usize>,
) -> anyhow::Result<()> {
    match (key, expected) {
        (Some(key), Some(expected)) => check_len(component, len(key)?, expected),
        (None, None) => Ok(()),
        (key, expected) => Err(anyhow_error_and_log(format!(
            "Reshare input {component} presence is {}, but the parameters expect {}",
            key.is_some(),
            expected.is_some()
        ))),
    }
}

/// Checks that the extracted batches hold `total128` and `total64` shares.
/// Zeroizes both batches when either count differs, because the batches hold
/// the shares that were moved out of the input keyset.
pub(super) fn check_batch_lens<const EXTENSION_DEGREE: usize>(
    batch128: &mut Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>,
    total128: usize,
    batch64: &mut Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
    total64: usize,
) -> anyhow::Result<()> {
    if batch128.len() == total128 && batch64.len() == total64 {
        return Ok(());
    }
    let err = anyhow_error_and_log(format!(
        "Reshare batches have {} Z128 and {} Z64 shares, expected {total128} and {total64}",
        batch128.len(),
        batch64.len(),
    ));
    batch128.zeroize();
    batch64.zeroize();
    Err(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoints::reshare_sk::tests::RESHARE_KEYSET;
    use crate::tfhe_internals::parameters::PARAMS_TEST_RESHARE;
    use crate::tfhe_internals::test_feature::keygen_all_party_shares_from_client_key;
    use algebra::structure_traits::Sample;
    use rand::SeedableRng;
    use threshold_types::rng::AesRng;
    use threshold_types::role::Role;

    /// Returns party 0's share of the reshare-test keyset and its expected component sizes.
    fn valid_reshare_input() -> (PrivateKeySet<4>, ComponentSizes) {
        let mut rng = AesRng::seed_from_u64(4242);
        let keyset = keygen_all_party_shares_from_client_key::<_, 4>(
            &RESHARE_KEYSET.client_key,
            PARAMS_TEST_RESHARE.classic_pbs(),
            &mut rng,
            4,
            1,
        )
        .unwrap()
        .swap_remove(0);
        let sizes = ComponentSizes::new(
            PARAMS_TEST_RESHARE,
            DedicatedOprfKeysPresent::from_private_keyset(&keyset),
        )
        .unwrap();
        (keyset, sizes)
    }

    #[test]
    fn check_input_keyset_accepts_valid_keyset() {
        let (keyset, sizes) = valid_reshare_input();
        // Guard against vacuous coverage: every optional component must be present.
        assert!(sizes.sns.is_some());
        assert!(sizes.oprf.is_some());
        assert!(sizes.transciphering.is_some());
        assert!(sizes.compression.is_some());
        assert!(sizes.sns_compression.is_some());
        check_input_keyset(&keyset, PARAMS_TEST_RESHARE, &sizes).unwrap();
    }

    /// One share moved from the GLWE compute key to the LWE compute key keeps the Z128 batch
    /// total unchanged, so only the per-component check detects it.
    #[test]
    fn check_input_keyset_rejects_offsetting_lengths() {
        let (mut keyset, sizes) = valid_reshare_input();
        let moved = keyset
            .glwe_secret_key_share
            .try_cast_mut_to_z128()
            .unwrap()
            .data
            .pop()
            .unwrap();
        keyset
            .lwe_compute_secret_key_share
            .try_cast_mut_to_z128()
            .unwrap()
            .data
            .push(moved);
        let err = check_input_keyset(&keyset, PARAMS_TEST_RESHARE, &sizes).unwrap_err();
        assert!(err.to_string().contains("LWE compute key"), "{err}");
    }

    #[test]
    fn check_input_keyset_rejects_presence_mismatch() {
        // Expected but absent.
        let (mut keyset, sizes) = valid_reshare_input();
        keyset.oprf_secret_key_share = None;
        let err = check_input_keyset(&keyset, PARAMS_TEST_RESHARE, &sizes).unwrap_err();
        assert!(err.to_string().contains("OPRF key"), "{err}");

        // Present but not expected: the reshare would drop it from the output.
        let (keyset, _) = valid_reshare_input();
        let sizes = ComponentSizes::new(
            PARAMS_TEST_RESHARE,
            DedicatedOprfKeysPresent {
                oprf: true,
                transciphering: false,
            },
        )
        .unwrap();
        let err = check_input_keyset(&keyset, PARAMS_TEST_RESHARE, &sizes).unwrap_err();
        assert!(err.to_string().contains("transciphering key"), "{err}");

        let (mut keyset, sizes) = valid_reshare_input();
        keyset.glwe_sns_compression_key_as_lwe = None;
        let err = check_input_keyset(&keyset, PARAMS_TEST_RESHARE, &sizes).unwrap_err();
        assert!(
            err.to_string().contains("GLWE SnS compression key"),
            "{err}"
        );
    }

    #[test]
    fn check_input_keyset_rejects_wrong_ring() {
        let (mut keyset, sizes) = valid_reshare_input();
        keyset.lwe_encryption_secret_key_share =
            LweSecretKeyShareEnum::Z64(keyset.lwe_encryption_secret_key_share.convert_to_z64());
        let err = check_input_keyset(&keyset, PARAMS_TEST_RESHARE, &sizes).unwrap_err();
        assert!(err.to_string().contains("LWE encryption key"), "{err}");
    }

    #[test]
    fn check_input_keyset_rejects_wrong_metadata() {
        let (mut keyset, sizes) = valid_reshare_input();
        keyset
            .glwe_secret_key_share
            .try_cast_mut_to_z128()
            .unwrap()
            .polynomial_size
            .0 *= 2;
        let err = check_input_keyset(&keyset, PARAMS_TEST_RESHARE, &sizes).unwrap_err();
        assert!(err.to_string().contains("GLWE compute key"), "{err}");

        let (mut keyset, sizes) = valid_reshare_input();
        let compression = keyset
            .glwe_secret_key_share_compression
            .as_mut()
            .unwrap()
            .try_cast_mut_to_z128()
            .unwrap();
        compression.post_packing_ks_key.polynomial_size.0 *= 2;
        let err = check_input_keyset(&keyset, PARAMS_TEST_RESHARE, &sizes).unwrap_err();
        assert!(err.to_string().contains("polynomial size"), "{err}");

        let (mut keyset, sizes) = valid_reshare_input();
        let compression = keyset
            .glwe_secret_key_share_compression
            .as_mut()
            .unwrap()
            .try_cast_mut_to_z128()
            .unwrap();
        let CompressionParameters::Classic(params) = &mut compression.params else {
            panic!("test keyset uses classic compression parameters");
        };
        params.lwe_per_glwe.0 += 1;
        let err = check_input_keyset(&keyset, PARAMS_TEST_RESHARE, &sizes).unwrap_err();
        assert!(err.to_string().contains("parameters"), "{err}");
    }

    #[test]
    fn check_batch_lens_zeroizes_on_mismatch() {
        let mut rng = AesRng::seed_from_u64(0);
        let owner = Role::indexed_from_zero(0);
        let mut batch128: Vec<Share<ResiduePoly<Z128, 4>>> = (0..3)
            .map(|_| Share::new(owner, ResiduePoly::sample(&mut rng)))
            .collect();
        let mut batch64: Vec<Share<ResiduePoly<Z64, 4>>> = (0..2)
            .map(|_| Share::new(owner, ResiduePoly::sample(&mut rng)))
            .collect();

        check_batch_lens(&mut batch128, 3, &mut batch64, 2).unwrap();
        assert_eq!((batch128.len(), batch64.len()), (3, 2));

        // Only the Z64 count is wrong, but both batches are wiped.
        check_batch_lens(&mut batch128, 3, &mut batch64, 1).unwrap_err();
        assert!(batch128.is_empty());
        assert!(batch64.is_empty());
    }
}
