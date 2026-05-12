use anyhow::anyhow;
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::{num::Wrapping, sync::Arc};
use tfhe::{
    ClientKey, Seed,
    core_crypto::{
        commons::traits::Numeric,
        entities::{GlweSecretKey, LweSecretKey},
        prelude::{NormalizedHammingWeightBound, UnsignedInteger},
    },
    integer::compression_keys::DecompressionKey,
    prelude::{FheDecrypt, FheEncrypt, ParameterSetConformant, SquashNoise, Tagged},
    shortint::{
        self, ClassicPBSParameters, PBSParameters,
        client_key::atomic_pattern::{AtomicPatternClientKey, StandardAtomicPatternClientKey},
        list_compression::{
            CompressionPrivateKeys, NoiseSquashingCompressionKey,
            NoiseSquashingCompressionPrivateKey,
        },
        parameters::CompressionParameters,
    },
    xof_key_set::CompressedXofKeySet,
    zk::CompactPkeCrs,
};
use tokio::{task::JoinSet, time::timeout_at};

use crate::network_value::NetworkValue;
use crate::{
    runtime::sessions::{
        base_session::BaseSessionHandles, session_parameters::DeSerializationRunTime,
    },
    sharing::input::robust_input,
    tfhe_internals::{
        compression_decompression_key::CompressionPrivateKeyShares, glwe_key::GlweSecretKeyShare,
        lwe_key::LweSecretKeyShare, parameters::DkgMode, private_keysets::LweSecretKeyShareEnum,
    },
};
use algebra::{
    base_ring::{Z64, Z128},
    galois_rings::common::ResiduePoly,
    sharing::{
        shamir::{InputOp, ShamirSharings},
        share::Share,
    },
    structure_traits::{Ring, RingWithExceptionalSequence},
};
use error_utils::anyhow_error_and_log;
use threshold_types::role::Role;

use super::{
    parameters::{DKGParams, DKGParamsBasics},
    private_keysets::{CompressionPrivateKeySharesEnum, GlweSecretKeyShareEnum, PrivateKeySet},
    public_keysets::FhePubKeySet,
};

/// the party ID of the party doing the reconstruction
pub const INPUT_PARTY_ID: usize = 1;

#[derive(Serialize, Deserialize, Clone)]
pub struct KeySet {
    pub client_key: tfhe::ClientKey,
    pub public_keys: FhePubKeySet,
}

impl KeySet {
    pub fn get_raw_lwe_client_key(&self) -> LweSecretKey<Vec<u64>> {
        let (inner_client_key, _, _, _, _, _, _, _) = self.client_key.clone().into_raw_parts();
        match inner_client_key.into_raw_parts().atomic_pattern {
            shortint::client_key::atomic_pattern::AtomicPatternClientKey::Standard(
                standard_atomic_pattern_client_key,
            ) => standard_atomic_pattern_client_key
                .into_raw_parts()
                .1
                .clone(),
            shortint::client_key::atomic_pattern::AtomicPatternClientKey::KeySwitch32(_) => {
                panic!("KeySwitch32 is not supported for now")
            }
        }
    }

    /// Returns the dedicated OPRF private LWE secret key embedded in the
    /// `ClientKey`, or `None` if the keyset was generated without one.
    pub fn get_raw_oprf_client_key(&self) -> Option<LweSecretKey<Vec<u64>>> {
        let (_, _, _, _, _, _, oprf_private_key, _) = self.client_key.clone().into_raw_parts();
        oprf_private_key.map(|sk| match sk.into_raw_parts().into_raw_parts() {
            tfhe::shortint::oprf::AtomicPatternOprfPrivateKey::Standard(lwe) => lwe,
            tfhe::shortint::oprf::AtomicPatternOprfPrivateKey::KeySwitch32(_) => {
                panic!("KeySwitch32 OPRF private key not supported")
            }
        })
    }

    pub fn get_raw_lwe_encryption_client_key(&self) -> LweSecretKey<Vec<u64>> {
        // We should have this key even if the compact PKE parameters are empty
        // because we want to match the behaviour of a normal DKG.
        // In the normal DKG the shares that correspond to the lwe private key
        // is copied to the encryption private key if the compact PKE parameters
        // don't exist.
        let (_, compact_private_key, _, _, _, _, _, _) = self.client_key.clone().into_raw_parts();
        if let Some(inner) = compact_private_key {
            let raw_parts = inner.0.into_raw_parts();
            raw_parts.into_raw_parts().0
        } else {
            self.get_raw_lwe_client_key()
        }
    }

    pub fn get_raw_compression_client_key(&self) -> Option<GlweSecretKey<Vec<u64>>> {
        let (_, _, compression_sk, _, _, _, _, _) = self.client_key.clone().into_raw_parts();
        if let Some(inner) = compression_sk {
            let raw_parts = inner.into_raw_parts();
            Some(raw_parts.post_packing_ks_key)
        } else {
            None
        }
    }

    pub fn get_raw_glwe_client_key(&self) -> GlweSecretKey<Vec<u64>> {
        let (inner_client_key, _, _, _, _, _, _, _) = self.client_key.clone().into_raw_parts();
        match inner_client_key.into_raw_parts().atomic_pattern {
            shortint::client_key::atomic_pattern::AtomicPatternClientKey::Standard(
                standard_atomic_pattern_client_key,
            ) => standard_atomic_pattern_client_key
                .into_raw_parts()
                .0
                .clone(),
            shortint::client_key::atomic_pattern::AtomicPatternClientKey::KeySwitch32(_) => {
                panic!("KeySwitch32 is not supported for now")
            }
        }
    }

    pub fn get_raw_glwe_client_sns_key(&self) -> Option<GlweSecretKey<Vec<u128>>> {
        let (_, _, _, noise_squashing_key, _, _, _, _) = self.client_key.clone().into_raw_parts();
        noise_squashing_key.map(|sns_key| sns_key.into_raw_parts().into_raw_parts().0)
    }

    pub fn get_raw_glwe_client_sns_key_as_lwe(&self) -> Option<LweSecretKey<Vec<u128>>> {
        self.get_raw_glwe_client_sns_key()
            .map(|inner| inner.into_lwe_secret_key())
    }

    pub fn get_raw_sns_compression_client_key(&self) -> Option<GlweSecretKey<Vec<u128>>> {
        let (_, _, _, _, sns_compression_key, _, _, _) = self.client_key.clone().into_raw_parts();
        sns_compression_key
            .map(|sns_compression_key| sns_compression_key.into_raw_parts().into_raw_parts().0)
    }

    pub fn get_raw_sns_compression_client_key_as_lwe(&self) -> Option<LweSecretKey<Vec<u128>>> {
        self.get_raw_sns_compression_client_key()
            .map(|inner| inner.into_lwe_secret_key())
    }

    pub fn get_cpu_params(&self) -> anyhow::Result<ClassicPBSParameters> {
        match self.client_key.computation_parameters() {
            shortint::AtomicPatternParameters::Standard(pbsparameters) => match pbsparameters {
                shortint::PBSParameters::PBS(classic_pbsparameters) => Ok(classic_pbsparameters),
                shortint::PBSParameters::MultiBitPBS(_) => {
                    anyhow::bail!("GPU parameters unsupported")
                }
            },
            shortint::AtomicPatternParameters::KeySwitch32(_) => {
                anyhow::bail!("KS32 parameters unsupported")
            }
        }
    }
}

/// Derives the seed used by tfhe-rs 1.6.1 to create the modulus-switched
/// PRF input. This mirrors `create_random_from_seed_modulus_switched` in
/// tfhe-rs so the expected plaintext is computed independently from the
/// encrypted OPRF path.
pub fn oprf_modulus_switched_seed(
    seed: tfhe_csprng::seeders::Seed,
    random_bits_count: u64,
) -> Vec<u8> {
    use sha3::{Digest, Sha3_256};

    let mut hasher = Sha3_256::default();
    hasher.update(b"TFHE_PRF");
    hasher.update(seed.0.to_le_bytes());
    hasher.update(1u64.to_le_bytes());
    hasher.update(random_bits_count.to_le_bytes());
    hasher.finalize().to_vec()
}

/// Plaintext reference for the shortint OPRF — mirrors
/// `oprf_compare_plain_from_seed` in tfhe-rs (shortint/oprf.rs).
/// Given the PRF's small LWE secret key, a seed, the shortint params, and
/// the `random_bits_count`, returns the expected OPRF output in
/// `[0, 2^random_bits_count)`.
pub fn oprf_expected_plaintext(
    prf_lwe_sk: &tfhe::core_crypto::prelude::LweSecretKeyView<u64>,
    seed: tfhe_csprng::seeders::Seed,
    params: tfhe::shortint::ShortintParameterSet,
    random_bits_count: u64,
) -> u64 {
    use tfhe::core_crypto::commons::math::random::{RandomGenerator, Uniform};
    use tfhe::core_crypto::prelude::{
        CiphertextModulus, DefaultRandomGenerator, LweCiphertextOwned, decrypt_lwe_ciphertext,
    };
    use tfhe_csprng::seeders::XofSeed;

    let lwe_size = params.lwe_dimension().to_lwe_size();
    let polynomial_size = params.polynomial_size();
    let input_p = 2 * polynomial_size.0 as u64;
    let log_input_p = input_p.ilog2() as usize;
    let log_modulus = polynomial_size.to_blind_rotation_input_modulus_log().0;

    let seed = oprf_modulus_switched_seed(seed, random_bits_count);
    let mut xof = RandomGenerator::<DefaultRandomGenerator>::new(XofSeed::new(seed, *b"PRF_INIT"));
    let mask = (0..lwe_size.to_lwe_dimension().0)
        .map(|_| {
            xof.random_from_distribution_custom_mod::<u32, _>(
                Uniform,
                CiphertextModulus::new(input_p as u128),
            ) as u64
        })
        .collect_vec();

    let shift = u64::BITS as usize - log_modulus;
    let container: Vec<u64> = mask
        .into_iter()
        .map(|sample| sample << shift)
        .chain(std::iter::once(0))
        .collect();
    let ct = LweCiphertextOwned::from_container(container, CiphertextModulus::new_native());

    let pt = decrypt_lwe_ciphertext(prf_lwe_sk, &ct).0;
    let plain_prf_input = pt.wrapping_add(1u64 << (u64::BITS as usize - log_input_p - 1))
        >> (u64::BITS as usize - log_input_p);

    tfhe::shortint::oprf::test_utils::cleatext_prf(
        plain_prf_input,
        random_bits_count,
        2 * params.carry_modulus().0 * params.message_modulus().0,
        polynomial_size.0 as u64,
    )
}

/// Verifies that an OPRF server key agrees with the cleartext PRF for a range
/// of seeds.
pub fn assert_oprf_matches_plaintext(
    shortint_ck: &tfhe::shortint::ClientKey,
    target_shortint_server_key: &tfhe::shortint::ServerKey,
    oprf_server_key: &tfhe::shortint::oprf::OprfServerKey,
    prf_lwe_sk: &LweSecretKey<Vec<u64>>,
    num_seeds: u128,
) {
    let shortint_params = shortint_ck.parameters();
    let random_bits_count: u64 = shortint_params.message_modulus().0.ilog2().into();

    for s in 0u128..num_seeds {
        let seed = tfhe_csprng::seeders::Seed(s);
        let img = oprf_server_key.generate_oblivious_pseudo_random(
            seed,
            random_bits_count,
            target_shortint_server_key,
        );
        let actual = shortint_ck.decrypt_message_and_carry(&img);
        let expected = oprf_expected_plaintext(
            &prf_lwe_sk.as_view(),
            seed,
            shortint_params,
            random_bits_count,
        );
        assert_eq!(actual, expected, "OPRF mismatch for seed {s}");
    }
}

pub fn gen_uncompressed_key_set<R>(params: DKGParams, tag: tfhe::Tag, rng: &mut R) -> KeySet
where
    R: Rng + CryptoRng,
{
    let config = params.to_tfhe_config();
    let seed = Seed(rng.r#gen());
    let mut client_key = ClientKey::generate_with_seed(config, seed);
    *client_key.tag_mut() = tag;

    let public_key = tfhe::CompactPublicKey::new(&client_key);
    let server_key = tfhe::ServerKey::new(&client_key);

    let public_keys = FhePubKeySet {
        public_key,
        server_key,
    };
    KeySet {
        client_key,
        public_keys,
    }
}

/// Generate the default [`CompressedXofKeySet`] together with the decompressed [`KeySet`]
/// needed by the test helpers.
///
/// The compressed keyset is decompressed once internally to build the `KeySet`.
// TODO(dp): Not convinced we need two key gen methods (this and gen_uncompressed_key_set). There's something weird with
// this method: why do we need to return both compressed and uncompressed keys? Re-visit once the tests are sorted.
#[allow(unknown_lints)]
#[allow(non_local_effect_before_error_return)]
pub fn gen_key_set<R>(
    params: DKGParams,
    tag: tfhe::Tag,
    rng: &mut R,
) -> anyhow::Result<(KeySet, CompressedXofKeySet)>
where
    R: Rng + CryptoRng,
{
    let config = params.to_tfhe_config();
    let seed_bytes = Seed(rng.r#gen()).0.to_le_bytes().to_vec();
    let security_bits = params.get_params_basics_handle().get_sec() as u32;

    // If pmax is not set (e.g. test parameters), use 1.0 to allow any HW.
    let pmax = params
        .get_params_basics_handle()
        .get_sk_deviations()
        .map(|x| x.pmax)
        .unwrap_or(1.0);
    let max_norm_hwt = NormalizedHammingWeightBound::new(pmax)
        .ok_or_else(|| anyhow!("Invalid Hamming Weight bound, range must be ]0.5,1.0]"))?;

    // TODO(dp): It's a bit annoying that `generate` can't return the `ServerKey` we need, forcing us to
    // decompress to get it. Should be possible to get all 4 keys in one go?
    let (client_key, compressed_keyset) =
        CompressedXofKeySet::generate(config, seed_bytes, security_bits, max_norm_hwt, tag)?;

    // Decompress once to get the public keys needed for KeySet / share generation.
    let (public_key, server_key) = compressed_keyset.decompress()?.into_raw_parts();

    let keyset = KeySet {
        client_key,
        public_keys: FhePubKeySet {
            public_key,
            server_key,
        },
    };
    Ok((keyset, compressed_keyset))
}

/// Helper struct to hold raw key containers extracted from a ClientKey.
/// All fields except `lwe_sk` and `glwe_sk` are optional depending on parameters.
struct RawKeyContainers {
    lwe_sk_container64: Vec<u64>,
    lwe_encryption_sk_container64: Vec<u64>,
    glwe_sk_container64: Vec<u64>,
    compression_sk_container64: Option<Vec<u64>>,
    sns_sk_container128: Option<Vec<u128>>,
    sns_compression_sk_container128: Option<Vec<u128>>,
    oprf_sk_container64: Vec<u64>,
}

/// Extract raw key containers from a KeySet or create zero-filled placeholders.
///
/// NOTE: For non-input parties, we use zero-filled vectors instead of empty vectors.
/// This is a hack to ensure that all parties wait for the input party to generate
/// the keyset and distribute the secret key vectors. If we used empty vectors,
/// the other parties would continue to transfer_pk and would panic because they
/// would receive something different from a PK.
fn extract_key_containers(
    keyset: Option<&KeySet>,
    params: DKGParams,
) -> anyhow::Result<RawKeyContainers> {
    let params_basic_handle = params.get_params_basics_handle();

    let lwe_sk_container64: Vec<u64> = keyset
        .map(|s| s.clone().get_raw_lwe_client_key().into_container())
        .unwrap_or_else(|| vec![Numeric::ZERO; params_basic_handle.lwe_dimension().0]);

    let lwe_encryption_sk_container64: Vec<u64> = keyset
        .map(|s| {
            s.clone()
                .get_raw_lwe_encryption_client_key()
                .into_container()
        })
        .unwrap_or_else(|| vec![Numeric::ZERO; params_basic_handle.lwe_hat_dimension().0]);

    let glwe_sk_container64: Vec<u64> = keyset
        .map(|s| s.clone().get_raw_glwe_client_key().into_container())
        .unwrap_or_else(|| vec![Numeric::ZERO; params_basic_handle.glwe_sk_num_bits()]);

    let sns_sk_container128: Option<Vec<u128>> = if let DKGParams::WithSnS(params_sns) = params {
        Some(
            keyset
                .and_then(|s| {
                    s.clone()
                        .get_raw_glwe_client_sns_key()
                        .map(|x| x.into_container())
                })
                .unwrap_or_else(|| vec![Numeric::ZERO; params_sns.glwe_sk_num_bits_sns()]),
        )
    } else {
        None
    };

    // Check compression key consistency
    if let Some(ks) = keyset
        && ks.get_raw_compression_client_key().is_none()
        && params_basic_handle
            .get_compression_decompression_params()
            .is_some()
    {
        anyhow::bail!("Compression client key is missing when parameter is available")
    }

    let compression_sk_container64: Option<Vec<u64>> = match keyset {
        Some(s) => {
            if params_basic_handle
                .get_compression_decompression_params()
                .is_none()
            {
                None
            } else {
                s.clone()
                    .get_raw_compression_client_key()
                    .map(|x| x.into_container())
            }
        }
        None => {
            if params_basic_handle
                .get_compression_decompression_params()
                .is_none()
            {
                None
            } else {
                Some(vec![
                    Numeric::ZERO;
                    params_basic_handle.compression_sk_num_bits()
                ])
            }
        }
    };

    let sns_compression_sk_container128: Option<Vec<u128>> = match keyset {
        Some(s) => {
            if params_basic_handle.get_sns_compression_params().is_none() {
                None
            } else {
                s.clone()
                    .get_raw_sns_compression_client_key()
                    .map(|x| x.into_container())
            }
        }
        None => {
            if let DKGParams::WithSnS(params_sns) = params {
                params_sns
                    .sns_compression_params
                    .map(|_sns_compression_params| {
                        vec![Numeric::ZERO; params_sns.sns_compression_sk_num_bits()]
                    })
            } else {
                None
            }
        }
    };

    let oprf_sk_container64: Vec<u64> = keyset
        .and_then(|s| s.get_raw_oprf_client_key().map(|k| k.into_container()))
        .unwrap_or_else(|| vec![Numeric::ZERO; params_basic_handle.lwe_dimension().0]);

    Ok(RawKeyContainers {
        lwe_sk_container64,
        lwe_encryption_sk_container64,
        glwe_sk_container64,
        compression_sk_container64,
        sns_sk_container128,
        sns_compression_sk_container128,
        oprf_sk_container64,
    })
}

/// Shares private key material from a ClientKey with all parties using robust_input.
/// Returns the PrivateKeySet for this party.
///
/// This function extracts the private keys from the keyset (if the current party is the input party)
/// and shares them with all other parties via secret sharing.
async fn share_client_key_material<S: BaseSessionHandles, const EXTENSION_DEGREE: usize>(
    session: &mut S,
    params: DKGParams,
    keyset: Option<&KeySet>,
) -> anyhow::Result<PrivateKeySet<EXTENSION_DEGREE>>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
{
    let params_basic_handle = params.get_params_basics_handle();
    let own_role = session.my_role();
    let is_input_party = own_role.one_based() == INPUT_PARTY_ID;

    let raw_keys = extract_key_containers(keyset, params)?;

    // Share lwe_sk
    tracing::debug!(
        "I'm {:?}, Sharing key64 to be sent: len {}",
        session.my_role(),
        raw_keys.lwe_sk_container64.len()
    );
    let secrets = if is_input_party {
        Some(
            raw_keys
                .lwe_sk_container64
                .iter()
                .map(|cur| ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<u64>(*cur)))
                .collect_vec(),
        )
    } else {
        None
    };
    let lwe_key_shares64 = robust_input(session, &secrets, &own_role, INPUT_PARTY_ID).await?;

    // Share lwe_encryption_sk
    tracing::debug!(
        "I'm {:?}, Sharing encryption key64 to be sent: len {}",
        session.my_role(),
        raw_keys.lwe_encryption_sk_container64.len()
    );
    let secrets = if is_input_party {
        Some(
            raw_keys
                .lwe_encryption_sk_container64
                .iter()
                .map(|cur| ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<u64>(*cur)))
                .collect_vec(),
        )
    } else {
        None
    };
    let lwe_encryption_key_shares64 =
        robust_input(session, &secrets, &own_role, INPUT_PARTY_ID).await?;

    // Share the dedicated OPRF LWE secret key
    tracing::debug!(
        "I'm {:?}, Sharing OPRF key64 to be sent: len {}",
        session.my_role(),
        raw_keys.oprf_sk_container64.len()
    );
    let secrets = if is_input_party {
        Some(
            raw_keys
                .oprf_sk_container64
                .iter()
                .map(|cur| ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<u64>(*cur)))
                .collect_vec(),
        )
    } else {
        None
    };
    let oprf_key_shares64 = robust_input(session, &secrets, &own_role, INPUT_PARTY_ID).await?;

    // Share glwe_sk
    tracing::debug!(
        "I'm {:?}, Sharing glwe client key 64 to be sent: len {}",
        session.my_role(),
        raw_keys.glwe_sk_container64.len(),
    );
    let secrets = if is_input_party {
        Some(
            raw_keys
                .glwe_sk_container64
                .iter()
                .map(|cur| {
                    ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<u128>((*cur).into()))
                })
                .collect_vec(),
        )
    } else {
        None
    };
    let glwe_key_shares128 = robust_input(session, &secrets, &own_role, INPUT_PARTY_ID).await?;

    // Share sns_sk (if present)
    let sns_key_shares128 = if let Some(sns_sk_container128) = raw_keys.sns_sk_container128 {
        tracing::debug!(
            "I'm {:?}, Sharing key128 to be sent: len {}",
            session.my_role(),
            sns_sk_container128.len()
        );
        let secrets = if is_input_party {
            Some(
                sns_sk_container128
                    .iter()
                    .map(|cur| {
                        ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<u128>(*cur))
                    })
                    .collect_vec(),
            )
        } else {
            None
        };
        let sns_key_shares128 = robust_input(session, &secrets, &own_role, INPUT_PARTY_ID).await?;

        Some(LweSecretKeyShare {
            data: sns_key_shares128,
        })
    } else {
        None
    };

    // Share compression_sk (if present)
    tracing::debug!(
        "I'm {:?}, Sharing compression key: len {:?}",
        session.my_role(),
        raw_keys
            .compression_sk_container64
            .as_ref()
            .map(|x| x.len()),
    );
    let mut glwe_compression_key_shares128 = Vec::new();
    if let Some(compression_container) = raw_keys.compression_sk_container64 {
        let secrets = if is_input_party {
            Some(
                compression_container
                    .iter()
                    .map(|cur| {
                        ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<u128>(
                            (*cur).into(),
                        ))
                    })
                    .collect_vec(),
            )
        } else {
            None
        };
        glwe_compression_key_shares128 =
            robust_input(session, &secrets, &own_role, INPUT_PARTY_ID).await?;
    };

    // Share sns_compression_sk (if present)
    tracing::debug!(
        "I'm {:?}, Sharing sns compression key: len {:?}",
        session.my_role(),
        raw_keys
            .sns_compression_sk_container128
            .as_ref()
            .map(|x| x.len()),
    );
    let mut glwe_sns_compression_key_shares128 = Vec::new();
    if let Some(compression_container) = raw_keys.sns_compression_sk_container128 {
        let secrets = if is_input_party {
            Some(
                compression_container
                    .iter()
                    .map(|cur| {
                        ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<u128>(*cur))
                    })
                    .collect_vec(),
            )
        } else {
            None
        };
        glwe_sns_compression_key_shares128 =
            robust_input(session, &secrets, &own_role, INPUT_PARTY_ID).await?;
    };

    tracing::debug!("I'm {:?}, private keys are all sent", session.my_role());

    let glwe_secret_key_share_compression = params_basic_handle
        .get_compression_decompression_params()
        .map(|compression_params| {
            let params = compression_params.raw_compression_parameters;
            CompressionPrivateKeySharesEnum::Z128(CompressionPrivateKeyShares {
                post_packing_ks_key: GlweSecretKeyShare {
                    data: glwe_compression_key_shares128,
                    polynomial_size: params.packing_ks_polynomial_size,
                },
                params: CompressionParameters::Classic(params),
            })
        });

    let glwe_sns_compression_key_as_lwe =
        params_basic_handle
            .get_sns_compression_params()
            .map(|_sns_compression_params| LweSecretKeyShare {
                data: glwe_sns_compression_key_shares128,
            });

    Ok(PrivateKeySet {
        lwe_compute_secret_key_share: LweSecretKeyShareEnum::Z64(LweSecretKeyShare {
            data: lwe_key_shares64,
        }),
        lwe_encryption_secret_key_share: LweSecretKeyShareEnum::Z64(LweSecretKeyShare {
            data: lwe_encryption_key_shares64,
        }),
        oprf_secret_key_share: Some(LweSecretKeyShareEnum::Z64(LweSecretKeyShare {
            data: oprf_key_shares64,
        })),
        glwe_secret_key_share: GlweSecretKeyShareEnum::Z128(GlweSecretKeyShare {
            data: glwe_key_shares128,
            polynomial_size: params_basic_handle.polynomial_size(),
        }),
        glwe_secret_key_share_sns_as_lwe: sns_key_shares128,
        parameters: params_basic_handle.to_classic_pbs_parameters(),
        glwe_secret_key_share_compression,
        glwe_sns_compression_key_as_lwe,
    })
}

/// This is an insecure way to initialize the key materials in a distributed setting.
/// Party 1 generates the full keyset and shares the private keys with all other parties.
pub async fn insecure_initialize_key_material<
    S: BaseSessionHandles,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut S,
    params: DKGParams,
    tag: tfhe::Tag,
) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
{
    let params_basic_handle = params.get_params_basics_handle();

    // This only supports Z128 DKG for now
    if params_basic_handle.get_dkg_mode() != DkgMode::Z128 {
        anyhow::bail!(
            "Incompatible DKG mode, expected Z128 got {:?}",
            params_basic_handle.get_dkg_mode()
        );
    }

    // Keys are big so we use rayon for (de)serialization
    session.set_deserialization_runtime(DeSerializationRunTime::Rayon);
    let own_role = session.my_role();

    let keyset = if own_role.one_based() == INPUT_PARTY_ID {
        tracing::info!("Keyset generated by input party {}", own_role);
        Some(gen_uncompressed_key_set(params, tag, &mut session.rng()))
    } else {
        None
    };

    // Share private keys with all parties
    let private_key_set = share_client_key_material(session, params, keyset.as_ref()).await?;

    // Transfer the public key set
    let transferred_pub_key =
        transfer_pub_key(session, keyset.map(|set| set.public_keys), INPUT_PARTY_ID).await?;

    Ok((transferred_pub_key, private_key_set))
}

/// This is an insecure way to initialize compressed key materials in a distributed setting.
/// Party 1 generates the full compressed keyset and shares the private keys with all other parties.
pub async fn initialize_compressed_key_material<
    S: BaseSessionHandles,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut S,
    params: DKGParams,
    tag: tfhe::Tag,
) -> anyhow::Result<(
    tfhe::xof_key_set::CompressedXofKeySet,
    PrivateKeySet<EXTENSION_DEGREE>,
)>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
{
    let params_basic_handle = params.get_params_basics_handle();

    // This only supports Z128 DKG for now
    if params_basic_handle.get_dkg_mode() != DkgMode::Z128 {
        anyhow::bail!(
            "Incompatible DKG mode, expected Z128 got {:?}",
            params_basic_handle.get_dkg_mode()
        );
    }

    // Keys are big so we use rayon for (de)serialization
    session.set_deserialization_runtime(DeSerializationRunTime::Rayon);
    let own_role = session.my_role();

    // Party 1 generates the compressed keyset
    let (keyset, compressed_keyset) = if own_role.one_based() == INPUT_PARTY_ID {
        tracing::info!("Compressed keyset generated by input party {}", own_role);
        let config = params.to_tfhe_config();

        // if the pmax value is not set, e.g., for test parameters, we do not do the HW check
        // and use a pmax=1 which should allow for any HW.
        let max_norm_hwt = params_basic_handle
            .get_sk_deviations()
            .map(|d| d.pmax)
            .unwrap_or(1.0);
        let max_norm_hwt =
            tfhe::core_crypto::prelude::NormalizedHammingWeightBound::new(max_norm_hwt).unwrap();

        // Generate seed bytes
        let private_seed_bytes: Vec<u8> = Seed(session.rng().r#gen()).0.to_le_bytes().to_vec();

        let (client_key, compressed_xof_keyset) = tfhe::xof_key_set::CompressedXofKeySet::generate(
            config,
            private_seed_bytes,
            params_basic_handle.get_sec() as u32,
            max_norm_hwt,
            tag,
        )
        .expect("Failed to generate compressed keyset");

        // Create a temporary KeySet to use the existing helper functions
        let public_key = tfhe::CompactPublicKey::new(&client_key);
        let server_key = tfhe::ServerKey::new(&client_key);
        let keyset = KeySet {
            client_key,
            public_keys: FhePubKeySet {
                public_key,
                server_key,
            },
        };

        (Some(keyset), Some(compressed_xof_keyset))
    } else {
        (None, None)
    };

    // Share private keys with all parties
    let private_key_set = share_client_key_material(session, params, keyset.as_ref()).await?;

    // Transfer the compressed keyset
    let transferred_compressed_keyset =
        transfer_compressed_keyset(session, compressed_keyset, INPUT_PARTY_ID).await?;

    Ok((transferred_compressed_keyset, private_key_set))
}

pub async fn transfer_pub_key<S: BaseSessionHandles>(
    session: &S,
    pubkey: Option<FhePubKeySet>,
    input_party_id: usize,
) -> anyhow::Result<FhePubKeySet> {
    let pkval = pubkey.map(|inner| NetworkValue::<Z128>::PubKeySet(Box::new(inner)));
    let network_val = transfer_network_value(session, pkval, input_party_id).await?;
    match network_val {
        NetworkValue::PubKeySet(pk) => Ok(*pk),
        e => Err(anyhow_error_and_log(format!(
            "Expected PubKeySet network message but got {}",
            e.network_type_name()
        )))?,
    }
}

pub async fn transfer_compressed_keyset<S: BaseSessionHandles>(
    session: &S,
    compressed_keyset: Option<tfhe::xof_key_set::CompressedXofKeySet>,
    input_party_id: usize,
) -> anyhow::Result<tfhe::xof_key_set::CompressedXofKeySet> {
    let keyset_networkval =
        compressed_keyset.map(|inner| NetworkValue::<Z128>::CompressedXofKeySet(Box::new(inner)));
    let network_val = transfer_network_value(session, keyset_networkval, input_party_id).await?;
    match network_val {
        NetworkValue::CompressedXofKeySet(keyset) => Ok(*keyset),
        e => Err(anyhow_error_and_log(format!(
            "Expected CompressedXofKeySet network message but got {}",
            e.network_type_name()
        )))?,
    }
}

pub async fn transfer_sns_compression_key<S: BaseSessionHandles>(
    session: &S,
    key: Option<NoiseSquashingCompressionKey>,
    input_party_id: usize,
) -> anyhow::Result<NoiseSquashingCompressionKey> {
    let key_networkval = key.map(|inner| NetworkValue::<Z128>::SnsCompressionKey(Box::new(inner)));
    let network_val = transfer_network_value(session, key_networkval, input_party_id).await?;
    match network_val {
        NetworkValue::SnsCompressionKey(k) => Ok(*k),
        e => Err(anyhow_error_and_log(format!(
            "Expected SnsCompressionKey network message but got {}",
            e.network_type_name()
        )))?,
    }
}

/// Send the CRS to the other parties, if I am the input party in this session. Else receive the CRS.
pub async fn transfer_crs<S: BaseSessionHandles>(
    session: &S,
    some_crs: Option<CompactPkeCrs>,
    input_party_id: usize,
) -> anyhow::Result<CompactPkeCrs> {
    let crs = some_crs.map(|inner| NetworkValue::<Z128>::Crs(Box::new(inner)));
    let network_val = transfer_network_value(session, crs, input_party_id).await?;
    match network_val {
        NetworkValue::Crs(crs) => Ok(*crs),
        e => Err(anyhow_error_and_log(format!(
            "Expected Crs network message but got {}",
            e.network_type_name()
        )))?,
    }
}

pub async fn transfer_decompression_key<S: BaseSessionHandles>(
    session: &S,
    decompression_key: Option<DecompressionKey>,
    input_party_id: usize,
) -> anyhow::Result<DecompressionKey> {
    let decompression_key =
        decompression_key.map(|inner| NetworkValue::<Z128>::DecompressionKey(Box::new(inner)));
    let network_val = transfer_network_value(session, decompression_key, input_party_id).await?;
    match network_val {
        NetworkValue::DecompressionKey(dk) => Ok(*dk),
        _ => Err(anyhow_error_and_log(
            "I have received something different from a DecompressionKey!",
        ))?,
    }
}

async fn transfer_network_value<S: BaseSessionHandles>(
    session: &S,
    network_value: Option<NetworkValue<Z128>>,
    input_party_id: usize,
) -> anyhow::Result<NetworkValue<Z128>> {
    // We are transferring only big things here, so always pick rayon
    let deserialization_runtime = DeSerializationRunTime::Rayon;
    session.network().increase_round_counter().await;
    if session.my_role().one_based() == input_party_id {
        // send the value
        let network_val =
            network_value.ok_or_else(|| anyhow_error_and_log("I have no value to send!"))?;
        let num_parties = session.num_parties();
        tracing::debug!(
            "I'm the input party. Sending value to {} other parties...",
            num_parties - 1
        );

        let mut set = JoinSet::new();
        let buf_to_send = Arc::new(network_val.clone().to_network());
        for receiver in 1..=num_parties {
            if receiver != input_party_id {
                let networking = Arc::clone(session.network());

                let cloned_buf = buf_to_send.clone();
                set.spawn(async move {
                    let _ = networking
                        .send(cloned_buf, &Role::indexed_from_one(receiver))
                        .await;
                });
            }
        }
        while (set.join_next().await).is_some() {}
        Ok(network_val)
    } else {
        // receive the value
        let networking = Arc::clone(session.network());
        let timeout = session.network().get_timeout_current_round().await;
        tracing::debug!(
            "Waiting to receive value from input party with timeout {:?}",
            timeout
        );
        let data = tokio::spawn(timeout_at(timeout.into(), async move {
            networking
                .receive(&Role::indexed_from_one(input_party_id))
                .await
        }))
        .await??;

        Ok(NetworkValue::<Z128>::from_network(data, deserialization_runtime).await?)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn to_hl_client_key(
    params: &DKGParams,
    tag: tfhe::Tag,
    lwe_secret_key: LweSecretKey<Vec<u64>>,
    glwe_secret_key: GlweSecretKey<Vec<u64>>,
    dedicated_compact_private_key: Option<LweSecretKey<Vec<u64>>>,
    compression_key: Option<GlweSecretKey<Vec<u64>>>,
    sns_secret_key: Option<GlweSecretKey<Vec<u128>>>,
    sns_compression_secret_key: Option<NoiseSquashingCompressionPrivateKey>,
    oprf_private_lwe_sk: Option<LweSecretKey<Vec<u64>>>,
) -> anyhow::Result<tfhe::ClientKey> {
    let regular_params = match params {
        DKGParams::WithSnS(p) => p.regular_params,
        DKGParams::WithoutSnS(p) => *p,
    };
    let ciphertext_params = regular_params.ciphertext_parameters;

    let sck = StandardAtomicPatternClientKey::from_raw_parts(
        glwe_secret_key,
        lwe_secret_key,
        PBSParameters::PBS(ciphertext_params),
        None,
    );
    let sck = shortint::ClientKey {
        atomic_pattern: AtomicPatternClientKey::Standard(sck),
    };

    //If necessary generate a dedicated compact private key
    let dedicated_compact_private_key =
        if let (Some(dedicated_compact_private_key), Some(pk_params)) = (
            dedicated_compact_private_key,
            regular_params.get_dedicated_pk_params(),
        ) {
            Some((
                tfhe::integer::CompactPrivateKey::from_raw_parts(
                    tfhe::shortint::CompactPrivateKey::from_raw_parts(
                        dedicated_compact_private_key,
                        pk_params.0,
                    )?,
                ),
                pk_params.1,
            ))
        } else {
            None
        };

    //If necessary generate a dedicated compression private key
    let compression_key = if let (Some(compression_private_key), Some(params)) = (
        compression_key,
        regular_params.get_compression_decompression_params(),
    ) {
        let polynomial_size = compression_private_key.polynomial_size();
        Some(
            tfhe::integer::compression_keys::CompressionPrivateKeys::from_raw_parts(
                CompressionPrivateKeys {
                    post_packing_ks_key: GlweSecretKey::from_container(
                        compression_private_key.into_container(),
                        polynomial_size,
                    ),
                    params: CompressionParameters::Classic(params.raw_compression_parameters),
                },
            ),
        )
    } else {
        None
    };

    // If necessary generate a dedicated noise squashing private key
    let noise_squashing_key = match (sns_secret_key, params) {
        (None, DKGParams::WithoutSnS(_)) => None,
        (None, DKGParams::WithSnS(_)) => {
            anyhow::bail!("missing noise squashing secret key")
        }
        (Some(_), DKGParams::WithoutSnS(_)) => {
            anyhow::bail!("missing noise squashing parameters")
        }
        (Some(sns_sk), DKGParams::WithSnS(sns_params)) => Some(
            tfhe::integer::noise_squashing::NoiseSquashingPrivateKey::from_raw_parts(
                tfhe::shortint::noise_squashing::NoiseSquashingPrivateKey::from_raw_parts(
                    sns_sk,
                    sns_params.sns_params,
                ),
            ),
        ),
    };

    let sns_compression_key = sns_compression_secret_key
        .map(tfhe::integer::ciphertext::NoiseSquashingCompressionPrivateKey::from_raw_parts);

    let oprf_private_key = oprf_private_lwe_sk.map(|lwe_sk| {
        tfhe::integer::oprf::OprfPrivateKey::from_raw_parts(
            tfhe::shortint::oprf::OprfPrivateKey::from_raw_parts(
                tfhe::shortint::oprf::AtomicPatternOprfPrivateKey::Standard(lwe_sk),
            ),
        )
    });

    Ok(ClientKey::from_raw_parts(
        sck.into(),
        dedicated_compact_private_key,
        compression_key,
        noise_squashing_key,
        sns_compression_key,
        regular_params.get_rerand_params().map(Into::into),
        oprf_private_key,
        tag,
    ))
}

/// Helper function to generate secret key shares
#[allow(clippy::type_complexity)]
fn secret_share_key_shares<
    R: Rng + CryptoRng,
    const EXTENSION_DEGREE: usize,
    Scalar: UnsignedInteger,
    Z,
>(
    secret_key_container: Vec<Scalar>,
    num_parties: usize,
    threshold: usize,
    rng: &mut R,
) -> anyhow::Result<Vec<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: RingWithExceptionalSequence,
    Z: Ring,
{
    let s_length = secret_key_container.len();
    let mut res: Vec<Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>> =
        vec![Vec::with_capacity(s_length); num_parties];

    // for each bit in the secret key generate all parties shares
    for (i, bit) in secret_key_container.into_iter().enumerate() {
        let embedded_secret =
            ResiduePoly::<Z, EXTENSION_DEGREE>::from_scalar(Z::from_u128(bit.cast_into()));
        let shares = ShamirSharings::share(rng, embedded_secret, num_parties, threshold)?;
        for (v, share) in res.iter_mut().zip_eq(shares.shares) {
            v.insert(i, share);
        }
    }

    Ok(res)
}

/// Keygen that generates secret key shares for many parties.
///
/// __NOTE__: Some secret keys are actually dummy or None, what we really need here are the key
/// passed as input.
// TODO(dp): is this slow?
pub fn keygen_all_party_shares_from_keyset<R, const EXTENSION_DEGREE: usize>(
    keyset: &KeySet,
    parameters: ClassicPBSParameters,
    rng: &mut R,
    num_parties: usize,
    threshold: usize,
) -> anyhow::Result<Vec<PrivateKeySet<EXTENSION_DEGREE>>>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: RingWithExceptionalSequence,
    ResiduePoly<Z64, EXTENSION_DEGREE>: RingWithExceptionalSequence,
    R: Rng + CryptoRng,
{
    let lwe_secret_key = keyset.get_raw_lwe_client_key();

    let lwe_encryption_secret_key = keyset.get_raw_lwe_encryption_client_key();
    let glwe_secret_key = keyset.get_raw_glwe_client_key();
    let glwe_secret_key_sns_as_lwe = keyset.get_raw_glwe_client_sns_key_as_lwe().unwrap();
    let glwe_secret_key_sns_compression_as_lwe = keyset.get_raw_sns_compression_client_key_as_lwe();
    let oprf_secret_key = keyset.get_raw_oprf_client_key();
    keygen_all_party_shares(
        lwe_secret_key,
        lwe_encryption_secret_key,
        glwe_secret_key,
        glwe_secret_key_sns_as_lwe,
        glwe_secret_key_sns_compression_as_lwe,
        oprf_secret_key,
        parameters,
        rng,
        num_parties,
        threshold,
    )
}

#[allow(clippy::too_many_arguments)]
fn keygen_all_party_shares<R: Rng + CryptoRng, const EXTENSION_DEGREE: usize>(
    lwe_secret_key: LweSecretKey<Vec<u64>>,
    lwe_encryption_secret_key: LweSecretKey<Vec<u64>>,
    glwe_secret_key: GlweSecretKey<Vec<u64>>,
    glwe_secret_key_sns_as_lwe: LweSecretKey<Vec<u128>>,
    glwe_secreet_key_sns_compression_as_lwe: Option<LweSecretKey<Vec<u128>>>,
    oprf_secret_key: Option<LweSecretKey<Vec<u64>>>,
    parameters: ClassicPBSParameters,
    rng: &mut R,
    num_parties: usize,
    threshold: usize,
) -> anyhow::Result<Vec<PrivateKeySet<EXTENSION_DEGREE>>>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: RingWithExceptionalSequence,
    ResiduePoly<Z64, EXTENSION_DEGREE>: RingWithExceptionalSequence,
{
    // for each bit in the secret key generate all parties shares
    let vv128: Vec<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>> = secret_share_key_shares(
        glwe_secret_key_sns_as_lwe.into_container(),
        num_parties,
        threshold,
        rng,
    )?;

    // do the same for 64 bit lwe key
    let vv128_lwe_key: Vec<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>> =
        secret_share_key_shares(lwe_secret_key.into_container(), num_parties, threshold, rng)?;

    // do the same for 64 bit lwe encryption key
    let vv128_lwe_enc_key: Vec<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>> =
        secret_share_key_shares(
            lwe_encryption_secret_key.into_container(),
            num_parties,
            threshold,
            rng,
        )?;

    // share the dedicated OPRF LWE key (if provided)
    let vv128_oprf_key: Option<Vec<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>> =
        match oprf_secret_key {
            Some(sk) => Some(secret_share_key_shares(
                sk.into_container(),
                num_parties,
                threshold,
                rng,
            )?),
            None => None,
        };

    // do the same for 128 bit glwe key, this is how we generate it normally
    let glwe_poly_size = glwe_secret_key.polynomial_size();
    let s_vector128 = glwe_secret_key
        .into_container()
        .into_iter()
        .map(|x| x as u128)
        .collect_vec();
    let vv128_glwe_key: Vec<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>> =
        secret_share_key_shares(s_vector128, num_parties, threshold, rng)?;

    // optionally share the sns compression secret key
    let all_glwe_sns_compression_key_as_lwe = match glwe_secreet_key_sns_compression_as_lwe {
        Some(inner) => Some(secret_share_key_shares(
            inner.into_container(),
            num_parties,
            threshold,
            rng,
        )?),
        None => None,
    };

    // put the individual parties shares into SecretKeyShare structs
    let shared_sks: Vec<_> = (0..num_parties)
        .map(|p| PrivateKeySet {
            lwe_compute_secret_key_share: LweSecretKeyShareEnum::Z128(LweSecretKeyShare {
                data: vv128_lwe_key[p].clone(),
            }),
            lwe_encryption_secret_key_share: LweSecretKeyShareEnum::Z128(LweSecretKeyShare {
                data: vv128_lwe_enc_key[p].clone(),
            }),
            oprf_secret_key_share: vv128_oprf_key
                .as_ref()
                .map(|x| LweSecretKeyShareEnum::Z128(LweSecretKeyShare { data: x[p].clone() })),
            glwe_secret_key_share: GlweSecretKeyShareEnum::Z128(GlweSecretKeyShare {
                data: vv128_glwe_key[p].clone(),
                polynomial_size: glwe_poly_size,
            }),
            glwe_secret_key_share_sns_as_lwe: Some(LweSecretKeyShare {
                data: vv128[p].clone(),
            }),
            parameters,
            // the below is not really used for any computation
            glwe_secret_key_share_compression: None,
            glwe_sns_compression_key_as_lwe: all_glwe_sns_compression_key_as_lwe
                .as_ref()
                .map(|x| LweSecretKeyShare { data: x[p].clone() }),
        })
        .collect();

    Ok(shared_sks)
}

impl PartialEq for FhePubKeySet {
    fn eq(&self, other: &Self) -> bool {
        // check the public keys are the same
        let ok1 = {
            let (pk, tag) = self.public_key.clone().into_raw_parts();
            let (other_pk, other_tag) = other.clone().public_key.into_raw_parts();
            pk.into_raw_parts() == other_pk.into_raw_parts() && tag == other_tag
        };

        let (sks, ksk, comp, decomp, sns, _sns_comp, _rerand_key, _oprf, tag) =
            self.server_key.clone().into_raw_parts();
        let (
            other_sks,
            other_ksk,
            other_comp,
            other_decomp,
            other_sns,
            _other_sns_comp,
            _other_rerand_key,
            _other_oprf,
            other_tag,
        ) = other.server_key.clone().into_raw_parts();

        // TODO: Can't compare the sns compression keys, and can't call into_raw_parts on them either.
        let ok2 = sks.into_raw_parts() == other_sks.into_raw_parts()
            && ksk.map(|x| x.into_raw_parts()) == other_ksk.map(|x| x.into_raw_parts())
            && comp.map(|x| x.into_raw_parts()) == other_comp.map(|x| x.into_raw_parts())
            && decomp.map(|x| x.into_raw_parts()) == other_decomp.map(|x| x.into_raw_parts())
            && sns.map(|x| x.into_raw_parts()) == other_sns.map(|x| x.into_raw_parts())
            && tag == other_tag;

        ok1 && ok2
    }
}

pub fn run_decompression_test(
    keyset1_client_key: &tfhe::ClientKey,
    keyset2_client_key: &tfhe::ClientKey,
    keyset1_server_key: Option<&tfhe::ServerKey>,
    decompression_key: tfhe::shortint::list_compression::DecompressionKey,
) {
    // do some sanity checks
    let server_key1 = match keyset1_server_key {
        Some(inner) => inner,
        None => &keyset1_client_key.generate_server_key(),
    };
    let (_, _, _, decompression_key1, _, _, _, _, _) = server_key1.clone().into_raw_parts();
    let decompression_key1 = decompression_key1.unwrap().into_raw_parts();

    assert_eq!(
        decompression_key1.out_glwe_size(),
        decompression_key.out_glwe_size()
    );

    // Deconstruct to get access to blind_rotate_key
    let (bsk_dec_1, ctxt_count_dec_1) = decompression_key1.into_raw_parts();
    let (bsk_dec, ctxt_count_dec) = decompression_key.into_raw_parts();

    assert_eq!(
        bsk_dec_1.input_lwe_dimension(),
        bsk_dec.input_lwe_dimension(),
    );

    //Reconstruct
    let decompression_key1 = tfhe::shortint::list_compression::DecompressionKey::from_raw_parts(
        bsk_dec_1,
        ctxt_count_dec_1,
    );
    let decompression_key =
        tfhe::shortint::list_compression::DecompressionKey::from_raw_parts(bsk_dec, ctxt_count_dec);

    assert_eq!(
        decompression_key1.output_lwe_dimension(),
        decompression_key.output_lwe_dimension(),
    );
    assert_eq!(
        decompression_key1.out_polynomial_size(),
        decompression_key.out_polynomial_size(),
    );

    let decompression_key =
        tfhe::integer::compression_keys::DecompressionKey::from_raw_parts(decompression_key);
    // create a ciphertext using keyset 1
    tfhe::set_server_key(server_key1.clone());
    let pt = 12u32;
    let ct = tfhe::FheUint32::encrypt(pt, keyset1_client_key);
    let compressed_ct = tfhe::CompressedCiphertextListBuilder::new()
        .push(ct)
        .build()
        .unwrap();

    // then decompression it into keyset 2
    println!("Decompression ct under keyset1 to keyset2");
    let (radix_ciphertext, _, _) = compressed_ct.into_raw_parts();
    let ct2: tfhe::FheUint32 = radix_ciphertext
        .get(0, &decompression_key)
        .unwrap()
        .unwrap();

    // finally check we can decrypt it using the client key from keyset 2
    println!("Attempting to decrypt under keyset2");
    let pt2: u32 = ct2.decrypt(keyset2_client_key);
    assert_eq!(pt, pt2);
}

pub fn run_sns_compression_test(new_client_key: tfhe::ClientKey, new_server_key: tfhe::ServerKey) {
    tfhe::set_server_key(new_server_key.clone());
    let pt = 12u32;
    let ct = tfhe::FheUint32::encrypt(pt, &new_client_key);
    let large_ct = ct.squash_noise().unwrap();
    let intermediate_pt: u32 = large_ct.decrypt(&new_client_key);
    assert_eq!(intermediate_pt, pt);

    // only after this point we start to use the sns compression key
    let compressed_large_ct = tfhe::CompressedSquashedNoiseCiphertextListBuilder::new()
        .push(large_ct)
        .build()
        .unwrap();
    let new_large_ct: tfhe::SquashedNoiseFheUint = compressed_large_ct.get(0).unwrap().unwrap();
    let actual_pt: u32 = new_large_ct.decrypt(&new_client_key);
    assert_eq!(actual_pt, pt);
}

pub fn combine_and_run_sns_compression_test(
    params: DKGParams,
    client_key: &tfhe::ClientKey,
    sns_compression_key: tfhe::shortint::list_compression::NoiseSquashingCompressionKey,
    sns_compression_private_key: tfhe::shortint::list_compression::NoiseSquashingCompressionPrivateKey,
    server_key: Option<&tfhe::ServerKey>,
) {
    // first we put the private key to the client key
    let int_sns_compression_private_key =
        tfhe::integer::ciphertext::NoiseSquashingCompressionPrivateKey::from_raw_parts(
            sns_compression_private_key,
        );
    let client_key_parts = client_key.clone().into_raw_parts();
    let new_client_key = tfhe::ClientKey::from_raw_parts(
        client_key_parts.0,
        client_key_parts.1,
        client_key_parts.2,
        client_key_parts.3,
        Some(int_sns_compression_private_key),
        client_key_parts.5,
        client_key_parts.6,
        client_key_parts.7,
    );

    let server_key = match server_key {
        Some(inner) => inner.clone(),
        None => new_client_key.generate_server_key(),
    };

    let (sns_params, sns_compression_params) = match params {
        DKGParams::WithoutSnS(_) => panic!("SNS compression test requires DKGParams with SnS"),
        DKGParams::WithSnS(dkgparams_sn_s) => (
            dkgparams_sn_s.sns_params,
            dkgparams_sn_s.sns_compression_params.unwrap(),
        ),
    };
    assert!(sns_compression_key.is_conformant(&(sns_params, sns_compression_params).into()));
    let int_sns_compression_key =
        tfhe::integer::ciphertext::NoiseSquashingCompressionKey::from_raw_parts(
            sns_compression_key,
        );
    let server_key_parts = server_key.into_raw_parts();
    let new_server_key = tfhe::ServerKey::from_raw_parts(
        server_key_parts.0,
        server_key_parts.1,
        server_key_parts.2,
        server_key_parts.3,
        server_key_parts.4,
        Some(int_sns_compression_key),
        server_key_parts.6,
        server_key_parts.7,
        server_key_parts.8,
    );

    run_sns_compression_test(new_client_key, new_server_key);
}

#[cfg(test)]
mod tests {
    use tfhe::{
        FheUint8,
        prelude::{CiphertextList, FheDecrypt},
        set_server_key,
    };

    use crate::{
        constants::REAL_KEY_PATH, tests::ensure_real_keys_setup,
        tfhe_internals::test_feature::KeySet,
    };
    use test_utils::read_element;

    // TODO does not work with test key. Enable if test keys get updated
    // // #[test]
    // fn sunshine_hl_keys_test() {
    //     sunshine_hl_keys(SMALL_TEST_KEY_PATH);
    // }

    #[test]
    fn sunshine_hl_keys_real() {
        ensure_real_keys_setup();
        sunshine_hl_keys(REAL_KEY_PATH);
    }

    /// Helper method for validating conversion to high level API keys.
    /// Method tries to encrypt using both public and client keys and validates
    /// that the results are correct and consistent.
    fn sunshine_hl_keys(path: &str) {
        let keyset: KeySet = read_element(path).unwrap();

        let ctxt_build = tfhe::CompactCiphertextListBuilder::new(&keyset.public_keys.public_key)
            .push(42_u8)
            .push(55_u8)
            .push(5_u8)
            .build();

        set_server_key(keyset.public_keys.server_key);
        let expanded_ctxt_build = ctxt_build.expand().unwrap();

        let ct_a: FheUint8 = expanded_ctxt_build.get(0).unwrap().unwrap();
        let ct_b: FheUint8 = expanded_ctxt_build.get(1).unwrap().unwrap();
        let ct_c: FheUint8 = expanded_ctxt_build.get(2).unwrap().unwrap();

        let compressed_list = tfhe::CompressedCiphertextListBuilder::new()
            .push(ct_a)
            .push(ct_b)
            .push(ct_c)
            .build()
            .unwrap();

        let ct_a: FheUint8 = compressed_list.get(0).unwrap().unwrap();
        let ct_b: FheUint8 = compressed_list.get(1).unwrap().unwrap();
        let ct_c: FheUint8 = compressed_list.get(2).unwrap().unwrap();

        let decrypted_a: u8 = ct_a.decrypt(&keyset.client_key);
        assert_eq!(42, decrypted_a);

        let ct_sum = ct_a.clone() + ct_b;
        let sum: u8 = ct_sum.decrypt(&keyset.client_key);
        assert_eq!(42 + 55, sum);
        let ct_product = ct_a * ct_c;
        let product: u8 = ct_product.decrypt(&keyset.client_key);
        assert_eq!(42 * 5, product);
    }
}
