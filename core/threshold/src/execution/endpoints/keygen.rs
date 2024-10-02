use crate::algebra::base_ring::{Z128, Z64};
use crate::algebra::residue_poly::ResiduePoly64;
use crate::execution::online::preprocessing::{DKGPreprocessing, RandomPreprocessing};
use crate::execution::sharing::share::Share;
use crate::execution::tfhe_internals::compression_decompression_key::CompressionPrivateKeyShares;
use crate::execution::tfhe_internals::lwe_key::LweCompactPublicKeyShare;
use crate::execution::tfhe_internals::lwe_packing_keyswitch_key_generation::allocate_and_generate_lwe_packing_keyswitch_key;
use crate::execution::tfhe_internals::parameters::{
    BKParams, DKGParams, DistributedCompressionParameters, KSKParams, NoiseBounds,
};
use crate::execution::tfhe_internals::switch_and_squash::SwitchAndSquashKey;
use crate::{
    algebra::{
        residue_poly::{ResiduePoly, ResiduePoly128},
        structure_traits::{BaseRing, ErrorCorrect, Ring},
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        online::triple::open_list,
        runtime::session::BaseSessionHandles,
        tfhe_internals::{
            glwe_key::GlweSecretKeyShare,
            lwe_bootstrap_key_generation::allocate_and_generate_lwe_bootstrap_key,
            lwe_key::{
                allocate_and_generate_new_lwe_compact_public_key,
                to_tfhe_hl_api_compact_public_key, LweSecretKeyShare,
            },
            lwe_keyswitch_key_generation::allocate_and_generate_new_lwe_keyswitch_key,
            randomness::MPCEncryptionRandomGenerator,
        },
    },
    file_handling::{read_element, write_element},
};
use concrete_csprng::generators::SoftwareRandomGenerator;
use itertools::Itertools;
use num_integer::div_ceil;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use tfhe::core_crypto::algorithms::convert_standard_lwe_bootstrap_key_to_fourier_128;
use tfhe::core_crypto::commons::traits::UnsignedInteger;
use tfhe::core_crypto::entities::Fourier128LweBootstrapKey;
use tfhe::shortint::list_compression::{CompressionKey, DecompressionKey};
use tfhe::shortint::ClassicPBSParameters;
use tfhe::Versionize;
use tfhe::{
    core_crypto::{
        algorithms::par_convert_standard_lwe_bootstrap_key_to_fourier,
        entities::{FourierLweBootstrapKey, LweBootstrapKey, LweCompactPublicKey, LweKeyswitchKey},
        prelude::ByteRandomGenerator,
    },
    shortint::{
        ciphertext::{MaxDegree, MaxNoiseLevel},
        server_key::ShortintBootstrappingKey,
    },
};
use tfhe_versionable::VersionsDispatch;
use tracing::instrument;

#[derive(Clone, Serialize, Deserialize)]
pub struct FhePubKeySet {
    pub public_key: tfhe::CompactPublicKey,
    pub server_key: tfhe::ServerKey,
    pub sns_key: Option<SwitchAndSquashKey>,
}

impl FhePubKeySet {
    pub fn write_to_file(&self, path: String) -> anyhow::Result<()> {
        write_element(path, self)
    }

    pub fn read_from_file(path: String) -> anyhow::Result<Self> {
        read_element(path)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct RawPubKeySet {
    pub lwe_public_key: LweCompactPublicKey<Vec<u64>>,
    pub ksk: LweKeyswitchKey<Vec<u64>>,
    pub pksk: Option<LweKeyswitchKey<Vec<u64>>>,
    pub bk: LweBootstrapKey<Vec<u64>>,
    pub bk_sns: Option<LweBootstrapKey<Vec<u128>>>,
    pub compression_keys: Option<(CompressionKey, DecompressionKey)>,
}

impl Eq for RawPubKeySet {}

impl RawPubKeySet {
    #[allow(dead_code)]
    pub fn write_to_file(&self, path: String) -> anyhow::Result<()> {
        write_element(path, self)
    }

    #[allow(dead_code)]
    pub fn read_from_file(path: String) -> anyhow::Result<Self> {
        read_element(path)
    }

    pub fn compute_switch_and_squash_key(&self) -> Option<SwitchAndSquashKey> {
        match &self.bk_sns {
            Some(bk_sns) => {
                let mut fourier_bk = Fourier128LweBootstrapKey::new(
                    bk_sns.input_lwe_dimension(),
                    bk_sns.glwe_size(),
                    bk_sns.polynomial_size(),
                    bk_sns.decomposition_base_log(),
                    bk_sns.decomposition_level_count(),
                );
                convert_standard_lwe_bootstrap_key_to_fourier_128(bk_sns, &mut fourier_bk);
                Some(SwitchAndSquashKey {
                    fbsk_out: fourier_bk,
                    ksk: self.ksk.clone(),
                })
            }
            None => None,
        }
    }

    pub fn compute_tfhe_shortint_server_key(&self, params: DKGParams) -> tfhe::shortint::ServerKey {
        let regular_params = params.get_params_basics_handle();
        let max_value =
            regular_params.get_message_modulus().0 * regular_params.get_carry_modulus().0 - 1;

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

        let pk_bk = ShortintBootstrappingKey::Classic(fourier_bsk);

        let max_noise_level = MaxNoiseLevel::from_msg_carry_modulus(
            regular_params.get_message_modulus(),
            regular_params.get_carry_modulus(),
        );

        let params_tfhe = regular_params.to_classic_pbs_parameters();

        tfhe::shortint::ServerKey::from_raw_parts(
            self.ksk.clone(),
            pk_bk,
            regular_params.get_message_modulus(),
            regular_params.get_carry_modulus(),
            MaxDegree::new(max_value),
            max_noise_level,
            params_tfhe.ciphertext_modulus,
            regular_params.encryption_key_choice().into(),
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

        if let Some(pksk) = &self.pksk {
            let shortint_pksk =
                tfhe::shortint::key_switching_key::KeySwitchingKeyMaterial::from_raw_parts(
                    pksk.clone(),
                    0,
                    params
                        .get_params_basics_handle()
                        .get_pksk_destination()
                        .unwrap(),
                );
            let integer_pksk =
                tfhe::integer::key_switching_key::KeySwitchingKeyMaterial::from_raw_parts(
                    shortint_pksk,
                );

            tfhe::ServerKey::from_raw_parts(
                integer_key,
                Some(integer_pksk),
                compression_key,
                decompression_key,
                tfhe::Tag::default(),
            )
        } else {
            tfhe::ServerKey::from_raw_parts(
                integer_key,
                None,
                compression_key,
                decompression_key,
                tfhe::Tag::default(),
            )
        }
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
            sns_key: self.compute_switch_and_squash_key(),
        }
    }
}

struct GenericPrivateKeySet<Z: Clone> {
    //The two Lwe keys are the same if there's no dedicated pk parameters
    pub lwe_encryption_secret_key_share: LweSecretKeyShare<Z>,
    pub lwe_secret_key_share: LweSecretKeyShare<Z>,
    pub glwe_secret_key_share: GlweSecretKeyShare<Z>,
    pub glwe_secret_key_share_sns: Option<GlweSecretKeyShare<Z>>,
    pub glwe_secret_key_share_compression: Option<CompressionPrivateKeyShares<Z>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum PrivateKeySetVersioned {
    V0(PrivateKeySet),
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize, PartialEq)]
#[versionize(PrivateKeySetVersioned)]
pub struct PrivateKeySet {
    //The two Lwe keys are the same if there's no dedicated pk parameters
    pub lwe_encryption_secret_key_share: LweSecretKeyShare<Z64>,
    pub lwe_compute_secret_key_share: LweSecretKeyShare<Z64>,
    pub glwe_secret_key_share: GlweSecretKeyShare<Z64>,
    pub glwe_secret_key_share_sns_as_lwe: Option<LweSecretKeyShare<Z128>>,
    pub glwe_secret_key_share_compression: Option<CompressionPrivateKeyShares<Z64>>,
    pub parameters: ClassicPBSParameters,
}

impl PrivateKeySet {
    pub fn write_to_file(&self, path: String) -> anyhow::Result<()> {
        write_element(path, self)
    }

    pub fn read_from_file(path: String) -> anyhow::Result<Self> {
        read_element(path)
    }
}

impl GenericPrivateKeySet<Z128> {
    pub fn finalize_keyset(self, parameters: ClassicPBSParameters) -> PrivateKeySet {
        let lwe_compute_data = self
            .lwe_secret_key_share
            .data
            .into_iter()
            .map(|share| {
                let converted_value = share.value().to_residuepoly64();
                Share::new(share.owner(), converted_value)
            })
            .collect_vec();
        let converted_lwe_secret_key_share = LweSecretKeyShare {
            data: lwe_compute_data,
        };

        let lwe_encryption_data = self
            .lwe_encryption_secret_key_share
            .data
            .into_iter()
            .map(|share| {
                let converted_value = share.value().to_residuepoly64();
                Share::new(share.owner(), converted_value)
            })
            .collect_vec();
        let converted_lwe_encryption_key_share = LweSecretKeyShare {
            data: lwe_encryption_data,
        };

        let glwe_data = self
            .glwe_secret_key_share
            .data
            .into_iter()
            .map(|share| {
                let converted_value = share.value().to_residuepoly64();
                Share::new(share.owner(), converted_value)
            })
            .collect_vec();
        let converted_glwe_secret_key_share = GlweSecretKeyShare {
            data: glwe_data,
            polynomial_size: self.glwe_secret_key_share.polynomial_size,
        };

        let glwe_secret_key_share_sns_as_lwe = self
            .glwe_secret_key_share_sns
            .map(|key| key.into_lwe_secret_key());

        let glwe_secret_key_share_compression = self.glwe_secret_key_share_compression.map_or_else(
            || None,
            |key| {
                let polynomial_size = key.polynomial_size();
                Some(CompressionPrivateKeyShares {
                    post_packing_ks_key: GlweSecretKeyShare {
                        data: key
                            .post_packing_ks_key
                            .data
                            .into_iter()
                            .map(|share| {
                                let converted_value = share.value().to_residuepoly64();
                                Share::new(share.owner(), converted_value)
                            })
                            .collect_vec(),
                        polynomial_size,
                    },
                    params: key.params,
                })
            },
        );

        PrivateKeySet {
            lwe_encryption_secret_key_share: converted_lwe_encryption_key_share,
            lwe_compute_secret_key_share: converted_lwe_secret_key_share,
            glwe_secret_key_share: converted_glwe_secret_key_share,
            glwe_secret_key_share_sns_as_lwe,
            glwe_secret_key_share_compression,
            parameters,
        }
    }
}

impl GenericPrivateKeySet<Z64> {
    pub fn finalize_keyset(self, parameters: ClassicPBSParameters) -> PrivateKeySet {
        PrivateKeySet {
            lwe_encryption_secret_key_share: self.lwe_encryption_secret_key_share,
            lwe_compute_secret_key_share: self.lwe_secret_key_share,
            glwe_secret_key_share: self.glwe_secret_key_share,
            glwe_secret_key_share_sns_as_lwe: None,
            glwe_secret_key_share_compression: self.glwe_secret_key_share_compression,
            parameters,
        }
    }
}

///Sample the random but public seed
async fn sample_seed<
    Z: Ring + ErrorCorrect,
    P: RandomPreprocessing<Z> + ?Sized,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
>(
    sec: u64,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<u128> {
    //NOTE: next_random_vec samples uniformly from Z[X]/F(X)
    //(as required by the ideal functional Fig.94).
    let num_seeds = div_ceil(sec, Z::BIT_LENGTH as u64) as usize;
    let shared_seeds = preprocessing.next_random_vec(num_seeds)?;
    let seeds = open_list(&shared_seeds, session).await?;
    //Turn the random element in Z[X]/F(X) to random params.sec bits
    Ok(seeds
        .iter()
        .flat_map(Z::to_byte_vec)
        .take((sec as usize) >> 3)
        .fold(0_u128, |acc, x| (acc << 8) + (x as u128)))
}

///Generates the lwe private key share and associated public key
fn generate_lwe_key_shares<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z>> + ?Sized,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    Gen: ByteRandomGenerator,
>(
    params: &DKGParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<(LweSecretKeyShare<Z>, LweCompactPublicKeyShare<Z>)>
where
    ResiduePoly<Z>: ErrorCorrect,
{
    let params = params.get_params_basics_handle();
    let my_role = session.my_role()?;
    //Init the shared LWE secret key
    tracing::info!("(Party {my_role}) Generating LWE Secret key...Start");
    let lwe_secret_key_share =
        LweSecretKeyShare::new_from_preprocessing(params.lwe_hat_dimension(), preprocessing)?;
    tracing::info!("(Party {my_role}) Generating corresponding public key...Start");
    let vec_tuniform_noise = preprocessing
        .next_noise_vec(
            params.num_needed_noise_pk(),
            NoiseBounds::LweHatNoise(params.lwe_hat_tuniform_bound()),
        )?
        .iter()
        .map(|share| share.value())
        .collect_vec();

    //and fill the noise generator with noise generated above
    mpc_encryption_rng.fill_noise(vec_tuniform_noise);

    //Then actually generate the public key
    let lwe_public_key_shared = allocate_and_generate_new_lwe_compact_public_key(
        &lwe_secret_key_share,
        mpc_encryption_rng,
    )?;

    Ok((lwe_secret_key_share, lwe_public_key_shared))
}

///Generates the lwe private key share and associated public key
#[instrument(skip( mpc_encryption_rng, session, preprocessing), fields(session_id = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_lwe_private_public_key_pair<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z>> + ?Sized,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    Gen: ByteRandomGenerator,
>(
    params: &DKGParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<(LweSecretKeyShare<Z>, LweCompactPublicKey<Vec<u64>>)>
where
    ResiduePoly<Z>: ErrorCorrect,
{
    let (lwe_secret_key_share, lwe_public_key_shared) =
        generate_lwe_key_shares(params, mpc_encryption_rng, session, preprocessing)?;

    //Open the public key and cast it to TFHE-RS type
    Ok((
        lwe_secret_key_share,
        lwe_public_key_shared.open_to_tfhers_type(session).await?,
    ))
}

///Generate the Key Switch Key from a Glwe key given in Lwe format,
///and an actual Lwe key
#[instrument(skip(input_lwe_sk, output_lwe_sk, mpc_encryption_rng, session, preprocessing), fields(session_id = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_key_switch_key<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z>> + ?Sized,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    Gen: ByteRandomGenerator,
>(
    input_lwe_sk: &LweSecretKeyShare<Z>,
    output_lwe_sk: &LweSecretKeyShare<Z>,
    params: &KSKParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<LweKeyswitchKey<Vec<u64>>>
where
    ResiduePoly<Z>: ErrorCorrect,
{
    let my_role = session.my_role()?;
    tracing::info!("(Party {my_role}) Generating KSK...Start");
    let vec_tuniform_noise = preprocessing
        .next_noise_vec(params.num_needed_noise, params.noise_bound)?
        .iter()
        .map(|share| share.value())
        .collect_vec();

    mpc_encryption_rng.fill_noise(vec_tuniform_noise);

    //Then compute the KSK
    let ksk_share = allocate_and_generate_new_lwe_keyswitch_key(
        input_lwe_sk,
        output_lwe_sk,
        params.decomposition_base_log,
        params.decomposition_level_count,
        mpc_encryption_rng,
    )?;

    //Open the KSK and cast it to TFHE-RS type
    ksk_share.open_to_tfhers_type(session).await
}

///Generates a Bootstrapping Key given a Glwe key in Glwe format
///, a Lwe key and the params for the BK generation
#[instrument(skip(glwe_secret_key_share, lwe_secret_key_share, mpc_encryption_rng, session, preprocessing), fields(session_id = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_bootstrap_key<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z>> + ?Sized,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    Gen: ByteRandomGenerator,
    Scalar: UnsignedInteger,
>(
    glwe_secret_key_share: &GlweSecretKeyShare<Z>,
    lwe_secret_key_share: &LweSecretKeyShare<Z>,
    params: BKParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<LweBootstrapKey<Vec<Scalar>>>
where
    ResiduePoly<Z>: ErrorCorrect,
{
    let my_role = session.my_role()?;
    //First sample the noise
    let vec_tuniform_noise = preprocessing
        .next_noise_vec(params.num_needed_noise, params.noise_bound)?
        .iter()
        .map(|share| share.value())
        .collect_vec();

    mpc_encryption_rng.fill_noise(vec_tuniform_noise);

    tracing::info!("(Party {my_role}) Generating BK for {:?} ...Start", params);

    let bk_share = allocate_and_generate_lwe_bootstrap_key(
        lwe_secret_key_share,
        glwe_secret_key_share,
        params.decomposition_base_log,
        params.decomposition_level_count,
        mpc_encryption_rng,
        params.enc_type,
        session,
        preprocessing,
    )
    .await?;

    tracing::info!("(Party {my_role}) Generating BK {:?} ...Done", params);
    tracing::info!("(Party {my_role}) Opening BK {:?} ...Start", params);
    //Open the bk and cast it to TFHE-rs type
    let bk = bk_share
        .open_to_tfhers_type::<Scalar, _, _>(session)
        .await?;
    tracing::info!("(Party {my_role}) Opening BK {:?} ...Done", params);
    Ok(bk)
}

async fn generate_compression_decompression_keys<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z>> + ?Sized,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    Gen: ByteRandomGenerator,
>(
    private_glwe_compute_key_as_lwe: &LweSecretKeyShare<Z>,
    private_glwe_compute_key: &GlweSecretKeyShare<Z>,
    private_compression_key: &CompressionPrivateKeyShares<Z>,
    params: DistributedCompressionParameters,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<(CompressionKey, DecompressionKey)>
where
    ResiduePoly<Z>: ErrorCorrect,
{
    let noise_vec = preprocessing
        .next_noise_vec(params.ksk_num_noise, params.ksk_noisebound)?
        .iter()
        .map(|share| share.value())
        .collect_vec();

    mpc_encryption_rng.fill_noise(noise_vec);

    let packing_key_switching_key_shares = allocate_and_generate_lwe_packing_keyswitch_key(
        private_glwe_compute_key_as_lwe,
        &private_compression_key.post_packing_ks_key,
        params.raw_compression_parameters.packing_ks_base_log,
        params.raw_compression_parameters.packing_ks_level,
        mpc_encryption_rng,
    )?;

    let packing_key_switching_key = packing_key_switching_key_shares
        .open_to_tfhers_type(session)
        .await?;

    let compression_key = CompressionKey {
        packing_key_switching_key,
        lwe_per_glwe: params.raw_compression_parameters.lwe_per_glwe,
        storage_log_modulus: params.raw_compression_parameters.storage_log_modulus,
    };

    let blind_rotate_key: LweBootstrapKey<Vec<u64>> = generate_bootstrap_key(
        private_glwe_compute_key,
        &private_compression_key.clone().into_lwe_secret_key(),
        params.bk_params,
        mpc_encryption_rng,
        session,
        preprocessing,
    )
    .await?;

    // Creation of the bootstrapping key in the Fourier domain
    let mut fourier_bsk = FourierLweBootstrapKey::new(
        blind_rotate_key.input_lwe_dimension(),
        blind_rotate_key.glwe_size(),
        blind_rotate_key.polynomial_size(),
        blind_rotate_key.decomposition_base_log(),
        blind_rotate_key.decomposition_level_count(),
    );

    // Conversion to fourier domain
    par_convert_standard_lwe_bootstrap_key_to_fourier(&blind_rotate_key, &mut fourier_bsk);

    let blind_rotate_key = ShortintBootstrappingKey::Classic(fourier_bsk);

    let decompression_key = DecompressionKey {
        blind_rotate_key,
        lwe_per_glwe: params.raw_compression_parameters.lwe_per_glwe,
    };
    Ok((compression_key, decompression_key))
}

/// This function generates a bootstrapping key (bsk)
/// that is used for the homomorphic PRF.
/// Typically bootstrapping keys are encryptions of some
/// LWE ciphertext. In thise use case, the LWE ciphertext
/// is the PRF seed/key and it is randomly sampled and discarded.
pub async fn distributed_homprf_bsk_gen<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z>> + ?Sized,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    Scalar: UnsignedInteger,
>(
    glwe_secret_key_share: &GlweSecretKeyShare<Z>,
    params: &DKGParams,
    preprocessing: &mut P,
    session: &mut S,
) -> anyhow::Result<LweBootstrapKey<Vec<Scalar>>>
where
    ResiduePoly<Z>: ErrorCorrect,
{
    let params_basics_handle = params.get_params_basics_handle();
    let seed = sample_seed(params_basics_handle.get_sec(), session, preprocessing).await?;
    //Init the XOF with the seed computed above
    let mut mpc_encryption_rng =
        MPCEncryptionRandomGenerator::<Z, SoftwareRandomGenerator>::new_from_seed(seed);

    // the `lwe_secret_key_share` is the PRF key/seed
    // we don't need the public component
    let lwe_secret_key_share = LweSecretKeyShare::new_from_preprocessing(
        params_basics_handle.lwe_dimension(),
        preprocessing,
    )?;

    // now generate the bootstrapping key
    let bsk = generate_bootstrap_key(
        glwe_secret_key_share,
        &lwe_secret_key_share,
        params_basics_handle.get_bk_params(),
        &mut mpc_encryption_rng,
        session,
        preprocessing,
    )
    .await?;

    // lwe_secret_key_share is dropped here
    Ok(bsk)
}

///Runs the distributed key generation protocol.
///
/// Expects:
/// - session: the session that holds necessary information for networking
/// - preprocessing: [`DKGPreprocessing`] handle with enough triples, bits and noise available
/// - params: [`DKGParams`] parameters for the Distributed Key Generation
///
/// Outputs:
/// - A [`RawPubKeySet`] composed of the public key, the KSK, the BK and the BK_sns if required
/// - a [`PrivateKeySet`] composed of shares of the lwe and glwe private keys
///
///If the [`DKGParams::o_flag`] is set in the params, then the sharing domain must be [`ResiduePoly128`] but the domain of
///all non-overlined key material is still [`u64`].
/// Note that there is some redundancy of information because we also explicitly ask the [`BaseRing`] as trait parameter
#[instrument(name="TFHE.Threshold-KeyGen", skip(session, preprocessing), fields(session_id = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn distributed_keygen<
    Z: BaseRing,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    P: DKGPreprocessing<ResiduePoly<Z>> + Send + ?Sized,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
) -> anyhow::Result<(RawPubKeySet, GenericPrivateKeySet<Z>)>
where
    ResiduePoly<Z>: ErrorCorrect,
{
    let params_basics_handle = params.get_params_basics_handle();
    let my_role = session.my_role()?;
    let seed = sample_seed(params_basics_handle.get_sec(), session, preprocessing).await?;
    //Init the XOF with the seed computed above
    let mut mpc_encryption_rng =
        MPCEncryptionRandomGenerator::<Z, SoftwareRandomGenerator>::new_from_seed(seed);

    //Generate the shared LWE hat secret key and corresponding public key
    let (lwe_hat_secret_key_share, lwe_public_key) = generate_lwe_private_public_key_pair(
        &params,
        &mut mpc_encryption_rng,
        session,
        preprocessing,
    )
    .await?;

    //Generate the LWE (no hat) secret key if it should exist
    let lwe_secret_key_share = if params_basics_handle.has_dedicated_compact_pk_params() {
        LweSecretKeyShare::new_from_preprocessing(
            params_basics_handle.lwe_dimension(),
            preprocessing,
        )?
    } else {
        lwe_hat_secret_key_share.clone()
    };

    tracing::info!("(Party {my_role}) Generating corresponding public key...Done");

    //Generate the GLWE secret key
    tracing::info!("(Party {my_role}) Generating GLWE secret key...Start");
    let glwe_secret_key_share = GlweSecretKeyShare::new_from_preprocessing(
        params_basics_handle.glwe_sk_num_bits(),
        params_basics_handle.polynomial_size(),
        preprocessing,
    )?;

    let glwe_sk_share_as_lwe = glwe_secret_key_share.clone().into_lwe_secret_key();

    tracing::info!("(Party {my_role}) Generating GLWE secret key...Done");

    //Generate the compression keys if needed
    let compression_material =
        if let Some(comp_params) = params_basics_handle.get_compression_decompression_params() {
            let compression_glwe_secret_key_share =
                CompressionPrivateKeyShares::new_from_preprocessing(
                    comp_params.raw_compression_parameters,
                    preprocessing,
                )?;
            let (compression_key, decompression_key) = generate_compression_decompression_keys(
                &glwe_sk_share_as_lwe,
                &glwe_secret_key_share,
                &compression_glwe_secret_key_share,
                comp_params,
                &mut mpc_encryption_rng,
                session,
                preprocessing,
            )
            .await?;
            Some((
                compression_glwe_secret_key_share,
                (compression_key, decompression_key),
            ))
        } else {
            None
        };

    //Generate the KSK
    let ksk_params = params_basics_handle.get_ksk_params();

    let ksk = generate_key_switch_key(
        &glwe_sk_share_as_lwe,
        &lwe_secret_key_share,
        &ksk_params,
        &mut mpc_encryption_rng,
        session,
        preprocessing,
    )
    .await?;
    tracing::info!("(Party {my_role}) Generating KSK...Done");

    //Computing and opening BK can take a while, so we increase the timeout
    session.network().set_timeout_for_bk()?;
    //Compute the bootstrapping keys
    let bk = generate_bootstrap_key(
        &glwe_secret_key_share,
        &lwe_secret_key_share,
        params_basics_handle.get_bk_params(),
        &mut mpc_encryption_rng,
        session,
        preprocessing,
    )
    .await?;

    //If needed, compute the SnS BK
    let (glwe_secret_key_share_sns, bk_sns) = match params {
        DKGParams::WithSnS(sns_params) => {
            tracing::info!("(Party {my_role}) Generating SnS GLWE...Start");
            //compute the SnS GLWE key
            let glwe_secret_key_share_sns = GlweSecretKeyShare::new_from_preprocessing(
                sns_params.glwe_sk_num_bits_sns(),
                sns_params.polynomial_size_sns(),
                preprocessing,
            )?;

            //Computing and opening BK SNS can take a while, so we increase the timeout
            session.network().set_timeout_for_bk_sns()?;

            tracing::info!("(Party {my_role}) Generating SnS GLWE...Done");
            let bk_sns = generate_bootstrap_key(
                &glwe_secret_key_share_sns,
                &lwe_secret_key_share,
                sns_params.get_bk_sns_params(),
                &mut mpc_encryption_rng,
                session,
                preprocessing,
            )
            .await?;

            tracing::info!("(Party {my_role}) Opening SnS BK...Done");
            (Some(glwe_secret_key_share_sns), Some(bk_sns))
        }
        DKGParams::WithoutSnS(_) => (None, None),
    };

    //Compute the PKSK
    let pksk = match (
        params_basics_handle.get_pksk_destination(),
        params_basics_handle.get_pksk_params(),
    ) {
        //Corresponds to type = F-GLWE
        (Some(tfhe::shortint::EncryptionKeyChoice::Big), Some(pksk_params)) => Some(
            generate_key_switch_key(
                &lwe_hat_secret_key_share,
                &glwe_sk_share_as_lwe,
                &pksk_params,
                &mut mpc_encryption_rng,
                session,
                preprocessing,
            )
            .await?,
        ),

        //Corresponds to type = LWE
        (Some(tfhe::shortint::EncryptionKeyChoice::Small), Some(pksk_params)) => Some(
            generate_key_switch_key(
                &lwe_hat_secret_key_share,
                &lwe_secret_key_share,
                &pksk_params,
                &mut mpc_encryption_rng,
                session,
                preprocessing,
            )
            .await?,
        ),
        (None, None) => None,
        _ => {
            tracing::error!("Incompatible parameters regarding pksk, can not generate it.");
            None
        }
    };

    let (glwe_secret_key_share_compression, compression_keys) =
        compression_material.map_or_else(|| (None, None), |(sk, pk)| (Some(sk), Some(pk)));

    let pub_key_set = RawPubKeySet {
        lwe_public_key,
        ksk,
        pksk,
        bk,
        bk_sns,
        compression_keys,
    };

    let priv_key_set = GenericPrivateKeySet {
        lwe_encryption_secret_key_share: lwe_hat_secret_key_share,
        lwe_secret_key_share,
        glwe_secret_key_share,
        glwe_secret_key_share_sns,
        glwe_secret_key_share_compression,
    };

    Ok((pub_key_set, priv_key_set))
}

pub async fn distributed_keygen_z64<
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    P: DKGPreprocessing<ResiduePoly64> + Send + ?Sized,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
) -> anyhow::Result<(FhePubKeySet, PrivateKeySet)> {
    if let DKGParams::WithSnS(_) = params {
        return Err(anyhow_error_and_log(
            "Can not generate Switch and Squash key with ResiduePoly64".to_string(),
        ));
    }
    let (pub_key_set, priv_key_set) = distributed_keygen(session, preprocessing, params).await?;
    Ok((
        pub_key_set.to_pubkeyset(params),
        priv_key_set.finalize_keyset(
            params
                .get_params_basics_handle()
                .to_classic_pbs_parameters(),
        ),
    ))
}

pub async fn distributed_keygen_z128<
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    P: DKGPreprocessing<ResiduePoly128> + Send + ?Sized,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
) -> anyhow::Result<(FhePubKeySet, PrivateKeySet)> {
    let (pub_key_set, priv_key_set) = distributed_keygen(session, preprocessing, params).await?;
    Ok((
        pub_key_set.to_pubkeyset(params),
        priv_key_set.finalize_keyset(
            params
                .get_params_basics_handle()
                .to_classic_pbs_parameters(),
        ),
    ))
}

#[cfg(test)]
pub mod tests {
    use std::fs;

    use concrete_csprng::seeders::Seeder;
    use itertools::Itertools;
    #[cfg(feature = "slow_tests")]
    use tfhe::{
        core_crypto::{
            algorithms::par_convert_standard_lwe_bootstrap_key_to_fourier,
            entities::FourierLweBootstrapKey,
        },
        integer::parameters::PolynomialSize,
        shortint::server_key::ShortintBootstrappingKey,
        Seed,
    };
    use tfhe::{
        core_crypto::{
            algorithms::{
                convert_standard_lwe_bootstrap_key_to_fourier_128, par_generate_lwe_bootstrap_key,
            },
            commons::{
                generators::{DeterministicSeeder, EncryptionRandomGenerator},
                math::random::{ActivatedRandomGenerator, TUniform},
                traits::CastInto,
            },
            entities::{Fourier128LweBootstrapKey, GlweSecretKey, LweBootstrapKey, LweSecretKey},
        },
        integer::parameters::DynamicDistribution,
        prelude::{CiphertextList, FheDecrypt, FheMin, FheTryEncrypt},
        set_server_key,
        shortint::parameters::CoreCiphertextModulus,
        CompressedCiphertextListBuilder, FheUint32, FheUint64, FheUint8,
    };

    use crate::{
        algebra::{
            base_ring::Z128,
            residue_poly::{ResiduePoly, ResiduePoly128},
            structure_traits::{BaseRing, ErrorCorrect},
        },
        execution::{
            online::preprocessing::dummy::DummyPreprocessing,
            runtime::session::{LargeSession, ParameterHandles},
            tfhe_internals::parameters::{DKGParamsBasics, DKGParamsRegular, DKGParamsSnS},
        },
        tests::helper::tests_and_benches::execute_protocol_large,
    };
    #[cfg(feature = "slow_tests")]
    use crate::{
        execution::tfhe_internals::{
            glwe_key::GlweSecretKeyShare, utils::tests::read_secret_key_shares_from_file,
        },
        file_handling::{read_element, write_element},
    };
    use crate::{
        execution::{
            endpoints::keygen::RawPubKeySet,
            tfhe_internals::{
                test_feature::SnsClientKey, utils::tests::reconstruct_lwe_secret_key_from_file,
            },
        },
        networking::NetworkMode,
    };
    use crate::{
        execution::{
            random::{get_rng, seed_from_rng},
            tfhe_internals::{
                parameters::{
                    BC_PARAMS_SAM_NO_SNS, NIST_PARAMS_P32_INTERNAL_FGLWE,
                    NIST_PARAMS_P32_NO_SNS_FGLWE, NIST_PARAMS_P32_NO_SNS_LWE,
                    NIST_PARAMS_P32_SNS_FGLWE, NIST_PARAMS_P8_NO_SNS_FGLWE,
                    NIST_PARAMS_P8_NO_SNS_LWE, NIST_PARAMS_P8_SNS_FGLWE,
                    OLD_PARAMS_P32_REAL_WITH_SNS, PARAMS_TEST_BK_SNS,
                },
                switch_and_squash::SwitchAndSquashKey,
                test_feature::to_hl_client_key,
                utils::tests::reconstruct_glwe_secret_key_from_file,
            },
        },
        expanded_encrypt,
    };

    #[cfg(feature = "slow_tests")]
    use super::distributed_homprf_bsk_gen;
    use super::{distributed_keygen, DKGParams};

    #[test]
    fn pure_tfhers_test() {
        let params = NIST_PARAMS_P32_INTERNAL_FGLWE;
        let classic_pbs = params.ciphertext_parameters;
        let dedicated_cpk_params = params.dedicated_compact_public_key_parameters.unwrap();

        let config = tfhe::ConfigBuilder::with_custom_parameters(classic_pbs)
            .use_dedicated_compact_public_key_parameters(dedicated_cpk_params);

        let client_key = tfhe::ClientKey::generate(config.clone());
        let server_key = tfhe::ServerKey::new(&client_key);
        let public_key = tfhe::CompactPublicKey::try_new(&client_key).unwrap();

        try_tfhe_pk_compactlist_computation(&client_key, &server_key, &public_key);
    }

    #[test]
    #[ignore]
    fn old_keygen_params32_with_sns() {
        let params = OLD_PARAMS_P32_REAL_WITH_SNS;
        let params_basics_handles = params.get_params_basics_handle();
        let num_parties = 5;
        let threshold = 1;
        let prefix_path = params_basics_handles.get_prefix_path();

        if !std::path::Path::new(&(prefix_path.clone() + "/params.json"))
            .try_exists()
            .unwrap()
        {
            _ = fs::create_dir(prefix_path.clone());
            run_dkg_and_save(params, num_parties, threshold, prefix_path.clone());
        }

        run_switch_and_squash(prefix_path.clone(), num_parties, threshold);

        run_tfhe_computation_shortint::<Z128, DKGParamsSnS>(
            prefix_path.clone(),
            num_parties,
            threshold,
            false,
        );
        run_tfhe_computation_fheuint::<Z128, DKGParamsSnS>(
            prefix_path,
            num_parties,
            threshold,
            false,
        );
    }

    ///Tests related to [`PARAMS_P32_NO_SNS_FGLWE`]
    #[test]
    #[ignore]
    fn keygen_params32_no_sns_fglwe() {
        let params = NIST_PARAMS_P32_NO_SNS_FGLWE;
        let params_basics_handles = params.get_params_basics_handle();
        let num_parties = 5;
        let threshold = 1;
        let prefix_path = params_basics_handles.get_prefix_path();

        if !std::path::Path::new(&(prefix_path.clone() + "/params.json"))
            .try_exists()
            .unwrap()
        {
            _ = fs::create_dir(prefix_path.clone());
            run_dkg_and_save(params, num_parties, threshold, prefix_path.clone());
        }

        run_tfhe_computation_shortint::<Z128, DKGParamsRegular>(
            prefix_path.clone(),
            num_parties,
            threshold,
            true,
        );
        run_tfhe_computation_fheuint::<Z128, DKGParamsRegular>(
            prefix_path,
            num_parties,
            threshold,
            false,
        );
    }

    ///Tests related to [`PARAMS_P8_NO_SNS_FGLWE`]
    #[test]
    #[ignore]
    fn keygen_params8_no_sns_fglwe() {
        let params = NIST_PARAMS_P8_NO_SNS_FGLWE;
        let params_basics_handles = params.get_params_basics_handle();
        let num_parties = 5;
        let threshold = 1;
        let prefix_path = params_basics_handles.get_prefix_path();

        if !std::path::Path::new(&(prefix_path.clone() + "/params.json"))
            .try_exists()
            .unwrap()
        {
            _ = fs::create_dir(prefix_path.clone());
            run_dkg_and_save(params, num_parties, threshold, prefix_path.clone());
        }

        //This parameter set isnt big enough to run the fheuint tests
        run_tfhe_computation_shortint::<Z128, DKGParamsRegular>(
            prefix_path.clone(),
            num_parties,
            threshold,
            true,
        );
    }

    ///Tests related to [`PARAMS_P32_NO_SNS_LWE`]
    #[test]
    #[ignore]
    fn keygen_params32_no_sns_lwe() {
        let params = NIST_PARAMS_P32_NO_SNS_LWE;
        let params_basics_handles = params.get_params_basics_handle();
        let num_parties = 5;
        let threshold = 1;
        let prefix_path = params_basics_handles.get_prefix_path();

        if !std::path::Path::new(&(prefix_path.clone() + "/params.json"))
            .try_exists()
            .unwrap()
        {
            _ = fs::create_dir(prefix_path.clone());
            run_dkg_and_save(params, num_parties, threshold, prefix_path.clone());
        }

        run_tfhe_computation_shortint::<Z128, DKGParamsRegular>(
            prefix_path.clone(),
            num_parties,
            threshold,
            true,
        );
        run_tfhe_computation_fheuint::<Z128, DKGParamsRegular>(
            prefix_path,
            num_parties,
            threshold,
            false,
        );
    }

    ///Tests related to [`PARAMS_P8_NO_SNS_LWE`]
    #[test]
    #[ignore]
    fn keygen_params8_no_sns_lwe() {
        let params = NIST_PARAMS_P8_NO_SNS_LWE;
        let params_basics_handles = params.get_params_basics_handle();
        let num_parties = 5;
        let threshold = 1;
        let prefix_path = params_basics_handles.get_prefix_path();

        if !std::path::Path::new(&(prefix_path.clone() + "/params.json"))
            .try_exists()
            .unwrap()
        {
            _ = fs::create_dir(prefix_path.clone());
            run_dkg_and_save(params, num_parties, threshold, prefix_path.clone());
        }

        //This parameter set isnt big enough to run the fheuint tests
        run_tfhe_computation_shortint::<Z128, DKGParamsRegular>(
            prefix_path,
            num_parties,
            threshold,
            true,
        );
    }

    ///Tests related to [`PARAMS_TEST_BK_SNS`]
    #[test]
    #[ignore]
    fn keygen_params_bk_sns() {
        let params = PARAMS_TEST_BK_SNS;
        let params_basics_handles = params.get_params_basics_handle();
        let num_parties = 5;
        let threshold = 1;
        let prefix_path = params_basics_handles.get_prefix_path();

        if !std::path::Path::new(&(prefix_path.clone() + "/params.json"))
            .try_exists()
            .unwrap()
        {
            _ = fs::create_dir(prefix_path.clone());
            run_dkg_and_save(params, num_parties, threshold, prefix_path.clone());
        }

        run_switch_and_squash(prefix_path.clone(), num_parties, threshold);

        run_tfhe_computation_shortint::<Z128, DKGParamsSnS>(
            prefix_path.clone(),
            num_parties,
            threshold,
            true,
        );
        run_tfhe_computation_fheuint::<Z128, DKGParamsSnS>(
            prefix_path,
            num_parties,
            threshold,
            true,
        );
    }

    ///Tests related to [`PARAMS_TEST_BK_SNS`] using _less fake_ preprocessing
    #[cfg(feature = "slow_tests")]
    #[test]
    fn integration_keygen_params_bk_sns() {
        let params = PARAMS_TEST_BK_SNS;
        let params_basics_handles = params.get_params_basics_handle();
        let num_parties = 4;
        let threshold = 1;
        let prefix_path = params_basics_handles.get_prefix_path() + "/integration";

        if !std::path::Path::new(&(prefix_path.clone() + "/params.json"))
            .try_exists()
            .unwrap()
        {
            _ = fs::create_dir_all(prefix_path.clone());
            run_real_dkg_and_save(params, num_parties, threshold, prefix_path.clone());
        }

        run_switch_and_squash(prefix_path.clone(), num_parties, threshold);

        run_tfhe_computation_shortint::<Z128, DKGParamsSnS>(
            prefix_path.clone(),
            num_parties,
            threshold,
            true,
        );
        run_tfhe_computation_fheuint::<Z128, DKGParamsSnS>(
            prefix_path,
            num_parties,
            threshold,
            true,
        );
    }

    ///Tests related to [`PARAMS_P32_SNS_FGLWE`]
    #[test]
    #[ignore]
    fn keygen_params32_with_sns_fglwe() {
        let params = NIST_PARAMS_P32_SNS_FGLWE;
        let params_basics_handles = params.get_params_basics_handle();
        let num_parties = 5;
        let threshold = 1;
        let prefix_path = params_basics_handles.get_prefix_path();

        if !std::path::Path::new(&(prefix_path.clone() + "/params.json"))
            .try_exists()
            .unwrap()
        {
            _ = fs::create_dir(prefix_path.clone());
            run_dkg_and_save(params, num_parties, threshold, prefix_path.clone());
        }

        run_switch_and_squash(prefix_path.clone(), num_parties, threshold);

        run_tfhe_computation_shortint::<Z128, DKGParamsSnS>(
            prefix_path.clone(),
            num_parties,
            threshold,
            true,
        );
        run_tfhe_computation_fheuint::<Z128, DKGParamsSnS>(
            prefix_path,
            num_parties,
            threshold,
            false,
        );
    }

    ///Tests related to [`PARAMS_P8_REAL_WITH_SNS`]
    #[test]
    #[ignore]
    fn keygen_params8_with_sns_fglwe() {
        let params = NIST_PARAMS_P8_SNS_FGLWE;
        let params_basics_handles = params.get_params_basics_handle();
        let num_parties = 5;
        let threshold = 1;
        let prefix_path = params_basics_handles.get_prefix_path();

        if !std::path::Path::new(&(prefix_path.clone() + "/params.json"))
            .try_exists()
            .unwrap()
        {
            _ = fs::create_dir(prefix_path.clone());
            run_dkg_and_save(params, num_parties, threshold, prefix_path.clone());
        }

        run_switch_and_squash(prefix_path.clone(), num_parties, threshold);

        //This parameter set isnt big enough to run the fheuint tests
        run_tfhe_computation_shortint::<Z128, DKGParamsSnS>(
            prefix_path,
            num_parties,
            threshold,
            true,
        );
    }

    ///Tests related to [`BC_PARAMS_SAM_SNS`]
    #[test]
    #[ignore]
    fn keygen_params_blockchain_with_sns() {
        let params = BC_PARAMS_SAM_NO_SNS;
        let params_basics_handles = params.get_params_basics_handle();
        let num_parties = 5;
        let threshold = 1;
        let prefix_path = params_basics_handles.get_prefix_path();

        if !std::path::Path::new(&(prefix_path.clone() + "/params.json"))
            .try_exists()
            .unwrap()
        {
            _ = fs::create_dir(prefix_path.clone());
            run_dkg_and_save(params, num_parties, threshold, prefix_path.clone());
        }

        run_tfhe_computation_shortint::<Z128, DKGParamsRegular>(
            prefix_path.clone(),
            num_parties,
            threshold,
            true,
        );
        run_tfhe_computation_fheuint::<Z128, DKGParamsRegular>(
            prefix_path,
            num_parties,
            threshold,
            true,
        );
    }

    #[cfg(feature = "slow_tests")]
    fn run_real_dkg_and_save(
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        prefix_path: String,
    ) {
        use std::time::Duration;

        use crate::{
            execution::{
                config::BatchParams,
                online::preprocessing::create_memory_factory,
                runtime::session::{BaseSessionHandles, SmallSession, ToBaseSession},
                small_execution::{agree_random::DummyAgreeRandom, offline::SmallPreprocessing},
            },
            tests::helper::tests_and_benches::execute_protocol_small,
        };

        let params_basics_handles = params.get_params_basics_handle();
        params_basics_handles
            .write_to_file(format!("{}/params.json", prefix_path))
            .unwrap();

        let mut task = |mut session: SmallSession<ResiduePoly128>| async move {
            session
                .network()
                .set_timeout_for_next_round(Duration::from_secs(120))
                .unwrap();
            let batch_size = BatchParams {
                triples: params.get_params_basics_handle().total_triples_required(),
                randoms: params
                    .get_params_basics_handle()
                    .total_randomness_required(),
            };

            let mut small_preproc =
                SmallPreprocessing::<_, DummyAgreeRandom>::init(&mut session, batch_size)
                    .await
                    .unwrap();

            let mut dkg_preproc = create_memory_factory().create_dkg_preprocessing_with_sns();

            dkg_preproc
                .fill_from_base_preproc(
                    params,
                    &mut session.to_base_session().unwrap(),
                    &mut small_preproc,
                )
                .await
                .unwrap();

            let my_role = session.my_role().unwrap();
            let (pk, sk) = distributed_keygen(&mut session, dkg_preproc.as_mut(), params)
                .await
                .unwrap();

            (
                my_role,
                pk,
                sk.finalize_keyset(
                    params
                        .get_params_basics_handle()
                        .to_classic_pbs_parameters(),
                ),
            )
        };

        // Sync network because we also init the PRSS in the task
        let results = execute_protocol_small::<ResiduePoly128, _, _>(
            num_parties,
            threshold as u8,
            None,
            NetworkMode::Sync,
            None,
            &mut task,
        );

        let pk_ref = results[0].1.clone();

        for (role, pk, sk) in results {
            assert_eq!(pk, pk_ref);
            sk.write_to_file(format!("{}/sk_p{}.der", prefix_path, role.zero_based()))
                .unwrap();
        }

        pk_ref
            .write_to_file(format!("{}/pk.der", prefix_path))
            .unwrap();
    }

    ///Runs the DKG protocol with [`DummyPreprocessing`]
    /// and [`FakeBitGenEven`]. Saves the results to file.
    fn run_dkg_and_save(
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        prefix_path: String,
    ) {
        let params_basics_handles = params.get_params_basics_handle();
        params_basics_handles
            .write_to_file(format!("{}/params.json", prefix_path))
            .unwrap();

        let mut task = |mut session: LargeSession| async move {
            let my_role = session.my_role().unwrap();
            let mut large_preproc = DummyPreprocessing::new(0_u64, session.clone());

            let (pk, sk) =
                distributed_keygen::<Z128, _, _, _>(&mut session, &mut large_preproc, params)
                    .await
                    .unwrap();

            (
                my_role,
                pk,
                sk.finalize_keyset(
                    params
                        .get_params_basics_handle()
                        .to_classic_pbs_parameters(),
                ),
            )
        };

        //Async because the preprocessing is Dummy
        //Delay P1 by 1s every round
        let delay_vec = vec![std::time::Duration::from_secs(1)];
        let results = execute_protocol_large::<ResiduePoly128, _, _>(
            num_parties,
            threshold,
            None,
            NetworkMode::Async,
            Some(delay_vec),
            &mut task,
        );

        let pk_ref = results[0].1.clone();

        for (role, pk, sk) in results {
            assert_eq!(pk, pk_ref);
            sk.write_to_file(format!("{}/sk_p{}.der", prefix_path, role.zero_based()))
                .unwrap();
        }

        pk_ref
            .write_to_file(format!("{}/pk.der", prefix_path))
            .unwrap();
    }

    #[cfg(feature = "slow_tests")]
    fn run_homprf_keygen_and_save(
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
    ) -> LweBootstrapKey<Vec<u64>> {
        let mut task = |mut session: LargeSession| async move {
            // assume private key shares exist
            // TODO how to pass it into this closure nicely?
            let prefix_path = params.get_params_basics_handle().get_prefix_path();
            let (glwe_key_shares, _) =
                read_secret_key_shares_from_file(num_parties, params, prefix_path);

            let my_role = session.my_role().unwrap();
            let mut large_preproc = DummyPreprocessing::new(1_u64, session.clone());

            let share_ref = glwe_key_shares.get(&my_role).unwrap();
            let share = GlweSecretKeyShare {
                data: share_ref.to_vec(),
                polynomial_size: PolynomialSize(share_ref.len()),
            };
            let bsk = distributed_homprf_bsk_gen::<_, _, _, _, u64>(
                &share,
                &params,
                &mut large_preproc,
                &mut session,
            )
            .await
            .unwrap();
            (my_role, bsk)
        };

        //Async because the preprocessing is Dummy
        //Delay P1 by 1s every round
        let delay_vec = vec![std::time::Duration::from_secs(1)];
        let results = execute_protocol_large::<ResiduePoly128, _, _>(
            num_parties,
            threshold,
            None,
            NetworkMode::Async,
            Some(delay_vec),
            &mut task,
        );

        let bsk_ref = results[0].1.clone();

        for (_, bsk) in results {
            assert_eq!(bsk, bsk_ref);
        }

        let params_basics_handles = params.get_params_basics_handle();
        write_element(
            format!("{}/homprf_bsk.der", params_basics_handles.get_prefix_path()),
            &bsk_ref,
        )
        .unwrap();

        bsk_ref
    }

    fn run_switch_and_squash(prefix_path: String, num_parties: usize, threshold: usize) {
        let params = DKGParamsSnS::read_from_file(prefix_path.clone() + "/params.json").unwrap();
        let message = (params.get_message_modulus().0 - 1) as u8;

        let sk_lwe = reconstruct_lwe_secret_key_from_file(
            num_parties,
            threshold,
            &params,
            prefix_path.clone(),
        );
        let (sk_glwe, big_sk_glwe) = reconstruct_glwe_secret_key_from_file(
            num_parties,
            threshold,
            DKGParams::WithSnS(params),
            prefix_path.clone(),
        );
        let sk_large = SnsClientKey::new(
            params.to_classic_pbs_parameters(),
            big_sk_glwe.clone().unwrap(),
        );
        let pk = RawPubKeySet::read_from_file(format!("{}/pk.der", prefix_path)).unwrap();
        let pub_key_set = pk.to_pubkeyset(DKGParams::WithSnS(params));

        set_server_key(pub_key_set.server_key);

        let ddec_pk = pk.compute_tfhe_hl_api_compact_public_key(DKGParams::WithSnS(params));
        let ddec_sk = to_hl_client_key(&params.regular_params, sk_lwe.clone(), sk_glwe, None, None);

        let ck = pk.compute_switch_and_squash_key().unwrap();
        //Try and generate the bk_sns directly from the private keys
        let sk_lwe_lifted_128 = LweSecretKey::from_container(
            sk_lwe
                .into_container()
                .iter()
                .map(|bit| *bit as u128)
                .collect_vec(),
        );

        let mut bsk_out = LweBootstrapKey::new(
            0_u128,
            params.glwe_dimension_sns().to_glwe_size(),
            params.polynomial_size_sns(),
            params.decomposition_base_log_bk_sns(),
            params.decomposition_level_count_bk_sns(),
            params.lwe_dimension(),
            CoreCiphertextModulus::<u128>::new_native(),
        );
        let mut rng = get_rng();
        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(seed_from_rng(&mut rng));
        let mut enc_rng = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
            deterministic_seeder.seed(),
            &mut deterministic_seeder,
        );

        let big_sk_glwe = GlweSecretKey::from_container(
            big_sk_glwe.unwrap().into_container(),
            params.polynomial_size_sns(),
        );

        par_generate_lwe_bootstrap_key(
            &sk_lwe_lifted_128,
            &big_sk_glwe,
            &mut bsk_out,
            DynamicDistribution::TUniform(TUniform::new(params.glwe_tuniform_bound_sns().0 as u32)),
            &mut enc_rng,
        );
        let mut fbsk_out = Fourier128LweBootstrapKey::new(
            params.lwe_dimension(),
            params.glwe_dimension_sns().to_glwe_size(),
            params.polynomial_size_sns(),
            params.decomposition_base_log_bk_sns(),
            params.decomposition_level_count_bk_sns(),
        );

        convert_standard_lwe_bootstrap_key_to_fourier_128(&bsk_out, &mut fbsk_out);
        drop(bsk_out);

        let ck_bis = SwitchAndSquashKey::new(fbsk_out, ck.ksk.clone());

        let small_ct: FheUint64 = expanded_encrypt!(&ddec_pk, message as u64, 64);
        let (raw_ct, _id, _tag) = small_ct.clone().into_raw_parts();
        let large_ct = ck.to_large_ciphertext(&raw_ct).unwrap();
        let large_ct_bis = ck_bis.to_large_ciphertext(&raw_ct).unwrap();

        let res_small: u8 = small_ct.decrypt(&ddec_sk);
        let res_large = sk_large.decrypt_128(&large_ct);
        let res_large_bis = sk_large.decrypt_128(&large_ct_bis);

        assert_eq!(message, res_small);
        assert_eq!(message as u128, res_large_bis);
        assert_eq!(message as u128, res_large);
    }

    ///Runs only the shortint computation
    pub fn run_tfhe_computation_shortint<Z: BaseRing, Params: DKGParamsBasics>(
        prefix_path: String,
        num_parties: usize,
        threshold: usize,
        with_compact: bool,
    ) where
        ResiduePoly<Z>: ErrorCorrect,
    {
        let params = Params::read_from_file(prefix_path.clone() + "/params.json")
            .unwrap()
            .to_dkg_params();
        let (shortint_sk, pk) =
            retrieve_keys_from_files::<Z>(params, num_parties, threshold, prefix_path);
        let pub_key_set = pk.to_pubkeyset(params);

        set_server_key(pub_key_set.server_key);
        let shortint_pk = pk.compute_tfhe_shortint_server_key(params);
        for _ in 0..100 {
            try_tfhe_shortint_computation(&shortint_sk, &shortint_pk);
        }

        if with_compact {
            let tfhe_sk = tfhe::ClientKey::from_raw_parts(
                shortint_sk.into(),
                None,
                None,
                tfhe::Tag::default(),
            );
            let pub_key_set = pk.to_pubkeyset(params);
            try_tfhe_pk_compactlist_computation(
                &tfhe_sk,
                &pub_key_set.server_key,
                &pub_key_set.public_key,
            );
        }
    }

    ///Runs both shortint and fheuint computation
    fn run_tfhe_computation_fheuint<Z: BaseRing, Params: DKGParamsBasics>(
        prefix_path: String,
        num_parties: usize,
        threshold: usize,
        do_compression_test: bool,
    ) where
        ResiduePoly<Z>: ErrorCorrect,
    {
        let params = Params::read_from_file(prefix_path.clone() + "/params.json")
            .unwrap()
            .to_dkg_params();
        let (shortint_sk, pk) =
            retrieve_keys_from_files::<Z>(params, num_parties, threshold, prefix_path);

        let pub_key_set = pk.to_pubkeyset(params);

        set_server_key(pub_key_set.server_key);

        let shortint_pk = pk.compute_tfhe_shortint_server_key(params);
        for _ in 0..100 {
            try_tfhe_shortint_computation(&shortint_sk, &shortint_pk);
        }

        let tfhe_sk =
            tfhe::ClientKey::from_raw_parts(shortint_sk.into(), None, None, tfhe::Tag::default());

        try_tfhe_fheuint_computation(&tfhe_sk);
        if do_compression_test {
            try_tfhe_compression_computation(&tfhe_sk);
        }
    }

    ///Read files created by [`run_dkg_and_save`] and reconstruct the secret keys
    ///from the parties' shares
    fn retrieve_keys_from_files<Z: BaseRing>(
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        prefix_path: String,
    ) -> (tfhe::shortint::ClientKey, RawPubKeySet)
    where
        ResiduePoly<Z>: ErrorCorrect,
    {
        let params_tfhe_rs = params
            .get_params_basics_handle()
            .to_classic_pbs_parameters();

        let lwe_secret_key = reconstruct_lwe_secret_key_from_file(
            num_parties,
            threshold,
            params.get_params_basics_handle(),
            prefix_path.clone(),
        );
        let (glwe_secret_key, _) = reconstruct_glwe_secret_key_from_file(
            num_parties,
            threshold,
            params,
            prefix_path.clone(),
        );
        let pk = RawPubKeySet::read_from_file(format!("{}/pk.der", prefix_path)).unwrap();

        let shortint_client_key = tfhe::shortint::ClientKey::from_raw_parts(
            glwe_secret_key,
            lwe_secret_key,
            params_tfhe_rs.into(),
        );

        (shortint_client_key, pk)
    }

    //TFHE-rs doctest for shortint
    fn try_tfhe_shortint_computation(
        shortint_client_key: &tfhe::shortint::ClientKey,
        shortint_server_key: &tfhe::shortint::ServerKey,
    ) {
        let clear_a = 3u64;
        let clear_b = 3u64;
        let scalar = 4u8;

        let mut ct_1 = shortint_client_key.encrypt(clear_a);
        let mut ct_2 = shortint_client_key.encrypt(clear_b);

        shortint_server_key.smart_scalar_mul_assign(&mut ct_1, scalar);
        shortint_server_key.smart_sub_assign(&mut ct_1, &mut ct_2);
        shortint_server_key.smart_mul_lsb_assign(&mut ct_1, &mut ct_2);

        let clear_res: u64 = shortint_client_key.decrypt(&ct_1);

        let modulus = shortint_client_key.parameters.message_modulus().0;

        let expected_res = ((clear_a * scalar as u64 - clear_b) * clear_b) % modulus as u64;
        assert_eq!(clear_res, expected_res);
    }

    fn try_tfhe_pk_compactlist_computation(
        client_key: &tfhe::ClientKey,
        server_keys: &tfhe::ServerKey,
        pk: &tfhe::CompactPublicKey,
    ) {
        let clear_a = 3u64;
        let clear_b = 5u64;

        let compact_ctxt_list = tfhe::CompactCiphertextList::builder(pk)
            .push(clear_a)
            .push(clear_b)
            .build_packed();

        let result = {
            set_server_key(server_keys.clone());
            let all_keys = server_keys.clone().into_raw_parts();
            let cpk_ksk = all_keys.1;
            assert!(cpk_ksk.is_some());
            // Verify the ciphertexts
            let expander = compact_ctxt_list.expand().unwrap();
            let a: tfhe::FheUint64 = expander.get(0).unwrap().unwrap();
            let b: tfhe::FheUint64 = expander.get(1).unwrap().unwrap();

            a + b
        };

        let a_plus_b: u64 = result.decrypt(client_key);
        assert_eq!(a_plus_b, clear_a.wrapping_add(clear_b));
    }

    //TFHE-rs doctest for fheuint
    fn try_tfhe_fheuint_computation(client_key: &tfhe::ClientKey) {
        //// Key generation
        let clear_a = 1344u32;
        let clear_b = 5u32;
        let clear_c = 7u8;

        // Encrypting the input data using the (private) client_key
        // FheUint32: Encrypted equivalent to u32
        let mut encrypted_a = FheUint32::try_encrypt(clear_a, client_key).unwrap();
        let encrypted_b = FheUint32::try_encrypt(clear_b, client_key).unwrap();

        // FheUint8: Encrypted equivalent to u8
        let encrypted_c = FheUint8::try_encrypt(clear_c, client_key).unwrap();

        // Clear equivalent computations: 1344 * 5 = 6720
        let encrypted_res_mul = &encrypted_a * &encrypted_b;

        let clear_mult: u32 = encrypted_res_mul.decrypt(client_key);
        assert_eq!(clear_mult, 6720);

        // Clear equivalent computations: 6720 >> 5 = 210
        encrypted_a = &encrypted_res_mul >> &encrypted_b;

        let clear_after_shift: u16 = encrypted_a.decrypt(client_key);
        assert_eq!(clear_after_shift, 210);

        // Clear equivalent computations: let casted_a = a as u8;
        let casted_a: FheUint8 = encrypted_a.cast_into();

        // Clear equivalent computations: min(42, 7) = 7
        let encrypted_res_min = &casted_a.min(&encrypted_c);

        let clear_after_min: u8 = encrypted_res_min.decrypt(client_key);
        assert_eq!(clear_after_min, 7);

        // Operation between clear and encrypted data:
        // Clear equivalent computations: 7 & 1 = 1
        let encrypted_res = encrypted_res_min & 1_u8;

        let clear_res: u8 = encrypted_res.decrypt(client_key);
        assert_eq!(clear_res, 1);
    }

    fn try_tfhe_compression_computation(client_key: &tfhe::ClientKey) {
        let clear_a = 1344u32;
        let clear_b = 5u32;
        let clear_c = 7u8;

        // Encrypting the input data using the (private) client_key
        // FheUint32: Encrypted equivalent to u32
        let encrypted_a = FheUint32::try_encrypt(clear_a, client_key).unwrap();
        let encrypted_b = FheUint32::try_encrypt(clear_b, client_key).unwrap();

        // FheUint8: Encrypted equivalent to u8
        let encrypted_c = FheUint8::try_encrypt(clear_c, client_key).unwrap();

        let compressed = CompressedCiphertextListBuilder::new()
            .push(encrypted_a)
            .push(encrypted_b)
            .push(encrypted_c)
            .build()
            .unwrap();

        let decompressed: FheUint32 = compressed.get(0).unwrap().unwrap();
        let decrypted: u32 = decompressed.decrypt(client_key);
        assert_eq!(decrypted, clear_a);

        let decompressed: FheUint32 = compressed.get(1).unwrap().unwrap();
        let decrypted: u32 = decompressed.decrypt(client_key);
        assert_eq!(decrypted, clear_b);

        let decompressed: FheUint8 = compressed.get(2).unwrap().unwrap();
        let decrypted: u8 = decompressed.decrypt(client_key);
        assert_eq!(decrypted, clear_c);
    }

    // TODO: ideally we'd like to verify the homPRF output
    // against the plaintext output. But no plaintext implementation
    // of the PRF exists so we simply check that the PRF output
    // is different when the PRF key is different.
    #[cfg(feature = "slow_tests")]
    #[test]
    fn keygen_params32_no_sns_fglwe_w_homprf() {
        let params = PARAMS_TEST_BK_SNS.get_params_without_sns();
        let params_basics_handles = params.get_params_basics_handle();
        let num_parties = 2;
        let threshold = 0;

        if !std::path::Path::new(&params_basics_handles.get_prefix_path())
            .try_exists()
            .unwrap()
        {
            _ = fs::create_dir(params_basics_handles.get_prefix_path());
            run_dkg_and_save(
                params,
                num_parties,
                threshold,
                params_basics_handles.get_prefix_path(),
            );
        }
        run_tfhe_computation_shortint::<Z128, DKGParamsRegular>(
            params_basics_handles.get_prefix_path(),
            num_parties,
            threshold,
            true,
        );

        // generate new bsk used for the hom-prf
        // this assumes the regular evaluation keys exist
        let homprf_bsk_path = format!("{}/homprf_bsk.der", params_basics_handles.get_prefix_path());
        let homprf_bsk = if std::path::Path::new(&homprf_bsk_path).try_exists().unwrap() {
            read_element(homprf_bsk_path).unwrap()
        } else {
            run_homprf_keygen_and_save(params, num_parties, threshold)
        };

        // we need to create a new ServerKey with the new bsk
        let (sk, pk) = retrieve_keys_from_files::<Z128>(
            params,
            num_parties,
            threshold,
            params_basics_handles.get_prefix_path(),
        );
        let orig_pk = pk.compute_tfhe_shortint_server_key(params);
        let mut homprf_pk = orig_pk.clone();
        let mut homprf_fourier_bsk = FourierLweBootstrapKey::new(
            homprf_bsk.input_lwe_dimension(),
            homprf_bsk.glwe_size(),
            homprf_bsk.polynomial_size(),
            homprf_bsk.decomposition_base_log(),
            homprf_bsk.decomposition_level_count(),
        );

        // substitute bsk part of the original evaluation key
        par_convert_standard_lwe_bootstrap_key_to_fourier(&homprf_bsk, &mut homprf_fourier_bsk);
        homprf_pk.bootstrapping_key = ShortintBootstrappingKey::Classic(homprf_fourier_bsk);

        // run the homprf and make sure it's different
        // if we run the homprf using the original bsk
        let mut equals = 0usize;
        let count = 1000usize;
        // the probability for one output to be equal is 4/16
        // 4 possible ways to be equal out of 16 by counting
        // so expected value is (1/4)*count
        for s in 0..count {
            let ct = homprf_pk.generate_oblivious_pseudo_random(Seed(s as u128), 2);
            let out = sk.decrypt_message_and_carry(&ct);
            // run the homprf on a different set of keys and we should see some differences
            let ct2 = orig_pk.generate_oblivious_pseudo_random(Seed(s as u128), 2);
            let out2 = sk.decrypt_message_and_carry(&ct2);

            if out == out2 {
                equals += 1;
            }
        }

        // we can compute the exact binomial distribution
        // so k out of n are equals is
        // P(n,k,p) = binomial(n, k)*p^k*(1-p)^(n-k)
        // if we're interested in a range of k, then just sum it
        // sum_{i=k}^n P(n,i,p)
        // for n = 1000, k > 350 this is less than 1e-12
        println!("{equals} / {count}");
        assert!(equals < 350);
    }
}
