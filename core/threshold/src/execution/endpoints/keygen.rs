use std::path::Path;

use crate::algebra::base_ring::{Z128, Z64};
use crate::execution::online::preprocessing::{DKGPreprocessing, RandomPreprocessing};
use crate::execution::sharing::share::Share;
use crate::execution::tfhe_internals::compression_decompression_key::CompressionPrivateKeyShares;
use crate::execution::tfhe_internals::lwe_key::LweCompactPublicKeyShare;
use crate::execution::tfhe_internals::lwe_packing_keyswitch_key_generation::allocate_and_generate_lwe_packing_keyswitch_key;
use crate::execution::tfhe_internals::parameters::{
    BKParams, DKGParams, DistributedCompressionParameters, KSKParams, NoiseInfo,
};
use crate::execution::tfhe_internals::switch_and_squash::SwitchAndSquashKey;
use crate::{
    algebra::{
        galois_rings::common::ResiduePoly,
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
use tfhe_csprng::generators::SoftwareRandomGenerator;
use tfhe_versionable::VersionsDispatch;
use tracing::instrument;

#[derive(Clone, Serialize, Deserialize)]
pub struct FhePubKeySet {
    pub public_key: tfhe::CompactPublicKey,
    pub server_key: tfhe::ServerKey,
    pub sns_key: Option<SwitchAndSquashKey>,
}

impl FhePubKeySet {
    pub fn write_to_file(&self, path: &Path) -> anyhow::Result<()> {
        write_element(path, self)
    }

    pub fn read_from_file(path: &Path) -> anyhow::Result<Self> {
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
    pub fn write_to_file(&self, path: &Path) -> anyhow::Result<()> {
        write_element(path, self)
    }

    #[allow(dead_code)]
    pub fn read_from_file(path: &Path) -> anyhow::Result<Self> {
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
        // TODO add `modulus_switch_noise_reduction_key` to RawPubKeySet
        par_convert_standard_lwe_bootstrap_key_to_fourier(&self.bk, &mut fourier_bsk);

        let pk_bk = ShortintBootstrappingKey::Classic {
            bsk: fourier_bsk,
            modulus_switch_noise_reduction_key: None,
        };

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

struct GenericPrivateKeySet<Z: Clone, const EXTENSION_DEGREE: usize> {
    //The two Lwe keys are the same if there's no dedicated pk parameters
    pub lwe_encryption_secret_key_share: LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    pub lwe_secret_key_share: LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    pub glwe_secret_key_share: GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    pub glwe_secret_key_share_sns: Option<GlweSecretKeyShare<Z, EXTENSION_DEGREE>>,
    pub glwe_secret_key_share_compression: Option<CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum PrivateKeySetVersioned<const EXTENSION_DEGREE: usize> {
    V0(PrivateKeySet<EXTENSION_DEGREE>),
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize, PartialEq)]
#[versionize(PrivateKeySetVersioned)]
pub struct PrivateKeySet<const EXTENSION_DEGREE: usize> {
    //The two Lwe keys are the same if there's no dedicated pk parameters
    pub lwe_encryption_secret_key_share: LweSecretKeyShare<Z64, EXTENSION_DEGREE>,
    pub lwe_compute_secret_key_share: LweSecretKeyShare<Z64, EXTENSION_DEGREE>,
    // eventually we'll remove the enum here when we support more Z64+Z128 preproc
    pub glwe_secret_key_share: GlweSecretKeyShareEnum<EXTENSION_DEGREE>,
    pub glwe_secret_key_share_sns_as_lwe: Option<LweSecretKeyShare<Z128, EXTENSION_DEGREE>>,
    // eventually we'll remove the enum here when we support more Z64+Z128 preproc
    pub glwe_secret_key_share_compression:
        Option<CompressionPrivateKeySharesEnum<EXTENSION_DEGREE>>,
    pub parameters: ClassicPBSParameters,
}

#[derive(Clone, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum CompressionPrivateKeySharesEnumVersioned<const EXTENSION_DEGREE: usize> {
    V0(CompressionPrivateKeySharesEnum<EXTENSION_DEGREE>),
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize, PartialEq)]
#[versionize(CompressionPrivateKeySharesEnumVersioned)]
pub enum CompressionPrivateKeySharesEnum<const EXTENSION_DEGREE: usize> {
    Z64(CompressionPrivateKeyShares<Z64, EXTENSION_DEGREE>),
    Z128(CompressionPrivateKeyShares<Z128, EXTENSION_DEGREE>),
}

#[derive(Clone, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum GlweSecretKeyShareEnumVersioned<const EXTENSION_DEGREE: usize> {
    V0(GlweSecretKeyShareEnum<EXTENSION_DEGREE>),
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize, PartialEq)]
#[versionize(GlweSecretKeyShareEnumVersioned)]
pub enum GlweSecretKeyShareEnum<const EXTENSION_DEGREE: usize> {
    Z64(GlweSecretKeyShare<Z64, EXTENSION_DEGREE>),
    Z128(GlweSecretKeyShare<Z128, EXTENSION_DEGREE>),
}

#[cfg(test)]
impl<const EXTENSION_DEGREE: usize> GlweSecretKeyShareEnum<EXTENSION_DEGREE> {
    pub(crate) fn unsafe_cast_to_z64(self) -> GlweSecretKeyShare<Z64, EXTENSION_DEGREE> {
        match self {
            GlweSecretKeyShareEnum::Z64(inner) => inner,
            GlweSecretKeyShareEnum::Z128(_) => panic!("not z64"),
        }
    }

    pub(crate) fn unsafe_cast_to_z128(self) -> GlweSecretKeyShare<Z128, EXTENSION_DEGREE> {
        match self {
            GlweSecretKeyShareEnum::Z64(_) => panic!("not z128"),
            GlweSecretKeyShareEnum::Z128(inner) => inner,
        }
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            GlweSecretKeyShareEnum::Z64(inner) => inner.data.len(),
            GlweSecretKeyShareEnum::Z128(inner) => inner.data.len(),
        }
    }

    pub(crate) fn polynomial_size(&self) -> tfhe::boolean::prelude::PolynomialSize {
        match self {
            GlweSecretKeyShareEnum::Z64(inner) => inner.polynomial_size,
            GlweSecretKeyShareEnum::Z128(inner) => inner.polynomial_size,
        }
    }
}

impl<const EXTENSION_DEGREE: usize> PrivateKeySet<EXTENSION_DEGREE> {
    pub fn write_to_file(&self, path: &Path) -> anyhow::Result<()> {
        write_element(path, self)
    }

    pub fn read_from_file(path: &Path) -> anyhow::Result<Self> {
        read_element(path)
    }
}

impl<const EXTENSION_DEGREE: usize> GenericPrivateKeySet<Z128, EXTENSION_DEGREE>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
{
    pub fn finalize_keyset(
        self,
        parameters: ClassicPBSParameters,
    ) -> PrivateKeySet<EXTENSION_DEGREE> {
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
                // TODO before we turn it to Z64 using to_residuepoly64, but we need Z128
                // as it's used by the core/service preprocessing.
                // this part needs to be reworked when we support Z64+Z128 preprocessing
                let converted_value = share.value();
                Share::new(share.owner(), converted_value)
            })
            .collect_vec();
        let converted_glwe_secret_key_share = GlweSecretKeyShareEnum::Z128(GlweSecretKeyShare {
            data: glwe_data,
            polynomial_size: self.glwe_secret_key_share.polynomial_size,
        });

        let glwe_secret_key_share_sns_as_lwe = self
            .glwe_secret_key_share_sns
            .map(|key| key.into_lwe_secret_key());

        let glwe_secret_key_share_compression = self.glwe_secret_key_share_compression.map_or_else(
            || None,
            |key| {
                let polynomial_size = key.polynomial_size();
                Some(CompressionPrivateKeySharesEnum::Z128(
                    CompressionPrivateKeyShares {
                        post_packing_ks_key: GlweSecretKeyShare {
                            data: key
                                .post_packing_ks_key
                                .data
                                .into_iter()
                                .map(|share| {
                                    // TODO before we turn it to Z64 using to_residuepoly64, but we need Z128
                                    // as it's used by the core/service preprocessing.
                                    // this part needs to be reworked when we support Z64+Z128 preprocessing
                                    let converted_value = share.value();
                                    Share::new(share.owner(), converted_value)
                                })
                                .collect_vec(),
                            polynomial_size,
                        },
                        params: key.params,
                    },
                ))
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

impl<const EXTENSION_DEGREE: usize> GenericPrivateKeySet<Z64, EXTENSION_DEGREE> {
    pub fn finalize_keyset(
        self,
        parameters: ClassicPBSParameters,
    ) -> PrivateKeySet<EXTENSION_DEGREE> {
        PrivateKeySet {
            lwe_encryption_secret_key_share: self.lwe_encryption_secret_key_share,
            lwe_compute_secret_key_share: self.lwe_secret_key_share,
            glwe_secret_key_share: GlweSecretKeyShareEnum::Z64(self.glwe_secret_key_share),
            glwe_secret_key_share_sns_as_lwe: None,
            glwe_secret_key_share_compression: self
                .glwe_secret_key_share_compression
                .map(CompressionPrivateKeySharesEnum::Z64),
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
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    Gen: ByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    params: &DKGParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<(
    LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    LweCompactPublicKeyShare<Z, EXTENSION_DEGREE>,
)>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let params = params.get_params_basics_handle();
    let my_role = session.my_role()?;
    //Init the shared LWE secret key
    tracing::info!("(Party {my_role}) Generating LWE Secret key...Start");
    let lwe_secret_key_share =
        LweSecretKeyShare::new_from_preprocessing(params.lwe_hat_dimension(), preprocessing)?;
    tracing::info!("(Party {my_role}) Generating corresponding public key...Start");
    let NoiseInfo { amount, bound } = params.num_needed_noise_pk();
    let vec_tuniform_noise = preprocessing
        .next_noise_vec(amount, bound)?
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
#[instrument(name="Gen Lwe keys",skip( mpc_encryption_rng, session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_lwe_private_public_key_pair<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    Gen: ByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    params: &DKGParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<(
    LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    LweCompactPublicKey<Vec<u64>>,
)>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
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
#[instrument(name="Gen KSK",skip(input_lwe_sk, output_lwe_sk, mpc_encryption_rng, session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_key_switch_key<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    Gen: ByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    input_lwe_sk: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    output_lwe_sk: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    params: &KSKParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<LweKeyswitchKey<Vec<u64>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
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
#[instrument(name="Gen BK", skip(glwe_secret_key_share, lwe_secret_key_share, mpc_encryption_rng, session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_bootstrap_key<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    Gen: ByteRandomGenerator,
    Scalar: UnsignedInteger,
    const EXTENSION_DEGREE: usize,
>(
    glwe_secret_key_share: &GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    lwe_secret_key_share: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    params: BKParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<LweBootstrapKey<Vec<Scalar>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
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

#[instrument(name="Gen Decompression Key", skip(private_glwe_compute_key, private_compression_key, mpc_encryption_rng, session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_decompression_keys<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    Gen: ByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    private_glwe_compute_key: &GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    private_compression_key: &CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>,
    params: DistributedCompressionParameters,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<DecompressionKey>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
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

    // TODO implement `modulus_switch_noise_reduction_key` keygen
    let blind_rotate_key = ShortintBootstrappingKey::Classic {
        bsk: fourier_bsk,
        modulus_switch_noise_reduction_key: None,
    };

    let decompression_key = DecompressionKey {
        blind_rotate_key,
        lwe_per_glwe: params.raw_compression_parameters.lwe_per_glwe,
    };
    Ok(decompression_key)
}

#[instrument(name="Gen Compression and Decompression Key", skip(private_glwe_compute_key_as_lwe, private_glwe_compute_key, private_compression_key, mpc_encryption_rng, session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn generate_compression_decompression_keys<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + ?Sized,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    Gen: ByteRandomGenerator,
    const EXTENSION_DEGREE: usize,
>(
    private_glwe_compute_key_as_lwe: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    private_glwe_compute_key: &GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    private_compression_key: &CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>,
    params: DistributedCompressionParameters,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<(CompressionKey, DecompressionKey)>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
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

    let decompression_key = generate_decompression_keys(
        private_glwe_compute_key,
        private_compression_key,
        params,
        mpc_encryption_rng,
        session,
        preprocessing,
    )
    .await?;

    Ok((compression_key, decompression_key))
}

/// Runs the distributed key generation protocol.
///
/// Inputs:
/// - `session`: the session that holds necessary information for networking
/// - `preprocessing`: [`DKGPreprocessing`] handle with enough triples, bits and noise available
/// - `params`: [`DKGParams`] parameters for the Distributed Key Generation
///
/// Outputs:
/// - A [`RawPubKeySet`] composed of the public key, the KSK, the BK and the BK_sns if required
/// - a [`PrivateKeySet`] composed of shares of the lwe and glwe private keys
///
/// When using the DKGParams::WithSnS variant, the sharing domain must be ResiduePoly<Z128, EXTENSION_DEGREE>.
/// Note that there is some redundancy of information because we also explicitly ask the [`BaseRing`] as trait parameter
#[instrument(name="TFHE.Threshold-KeyGen", skip(session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
async fn distributed_keygen<
    Z: BaseRing,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send + ?Sized,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
) -> anyhow::Result<(RawPubKeySet, GenericPrivateKeySet<Z, EXTENSION_DEGREE>)>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    distributed_keygen_from_optional_compression_sk(session, preprocessing, params, None).await
}

/// Note that in the return value, it is possible for [CompressionPrivateKeyShares] to be None
/// while [CompressionKey], [DecompressionKey] exists because we do not copy the secret shares again.
async fn distributed_keygen_compression_material<
    Z: BaseRing,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send + ?Sized,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<
        Z,
        SoftwareRandomGenerator,
        EXTENSION_DEGREE,
    >,
    glwe_sk_share_as_lwe: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    glwe_secret_key_share: &GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
    glwe_secret_key_share_compression: Option<&CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
) -> anyhow::Result<(
    Option<CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
    Option<(CompressionKey, DecompressionKey)>,
)>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let params_basics_handle = params.get_params_basics_handle();

    let compression_material = if let Some(comp_params) =
        params_basics_handle.get_compression_decompression_params()
    {
        match glwe_secret_key_share_compression {
            Some(inner) => {
                let compression_keys = generate_compression_decompression_keys(
                    glwe_sk_share_as_lwe,
                    glwe_secret_key_share,
                    inner,
                    comp_params,
                    mpc_encryption_rng,
                    session,
                    preprocessing,
                )
                .await?;
                (None, Some(compression_keys))
            }
            None => {
                let private_compression_key = CompressionPrivateKeyShares::new_from_preprocessing(
                    comp_params.raw_compression_parameters,
                    preprocessing,
                )?;

                let compression_keys = generate_compression_decompression_keys(
                    glwe_sk_share_as_lwe,
                    glwe_secret_key_share,
                    &private_compression_key,
                    comp_params,
                    mpc_encryption_rng,
                    session,
                    preprocessing,
                )
                .await?;
                (Some(private_compression_key), Some(compression_keys))
            }
        }
    } else {
        (None, None)
    };
    Ok(compression_material)
}

/// Runs the distributed key generation protocol but optionally
/// uses an existing compression secret key.
///
/// Inputs:
/// - `session`: the session that holds necessary information for networking
/// - `preprocessing`: [`DKGPreprocessing`] handle with enough triples, bits and noise available
/// - `params`: [`DKGParams`] parameters for the Distributed Key Generation
/// - `existing_compression_sk`: an optional compression secret key,
///   a new one is generated if this argument is None.
///
/// Outputs:
/// - A [`RawPubKeySet`] composed of the public key, the KSK, the BK and the BK_sns if required
/// - a [`PrivateKeySet`] composed of shares of the lwe and glwe private keys
///
/// When using the DKGParams::WithSnS variant, the sharing domain must be ResiduePoly<Z128, EXTENSION_DEGREE>.
/// Note that there is some redundancy of information because we also explicitly ask the [`BaseRing`] as trait parameter
async fn distributed_keygen_from_optional_compression_sk<
    Z: BaseRing,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send + ?Sized,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
    existing_compression_sk: Option<&CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
) -> anyhow::Result<(RawPubKeySet, GenericPrivateKeySet<Z, EXTENSION_DEGREE>)>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let params_basics_handle = params.get_params_basics_handle();
    let my_role = session.my_role()?;
    let seed = sample_seed(params_basics_handle.get_sec(), session, preprocessing).await?;
    //Init the XOF with the seed computed above
    let mut mpc_encryption_rng = MPCEncryptionRandomGenerator::<
        Z,
        SoftwareRandomGenerator,
        EXTENSION_DEGREE,
    >::new_from_seed(seed);

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
    //Generate the compression keys, we'll have None if there are no
    //compression materials to generate
    let compression_material = distributed_keygen_compression_material(
        session,
        preprocessing,
        params,
        &mut mpc_encryption_rng,
        &glwe_sk_share_as_lwe,
        &glwe_secret_key_share,
        existing_compression_sk,
    )
    .await?;

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

    // note that glwe_secret_key_share_compression may be None even if compression_keys is Some
    // this is because we might have generated the compression keys from an existing compression sk share
    let (glwe_secret_key_share_compression, compression_keys) = compression_material;

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
    P: DKGPreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>> + Send + ?Sized,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
{
    if let DKGParams::WithSnS(_) = params {
        return Err(anyhow_error_and_log(
            "Can not generate Switch and Squash key with ResiduePolyF8Z64".to_string(),
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
    P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
{
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

#[instrument(name="DKG with optional compression SK Z128", skip(existing_compression_sk, session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
pub async fn distributed_keygen_from_optional_compression_sk_z128<
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
    existing_compression_sk: Option<&CompressionPrivateKeyShares<Z128, EXTENSION_DEGREE>>,
) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
{
    let (pub_key_set, priv_key_set) = distributed_keygen_from_optional_compression_sk(
        session,
        preprocessing,
        params,
        existing_compression_sk,
    )
    .await?;
    Ok((
        pub_key_set.to_pubkeyset(params),
        priv_key_set.finalize_keyset(
            params
                .get_params_basics_handle()
                .to_classic_pbs_parameters(),
        ),
    ))
}

#[instrument(name="Gen Decompression Key Z128", skip(private_glwe_compute_key, private_compression_key, session, preprocessing), fields(sid = ?session.session_id(), own_identity = ?session.own_identity()))]
pub async fn distributed_decompression_keygen_z128<
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
    private_glwe_compute_key: &GlweSecretKeyShare<Z128, EXTENSION_DEGREE>,
    private_compression_key: &CompressionPrivateKeyShares<Z128, EXTENSION_DEGREE>,
) -> anyhow::Result<DecompressionKey>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
{
    let params_basics_handle = params.get_params_basics_handle();
    let seed = sample_seed(params_basics_handle.get_sec(), session, preprocessing).await?;
    //Init the XOF with the seed computed above
    let mut mpc_encryption_rng = MPCEncryptionRandomGenerator::<
        Z128,
        SoftwareRandomGenerator,
        EXTENSION_DEGREE,
    >::new_from_seed(seed);

    let params = params_basics_handle
        .get_compression_decompression_params()
        .ok_or(anyhow::anyhow!("missing (de)compression parameters"))?;

    generate_decompression_keys(
        private_glwe_compute_key,
        private_compression_key,
        params,
        &mut mpc_encryption_rng,
        session,
        preprocessing,
    )
    .await
}

#[cfg(test)]
pub mod tests {
    use crate::execution::{
        random::{get_rng, seed_from_rng},
        tfhe_internals::{
            parameters::{
                DKGParams, BC_PARAMS_SAM_NO_SNS, NIST_PARAMS_P32_NO_SNS_FGLWE,
                NIST_PARAMS_P32_NO_SNS_LWE, NIST_PARAMS_P32_SNS_FGLWE, NIST_PARAMS_P8_NO_SNS_FGLWE,
                NIST_PARAMS_P8_NO_SNS_LWE, NIST_PARAMS_P8_SNS_FGLWE, OLD_PARAMS_P32_REAL_WITH_SNS,
                PARAMS_TEST_BK_SNS,
            },
            switch_and_squash::SwitchAndSquashKey,
            test_feature::to_hl_client_key,
            utils::tests::reconstruct_glwe_secret_key_from_file,
        },
    };
    use crate::{
        algebra::{
            base_ring::{Z128, Z64},
            galois_rings::common::ResiduePoly,
            structure_traits::{ErrorCorrect, Invert, Ring, Solve},
        },
        execution::{
            online::preprocessing::dummy::DummyPreprocessing,
            runtime::session::{LargeSession, ParameterHandles},
            tfhe_internals::{
                parameters::{DKGParamsBasics, DKGParamsRegular, DKGParamsSnS},
                utils::expanded_encrypt,
            },
        },
        tests::helper::tests_and_benches::execute_protocol_large,
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
    use itertools::Itertools;
    use std::path::Path;
    use tfhe::{
        core_crypto::{
            algorithms::{
                convert_standard_lwe_bootstrap_key_to_fourier_128, par_generate_lwe_bootstrap_key,
            },
            commons::{
                generators::{DeterministicSeeder, EncryptionRandomGenerator},
                math::random::{DefaultRandomGenerator, TUniform},
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
    use tfhe_csprng::seeders::Seeder;

    #[cfg(feature = "slow_tests")]
    use super::{distributed_keygen, distributed_keygen_from_optional_compression_sk};

    #[cfg(feature = "slow_tests")]
    use tokio::time::Duration;

    #[cfg(feature = "slow_tests")]
    use crate::{
        execution::{
            config::BatchParams,
            keyset_config::KeySetConfig,
            online::preprocessing::create_memory_factory,
            runtime::session::{BaseSessionHandles, SmallSession, ToBaseSession},
            small_execution::{agree_random::DummyAgreeRandom, offline::SmallPreprocessing},
            tfhe_internals::test_feature::run_decompression_test,
        },
        tests::helper::tests_and_benches::execute_protocol_small,
    };

    #[cfg(not(target_arch = "aarch64"))]
    #[test]
    fn pure_tfhers_test() {
        let params = crate::execution::tfhe_internals::parameters::NIST_PARAMS_P32_INTERNAL_FGLWE;
        let classic_pbs = params.ciphertext_parameters;
        let dedicated_cpk_params = params.dedicated_compact_public_key_parameters.unwrap();

        let config = tfhe::ConfigBuilder::with_custom_parameters(classic_pbs)
            .use_dedicated_compact_public_key_parameters(dedicated_cpk_params);

        let client_key = tfhe::ClientKey::generate(config.clone());
        let server_key = tfhe::ServerKey::new(&client_key);
        let public_key = tfhe::CompactPublicKey::try_new(&client_key).unwrap();

        try_tfhe_pk_compactlist_computation(&client_key, &server_key, &public_key);
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    #[ignore]
    fn old_keygen_params32_with_sns_f8() {
        old_keygen_params32_with_sns::<8>()
    }

    #[test]
    #[ignore]
    fn old_keygen_params32_with_sns_f4() {
        old_keygen_params32_with_sns::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    #[ignore]
    fn old_keygen_params32_with_sns_f3() {
        old_keygen_params32_with_sns::<3>()
    }

    fn old_keygen_params32_with_sns<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = OLD_PARAMS_P32_REAL_WITH_SNS;
        let num_parties = 5;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_dkg_and_save(params, num_parties, threshold, temp_dir.path());

        run_switch_and_squash(temp_dir.path(), num_parties, threshold);

        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsSnS>(
            temp_dir.path(),
            num_parties,
            threshold,
            false,
        );
        run_tfhe_computation_fheuint::<EXTENSION_DEGREE, DKGParamsSnS>(
            temp_dir.path(),
            num_parties,
            threshold,
            false,
        );
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    #[ignore]
    fn keygen_params32_no_sns_fglwe_f8() {
        keygen_params32_no_sns_fglwe::<8>()
    }

    #[test]
    #[ignore]
    fn keygen_params32_no_sns_fglwe_f4() {
        keygen_params32_no_sns_fglwe::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    #[ignore]
    fn keygen_params32_no_sns_fglwe_f3() {
        keygen_params32_no_sns_fglwe::<3>()
    }

    ///Tests related to [`PARAMS_P32_NO_SNS_FGLWE`]
    fn keygen_params32_no_sns_fglwe<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = NIST_PARAMS_P32_NO_SNS_FGLWE;
        let num_parties = 5;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_dkg_and_save(params, num_parties, threshold, temp_dir.path());

        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsRegular>(
            temp_dir.path(),
            num_parties,
            threshold,
            true,
        );
        run_tfhe_computation_fheuint::<EXTENSION_DEGREE, DKGParamsRegular>(
            temp_dir.path(),
            num_parties,
            threshold,
            false,
        );
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    #[ignore]
    fn keygen_params8_no_sns_fglwe_f8() {
        keygen_params8_no_sns_fglwe::<8>()
    }

    #[test]
    #[ignore]
    fn keygen_params8_no_sns_fglwe_f4() {
        keygen_params8_no_sns_fglwe::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    #[ignore]
    fn keygen_params8_no_sns_fglwe_f3() {
        keygen_params8_no_sns_fglwe::<3>()
    }

    ///Tests related to [`PARAMS_P8_NO_SNS_FGLWE`]
    fn keygen_params8_no_sns_fglwe<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = NIST_PARAMS_P8_NO_SNS_FGLWE;
        let num_parties = 5;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_dkg_and_save(params, num_parties, threshold, temp_dir.path());

        //This parameter set isnt big enough to run the fheuint tests
        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsRegular>(
            temp_dir.path(),
            num_parties,
            threshold,
            true,
        );
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    #[ignore]
    fn keygen_params32_no_sns_lwe_f8() {
        keygen_params32_no_sns_lwe::<8>()
    }

    #[test]
    #[ignore]
    fn keygen_params32_no_sns_lwe_f4() {
        keygen_params32_no_sns_lwe::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    #[ignore]
    fn keygen_params32_no_sns_lwe_f3() {
        keygen_params32_no_sns_lwe::<3>()
    }

    ///Tests related to [`PARAMS_P32_NO_SNS_LWE`]
    fn keygen_params32_no_sns_lwe<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = NIST_PARAMS_P32_NO_SNS_LWE;
        let num_parties = 5;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_dkg_and_save(params, num_parties, threshold, temp_dir.path());

        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsRegular>(
            temp_dir.path(),
            num_parties,
            threshold,
            true,
        );
        run_tfhe_computation_fheuint::<EXTENSION_DEGREE, DKGParamsRegular>(
            temp_dir.path(),
            num_parties,
            threshold,
            false,
        );
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    #[ignore]
    fn keygen_params8_no_sns_lwe_f8() {
        keygen_params8_no_sns_lwe::<8>()
    }

    #[test]
    #[ignore]
    fn keygen_params8_no_sns_lwe_f4() {
        keygen_params8_no_sns_lwe::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    #[ignore]
    fn keygen_params8_no_sns_lwe_f3() {
        keygen_params8_no_sns_lwe::<3>()
    }

    ///Tests related to [`PARAMS_P8_NO_SNS_LWE`]
    fn keygen_params8_no_sns_lwe<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = NIST_PARAMS_P8_NO_SNS_LWE;
        let num_parties = 5;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_dkg_and_save(params, num_parties, threshold, temp_dir.path());

        //This parameter set isnt big enough to run the fheuint tests
        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsRegular>(
            temp_dir.path(),
            num_parties,
            threshold,
            true,
        );
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    #[ignore]
    fn keygen_params_bk_sns_f8() {
        keygen_params_bk_sns::<8>()
    }

    #[test]
    #[ignore]
    fn keygen_params_bk_sns_f4() {
        keygen_params_bk_sns::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    #[ignore]
    fn keygen_params_bk_sns_f3() {
        keygen_params_bk_sns::<3>()
    }

    ///Tests related to [`PARAMS_TEST_BK_SNS`]
    fn keygen_params_bk_sns<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = PARAMS_TEST_BK_SNS;
        let num_parties = 5;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_dkg_and_save(params, num_parties, threshold, temp_dir.path());

        run_switch_and_squash(temp_dir.path(), num_parties, threshold);

        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsSnS>(
            temp_dir.path(),
            num_parties,
            threshold,
            true,
        );
        run_tfhe_computation_fheuint::<EXTENSION_DEGREE, DKGParamsSnS>(
            temp_dir.path(),
            num_parties,
            threshold,
            true,
        );
    }

    #[cfg(feature = "slow_tests")]
    #[test]
    fn integration_keygen_params_bk_sns_f8() {
        integration_keygen_params_bk_sns::<8>(KeySetConfig::default())
    }

    #[cfg(feature = "slow_tests")]
    #[test]
    fn integration_keygen_params_bk_sns_f4() {
        integration_keygen_params_bk_sns::<4>(KeySetConfig::default())
    }

    #[cfg(feature = "slow_tests")]
    #[test]
    fn integration_keygen_params_bk_sns_f3() {
        integration_keygen_params_bk_sns::<3>(KeySetConfig::default())
    }

    #[cfg(feature = "slow_tests")]
    #[test]
    fn integration_keygen_params_bk_sns_existing_compression_sk_f4() {
        integration_keygen_params_bk_sns::<4>(KeySetConfig::use_existing_compression_sk())
    }

    #[cfg(feature = "slow_tests")]
    ///Tests related to [`PARAMS_TEST_BK_SNS`] using _less fake_ preprocessing
    fn integration_keygen_params_bk_sns<const EXTENSION_DEGREE: usize>(keyset_config: KeySetConfig)
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = PARAMS_TEST_BK_SNS;
        let num_parties = 4;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_real_dkg_and_save(
            params,
            num_parties,
            threshold,
            temp_dir.path(),
            keyset_config,
        );

        run_switch_and_squash(temp_dir.path(), num_parties, threshold);

        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsSnS>(
            temp_dir.path(),
            num_parties,
            threshold,
            true,
        );
        run_tfhe_computation_fheuint::<EXTENSION_DEGREE, DKGParamsSnS>(
            temp_dir.path(),
            num_parties,
            threshold,
            true,
        );
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    #[ignore]
    fn keygen_params32_with_sns_fglwe_f8() {
        keygen_params32_with_sns_fglwe::<8>()
    }

    #[test]
    #[ignore]
    fn keygen_params32_with_sns_fglwe_f4() {
        keygen_params32_with_sns_fglwe::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    #[ignore]
    fn keygen_params32_with_sns_fglwe_f3() {
        keygen_params32_with_sns_fglwe::<3>()
    }

    ///Tests related to [`PARAMS_P32_SNS_FGLWE`]
    fn keygen_params32_with_sns_fglwe<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = NIST_PARAMS_P32_SNS_FGLWE;
        let num_parties = 5;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_dkg_and_save(params, num_parties, threshold, temp_dir.path());

        run_switch_and_squash(temp_dir.path(), num_parties, threshold);

        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsSnS>(
            temp_dir.path(),
            num_parties,
            threshold,
            true,
        );
        run_tfhe_computation_fheuint::<EXTENSION_DEGREE, DKGParamsSnS>(
            temp_dir.path(),
            num_parties,
            threshold,
            false,
        );
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    #[ignore]
    fn keygen_params8_with_sns_fglwe_f8() {
        keygen_params8_with_sns_fglwe::<8>()
    }

    #[test]
    #[ignore]
    fn keygen_params8_with_sns_fglwe_f4() {
        keygen_params8_with_sns_fglwe::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    #[ignore]
    fn keygen_params8_with_sns_fglwe_f3() {
        keygen_params8_with_sns_fglwe::<3>()
    }

    ///Tests related to [`PARAMS_P8_REAL_WITH_SNS`]
    fn keygen_params8_with_sns_fglwe<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = NIST_PARAMS_P8_SNS_FGLWE;
        let num_parties = 5;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_dkg_and_save(params, num_parties, threshold, temp_dir.path());

        run_switch_and_squash(temp_dir.path(), num_parties, threshold);

        //This parameter set isnt big enough to run the fheuint tests
        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsSnS>(
            temp_dir.path(),
            num_parties,
            threshold,
            true,
        );
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    #[ignore]
    fn keygen_params_blockchain_without_sns_f8() {
        keygen_params_blockchain_without_sns::<8>()
    }

    #[test]
    #[ignore]
    fn keygen_params_blockchain_without_sns_f4() {
        keygen_params_blockchain_without_sns::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    #[ignore]
    fn keygen_params_blockchain_without_sns_f3() {
        keygen_params_blockchain_without_sns::<3>()
    }

    ///Tests related to [`BC_PARAMS_SAM_NO_SNS`]
    fn keygen_params_blockchain_without_sns<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = BC_PARAMS_SAM_NO_SNS;
        let num_parties = 5;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();

        run_dkg_and_save(params, num_parties, threshold, temp_dir.path());

        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsRegular>(
            temp_dir.path(),
            num_parties,
            threshold,
            true,
        );
        run_tfhe_computation_fheuint::<EXTENSION_DEGREE, DKGParamsRegular>(
            temp_dir.path(),
            num_parties,
            threshold,
            true,
        );
    }

    // taken from https://stackoverflow.com/questions/64498617/how-to-transpose-a-vector-of-vectors-in-rust
    #[cfg(feature = "slow_tests")]
    fn transpose2<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
        assert!(!v.is_empty());
        let len = v[0].len();
        let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();
        (0..len)
            .map(|_| {
                iters
                    .iter_mut()
                    .map(|n| n.next().unwrap())
                    .collect::<Vec<T>>()
            })
            .collect()
    }

    #[cfg(feature = "slow_tests")]
    fn vec64_to_shares128<R: rand::Rng + rand::CryptoRng, const EXTENSION_DEGREE: usize>(
        v: Vec<u64>,
        n: usize,
        t: usize,
        rng: &mut R,
    ) -> Vec<Vec<crate::execution::sharing::share::Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    {
        use crate::execution::sharing::shamir::{InputOp, ShamirSharings};
        use std::num::Wrapping;
        transpose2(
            v.into_iter()
                .map(|s| {
                    let s = ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<u128>(
                        s as u128,
                    ));
                    ShamirSharings::share(rng, s, n, t).unwrap().shares
                })
                .collect::<Vec<Vec<_>>>(),
        )
    }

    #[cfg(feature = "slow_tests")]
    fn run_real_decompression_dkg_and_save<const EXTENSION_DEGREE: usize>(
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        prefix_path: &Path,
    ) where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    {
        // first we need to generate two server keys
        use crate::{
            execution::{
                endpoints::keygen::distributed_decompression_keygen_z128,
                sharing::share::Share,
                tfhe_internals::{
                    compression_decompression_key::CompressionPrivateKeyShares,
                    glwe_key::GlweSecretKeyShare, test_feature::gen_key_set,
                },
            },
            file_handling::{read_element, write_element},
        };

        let keyset_config = KeySetConfig::DecompressionOnly;
        let mut rng = aes_prng::AesRng::from_random_seed();
        let keyset1 = gen_key_set(params, &mut rng);
        let keyset2 = gen_key_set(params, &mut rng);

        let compression_key_1_poly_size = keyset1
            .get_raw_compression_client_key()
            .unwrap()
            .polynomial_size();
        let compression_key_1 = keyset1
            .get_raw_compression_client_key()
            .unwrap()
            .into_container();
        let glwe_key_2_poly_size = keyset2.get_raw_glwe_client_key().polynomial_size();
        let glwe_key_2 = keyset2.get_raw_glwe_client_key().into_container();

        // and then secret share the secret keys
        let compression_key_shares_1 =
            vec64_to_shares128(compression_key_1, num_parties, threshold, &mut rng);
        assert_eq!(compression_key_shares_1.len(), num_parties);
        let glwe_key_shares_2 = vec64_to_shares128(glwe_key_2, num_parties, threshold, &mut rng);
        assert_eq!(glwe_key_shares_2.len(), num_parties);

        // We need to pass these shares into the FnMut,
        // but FnMut doesn't allow us to move a reference
        // so write these two shares into the temporary storage
        // and then we'll read it in the task.
        write_element(
            prefix_path.join("compression_key_shares_1"),
            &compression_key_shares_1,
        )
        .unwrap();
        write_element(prefix_path.join("glwe_key_shares_2"), &glwe_key_shares_2).unwrap();

        let mut task = |mut session: SmallSession<ResiduePoly<Z128, EXTENSION_DEGREE>>,
                        prefix: Option<String>| async move {
            session
                .network()
                .set_timeout_for_next_round(Duration::from_secs(120))
                .unwrap();
            let batch_size = BatchParams {
                triples: params
                    .get_params_basics_handle()
                    .total_triples_required(keyset_config),
                randoms: params
                    .get_params_basics_handle()
                    .total_randomness_required(keyset_config),
            };

            let mut small_preproc =
                SmallPreprocessing::<_, DummyAgreeRandom>::init(&mut session, batch_size)
                    .await
                    .unwrap();

            let mut dkg_preproc = create_memory_factory().create_dkg_preprocessing_with_sns();

            dkg_preproc
                .fill_from_base_preproc(
                    params,
                    keyset_config,
                    &mut session.to_base_session().unwrap(),
                    &mut small_preproc,
                )
                .await
                .unwrap();

            let my_role = session.my_role().unwrap();
            let prefix = prefix.unwrap();
            let path_compression_key_shares_1 = Path::new(&prefix).join("compression_key_shares_1");
            let path_glwe_key_shares_2 = Path::new(&prefix).join("glwe_key_shares_2");
            let compression_key_shares_1 = &read_element::<
                Vec<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>,
                _,
            >(path_compression_key_shares_1)
            .unwrap()[my_role.zero_based()];
            let glwe_key_shares_2 = &read_element::<
                Vec<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>,
                _,
            >(path_glwe_key_shares_2)
            .unwrap()[my_role.zero_based()];

            let params_handle = params.get_params_basics_handle();
            let private_glwe_compute_key = GlweSecretKeyShare {
                data: glwe_key_shares_2.to_vec(),
                polynomial_size: glwe_key_2_poly_size,
            };
            let private_compression_key = CompressionPrivateKeyShares {
                post_packing_ks_key: GlweSecretKeyShare {
                    data: compression_key_shares_1.to_vec(),
                    polynomial_size: compression_key_1_poly_size,
                },
                params: params_handle
                    .get_compression_decompression_params()
                    .unwrap()
                    .raw_compression_parameters,
            };
            let decompression_key = distributed_decompression_keygen_z128(
                &mut session,
                dkg_preproc.as_mut(),
                params,
                &private_glwe_compute_key,
                &private_compression_key,
            )
            .await
            .unwrap();

            // make sure we used up all the preprocessing materials
            assert_eq!(0, dkg_preproc.bits_len());
            assert_eq!(0, dkg_preproc.triples_len());
            assert_eq!(0, dkg_preproc.randoms_len());

            use strum::IntoEnumIterator;
            for bound in crate::execution::tfhe_internals::parameters::NoiseBounds::iter() {
                assert_eq!(0, dkg_preproc.noise_len(bound));
            }

            (my_role, decompression_key)
        };

        // Sync network because we also init the PRSS in the task
        let mut results =
            execute_protocol_small::<_, _, ResiduePoly<Z128, EXTENSION_DEGREE>, EXTENSION_DEGREE>(
                num_parties,
                threshold as u8,
                None,
                NetworkMode::Sync,
                None,
                &mut task,
                Some(prefix_path.to_str().unwrap().to_string()),
            );

        // check that the decompression keys are the same
        let decompression_key = results.pop().unwrap().1;
        let decompression_key_bytes = bincode::serialize(&decompression_key).unwrap();
        for (_role, key) in results {
            let buf = bincode::serialize(&key).unwrap();
            assert_eq!(buf, decompression_key_bytes);
        }
        // check that we can do the decompression
        run_decompression_test(
            &keyset1.client_key,
            &keyset2.client_key,
            None,
            decompression_key,
        );
    }

    #[cfg(feature = "slow_tests")]
    #[test]
    fn decompresion_keygen_f4() {
        let params = PARAMS_TEST_BK_SNS;
        let num_parties = 4;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();
        run_real_decompression_dkg_and_save::<4>(params, num_parties, threshold, temp_dir.path())
    }

    #[cfg(feature = "slow_tests")]
    fn run_real_dkg_and_save<const EXTENSION_DEGREE: usize>(
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        prefix_path: &Path,
        keyset_config: KeySetConfig,
    ) where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    {
        let params_basics_handles = params.get_params_basics_handle();
        params_basics_handles
            .write_to_file(&prefix_path.join("params.json"))
            .unwrap();

        let mut task = |mut session: SmallSession<ResiduePoly<Z128, EXTENSION_DEGREE>>,
                        _bot: Option<String>| async move {
            use crate::execution::tfhe_internals::compression_decompression_key::CompressionPrivateKeyShares;
            let compression_sk_skares = if keyset_config.is_standard_using_existing_compression_sk()
            {
                // we use dummy preprocessing to generate the existing compression sk
                // because it won't consume our preprocessing materials
                let mut dummy_preproc = DummyPreprocessing::<
                    ResiduePoly<Z128, EXTENSION_DEGREE>,
                    _,
                    _,
                >::new(0_u64, session.clone());
                let params_basics_handles = params.get_params_basics_handle();
                Some(
                    CompressionPrivateKeyShares::new_from_preprocessing(
                        params_basics_handles
                            .get_compression_decompression_params()
                            .unwrap()
                            .raw_compression_parameters,
                        &mut dummy_preproc,
                    )
                    .unwrap(),
                )
            } else {
                None
            };

            session
                .network()
                .set_timeout_for_next_round(Duration::from_secs(120))
                .unwrap();
            let batch_size = BatchParams {
                triples: params
                    .get_params_basics_handle()
                    .total_triples_required(keyset_config),
                randoms: params
                    .get_params_basics_handle()
                    .total_randomness_required(keyset_config),
            };

            let mut small_preproc =
                SmallPreprocessing::<_, DummyAgreeRandom>::init(&mut session, batch_size)
                    .await
                    .unwrap();

            let mut dkg_preproc = create_memory_factory().create_dkg_preprocessing_with_sns();

            dkg_preproc
                .fill_from_base_preproc(
                    params,
                    keyset_config,
                    &mut session.to_base_session().unwrap(),
                    &mut small_preproc,
                )
                .await
                .unwrap();

            assert_ne!(0, dkg_preproc.bits_len());
            assert_ne!(0, dkg_preproc.triples_len());
            assert_ne!(0, dkg_preproc.randoms_len());

            let my_role = session.my_role().unwrap();
            let (pk, sk) = if keyset_config.is_standard_using_existing_compression_sk() {
                distributed_keygen_from_optional_compression_sk(
                    &mut session,
                    dkg_preproc.as_mut(),
                    params,
                    compression_sk_skares.as_ref(),
                )
                .await
                .unwrap()
            } else {
                distributed_keygen(&mut session, dkg_preproc.as_mut(), params)
                    .await
                    .unwrap()
            };

            // make sure we used up all the preprocessing materials
            assert_eq!(0, dkg_preproc.bits_len());
            assert_eq!(0, dkg_preproc.triples_len());
            assert_eq!(0, dkg_preproc.randoms_len());

            use strum::IntoEnumIterator;
            for bound in crate::execution::tfhe_internals::parameters::NoiseBounds::iter() {
                assert_eq!(0, dkg_preproc.noise_len(bound));
            }

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
        let results =
            execute_protocol_small::<_, _, ResiduePoly<Z128, EXTENSION_DEGREE>, EXTENSION_DEGREE>(
                num_parties,
                threshold as u8,
                None,
                NetworkMode::Sync,
                None,
                &mut task,
                None,
            );

        let pk_ref = results[0].1.clone();

        for (role, pk, sk) in results {
            assert_eq!(pk, pk_ref);
            sk.write_to_file(&prefix_path.join(format!("sk_p{}.der", role.zero_based())))
                .unwrap();
        }

        pk_ref.write_to_file(&prefix_path.join("pk.der")).unwrap();
    }

    ///Runs the DKG protocol with [`DummyPreprocessing`]
    /// and [`FakeBitGenEven`]. Saves the results to file.
    fn run_dkg_and_save<const EXTENSION_DEGREE: usize>(
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        prefix_path: &Path,
    ) where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
        ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
    {
        let params_basics_handles = params.get_params_basics_handle();
        params_basics_handles
            .write_to_file(&prefix_path.join("params.json"))
            .unwrap();

        let mut task = |mut session: LargeSession| async move {
            let my_role = session.my_role().unwrap();
            let mut large_preproc = DummyPreprocessing::new(0_u64, session.clone());

            let (pk, sk) = super::distributed_keygen::<Z128, _, _, _, EXTENSION_DEGREE>(
                &mut session,
                &mut large_preproc,
                params,
            )
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
        let delay_vec = vec![tokio::time::Duration::from_secs(1)];
        let results =
            execute_protocol_large::<_, _, ResiduePoly<Z128, EXTENSION_DEGREE>, EXTENSION_DEGREE>(
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
            sk.write_to_file(&prefix_path.join(format!("sk_p{}.der", role.zero_based())))
                .unwrap();
        }

        pk_ref.write_to_file(&prefix_path.join("pk.der")).unwrap();
    }

    fn run_switch_and_squash<const EXTENSION_DEGREE: usize>(
        prefix_path: &Path,
        num_parties: usize,
        threshold: usize,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let params = DKGParamsSnS::read_from_file(&prefix_path.join("params.json")).unwrap();
        let message = (params.get_message_modulus().0 - 1) as u8;

        let sk_lwe = reconstruct_lwe_secret_key_from_file::<EXTENSION_DEGREE, _>(
            num_parties,
            threshold,
            &params,
            prefix_path,
        );
        let (sk_glwe, big_sk_glwe) = reconstruct_glwe_secret_key_from_file::<EXTENSION_DEGREE>(
            num_parties,
            threshold,
            DKGParams::WithSnS(params),
            prefix_path,
        );
        let sk_large = SnsClientKey::new(
            params.to_classic_pbs_parameters(),
            big_sk_glwe.clone().unwrap(),
        );
        let pk = RawPubKeySet::read_from_file(&prefix_path.join("pk.der")).unwrap();
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
            DeterministicSeeder::<DefaultRandomGenerator>::new(seed_from_rng(&mut rng));
        let mut enc_rng = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
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

        let small_ct: FheUint64 = expanded_encrypt(&ddec_pk, message as u64, 64).unwrap();
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
    pub fn run_tfhe_computation_shortint<const EXTENSION_DEGREE: usize, Params: DKGParamsBasics>(
        prefix_path: &Path,
        num_parties: usize,
        threshold: usize,
        with_compact: bool,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let params = Params::read_from_file(&prefix_path.join("params.json"))
            .unwrap()
            .to_dkg_params();
        let (shortint_sk, pk) = retrieve_keys_from_files::<EXTENSION_DEGREE>(
            params,
            num_parties,
            threshold,
            prefix_path,
        );
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
    fn run_tfhe_computation_fheuint<const EXTENSION_DEGREE: usize, Params: DKGParamsBasics>(
        prefix_path: &Path,
        num_parties: usize,
        threshold: usize,
        do_compression_test: bool,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let params = Params::read_from_file(&prefix_path.join("params.json"))
            .unwrap()
            .to_dkg_params();
        let (shortint_sk, pk) = retrieve_keys_from_files::<EXTENSION_DEGREE>(
            params,
            num_parties,
            threshold,
            prefix_path,
        );

        let pub_key_set = pk.to_pubkeyset(params);

        set_server_key(pub_key_set.server_key);

        let shortint_pk = pk.compute_tfhe_shortint_server_key(params);
        for _ in 0..100 {
            try_tfhe_shortint_computation(&shortint_sk, &shortint_pk);
        }

        // Note that there is no `compression_key` because this key is never used to
        // encrypt/decrypt. We only compress and decompress which doesn't require this key.
        let tfhe_sk =
            tfhe::ClientKey::from_raw_parts(shortint_sk.into(), None, None, tfhe::Tag::default());

        try_tfhe_fheuint_computation(&tfhe_sk);
        if do_compression_test {
            try_tfhe_compression_computation(&tfhe_sk);
        }
    }

    ///Read files created by [`run_dkg_and_save`] and reconstruct the secret keys
    ///from the parties' shares
    fn retrieve_keys_from_files<const EXTENSION_DEGREE: usize>(
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        prefix_path: &Path,
    ) -> (tfhe::shortint::ClientKey, RawPubKeySet)
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let params_tfhe_rs = params
            .get_params_basics_handle()
            .to_classic_pbs_parameters();

        let lwe_secret_key = reconstruct_lwe_secret_key_from_file::<EXTENSION_DEGREE, _>(
            num_parties,
            threshold,
            params.get_params_basics_handle(),
            prefix_path,
        );
        let (glwe_secret_key, _) = reconstruct_glwe_secret_key_from_file::<EXTENSION_DEGREE>(
            num_parties,
            threshold,
            params,
            prefix_path,
        );
        let pk = RawPubKeySet::read_from_file(&prefix_path.join("pk.der")).unwrap();

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

        let expected_res = ((clear_a * scalar as u64 - clear_b) * clear_b) % modulus;
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

        // note that the server key is set in the caller of this function
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
}
