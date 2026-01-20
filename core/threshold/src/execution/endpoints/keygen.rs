use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        galois_rings::common::ResiduePoly,
        structure_traits::{BaseRing, ErrorCorrect, Ring},
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        online::{
            preprocessing::{DKGPreprocessing, RandomPreprocessing},
            triple::open_list,
        },
        runtime::sessions::{
            base_session::BaseSessionHandles, session_parameters::DeSerializationRunTime,
        },
        tfhe_internals::{
            compression_decompression_key::CompressionPrivateKeyShares,
            compression_decompression_key_generation::{
                distributed_keygen_compressed_compression_material,
                distributed_keygen_compression_material, generate_compressed_decompression_keys,
                generate_decompression_keys,
            },
            glwe_key::GlweSecretKeyShare,
            lwe_bootstrap_key::par_decompress_into_lwe_bootstrap_key_generated_from_xof,
            lwe_bootstrap_key_generation::{
                generate_bootstrap_key, generate_compressed_bootstrap_key,
            },
            lwe_key::{
                generate_lwe_private_compressed_public_key_pair,
                generate_lwe_private_public_key_pair, LweSecretKeyShare,
            },
            lwe_keyswitch_key_generation::{
                generate_compressed_key_switch_key, generate_key_switch_key,
            },
            modulus_switch_noise_reduction_key_generation::{
                generate_compressed_mod_switch_noise_reduction_key,
                generate_mod_switch_noise_reduction_key,
            },
            parameters::{DKGParams, DKGParamsBasics, MSNRKConfiguration},
            private_keysets::{GenericPrivateKeySet, PrivateKeySet},
            public_keysets::{
                CompressedReRandomizationRawKeySwitchingKey, FhePubKeySet, RawCompressedPubKeySet,
                RawPubKeySet, ReRandomizationRawKeySwitchingKey,
            },
            randomness::MPCEncryptionRandomGenerator,
            sns_compression_key_generation::{
                generate_compressed_sns_compression_keys, generate_sns_compression_keys,
            },
        },
    },
    hashing::DomainSep,
};
use num_integer::div_ceil;
use tfhe::{
    core_crypto::entities::LweBootstrapKey,
    shortint::{
        list_compression::{CompressedDecompressionKey, DecompressionKey},
        parameters::LweCiphertextCount,
        server_key::{CompressedModulusSwitchConfiguration, ModulusSwitchConfiguration},
        ClassicPBSParameters,
    },
    xof_key_set::CompressedXofKeySet,
};
use tfhe_csprng::{generators::SoftwareRandomGenerator, seeders::XofSeed};
use tracing::instrument;

pub(crate) const DSEP_KG: DomainSep = *b"TFHE_GEN";

///Sample the random but public seed
async fn sample_seed<
    Z: Ring + ErrorCorrect,
    P: RandomPreprocessing<Z> + ?Sized,
    S: BaseSessionHandles,
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

trait Finalizable<const EXTENSION_DEGREE: usize> {
    /// Finalizes the keyset by converting it to a `PrivateKeySet`.
    ///
    /// This method is used to convert the generic private key set into a concrete
    /// `PrivateKeySet` with the given parameters.
    ///
    /// Inputs:
    /// - `self`: The generic private key set to finalize.
    /// - `parameters`: The parameters for the classic PBS.
    ///
    /// Outputs:
    /// - A finalized `PrivateKeySet`.
    fn finalize_keyset(self, parameters: ClassicPBSParameters) -> PrivateKeySet<EXTENSION_DEGREE>;
}

impl<const EXTENSION_DEGREE: usize> Finalizable<EXTENSION_DEGREE>
    for GenericPrivateKeySet<Z128, EXTENSION_DEGREE>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
{
    fn finalize_keyset(self, parameters: ClassicPBSParameters) -> PrivateKeySet<EXTENSION_DEGREE> {
        self.finalize_keyset(parameters)
    }
}

impl<const EXTENSION_DEGREE: usize> Finalizable<EXTENSION_DEGREE>
    for GenericPrivateKeySet<Z64, EXTENSION_DEGREE>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
{
    fn finalize_keyset(self, parameters: ClassicPBSParameters) -> PrivateKeySet<EXTENSION_DEGREE> {
        self.finalize_keyset(parameters)
    }
}

/// Trait for generic online distributed key generation.
/// It is used for testing since the return types are generic private types.
/// For public use, the [OnlineDistributedKeyGen128] trait should be used instead.
#[tonic::async_trait]
pub trait OnlineDistributedKeyGen<Z, const EXTENSION_DEGREE: usize>: Send + Sync {
    /// Runs the distributed key generation protocol.
    ///
    /// Inputs:
    /// - `session`: the session that holds necessary information for networking
    /// - `preprocessing`: [`DKGPreprocessing`] handle with enough triples, bits and noise available
    /// - `params`: [`DKGParams`] parameters for the Distributed Key Generation
    ///
    /// Outputs:
    /// - A [`FhePubKeySet`] composed of a [`tfhe::CompactPublicKey`] and a [`tfhe::ServerKey`]
    /// - a [`PrivateKeySet`] composed of shares of the lwe and glwe private keys
    ///
    /// When using the DKGParams::WithSnS variant, the sharing domain must be ResiduePoly<Z128, EXTENSION_DEGREE>.
    /// Note that there is some redundancy of information because we also explicitly ask the [`BaseRing`] as trait parameter
    ///
    ///
    /// We have a private trait bound here to ensure that the
    /// an internal type implements a private trait Finalizable.
    #[allow(private_bounds)]
    async fn keygen<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send + ?Sized,
    >(
        session: &mut S,
        preprocessing: &mut P,
        params: DKGParams,
        tag: tfhe::Tag,
        existing_compression_sk: Option<&CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
    ) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
    where
        Z: BaseRing,
        ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
        GenericPrivateKeySet<Z, EXTENSION_DEGREE>: Finalizable<EXTENSION_DEGREE>;

    // NOTE: This can not be used or tested yet as we are waiting for tfhe-rs
    // next release to be able to decompress the keys generated here.
    // see https://github.com/zama-ai/kms/pull/40

    /// Runs the distributed key generation protocol for compressed keys.
    ///
    /// Inputs:
    /// - `session`: the session that holds necessary information for networking
    /// - `preprocessing`: [`DKGPreprocessing`] handle with enough triples, bits and noise available
    /// - `params`: [`DKGParams`] parameters for the Distributed Key Generation
    ///
    /// Outputs:
    /// - A [`CompressedFhePubKeySet`] composed of a [`tfhe::CompressedCompactPublicKey`] and a [`tfhe::CompressedServerKey`] as well as the seed of the XOF to decompress the keys.
    ///
    /// __NOTE__ Decompressing those keys require a custom decompression technique and not the usual _decompress_ fn provided on those structs.
    /// - a [`PrivateKeySet`] composed of shares of the lwe and glwe private keys
    ///
    /// When using the DKGParams::WithSnS variant, the sharing domain must be ResiduePoly<Z128, EXTENSION_DEGREE>.
    /// Note that there is some redundancy of information because we also explicitly ask the [`BaseRing`] as trait parameter
    ///
    ///
    /// We have a private trait bound here to ensure that the
    /// an internal type implements a private trait Finalizable.
    #[allow(private_bounds)]
    async fn compressed_keygen<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send + ?Sized,
    >(
        session: &mut S,
        preprocessing: &mut P,
        params: DKGParams,
        tag: tfhe::Tag,
        existing_compression_sk: Option<&CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
    ) -> anyhow::Result<(CompressedXofKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
    where
        Z: BaseRing,
        ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
        GenericPrivateKeySet<Z, EXTENSION_DEGREE>: Finalizable<EXTENSION_DEGREE>;
}

pub type SecureOnlineDistributedKeyGen128<const EXTENSION_DEGREE: usize> =
    SecureOnlineDistributedKeyGen<Z128, EXTENSION_DEGREE>;

pub struct SecureOnlineDistributedKeyGen<Z: BaseRing, const EXTENSION_DEGREE: usize>(
    std::marker::PhantomData<Z>,
);

#[tonic::async_trait]
impl<Z: BaseRing, const EXTENSION_DEGREE: usize> OnlineDistributedKeyGen<Z, EXTENSION_DEGREE>
    for SecureOnlineDistributedKeyGen<Z, EXTENSION_DEGREE>
{
    #[instrument(name="TFHE.Threshold-KeyGen", skip(session, preprocessing), fields(sid = ?session.session_id(), my_role = ?session.my_role()))]
    #[allow(private_bounds)]
    async fn keygen<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send + ?Sized,
    >(
        session: &mut S,
        preprocessing: &mut P,
        params: DKGParams,
        tag: tfhe::Tag,
        existing_compression_sk: Option<&CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
    ) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
    where
        ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
        GenericPrivateKeySet<Z, EXTENSION_DEGREE>: Finalizable<EXTENSION_DEGREE>,
    {
        // Messages exchanged are big so we deserialize them on Rayon
        session.set_deserialization_runtime(DeSerializationRunTime::Rayon);
        if Z::BIT_LENGTH == 64 {
            if let DKGParams::WithSnS(_) = params {
                return Err(anyhow_error_and_log(
                    "Can not generate Switch and Squash key in Z64".to_string(),
                ));
            }
        }

        if Z::BIT_LENGTH
            != params
                .get_params_basics_handle()
                .get_dkg_mode()
                .expected_bit_length()
        {
            return Err(anyhow_error_and_log(format!(
                "Inconsistent parameters: trying to do DKG in Z{} with DKGParams in Z{}",
                Z::BIT_LENGTH,
                params
                    .get_params_basics_handle()
                    .get_dkg_mode()
                    .expected_bit_length()
            )));
        }

        let (pub_key_set, priv_key_set) = distributed_keygen_from_optional_compression_sk(
            session,
            preprocessing,
            params,
            existing_compression_sk,
        )
        .await?;
        Ok((
            pub_key_set.to_pubkeyset(params, tag),
            priv_key_set.finalize_keyset(
                params
                    .get_params_basics_handle()
                    .to_classic_pbs_parameters(),
            ),
        ))
    }

    #[instrument(name="TFHE.Threshold-CompressedKeyGen", skip(session, preprocessing), fields(sid = ?session.session_id(), my_role = ?session.my_role()))]
    #[allow(private_bounds)]
    async fn compressed_keygen<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send + ?Sized,
    >(
        session: &mut S,
        preprocessing: &mut P,
        params: DKGParams,
        tag: tfhe::Tag,
        existing_compression_sk: Option<&CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
    ) -> anyhow::Result<(CompressedXofKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
    where
        ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
        GenericPrivateKeySet<Z, EXTENSION_DEGREE>: Finalizable<EXTENSION_DEGREE>,
    {
        // Messages exchanged are big so we deserialize them on Rayon
        session.set_deserialization_runtime(DeSerializationRunTime::Rayon);
        if Z::BIT_LENGTH == 64 {
            if let DKGParams::WithSnS(_) = params {
                return Err(anyhow_error_and_log(
                    "Can not generate Switch and Squash key with in Z64".to_string(),
                ));
            }
        }

        if Z::BIT_LENGTH
            != params
                .get_params_basics_handle()
                .get_dkg_mode()
                .expected_bit_length()
        {
            return Err(anyhow_error_and_log(format!(
                "Inconsistent parameters: trying to do DKG in Z{} with DKGParams in Z{}",
                Z::BIT_LENGTH,
                params
                    .get_params_basics_handle()
                    .get_dkg_mode()
                    .expected_bit_length()
            )));
        }

        let (pub_key_set, priv_key_set) =
            distributed_keygen_compressed_from_optional_compression_sk(
                session,
                preprocessing,
                params,
                existing_compression_sk,
            )
            .await?;
        Ok((
            pub_key_set.to_compressed_pubkeyset(params, tag),
            priv_key_set.finalize_keyset(
                params
                    .get_params_basics_handle()
                    .to_classic_pbs_parameters(),
            ),
        ))
    }
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
    S: BaseSessionHandles,
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
    let my_role = session.my_role();
    let seed = sample_seed(params_basics_handle.get_sec(), session, preprocessing).await?;
    //Init the XOF with the seed computed above
    let mut mpc_encryption_rng = MPCEncryptionRandomGenerator::<
        Z,
        SoftwareRandomGenerator,
        EXTENSION_DEGREE,
    >::new_from_seed(XofSeed::new_u128(seed, DSEP_KG));

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
            params_basics_handle.get_pmax(),
            session,
        )
        .await?
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
        params_basics_handle.get_pmax(),
        session,
    )
    .await?;

    let glwe_sk_share_as_lwe = glwe_secret_key_share.clone().into_lwe_secret_key();

    tracing::info!("(Party {my_role}) Generating GLWE secret key...Done");

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
    session.network().set_timeout_for_bk().await;
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
    let (glwe_secret_key_share_sns, bk_sns, msnrk_sns) = match params {
        DKGParams::WithSnS(sns_params) => {
            tracing::info!("(Party {my_role}) Generating SnS GLWE...Start");
            //compute the SnS GLWE key
            let glwe_secret_key_share_sns = GlweSecretKeyShare::new_from_preprocessing(
                sns_params.glwe_sk_num_bits_sns(),
                sns_params.polynomial_size_sns(),
                preprocessing,
                sns_params.get_pmax(),
                session,
            )
            .await?;

            //Computing and opening BK SNS can take a while, so we increase the timeout
            session.network().set_timeout_for_bk_sns().await;

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

            let msnrk_sns = match sns_params.get_msnrk_configuration_sns() {
                MSNRKConfiguration::Standard => ModulusSwitchConfiguration::Standard,
                MSNRKConfiguration::DriftTechniqueNoiseReduction(msnrkparams) => {
                    ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                        generate_mod_switch_noise_reduction_key(
                            &lwe_secret_key_share,
                            &msnrkparams,
                            &mut mpc_encryption_rng,
                            session,
                            preprocessing,
                        )
                        .await?,
                    )
                }
                MSNRKConfiguration::CenteredMeanNoiseReduction => {
                    ModulusSwitchConfiguration::CenteredMeanNoiseReduction
                }
            };

            tracing::info!("(Party {my_role}) Opening SnS BK...Done");
            (
                Some(glwe_secret_key_share_sns),
                Some(bk_sns),
                Some(msnrk_sns),
            )
        }
        DKGParams::WithoutSnS(_) => (None, None, None),
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

    // If needed, compute the mod switch noise reduction key
    let msnrk = match params_basics_handle.get_msnrk_configuration() {
        MSNRKConfiguration::Standard => ModulusSwitchConfiguration::Standard,
        MSNRKConfiguration::DriftTechniqueNoiseReduction(msnrkparams) => {
            ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                generate_mod_switch_noise_reduction_key(
                    &lwe_secret_key_share,
                    &msnrkparams,
                    &mut mpc_encryption_rng,
                    session,
                    preprocessing,
                )
                .await?,
            )
        }
        MSNRKConfiguration::CenteredMeanNoiseReduction => {
            ModulusSwitchConfiguration::CenteredMeanNoiseReduction
        }
    };

    // note that glwe_secret_key_share_compression may be None even if compression_keys is Some
    // this is because we might have generated the compression keys from an existing compression sk share
    let (glwe_secret_key_share_compression, compression_keys) = compression_material;

    // If needed, compute the sns compression keys
    let sns_compression_materials =
        match (params, params_basics_handle.get_sns_compression_params()) {
            (DKGParams::WithSnS(_), Some(comp_params)) => {
                let (private_sns_compression_key, sns_compression_key) =
                    generate_sns_compression_keys(
                        &glwe_secret_key_share_sns
                            .clone()
                            .map(|key| key.into_lwe_secret_key())
                            .unwrap(),
                        comp_params,
                        &mut mpc_encryption_rng,
                        session,
                        preprocessing,
                    )
                    .await?;

                Some((private_sns_compression_key, sns_compression_key))
            }
            _ => None,
        };

    let (glwe_secret_key_share_sns_compression, sns_compression_key) =
        match sns_compression_materials {
            Some((private_sns_compression_key, sns_compression_key)) => {
                (Some(private_sns_compression_key), Some(sns_compression_key))
            }
            None => (None, None),
        };

    let cpk_re_randomization_ksk = match (
        params_basics_handle.get_pksk_params(),
        params_basics_handle.get_rerand_ksk_params(),
    ) {
        (Some(pksk_params), Some(cpk_re_randomization_ksk_params)) => {
            // If these are equal, we already have the KSK from the LWE sk of the PK
            // and the glwe sk that's necessary for rerand
            if pksk_params == cpk_re_randomization_ksk_params {
                Some(ReRandomizationRawKeySwitchingKey::UseCPKEncryptionKSK)
            } else {
                Some(ReRandomizationRawKeySwitchingKey::DedicatedKSK(
                    generate_key_switch_key(
                        &lwe_hat_secret_key_share,
                        &glwe_sk_share_as_lwe,
                        &cpk_re_randomization_ksk_params,
                        &mut mpc_encryption_rng,
                        session,
                        preprocessing,
                    )
                    .await?,
                ))
            }
        }
        (_, None) => None,
        _ => {
            panic!("Inconsistent ClientKey set-up for CompactPublicKey re-randomization.")
        }
    };

    let pub_key_set = RawPubKeySet {
        lwe_public_key,
        ksk,
        pksk,
        bk,
        bk_sns,
        compression_keys,
        msnrk,
        msnrk_sns,
        seed,
        cpk_re_randomization_ksk,
        sns_compression_key,
    };

    let priv_key_set = GenericPrivateKeySet {
        lwe_encryption_secret_key_share: lwe_hat_secret_key_share,
        lwe_secret_key_share,
        glwe_secret_key_share,
        glwe_secret_key_share_sns,
        glwe_secret_key_share_compression,
        glwe_secret_key_share_sns_compression,
    };

    Ok((pub_key_set, priv_key_set))
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
async fn distributed_keygen_compressed_from_optional_compression_sk<
    Z: BaseRing,
    S: BaseSessionHandles,
    P: DKGPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>> + Send + ?Sized,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
    existing_compression_sk: Option<&CompressionPrivateKeyShares<Z, EXTENSION_DEGREE>>,
) -> anyhow::Result<(
    RawCompressedPubKeySet,
    GenericPrivateKeySet<Z, EXTENSION_DEGREE>,
)>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let params_basics_handle = params.get_params_basics_handle();
    let my_role = session.my_role();
    let seed = sample_seed(params_basics_handle.get_sec(), session, preprocessing).await?;
    //Init the XOF with the seed computed above
    let mut mpc_encryption_rng = MPCEncryptionRandomGenerator::<
        Z,
        SoftwareRandomGenerator,
        EXTENSION_DEGREE,
    >::new_from_seed(XofSeed::new_u128(seed, DSEP_KG));

    //Generate the shared LWE hat secret key and corresponding public key
    let (lwe_hat_secret_key_share, lwe_public_key) =
        generate_lwe_private_compressed_public_key_pair(
            &params,
            &mut mpc_encryption_rng,
            session,
            preprocessing,
            seed,
        )
        .await?;

    //Generate the LWE (no hat) secret key if it should exist
    let lwe_secret_key_share = if params_basics_handle.has_dedicated_compact_pk_params() {
        LweSecretKeyShare::new_from_preprocessing(
            params_basics_handle.lwe_dimension(),
            preprocessing,
            params_basics_handle.get_pmax(),
            session,
        )
        .await?
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
        params_basics_handle.get_pmax(),
        session,
    )
    .await?;

    let glwe_sk_share_as_lwe = glwe_secret_key_share.clone().into_lwe_secret_key();

    tracing::info!("(Party {my_role}) Generating GLWE secret key...Done");

    //Generate the compression keys, we'll have None if there are no
    //compression materials to generate
    let compression_material = distributed_keygen_compressed_compression_material(
        session,
        preprocessing,
        params,
        &mut mpc_encryption_rng,
        &glwe_sk_share_as_lwe,
        &glwe_secret_key_share,
        existing_compression_sk,
        seed,
    )
    .await?;

    //Generate the KSK
    let ksk_params = params_basics_handle.get_ksk_params();

    let ksk = generate_compressed_key_switch_key(
        &glwe_sk_share_as_lwe,
        &lwe_secret_key_share,
        &ksk_params,
        &mut mpc_encryption_rng,
        session,
        preprocessing,
        seed,
    )
    .await?;
    tracing::info!("(Party {my_role}) Generating KSK...Done");

    //Computing and opening BK can take a while, so we increase the timeout
    //(in theory we should be in async setting here anyway)
    session.network().set_timeout_for_bk().await;
    //Compute the bootstrapping keys
    let bk = generate_compressed_bootstrap_key(
        &glwe_secret_key_share,
        &lwe_secret_key_share,
        params_basics_handle.get_bk_params(),
        &mut mpc_encryption_rng,
        session,
        preprocessing,
        seed,
    )
    .await?;

    // If needed, compute the mod switch noise reduction key
    let msnrk = match params_basics_handle.get_msnrk_configuration() {
        MSNRKConfiguration::Standard => CompressedModulusSwitchConfiguration::Standard,
        MSNRKConfiguration::DriftTechniqueNoiseReduction(msnrkparams) => {
            CompressedModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                generate_compressed_mod_switch_noise_reduction_key(
                    &lwe_secret_key_share,
                    &msnrkparams,
                    &mut mpc_encryption_rng,
                    session,
                    preprocessing,
                    seed,
                )
                .await?,
            )
        }
        MSNRKConfiguration::CenteredMeanNoiseReduction => {
            CompressedModulusSwitchConfiguration::CenteredMeanNoiseReduction
        }
    };

    //If needed, compute the SnS BK
    let (glwe_secret_key_share_sns, bk_sns, msnrk_sns) = match params {
        DKGParams::WithSnS(sns_params) => {
            tracing::info!("(Party {my_role}) Generating SnS GLWE...Start");
            //compute the SnS GLWE key
            let glwe_secret_key_share_sns = GlweSecretKeyShare::new_from_preprocessing(
                sns_params.glwe_sk_num_bits_sns(),
                sns_params.polynomial_size_sns(),
                preprocessing,
                sns_params.get_pmax(),
                session,
            )
            .await?;

            //Computing and opening BK SNS can take a while, so we increase the timeout
            //(in theory we should be in async setting here anyway)
            session.network().set_timeout_for_bk_sns().await;

            tracing::info!("(Party {my_role}) Generating SnS GLWE...Done");
            let bk_sns = generate_compressed_bootstrap_key(
                &glwe_secret_key_share_sns,
                &lwe_secret_key_share,
                sns_params.get_bk_sns_params(),
                &mut mpc_encryption_rng,
                session,
                preprocessing,
                seed,
            )
            .await?;

            let msnrk_sns = match sns_params.get_msnrk_configuration_sns() {
                MSNRKConfiguration::Standard => CompressedModulusSwitchConfiguration::Standard,
                MSNRKConfiguration::DriftTechniqueNoiseReduction(msnrkparams) => {
                    CompressedModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                        generate_compressed_mod_switch_noise_reduction_key(
                            &lwe_secret_key_share,
                            &msnrkparams,
                            &mut mpc_encryption_rng,
                            session,
                            preprocessing,
                            seed,
                        )
                        .await?,
                    )
                }
                MSNRKConfiguration::CenteredMeanNoiseReduction => {
                    CompressedModulusSwitchConfiguration::CenteredMeanNoiseReduction
                }
            };

            tracing::info!("(Party {my_role}) Opening SnS BK...Done");
            (
                Some(glwe_secret_key_share_sns),
                Some(bk_sns),
                Some(msnrk_sns),
            )
        }
        DKGParams::WithoutSnS(_) => (None, None, None),
    };

    //Compute the PKSK
    let pksk = match (
        params_basics_handle.get_pksk_destination(),
        params_basics_handle.get_pksk_params(),
    ) {
        //Corresponds to type = F-GLWE
        (Some(tfhe::shortint::EncryptionKeyChoice::Big), Some(pksk_params)) => Some(
            generate_compressed_key_switch_key(
                &lwe_hat_secret_key_share,
                &glwe_sk_share_as_lwe,
                &pksk_params,
                &mut mpc_encryption_rng,
                session,
                preprocessing,
                seed,
            )
            .await?,
        ),

        //Corresponds to type = LWE
        (Some(tfhe::shortint::EncryptionKeyChoice::Small), Some(pksk_params)) => Some(
            generate_compressed_key_switch_key(
                &lwe_hat_secret_key_share,
                &lwe_secret_key_share,
                &pksk_params,
                &mut mpc_encryption_rng,
                session,
                preprocessing,
                seed,
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

    let cpk_re_randomization_ksk = match (
        params_basics_handle.get_pksk_params(),
        params_basics_handle.get_rerand_ksk_params(),
    ) {
        (Some(pksk_params), Some(cpk_re_randomization_ksk_params)) => {
            // If these are equal, we already have the KSK from the LWE sk of the PK
            // and the glwe sk that's necessary for rerand
            if pksk_params == cpk_re_randomization_ksk_params {
                Some(CompressedReRandomizationRawKeySwitchingKey::UseCPKEncryptionKSK)
            } else {
                Some(CompressedReRandomizationRawKeySwitchingKey::DedicatedKSK(
                    generate_compressed_key_switch_key(
                        &lwe_hat_secret_key_share,
                        &glwe_sk_share_as_lwe,
                        &cpk_re_randomization_ksk_params,
                        &mut mpc_encryption_rng,
                        session,
                        preprocessing,
                        seed,
                    )
                    .await?,
                ))
            }
        }
        (_, None) => None,
        _ => {
            panic!("Inconsistent ClientKey set-up for CompactPublicKey re-randomization.")
        }
    };

    // If needed, compute the sns compression keys
    let sns_compression_materials =
        match (params, params_basics_handle.get_sns_compression_params()) {
            (DKGParams::WithSnS(_), Some(comp_params)) => {
                let (private_sns_compression_key, sns_compression_key) =
                    generate_compressed_sns_compression_keys(
                        &glwe_secret_key_share_sns
                            .clone()
                            .map(|key| key.into_lwe_secret_key())
                            .unwrap(),
                        comp_params,
                        &mut mpc_encryption_rng,
                        session,
                        preprocessing,
                        seed,
                    )
                    .await?;

                Some((private_sns_compression_key, sns_compression_key))
            }
            _ => None,
        };

    let (glwe_secret_key_share_sns_compression, sns_compression_key) =
        match sns_compression_materials {
            Some((private_sns_compression_key, sns_compression_key)) => {
                (Some(private_sns_compression_key), Some(sns_compression_key))
            }
            None => (None, None),
        };

    let pub_key_set = RawCompressedPubKeySet {
        lwe_public_key,
        ksk,
        pksk,
        bk,
        bk_sns,
        compression_keys,
        msnrk,
        msnrk_sns,
        sns_compression_key,
        cpk_re_randomization_ksk,
        seed,
    };

    let priv_key_set = GenericPrivateKeySet {
        lwe_encryption_secret_key_share: lwe_hat_secret_key_share,
        lwe_secret_key_share,
        glwe_secret_key_share,
        glwe_secret_key_share_sns,
        glwe_secret_key_share_compression,
        glwe_secret_key_share_sns_compression,
    };

    Ok((pub_key_set, priv_key_set))
}

#[instrument(name="Gen Decompression Key Z128", skip(private_glwe_compute_key, private_compression_key, session, preprocessing), fields(sid = ?session.session_id(), my_role = ?session.my_role()))]
pub async fn distributed_decompression_keygen_z128<
    S: BaseSessionHandles,
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
    >::new_from_seed(XofSeed::new_u128(seed, DSEP_KG));

    let params = params_basics_handle
        .get_compression_decompression_params()
        .ok_or_else(|| anyhow::anyhow!("missing (de)compression parameters"))?;

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

/// NOTE: When we generate a standalone CompressedDecompressionKey via this fn, it needs to be decompressed
/// using the decompression function WE provide [`decompressed_compressed_standalone_decompression_key_from_xof`], not the one from the TFHE-rs library.
#[instrument(name="Gen compressed Decompression Key Z128", skip(private_glwe_compute_key, private_compression_key, session, preprocessing), fields(sid = ?session.session_id(), my_role = ?session.my_role()))]
pub async fn distributed_compressed_decompression_keygen_z128<
    S: BaseSessionHandles,
    P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
    private_glwe_compute_key: &GlweSecretKeyShare<Z128, EXTENSION_DEGREE>,
    private_compression_key: &CompressionPrivateKeyShares<Z128, EXTENSION_DEGREE>,
) -> anyhow::Result<CompressedDecompressionKey>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
{
    let params_basics_handle = params.get_params_basics_handle();
    let seed = sample_seed(params_basics_handle.get_sec(), session, preprocessing).await?;
    //Init the XOF with the seed computed above
    // QU: Do we want to use the same DSEP as in the regualr KG?
    let mut mpc_encryption_rng = MPCEncryptionRandomGenerator::<
        Z128,
        SoftwareRandomGenerator,
        EXTENSION_DEGREE,
    >::new_from_seed(XofSeed::new_u128(seed, DSEP_KG));

    let params = params_basics_handle
        .get_compression_decompression_params()
        .ok_or_else(|| anyhow::anyhow!("missing (de)compression parameters"))?;

    generate_compressed_decompression_keys(
        private_glwe_compute_key,
        private_compression_key,
        params,
        &mut mpc_encryption_rng,
        session,
        preprocessing,
        seed,
    )
    .await
}

/// Correctly decompresses a CompressedDecompressionKey standalone generated from the XOF
/// and outputs a the raw elements of a [`DecompressionKey`] __BEFORE__ the fourrier transform.
pub fn decompress_compressed_standalone_decompression_key_from_xof(
    compressed_decompression_key: CompressedDecompressionKey,
) -> (LweBootstrapKey<Vec<u64>>, LweCiphertextCount) {
    let CompressedDecompressionKey {
        blind_rotate_key: key,
        lwe_per_glwe: count,
    } = compressed_decompression_key;

    let decompressed_key = par_decompress_into_lwe_bootstrap_key_generated_from_xof::<
        _,
        SoftwareRandomGenerator,
    >(key, DSEP_KG);
    (decompressed_key, count)
}

#[cfg(feature = "testing")]
pub mod conformance {
    use tfhe::core_crypto::prelude::{
        decrypt_lwe_ciphertext, divide_round, ContiguousEntityContainer, LweCiphertextOwned,
    };
    use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
    use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
    use tfhe::shortint::server_key::ModulusSwitchConfiguration;
    use tfhe::shortint::ClassicPBSParameters;

    pub fn check_drift_technique_key(
        pbs_params: ClassicPBSParameters,
        server_key: &tfhe::ServerKey,
        client_key: &tfhe::shortint::ClientKey,
    ) {
        let int_server_key: &tfhe::integer::ServerKey = server_key.as_ref();
        let shortint_server_key: &tfhe::shortint::ServerKey = int_server_key.as_ref();

        match &shortint_server_key.atomic_pattern {
            AtomicPatternServerKey::Standard(atomic_pattern) => {
                match &atomic_pattern.bootstrapping_key {
                    tfhe::shortint::server_key::ShortintBootstrappingKey::Classic {
                        bsk: _bsk,
                        modulus_switch_noise_reduction_key,
                    } => {
                        match modulus_switch_noise_reduction_key {
                            // Check that we can decrypt this key to 0
                            ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(key) => {
                                let zeros_ct = &key.modulus_switch_zeros;
                                let client_key = client_key.clone().atomic_pattern;

                                //NOTE: Small workaround to cope with tfhe-rs change to the ClientKey decryption
                                //to fetch the key based on the ctxt's PBSOrder and not the key's EncryptionKeyChoice
                                let lwe_secret_key = if let AtomicPatternClientKey::Standard(
                                    client_key,
                                ) = client_key
                                {
                                    let (_, lwe_sk, _, _) = client_key.into_raw_parts();
                                    lwe_sk
                                } else {
                                    panic!("Expected Standard AtomicPatternClientKey");
                                };

                                let message_space_size =
                                    pbs_params.message_modulus.0 * pbs_params.carry_modulus.0 * 2;
                                let delta = 1u64 << (u64::BITS - (message_space_size).ilog2());
                                // We need to make a reference ciphertext to convert
                                // the zero ciphertexts into a Ciphertext Type
                                for ct in zeros_ct.iter() {
                                    let ctt = LweCiphertextOwned::from_container(
                                        ct.into_container().to_vec(),
                                        ct.ciphertext_modulus(),
                                    );

                                    let pt = decrypt_lwe_ciphertext(&lwe_secret_key, &ctt);
                                    // This is enough as this is expected to be a fresh encryption of 0
                                    let pt = divide_round(pt.0, delta) % message_space_size;
                                    assert_eq!(pt, 0);
                                }
                            }
                            //In case of Standard or CenteredMeanNoiseReduction, we don't have a modulus switch key so do nothing
                            ModulusSwitchConfiguration::Standard => {}
                            ModulusSwitchConfiguration::CenteredMeanNoiseReduction => {}
                        }
                    }
                    _ => panic!("expected classic bsk"),
                }
            }
            AtomicPatternServerKey::KeySwitch32(_) => {
                panic!("Unsuported AtomicPatternServerKey::KeySwitch32")
            }
            AtomicPatternServerKey::Dynamic(_) => {
                panic!("Unsuported AtomicPatternServerKey::Dynamic")
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::OnlineDistributedKeyGen;
    use crate::{
        algebra::{
            base_ring::{Z128, Z64},
            galois_rings::common::ResiduePoly,
            structure_traits::{ErrorCorrect, Invert, Solve},
        },
        execution::{
            endpoints::keygen::conformance::check_drift_technique_key,
            online::preprocessing::dummy::DummyPreprocessing,
            runtime::sessions::{
                large_session::LargeSession, session_parameters::GenericParameterHandles,
            },
            tfhe_internals::{
                parameters::{DKGParamsBasics, DKGParamsRegular, DKGParamsSnS},
                public_keysets::FhePubKeySet,
                utils::expanded_encrypt,
            },
        },
        file_handling::tests::read_element,
        tests::helper::tests_and_benches::execute_protocol_large_w_extra_data,
    };
    use crate::{
        execution::tfhe_internals::utils::tests::reconstruct_lwe_secret_key_from_file,
        networking::NetworkMode,
    };
    use crate::{
        execution::{
            random::{get_rng, seed_from_rng},
            tfhe_internals::{
                parameters::{
                    DKGParams, BC_PARAMS_NO_SNS, NIST_PARAMS_P32_NO_SNS_FGLWE,
                    NIST_PARAMS_P32_NO_SNS_LWE, NIST_PARAMS_P32_SNS_FGLWE,
                    NIST_PARAMS_P8_NO_SNS_FGLWE, NIST_PARAMS_P8_NO_SNS_LWE,
                    NIST_PARAMS_P8_SNS_FGLWE, PARAMS_TEST_BK_SNS,
                },
                test_feature::to_hl_client_key,
                utils::tests::reconstruct_glwe_secret_key_from_file,
            },
        },
        file_handling::tests::write_element,
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
        prelude::{CiphertextList, FheDecrypt, FheMin, FheTryEncrypt, ReRandomize, Tagged},
        set_server_key,
        shortint::{
            client_key::atomic_pattern::{AtomicPatternClientKey, StandardAtomicPatternClientKey},
            noise_squashing::{
                atomic_pattern::{
                    standard::StandardAtomicPatternNoiseSquashingKey,
                    AtomicPatternNoiseSquashingKey,
                },
                NoiseSquashingKey, Shortint128BootstrappingKey,
            },
            parameters::CoreCiphertextModulus,
            PBSParameters,
        },
        CompressedCiphertextListBuilder, FheUint32, FheUint64, FheUint8, ReRandomizationContext,
    };
    use tfhe_csprng::seeders::Seeder;

    #[cfg(feature = "slow_tests")]
    use tokio::time::Duration;

    #[cfg(feature = "slow_tests")]
    use crate::{
        execution::{
            config::BatchParams,
            keyset_config::KeySetConfig,
            online::preprocessing::{create_memory_factory, DKGPreprocessing},
            runtime::sessions::{
                base_session::ToBaseSession,
                small_session::{SmallSession, SmallSessionHandles},
            },
            small_execution::offline::{Preprocessing, SecureSmallPreprocessing},
            tfhe_internals::test_feature::run_decompression_test,
        },
        tests::helper::tests_and_benches::execute_protocol_small,
    };

    // NOTE: Most tests below are ignored because they are very slow and mostly redundant.
    // We only run:
    // - keygen_params_test_bk_sns_f4 which runs DKG for the test params on a degree 4 extension
    //   with a completely dummy preprocessing
    // - integration_keygen_params_test_bk_sns_existing_compression_sk_f4 which runs DKG for the test
    //   params on a degree 4 extension, using a less dummy preprocessing
    //   (i.e. dummy preprocessing is used to fill DKGPreprocessing instead of directly used)

    const DUMMY_PREPROC_SEED: u64 = 42;

    #[cfg(not(target_arch = "aarch64"))]
    #[test]
    fn pure_tfhers_test() {
        let params = crate::execution::tfhe_internals::parameters::BC_PARAMS;
        let classic_pbs = params.ciphertext_parameters;
        let dedicated_cpk_params = params.dedicated_compact_public_key_parameters.unwrap();
        let compression_params = params.compression_decompression_parameters.unwrap();
        let re_rand_ks_params = params.cpk_re_randomization_ksk_params.unwrap();

        let config = tfhe::ConfigBuilder::with_custom_parameters(classic_pbs)
            .use_dedicated_compact_public_key_parameters(dedicated_cpk_params)
            .enable_compression(compression_params)
            .enable_ciphertext_re_randomization(re_rand_ks_params);

        let client_key = tfhe::ClientKey::generate(config.clone());
        let server_key = tfhe::ServerKey::new(&client_key);
        let public_key = tfhe::CompactPublicKey::try_new(&client_key).unwrap();

        try_tfhe_pk_compactlist_computation(&client_key, &server_key, &public_key);
        set_server_key(server_key);
        try_tfhe_rerand(&client_key, &public_key);
    }

    #[cfg(feature = "extension_degree_8")]
    #[tokio::test]
    #[ignore]
    async fn keygen_params32_no_sns_fglwe_f8() {
        keygen_params32_no_sns_fglwe::<8>(false).await
    }

    #[tokio::test]
    #[ignore]
    async fn keygen_params32_no_sns_fglwe_f4() {
        keygen_params32_no_sns_fglwe::<4>(false).await
    }

    #[cfg(feature = "extension_degree_3")]
    #[tokio::test]
    #[ignore]
    async fn keygen_params32_no_sns_fglwe_f3() {
        keygen_params32_no_sns_fglwe::<3>(false).await
    }

    ///Tests related to [`PARAMS_P32_NO_SNS_FGLWE`]
    async fn keygen_params32_no_sns_fglwe<const EXTENSION_DEGREE: usize>(run_compressed: bool)
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        run_keygen_test::<EXTENSION_DEGREE>(
            NIST_PARAMS_P32_NO_SNS_FGLWE,
            5,
            1,
            KeygenTestConfig {
                run_switch_and_squash: false,
                run_shortint_with_compact: true,
                run_fheuint: true,
                run_fheuint_with_compression: false,
                run_rerand: false,
                run_compressed,
            },
        )
        .await
    }

    #[cfg(feature = "extension_degree_8")]
    #[tokio::test]
    #[ignore]
    async fn keygen_params8_no_sns_fglwe_f8() {
        keygen_params8_no_sns_fglwe::<8>(false).await
    }

    #[tokio::test]
    #[ignore]
    async fn keygen_params8_no_sns_fglwe_f4() {
        keygen_params8_no_sns_fglwe::<4>(false).await
    }

    #[cfg(feature = "extension_degree_3")]
    #[tokio::test]
    #[ignore]
    async fn keygen_params8_no_sns_fglwe_f3() {
        keygen_params8_no_sns_fglwe::<3>(false).await
    }

    ///Tests related to [`PARAMS_P8_NO_SNS_FGLWE`]
    async fn keygen_params8_no_sns_fglwe<const EXTENSION_DEGREE: usize>(run_compressed: bool)
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        run_keygen_test::<EXTENSION_DEGREE>(
            NIST_PARAMS_P8_NO_SNS_FGLWE,
            5,
            1,
            KeygenTestConfig {
                run_switch_and_squash: false,
                run_shortint_with_compact: true,
                run_fheuint: false,
                run_fheuint_with_compression: false,
                run_rerand: false,
                run_compressed,
            },
        )
        .await
    }

    #[cfg(feature = "extension_degree_8")]
    #[tokio::test]
    #[ignore]
    async fn keygen_params32_no_sns_lwe_f8() {
        keygen_params32_no_sns_lwe::<8>(false).await
    }

    #[tokio::test]
    #[ignore]
    async fn keygen_params32_no_sns_lwe_f4() {
        keygen_params32_no_sns_lwe::<4>(false).await
    }

    #[cfg(feature = "extension_degree_3")]
    #[tokio::test]
    #[ignore]
    async fn keygen_params32_no_sns_lwe_f3() {
        keygen_params32_no_sns_lwe::<3>(false).await
    }

    ///Tests related to [`PARAMS_P32_NO_SNS_LWE`]
    async fn keygen_params32_no_sns_lwe<const EXTENSION_DEGREE: usize>(run_compressed: bool)
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        run_keygen_test::<EXTENSION_DEGREE>(
            NIST_PARAMS_P32_NO_SNS_LWE,
            5,
            1,
            KeygenTestConfig {
                run_switch_and_squash: false,
                run_shortint_with_compact: true,
                run_fheuint: true,
                run_fheuint_with_compression: false,
                run_rerand: false,
                run_compressed,
            },
        )
        .await
    }

    #[cfg(feature = "extension_degree_8")]
    #[tokio::test]
    #[ignore]
    async fn keygen_params8_no_sns_lwe_f8() {
        keygen_params8_no_sns_lwe::<8>(false).await
    }

    #[tokio::test]
    #[ignore]
    async fn keygen_params8_no_sns_lwe_f4() {
        keygen_params8_no_sns_lwe::<4>(false).await
    }

    #[cfg(feature = "extension_degree_3")]
    #[tokio::test]
    #[ignore]
    async fn keygen_params8_no_sns_lwe_f3() {
        keygen_params8_no_sns_lwe::<3>(false).await
    }

    ///Tests related to [`PARAMS_P8_NO_SNS_LWE`]
    async fn keygen_params8_no_sns_lwe<const EXTENSION_DEGREE: usize>(run_compressed: bool)
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        run_keygen_test::<EXTENSION_DEGREE>(
            NIST_PARAMS_P8_NO_SNS_LWE,
            5,
            1,
            KeygenTestConfig {
                run_switch_and_squash: false,
                run_shortint_with_compact: true,
                run_fheuint: false,
                run_fheuint_with_compression: false,
                run_rerand: false,
                run_compressed,
            },
        )
        .await
    }

    #[cfg(feature = "extension_degree_8")]
    #[tokio::test]
    #[ignore]
    async fn keygen_params_test_bk_sns_f8() {
        keygen_params_test_bk_sns::<8>(false).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn keygen_params_test_bk_sns_f4() {
        keygen_params_test_bk_sns::<4>(false).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn keygen_params_test_compressed_bk_sns_f4() {
        keygen_params_test_bk_sns::<4>(true).await
    }

    #[cfg(feature = "extension_degree_3")]
    #[tokio::test]
    #[ignore]
    async fn keygen_params_test_bk_sns_f3() {
        keygen_params_test_bk_sns::<3>(false).await
    }

    ///Tests related to [`PARAMS_TEST_BK_SNS`]
    async fn keygen_params_test_bk_sns<const EXTENSION_DEGREE: usize>(run_compressed: bool)
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        run_keygen_test::<EXTENSION_DEGREE>(
            PARAMS_TEST_BK_SNS,
            5,
            1,
            KeygenTestConfig {
                run_switch_and_squash: true,
                run_shortint_with_compact: true,
                run_fheuint: true,
                run_fheuint_with_compression: true,
                run_rerand: true,
                run_compressed,
            },
        )
        .await
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[ignore] // Ignored because we run the same test for degree 4 extension
    async fn integration_keygen_params_test_bk_sns_f8() {
        integration_keygen_params_test_bk_sns::<8>(KeySetConfig::default(), false).await
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial_test::serial]
    async fn integration_keygen_params_test_bk_sns_f4() {
        integration_keygen_params_test_bk_sns::<4>(KeySetConfig::default(), false).await
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial_test::serial]
    async fn integration_keygen_params_test_compressed_bk_sns_f4() {
        integration_keygen_params_test_bk_sns::<4>(KeySetConfig::default(), true).await
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[ignore] // Ignored because we run the same test for degree 4 extension
    async fn integration_keygen_params_test_bk_sns_f3() {
        integration_keygen_params_test_bk_sns::<3>(KeySetConfig::default(), false).await
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial_test::serial]
    async fn integration_keygen_params_test_bk_sns_existing_compression_sk_f4() {
        integration_keygen_params_test_bk_sns::<4>(
            KeySetConfig::use_existing_compression_sk(),
            false,
        )
        .await
    }

    #[cfg(feature = "slow_tests")]
    ///Tests related to [`PARAMS_TEST_BK_SNS`] using _less fake_ preprocessing
    async fn integration_keygen_params_test_bk_sns<const EXTENSION_DEGREE: usize>(
        keyset_config: KeySetConfig,
        run_compressed: bool,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let params = PARAMS_TEST_BK_SNS;
        let num_parties = 4;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();
        let tag = {
            let mut tag = tfhe::Tag::default();
            tag.set_data("hello tag".as_bytes());
            tag
        };

        run_real_dkg_and_save(
            params,
            tag.clone(),
            num_parties,
            threshold,
            temp_dir.path(),
            keyset_config,
            run_compressed,
        )
        .await;

        run_switch_and_squash(
            temp_dir.path(),
            params.try_into().unwrap(),
            tag.clone(),
            num_parties,
            threshold,
        );

        run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsSnS>(
            temp_dir.path(),
            params,
            num_parties,
            threshold,
            true,
        );

        run_tfhe_computation_fheuint::<EXTENSION_DEGREE>(
            temp_dir.path(),
            params,
            num_parties,
            threshold,
            true,
            false,
        );

        run_tag_test::<EXTENSION_DEGREE>(temp_dir.path(), params, num_parties, threshold, &tag);
    }

    #[cfg(feature = "extension_degree_8")]
    #[tokio::test]
    #[ignore]
    async fn keygen_params32_with_sns_fglwe_f8() {
        keygen_params32_with_sns_fglwe::<8>(false).await
    }

    #[tokio::test]
    #[ignore]
    async fn keygen_params32_with_sns_fglwe_f4() {
        keygen_params32_with_sns_fglwe::<4>(false).await
    }

    #[cfg(feature = "extension_degree_3")]
    #[tokio::test]
    #[ignore]
    async fn keygen_params32_with_sns_fglwe_f3() {
        keygen_params32_with_sns_fglwe::<3>(false).await
    }

    ///Tests related to [`PARAMS_P32_SNS_FGLWE`]
    async fn keygen_params32_with_sns_fglwe<const EXTENSION_DEGREE: usize>(run_compressed: bool)
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        run_keygen_test::<EXTENSION_DEGREE>(
            NIST_PARAMS_P32_SNS_FGLWE,
            5,
            1,
            KeygenTestConfig {
                run_switch_and_squash: true,
                run_shortint_with_compact: true,
                run_fheuint: true,
                run_fheuint_with_compression: false,
                run_rerand: false,
                run_compressed,
            },
        )
        .await
    }

    #[cfg(feature = "extension_degree_8")]
    #[tokio::test]
    #[ignore]
    async fn keygen_params8_with_sns_fglwe_f8() {
        keygen_params8_with_sns_fglwe::<8>(false).await
    }

    #[tokio::test]
    #[ignore]
    async fn keygen_params8_with_sns_fglwe_f4() {
        keygen_params8_with_sns_fglwe::<4>(false).await
    }

    #[cfg(feature = "extension_degree_3")]
    #[tokio::test]
    #[ignore]
    async fn keygen_params8_with_sns_fglwe_f3() {
        keygen_params8_with_sns_fglwe::<3>(false).await
    }

    ///Tests related to [`PARAMS_P8_REAL_WITH_SNS`]
    async fn keygen_params8_with_sns_fglwe<const EXTENSION_DEGREE: usize>(run_compressed: bool)
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        run_keygen_test::<EXTENSION_DEGREE>(
            NIST_PARAMS_P8_SNS_FGLWE,
            5,
            1,
            KeygenTestConfig {
                run_switch_and_squash: true,
                run_shortint_with_compact: true,
                run_fheuint: false,
                run_fheuint_with_compression: false,
                run_rerand: false,
                run_compressed,
            },
        )
        .await
    }

    #[cfg(feature = "extension_degree_8")]
    #[tokio::test]
    #[ignore]
    async fn keygen_params_blockchain_without_sns_f8() {
        keygen_params_blockchain_without_sns::<8>(false).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    #[ignore]
    async fn keygen_params_blockchain_without_sns_f4() {
        keygen_params_blockchain_without_sns::<4>(false).await
    }

    #[cfg(feature = "extension_degree_3")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    #[ignore]
    async fn keygen_params_blockchain_without_sns_f3() {
        keygen_params_blockchain_without_sns::<3>(false).await
    }

    ///Tests related to [`BC_PARAMS_NO_SNS`]
    async fn keygen_params_blockchain_without_sns<const EXTENSION_DEGREE: usize>(
        run_compressed: bool,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        run_keygen_test::<EXTENSION_DEGREE>(
            BC_PARAMS_NO_SNS,
            5,
            1,
            KeygenTestConfig {
                run_switch_and_squash: false,
                run_shortint_with_compact: true,
                run_fheuint: true,
                run_fheuint_with_compression: true,
                run_rerand: true,
                run_compressed,
            },
        )
        .await
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial_test::serial]
    async fn decompression_keygen_f4() {
        let params = PARAMS_TEST_BK_SNS;
        let num_parties = 4;
        let threshold = 1;
        let temp_dir = tempfile::tempdir().unwrap();
        run_real_decompression_dkg_and_save::<4>(params, num_parties, threshold, temp_dir.path())
            .await
    }

    struct KeygenTestConfig {
        run_switch_and_squash: bool,
        run_shortint_with_compact: bool,
        run_fheuint: bool,
        run_fheuint_with_compression: bool,
        run_rerand: bool,
        run_compressed: bool,
    }

    async fn run_keygen_test<const EXTENSION_DEGREE: usize>(
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        config: KeygenTestConfig,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Solve + Invert,
    {
        let temp_dir = tempfile::tempdir().unwrap();
        let tag = {
            let mut tag = tfhe::Tag::default();
            tag.set_data("hello tag".as_bytes());
            tag
        };

        run_dkg_and_save(
            params,
            tag.clone(),
            num_parties,
            threshold,
            temp_dir.path(),
            config.run_compressed,
        )
        .await;

        if config.run_switch_and_squash {
            run_switch_and_squash(
                temp_dir.path(),
                params.try_into().unwrap(),
                tag.clone(),
                num_parties,
                threshold,
            );
        }

        match params {
            DKGParams::WithSnS(_) => {
                run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsSnS>(
                    temp_dir.path(),
                    params,
                    num_parties,
                    threshold,
                    config.run_shortint_with_compact,
                );
            }
            DKGParams::WithoutSnS(_) => {
                run_tfhe_computation_shortint::<EXTENSION_DEGREE, DKGParamsRegular>(
                    temp_dir.path(),
                    params,
                    num_parties,
                    threshold,
                    config.run_shortint_with_compact,
                );
            }
        }

        // Only run fheuint tests for parameter sets that are large enough
        if config.run_fheuint {
            run_tfhe_computation_fheuint::<EXTENSION_DEGREE>(
                temp_dir.path(),
                params,
                num_parties,
                threshold,
                config.run_fheuint_with_compression,
                config.run_rerand,
            );
        }

        run_tag_test::<EXTENSION_DEGREE>(temp_dir.path(), params, num_parties, threshold, &tag);
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
    fn binary_vec_to_shares128<R: rand::Rng + rand::CryptoRng, const EXTENSION_DEGREE: usize>(
        v: Vec<impl Into<u128>>,
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
                    let s: u128 = s.into();
                    assert!(s == 0 || s == 1);
                    let s = ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<u128>(s));
                    ShamirSharings::share(rng, s, n, t).unwrap().shares
                })
                .collect::<Vec<Vec<_>>>(),
        )
    }

    #[cfg(feature = "slow_tests")]
    async fn generate_preproc_from_params<
        const EXTENSION_DEGREE: usize,
        Ses: SmallSessionHandles<ResiduePoly<Z128, EXTENSION_DEGREE>> + ToBaseSession,
    >(
        params: &DKGParams,
        keyset_config: KeySetConfig,
        session: &mut Ses,
    ) -> Box<dyn DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    {
        let params_handle = params.get_params_basics_handle();
        let batch_size = BatchParams {
            triples: params_handle.total_triples_required(keyset_config),
            randoms: params_handle.total_randomness_required(keyset_config),
        };

        let mut small_preproc = SecureSmallPreprocessing::default()
            .execute(session, batch_size)
            .await
            .unwrap();

        let mut dkg_preproc = create_memory_factory().create_dkg_preprocessing_with_sns();

        dkg_preproc
            .fill_from_base_preproc(
                *params,
                keyset_config,
                session.get_mut_base_session(),
                &mut small_preproc,
            )
            .await
            .unwrap();

        dkg_preproc
    }

    #[cfg(feature = "slow_tests")]
    async fn run_real_decompression_dkg_and_save<const EXTENSION_DEGREE: usize>(
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        prefix_path: &Path,
    ) where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    {
        use crate::{
            execution::{
                endpoints::keygen::distributed_decompression_keygen_z128,
                sharing::share::Share,
                tfhe_internals::{
                    compression_decompression_key::CompressionPrivateKeyShares,
                    glwe_key::GlweSecretKeyShare, test_feature::gen_key_set,
                },
            },
            file_handling::tests::{read_element, write_element},
        };

        // first we need to generate two server keys
        let keyset_config = KeySetConfig::DecompressionOnly;
        let mut rng = aes_prng::AesRng::from_random_seed();
        let tag = tfhe::Tag::default();
        let keyset1 = gen_key_set(params, tag.clone(), &mut rng);
        let keyset2 = gen_key_set(params, tag, &mut rng);

        let compression_key_1_poly_size = keyset1
            .get_raw_compression_client_key()
            .unwrap()
            .polynomial_size();
        let compression_key_1 = keyset1
            .get_raw_compression_client_key()
            .unwrap()
            .into_container();
        let glwe_key_2 = keyset2.get_raw_glwe_client_key();
        let glwe_key_2_poly_size = glwe_key_2.polynomial_size();
        let glwe_key_2 = glwe_key_2.into_container();

        // and then secret share the secret keys
        let compression_key_shares_1 =
            binary_vec_to_shares128(compression_key_1, num_parties, threshold, &mut rng);
        assert_eq!(compression_key_shares_1.len(), num_parties);
        let glwe_key_shares_2 =
            binary_vec_to_shares128(glwe_key_2, num_parties, threshold, &mut rng);
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
                .set_timeout_for_next_round(Duration::from_secs(240))
                .await;
            let mut dkg_preproc =
                generate_preproc_from_params(&params, keyset_config, &mut session).await;

            let my_role = session.my_role();
            let prefix = prefix.unwrap();
            let path_compression_key_shares_1 = Path::new(&prefix).join("compression_key_shares_1");
            let path_glwe_key_shares_2 = Path::new(&prefix).join("glwe_key_shares_2");
            let compression_key_shares_1 = &read_element::<
                Vec<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>,
                _,
            >(path_compression_key_shares_1)
            .unwrap()[&my_role];
            let glwe_key_shares_2 = &read_element::<
                Vec<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>,
                _,
            >(path_glwe_key_shares_2)
            .unwrap()[&my_role];

            let private_glwe_compute_key = GlweSecretKeyShare {
                data: glwe_key_shares_2.to_vec(),
                polynomial_size: glwe_key_2_poly_size,
            };
            let private_compression_key = CompressionPrivateKeyShares {
                post_packing_ks_key: GlweSecretKeyShare {
                    data: compression_key_shares_1.to_vec(),
                    polynomial_size: compression_key_1_poly_size,
                },
                params: params
                    .get_params_basics_handle()
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

            use crate::execution::runtime::sessions::{
                base_session::GenericBaseSessionHandles,
                session_parameters::GenericParameterHandles,
            };
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
            )
            .await;

        // check that the decompression keys are the same
        let decompression_key = results.pop().unwrap().1;
        let decompression_key_bytes = bc2wrap::serialize(&decompression_key).unwrap();
        for (_role, key) in results {
            let buf = bc2wrap::serialize(&key).unwrap();
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
    async fn run_real_dkg_and_save<const EXTENSION_DEGREE: usize>(
        params: DKGParams,
        tag: tfhe::Tag,
        num_parties: usize,
        threshold: usize,
        prefix_path: &Path,
        keyset_config: KeySetConfig,
        compressed_keygen: bool,
    ) where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    {
        let mut task = |mut session: SmallSession<ResiduePoly<Z128, EXTENSION_DEGREE>>,
                        tag: Option<String>| async move {
            use crate::execution::{
                runtime::sessions::base_session::GenericBaseSessionHandles,
                tfhe_internals::compression_decompression_key::CompressionPrivateKeyShares,
            };
            let tag = tag
                .map(|s| {
                    let mut tag = tfhe::Tag::default();
                    tag.set_data(s.as_bytes());
                    tag
                })
                .unwrap_or_default();
            let compression_sk_shares = if keyset_config.is_standard_using_existing_compression_sk()
            {
                // we use dummy preprocessing to generate the existing compression sk
                // because it won't consume our preprocessing materials
                let mut dummy_preproc =
                    DummyPreprocessing::<ResiduePoly<Z128, EXTENSION_DEGREE>>::new(
                        DUMMY_PREPROC_SEED,
                        &session,
                    );
                let params_basics_handles = params.get_params_basics_handle();
                Some(
                    CompressionPrivateKeyShares::new_from_preprocessing(
                        params_basics_handles
                            .get_compression_decompression_params()
                            .unwrap()
                            .raw_compression_parameters,
                        &mut dummy_preproc,
                        params_basics_handles.get_pmax(),
                        &mut session,
                    )
                    .await
                    .unwrap(),
                )
            } else {
                None
            };

            session
                .network()
                .set_timeout_for_next_round(Duration::from_secs(240))
                .await;
            let mut dkg_preproc =
                generate_preproc_from_params(&params, keyset_config, &mut session).await;

            assert_ne!(0, dkg_preproc.bits_len());
            assert_ne!(0, dkg_preproc.triples_len());
            assert_ne!(0, dkg_preproc.randoms_len());

            let my_role = session.my_role();
            let (pk, sk) = if compressed_keygen {
                let (compressed_pk, sk) =
                    super::SecureOnlineDistributedKeyGen128::<EXTENSION_DEGREE>::compressed_keygen(
                        &mut session,
                        &mut dkg_preproc,
                        params,
                        tag.clone(),
                        compression_sk_shares.as_ref(),
                    )
                    .await
                    .unwrap();
                let (public_key, server_key) = compressed_pk.decompress().unwrap().into_raw_parts();
                (
                    FhePubKeySet {
                        public_key,
                        server_key,
                    },
                    sk,
                )
            } else {
                super::SecureOnlineDistributedKeyGen128::<EXTENSION_DEGREE>::keygen(
                    &mut session,
                    &mut dkg_preproc,
                    params,
                    tag,
                    compression_sk_shares.as_ref(),
                )
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

            (my_role, pk, sk)
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
                Some(std::str::from_utf8(tag.as_slice()).unwrap().to_string()),
            )
            .await;

        let pk_ref = results[0].1.clone();

        for (role, pk, sk) in results {
            assert_eq!(pk, pk_ref);
            write_element(
                prefix_path.join(format!("sk_p{}.der", role.one_based())),
                &sk,
            )
            .unwrap();
        }

        write_element(prefix_path.join("pk.der"), &pk_ref).unwrap();
    }

    ///Runs the DKG protocol with [`DummyPreprocessing`]
    /// and [`FakeBitGenEven`]. Saves the results to file.
    async fn run_dkg_and_save<const EXTENSION_DEGREE: usize>(
        params: DKGParams,
        tag: tfhe::Tag,
        num_parties: usize,
        threshold: usize,
        prefix_path: &Path,
        run_compressed: bool,
    ) where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let mut task = |mut session: LargeSession, tag: Option<String>| async move {
            let my_role = session.my_role();
            let mut dkg_preproc = DummyPreprocessing::new(DUMMY_PREPROC_SEED, &session);
            let tag = tag
                .map(|s| {
                    let mut tag = tfhe::Tag::default();
                    tag.set_data(s.as_bytes());
                    tag
                })
                .unwrap_or_default();

            let (pk, sk) = if run_compressed {
                let (compressed_pk, sk) =
                    super::SecureOnlineDistributedKeyGen128::<EXTENSION_DEGREE>::compressed_keygen(
                        &mut session,
                        &mut dkg_preproc,
                        params,
                        tag.clone(),
                        None,
                    )
                    .await
                    .unwrap();
                let (public_key, server_key) = compressed_pk.decompress().unwrap().into_raw_parts();
                (
                    FhePubKeySet {
                        public_key,
                        server_key,
                    },
                    sk,
                )
            } else {
                super::SecureOnlineDistributedKeyGen128::<EXTENSION_DEGREE>::keygen(
                    &mut session,
                    &mut dkg_preproc,
                    params,
                    tag,
                    None,
                )
                .await
                .unwrap()
            };

            (my_role, pk, sk)
        };

        //Async because the preprocessing is Dummy
        //Delay P1 by 1s every round
        let delay_vec = vec![tokio::time::Duration::from_secs(1)];
        let results = execute_protocol_large_w_extra_data::<
            _,
            _,
            ResiduePoly<Z128, EXTENSION_DEGREE>,
            EXTENSION_DEGREE,
        >(
            num_parties,
            threshold,
            None,
            NetworkMode::Async,
            Some(delay_vec),
            Some(std::str::from_utf8(tag.as_slice()).unwrap().to_string()),
            &mut task,
        )
        .await;

        let pk_ref = results[0].1.clone();

        for (role, pk, sk) in results {
            assert_eq!(pk, pk_ref);
            write_element(
                prefix_path.join(format!("sk_p{}.der", role.one_based())),
                &sk,
            )
            .unwrap();
        }

        write_element(prefix_path.join("pk.der"), &pk_ref).unwrap();
    }

    fn run_switch_and_squash<const EXTENSION_DEGREE: usize>(
        prefix_path: &Path,
        params: DKGParamsSnS,
        tag: tfhe::Tag,
        num_parties: usize,
        threshold: usize,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let message = (params.get_message_modulus().0 - 1) as u8;

        let sk_lwe = reconstruct_lwe_secret_key_from_file::<EXTENSION_DEGREE, _>(
            num_parties,
            threshold,
            &params,
            prefix_path,
        );
        let (sk_glwe, big_sk_glwe, sns_compression_sk) =
            reconstruct_glwe_secret_key_from_file::<EXTENSION_DEGREE>(
                num_parties,
                threshold,
                DKGParams::WithSnS(params),
                prefix_path,
            );

        let sns_raw_private_key = GlweSecretKey::from_container(
            big_sk_glwe.clone().unwrap().into_container(),
            params.sns_params.polynomial_size(),
        );

        let pk: FhePubKeySet = read_element(prefix_path.join("pk.der")).unwrap();
        let (integer_server_key, _, _, _, ck, _, _, _) = pk.server_key.clone().into_raw_parts();
        let ck = ck.unwrap();

        set_server_key(pk.server_key);

        let ddec_pk = pk.public_key;
        let ddec_sk = to_hl_client_key(
            &DKGParams::WithSnS(params),
            tag,
            sk_lwe.clone(),
            sk_glwe,
            None,
            None,
            Some(sns_raw_private_key),
            sns_compression_sk,
        )
        .unwrap();

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

        let ck_bis = {
            let (key, pt_modulus, pt_carry, ct_modulus) =
                ck.clone().into_raw_parts().into_raw_parts();
            let mod_switch = match key {
                AtomicPatternNoiseSquashingKey::Standard(ref standard_sns_key) => {
                    match standard_sns_key.bootstrapping_key() {
                        Shortint128BootstrappingKey::Classic {
                            bsk: _bsk,
                            modulus_switch_noise_reduction_key,
                        } => modulus_switch_noise_reduction_key,
                        Shortint128BootstrappingKey::MultiBit {
                            bsk: _bsk,
                            thread_count: _thread_count,
                            deterministic_execution: _deterministic_execution,
                        } => panic!("Do not support multibit for now"),
                    }
                }
                AtomicPatternNoiseSquashingKey::KeySwitch32(_) => {
                    panic!("Do not support KeySwitch32 for now")
                }
            };

            tfhe::integer::noise_squashing::NoiseSquashingKey::from_raw_parts(
                NoiseSquashingKey::from_raw_parts(
                    AtomicPatternNoiseSquashingKey::Standard(
                        StandardAtomicPatternNoiseSquashingKey::from_raw_parts(
                            Shortint128BootstrappingKey::Classic {
                                bsk: fbsk_out,
                                modulus_switch_noise_reduction_key: mod_switch.clone(),
                            },
                        ),
                    ),
                    pt_modulus,
                    pt_carry,
                    ct_modulus,
                ),
            )
        };

        let small_ct: FheUint64 = expanded_encrypt(&ddec_pk, message as u64, 64).unwrap();
        let (raw_ct, _id, _tag, _rerand_metadata) = small_ct.clone().into_raw_parts();
        let large_ct = ck
            .squash_radix_ciphertext_noise(&integer_server_key, &raw_ct)
            .unwrap();
        let large_ct_bis = ck_bis
            .squash_radix_ciphertext_noise(&integer_server_key, &raw_ct)
            .unwrap();

        let res_small: u8 = small_ct.decrypt(&ddec_sk);
        let sns_private_key = ddec_sk.clone().into_raw_parts().3.unwrap();
        let res_large = sns_private_key.decrypt_radix(&large_ct).unwrap();
        let res_large_bis = sns_private_key.decrypt_radix(&large_ct_bis).unwrap();

        assert_eq!(message, res_small);
        assert_eq!(message as u128, res_large_bis);
        assert_eq!(message as u128, res_large);
    }

    ///Runs only the shortint computation
    pub fn run_tfhe_computation_shortint<const EXTENSION_DEGREE: usize, Params: DKGParamsBasics>(
        prefix_path: &Path,
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        with_compact: bool,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let (shortint_sk, pk) = retrieve_keys_from_files::<EXTENSION_DEGREE>(
            params,
            num_parties,
            threshold,
            prefix_path,
        );

        set_server_key(pk.server_key.clone());
        let (shortint_pk, tag) = {
            let (shorint_pk, _, _, _, _, _, _, tag) = pk.server_key.clone().into_raw_parts();
            (shorint_pk.into_raw_parts(), tag)
        };
        for _ in 0..100 {
            try_tfhe_shortint_computation(&shortint_sk, &shortint_pk);
        }

        if with_compact {
            let tfhe_sk = tfhe::ClientKey::from_raw_parts(
                shortint_sk.into(),
                None,
                None,
                None,
                None,
                None,
                tag,
            );
            try_tfhe_pk_compactlist_computation(&tfhe_sk, &pk.server_key, &pk.public_key);
        }
    }

    ///Runs both shortint and fheuint computation
    fn run_tag_test<const EXTENSION_DEGREE: usize>(
        prefix_path: &Path,
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        expected_tag: &tfhe::Tag,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let (_shortint_sk, pk) = retrieve_keys_from_files::<EXTENSION_DEGREE>(
            params,
            num_parties,
            threshold,
            prefix_path,
        );

        assert_eq!(expected_tag, pk.server_key.tag());
        assert_eq!(expected_tag, pk.public_key.tag());

        let msg = 12u64;
        let small_ct: FheUint64 = expanded_encrypt(&pk.public_key, msg, 64).unwrap();

        assert_eq!(expected_tag, small_ct.tag());
    }

    ///Runs both shortint and fheuint computation
    fn run_tfhe_computation_fheuint<const EXTENSION_DEGREE: usize>(
        prefix_path: &Path,
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        do_compression_test: bool,
        with_rerand: bool,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let (shortint_sk, pk) = retrieve_keys_from_files::<EXTENSION_DEGREE>(
            params,
            num_parties,
            threshold,
            prefix_path,
        );

        set_server_key(pk.server_key.clone());
        let tag = pk.server_key.tag();

        let shortint_pk = pk.server_key.clone().into_raw_parts().0.into_raw_parts();
        for _ in 0..100 {
            try_tfhe_shortint_computation(&shortint_sk, &shortint_pk);
        }

        // Note that there is no `compression_key` because this key is never used to
        // encrypt/decrypt. We only compress and decompress which doesn't require this key.
        let tfhe_sk = tfhe::ClientKey::from_raw_parts(
            shortint_sk.into(),
            None,
            None,
            None,
            None,
            None,
            tag.clone(),
        );

        try_tfhe_fheuint_computation(&tfhe_sk);
        if do_compression_test {
            try_tfhe_compression_computation(&tfhe_sk);
        }
        if with_rerand {
            try_tfhe_rerand(&tfhe_sk, &pk.public_key);
        }
    }

    ///Read files created by [`run_dkg_and_save`] and reconstruct the secret keys
    ///from the parties' shares
    fn retrieve_keys_from_files<const EXTENSION_DEGREE: usize>(
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
        prefix_path: &Path,
    ) -> (tfhe::shortint::ClientKey, FhePubKeySet)
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
        let (glwe_secret_key, _, _) = reconstruct_glwe_secret_key_from_file::<EXTENSION_DEGREE>(
            num_parties,
            threshold,
            params,
            prefix_path,
        );
        let pk: FhePubKeySet = read_element(prefix_path.join("pk.der")).unwrap();

        let sck = StandardAtomicPatternClientKey::from_raw_parts(
            glwe_secret_key,
            lwe_secret_key,
            PBSParameters::PBS(params_tfhe_rs),
            None,
        );
        let shortint_client_key = tfhe::shortint::ClientKey {
            atomic_pattern: AtomicPatternClientKey::Standard(sck),
        };

        check_drift_technique_key(params_tfhe_rs, &pk.server_key, &shortint_client_key);
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

        let modulus = shortint_client_key.parameters().message_modulus().0;

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

    fn try_tfhe_rerand(cks: &tfhe::ClientKey, cpk: &tfhe::CompactPublicKey) {
        let compact_public_encryption_domain_separator = *b"TFHE.Enc";
        let rerand_domain_separator = *b"TFHE.Rrd";

        // Case where we want to compute FheUint64 + FheUint64 and re-randomize those inputs
        {
            let clear_a = rand::random::<u64>();
            let clear_b = rand::random::<u64>();
            let compact_ctxt_list = tfhe::CompactCiphertextList::builder(cpk)
                .push(clear_a)
                .push(clear_b)
                .build_packed();
            let expander = compact_ctxt_list.expand().unwrap();
            let mut a: tfhe::FheUint64 = expander.get(0).unwrap().unwrap();
            let mut b: tfhe::FheUint64 = expander.get(1).unwrap().unwrap();

            // Simulate a 256 bits hash added as metadata
            let rand_a: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
            let rand_b: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
            a.re_randomization_metadata_mut().set_data(&rand_a);
            b.re_randomization_metadata_mut().set_data(&rand_b);

            let mut builder = CompressedCiphertextListBuilder::new();
            builder.push(a);
            builder.push(b);
            let list = builder.build().unwrap();

            let mut a: FheUint64 = list.get(0).unwrap().unwrap();
            let mut b: FheUint64 = list.get(1).unwrap().unwrap();

            assert_eq!(a.re_randomization_metadata().data(), &rand_a);
            assert_eq!(b.re_randomization_metadata().data(), &rand_b);

            // Simulate a 256 bits nonce
            let nonce: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());

            let mut re_rand_context = ReRandomizationContext::new(
                rerand_domain_separator,
                // First is the function description, second is a nonce
                [b"FheUint64+FheUint64".as_slice(), nonce.as_slice()],
                compact_public_encryption_domain_separator,
            );

            // Add ciphertexts to the context

            re_rand_context.add_ciphertext(&a);
            re_rand_context.add_ciphertext(&b);

            let mut seed_gen = re_rand_context.finalize();

            a.re_randomize(cpk, seed_gen.next_seed().unwrap()).unwrap();

            b.re_randomize(cpk, seed_gen.next_seed().unwrap()).unwrap();

            let c = a + b;
            let dec: u64 = c.decrypt(cks);

            assert_eq!(clear_a.wrapping_add(clear_b), dec);
        }
    }
}
