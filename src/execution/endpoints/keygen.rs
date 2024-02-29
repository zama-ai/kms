use std::{num::Wrapping, sync::Arc};

use crate::execution::tfhe_internals::parameters::{DKGParams, DKGParamsBasics};
use crate::{
    algebra::{
        residue_poly::{ResiduePoly, ResiduePoly128},
        structure_traits::{BaseRing, Ring},
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        constants::INPUT_PARTY_ID,
        online::triple::open_list,
        runtime::{
            party::Role,
            session::{
                BaseSession, BaseSessionHandles, ParameterHandles, SessionParameters, SetupMode,
                SmallSession, SmallSessionStruct, ToBaseSession,
            },
        },
        sharing::{input::robust_input, shamir::ErrorCorrect},
        small_execution::{agree_random::DummyAgreeRandom, prss::PRSSSetup},
        tfhe_internals::{
            glwe_key::GlweSecretKeyShare,
            lwe_bootstrap_key_generation::allocate_and_generate_lwe_bootstrap_key,
            lwe_key::{allocate_and_generate_new_lwe_compact_public_key, LweSecretKeyShare},
            lwe_keyswitch_key_generation::allocate_and_generate_new_lwe_keyswitch_key,
            randomness::{EncryptionType, MPCEncryptionRandomGenerator},
        },
    },
    file_handling::{read_element, write_element},
    lwe::{gen_key_set, KeySet, PubConKeyPair, SecretKeyShare},
    networking::value::NetworkValue,
};
use crate::{
    execution::online::preprocessing::{DKGPreprocessing, NoiseBounds, RandomPreprocessing},
    lwe::ThresholdLWEParameters,
};
use aes_prng::AesRng;
use concrete_csprng::generators::SoftwareRandomGenerator;
use itertools::Itertools;
use ndarray::Array1;
use num_integer::div_ceil;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use tfhe::core_crypto::commons::traits::UnsignedInteger;
use tfhe::core_crypto::prelude::Numeric;
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
use tokio::{task::JoinSet, time::timeout_at};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PubKeySet {
    pub lwe_public_key: LweCompactPublicKey<Vec<u64>>,
    pub ksk: LweKeyswitchKey<Vec<u64>>,
    pub bk: LweBootstrapKey<Vec<u64>>,
    pub bk_sns: Option<LweBootstrapKey<Vec<u128>>>,
}

impl PubKeySet {
    pub fn write_to_file(&self, path: String) -> anyhow::Result<()> {
        write_element(path, self)
    }

    pub fn read_from_file(path: String) -> anyhow::Result<Self> {
        read_element(path)
    }

    pub fn into_tfhe_shortint_keys(self, params: DKGParams) -> tfhe::shortint::ServerKey {
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

        let max_noise_level = MaxNoiseLevel::from_msg_carry_modulus(
            regular_params.get_message_modulus(),
            regular_params.get_carry_modulus(),
        );

        let pk_bk = ShortintBootstrappingKey::Classic(fourier_bsk);

        let params_tfhe = regular_params.to_classic_pbs_parameters();

        tfhe::shortint::ServerKey::from_raw_parts(
            self.ksk,
            pk_bk,
            regular_params.get_message_modulus(),
            regular_params.get_carry_modulus(),
            MaxDegree::new(max_value),
            max_noise_level,
            params_tfhe.ciphertext_modulus,
            params_tfhe.encryption_key_choice.into(),
        )
    }

    pub fn into_tfhe_hl_api_keys(self, params: DKGParams) -> tfhe::ServerKey {
        let shortint_key = self.into_tfhe_shortint_keys(params);
        let integer_key = tfhe::integer::ServerKey::from_raw_parts(shortint_key);
        tfhe::ServerKey::from_raw_parts(integer_key, None)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateKeySet<Z> {
    pub lwe_secret_key_share: LweSecretKeyShare<Z>,
    pub glwe_secret_key_share: GlweSecretKeyShare<Z>,
    pub glwe_secret_key_share_sns: Option<GlweSecretKeyShare<Z>>,
}
impl<Z: BaseRing> PrivateKeySet<Z> {
    pub fn write_to_file(&self, path: String) -> anyhow::Result<()> {
        write_element(path, self)
    }

    pub fn read_from_file(path: String) -> anyhow::Result<Self> {
        read_element(path)
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
    let params = params.get_params_basics_handle();
    let my_role = session.my_role()?;
    //Init the shared LWE secret key
    tracing::info!("(Party {my_role}) Generating LWE Secret key...Start");
    let lwe_secret_key_share =
        LweSecretKeyShare::new_from_preprocessing(params.lwe_dimension(), preprocessing)?;
    tracing::info!("(Party {my_role}) Generating corresponding public key...Start");
    let vec_tuniform_noise = preprocessing
        .next_noise_vec(
            params.num_needed_noise_pk(),
            NoiseBounds::LweNoise(params.lwe_tuniform_bound()),
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

    //Open the public key and cast it to TFHE-RS type
    Ok((
        lwe_secret_key_share,
        lwe_public_key_shared.open_to_tfhers_type(session).await?,
    ))
}

///Generate the Key Switch Key from a Glwe key given in Lwe format,
///and an actual Lwe key
async fn generate_key_switch_key<
    Z: BaseRing,
    P: DKGPreprocessing<ResiduePoly<Z>> + ?Sized,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    Gen: ByteRandomGenerator,
>(
    glwe_sk_share_as_lwe: &LweSecretKeyShare<Z>,
    lwe_secret_key_share: &LweSecretKeyShare<Z>,
    params: &DKGParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<LweKeyswitchKey<Vec<u64>>>
where
    ResiduePoly<Z>: ErrorCorrect,
{
    let params = params.get_params_basics_handle();
    let my_role = session.my_role()?;
    tracing::info!("(Party {my_role}) Generating KSK...Start");
    let vec_tuniform_noise = preprocessing
        .next_noise_vec(
            params.num_needed_noise_ksk(),
            NoiseBounds::LweNoise(params.lwe_tuniform_bound()),
        )?
        .iter()
        .map(|share| share.value())
        .collect_vec();

    mpc_encryption_rng.fill_noise(vec_tuniform_noise);

    //Then compute the KSK
    let ksk_share = allocate_and_generate_new_lwe_keyswitch_key(
        glwe_sk_share_as_lwe,
        lwe_secret_key_share,
        params.decomposition_base_log_ksk(),
        params.decomposition_level_count_ksk(),
        mpc_encryption_rng,
    )?;

    //Open the KSK and cast it to TFHE-RS type
    ksk_share.open_to_tfhers_type(session).await
}

///Generates a Bootstrapping Key given a Glwe key in Glwe format
///, a Lwe key and the params enum variant:
/// - [`DKGParams::WithoutSnS`] for __regular__ BK
/// - [`DKGParams::WithSnS`] for __Switch and Squash__ BK
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
    params: &DKGParams,
    mpc_encryption_rng: &mut MPCEncryptionRandomGenerator<Z, Gen>,
    session: &mut S,
    preprocessing: &mut P,
) -> anyhow::Result<LweBootstrapKey<Vec<Scalar>>>
where
    ResiduePoly<Z>: ErrorCorrect,
{
    let my_role = session.my_role()?;
    //First sample the noise
    let vec_tuniform_noise = match params {
        DKGParams::WithoutSnS(regular_params) => preprocessing
            .next_noise_vec(
                regular_params.num_needed_noise_bk(),
                NoiseBounds::GlweNoise(regular_params.glwe_tuniform_bound()),
            )?
            .iter()
            .map(|share| share.value())
            .collect_vec(),

        DKGParams::WithSnS(sns_params) => preprocessing
            .next_noise_vec(
                sns_params.num_needed_noise_bk_sns(),
                NoiseBounds::GlweNoiseSnS(sns_params.glwe_tuniform_bound_sns()),
            )?
            .iter()
            .map(|share| share.value())
            .collect_vec(),
    };

    mpc_encryption_rng.fill_noise(vec_tuniform_noise);

    tracing::info!(
        "(Party {my_role}) Generating BK for {} ...Start",
        params.kind_to_str()
    );

    let bk_share = match params {
        DKGParams::WithoutSnS(regular_params) => allocate_and_generate_lwe_bootstrap_key(
            lwe_secret_key_share,
            glwe_secret_key_share,
            regular_params.decomposition_base_log_bk(),
            regular_params.decomposition_level_count_bk(),
            mpc_encryption_rng,
            EncryptionType::Bits64,
            session,
            preprocessing,
        ),
        DKGParams::WithSnS(sns_params) => allocate_and_generate_lwe_bootstrap_key(
            lwe_secret_key_share,
            glwe_secret_key_share,
            sns_params.decomposition_base_log_bk_sns(),
            sns_params.decomposition_level_count_bk_sns(),
            mpc_encryption_rng,
            EncryptionType::Bits128,
            session,
            preprocessing,
        ),
    }
    .await?;

    tracing::info!(
        "(Party {my_role}) Generating BK {} ...Done",
        params.kind_to_str()
    );
    tracing::info!(
        "(Party {my_role}) Opening BK {} ...Start",
        params.kind_to_str()
    );
    //Open the bk and cast it to TFHE-rs type
    let bk = bk_share
        .open_to_tfhers_type::<Scalar, _, _>(session)
        .await?;
    tracing::info!(
        "(Party {my_role}) Opening BK {:?} ...Done",
        params.kind_to_str()
    );
    Ok(bk)
}

///Runs the distributed key generation protocol.
///
/// Expects:
/// - session: the session that holds necessary information for networking
/// - preprocessing: [`DKGPreprocessing`] handle with enough triples, bits and noise available
/// - params: [`DKGParams`] parameters for the Distributed Key Generation
///
/// Outputs:
/// - A [`PubKeySet`] composed of the public key, the KSK, the BK and the BK_sns if required
/// - a [`PrivateKeySet`] composed of shares of the lwe and glwe private keys
///
///If the [`DKGParams::o_flag`] is set in the params, then the sharing domain must be [`ResiduePoly128`] but the domain of
///all non-overlined key material is still [`u64`].
/// Note that there is some redundancy of information because we also explicitly ask the [`BaseRing`] as trait parameter
pub async fn distributed_keygen<
    Z: BaseRing,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    P: DKGPreprocessing<ResiduePoly<Z>> + Send + ?Sized,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
) -> anyhow::Result<(PubKeySet, PrivateKeySet<Z>)>
where
    ResiduePoly<Z>: ErrorCorrect,
{
    let params_basics_handle = params.get_params_basics_handle();
    let my_role = session.my_role()?;
    let seed = sample_seed(params_basics_handle.get_sec(), session, preprocessing).await?;
    //Init the XOF with the seed computed above
    let mut mpc_encryption_rng =
        MPCEncryptionRandomGenerator::<Z, SoftwareRandomGenerator>::new_from_seed(seed);

    //Generate the shared LWE secret key and corresponding public key
    let (lwe_secret_key_share, lwe_public_key) = generate_lwe_private_public_key_pair(
        &params,
        &mut mpc_encryption_rng,
        session,
        preprocessing,
    )
    .await?;

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

    //Generate the KSK
    let ksk = generate_key_switch_key(
        &glwe_sk_share_as_lwe,
        &lwe_secret_key_share,
        &params,
        &mut mpc_encryption_rng,
        session,
        preprocessing,
    )
    .await?;
    tracing::info!("(Party {my_role}) Generating KSK...Done");

    //Compute the bootstrapping keys
    let bk = generate_bootstrap_key(
        &glwe_secret_key_share,
        &lwe_secret_key_share,
        &params.get_params_without_sns(),
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

            tracing::info!("(Party {my_role}) Generating SnS GLWE...Done");
            let bk_sns = generate_bootstrap_key(
                &glwe_secret_key_share_sns,
                &lwe_secret_key_share,
                &params,
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

    let pub_key_set = PubKeySet {
        lwe_public_key,
        ksk,
        bk,
        bk_sns,
    };

    let priv_key_set = PrivateKeySet {
        lwe_secret_key_share,
        glwe_secret_key_share,
        glwe_secret_key_share_sns,
    };

    Ok((pub_key_set, priv_key_set))
}

pub async fn transfer_pk<Z: Ring>(
    session: &BaseSession,
    pubkey: Option<PubConKeyPair>,
    role: &Role,
    input_party_id: usize,
) -> anyhow::Result<PubConKeyPair> {
    session.network().increase_round_counter().await?;
    if role.one_based() == input_party_id {
        let pubkey_raw = pubkey
            .ok_or_else(|| anyhow_error_and_log("I have no public key to send!".to_string()))?;
        let num_parties = session.num_parties();
        let pkval = NetworkValue::<Z>::PubKey(Box::new(pubkey_raw.clone()));

        let mut set = JoinSet::new();
        for to_send_role in 1..=num_parties {
            if to_send_role != input_party_id {
                let identity = session.identity_from(&Role::indexed_by_one(to_send_role))?;

                let networking = Arc::clone(session.network());
                let session_id = session.session_id();
                let send_pk = pkval.clone();

                set.spawn(async move {
                    let _ = networking
                        .send(send_pk.to_network(), &identity, &session_id)
                        .await;
                });
            }
        }
        while (set.join_next().await).is_some() {}
        Ok(pubkey_raw)
    } else {
        let receiver = session.identity_from(&Role::indexed_by_one(input_party_id))?;
        let networking = Arc::clone(session.network());
        let session_id = session.session_id();
        let timeout = session.network().get_timeout_current_round()?;
        tracing::debug!(
            "Waiting for receiving public key from input party with timeout {:?}",
            timeout
        );
        let data = tokio::spawn(timeout_at(timeout, async move {
            networking.receive(&receiver, &session_id).await
        }))
        .await??;

        let pk = match NetworkValue::<Z>::from_network(data)? {
            NetworkValue::PubKey(pk) => pk,
            _ => Err(anyhow_error_and_log(
                "I have received sth different from a public key!".to_string(),
            ))?,
        };
        Ok(*pk)
    }
}

pub async fn initialize_key_material(
    session: &mut SmallSession<ResiduePoly128>,
    setup_mode: SetupMode,
    params: ThresholdLWEParameters,
) -> anyhow::Result<(
    SecretKeyShare,
    PubConKeyPair,
    Option<PRSSSetup<ResiduePoly128>>,
)> {
    let prss_setup = if setup_mode == SetupMode::AllProtos {
        Some(
            PRSSSetup::init_with_abort::<
                DummyAgreeRandom,
                AesRng,
                SmallSessionStruct<ResiduePoly128, AesRng, SessionParameters>,
            >(session)
            .await?,
        )
    } else {
        None
    };

    let own_role = session.my_role()?;

    let mut keyset: Option<KeySet> = None;

    if own_role.one_based() == INPUT_PARTY_ID {
        keyset = Some(gen_key_set(params, &mut session.rng()));
        tracing::info!("Keyset generated by input party {}", own_role);
    }

    let sk_container64: Vec<u64> = keyset
        .as_ref()
        .map(|s| s.clone().get_raw_client_key().into_container())
        .unwrap_or_else(|| {
            // TODO: This needs to be refactor, since we have done this hack in order all the
            // parties that are not INPUT_PARTY_ID wait for INPUT_PARTY_ID to generate the keyset
            // and distribute the lwe secret key vector to the rest. Otherwise if we would have set
            // Vec::new() here, the other parties would have continued to transfer_pk and would
            // have panicked because they would have received something different from a PK.
            vec![Numeric::ZERO; params.input_cipher_parameters.lwe_dimension.0]
        });

    let sk_container128: Vec<u128> = keyset
        .as_ref()
        .map(|s| s.clone().client_output_key.large_key.into_container())
        .unwrap_or_else(|| {
            // TODO: This needs to be refactor, since we have done this hack in order all the
            // parties that are not INPUT_PARTY_ID wait for INPUT_PARTY_ID to generate the keyset
            // and distribute the lwe secret key vector to the rest. Otherwise if we would have set
            // Vec::new() here, the other parties would have continued to transfer_pk and would
            // have panicked because they would have received something different from a PK.
            vec![
                Numeric::ZERO;
                params.output_cipher_parameters.polynomial_size.0
                    * params.output_cipher_parameters.glwe_dimension.0
            ]
        });

    // iterate through sk and share each element

    let mut key_shares64 = Vec::new();
    // iterate through sk and share each element
    // TODO(Dragos) this sharing can be done in a single round
    tracing::info!("Sharing key64 to be send {}", sk_container64.len());
    for cur in sk_container64 {
        let secret = match own_role.one_based() {
            1 => Some(ResiduePoly::from_scalar(Wrapping::<u64>(cur))),
            _ => None,
        };
        let share = robust_input::<_, AesRng>(
            &mut session.to_base_session(),
            &secret,
            &own_role,
            INPUT_PARTY_ID,
        )
        .await?; //TODO(Daniel) batch this for all big_ell

        key_shares64.push(share);
    }

    let mut key_shares128 = Vec::new();
    // TODO(Dragos) this sharing can be done in a single round
    tracing::info!("Sharing key128 to be send {}", sk_container128.len());
    for cur in sk_container128 {
        let secret = match own_role.one_based() {
            1 => Some(ResiduePoly::from_scalar(Wrapping::<u128>(cur))),
            _ => None,
        };
        let share = robust_input::<_, AesRng>(
            &mut session.to_base_session(),
            &secret,
            &own_role,
            INPUT_PARTY_ID,
        )
        .await?; //TODO(Daniel) batch this for all big_ell

        key_shares128.push(share);
    }

    let pubcon = keyset.map(|s| PubConKeyPair {
        public_key: s.public_key,
        conversion_key: s.conversion_key,
    });
    let transferred_pk = transfer_pk::<ResiduePoly128>(
        &session.to_base_session(),
        pubcon,
        &own_role,
        INPUT_PARTY_ID,
    )
    .await?;

    let shared_sk = SecretKeyShare {
        input_key_share64: Array1::from_vec(key_shares64),
        input_key_share128: Array1::from_vec(key_shares128),
        threshold_lwe_parameters: params,
    };

    Ok((shared_sk, transferred_pk, prss_setup))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use concrete_csprng::seeders::Seeder;
    use itertools::Itertools;
    use tfhe::{
        core_crypto::{
            algorithms::{
                convert_standard_lwe_bootstrap_key_to_fourier_128, par_generate_lwe_bootstrap_key,
            },
            commons::{
                generators::{DeterministicSeeder, EncryptionRandomGenerator},
                math::random::ActivatedRandomGenerator,
                traits::CastInto,
            },
            entities::{Fourier128LweBootstrapKey, LweBootstrapKey, LweSecretKey},
        },
        prelude::{FheDecrypt, FheEncrypt, FheMin, FheTryEncrypt},
        set_server_key,
        shortint::parameters::{CoreCiphertextModulus, StandardDev},
        FheUint32, FheUint64, FheUint8,
    };

    use crate::{
        algebra::{base_ring::Z128, residue_poly::ResiduePoly128},
        execution::{
            config::BatchParams,
            online::preprocessing::{default_factory, dummy::DummyPreprocessing},
            runtime::session::{
                LargeSession, ParameterHandles, SmallSession, SmallSessionHandles, ToBaseSession,
            },
            small_execution::{
                agree_random::DummyAgreeRandom, offline::SmallPreprocessing, prss::PRSSSetup,
            },
            tfhe_internals::parameters::{
                DKGParamsBasics, DKGParamsRegular, DKGParamsSnS, PARAMS_P32_SMALL_NO_SNS,
                PARAMS_P8_SMALL_NO_SNS,
            },
        },
        lwe::{to_hl_client_key, to_hl_public_key},
        tests::helper::tests_and_benches::{execute_protocol_large, execute_protocol_small},
    };
    use crate::{
        execution::tfhe_internals::{
            parameters::{PARAMS_P32_REAL_WITH_SNS, PARAMS_P8_REAL_WITH_SNS},
            utils::tests::reconstruct_lwe_secret_key_from_file,
        },
        lwe::LargeClientKey,
    };
    use crate::{
        execution::{
            random::{get_rng, seed_from_rng},
            tfhe_internals::{
                parameters::PARAMS_TEST_BK_SNS, utils::tests::reconstruct_glwe_secret_key_from_file,
            },
        },
        lwe::ConversionKey,
    };

    use super::{distributed_keygen, DKGParams, PubKeySet};

    struct TestKeySize {
        public_key_material_size: u64,
        secret_key_material_size: u64,
    }

    ///Tests related to [`PARAMS_P32_SMALL_NO_SNS`]
    #[test]
    #[ignore]
    fn keygen_params32_small_no_sns() {
        let params = PARAMS_P32_SMALL_NO_SNS;
        let params_basics_handles = params.get_params_basics_handle();
        let num_parties = 5;
        let threshold = 1;

        if !std::path::Path::new(&params_basics_handles.get_prefix_path()).exists() {
            _ = fs::create_dir(params_basics_handles.get_prefix_path());
            run_dkg_and_save(params, num_parties, threshold);
        }
        let expected_size = TestKeySize {
            public_key_material_size: 117506209,
            secret_key_material_size: 417817,
        };

        assert_key_size(
            params_basics_handles.get_prefix_path(),
            expected_size,
            num_parties,
        );
        run_tfhe_computation_shortint::<DKGParamsRegular>(
            params_basics_handles.get_prefix_path(),
            num_parties,
            threshold,
        );
        run_tfhe_computation_fheuint::<DKGParamsRegular>(
            params_basics_handles.get_prefix_path(),
            num_parties,
            threshold,
        );
    }

    ///Tests related to [`PARAMS_P8_SMALL_NO_SNS`]
    #[test]
    #[ignore]
    fn keygen_params8_small_no_sns() {
        let params = PARAMS_P8_SMALL_NO_SNS;
        let params_basics_handles = params.get_params_basics_handle();
        let num_parties = 5;
        let threshold = 1;

        if !std::path::Path::new(&params_basics_handles.get_prefix_path()).exists() {
            _ = fs::create_dir(params_basics_handles.get_prefix_path());
            run_dkg_and_save(params, num_parties, threshold);
        }

        let expected_size = TestKeySize {
            public_key_material_size: 10498209,
            secret_key_material_size: 139289,
        };

        assert_key_size(
            params_basics_handles.get_prefix_path(),
            expected_size,
            num_parties,
        );
        //This parameter set isnt big enough to run the fheuint tests
        run_tfhe_computation_shortint::<DKGParamsRegular>(
            params_basics_handles.get_prefix_path(),
            num_parties,
            threshold,
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

        if !std::path::Path::new(&params_basics_handles.get_prefix_path()).exists() {
            _ = fs::create_dir(params_basics_handles.get_prefix_path());
            run_dkg_and_save(params, num_parties, threshold);
        }

        let expected_size = TestKeySize {
            public_key_material_size: 2493153,
            secret_key_material_size: 82729,
        };

        assert_key_size(
            params_basics_handles.get_prefix_path(),
            expected_size,
            num_parties,
        );
        run_switch_and_squash(
            params_basics_handles.get_prefix_path(),
            num_parties,
            threshold,
        );
    }

    ///Tests related to [`PARAMS_TEST_BK_SNS`] using _less fake_ preprocessing
    #[test]
    #[ignore]
    fn integration_keygen_params_bk_sns() {
        let params = PARAMS_TEST_BK_SNS;
        let params_basics_handles = params.get_params_basics_handle();
        let num_parties = 4;
        let threshold = 1;

        if !std::path::Path::new(&(params_basics_handles.get_prefix_path() + "/integration/"))
            .exists()
        {
            _ = fs::create_dir(params_basics_handles.get_prefix_path() + "/integration/");
            run_real_dkg_and_save(params, num_parties, threshold);
        }
        let expected_size = TestKeySize {
            public_key_material_size: 2493153,
            secret_key_material_size: 82729,
        };

        assert_key_size(
            params_basics_handles.get_prefix_path() + "/integration/",
            expected_size,
            num_parties,
        );
        run_switch_and_squash(
            params_basics_handles.get_prefix_path() + "/integration/",
            num_parties,
            threshold.into(),
        );
    }

    ///Tests related to [`PARAMS_P32_REAL_WITH_SNS`]
    #[test]
    #[ignore]
    fn keygen_params32_real_with_sns() {
        let params = PARAMS_P32_REAL_WITH_SNS;
        let params_basics_handles = params.get_params_basics_handle();
        let num_parties = 5;
        let threshold = 1;

        if !std::path::Path::new(&params_basics_handles.get_prefix_path()).exists() {
            _ = fs::create_dir(params_basics_handles.get_prefix_path());
            run_dkg_and_save(params, num_parties, threshold);
        }

        let expected_size = TestKeySize {
            public_key_material_size: 1023475937,
            secret_key_material_size: 974889,
        };

        assert_key_size(
            params_basics_handles.get_prefix_path(),
            expected_size,
            num_parties,
        );

        run_switch_and_squash(
            params_basics_handles.get_prefix_path(),
            num_parties,
            threshold,
        );

        run_tfhe_computation_shortint::<DKGParamsSnS>(
            params_basics_handles.get_prefix_path(),
            num_parties,
            threshold,
        );
        run_tfhe_computation_fheuint::<DKGParamsSnS>(
            params_basics_handles.get_prefix_path(),
            num_parties,
            threshold,
        );
    }

    ///Tests related to [`PARAMS_P8_REAL_WITH_SNS`]
    #[test]
    #[ignore]
    fn keygen_params8_real_with_sns() {
        let params = PARAMS_P8_REAL_WITH_SNS;
        let params_basics_handles = params.get_params_basics_handle();
        let num_parties = 5;
        let threshold = 1;

        if !std::path::Path::new(&params_basics_handles.get_prefix_path()).exists() {
            _ = fs::create_dir(params_basics_handles.get_prefix_path());
            run_dkg_and_save(params, num_parties, threshold);
        }

        let expected_size = TestKeySize {
            public_key_material_size: 1350607073,
            secret_key_material_size: 905257,
        };

        assert_key_size(
            params_basics_handles.get_prefix_path(),
            expected_size,
            num_parties,
        );

        run_switch_and_squash(
            params_basics_handles.get_prefix_path(),
            num_parties,
            threshold,
        );

        //This parameter set isnt big enough to run the fheuint tests
        run_tfhe_computation_shortint::<DKGParamsSnS>(
            params_basics_handles.get_prefix_path(),
            num_parties,
            threshold,
        );
    }

    fn assert_key_size(prefix_path: String, expected_size: TestKeySize, num_parties: usize) {
        let pk_size = fs::metadata(format!("{}/pk.der", prefix_path))
            .unwrap()
            .len();
        assert_eq!(pk_size, expected_size.public_key_material_size);
        for i in 0..num_parties {
            let sk_size = fs::metadata(format!("{}/sk_p{i}.der", prefix_path))
                .unwrap()
                .len();
            assert_eq!(sk_size, expected_size.secret_key_material_size);
        }
    }

    fn run_real_dkg_and_save(params: DKGParams, num_parties: usize, threshold: u8) {
        let params_basics_handles = params.get_params_basics_handle();
        params_basics_handles
            .write_to_file(format!(
                "{}/integration/params.json",
                params_basics_handles.get_prefix_path()
            ))
            .unwrap();

        let mut task = |mut session: SmallSession<ResiduePoly128>| async move {
            let prss_setup = PRSSSetup::init_with_abort::<DummyAgreeRandom, _, _>(&mut session)
                .await
                .unwrap();
            session.set_prss(Some(
                prss_setup.new_prss_session_state(session.session_id()),
            ));

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

            let mut dkg_preproc =
                default_factory::<Z128>().create_dkg_preprocessing_with_sns(params);

            dkg_preproc
                .fill_from_base_preproc(&mut session.to_base_session(), &mut small_preproc)
                .await
                .unwrap();

            let my_role = session.my_role().unwrap();
            let (pk, sk) =
                distributed_keygen::<Z128, _, _, _>(&mut session, dkg_preproc.as_mut(), params)
                    .await
                    .unwrap();

            (my_role, pk, sk)
        };

        let results =
            execute_protocol_small::<ResiduePoly128, _, _>(num_parties, threshold, None, &mut task);

        let pk_ref = results[0].1.clone();

        for (role, pk, sk) in results {
            assert_eq!(pk, pk_ref);
            sk.write_to_file(format!(
                "{}/integration/sk_p{}.der",
                params_basics_handles.get_prefix_path(),
                role.zero_based()
            ))
            .unwrap();
        }

        pk_ref
            .write_to_file(format!(
                "{}/integration/pk.der",
                params_basics_handles.get_prefix_path()
            ))
            .unwrap();
    }

    ///Runs the DKG protocol with [`DummyPreprocessing`]
    /// and [`FakeBitGenEven`]. Saves the results to file.
    fn run_dkg_and_save(params: DKGParams, num_parties: usize, threshold: usize) {
        let params_basics_handles = params.get_params_basics_handle();
        params_basics_handles
            .write_to_file(format!(
                "{}/params.json",
                params_basics_handles.get_prefix_path()
            ))
            .unwrap();

        let mut task = |mut session: LargeSession| async move {
            let my_role = session.my_role().unwrap();
            let mut large_preproc = DummyPreprocessing::new(0_u64, session.clone());

            let (pk, sk) =
                distributed_keygen::<Z128, _, _, _>(&mut session, &mut large_preproc, params)
                    .await
                    .unwrap();

            (my_role, pk, sk)
        };

        let results =
            execute_protocol_large::<ResiduePoly128, _, _>(num_parties, threshold, None, &mut task);

        let pk_ref = results[0].1.clone();

        for (role, pk, sk) in results {
            assert_eq!(pk, pk_ref);
            sk.write_to_file(format!(
                "{}/sk_p{}.der",
                params_basics_handles.get_prefix_path(),
                role.zero_based()
            ))
            .unwrap();
        }

        pk_ref
            .write_to_file(format!(
                "{}/pk.der",
                params_basics_handles.get_prefix_path()
            ))
            .unwrap();
    }

    fn run_switch_and_squash(prefix_path: String, num_parties: usize, threshold: usize) {
        let params = DKGParamsSnS::read_from_file(prefix_path + "/params.json").unwrap();
        let message = (params.get_message_modulus().0 - 1) as u8;
        let threshold_lwe_parameters = params.to_threshold_parameters();

        let sk_lwe =
            reconstruct_lwe_secret_key_from_file::<Z128, _>(num_parties, threshold, &params);
        let (sk_glwe, big_sk_glwe) = reconstruct_glwe_secret_key_from_file::<Z128>(
            num_parties,
            threshold,
            DKGParams::WithSnS(params),
        );
        let sk_large = LargeClientKey::new(
            threshold_lwe_parameters.output_cipher_parameters,
            big_sk_glwe.clone().unwrap().into_lwe_secret_key(),
        );
        let pk = PubKeySet::read_from_file(format!("{}/pk.der", params.get_prefix_path())).unwrap();

        let ddec_pk = to_hl_public_key(&threshold_lwe_parameters, pk.lwe_public_key);
        let ddec_sk = to_hl_client_key(&threshold_lwe_parameters, sk_lwe.clone(), sk_glwe);

        let bk_sns = pk.bk_sns.unwrap();
        let mut fourier_bsk = Fourier128LweBootstrapKey::new(
            bk_sns.input_lwe_dimension(),
            bk_sns.glwe_size(),
            bk_sns.polynomial_size(),
            bk_sns.decomposition_base_log(),
            bk_sns.decomposition_level_count(),
        );

        convert_standard_lwe_bootstrap_key_to_fourier_128(&bk_sns, &mut fourier_bsk);

        let ck = crate::lwe::ConversionKey {
            fbsk_out: fourier_bsk,
            threshold_lwe_parameters,
        };

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

        par_generate_lwe_bootstrap_key(
            &sk_lwe_lifted_128,
            &big_sk_glwe.unwrap(),
            &mut bsk_out,
            StandardDev(3.15283466779972e-16),
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

        let ck_bis = ConversionKey::new(threshold_lwe_parameters, fbsk_out);
        let small_ct = FheUint64::encrypt(message, &ddec_pk);
        let (raw_ct, _id) = small_ct.clone().into_raw_parts();
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
    fn run_tfhe_computation_shortint<Params: DKGParamsBasics>(
        prefix_path: String,
        num_parties: usize,
        threshold: usize,
    ) {
        let params = Params::read_from_file(prefix_path + "/params.json")
            .unwrap()
            .to_dkg_params();
        let (shortint_sk, pk) = retrieve_keys_from_files(params, num_parties, threshold);
        let shortint_pk = pk.into_tfhe_shortint_keys(params);
        for _ in 0..100 {
            try_tfhe_shortint_computation(&shortint_sk, &shortint_pk);
        }
    }

    ///Runs both shortint and fheuint computation
    fn run_tfhe_computation_fheuint<Params: DKGParamsBasics>(
        prefix_path: String,
        num_parties: usize,
        threshold: usize,
    ) {
        let params = Params::read_from_file(prefix_path + "/params.json")
            .unwrap()
            .to_dkg_params();
        let (shortint_sk, pk) = retrieve_keys_from_files(params, num_parties, threshold);
        let shortint_pk = pk.clone().into_tfhe_shortint_keys(params);
        for _ in 0..100 {
            try_tfhe_shortint_computation(&shortint_sk, &shortint_pk);
        }

        let tfhe_sk = tfhe::ClientKey::from_raw_parts(shortint_sk.into(), None);
        let tfhe_pk = pk.into_tfhe_hl_api_keys(params);

        try_tfhe_fheuint_computation(&tfhe_sk, &tfhe_pk);
    }

    ///Read files created by [`run_dkg_and_save`] and reconstruct the secret keys
    ///from the parties' shares
    fn retrieve_keys_from_files(
        params: DKGParams,
        num_parties: usize,
        threshold: usize,
    ) -> (tfhe::shortint::ClientKey, PubKeySet) {
        let params_tfhe_rs = params
            .get_params_basics_handle()
            .to_classic_pbs_parameters();

        let lwe_secret_key = reconstruct_lwe_secret_key_from_file::<Z128, _>(
            num_parties,
            threshold,
            params.get_params_basics_handle(),
        );
        let (glwe_secret_key, _) =
            reconstruct_glwe_secret_key_from_file::<Z128>(num_parties, threshold, params);
        let pk = PubKeySet::read_from_file(format!(
            "{}/pk.der",
            params.get_params_basics_handle().get_prefix_path()
        ))
        .unwrap();

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

    //TFHE-rs doctest for fheuint
    fn try_tfhe_fheuint_computation(client_key: &tfhe::ClientKey, server_keys: &tfhe::ServerKey) {
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

        // On the server side:
        set_server_key(server_keys.clone());

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
}
