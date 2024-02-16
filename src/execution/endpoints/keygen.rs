use std::{num::Wrapping, sync::Arc};

use aes_prng::AesRng;
use concrete_csprng::generators::SoftwareRandomGenerator;
use itertools::Itertools;
use ndarray::Array1;
use num_integer::div_ceil;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use tfhe::core_crypto::prelude::Numeric;
use tfhe::{
    core_crypto::{
        algorithms::par_convert_standard_lwe_bootstrap_key_to_fourier,
        entities::{FourierLweBootstrapKey, LweBootstrapKey, LweCompactPublicKey, LweKeyswitchKey},
    },
    shortint::{
        ciphertext::{MaxDegree, MaxNoiseLevel},
        parameters::{
            DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension,
            PolynomialSize, StandardDev,
        },
        server_key::ShortintBootstrappingKey,
        CarryModulus, CiphertextModulus, ClassicPBSParameters, EncryptionKeyChoice, MessageModulus,
    },
};
use tokio::{task::JoinSet, time::timeout_at};

use crate::{
    algebra::{
        residue_poly::ResiduePoly,
        residue_poly::ResiduePoly128,
        structure_traits::{BaseRing, Ring},
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        constants::INPUT_PARTY_ID,
        online::{
            gen_bits::BitGenEven,
            preprocessing::Preprocessing,
            secret_distributions::{RealSecretDistributions, SecretDistributions},
            triple::open_list,
        },
        runtime::{
            party::Role,
            session::{
                BaseSession, BaseSessionHandles, ParameterHandles, SessionParameters, SetupMode,
                SmallSession, SmallSessionStruct, ToBaseSession,
            },
        },
        sharing::input::robust_input,
        small_execution::{agree_random::DummyAgreeRandom, prss::PRSSSetup},
        tfhe_internals::{
            glwe_key::GlweSecretKeyShare,
            lwe_bootstrap_key_generation::allocate_and_generate_lwe_bootstrap_key,
            lwe_key::{allocate_and_generate_new_lwe_compact_public_key, LweSecretKeyShare},
            lwe_keyswitch_key_generation::allocate_and_generate_new_lwe_keyswitch_key,
            randomness::{
                EncryptionType, MPCEncryptionRandomGenerator, MPCMaskRandomGenerator,
                MPCNoiseRandomGenerator,
            },
        },
    },
    file_handling::{read_as_json, read_element, write_as_json, write_element},
    lwe::{
        gen_key_set, CiphertextParameters, KeySet, PubConKeyPair, SecretKeyShare,
        ThresholdLWEParameters,
    },
    networking::value::NetworkValue,
};

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
        let max_value = params.message_modulus.0 * params.carry_modulus.0 - 1;

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

        let max_noise_level =
            MaxNoiseLevel::from_msg_carry_modulus(params.message_modulus, params.carry_modulus);

        let pk_bk = ShortintBootstrappingKey::Classic(fourier_bsk);

        let params_tfhe = params.to_classic_pbs_parameters();

        tfhe::shortint::ServerKey::from_raw_parts(
            self.ksk,
            pk_bk,
            params.message_modulus,
            params.carry_modulus,
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

//Todo, may want to put this type inside the correct file
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct TUniformBound(pub usize);

#[derive(Clone, Copy, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct DKGParams {
    ///Security parameter (related to the size of the XOF seed)
    pub sec: u64,
    ///The lwe dimension (length of the secret key)
    pub l: LweDimension,
    ///The degree of the GLWE cyclotomic polynomial
    pub N: PolynomialSize,
    ///The glwe dimension (length of the secret key)
    pub w: GlweDimension,
    ///Log of the bound for the TUniform distribution in lwe ciphertexts
    pub b_l: TUniformBound,
    ///Log of the bound for the TUniform distribution in glwe ciphertexts
    pub b_wn: TUniformBound,
    ///Log of the base for the decomposition of the key-switch-key
    pub beta_ksk: DecompositionBaseLog,
    ///Number of levels for the decomposition of the key-switch-key
    pub nu_ksk: DecompositionLevelCount,
    ///Log of the base for the decomposition of the bootstrapping key
    pub beta_bk: DecompositionBaseLog,
    ///Number of levels for the decomposition of bootstrapping key
    pub nu_bk: DecompositionLevelCount,
    ///**Switch-and-Squah Output domain** The degree of the GLWE cyclotomic polynomial
    pub o_N: Option<PolynomialSize>,
    ///**Switch-and-Squah Output domain** The glwe dimension (length of the secret key)
    pub o_w: Option<GlweDimension>,
    ///**Switch-and-Squah Output domain** Log of the base for the decomposition of the SnS-bootstrapping key
    pub o_beta_bk: Option<DecompositionBaseLog>,
    ///**Switch-and-Squah Output domain** Number of levels for the decomposition of the SnS-bootstrapping key
    pub o_nu_bk: Option<DecompositionLevelCount>,
    ///**Switch-and-Squah Output domain** Log of the bound for the TUniform distribution in glwe ciphertexts
    pub o_b_wn: Option<TUniformBound>,
    ///In-extenso (**NOT** log) message modulus
    pub message_modulus: MessageModulus,
    ///In-extenso (**NOT** log) carry modulus
    pub carry_modulus: CarryModulus,
    ///States whether we want compressed ciphertexts
    pub flag: bool,
    ///States whether we want to generate the Switch-and-Squash key material
    pub o_flag: bool,
}

impl DKGParams {
    pub fn write_to_file(&self, path: String) -> anyhow::Result<()> {
        write_as_json(path, self)
    }

    pub fn read_from_file(path: String) -> anyhow::Result<Self> {
        read_as_json(path)
    }

    pub fn to_classic_pbs_parameters(&self) -> ClassicPBSParameters {
        ClassicPBSParameters {
            lwe_dimension: self.l,
            glwe_dimension: self.w,
            polynomial_size: self.N,
            //TODO(issue#350): Once TFHE-RS supports TUNIFORM noise modif this!
            lwe_modular_std_dev: StandardDev(1e-37),
            //TODO(issue#350): Once TFHE-RS supports TUNIFORM noise modif this!
            glwe_modular_std_dev: StandardDev(1e-37),
            pbs_base_log: self.beta_bk,
            pbs_level: self.nu_bk,
            ks_base_log: self.beta_ksk,
            ks_level: self.nu_ksk,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            ciphertext_modulus: CiphertextModulus::new_native(),
            encryption_key_choice: EncryptionKeyChoice::Small,
        }
    }

    pub fn get_prefix_path(&self) -> String {
        format!(
            "temp/dkg/MSGMOD_{}_CARRYMOD_{}_SNS_{}",
            self.message_modulus.0, self.carry_modulus.0, self.o_flag
        )
    }
}

impl DKGParams {
    pub fn lwe_dimension(&self) -> LweDimension {
        self.l
    }

    pub fn glwe_dimension(&self) -> GlweDimension {
        self.w
    }

    pub fn lwe_tuniform_bound(&self) -> TUniformBound {
        self.b_l
    }

    pub fn glwe_tuniform_bound(&self) -> TUniformBound {
        self.b_wn
    }

    pub fn glwe_tuniform_bound_sns(&self) -> Option<TUniformBound> {
        self.o_b_wn
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.N
    }

    pub fn polynomial_size_sns(&self) -> Option<PolynomialSize> {
        self.o_N
    }

    pub fn glwe_sk_num_bits(&self) -> usize {
        self.N.0 * self.w.0
    }

    pub fn glwe_sk_num_bits_sns(&self) -> Option<usize> {
        match (self.o_N, self.o_w) {
            (Some(psize), Some(glwedim)) => Some(psize.0 * glwedim.0),
            _ => None,
        }
    }

    pub fn decomposition_base_log_ksk(&self) -> DecompositionBaseLog {
        self.beta_ksk
    }

    pub fn decomposition_base_log_bk(&self) -> DecompositionBaseLog {
        self.beta_bk
    }

    pub fn decomposition_base_log_bk_sns(&self) -> Option<DecompositionBaseLog> {
        self.o_beta_bk
    }

    pub fn decomposition_level_count_ksk(&self) -> DecompositionLevelCount {
        self.nu_ksk
    }

    pub fn decomposition_level_count_bk(&self) -> DecompositionLevelCount {
        self.nu_bk
    }

    pub fn decomposition_level_count_bk_sns(&self) -> Option<DecompositionLevelCount> {
        self.o_nu_bk
    }

    pub fn num_needed_noise_ksk(&self) -> usize {
        self.w.0 * self.N.0 * self.nu_ksk.0
    }

    pub fn num_needed_noise_bk(&self) -> usize {
        self.l.0 * (self.w.0 + 1) * self.nu_bk.0 * self.N.0
    }

    #[allow(non_snake_case)]
    pub fn num_needed_noise_bk_sns(&self) -> Option<usize> {
        match (self.o_N, self.o_nu_bk, self.o_w) {
            (Some(o_N), Some(o_nu_bk), Some(o_w)) => {
                Some(self.l.0 * (o_w.0 + 1) * o_nu_bk.0 * o_N.0)
            }
            _ => None,
        }
    }

    pub fn sns_required(&self) -> bool {
        self.o_flag
    }

    pub fn to_threshold_parameters(&self) -> ThresholdLWEParameters {
        let input_ciphertext_parameters = CiphertextParameters {
            lwe_dimension: self.lwe_dimension(),
            glwe_dimension: self.glwe_dimension(),
            polynomial_size: self.polynomial_size(),
            //TODO(issue#350): Once TFHE-RS supports TUNIFORM noise modif this!
            lwe_modular_std_dev: StandardDev(1e-37),
            //TODO(issue#350): Once TFHE-RS supports TUNIFORM noise modif this!
            glwe_modular_std_dev: StandardDev(1e-37),
            pbs_base_log: self.decomposition_base_log_bk(),
            pbs_level: self.decomposition_level_count_bk(),
            ks_base_log: self.decomposition_base_log_ksk(),
            ks_level: self.decomposition_level_count_ksk(),
            message_modulus_log: self.message_modulus,
            usable_message_modulus_log: self.message_modulus, //TODO: NEED TO MAP THESE PARAM STRUCTURE CORRECTLY WITH TFHERS
            ciphertext_modulus: CiphertextModulus::new_native(),
        };
        let output_ciphertext_parameters = CiphertextParameters {
            lwe_dimension: self.lwe_dimension(),
            glwe_dimension: self.o_w.unwrap(),
            polynomial_size: self.polynomial_size_sns().unwrap(),
            //TODO(issue#350): Once TFHE-RS supports TUNIFORM noise modif this!
            lwe_modular_std_dev: StandardDev(1e-37),
            //TODO(issue#350): Once TFHE-RS supports TUNIFORM noise modif this!
            glwe_modular_std_dev: StandardDev(1e-37),
            pbs_base_log: self.decomposition_base_log_bk_sns().unwrap(),
            pbs_level: self.decomposition_level_count_bk_sns().unwrap(),
            ks_base_log: self.decomposition_base_log_ksk(),
            ks_level: self.decomposition_level_count_ksk(),
            message_modulus_log: self.message_modulus,
            usable_message_modulus_log: self.message_modulus, //TODO: NEED TO MAP THESE PARAM STRUCTURE CORRECTLY WITH TFHERS
            ciphertext_modulus: tfhe::core_crypto::commons::ciphertext_modulus::CiphertextModulus::<
                u128,
            >::new_native(),
        };

        ThresholdLWEParameters {
            input_cipher_parameters: input_ciphertext_parameters,
            output_cipher_parameters: output_ciphertext_parameters,
        }
    }
}
///Runs the distributed key generation protocol.
///
/// Expects:
/// - session: the session that holds necessary information for networking
/// - preprocessing: preprocessing data with enough triples and randomness available
/// - params: parameters for the Distributed Key Generation
///
/// Outputs:
/// - A PubKeySet composed of the public key, the KSK, the BK and the BK_sns if required
/// - a PriveateKeySet composed of shares of the lwe and glwe private keys
///
///If the o_flag is set in the params, then the sharing domain must be ResiduePoly128 but the domain of
///all non-overlined key material is still Z64.
/// Note that there is some redundancy of information because we also explicitly ask the BaseRing as trait parameter
pub async fn distributed_keygen<
    Z: BaseRing,
    R: Rng + CryptoRng + Sync,
    S: BaseSessionHandles<R>,
    P: Preprocessing<ResiduePoly<Z>> + Send,
    BitGen: BitGenEven,
>(
    session: &mut S,
    preprocessing: &mut P,
    params: DKGParams,
) -> anyhow::Result<(PubKeySet, PrivateKeySet<Z>)> {
    let my_role = session.my_role()?;
    //Sample the random but public seed and cast it into TFHE-rs seed type
    //NOTE: next_random_vec samples uniformly from Z[X]/F(X)
    //(as required by the ideal functional Fig.94).
    let num_seeds = div_ceil(params.sec, ResiduePoly::<Z>::BIT_LENGTH as u64) as usize;
    let shared_seeds = preprocessing.next_random_vec(num_seeds)?;
    let seeds = open_list(&shared_seeds, session).await?;
    //Turn the random element in Z[X]/F(X) to random params.sec bits
    let seed = seeds
        .iter()
        .flat_map(ResiduePoly::<Z>::to_byte_vec)
        .take((params.sec as usize) >> 3)
        .fold(0_u128, |acc, x| (acc << 8) + (x as u128));

    //Init the shared LWE secret key
    tracing::info!("(Party {my_role}) Generating LWE Secret key...Start");
    let lwe_secret_key_share = LweSecretKeyShare {
        data: BitGen::gen_bits_even(params.lwe_dimension().0, preprocessing, session).await?,
    };
    tracing::info!("(Party {my_role}) Generating LWE Secret key...Done");
    //Generate corresponding public key
    //First generate the needed noise
    tracing::info!("(Party {my_role}) Generating corresponding public key...Start");
    let vec_tuniform_noise = RealSecretDistributions::t_uniform::<_, _, _, _, BitGen>(
        params.lwe_dimension().0,
        params.lwe_tuniform_bound().0,
        preprocessing,
        session,
    )
    .await?
    .iter()
    .map(|share| share.value())
    .collect_vec();

    //Init the XOF with the seed computed above
    //and fill the noise generator with noise generated above
    let mut mpc_encryption_rng = MPCEncryptionRandomGenerator {
        mask: MPCMaskRandomGenerator::<SoftwareRandomGenerator>::new_from_seed(seed),
        noise: MPCNoiseRandomGenerator {
            vec: vec_tuniform_noise,
        },
    };

    //Then actually generate the public key
    let lwe_public_key_shared = allocate_and_generate_new_lwe_compact_public_key(
        &lwe_secret_key_share,
        &mut mpc_encryption_rng,
    )?;

    //Open the public key and cast it to TFHE-RS type
    let lwe_public_key = lwe_public_key_shared.open_to_tfhers_type(session).await?;

    tracing::info!("(Party {my_role}) Generating corresponding public key...Done");

    //Generate the GLWE secret key
    tracing::info!("(Party {my_role}) Generating GLWE secret key...Start");
    let glwe_secret_key_share = GlweSecretKeyShare {
        data: BitGen::gen_bits_even(params.glwe_sk_num_bits(), preprocessing, session).await?,
        polynomial_size: params.polynomial_size(),
    };

    let glwe_sk_share_as_lwe = glwe_secret_key_share.clone().into_lwe_secret_key();

    tracing::info!("(Party {my_role}) Generating GLWE secret key...Done");

    //Generate the KSK
    //First sample the noise
    tracing::info!("(Party {my_role}) Generating KSK...Start");
    let vec_tuniform_noise = RealSecretDistributions::t_uniform::<_, _, _, _, BitGen>(
        params.num_needed_noise_ksk(),
        params.lwe_tuniform_bound().0,
        preprocessing,
        session,
    )
    .await?
    .iter()
    .map(|share| share.value())
    .collect_vec();

    mpc_encryption_rng.fill_noise(vec_tuniform_noise);

    //Then compute the KSK
    let ksk_share = allocate_and_generate_new_lwe_keyswitch_key(
        &glwe_sk_share_as_lwe,
        &lwe_secret_key_share,
        params.decomposition_base_log_ksk(),
        params.decomposition_level_count_ksk(),
        &mut mpc_encryption_rng,
    )?;

    //Open the KSK and cast it to TFHE-RS type
    let ksk = ksk_share.open_to_tfhers_type(session).await?;

    tracing::info!("(Party {my_role}) Generating KSK...Done");

    //Compute the bootstrapping keys
    //First sample the noise
    let vec_tuniform_noise = RealSecretDistributions::t_uniform::<_, _, _, _, BitGen>(
        params.num_needed_noise_bk(),
        params.glwe_tuniform_bound().0,
        preprocessing,
        session,
    )
    .await?
    .iter()
    .map(|share| share.value())
    .collect_vec();

    mpc_encryption_rng.fill_noise(vec_tuniform_noise);

    tracing::info!("(Party {my_role}) Generating BK...Start");
    let bk_share = allocate_and_generate_lwe_bootstrap_key(
        &lwe_secret_key_share,
        &glwe_secret_key_share,
        params.decomposition_base_log_bk(),
        params.decomposition_level_count_bk(),
        &mut mpc_encryption_rng,
        EncryptionType::Bits64,
        session,
        preprocessing,
    )
    .await?;

    tracing::info!("(Party {my_role}) Generating BK...Done");
    tracing::info!("(Party {my_role}) Opening BK...Start");
    //Open the bk and cast it to TFHE-rs type
    let bk = bk_share.open_to_tfhers_type::<u64, _, _>(session).await?;
    tracing::info!("(Party {my_role}) Opening BK...Done");

    //If needed, compute the SnS BK
    let (glwe_secret_key_share_sns, bk_sns) = if params.sns_required() {
        tracing::info!("(Party {my_role}) Generating SnS GLWE...Start");
        //compute the SnS GLWE key
        let glwe_secret_key_share_sns = GlweSecretKeyShare {
            data: BitGen::gen_bits_even(
                params
                    .glwe_sk_num_bits_sns()
                    .expect("Need SnS parameters to compute SnS keys"),
                preprocessing,
                session,
            )
            .await?,
            polynomial_size: params
                .polynomial_size_sns()
                .expect("Need SnS parameters to compute SnS keys"),
        };

        tracing::info!("(Party {my_role}) Generating SnS GLWE...Done");

        //First sample the noise
        tracing::info!("(Party {my_role}) Generating SnS BK...Start");
        let vec_tuniform_noise = RealSecretDistributions::t_uniform::<_, _, _, _, BitGen>(
            params
                .num_needed_noise_bk_sns()
                .expect("Need SnS parameters to compute SnS BK"),
            params
                .glwe_tuniform_bound_sns()
                .expect("Need SnS parameters to compute SnS BK")
                .0,
            preprocessing,
            session,
        )
        .await?
        .iter()
        .map(|share| share.value())
        .collect_vec();

        mpc_encryption_rng.fill_noise(vec_tuniform_noise);

        let bk_sns_share = allocate_and_generate_lwe_bootstrap_key(
            &lwe_secret_key_share,
            &glwe_secret_key_share_sns,
            params
                .decomposition_base_log_bk_sns()
                .expect("Need SnS parameters to compute SnS BK"),
            params
                .decomposition_level_count_bk_sns()
                .expect("Need SnS parameters to compute SnS BK"),
            &mut mpc_encryption_rng,
            EncryptionType::Bits128,
            session,
            preprocessing,
        )
        .await?;

        tracing::info!("(Party {my_role}) Generating SnS BK...Done");
        tracing::info!("(Party {my_role}) Opening SnS BK...Start");
        let res = (
            Some(glwe_secret_key_share_sns),
            Some(
                bk_sns_share
                    .open_to_tfhers_type::<u128, _, _>(session)
                    .await?,
            ),
        );

        tracing::info!("(Party {my_role}) Opening SnS BK...Done");
        res
    } else {
        (None, None)
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
        .map(|s| s.clone().sk.lwe_secret_key_64.into_container())
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
        .map(|s| s.clone().sk.lwe_secret_key_128.into_container())
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

    let pubcon = keyset.map(|s| PubConKeyPair { pk: s.pk, ck: s.ck });
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
        prelude::{FheDecrypt, FheMin, FheTryEncrypt},
        set_server_key,
        shortint::parameters::{CoreCiphertextModulus, StandardDev},
        FheUint32, FheUint8,
    };

    use crate::{
        algebra::{base_ring::Z128, residue_poly::ResiduePoly128},
        execution::{
            online::{gen_bits::FakeBitGenEven, preprocessing::DummyPreprocessing},
            runtime::session::{LargeSession, ParameterHandles},
            tfhe_internals::parameters::{PARAMS_P32_SMALL_NO_SNS, PARAMS_P8_SMALL_NO_SNS},
        },
        tests::helper::tests_and_benches::execute_protocol_large,
    };
    use crate::{
        execution::tfhe_internals::{
            parameters::{PARAMS_P32_REAL_WITH_SNS, PARAMS_P8_REAL_WITH_SNS},
            utils::tests::reconstruct_lwe_secret_key_from_file,
        },
        lwe::to_large_ciphertext_block,
    };
    use crate::{
        execution::{
            random::{get_rng, seed_from_rng},
            tfhe_internals::{
                parameters::PARAMS_TEST_BK_SNS, utils::tests::reconstruct_glwe_secret_key_from_file,
            },
        },
        lwe::BootstrappingKey,
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
        if !std::path::Path::new(&params.get_prefix_path()).exists() {
            _ = fs::create_dir(params.get_prefix_path());
            run_dkg_and_save(params);
        }
        let expected_size = TestKeySize {
            public_key_material_size: 117506209,
            secret_key_material_size: 417817,
        };

        assert_key_size(params, expected_size);
        run_tfhe_computation_shortint(params);
        run_tfhe_computation_fheuint(params);
    }

    ///Tests related to [`PARAMS_P8_SMALL_NO_SNS`]
    #[test]
    #[ignore]
    fn keygen_params8_small_no_sns() {
        let params = PARAMS_P8_SMALL_NO_SNS;

        if !std::path::Path::new(&params.get_prefix_path()).exists() {
            _ = fs::create_dir(params.get_prefix_path());
            run_dkg_and_save(params);
        }

        let expected_size = TestKeySize {
            public_key_material_size: 10498209,
            secret_key_material_size: 139289,
        };

        assert_key_size(params, expected_size);
        //This parameter set isnt big enough to run the fheuint tests
        run_tfhe_computation_shortint(params);
    }

    ///Tests realted to [`PARAMS_TEST_BK_SNS`]
    #[test]
    #[ignore]
    fn keygen_params_bk_sns() {
        let params = PARAMS_TEST_BK_SNS;

        if !std::path::Path::new(&params.get_prefix_path()).exists() {
            _ = fs::create_dir(params.get_prefix_path());
            run_dkg_and_save(params);
        }

        let expected_size = TestKeySize {
            public_key_material_size: 2493153,
            secret_key_material_size: 82729,
        };

        assert_key_size(params, expected_size);
        run_switch_and_squash(params);
    }

    ///Tests realted to [`PARAMS_P32_REAL_WITH_SNS`]
    #[test]
    #[ignore]
    fn keygen_params32_real_with_sns() {
        let params = PARAMS_P32_REAL_WITH_SNS;

        if !std::path::Path::new(&params.get_prefix_path()).exists() {
            _ = fs::create_dir(params.get_prefix_path());
            run_dkg_and_save(params);
        }

        let expected_size = TestKeySize {
            public_key_material_size: 1023475937,
            secret_key_material_size: 974889,
        };

        assert_key_size(params, expected_size);

        run_switch_and_squash(params);

        run_tfhe_computation_shortint(PARAMS_P32_REAL_WITH_SNS);
        run_tfhe_computation_fheuint(PARAMS_P32_REAL_WITH_SNS);
    }

    ///Tests realted to [`PARAMS_P8_REAL_WITH_SNS`]
    #[test]
    #[ignore]
    fn keygen_params8_real_with_sns() {
        let params = PARAMS_P8_REAL_WITH_SNS;

        if !std::path::Path::new(&params.get_prefix_path()).exists() {
            _ = fs::create_dir(params.get_prefix_path());
            run_dkg_and_save(params);
        }

        let expected_size = TestKeySize {
            public_key_material_size: 1350607073,
            secret_key_material_size: 905257,
        };

        assert_key_size(params, expected_size);

        run_switch_and_squash(params);

        //This parameter set isnt big enough to run the fheuint tests
        run_tfhe_computation_shortint(PARAMS_P8_REAL_WITH_SNS);
    }

    fn assert_key_size(params: DKGParams, expected_size: TestKeySize) {
        let parties = 5;
        let pk_size = fs::metadata(format!("{}/pk.der", params.get_prefix_path()))
            .unwrap()
            .len();
        assert_eq!(pk_size, expected_size.public_key_material_size);
        for i in 0..parties {
            let sk_size = fs::metadata(format!("{}/sk_p{i}.der", params.get_prefix_path()))
                .unwrap()
                .len();
            assert_eq!(sk_size, expected_size.secret_key_material_size);
        }
    }

    ///Runs the DKG protocol with [`DummyPreprocessing`]
    /// and [`FakeBitGenEven`]. Saves the results to file.
    fn run_dkg_and_save(params: DKGParams) {
        params
            .write_to_file(format!("{}/params.json", params.get_prefix_path()))
            .unwrap();

        let mut task = |mut session: LargeSession| async move {
            let my_role = session.my_role().unwrap();
            let mut large_preproc = DummyPreprocessing::new(0_u64, session.clone());

            let (pk, sk) = distributed_keygen::<Z128, _, _, _, FakeBitGenEven>(
                &mut session,
                &mut large_preproc,
                params,
            )
            .await
            .unwrap();

            (my_role, pk, sk)
        };

        let parties = 5;
        let threshold = 1;
        let results =
            execute_protocol_large::<ResiduePoly128, _, _>(parties, threshold, None, &mut task);

        let pk_ref = results[0].1.clone();

        for (role, pk, sk) in results {
            assert_eq!(pk, pk_ref);
            sk.write_to_file(format!(
                "{}/sk_p{}.der",
                params.get_prefix_path(),
                role.zero_based()
            ))
            .unwrap();
        }

        pk_ref
            .write_to_file(format!("{}/pk.der", params.get_prefix_path()))
            .unwrap();
    }

    ///Tests switch and squash decryption
    fn run_switch_and_squash(params: DKGParams) {
        let parties = 5;
        let threshold = 1;
        let message = (params.message_modulus.0 - 1) as u64;
        let threshold_lwe_parameters = params.to_threshold_parameters();

        let sk_lwe = reconstruct_lwe_secret_key_from_file::<Z128>(parties, threshold, params);
        let (sk_glwe, big_sk_glwe) =
            reconstruct_glwe_secret_key_from_file::<Z128>(parties, threshold, params);
        let pk = PubKeySet::read_from_file(format!("{}/pk.der", params.get_prefix_path())).unwrap();

        let ddec_pk = crate::lwe::PublicKey {
            public_key: pk.lwe_public_key,
            threshold_lwe_parameters,
        };

        let bk_sns = pk.bk_sns.unwrap();
        let mut fourier_bsk = Fourier128LweBootstrapKey::new(
            bk_sns.input_lwe_dimension(),
            bk_sns.glwe_size(),
            bk_sns.polynomial_size(),
            bk_sns.decomposition_base_log(),
            bk_sns.decomposition_level_count(),
        );

        convert_standard_lwe_bootstrap_key_to_fourier_128(&bk_sns, &mut fourier_bsk);

        let ck = crate::lwe::BootstrappingKey {
            fbsk_out: fourier_bsk,
            threshold_lwe_parameters,
        };

        //Try and generate the bk_sns directly from the private keys
        let sk_lwe_lifted_128 = LweSecretKey::from_container(
            sk_lwe
                .clone()
                .into_container()
                .iter()
                .map(|bit| *bit as u128)
                .collect_vec(),
        );

        let mut bsk_out = LweBootstrapKey::new(
            0_u128,
            params.o_w.unwrap().to_glwe_size(),
            params.o_N.unwrap(),
            params.o_beta_bk.unwrap(),
            params.o_nu_bk.unwrap(),
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
            &big_sk_glwe.clone().unwrap(),
            &mut bsk_out,
            StandardDev(3.15283466779972e-16),
            &mut enc_rng,
        );
        let mut fbsk_out = Fourier128LweBootstrapKey::new(
            params.lwe_dimension(),
            params.o_w.unwrap().to_glwe_size(),
            params.o_N.unwrap(),
            params.o_beta_bk.unwrap(),
            params.o_nu_bk.unwrap(),
        );

        convert_standard_lwe_bootstrap_key_to_fourier_128(&bsk_out, &mut fbsk_out);
        drop(bsk_out);

        let ck_bis = BootstrappingKey::new(threshold_lwe_parameters, fbsk_out);

        let small_ct = ddec_pk.encrypt_block(&mut get_rng(), message);
        let large_ct = to_large_ciphertext_block(&ck, &small_ct);
        let large_ct_bis = to_large_ciphertext_block(&ck_bis, &small_ct);

        let sk = crate::lwe::SecretKey {
            lwe_secret_key_64: sk_lwe,
            glwe_secret_key_64: sk_glwe,
            lwe_secret_key_128: big_sk_glwe.unwrap().into_lwe_secret_key(),
            threshold_lwe_parameters,
        };
        let res_small = sk.decrypt_block_64(&small_ct);
        let res_large = sk.decrypt_block_128(&large_ct);
        let res_large_bis = sk.decrypt_block_128(&large_ct_bis);

        assert_eq!(message as u128, res_small.0);
        assert_eq!(message as u128, res_large_bis.0);
        assert_eq!(message as u128, res_large.0);
    }

    ///Runs only the shortint computation
    fn run_tfhe_computation_shortint(params: DKGParams) {
        let (shortint_sk, pk) = retrieve_keys_from_files(params);
        let shortint_pk = pk.into_tfhe_shortint_keys(params);
        for _ in 0..100 {
            try_tfhe_shortint_computation(&shortint_sk, &shortint_pk);
        }
    }

    ///Runs both shortint and fheuint computation
    fn run_tfhe_computation_fheuint(params: DKGParams) {
        let (shortint_sk, pk) = retrieve_keys_from_files(params);
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
    fn retrieve_keys_from_files(params: DKGParams) -> (tfhe::shortint::ClientKey, PubKeySet) {
        let parties = 5;
        let threshold = 1;
        let params_tfhe_rs = params.to_classic_pbs_parameters();

        let lwe_secret_key =
            reconstruct_lwe_secret_key_from_file::<Z128>(parties, threshold, params);
        let (glwe_secret_key, _) =
            reconstruct_glwe_secret_key_from_file::<Z128>(parties, threshold, params);
        let pk = PubKeySet::read_from_file(format!("{}/pk.der", params.get_prefix_path())).unwrap();

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
