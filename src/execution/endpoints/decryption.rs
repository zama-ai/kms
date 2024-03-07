#[cfg(any(test, feature = "testing"))]
use crate::algebra::structure_traits::Ring;
#[cfg(any(test, feature = "testing"))]
use crate::computation::SessionId;
use crate::execution::large_execution::offline::LargePreprocessing;
use crate::execution::online::preprocessing::create_memory_factory;
use crate::execution::online::preprocessing::BitDecPreprocessing;
use crate::execution::online::preprocessing::NoiseFloodPreprocessing;
use crate::execution::runtime::party::Identity;
use crate::execution::runtime::session::ToBaseSession;
use crate::execution::runtime::session::{DecryptionMode, SmallSession64};
#[cfg(any(test, feature = "testing"))]
use crate::execution::sharing::shamir::{HenselLiftInverse, RingEmbed};
use crate::execution::sharing::share::Share;
use crate::execution::small_execution::agree_random::RealAgreeRandom;
use crate::execution::small_execution::offline::SmallPreprocessing;
use crate::execution::{
    online::bit_manipulation::{bit_dec_batch, BatchedBits},
    sharing::open::robust_opens_to_all,
};
#[cfg(any(test, feature = "testing"))]
use crate::execution::{
    runtime::{
        party::RoleAssignment,
        session::{NetworkingImpl, SessionParameters},
        test_runtime::DistributedTestRuntime,
    },
    small_execution::prss::PRSSSetup,
};
use crate::lwe::combine128;
use crate::lwe::ConversionKey;
use crate::{
    algebra::residue_poly::ResiduePoly, execution::config::BatchParams, lwe::ThresholdLWEParameters,
};
use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        residue_poly::ResiduePoly128,
        residue_poly::ResiduePoly64,
        structure_traits::Zero,
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        constants::{LOG_BD, STATSEC},
        large_execution::offline::{RealLargePreprocessing, TrueDoubleSharing, TrueSingleSharing},
        runtime::session::{BaseSessionHandles, LargeSession, SmallSession},
    },
    lwe::{
        from_expanded_msg, Ciphertext128, Ciphertext128Block, Ciphertext64, Ciphertext64Block,
        SecretKeyShare,
    },
};
#[cfg(any(test, feature = "testing"))]
use aes_prng::AesRng;
use async_trait::async_trait;
use enum_dispatch::enum_dispatch;
#[cfg(any(test, feature = "testing"))]
use rand::SeedableRng;
use rand::{CryptoRng, Rng};
use std::cell::RefCell;
use std::collections::HashMap;
use std::num::Wrapping;
#[cfg(any(test, feature = "testing"))]
use std::sync::Arc;
use std::time::{Duration, Instant};
use tfhe::integer::IntegerCiphertext;
#[cfg(any(test, feature = "testing"))]
use tokio::task::JoinSet;
use tracing::instrument;

#[enum_dispatch]
#[allow(clippy::large_enum_variant)]
enum ProtocolType {
    Small(Small),
    Large(Large),
}

pub struct Small {
    session: RefCell<SmallSession<ResiduePoly128>>,
}

impl Small {
    pub fn new(session: SmallSession<ResiduePoly128>) -> Self {
        Small {
            session: RefCell::new(session),
        }
    }
}

pub struct Large {
    session: RefCell<LargeSession>,
}

impl Large {
    pub fn new(session: LargeSession) -> Self {
        Large {
            session: RefCell::new(session),
        }
    }
}

#[async_trait]
#[enum_dispatch(ProtocolType)]
pub trait ProtocolDecryption {
    async fn init_prep_noiseflooding(
        &mut self,
        num_ctxt: usize,
    ) -> Box<dyn NoiseFloodPreprocessing>;
}

#[async_trait]
impl ProtocolDecryption for Small {
    async fn init_prep_noiseflooding(
        &mut self,
        num_ctxt: usize,
    ) -> Box<dyn NoiseFloodPreprocessing> {
        let session = self.session.get_mut();
        let mut sns_preprocessing = create_memory_factory().create_noise_flood_preprocessing();
        sns_preprocessing
            .fill_from_small_session(session, num_ctxt)
            .unwrap();
        sns_preprocessing
    }
}

#[async_trait]
impl ProtocolDecryption for Large {
    async fn init_prep_noiseflooding(
        &mut self,
        num_ctxt: usize,
    ) -> Box<dyn NoiseFloodPreprocessing> {
        let session = self.session.get_mut();
        let nb_preproc = 2 * num_ctxt * ((STATSEC + LOG_BD) as usize + 2);
        let batch_size = BatchParams {
            triples: nb_preproc,
            randoms: nb_preproc,
        };

        let mut large_preproc = RealLargePreprocessing::init(
            session,
            batch_size,
            TrueSingleSharing::default(),
            TrueDoubleSharing::default(),
        )
        .await
        .unwrap();

        let mut sns_preprocessing = create_memory_factory().create_noise_flood_preprocessing();
        sns_preprocessing
            .fill_from_base_preproc(&mut large_preproc, &mut session.to_base_session(), num_ctxt)
            .await
            .unwrap();
        sns_preprocessing
    }
}

/// Decrypts a ciphertext using the noise flooding `ProtocolType`
///
/// This is the entry point of the decryption protocol.
///
/// # Arguments
/// * `session` - The session object that contains the networking and the role of the party_keyshare
/// * `protocol` - The protocol object that contains the decryption `ProtocolType`. `ProtocolType` is the preparation of the noise flooding which holds the `Session` type
/// * `ck` - The conversion key
/// * `ct` - The ciphertext to be decrypted
/// * `secret_key_share` - The secret key share of the party_keyshare
/// * `_mode` - The decryption mode. This is used only for tracing purposes
/// * `_own_identity` - The identity of the party_keyshare. This is used only for tracing purposes
///
/// # Returns
/// * A tuple containing the results of the decryption and the time it took to execute the decryption
/// * The results of the decryption are a hashmap containing the session id and the decrypted plaintexts
/// * The time it took to execute the decryption
///
/// # Remarks
/// The decryption protocol is executed in the following steps:
/// 1. The ciphertext is converted to a large ciphertext block
/// 2. The protocol is initialized with the noise flooding
/// 3. The decryption is executed
/// 4. The results are returned
///
#[allow(clippy::too_many_arguments)]
#[instrument(skip(session, protocol, ck, ct, secret_key_share), fields(session_id = ?session.session_id(), own_identity = %_own_identity, mode = %_mode))]
pub async fn decrypt_using_noiseflooding<S, P, R>(
    session: &mut S,
    protocol: &mut P,
    ck: &ConversionKey,
    ct: Ciphertext64,
    secret_key_share: &SecretKeyShare,
    _mode: DecryptionMode,
    _own_identity: Identity,
) -> anyhow::Result<(HashMap<String, Z64>, Duration)>
where
    R: Rng + CryptoRng + Send,
    S: BaseSessionHandles<R>,
    P: ProtocolDecryption,
{
    let execution_start_timer = Instant::now();
    let ct_large = ck.to_large_ciphertext(&ct)?;
    let mut results = HashMap::with_capacity(1);
    let len = ct_large.len();
    let mut preparation = protocol.init_prep_noiseflooding(len).await;
    let preparation = preparation.as_mut();
    let outputs = run_decryption_noiseflood(session, preparation, secret_key_share, ct_large)
        .await
        .unwrap();

    tracing::info!("Result in session {:?} is ready", session.session_id());
    results.insert(format!("{}", session.session_id()), outputs);

    let execution_stop_timer = Instant::now();
    let elapsed_time = execution_stop_timer.duration_since(execution_start_timer);
    Ok((results, elapsed_time))
}

/// Partially decrypt a ciphertext using the noise flooding `ProtocolType`.
/// Partially here means that each party outputs a share of the decrypted result.
///
/// This is the entry point of the reencryption protocol.
///
/// # Arguments
/// * `session` - The session object that contains the networking and the role of the party_keyshare
/// * `protocol` - The protocol object that contains the decryption `ProtocolType`. `ProtocolType` is the preparation of the noise flooding which holds the `Session` type
/// * `ck` - The conversion key
/// * `ct` - The ciphertext to be decrypted
/// * `secret_key_share` - The secret key share of the party_keyshare
/// * `_mode` - The decryption mode. This is used only for tracing purposes
/// * `_own_identity` - The identity of the party_keyshare. This is used only for tracing purposes
///
/// # Returns
/// * A tuple containing the results of the partial decryption and the time it took to execute
/// * The results of the partial decryption are a hashmap containing the session id and the partially decrypted ciphertexts
/// * The time it took to execute the partial decryption
///
/// # Remarks
/// The partial decryption protocol is executed in the following steps:
/// 1. The ciphertext is converted to a large ciphertext block
/// 2. The protocol is initialized with the noise flooding
/// 3. The local decryption is executed
/// 4. The results are returned
///
#[allow(clippy::too_many_arguments)]
#[instrument(skip(session, protocol, ck, ct, secret_key_share), fields(session_id = ?session.session_id(), own_identity = %session.my_identity()?, mode = %_mode))]
pub async fn partial_decrypt_using_noiseflooding<S, P, R>(
    session: &mut S,
    protocol: &mut P,
    ck: &ConversionKey,
    ct: Ciphertext64,
    secret_key_share: &SecretKeyShare,
    _mode: DecryptionMode,
) -> anyhow::Result<(HashMap<String, Vec<ResiduePoly128>>, Duration)>
where
    R: Rng + CryptoRng + Send,
    S: BaseSessionHandles<R>,
    P: ProtocolDecryption,
{
    let execution_start_timer = Instant::now();
    let ct_large = ck.to_large_ciphertext(&ct)?;
    let mut results = HashMap::with_capacity(1);
    let len = ct_large.len();
    let mut preparation = protocol.init_prep_noiseflooding(len).await;
    let preparation = preparation.as_mut();
    let mut shared_masked_ptxts = Vec::with_capacity(ct_large.len());
    for current_ct_block in ct_large {
        let partial_decrypt = partial_decrypt128(secret_key_share, &current_ct_block)?;
        let res = partial_decrypt + preparation.next_mask()?;

        shared_masked_ptxts.push(res);
    }

    tracing::info!("Result in session {:?} is ready", session.session_id());
    results.insert(format!("{}", session.session_id()), shared_masked_ptxts);

    let execution_stop_timer = Instant::now();
    let elapsed_time = execution_stop_timer.duration_since(execution_start_timer);
    Ok((results, elapsed_time))
}

/// Takes as input plaintexts blocks m1, ..., mN revealed to all parties
/// which we call partial decryptions each of B bits
/// and uses tfhe block recomposer to get back the u64 plaintext.
fn combine_plaintext_blocks(
    bits_in_block: usize,
    partial_decrypted: Vec<Z128>,
) -> anyhow::Result<Z64> {
    let res = match combine128(bits_in_block as u32, partial_decrypted) {
        Ok(res) => res,
        Err(error) => {
            eprint!("Panicked in combining {error}");
            return Err(anyhow_error_and_log(format!(
                "Panicked in combining {error}"
            )));
        }
    };
    Ok(Wrapping(res as u64))
}

#[cfg(any(test, feature = "testing"))]
async fn setup_small_session<Z>(
    session_id: SessionId,
    role_assignments: RoleAssignment,
    threshold: u8,
    network: NetworkingImpl,
    identity: Identity,
) -> SmallSession<Z>
where
    Z: Ring,
    Z: RingEmbed,
    Z: HenselLiftInverse,
{
    use crate::execution::runtime::session::{ParameterHandles, SmallSessionHandles};

    let mut session = SmallSession::<Z>::new(
        session_id,
        role_assignments,
        network,
        threshold,
        None,
        identity.clone(),
        Some(AesRng::from_entropy()),
    )
    .unwrap();

    let prss_setup =
        PRSSSetup::init_with_abort::<RealAgreeRandom, AesRng, SmallSession<Z>>(&mut session)
            .await
            .unwrap();

    session.set_prss(Some(
        prss_setup.new_prss_session_state(session.session_id()),
    ));

    session
}

pub async fn init_prep_bitdec_small(
    session: &mut SmallSession64,
    num_ctxts: usize,
) -> Box<dyn BitDecPreprocessing> {
    let mut bitdec_preprocessing = create_memory_factory().create_bit_decryption_preprocessing();
    let bitdec_batch = BatchParams {
        triples: bitdec_preprocessing.num_required_triples(num_ctxts)
            + bitdec_preprocessing.num_required_bits(num_ctxts),
        randoms: bitdec_preprocessing.num_required_bits(num_ctxts),
    };

    let mut small_preprocessing =
        SmallPreprocessing::<ResiduePoly64, RealAgreeRandom>::init(session, bitdec_batch)
            .await
            .unwrap();

    bitdec_preprocessing
        .fill_from_base_preproc(
            &mut small_preprocessing,
            &mut session.to_base_session(),
            num_ctxts,
        )
        .await
        .unwrap();

    bitdec_preprocessing
}

pub async fn init_prep_bitdec_large(
    session: &mut LargeSession,
    num_ctxts: usize,
) -> Box<dyn BitDecPreprocessing> {
    let mut bitdec_preprocessing = create_memory_factory().create_bit_decryption_preprocessing();
    let bitdec_batch = BatchParams {
        triples: bitdec_preprocessing.num_required_triples(num_ctxts)
            + bitdec_preprocessing.num_required_bits(num_ctxts),
        randoms: bitdec_preprocessing.num_required_bits(num_ctxts),
    };

    let mut large_preprocessing = LargePreprocessing::<
        ResiduePoly64,
        TrueSingleSharing<ResiduePoly64>,
        TrueDoubleSharing<ResiduePoly64>,
    >::init(
        session,
        bitdec_batch,
        TrueSingleSharing::default(),
        TrueDoubleSharing::default(),
    )
    .await
    .unwrap();

    bitdec_preprocessing
        .fill_from_base_preproc(
            &mut large_preprocessing,
            &mut session.to_base_session(),
            num_ctxts,
        )
        .await
        .unwrap();

    bitdec_preprocessing
}

/// test the threshold decryption
#[cfg(any(test, feature = "testing"))]
pub fn threshold_decrypt64<Z: Ring>(
    runtime: &DistributedTestRuntime<Z>,
    ct: &Ciphertext64,
    mode: DecryptionMode,
) -> anyhow::Result<HashMap<Identity, Z64>> {
    let session_id = SessionId(1);

    let rt = tokio::runtime::Runtime::new()?;
    let _guard = rt.enter();

    let mut set = JoinSet::new();

    // Do the Switch&Squash only once instead of having all test parties run it.
    let large_ct = match mode {
        DecryptionMode::PRSSDecrypt | DecryptionMode::LargeDecrypt => {
            tracing::info!("Switch&Squash started...");
            let keyset_ck = runtime.get_conversion_key();
            let large_ct = keyset_ck.to_large_ciphertext(ct)?;
            tracing::info!("Switch&Squash done.");
            Some(large_ct)
        }
        _ => None,
    };

    for (index_id, identity) in runtime.identities.clone().into_iter().enumerate() {
        let role_assignments = runtime.role_assignments.clone();
        let net = Arc::clone(&runtime.user_nets[index_id]);
        let threshold = runtime.threshold;

        let party_keyshare = runtime
            .keyshares
            .clone()
            .map(|ks| ks[index_id].clone())
            .ok_or_else(|| {
                anyhow_error_and_log("key share not set during decryption".to_string())
            })?;

        let ct = ct.clone();
        let large_ct = large_ct.clone();

        tracing::info!(
            "{}: starting threshold decrypt with mode {}",
            identity,
            mode
        );

        match mode {
            DecryptionMode::PRSSDecrypt => {
                let large_ct = large_ct.unwrap();
                set.spawn(async move {
                    let mut session = setup_small_session::<ResiduePoly128>(
                        session_id,
                        role_assignments,
                        threshold,
                        net,
                        identity.clone(),
                    )
                    .await;

                    let mut noiseflood_preprocessing = Small::new(session.clone())
                        .init_prep_noiseflooding(ct.blocks().len())
                        .await;
                    let out = run_decryption_noiseflood(
                        &mut session,
                        noiseflood_preprocessing.as_mut(),
                        &party_keyshare,
                        large_ct,
                    )
                    .await
                    .unwrap();

                    (identity, out)
                });
            }
            DecryptionMode::LargeDecrypt => {
                let large_ct = large_ct.unwrap();
                set.spawn(async move {
                    let session_params = SessionParameters::new(
                        threshold,
                        session_id,
                        identity.clone(),
                        role_assignments,
                    )
                    .unwrap();
                    let mut session = LargeSession::new(session_params, net).unwrap();
                    let mut noiseflood_preprocessing = Large::new(session.clone())
                        .init_prep_noiseflooding(ct.blocks().len())
                        .await;
                    let out = run_decryption_noiseflood(
                        &mut session,
                        noiseflood_preprocessing.as_mut(),
                        &party_keyshare,
                        large_ct,
                    )
                    .await
                    .unwrap();

                    (identity, out)
                });
            }
            DecryptionMode::BitDecLargeDecrypt => {
                set.spawn(async move {
                    let session_params = SessionParameters::new(
                        threshold,
                        session_id,
                        identity.clone(),
                        role_assignments,
                    )
                    .unwrap();
                    let mut session = LargeSession::new(session_params, net).unwrap();
                    let mut prep = init_prep_bitdec_large(&mut session, ct.blocks().len()).await;
                    let out =
                        run_decryption_bitdec(&mut session, prep.as_mut(), &party_keyshare, ct)
                            .await
                            .unwrap();

                    (identity, out)
                });
            }
            DecryptionMode::BitDecSmallDecrypt => {
                set.spawn(async move {
                    let mut session = setup_small_session::<ResiduePoly64>(
                        session_id,
                        role_assignments,
                        threshold,
                        net,
                        identity.clone(),
                    )
                    .await;
                    let mut prep = init_prep_bitdec_small(&mut session, ct.blocks().len()).await;
                    let out =
                        run_decryption_bitdec(&mut session, prep.as_mut(), &party_keyshare, ct)
                            .await
                            .unwrap();
                    (identity, out)
                });
            }
        }
    }

    let results = rt.block_on(async {
        let mut results = HashMap::new();
        while let Some(v) = set.join_next().await {
            let (identity, val) = v.unwrap();
            results.insert(identity, val);
        }
        results
    });
    Ok(results)
}

async fn open_masked_ptxts<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
    session: &S,
    res: Vec<ResiduePoly128>,
    keyshares: &SecretKeyShare,
) -> anyhow::Result<Vec<Z128>> {
    let openeds = robust_opens_to_all(session, &res, session.threshold() as usize).await?;
    reconstruct_message(openeds, &keyshares.threshold_lwe_parameters)
}

/// Reconstructs a vector of plaintexts from raw, opened ciphertexts, by using the contant term of the `openeds`
/// and mapping it down to the message space of a ciphertext block.
pub fn reconstruct_message(
    openeds: Option<Vec<ResiduePoly<Z128>>>,
    params: &ThresholdLWEParameters,
) -> anyhow::Result<Vec<Z128>> {
    let total_mod_bits = params.output_cipher_parameters.total_block_bits() as usize;
    // shift
    let mut out = Vec::new();
    match openeds {
        Some(openeds) => {
            for opened in openeds {
                let v_scalar = opened.to_scalar()?;
                out.push(from_expanded_msg(v_scalar.0, total_mod_bits));
            }
        }
        _ => {
            return Err(anyhow_error_and_log(
                "Right shift not possible - no opened value".to_string(),
            ))
        }
    };
    Ok(out)
}

async fn open_bit_composed_ptxts<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
    session: &S,
    res: Vec<ResiduePoly64>,
) -> anyhow::Result<Vec<Z64>> {
    let openeds = robust_opens_to_all(session, &res, session.threshold() as usize).await?;

    let mut out = Vec::with_capacity(res.len());
    match openeds {
        Some(openeds) => {
            for opened in openeds {
                let v_scalar = opened.to_scalar()?;
                out.push(v_scalar);
            }
        }
        _ => {
            return Err(anyhow_error_and_log(
                "Error receiving shares for reconstructing bit-composed message".to_string(),
            ))
        }
    };
    Ok(out)
}

pub async fn run_decryption_noiseflood<
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    P: NoiseFloodPreprocessing + ?Sized,
>(
    session: &mut S,
    preprocessing: &mut P,
    keyshares: &SecretKeyShare,
    ciphertext: Ciphertext128,
) -> anyhow::Result<Z64> {
    let mut shared_masked_ptxts = Vec::with_capacity(ciphertext.len());
    for current_ct_block in ciphertext {
        let partial_decrypt = partial_decrypt128(keyshares, &current_ct_block)?;
        let res = partial_decrypt + preprocessing.next_mask()?;

        shared_masked_ptxts.push(res);
    }
    let partial_decrypted = open_masked_ptxts(session, shared_masked_ptxts, keyshares).await?;
    let usable_message_bits = keyshares
        .threshold_lwe_parameters
        .output_cipher_parameters
        .message_modulus_log() as usize;
    combine_plaintext_blocks(usable_message_bits, partial_decrypted)
}

// run decryption with bit-decomposition
pub async fn run_decryption_bitdec<
    P: BitDecPreprocessing + Send + ?Sized,
    Rnd: Rng + CryptoRng,
    Ses: BaseSessionHandles<Rnd>,
>(
    session: &mut Ses,
    prep: &mut P,
    keyshares: &SecretKeyShare,
    ciphertext: Ciphertext64,
) -> anyhow::Result<Z64> {
    let own_role = session.my_role()?;

    let mut shared_ptxts = Vec::with_capacity(ciphertext.blocks().len());
    for current_ct_block in ciphertext.blocks() {
        let partial_dec = partial_decrypt64(keyshares, current_ct_block)?;
        shared_ptxts.push(Share::new(own_role, partial_dec));
    }

    let bits = bit_dec_batch::<Z64, P, _, _>(session, prep, shared_ptxts)
        .await
        .unwrap();

    let total_bits = keyshares
        .threshold_lwe_parameters
        .input_cipher_parameters
        .total_block_bits() as usize;

    // bit-compose the plaintexts
    let ptxt_sums = BatchedBits::extract_ptxts(bits, total_bits, prep, session).await?;
    let ptxt_sums: Vec<_> = ptxt_sums.iter().map(|ptxt_sum| ptxt_sum.value()).collect();

    // output results to party 0
    let ptxts64 = open_bit_composed_ptxts(session, ptxt_sums).await?;
    let ptxts128: Vec<_> = ptxts64
        .iter()
        .map(|ptxt| Wrapping(ptxt.0 as u128))
        .collect();

    let usable_message_bits = keyshares
        .threshold_lwe_parameters
        .input_cipher_parameters
        .message_modulus_log() as usize;

    // combine outputs to form the decrypted integer on party 0
    combine_plaintext_blocks(usable_message_bits, ptxts128)
}

/// computes b - <a, s> with no rounding of the noise. This is used for noise flooding decryption
pub fn partial_decrypt128(
    sk_share: &SecretKeyShare,
    ct: &Ciphertext128Block,
) -> anyhow::Result<ResiduePoly128> {
    // NOTE eventually this secret key share will be a vector of ResiduePoly128 elements
    let (mask, body) = ct.get_mask_and_body();
    let a_time_s =
        (0..sk_share.input_key_share128.len()).fold(ResiduePoly128::ZERO, |acc, column| {
            acc + sk_share.input_key_share128[column]
                * ResiduePoly128::from_scalar(Wrapping(mask.as_ref()[column]))
        });
    // b-<a, s>
    let res = ResiduePoly128::from_scalar(Wrapping(*body.data)) - a_time_s;
    Ok(res)
}

// computes b - <a, s> + \Delta/2 for the bitwise decryption method
pub fn partial_decrypt64(
    sk_share: &SecretKeyShare,
    ct_block: &Ciphertext64Block,
) -> anyhow::Result<ResiduePoly64> {
    let ciphertext_modulus = 64;
    let (mask, body) = ct_block.ct.get_mask_and_body();
    let key_share64 = sk_share.input_key_share64.clone();
    let a_time_s = (0..key_share64.len()).fold(ResiduePoly64::ZERO, |acc, column| {
        acc + key_share64[column] * ResiduePoly64::from_scalar(Wrapping(mask.as_ref()[column]))
    });
    // b-<a, s>
    let delta_pad_bits = ciphertext_modulus
        - (sk_share
            .threshold_lwe_parameters
            .input_cipher_parameters
            .total_block_bits()
            + 1);
    let delta_pad_half = (1_u64 << delta_pad_bits) >> 1;
    let scalar_delta_half = ResiduePoly64::from_scalar(Wrapping(delta_pad_half));
    let res = ResiduePoly64::from_scalar(Wrapping(*body.data)) - a_time_s + scalar_delta_half;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use crate::execution::sharing::shamir::RevealOp;
    use crate::{
        algebra::residue_poly::{ResiduePoly128, ResiduePoly64},
        execution::{
            constants::SMALL_TEST_KEY_PATH,
            endpoints::decryption::threshold_decrypt64,
            runtime::{
                party::{Identity, Role},
                session::DecryptionMode,
                test_runtime::{generate_fixed_identities, DistributedTestRuntime},
            },
            sharing::{shamir::ShamirSharings, share::Share},
        },
        file_handling::read_element,
        lwe::{keygen_all_party_shares, KeySet},
    };
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use std::sync::Arc;
    use tfhe::{prelude::FheEncrypt, FheUint8};

    #[test]
    fn reconstruct_key() {
        let parties = 5;
        let keyset = read_element(SMALL_TEST_KEY_PATH.to_string()).unwrap();
        let shares =
            keygen_all_party_shares(&keyset, &mut AesRng::seed_from_u64(0), parties, 1).unwrap();
        let mut first_bit_shares = Vec::with_capacity(parties);
        (0..parties).for_each(|i| {
            first_bit_shares.push(Share::new(
                Role::indexed_by_zero(i),
                *shares[i].input_key_share128.get(0).unwrap(),
            ));
        });
        let first_bit_sharing = ShamirSharings::create(first_bit_shares);
        let rec = first_bit_sharing.err_reconstruct(1, 0).unwrap();
        let inner_rec = rec.to_scalar().unwrap();
        assert_eq!(
            keyset.client_output_key.large_key.into_container()[0],
            inner_rec.0
        );
    }

    #[test]
    fn test_large_threshold_decrypt() {
        let threshold = 1;
        let num_parties = 5;
        let msg: u8 = 3;
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH.to_string()).unwrap();

        let mut rng = AesRng::seed_from_u64(42);
        // generate keys
        let key_shares =
            keygen_all_party_shares(&keyset, &mut rng, num_parties, threshold).unwrap();
        let (ct, _id) = FheUint8::encrypt(msg, &keyset.client_key).into_raw_parts();

        let identities = generate_fixed_identities(num_parties);
        let mut runtime = DistributedTestRuntime::new(identities, threshold as u8);

        runtime.setup_conversion_key(Arc::new(keyset.conversion_key.clone()));
        runtime.setup_sks(key_shares);

        let results_dec =
            threshold_decrypt64::<ResiduePoly128>(&runtime, &ct, DecryptionMode::LargeDecrypt)
                .unwrap();
        let out_dec = &results_dec[&Identity("localhost:5000".to_string())];

        let ref_res = std::num::Wrapping(msg as u64);
        assert_eq!(*out_dec, ref_res);
    }

    #[test]
    fn test_small_threshold_decrypt() {
        let threshold = 1;
        let num_parties = 4;
        let msg: u8 = 3;
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH.to_string()).unwrap();

        let mut rng = AesRng::seed_from_u64(42);
        // generate keys
        let key_shares =
            keygen_all_party_shares(&keyset, &mut rng, num_parties, threshold).unwrap();
        let (ct, _id) = FheUint8::encrypt(msg, &keyset.client_key).into_raw_parts();

        let identities = generate_fixed_identities(num_parties);
        let mut runtime = DistributedTestRuntime::new(identities, threshold as u8);

        runtime.setup_conversion_key(Arc::new(keyset.conversion_key.clone()));
        runtime.setup_sks(key_shares);

        let results_dec =
            threshold_decrypt64::<ResiduePoly128>(&runtime, &ct, DecryptionMode::PRSSDecrypt)
                .unwrap();
        let out_dec = &results_dec[&Identity("localhost:5000".to_string())];

        let ref_res = std::num::Wrapping(msg as u64);
        assert_eq!(*out_dec, ref_res);
    }

    #[test]
    fn test_small_bitdec_threshold_decrypt() {
        let threshold = 1;
        let num_parties = 5;
        let msg: u8 = 3;
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH.to_string()).unwrap();

        let mut rng = AesRng::seed_from_u64(42);
        // generate keys
        let key_shares =
            keygen_all_party_shares(&keyset, &mut rng, num_parties, threshold).unwrap();
        let (ct, _id) = FheUint8::encrypt(msg, &keyset.client_key).into_raw_parts();

        let identities = generate_fixed_identities(num_parties);
        let mut runtime = DistributedTestRuntime::<ResiduePoly64>::new(identities, threshold as u8);

        runtime.setup_sks(key_shares);

        let results_dec =
            threshold_decrypt64(&runtime, &ct, DecryptionMode::BitDecSmallDecrypt).unwrap();
        let out_dec = &results_dec[&Identity("localhost:5000".to_string())];

        let ref_res = std::num::Wrapping(msg as u64);
        assert_eq!(*out_dec, ref_res);
    }

    #[test]
    fn test_large_bitdec_threshold_decrypt() {
        let threshold = 1;
        let num_parties = 5;
        let msg: u8 = 15;
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH.to_string()).unwrap();

        let mut rng = AesRng::seed_from_u64(42);
        // generate keys
        let key_shares =
            keygen_all_party_shares(&keyset, &mut rng, num_parties, threshold).unwrap();
        let (ct, _id) = FheUint8::encrypt(msg, &keyset.client_key).into_raw_parts();

        let identities = generate_fixed_identities(num_parties);
        let mut runtime = DistributedTestRuntime::<ResiduePoly64>::new(identities, threshold as u8);

        runtime.setup_sks(key_shares);

        let results_dec =
            threshold_decrypt64(&runtime, &ct, DecryptionMode::BitDecLargeDecrypt).unwrap();
        let out_dec = &results_dec[&Identity("localhost:5000".to_string())];

        let ref_res = std::num::Wrapping(msg as u64);
        assert_eq!(*out_dec, ref_res);
    }
}
