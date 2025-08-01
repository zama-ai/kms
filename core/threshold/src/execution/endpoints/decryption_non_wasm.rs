use crate::algebra::structure_traits::Derive;
use crate::algebra::structure_traits::Ring;
use crate::algebra::structure_traits::{ErrorCorrect, Invert, Solve};
use crate::execution::config::BatchParams;
use crate::execution::constants::B_SWITCH_SQUASH;
use crate::execution::endpoints::decryption::RadixOrBoolCiphertext;
use crate::execution::endpoints::decryption::SnsDecryptionKeyType;
use crate::execution::endpoints::decryption::SnsRadixOrBoolCiphertext;
use crate::execution::large_execution::offline::SecureLargePreprocessing;
use crate::execution::online::bit_manipulation::{bit_dec_batch, BatchedBits};
use crate::execution::online::preprocessing::memory::noiseflood::InMemoryNoiseFloodPreprocessing;
use crate::execution::online::preprocessing::BitDecPreprocessing;
use crate::execution::online::preprocessing::InMemoryBitDecPreprocessing;
use crate::execution::online::preprocessing::NoiseFloodPreprocessing;
use crate::execution::runtime::party::Identity;
use crate::execution::runtime::session::BaseSession;
use crate::execution::runtime::session::ParameterHandles;
#[cfg(any(test, feature = "testing"))]
use crate::execution::runtime::session::SessionParameters;
use crate::execution::runtime::session::SmallSessionHandles;
use crate::execution::runtime::session::ToBaseSession;
use crate::execution::sharing::open::{RobustOpen, SecureRobustOpen};
use crate::execution::sharing::share::Share;
use crate::execution::small_execution::offline::{Preprocessing, SecureSmallPreprocessing};
use crate::execution::small_execution::prss::PRSSPrimitives;
use crate::execution::tfhe_internals::parameters::AugmentedCiphertextParameters;
#[cfg(any(test, feature = "testing"))]
use crate::execution::{
    runtime::test_runtime::DistributedTestRuntime, small_execution::prf::PRSSConversions,
};
#[cfg(any(test, feature = "testing"))]
use crate::session_id::SessionId;
use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        galois_rings::common::ResiduePoly,
        structure_traits::Zero,
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        constants::{LOG_B_SWITCH_SQUASH, STATSEC},
        runtime::session::{BaseSessionHandles, LargeSession, SmallSession},
    },
};
#[cfg(any(test, feature = "testing"))]
use aes_prng::AesRng;
use anyhow::Context;
use async_trait::async_trait;
use itertools::Itertools;
#[cfg(any(test, feature = "testing"))]
use rand::SeedableRng;
use std::cell::RefCell;
use std::collections::HashMap;
use std::num::Wrapping;
use std::ops::Mul;
#[cfg(any(test, feature = "testing"))]
use std::sync::Arc;
use tfhe::core_crypto::prelude::{keyswitch_lwe_ciphertext, LweCiphertext, LweKeyswitchKey};
use tfhe::integer::noise_squashing::NoiseSquashingKey;
use tfhe::integer::ServerKey;
use tfhe::shortint::ciphertext::SquashedNoiseCiphertext;
use tfhe::shortint::Ciphertext;
use tfhe::shortint::PBSOrder;
#[cfg(any(test, feature = "testing"))]
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant};
use tracing::info_span;
use tracing::instrument;

#[cfg(any(test, feature = "testing"))]
use super::decryption::DecryptionMode;
use super::decryption::LowLevelCiphertext;
use super::keygen::PrivateKeySet;
use super::reconstruct::{combine_decryptions, reconstruct_message};

// NOTE: This whole trait system for noiseflood preproc is
// a bit convoluted and could probably be refactored to be simpler.
pub struct NoiseFloodSmallSession<
    const EXTENSION_DEGREE: usize,
    Ses: SmallSessionHandles<ResiduePoly<Z128, EXTENSION_DEGREE>>,
> where
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
{
    pub session: RefCell<Ses>,
}

impl<
        const EXTENSION_DEGREE: usize,
        Ses: SmallSessionHandles<ResiduePoly<Z128, EXTENSION_DEGREE>>,
    > NoiseFloodSmallSession<EXTENSION_DEGREE, Ses>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
{
    pub fn new(session: Ses) -> Self {
        NoiseFloodSmallSession {
            session: RefCell::new(session),
        }
    }
}

pub struct NoiseFloodLargeSession<PreprocStrat> {
    pub session: RefCell<LargeSession>,
    _marker: std::marker::PhantomData<PreprocStrat>,
}

impl<PreprocStrat> NoiseFloodLargeSession<PreprocStrat> {
    pub fn new(session: LargeSession) -> Self {
        NoiseFloodLargeSession {
            session: RefCell::new(session),
            _marker: std::marker::PhantomData,
        }
    }
}

pub type SecureNoiseFloodLargeSession<Z> = NoiseFloodLargeSession<SecureLargePreprocessing<Z>>;

#[async_trait]
pub trait NoiseFloodPreparation<const EXTENSION_DEGREE: usize> {
    async fn init_prep_noiseflooding(
        &mut self,
        num_ctxt: usize,
    ) -> anyhow::Result<InMemoryNoiseFloodPreprocessing<EXTENSION_DEGREE>>;

    fn get_mut_base_session(&mut self) -> &mut BaseSession;
}

#[async_trait]
impl<
        const EXTENSION_DEGREE: usize,
        Ses: SmallSessionHandles<ResiduePoly<Z128, EXTENSION_DEGREE>> + ToBaseSession,
    > NoiseFloodPreparation<EXTENSION_DEGREE> for NoiseFloodSmallSession<EXTENSION_DEGREE, Ses>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    /// Load precomputed init data for noise flooding.
    ///
    /// Note: this is actually a synchronous function. It just needs to be async to implement the trait (which is async in the Large case)
    /// TODO: we should move the slow parts to rayon
    async fn init_prep_noiseflooding(
        &mut self,
        num_ctxt: usize,
    ) -> anyhow::Result<InMemoryNoiseFloodPreprocessing<EXTENSION_DEGREE>> {
        let session = self.session.get_mut();
        let mut sns_preprocessing = InMemoryNoiseFloodPreprocessing::default();
        let own_role = session.my_role();

        let prss_span = info_span!("PRSS-MASK.Next", batch_size = num_ctxt);
        let masks = prss_span.in_scope(|| {
            (0..num_ctxt)
                .map(|_| {
                    self.session
                        .get_mut()
                        .prss_as_mut()
                        .mask_next(own_role, B_SWITCH_SQUASH)
                })
                .try_collect()
        })?;

        sns_preprocessing.append_masks(masks);
        Ok(sns_preprocessing)
    }

    fn get_mut_base_session(&mut self) -> &mut BaseSession {
        self.session.get_mut().get_mut_base_session()
    }
}

#[async_trait]
impl<
        const EXTENSION_DEGREE: usize,
        PreprocStrat: Preprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>, LargeSession> + Default,
    > NoiseFloodPreparation<EXTENSION_DEGREE> for NoiseFloodLargeSession<PreprocStrat>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
{
    /// Compute precomputed init data for noise flooding.
    async fn init_prep_noiseflooding(
        &mut self,
        num_ctxt: usize,
    ) -> anyhow::Result<InMemoryNoiseFloodPreprocessing<EXTENSION_DEGREE>> {
        let session = self.session.get_mut();
        let num_preproc = 2 * num_ctxt * ((STATSEC + LOG_B_SWITCH_SQUASH) as usize + 2);
        let batch_size = BatchParams {
            triples: num_preproc,
            randoms: num_preproc,
        };

        let mut correlated_randomness =
            PreprocStrat::default().execute(session, batch_size).await?;

        let mut sns_preprocessing = InMemoryNoiseFloodPreprocessing::default();
        sns_preprocessing
            .fill_from_base_preproc(
                &mut correlated_randomness,
                session.get_mut_base_session(),
                num_ctxt,
            )
            .await?;
        Ok(sns_preprocessing)
    }

    fn get_mut_base_session(&mut self) -> &mut BaseSession {
        self.session.get_mut().get_mut_base_session()
    }
}

#[async_trait]
pub trait OnlineNoiseFloodDecryption<const EXTENSION_DEGREE: usize> {
    async fn decrypt<
        S: BaseSessionHandles,
        P: NoiseFloodPreprocessing<EXTENSION_DEGREE> + ?Sized,
        T,
    >(
        session: &mut S,
        preprocessing: &mut P,
        keyshares: &PrivateKeySet<EXTENSION_DEGREE>,
        ciphertext: &SnsRadixOrBoolCiphertext,
        ddec_key_type: SnsDecryptionKeyType,
    ) -> anyhow::Result<T>
    where
        T: tfhe::integer::block_decomposition::Recomposable
            + tfhe::core_crypto::commons::traits::CastFrom<u128>,
        ResiduePoly<Z128, EXTENSION_DEGREE>: Invert + Solve + ErrorCorrect;
}

pub struct SecureOnlineNoiseFloodDecryption;

#[async_trait]
impl<const EXTENSION_DEGREE: usize> OnlineNoiseFloodDecryption<EXTENSION_DEGREE>
    for SecureOnlineNoiseFloodDecryption
{
    async fn decrypt<
        S: BaseSessionHandles,
        P: NoiseFloodPreprocessing<EXTENSION_DEGREE> + ?Sized,
        T,
    >(
        session: &mut S,
        preprocessing: &mut P,
        keyshares: &PrivateKeySet<EXTENSION_DEGREE>,
        ciphertext: &SnsRadixOrBoolCiphertext,
        ddec_key_type: SnsDecryptionKeyType,
    ) -> anyhow::Result<T>
    where
        T: tfhe::integer::block_decomposition::Recomposable
            + tfhe::core_crypto::commons::traits::CastFrom<u128>,
        ResiduePoly<Z128, EXTENSION_DEGREE>: Invert + Solve + ErrorCorrect,
    {
        run_decryption_noiseflood::<EXTENSION_DEGREE, _, _, T>(
            session,
            preprocessing,
            keyshares,
            ciphertext,
            ddec_key_type,
        )
        .await
    }
}

#[cfg(any(feature = "testing", test))]
pub struct MaliciousOnlineNoiseFloodDecryption;

#[cfg(any(feature = "testing", test))]
#[async_trait]
impl<const EXTENSION_DEGREE: usize> OnlineNoiseFloodDecryption<EXTENSION_DEGREE>
    for MaliciousOnlineNoiseFloodDecryption
{
    async fn decrypt<
        S: BaseSessionHandles,
        P: NoiseFloodPreprocessing<EXTENSION_DEGREE> + ?Sized,
        T,
    >(
        _session: &mut S,
        _preprocessing: &mut P,
        _keyshares: &PrivateKeySet<EXTENSION_DEGREE>,
        _ciphertext: &SnsRadixOrBoolCiphertext,
        _ddec_key_type: SnsDecryptionKeyType,
    ) -> anyhow::Result<T>
    where
        T: tfhe::integer::block_decomposition::Recomposable
            + tfhe::core_crypto::commons::traits::CastFrom<u128>,
        ResiduePoly<Z128, EXTENSION_DEGREE>: Invert + Solve + ErrorCorrect,
    {
        Ok(T::ZERO)
    }
}

/// Decrypts a ciphertext using noise flooding.
///
/// Returns the plaintext plus some timing information.
///
/// This is the entry point of the decryption protocol.
///
/// # Arguments
/// * `noiseflood_session` - The preparation object that contains the decryption `ProtocolType`. `ProtocolType` is the preparation of the noise flooding which holds the `Session` type
/// * `ck` - The conversion key, used for switch&squash
/// * `ct` - The ciphertext to be decrypted
/// * `secret_key_share` - The secret key share of the party_keyshare
/// * `_mode` - The decryption mode. This is used only for tracing purposes
///
/// # Returns
/// * A tuple containing the results of the decryption and the time it took to execute the decryption
/// * The results of the decryption are a hashmap containing the session id and the decrypted plaintexts
/// * The time it took to execute the decryption
///
/// # Remarks
/// The decryption protocol is executed in the following steps:
/// 1. The ciphertext is converted to a large ciphertext block
/// 2. The protocol preprocessing is initialized with the noise flooding
/// 3. The decryption is executed
/// 4. The results are returned
///
#[allow(clippy::too_many_arguments)]
#[instrument(skip_all, fields(sid, own_identity))]
pub async fn decrypt_using_noiseflooding<const EXTENSION_DEGREE: usize, P, O, T>(
    noiseflood_session: &mut P,
    server_key: &ServerKey,
    ck: &NoiseSquashingKey,
    ct: LowLevelCiphertext,
    secret_key_share: &PrivateKeySet<EXTENSION_DEGREE>,
) -> anyhow::Result<(HashMap<String, T>, Duration)>
where
    P: NoiseFloodPreparation<EXTENSION_DEGREE>,
    O: OnlineNoiseFloodDecryption<EXTENSION_DEGREE>,
    T: tfhe::integer::block_decomposition::Recomposable
        + tfhe::core_crypto::commons::traits::CastFrom<u128>,
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    let execution_start_timer = Instant::now();
    let ddec_key_type = ct.decryption_key_type();
    let ct_large = match ct {
        LowLevelCiphertext::BigCompressed(ct128) => ct128,
        LowLevelCiphertext::BigStandard(ct128) => ct128,
        LowLevelCiphertext::Small(ct64) => match ct64 {
            RadixOrBoolCiphertext::Radix(base_radix_ciphertext) => SnsRadixOrBoolCiphertext::Radix(
                ck.squash_radix_ciphertext_noise(server_key, &base_radix_ciphertext)?,
            ),
            RadixOrBoolCiphertext::Bool(boolean_block) => SnsRadixOrBoolCiphertext::Bool(
                ck.squash_boolean_block_noise(server_key, &boolean_block)?,
            ),
        },
    };

    let mut results = HashMap::with_capacity(1);
    let len = ct_large.len();
    let mut preprocessing = noiseflood_session.init_prep_noiseflooding(len).await?;
    let session = noiseflood_session.get_mut_base_session();
    let sid: u128 = session.session_id().into();
    tracing::Span::current().record("sid", sid);
    let own_identity = session.own_identity();
    tracing::Span::current().record("own_identity", own_identity.to_string());

    let outputs = O::decrypt::<_, _, T>(
        session,
        &mut preprocessing,
        secret_key_share,
        &ct_large,
        ddec_key_type,
    )
    .await?;

    tracing::info!(
        "Noiseflood result in session {:?} is ready",
        session.session_id()
    );
    results.insert(format!("{}", session.session_id()), outputs);

    let execution_stop_timer = Instant::now();
    let elapsed_time = execution_stop_timer.duration_since(execution_start_timer);
    Ok((results, elapsed_time))
}

/// Partially decrypt a ciphertext using noise flooding.
/// Partially here means that each party outputs a share of the decrypted result.
///
/// Returns this party's share of the plaintext plus some timing information.
///
/// This is the entry point of the User decryption protocol.
///
/// # Arguments
/// * `parameters` - The parameters object that contains the required session information
/// * `noiseflood_session` - The preparation object that contains the decryption `ProtocolType`. `ProtocolType` is the preparation of the noise flooding which holds the `Session` type
/// * `ck` - The conversion key, used for switch&squash
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
/// 3. The local decryption is executed, without opening the result resulting in a partial decryption
/// 4. The results are returned
///
/// There is no "online" phase for partial decryption because all computation is local,
/// that's why there are no traits similar to [OnlineNoiseFloodDecryption].
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
#[instrument(skip_all, fields(sid, own_identity))]
pub async fn partial_decrypt_using_noiseflooding<const EXTENSION_DEGREE: usize, P>(
    noiseflood_session: &mut P,
    server_key: &ServerKey,
    ck: &NoiseSquashingKey,
    ct: LowLevelCiphertext,
    secret_key_share: &PrivateKeySet<EXTENSION_DEGREE>,
) -> anyhow::Result<(
    HashMap<String, Vec<ResiduePoly<Z128, EXTENSION_DEGREE>>>,
    u32,
    Duration,
)>
where
    P: NoiseFloodPreparation<EXTENSION_DEGREE>,
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    let sid = {
        let session = noiseflood_session.get_mut_base_session();
        let sid: u128 = session.session_id().into();
        tracing::Span::current().record("sid", sid);
        let own_identity = session.own_identity();
        tracing::Span::current().record("own_identity", own_identity.to_string());
        sid
    };

    let execution_start_timer = Instant::now();
    let ddec_key_type = ct.decryption_key_type();
    let ct_large = match ct {
        LowLevelCiphertext::BigCompressed(ct128) => ct128,
        LowLevelCiphertext::BigStandard(ct128) => ct128,
        LowLevelCiphertext::Small(ct64) => match ct64 {
            RadixOrBoolCiphertext::Radix(base_radix_ciphertext) => SnsRadixOrBoolCiphertext::Radix(
                ck.squash_radix_ciphertext_noise(server_key, &base_radix_ciphertext)?,
            ),
            RadixOrBoolCiphertext::Bool(boolean_block) => SnsRadixOrBoolCiphertext::Bool(
                ck.squash_boolean_block_noise(server_key, &boolean_block)?,
            ),
        },
    };
    let packing_factor = ct_large.packing_factor();
    #[cfg(test)]
    {
        match &ct_large {
            SnsRadixOrBoolCiphertext::Radix(_) => {
                let msg_bits = secret_key_share.parameters.message_modulus_log();
                let carry_bits = secret_key_share.parameters.carry_modulus_log();
                assert_eq!(packing_factor as u32, (msg_bits + carry_bits) / msg_bits);
            }
            SnsRadixOrBoolCiphertext::Bool(_) => {}
        }
    }

    let mut results = HashMap::with_capacity(1);
    let len = ct_large.len();
    let mut preparation = noiseflood_session.init_prep_noiseflooding(len).await?;
    let mut shared_masked_ptxts = Vec::with_capacity(len);
    for current_ct_block in ct_large.packed_blocks() {
        let partial_decrypt =
            partial_decrypt128(secret_key_share, current_ct_block, ddec_key_type)?;
        let res = partial_decrypt + preparation.next_mask()?;

        shared_masked_ptxts.push(res);
    }

    tracing::info!("Noiseflood result in session {sid} is ready, got {len} blocks");
    results.insert(format!("{sid}"), shared_masked_ptxts);

    let execution_stop_timer = Instant::now();
    let elapsed_time = execution_stop_timer.duration_since(execution_start_timer);
    Ok((results, packing_factor as u32, elapsed_time))
}

/// Decrypts a ciphertext using bit decomposition.
///
/// Returns the plaintext plus some timing information.
///
/// This is the entry point of the decryption protocol.
///
/// # Arguments
/// * `session` - The session object that contains the networking and the role of the party_keyshare
/// * `ct` - The ciphertext to be decrypted
/// * `secret_key_share` - The secret key share of the party_keyshare
/// * `ksk` - The public keyswitch key
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
/// 1. The protocol preprocessing is initialized and the required number of random bits and triples are generated.
/// 2. The decryption protocol is executed
/// 3. The results are returned
///
#[allow(clippy::too_many_arguments)]
#[instrument(skip(session, ct, secret_key_share, ksk), fields(session_id = ?session.session_id(), own_identity = %_own_identity))]
pub async fn secure_decrypt_using_bitdec<const EXTENSION_DEGREE: usize, T>(
    session: &mut SmallSession<ResiduePoly<Z64, EXTENSION_DEGREE>>,
    ct: &RadixOrBoolCiphertext,
    secret_key_share: &PrivateKeySet<EXTENSION_DEGREE>,
    ksk: &LweKeyswitchKey<Vec<u64>>,
    _own_identity: Identity,
) -> anyhow::Result<(HashMap<String, T>, Duration)>
where
    T: tfhe::integer::block_decomposition::Recomposable
        + tfhe::core_crypto::commons::traits::CastFrom<u128>,
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    let execution_start_timer = Instant::now();
    let mut results = HashMap::with_capacity(1);

    let sid = session.session_id();

    let mut preparation = secure_init_prep_bitdec_small_session(session, ct.len()).await?;

    let outputs = run_decryption_bitdec::<EXTENSION_DEGREE, _, _, T>(
        session,
        &mut preparation,
        secret_key_share,
        ksk,
        ct,
    )
    .await?;

    tracing::info!("Bitdec result in session {:?} is ready", sid);
    results.insert(format!("{sid}"), outputs);

    let execution_stop_timer = Instant::now();
    let elapsed_time = execution_stop_timer.duration_since(execution_start_timer);
    Ok((results, elapsed_time))
}

/// Partially decrypt a ciphertext using bit decomposition.
/// Partially here means that each party outputs a share of the decrypted result.
///
/// Returns this party's share of the plaintext plus some timing information.
///
/// This is the entry point of the User decryption protocol.
///
/// # Arguments
/// * `session` - The session object that contains the networking and the role of the party_keyshare
/// * `ct` - The ciphertext to be decrypted
/// * `secret_key_share` - The secret key share of the party_keyshare
/// * `ksk` - The public keyswitch key
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
/// 1. The protocol preprocessing is initialized and the required number of random bits and triples are generated.
/// 2. The partial interactive decryption is executed, without opening the result in the last step
/// 4. The results are returned
///
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
#[instrument(skip(session, ct, secret_key_share, ksk), fields(session_id = ?session.session_id(), own_identity = ?session.own_identity()))]
pub async fn secure_partial_decrypt_using_bitdec<const EXTENSION_DEGREE: usize>(
    session: &mut SmallSession<ResiduePoly<Z64, EXTENSION_DEGREE>>,
    ct: &RadixOrBoolCiphertext,
    secret_key_share: &PrivateKeySet<EXTENSION_DEGREE>,
    ksk: &LweKeyswitchKey<Vec<u64>>,
) -> anyhow::Result<(
    HashMap<String, Vec<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
    Duration,
)>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    let execution_start_timer = Instant::now();
    let sid = session.session_id();
    let own_role = session.my_role();
    let mut prep = secure_init_prep_bitdec_small_session(session, ct.len()).await?;

    let mut results = HashMap::with_capacity(1);

    let mut pdec_blocks = Vec::with_capacity(ct.len());
    for current_ct_block in ct.blocks() {
        let partial_dec = partial_decrypt64(secret_key_share, ksk, current_ct_block)?;
        pdec_blocks.push(Share::new(own_role, partial_dec));
    }

    // bit decomposition
    let bits = bit_dec_batch::<Z64, EXTENSION_DEGREE, _, _>(
        &mut session.base_session,
        &mut prep,
        pdec_blocks,
    )
    .await?;

    let total_bits = secret_key_share.parameters.total_block_bits() as usize;

    // bit-compose the plaintexts
    let ptxt_sums = BatchedBits::extract_ptxts(bits, total_bits, &mut prep, session).await?;
    let ptxt_sums: Vec<_> = ptxt_sums.iter().map(|ptxt_sum| ptxt_sum.value()).collect();

    tracing::info!("Bitdec result in session {:?} is ready", sid);
    results.insert(format!("{sid}"), ptxt_sums);

    let execution_stop_timer = Instant::now();
    let elapsed_time = execution_stop_timer.duration_since(execution_start_timer);
    Ok((results, elapsed_time))
}

/// Represent the blocks (decryptions of the LWE ciphertext)
/// of a partial decryption
/// before we combine them to output the integer
/// message
#[derive(Default)]
pub struct BlocksPartialDecrypt {
    pub bits_in_block: u32,
    pub partial_decryptions: Vec<Z128>,
}
/// Takes as input plaintexts blocks m1, ..., mN revealed to all parties
/// which we call partial decryptions each of B bits
/// and uses tfhe block recomposer to get back the u64 plaintext.
pub fn combine_plaintext_blocks<T>(
    shared_partial_decrypt: BlocksPartialDecrypt,
) -> anyhow::Result<T>
where
    T: tfhe::integer::block_decomposition::Recomposable
        + tfhe::core_crypto::commons::traits::CastFrom<u128>,
{
    let res = match combine_decryptions::<T>(
        shared_partial_decrypt.bits_in_block,
        shared_partial_decrypt.partial_decryptions,
    ) {
        Ok(res) => res,
        Err(error) => {
            return Err(anyhow_error_and_log(format!(
                "Panicked in combining {error}"
            )));
        }
    };
    Ok(res)
}

#[cfg(any(test, feature = "testing"))]
async fn setup_small_session<Z>(mut base_session: BaseSession) -> SmallSession<Z>
where
    Z: ErrorCorrect,
    Z: Invert,
    Z: PRSSConversions,
{
    use crate::execution::{
        runtime::session::{ParameterHandles, SmallSession},
        small_execution::prss::{AbortSecurePrssInit, DerivePRSSState, PRSSInit},
    };
    let session_id = base_session.session_id();

    let prss_setup = AbortSecurePrssInit::default()
        .init(&mut base_session)
        .await
        .unwrap();
    SmallSession::new_from_prss_state(base_session, prss_setup.new_prss_session_state(session_id))
        .unwrap()
}

/// Generically compute preprocessing information for a bit-decomposition decryption for the given session and number of ciphertexts.
#[instrument(
name = "TFHE.Threshold-Dec-2.Preprocessing",
skip_all,
fields(batch_size=?num_ctxts)
)]
pub async fn init_prep_bitdec<
    const EXTENSION_DEGREE: usize,
    Sess: BaseSessionHandles + ToBaseSession,
    PreprocStrat: Preprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>, Sess> + Default,
>(
    session: &mut Sess,
    num_ctxts: usize,
) -> anyhow::Result<InMemoryBitDecPreprocessing<EXTENSION_DEGREE>>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    let mut bitdec_preprocessing = InMemoryBitDecPreprocessing::default();
    let bitdec_batch = BatchParams {
        triples: bitdec_preprocessing.num_required_triples(num_ctxts)
            + bitdec_preprocessing.num_required_bits(num_ctxts),
        randoms: bitdec_preprocessing.num_required_bits(num_ctxts),
    };

    let mut correlated_randomness = PreprocStrat::default()
        .execute(session, bitdec_batch)
        .await?;

    bitdec_preprocessing
        .fill_from_base_preproc(
            &mut correlated_randomness,
            session.get_mut_base_session(),
            num_ctxts,
        )
        .await?;

    Ok(bitdec_preprocessing)
}

/// Wrapper around [`init_prep_bitdec`] for small sessions that uses the secure small preprocessing strategy.
pub async fn secure_init_prep_bitdec_small_session<const EXTENSION_DEGREE: usize>(
    session: &mut SmallSession<ResiduePoly<Z64, EXTENSION_DEGREE>>,
    num_ctxts: usize,
) -> anyhow::Result<InMemoryBitDecPreprocessing<EXTENSION_DEGREE>>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    init_prep_bitdec::<EXTENSION_DEGREE, _, SecureSmallPreprocessing>(session, num_ctxts).await
}

/// Wrapper around [`init_prep_bitdec`] for large sessions that uses the secure large preprocessing strategy.
pub async fn secure_init_prep_bitdec_large_session<const EXTENSION_DEGREE: usize>(
    session: &mut LargeSession,
    num_ctxts: usize,
) -> anyhow::Result<InMemoryBitDecPreprocessing<EXTENSION_DEGREE>>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
{
    init_prep_bitdec::<
        EXTENSION_DEGREE,
        _,
        SecureLargePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>,
    >(session, num_ctxts)
    .await
}

/// test the threshold decryption for a given 64-bit TFHE-rs ciphertext
///
/// NOTE: Trait bounds are a bit odd here because this function does a bit too many things
/// at once
#[cfg(any(test, feature = "testing"))]
pub fn threshold_decrypt64<Z: Ring, const EXTENSION_DEGREE: usize>(
    runtime: &DistributedTestRuntime<Z, EXTENSION_DEGREE>,
    ct: &RadixOrBoolCiphertext,
    mode: DecryptionMode,
    malicious_set: &[usize],
) -> anyhow::Result<HashMap<Identity, Z64>>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
{
    let session_id = SessionId::new(ct)?;

    let rt = tokio::runtime::Runtime::new()?;
    let _guard = rt.enter();

    let mut set = JoinSet::new();

    // Do the Switch&Squash for testing only once instead of having all test parties run it.
    let large_ct = match mode {
        DecryptionMode::NoiseFloodSmall | DecryptionMode::NoiseFloodLarge => {
            tracing::info!("Switch&Squash started...");
            let server_key = runtime.get_server_key();
            let int_server_key: &tfhe::integer::ServerKey = server_key.as_ref().as_ref();
            let sns_key = server_key.noise_squashing_key().unwrap();
            let large_ct = match ct {
                RadixOrBoolCiphertext::Radix(ct) => SnsRadixOrBoolCiphertext::Radix(
                    sns_key.squash_radix_ciphertext_noise(int_server_key, ct)?,
                ),
                RadixOrBoolCiphertext::Bool(boolean_block) => SnsRadixOrBoolCiphertext::Bool(
                    sns_key.squash_boolean_block_noise(int_server_key, boolean_block)?,
                ),
            };
            tracing::info!("Switch&Squash done.");
            Some(large_ct)
        }
        _ => None,
    };

    for (index_id, identity) in runtime.identities.clone().into_iter().enumerate() {
        let role_assignments = runtime.role_assignments.clone();
        let net = Arc::clone(&runtime.user_nets[index_id]);
        let threshold = runtime.threshold;
        let ct = ct.clone();
        let malicious_set = malicious_set.to_vec();

        let party_keyshare = runtime
            .keyshares
            .clone()
            .map(|ks| ks[index_id].clone())
            .ok_or_else(|| {
                anyhow_error_and_log("key share not set during decryption".to_string())
            })?;

        let large_ct = large_ct.clone();

        tracing::info!(
            "{}: starting threshold decrypt with mode {}",
            identity,
            mode
        );

        let session_params =
            SessionParameters::new(threshold, session_id, identity.clone(), role_assignments)
                .unwrap();
        let base_session = BaseSession::new(session_params, net, AesRng::from_entropy()).unwrap();

        match mode {
            DecryptionMode::NoiseFloodSmall => {
                let large_ct = large_ct.unwrap();
                set.spawn(async move {
                    let session =
                        setup_small_session::<ResiduePoly<Z128, EXTENSION_DEGREE>>(base_session)
                            .await;

                    let mut session_noiseflood = NoiseFloodSmallSession::new(session);
                    let mut noiseflood_preprocessing = session_noiseflood
                        .init_prep_noiseflooding(ct.len())
                        .await
                        .unwrap();
                    let out = if malicious_set.contains(&index_id) {
                        run_decryption_noiseflood_64::<
                            EXTENSION_DEGREE,
                            _,
                            _,
                            MaliciousOnlineNoiseFloodDecryption,
                        >(
                            session_noiseflood.session.get_mut(),
                            &mut noiseflood_preprocessing,
                            &party_keyshare,
                            &large_ct,
                            SnsDecryptionKeyType::SnsKey,
                        )
                        .await
                        .unwrap()
                    } else {
                        run_decryption_noiseflood_64::<
                            EXTENSION_DEGREE,
                            _,
                            _,
                            SecureOnlineNoiseFloodDecryption,
                        >(
                            session_noiseflood.session.get_mut(),
                            &mut noiseflood_preprocessing,
                            &party_keyshare,
                            &large_ct,
                            SnsDecryptionKeyType::SnsKey,
                        )
                        .await
                        .unwrap()
                    };

                    (identity, out)
                });
            }
            DecryptionMode::NoiseFloodLarge => {
                let large_ct = large_ct.unwrap();
                set.spawn(async move {
                    let session = LargeSession::new(base_session);
                    let mut session_noiseflood = SecureNoiseFloodLargeSession::new(session);
                    let mut noiseflood_preprocessing = session_noiseflood
                        .init_prep_noiseflooding(ct.len())
                        .await
                        .unwrap();
                    let out = if malicious_set.contains(&index_id) {
                        run_decryption_noiseflood_64::<
                            EXTENSION_DEGREE,
                            _,
                            _,
                            MaliciousOnlineNoiseFloodDecryption,
                        >(
                            session_noiseflood.session.get_mut(),
                            &mut noiseflood_preprocessing,
                            &party_keyshare,
                            &large_ct,
                            SnsDecryptionKeyType::SnsKey,
                        )
                        .await
                        .unwrap()
                    } else {
                        run_decryption_noiseflood_64::<
                            EXTENSION_DEGREE,
                            _,
                            _,
                            SecureOnlineNoiseFloodDecryption,
                        >(
                            session_noiseflood.session.get_mut(),
                            &mut noiseflood_preprocessing,
                            &party_keyshare,
                            &large_ct,
                            SnsDecryptionKeyType::SnsKey,
                        )
                        .await
                        .unwrap()
                    };

                    (identity, out)
                });
            }
            DecryptionMode::BitDecLarge => {
                let ks_key = runtime.get_ks_key();
                set.spawn(async move {
                    let mut session = LargeSession::new(base_session);
                    let mut prep = secure_init_prep_bitdec_large_session(&mut session, ct.len())
                        .await
                        .unwrap();
                    let out = if malicious_set.contains(&index_id) {
                        unimplemented!("malicious unimplemented")
                    } else {
                        run_decryption_bitdec_64(
                            &mut session,
                            &mut prep,
                            &party_keyshare,
                            &ks_key,
                            &ct,
                        )
                        .await
                        .unwrap()
                    };

                    (identity, out)
                });
            }
            DecryptionMode::BitDecSmall => {
                let ks_key = runtime.get_ks_key();
                set.spawn(async move {
                    let mut session =
                        setup_small_session::<ResiduePoly<Z64, EXTENSION_DEGREE>>(base_session)
                            .await;
                    let mut prep = secure_init_prep_bitdec_small_session(&mut session, ct.len())
                        .await
                        .unwrap();
                    let out = if malicious_set.contains(&index_id) {
                        unimplemented!("malicious unimplemented")
                    } else {
                        run_decryption_bitdec_64(
                            &mut session,
                            &mut prep,
                            &party_keyshare,
                            &ks_key,
                            &ct,
                        )
                        .await
                        .unwrap()
                    };
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

async fn open_masked_ptxts<const EXTENSION_DEGREE: usize, S: BaseSessionHandles>(
    session: &S,
    res: Vec<ResiduePoly<Z128, EXTENSION_DEGREE>>,
    keyshares: &PrivateKeySet<EXTENSION_DEGREE>,
) -> anyhow::Result<Vec<Z128>>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
{
    let openeds = SecureRobustOpen::default()
        .robust_open_list_to_all(session, res, session.threshold() as usize)
        .await?;
    reconstruct_message(openeds, &keyshares.parameters)
}

async fn open_bit_composed_ptxts<const EXTENSION_DEGREE: usize, S: BaseSessionHandles>(
    session: &S,
    res: Vec<ResiduePoly<Z64, EXTENSION_DEGREE>>,
) -> anyhow::Result<Vec<Z64>>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
{
    let mut out = Vec::with_capacity(res.len());
    let openeds = SecureRobustOpen::default()
        .robust_open_list_to_all(session, res, session.threshold() as usize)
        .await?;

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

#[instrument(
    name = "TFHE.Threshold-Dec-1",
    skip(session, preprocessing, keyshares, ciphertext)
    fields(sid=?session.session_id(),batch_size=?ciphertext.len())
)]
async fn run_decryption_noiseflood<
    const EXTENSION_DEGREE: usize,
    S: BaseSessionHandles,
    P: NoiseFloodPreprocessing<EXTENSION_DEGREE> + ?Sized,
    T,
>(
    session: &mut S,
    preprocessing: &mut P,
    keyshares: &PrivateKeySet<EXTENSION_DEGREE>,
    ciphertext: &SnsRadixOrBoolCiphertext,
    ddec_key_type: SnsDecryptionKeyType,
) -> anyhow::Result<T>
where
    T: tfhe::integer::block_decomposition::Recomposable
        + tfhe::core_crypto::commons::traits::CastFrom<u128>,
    ResiduePoly<Z128, EXTENSION_DEGREE>: Invert + Solve + ErrorCorrect,
{
    let mut shared_masked_ptxts = Vec::with_capacity(ciphertext.len());
    for current_ct_block in ciphertext.packed_blocks() {
        let partial_decrypt = partial_decrypt128(keyshares, current_ct_block, ddec_key_type)?;
        let res = partial_decrypt + preprocessing.next_mask()?;

        shared_masked_ptxts.push(res);
    }
    let partial_decrypted = open_masked_ptxts(session, shared_masked_ptxts, keyshares).await?;
    let usable_message_bits =
        ciphertext.packing_factor() * keyshares.parameters.message_modulus_log() as usize;
    let shared_partial_decrypt = BlocksPartialDecrypt {
        bits_in_block: usable_message_bits as u32,
        partial_decryptions: partial_decrypted,
    };
    combine_plaintext_blocks(shared_partial_decrypt)
}

pub async fn run_decryption_noiseflood_64<
    const EXTENSION_DEGREE: usize,
    S: BaseSessionHandles,
    P: NoiseFloodPreprocessing<EXTENSION_DEGREE> + ?Sized,
    O: OnlineNoiseFloodDecryption<EXTENSION_DEGREE>,
>(
    session: &mut S,
    preprocessing: &mut P,
    keyshares: &PrivateKeySet<EXTENSION_DEGREE>,
    ciphertext: &SnsRadixOrBoolCiphertext,
    ddec_key_type: SnsDecryptionKeyType,
) -> anyhow::Result<Z64>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: Invert + Solve + ErrorCorrect,
{
    let res = O::decrypt::<_, _, u64>(session, preprocessing, keyshares, ciphertext, ddec_key_type)
        .await?;
    Ok(Wrapping(res))
}

pub async fn run_decryption_bitdec_64<
    const EXTENSION_DEGREE: usize,
    P: BitDecPreprocessing<EXTENSION_DEGREE> + Send + ?Sized,
    Ses: BaseSessionHandles,
>(
    session: &mut Ses,
    prep: &mut P,
    keyshares: &PrivateKeySet<EXTENSION_DEGREE>,
    ksk: &LweKeyswitchKey<Vec<u64>>,
    ciphertext: &RadixOrBoolCiphertext,
) -> anyhow::Result<Z64>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Solve,
{
    let res = run_decryption_bitdec(session, prep, keyshares, ksk, ciphertext).await?;
    Ok(Wrapping(res))
}

// run decryption with bit-decomposition
#[instrument(
    name = "TFHE.Threshold-Dec-2",
    skip(session, prep, keyshares, ksk, ciphertext),
    fields(sid=?session.session_id(),batch_size=?ciphertext.len())
)]
pub async fn run_decryption_bitdec<
    const EXTENSION_DEGREE: usize,
    P: BitDecPreprocessing<EXTENSION_DEGREE> + Send + ?Sized,
    Ses: BaseSessionHandles,
    T,
>(
    session: &mut Ses,
    prep: &mut P,
    keyshares: &PrivateKeySet<EXTENSION_DEGREE>,
    ksk: &LweKeyswitchKey<Vec<u64>>,
    ciphertext: &RadixOrBoolCiphertext,
) -> anyhow::Result<T>
where
    T: tfhe::integer::block_decomposition::Recomposable
        + tfhe::core_crypto::commons::traits::CastFrom<u128>,
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Solve,
{
    let own_role = session.my_role();

    let mut shared_ptxts = Vec::with_capacity(ciphertext.len());
    for current_ct_block in ciphertext.blocks() {
        let partial_dec = partial_decrypt64(keyshares, ksk, current_ct_block)?;
        shared_ptxts.push(Share::new(own_role, partial_dec));
    }

    let bits = bit_dec_batch::<Z64, EXTENSION_DEGREE, P, _>(session, prep, shared_ptxts).await?;

    let total_bits = keyshares.parameters.total_block_bits() as usize;

    // bit-compose the plaintexts
    let ptxt_sums = BatchedBits::extract_ptxts(bits, total_bits, prep, session).await?;
    let ptxt_sums: Vec<_> = ptxt_sums.iter().map(|ptxt_sum| ptxt_sum.value()).collect();

    // output results
    let ptxts64 = open_bit_composed_ptxts(session, ptxt_sums).await?;
    let ptxts128: Vec<_> = ptxts64
        .iter()
        .map(|ptxt| Wrapping(ptxt.0 as u128))
        .collect();

    let usable_message_bits = keyshares.parameters.message_modulus_log() as usize;

    let shared_partial_decrypt = BlocksPartialDecrypt {
        bits_in_block: usable_message_bits as u32,
        partial_decryptions: ptxts128,
    };
    // combine outputs to form the decrypted integer on party 0
    combine_plaintext_blocks(shared_partial_decrypt)
}

/// A block
/// of [`BlocksPartialDecrypt`]
/// which is created by aggregating all the blocks
/// ensuring each have the same bit_in_block
/// for sanity
pub struct BlockPartialDecrypt {
    pub bits_in_block: u32,
    pub partial_decryption: Z128,
}

/// This is used as a task that is joined on to finish the
/// whole decryption process.
/// Run decryption with bit-decomposition at the raw ctxt level
/// - ciphertexts: a vector or blocks, each block may
/// belong to a different FheType ciphertext.
/// - preprocessings a vector of preprocessings,
/// each may have been created in a separate session
///
/// Returns a vector of decrypted raw ctxt,
/// each needs to be recombined with their other
/// blocks to finish the reconstruction
#[instrument(
    name = "TFHE.Threshold-Dec-2-task",
    skip(session, preprocessings, keyshares, ksk, ciphertexts),
    fields(sid=?session.session_id(),num_ctxts=?ciphertexts.len())
)]
pub async fn task_decryption_bitdec_par<
    const EXTENSION_DEGREE: usize,
    P: BitDecPreprocessing<EXTENSION_DEGREE> + Send,
    Ses: BaseSessionHandles,
    T,
>(
    session: &mut Ses,
    preprocessings: &mut [P],
    keyshares: &PrivateKeySet<EXTENSION_DEGREE>,
    ksk: &LweKeyswitchKey<Vec<u64>>,
    ciphertexts: Vec<Ciphertext>,
) -> anyhow::Result<Vec<BlockPartialDecrypt>>
where
    T: tfhe::integer::block_decomposition::Recomposable
        + tfhe::core_crypto::commons::traits::CastFrom<u128>,
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Solve,
{
    let role = session.my_role();
    // This vec will be joined on "main" task and all results recombined there
    let mut vec_partial_decryptions = Vec::new();
    if ciphertexts.len() != preprocessings.len() {
        return Err(anyhow_error_and_log(format!(
            "Expected {} preprocessings, got {}",
            ciphertexts.len(),
            preprocessings.len()
        )));
    }
    for (block, preprocessing) in ciphertexts.iter().zip_eq(preprocessings.iter_mut()) {
        //We create a batch of size 1
        let partial_decrypt = vec![Share::new(
            role,
            partial_decrypt64(keyshares, ksk, block).unwrap(),
        )];
        let bits =
            bit_dec_batch::<Z64, EXTENSION_DEGREE, _, _>(session, preprocessing, partial_decrypt)
                .await?;

        let total_bits = keyshares.parameters.total_block_bits() as usize;

        // bit-compose the plaintext
        let ptxt_sums =
            BatchedBits::extract_ptxts(bits, total_bits, preprocessing, session).await?;
        let ptxt_sums: Vec<_> = ptxt_sums.iter().map(|ptxt_sum| ptxt_sum.value()).collect();

        // output result
        let ptxts64 = open_bit_composed_ptxts(session, ptxt_sums).await?;
        let ptxts128: Vec<_> = ptxts64
            .iter()
            .map(|ptxt| Wrapping(ptxt.0 as u128))
            .collect();
        let usable_message_bits = keyshares.parameters.message_modulus_log() as usize;

        //We collect the only result in our batch of size 1
        let ptxt128 = ptxts128.first().context(format!(
            "Expected batch of size 1, got batch of size {}",
            ptxts128.len()
        ))?;
        let shared_partial_decrypt = BlockPartialDecrypt {
            bits_in_block: usable_message_bits as u32,
            partial_decryption: *ptxt128,
        };
        vec_partial_decryptions.push(shared_partial_decrypt);
    }
    Ok(vec_partial_decryptions)
}

/// computes b - <a, s> with no rounding of the noise. This is used for noise flooding decryption
pub fn partial_decrypt128<const EXTENSION_DEGREE: usize>(
    sk_share: &PrivateKeySet<EXTENSION_DEGREE>,
    ct: &SquashedNoiseCiphertext,
    ddec_key_type: SnsDecryptionKeyType,
) -> anyhow::Result<ResiduePoly<Z128, EXTENSION_DEGREE>>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
{
    let sns_secret_key = match ddec_key_type {
        SnsDecryptionKeyType::SnsKey => match &sk_share.glwe_secret_key_share_sns_as_lwe {
            Some(key) => key.data_as_raw_iter(),
            None => {
                return Err(anyhow_error_and_log(
                    "Missing the switch and squash secret key".to_string(),
                ))
            }
        },
        SnsDecryptionKeyType::SnsCompressionKey => {
            match &sk_share.glwe_sns_compression_key_as_lwe {
                Some(key) => key.data_as_raw_iter(),
                None => {
                    return Err(anyhow_error_and_log(
                        "Missing the switch and squash compression secret key".to_string(),
                    ))
                }
            }
        }
    };
    let ct = ct.lwe_ciphertext();
    let (mask, body) = ct.get_mask_and_body();

    let a_time_s = (sns_secret_key.zip_eq(mask.as_ref())).fold(
        ResiduePoly::<Z128, EXTENSION_DEGREE>::ZERO,
        |acc, (sk, m)| {
            let tmp =
                <ResiduePoly<Z128, EXTENSION_DEGREE> as Mul<Z128>>::mul(sk, Wrapping::<u128>(*m));
            acc + tmp
        },
    );
    // b-<a, s>
    let res = ResiduePoly::<Z128, EXTENSION_DEGREE>::from_scalar(Wrapping(*body.data)) - a_time_s;
    Ok(res)
}

// computes b - <a, s> + \Delta/2 for the bitwise decryption method
pub fn partial_decrypt64<const EXTENSION_DEGREE: usize>(
    sk_share: &PrivateKeySet<EXTENSION_DEGREE>,
    ksk: &LweKeyswitchKey<Vec<u64>>,
    ct_block: &tfhe::shortint::Ciphertext,
) -> anyhow::Result<ResiduePoly<Z64, EXTENSION_DEGREE>>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
{
    let ciphertext_modulus = 64;
    let mut output_ctxt;

    let pbs_order = match ct_block.atomic_pattern {
        tfhe::shortint::AtomicPatternKind::Standard(pbsorder) => pbsorder,
        tfhe::shortint::AtomicPatternKind::KeySwitch32 => PBSOrder::KeyswitchBootstrap,
    };

    //If ctype = F-GLWE we need to KS before doing the decryption
    let (mask, body) = if pbs_order == PBSOrder::KeyswitchBootstrap {
        output_ctxt = LweCiphertext::new(0, ksk.output_lwe_size(), ksk.ciphertext_modulus());
        keyswitch_lwe_ciphertext(ksk, &ct_block.ct, &mut output_ctxt);
        output_ctxt.get_mask_and_body()
    } else {
        ct_block.ct.get_mask_and_body()
    };

    let key_share64 = sk_share.lwe_compute_secret_key_share.data_as_raw_iter();
    let a_time_s = key_share64.zip_eq(mask.as_ref()).fold(
        ResiduePoly::<Z64, EXTENSION_DEGREE>::ZERO,
        |acc, (sk, m)| {
            let tmp =
                <ResiduePoly<Z64, EXTENSION_DEGREE> as Mul<Z64>>::mul(sk, Wrapping::<u64>(*m));
            acc + tmp
        },
    );

    // b-<a, s>
    // Compute Delta, taking into account that total_block_bits omits the additional padding bit
    let delta_pad_bits = ciphertext_modulus - (sk_share.parameters.total_block_bits() + 1);
    let delta_pad_half = 1_u64 << (delta_pad_bits - 1);
    let scalar_delta_half =
        ResiduePoly::<Z64, EXTENSION_DEGREE>::from_scalar(Wrapping(delta_pad_half));
    let res = ResiduePoly::<Z64, EXTENSION_DEGREE>::from_scalar(Wrapping(*body.data)) - a_time_s
        + scalar_delta_half;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use crate::algebra::structure_traits::{Derive, ErrorCorrect, Invert, Solve};
    use crate::execution::endpoints::decryption::{DecryptionMode, RadixOrBoolCiphertext};
    use crate::execution::sharing::shamir::RevealOp;
    use crate::execution::tfhe_internals::test_feature::{
        keygen_all_party_shares_from_keyset, KeySet,
    };
    use crate::networking::NetworkMode;
    use crate::{
        algebra::base_ring::{Z128, Z64},
        algebra::galois_rings::common::ResiduePoly,
        execution::{
            constants::SMALL_TEST_KEY_PATH,
            endpoints::decryption::threshold_decrypt64,
            runtime::{
                party::{Identity, Role},
                test_runtime::{generate_fixed_identities, DistributedTestRuntime},
            },
            sharing::{shamir::ShamirSharings, share::Share},
        },
        file_handling::tests::read_element,
    };
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use std::sync::Arc;
    use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
    use tfhe::{prelude::FheEncrypt, FheUint8};

    #[test]
    fn reconstruct_key() {
        let parties = 5;
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH).unwrap();
        let params = keyset.get_cpu_params().unwrap();
        let shares = keygen_all_party_shares_from_keyset::<_, 4>(
            &keyset,
            params,
            &mut AesRng::seed_from_u64(0),
            parties,
            1,
        )
        .unwrap();
        let mut first_bit_shares = Vec::with_capacity(parties);
        (0..parties).for_each(|i| {
            first_bit_shares.push(Share::new(
                Role::indexed_from_zero(i),
                *shares[i]
                    .glwe_secret_key_share_sns_as_lwe
                    .as_ref()
                    .unwrap()
                    .data_as_raw_vec()
                    .first()
                    .unwrap(),
            ));
        });
        let first_bit_sharing = ShamirSharings::create(first_bit_shares);
        let rec = first_bit_sharing.err_reconstruct(1, 0).unwrap();
        let inner_rec = rec.to_scalar().unwrap();
        assert_eq!(
            keyset
                .get_raw_glwe_client_sns_key()
                .unwrap()
                .into_container()[0],
            inner_rec.0
        );
    }

    #[test]
    fn test_large_threshold_decrypt_f4() {
        test_large_threshold_decrypt::<4>(1, 5, &[])
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn test_large_threshold_decrypt_f3() {
        test_large_threshold_decrypt::<3>(1, 5, &[])
    }

    #[cfg(feature = "extension_degree_5")]
    #[test]
    fn test_large_threshold_decrypt_f5() {
        test_large_threshold_decrypt::<5>(1, 5, &[])
    }

    #[cfg(feature = "extension_degree_6")]
    #[test]
    fn test_large_threshold_decrypt_f6() {
        test_large_threshold_decrypt::<6>(1, 5, &[])
    }

    #[cfg(feature = "extension_degree_7")]
    #[test]
    fn test_large_threshold_decrypt_f7() {
        test_large_threshold_decrypt::<7>(1, 5, &[])
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn test_large_threshold_decrypt_f8() {
        test_large_threshold_decrypt::<8>(1, 5, &[])
    }

    fn test_large_threshold_decrypt<const EXTENSION_DEGREE: usize>(
        threshold: usize,
        num_parties: usize,
        malicious_set: &[usize],
    ) where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
    {
        let msg: u8 = 3;
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH).unwrap();
        let params = keyset.get_cpu_params().unwrap();

        let mut rng = AesRng::seed_from_u64(42);
        // generate keys
        let key_shares =
            keygen_all_party_shares_from_keyset(&keyset, params, &mut rng, num_parties, threshold)
                .unwrap();
        let (ct, _id, _tag) = FheUint8::encrypt(msg, &keyset.client_key).into_raw_parts();

        let identities = generate_fixed_identities(num_parties);
        //Assumes Sync because preprocessing is part of the task
        let mut runtime = DistributedTestRuntime::<
            ResiduePoly<Z128, EXTENSION_DEGREE>,
            EXTENSION_DEGREE,
        >::new(identities, threshold as u8, NetworkMode::Sync, None);

        runtime.setup_server_key(Arc::new(keyset.public_keys.server_key.clone()));
        runtime.setup_sks(key_shares);

        let ct = RadixOrBoolCiphertext::Radix(ct);
        let results_dec = threshold_decrypt64(
            &runtime,
            &ct,
            DecryptionMode::NoiseFloodLarge,
            malicious_set,
        )
        .unwrap();
        let out_dec = &results_dec[&Identity("localhost".to_string(), 5000)];

        let ref_res = std::num::Wrapping(msg as u64);
        assert_eq!(*out_dec, ref_res);
    }

    #[test]
    fn test_small_threshold_decrypt_f4() {
        test_small_threshold_decrypt::<4>(1, 4, &[])
    }

    #[test]
    fn test_small_threshold_decrypt_malicious_f4() {
        test_small_threshold_decrypt::<4>(1, 4, &[1])
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn test_small_threshold_decrypt_f3() {
        test_small_threshold_decrypt::<3>(1, 4, &[])
    }

    #[cfg(feature = "extension_degree_5")]
    #[test]
    fn test_small_threshold_decrypt_f5() {
        test_small_threshold_decrypt::<5>(1, 4, &[])
    }

    #[cfg(feature = "extension_degree_6")]
    #[test]
    fn test_small_threshold_decrypt_f6() {
        test_small_threshold_decrypt::<6>(1, 4, &[])
    }

    #[cfg(feature = "extension_degree_7")]
    #[test]
    fn test_small_threshold_decrypt_f7() {
        test_small_threshold_decrypt::<7>(1, 4, &[])
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn test_small_threshold_decrypt_f8() {
        test_small_threshold_decrypt::<8>(1, 4, &[])
    }

    fn test_small_threshold_decrypt<const EXTENSION_DEGREE: usize>(
        threshold: usize,
        num_parties: usize,
        malicious_set: &[usize],
    ) where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
    {
        let msg: u8 = 3;
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH).unwrap();
        let params = keyset.get_cpu_params().unwrap();

        let mut rng = AesRng::seed_from_u64(42);
        // generate keys
        let key_shares =
            keygen_all_party_shares_from_keyset(&keyset, params, &mut rng, num_parties, threshold)
                .unwrap();
        let (ct, _id, _tag) = FheUint8::encrypt(msg, &keyset.client_key).into_raw_parts();

        let identities = generate_fixed_identities(num_parties);
        //Assumes Sync because preprocessing is part of the task
        let mut runtime = DistributedTestRuntime::<
            ResiduePoly<Z128, EXTENSION_DEGREE>,
            EXTENSION_DEGREE,
        >::new(identities, threshold as u8, NetworkMode::Sync, None);

        runtime.setup_sks(key_shares);
        runtime.setup_server_key(Arc::new(keyset.public_keys.server_key.clone()));

        let ct = RadixOrBoolCiphertext::Radix(ct);
        let results_dec = threshold_decrypt64(
            &runtime,
            &ct,
            DecryptionMode::NoiseFloodSmall,
            malicious_set,
        )
        .unwrap();
        let out_dec = &results_dec[&Identity("localhost".to_string(), 5000)];

        let ref_res = std::num::Wrapping(msg as u64);
        assert_eq!(*out_dec, ref_res);
    }

    #[test]
    fn test_small_bitdec_threshold_decrypt_f4() {
        test_small_bitdec_threshold_decrypt::<4>(1, 5, &[])
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn test_small_bitdec_threshold_decrypt_f3() {
        test_small_bitdec_threshold_decrypt::<3>(1, 5, &[])
    }

    #[cfg(feature = "extension_degree_5")]
    #[test]
    fn test_small_bitdec_threshold_decrypt_f5() {
        test_small_bitdec_threshold_decrypt::<5>(1, 5, &[])
    }

    #[cfg(feature = "extension_degree_6")]
    #[test]
    fn test_small_bitdec_threshold_decrypt_f6() {
        test_small_bitdec_threshold_decrypt::<6>(1, 5, &[])
    }

    #[cfg(feature = "extension_degree_7")]
    #[test]
    fn test_small_bitdec_threshold_decrypt_f7() {
        test_small_bitdec_threshold_decrypt::<7>(1, 5, &[])
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn test_small_bitdec_threshold_decrypt_f8() {
        test_small_bitdec_threshold_decrypt::<8>(1, 5, &[])
    }

    fn test_small_bitdec_threshold_decrypt<const EXTENSION_DEGREE: usize>(
        threshold: usize,
        num_parties: usize,
        malicious_set: &[usize],
    ) where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
    {
        let msg: u8 = 3;
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH).unwrap();
        let params = keyset.get_cpu_params().unwrap();

        let mut rng = AesRng::seed_from_u64(42);
        // generate keys
        let key_shares =
            keygen_all_party_shares_from_keyset(&keyset, params, &mut rng, num_parties, threshold)
                .unwrap();
        let (ct, _id, _tag) = FheUint8::encrypt(msg, &keyset.client_key).into_raw_parts();

        let identities = generate_fixed_identities(num_parties);
        //Assumes Sync because preprocessing is part of the task
        let mut runtime = DistributedTestRuntime::<
            ResiduePoly<Z64, EXTENSION_DEGREE>,
            EXTENSION_DEGREE,
        >::new(identities, threshold as u8, NetworkMode::Sync, None);

        runtime.setup_sks(key_shares);
        runtime.setup_ks(
            match &keyset
                .public_keys
                .server_key
                .as_ref()
                .as_ref()
                .atomic_pattern
            {
                AtomicPatternServerKey::Standard(ap) => Arc::new(ap.key_switching_key.clone()),
                AtomicPatternServerKey::KeySwitch32(_) => {
                    panic!("Unsupported KeySwitch32 AP",);
                }
                AtomicPatternServerKey::Dynamic(_) => {
                    panic!("Unsupported Dynamic AP",);
                }
            },
        );

        let ct = RadixOrBoolCiphertext::Radix(ct);
        let results_dec =
            threshold_decrypt64(&runtime, &ct, DecryptionMode::BitDecSmall, malicious_set).unwrap();
        let out_dec = &results_dec[&Identity("localhost".to_string(), 5000)];

        let ref_res = std::num::Wrapping(msg as u64);
        assert_eq!(*out_dec, ref_res);
    }

    #[test]
    fn test_large_bitdec_threshold_decrypt_f4() {
        test_large_bitdec_threshold_decrypt::<4>(1, 5, &[])
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn test_large_bitdec_threshold_decrypt_f3() {
        test_large_bitdec_threshold_decrypt::<3>(1, 5, &[])
    }

    #[cfg(feature = "extension_degree_5")]
    #[test]
    fn test_large_bitdec_threshold_decrypt_f5() {
        test_large_bitdec_threshold_decrypt::<5>(1, 5, &[])
    }

    #[cfg(feature = "extension_degree_6")]
    #[test]
    fn test_large_bitdec_threshold_decrypt_f6() {
        test_large_bitdec_threshold_decrypt::<6>(1, 5, &[])
    }

    #[cfg(feature = "extension_degree_7")]
    #[test]
    fn test_large_bitdec_threshold_decrypt_f7() {
        test_large_bitdec_threshold_decrypt::<7>(1, 5, &[])
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn test_large_bitdec_threshold_decrypt_f8() {
        test_large_bitdec_threshold_decrypt::<8>(1, 5, &[])
    }

    fn test_large_bitdec_threshold_decrypt<const EXTENSION_DEGREE: usize>(
        threshold: usize,
        num_parties: usize,
        malicious_set: &[usize],
    ) where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
    {
        let msg: u8 = 15;
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH).unwrap();
        let params = keyset.get_cpu_params().unwrap();

        let mut rng = AesRng::seed_from_u64(42);
        // generate keys
        let key_shares =
            keygen_all_party_shares_from_keyset(&keyset, params, &mut rng, num_parties, threshold)
                .unwrap();
        let (ct, _id, _tag) = FheUint8::encrypt(msg, &keyset.client_key).into_raw_parts();

        let identities = generate_fixed_identities(num_parties);
        //Assumes Sync because preprocessing is part of the task
        let mut runtime = DistributedTestRuntime::<
            ResiduePoly<Z64, EXTENSION_DEGREE>,
            EXTENSION_DEGREE,
        >::new(identities, threshold as u8, NetworkMode::Sync, None);

        runtime.setup_sks(key_shares);
        runtime.setup_ks(
            match &keyset
                .public_keys
                .server_key
                .as_ref()
                .as_ref()
                .atomic_pattern
            {
                AtomicPatternServerKey::Standard(ap) => Arc::new(ap.key_switching_key.clone()),
                AtomicPatternServerKey::KeySwitch32(_) => {
                    panic!("Unsupported KeySwitch32 AP",);
                }
                AtomicPatternServerKey::Dynamic(_) => {
                    panic!("Unsupported Dynamic AP",);
                }
            },
        );

        let ct = RadixOrBoolCiphertext::Radix(ct);
        let results_dec =
            threshold_decrypt64(&runtime, &ct, DecryptionMode::BitDecLarge, malicious_set).unwrap();
        let out_dec = &results_dec[&Identity("localhost".to_string(), 5000)];

        let ref_res = std::num::Wrapping(msg as u64);
        assert_eq!(*out_dec, ref_res);
    }
}
