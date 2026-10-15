use crate::config::BatchParams;
use crate::constants::B_SWITCH_SQUASH;
use crate::constants::LOG_B_SWITCH_SQUASH;
use crate::constants::STATSEC;
use crate::constants::{PDEC_INLINE_MAX_BLOCKS, PDEC_PAR_MIN_BLOCKS};
use crate::endpoints::decryption::RadixOrBoolCiphertext;
use crate::endpoints::decryption::SnsDecryptionKeyType;
use crate::endpoints::decryption::SnsRadixOrBoolCiphertext;
use crate::large_execution::offline::SecureLargePreprocessing;
use crate::online::bit_manipulation::{BatchedBits, bit_dec_batch};
use crate::online::preprocessing::BitDecPreprocessing;
use crate::online::preprocessing::InMemoryBitDecPreprocessing;
use crate::online::preprocessing::NoiseFloodPreprocessing;
use crate::online::preprocessing::memory::noiseflood::InMemoryNoiseFloodPreprocessing;
use crate::runtime::sessions::base_session::BaseSession;
use crate::runtime::sessions::base_session::BaseSessionHandles;
use crate::runtime::sessions::base_session::ToBaseSession;
use crate::runtime::sessions::large_session::LargeSession;
use crate::runtime::sessions::session_parameters::GenericParameterHandles;
#[cfg(any(test, feature = "testing"))]
use crate::runtime::sessions::session_parameters::SessionParameters;
use crate::runtime::sessions::small_session::SmallSession;
use crate::runtime::sessions::small_session::SmallSessionHandles;
use crate::sharing::open::{RobustOpen, SecureRobustOpen};
use crate::small_execution::offline::{Preprocessing, SecureSmallPreprocessing};
use crate::small_execution::prss::PRSSPrimitives;
use crate::tfhe_internals::lwe_key::LweSecretKeyShare;
use crate::tfhe_internals::parameters::AugmentedCiphertextParameters;
use crate::tfhe_internals::private_keysets::LweSecretKeyShareEnum;
#[cfg(any(test, feature = "testing"))]
use crate::{runtime::test_runtime::DistributedTestRuntime, small_execution::prf::PRSSConversions};
use algebra::{
    base_ring::{Z64, Z128},
    galois_rings::common::ResiduePoly,
    lincomb::LinearCombinator,
    sharing::share::Share,
    structure_traits::{Derive, ErrorCorrect, FromU128, Invert, Ring, Solve, Zero},
};
use anyhow::Context;
use async_trait::async_trait;
use error_utils::anyhow_error_and_log;
use itertools::Itertools;
#[cfg(any(test, feature = "testing"))]
use rand::SeedableRng;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::cell::RefCell;
#[cfg(any(test, feature = "testing"))]
use std::collections::HashMap;
#[cfg(any(test, feature = "testing"))]
use std::collections::HashSet;
use std::num::Wrapping;
use std::ops::Mul;
use std::sync::Arc;
use std::sync::Mutex;
use tfhe::core_crypto::prelude::{LweCiphertext, LweKeyswitchKey, keyswitch_lwe_ciphertext};
use tfhe::integer::ServerKey;
use tfhe::integer::noise_squashing::NoiseSquashingKey;
use tfhe::shortint::Ciphertext;
use tfhe::shortint::PBSOrder;
use tfhe::shortint::ciphertext::SquashedNoiseCiphertext;
use thread_handles::spawn_compute_bound;
#[cfg(any(test, feature = "testing"))]
use threshold_types::rng::AesRng;
use threshold_types::role::Role;
#[cfg(any(test, feature = "testing"))]
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant};
use tracing::instrument;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(any(test, feature = "testing"))]
use super::decryption::DecryptionMode;
use super::decryption::LowLevelCiphertext;
use super::reconstruct::{combine_decryptions, reconstruct_message};
use crate::tfhe_internals::private_keysets::PrivateKeySet;

/// A [`LowLevelCiphertext`] bundled with exactly the keys its variant needs to be
/// converted into a squashed-noise ciphertext.
///
/// The `Big*` variants are already squashed and need no keys; the `Small` variant
/// always carries the switch-and-squash keys (server key + noise squashing key).
/// This makes it impossible to call the noise-flooding decryption with a keyless
/// small ciphertext, and lets the production (`Big*`) path avoid touching — and
/// thus avoid lazily decompressing — those keys entirely.
pub enum LowLevelCiphertextAndKeys {
    BigCompressed(SnsRadixOrBoolCiphertext),
    BigStandard(SnsRadixOrBoolCiphertext),
    Small {
        ct: RadixOrBoolCiphertext,
        server_key: Arc<ServerKey>,
        ck: Arc<NoiseSquashingKey>,
    },
}

impl LowLevelCiphertextAndKeys {
    pub fn decryption_key_type(&self) -> SnsDecryptionKeyType {
        match self {
            Self::BigCompressed(_) => SnsDecryptionKeyType::SnsCompressionKey,
            Self::BigStandard(_) | Self::Small { .. } => SnsDecryptionKeyType::SnsKey,
        }
    }
}

impl LowLevelCiphertext {
    /// Attach the switch-and-squash keys needed to decrypt this ciphertext.
    ///
    /// `provide` is invoked **only** for the [`LowLevelCiphertext::Small`] variant —
    /// the `Big*` variants are already squashed and need no keys, so callers never
    /// fetch (and thus never trigger lazy decompression of) the keys on the
    /// production path.
    pub fn with_sns_keys<F>(self, provide: F) -> anyhow::Result<LowLevelCiphertextAndKeys>
    where
        F: FnOnce() -> anyhow::Result<(Arc<ServerKey>, Arc<NoiseSquashingKey>)>,
    {
        Ok(match self {
            LowLevelCiphertext::BigCompressed(ct) => LowLevelCiphertextAndKeys::BigCompressed(ct),
            LowLevelCiphertext::BigStandard(ct) => LowLevelCiphertextAndKeys::BigStandard(ct),
            LowLevelCiphertext::Small(ct) => {
                let (server_key, ck) = provide()?;
                LowLevelCiphertextAndKeys::Small { ct, server_key, ck }
            }
        })
    }
}

// NOTE: This whole trait system for noiseflood preproc is
// a bit convoluted and could probably be refactored to be simpler.
pub struct SmallOfflineNoiseFloodSession<
    const EXTENSION_DEGREE: usize,
    Ses: SmallSessionHandles<ResiduePoly<Z128, EXTENSION_DEGREE>>,
> where
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
{
    pub session: RefCell<Ses>,
}

pub struct LargeOfflineNoiseFloodSession<PreprocStrat> {
    pub session: RefCell<LargeSession>,
    _marker: std::marker::PhantomData<PreprocStrat>,
}

pub type SecureNoiseFloodLargeSession<Z> =
    LargeOfflineNoiseFloodSession<SecureLargePreprocessing<Z>>;

#[async_trait]
pub trait OfflineNoiseFloodSession<const EXTENSION_DEGREE: usize> {
    type SessionType: BaseSessionHandles;
    async fn init_prep_noiseflooding(
        &mut self,
        num_ctxt: usize,
    ) -> anyhow::Result<InMemoryNoiseFloodPreprocessing<EXTENSION_DEGREE>>;

    fn get_mut_base_session(&mut self) -> &mut BaseSession;

    fn new(session: Self::SessionType) -> Self;
}

#[async_trait]
impl<
    const EXTENSION_DEGREE: usize,
    Ses: SmallSessionHandles<ResiduePoly<Z128, EXTENSION_DEGREE>> + ToBaseSession,
> OfflineNoiseFloodSession<EXTENSION_DEGREE>
    for SmallOfflineNoiseFloodSession<EXTENSION_DEGREE, Ses>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    type SessionType = Ses;

    fn new(session: Self::SessionType) -> Self {
        SmallOfflineNoiseFloodSession {
            session: RefCell::new(session),
        }
    }

    /// Load precomputed init data for noise flooding.
    ///
    /// Note: this is actually a synchronous function. It just needs to be async to implement the trait (which is async in the Large case)
    async fn init_prep_noiseflooding(
        &mut self,
        num_ctxt: usize,
    ) -> anyhow::Result<InMemoryNoiseFloodPreprocessing<EXTENSION_DEGREE>> {
        let session = self.session.get_mut();
        let mut sns_preprocessing = InMemoryNoiseFloodPreprocessing::default();
        let own_role = session.my_role();

        let masks = self
            .session
            .get_mut()
            .prss_as_mut()
            .mask_next_vec(own_role, B_SWITCH_SQUASH, num_ctxt)
            .await?;
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
> OfflineNoiseFloodSession<EXTENSION_DEGREE> for LargeOfflineNoiseFloodSession<PreprocStrat>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
{
    type SessionType = LargeSession;

    fn new(session: Self::SessionType) -> Self {
        LargeOfflineNoiseFloodSession {
            session: RefCell::new(session),
            _marker: std::marker::PhantomData,
        }
    }

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
        P: NoiseFloodPreprocessing<EXTENSION_DEGREE> + 'static,
        T,
    >(
        session: &mut S,
        preprocessing: Arc<Mutex<P>>,
        keyshares: Arc<PrivateKeySet<EXTENSION_DEGREE>>,
        prepared_sns_keys: Arc<PreparedSnsKeys<EXTENSION_DEGREE>>,
        ciphertext: Arc<SnsRadixOrBoolCiphertext>,
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
    #[instrument(
        name = "TFHE.Threshold-Dec-1",
        skip(session, preprocessing, keyshares, prepared_sns_keys, ciphertext)
        fields(sid=?session.session_id(),batch_size=?ciphertext.len())
    )]
    async fn decrypt<
        S: BaseSessionHandles,
        P: NoiseFloodPreprocessing<EXTENSION_DEGREE> + 'static,
        T,
    >(
        session: &mut S,
        preprocessing: Arc<Mutex<P>>,
        keyshares: Arc<PrivateKeySet<EXTENSION_DEGREE>>,
        prepared_sns_keys: Arc<PreparedSnsKeys<EXTENSION_DEGREE>>,
        ciphertext: Arc<SnsRadixOrBoolCiphertext>,
        ddec_key_type: SnsDecryptionKeyType,
    ) -> anyhow::Result<T>
    where
        T: tfhe::integer::block_decomposition::Recomposable
            + tfhe::core_crypto::commons::traits::CastFrom<u128>,
        ResiduePoly<Z128, EXTENSION_DEGREE>: Invert + Solve + ErrorCorrect,
    {
        // Take the masks under the lock, then run the local decryption on the compute pool: it holds no lock
        // and borrows nothing from this task.
        let masks = {
            let mut preparation = preprocessing
                .lock()
                .map_err(|_| anyhow_error_and_log("Poisoned mutex guard"))?;
            preparation.next_mask_vec(ciphertext.len())?
        };
        let prepared_key = prepared_sns_keys.key(ddec_key_type)?;
        let shared_masked_ptxts = {
            let ciphertext = Arc::clone(&ciphertext);
            spawn_compute_bound(move || {
                masked_partial_decrypt_with(&prepared_key, &ciphertext, masks)
            })
            .await??
        };

        let partial_decrypted = open_masked_ptxts(session, shared_masked_ptxts, &keyshares).await?;
        let usable_message_bits =
            ciphertext.packing_factor() * keyshares.parameters.message_modulus_log() as usize;
        let shared_partial_decrypt = BlocksPartialDecrypt {
            bits_in_block: usable_message_bits as u32,
            partial_decryptions: partial_decrypted,
        };
        combine_plaintext_blocks(shared_partial_decrypt)
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
/// * `ct` - The ciphertext to be decrypted, bundled with the switch&squash keys
///   (server key + noise squashing key) that its `Small` variant requires; the
///   `Big*` variants carry no keys
/// * `secret_key_share` - The secret key share of the party_keyshare
///
/// # Returns
/// * A tuple containing the decrypted plaintext and the time it took to execute the decryption
///
/// # Remarks
/// The decryption protocol is executed in the following steps:
/// 1. The ciphertext is converted to a large ciphertext block
/// 2. The protocol preprocessing is initialized with the noise flooding
/// 3. The decryption is executed
/// 4. The results are returned
///
#[instrument(skip_all, fields(sid, my_role))]
pub async fn decrypt_using_noiseflooding<const EXTENSION_DEGREE: usize, P, O, T>(
    noiseflood_session: &mut P,
    ct: LowLevelCiphertextAndKeys,
    secret_key_share: Arc<PrivateKeySet<EXTENSION_DEGREE>>,
    prepared_sns_keys: Arc<PreparedSnsKeys<EXTENSION_DEGREE>>,
) -> anyhow::Result<(T, Duration)>
where
    P: OfflineNoiseFloodSession<EXTENSION_DEGREE>,
    O: OnlineNoiseFloodDecryption<EXTENSION_DEGREE>,
    T: tfhe::integer::block_decomposition::Recomposable
        + tfhe::core_crypto::commons::traits::CastFrom<u128>,
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    let execution_start_timer = Instant::now();
    let (ct_large, ddec_key_type) = switch_and_squash_for_partial_decrypt(ct).await?;

    let len = ct_large.len();
    let preprocessing = noiseflood_session.init_prep_noiseflooding(len).await?;
    let session = noiseflood_session.get_mut_base_session();
    let sid: u128 = session.session_id().into();
    tracing::Span::current().record("sid", sid);
    let my_role = session.my_role();
    tracing::Span::current().record("my_role", my_role.to_string());

    let outputs = O::decrypt::<_, _, T>(
        session,
        Arc::new(Mutex::new(preprocessing)),
        secret_key_share,
        prepared_sns_keys,
        Arc::new(ct_large),
        ddec_key_type,
    )
    .await?;

    tracing::info!(
        "Noiseflood result in session {:?} is ready",
        session.session_id()
    );

    let execution_stop_timer = Instant::now();
    let elapsed_time = execution_stop_timer.duration_since(execution_start_timer);
    Ok((outputs, elapsed_time))
}

/// Partially decrypts a ciphertext using noise flooding.
/// Each party outputs a masked share of the decrypted result.
///
/// This is the entry point of the user decryption protocol.
///
/// # Arguments
/// * `prss` - The PRSS state for the ciphertext's session and epoch. The caller must derive it
///   from the correct session ID and epoch.
/// * `my_role` - This party's role, which selects its PRSS masks.
/// * `ct` - The ciphertext to decrypt. Its `Small` variant carries the switch-and-squash keys;
///   the `Big*` variants are already noise-squashed and carry no keys.
/// * `prepared_sns_keys` - This party's SnS key shares prepared for the inner product (see
///   [`PreparedSnsKeys`]). `BigCompressed` uses the SnS compression key share; the other variants the SnS
///   key share.
///
/// # Returns
/// * A tuple with one masked partial decryption per packed block and the packing factor.
/// * The partial decryptions use [`Zeroizing`] because they contain this party's plaintext share.
///
/// # Remarks
/// The partial decryption protocol has these steps:
/// 1. Convert a `Small` ciphertext to the large form. The `Big*` variants need no conversion.
/// 2. Derive one noise-flooding mask per packed block from `prss` and `my_role`.
/// 3. Decrypt each block locally and add its mask, without opening the result.
/// 4. Return the masked shares and packing factor.
///
/// There is no online phase because all computation is local. This function creates no network
/// session and needs no trait similar to [`OnlineNoiseFloodDecryption`].
#[instrument(skip_all, fields(my_role = %my_role))]
pub async fn partial_decrypt_using_noiseflooding<const EXTENSION_DEGREE: usize, P>(
    prss: &mut P,
    my_role: Role,
    ct: LowLevelCiphertextAndKeys,
    prepared_sns_keys: &PreparedSnsKeys<EXTENSION_DEGREE>,
) -> anyhow::Result<(Zeroizing<Vec<ResiduePoly<Z128, EXTENSION_DEGREE>>>, u32)>
where
    P: PRSSPrimitives<ResiduePoly<Z128, EXTENSION_DEGREE>>,
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    let (ct_large, ddec_key_type) = switch_and_squash_for_partial_decrypt(ct).await?;
    let packing_factor = ct_large.packing_factor();
    let masks = prss
        .mask_next_vec(my_role, B_SWITCH_SQUASH, ct_large.len())
        .await?;
    let prepared_key = prepared_sns_keys.key(ddec_key_type)?;
    // The local decryption runs on the compute pool, like the mask derivation above.
    let shared_masked_ptxts =
        spawn_compute_bound(move || masked_partial_decrypt_with(&prepared_key, &ct_large, masks))
            .await??;
    Ok((shared_masked_ptxts, packing_factor as u32))
}

/// The SnS key shares of a [`PrivateKeySet`] prepared for the partial decryption inner product `<a, s>` (see
/// [`LinearCombinator`]: the share's coefficients as 52-bit limbs, read by the AVX-512 IFMA kernel without any
/// per-request work). Built once per key set by its owner, next to the key set, and passed to the decryption
/// entry points; `prepare` takes about 50 µs and 100 KB per thousand key coefficients. Both shares live behind
/// an `Arc`, so cloning is cheap and the compute pool can hold them.
#[derive(Clone, Debug)]
pub struct PreparedSnsKeys<const EXTENSION_DEGREE: usize> {
    sns: Option<Arc<LinearCombinator<ResiduePoly<Z128, EXTENSION_DEGREE>>>>,
    sns_compression: Option<Arc<LinearCombinator<ResiduePoly<Z128, EXTENSION_DEGREE>>>>,
}

impl<const EXTENSION_DEGREE: usize> PreparedSnsKeys<EXTENSION_DEGREE>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
{
    /// Prepares whichever SnS key shares `key_set` holds.
    pub fn prepare(key_set: &PrivateKeySet<EXTENSION_DEGREE>) -> Self {
        let prepare = |key: &LweSecretKeyShare<Z128, EXTENSION_DEGREE>| {
            Arc::new(LinearCombinator::for_scalars(key.data_iter()))
        };
        Self {
            sns: key_set
                .glwe_secret_key_share_sns_as_lwe
                .as_ref()
                .map(prepare),
            sns_compression: key_set
                .glwe_sns_compression_key_as_lwe
                .as_ref()
                .map(prepare),
        }
    }

    /// The prepared share selected by `ddec_key_type`.
    pub fn key(
        &self,
        ddec_key_type: SnsDecryptionKeyType,
    ) -> anyhow::Result<Arc<LinearCombinator<ResiduePoly<Z128, EXTENSION_DEGREE>>>> {
        let key = match ddec_key_type {
            SnsDecryptionKeyType::SnsKey => self.sns.as_ref().ok_or_else(|| {
                anyhow_error_and_log("Missing the switch and squash secret key".to_string())
            })?,
            SnsDecryptionKeyType::SnsCompressionKey => {
                self.sns_compression.as_ref().ok_or_else(|| {
                    anyhow_error_and_log(
                        "Missing the switch and squash compression secret key".to_string(),
                    )
                })?
            }
        };
        Ok(Arc::clone(key))
    }
}

/// `b - <a, s>` for every block of `ct_large` with the prepared key share `s`, plus one mask per block, in block
/// order. Each block is one [`LinearCombinator::dot`] (eight key coefficients per lane, accumulators in
/// registers for the whole inner product); blocks are independent and, above
/// [`PDEC_INLINE_MAX_BLOCKS`] of them, run in parallel on the Rayon pool in tasks of
/// [`PDEC_PAR_MIN_BLOCKS`].
pub fn masked_partial_decrypt_with<const EXTENSION_DEGREE: usize>(
    prepared_key: &LinearCombinator<ResiduePoly<Z128, EXTENSION_DEGREE>>,
    ct_large: &SnsRadixOrBoolCiphertext,
    masks: Vec<ResiduePoly<Z128, EXTENSION_DEGREE>>,
) -> anyhow::Result<Zeroizing<Vec<ResiduePoly<Z128, EXTENSION_DEGREE>>>>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
{
    let blocks: Vec<&SquashedNoiseCiphertext> = ct_large.packed_blocks().collect();
    if masks.len() != blocks.len() {
        return Err(anyhow_error_and_log(format!(
            "Expected {} masks for {} ciphertext blocks, got {}",
            blocks.len(),
            blocks.len(),
            masks.len()
        )));
    }
    for block in &blocks {
        let (mask, _) = block.lwe_ciphertext().get_mask_and_body();
        if mask.as_ref().len() != prepared_key.len() {
            return Err(anyhow_error_and_log(format!(
                "Ciphertext mask has {} coefficients but the key share has {}",
                mask.as_ref().len(),
                prepared_key.len()
            )));
        }
    }
    // The capacity is exact, so the vector never reallocates and leaves no unwiped copy.
    let mut shared_masked_ptxts = Zeroizing::new(Vec::with_capacity(blocks.len()));
    let partial_decrypt = |block: &&SquashedNoiseCiphertext| {
        let (mask, body) = block.lwe_ciphertext().get_mask_and_body();
        ResiduePoly::from_scalar(Wrapping(*body.data)) - prepared_key.dot(mask.as_ref())
    };
    let partial_decryptions: Vec<ResiduePoly<Z128, EXTENSION_DEGREE>> =
        if blocks.len() <= *PDEC_INLINE_MAX_BLOCKS {
            blocks.iter().map(partial_decrypt).collect()
        } else {
            blocks
                .par_iter()
                .with_min_len(*PDEC_PAR_MIN_BLOCKS)
                .map(partial_decrypt)
                .collect()
        };
    for (partial_decrypt, mask) in partial_decryptions.into_iter().zip(masks) {
        // TODO(https://github.com/zama-ai/kms-internal/issues/3159)
        // The unmasked `partial_decrypt` is not wiped. `ResiduePoly` is `Copy`,
        // so the compiler can leave copies of it on the stack. Also zeroize
        // conflicts with versioning. We need to resolve
        // github.com/zama-ai/kms-internal/issues/3176 (removing Copy) and
        // github.com/zama-ai/tfhe-rs-internal/issues/1535 (versioning conflict with zeroize).
        shared_masked_ptxts.push(partial_decrypt + mask);
    }
    Ok(shared_masked_ptxts)
}

/// Brings a ciphertext to the large (noise-squashed) form that partial decryption works on.
async fn switch_and_squash_for_partial_decrypt(
    ct: LowLevelCiphertextAndKeys,
) -> anyhow::Result<(SnsRadixOrBoolCiphertext, SnsDecryptionKeyType)> {
    let ddec_key_type = ct.decryption_key_type();
    let ct_large = match ct {
        LowLevelCiphertextAndKeys::BigCompressed(ct128) => ct128,
        LowLevelCiphertextAndKeys::BigStandard(ct128) => ct128,
        LowLevelCiphertextAndKeys::Small { ct, server_key, ck } => match ct {
            RadixOrBoolCiphertext::Radix(base_radix_ciphertext) => SnsRadixOrBoolCiphertext::Radix(
                spawn_compute_bound(move || {
                    ck.squash_radix_ciphertext_noise(&server_key, &base_radix_ciphertext)
                })
                .await??,
            ),
            RadixOrBoolCiphertext::Bool(boolean_block) => SnsRadixOrBoolCiphertext::Bool(
                spawn_compute_bound(move || {
                    ck.squash_boolean_block_noise(&server_key, &boolean_block)
                })
                .await??,
            ),
        },
    };
    Ok((ct_large, ddec_key_type))
}

/// Locally partially decrypts every packed block of `ct_large` and masks it with the next
/// noise-flooding masks from `preparation`, synchronously on the calling thread. The request entry points
/// take the masks first and run [`masked_partial_decrypt_with`] on the compute pool instead.
pub fn masked_partial_decrypt<const EXTENSION_DEGREE: usize>(
    prepared_sns_keys: &PreparedSnsKeys<EXTENSION_DEGREE>,
    ct_large: &SnsRadixOrBoolCiphertext,
    ddec_key_type: SnsDecryptionKeyType,
    preparation: &mut impl NoiseFloodPreprocessing<EXTENSION_DEGREE>,
) -> anyhow::Result<Zeroizing<Vec<ResiduePoly<Z128, EXTENSION_DEGREE>>>>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    let masks = preparation.next_mask_vec(ct_large.len())?;
    let prepared_key = prepared_sns_keys.key(ddec_key_type)?;
    masked_partial_decrypt_with(&prepared_key, ct_large, masks)
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
///
/// # Returns
/// * A tuple containing the decrypted plaintext and the time it took to execute the decryption
///
/// # Remarks
/// The decryption protocol is executed in the following steps:
/// 1. The protocol preprocessing is initialized and the required number of random bits and triples are generated.
/// 2. The decryption protocol is executed
/// 3. The results are returned
///
#[instrument(skip_all, fields(session_id = ?session.session_id(), my_role = ?session.my_role()))]
pub async fn secure_decrypt_using_bitdec<const EXTENSION_DEGREE: usize, T>(
    session: &mut SmallSession<ResiduePoly<Z64, EXTENSION_DEGREE>>,
    ct: &RadixOrBoolCiphertext,
    secret_key_share: &PrivateKeySet<EXTENSION_DEGREE>,
    ksk: &LweKeyswitchKey<Vec<u64>>,
) -> anyhow::Result<(T, Duration)>
where
    T: tfhe::integer::block_decomposition::Recomposable
        + tfhe::core_crypto::commons::traits::CastFrom<u128>,
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    let execution_start_timer = Instant::now();

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

    let execution_stop_timer = Instant::now();
    let elapsed_time = execution_stop_timer.duration_since(execution_start_timer);
    Ok((outputs, elapsed_time))
}

/// Partially decrypt a ciphertext using bit decomposition.
/// Partially here means that each party outputs a share of the decrypted result.
///
/// Returns this party's share of the plaintext.
///
/// This is the entry point of the User decryption protocol.
///
/// # Arguments
/// * `session` - The session object that contains the networking and the role of the party_keyshare
/// * `ct` - The ciphertext to be decrypted
/// * `secret_key_share` - The secret key share of the party_keyshare
/// * `ksk` - The public keyswitch key
///
/// # Returns
/// * The partial decryptions are wrapped in [`Zeroizing`] because they are this party's share of the plaintext
///
/// # Remarks
/// The partial decryption protocol is executed in the following steps:
/// 1. The protocol preprocessing is initialized and the required number of random bits and triples are generated.
/// 2. The partial interactive decryption is executed, without opening the result in the last step
/// 4. The results are returned
///
#[instrument(skip_all, fields(session_id = ?session.session_id(), my_role = ?session.my_role()))]
pub async fn secure_partial_decrypt_using_bitdec<const EXTENSION_DEGREE: usize>(
    session: &mut SmallSession<ResiduePoly<Z64, EXTENSION_DEGREE>>,
    ct: &RadixOrBoolCiphertext,
    secret_key_share: &PrivateKeySet<EXTENSION_DEGREE>,
    ksk: &LweKeyswitchKey<Vec<u64>>,
) -> anyhow::Result<Zeroizing<Vec<ResiduePoly<Z64, EXTENSION_DEGREE>>>>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    let sid = session.session_id();
    let own_role = session.my_role();
    let mut prep = secure_init_prep_bitdec_small_session(session, ct.len()).await?;

    // TODO(github.com/zama-ai/kms-internal/issues/3159)
    // Neither `partial_dec` nor `pdec_blocks` is zeroized. `ResiduePoly` is `Copy`, so the
    // compiler can leave copies of `partial_dec` that `Zeroize` cannot reach.
    // Also ZeroizeOnDrop conflicts with versioning. We need to resolve
    // github.com/zama-ai/kms-internal/issues/3176 (removing Copy) and
    // github.com/zama-ai/tfhe-rs-internal/issues/1535 (versioning conflict with zeroize).
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
    let ptxt_sums =
        Zeroizing::new(BatchedBits::extract_ptxts(bits, total_bits, &mut prep, session).await?);
    let ptxt_sums: Zeroizing<Vec<_>> =
        Zeroizing::new(ptxt_sums.iter().map(|ptxt_sum| ptxt_sum.value()).collect());

    tracing::info!("Bitdec result in session {:?} is ready", sid);

    Ok(ptxt_sums)
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

/// Wipes the opened plaintext blocks.
impl Zeroize for BlocksPartialDecrypt {
    fn zeroize(&mut self) {
        // `bits_in_block` is public metadata.
        self.partial_decryptions.zeroize();
    }
}

impl Drop for BlocksPartialDecrypt {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for BlocksPartialDecrypt {}
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
        &shared_partial_decrypt.partial_decryptions,
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
    use crate::{
        runtime::sessions::{
            session_parameters::GenericParameterHandles, small_session::SmallSession,
        },
        small_execution::prss::{AbortSecurePrssInit, DerivePRSSState, PRSSInit},
    };
    let session_id = base_session.session_id();

    let prss_setup = AbortSecurePrssInit::default()
        .init(&mut base_session)
        .await
        .unwrap();
    let prss_state = prss_setup
        .new_prss_session_state(session_id, base_session.my_role())
        .unwrap();
    SmallSession::new_from_prss_state(base_session, prss_state).unwrap()
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

#[cfg(any(test, feature = "testing"))]
pub async fn threshold_decrypt64<Z: Ring, const EXTENSION_DEGREE: usize>(
    runtime: &DistributedTestRuntime<Z, Role, EXTENSION_DEGREE>,
    ct: &RadixOrBoolCiphertext,
    mode: DecryptionMode,
) -> anyhow::Result<HashMap<Role, Z64>>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
{
    threshold_decrypt64_maybe_malicious::<Z, SecureOnlineNoiseFloodDecryption, EXTENSION_DEGREE>(
        runtime,
        ct,
        mode,
        HashSet::new(),
    )
    .await
}

/// Test the threshold decryption for a given 64-bit TFHE-rs ciphertext
///
/// NOTE: Trait bounds are a bit odd here because this function does a bit too many things
/// at once
///
/// The malicious set is a list of party indices (starting at 0)
/// that will run (potentially) decryption protocol defined by the MalDec trait.
#[cfg(any(test, feature = "testing"))]
async fn threshold_decrypt64_maybe_malicious<
    Z: Ring,
    MalDec: OnlineNoiseFloodDecryption<EXTENSION_DEGREE>,
    const EXTENSION_DEGREE: usize,
>(
    runtime: &DistributedTestRuntime<Z, Role, EXTENSION_DEGREE>,
    ct: &RadixOrBoolCiphertext,
    mode: DecryptionMode,
    malicious_set: HashSet<Role>,
) -> anyhow::Result<HashMap<Role, Z64>>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
{
    use threshold_types::session_id::SessionId;
    let session_id = SessionId::new(ct)?;

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

    for role in runtime.roles.clone().into_iter() {
        let roles = runtime.roles.clone();
        let net = runtime.user_nets[&role].clone();
        let threshold = runtime.threshold;
        let ct = ct.clone();
        let malicious_set = malicious_set.clone();

        let party_keyshare = runtime
            .keyshares
            .clone()
            .map(|ks| ks[role.one_based() - 1].clone())
            .ok_or_else(|| {
                anyhow_error_and_log("key share not set during decryption".to_string())
            })?;

        let large_ct = large_ct.clone();

        tracing::info!(
            "party {}: starting threshold decrypt with mode {}",
            role,
            mode
        );

        let session_params = SessionParameters::new(threshold, session_id, role, roles).unwrap();
        let base_session = BaseSession::new(session_params, net, AesRng::from_entropy()).unwrap();

        match mode {
            DecryptionMode::NoiseFloodSmall => {
                let large_ct = large_ct.unwrap();
                set.spawn(async move {
                    let session =
                        setup_small_session::<ResiduePoly<Z128, EXTENSION_DEGREE>>(base_session)
                            .await;

                    let mut session_noiseflood = SmallOfflineNoiseFloodSession::new(session);
                    let noiseflood_preprocessing = session_noiseflood
                        .init_prep_noiseflooding(ct.len())
                        .await
                        .unwrap();
                    let out = if malicious_set.contains(&role) {
                        run_decryption_noiseflood_64::<EXTENSION_DEGREE, _, _, MalDec>(
                            session_noiseflood.session.get_mut(),
                            Arc::new(Mutex::new(noiseflood_preprocessing)),
                            Arc::new(party_keyshare),
                            Arc::new(large_ct),
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
                            Arc::new(Mutex::new(noiseflood_preprocessing)),
                            Arc::new(party_keyshare),
                            Arc::new(large_ct),
                            SnsDecryptionKeyType::SnsKey,
                        )
                        .await
                        .unwrap()
                    };

                    (role, out)
                });
            }
            DecryptionMode::NoiseFloodLarge => {
                let large_ct = large_ct.unwrap();
                set.spawn(async move {
                    let session = LargeSession::new(base_session);
                    let mut session_noiseflood = SecureNoiseFloodLargeSession::new(session);
                    let noiseflood_preprocessing = session_noiseflood
                        .init_prep_noiseflooding(ct.len())
                        .await
                        .unwrap();
                    let out = if malicious_set.contains(&role) {
                        run_decryption_noiseflood_64::<EXTENSION_DEGREE, _, _, MalDec>(
                            session_noiseflood.session.get_mut(),
                            Arc::new(Mutex::new(noiseflood_preprocessing)),
                            Arc::new(party_keyshare),
                            Arc::new(large_ct),
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
                            Arc::new(Mutex::new(noiseflood_preprocessing)),
                            Arc::new(party_keyshare),
                            Arc::new(large_ct),
                            SnsDecryptionKeyType::SnsKey,
                        )
                        .await
                        .unwrap()
                    };

                    (role, out)
                });
            }
            DecryptionMode::BitDecLarge => {
                let ks_key = runtime.get_ks_key();
                set.spawn(async move {
                    let mut session = LargeSession::new(base_session);
                    let mut prep = secure_init_prep_bitdec_large_session(&mut session, ct.len())
                        .await
                        .unwrap();
                    let out = if malicious_set.contains(&role) {
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

                    (role, out)
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
                    let out = if malicious_set.contains(&role) {
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
                    (role, out)
                });
            }
        }
    }

    let mut results = HashMap::new();
    while let Some(v) = set.join_next().await {
        let (role, val) = v.unwrap();
        results.insert(role, val);
    }

    Ok(results)
}

async fn open_masked_ptxts<const EXTENSION_DEGREE: usize, S: BaseSessionHandles>(
    session: &S,
    mut res: Zeroizing<Vec<ResiduePoly<Z128, EXTENSION_DEGREE>>>,
    keyshares: &PrivateKeySet<EXTENSION_DEGREE>,
) -> anyhow::Result<Vec<Z128>>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
{
    // Transfer the masked shares into the public opening without copying the allocation.
    let shares = std::mem::take(&mut *res);
    let opened = SecureRobustOpen::default()
        .robust_open_list_to_all(session, shares, session.threshold() as usize)
        .await?;
    reconstruct_message(opened, &keyshares.parameters)
}

async fn open_bit_composed_ptxts<Z, const EXTENSION_DEGREE: usize, S: BaseSessionHandles>(
    session: &S,
    res: Vec<ResiduePoly<Z64, EXTENSION_DEGREE>>,
) -> anyhow::Result<Vec<Z>>
where
    Z: FromU128,
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
{
    let mut out = Vec::with_capacity(res.len());
    let opened = SecureRobustOpen::default()
        .robust_open_list_to_all(session, res, session.threshold() as usize)
        .await?;

    match opened {
        Some(openeds) => {
            for open in openeds {
                let v_scalar = open.to_scalar()?;
                out.push(Z::from_u128(v_scalar.0 as u128));
            }
        }
        _ => {
            return Err(anyhow_error_and_log(
                "Error receiving shares for reconstructing bit-composed message".to_string(),
            ));
        }
    };
    Ok(out)
}

pub async fn run_decryption_noiseflood_64<
    const EXTENSION_DEGREE: usize,
    S: BaseSessionHandles,
    P: NoiseFloodPreprocessing<EXTENSION_DEGREE> + 'static,
    O: OnlineNoiseFloodDecryption<EXTENSION_DEGREE>,
>(
    session: &mut S,
    preprocessing: Arc<Mutex<P>>,
    keyshares: Arc<PrivateKeySet<EXTENSION_DEGREE>>,
    ciphertext: Arc<SnsRadixOrBoolCiphertext>,
    ddec_key_type: SnsDecryptionKeyType,
) -> anyhow::Result<Z64>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: Invert + Solve + ErrorCorrect,
{
    // Test and experiment helper: the key share is prepared per call rather than kept with the key set.
    let prepared_sns_keys = Arc::new(PreparedSnsKeys::prepare(&keyshares));
    let res = O::decrypt::<_, _, u64>(
        session,
        preprocessing,
        keyshares,
        prepared_sns_keys,
        ciphertext,
        ddec_key_type,
    )
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
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
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
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
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
    let ptxts128 = open_bit_composed_ptxts::<Z128, _, _>(session, ptxt_sums).await?;

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
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
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
        let ptxts128 = open_bit_composed_ptxts::<Z128, _, _>(session, ptxt_sums).await?;
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
    prepared_sns_keys: &PreparedSnsKeys<EXTENSION_DEGREE>,
    ct: &SquashedNoiseCiphertext,
    ddec_key_type: SnsDecryptionKeyType,
) -> anyhow::Result<ResiduePoly<Z128, EXTENSION_DEGREE>>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
{
    let prepared_key = prepared_sns_keys.key(ddec_key_type)?;
    let (mask, body) = ct.lwe_ciphertext().get_mask_and_body();
    if mask.as_ref().len() != prepared_key.len() {
        return Err(anyhow_error_and_log(format!(
            "Ciphertext mask has {} coefficients but the key share has {}",
            mask.as_ref().len(),
            prepared_key.len()
        )));
    }
    let a_time_s = prepared_key.dot(mask.as_ref());
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
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
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

    let key_share64 = match &sk_share.lwe_compute_secret_key_share {
        LweSecretKeyShareEnum::Z64(key) => key,
        LweSecretKeyShareEnum::Z128(_) => {
            // NOTE: We turn the key to it's Z64 representation here instead of erroring out
            // but would be very inefficient to do this for every decrypt.
            // If we ever use this path in production, we should consider caching the Z64 version of the key share instead.
            tracing::warn!("Switching to Z64 key during decrypt, very much not optimal",);
            &sk_share
                .lwe_compute_secret_key_share
                .clone()
                .convert_to_z64()
        }
    };
    let key_share64_iter = key_share64.data_iter();
    let a_time_s = key_share64_iter.zip_eq(mask.as_ref()).fold(
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

/// Synthetic material for tests and benchmarks of the local partial decryption: random key shares and
/// squashed-noise ciphertexts of a chosen dimension, without any key generation.
#[cfg(any(test, feature = "testing"))]
pub mod synthetic {
    use super::*;
    use crate::tfhe_internals::lwe_key::LweSecretKeyShare;
    use crate::tfhe_internals::parameters::DKGParams;
    use rand::Rng;
    use tfhe::core_crypto::prelude::{CiphertextModulus, LweCiphertextOwned};
    use tfhe::integer::ciphertext::SquashedNoiseRadixCiphertext;

    /// A dummy key set whose SnS key shares (both kinds) are `lwe_dimension` random ring elements.
    pub fn private_key_set<const EXTENSION_DEGREE: usize>(
        rng: &mut impl Rng,
        params: DKGParams,
        lwe_dimension: usize,
    ) -> PrivateKeySet<EXTENSION_DEGREE>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
    {
        let mut key_set = PrivateKeySet::<EXTENSION_DEGREE>::init_dummy(params);
        let random_share = |rng: &mut dyn rand::RngCore| {
            let data = (0..lwe_dimension)
                .map(|_| {
                    Share::new(
                        Role::indexed_from_one(1),
                        ResiduePoly::<Z128, EXTENSION_DEGREE>::from_u128_iter(
                            (0..EXTENSION_DEGREE).map(|_| rng.r#gen::<u128>()),
                        ),
                    )
                })
                .collect();
            LweSecretKeyShare { data }
        };
        key_set.glwe_secret_key_share_sns_as_lwe = Some(random_share(rng));
        key_set.glwe_sns_compression_key_as_lwe = Some(random_share(rng));
        key_set
    }

    /// A radix ciphertext of `blocks` random packed blocks over an LWE dimension of `lwe_dimension`.
    pub fn squashed_radix_ciphertext(
        rng: &mut impl Rng,
        blocks: usize,
        lwe_dimension: usize,
    ) -> SnsRadixOrBoolCiphertext {
        // The constructors of tfhe-rs's squashed-noise ciphertexts are crate-private, so the blocks are built
        // through their (plain, positional) serde encoding from a struct with the same fields.
        #[derive(serde::Serialize)]
        struct Block {
            ct: LweCiphertextOwned<u128>,
            degree: u64,
            message_modulus: u64,
            carry_modulus: u64,
        }
        #[derive(serde::Serialize)]
        struct Radix {
            packed_blocks: Vec<Block>,
            original_block_count: usize,
        }
        let packed_blocks = (0..blocks)
            .map(|_| Block {
                ct: LweCiphertextOwned::from_container(
                    (0..lwe_dimension + 1)
                        .map(|_| rng.r#gen::<u128>())
                        .collect(),
                    CiphertextModulus::new_native(),
                ),
                degree: 3,
                message_modulus: 4,
                carry_modulus: 4,
            })
            .collect();
        let bytes = bc2wrap::serialize(&Radix {
            packed_blocks,
            original_block_count: 2 * blocks,
        })
        .expect("serializing a synthetic ciphertext");
        SnsRadixOrBoolCiphertext::Radix(
            bc2wrap::deserialize_slice::<SquashedNoiseRadixCiphertext>(&bytes)
                .expect("deserializing a synthetic ciphertext"),
        )
    }

    /// The reference `b - <a, s>` of one block: the plain fold with the ring's scalar multiplication.
    pub fn partial_decrypt128_fold<const EXTENSION_DEGREE: usize>(
        key_share: &LweSecretKeyShare<Z128, EXTENSION_DEGREE>,
        block: &SquashedNoiseCiphertext,
    ) -> ResiduePoly<Z128, EXTENSION_DEGREE>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let (mask, body) = block.lwe_ciphertext().get_mask_and_body();
        let a_time_s = key_share.data_iter().zip_eq(mask.as_ref()).fold(
            ResiduePoly::<Z128, EXTENSION_DEGREE>::ZERO,
            |acc, (sk, m)| {
                acc + <ResiduePoly<Z128, EXTENSION_DEGREE> as Mul<Z128>>::mul(
                    sk,
                    Wrapping::<u128>(*m),
                )
            },
        );
        ResiduePoly::<Z128, EXTENSION_DEGREE>::from_scalar(Wrapping(*body.data)) - a_time_s
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LowLevelCiphertextAndKeys, OfflineNoiseFloodSession, PreparedSnsKeys,
        SmallOfflineNoiseFloodSession, masked_partial_decrypt, masked_partial_decrypt_with,
        partial_decrypt_using_noiseflooding, partial_decrypt128, synthetic,
        threshold_decrypt64_maybe_malicious,
    };
    use crate::endpoints::decryption::{
        DecryptionMode, RadixOrBoolCiphertext, SnsDecryptionKeyType, SnsRadixOrBoolCiphertext,
    };
    use crate::malicious_execution::endpoints::decryption::DroppingOnlineNoiseFloodDecryption;
    use crate::runtime::sessions::{
        session_parameters::GenericParameterHandles, small_session::SmallSession,
    };
    use crate::small_execution::prss::{DerivePRSSState, PRSSSetup};
    use crate::tests::helper::testing::{
        get_dummy_prss_setup, get_networkless_base_session_for_parties,
    };
    use crate::tfhe_internals::test_feature::{
        ClientKeyView, KeySet, keygen_all_party_shares_from_client_key,
    };
    use crate::{
        constants::SMALL_TEST_KEY_PATH,
        runtime::test_runtime::{DistributedTestRuntime, generate_fixed_roles},
        tests::ensure_test_data_setup,
    };
    use algebra::PRSSConversions;
    use algebra::{
        base_ring::{Z64, Z128},
        galois_rings::common::ResiduePoly,
        sharing::{
            shamir::{RevealOp, ShamirSharings},
            share::Share,
        },
        structure_traits::{Derive, ErrorCorrect, Invert, Solve},
    };
    use rand::{Rng, SeedableRng};
    use std::{collections::HashSet, sync::Arc};
    use test_utils::read_element;
    use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
    use tfhe::{
        FheUint8,
        prelude::{FheEncrypt, SquashNoise},
    };
    use threshold_types::network::NetworkMode;
    use threshold_types::rng::AesRng;
    use threshold_types::role::Role;
    use threshold_types::session_id::SessionId;

    #[test]
    fn reconstruct_key() {
        ensure_test_data_setup();
        let parties = 5;
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH).unwrap();
        let params = keyset.get_cpu_params().unwrap();
        let shares = keygen_all_party_shares_from_client_key::<_, 4>(
            &keyset.client_key,
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
                shares[i]
                    .glwe_secret_key_share_sns_as_lwe
                    .as_ref()
                    .unwrap()
                    .data_iter()
                    .next()
                    .unwrap(),
            ));
        });
        let first_bit_sharing = ShamirSharings::create(first_bit_shares);
        let rec = first_bit_sharing.error_reconstruct(1, 0).unwrap();
        let inner_rec = rec.to_scalar().unwrap();
        assert_eq!(
            ClientKeyView::new(&keyset.client_key)
                .raw_glwe_client_sns_key()
                .unwrap()
                .into_container()[0],
            inner_rec.0
        );
    }

    #[tokio::test]
    async fn test_large_threshold_decrypt_f4() {
        test_large_threshold_decrypt::<4>(1, 5, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_large_threshold_decrypt_f3() {
        test_large_threshold_decrypt::<3>(1, 5, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_large_threshold_decrypt_f5() {
        test_large_threshold_decrypt::<5>(1, 5, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_large_threshold_decrypt_f6() {
        test_large_threshold_decrypt::<6>(1, 5, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_large_threshold_decrypt_f7() {
        test_large_threshold_decrypt::<7>(1, 5, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_large_threshold_decrypt_f8() {
        test_large_threshold_decrypt::<8>(1, 5, HashSet::new()).await
    }

    async fn test_large_threshold_decrypt<const EXTENSION_DEGREE: usize>(
        threshold: usize,
        num_parties: usize,
        malicious_set: HashSet<Role>,
    ) where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
    {
        ensure_test_data_setup();
        let msg: u8 = 3;
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH).unwrap();
        let params = keyset.get_cpu_params().unwrap();

        let mut rng = AesRng::seed_from_u64(42);
        // generate keys
        let key_shares = keygen_all_party_shares_from_client_key(
            &keyset.client_key,
            params,
            &mut rng,
            num_parties,
            threshold,
        )
        .unwrap();
        let (ct, _id, _tag, _rerand_metadata) =
            FheUint8::encrypt(msg, &keyset.client_key).into_raw_parts();

        let roles = generate_fixed_roles(num_parties);
        //Assumes Sync because preprocessing is part of the task
        let mut runtime = DistributedTestRuntime::<
            ResiduePoly<Z128, EXTENSION_DEGREE>,
            Role,
            EXTENSION_DEGREE,
        >::new(roles, threshold as u8, NetworkMode::Sync, None);

        runtime.setup_server_key(Arc::new(keyset.public_keys.server_key.clone()));
        runtime.setup_sks(key_shares);

        let ct = RadixOrBoolCiphertext::Radix(ct);
        let results_dec = threshold_decrypt64_maybe_malicious::<
            _,
            DroppingOnlineNoiseFloodDecryption,
            EXTENSION_DEGREE,
        >(
            &runtime,
            &ct,
            DecryptionMode::NoiseFloodLarge,
            malicious_set.clone(),
        )
        .await
        .unwrap();
        assert!(!malicious_set.contains(&Role::indexed_from_one(1)));
        let out_dec = &results_dec[&Role::indexed_from_one(1)];

        let ref_res = std::num::Wrapping(msg as u64);
        assert_eq!(*out_dec, ref_res);
    }

    #[tokio::test]
    async fn test_small_threshold_decrypt_f4() {
        test_small_threshold_decrypt::<4>(1, 4, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_small_threshold_decrypt_malicious_f4() {
        test_small_threshold_decrypt::<4>(1, 4, HashSet::from([Role::indexed_from_zero(1)])).await
    }

    #[tokio::test]
    async fn test_small_threshold_decrypt_f3() {
        test_small_threshold_decrypt::<3>(1, 4, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_small_threshold_decrypt_f5() {
        test_small_threshold_decrypt::<5>(1, 4, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_small_threshold_decrypt_f6() {
        test_small_threshold_decrypt::<6>(1, 4, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_small_threshold_decrypt_f7() {
        test_small_threshold_decrypt::<7>(1, 4, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_small_threshold_decrypt_f8() {
        test_small_threshold_decrypt::<8>(1, 4, HashSet::new()).await
    }

    /// A partial decryption and its packing factor.
    type PDecOutput = (Vec<ResiduePoly<Z128, 4>>, u32);

    /// Runs partial decryption through session preprocessing and direct PRSS derivation on the
    /// same ciphertext. Returns the session result first and the direct PRSS result second.
    /// The session path uses ID 1; `prss_session_id` selects the direct PRSS state.
    fn partial_decrypt_both_ways(
        prss_session_id: SessionId,
        key_type: SnsDecryptionKeyType,
    ) -> (PDecOutput, PDecOutput) {
        ensure_test_data_setup();
        let (num_parties, threshold) = (4, 1);
        let role = Role::indexed_from_one(1);
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH).unwrap();
        let params = keyset.get_cpu_params().unwrap();
        let key_shares = keygen_all_party_shares_from_client_key::<_, 4>(
            &keyset.client_key,
            params,
            &mut AesRng::seed_from_u64(0),
            num_parties,
            threshold,
        )
        .unwrap();
        let key_share = &key_shares[role.one_based() - 1];
        let prepared_sns_keys = PreparedSnsKeys::prepare(key_share);

        let ct = FheUint8::encrypt(3_u8, &keyset.client_key);
        let server_key = &keyset.public_keys.server_key;
        let large_ct = match key_type {
            SnsDecryptionKeyType::SnsKey => {
                let (ct, _id, _tag, _rerand_metadata) = ct.into_raw_parts();
                let int_server_key: &tfhe::integer::ServerKey = server_key.as_ref();
                SnsRadixOrBoolCiphertext::Radix(
                    server_key
                        .noise_squashing_key()
                        .unwrap()
                        .squash_radix_ciphertext_noise(int_server_key, &ct)
                        .unwrap(),
                )
            }
            SnsDecryptionKeyType::SnsCompressionKey => {
                tfhe::set_server_key(server_key.clone());
                let compressed = tfhe::CompressedSquashedNoiseCiphertextListBuilder::new()
                    .push(ct.squash_noise().unwrap())
                    .build()
                    .unwrap();
                let expanded: tfhe::SquashedNoiseFheUint = compressed.get(0).unwrap().unwrap();
                SnsRadixOrBoolCiphertext::Radix(
                    expanded.underlying_squashed_noise_ciphertext().clone(),
                )
            }
        };

        // `get_dummy_prss_setup` drives its own runtime, so it runs before the test's runtime.
        let prss_setup: PRSSSetup<ResiduePoly<Z128, 4>> = get_dummy_prss_setup(
            get_networkless_base_session_for_parties(num_parties, threshold as u8, role),
        );
        let base_session =
            get_networkless_base_session_for_parties(num_parties, threshold as u8, role);
        let session_id = base_session.session_id();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let session = SmallSession::new_from_prss_state(
                base_session,
                prss_setup.new_prss_session_state(session_id, role).unwrap(),
            )
            .unwrap();
            let mut noiseflood_session = SmallOfflineNoiseFloodSession::new(session);
            let mut prep = noiseflood_session
                .init_prep_noiseflooding(large_ct.len())
                .await
                .unwrap();
            let via_session =
                masked_partial_decrypt(&prepared_sns_keys, &large_ct, key_type, &mut prep).unwrap();
            let packing_via_session = large_ct.packing_factor() as u32;

            let mut prss_state = prss_setup
                .new_prss_session_state(prss_session_id, role)
                .unwrap();
            let ct = match key_type {
                SnsDecryptionKeyType::SnsKey => LowLevelCiphertextAndKeys::BigStandard(large_ct),
                SnsDecryptionKeyType::SnsCompressionKey => {
                    LowLevelCiphertextAndKeys::BigCompressed(large_ct)
                }
            };
            let (via_prss, packing_via_prss) =
                partial_decrypt_using_noiseflooding(&mut prss_state, role, ct, &prepared_sns_keys)
                    .await
                    .unwrap();

            (
                (via_session.to_vec(), packing_via_session),
                (via_prss.to_vec(), packing_via_prss),
            )
        })
    }

    #[rstest::rstest]
    #[case::big_standard(SnsDecryptionKeyType::SnsKey)]
    #[case::big_compressed(SnsDecryptionKeyType::SnsCompressionKey)]
    fn partial_decrypt_with_prss_matches_session_based(#[case] key_type: SnsDecryptionKeyType) {
        let (via_session, via_prss) =
            partial_decrypt_both_ways(threshold_types::session_id::SessionId::from(1), key_type);
        assert!(!via_session.0.is_empty());
        assert_eq!(via_session, via_prss);
    }

    /// The masks depend on the session ID: a PRSS state for another session yields a different
    /// partial decryption, so the equality above is not an artefact of unused masks.
    #[rstest::rstest]
    #[case::big_standard(SnsDecryptionKeyType::SnsKey)]
    #[case::big_compressed(SnsDecryptionKeyType::SnsCompressionKey)]
    fn partial_decrypt_with_prss_depends_on_session_id(#[case] key_type: SnsDecryptionKeyType) {
        let (via_session, via_prss) =
            partial_decrypt_both_ways(threshold_types::session_id::SessionId::from(2), key_type);
        assert_eq!(via_session.1, via_prss.1);
        assert_ne!(via_session.0, via_prss.0);
    }

    /// The batched partial decryption (one `dot` per block with eight key coefficients per lane, blocks on
    /// Rayon) equals the plain fold per block, for both backends, both key types, and key dimensions that are
    /// not multiples of the lane count.
    #[test]
    fn batched_partial_decrypt_matches_fold() {
        use crate::tfhe_internals::parameters::PARAMS_TEST_BK_SNS;
        use algebra::lincomb::{Backend, LinearCombinator, Operand};
        let mut rng = AesRng::seed_from_u64(7);
        for lwe_dimension in [4096, 1000, 7] {
            let key_set =
                synthetic::private_key_set::<4>(&mut rng, PARAMS_TEST_BK_SNS, lwe_dimension);
            for key_type in [
                SnsDecryptionKeyType::SnsKey,
                SnsDecryptionKeyType::SnsCompressionKey,
            ] {
                let key_share = match key_type {
                    SnsDecryptionKeyType::SnsKey => &key_set.glwe_secret_key_share_sns_as_lwe,
                    SnsDecryptionKeyType::SnsCompressionKey => {
                        &key_set.glwe_sns_compression_key_as_lwe
                    }
                }
                .as_ref()
                .unwrap();
                let prepared = PreparedSnsKeys::prepare(&key_set);
                let cached = prepared.key(key_type).unwrap();
                assert!(Arc::ptr_eq(&cached, &prepared.key(key_type).unwrap()));
                let forced_scalar = LinearCombinator::with_backend(
                    key_share.data_iter(),
                    Operand::Scalar,
                    Backend::Scalar,
                );
                for blocks in [1, 2, 7, 8, 9, 15, 16, 17, 24, 33] {
                    let ct = synthetic::squashed_radix_ciphertext(&mut rng, blocks, lwe_dimension);
                    let masks: Vec<ResiduePoly<Z128, 4>> = (0..blocks)
                        .map(|_| ResiduePoly::from_u128_iter((0..4).map(|_| rng.r#gen::<u128>())))
                        .collect();
                    let expected: Vec<ResiduePoly<Z128, 4>> = ct
                        .packed_blocks()
                        .zip(&masks)
                        .map(|(block, mask)| {
                            synthetic::partial_decrypt128_fold(key_share, block) + *mask
                        })
                        .collect();
                    for prepared in [&*cached, &forced_scalar] {
                        let got =
                            masked_partial_decrypt_with(prepared, &ct, masks.clone()).unwrap();
                        assert_eq!(
                            *got,
                            expected,
                            "{blocks} blocks, dimension {lwe_dimension}, {:?}",
                            prepared.backend()
                        );
                    }
                    for block in ct.packed_blocks() {
                        assert_eq!(
                            partial_decrypt128(&prepared, block, key_type).unwrap(),
                            synthetic::partial_decrypt128_fold(key_share, block)
                        );
                    }
                    assert!(
                        masked_partial_decrypt_with(&cached, &ct, masks[..blocks - 1].to_vec())
                            .is_err()
                    );
                }
            }
        }
    }

    async fn test_small_threshold_decrypt<const EXTENSION_DEGREE: usize>(
        threshold: usize,
        num_parties: usize,
        malicious_set: HashSet<Role>,
    ) where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
    {
        ensure_test_data_setup();
        let msg: u8 = 3;
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH).unwrap();
        let params = keyset.get_cpu_params().unwrap();

        let mut rng = AesRng::seed_from_u64(42);
        // generate keys
        let key_shares = keygen_all_party_shares_from_client_key(
            &keyset.client_key,
            params,
            &mut rng,
            num_parties,
            threshold,
        )
        .unwrap();
        let (ct, _id, _tag, _rerand_metadata) =
            FheUint8::encrypt(msg, &keyset.client_key).into_raw_parts();

        let roles = generate_fixed_roles(num_parties);
        //Assumes Sync because preprocessing is part of the task
        let mut runtime = DistributedTestRuntime::<
            ResiduePoly<Z128, EXTENSION_DEGREE>,
            Role,
            EXTENSION_DEGREE,
        >::new(roles, threshold as u8, NetworkMode::Sync, None);

        runtime.setup_sks(key_shares);
        runtime.setup_server_key(Arc::new(keyset.public_keys.server_key.clone()));

        let ct = RadixOrBoolCiphertext::Radix(ct);
        let results_dec = threshold_decrypt64_maybe_malicious::<
            _,
            DroppingOnlineNoiseFloodDecryption,
            EXTENSION_DEGREE,
        >(
            &runtime,
            &ct,
            DecryptionMode::NoiseFloodSmall,
            malicious_set.clone(),
        )
        .await
        .unwrap();
        assert!(!malicious_set.contains(&Role::indexed_from_one(1)));
        let out_dec = &results_dec[&Role::indexed_from_one(1)];

        let ref_res = std::num::Wrapping(msg as u64);
        assert_eq!(*out_dec, ref_res);
    }

    #[tokio::test]
    async fn test_small_bitdec_threshold_decrypt_f4() {
        test_small_bitdec_threshold_decrypt::<4>(1, 5, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_small_bitdec_threshold_decrypt_f3() {
        test_small_bitdec_threshold_decrypt::<3>(1, 5, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_small_bitdec_threshold_decrypt_f5() {
        test_small_bitdec_threshold_decrypt::<5>(1, 5, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_small_bitdec_threshold_decrypt_f6() {
        test_small_bitdec_threshold_decrypt::<6>(1, 5, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_small_bitdec_threshold_decrypt_f7() {
        test_small_bitdec_threshold_decrypt::<7>(1, 5, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_small_bitdec_threshold_decrypt_f8() {
        test_small_bitdec_threshold_decrypt::<8>(1, 5, HashSet::new()).await
    }

    async fn test_small_bitdec_threshold_decrypt<const EXTENSION_DEGREE: usize>(
        threshold: usize,
        num_parties: usize,
        malicious_set: HashSet<Role>,
    ) where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
    {
        ensure_test_data_setup();
        let msg: u8 = 3;
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH).unwrap();
        let params = keyset.get_cpu_params().unwrap();

        let mut rng = AesRng::seed_from_u64(42);
        // generate keys
        let key_shares = keygen_all_party_shares_from_client_key(
            &keyset.client_key,
            params,
            &mut rng,
            num_parties,
            threshold,
        )
        .unwrap();
        let (ct, _id, _tag, _rerand_metadata) =
            FheUint8::encrypt(msg, &keyset.client_key).into_raw_parts();

        let roles = generate_fixed_roles(num_parties);
        //Assumes Sync because preprocessing is part of the task
        let mut runtime = DistributedTestRuntime::<
            ResiduePoly<Z64, EXTENSION_DEGREE>,
            Role,
            EXTENSION_DEGREE,
        >::new(roles, threshold as u8, NetworkMode::Sync, None);

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
        let results_dec = threshold_decrypt64_maybe_malicious::<
            _,
            DroppingOnlineNoiseFloodDecryption,
            EXTENSION_DEGREE,
        >(
            &runtime,
            &ct,
            DecryptionMode::BitDecSmall,
            malicious_set.clone(),
        )
        .await
        .unwrap();
        assert!(!malicious_set.contains(&Role::indexed_from_one(1)));
        let out_dec = &results_dec[&Role::indexed_from_one(1)];

        let ref_res = std::num::Wrapping(msg as u64);
        assert_eq!(*out_dec, ref_res);
    }

    #[tokio::test]
    async fn test_large_bitdec_threshold_decrypt_f4() {
        test_large_bitdec_threshold_decrypt::<4>(1, 5, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_large_bitdec_threshold_decrypt_f3() {
        test_large_bitdec_threshold_decrypt::<3>(1, 5, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_large_bitdec_threshold_decrypt_f5() {
        test_large_bitdec_threshold_decrypt::<5>(1, 5, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_large_bitdec_threshold_decrypt_f6() {
        test_large_bitdec_threshold_decrypt::<6>(1, 5, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_large_bitdec_threshold_decrypt_f7() {
        test_large_bitdec_threshold_decrypt::<7>(1, 5, HashSet::new()).await
    }

    #[tokio::test]
    async fn test_large_bitdec_threshold_decrypt_f8() {
        test_large_bitdec_threshold_decrypt::<8>(1, 5, HashSet::new()).await
    }

    async fn test_large_bitdec_threshold_decrypt<const EXTENSION_DEGREE: usize>(
        threshold: usize,
        num_parties: usize,
        malicious_set: HashSet<Role>,
    ) where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
    {
        ensure_test_data_setup();
        let msg: u8 = 15;
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH).unwrap();
        let params = keyset.get_cpu_params().unwrap();

        let mut rng = AesRng::seed_from_u64(42);
        // generate keys
        let key_shares = keygen_all_party_shares_from_client_key(
            &keyset.client_key,
            params,
            &mut rng,
            num_parties,
            threshold,
        )
        .unwrap();
        let (ct, _id, _tag, _rerand_metadata) =
            FheUint8::encrypt(msg, &keyset.client_key).into_raw_parts();

        let roles = generate_fixed_roles(num_parties);
        //Assumes Sync because preprocessing is part of the task
        let mut runtime = DistributedTestRuntime::<
            ResiduePoly<Z64, EXTENSION_DEGREE>,
            Role,
            EXTENSION_DEGREE,
        >::new(roles, threshold as u8, NetworkMode::Sync, None);

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
        let results_dec = threshold_decrypt64_maybe_malicious::<
            _,
            DroppingOnlineNoiseFloodDecryption,
            EXTENSION_DEGREE,
        >(
            &runtime,
            &ct,
            DecryptionMode::BitDecLarge,
            malicious_set.clone(),
        )
        .await
        .unwrap();
        assert!(!malicious_set.contains(&Role::indexed_from_one(1)));
        let out_dec = &results_dec[&Role::indexed_from_one(1)];

        let ref_res = std::num::Wrapping(msg as u64);
        assert_eq!(*out_dec, ref_res);
    }
}
