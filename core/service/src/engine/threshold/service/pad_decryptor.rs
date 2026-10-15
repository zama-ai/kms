//! Threshold pad decryption (tech-spec RFC-030).
//!
//! Pad decryption reuses the key material, sessions and task tracker of [`UserDecryptor`].
//! Each pad block is a BigCompressed ciphertext that this party partially decrypts with noise
//! flooding, as in user decryption. The party signs the shares with EIP-712 and encrypts the
//! signed shares under the user's public key.

// === Standard Library ===
use std::{collections::HashMap, sync::Arc};

// === External Crates ===
use algebra::galois_rings::common::pack_residue_poly;
use alloy_sol_types::Eip712Domain;
use anyhow::anyhow;
use kms_grpc::{
    RequestId,
    identifiers::{ContextId, EpochId},
    kms::v1::{
        self, CiphertextFormat, Empty, PadDecryptionRequest, PadDecryptionResponse,
        PadDecryptionResponsePayload, PadDecryptionResponsePlaintext, PadShare,
    },
};
use observability::{
    metrics,
    metrics_names::{OP_PAD_DECRYPT_REQUEST, OP_PAD_DECRYPT_RESULT},
};
use rand::{CryptoRng, RngCore};
use tfhe::FheTypes;
use thread_handles::spawn_compute_bound;
use tokio::sync::OwnedRwLockReadGuard;
use tonic::{Code, Request, Response};
use tracing::Instrument;
use zeroize::{Zeroize, Zeroizing};

// === Internal Crate ===
use crate::{
    consts::DURATION_WAITING_ON_RESULT_SECONDS,
    cryptography::{
        encryption::UnifiedPublicEncKey,
        signatures::{NodeSigningIdentity, eip712_sign_hash},
        zeroizing_writer::ZeroizingWriter,
    },
    engine::{
        base::deserialize_to_low_level,
        pad::pad_payload_signing_hash,
        threshold::service::session::{ImmutableSessionMaker, validate_context_and_epoch},
        utils::{MetricedError, format_unvalidated_id},
        validation::{
            RequestIdParsingErr, ValidatedPad, ValidatedPadDecryptRequest, parse_grpc_request_id,
            parse_optional_grpc_request_id, validate_pad_decrypt_req,
        },
    },
    util::meta_store::{
        add_or_redo_failed_in_meta_store, retrieve_from_meta_store_with_timeout,
        update_req_in_meta_store,
    },
    vault::storage::{Storage, StorageExt},
};

// === Current Module Imports ===
use super::{
    ThresholdFheKeys,
    user_decryptor::{NoiseFloodPartialDecryptor, UserDecryptor},
};

/// The first counter of the MPC session IDs of a pad decryption. The session ID of block `i`
/// (counted over all pads of the request) derives from the request ID and the counter
/// `PAD_SESSION_COUNTER_BASE + i`. User and public decryption count from 0, so a request ID
/// that a user decryption also uses never gives the same session ID, and thus never the same
/// noise-flooding mask.
const PAD_SESSION_COUNTER_BASE: u64 = 1 << 63;

impl<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
    Dec: NoiseFloodPartialDecryptor + 'static,
> UserDecryptor<PubS, PrivS, Dec>
{
    /// Partially decrypts every block of `pads` and returns the signed and encrypted response
    /// of this party.
    #[expect(clippy::too_many_arguments)]
    async fn inner_pad_decrypt(
        req_id: RequestId,
        session_maker: ImmutableSessionMaker,
        context_id: ContextId,
        epoch_id: EpochId,
        mut rng: impl CryptoRng + RngCore + Send + 'static,
        pads: Vec<ValidatedPad>,
        block_fhe_type: FheTypes,
        enc_key: UnifiedPublicEncKey,
        identity: Arc<NodeSigningIdentity>,
        fhe_keys: OwnedRwLockReadGuard<
            HashMap<(RequestId, EpochId), ThresholdFheKeys>,
            ThresholdFheKeys,
        >,
        domain: Eip712Domain,
        extra_data: Vec<u8>,
    ) -> anyhow::Result<PadDecryptionResponse> {
        let my_role = session_maker
            .my_role(&context_id)
            .await
            .map_err(|e| anyhow!("Could not get my role: {e}"))?;

        let mut ctr = PAD_SESSION_COUNTER_BASE;
        let mut pad_shares = Vec::with_capacity(pads.len());
        for pad in pads {
            let mut block_shares = Vec::with_capacity(pad.block_ciphertexts.len());
            let mut packing_factor = None;
            for ct in pad.block_ciphertexts {
                let session_id = req_id.derive_session_id_with_counter(ctr)?;
                ctr += 1;

                // A BigCompressed ciphertext needs no decompression key.
                let low_level_ct = deserialize_to_low_level(
                    block_fhe_type,
                    CiphertextFormat::BigCompressed,
                    &ct,
                    None,
                )?;
                let ct = low_level_ct.with_sns_keys(|| {
                    Err(anyhow!(
                        "A BigCompressed pad block does not need switch and squash keys"
                    ))
                })?;
                let mut prss_state = session_maker
                    .prss_state_z128(session_id, epoch_id, my_role)
                    .await
                    .map_err(|e| anyhow!("Could not prepare the PRSS state: {e}"))?;
                let (partial_dec, block_packing_factor) =
                    Dec::partial_decrypt(&mut prss_state, my_role, ct, &fhe_keys.private_keys)
                        .await
                        .map_err(|e| {
                            anyhow!(
                                "Failed pad decryption of label {} in session {session_id}: {e}",
                                hex::encode(pad.label)
                            )
                        })?;
                // All blocks of a pad have the same type, so they have the same packing factor.
                match packing_factor {
                    None => packing_factor = Some(block_packing_factor),
                    Some(expected) if expected != block_packing_factor => {
                        anyhow::bail!(
                            "Packing factor {block_packing_factor} of a block differs from {expected}"
                        )
                    }
                    Some(_) => {}
                }
                let partial_dec = Zeroizing::new(pack_residue_poly(&partial_dec));
                block_shares.push(bc2wrap::serialize(&*partial_dec)?);
            }
            pad_shares.push(PadShare {
                label: pad.label.to_vec(),
                block_shares,
                // Validation guarantees at least one block per pad.
                packing_factor: packing_factor.expect("a validated pad has at least one block"),
            });
        }

        let threshold = session_maker
            .threshold(&context_id)
            .await
            .map_err(|e| anyhow!("Could not get threshold: {e}"))?;
        let party_id = my_role.one_based() as u32;
        let payload = PadDecryptionResponsePayload {
            extra_data,
            request_id: Some(req_id.into()),
            degree: threshold as u32,
            party_id,
            pad_shares,
        };

        spawn_compute_bound(move || {
            sign_and_encrypt_pad_payload(&mut rng, payload, &identity, &enc_key, &domain).map(
                |encrypted| PadDecryptionResponse {
                    request_id: Some(req_id.into()),
                    party_id,
                    encrypted,
                },
            )
        })
        .await
        .map_err(|e| anyhow!("Failed to run signing task for pad decryption {req_id}: {e}"))?
    }
}

/// Signs `payload` with EIP-712 under `domain` and returns the encryption under `enc_key` of the
/// bc2wrap serialization of the [`PadDecryptionResponsePlaintext`].
///
/// The encryption is the hybrid encryption that signcryption uses, with the ciphertext
/// serialized by bc2wrap.
fn sign_and_encrypt_pad_payload(
    rng: &mut (impl CryptoRng + RngCore),
    payload: PadDecryptionResponsePayload,
    identity: &NodeSigningIdentity,
    enc_key: &UnifiedPublicEncKey,
    domain: &Eip712Domain,
) -> anyhow::Result<Vec<u8>> {
    let signing_hash = pad_payload_signing_hash(&payload, domain)?;
    let signature = eip712_sign_hash(identity.ecdsa(), &signing_hash)?;
    let mut plaintext = PadDecryptionResponsePlaintext {
        payload: Some(payload),
        signature,
    };
    // Serialize into a sink that wipes intermediate buffers.
    let mut serialized = ZeroizingWriter::new();
    let serialization = bc2wrap::serialize_into(&plaintext, &mut serialized);
    // The shares are only for the user, so wipe them before either outcome leaves the function.
    if let Some(payload) = plaintext.payload.as_mut() {
        for share in payload.pad_shares.iter_mut() {
            share.block_shares.zeroize();
        }
    }
    serialization?;
    let ciphertext = enc_key.hybrid_encrypt(rng, serialized.as_slice())?;
    Ok(bc2wrap::serialize(&ciphertext)?)
}

impl<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
    Dec: NoiseFloodPartialDecryptor + 'static,
> UserDecryptor<PubS, PrivS, Dec>
{
    // `context_id`/`epoch_id` are only known after request validation, so they start empty and
    // are recorded below. The spawned decryption task inherits this span.
    #[tracing::instrument(skip_all, fields(
        request_id = %format_unvalidated_id(&request.get_ref().request_id),
        operation = "pad_decrypt",
        context_id = tracing::field::Empty,
        epoch_id = tracing::field::Empty
    ))]
    pub(crate) async fn pad_decrypt(
        &self,
        request: Request<PadDecryptionRequest>,
    ) -> Result<Response<Empty>, MetricedError> {
        metrics::METRICS.increment_request_counter(OP_PAD_DECRYPT_REQUEST);
        let timer = metrics::METRICS
            .time_operation(OP_PAD_DECRYPT_REQUEST)
            .start();

        let inner = request.into_inner();
        let ValidatedPadDecryptRequest {
            request_id: req_id,
            key_id,
            context_id,
            epoch_id,
            pads,
            block_fhe_type,
            enc_key,
            domain,
            extra_data,
        } = validate_pad_decrypt_req(&inner).inspect_err(|_| {
            // The IDs are unvalidated here, so they are size-bounded rather than printed verbatim.
            tracing::warn!(
                "Rejected PadDecryptionRequest {{ request_id: {}, key_id: {}, context_id: {}, epoch_id: {}, pad_count: {} }}",
                format_unvalidated_id(&inner.request_id),
                format_unvalidated_id(&inner.key_id),
                format_unvalidated_id(&inner.context_id),
                format_unvalidated_id(&inner.epoch_id),
                inner.pads.len()
            );
        })?;
        // Recorded before the context/epoch check so that a rejection there is attributed too.
        let span = tracing::Span::current();
        span.record("context_id", tracing::field::display(&context_id));
        span.record("epoch_id", tracing::field::display(&epoch_id));
        validate_context_and_epoch(
            OP_PAD_DECRYPT_REQUEST,
            &self.session_maker,
            Some(req_id),
            &context_id,
            &epoch_id,
        )
        .await?;

        let identity = self.base_kms.signing_identity().map_err(|e| {
            MetricedError::new(
                OP_PAD_DECRYPT_REQUEST,
                Some(req_id),
                anyhow!(
                    "Signing key is not present. This should only happen when server is booted \
                     in recovery mode: {e}"
                ),
                Code::FailedPrecondition,
            )
        })?;

        // The read lock moves into the task. Write locks only happen at key generation, which
        // is rare, so holding the read lock for the duration of the decryption is acceptable.
        let fhe_keys_rlock = self
            .crypto_storage
            .read_guarded_fhe_keys(&key_id.into(), &epoch_id)
            .await
            .map_err(|e| {
                MetricedError::new(
                    OP_PAD_DECRYPT_REQUEST,
                    Some(req_id),
                    anyhow!("fhe key not found due to {e:?}"),
                    Code::NotFound,
                )
            })?;

        let meta_store = Arc::clone(&self.pad_decrypt_meta_store);
        // The management task updates the entry on every outcome path. Should the permit ever be
        // dropped without an update, the store's reaper fails the entry.
        let meta_permit =
            add_or_redo_failed_in_meta_store(&meta_store, &req_id, OP_PAD_DECRYPT_REQUEST).await?;

        let session_maker = self.session_maker.clone();
        let rng = self.base_kms.new_rng();
        self.tracker.spawn(
            async move {
                // Capture the timer, it is stopped when it's dropped
                let _timer = timer;
                let result = Self::inner_pad_decrypt(
                    req_id,
                    session_maker,
                    context_id,
                    epoch_id,
                    rng,
                    pads,
                    block_fhe_type,
                    enc_key,
                    identity,
                    fhe_keys_rlock,
                    domain,
                    extra_data,
                )
                .await;
                update_req_in_meta_store(&meta_store, meta_permit, result, OP_PAD_DECRYPT_REQUEST)
                    .await;
            }
            .instrument(tracing::Span::current()),
        );
        Ok(Response::new(Empty {}))
    }

    pub(crate) async fn pad_decrypt_sync(
        &self,
        request: Request<PadDecryptionRequest>,
    ) -> Result<Response<PadDecryptionResponse>, MetricedError> {
        // `pad_decrypt` consumes the request, so keep the raw id for fetching the result below.
        let raw_request_id = request.get_ref().request_id.clone();

        match self.pad_decrypt(request).await {
            Ok(_empty) => (),
            // Already succeeded, in flight, or tombstoned: attach to the existing entry
            Err(e) if e.code() == Code::AlreadyExists => e.defuse(),
            Err(e) => return Err(e),
        }

        // `pad_decrypt` accepted the request, so its id must parse.
        let req_id: RequestId =
            parse_optional_grpc_request_id(&raw_request_id, RequestIdParsingErr::PadDecRequest)
                .map_err(|e| {
                    MetricedError::new(OP_PAD_DECRYPT_REQUEST, None, e, Code::InvalidArgument)
                })?;

        self.get_pad_result(Request::new(req_id.into())).await
    }

    pub(crate) async fn get_pad_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<PadDecryptionResponse>, MetricedError> {
        metrics::METRICS.increment_request_counter(OP_PAD_DECRYPT_RESULT);

        let request_id =
            parse_grpc_request_id(&request.into_inner(), RequestIdParsingErr::PadDecResponse)
                .map_err(|e| {
                    MetricedError::new(OP_PAD_DECRYPT_RESULT, None, e, Code::InvalidArgument)
                })?;

        let response = retrieve_from_meta_store_with_timeout(
            &self.pad_decrypt_meta_store,
            &request_id,
            OP_PAD_DECRYPT_RESULT,
            DURATION_WAITING_ON_RESULT_SECONDS,
        )
        .await?;
        Ok(Response::new((*response).clone()))
    }
}

#[cfg(test)]
mod tests {
    use algebra::{
        base_ring::Z128,
        galois_rings::{
            common::ResiduePoly,
            degree_4::{ResiduePolyF4, ResiduePolyF4Z128},
        },
        structure_traits::{ErrorCorrect, Invert, Ring, Solve},
    };
    use kms_grpc::{
        kms::v1::{PadDecryptionEntry, PadDecryptionResponsePayload},
        rpc_types::{KMSType, fhe_types_to_num_blocks},
    };
    use rand::SeedableRng;
    use std::num::Wrapping;
    use threshold_execution::{
        endpoints::decryption::{DecryptionMode, LowLevelCiphertextAndKeys},
        small_execution::prss::{PRSSSetup, SecurePRSSState},
        tfhe_internals::{
            parameters::AugmentedCiphertextParameters, private_keysets::PrivateKeySet,
        },
    };
    use threshold_types::{rng::AesRng, role::Role};
    use tokio::sync::RwLock;
    use tokio_util::task::TaskTracker;

    use super::*;
    use crate::{
        client::{
            client_wasm::Client,
            local_crypto::{EncryptionConfig, TestingPlaintext, compute_cipher},
        },
        consts::{DEFAULT_MPC_CONTEXT, TEST_PARAM},
        cryptography::{
            encryption::{Encryption, PkeScheme, PkeSchemeType, UnifiedPrivateEncKey},
            hybrid_ml_kem::HybridKemCt,
            signatures::{PrivateSigKey, PublicSigKey, gen_sig_keys},
        },
        dummy_domain,
        engine::{
            base::BaseKmsStruct, pad::LABEL_BYTES, rng_source::test_rng_source,
            threshold::service::session::SessionMaker, utils::make_extra_data,
        },
        util::meta_store::MetaStore,
        vault::storage::{
            crypto_material::{PublicKeySet, ThresholdCryptoMaterialStorage},
            ram,
        },
    };

    /// The value that every pad block decrypts to with [`ConstantPartialDecryptor`].
    const PAD_BLOCK_VALUE: u64 = 0x0123_4567_89ab_cdef;

    /// Returns the noise-free encoding of [`PAD_BLOCK_VALUE`] under [`TEST_PARAM`], one
    /// polynomial per message block with the value in the constant term.
    fn encoded_pad_block() -> Vec<ResiduePolyF4Z128> {
        let pbs = TEST_PARAM.classic_pbs();
        let msg_bits = pbs.message_modulus_log();
        let delta_pad_bits = 128 - (pbs.total_block_bits() + 1);
        let num_blocks = fhe_types_to_num_blocks(FheTypes::Uint64, &pbs, 1).unwrap();
        (0..num_blocks)
            .map(|j| {
                let block = (PAD_BLOCK_VALUE >> (j as u32 * msg_bits)) & ((1 << msg_bits) - 1);
                ResiduePolyF4::from_scalar(Z128::from(Wrapping((block as u128) << delta_pad_bits)))
            })
            .collect()
    }

    /// Returns the same share of [`PAD_BLOCK_VALUE`] to every party. A constant is a valid
    /// sharing of any degree, so the shares of all parties reconstruct to the value.
    struct ConstantPartialDecryptor;

    #[tonic::async_trait]
    impl NoiseFloodPartialDecryptor for ConstantPartialDecryptor {
        async fn partial_decrypt(
            _prss_state: &mut SecurePRSSState<ResiduePolyF4Z128>,
            _my_role: Role,
            _ct: LowLevelCiphertextAndKeys,
            _secret_key_share: &PrivateKeySet<{ ResiduePolyF4Z128::EXTENSION_DEGREE }>,
        ) -> anyhow::Result<(
            Zeroizing<Vec<ResiduePoly<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>>>,
            u32,
        )>
        where
            ResiduePoly<Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>:
                ErrorCorrect + Invert + Solve,
        {
            Ok((Zeroizing::new(encoded_pad_block()), 1))
        }
    }

    type TestDecryptor =
        UserDecryptor<ram::RamStorage, ram::RamStorage, ConstantPartialDecryptor>;

    struct TestSetup {
        key_id: RequestId,
        epoch_id: EpochId,
        /// A BigCompressed Uint64 ciphertext under the key `key_id`.
        block_ct: Vec<u8>,
        decryptor: TestDecryptor,
        /// The signing key of the decryptor, which is party 1.
        server_sk: PrivateSigKey,
    }

    async fn setup(rng: &mut AesRng) -> TestSetup {
        let (_pk, server_sk) = gen_sig_keys(rng);
        let base_kms = BaseKmsStruct::new(
            KMSType::Threshold,
            NodeSigningIdentity::ecdsa_only(server_sk.clone()),
            test_rng_source(),
        );
        let epoch_id = EpochId::new_random(rng);
        let role = Role::indexed_from_one(1);
        let session_maker = SessionMaker::four_party_dummy_session(
            Some(
                PRSSSetup::testing_party_epoch_init(4, 1, role)
                    .await
                    .unwrap(),
            ),
            Some(
                PRSSSetup::testing_party_epoch_init(4, 1, role)
                    .await
                    .unwrap(),
            ),
            &epoch_id,
            base_kms.new_rngs(),
        );

        let decryptor = UserDecryptor {
            base_kms,
            crypto_storage: ThresholdCryptoMaterialStorage::new(
                ram::RamStorage::new(),
                ram::RamStorage::new(),
                None,
                HashMap::new(),
            ),
            user_decrypt_meta_store: MetaStore::new_unlimited(),
            pad_decrypt_meta_store: MetaStore::new_unlimited(),
            session_maker: session_maker.make_immutable(),
            tracker: Arc::new(TaskTracker::new()),
            decryption_mode: DecryptionMode::NoiseFloodSmall,
            _dec: std::marker::PhantomData,
        };

        let key_id = RequestId::new_random(rng);
        let key_meta_store: Arc<RwLock<MetaStore<_>>> = MetaStore::new_unlimited();
        let meta_store_permit = key_meta_store.write().await.insert(&key_id).unwrap();
        let (threshold_fhe_keys, fhe_key_set) =
            ThresholdFheKeys::init_dummy(TEST_PARAM, key_id.into(), rng);
        let (block_ct, _, _) = compute_cipher(
            TestingPlaintext::U64(42),
            &fhe_key_set.public_key,
            Some(fhe_key_set.server_key.clone()),
            EncryptionConfig {
                compression: true,
                precompute_sns: true,
            },
        );
        decryptor
            .crypto_storage
            .write_fhe_keys(
                &key_id,
                &epoch_id,
                threshold_fhe_keys,
                PublicKeySet::Uncompressed(Arc::new(fhe_key_set)),
                key_meta_store,
                meta_store_permit,
                "",
            )
            .await
            .unwrap();

        TestSetup {
            key_id,
            epoch_id,
            block_ct,
            decryptor,
            server_sk,
        }
    }

    fn pad_entry(label_byte: u8, pad_length: u32, block_ct: &[u8]) -> PadDecryptionEntry {
        PadDecryptionEntry {
            label: vec![label_byte; LABEL_BYTES],
            pad_length,
            block_ciphertexts: vec![block_ct.to_vec(); pad_length.div_ceil(64) as usize],
        }
    }

    /// Returns a client for four parties, where `server_sk` is party 1, together with the
    /// signing keys of parties 2 to 4.
    fn four_party_client(
        rng: &mut AesRng,
        server_sk: &PrivateSigKey,
    ) -> (Client, Vec<PrivateSigKey>) {
        let other_sks: Vec<PrivateSigKey> = (0..3).map(|_| gen_sig_keys(rng).1).collect();
        let mut server_pks = HashMap::from([(1, PublicSigKey::from_sk(server_sk))]);
        for (idx, sk) in other_sks.iter().enumerate() {
            server_pks.insert(idx as u32 + 2, PublicSigKey::from_sk(sk));
        }
        let client = Client::new(
            server_pks,
            HashMap::new(),
            alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045"),
            None,
            TEST_PARAM,
            None,
        );
        (client, other_sks)
    }

    fn open_payload(
        response: &PadDecryptionResponse,
        dec_key: &UnifiedPrivateEncKey,
    ) -> PadDecryptionResponsePlaintext {
        let ct: HybridKemCt = bc2wrap::deserialize_slice(&response.encrypted).unwrap();
        bc2wrap::deserialize_slice(&dec_key.hybrid_decrypt(ct).unwrap()).unwrap()
    }

    /// Returns the response of the party with `party_id` and signing key `sk`, carrying the
    /// shares of `payload`.
    fn response_of(
        rng: &mut AesRng,
        mut payload: PadDecryptionResponsePayload,
        party_id: u32,
        sk: &PrivateSigKey,
        enc_key: &UnifiedPublicEncKey,
    ) -> PadDecryptionResponse {
        payload.party_id = party_id;
        let request_id = payload.request_id.clone();
        let encrypted = sign_and_encrypt_pad_payload(
            rng,
            payload,
            &NodeSigningIdentity::ecdsa_only(sk.clone()),
            enc_key,
            &dummy_domain(),
        )
        .unwrap();
        PadDecryptionResponse {
            request_id,
            party_id,
            encrypted,
        }
    }

    /// The request and the response of every party for two pads of 64 and 100 bits.
    struct Exchange {
        client: Client,
        request: PadDecryptionRequest,
        dec_key: UnifiedPrivateEncKey,
        enc_key: UnifiedPublicEncKey,
        responses: Vec<PadDecryptionResponse>,
        other_sks: Vec<PrivateSigKey>,
    }

    async fn run_exchange(rng: &mut AesRng) -> Exchange {
        let setup = setup(rng).await;
        let (mut client, other_sks) = four_party_client(rng, &setup.server_sk);
        let extra_data =
            make_extra_data(2, Some(&DEFAULT_MPC_CONTEXT), Some(&setup.epoch_id)).unwrap();
        let (request, enc_key, dec_key) = client
            .pad_decryption_request(
                &dummy_domain(),
                vec![
                    pad_entry(1, 64, &setup.block_ct),
                    pad_entry(2, 100, &setup.block_ct),
                ],
                0,
                &RequestId::new_random(rng),
                &setup.key_id,
                &DEFAULT_MPC_CONTEXT,
                &setup.epoch_id,
                &extra_data,
            )
            .unwrap();

        let response = setup
            .decryptor
            .pad_decrypt_sync(Request::new(request.clone()))
            .await
            .unwrap()
            .into_inner();
        let payload = open_payload(&response, &dec_key).payload.unwrap();
        let mut responses = vec![response];
        for (idx, sk) in other_sks.iter().enumerate() {
            responses.push(response_of(
                rng,
                payload.clone(),
                idx as u32 + 2,
                sk,
                &enc_key,
            ));
        }
        Exchange {
            client,
            request,
            dec_key,
            enc_key,
            responses,
            other_sks,
        }
    }

    fn expected_pads() -> Vec<Vec<u8>> {
        let block = PAD_BLOCK_VALUE.to_le_bytes();
        let mut second = [block, block].concat();
        // 100 bits are 12 full bytes and 4 bits of the 13th byte.
        second.truncate(13);
        second[12] &= 0x0f;
        vec![block.to_vec(), second]
    }

    fn to_vecs(pads: Vec<Zeroizing<Vec<u8>>>) -> Vec<Vec<u8>> {
        pads.iter().map(|pad| pad.to_vec()).collect()
    }

    #[tokio::test]
    async fn pad_decrypt_sunshine() {
        let mut rng = AesRng::seed_from_u64(1);
        let ex = run_exchange(&mut rng).await;

        let response = &ex.responses[0];
        assert_eq!(response.request_id, ex.request.request_id);
        assert_eq!(response.party_id, 1);
        let payload = open_payload(response, &ex.dec_key).payload.unwrap();
        assert_eq!(payload.request_id, ex.request.request_id);
        assert_eq!(payload.extra_data, ex.request.extra_data);
        assert_eq!(payload.degree, 1);
        assert_eq!(payload.party_id, 1);
        let labels: Vec<_> = payload.pad_shares.iter().map(|s| s.label.clone()).collect();
        assert_eq!(labels, vec![vec![1; LABEL_BYTES], vec![2; LABEL_BYTES]]);
        let block_counts: Vec<_> = payload
            .pad_shares
            .iter()
            .map(|s| s.block_shares.len())
            .collect();
        assert_eq!(block_counts, vec![1, 2]);

        let pads = ex
            .client
            .process_pad_decryption_resp(&ex.request, &ex.dec_key, None, &ex.responses)
            .unwrap();
        assert_eq!(to_vecs(pads), expected_pads());
    }

    #[tokio::test]
    async fn client_tolerates_one_fault() {
        let mut rng = AesRng::seed_from_u64(2);
        let mut ex = run_exchange(&mut rng).await;
        let payload = open_payload(&ex.responses[0], &ex.dec_key).payload.unwrap();

        // party 4 signs with a key that the client does not know
        let (_pk, unknown_sk) = gen_sig_keys(&mut rng);
        ex.responses[3] = response_of(&mut rng, payload, 4, &unknown_sk, &ex.enc_key);
        let pads = ex
            .client
            .process_pad_decryption_resp(&ex.request, &ex.dec_key, None, &ex.responses)
            .unwrap();
        assert_eq!(to_vecs(pads), expected_pads());

        // a missing response is also one fault
        let pads = ex
            .client
            .process_pad_decryption_resp(&ex.request, &ex.dec_key, None, &ex.responses[..3])
            .unwrap();
        assert_eq!(to_vecs(pads), expected_pads());
    }

    #[tokio::test]
    async fn client_rejects_too_many_faults() {
        let mut rng = AesRng::seed_from_u64(3);
        let ex = run_exchange(&mut rng).await;
        let payload = open_payload(&ex.responses[0], &ex.dec_key).payload.unwrap();

        let faults: Vec<fn(&mut PadDecryptionResponsePayload)> = vec![
            |p| p.extra_data.push(0),
            |p| p.request_id = Some(RequestId::from_bytes([3; 32]).into()),
            |p| p.degree = 2,
            |p| p.pad_shares.truncate(1),
            |p| p.pad_shares[1].label = vec![5; LABEL_BYTES],
            |p| p.pad_shares[0].label = p.pad_shares[1].label.clone(),
            |p| p.pad_shares[1].block_shares.truncate(1),
            |p| p.pad_shares[0].block_shares[0] = vec![1, 2, 3],
            |p| p.pad_shares[0].packing_factor = 2,
        ];
        for fault in faults {
            let mut faulty = payload.clone();
            fault(&mut faulty);
            // parties 3 and 4 are faulty, which is more than t = 1
            let mut responses = ex.responses[..2].to_vec();
            for party_id in [3, 4] {
                responses.push(response_of(
                    &mut rng,
                    faulty.clone(),
                    party_id,
                    &ex.other_sks[party_id as usize - 2],
                    &ex.enc_key,
                ));
            }
            assert!(
                ex.client
                    .process_pad_decryption_resp(&ex.request, &ex.dec_key, None, &responses)
                    .is_err()
            );
        }

        // a duplicate response counts once
        let responses = vec![
            ex.responses[0].clone(),
            ex.responses[0].clone(),
            ex.responses[1].clone(),
        ];
        assert!(
            ex.client
                .process_pad_decryption_resp(&ex.request, &ex.dec_key, None, &responses)
                .is_err()
        );

        // a response under another encryption key does not decrypt
        let (_other_dec_key, other_enc_key) = Encryption::new(PkeSchemeType::MlKem512, &mut rng)
            .keygen()
            .unwrap();
        let mut responses = ex.responses[..2].to_vec();
        for party_id in [3, 4] {
            responses.push(response_of(
                &mut rng,
                payload.clone(),
                party_id,
                &ex.other_sks[party_id as usize - 2],
                &other_enc_key,
            ));
        }
        assert!(
            ex.client
                .process_pad_decryption_resp(&ex.request, &ex.dec_key, None, &responses)
                .is_err()
        );
    }

    #[tokio::test]
    async fn invalid_argument() {
        let mut rng = AesRng::seed_from_u64(4);
        let setup = setup(&mut rng).await;
        let (mut client, _) = four_party_client(&mut rng, &setup.server_sk);
        let (valid, _, _) = client
            .pad_decryption_request(
                &dummy_domain(),
                vec![pad_entry(1, 64, &setup.block_ct)],
                0,
                &RequestId::new_random(&mut rng),
                &setup.key_id,
                &DEFAULT_MPC_CONTEXT,
                &setup.epoch_id,
                &[],
            )
            .unwrap();

        let block_ct = setup.block_ct.clone();
        type RequestChange = Box<dyn Fn(&mut PadDecryptionRequest)>;
        let changes: Vec<RequestChange> = vec![
            Box::new(|r| r.request_id = None),
            Box::new(|r| {
                r.request_id = Some(v1::RequestId {
                    request_id: "invalid_id".to_string(),
                })
            }),
            Box::new(|r| r.key_id = None),
            Box::new(|r| r.context_id = None),
            Box::new(|r| r.epoch_id = None),
            Box::new(|r| r.domain = None),
            Box::new(|r| r.enc_key = vec![1, 2, 3]),
            Box::new(|r| r.prf = 1),
            Box::new(|r| r.pads.clear()),
            Box::new(|r| r.pads[0].label.truncate(LABEL_BYTES - 1)),
            Box::new(|r| r.pads[0].pad_length = 0),
            Box::new(|r| r.pads[0].block_ciphertexts.clear()),
            Box::new(|r| {
                let extra = r.pads[0].block_ciphertexts[0].clone();
                r.pads[0].block_ciphertexts.push(extra)
            }),
            Box::new(|r| {
                let duplicate = r.pads[0].clone();
                r.pads.push(duplicate)
            }),
            Box::new(move |r| {
                // 2048 bits in pad 0 and 1 more bit in pad 1
                r.pads[0] = pad_entry(1, 2048, &block_ct);
                r.pads.push(pad_entry(2, 1, &block_ct));
            }),
        ];
        for change in changes {
            let mut request = valid.clone();
            change(&mut request);
            let err = setup
                .decryptor
                .pad_decrypt(Request::new(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            let err = setup
                .decryptor
                .pad_decrypt_sync(Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
        }

        // exactly 2048 bits over two pads is valid
        let mut request = valid.clone();
        request.pads = vec![
            pad_entry(1, 2000, &setup.block_ct),
            pad_entry(2, 48, &setup.block_ct),
        ];
        setup
            .decryptor
            .pad_decrypt(Request::new(request))
            .await
            .unwrap();

        let err = setup
            .decryptor
            .get_pad_result(Request::new(v1::RequestId {
                request_id: "invalid_id".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn not_found_and_already_exists() {
        let mut rng = AesRng::seed_from_u64(5);
        let setup = setup(&mut rng).await;
        let (mut client, _) = four_party_client(&mut rng, &setup.server_sk);
        let (request, _, _) = client
            .pad_decryption_request(
                &dummy_domain(),
                vec![pad_entry(1, 64, &setup.block_ct)],
                0,
                &RequestId::new_random(&mut rng),
                &setup.key_id,
                &DEFAULT_MPC_CONTEXT,
                &setup.epoch_id,
                &[],
            )
            .unwrap();

        // unknown request ID
        let err = setup
            .decryptor
            .get_pad_result(Request::new(RequestId::new_random(&mut rng).into()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::NotFound);

        // unknown key, epoch and context
        let mut unknown_key = request.clone();
        unknown_key.key_id = Some(RequestId::new_random(&mut rng).into());
        let mut unknown_epoch = request.clone();
        unknown_epoch.epoch_id = Some(EpochId::new_random(&mut rng).into());
        let mut unknown_context = request.clone();
        unknown_context.context_id = Some(ContextId::new_random(&mut rng).into());
        for bad in [unknown_key, unknown_epoch, unknown_context] {
            let err = setup
                .decryptor
                .pad_decrypt(Request::new(bad))
                .await
                .unwrap_err();
            assert_eq!(err.code(), Code::NotFound);
        }

        // a known request ID is rejected by the async call, and the sync call attaches to it
        setup
            .decryptor
            .pad_decrypt(Request::new(request.clone()))
            .await
            .unwrap();
        let err = setup
            .decryptor
            .pad_decrypt(Request::new(request.clone()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::AlreadyExists);
        let first = setup
            .decryptor
            .get_pad_result(Request::new(request.request_id.clone().unwrap()))
            .await
            .unwrap()
            .into_inner();
        let second = setup
            .decryptor
            .pad_decrypt_sync(Request::new(request))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(first, second);
    }
}
