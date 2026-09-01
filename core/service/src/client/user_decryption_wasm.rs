use crate::client::client_wasm::Client;
#[cfg(feature = "wasm_tests")]
use crate::cryptography::signatures::PrivateSigKey;
use crate::cryptography::signcryption::insecure_decrypt_ignoring_signature;
use crate::cryptography::{
    encryption::{UnifiedPrivateEncKey, UnifiedPublicEncKey},
    signatures::PublicSigKey,
    signcryption::{UnifiedUnsigncryptionKey, UnsigncryptFHEPlaintext},
};
use crate::engine::validation::{
    AuthenticatedUserDecResponse, DSEP_USER_DECRYPTION,
    ERR_VALIDATE_USER_DECRYPTION_MISMATCH_EXTRA_DATA, RejectedUserDecResponse,
    ShareAuthenticationError, UserDecRejectReason, UserDecTrustedValidationContext,
    UserDecryptionInvariants, authenticate_user_decrypt_share, validate_user_decrypt_responses,
};
use crate::{anyhow_error_and_log, some_or_err};
use algebra::error_correction::ReconstructionHints;
use algebra::{
    base_ring::{Z64, Z128},
    error_correction::MemoizedExceptionals,
    galois_rings::degree_4::ResiduePolyF4,
    sharing::shamir::{ShamirSharings, fill_indexed_shares, reconstruct_w_errors_sync},
    structure_traits::{BaseRing, ErrorCorrect, Ring},
};
use alloy_sol_types::Eip712Domain;
use alloy_sol_types::SolStruct;
use itertools::Itertools;
use kms_grpc::kms::v1::{
    TypedPlaintext, UserDecryptionRequest, UserDecryptionResponse, UserDecryptionResponsePayload,
};
use kms_grpc::rpc_types::{PlaintextReceiver, fhe_types_to_num_blocks};
use kms_grpc::solidity_types::UserDecryptionLinker;
use std::num::Wrapping;
use tfhe::FheTypes;
use tfhe::shortint::ClassicPBSParameters;
use threshold_execution::endpoints::decryption::DecryptionMode;
use threshold_execution::endpoints::reconstruct::{
    combine_decryptions, reconstruct_packed_message,
};
use threshold_execution::tfhe_internals::parameters::AugmentedCiphertextParameters;
use threshold_types::role::Role;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsError, JsValue};
use zeroize::{Zeroize, Zeroizing};

/// A fully-verified user-decryption response: it passed metadata + signature validation **and**
/// every one of its signcryptions was un-signcrypted and its inner share decoded. Its decoded
/// shares are ready to be placed into the Shamir sharings, so nothing downstream can fail on this
/// response's content.
struct AcceptedUserDecResponse<Z: BaseRing + Zeroize> {
    role: Role,
    /// Decoded shares, one guarded inner `Vec` (blocks) per signcrypted-ciphertext slot, aligned
    /// 1:1 with [`UserDecryptionInvariants::slots`].
    shares_per_slot: Vec<Zeroizing<Vec<ResiduePolyF4<Z>>>>,
}

/// The result of partitioning user-decryption responses into fully-verified `accepted` and typed
/// `rejected`, mirroring `PartitionedPublicResponses` on the public-decryption side. A response is
/// `accepted` only once it has been authenticated (secret-free validation) **and** un-signcrypted +
/// decoded, so the fault count is simply `num_parties - accepted.len()`.
struct PartitionedUserDecResponses<Z: BaseRing + Zeroize> {
    invariants: UserDecryptionInvariants,
    accepted: Vec<AcceptedUserDecResponse<Z>>,
    rejected: Vec<RejectedUserDecResponse>,
    /// Total number of known parties (from the trusted context), used to compute the fault count for reconstruction.
    num_parties: usize,
}

impl<Z: BaseRing + Zeroize> PartitionedUserDecResponses<Z>
where
    ResiduePolyF4<Z>: ErrorCorrect,
{
    /// Reconstruct every slot's decrypted blocks from the fully-verified accepted responses.
    ///
    /// `num_bots = num_parties - accepted.len()` is the single source of truth for the fault count
    /// (missing, rejected, and unrecoverable responses all collapse into it), so it is the same for
    /// every slot and `reconstruct_w_errors_sync` can never underflow.
    ///
    /// Returns `Ok(None)` if there are no shares at all (empty slot set)
    #[expect(clippy::type_complexity)]
    fn reconstruct_all_slots(
        &self,
        pbs_params: &ClassicPBSParameters,
        intra_share_packing: usize,
    ) -> anyhow::Result<Option<Vec<(FheTypes, u32, Zeroizing<Vec<ResiduePolyF4<Z>>>)>>> {
        let n = self.num_parties;
        let degree = self.invariants.degree;

        let num_bots = if let Some(num_bots) = n.checked_sub(self.accepted.len()) {
            num_bots
        } else {
            anyhow::bail!(
                "More accepted responses than parties: n ({n}) < accepted.len() ({})",
                self.accepted.len()
            );
        };

        let mut out = Vec::with_capacity(self.invariants.slots.len());
        for (slot_idx, slot) in self.invariants.slots.iter().enumerate() {
            let num_shares =
                fhe_types_to_num_blocks(slot.fhe_type, pbs_params, slot.packing_factor)?
                    .div_ceil(intra_share_packing);
            let mut sharings = Zeroizing::new(
                (0..num_shares)
                    .map(|_| ShamirSharings::with_capacity(self.accepted.len()))
                    .collect::<Vec<_>>(),
            );
            for acc in &self.accepted {
                // Slot-aligned by construction: a response is accepted only if ALL its slots
                // decoded, so `shares_per_slot[slot_idx]` exists. Stay defensive against adversarial
                // input by never indexing directly.
                let blocks = acc
                    .shares_per_slot
                    .get(slot_idx)
                    .map(|blocks| blocks.to_vec())
                    .unwrap_or_default();
                fill_indexed_shares(&mut sharings, blocks, acc.role);
            }
            match Client::reconstruct_blocks(n, degree, num_bots, &sharings)? {
                Some(blocks) => out.push((slot.fhe_type, slot.packing_factor, blocks)),
                None => anyhow::bail!("No shares to reconstruct for slot {slot_idx}"),
            }
        }
        Ok(Some(out))
    }
}

impl Client {
    /// Processes the aggregated user decryption responses to attempt to decrypt
    /// the encryption of the secret shared plaintext and returns this. Validates the
    /// response matches the request, checks signatures, and handles both
    /// centralized and distributed cases.
    ///
    /// If there is more than one response or more than one server identity,
    /// then the threshold mode is used.
    ///
    /// # Arguments
    ///
    /// All arguments except `agg_resp` are **trusted** (client-side state):
    ///
    /// * `client_request` — The original user decryption request constructed by
    ///   this client. Used to verify that the server responses match the request.
    /// * `eip712_domain` — The EIP-712 domain used for signature verification.
    /// * `enc_key` — The ephemeral public encryption key generated by this client
    ///   for signcryption.
    /// * `dec_key` — The ephemeral private decryption key generated by this client,
    ///   used to unsigncrypt the server responses.
    /// * `threshold` — Optional expected threshold/degree override used during
    ///   validation and pivot selection. If `Some`, that value is used as the
    ///   expected threshold. If `None`, the expected threshold is derived from the
    ///   configured server count as `(n - 1) / 3`. Validation then requires the
    ///   selected pivot response's `degree` to equal that expected threshold.
    ///   Reconstruction still uses the validated payload degree.
    ///
    /// The following argument is **untrusted** (received from the network):
    ///
    /// * `agg_resp` — The aggregated server responses. These are validated against
    ///   the trusted parameters before use (signature checks, digest matching, etc.).
    pub fn process_user_decryption_resp(
        &self,
        client_request: &ParsedUserDecryptionRequest,
        eip712_domain: &Eip712Domain,
        enc_key: &UnifiedPublicEncKey,
        dec_key: &UnifiedPrivateEncKey,
        threshold: Option<usize>,
        agg_resp: &[UserDecryptionResponse],
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        // The condition below decides whether we'll parse the response
        // in the centralized mode or threshold mode.
        //
        // It's important to check both the length of the server identities
        // and the number of responses at the start to avoid "falling back"
        // to the centralized mode by mistake since the checks that happen
        // in the centralized mode is weaker (there are no checks on the threshold).
        if agg_resp.len() <= 1 && self.server_identities.len() == 1 {
            // Execute simplified and faster flow for the centralized case
            // Observe that we don't encode exactly the same in the centralized case and in the
            // distributed case. For the centralized case we directly encode the [Plaintext]
            // object whereas for the distributed we encode the plain text as a
            // Vec<ResiduePolyF4Z128>.
            self.centralized_user_decryption_resp(
                client_request,
                eip712_domain,
                enc_key,
                dec_key,
                agg_resp,
            )
        } else {
            self.threshold_user_decryption_resp(
                client_request,
                eip712_domain,
                enc_key,
                dec_key,
                threshold,
                agg_resp,
            )
        }
    }

    /// Processes the aggregated user decryption response to attempt to decrypt
    /// the encryption of the secret shared plaintext and returns this.
    /// This function does *not* do any verification and is thus insecure and should be used only for testing.
    /// TODO hide behind flag for insecure function?
    pub fn insecure_process_user_decryption_resp(
        &self,
        dec_key: &UnifiedPrivateEncKey,
        agg_resp: &[UserDecryptionResponse],
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        // The same logic is used in `process_user_decryption_resp`.
        if agg_resp.len() <= 1 && self.server_identities.len() == 1 {
            self.insecure_centralized_user_decryption_resp(agg_resp, dec_key)
        } else {
            self.insecure_threshold_user_decryption_resp(agg_resp, dec_key)
        }
    }

    /// Decrypt the user decryption response from the centralized KMS and verify that the signatures are valid
    fn centralized_user_decryption_resp(
        &self,
        request: &ParsedUserDecryptionRequest,
        eip712_domain: &Eip712Domain,
        enc_key: &UnifiedPublicEncKey,
        dec_key: &UnifiedPrivateEncKey,
        agg_resp: &[UserDecryptionResponse],
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let resp = some_or_err(agg_resp.last(), "Response does not exist".to_owned())?;
        let payload = some_or_err(resp.payload.clone(), "Payload does not exist".to_owned())?;

        let link = compute_link(request, eip712_domain)?;
        if link != payload.digest {
            return Err(anyhow_error_and_log(format!(
                "link mismatch ({} != {}) for domain {:?}",
                hex::encode(&link),
                hex::encode(&payload.digest),
                eip712_domain,
            )));
        }

        let stored_server_addrs = &self.get_server_addrs();
        if stored_server_addrs.len() != 1 {
            return Err(anyhow_error_and_log("incorrect length for addresses"));
        }

        // NOTE: ID starts at 1
        let expected_server_addr = some_or_err(
            stored_server_addrs.get(&1),
            "missing server address at ID 1".to_owned(),
        )?;

        // The response must echo the request's extra data whichever signature the authenticator
        // goes on to verify. The EIP-712 signature covers `extraData`, but the raw ECDSA one does
        // not, so this check has to happen outside the authenticator's branch.
        if resp.extra_data != request.extra_data() {
            return Err(anyhow_error_and_log(
                ERR_VALIDATE_USER_DECRYPTION_MISMATCH_EXTRA_DATA,
            ));
        }

        let cur_verf_key = authenticate_user_decrypt_share(
            &payload,
            expected_server_addr,
            &resp.signatures,
            &resp.signature,
            &resp.external_signature,
            &resp.extra_data,
            request.enc_key(),
            request.extra_data(),
            eip712_domain,
        )
        .map_err(|reason| match reason {
            ShareAuthenticationError::WrongAddress => {
                anyhow_error_and_log("server address is not consistent")
            }
            ShareAuthenticationError::MissingSignature => anyhow_error_and_log("empty signature"),
            reason => {
                tracing::warn!("signature on received response is not valid ({reason:?})");
                anyhow_error_and_log("signature on received response is not valid")
            }
        })?;
        let receiver_id = self.client_address.to_vec();
        let unsign_key =
            UnifiedUnsigncryptionKey::new(dec_key, enc_key, &cur_verf_key, &receiver_id);

        payload
            .signcrypted_ciphertexts
            .into_iter()
            .map(|ct| {
                unsign_key
                    .unsigncrypt_plaintext(&DSEP_USER_DECRYPTION, &ct.signcrypted_ciphertext, &link)
                    .map(|res| res.plaintext)
                    .map_err(|e| anyhow::anyhow!("unsigncrypt_plaintext failed: {}", e))
            })
            .collect()
    }

    /// Decrypt the user decryption response from the centralized KMS.
    /// This function does *not* do any verification and is thus insecure and should be used only for testing.
    /// TODO hide behind flag for insecure function?
    fn insecure_centralized_user_decryption_resp(
        &self,
        agg_resp: &[UserDecryptionResponse],
        dec_key: &UnifiedPrivateEncKey,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let resp = some_or_err(agg_resp.last(), "Response does not exist".to_owned())?;
        let payload = some_or_err(resp.payload.clone(), "Payload does not exist".to_owned())?;

        let mut out = vec![];
        for ct in payload.signcrypted_ciphertexts {
            out.push(
                crate::cryptography::signcryption::insecure_decrypt_ignoring_signature(
                    &ct.signcrypted_ciphertext,
                    dec_key,
                )?,
            )
        }
        Ok(out)
    }

    /// Decrypt the user decryption responses from the threshold KMS and verify that the signatures are valid
    fn threshold_user_decryption_resp(
        &self,
        client_request: &ParsedUserDecryptionRequest,
        eip712_domain: &Eip712Domain,
        enc_key: &UnifiedPublicEncKey,
        dec_key: &UnifiedPrivateEncKey,
        threshold: Option<usize>,
        agg_resp: &[UserDecryptionResponse],
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        // If there is an error in construction the trusted context,
        // there's not much we can do.
        let server_addresses = self.get_server_addrs();
        let ctx = UserDecTrustedValidationContext::new(
            &server_addresses,
            client_request,
            eip712_domain,
            threshold,
        )?;
        // The EVM path opens shares signcrypted to the client's wallet address; the Solana
        // path enters below through `reconstruct_validated_user_decryption` with its own receiver.
        let receiver = PlaintextReceiver::Evm(self.client_address);

        tracing::debug!(
            "User decryption response reconstruction with mode: {:?}",
            self.decryption_mode,
        );

        // Single classify-and-recover pass per response: `partition_user_decrypt_responses`
        // authenticates (secret-free) *and* un-signcrypts + decodes, so a response is either fully
        // `accepted` or `rejected` — there is no partially-verified in-between state. All consensus
        // values used below (degree, link, per-slot fhe_type / packing factor / slot count) come
        // from `partitioned.invariants`, never from an individual contribution.
        match self.decryption_mode {
            DecryptionMode::BitDecSmall => {
                let partitioned = self.partition_user_decrypt_responses::<Z64>(
                    &ctx, &receiver, agg_resp, enc_key, dec_key,
                )?;
                self.finish_bitdec_reconstruction(partitioned)
            }
            DecryptionMode::NoiseFloodSmall => {
                let partitioned = self.partition_user_decrypt_responses::<Z128>(
                    &ctx, &receiver, agg_resp, enc_key, dec_key,
                )?;
                self.finish_noiseflood_reconstruction(partitioned)
            }
            e => Err(anyhow_error_and_log(format!(
                "Unsupported decryption mode: {e}"
            ))),
        }
    }

    /// The BitDecSmall tail of a user-decryption reconstruction: Shamir-reconstruct every slot of
    /// the partitioned responses and decode the blocks to plaintexts. Shared by the EVM threshold
    /// path and [`Client::reconstruct_validated_user_decryption`].
    fn finish_bitdec_reconstruction(
        &self,
        partitioned: PartitionedUserDecResponses<Z64>,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let pbs_params = self.params.classic_pbs();
        // Note: We will create way too many shares here, if we use BitDec kind of decryption we
        // can actually fit 4*64 bits of actual data in a single share.
        // For now we don't use intra share packing for BitDecSmall
        let per_slot = match partitioned.reconstruct_all_slots(&pbs_params, 1)? {
            Some(per_slot) => per_slot,
            None => return Ok(Vec::new()),
        };

        let mut out = vec![];
        for (fhe_type, packing_factor, decrypted_blocks) in per_slot {
            // extract plaintexts from decrypted blocks
            let mut ptxts64 = Zeroizing::new(Vec::new());
            for block in decrypted_blocks.iter() {
                let scalar = block.to_scalar()?;
                ptxts64.push(scalar);
            }

            // convert to Z128
            out.push((
                fhe_type,
                packing_factor,
                Zeroizing::new(
                    ptxts64
                        .iter()
                        .map(|ptxt| Wrapping(ptxt.0 as u128))
                        .collect_vec(),
                ),
            ));
        }
        out.into_iter()
            .map(|(fhe_type, packing_factor, blocks)| {
                decrypted_blocks_to_plaintext(&pbs_params, fhe_type, packing_factor, &blocks)
            })
            .collect()
    }

    /// The NoiseFloodSmall tail of a user-decryption reconstruction — see
    /// [`Client::finish_bitdec_reconstruction`].
    fn finish_noiseflood_reconstruction(
        &self,
        partitioned: PartitionedUserDecResponses<Z128>,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let pbs_params = self.params.classic_pbs();
        let intra_share_packing = ResiduePolyF4::<Z128>::EXTENSION_DEGREE;
        let per_slot = match partitioned.reconstruct_all_slots(&pbs_params, intra_share_packing)? {
            Some(per_slot) => per_slot,
            None => return Ok(Vec::new()),
        };

        let mut out = vec![];
        for (fhe_type, packing_factor, decrypted_blocks) in per_slot {
            out.push((
                fhe_type,
                packing_factor,
                Zeroizing::new(reconstruct_packed_message(
                    Some(&decrypted_blocks),
                    &pbs_params,
                    fhe_types_to_num_blocks(fhe_type, &pbs_params, packing_factor)?,
                )?),
            ));
        }
        out.into_iter()
            .map(|(fhe_type, packing_factor, blocks)| {
                decrypted_blocks_to_plaintext(&pbs_params, fhe_type, packing_factor, &blocks)
            })
            .collect()
    }

    /// Reconstructs plaintexts from already-validated threshold response payloads — the recovery
    /// and reconstruction half of a threshold user decryption, shared by the EVM and Solana paths.
    ///
    /// The caller has already decided which payloads are trustworthy (the EVM path in
    /// [`validate_user_decrypt_responses`], the Solana path in its verify-then-release rules) and
    /// passes the receiver the shares were signcrypted to. The two paths differ only in that
    /// decision and in the receiver; share recovery and reconstruction exist exactly once, in the
    /// partition machinery above.
    pub(crate) fn reconstruct_validated_user_decryption(
        &self,
        receiver: PlaintextReceiver,
        validated_resps: &[UserDecryptionResponsePayload],
        enc_key: &UnifiedPublicEncKey,
        dec_key: &UnifiedPrivateEncKey,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let first = some_or_err(
            validated_resps.first(),
            "No valid responses parsed".to_string(),
        )?;
        // The caller validated agreement across the payloads, so the consensus invariants are the
        // first payload's — the same fields every other payload was accepted for carrying.
        let invariants = UserDecryptionInvariants::try_from(first.clone())?;
        // TODO: in general this is not true, degree isn't a perfect proxy for num_parties
        let num_parties = 3 * invariants.degree + 1;
        if validated_resps.len() > num_parties {
            return Err(anyhow_error_and_log(format!(
                "Received more shares than expected for number of parties. n={num_parties}, #shares={}",
                validated_resps.len()
            )));
        }

        let mut authenticated = Vec::with_capacity(validated_resps.len());
        for payload in validated_resps {
            // The caller already verified the advertised key against its trusted signer set;
            // parsing it again here is deserialization, not re-authentication.
            let verification_key: PublicSigKey =
                bc2wrap::deserialize_slice(&payload.verification_key)?;
            authenticated.push(AuthenticatedUserDecResponse {
                verification_key,
                role: Role::indexed_from_one(payload.party_id as usize),
                signcrypted_ciphertexts: payload
                    .signcrypted_ciphertexts
                    .iter()
                    .map(|ct| ct.signcrypted_ciphertext.clone())
                    .collect(),
            });
        }

        tracing::debug!(
            "User decryption response reconstruction with mode: {:?}, deg={}, #shares={}",
            self.decryption_mode,
            invariants.degree,
            validated_resps.len()
        );

        match self.decryption_mode {
            DecryptionMode::BitDecSmall => {
                let partitioned = Self::recover_authenticated_responses::<Z64>(
                    invariants,
                    authenticated,
                    Vec::new(),
                    num_parties,
                    &receiver,
                    enc_key,
                    dec_key,
                    validated_resps.len(),
                );
                self.finish_bitdec_reconstruction(partitioned)
            }
            DecryptionMode::NoiseFloodSmall => {
                let partitioned = Self::recover_authenticated_responses::<Z128>(
                    invariants,
                    authenticated,
                    Vec::new(),
                    num_parties,
                    &receiver,
                    enc_key,
                    dec_key,
                    validated_resps.len(),
                );
                self.finish_noiseflood_reconstruction(partitioned)
            }
            e => Err(anyhow_error_and_log(format!(
                "Unsupported decryption mode: {e}"
            ))),
        }
    }

    fn insecure_threshold_user_decryption_resp(
        &self,
        agg_resp: &[UserDecryptionResponse],
        dec_key: &UnifiedPrivateEncKey,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        match self.decryption_mode {
            DecryptionMode::BitDecSmall => {
                self.insecure_threshold_user_decryption_resp_z64(agg_resp, dec_key)
            }
            DecryptionMode::NoiseFloodSmall => {
                self.insecure_threshold_user_decryption_resp_z128(agg_resp, dec_key)
            }
            e => Err(anyhow_error_and_log(format!(
                "Unsupported decryption mode: {e}"
            ))),
        }
    }

    #[expect(clippy::type_complexity)]
    // We do not attempt to zeroize when using these insecure functions.
    fn insecure_threshold_user_decryption_resp_to_blocks<Z: BaseRing>(
        agg_resp: &[UserDecryptionResponse],
        dec_key: &UnifiedPrivateEncKey,
    ) -> anyhow::Result<Vec<(FheTypes, u32, Vec<ResiduePolyF4<Z>>)>>
    where
        ResiduePolyF4<Z>: ErrorCorrect + MemoizedExceptionals,
    {
        let batch_count = agg_resp
            .first()
            .ok_or_else(|| anyhow::anyhow!("agg_resp is empty"))?
            .payload
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("payload is empty in user deryption response"))?
            .signcrypted_ciphertexts
            .len();

        let mut out = vec![];
        for batch_i in 0..batch_count {
            // Recover sharings
            let mut opt_sharings = None;
            let degree = some_or_err(
                some_or_err(agg_resp.first().as_ref(), "empty responses".to_owned())?
                    .payload
                    .as_ref(),
                "empty payload".to_owned(),
            )?
            .degree as usize;
            let fhe_type = agg_resp
                .first()
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("agg_resp is empty"))?
                .payload
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("payload is empty"))?
                .signcrypted_ciphertexts[batch_i]
                .fhe_type()?;
            let packing_factor = agg_resp
                .first()
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("agg_resp is empty"))?
                .payload
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("payload is empty"))?
                .signcrypted_ciphertexts[batch_i]
                .packing_factor;

            // Trust all responses have all expected blocks
            for cur_resp in agg_resp {
                let payload = some_or_err(
                    cur_resp.payload.clone(),
                    "Payload does not exist".to_owned(),
                )?;
                let shares = insecure_decrypt_ignoring_signature(
                    &payload.signcrypted_ciphertexts[batch_i].signcrypted_ciphertext,
                    dec_key,
                )?;

                let cipher_blocks_share: Vec<ResiduePolyF4<Z>> =
                    bc2wrap::deserialize_slice(&shares.bytes)?;
                let mut cur_blocks = Vec::with_capacity(cipher_blocks_share.len());
                for cur_block_share in cipher_blocks_share {
                    cur_blocks.push(cur_block_share);
                }
                if opt_sharings.is_none() {
                    let mut sharings = Vec::new();
                    for _i in 0..cur_blocks.len() {
                        sharings.push(ShamirSharings::new());
                    }
                    opt_sharings = Some(sharings);
                }
                fill_indexed_shares(
                    opt_sharings.as_mut().unwrap(),
                    cur_blocks,
                    Role::indexed_from_one(payload.party_id as usize),
                );
            }
            let sharings = opt_sharings.unwrap();
            // TODO: in general this is not true, degree isn't a perfect proxy for num_parties
            let num_parties = 3 * degree + 1;
            let amount_shares = agg_resp.len();
            if amount_shares > num_parties {
                return Err(anyhow_error_and_log(format!(
                    "Received more shares than expected for number of parties. n={num_parties}, #shares={amount_shares}"
                )));
            }

            let mut decrypted_blocks = Vec::new();
            let pivot = if let Some(pivot) = sharings.first() {
                pivot
            } else {
                return Ok(Vec::new());
            };
            let hints = ReconstructionHints::new(pivot, degree)?;
            for cur_block_shares in sharings {
                // NOTE: this performs optimistic reconstruction
                match reconstruct_w_errors_sync(
                    num_parties,
                    degree,
                    degree,
                    num_parties - amount_shares,
                    &cur_block_shares,
                    &hints,
                ) {
                    Ok(Some(r)) => decrypted_blocks.push(r),
                    Ok(None) => {
                        return Err(anyhow_error_and_log(format!(
                            "Not enough shares to reconstruct. n={num_parties}, deg={degree}, #shares={amount_shares}, block_shares={}",
                            cur_block_shares.shares.len()
                        )));
                    }
                    Err(e) => {
                        return Err(anyhow_error_and_log(format!(
                            "Error reconstructing all blocks: {e}. n={num_parties}, deg={degree}, #shares={amount_shares}, block_shares={}",
                            cur_block_shares.shares.len()
                        )));
                    }
                }
            }
            out.push((fhe_type, packing_factor, decrypted_blocks))
        }
        Ok(out)
    }

    // We do not attempt to zeroize when using these insecure functions.
    fn insecure_threshold_user_decryption_resp_z128(
        &self,
        agg_resp: &[UserDecryptionResponse],
        dec_key: &UnifiedPrivateEncKey,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let all_decrypted_blocks =
            Self::insecure_threshold_user_decryption_resp_to_blocks::<Z128>(agg_resp, dec_key)?;

        let mut out = vec![];

        for (fhe_type, packing_factor, decrypted_blocks) in all_decrypted_blocks {
            let pbs_params = self.params.classic_pbs();

            let recon_blocks = reconstruct_packed_message(
                Some(&decrypted_blocks),
                &pbs_params,
                fhe_types_to_num_blocks(fhe_type, &self.params.classic_pbs(), packing_factor)?,
            )?;

            out.push(decrypted_blocks_to_plaintext(
                &pbs_params,
                fhe_type,
                packing_factor,
                &recon_blocks,
            )?);
        }
        Ok(out)
    }

    /// Decrypt the user decryption response from the threshold KMS.
    /// This function does *not* do any verification and is thus insecure and should be used only for testing.
    /// TODO hide behind flag for insecure function?
    // We do not attempt to zeroize when using these insecure functions.
    fn insecure_threshold_user_decryption_resp_z64(
        &self,
        agg_resp: &[UserDecryptionResponse],
        dec_key: &UnifiedPrivateEncKey,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let all_decrypted_blocks =
            Self::insecure_threshold_user_decryption_resp_to_blocks::<Z64>(agg_resp, dec_key)?;

        let mut out = vec![];
        for (fhe_type, packing_factor, decrypted_blocks) in all_decrypted_blocks {
            let pbs_params = self.params.classic_pbs();

            let mut ptxts64 = Vec::new();

            for opened in decrypted_blocks {
                let v_scalar = opened.to_scalar()?;
                ptxts64.push(v_scalar);
            }

            let ptxts128: Vec<_> = ptxts64
                .iter()
                .map(|ptxt| Wrapping(ptxt.0 as u128))
                .collect();

            out.push(decrypted_blocks_to_plaintext(
                &pbs_params,
                fhe_type,
                packing_factor,
                &ptxts128,
            )?);
        }
        Ok(out)
    }

    /// Partition untrusted user-decryption responses into fully-verified `accepted` and typed
    /// `rejected`, mirroring `partition_public_decrypt_responses` on the public-decryption side.
    ///
    /// Authenticity and consensus are established by the **secret-free**
    /// [`validate_user_decrypt_responses`] (which needs no client key and can be
    /// called independently by e.g. a relayer); this method then un-signcrypts and decodes every
    /// authenticated response with the client's key. A response is `accepted` only if every one of
    /// its signcryptions un-signcrypts *and* its inner bytes decode into a share vector. Any
    /// failure — an authenticity mismatch, a bad signcryption, **or** a malformed inner share —
    /// moves the whole response to `rejected` as one tolerated fault; it never aborts on a single
    /// (untrusted) response and never half-accepts one.
    ///
    /// Because acceptance subsumes recovery, `num_bots = n - accepted.len()` is a single fault count
    /// for the whole partition (see [`PartitionedUserDecResponses::reconstruct_all_slots`]).
    fn partition_user_decrypt_responses<Z: BaseRing + Zeroize>(
        &self,
        trusted_ctx: &UserDecTrustedValidationContext,
        receiver: &PlaintextReceiver,
        agg_resp: &[UserDecryptionResponse],
        enc_key: &UnifiedPublicEncKey,
        dec_key: &UnifiedPrivateEncKey,
    ) -> anyhow::Result<PartitionedUserDecResponses<Z>> {
        // Secret-free authenticity + consensus validation: establishes the invariants (once, from
        // the pivot) and returns the authenticated responses, each already carrying its parsed
        // verification key. No client key is used here.
        // The validator already reports the authenticity failures it dropped, so we start the
        // rejected bucket from those and only append recovery failures below
        let (invariants, authenticated, rejected) =
            match validate_user_decrypt_responses(trusted_ctx, agg_resp) {
                Ok(v) => v.into_parts(),
                Err(e) => {
                    anyhow::bail!("User decryption responses unrecoverably invalid: {e}.",)
                }
            };
        Ok(Self::recover_authenticated_responses(
            invariants,
            authenticated,
            rejected,
            trusted_ctx.num_parties(),
            receiver,
            enc_key,
            dec_key,
            agg_resp.len(),
        ))
    }

    /// Recover (un-signcrypt + decode) each authenticated response under `receiver` — the second
    /// half of [`Client::partition_user_decrypt_responses`], shared with
    /// [`Client::reconstruct_validated_user_decryption`] whose caller authenticates the responses
    /// itself. Recovery failures append to the passed-in `rejected` bucket as one tolerated fault
    /// each; nothing here aborts on a single (untrusted) response and nothing half-accepts one.
    #[allow(clippy::too_many_arguments)]
    fn recover_authenticated_responses<Z: BaseRing + Zeroize>(
        invariants: UserDecryptionInvariants,
        authenticated: Vec<AuthenticatedUserDecResponse>,
        mut rejected: Vec<RejectedUserDecResponse>,
        num_parties: usize,
        receiver: &PlaintextReceiver,
        enc_key: &UnifiedPublicEncKey,
        dec_key: &UnifiedPrivateEncKey,
        total_responses: usize,
    ) -> PartitionedUserDecResponses<Z> {
        let mut accepted = Vec::with_capacity(authenticated.len());

        // Reuse the verification key that was already deserialized during authentication.
        for authenticated_resp in &authenticated {
            let signcrypted_ciphertexts = &authenticated_resp.signcrypted_ciphertexts;
            let role = authenticated_resp.role;
            let unsign_key = UnifiedUnsigncryptionKey::new(
                dec_key,
                enc_key,
                &authenticated_resp.verification_key,
                receiver.as_bytes(),
            );
            let mut shares_per_slot = Vec::with_capacity(signcrypted_ciphertexts.len());
            let mut recovered_ok = true;
            for ct in signcrypted_ciphertexts {
                match unsign_key.unsigncrypt_plaintext(&DSEP_USER_DECRYPTION, ct, &invariants.link)
                {
                    Ok(decryption_share) => {
                        match bc2wrap::deserialize_slice::<Vec<ResiduePolyF4<Z>>>(
                            &decryption_share.plaintext.bytes,
                        ) {
                            Ok(cipher_blocks_share) => {
                                shares_per_slot.push(Zeroizing::new(cipher_blocks_share));
                            }
                            Err(e) => {
                                tracing::warn!("Malformed inner share from party {role}: {e}");
                                recovered_ok = false;
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Could not decrypt or validate signcrypted response from party {role}: {e}"
                        );
                        recovered_ok = false;
                        break;
                    }
                }
            }
            if recovered_ok {
                accepted.push(AcceptedUserDecResponse {
                    role,
                    shares_per_slot,
                });
            } else {
                rejected.push(RejectedUserDecResponse {
                    role: Some(role),
                    reason: UserDecRejectReason::Unrecoverable,
                });
            }
        }

        let partitioned = PartitionedUserDecResponses {
            invariants,
            accepted,
            rejected,
            num_parties,
        };
        if !partitioned.rejected.is_empty() {
            tracing::warn!(
                "User decryption accepted {} responses out of {} authenticated. \
                Rejected {} out of {} total response(s): {:?}",
                partitioned.accepted.len(),
                authenticated.len(),
                partitioned.rejected.len(),
                total_responses,
                partitioned
                    .rejected
                    .iter()
                    .map(|r| (r.role, &r.reason))
                    .collect::<Vec<_>>(),
            );
        }
        partitioned
    }

    /// Reconstruct every block of one slot from its Shamir sharings
    /// Expects all sharings to have the same degree and the same number of parties, and that `num_bots`
    /// is the number of missing/rejected/unrecoverable responses.
    ///
    /// We can correct up to threshold.saturated_sub(num_bots) errors, so
    /// the numbers of corrupted shares + num_bots must be <= threshold,
    /// otherwise reconstruction fails (hence the NOTE about optimism in the code).
    /// Returns `Ok(None)` when there are no shares at all (empty slot).
    fn reconstruct_blocks<Z: BaseRing + Zeroize>(
        num_parties: usize,
        degree: usize,
        num_bots: usize,
        sharings: &[ShamirSharings<ResiduePolyF4<Z>>],
    ) -> anyhow::Result<Option<Zeroizing<Vec<ResiduePolyF4<Z>>>>>
    where
        ResiduePolyF4<Z>: ErrorCorrect,
    {
        if num_bots > degree {
            return Err(anyhow_error_and_log(format!(
                "Too many faulty user decryption responses: {num_bots} > t={degree} (n={num_parties})"
            )));
        }
        let pivot = match sharings.first() {
            Some(pivot) => pivot,
            None => return Ok(None),
        };
        let hints = ReconstructionHints::new(pivot, degree)?;
        let mut decrypted_blocks = Zeroizing::new(Vec::with_capacity(sharings.len()));
        for cur_block_shares in sharings {
            // NOTE: this performs optimistic reconstruction
            match reconstruct_w_errors_sync(
                num_parties,
                degree,
                degree,
                num_bots,
                cur_block_shares,
                &hints,
            ) {
                Ok(Some(r)) => decrypted_blocks.push(r),
                Ok(None) => {
                    return Err(anyhow_error_and_log(format!(
                        "Not enough shares to reconstruct. n={num_parties}, deg={degree}, num_bots={num_bots}, block_shares={}",
                        cur_block_shares.shares.len()
                    )));
                }
                Err(e) => {
                    return Err(anyhow_error_and_log(format!(
                        "Error reconstructing all blocks: {e}. n={num_parties}, deg={degree}, num_bots={num_bots}, block_shares={}",
                        cur_block_shares.shares.len()
                    )));
                }
            }
        }
        Ok(Some(decrypted_blocks))
    }
}

// This testing struct needs to be outside of js_api module
// since it is needed in the tests to generate the right files for js/wasm tests.
//
// NOTE: this struct is intentionally *not* exposed to wasm and is *not* a stable
// type. The JS tests do not load it directly; instead they load a
// [StableUserDecryptionTestVector] (produced by [TestingUserDecryptionTranscript::write_stable_test_vector_json])
// which is decoupled from this in-memory layout. This lets an older published wasm
// build be exercised against a vector generated by a newer KMS.
#[cfg(feature = "wasm_tests")]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TestingUserDecryptionTranscript {
    // client
    pub(crate) server_addrs: std::collections::HashMap<u32, alloy_primitives::Address>,
    pub(crate) client_address: alloy_primitives::Address,
    pub(crate) client_sk: Option<PrivateSigKey>,
    pub(crate) degree: u32,
    pub(crate) params: threshold_execution::tfhe_internals::parameters::DKGParams,
    // example pt and ct
    pub(crate) fhe_types: Vec<i32>,
    pub(crate) pts: Vec<Vec<u8>>,
    pub(crate) cts: Vec<Vec<u8>>,
    // request
    pub(crate) request: Option<UserDecryptionRequest>,
    // We keep the unified keys here because for legacy tests we need to produce legacy transcripts
    pub(crate) eph_sk: UnifiedPrivateEncKey,
    pub(crate) eph_pk: UnifiedPublicEncKey,
    // response
    pub(crate) agg_resp: Vec<kms_grpc::kms::v1::UserDecryptionResponse>,
}

/// A single KMS server identity (id + EIP-55 address) in the stable test vector.
#[cfg(all(test, feature = "wasm_tests"))]
#[derive(serde::Serialize)]
pub(crate) struct StableServerIdAddr {
    pub id: u32,
    pub addr: String,
}

/// An expected plaintext used by the JS test to assert the decryption result.
#[cfg(all(test, feature = "wasm_tests"))]
#[derive(serde::Serialize)]
pub(crate) struct StableExpectedPlaintext {
    pub fhe_type: i32,
    /// Little-endian plaintext bytes, hex-encoded (no `0x` prefix).
    pub plaintext_hex: String,
}

/// A stable, self-describing representation of a user decryption transcript that the
/// JS/WASM tests (`tests/js/test.js`) load instead of [TestingUserDecryptionTranscript].
///
/// Every field is encoded in the exact hex/JSON shape that the *stable* public WASM API
/// (`process_user_decryption_resp_from_js`, `new_client`, `u8vec_to_ml_kem_pke_pk`/`sk`)
/// already accepts. None of [TestingUserDecryptionTranscript]'s Rust layout leaks into the
/// serialized form, so a vector generated by a newer KMS can be consumed by an older wasm
/// build that no longer carries the same testing struct.
///
/// # Backward compatibility
///
/// Only **adding new fields is backward-compatible** — an older `test.js` simply ignores keys
/// it doesn't know about. Any other change (renaming a field, removing a field, changing the
/// inner shape of `request` / `eip712_domain` / `responses`, or introducing a new
/// `fhe_parameter` value) will break older published wasm builds that consume the vector.
///
/// In practice this means **any future change must be additive and optional**: new fields
/// must be added as `Option<T>` (or have a sensible default on the JS side) so that an older
/// `test.js` keeps working when the field is absent, and a newer `test.js` can opt in when it
/// is present. Treat this struct as an append-only wire format, not as a normal Rust type.
#[cfg(all(test, feature = "wasm_tests"))]
#[derive(serde::Serialize)]
pub(crate) struct StableUserDecryptionTestVector {
    /// FHE parameter name accepted by `new_client` (`"test"` or `"default"`).
    pub fhe_parameter: String,
    /// Client (wallet) address, EIP-55 checksummed.
    pub client_address: String,
    /// KMS server identities.
    pub server_addrs: Vec<StableServerIdAddr>,
    /// Reconstruction threshold/degree; `None` for the centralized case.
    pub threshold: Option<u32>,
    /// The user decryption request in the hex shape `process_user_decryption_resp_from_js` expects.
    pub request: ParsedUserDecryptionRequestHex,
    /// The EIP-712 domain of the request.
    pub eip712_domain: kms_grpc::kms::v1::Eip712DomainMsg,
    /// The aggregated server responses in hex shape.
    pub responses: Vec<UserDecryptionResponseHex>,
    /// Ephemeral public encryption key, hex of `ml_kem_pke_pk_to_u8vec` (safe-serialized).
    pub enc_pk: String,
    /// Ephemeral private decryption key, hex of `ml_kem_pke_sk_to_u8vec` (bincode).
    pub enc_sk: String,
    /// Expected plaintext(s) for assertions.
    pub expected: Vec<StableExpectedPlaintext>,
}

#[cfg(all(test, feature = "wasm_tests"))]
impl TestingUserDecryptionTranscript {
    /// Serialize this transcript as a pretty-printed [StableUserDecryptionTestVector] JSON file.
    ///
    /// Creates any missing parent directories. The encodings used here are byte-identical to
    /// the stable WASM helpers, so the resulting JSON round-trips through the public API
    /// unchanged.
    pub(crate) fn write_stable_test_vector_json(&self, path: &str) -> anyhow::Result<()> {
        let vector = self.to_stable_test_vector()?;
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(&vector)?)?;
        Ok(())
    }

    fn to_stable_test_vector(&self) -> anyhow::Result<StableUserDecryptionTestVector> {
        let request = self
            .request
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("transcript has no request"))?;
        let eip712_domain = request
            .domain
            .clone()
            .ok_or_else(|| anyhow::anyhow!("request has no eip712 domain"))?;
        let parsed = ParsedUserDecryptionRequest::try_from(request)?;

        // The `fhe_parameter` string is the name accepted by `new_client` that reconstructs
        // the same [DKGParams] used to produce this transcript.
        let fhe_parameter =
            if self.params == threshold_execution::tfhe_internals::parameters::PARAMS_TEST_BK_SNS {
                "test"
            } else {
                "default"
            };

        // enc_pk: byte-identical to `ml_kem_pke_pk_to_u8vec`.
        let enc_pk = {
            let mut buf = Vec::new();
            tfhe::safe_serialization::safe_serialize(
                &self.eph_pk,
                &mut buf,
                crate::consts::SAFE_SER_SIZE_LIMIT,
            )
            .map_err(|e| anyhow::anyhow!("could not serialize enc_pk: {e}"))?;
            hex::encode(buf)
        };
        // enc_sk: byte-identical to `ml_kem_pke_sk_to_u8vec`.
        let enc_sk = hex::encode(bc2wrap::serialize(
            &self.eph_sk.clone().unwrap_ml_kem_512(),
        )?);

        let server_addrs = self
            .server_addrs
            .iter()
            .map(|(id, addr)| StableServerIdAddr {
                id: *id,
                addr: addr.to_checksum(None),
            })
            .collect();

        let responses = self
            .agg_resp
            .iter()
            .map(UserDecryptionResponseHex::try_from)
            .collect::<anyhow::Result<Vec<_>>>()?;

        let expected = self
            .fhe_types
            .iter()
            .zip(self.pts.iter())
            .map(|(fhe_type, pt)| StableExpectedPlaintext {
                fhe_type: *fhe_type,
                plaintext_hex: hex::encode(pt),
            })
            .collect();

        Ok(StableUserDecryptionTestVector {
            fhe_parameter: fhe_parameter.to_string(),
            client_address: self.client_address.to_checksum(None),
            server_addrs,
            threshold: (self.degree > 0).then_some(self.degree),
            request: ParsedUserDecryptionRequestHex::from(&parsed),
            eip712_domain,
            responses,
            enc_pk,
            enc_sk,
            expected,
        })
    }
}

#[wasm_bindgen]
#[derive(serde::Serialize, Debug)]
pub struct CiphertextHandle(Vec<u8>);

impl CiphertextHandle {
    pub fn new(handle: Vec<u8>) -> Self {
        CiphertextHandle(handle)
    }
}

/// Validity of this struct is not checked.
#[wasm_bindgen]
pub struct ParsedUserDecryptionRequest {
    // We allow dead_code because these are required to parse from JSON
    #[allow(dead_code)]
    signature: Option<alloy_primitives::Signature>,
    #[allow(dead_code)]
    client_address: alloy_primitives::Address,
    enc_key: Vec<u8>,
    ciphertext_handles: Vec<CiphertextHandle>,
    eip712_verifying_contract: alloy_primitives::Address,
    extra_data: Vec<u8>,
}

impl ParsedUserDecryptionRequest {
    pub fn new(
        signature: Option<alloy_primitives::Signature>,
        client_address: alloy_primitives::Address,
        enc_key: Vec<u8>,
        ciphertext_handles: Vec<CiphertextHandle>,
        eip712_verifying_contract: alloy_primitives::Address,
        extra_data: Vec<u8>,
    ) -> Self {
        Self {
            signature,
            client_address,
            enc_key,
            ciphertext_handles,
            eip712_verifying_contract,
            extra_data,
        }
    }

    pub fn enc_key(&self) -> &[u8] {
        &self.enc_key
    }

    pub fn extra_data(&self) -> &[u8] {
        &self.extra_data
    }

    /// The ciphertext handles, in request order and with duplicates preserved, as plain bytes.
    ///
    /// Order and multiplicity are what a linker binds, so this must stay a faithful copy of the
    /// request's list — never deduplicated, never sorted.
    pub fn ciphertext_handle_bytes(&self) -> Vec<Vec<u8>> {
        self.ciphertext_handles
            .iter()
            .map(|handle| handle.0.clone())
            .collect()
    }
}

pub(crate) fn hex_decode_js_err(msg: &str) -> Result<Vec<u8>, JsError> {
    if msg.len() >= 2 {
        if msg[0..2] == *"0x" {
            hex::decode(&msg[2..]).map_err(|e| JsError::new(&e.to_string()))
        } else {
            hex::decode(msg).map_err(|e| JsError::new(&e.to_string()))
        }
    } else {
        Err(JsError::new(
            "cannot decode hex string with fewer than 2 characters",
        ))
    }
}

// we need this type because the json fields are hex-encoded
// which cannot be converted to Vec<u8> automatically.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct ParsedUserDecryptionRequestHex {
    signature: Option<String>,
    client_address: String,
    enc_key: String,
    ciphertext_handles: Vec<String>,
    eip712_verifying_contract: String,
    extra_data: String,
}

impl TryFrom<&ParsedUserDecryptionRequestHex> for ParsedUserDecryptionRequest {
    type Error = JsError;

    fn try_from(req_hex: &ParsedUserDecryptionRequestHex) -> Result<Self, Self::Error> {
        let signature_buf = req_hex
            .signature
            .as_ref()
            .map(|sig| hex_decode_js_err(sig))
            .transpose()?;
        let signature = signature_buf
            .map(|buf| alloy_primitives::Signature::try_from(buf.as_slice()))
            .transpose()
            .map_err(|e| JsError::new(&e.to_string()))?;
        let client_address =
            alloy_primitives::Address::parse_checksummed(&req_hex.client_address, None)
                .map_err(|e| JsError::new(&e.to_string()))?;
        let eip712_verifying_contract =
            alloy_primitives::Address::parse_checksummed(&req_hex.eip712_verifying_contract, None)
                .map_err(|e| JsError::new(&e.to_string()))?;
        let extra_data = if req_hex.extra_data.is_empty() {
            vec![]
        } else {
            hex_decode_js_err(&req_hex.extra_data)?
        };
        let out = Self {
            signature,
            client_address,
            enc_key: hex_decode_js_err(&req_hex.enc_key)?,
            ciphertext_handles: req_hex
                .ciphertext_handles
                .iter()
                .map(|hdl_str| hex_decode_js_err(hdl_str).map(CiphertextHandle))
                .collect::<Result<Vec<_>, JsError>>()?,
            eip712_verifying_contract,
            extra_data,
        };
        Ok(out)
    }
}

impl TryFrom<JsValue> for ParsedUserDecryptionRequest {
    type Error = JsError;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        // JsValue -> JsClientUserDecryptionRequestHex
        let req_hex: ParsedUserDecryptionRequestHex =
            serde_wasm_bindgen::from_value(value).map_err(|e| JsError::new(&e.to_string()))?;

        // JsClientUserDecryptionRequestHex -> JsClientUserDecryptionRequest
        ParsedUserDecryptionRequest::try_from(&req_hex)
    }
}

impl From<&ParsedUserDecryptionRequest> for ParsedUserDecryptionRequestHex {
    fn from(value: &ParsedUserDecryptionRequest) -> Self {
        Self {
            signature: value
                .signature
                .as_ref()
                .map(|sig| hex::encode(sig.as_bytes())),
            client_address: value.client_address.to_checksum(None),
            enc_key: hex::encode(&value.enc_key),
            ciphertext_handles: value
                .ciphertext_handles
                .iter()
                .map(|hdl| hex::encode(&hdl.0))
                .collect::<Vec<_>>(),
            eip712_verifying_contract: value.eip712_verifying_contract.to_checksum(None),
            extra_data: hex::encode(&value.extra_data),
        }
    }
}

// The hex/JSON wire shape for a user decryption response. It is deserialized by
// `js_api::js_to_resp` in the wasm build, and serialized by the stable test-vector generator
// ([TestingUserDecryptionTranscript::write_stable_test_vector_json]) on the host. It is therefore only
// compiled in the wasm build (`not(non-wasm)`, where `js_api` exists) or in host tests that
// exercise the generator — never in the host non-test library, where it would be dead.
#[cfg(any(not(feature = "non-wasm"), all(test, feature = "wasm_tests")))]
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct UserDecryptionResponseHex {
    // NOTE: this is the external signature
    pub(crate) signature: String,
    pub(crate) payload: Option<String>,
    pub(crate) extra_data: Option<String>,
}

// Only the stable test-vector generator constructs this type; in the wasm build it is solely
// deserialized by `js_api::js_to_resp`.
#[cfg(all(test, feature = "wasm_tests"))]
impl TryFrom<&UserDecryptionResponse> for UserDecryptionResponseHex {
    type Error = anyhow::Error;

    fn try_from(resp: &UserDecryptionResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            signature: hex::encode(&resp.external_signature),
            payload: resp
                .payload
                .as_ref()
                .map(|inner| bc2wrap::serialize(inner).map(hex::encode))
                .transpose()?,
            extra_data: Some(hex::encode(&resp.extra_data)),
        })
    }
}

impl TryFrom<&UserDecryptionRequest> for ParsedUserDecryptionRequest {
    type Error = anyhow::Error;

    fn try_from(value: &UserDecryptionRequest) -> Result<Self, Self::Error> {
        let domain = value
            .domain
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing domain"))?;

        let client_address =
            alloy_primitives::Address::parse_checksummed(&value.client_address, None)?;

        let eip712_verifying_contract =
            alloy_primitives::Address::parse_checksummed(domain.verifying_contract.clone(), None)?;

        let ciphertext_handles = value
            .typed_ciphertexts
            .iter()
            .map(|ct| CiphertextHandle(ct.external_handle.clone()))
            .collect::<Vec<_>>();

        let out = Self {
            signature: None,
            client_address,
            enc_key: value.enc_key.clone(),
            ciphertext_handles,
            eip712_verifying_contract,
            extra_data: value.extra_data.clone(),
        };
        Ok(out)
    }
}

/// Compute the link as (eip712_signing_hash(pk, domain) || hash(ciphertext handles)).
/// TODO(#2781) move to signatures module
pub fn compute_link(
    req: &ParsedUserDecryptionRequest,
    domain: &Eip712Domain,
) -> anyhow::Result<Vec<u8>> {
    // check consistency
    let handles = req
        .ciphertext_handles
        .iter()
        .enumerate()
        .map(|(idx, c)| {
            if c.0.len() > 32 {
                anyhow::bail!(
                    "external_handle at index {idx} too long: {} bytes (max 32)",
                    c.0.len()
                );
            }
            Ok(alloy_primitives::FixedBytes::<32>::left_padding_from(&c.0))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let linker = UserDecryptionLinker {
        publicKey: req.enc_key.clone().into(),
        handles,
        userAddress: req.client_address,
    };
    // TODO(#2781) ensure s is normalized!!!
    let link = linker.eip712_signing_hash(domain).to_vec();

    Ok(link)
}

/// Helper method for combining reconstructed messages after decryption.
fn decrypted_blocks_to_plaintext(
    params: &ClassicPBSParameters,
    fhe_type: FheTypes,
    packing_factor: u32,
    recon_blocks: &[Z128],
) -> anyhow::Result<TypedPlaintext> {
    let bits_in_block = params.message_modulus_log() * packing_factor;
    let res_pt = match fhe_type {
        FheTypes::Uint2048 => {
            combine_decryptions::<tfhe::integer::bigint::U2048>(bits_in_block, recon_blocks)
                .map(TypedPlaintext::from_u2048)
        }
        FheTypes::Uint1024 => {
            combine_decryptions::<tfhe::integer::bigint::U1024>(bits_in_block, recon_blocks)
                .map(TypedPlaintext::from_u1024)
        }
        FheTypes::Uint512 => {
            combine_decryptions::<tfhe::integer::bigint::U512>(bits_in_block, recon_blocks)
                .map(TypedPlaintext::from_u512)
        }
        FheTypes::Uint256 => {
            combine_decryptions::<tfhe::integer::U256>(bits_in_block, recon_blocks)
                .map(TypedPlaintext::from_u256)
        }
        FheTypes::Uint160 => {
            combine_decryptions::<tfhe::integer::U256>(bits_in_block, recon_blocks)
                .map(TypedPlaintext::from_u160)
        }
        FheTypes::Uint128 => combine_decryptions::<u128>(bits_in_block, recon_blocks)
            .map(|x| TypedPlaintext::new(x, fhe_type)),
        FheTypes::Uint80 => {
            combine_decryptions::<u128>(bits_in_block, recon_blocks).map(TypedPlaintext::from_u80)
        }
        FheTypes::Bool
        | FheTypes::Uint4
        | FheTypes::Uint8
        | FheTypes::Uint16
        | FheTypes::Uint32
        | FheTypes::Uint64 => combine_decryptions::<u64>(bits_in_block, recon_blocks)
            .map(|x| TypedPlaintext::new(x as u128, fhe_type)),
        unsupported_fhe_type => anyhow::bail!("Unsupported fhe_type {unsupported_fhe_type:?}"),
    };
    res_pt.map_err(|error| anyhow_error_and_log(format!("Panicked in combining {error}")))
}
