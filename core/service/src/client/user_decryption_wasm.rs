use crate::client::client_wasm::Client;
#[cfg(feature = "wasm_tests")]
use crate::cryptography::signatures::PrivateSigKey;
use crate::cryptography::signcryption::insecure_decrypt_ignoring_signature;
use crate::cryptography::{
    encryption::{UnifiedPrivateEncKey, UnifiedPublicEncKey},
    signatures::{internal_verify_sig, PublicSigKey, Signature},
    signcryption::{UnifiedUnsigncryptionKey, UnsigncryptFHEPlaintext},
};
use crate::engine::validation::{
    check_ext_user_decryption_signature, validate_user_decrypt_responses_against_request,
    DSEP_USER_DECRYPTION,
};
use crate::{anyhow_error_and_log, some_or_err};
use alloy_sol_types::Eip712Domain;
use alloy_sol_types::SolStruct;
use itertools::Itertools;
use kms_grpc::kms::v1::{
    TypedPlaintext, UserDecryptionRequest, UserDecryptionResponse, UserDecryptionResponsePayload,
};
use kms_grpc::rpc_types::fhe_types_to_num_blocks;
use kms_grpc::solidity_types::UserDecryptionLinker;
use std::num::Wrapping;
use tfhe::shortint::ClassicPBSParameters;
use tfhe::FheTypes;
use threshold_fhe::algebra::base_ring::{Z128, Z64};
use threshold_fhe::algebra::error_correction::MemoizedExceptionals;
use threshold_fhe::algebra::galois_rings::degree_4::ResiduePolyF4;
use threshold_fhe::algebra::structure_traits::{BaseRing, ErrorCorrect, Ring};
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::endpoints::reconstruct::{
    combine_decryptions, reconstruct_packed_message,
};
use threshold_fhe::execution::runtime::party::Role;
use threshold_fhe::execution::sharing::shamir::{
    fill_indexed_shares, reconstruct_w_errors_sync, ShamirSharings,
};
use threshold_fhe::execution::tfhe_internals::parameters::AugmentedCiphertextParameters;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsError, JsValue};

impl Client {
    /// Processes the aggregated user decryption responses to attempt to decrypt
    /// the encryption of the secret shared plaintext and returns this. Validates the
    /// response matches the request, checks signatures, and handles both
    /// centralized and distributed cases.
    ///
    /// If there is more than one response or more than one server identity,
    /// then the threshold mode is used.
    pub fn process_user_decryption_resp(
        &self,
        client_request: &ParsedUserDecryptionRequest,
        eip712_domain: &Eip712Domain,
        agg_resp: &[UserDecryptionResponse],
        enc_key: &UnifiedPublicEncKey,
        dec_key: &UnifiedPrivateEncKey,
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
                agg_resp,
                enc_key,
                dec_key,
            )
        } else {
            self.threshold_user_decryption_resp(
                client_request,
                eip712_domain,
                agg_resp,
                enc_key,
                dec_key,
            )
        }
    }

    /// Processes the aggregated user decryption response to attempt to decrypt
    /// the encryption of the secret shared plaintext and returns this.
    /// This function does *not* do any verification and is thus insecure and should be used only for testing.
    /// TODO hide behind flag for insecure function?
    pub fn insecure_process_user_decryption_resp(
        &self,
        agg_resp: &[UserDecryptionResponse],
        enc_key: &UnifiedPublicEncKey,
        dec_key: &UnifiedPrivateEncKey,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let sig_sk = match &self.client_sk {
            Some(sk) => sk,
            None => {
                return Err(anyhow_error_and_log(
                    "missing client signing key".to_string(),
                ));
            }
        };
        let receiver_id = self.client_address.to_vec();
        let client_keys = UnifiedUnsigncryptionKey {
            sender_verf_key: &sig_sk.verf_key(),
            decryption_key: dec_key,
            encryption_key: enc_key,
            receiver_id: &receiver_id,
        };

        // The same logic is used in `process_user_decryption_resp`.
        if agg_resp.len() <= 1 && self.server_identities.len() == 1 {
            self.insecure_centralized_user_decryption_resp(agg_resp, &client_keys)
        } else {
            self.insecure_threshold_user_decryption_resp(agg_resp, &client_keys)
        }
    }

    /// Decrypt the user decryption response from the centralized KMS and verify that the signatures are valid
    fn centralized_user_decryption_resp(
        &self,
        request: &ParsedUserDecryptionRequest,
        eip712_domain: &Eip712Domain,
        agg_resp: &[UserDecryptionResponse],
        enc_key: &UnifiedPublicEncKey,
        dec_key: &UnifiedPrivateEncKey,
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

        let cur_verf_key: PublicSigKey = bc2wrap::deserialize_safe(&payload.verification_key)?;

        // NOTE: ID starts at 1
        let expected_server_addr = if let Some(server_addr) = stored_server_addrs.get(&1) {
            if *server_addr != cur_verf_key.address() {
                return Err(anyhow_error_and_log("server address is not consistent"));
            }
            server_addr
        } else {
            return Err(anyhow_error_and_log("missing server address at ID 1"));
        };

        // prefer the normal ECDSA verification over the EIP712 one
        if resp.signature.is_empty() {
            // we only consider the external signature in wasm
            let eip712_signature = &resp.external_signature;

            // check signature
            if eip712_signature.is_empty() {
                return Err(anyhow_error_and_log("empty signature"));
            }

            check_ext_user_decryption_signature(
                eip712_signature,
                &payload,
                request,
                eip712_domain,
                expected_server_addr,
            )
            .inspect_err(|e| {
                tracing::warn!("signature on received response is not valid ({})", e)
            })?;
        } else {
            let sig = Signature {
                sig: k256::ecdsa::Signature::from_slice(&resp.signature)?,
            };
            internal_verify_sig(
                &DSEP_USER_DECRYPTION,
                &bc2wrap::serialize(&payload)?,
                &sig,
                &cur_verf_key,
            )
            .inspect_err(|e| {
                tracing::warn!("signature on received response is not valid ({})", e)
            })?;
        }
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
        client_keys: &UnifiedUnsigncryptionKey,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let resp = some_or_err(agg_resp.last(), "Response does not exist".to_owned())?;
        let payload = some_or_err(resp.payload.clone(), "Payload does not exist".to_owned())?;

        let mut out = vec![];
        for ct in payload.signcrypted_ciphertexts {
            out.push(
                crate::cryptography::signcryption::insecure_decrypt_ignoring_signature(
                    &ct.signcrypted_ciphertext,
                    client_keys,
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
        agg_resp: &[UserDecryptionResponse],
        enc_key: &UnifiedPublicEncKey,
        dec_key: &UnifiedPrivateEncKey,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let validated_resps = some_or_err(
            validate_user_decrypt_responses_against_request(
                &self.get_server_addrs(),
                client_request,
                eip712_domain,
                agg_resp,
            )?,
            "Could not validate request".to_owned(),
        )?;
        let degree = some_or_err(
            validated_resps.first(),
            "No valid responses parsed".to_string(),
        )?
        .degree as usize;

        let amount_shares = validated_resps.len();
        // TODO: in general this is not true, degree isn't a perfect proxy for num_parties
        let num_parties = 3 * degree + 1;
        if amount_shares > num_parties {
            return Err(anyhow_error_and_log(format!(
                    "Received more shares than expected for number of parties. n={num_parties}, #shares={amount_shares}"
                )));
        }

        let pbs_params = self
            .params
            .get_params_basics_handle()
            .to_classic_pbs_parameters();

        tracing::info!(
            "User decryption response reconstruction with mode: {:?}. deg={degree}, #shares={amount_shares}",
            self.decryption_mode
        );

        let res = match self.decryption_mode {
            DecryptionMode::BitDecSmall => {
                // Note: We will create way too many shares here, if we use BitDec kind of decryption we can actually fit 4*64 bits of actual data in a single share.
                let all_sharings =
                    self.recover_sharings::<Z64>(&validated_resps, enc_key, dec_key)?;

                let mut out = vec![];
                for (fhe_type, packing_factor, sharings, recovery_errors) in all_sharings {
                    // we can tolerate at most t=degree errors in the recovered shares
                    if recovery_errors > degree {
                        return Err(anyhow_error_and_log(
                            format!("Too many errors in share recovery / signcryption: {recovery_errors} (threshold {degree})"),
                        ));
                    }
                    let mut decrypted_blocks = Vec::new();
                    for cur_block_shares in sharings {
                        // NOTE: this performs optimistic reconstruction
                        match reconstruct_w_errors_sync(
                            num_parties,
                            degree,
                            degree,
                            num_parties - amount_shares,
                            &cur_block_shares,
                        ) {
                            Ok(Some(r)) => decrypted_blocks.push(r),
                            Ok(None) => {
                                return Err(anyhow_error_and_log(
                                    format!("Not enough shares to reconstruct. n={num_parties}, deg={degree}, #shares={amount_shares}, block_shares={}, recovery_errors={recovery_errors}", &cur_block_shares.shares.len()),
                                ));
                            }
                            Err(e) => {
                                return Err(anyhow_error_and_log(format!(
                                    "Error reconstructing all blocks: {e}. n={num_parties}, deg={degree}, #shares={amount_shares}, block_shares={}, recovery_errors={recovery_errors}", &cur_block_shares.shares.len()
                                )));
                            }
                        }
                    }
                    // extract plaintexts from decrypted blocks
                    let mut ptxts64 = Vec::new();
                    for block in decrypted_blocks {
                        let scalar = block.to_scalar()?;
                        ptxts64.push(scalar);
                    }

                    // convert to Z128
                    out.push((
                        fhe_type,
                        packing_factor,
                        ptxts64
                            .iter()
                            .map(|ptxt| Wrapping(ptxt.0 as u128))
                            .collect_vec(),
                    ));
                }
                out
            }
            DecryptionMode::NoiseFloodSmall => {
                let all_sharings =
                    self.recover_sharings::<Z128>(&validated_resps, enc_key, dec_key)?;

                let mut out = vec![];
                for (fhe_type, packing_factor, sharings, recovery_errors) in all_sharings {
                    // we can tolerate at most t=degree errors in the recovered shares
                    if recovery_errors > degree {
                        return Err(anyhow_error_and_log(
                            format!("Too many errors in share recovery / signcryption: {recovery_errors} (threshold {degree})"),
                        ));
                    }

                    let mut decrypted_blocks = Vec::new();
                    for cur_block_shares in sharings {
                        // NOTE: this performs optimistic reconstruction
                        match reconstruct_w_errors_sync(
                            num_parties,
                            degree,
                            degree,
                            num_parties - amount_shares,
                            &cur_block_shares,
                        ) {
                            Ok(Some(r)) => decrypted_blocks.push(r),
                            Ok(None) => {
                                return Err(anyhow_error_and_log(
                                    format!("Not enough shares to reconstruct. n={num_parties}, deg={degree}, #shares={amount_shares}, block_shares={}, recovery_errors={recovery_errors}", &cur_block_shares.shares.len()),
                                ));
                            }
                            Err(e) => {
                                return Err(anyhow_error_and_log(format!(
                                    "Error reconstructing all blocks: {e}. n={num_parties}, deg={degree}, #shares={amount_shares}, block_shares={}, recovery_errors={recovery_errors}", &cur_block_shares.shares.len()
                                )));
                            }
                        }
                    }

                    out.push((
                        fhe_type,
                        packing_factor,
                        reconstruct_packed_message(
                            Some(decrypted_blocks),
                            &pbs_params,
                            fhe_types_to_num_blocks(
                                fhe_type,
                                &self
                                    .params
                                    .get_params_basics_handle()
                                    .to_classic_pbs_parameters(),
                                packing_factor,
                            )?,
                        )?,
                    ));
                }
                out
            }
            e => {
                return Err(anyhow_error_and_log(format!(
                    "Unsupported decryption mode: {e}"
                )));
            }
        };

        let mut final_result = vec![];
        for (fhe_type, packing_factor, res) in res {
            final_result.push(decrypted_blocks_to_plaintext(
                &pbs_params,
                fhe_type,
                packing_factor,
                res,
            )?);
        }
        Ok(final_result)
    }

    fn insecure_threshold_user_decryption_resp(
        &self,
        agg_resp: &[UserDecryptionResponse],
        client_keys: &UnifiedUnsigncryptionKey,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        match self.decryption_mode {
            DecryptionMode::BitDecSmall => {
                self.insecure_threshold_user_decryption_resp_z64(agg_resp, client_keys)
            }
            DecryptionMode::NoiseFloodSmall => {
                self.insecure_threshold_user_decryption_resp_z128(agg_resp, client_keys)
            }
            e => Err(anyhow_error_and_log(format!(
                "Unsupported decryption mode: {e}"
            ))),
        }
    }

    #[allow(clippy::type_complexity)]
    fn insecure_threshold_user_decryption_resp_to_blocks<Z: BaseRing>(
        agg_resp: &[UserDecryptionResponse],
        client_keys: &UnifiedUnsigncryptionKey,
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
                    client_keys,
                )?;

                let cipher_blocks_share: Vec<ResiduePolyF4<Z>> =
                    bc2wrap::deserialize_unsafe(&shares.bytes)?;
                let mut cur_blocks = Vec::with_capacity(cipher_blocks_share.len());
                for cur_block_share in cipher_blocks_share {
                    cur_blocks.push(cur_block_share);
                }
                if opt_sharings.is_none() {
                    opt_sharings = Some(Vec::new());
                    for _i in 0..cur_blocks.len() {
                        (opt_sharings.as_mut()).unwrap().push(ShamirSharings::new());
                    }
                }
                let num_values = cur_blocks.len();
                fill_indexed_shares(
                    opt_sharings.as_mut().unwrap(),
                    cur_blocks,
                    num_values,
                    Role::indexed_from_one(payload.party_id as usize),
                )?;
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
            for cur_block_shares in sharings {
                // NOTE: this performs optimistic reconstruction
                match reconstruct_w_errors_sync(
                    num_parties,
                    degree,
                    degree,
                    num_parties - amount_shares,
                    &cur_block_shares,
                ) {
                    Ok(Some(r)) => decrypted_blocks.push(r),
                    Ok(None) => {
                        return Err(anyhow_error_and_log(
                                    format!("Not enough shares to reconstruct. n={num_parties}, deg={degree}, #shares={amount_shares}, block_shares={}", &cur_block_shares.shares.len()),
                                ));
                    }
                    Err(e) => {
                        return Err(anyhow_error_and_log(format!(
                                    "Error reconstructing all blocks: {e}. n={num_parties}, deg={degree}, #shares={amount_shares}, block_shares={}", &cur_block_shares.shares.len()
                                )));
                    }
                }
            }
            out.push((fhe_type, packing_factor, decrypted_blocks))
        }
        Ok(out)
    }

    fn insecure_threshold_user_decryption_resp_z128(
        &self,
        agg_resp: &[UserDecryptionResponse],
        client_keys: &UnifiedUnsigncryptionKey,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let all_decrypted_blocks =
            Self::insecure_threshold_user_decryption_resp_to_blocks::<Z128>(agg_resp, client_keys)?;

        let mut out = vec![];

        for (fhe_type, packing_factor, decrypted_blocks) in all_decrypted_blocks {
            let pbs_params = self
                .params
                .get_params_basics_handle()
                .to_classic_pbs_parameters();

            let recon_blocks = reconstruct_packed_message(
                Some(decrypted_blocks),
                &pbs_params,
                fhe_types_to_num_blocks(
                    fhe_type,
                    &self
                        .params
                        .get_params_basics_handle()
                        .to_classic_pbs_parameters(),
                    packing_factor,
                )?,
            )?;

            out.push(decrypted_blocks_to_plaintext(
                &pbs_params,
                fhe_type,
                packing_factor,
                recon_blocks,
            )?);
        }
        Ok(out)
    }

    /// Decrypt the user decryption response from the threshold KMS.
    /// This function does *not* do any verification and is thus insecure and should be used only for testing.
    /// TODO hide behind flag for insecure function?
    fn insecure_threshold_user_decryption_resp_z64(
        &self,
        agg_resp: &[UserDecryptionResponse],
        client_keys: &UnifiedUnsigncryptionKey,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let all_decrypted_blocks =
            Self::insecure_threshold_user_decryption_resp_to_blocks::<Z64>(agg_resp, client_keys)?;

        let mut out = vec![];
        for (fhe_type, packing_factor, decrypted_blocks) in all_decrypted_blocks {
            let pbs_params = self
                .params
                .get_params_basics_handle()
                .to_classic_pbs_parameters();

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
                ptxts128,
            )?);
        }
        Ok(out)
    }

    /// Decrypts the user decryption responses and decodes the responses onto the Shamir shares
    /// that the servers should have encrypted.
    #[allow(clippy::type_complexity)]
    fn recover_sharings<Z: BaseRing>(
        &self,
        agg_resp: &[UserDecryptionResponsePayload],
        enc_key: &UnifiedPublicEncKey,
        dec_key: &UnifiedPrivateEncKey,
    ) -> anyhow::Result<Vec<(FheTypes, u32, Vec<ShamirSharings<ResiduePolyF4<Z>>>, usize)>> {
        let batch_count = agg_resp
            .first()
            .ok_or_else(|| anyhow::anyhow!("response payloads is empty"))?
            .signcrypted_ciphertexts
            .len();

        let intra_share_packing = match self.decryption_mode {
            DecryptionMode::BitDecSmall => 1, //TODO: For now we don't use intra share packing for BitDecSmall
            DecryptionMode::NoiseFloodSmall => ResiduePolyF4::<Z>::EXTENSION_DEGREE,
            _ => {
                return Err(anyhow_error_and_log(format!(
                    "Unsupported decryption mode: {}",
                    self.decryption_mode
                )));
            }
        };
        let mut out = vec![];
        for batch_i in 0..batch_count {
            // It is ok to use the first packing factor because this is checked by [self.validate_user_decrypt_responses_against_request]
            let packing_factor = agg_resp[0].signcrypted_ciphertexts[batch_i].packing_factor;
            // taking agg_resp[0] is safe since batch_count before exists
            let fhe_type = agg_resp[0].signcrypted_ciphertexts[batch_i].fhe_type()?;
            let num_shares = fhe_types_to_num_blocks(
                fhe_type,
                &self
                    .params
                    .get_params_basics_handle()
                    .to_classic_pbs_parameters(),
                packing_factor,
            )?
            .div_ceil(intra_share_packing);
            let mut sharings = Vec::new();
            for _i in 0..num_shares {
                sharings.push(ShamirSharings::new());
            }
            // the number of recovery errors in this block (e.g. due to failed signcryption)
            let mut recovery_errors = 0;
            for cur_resp in agg_resp {
                // Observe that it has already been verified in [validate_meta_data] that server
                // verification key is in the set of permissible keys
                //
                // Also it's ok to use [cur_resp.digest] as the link since we already checked
                // that it matches with the original request
                let cur_verf_key: PublicSigKey =
                    bc2wrap::deserialize_unsafe(&cur_resp.verification_key)?; // TODO(#2781)
                let client_id = self.client_address.to_vec();
                let unsign_key =
                    UnifiedUnsigncryptionKey::new(dec_key, enc_key, &cur_verf_key, &client_id);
                match unsign_key.unsigncrypt_plaintext(
                    &DSEP_USER_DECRYPTION,
                    &cur_resp.signcrypted_ciphertexts[batch_i].signcrypted_ciphertext,
                    &cur_resp.digest,
                ) {
                    Ok(decryption_share) => {
                        let cipher_blocks_share: Vec<ResiduePolyF4<Z>> =
                            bc2wrap::deserialize_unsafe(&decryption_share.plaintext.bytes)?;
                        let mut cur_blocks = Vec::with_capacity(cipher_blocks_share.len());
                        for cur_block_share in cipher_blocks_share {
                            cur_blocks.push(cur_block_share);
                        }
                        fill_indexed_shares(
                            &mut sharings,
                            cur_blocks,
                            num_shares,
                            Role::indexed_from_one(cur_resp.party_id as usize),
                        )?;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Could not decrypt or validate signcrypted response from party {}: {}",
                            cur_resp.party_id,
                            e
                        );
                        recovery_errors += 1;
                    }
                };
            }
            out.push((fhe_type, packing_factor, sharings, recovery_errors));
        }
        Ok(out)
    }
}

// This testing struct needs to be outside of js_api module
// since it is needed in the tests to generate the right files for js/wasm tests.
#[cfg(feature = "wasm_tests")]
#[wasm_bindgen]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TestingUserDecryptionTranscript {
    // client
    pub(crate) server_addrs: std::collections::HashMap<u32, alloy_primitives::Address>,
    pub(crate) client_address: alloy_primitives::Address,
    pub(crate) client_sk: Option<PrivateSigKey>,
    pub(crate) degree: u32,
    pub(crate) params: threshold_fhe::execution::tfhe_internals::parameters::DKGParams,
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
}

impl ParsedUserDecryptionRequest {
    pub fn new(
        signature: Option<alloy_primitives::Signature>,
        client_address: alloy_primitives::Address,
        enc_key: Vec<u8>,
        ciphertext_handles: Vec<CiphertextHandle>,
        eip712_verifying_contract: alloy_primitives::Address,
    ) -> Self {
        Self {
            signature,
            client_address,
            enc_key,
            ciphertext_handles,
            eip712_verifying_contract,
        }
    }

    pub fn enc_key(&self) -> &[u8] {
        &self.enc_key
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
        }
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
    recon_blocks: Vec<Z128>,
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
