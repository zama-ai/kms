//! Client side of pad decryption (tech-spec RFC-030).

use crate::client::client_wasm::Client;
use crate::client::user_decryption_wasm::decrypted_blocks_to_plaintext;
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::encryption::{
    Encryption, PkeScheme, PkeSchemeType, UnifiedPrivateEncKey, UnifiedPublicEncKey,
};
use crate::cryptography::hybrid_ml_kem::HybridKemCt;
use crate::cryptography::signing::ecdsa::recover_address_from_eip712_hash;
use crate::engine::pad::{
    LABEL_BYTES, num_pad_blocks, pad_block_fhe_type, pad_payload_signing_hash,
};
use crate::{anyhow_error_and_log, some_or_err};
use algebra::{
    base_ring::Z128,
    galois_rings::degree_4::ResiduePolyF4,
    sharing::shamir::{ShamirSharings, fill_indexed_shares},
    structure_traits::Ring,
};
use alloy_sol_types::Eip712Domain;
use itertools::Itertools;
use kms_grpc::kms::v1::{
    PadDecryptionEntry, PadDecryptionRequest, PadDecryptionResponse, PadDecryptionResponsePlaintext,
};
use kms_grpc::rpc_types::{
    alloy_to_protobuf_domain, fhe_type_to_num_bits, fhe_types_to_num_blocks,
    optional_protobuf_to_alloy_domain,
};
use kms_grpc::{ContextId, EpochId, RequestId};
use std::collections::{HashMap, HashSet};
use threshold_execution::endpoints::reconstruct::reconstruct_packed_message;
use threshold_types::role::Role;
use zeroize::Zeroizing;

/// The decoded shares of one authenticated pad decryption response.
struct OpenedPadResponse {
    role: Role,
    /// The packing factor of each pad, in request order.
    packing_factors: Vec<u32>,
    /// The decoded share of each block of each pad, in request order.
    block_shares: Vec<Vec<Zeroizing<Vec<ResiduePolyF4<Z128>>>>>,
}

impl Client {
    /// Creates a pad decryption request to send to the KMS servers, together with a fresh
    /// ML-KEM-512 key pair. The private key decrypts the responses, see
    /// [`Client::process_pad_decryption_resp`].
    ///
    /// In a deployment, the KMS connector builds this request after it has authenticated and
    /// authorized the user.
    #[allow(clippy::too_many_arguments)]
    pub fn pad_decryption_request(
        &mut self,
        domain: &Eip712Domain,
        pads: Vec<PadDecryptionEntry>,
        prf: u32,
        request_id: &RequestId,
        key_id: &RequestId,
        context_id: &ContextId,
        epoch_id: &EpochId,
        extra_data: &[u8],
    ) -> anyhow::Result<(
        PadDecryptionRequest,
        UnifiedPublicEncKey,
        UnifiedPrivateEncKey,
    )> {
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }
        let domain_msg = alloy_to_protobuf_domain(domain)?;

        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut self.rng);
        let (enc_sk, enc_pk) = encryption.keygen()?;
        let mut enc_key = Vec::new();
        tfhe::safe_serialization::safe_serialize(&enc_pk, &mut enc_key, SAFE_SER_SIZE_LIMIT)
            .map_err(|e| anyhow::anyhow!("Failed to serialize the encryption key: {e}"))?;

        Ok((
            PadDecryptionRequest {
                request_id: Some((*request_id).into()),
                pads,
                prf,
                key_id: Some((*key_id).into()),
                enc_key,
                domain: Some(domain_msg),
                extra_data: extra_data.to_vec(),
                context_id: Some((*context_id).into()),
                epoch_id: Some((*epoch_id).into()),
            },
            enc_pk,
            enc_sk,
        ))
    }

    /// Decrypts and verifies the pad decryption responses of the threshold KMS, and returns the
    /// pad of each label of `request`, in request order.
    ///
    /// Each pad holds the first `pad_length` bits of the pad stream of its label, least
    /// significant bit first, in `ceil(pad_length / 8)` bytes. The bits above `pad_length` in the
    /// last byte are zero.
    ///
    /// A response is rejected, and counts as a fault, if it does not decrypt, if its signature
    /// does not recover to the address of its party, if its `extra_data`, request ID or degree
    /// differ from the expected values, if its labels are not exactly the labels of `request`,
    /// or if its shares do not decode. The responses are combined with robust reconstruction,
    /// which fails when more than `degree` of the `n` parties are faulty or missing.
    ///
    /// # Arguments
    ///
    /// All arguments except `responses` are trusted client-side state:
    ///
    /// * `request` - The request that this client sent.
    /// * `dec_key` - The private key of the `enc_key` in `request`.
    /// * `threshold` - The expected degree. If `None`, the degree is `(n - 1) / 3`, where `n` is
    ///   the number of servers of this client.
    pub fn process_pad_decryption_resp(
        &self,
        request: &PadDecryptionRequest,
        dec_key: &UnifiedPrivateEncKey,
        threshold: Option<usize>,
        responses: &[PadDecryptionResponse],
    ) -> anyhow::Result<Vec<Zeroizing<Vec<u8>>>> {
        let domain = optional_protobuf_to_alloy_domain(request.domain.as_ref())?;
        let request_id: RequestId = some_or_err(
            request.request_id.as_ref(),
            "Missing request ID in pad decryption request".to_string(),
        )?
        .try_into()?;
        let server_addrs = self.get_server_addrs();
        let num_parties = server_addrs.len();
        let degree = match threshold {
            Some(threshold) => threshold,
            None => {
                num_parties
                    .checked_sub(1)
                    .ok_or_else(|| anyhow::anyhow!("The client has no servers"))?
                    / 3
            }
        };
        let block_fhe_type = pad_block_fhe_type(request.prf)?;
        let block_bytes = fhe_type_to_num_bits(block_fhe_type)?.div_ceil(8);
        let block_counts = request
            .pads
            .iter()
            .map(|pad| num_pad_blocks(request.prf, pad.pad_length))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let ctx = PadResponseContext {
            request,
            request_id,
            domain: &domain,
            server_addrs: &server_addrs,
            degree,
            block_counts: &block_counts,
        };

        let mut seen_roles = HashSet::new();
        let mut opened = Vec::with_capacity(responses.len());
        for (idx, response) in responses.iter().enumerate() {
            match ctx.open(response, dec_key) {
                Ok(resp) if seen_roles.insert(resp.role) => opened.push(resp),
                Ok(resp) => tracing::warn!(
                    "Rejected pad decryption response {idx}: duplicate party {}",
                    resp.role
                ),
                Err(e) => tracing::warn!("Rejected pad decryption response {idx}: {e}"),
            }
        }

        // The packing factors are a property of the FHE parameters, so honest parties agree on
        // them. Keep the responses with the most common packing factors.
        let packing_factors = opened
            .iter()
            .map(|resp| resp.packing_factors.clone())
            .counts()
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(packing_factors, _)| packing_factors)
            .ok_or_else(|| anyhow_error_and_log("No valid pad decryption responses"))?;
        let pbs_params = self.params.classic_pbs();
        let mut num_shares = Vec::with_capacity(packing_factors.len());
        for packing_factor in &packing_factors {
            num_shares.push(
                fhe_types_to_num_blocks(block_fhe_type, &pbs_params, *packing_factor)?
                    .div_ceil(ResiduePolyF4::<Z128>::EXTENSION_DEGREE),
            );
        }
        let accepted = opened
            .into_iter()
            .filter(|resp| {
                let ok = resp.packing_factors == packing_factors
                    && resp
                        .block_shares
                        .iter()
                        .zip(&num_shares)
                        .all(|(blocks, n)| blocks.iter().all(|share| share.len() == *n));
                if !ok {
                    tracing::warn!(
                        "Rejected pad decryption response of party {}: unexpected share shape",
                        resp.role
                    );
                }
                ok
            })
            .collect::<Vec<_>>();
        let num_bots = num_parties.checked_sub(accepted.len()).ok_or_else(|| {
            anyhow::anyhow!(
                "More accepted responses ({}) than parties ({num_parties})",
                accepted.len()
            )
        })?;

        let mut pads = Vec::with_capacity(request.pads.len());
        for (pad_idx, pad) in request.pads.iter().enumerate() {
            let packing_factor = packing_factors[pad_idx];
            let num_blocks = fhe_types_to_num_blocks(block_fhe_type, &pbs_params, packing_factor)?;
            let mut pad_bytes = Zeroizing::new(Vec::new());
            for block_idx in 0..block_counts[pad_idx] {
                let mut sharings = Zeroizing::new(
                    (0..num_shares[pad_idx])
                        .map(|_| ShamirSharings::with_capacity(accepted.len()))
                        .collect::<Vec<_>>(),
                );
                for resp in &accepted {
                    fill_indexed_shares(
                        &mut sharings,
                        resp.block_shares[pad_idx][block_idx].to_vec(),
                        resp.role,
                    );
                }
                let opened_blocks =
                    Client::reconstruct_blocks(num_parties, degree, num_bots, &sharings)?
                        .ok_or_else(|| anyhow::anyhow!("No shares for pad {pad_idx}"))?;
                let message_blocks = Zeroizing::new(reconstruct_packed_message(
                    Some(&opened_blocks),
                    &pbs_params,
                    num_blocks,
                )?);
                let block = decrypted_blocks_to_plaintext(
                    &pbs_params,
                    block_fhe_type,
                    packing_factor,
                    &message_blocks,
                )?;
                // The plaintext holds the block in little-endian order, so its bytes continue
                // the pad stream with the least significant bit first.
                if block.bytes.len() != block_bytes {
                    anyhow::bail!(
                        "Pad block has {} bytes, expected {block_bytes}",
                        block.bytes.len()
                    );
                }
                pad_bytes.extend_from_slice(&block.bytes);
            }
            truncate_to_bits(&mut pad_bytes, pad.pad_length);
            pads.push(pad_bytes);
        }
        Ok(pads)
    }
}

/// Keeps the first `num_bits` bits of `bytes`, least significant bit first, and clears the
/// bits above `num_bits` in the last byte.
fn truncate_to_bits(bytes: &mut Zeroizing<Vec<u8>>, num_bits: u32) {
    let num_bits = num_bits as usize;
    bytes.truncate(num_bits.div_ceil(8));
    if !num_bits.is_multiple_of(8)
        && let Some(last) = bytes.last_mut()
    {
        *last &= (1u8 << (num_bits % 8)) - 1;
    }
}

/// The trusted values that every pad decryption response must match.
struct PadResponseContext<'a> {
    request: &'a PadDecryptionRequest,
    request_id: RequestId,
    domain: &'a Eip712Domain,
    server_addrs: &'a HashMap<u32, alloy_primitives::Address>,
    degree: usize,
    /// The number of blocks of each pad, in request order.
    block_counts: &'a [usize],
}

impl PadResponseContext<'_> {
    /// Decrypts `response`, checks it against the request and decodes its shares.
    fn open(
        &self,
        response: &PadDecryptionResponse,
        dec_key: &UnifiedPrivateEncKey,
    ) -> anyhow::Result<OpenedPadResponse> {
        let ciphertext: HybridKemCt = bc2wrap::deserialize_slice(&response.encrypted)?;
        let plaintext_bytes = dec_key.hybrid_decrypt(ciphertext)?;
        let plaintext: PadDecryptionResponsePlaintext =
            bc2wrap::deserialize_slice(&plaintext_bytes)?;
        let payload = some_or_err(plaintext.payload, "Missing payload".to_string())?;

        let expected_signer = self
            .server_addrs
            .get(&payload.party_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown party ID {}", payload.party_id))?;
        let signing_hash = pad_payload_signing_hash(&payload, self.domain)?;
        let signer = recover_address_from_eip712_hash(&signing_hash, &plaintext.signature)?;
        if signer != *expected_signer {
            anyhow::bail!(
                "Signature of party {} recovers to {signer}, expected {expected_signer}",
                payload.party_id
            );
        }

        if payload.extra_data != self.request.extra_data {
            anyhow::bail!("Extra data differs from the request");
        }
        let payload_request_id: RequestId = some_or_err(
            payload.request_id.as_ref(),
            "Missing request ID in payload".to_string(),
        )?
        .try_into()?;
        if payload_request_id != self.request_id {
            anyhow::bail!(
                "Request ID {payload_request_id} differs from {}",
                self.request_id
            );
        }
        if payload.degree as usize != self.degree {
            anyhow::bail!(
                "Degree {} differs from the expected {}",
                payload.degree,
                self.degree
            );
        }

        let mut shares_by_label = HashMap::with_capacity(payload.pad_shares.len());
        for share in payload.pad_shares {
            let label: [u8; LABEL_BYTES] = share.label.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!(
                    "Label has {} bytes, expected {LABEL_BYTES}",
                    share.label.len()
                )
            })?;
            if shares_by_label.insert(label, share).is_some() {
                anyhow::bail!("Duplicate label {}", hex::encode(label));
            }
        }
        if shares_by_label.len() != self.request.pads.len() {
            anyhow::bail!(
                "Response has {} pads, expected {}",
                shares_by_label.len(),
                self.request.pads.len()
            );
        }

        let mut packing_factors = Vec::with_capacity(self.request.pads.len());
        let mut block_shares = Vec::with_capacity(self.request.pads.len());
        for (pad, expected_blocks) in self.request.pads.iter().zip(self.block_counts) {
            let share = shares_by_label
                .remove(pad.label.as_slice())
                .ok_or_else(|| anyhow::anyhow!("Missing label {}", hex::encode(&pad.label)))?;
            if share.block_shares.len() != *expected_blocks {
                anyhow::bail!(
                    "Label {} has {} block shares, expected {expected_blocks}",
                    hex::encode(&pad.label),
                    share.block_shares.len()
                );
            }
            let decoded = share
                .block_shares
                .iter()
                .map(|block| {
                    bc2wrap::deserialize_slice::<Vec<ResiduePolyF4<Z128>>>(block)
                        .map(Zeroizing::new)
                })
                .collect::<Result<Vec<_>, _>>()?;
            packing_factors.push(share.packing_factor);
            block_shares.push(decoded);
        }

        Ok(OpenedPadResponse {
            role: Role::indexed_from_one(payload.party_id as usize),
            packing_factors,
            block_shares,
        })
    }
}
