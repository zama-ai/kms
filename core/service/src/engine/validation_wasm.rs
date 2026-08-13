use alloy_dyn_abi::Eip712Domain;
use alloy_primitives::Address;
use hashing::DomainSep;
use kms_grpc::kms::v1::{UserDecryptionResponse, UserDecryptionResponsePayload};
use std::collections::{HashMap, HashSet};
use tfhe::FheTypes;
use threshold_types::role::Role;

use crate::{
    anyhow_error_and_log,
    client::user_decryption_wasm::{ParsedUserDecryptionRequest, compute_link},
    cryptography::{
        compute_user_decrypt_message,
        signatures::{
            PublicSigKey, Signature, internal_verify_sig, recover_address_from_ext_signature,
        },
    },
};

pub(crate) const DSEP_USER_DECRYPTION: DomainSep = *b"USER_DEC";

/// Trusted client-side configuration used to validate server responses.
/// The expectation is that no unvalidated data coming from e.g., the network should be used in this type.
/// All fields MUST originate from the client's own configuration or some trusted source.
pub(crate) struct UserDecTrustedValidationContext<'a> {
    server_addresses: &'a HashMap<u32, Address>,
    client_request: &'a ParsedUserDecryptionRequest,
    eip712_domain: &'a Eip712Domain,
    threshold: usize,
}

impl<'a> UserDecTrustedValidationContext<'a> {
    pub fn num_parties(&self) -> usize {
        self.server_addresses.len()
    }
    pub fn threshold(&self) -> usize {
        self.threshold
    }
}

impl<'a> UserDecTrustedValidationContext<'a> {
    /// Creates a new context and check sanity
    pub fn new(
        server_addresses: &'a HashMap<u32, Address>,
        client_request: &'a ParsedUserDecryptionRequest,
        eip712_domain: &'a Eip712Domain,
        threshold: Option<usize>,
    ) -> anyhow::Result<Self> {
        if server_addresses.is_empty() {
            anyhow::bail!("Server addresses must not be empty");
        }

        let max_threshold = (server_addresses.len() - 1) / 3; // Note that this is floored division.
        let threshold = threshold.unwrap_or(max_threshold);

        if threshold > max_threshold {
            anyhow::bail!("Threshold is too high for the number of servers");
        }

        if server_addresses.contains_key(&0) {
            anyhow::bail!("Server addresses must not contain party ID 0");
        }

        // Check that all server addresses are unique
        let mut unique_addresses = HashSet::new();
        for (party_id, address) in server_addresses {
            if !unique_addresses.insert(address) {
                anyhow::bail!("Duplicate server address found for party ID {party_id}");
            }
        }

        Ok(Self {
            server_addresses,
            client_request,
            eip712_domain,
            threshold,
        })
    }
}

/// Why a response was dropped during the (secret-free) authenticity/consensus validation, or later
/// during recovery. The authenticity variants are produced by [`validate_user_decrypt_responses`];
/// [`UserDecRejectReason::Unrecoverable`] is produced by the client while un-signcrypting.
#[derive(Debug)]
pub(crate) enum UserDecRejectReason {
    /// The response carried no payload.
    MissingPayload,
    /// Failed authenticity / consensus validation (unknown or duplicate server, bad signature,
    /// disagreement with the consensus, ...); the fine-grained reason is logged as the response is
    /// dropped.
    FailedValidation,
    /// Two responses from the same role were accepted; the first one is kept, the subsequent ones are dropped.
    DuplicateRole,
    /// Authenticated, but a signcryption could not be un-signcrypted or its inner bytes could not be
    /// decoded during recovery — so it is not a fully-verified accepted response.
    Unrecoverable,
}

/// A response that did not make it into the accepted set, with the reason it was dropped.
#[derive(Debug)]
pub(crate) struct RejectedUserDecResponse {
    /// The role of the server that sent the response, `None` if we weren't able to authenticate it.
    pub role: Option<Role>,
    pub reason: UserDecRejectReason,
}

/// A response that passed the secret-free authenticity/consensus validation, paired with its
/// verification key deserialized **once** here. The client uses the carried key to un-signcrypt
/// without re-parsing the raw bytes.
#[derive(Debug)]
pub(crate) struct AuthenticatedUserDecResponse {
    pub verification_key: PublicSigKey,
    pub role: Role,
    pub signcrypted_ciphertexts: Vec<Vec<u8>>,
}

/// The outcome of the (secret-free) authenticity/consensus validation pass: the
/// [`UserDecryptionInvariants`] established from the pivot at the moment of consensus, the
/// authenticated responses (each carrying its parsed verification key), and the typed rejections for
/// those that did not pass. The invariants are computed once, here, and every response was classified
/// against them — so downstream code never re-derives "what the servers agreed on" from an individual
/// payload, and never has to recompute which responses were rejected.
#[derive(Debug)]
pub(crate) struct AuthenticatedUserDecResponses {
    invariants: UserDecryptionInvariants,
    authenticated: Vec<AuthenticatedUserDecResponse>,
    rejected: Vec<RejectedUserDecResponse>,
}

impl AuthenticatedUserDecResponses {
    /// The authenticated responses. Only used by tests to count how many passed.
    #[cfg(test)]
    pub fn as_slice(&self) -> &[AuthenticatedUserDecResponse] {
        &self.authenticated
    }

    pub fn into_parts(
        self,
    ) -> (
        UserDecryptionInvariants,
        Vec<AuthenticatedUserDecResponse>,
        Vec<RejectedUserDecResponse>,
    ) {
        (self.invariants, self.authenticated, self.rejected)
    }
}

/// Groups EIP-712 external signature verification parameters.
pub(crate) struct Eip712VerificationParams<'a> {
    pub response_external_signature: &'a [u8],
    pub response_extra_data: &'a [u8],
    pub trusted_eip712_domain: &'a Eip712Domain,
}

const ERR_EXT_USER_DECRYPTION_SIG_VERIFICATION_FAILURE: &str =
    "External PT signature verification failed";

const ERR_VALIDATE_USER_DECRYPTION_MISSING_SIGNATURE: &str =
    "Missing signature in user decryption response";
const ERR_VALIDATE_USER_DECRYPTION_ID_NOT_FOUND: &str = "ID claimed in payload not found";
const ERR_VALIDATE_USER_DECRYPTION_WRONG_ADDRESS: &str =
    "ID or address claimed in payload is incorrect";
pub(crate) const ERR_VALIDATE_USER_DECRYPTION_MISMATCH_EXTRA_DATA: &str =
    "Extra data mismatch in user decryption";
const ERR_VALIDATE_USER_DECRYPTION_NO_RESP: &str = "No response to verify in user decryption";
const ERR_VALIDATE_USER_DECRYPTION_NOT_ENOUGH_RESP: &str =
    "Not enough correct responses to user-decrypt the data!";

/// check that the external signature on the decryption result(s) is valid, i.e. was made by one of the supplied addresses
pub(crate) fn check_ext_user_decryption_signature(
    external_sig: &[u8],
    payload: &UserDecryptionResponsePayload,
    request: &ParsedUserDecryptionRequest,
    eip712_domain: &Eip712Domain,
    expected_addr: &alloy_primitives::Address,
) -> anyhow::Result<()> {
    let extra_data = request.extra_data();
    let message = compute_user_decrypt_message(payload, request.enc_key(), extra_data)?;
    tracing::debug!(
        "Verifying external user decryption signature for UserDecryptResponseVerification"
    );
    let addr = recover_address_from_ext_signature(&message, eip712_domain, external_sig)?;
    if addr != *expected_addr {
        anyhow::bail!(ERR_EXT_USER_DECRYPTION_SIG_VERIFICATION_FAILURE);
    }

    Ok(())
}

/// Authenticate a single (untrusted) response: look its `party_id` up in
/// `trusted_ctx.server_addresses` and verify its signature under the key registered for that party —
/// so on success the party identity is *verified*, not merely claimed. Agreement with the consensus
/// (degree, link, per-slot fhe_type / packing) is **not** checked here; that is a single invariants
/// equality in [`classify_user_decrypt_response`].
///
/// Returns the (verified) role and verification key it deserialized, so the caller can reuse it without
/// parsing the raw bytes a second time.
fn authenticate_user_decrypt_and_check_meta_data(
    trusted_ctx: &UserDecTrustedValidationContext,
    response: &UserDecryptionResponsePayload,
    signature: &[u8],
    eip712_params: &Eip712VerificationParams,
) -> anyhow::Result<(PublicSigKey, Role)> {
    // TODO: Need to update this to a safer deserialization (which checks versions) with #2781 ?
    let resp_verf_key: PublicSigKey = bc2wrap::deserialize_slice(&response.verification_key)?;

    let expected_addr =
        if let Some(expected_addr) = trusted_ctx.server_addresses.get(&(response.party_id)) {
            if *expected_addr != resp_verf_key.address() {
                anyhow::bail!(ERR_VALIDATE_USER_DECRYPTION_WRONG_ADDRESS)
            }
            expected_addr
        } else {
            anyhow::bail!(ERR_VALIDATE_USER_DECRYPTION_ID_NOT_FOUND)
        };

    // The response must echo the request's extra data whichever signature we go
    // on to verify below. The EIP-712 signature covers `extraData`, but the raw
    // ECDSA one does not, so this check has to happen outside the branch.
    if eip712_params.response_extra_data != trusted_ctx.client_request.extra_data() {
        return Err(anyhow_error_and_log(
            ERR_VALIDATE_USER_DECRYPTION_MISMATCH_EXTRA_DATA,
        ));
    }

    // Prefer ECDSA signature over the eip712 one
    if signature.is_empty() {
        // check signature
        if eip712_params.response_external_signature.is_empty() {
            return Err(anyhow_error_and_log(
                ERR_VALIDATE_USER_DECRYPTION_MISSING_SIGNATURE,
            ));
        }

        check_ext_user_decryption_signature(
            eip712_params.response_external_signature,
            response,
            trusted_ctx.client_request,
            eip712_params.trusted_eip712_domain,
            expected_addr,
        )
        .inspect_err(|e| tracing::warn!("signature on received response is not valid ({})!", e))?;
    } else {
        let sig = Signature::from_ecdsa(k256::ecdsa::Signature::from_slice(signature)?);
        // NOTE that we cannot use `BaseKmsStruct::verify_sig`
        // because `BaseKmsStruct` cannot be compiled for wasm (it has an async mutex).
        if internal_verify_sig(
            &DSEP_USER_DECRYPTION,
            &bc2wrap::serialize(&response)?,
            &sig,
            &resp_verf_key,
        )
        .is_err()
        {
            anyhow::bail!("Signature on received response is not valid!");
        }
    }

    Ok((
        resp_verf_key,
        Role::indexed_from_one(response.party_id as usize),
    ))
}

/// Return the invariants key `T` shared by the largest group of responses, provided that group has
/// at least `min_occurence` members (else `None`).
pub(crate) fn select_most_common<'a, P, T>(
    min_occurence: usize,
    agg_resp: impl Iterator<Item = Option<&'a P>>,
) -> Option<T>
where
    P: Clone + 'a,
    T: TryFrom<P, Error = anyhow::Error> + std::cmp::Eq + std::hash::Hash,
{
    // this hashmap is keyed on [T]
    // and its values contain a tuple (x, y), where x is the occurence and y is the original index
    let mut occurence_map: HashMap<T, (usize, usize), _> = HashMap::new();
    for (i, resp) in agg_resp.enumerate() {
        let Some(inner) = resp else {
            continue;
        };
        // A single (untrusted) response whose invariants cannot even be built — e.g. a malformed
        // request ID that fails to parse — must NOT abort the whole vote. Treat it like a missing
        // response: it simply does not get counted, so the honest majority can still form a pivot.
        // The response is independently surfaced as a rejection during classification.
        let key: T = match inner.clone().try_into() {
            Ok(key) => key,
            Err(e) => {
                tracing::warn!("Dropping a response whose invariants could not be built: {e}");
                continue;
            }
        };
        occurence_map.entry(key).or_insert_with(|| (0, i)).0 += 1;
    }

    // Winner: highest occurence, ties broken by lowest original index.
    occurence_map
        .into_iter()
        .max_by(|(_, a), (_, b)| a.0.cmp(&b.0).then(b.1.cmp(&a.1)))
        .filter(|(_, (count, _))| *count >= min_occurence)
        .map(|(key, _)| key)
}

/// Validate the aggregated (untrusted) user-decryption responses and partition them into
/// authenticated / rejected against the consensus invariants.
///
/// The flow is deliberately **authenticate → agree → match**, so that consensus can never be
/// skewed by duplicate or unauthenticated responses:
/// 1. Authenticate every response (identity + signature) and keep at most one payload per role.
/// 2. Establish the consensus invariants by majority vote over those authenticated, de-duplicated
///    payloads only — a Byzantine party gets exactly one vote, not one per copy it sends, and
///    unauthenticated payloads never get to vote at all.
/// 3. Discard every authenticated payload that does not match the consensus invariants.
///
/// It is **infallible w.r.t. any individual response's content**: every per-response failure is a
/// typed [`UserDecRejectReason`] pushed to `rejected`, never a propagated error, so no single
/// response can abort the batch.
///
/// # Arguments
/// * `trusted_ctx` — Trusted client-side configuration and request.
/// * `agg_resp` — Untrusted aggregated server responses received over the network.
///
/// # Returns
/// * `Ok(verified)` — More than `degree` responses passed; `verified` carries the consensus
///   invariants, the authenticated responses, and the typed rejections for everything that was
///   dropped, so the caller never has to recompute which responses failed.
/// * `Err(_)` — A batch-level error (no responses, no configured servers, no pivot, failed sanity
///   check, or fewer than `degree + 1` authenticated responses).
///
/// __NOTE__: the caller should not rely on the ordering of `verified.authenticated` /
/// `verified.rejected`.
pub(crate) fn validate_user_decrypt_responses(
    trusted_ctx: &UserDecTrustedValidationContext,
    agg_resp: &[UserDecryptionResponse],
) -> anyhow::Result<AuthenticatedUserDecResponses> {
    if agg_resp.is_empty() {
        anyhow::bail!(ERR_VALIDATE_USER_DECRYPTION_NO_RESP);
    }
    if trusted_ctx.server_addresses.is_empty() {
        anyhow::bail!("No servers configured in trusted user decryption context");
    }

    // We need t+1 authenticated responses at least to find the pivot.
    let min_occurence = trusted_ctx
        .threshold
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("Invalid user decryption threshold: overflow"))?;

    let mut rejected = Vec::new();

    // (1) Authenticate every response (identity + signature) and keep at most one payload per role.
    //     Doing this *before* consensus means the pivot vote in (2) is taken over distinct,
    //     authenticated parties only: a Byzantine party cannot skew the consensus by sending many
    //     copies of a bogus payload (copies collapse to a single role here), and unauthenticated
    //     payloads never get to vote at all.
    let mut seen_roles = HashSet::new();
    let mut authenticated_payloads: Vec<(PublicSigKey, Role, &UserDecryptionResponsePayload)> =
        Vec::with_capacity(agg_resp.len());
    for cur_resp in agg_resp {
        let Some(payload) = cur_resp.payload.as_ref() else {
            tracing::warn!("No payload in current response from server!");
            rejected.push(RejectedUserDecResponse {
                role: None,
                reason: UserDecRejectReason::MissingPayload,
            });
            continue;
        };
        let eip712_params = Eip712VerificationParams {
            response_external_signature: &cur_resp.external_signature,
            response_extra_data: &cur_resp.extra_data,
            trusted_eip712_domain: trusted_ctx.eip712_domain,
        };
        // The deprecated scalar `signature` field carries the raw internal ECDSA signature over the
        // serialized payload.
        // TODO(0.16) verify `signatures` and drop the two deprecated fields.
        let (verification_key, role) = match authenticate_user_decrypt_and_check_meta_data(
            trusted_ctx,
            payload,
            &cur_resp.signature,
            &eip712_params,
        ) {
            Ok(key) => key,
            Err(e) => {
                tracing::warn!(
                    "User decryption authentication failed for party {} with error: {e:?}",
                    payload.party_id
                );
                rejected.push(RejectedUserDecResponse {
                    role: None,
                    reason: UserDecRejectReason::FailedValidation,
                });
                continue;
            }
        };
        if !seen_roles.insert(role) {
            tracing::warn!(
                "Duplicate response from role {role:?} in user decryption, keeping the first one we saw"
            );
            rejected.push(RejectedUserDecResponse {
                role: Some(role),
                reason: UserDecRejectReason::DuplicateRole,
            });
            continue;
        }
        authenticated_payloads.push((verification_key, role, payload));
    }

    // (2) Establish the consensus invariants by majority vote over the authenticated, de-duplicated
    //     payloads only (the vote key *is* the invariants). A payload whose invariants cannot even
    //     be built is skipped from the tally and then rejected in (3).
    let invariants = match select_most_common::<_, UserDecryptionInvariants>(
        min_occurence,
        authenticated_payloads
            .iter()
            .map(|(_, _, payload)| Some(*payload)),
    ) {
        Some(inner) => inner,
        None => anyhow::bail!("Cannot find user decryption pivot"),
    };
    invariants.sanity_check(trusted_ctx)?;

    // (3) Keep only the authenticated responses whose payload matches the consensus invariants. This
    //     single equality subsumes the per-slot fhe_type, packing factor, slot count, digest/link
    //     and degree checks — they are all just the fields of `UserDecryptionInvariants`.
    let mut authenticated = Vec::with_capacity(authenticated_payloads.len());
    for (verification_key, role, payload) in authenticated_payloads {
        match UserDecryptionInvariants::try_from(payload.clone()) {
            Ok(resp_invariants) if resp_invariants == invariants => {
                authenticated.push(AuthenticatedUserDecResponse {
                    verification_key,
                    role,
                    signcrypted_ciphertexts: payload
                        .signcrypted_ciphertexts
                        .iter()
                        .map(|ct| ct.signcrypted_ciphertext.clone())
                        .collect(),
                });
            }
            _ => {
                tracing::warn!(
                    "Response from role {role:?} does not match the consensus invariants"
                );
                rejected.push(RejectedUserDecResponse {
                    role: Some(role),
                    reason: UserDecRejectReason::FailedValidation,
                });
            }
        }
    }

    if authenticated.len() <= invariants.degree {
        anyhow::bail!(ERR_VALIDATE_USER_DECRYPTION_NOT_ENOUGH_RESP);
    }
    Ok(AuthenticatedUserDecResponses {
        invariants,
        authenticated,
        rejected,
    })
}

/// Consensus metadata for a single signcrypted-ciphertext slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CiphertextSlotInvariant {
    /// The plaintext type, parsed from `i32` a single time so it is never re-parsed from a
    /// (potentially adversarial) contribution during reconstruction.
    pub fhe_type: FheTypes,
    pub packing_factor: u32,
    /// The ciphertext handle the response echoes. Not read during reconstruction, but part of the
    /// consensus (see the manual `Hash` impl): the request `link` already binds the handles, so this
    /// is redundant, yet kept so the vote groups responses exactly as before.
    pub external_handle: Vec<u8>,
}

/// The fields every honest user-decryption response must agree on for a given request.
///
/// Like `PublicDecryptionInvariants` on the public side, this single type is both the
/// **majority-vote key** (responses are grouped by it to find the ≥ `t + 1` pivot) and the
/// **consensus result** read downstream (degree, link, per-slot fhe_type / packing / slot count).
/// Because `FheTypes` is not `Hash`, `Hash` is implemented by hand (hashing the `fhe_type`
/// discriminant); the derived `Eq` compares the same fields, so the two stay consistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UserDecryptionInvariants {
    /// Sharing degree = corruption threshold `t`. Checked `== trusted threshold` during validation.
    pub degree: usize,
    /// EIP-712 request link (`digest`); also the signcryption link.
    pub link: Vec<u8>,
    /// One entry per signcrypted-ciphertext slot; `slots.len()` is the batch count.
    pub slots: Vec<CiphertextSlotInvariant>,
}

impl UserDecryptionInvariants {
    /// Sanity-check the invariants against the trusted context.
    pub fn sanity_check(
        &self,
        trusted_ctx: &UserDecTrustedValidationContext,
    ) -> anyhow::Result<()> {
        let expected_link = compute_link(trusted_ctx.client_request, trusted_ctx.eip712_domain)?;
        // Compare against the consensus link established from the pivot, not against an individual
        // response's digest.
        if expected_link != self.link {
            anyhow::bail!("The user decryption response is not linked to the correct request");
        }

        // if the pivot response degree does not match the threshold, we cannot proceed
        if self.degree != trusted_ctx.threshold {
            anyhow::bail!(
                "Pivot user decrypt responses gave degree {} which does not match expected threshold {} for {} known servers",
                self.degree,
                trusted_ctx.threshold,
                trusted_ctx.server_addresses.len()
            );
        }

        // The consensus must decrypt at least one ciphertext. Checked once here on the pivot, since the
        // per-response equality below no longer catches an all-empty consensus.
        if self.slots.is_empty() {
            anyhow::bail!("Consensus user decryption response has no ciphertext slots");
        }

        Ok(())
    }
}

impl std::hash::Hash for UserDecryptionInvariants {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.degree.hash(state);
        self.link.hash(state);
        // `Vec<SlotInvariant>` can't derive `Hash` (`FheTypes` isn't `Hash`), so hash the slots by
        // hand. `FheTypes` is `#[repr(i32)]` and its `Eq` is by discriminant, so hashing `as i32`
        // is consistent with the derived `Eq`.
        self.slots.len().hash(state);
        for slot in &self.slots {
            (slot.fhe_type as i32).hash(state);
            slot.packing_factor.hash(state);
            slot.external_handle.hash(state);
        }
    }
}

impl TryFrom<UserDecryptionResponsePayload> for UserDecryptionInvariants {
    type Error = anyhow::Error;

    /// Build the consensus invariants (and the majority-vote key) from a response payload. The
    /// per-slot `fhe_type` is parsed from `i32` here; during voting a response whose `fhe_type`
    /// fails to parse is simply skipped from the tally (see [`select_most_common`]).
    fn try_from(value: UserDecryptionResponsePayload) -> anyhow::Result<Self> {
        let mut slots = Vec::with_capacity(value.signcrypted_ciphertexts.len());
        for ct in value.signcrypted_ciphertexts {
            let fhe_type = ct.fhe_type()?;
            slots.push(CiphertextSlotInvariant {
                fhe_type,
                packing_factor: ct.packing_factor,
                external_handle: ct.external_handle,
            });
        }
        Ok(Self {
            degree: value.degree as usize,
            link: value.digest,
            slots,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use aes_prng::AesRng;
    use alloy_dyn_abi::Eip712Domain;
    use kms_grpc::kms::v1::{
        TypedSigncryptedCiphertext, UserDecryptionResponse, UserDecryptionResponsePayload,
    };
    use rand::SeedableRng;

    use crate::{
        client::user_decryption_wasm::{
            CiphertextHandle, ParsedUserDecryptionRequest, compute_link,
        },
        cryptography::{
            encryption::{Encryption, PkeScheme, PkeSchemeType},
            signatures::{
                ERR_EXT_USER_DECRYPTION_SIG_BAD_LENGTH, PrivateSigKey, PublicSigKey, gen_sig_keys,
                internal_sign,
            },
        },
        dummy_domain,
        engine::{
            base::sign_user_decryption_result,
            validation::{ERR_VALIDATE_USER_DECRYPTION_MISMATCH_EXTRA_DATA, select_most_common},
            validation_wasm::{
                ERR_EXT_USER_DECRYPTION_SIG_VERIFICATION_FAILURE,
                ERR_VALIDATE_USER_DECRYPTION_ID_NOT_FOUND, ERR_VALIDATE_USER_DECRYPTION_NO_RESP,
                ERR_VALIDATE_USER_DECRYPTION_WRONG_ADDRESS,
                authenticate_user_decrypt_and_check_meta_data,
            },
        },
    };

    use super::{
        DSEP_USER_DECRYPTION, ERR_VALIDATE_USER_DECRYPTION_MISSING_SIGNATURE,
        Eip712VerificationParams, UserDecTrustedValidationContext, UserDecryptionInvariants,
        check_ext_user_decryption_signature, validate_user_decrypt_responses,
    };

    /// Helper method to be removed in 0.16 when the external signature is no longer used in production.
    /// TODO(0.16)
    fn compute_external_user_decrypt_signature(
        server_sk: &PrivateSigKey,
        payload: &UserDecryptionResponsePayload,
        eip712_domain: &Eip712Domain,
        user_pk_buf: &[u8],
        extra_data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        Ok(sign_user_decryption_result(
            server_sk,
            &[],
            payload.clone(),
            user_pk_buf,
            extra_data.to_vec(),
            eip712_domain,
        )?
        .external_signature)
    }

    #[test]
    fn test_check_ext_user_decryption_signature() {
        let mut rng = AesRng::seed_from_u64(0);
        let (vk0, sk0) = gen_sig_keys(&mut rng);
        let (vk1, _sk1) = gen_sig_keys(&mut rng);
        let (vk2, _sk2) = gen_sig_keys(&mut rng);
        let pks: HashMap<u32, PublicSigKey> = HashMap::from_iter(
            [vk0, vk1, vk2]
                .into_iter()
                .enumerate()
                .map(|(i, k)| (i as u32 + 1, k)),
        );
        let kms_addrs = pks
            .iter()
            .map(|(i, pk)| (*i, pk.address()))
            .collect::<HashMap<u32, alloy_primitives::Address>>();

        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_eph_client_sk, eph_client_pk) = encryption.keygen().unwrap();
        let (client_vk, _client_sk) = gen_sig_keys(&mut rng);

        let ciphertext_handle = vec![5, 6, 7, 8];

        let mut enc_key_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(
            &eph_client_pk,
            &mut enc_key_buf,
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();

        let domain = dummy_domain();
        let extra_data = vec![1, 2, 3, 4];
        let request = ParsedUserDecryptionRequest::new(
            None, // No signature is needed
            client_vk.address(),
            enc_key_buf,
            vec![CiphertextHandle::new(ciphertext_handle.clone())],
            domain.verifying_contract.unwrap(),
            extra_data,
        );

        let payload = UserDecryptionResponsePayload {
            verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
            digest: vec![1, 2, 3, 4],
            signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                fhe_type: tfhe::FheTypes::Uint4 as i32,
                signcrypted_ciphertext: vec![1, 2, 3, 4],
                external_handle: ciphertext_handle.clone(),
                packing_factor: 1,
            }],
            party_id: 1,
            degree: 1,
        };
        let external_sig = compute_external_user_decrypt_signature(
            &sk0,
            &payload,
            &domain,
            request.enc_key(),
            request.extra_data(),
        )
        .unwrap();

        // incorrect external signature length
        {
            assert!(
                check_ext_user_decryption_signature(
                    &external_sig[0..64],
                    &payload,
                    &request,
                    &domain,
                    &kms_addrs[&1],
                )
                .unwrap_err()
                .to_string()
                .contains(ERR_EXT_USER_DECRYPTION_SIG_BAD_LENGTH)
            );
        }

        // bad signature due to bad signing key
        {
            let (_vk_bad, sk_bad) = gen_sig_keys(&mut rng);
            let bad_external_sig = compute_external_user_decrypt_signature(
                &sk_bad,
                &payload,
                &domain,
                request.enc_key(),
                &[],
            )
            .unwrap();
            assert!(
                check_ext_user_decryption_signature(
                    &bad_external_sig,
                    &payload,
                    &request,
                    &domain,
                    &kms_addrs[&1],
                )
                .is_err()
            );
        }

        // bad signature due to bad domain
        {
            let bad_domain = alloy_sol_types::eip712_domain!(
                name: "Authorization token",
                version: "1",
                chain_id: 1234, // incorrect chain ID
                verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
            );
            assert!(
                check_ext_user_decryption_signature(
                    &external_sig,
                    &payload,
                    &request,
                    &bad_domain,
                    &kms_addrs[&1],
                )
                .is_err()
            );
        }

        // check that we detect the error if payload is modified
        {
            let mut bad_payload = payload.clone();
            bad_payload.party_id = 2; // modify ID
            assert!(
                check_ext_user_decryption_signature(
                    &external_sig,
                    &bad_payload,
                    &request,
                    &domain,
                    &kms_addrs[&1],
                )
                .unwrap_err()
                .to_string()
                .contains(ERR_EXT_USER_DECRYPTION_SIG_VERIFICATION_FAILURE)
            );
        }

        // happy path
        {
            check_ext_user_decryption_signature(
                &external_sig,
                &payload,
                &request,
                &domain,
                &kms_addrs[&1],
            )
            .unwrap();
        }
    }

    #[test]
    fn test_validate_user_decrypt_meta_data_and_signature() {
        let mut rng = AesRng::seed_from_u64(0);
        let (vk0, sk0) = gen_sig_keys(&mut rng);
        let (vk1, _sk1) = gen_sig_keys(&mut rng);
        let (vk2, _sk2) = gen_sig_keys(&mut rng);
        let pks: HashMap<u32, PublicSigKey> = HashMap::from_iter(
            [vk0, vk1, vk2]
                .into_iter()
                .enumerate()
                .map(|(i, k)| (i as u32 + 1, k)),
        );
        let server_addresses = pks
            .iter()
            .map(|(i, pk)| (*i, pk.address()))
            .collect::<HashMap<u32, alloy_primitives::Address>>();

        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_eph_client_sk, eph_client_pk) = encryption.keygen().unwrap();

        let mut enc_key_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(
            &eph_client_pk,
            &mut enc_key_buf,
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();

        let (client_vk, _client_sk) = gen_sig_keys(&mut rng);

        let dummy_domain = dummy_domain();
        let ciphertext_handle = vec![5, 6, 7, 8];

        let extra_data = vec![1, 2, 3, 4];
        let client_request = ParsedUserDecryptionRequest::new(
            None, // No signature is needed here because we're testing response validation
            client_vk.address(),
            enc_key_buf,
            vec![CiphertextHandle::new(ciphertext_handle.clone())],
            dummy_domain.verifying_contract.unwrap(),
            extra_data.clone(),
        );

        let pivot_resp = UserDecryptionResponsePayload {
            verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
            digest: vec![1, 2, 3, 4],
            signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                fhe_type: tfhe::FheTypes::Uint4 as i32,
                signcrypted_ciphertext: vec![1, 2, 3, 4],
                external_handle: ciphertext_handle.clone(),
                packing_factor: 1,
            }],
            party_id: 1,
            degree: 1,
        };
        let external_signature = compute_external_user_decrypt_signature(
            &sk0,
            &pivot_resp,
            &dummy_domain,
            client_request.enc_key(),
            &extra_data,
        )
        .unwrap();

        let trusted_ctx = UserDecTrustedValidationContext::new(
            &server_addresses,
            &client_request,
            &dummy_domain,
            None,
        )
        .unwrap();

        // Consensus-agreement checks (fhe type length / mismatch, digest mismatch) are no longer
        // done here — they are a single `UserDecryptionInvariants` equality in
        // `classify_user_decrypt_response`, exercised via `test_validate_user_decrypt_responses`.

        // no signatures are provided
        {
            let params = Eip712VerificationParams {
                response_external_signature: &[],
                response_extra_data: &extra_data,
                trusted_eip712_domain: &dummy_domain,
            };
            assert!(
                authenticate_user_decrypt_and_check_meta_data(
                    &trusted_ctx,
                    &pivot_resp,
                    &[], // the ECDSA signature may be empty, thus we check the external one
                    &params,
                )
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_USER_DECRYPTION_MISSING_SIGNATURE)
            );
        }

        // if the ID is changed to something that does not exist, return error
        {
            let mut other_resp = pivot_resp.clone();
            other_resp.party_id = 10;
            let params = Eip712VerificationParams {
                response_external_signature: &external_signature,
                response_extra_data: &extra_data,
                trusted_eip712_domain: &dummy_domain,
            };
            assert!(
                authenticate_user_decrypt_and_check_meta_data(
                    &trusted_ctx,
                    &other_resp,
                    &[],
                    &params,
                )
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_USER_DECRYPTION_ID_NOT_FOUND)
            );
        }

        // no signatures are provided
        {
            let params = Eip712VerificationParams {
                response_external_signature: &[],
                response_extra_data: &extra_data,
                trusted_eip712_domain: &dummy_domain,
            };
            assert!(
                authenticate_user_decrypt_and_check_meta_data(
                    &trusted_ctx,
                    &pivot_resp,
                    &[], // the ECDSA signature may be empty, thus we check the external one
                    &params,
                )
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_USER_DECRYPTION_MISSING_SIGNATURE)
            );
        }

        // if the ID is changed to something that does not exist, return error
        {
            let mut other_resp = pivot_resp.clone();
            other_resp.party_id = 2; // originally the ID is 1
            let params = Eip712VerificationParams {
                response_external_signature: &external_signature,
                response_extra_data: &extra_data,
                trusted_eip712_domain: &dummy_domain,
            };
            assert!(
                authenticate_user_decrypt_and_check_meta_data(
                    &trusted_ctx,
                    &other_resp,
                    &[],
                    &params,
                )
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_USER_DECRYPTION_WRONG_ADDRESS)
            );
        }

        // no need to explicitly test the signature issues again since they were tested in [test_check_ext_user_decryption_signature]
        {
            let pivot_buf = bc2wrap::serialize(&pivot_resp).unwrap();
            let signature_buf = internal_sign(&DSEP_USER_DECRYPTION, &pivot_buf, &sk0)
                .unwrap()
                .to_bytes();
            let params = Eip712VerificationParams {
                response_external_signature: &[],
                response_extra_data: &[42], // the request's extra data is [1, 2, 3, 4]
                trusted_eip712_domain: &dummy_domain,
            };
            assert!(
                authenticate_user_decrypt_and_check_meta_data(
                    &trusted_ctx,
                    &pivot_resp,
                    &signature_buf,
                    &params,
                )
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_USER_DECRYPTION_MISMATCH_EXTRA_DATA)
            );
        }

        // happy path for empty ECDSA, so we check external signature
        {
            let params = Eip712VerificationParams {
                response_external_signature: &external_signature,
                response_extra_data: &extra_data,
                trusted_eip712_domain: &dummy_domain,
            };
            authenticate_user_decrypt_and_check_meta_data(
                &trusted_ctx,
                &pivot_resp,
                &[], // the ECDSA signature may be empty, thus we check the external one
                &params,
            )
            .unwrap();
        }

        // happy path for empty external_signature, so we check ECDSA
        {
            let pivot_buf = bc2wrap::serialize(&pivot_resp).unwrap();
            let signature = &internal_sign(&DSEP_USER_DECRYPTION, &pivot_buf, &sk0).unwrap();
            let signature_buf = signature.to_bytes();
            let params = Eip712VerificationParams {
                response_external_signature: &[],
                response_extra_data: &extra_data,
                trusted_eip712_domain: &dummy_domain,
            };
            authenticate_user_decrypt_and_check_meta_data(
                &trusted_ctx,
                &pivot_resp,
                &signature_buf,
                &params,
            )
            .unwrap();
        }
    }

    #[test]
    fn test_validate_user_decrypt_responses() {
        let mut rng = AesRng::seed_from_u64(0);
        let (vk1, sk1) = gen_sig_keys(&mut rng);
        let (vk2, sk2) = gen_sig_keys(&mut rng);
        let (vk3, sk3) = gen_sig_keys(&mut rng);
        let (vk4, sk4) = gen_sig_keys(&mut rng);
        let pks: HashMap<u32, PublicSigKey> = HashMap::from_iter(
            [vk1, vk2, vk3, vk4]
                .into_iter()
                .enumerate()
                .map(|(i, k)| (i as u32 + 1, k)),
        );
        let server_addresses = pks
            .iter()
            .map(|(i, pk)| (*i, pk.address()))
            .collect::<HashMap<u32, alloy_primitives::Address>>();

        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_eph_client_sk, eph_client_pk) = encryption.keygen().unwrap();

        let (client_vk, _client_sk) = gen_sig_keys(&mut rng);

        let dummy_domain = dummy_domain();
        let ciphertext_handle = vec![5, 6, 7, 8];

        let mut enc_key_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(
            &eph_client_pk,
            &mut enc_key_buf,
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        let client_request = ParsedUserDecryptionRequest::new(
            None, // No signature is needed here because we're testing response validation
            client_vk.address(),
            enc_key_buf,
            vec![CiphertextHandle::new(ciphertext_handle.clone())],
            dummy_domain.verifying_contract.unwrap(),
            vec![],
        );

        let trusted_ctx = UserDecTrustedValidationContext::new(
            &server_addresses,
            &client_request,
            &dummy_domain,
            None,
        )
        .unwrap();

        let digest = compute_link(&client_request, &dummy_domain).unwrap();

        // Build a fully-signed response for `party_id` (1..=4), applying `tweak` to the payload
        // *before* signing so the signature stays valid. The baseline responses below use the identity
        // tweak; a non-trivial tweak lets a block exercise the consensus/invariants layer (a response
        // that authenticates but disagrees with the majority) instead of accidentally tripping the
        // signature check: `degree`, `digest`, `fhe_type`, etc. are all part of the signed payload, so
        // mutating them *after* signing would silently reject the response at authentication rather
        // than where the test intends.
        let make_signed_resp =
            |party_id: u32, tweak: &dyn Fn(&mut UserDecryptionResponsePayload)| {
                let sk = match party_id {
                    1 => &sk1,
                    2 => &sk2,
                    3 => &sk3,
                    4 => &sk4,
                    _ => panic!("unsupported party_id {party_id} in make_signed_resp"),
                };
                let mut payload = UserDecryptionResponsePayload {
                    verification_key: bc2wrap::serialize(&pks[&party_id]).unwrap(),
                    digest: digest.clone(),
                    signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                        fhe_type: tfhe::FheTypes::Uint4 as i32,
                        signcrypted_ciphertext: vec![1, 2, 3, 4],
                        external_handle: ciphertext_handle.clone(),
                        packing_factor: 1,
                    }],
                    party_id,
                    degree: 1,
                };
                tweak(&mut payload);
                let external_signature = compute_external_user_decrypt_signature(
                    sk,
                    &payload,
                    &dummy_domain,
                    client_request.enc_key(),
                    &[],
                )
                .unwrap();
                UserDecryptionResponse {
                    signature: vec![],
                    signatures: vec![],
                    external_signature,
                    payload: Some(payload),
                    extra_data: vec![],
                }
            };

        let resp1 = make_signed_resp(1, &|_| {});

        let resp2 = make_signed_resp(2, &|_| {});

        let resp3 = make_signed_resp(3, &|_| {});

        let resp4 = make_signed_resp(4, &|_| {});

        // happy path / sunshine; we should have 4 valid responses
        {
            let agg_resp = vec![resp1.clone(), resp2.clone(), resp3.clone(), resp4.clone()];

            assert_eq!(
                validate_user_decrypt_responses(&trusted_ctx, &agg_resp)
                    .unwrap()
                    .as_slice()
                    .len(),
                4
            );
        }

        // one response has a wrong extra_data
        {
            let mut bad_resp = resp4.clone();
            bad_resp.extra_data = vec![0];
            let agg_resp = vec![resp1.clone(), resp2.clone(), resp3.clone(), bad_resp];

            assert_eq!(
                validate_user_decrypt_responses(&trusted_ctx, &agg_resp)
                    .unwrap()
                    .as_slice()
                    .len(),
                3 // instead of 4
            );
        }

        // empty responses, should return error
        {
            assert!(
                validate_user_decrypt_responses(&trusted_ctx, &[])
                    .unwrap_err()
                    .to_string()
                    .contains(ERR_VALIDATE_USER_DECRYPTION_NO_RESP)
            );
        }

        // empty payload
        {
            // we need at least 2 valid responses because our degree is 1,
            // otherwise None will be returned since there are not enough responses
            let mut bad_resp2 = resp3.clone();
            bad_resp2.payload = None;
            let agg_resp = vec![resp1.clone(), resp2.clone(), bad_resp2];

            // We will have 2 accepted responses because
            // the third one does not have a payload
            assert_eq!(
                validate_user_decrypt_responses(&trusted_ctx, &agg_resp)
                    .unwrap()
                    .as_slice()
                    .len(),
                2
            );
        }

        // not enough correct payloads: bad_resp3 authenticates fine but carries a *different* (yet
        // properly signed) digest, so it forms its own singleton group; bad_resp2 has no payload at
        // all. That leaves resp1 and bad_resp3 in two distinct groups of one each — neither reaches
        // the t+1 = 2 quorum, so no pivot can be formed.
        {
            let mut bad_resp2 = resp2.clone();
            bad_resp2.payload = None; // no payload here, cannot be used for pivot
            let bad_resp3 = make_signed_resp(3, &|p| p.digest[0] ^= 1); // signed, but different digest

            let agg_resp = vec![resp1.clone(), bad_resp2, bad_resp3];

            assert!(
                validate_user_decrypt_responses(&trusted_ctx, &agg_resp)
                    .unwrap_err()
                    .to_string()
                    .contains("Cannot find user decryption pivot")
            );
        }

        // one response has a wrong degree, but validation should still pass: it authenticates, then
        // the degree-1 majority (resp1 + resp3) out-votes it, so it is dropped by the invariants
        // equality rather than by the signature check.
        {
            let bad_resp2 = make_signed_resp(2, &|p| p.degree = 35); // authenticates, but wrong degree
            let agg_resp = vec![resp1.clone(), bad_resp2, resp3.clone()];

            assert_eq!(
                validate_user_decrypt_responses(&trusted_ctx, &agg_resp)
                    .unwrap()
                    .as_slice()
                    .len(),
                2
            );
        }

        // one response has a mismatching fhe_type: it authenticates, then is dropped by the per-slot
        // fhe_type field of the invariants equality (the comparison that used to live in the meta-data
        // validator), leaving the degree-1 / Uint4 majority.
        {
            let bad_resp2 = make_signed_resp(2, &|p| {
                p.signcrypted_ciphertexts[0].fhe_type = tfhe::FheTypes::Uint8 as i32; // others are Uint4
            });
            let agg_resp = vec![resp1.clone(), bad_resp2, resp3.clone()];

            assert_eq!(
                validate_user_decrypt_responses(&trusted_ctx, &agg_resp)
                    .unwrap()
                    .as_slice()
                    .len(),
                2
            );
        }

        // the whole (authenticated) quorum agrees on degree 0, which does not match the trusted
        // threshold 1 for 4 parties: a pivot *is* formed, but the invariants sanity-check rejects it.
        {
            let bad_resp2 = make_signed_resp(2, &|p| p.degree = 0);
            let bad_resp3 = make_signed_resp(3, &|p| p.degree = 0);
            let agg_resp = vec![bad_resp2, bad_resp3];

            assert!(validate_user_decrypt_responses(&trusted_ctx, &agg_resp)
                .unwrap_err()
                .to_string()
                .contains("Pivot user decrypt responses gave degree 0 which does not match expected threshold 1 for 4 known servers"));
        }

        let run_with_customized_resp2 = |party_id, digest, pk, packing_factor| {
            // the correct parameters should be party_id = 3, digest = vec![1,2,3,4], pk = &pks[2], packing_factor = 1
            let bad_resp2 = {
                let payload = UserDecryptionResponsePayload {
                    verification_key: bc2wrap::serialize(pk).unwrap(),
                    digest,
                    signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                        fhe_type: tfhe::FheTypes::Uint4 as i32,
                        signcrypted_ciphertext: vec![1, 2, 3, 4],
                        external_handle: ciphertext_handle.clone(),
                        packing_factor,
                    }],
                    party_id, // invalid party ID
                    degree: 1,
                };
                let external_signature = compute_external_user_decrypt_signature(
                    &sk3,
                    &payload,
                    &dummy_domain,
                    client_request.enc_key(),
                    &[],
                )
                .unwrap();
                UserDecryptionResponse {
                    signature: vec![],
                    signatures: vec![],
                    external_signature,
                    payload: Some(payload),
                    extra_data: vec![],
                }
            };
            let agg_resp = vec![resp1.clone(), resp2.clone(), bad_resp2];

            assert_eq!(
                validate_user_decrypt_responses(&trusted_ctx, &agg_resp)
                    .unwrap()
                    .as_slice()
                    .len(),
                2
            );
        };

        let digest = compute_link(&client_request, &dummy_domain).unwrap();

        // sanity check the closure passes with the correct arguments
        {
            let result = std::panic::catch_unwind(|| {
                run_with_customized_resp2(3, digest.clone(), &pks[&3], 1);
            });
            assert!(result.is_err());
        }

        // digest mismatch
        {
            run_with_customized_resp2(3, vec![1, 2, 3, 4, 5], &pks[&3], 1);
        }

        // invalid party ID (too big)
        {
            run_with_customized_resp2(10, digest.clone(), &pks[&3], 1);
        }

        // invalid party ID (cannot be 0)
        {
            run_with_customized_resp2(0, digest.clone(), &pks[&3], 1);
        }

        // invalid party ID (same as another party)
        {
            run_with_customized_resp2(1, digest.clone(), &pks[&3], 1);
        }

        // invalid packing factor
        {
            run_with_customized_resp2(3, digest.clone(), &pks[&3], 2);
        }

        // invalid verification key
        {
            let (vk, _sk) = gen_sig_keys(&mut rng);
            run_with_customized_resp2(3, digest.clone(), &vk, 1);
        }

        // not enough correct responses: bad_resp2 fails the signature check (wrong extra_data), so
        // it is never authenticated and therefore does not count toward the consensus quorum. That
        // leaves only resp1 as an authenticated voter — fewer than the t+1 = 2 needed for a pivot.
        {
            let mut bad_resp2 = resp2.clone();
            bad_resp2.extra_data = vec![0];
            let agg_resp = vec![resp1.clone(), bad_resp2];

            assert!(
                validate_user_decrypt_responses(&trusted_ctx, &agg_resp)
                    .unwrap_err()
                    .to_string()
                    .contains("Cannot find user decryption pivot")
            );
        }

        // Duplicate party IDs: resp1 and bad_resp2 are duplicates, so only 1 valid response is counted
        // resp2 is valid, so we should have 2 valid responses in total, which is enough for degree=1
        {
            let bad_resp2 = resp1.clone();
            let agg_resp = vec![resp1.clone(), bad_resp2, resp2.clone()];

            assert_eq!(
                validate_user_decrypt_responses(&trusted_ctx, &agg_resp)
                    .unwrap()
                    .as_slice()
                    .len(),
                2
            );
        }

        // happy path
        {
            let agg_resp = vec![resp1.clone(), resp2.clone(), resp3.clone()];
            assert_eq!(
                validate_user_decrypt_responses(&trusted_ctx, &agg_resp)
                    .unwrap()
                    .as_slice()
                    .len(),
                3
            );
        }
    }

    #[test]
    fn test_validate_user_decrypt_responses_request_linkage() {
        let mut rng = AesRng::seed_from_u64(0);
        let (vk1, sk1) = gen_sig_keys(&mut rng);
        let (vk2, sk2) = gen_sig_keys(&mut rng);
        let (vk3, _sk3) = gen_sig_keys(&mut rng);
        let (vk4, _sk4) = gen_sig_keys(&mut rng);
        let pks: HashMap<u32, PublicSigKey> = HashMap::from_iter(
            [vk1, vk2, vk3, vk4]
                .into_iter()
                .enumerate()
                .map(|(i, k)| (i as u32 + 1, k)),
        );
        let server_addresses = pks
            .iter()
            .map(|(i, pk)| (*i, pk.address()))
            .collect::<HashMap<u32, alloy_primitives::Address>>();

        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_eph_client_sk, eph_client_pk) = encryption.keygen().unwrap();
        let (client_vk, _client_sk) = gen_sig_keys(&mut rng);

        let dummy_domain = dummy_domain();
        let ciphertext_handle = vec![5, 6, 7, 8];

        let mut enc_key_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(
            &eph_client_pk,
            &mut enc_key_buf,
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        let client_request = ParsedUserDecryptionRequest::new(
            None, // No signature is needed here because we're testing response validation
            client_vk.address(),
            enc_key_buf.clone(),
            vec![CiphertextHandle::new(ciphertext_handle.clone())],
            dummy_domain.verifying_contract.unwrap(),
            vec![],
        );

        let digest = compute_link(&client_request, &dummy_domain).unwrap();

        let resp0 = {
            let payload0 = UserDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
                digest: digest.clone(),
                signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                    fhe_type: tfhe::FheTypes::Uint4 as i32,
                    signcrypted_ciphertext: vec![1, 2, 3, 4],
                    external_handle: ciphertext_handle.clone(),
                    packing_factor: 1,
                }],
                party_id: 1,
                degree: 1,
            };
            let external_signature = compute_external_user_decrypt_signature(
                &sk1,
                &payload0,
                &dummy_domain,
                client_request.enc_key(),
                &[],
            )
            .unwrap();
            UserDecryptionResponse {
                signature: vec![],
                signatures: vec![],
                external_signature,
                payload: Some(payload0),
                extra_data: vec![],
            }
        };

        let resp1 = {
            let payload = UserDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&2]).unwrap(),
                digest: digest.clone(),
                signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                    fhe_type: tfhe::FheTypes::Uint4 as i32,
                    signcrypted_ciphertext: vec![1, 2, 3, 4],
                    external_handle: ciphertext_handle.clone(),
                    packing_factor: 1,
                }],
                party_id: 2,
                degree: 1,
            };
            let external_signature = compute_external_user_decrypt_signature(
                &sk2,
                &payload,
                &dummy_domain,
                client_request.enc_key(),
                &[],
            )
            .unwrap();
            UserDecryptionResponse {
                signature: vec![],
                signatures: vec![],
                external_signature,
                payload: Some(payload),
                extra_data: vec![],
            }
        };

        // wrong link
        // Note that we cannot change the domain or other parts of the response to cause the failure
        // because that would lead to other failures in [validate_user_decrypt_responses], which are already tested.
        // So we change the client request to cause the failure.
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];

            let (bad_client_vk, _bad_client_sk) = gen_sig_keys(&mut rng);
            let bad_client_request = ParsedUserDecryptionRequest::new(
                None, // No signature is needed here because we're testing response validation
                bad_client_vk.address(),
                enc_key_buf,
                vec![CiphertextHandle::new(ciphertext_handle.clone())],
                dummy_domain.verifying_contract.unwrap(),
                vec![],
            );
            let bad_ctx = UserDecTrustedValidationContext::new(
                &server_addresses,
                &bad_client_request,
                &dummy_domain,
                None,
            )
            .unwrap();
            assert!(validate_user_decrypt_responses(&bad_ctx, &agg_resp).is_err());
        }

        // happy path
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            let trusted_ctx = UserDecTrustedValidationContext::new(
                &server_addresses,
                &client_request,
                &dummy_domain,
                None,
            )
            .unwrap();
            assert_eq!(
                validate_user_decrypt_responses(&trusted_ctx, &agg_resp)
                    .unwrap()
                    .as_slice()
                    .len(),
                2
            );
        }
    }

    fn find_most_common_invariants_udec(
        min_occurence: usize,
        agg_resp: &[UserDecryptionResponse],
    ) -> Option<UserDecryptionInvariants> {
        let iter = agg_resp.iter().map(|resp| resp.payload.as_ref());
        select_most_common::<_, UserDecryptionInvariants>(min_occurence, iter)
    }

    #[test]
    fn test_select_most_common_user_dec() {
        let digest = vec![1, 2, 3, 4];
        let ciphertext_handle = vec![5, 6, 7, 8];
        let resp0 = {
            let payload = UserDecryptionResponsePayload {
                verification_key: vec![],
                digest: digest.clone(),
                signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                    fhe_type: tfhe::FheTypes::Uint4 as i32,
                    signcrypted_ciphertext: vec![],
                    external_handle: ciphertext_handle.clone(),
                    packing_factor: 1,
                }],
                party_id: 1,
                degree: 1,
            };
            UserDecryptionResponse {
                signature: vec![],
                signatures: vec![],
                external_signature: vec![],
                payload: Some(payload),
                extra_data: vec![],
            }
        };

        // two responses, second response has modified packing_factor
        {
            let mut resp1 = resp0.clone();
            resp1
                .payload
                .iter_mut()
                .for_each(|x| x.signcrypted_ciphertexts[0].packing_factor = 2);
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            assert_eq!(find_most_common_invariants_udec(2, &agg_resp), None);
        }

        // two responses, second response has modified fhe_type
        {
            let mut resp1 = resp0.clone();
            resp1
                .payload
                .iter_mut()
                .for_each(|x| x.signcrypted_ciphertexts[0].fhe_type = 2);
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            assert_eq!(find_most_common_invariants_udec(2, &agg_resp), None);
        }

        // two responses, second response has modified handle
        {
            let mut resp1 = resp0.clone();
            resp1
                .payload
                .iter_mut()
                .for_each(|x| x.signcrypted_ciphertexts[0].external_handle = vec![42]);
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            assert_eq!(find_most_common_invariants_udec(2, &agg_resp), None);
        }

        // two responses, second response has modified degree
        {
            let mut resp1 = resp0.clone();
            resp1.payload.iter_mut().for_each(|x| x.degree = 2);
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            assert_eq!(find_most_common_invariants_udec(2, &agg_resp), None);
        }

        // two responses, second response has modified digest
        {
            let mut resp1 = resp0.clone();
            resp1
                .payload
                .iter_mut()
                .for_each(|x| x.digest = vec![9, 9, 9, 9]);
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            assert_eq!(find_most_common_invariants_udec(2, &agg_resp), None);
        }

        // two responses, no modification
        {
            let resp1 = resp0.clone();
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            assert_eq!(
                find_most_common_invariants_udec(2, &agg_resp),
                Some(UserDecryptionInvariants::try_from(resp0.payload.clone().unwrap()).unwrap())
            );
        }

        let resp1 = resp0.clone();

        // resp2 is different from resp0 and resp1
        let resp2 = {
            let payload = UserDecryptionResponsePayload {
                verification_key: vec![],
                digest: digest.clone(),
                signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                    fhe_type: tfhe::FheTypes::Uint4 as i32,
                    signcrypted_ciphertext: vec![],
                    external_handle: ciphertext_handle.clone(),
                    packing_factor: 1,
                }],
                party_id: 1,
                degree: 2, // degree is different
            };
            UserDecryptionResponse {
                signature: vec![],
                signatures: vec![],
                external_signature: vec![],
                payload: Some(payload),
                extra_data: vec![],
            }
        };

        // three responses, but does not exceed threshold, we should have None
        {
            let agg_resp = vec![resp0.clone(), resp1.clone(), resp2.clone()];
            assert_eq!(find_most_common_invariants_udec(3, &agg_resp), None);
        }

        // three responses where the second response is modified field that's unrelated to the hashmap key
        {
            let mut resp1 = resp1.clone();
            resp1.external_signature = vec![1, 2, 3, 4];
            let agg_resp = vec![resp0.clone(), resp1, resp2.clone()];
            assert_eq!(
                find_most_common_invariants_udec(2, &agg_resp),
                Some(UserDecryptionInvariants::try_from(resp0.payload.clone().unwrap()).unwrap())
            );
        }
    }

    #[test]
    fn test_validate_user_decrypt_responses_with_5_responses() {
        // our verification functions only support 4 responses when threshold is 1
        // in this case we use 5, so the last one will be filtered out

        let mut rng = AesRng::seed_from_u64(0);
        let (vk1, sk1) = gen_sig_keys(&mut rng);
        let (vk2, sk2) = gen_sig_keys(&mut rng);
        let (vk3, sk3) = gen_sig_keys(&mut rng);
        let (vk4, sk4) = gen_sig_keys(&mut rng);
        let (vk5, sk5) = gen_sig_keys(&mut rng);
        let pks: HashMap<u32, PublicSigKey> = HashMap::from_iter(
            [vk1, vk2, vk3, vk4, vk5]
                .into_iter()
                .enumerate()
                .map(|(i, k)| (i as u32 + 1, k)),
        );
        let server_addresses = pks
            .iter()
            .map(|(i, pk)| (*i, pk.address()))
            .collect::<HashMap<u32, alloy_primitives::Address>>();

        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_eph_client_sk, eph_client_pk) = encryption.keygen().unwrap();

        let (client_vk, _client_sk) = gen_sig_keys(&mut rng);

        let dummy_domain = dummy_domain();
        let ciphertext_handle = vec![5, 6, 7, 8];

        let mut enc_key_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(
            &eph_client_pk,
            &mut enc_key_buf,
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        let client_request = ParsedUserDecryptionRequest::new(
            None,
            client_vk.address(),
            enc_key_buf,
            vec![CiphertextHandle::new(ciphertext_handle.clone())],
            dummy_domain.verifying_contract.unwrap(),
            vec![],
        );

        let sks = [&sk1, &sk2, &sk3, &sk4, &sk5];
        let make_resp =
            |party_id: u32, sk: &PrivateSigKey, digest: Vec<u8>| -> UserDecryptionResponse {
                let payload = UserDecryptionResponsePayload {
                    verification_key: bc2wrap::serialize(&pks[&party_id]).unwrap(),
                    digest,
                    signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                        fhe_type: tfhe::FheTypes::Uint4 as i32,
                        signcrypted_ciphertext: vec![1, 2, 3, 4],
                        external_handle: ciphertext_handle.clone(),
                        packing_factor: 1,
                    }],
                    party_id,
                    degree: 1,
                };
                let external_signature = compute_external_user_decrypt_signature(
                    sk,
                    &payload,
                    &dummy_domain,
                    client_request.enc_key(),
                    &[],
                )
                .unwrap();
                UserDecryptionResponse {
                    signature: vec![],
                    signatures: vec![],
                    external_signature,
                    payload: Some(payload),
                    extra_data: vec![],
                }
            };

        let digest = compute_link(&client_request, &dummy_domain).unwrap();

        // Test 1: happy path with threshold=Some(1), all 5 responses valid.
        {
            let trusted_ctx = UserDecTrustedValidationContext::new(
                &server_addresses,
                &client_request,
                &dummy_domain,
                Some(1),
            )
            .unwrap();
            let agg_resp: Vec<_> = (1..=5)
                .map(|i| make_resp(i, sks[i as usize - 1], digest.clone()))
                .collect();

            assert_eq!(
                validate_user_decrypt_responses(&trusted_ctx, &agg_resp)
                    .unwrap()
                    .as_slice()
                    .len(),
                5
            );
        }

        // Test 2: all responses have different digests, no 2 match;
        // threshold=Some(1) means min_occurence=2, so pivot selection fails
        {
            let trusted_ctx = UserDecTrustedValidationContext::new(
                &server_addresses,
                &client_request,
                &dummy_domain,
                Some(1),
            )
            .unwrap();
            let agg_resp = vec![
                make_resp(1, &sk1, vec![1, 1, 1, 1]),
                make_resp(2, &sk2, vec![2, 2, 2, 2]),
                make_resp(3, &sk3, vec![3, 3, 3, 3]),
                make_resp(4, &sk4, vec![4, 4, 4, 4]),
                make_resp(5, &sk5, vec![5, 5, 5, 5]),
            ];

            let result = validate_user_decrypt_responses(&trusted_ctx, &agg_resp);
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Cannot find user decryption pivot")
            );
        }
    }

    /// Negative tests for [`UserDecTrustedValidationContext::new`]: every rejection branch (empty
    /// server set, excessive threshold, party id 0, duplicate addresses) must keep failing, plus a
    /// positive control anchoring the happy path.
    #[test]
    fn test_user_dec_trusted_context_new_validation() {
        let mut rng = AesRng::seed_from_u64(0);

        // Four distinct server addresses (for party ids 1..=4), shared across the sub-cases.
        let addrs: Vec<alloy_primitives::Address> =
            (0..4).map(|_| gen_sig_keys(&mut rng).0.address()).collect();

        // A valid client request + domain to hand to the constructor. They are irrelevant to the
        // branches under test, which only inspect `server_addresses` and `threshold`.
        let dummy_domain = dummy_domain();
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_eph_client_sk, eph_client_pk) = encryption.keygen().unwrap();
        let mut enc_key_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(
            &eph_client_pk,
            &mut enc_key_buf,
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        let (client_vk, _client_sk) = gen_sig_keys(&mut rng);
        let client_request = ParsedUserDecryptionRequest::new(
            None,
            client_vk.address(),
            enc_key_buf,
            vec![CiphertextHandle::new(vec![5, 6, 7, 8])],
            dummy_domain.verifying_contract.unwrap(),
            vec![],
        );

        // Positive control: 4 distinct servers, default threshold => Ok, threshold defaults to 1.
        {
            let servers: HashMap<u32, alloy_primitives::Address> =
                (1u32..=4).map(|i| (i, addrs[i as usize - 1])).collect();
            let ctx = UserDecTrustedValidationContext::new(
                &servers,
                &client_request,
                &dummy_domain,
                None,
            )
            .expect("a well-formed context should be accepted");
            assert_eq!(ctx.num_parties(), 4);
            assert_eq!(ctx.threshold, 1);
        }

        // (1) Empty server set is rejected.
        {
            let servers: HashMap<u32, alloy_primitives::Address> = HashMap::new();
            assert!(
                UserDecTrustedValidationContext::new(
                    &servers,
                    &client_request,
                    &dummy_domain,
                    None,
                )
                .is_err()
            );
        }

        // (2) Threshold too high: with 4 servers the max is (4-1)/3 = 1, so 2 must be rejected.
        {
            let servers: HashMap<u32, alloy_primitives::Address> =
                (1u32..=4).map(|i| (i, addrs[i as usize - 1])).collect();
            assert!(
                UserDecTrustedValidationContext::new(
                    &servers,
                    &client_request,
                    &dummy_domain,
                    Some(2),
                )
                .is_err()
            );
        }

        // (3) Party id 0 present (roles are 1-indexed, so 0 is never legitimate).
        {
            let servers: HashMap<u32, alloy_primitives::Address> =
                (0u32..4).map(|i| (i, addrs[i as usize])).collect();
            assert!(
                UserDecTrustedValidationContext::new(
                    &servers,
                    &client_request,
                    &dummy_domain,
                    None,
                )
                .is_err()
            );
        }

        // (4) Two parties sharing the same address is rejected.
        {
            let mut servers: HashMap<u32, alloy_primitives::Address> =
                (1u32..=4).map(|i| (i, addrs[i as usize - 1])).collect();
            servers.insert(4, addrs[0]); // party 4 reuses party 1's address
            assert!(
                UserDecTrustedValidationContext::new(
                    &servers,
                    &client_request,
                    &dummy_domain,
                    None,
                )
                .is_err()
            );
        }
    }
}
