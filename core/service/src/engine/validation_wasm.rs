use crate::cryptography::signing::composite::{
    verify_scheme_bound_entries, wire_scheme_bound_preimage,
};
use crate::cryptography::signing::ecdsa::recover_address_from_eip712_hash;
use crate::{
    anyhow_error_and_log, anyhow_tracked,
    client::user_decryption_wasm::{ParsedUserDecryptionRequest, compute_link},
    cryptography::{
        compute_user_decrypt_message,
        signatures::{PublicSigKey, Signature, internal_verify_sig},
        signing::{SchemeVerfKeys, SigningSchemeType},
    },
    engine::signed_payload::user_dec_payload,
};
use alloy_dyn_abi::Eip712Domain;
use alloy_primitives::{Address, B256};
use alloy_sol_types::SolStruct;
use hashing::DomainSep;
use kms_grpc::kms::v1::{TypedSignature, UserDecryptionResponse, UserDecryptionResponsePayload};
use std::collections::{HashMap, HashSet};
use tfhe::FheTypes;
use threshold_types::role::Role;

pub(crate) const DSEP_USER_DECRYPTION: DomainSep = *b"USER_DEC";

/// Trusted client-side configuration used to validate server responses.
/// The expectation is that no unvalidated data coming from e.g., the network should be used in this type.
/// All fields MUST originate from the client's own configuration or some trusted source.
pub(crate) struct UserDecTrustedValidationContext<'a> {
    server_addresses: &'a HashMap<u32, Address>,
    scheme_verf_keys: &'a SchemeVerfKeys,
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
        scheme_verf_keys: &'a SchemeVerfKeys,
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
            scheme_verf_keys,
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

const ERR_VALIDATE_USER_DECRYPTION_ID_NOT_FOUND: &str = "ID claimed in payload not found";
const ERR_VALIDATE_USER_DECRYPTION_WRONG_ADDRESS: &str =
    "ID or address claimed in payload is incorrect";
pub(crate) const ERR_VALIDATE_USER_DECRYPTION_MISMATCH_EXTRA_DATA: &str =
    "Extra data mismatch in user decryption";
const ERR_VALIDATE_USER_DECRYPTION_NO_RESP: &str = "No response to verify in user decryption";
const ERR_VALIDATE_USER_DECRYPTION_NOT_ENOUGH_RESP: &str =
    "Not enough correct responses to user-decrypt the data!";

/// The EIP-712 signing hash that the ECDSA signature of a user decryption response
/// covers, whether it arrives in the deprecated `external_signature` field or as the
/// ECDSA entry of `signatures`.
pub(crate) fn user_decrypt_eip712_hash(
    payload: &UserDecryptionResponsePayload,
    request: &ParsedUserDecryptionRequest,
    eip712_domain: &Eip712Domain,
) -> anyhow::Result<B256> {
    let message = compute_user_decrypt_message(payload, request.enc_key(), request.extra_data())?;
    tracing::debug!("Built the UserDecryptResponseVerification EIP-712 message");
    Ok(message.eip712_signing_hash(eip712_domain))
}

/// The signatures one server response carries, whatever kind of result it is.
///
/// A node from 0.15 on carries every signature in `list`. A node from before `list`
/// sends it empty. The deprecated fields are verified whenever they are present, and
/// beside an ECDSA entry of `list`, a non-empty `external` has to equal that entry.
pub(crate) struct ResponseSignatures<'a> {
    /// The deprecated raw ECDSA signature over the serialized response payload. Only a
    /// decryption response carries one; every other result kind leaves this empty.
    pub internal: &'a [u8],
    /// The deprecated ECDSA/EIP-712 signature.
    pub external: &'a [u8],
    /// One entry per scheme, for the schemes the request asked for.
    pub list: &'a [TypedSignature],
}

/// What each signature of a [`ResponseSignatures`] covers.
pub(crate) struct SignedPayloads<'a, T> {
    /// Domain separator of the raw and the per-scheme signatures.
    pub dsep: &'a DomainSep,
    /// The serialized response payload, which the deprecated internal signature covers.
    /// Unused when [`ResponseSignatures::internal`] is empty.
    pub internal_bytes: &'a [u8],
    /// The payload every non-ECDSA scheme covers.
    pub payload: &'a T,
    /// The EIP-712 signing hash the ECDSA signatures recover from. Every result is
    /// signed under a domain, so the verifier always has one.
    pub eip712_hash: B256,
}

/// The party a response has to belong to.
pub(crate) enum ExpectedSigner<'a> {
    /// Established before any signature is read, by matching the verification key the
    /// response carries against the caller's trusted set.
    Known {
        party_id: u32,
        address: Address,
        /// Verifies the deprecated internal signature, which is not recoverable.
        verf_key: &'a PublicSigKey,
    },
    /// Discovered from the signatures: whichever party an ECDSA signature recovers to,
    /// or whichever party's published key a per-scheme entry verifies under.
    ///
    /// Only the native client verifies results whose signer has to be discovered, so a
    /// wasm build never constructs this variant.
    #[cfg_attr(not(feature = "non-wasm"), allow(dead_code))]
    Discover {
        addresses: &'a HashMap<u32, Address>,
    },
}

impl ExpectedSigner<'_> {
    /// The party `recovered` belongs to, or an error saying why it belongs to none.
    fn attribute(&self, recovered: Address) -> anyhow::Result<(u32, Address)> {
        match self {
            ExpectedSigner::Known {
                party_id, address, ..
            } => {
                if recovered == *address {
                    Ok((*party_id, *address))
                } else {
                    Err(anyhow_tracked(format!(
                        "an ECDSA signature of party {party_id} recovered to {recovered}, but \
                         {address} was expected"
                    )))
                }
            }
            ExpectedSigner::Discover { addresses } => addresses
                .iter()
                .find(|(_party_id, address)| **address == recovered)
                .map(|(party_id, address)| (*party_id, *address))
                .ok_or_else(|| {
                    anyhow_tracked(format!(
                        "an ECDSA signature of the response recovered to {recovered}, which \
                         belongs to no known party"
                    ))
                }),
        }
    }
}

/// Hold two signatures of one response to the same party.
fn agree(signer: (u32, Address), found: (u32, Address)) -> anyhow::Result<()> {
    if signer.0 != found.0 {
        return Err(anyhow_tracked(format!(
            "the response mixes signatures of party {} and party {}",
            signer.0, found.0
        )));
    }
    Ok(())
}

/// Verify the signatures of a server response that meet the request, and return the
/// party that signed it. This is the one signature check behind decryption, key
/// generation, CRS generation and preprocessing.
///
/// # What gets checked, in order
///
/// 1. `requested` names at least one scheme; an empty request is a rejection rather
///    than a lenient one.
/// 2. Before any cryptography, `list` carries an entry for every requested scheme.
///    Only when `list` is empty, as a node from before it sends, may
///    `external_signature` meet a requested ECDSA instead.
/// 3. When ECDSA was requested: the ECDSA entries of `list`. Beside an ECDSA entry, a
///    non-empty `external_signature` has to equal that entry.
/// 4. Every other requested entry of `list`, against the keys of the party that
///    signed. These entries are bound to the scheme set `list` presents, which may be
///    a superset of `requested` and may name schemes this release does not know.
/// 5. The deprecated `external_signature` and internal `signature`, whenever they are
///    present, whatever was requested.
/// 6. Every signature agreed on one party.
///
/// Steps 2 to 5 leave no requested scheme unverified: each one is either verified or
/// the response is rejected.
///
/// An entry of `list` for a scheme nobody requested carries no weight: it is not
/// checked. The deprecated fields are different. Every server fills them in until
/// 0.16, and a caller can forward them, so a present field always has to verify.
///
/// # Errors
///
/// The error is returned **unlogged**: whether a failure here is a fault or an expected
/// Byzantine rejection is the caller's to know, and so is the level it deserves.
pub(crate) fn verify_response_signatures<T>(
    sigs: &ResponseSignatures,
    payloads: &SignedPayloads<T>,
    requested: &[SigningSchemeType],
    expected: &ExpectedSigner,
    keys: &SchemeVerfKeys,
) -> anyhow::Result<(u32, Address)>
where
    T: serde::Serialize + tfhe::Versionize + tfhe::named::Named,
{
    // 1–2. Something was requested, and the list carries all of it.
    ensure_requested_present(requested, sigs.list)?;
    let (ecdsa_entries, scheme_entries) = requested_entries(sigs.list, requested);
    // 3. The ECDSA entries of the list, when ECDSA was requested.
    let signer = if requested.contains(&SigningSchemeType::Ecdsa256k1) {
        verify_ecdsa(sigs, &ecdsa_entries, payloads, expected)?
    } else {
        None
    };
    // 4. Every other requested scheme, against the keys of the party that signed.
    let signer =
        verify_scheme_entries(&scheme_entries, sigs.list, payloads, expected, keys, signer)?;
    // 5. The deprecated fields, whenever they are present.
    let signer = verify_deprecated_fields(sigs, payloads, expected, signer)?;
    // `requested` is not empty, so step 3, 4 or 5 identified the signer.
    signer.ok_or_else(|| {
        anyhow_tracked(
            "no signature of the response could be checked, so it identified no party".to_string(),
        )
    })
}

/// Steps 1 and 2: `requested` names at least one scheme, and `list` carries an entry
/// for each of them.
///
/// A node that sends `list` must sign using every requested scheme, ECDSA included.
/// A legacy node is allowed to send an empty list, in which case ECDSA must be verified.
fn ensure_requested_present(
    requested: &[SigningSchemeType],
    list: &[TypedSignature],
) -> anyhow::Result<()> {
    if requested.is_empty() {
        return Err(anyhow_tracked(
            "the response was measured against no signing scheme at all, which any signature \
             would satisfy and none would fail"
                .to_string(),
        ));
    }
    if let Some(missing) = requested.iter().find(|scheme| {
        let in_list = list.iter().any(|typed| typed.scheme == scheme.as_wire());
        // A legacy node may send an empty list, in which case an ECDSA signature must be
        // done. Step 3 verifies such signatures.
        let met_by_deprecated_fields = list.is_empty() && **scheme == SigningSchemeType::Ecdsa256k1;
        !in_list && !met_by_deprecated_fields
    }) {
        return Err(anyhow_tracked(format!(
            "the response carries no {missing} signature, but {missing} was requested"
        )));
    }
    Ok(())
}

/// The entries of `list` for a requested scheme, split into the ECDSA signatures and
/// the scheme-bound rest.
///
/// An entry for a scheme that was not requested is skipped, but does not cause a failure.
/// Still, even if it was not requested, it still count towards the scheme set the preimage
/// which is signed such that a verifier keeps working when a newer node signs under more schemes.
#[allow(clippy::type_complexity)]
fn requested_entries<'a>(
    list: &'a [TypedSignature],
    requested: &[SigningSchemeType],
) -> (Vec<&'a [u8]>, Vec<(SigningSchemeType, &'a [u8])>) {
    let mut ecdsa = Vec::new();
    let mut scheme_bound = Vec::new();
    for typed in list {
        let Ok(scheme) = SigningSchemeType::try_from(typed.scheme) else {
            tracing::warn!(
                "A response carries a signature of the unknown scheme {}, which is skipped",
                typed.scheme
            );
            // Skip validation of un-requested schemes
            continue;
        };
        if !requested.contains(&scheme) {
            tracing::warn!("A response carries a {scheme} signature that was not requested");
        } else if scheme == SigningSchemeType::Ecdsa256k1 {
            ecdsa.push(typed.signature.as_slice());
        } else {
            scheme_bound.push((scheme, typed.signature.as_slice()));
        }
    }
    (ecdsa, scheme_bound)
}

/// Step 3: the ECDSA entries of `list`, which have to recover to one party. Returns
/// that party.
///
/// A server signs `external_signature` and the ECDSA entry of `list` over the same
/// EIP-712 hash with deterministic ECDSA, so the two are byte-identical. Beside an
/// ECDSA entry, a non-empty `external_signature` therefore has to equal that entry.
///
/// A node from before `list` sends it empty. For such a node, `external_signature`
/// meets ECDSA instead. Step 5 verifies it, so this step returns `None`.
fn verify_ecdsa<T>(
    sigs: &ResponseSignatures,
    ecdsa_entries: &[&[u8]],
    payloads: &SignedPayloads<T>,
    expected: &ExpectedSigner,
) -> anyhow::Result<Option<(u32, Address)>> {
    // Step 2 rejected a non-empty `list` without a requested ECDSA entry, so no entry
    // here means that `list` is empty.
    let Some((&first, rest)) = ecdsa_entries.split_first() else {
        if sigs.external.is_empty() {
            let ecdsa = SigningSchemeType::Ecdsa256k1;
            return Err(anyhow_tracked(format!(
                "the response carries no verified {ecdsa} signature"
            )));
        }
        return Ok(None);
    };
    if !sigs.external.is_empty() && !ecdsa_entries.contains(&sigs.external) {
        return Err(anyhow_tracked(
            "the deprecated external signature of the response differs from its ECDSA entry"
                .to_string(),
        ));
    }
    let recover = |signature: &[u8]| -> anyhow::Result<(u32, Address)> {
        expected.attribute(recover_address_from_eip712_hash(
            &payloads.eip712_hash,
            signature,
        )?)
    };
    let signer = recover(first)?;
    for &signature in rest {
        agree(signer, recover(signature)?)?;
    }
    Ok(Some(signer))
}

/// Step 5: the deprecated fields, whenever the response carries them, held to the
/// party `signer` that the earlier steps identified, if any. Returns the party.
///
/// `external_signature` recovers its signer from the EIP-712 hash. The internal
/// `signature`, which only a decryption response carries, covers the serialized
/// payload alone. It cannot meet ECDSA on its own.
///
/// TODO(0.16): remove together with the fields.
fn verify_deprecated_fields<T>(
    sigs: &ResponseSignatures,
    payloads: &SignedPayloads<T>,
    expected: &ExpectedSigner,
    mut signer: Option<(u32, Address)>,
) -> anyhow::Result<Option<(u32, Address)>> {
    if !sigs.external.is_empty() {
        let found = expected.attribute(recover_address_from_eip712_hash(
            &payloads.eip712_hash,
            sigs.external,
        )?)?;
        if let Some(signer) = signer {
            agree(signer, found)?;
        }
        signer = Some(found);
    }
    if sigs.internal.is_empty() {
        return Ok(signer);
    }
    // The raw signature is not recoverable, so it is checked against the key the
    // caller established rather than used to find one.
    let ExpectedSigner::Known {
        party_id,
        address,
        verf_key,
    } = expected
    else {
        return Err(anyhow_tracked(
            "the response carries a deprecated internal signature, but its signer has to be \
             discovered from its signatures and that field is not recoverable"
                .to_string(),
        ));
    };
    let parsed = k256::ecdsa::Signature::from_slice(sigs.internal).map_err(|e| {
        anyhow_tracked(format!(
            "could not parse the deprecated internal signature: {e}"
        ))
    })?;
    internal_verify_sig(
        payloads.dsep,
        payloads.internal_bytes,
        &Signature::from_ecdsa(parsed),
        verf_key,
    )
    .map_err(|e| {
        anyhow_tracked(format!(
            "the deprecated internal signature of party {party_id} did not verify: {e}"
        ))
    })?;
    let found = (*party_id, *address);
    if let Some(signer) = signer {
        agree(signer, found)?;
    }
    Ok(Some(found))
}

/// Step 4: every requested non-ECDSA entry, against the keys of the party that signed,
/// which is returned. `signer` is the party step 3 identified, if any.
///
/// That party is the one the caller expects, else the one an ECDSA signature recovered
/// to, else the one whose keys every entry verifies under. The entries are bound to
/// the scheme set `list` presents, not to `requested`, so adding or removing any entry
/// makes them all fail.
fn verify_scheme_entries<T>(
    entries: &[(SigningSchemeType, &[u8])],
    list: &[TypedSignature],
    payloads: &SignedPayloads<T>,
    expected: &ExpectedSigner,
    keys: &SchemeVerfKeys,
    signer: Option<(u32, Address)>,
) -> anyhow::Result<Option<(u32, Address)>>
where
    T: serde::Serialize + tfhe::Versionize + tfhe::named::Named,
{
    let Some(&first) = entries.first() else {
        return Ok(signer);
    };
    let presented: Vec<i32> = list.iter().map(|typed| typed.scheme).collect();
    let preimage = wire_scheme_bound_preimage(&presented, payloads.payload)
        .map_err(|e| anyhow_tracked(format!("could not build the signed payload: {e}")))?;
    // Under `Known`, `attribute` already held any ECDSA signer to the expected party,
    // and under `Discover` an ECDSA signer fixes the keys checked below, so `party`
    // cannot differ from `signer`.
    let party = match (expected, signer) {
        (
            ExpectedSigner::Known {
                party_id, address, ..
            },
            _,
        ) => (*party_id, *address),
        (ExpectedSigner::Discover { .. }, Some(found)) => found,
        (ExpectedSigner::Discover { addresses }, None) => {
            identify_party(first, keys, addresses, payloads.dsep, &preimage)?
        }
    };
    let party_id = party.0;
    // A missing key is a rejection rather than a skip: accepting an entry nobody can
    // check would let a party satisfy a requested scheme without a valid signature.
    let party_keys = keys.get(&party_id).ok_or_else(|| {
        anyhow_tracked(format!(
            "party {party_id} published no verification keys, so its {} signature cannot be \
             checked",
            first.0
        ))
    })?;
    verify_scheme_bound_entries(
        entries.iter().copied(),
        party_keys,
        payloads.dsep,
        &preimage,
    )
    .map_err(|e| {
        anyhow_tracked(format!(
            "a signature of party {party_id} did not verify: {e}"
        ))
    })?;
    Ok(Some(party))
}

/// The party whose published key `entry` verifies under, for a response whose signer
/// neither the caller nor an ECDSA signature identified.
fn identify_party(
    entry: (SigningSchemeType, &[u8]),
    keys: &SchemeVerfKeys,
    addresses: &HashMap<u32, Address>,
    dsep: &DomainSep,
    preimage: &[u8],
) -> anyhow::Result<(u32, Address)> {
    keys.iter()
        .find(|(_, party_keys)| {
            verify_scheme_bound_entries([entry], party_keys, dsep, preimage).is_ok()
        })
        .and_then(|(party_id, _)| addresses.get(party_id).map(|address| (*party_id, *address)))
        .ok_or_else(|| {
            anyhow_tracked(format!(
                "the {} signature of the response verifies under no known party key",
                entry.0
            ))
        })
}

/// Authenticate a single (untrusted) response: look its `party_id` up in
/// `trusted_ctx.server_addresses` and verify its signature under the key registered for that party —
/// so on success the party identity is *verified*, not merely claimed. Agreement with the consensus
/// (degree, link, per-slot fhe_type / packing) is **not** checked here; that is a single invariants
/// equality in [`classify_user_decrypt_response`].
///
/// Returns the (verified) role and verification key it deserialized, so the caller can reuse it without
/// parsing the raw bytes a second time.
pub(crate) fn authenticate_user_decrypt_and_check_meta_data(
    trusted_ctx: &UserDecTrustedValidationContext,
    response: &UserDecryptionResponsePayload,
    signature: &[u8],
    signatures: &[TypedSignature],
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

    let response_bytes = bc2wrap::serialize(&response)?;
    verify_response_signatures(
        &ResponseSignatures {
            internal: signature,
            external: eip712_params.response_external_signature,
            list: signatures,
        },
        &SignedPayloads {
            dsep: &DSEP_USER_DECRYPTION,
            internal_bytes: &response_bytes,
            payload: &user_dec_payload(&response_bytes, eip712_params.response_extra_data),
            eip712_hash: user_decrypt_eip712_hash(
                response,
                trusted_ctx.client_request,
                eip712_params.trusted_eip712_domain,
            )?,
        },
        trusted_ctx.client_request.signing_schemes(),
        &ExpectedSigner::Known {
            party_id: response.party_id,
            address: *expected_addr,
            verf_key: &resp_verf_key,
        },
        trusted_ctx.scheme_verf_keys,
    )
    .inspect_err(|e| tracing::warn!("signature on received response is not valid ({})!", e))?;

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
///    payloads only — a Byzantine party gets exactly one vote, and
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
        let (verification_key, role) = match authenticate_user_decrypt_and_check_meta_data(
            trusted_ctx,
            payload,
            &cur_resp.signature,
            &cur_resp.signatures,
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

    // We need 2t+1 (where threshold == degree) authenticated responses to guarantee that at least t+1 of them are honest.
    if authenticated_payloads.len() < 2 * trusted_ctx.threshold() + 1 {
        anyhow::bail!(ERR_VALIDATE_USER_DECRYPTION_NOT_ENOUGH_RESP);
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
        TypedSignature, TypedSigncryptedCiphertext, UserDecryptionResponse,
        UserDecryptionResponsePayload,
    };
    use rand::SeedableRng;
    use strum::IntoEnumIterator;

    use crate::{
        client::user_decryption_wasm::{
            CiphertextHandle, ParsedUserDecryptionRequest, compute_link,
        },
        cryptography::{
            encryption::{Encryption, PkeScheme, PkeSchemeType},
            signatures::{
                NodeSigningIdentity, PrivateSigKey, PublicSigKey, gen_sig_keys, internal_sign,
            },
            signing::SigningSchemeType,
        },
        dummy_domain,
        engine::{
            base::sign_user_decryption_result,
            validation::{ERR_VALIDATE_USER_DECRYPTION_MISMATCH_EXTRA_DATA, select_most_common},
            validation_wasm::{
                ERR_VALIDATE_USER_DECRYPTION_ID_NOT_FOUND, ERR_VALIDATE_USER_DECRYPTION_NO_RESP,
                ERR_VALIDATE_USER_DECRYPTION_WRONG_ADDRESS,
                authenticate_user_decrypt_and_check_meta_data,
            },
        },
    };

    use super::{
        DSEP_USER_DECRYPTION, ERR_VALIDATE_USER_DECRYPTION_NOT_ENOUGH_RESP,
        Eip712VerificationParams, UserDecTrustedValidationContext, UserDecryptionInvariants,
        validate_user_decrypt_responses,
    };

    /// Asking for no scheme at all is a rejection, whatever the response carries.
    #[test]
    fn no_requested_scheme_is_a_rejection() {
        let every_scheme: Vec<_> = SigningSchemeType::iter().collect();
        let full_list: Vec<_> = every_scheme
            .iter()
            .map(|scheme| TypedSignature {
                scheme: scheme.as_wire(),
                signature: vec![],
            })
            .collect();

        for list in [&[][..], &full_list[..]] {
            let err = super::ensure_requested_present(&[], list)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("no signing scheme at all"),
                "the error does not name the cause: {err}"
            );
        }

        // A request whose schemes are all present still passes, so the rejection did
        // not swallow the ordinary case.
        super::ensure_requested_present(&every_scheme, &full_list).unwrap();
    }

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
            &NodeSigningIdentity::ecdsa_only(server_sk.clone()),
            &[SigningSchemeType::Ecdsa256k1],
            payload.clone(),
            user_pk_buf,
            extra_data.to_vec(),
            eip712_domain,
        )?
        .external_signature)
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
            vec![SigningSchemeType::Ecdsa256k1],
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
        let scheme_verf_keys = HashMap::new();
        let trusted_ctx = UserDecTrustedValidationContext::new(
            &server_addresses,
            &scheme_verf_keys,
            &client_request,
            &dummy_domain,
            None,
        )
        .unwrap();

        // Consensus-agreement checks (fhe type length / mismatch, digest mismatch) are no longer
        // done here — they are a single `UserDecryptionInvariants` equality in
        // `classify_user_decrypt_response`, exercised via `test_validate_user_decrypt_responses`.

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
                    &[],
                    &params,
                )
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_USER_DECRYPTION_ID_NOT_FOUND)
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
                    &[],
                    &params,
                )
                .unwrap_err()
                .to_string()
                .contains(ERR_VALIDATE_USER_DECRYPTION_WRONG_ADDRESS)
            );
        }

        // The response has to echo the request's extra data.
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
                    &[],
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
                &[],
                &params,
            )
            .unwrap();
        }

        // The EIP-712 message covers the whole payload and is bound to the domain, so the
        // same external signature fails for a changed payload or under another domain.
        {
            let params = Eip712VerificationParams {
                response_external_signature: &external_signature,
                response_extra_data: &extra_data,
                trusted_eip712_domain: &dummy_domain,
            };
            let changed = UserDecryptionResponsePayload {
                degree: 2,
                ..pivot_resp.clone()
            };
            let err = authenticate_user_decrypt_and_check_meta_data(
                &trusted_ctx,
                &changed,
                &[],
                &[],
                &params,
            )
            .unwrap_err()
            .to_string();
            assert!(
                err.contains("an ECDSA signature of party 1 recovered to"),
                "{err}"
            );

            let other_domain = alloy_sol_types::eip712_domain!(
                name: "Authorization token",
                version: "1",
                chain_id: 1234, // incorrect chain ID
                verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
            );
            let params = Eip712VerificationParams {
                trusted_eip712_domain: &other_domain,
                ..params
            };
            assert!(
                authenticate_user_decrypt_and_check_meta_data(
                    &trusted_ctx,
                    &pivot_resp,
                    &[],
                    &[],
                    &params,
                )
                .is_err()
            );
        }

        // The internal signature alone is not enough: a domain is always available for user
        // decryption, and the internal signature covers the payload only, so the requested
        // ECDSA has to be met by an EIP-712 form.
        {
            let pivot_buf = bc2wrap::serialize(&pivot_resp).unwrap();
            let signature = &internal_sign(&DSEP_USER_DECRYPTION, &pivot_buf, &sk0).unwrap();
            let signature_buf = signature.to_bytes();
            let params = Eip712VerificationParams {
                response_external_signature: &[],
                response_extra_data: &extra_data,
                trusted_eip712_domain: &dummy_domain,
            };
            let err = authenticate_user_decrypt_and_check_meta_data(
                &trusted_ctx,
                &pivot_resp,
                &signature_buf,
                &[],
                &params,
            )
            .unwrap_err()
            .to_string();
            assert!(
                err.contains("carries no verified Ecdsa256k1 signature"),
                "the error does not name the unverified scheme: {err}"
            );
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
            vec![SigningSchemeType::Ecdsa256k1],
            vec![],
        );
        let scheme_verf_keys = HashMap::new();
        let trusted_ctx = UserDecTrustedValidationContext::new(
            &server_addresses,
            &scheme_verf_keys,
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
                    signatures: kms_grpc::rpc_types::ecdsa_signatures(external_signature.clone()),
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
            // we need at least 3 valid responses because our degree is 1,
            // otherwise None will be returned since there are not enough responses
            let mut bad_resp3 = resp3.clone();
            bad_resp3.payload = None;
            let agg_resp = vec![resp1.clone(), resp2.clone(), resp3.clone(), bad_resp3];

            // We will have 2 accepted responses because
            // the third one does not have a payload
            assert_eq!(
                validate_user_decrypt_responses(&trusted_ctx, &agg_resp)
                    .unwrap()
                    .as_slice()
                    .len(),
                3
            );
        }

        // not enough correct payloads:
        // both bad responses are signed, but they disagree with the majority, so the pivot cannot be formed and we return an error
        {
            let bad_resp2 = make_signed_resp(2, &|p| p.signcrypted_ciphertexts = vec![]); // signed, but differnt digest
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
            let agg_resp = vec![resp1.clone(), bad_resp2, bad_resp3];

            assert!(validate_user_decrypt_responses(&trusted_ctx, &agg_resp)
                .unwrap_err()
                .to_string()
                .contains("Pivot user decrypt responses gave degree 0 which does not match expected threshold 1 for 4 known servers"));
        }

        let run_with_customized_resp2 = |party_id, digest, pk, packing_factor| {
            // the correct parameters should be party_id = 3, digest = compute_link(..), pk = &pks[3], packing_factor = 1
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
                    signatures: kms_grpc::rpc_types::ecdsa_signatures(external_signature.clone()),
                    external_signature,
                    payload: Some(payload),
                    extra_data: vec![],
                }
            };
            // Three well-formed responses (parties 1, 2, 4) accompany `bad_resp2`, so that even when
            // `bad_resp2` is dropped there are still 2t+1 = 3 authenticated, agreeing responses. With
            // only resp1 + resp2 the batch would be rejected for too few responses (2 < 3) before
            // `bad_resp2` is ever evaluated, which is not what these cases mean to exercise.
            let agg_resp = vec![resp1.clone(), resp2.clone(), resp4.clone(), bad_resp2];

            assert_eq!(
                validate_user_decrypt_responses(&trusted_ctx, &agg_resp)
                    .unwrap()
                    .as_slice()
                    .len(),
                3
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
        // it is never authenticated. That leaves only resp1 and resp3 authenticated — fewer than the required
        // 2t+1 = 3, so the batch is rejected before a pivot is even sought.
        {
            let mut bad_resp2 = resp2.clone();
            bad_resp2.extra_data = vec![0];
            let agg_resp = vec![resp1.clone(), bad_resp2, resp3.clone()];

            assert!(
                validate_user_decrypt_responses(&trusted_ctx, &agg_resp)
                    .unwrap_err()
                    .to_string()
                    .contains(ERR_VALIDATE_USER_DECRYPTION_NOT_ENOUGH_RESP)
            );
        }

        // Duplicate party IDs: resp1 appears twice, so the duplicate is dropped and party 1 is
        // counted once. resp2 and resp3 are also present, leaving 2t+1 = 3 distinct authenticated
        // responses — enough to reconstruct for degree = 1.
        {
            let dup_resp1 = resp1.clone();
            let agg_resp = vec![resp1.clone(), dup_resp1, resp2.clone(), resp3.clone()];

            assert_eq!(
                validate_user_decrypt_responses(&trusted_ctx, &agg_resp)
                    .unwrap()
                    .as_slice()
                    .len(),
                3
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
        let (vk3, sk3) = gen_sig_keys(&mut rng);
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
            vec![SigningSchemeType::Ecdsa256k1],
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
                signatures: kms_grpc::rpc_types::ecdsa_signatures(external_signature.clone()),
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
                signatures: kms_grpc::rpc_types::ecdsa_signatures(external_signature.clone()),
                external_signature,
                payload: Some(payload),
                extra_data: vec![],
            }
        };

        let resp2 = {
            let payload = UserDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&3]).unwrap(),
                digest: digest.clone(),
                signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                    fhe_type: tfhe::FheTypes::Uint4 as i32,
                    signcrypted_ciphertext: vec![1, 2, 3, 4],
                    external_handle: ciphertext_handle.clone(),
                    packing_factor: 1,
                }],
                party_id: 3,
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
                signatures: kms_grpc::rpc_types::ecdsa_signatures(external_signature.clone()),
                external_signature,
                payload: Some(payload),
                extra_data: vec![],
            }
        };
        let scheme_verf_keys = HashMap::new();
        // wrong link
        // Note that we cannot change the domain or other parts of the response to cause the failure
        // because that would lead to other failures in [validate_user_decrypt_responses], which are already tested.
        // So we change the client request to cause the failure.
        {
            let agg_resp = vec![resp0.clone(), resp1.clone(), resp2.clone()];

            let (bad_client_vk, _bad_client_sk) = gen_sig_keys(&mut rng);
            let bad_client_request = ParsedUserDecryptionRequest::new(
                None, // No signature is needed here because we're testing response validation
                bad_client_vk.address(),
                enc_key_buf,
                vec![CiphertextHandle::new(ciphertext_handle.clone())],
                dummy_domain.verifying_contract.unwrap(),
                vec![SigningSchemeType::Ecdsa256k1],
                vec![],
            );
            let bad_ctx = UserDecTrustedValidationContext::new(
                &server_addresses,
                &scheme_verf_keys,
                &bad_client_request,
                &dummy_domain,
                None,
            )
            .unwrap();
            assert!(validate_user_decrypt_responses(&bad_ctx, &agg_resp).is_err());
        }

        // happy path
        {
            let agg_resp = vec![resp0.clone(), resp1.clone(), resp2.clone()];
            let trusted_ctx = UserDecTrustedValidationContext::new(
                &server_addresses,
                &scheme_verf_keys,
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
                3
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
            vec![SigningSchemeType::Ecdsa256k1],
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
                    signatures: kms_grpc::rpc_types::ecdsa_signatures(external_signature.clone()),
                    external_signature,
                    payload: Some(payload),
                    extra_data: vec![],
                }
            };

        let digest = compute_link(&client_request, &dummy_domain).unwrap();
        let scheme_verf_keys = HashMap::new();
        // Test 1: happy path with threshold=Some(1), all 5 responses valid.
        {
            let trusted_ctx = UserDecTrustedValidationContext::new(
                &server_addresses,
                &scheme_verf_keys,
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
                &scheme_verf_keys,
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
            vec![SigningSchemeType::Ecdsa256k1],
            vec![],
        );

        let scheme_verf_keys = HashMap::new();
        // Positive control: 4 distinct servers, default threshold => Ok, threshold defaults to 1.
        {
            let servers: HashMap<u32, alloy_primitives::Address> =
                (1u32..=4).map(|i| (i, addrs[i as usize - 1])).collect();
            let ctx = UserDecTrustedValidationContext::new(
                &servers,
                &scheme_verf_keys,
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
                    &scheme_verf_keys,
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
                    &scheme_verf_keys,
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
                    &scheme_verf_keys,
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
                    &scheme_verf_keys,
                    &client_request,
                    &dummy_domain,
                    None,
                )
                .is_err()
            );
        }
    }
}
