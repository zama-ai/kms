use crate::consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT};
use crate::engine::base::retrieve_parameters;
use crate::engine::keyset_configuration::{InternalKeySetConfig, preproc_proto_to_keyset_config};
use crate::engine::utils::{MetricedError, sanity_check_extra_data};
use crate::{
    anyhow_error_and_log,
    cryptography::{
        encryption::UnifiedPublicEncKey,
        signatures::{
            PublicSigKey, Signature, internal_verify_sig, recover_address_from_ext_signature,
        },
        signing::SigningSchemeType,
    },
    engine::base::compute_public_decryption_message,
    engine::validation::Eip712VerificationParams,
};
use alloy_dyn_abi::Eip712Domain;
use hashing::DomainSep;
use itertools::Itertools;
use kms_grpc::identifiers::{ContextId, EpochId};
use kms_grpc::kms::v1::{
    CrsGenRequest, KeyGenPreprocRequest, KeyGenRequest, NewMpcEpochRequest, PreviousEpochInfo,
};
use kms_grpc::utils::tonic_result::BoxedStatus;
use kms_grpc::{KeyId, RequestId};
use kms_grpc::{
    kms::v1::{
        PublicDecryptionRequest, PublicDecryptionResponse, PublicDecryptionResponsePayload,
        TypedCiphertext, TypedPlaintext, UserDecryptionRequest,
    },
    rpc_types::{PlaintextReceiver, optional_protobuf_to_alloy_domain},
};
use observability::metrics_names::{
    OP_KEYGEN_PREPROC_REQUEST, OP_NEW_EPOCH, OP_PUBLIC_DECRYPT_REQUEST, OP_USER_DECRYPT_REQUEST,
};
use std::collections::{HashMap, HashSet};
use strum::EnumCount;
use threshold_execution::keyset_config::KeySetConfig;
use threshold_execution::tfhe_internals::parameters::DKGParams;
use threshold_execution::zk::ceremony::compute_witness_dim;

pub(crate) const DSEP_PUBLIC_DECRYPTION: DomainSep = *b"PUBL_DEC";

/// Trusted client-side configuration used to validate public decryption server responses.
/// The expectation is that no unvalidated data coming from e.g., the network should be used in this type.
/// All fields MUST originate from the client's own configuration or some trusted source.
pub(crate) struct PublicDecTrustedValidationContext<'a> {
    server_pks: &'a HashMap<u32, PublicSigKey>,
    eip712_domain: Option<&'a Eip712Domain>,
    ext_handles_bytes: &'a [Vec<u8>],
    extra_data: Option<&'a [u8]>,
    request: Option<&'a PublicDecryptionRequest>,
}

impl<'a> PublicDecTrustedValidationContext<'a> {
    pub fn new(
        server_pks: &'a HashMap<u32, PublicSigKey>,
        eip712_domain: Option<&'a Eip712Domain>,
        ext_handles_bytes: &'a [Vec<u8>],
        extra_data: Option<&'a [u8]>,
        request: Option<&'a PublicDecryptionRequest>,
    ) -> anyhow::Result<Self> {
        // Sanity check uniqueness of server public keys. This is a trusted context, so if the server keys are not unique, it is a configuration error.
        let unique_keys: HashSet<&PublicSigKey> = server_pks.values().collect();
        if unique_keys.len() != server_pks.len() {
            anyhow::bail!("Duplicate server public keys found in trusted validation context");
        }

        Ok(Self {
            server_pks,
            eip712_domain,
            ext_handles_bytes,
            extra_data,
            request,
        })
    }
}

const ERR_VALIDATE_PUBLIC_DECRYPTION_EMPTY_CTS: &str =
    "No ciphertexts in public decryption request";
const ERR_VALIDATE_PUBLIC_DECRYPTION_NO_RESP: &str =
    "No responses to validate in public decryption!";
const ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_CT_COUNT: &str =
    "The number of ciphertexts in the public decryption response is wrong";
const ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_LINK: &str =
    "The public decryption response is not linked to the correct public decryption request";
const ERR_VALIDATE_PUBLIC_DECRYPTION_MISSING_REQ_ID: &str =
    "Request ID is not set in public decryption response";
const ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_FHE_TYPE: &str =
    "Plaintext type mismatch in public decryption response";
const ERR_VALIDATE_PUBLIC_DECRYPTION_EMPTY_REQUEST: &str =
    "Public decryption request is None while validating public decryption responses";

const ERR_VALIDATE_USER_DECRYPTION_EMPTY_CTS: &str = "No ciphertexts in user decryption request";

#[derive(Clone)]
pub(crate) enum RequestIdParsingErr {
    Other(String),
    Context,
    Epoch,

    CrsGenRequest,
    PreprocRequest,
    KeyGenRequest,
    UserDecRequest,
    PublicDecRequest,
    UserDecRequestBadKeyId,
    PublicDecRequestBadKeyId,

    CrsGenResponse,
    CrsGenAbort,
    PreprocResponse,
    KeyGenResponse,
    KeyGenAbort,
    UserDecResponse,
    PublicDecResponse,
    EpochResponse,

    CustodianContext,
    CustodianContextDestruction,
    BackupRecovery,
}

impl std::fmt::Display for RequestIdParsingErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestIdParsingErr::Other(msg) => write!(f, "Other request ID error: {msg}"),
            RequestIdParsingErr::Context => write!(f, "Invalid context ID"),
            RequestIdParsingErr::Epoch => write!(f, "Invalid epoch ID"),
            RequestIdParsingErr::CrsGenRequest => write!(f, "Invalid CRS generation request ID"),
            RequestIdParsingErr::PreprocRequest => write!(f, "Invalid pre-processing request ID"),
            RequestIdParsingErr::KeyGenRequest => write!(f, "Invalid key generation request ID"),
            RequestIdParsingErr::UserDecRequest => write!(f, "Invalid user decryption request ID"),
            RequestIdParsingErr::PublicDecRequest => {
                write!(f, "Invalid public decryption request ID")
            }
            RequestIdParsingErr::UserDecRequestBadKeyId => {
                write!(f, "Invalid key ID in user decryption request")
            }
            RequestIdParsingErr::PublicDecRequestBadKeyId => {
                write!(f, "Invalid key ID in public decryption request")
            }
            RequestIdParsingErr::CrsGenResponse => {
                write!(f, "Invalid get CRS generation result request ID")
            }
            RequestIdParsingErr::CrsGenAbort => {
                write!(f, "Invalid abort CRS generation request ID")
            }
            RequestIdParsingErr::PreprocResponse => {
                write!(f, "Invalid get pre-processing result response ID")
            }
            RequestIdParsingErr::KeyGenAbort => {
                write!(f, "Invalid abort key generation request ID")
            }
            RequestIdParsingErr::KeyGenResponse => {
                write!(f, "Invalid get key generation result response ID")
            }
            RequestIdParsingErr::UserDecResponse => {
                write!(f, "Invalid get user decryption result response ID")
            }
            RequestIdParsingErr::PublicDecResponse => {
                write!(f, "Invalid get public decryption result response ID")
            }
            RequestIdParsingErr::CustodianContext => {
                write!(f, "Invalid new custodian context result response ID")
            }
            RequestIdParsingErr::CustodianContextDestruction => {
                write!(f, "Invalid new custodian context destruction ID")
            }
            RequestIdParsingErr::BackupRecovery => {
                write!(f, "Invalid new backup recovery result response ID")
            }
            RequestIdParsingErr::EpochResponse => {
                write!(f, "Invalid epoch response ID")
            }
        }
    }
}

pub(crate) fn parse_optional_grpc_request_id<'a, O: TryFrom<&'a kms_grpc::kms::v1::RequestId>>(
    request_id: &'a Option<kms_grpc::kms::v1::RequestId>,
    id_type: RequestIdParsingErr,
) -> anyhow::Result<O, BoxedStatus> {
    request_id
        .as_ref()
        .map(|id| parse_grpc_request_id(id, id_type.clone()))
        .transpose()?
        .ok_or_else(|| {
            BoxedStatus::from(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("{id_type}: {request_id:?}"),
            ))
        })
}

pub(crate) fn parse_grpc_request_id<'a, O: TryFrom<&'a kms_grpc::kms::v1::RequestId>>(
    request_id: &'a kms_grpc::kms::v1::RequestId,
    id_type: RequestIdParsingErr,
) -> Result<O, BoxedStatus> {
    request_id.try_into().map_err(|_| {
        BoxedStatus::from(tonic::Status::new(
            tonic::Code::InvalidArgument,
            format!("{id_type}: {request_id:?}"),
        ))
    })
}

/// Resolve the per-scheme `signatures` a request asks the response to be signed
/// under, validating and de-duplicating the requested schemes.
///
/// An empty list resolves to `[]`: the response still carries the always-present
/// ECDSA/EIP-712 `external_signature`.
pub(crate) fn resolve_signing_schemes(
    requested: &[i32],
) -> Result<Vec<SigningSchemeType>, Box<dyn std::error::Error + Send + Sync>> {
    let mut resolved = Vec::with_capacity(SigningSchemeType::COUNT);
    for &raw in requested {
        let scheme = SigningSchemeType::try_from(raw)
            .map_err(|e| anyhow::anyhow!("unsupported signing scheme requested: {e}"))?;
        if !resolved.contains(&scheme) {
            resolved.push(scheme);
        }
    }
    Ok(resolved)
}

/// Validates and unpacks a user decryption request and returns ciphertext, FheType, request digest, client
/// encryption key, the recipient the result is signcrypted to, key_id and request_id if valid.
///
/// Observe that the validation is limited to checking the structure of the request and parsing data into the correct types,
/// and does not check the existence of any of the referenced IDs (like request_id or key_id) or the consistency between them.
#[expect(clippy::type_complexity)]
pub(crate) fn validate_user_decrypt_req(
    req: &UserDecryptionRequest,
) -> Result<
    (
        Vec<TypedCiphertext>,
        Vec<u8>,
        Vec<u8>,
        PlaintextReceiver,
        RequestId,
        KeyId,
        ContextId,
        EpochId,
        alloy_sol_types::Eip712Domain,
        Vec<u8>,
        Vec<SigningSchemeType>,
    ),
    MetricedError,
> {
    unpack_user_decrypt_req(req).map_err(|e| {
        MetricedError::new(
            OP_USER_DECRYPT_REQUEST,
            None,
            e, // Validation error
            tonic::Code::InvalidArgument,
        )
    })
}

#[expect(clippy::type_complexity)]
fn unpack_user_decrypt_req(
    req: &UserDecryptionRequest,
) -> Result<
    (
        Vec<TypedCiphertext>,
        Vec<u8>,
        Vec<u8>,
        PlaintextReceiver,
        RequestId,
        KeyId,
        ContextId,
        EpochId,
        alloy_sol_types::Eip712Domain,
        Vec<u8>,
        Vec<SigningSchemeType>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let request_id =
        parse_optional_grpc_request_id(&req.request_id, RequestIdParsingErr::UserDecRequest)?;
    let key_id =
        parse_optional_grpc_request_id(&req.key_id, RequestIdParsingErr::UserDecRequestBadKeyId)?;
    // TODO(zama-ai/kms-internal/issues/2758)
    // remove the default context when all of context is ready
    let context_id: ContextId = match &req.context_id {
        Some(context_id) => context_id.try_into()?,
        None => *DEFAULT_MPC_CONTEXT,
    };
    let epoch_id: EpochId = match &req.epoch_id {
        Some(epoch_id) => epoch_id.try_into()?,
        None => *DEFAULT_EPOCH_ID,
    };

    sanity_check_extra_data(&req.extra_data, &epoch_id, &context_id);
    if req.typed_ciphertexts.is_empty() {
        return Err(anyhow::anyhow!(ERR_VALIDATE_USER_DECRYPTION_EMPTY_CTS).into());
    }

    // Dispatch: presence of the Solana identity selects the branch, and the chain-kind bit
    // embedded in every ciphertext handle backstops it — `validate_solana_request` rejects
    // EVM-kind handles, and `compute_link_checked` below rejects Solana-kind ones, so a request
    // cannot cross over by carrying the wrong field. All four field-by-handle-kind combinations
    // are pinned by `validation_solana::tests::dispatch_table_is_closed`.
    if let Some((link, receiver, response_domain)) =
        super::validation_solana::validate_solana_request(req)?
    {
        return Ok((
            req.typed_ciphertexts.clone(),
            link,
            req.enc_key.clone(),
            receiver,
            request_id,
            key_id,
            context_id,
            epoch_id,
            response_domain,
            req.extra_data.clone(),
            // Signing schemes are resolved exactly as on the EVM path: the Solana receiver
            // changes who the result is sealed to, not which schemes sign the response.
            resolve_signing_schemes(&req.signing_schemes)?,
        ));
    }

    let client_verf_key = alloy_primitives::Address::parse_checksummed(&req.client_address, None);
    let client_verf_key = client_verf_key.map_err(|e| {
        anyhow::anyhow!(
            "Error parsing checksummed client address: {} - {e}",
            req.client_address
        )
    })?;

    // One validating construction: the request's EIP-712 linker digest, and the domain it is
    // computed under. Note there is no signature to verify here — the user's EIP-712 signature is
    // checked by the gateway and the connector and never reaches the KMS.
    let (link, domain) = req.compute_link_checked()?;
    // Deserialize to validate the enc_key bytes, but don't return the typed key —
    // callers use raw bytes for EIP-712 and deserialize at point-of-use for crypto.
    let _client_enc_key =
        UnifiedPublicEncKey::deserialize_and_validate(&req.enc_key).map_err(|e| {
            anyhow::anyhow!(
                "Error deserializing UnifiedPublicEncKey from UserDecryptionRequest: {e}"
            )
        })?;
    Ok((
        req.typed_ciphertexts.clone(),
        link,
        req.enc_key.clone(),
        PlaintextReceiver::Evm(client_verf_key),
        request_id,
        key_id,
        context_id,
        epoch_id,
        domain,
        req.extra_data.clone(),
        resolve_signing_schemes(&req.signing_schemes)?,
    ))
}

/// Validates and unpacks a public decryption request and returns
/// the ciphertext, FheType, digest, key_id and request_id if it is valid.
///
/// Observe that validation is limited to checking the structure of the request and unpacking parameters into their correct structs.
#[expect(clippy::type_complexity)]
pub(crate) fn validate_public_decrypt_req(
    req: &PublicDecryptionRequest,
) -> Result<
    (
        Vec<TypedCiphertext>,
        RequestId,
        KeyId,
        ContextId,
        EpochId,
        Eip712Domain,
        Vec<u8>,
        Vec<SigningSchemeType>,
    ),
    MetricedError,
> {
    unpack_public_decrypt_req(req).map_err(|e| {
        MetricedError::new(
            OP_PUBLIC_DECRYPT_REQUEST,
            None,
            e, // Validation error
            tonic::Code::InvalidArgument,
        )
    })
}

#[expect(clippy::type_complexity)]
fn unpack_public_decrypt_req(
    req: &PublicDecryptionRequest,
) -> Result<
    (
        Vec<TypedCiphertext>,
        RequestId,
        KeyId,
        ContextId,
        EpochId,
        Eip712Domain,
        Vec<u8>,
        Vec<SigningSchemeType>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let req_id: RequestId =
        parse_optional_grpc_request_id(&req.request_id, RequestIdParsingErr::PublicDecRequest)?;

    tracing::info!(
        request_id = ?req_id,
        "Received new decryption request"
    );

    // TODO(zama-ai/kms-internal/issues/2758)
    // remove the default context when all of context is ready
    let context_id: ContextId = match &req.context_id {
        Some(context_id) => context_id.try_into()?,
        None => *DEFAULT_MPC_CONTEXT,
    };
    let epoch_id: EpochId = match &req.epoch_id {
        Some(epoch_id) => epoch_id.try_into()?,
        None => *DEFAULT_EPOCH_ID,
    };

    sanity_check_extra_data(&req.extra_data, &epoch_id, &context_id);
    let key_id: KeyId =
        parse_optional_grpc_request_id(&req.key_id, RequestIdParsingErr::PublicDecRequestBadKeyId)?;

    if req.ciphertexts.is_empty() {
        return Err(anyhow::anyhow!(ERR_VALIDATE_PUBLIC_DECRYPTION_EMPTY_CTS).into());
    }

    let eip712_domain = optional_protobuf_to_alloy_domain(req.domain.as_ref())?;
    Ok((
        req.ciphertexts.clone(),
        req_id,
        key_id,
        context_id,
        epoch_id,
        eip712_domain,
        req.extra_data.clone(),
        resolve_signing_schemes(&req.signing_schemes)?,
    ))
}

/// Check that a single (untrusted) public-decryption `response` carries a valid signature from the
/// supplied server `verification_key` — its **authenticity** only.
///
/// Note that `eip712_params` needs to be optional because for some tests, e.g.,
/// when the core-client just tried to query for a decryption result without knowing the
/// original request, we will not have EIP-712 parameters.
/// See the call `get_public_decrypt_responses` in core-client/src/lib.rs.
///
/// This function is **infallible with respect to the (untrusted) response
/// content**: any malformed field — an unparseable signature, a payload that fails to serialize — is
/// treated exactly like a mismatch and yields `false`, never an error. This is
/// what lets [`partition_public_decrypt_responses`] tolerate up to `t` Byzantine
/// responses without a single one being able to abort the whole validation.
///
/// `verification_key` is the response's key, already deserialized by the caller
/// ([`authenticate_public_decrypt_response`]) so it is not parsed twice.
fn verify_public_decrypt_signature(
    ext_handles_bytes: &[Vec<u8>],
    response: &PublicDecryptionResponsePayload,
    verification_key: &PublicSigKey,
    signature: &[u8],
    eip712_params: Option<&Eip712VerificationParams>,
) -> bool {
    let sig = match k256::ecdsa::Signature::from_slice(signature) {
        Ok(sig) => Signature::from_ecdsa(sig),
        Err(e) => {
            tracing::warn!("Could not parse signature in public decryption response: {e}");
            return false;
        }
    };

    // NOTE that we cannot use `BaseKmsStruct::verify_sig`
    // because `BaseKmsStruct` cannot be compiled for wasm (it has an async mutex).
    let payload = match bc2wrap::serialize(&response) {
        Ok(payload) => payload,
        Err(e) => {
            tracing::warn!("Could not serialize public decryption response: {e}");
            return false;
        }
    };

    if internal_verify_sig(&DSEP_PUBLIC_DECRYPTION, &payload, &sig, verification_key).is_err() {
        tracing::warn!("Signature on received public decryption response is not valid!");
        return false;
    }

    // Verify the external (EIP-712) signature if params are provided
    if let Some(params) = eip712_params {
        if params.response_external_signature.is_empty() {
            tracing::warn!("External signature is empty!");
            return false;
        }
        let message = match compute_public_decryption_message(
            ext_handles_bytes,
            &response.plaintexts,
            params.response_extra_data,
        ) {
            Ok(msg) => msg,
            Err(e) => {
                tracing::warn!("Failed to compute public decryption message: {e}");
                return false;
            }
        };
        match recover_address_from_ext_signature(
            &message,
            params.trusted_eip712_domain,
            params.response_external_signature,
        ) {
            Ok(recovered_addr) => {
                let expected_addr = verification_key.address();
                if recovered_addr != expected_addr {
                    tracing::warn!(
                        "External signature address mismatch: recovered {} but expected {}",
                        recovered_addr,
                        expected_addr
                    );
                    return false;
                }
            }
            Err(e) => {
                tracing::warn!("Failed to recover address from external signature: {e}");
                return false;
            }
        }
    }

    true
}

/// The fields every honest public-decryption response must agree on for a given request.
///
/// This single type plays both roles: it is the **majority-vote key** (responses are grouped by it
/// to find the ≥ `t + 1` pivot) *and* the **consensus result** read downstream — so the invariants
/// literally *are* what the servers voted on. In public decryption every party returns the same,
/// already-reconstructed plaintext, so the result *is* one of the invariants; there is no share
/// reconstruction to perform. All downstream reads of "what the servers agreed on" come from here,
/// never from an individual (untrusted) response.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct PublicDecryptionInvariants {
    /// The agreed-upon decrypted plaintexts: a consensus value (≥ `t + 1` servers returned it),
    /// not a per-party read. This is the public-decryption result.
    pub plaintexts: Vec<TypedPlaintext>,
    /// The request link every agreeing response is bound to; the yardstick each response is
    /// classified against (so classification compares against the consensus, never against another
    /// untrusted response).
    pub request_id: Option<RequestId>,
}

impl PublicDecryptionInvariants {
    /// Sanity-check the invariants against the trusted context.
    fn sanity_check(&self, trusted_ctx: &PublicDecTrustedValidationContext) -> anyhow::Result<()> {
        let Some(req) = trusted_ctx.request else {
            tracing::warn!(ERR_VALIDATE_PUBLIC_DECRYPTION_EMPTY_REQUEST);
            return Ok(());
        };

        // The consensus plaintext count must match the number of ciphertexts the client asked to
        // decrypt. This is a property of the (majority-backed) consensus, so a mismatch is a genuine
        // hard error rather than something a minority of adversaries can induce.
        if req.ciphertexts.len() != self.plaintexts.len() {
            return Err(anyhow_error_and_log(
                ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_CT_COUNT,
            ));
        }

        for (ct, pt) in req.ciphertexts.iter().zip_eq(self.plaintexts.iter()) {
            if ct.fhe_type != pt.fhe_type {
                return Err(anyhow_error_and_log(
                    ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_FHE_TYPE,
                ));
            }
        }

        // `invariants.request_id` is the parsed consensus link; compare it to the client's own request
        // id (parsing the request's — a failure there is a client-side error, not adversarial).
        match (&req.request_id, &self.request_id) {
            (Some(expected), Some(actual)) => {
                let expected: RequestId = expected.try_into()?;
                if &expected != actual {
                    return Err(anyhow_error_and_log(
                        ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_LINK,
                    ));
                }
            }
            _ => {
                return Err(anyhow_error_and_log(
                    ERR_VALIDATE_PUBLIC_DECRYPTION_MISSING_REQ_ID,
                ));
            }
        }

        Ok(())
    }
}

impl TryFrom<PublicDecryptionResponsePayload> for PublicDecryptionInvariants {
    type Error = anyhow::Error;
    fn try_from(value: PublicDecryptionResponsePayload) -> anyhow::Result<Self> {
        Ok(Self {
            request_id: match &value.request_id {
                Some(id) => Some(id.try_into()?),
                None => None,
            },
            plaintexts: value.plaintexts,
        })
    }
}

/// A public-decryption response that matched the invariants and carried a valid signature from a
/// known, unique server. Only the *count* of accepted responses matters (it must reach the
/// agreement threshold), so this carries no payload.
#[derive(Debug)]
pub(crate) struct AcceptedPublicResponse;

/// Why a response was placed in the `rejected` bucket. Typed so rejections are log- and
/// test-friendly rather than silently dropped.
#[derive(Debug)]
pub(crate) enum PublicRejectReason {
    MissingPayload,
    MissingRequestId,
    ExtraDataMismatch,
    MalformedVerificationKey,
    UnknownOrDuplicateVerificationKey,
    /// Failed the authenticity check: the internal ECDSA or external EIP-712 signature did not
    /// verify under the (known, unique) server key. Produced during the authentication pass.
    SignatureMismatch,
    /// Authenticated, but the payload disagreed with the consensus invariants (request id or
    /// plaintexts). Produced during the match pass, once the pivot has been established.
    InvariantMismatch,
}

#[derive(Debug)]
pub(crate) struct RejectedPublicResponse {
    pub reason: PublicRejectReason,
}

/// Result of partitioning untrusted public-decryption responses against invariants established
/// from the majority pivot. Construction is infallible w.r.t. the *content* of any individual
/// response: a malformed/inconsistent response lands in `rejected`, never propagated as an error.
#[derive(Debug)]
pub(crate) struct PartitionedPublicResponses {
    pub invariants: PublicDecryptionInvariants,
    pub accepted: Vec<AcceptedPublicResponse>,
    pub rejected: Vec<RejectedPublicResponse>,
}

#[cfg(test)]
fn find_most_common_invariants_pubdec(
    min_occurence: usize,
    agg_resp: &[PublicDecryptionResponse],
) -> Option<PublicDecryptionInvariants> {
    let iter = agg_resp.iter().map(|resp| resp.payload.as_ref());
    // `select_most_common` returns the winning invariants key directly (the vote key *is* the
    // consensus result for public decryption), so there is nothing to re-derive from a payload.
    crate::engine::validation::select_most_common::<_, PublicDecryptionInvariants>(
        min_occurence,
        iter,
    )
}

/// Authenticate a single (untrusted) public-decryption response: check its extra data, match its
/// verification key against a **unique** trusted server key, and verify its signature — so on
/// success the party identity is *verified*, not merely claimed. Agreement with the consensus
/// (request id, plaintexts) is **not** checked here; that is a single invariants equality in the
/// match pass of [`partition_public_decrypt_responses`], performed only once the pivot has been
/// established over the authenticated payloads.
///
/// On success the deserialized `verification_key` is inserted into `verification_keys`, so the caller
/// keeps at most one payload per server (a duplicate from the same server is rejected).
///
/// This is **infallible w.r.t. the response content**: every failure mode is a typed
/// [`PublicRejectReason`], never a propagated error, so no single response can abort the batch.
fn authenticate_public_decrypt_response(
    trusted_ctx: &PublicDecTrustedValidationContext,
    cur_resp: &PublicDecryptionResponse,
    cur_payload: &PublicDecryptionResponsePayload,
    verification_keys_seen: &mut HashSet<PublicSigKey>,
) -> Result<(), PublicRejectReason> {
    if cur_payload.request_id.is_none() {
        tracing::warn!("A request ID must be present!");
        return Err(PublicRejectReason::MissingRequestId);
    }
    if let Some(expected_extra_data) = trusted_ctx.extra_data
        && cur_resp.extra_data != expected_extra_data
    {
        tracing::warn!("Extra data mismatch in public decryption!");
        return Err(PublicRejectReason::ExtraDataMismatch);
    }
    // TODO: Need to update this to a safer deserialization (which checks versions) with #2781 ?
    let cur_verf_key: PublicSigKey = match bc2wrap::deserialize_slice(&cur_payload.verification_key)
    {
        Ok(key) => key,
        Err(e) => {
            // A single party sending a malformed verification key must not abort validation of
            // all responses: reject it like every other bad response.
            tracing::warn!(
                "Could not deserialize verification key {} in public decryption response: {e}",
                hex::encode(&cur_payload.verification_key),
            );
            return Err(PublicRejectReason::MalformedVerificationKey);
        }
    };
    let mut found_new_verf_key = false;
    // Validate the verf key: it must match a trusted server key and must not have been seen before
    // (keeping at most one authenticated payload per server).
    for (cur_id, key_to_check_against) in trusted_ctx.server_pks {
        if key_to_check_against == &cur_verf_key {
            if verification_keys_seen.contains(&cur_verf_key) {
                tracing::warn!(
                    "Verification key {} for server {} has already been found. This means at least two servers are using the same verification key, which should not happen!",
                    hex::encode(&cur_payload.verification_key),
                    cur_id
                );
            } else {
                found_new_verf_key = true;
            }
            // We found the key so break the inner loop
            break;
        }
    }
    if !found_new_verf_key {
        tracing::warn!(
            "Verification key {} in public decryption could not be matched with a unique and validated verification key",
            hex::encode(&cur_payload.verification_key),
        );
        return Err(PublicRejectReason::UnknownOrDuplicateVerificationKey);
    }

    // Verify the signature(s) carried by the response. This is pure authenticity and does not
    // depend on the (not-yet-established) consensus.
    let eip712_params = trusted_ctx
        .eip712_domain
        .map(|domain| Eip712VerificationParams {
            response_external_signature: &cur_resp.external_signature,
            response_extra_data: &cur_resp.extra_data,
            trusted_eip712_domain: domain,
        });
    // The deprecated scalar `signature` field carries the raw internal ECDSA
    // signature over the serialized payload.
    // TODO(0.16) verify `signatures` and drop the two deprecated fields.
    if cur_resp.signature.is_empty() {
        tracing::warn!("Response carries no ECDSA signature to verify!");
    }
    if !verify_public_decrypt_signature(
        trusted_ctx.ext_handles_bytes,
        cur_payload,
        &cur_verf_key,
        &cur_resp.signature,
        eip712_params.as_ref(),
    ) {
        tracing::warn!("Some server did not provide a properly signed response!");
        return Err(PublicRejectReason::SignatureMismatch);
    }

    // Record the authenticated key so a duplicate from the same server is dropped.
    verification_keys_seen.insert(cur_verf_key);
    Ok(())
}

/// Partition untrusted public-decryption responses into (accepted, rejected).
///
/// The flow mirrors user decryption: **authenticate → agree → match**, so that consensus can never
/// be skewed by duplicate or unauthenticated responses:
/// 1. Authenticate every response (identity + signature) and keep at most one payload per server.
/// 2. Establish the consensus invariants by majority vote over those authenticated, de-duplicated
///    payloads only — a Byzantine party gets exactly one vote, and unauthenticated payloads never
///    get to vote at all.
/// 3. Discard every authenticated payload that does not match the consensus invariants.
///
/// In addition, if the original request is provided (via `trusted_ctx.request`)
/// the response matches the original request
///
/// Infallible w.r.t. adversarial per-response content: any malformed/inconsistent response is
/// placed in `rejected`, never propagated. Returns `Err` ONLY when the honest invariant set cannot
/// be established at all: no responses, no configured servers, no pivot with ≥ `t + 1` agreement,
/// or — when a request is provided — the agreed result does not match the client's own request.
/// With ≥ `2t + 1` honest responses present, none of those `Err` cases can be triggered by ≤ `t`
/// adversaries.
///
/// # Arguments
/// * `trusted_ctx` — Trusted client-side configuration and request.
/// * `min_agree_count` — Trusted minimum number of agreeing responses required.
/// * `agg_resp` — Untrusted aggregated server responses received over the network.
pub(crate) fn validate_public_decrypt_responses(
    trusted_ctx: &PublicDecTrustedValidationContext,
    min_agree_count: u32,
    agg_resp: &[PublicDecryptionResponse],
) -> anyhow::Result<PartitionedPublicResponses> {
    if agg_resp.is_empty() {
        anyhow::bail!(ERR_VALIDATE_PUBLIC_DECRYPTION_NO_RESP);
    }
    if trusted_ctx.server_pks.is_empty() {
        anyhow::bail!("No servers configured in trusted public decryption context");
    }

    let mut rejected = Vec::new();

    // Authenticate every response (identity + signature) and keep at most one payload per
    // server.
    let mut verification_keys_seen = HashSet::new();
    let mut authenticated_payloads: Vec<&PublicDecryptionResponsePayload> =
        Vec::with_capacity(agg_resp.len());
    for cur_resp in agg_resp {
        let Some(cur_payload) = cur_resp.payload.as_ref() else {
            tracing::warn!("No payload in current public decryption response from server!");
            rejected.push(RejectedPublicResponse {
                reason: PublicRejectReason::MissingPayload,
            });
            continue;
        };
        match authenticate_public_decrypt_response(
            trusted_ctx,
            cur_resp,
            cur_payload,
            &mut verification_keys_seen,
        ) {
            Ok(()) => authenticated_payloads.push(cur_payload),
            Err(reason) => rejected.push(RejectedPublicResponse { reason }),
        }
    }

    if authenticated_payloads.len() < min_agree_count as usize {
        anyhow::bail!(
            "Not enough authenticated public decryption responses: {} < {}",
            authenticated_payloads.len(),
            min_agree_count
        );
    }

    //  Establish the consensus invariants by majority vote over the authenticated, de-duplicated
    //  payloads only (the vote key *is* the invariants). The selector returns the winning
    //  invariants directly — there is nothing to re-derive from a payload.
    let min_occurence = (trusted_ctx.server_pks.len() - 1) / 3 + 1; // note that this is floored division
    let invariants =
        match crate::engine::validation::select_most_common::<_, PublicDecryptionInvariants>(
            min_occurence,
            authenticated_payloads.iter().map(|payload| Some(*payload)),
        ) {
            Some(inner) => inner,
            None => anyhow::bail!("Cannot find public decryption pivot"),
        };
    invariants.sanity_check(trusted_ctx)?;

    //  Keep only the authenticated responses whose payload matches the consensus invariants. This
    //  single equality subsumes the request-id and plaintexts checks — they are all just the
    //  fields of `PublicDecryptionInvariants`.
    let mut accepted = Vec::with_capacity(authenticated_payloads.len());
    for cur_payload in authenticated_payloads {
        match PublicDecryptionInvariants::try_from(cur_payload.clone()) {
            Ok(resp_invariants) if resp_invariants == invariants => {
                accepted.push(AcceptedPublicResponse);
            }
            _ => {
                tracing::warn!(
                    "A public decryption response does not match the consensus invariants"
                );
                rejected.push(RejectedPublicResponse {
                    reason: PublicRejectReason::InvariantMismatch,
                });
            }
        }
    }

    let partitioned = PartitionedPublicResponses {
        invariants,
        accepted,
        rejected,
    };
    if !partitioned.rejected.is_empty() {
        tracing::warn!(
            "Public decryption partition rejected {} of {} response(s): {:?}",
            partitioned.rejected.len(),
            agg_resp.len(),
            partitioned
                .rejected
                .iter()
                .map(|r| &r.reason)
                .collect::<Vec<_>>(),
        );
    }

    if partitioned.accepted.len() < min_agree_count as usize {
        anyhow::bail!(
            "Not enough agreeing public decryption responses: {} < {}",
            partitioned.accepted.len(),
            min_agree_count
        );
    }

    Ok(partitioned)
}

#[expect(clippy::type_complexity)]
pub(crate) fn validate_preproc_request(
    req: KeyGenPreprocRequest,
) -> Result<
    (
        RequestId,
        ContextId,
        EpochId,
        DKGParams,
        KeySetConfig,
        Eip712Domain,
        Vec<u8>,
        Vec<SigningSchemeType>,
    ),
    MetricedError,
> {
    unpack_preproc_request(req).map_err(|e| {
        MetricedError::new(
            OP_KEYGEN_PREPROC_REQUEST,
            None,
            e, // Validation error
            tonic::Code::InvalidArgument,
        )
    })
}

#[expect(clippy::type_complexity)]
fn unpack_preproc_request(
    req: KeyGenPreprocRequest,
) -> anyhow::Result<(
    RequestId,
    ContextId,
    EpochId,
    DKGParams,
    KeySetConfig,
    Eip712Domain,
    Vec<u8>,
    Vec<SigningSchemeType>,
)> {
    let req_id =
        parse_optional_grpc_request_id(&req.request_id, RequestIdParsingErr::KeyGenRequest)?;
    tracing::info!(
        request_id = ?req_id,
        "Received new preprocessing request"
    );

    // TODO(zama-ai/kms-internal/issues/2758)
    // remove the default context when all of context is ready
    // context_id is not used at the moment, but we validate it if present
    let context_id: ContextId = match &req.context_id {
        Some(context_id) => context_id.try_into()?,
        None => *DEFAULT_MPC_CONTEXT,
    };
    let epoch_id: EpochId = match &req.epoch_id {
        Some(epoch_id) => epoch_id.try_into()?,
        None => *DEFAULT_EPOCH_ID,
    };

    sanity_check_extra_data(&req.extra_data, &epoch_id, &context_id);

    let dkg_params = retrieve_parameters(Some(req.params))?;
    let keyset_config = preproc_proto_to_keyset_config(&req.keyset_config)?;

    let eip712_domain = optional_protobuf_to_alloy_domain(req.domain.as_ref())?;

    Ok((
        req_id,
        context_id,
        epoch_id,
        dkg_params,
        keyset_config,
        eip712_domain,
        req.extra_data,
        resolve_signing_schemes(&req.signing_schemes).map_err(|e| anyhow::anyhow!("{e}"))?,
    ))
}

#[expect(clippy::type_complexity)]
pub(crate) fn validate_key_gen_request(
    req: KeyGenRequest,
    op_tag: &'static str,
) -> Result<
    (
        RequestId,
        Option<RequestId>,
        ContextId,
        EpochId,
        DKGParams,
        InternalKeySetConfig,
        Eip712Domain,
        Vec<u8>,
        Vec<SigningSchemeType>,
    ),
    MetricedError,
> {
    unpack_key_gen_request(req).map_err(|e| {
        MetricedError::new(
            op_tag,
            None,
            e, // Validation error
            tonic::Code::InvalidArgument,
        )
    })
}

#[expect(clippy::type_complexity)]
fn unpack_key_gen_request(
    req: KeyGenRequest,
) -> anyhow::Result<(
    RequestId,
    Option<RequestId>,
    ContextId,
    EpochId,
    DKGParams,
    InternalKeySetConfig,
    Eip712Domain,
    Vec<u8>,
    Vec<SigningSchemeType>,
)> {
    let req_id =
        parse_optional_grpc_request_id(&req.request_id, RequestIdParsingErr::KeyGenRequest)?;
    // Presence of the preprocessing ID is enforced by the caller; only the
    // format is validated here.
    let preproc_id = req
        .preproc_id
        .as_ref()
        .map(|id| parse_grpc_request_id(id, RequestIdParsingErr::PreprocRequest))
        .transpose()?;

    tracing::info!(
        request_id = ?req_id,
        "Received new key generation request"
    );

    // TODO(zama-ai/kms-internal/issues/2758)
    // remove the default context when all of context is ready
    // context_id is not used at the moment, but we validate it if present
    let context_id: ContextId = match &req.context_id {
        Some(context_id) => context_id.try_into()?,
        None => *DEFAULT_MPC_CONTEXT,
    };
    let epoch_id: EpochId = match &req.epoch_id {
        Some(epoch_id) => epoch_id.try_into()?,
        None => *DEFAULT_EPOCH_ID,
    };
    sanity_check_extra_data(&req.extra_data, &epoch_id, &context_id);
    let internal_keyset_config =
        InternalKeySetConfig::new(req.keyset_config, req.keyset_added_info).map_err(|e| {
            tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Failed to parse KeySetConfig: {e}"),
            )
        })?;
    let dkg_params = retrieve_parameters(req.params)?;
    let eip712_domain = optional_protobuf_to_alloy_domain(req.domain.as_ref())?;

    Ok((
        req_id,
        preproc_id,
        context_id,
        epoch_id,
        dkg_params,
        internal_keyset_config,
        eip712_domain,
        req.extra_data,
        resolve_signing_schemes(&req.signing_schemes).map_err(|e| anyhow::anyhow!("{e}"))?,
    ))
}

pub(crate) struct VerifiedCrsGenRequest {
    pub req_id: RequestId,
    pub epoch_id: EpochId,
    pub context_id: ContextId,
    pub witness_dim: usize,
    pub params: DKGParams,
    pub eip712_domain: Eip712Domain,
    pub extra_data: Vec<u8>,
    pub signing_schemes: Vec<SigningSchemeType>,
}

pub(crate) fn validate_crs_gen_request(
    req: CrsGenRequest,
    op_tag: &'static str,
) -> Result<VerifiedCrsGenRequest, MetricedError> {
    unpack_crs_gen_request(req).map_err(|e| {
        MetricedError::new(
            op_tag,
            None,
            e, // Validation error
            tonic::Code::InvalidArgument,
        )
    })
}

fn unpack_crs_gen_request(req: CrsGenRequest) -> anyhow::Result<VerifiedCrsGenRequest> {
    let req_id =
        parse_optional_grpc_request_id(&req.request_id, RequestIdParsingErr::CrsGenRequest)?;

    tracing::info!(
        request_id = ?req_id,
        "Received new crs generation request"
    );

    // This verification is more strict than the checks in [compute_witness_dim] below
    // because it only allows powers of 2. But there are no strong reasons
    // to use max_num_bits that are not powers of 2 so we enforce it here.
    if let Some(max_num_bits) = req.max_num_bits {
        verify_max_num_bits(max_num_bits as usize)?;
    }

    let params = retrieve_parameters(Some(req.params))?;
    let crs_params = params.compact_pk_enc_params();

    let witness_dim = compute_witness_dim(&crs_params, req.max_num_bits.map(|x| x as usize))?;

    // TODO(zama-ai/kms-internal/issues/2758)
    // remove the default context and epoch when all of context is ready
    let context_id = match &req.context_id {
        Some(ctx) => parse_grpc_request_id(ctx, RequestIdParsingErr::Context)?,
        None => *DEFAULT_MPC_CONTEXT,
    };

    let epoch_id = match &req.epoch_id {
        Some(epoch) => parse_grpc_request_id(epoch, RequestIdParsingErr::Epoch)?,
        None => *DEFAULT_EPOCH_ID,
    };
    sanity_check_extra_data(&req.extra_data, &epoch_id, &context_id);
    let eip712_domain = optional_protobuf_to_alloy_domain(req.domain.as_ref())?;

    Ok(VerifiedCrsGenRequest {
        req_id,
        epoch_id,
        context_id,
        witness_dim,
        params,
        eip712_domain,
        extra_data: req.extra_data,
        signing_schemes: resolve_signing_schemes(&req.signing_schemes)
            .map_err(|e| anyhow::anyhow!("{e}"))?,
    })
}

/// The max_num_bits should be a power of 2 between 1 and 2048 (inclusive)
fn verify_max_num_bits(max_num_bits: usize) -> anyhow::Result<()> {
    if max_num_bits > 0 && max_num_bits <= 2048 && usize::is_power_of_two(max_num_bits) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "max_num_bits must be a power of 2 between 1 and 2048, got {}",
            max_num_bits
        ))
    }
}

#[derive(Debug)]
pub(crate) struct ResharingParams {
    pub previous_epoch: PreviousEpochInfo,
    /// The EIP-712 domain used to sign the reshared key results.
    pub signing_domain: Eip712Domain,
}

#[derive(Debug)]
pub(crate) struct VerifiedNewMpcEpochRequest {
    pub context_id: ContextId,
    pub epoch_id: EpochId,
    pub extra_data: Vec<u8>,
    pub resharing: Option<ResharingParams>,
    pub signing_schemes: Vec<SigningSchemeType>,
}

pub(crate) fn validate_new_mpc_epoch_request(
    req: NewMpcEpochRequest,
) -> Result<VerifiedNewMpcEpochRequest, MetricedError> {
    unpack_new_mpc_epoch_req(req).map_err(|e| {
        MetricedError::new(
            OP_NEW_EPOCH,
            None,
            e, // Validation error
            tonic::Code::InvalidArgument,
        )
    })
}

fn unpack_new_mpc_epoch_req(req: NewMpcEpochRequest) -> anyhow::Result<VerifiedNewMpcEpochRequest> {
    let context_id = match req.context_id {
        Some(context_id) => parse_grpc_request_id(&context_id, RequestIdParsingErr::Context)?,
        None => *DEFAULT_MPC_CONTEXT,
    };
    let epoch_id: EpochId =
        parse_optional_grpc_request_id(&req.epoch_id, RequestIdParsingErr::Epoch)?;

    sanity_check_extra_data(&req.extra_data, &epoch_id, &context_id);
    let resharing = match req.previous_epoch {
        Some(previous_epoch) => {
            let signing_domain = optional_protobuf_to_alloy_domain(req.domain.as_ref())?;
            Some(ResharingParams {
                previous_epoch,
                signing_domain,
            })
        }
        None => None,
    };
    Ok(VerifiedNewMpcEpochRequest {
        context_id,
        epoch_id,
        resharing,
        extra_data: req.extra_data,
        signing_schemes: resolve_signing_schemes(&req.signing_schemes)
            .map_err(|e| anyhow::anyhow!("{e}"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::resolve_signing_schemes;
    use aes_prng::AesRng;
    use alloy_dyn_abi::Eip712Domain;
    use kms_grpc::{
        RequestId,
        kms::v1::{
            self, NewMpcEpochRequest, PreviousEpochInfo, PublicDecryptionRequest,
            PublicDecryptionResponse, PublicDecryptionResponsePayload, TypedCiphertext,
            TypedPlaintext, UserDecryptionRequest,
        },
        rpc_types::{ID_LENGTH, alloy_to_protobuf_domain},
        solana_binding::{SolanaUserDecryptBinding, SolanaUserDecryptBindingError},
    };
    use rand::SeedableRng;
    use std::collections::HashMap;

    use crate::{
        cryptography::{
            encryption::{Encryption, PkeScheme, PkeSchemeType, UnifiedPublicEncKey},
            signatures::{PrivateSigKey, PublicSigKey, gen_sig_keys, internal_sign},
            signing::SigningSchemeType,
        },
        dummy_domain,
        engine::{
            base::{PubDecCallValues, derive_request_id, sign_public_decryption_result},
            validation::{
                RequestIdParsingErr, parse_grpc_request_id, validate_new_mpc_epoch_request,
            },
            validation_non_wasm::{
                ERR_VALIDATE_PUBLIC_DECRYPTION_NO_RESP, find_most_common_invariants_pubdec,
                validate_public_decrypt_responses,
            },
        },
    };

    use super::{
        DSEP_PUBLIC_DECRYPTION, ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_FHE_TYPE,
        ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_LINK, ERR_VALIDATE_PUBLIC_DECRYPTION_EMPTY_CTS,
        ERR_VALIDATE_USER_DECRYPTION_EMPTY_CTS, Eip712VerificationParams,
        PublicDecTrustedValidationContext, unpack_public_decrypt_req, unpack_user_decrypt_req,
        verify_max_num_bits, verify_public_decrypt_signature,
    };

    /// Sign a public decryption result the way the server does, under ECDSA only.
    fn sign_ecdsa_public_decrypt_result(
        server_sk: &PrivateSigKey,
        payload: PublicDecryptionResponsePayload,
        ext_handles_bytes: &[Vec<u8>],
        extra_data: Vec<u8>,
        eip712_domain: &Eip712Domain,
    ) -> PubDecCallValues {
        sign_public_decryption_result(
            server_sk,
            &[SigningSchemeType::Ecdsa256k1],
            payload,
            ext_handles_bytes,
            extra_data,
            eip712_domain,
        )
        .unwrap()
    }

    /// Build a public decryption response exactly as the server produces one: the
    /// deprecated scalar `signature` over the serialized payload, the EIP-712
    /// `external_signature`, and the per-scheme `signatures` list.
    fn signed_public_decrypt_response(
        server_sk: &PrivateSigKey,
        payload: PublicDecryptionResponsePayload,
        ext_handles_bytes: &[Vec<u8>],
        extra_data: Vec<u8>,
        eip712_domain: &Eip712Domain,
    ) -> PublicDecryptionResponse {
        let signed = sign_ecdsa_public_decrypt_result(
            server_sk,
            payload,
            ext_handles_bytes,
            extra_data,
            eip712_domain,
        );
        PublicDecryptionResponse {
            signature: signed.signature,
            signatures: signed.signatures,
            payload: Some(signed.payload),
            external_signature: signed.external_signature,
            extra_data: signed.extra_data,
        }
    }

    /// Empty signing schemes resolves to an empty list (opt-in), known schemes map through
    #[test]
    fn test_resolve_signing_schemes() {
        // Empty ⇒ empty: `signatures` is opt-in, the ECDSA/EIP-712 signature is
        // carried by `external_signature` independently.
        assert_eq!(resolve_signing_schemes(&[]).unwrap(), vec![]);

        // Known schemes map through, preserving order.
        let ecdsa = kms_grpc::kms::v1::SigningSchemeType::Ecdsa256k1 as i32;
        let mldsa65 = kms_grpc::kms::v1::SigningSchemeType::Mldsa65 as i32;
        assert_eq!(
            resolve_signing_schemes(&[ecdsa, mldsa65]).unwrap(),
            vec![SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa65]
        );

        // Duplicates are removed while preserving first-seen order.
        assert_eq!(
            resolve_signing_schemes(&[mldsa65, ecdsa, mldsa65]).unwrap(),
            vec![SigningSchemeType::MlDsa65, SigningSchemeType::Ecdsa256k1]
        );

        // An unknown scheme is an error.
        assert!(resolve_signing_schemes(&[9999]).is_err());
    }

    /// The verification key a response carries, deserialized — as `authenticate_public_decrypt_response`
    /// does before calling `verify_public_decrypt_signature`.
    fn vk_of(payload: &PublicDecryptionResponsePayload) -> PublicSigKey {
        bc2wrap::deserialize_slice(&payload.verification_key).unwrap()
    }

    #[test]
    fn test_validate_public_decrypt_req() {
        // setup data we're going to use in this test
        let alloy_domain = dummy_domain();
        let domain = alloy_to_protobuf_domain(&alloy_domain).unwrap();
        let request_id = derive_request_id("request_id").unwrap();
        let key_id = derive_request_id("key_id").unwrap();

        // ciphertexts are not directly verified except the length
        let ciphertexts = vec![TypedCiphertext {
            ciphertext: vec![],
            fhe_type: 0,
            external_handle: vec![],
            ciphertext_format: 0,
        }];

        // empty key ID
        {
            let req = PublicDecryptionRequest {
                signing_schemes: vec![SigningSchemeType::Ecdsa256k1 as i32],
                request_id: Some(request_id.into()),
                ciphertexts: ciphertexts.clone(),
                key_id: None,
                domain: Some(domain.clone()),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
            };
            assert!(
                unpack_public_decrypt_req(&req)
                    .unwrap_err()
                    .to_string()
                    .contains(&RequestIdParsingErr::PublicDecRequestBadKeyId.to_string())
            );
        }

        // empty request ID
        {
            let req = PublicDecryptionRequest {
                signing_schemes: vec![SigningSchemeType::Ecdsa256k1 as i32],
                request_id: None,
                ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
            };
            assert!(
                unpack_public_decrypt_req(&req)
                    .unwrap_err()
                    .to_string()
                    .contains(&RequestIdParsingErr::PublicDecRequest.to_string())
            );
        }

        // invalid request ID
        {
            let bad_req_id = v1::RequestId {
                request_id: ['x'; ID_LENGTH].iter().collect(),
            };
            let req = PublicDecryptionRequest {
                signing_schemes: vec![SigningSchemeType::Ecdsa256k1 as i32],
                request_id: Some(bad_req_id),
                ciphertexts: vec![],
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
            };
            assert!(
                unpack_public_decrypt_req(&req)
                    .unwrap_err()
                    .to_string()
                    .contains(&RequestIdParsingErr::PublicDecRequest.to_string())
            );
        }

        // empty ciphertext
        {
            let req = PublicDecryptionRequest {
                signing_schemes: vec![SigningSchemeType::Ecdsa256k1 as i32],
                request_id: Some(request_id.into()),
                ciphertexts: vec![],
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
            };
            assert!(
                unpack_public_decrypt_req(&req)
                    .unwrap_err()
                    .to_string()
                    .contains(ERR_VALIDATE_PUBLIC_DECRYPTION_EMPTY_CTS)
            );
        }

        // finally everything is ok
        {
            let req = PublicDecryptionRequest {
                signing_schemes: vec![], // empty signing schemes defaults to ECDSA
                request_id: Some(request_id.into()),
                ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
            };
            let (_, _, _, _, _, _domain, _, _) = unpack_public_decrypt_req(&req).unwrap();
        }
    }

    #[test]
    fn test_validate_user_decrypt_req() {
        // setup data we're going to use in this test
        let alloy_domain = dummy_domain();
        let domain = alloy_to_protobuf_domain(&alloy_domain).unwrap();
        let request_id = derive_request_id("request_id").unwrap();
        let key_id = derive_request_id("key_id").unwrap();
        let client_address = alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045");
        let mut rng = AesRng::from_random_seed();
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_enc_sk, enc_pk) = encryption.keygen().unwrap();

        let mut enc_pk_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(
            &enc_pk,
            &mut enc_pk_buf,
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();

        // ciphertexts are not directly verified except the length
        let ciphertexts = vec![TypedCiphertext {
            ciphertext: vec![],
            fhe_type: 0,
            external_handle: vec![],
            ciphertext_format: 0,
        }];

        // empty key ID
        {
            let req = UserDecryptionRequest {
                signing_schemes: vec![SigningSchemeType::Ecdsa256k1 as i32],
                request_id: Some(request_id.into()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: None,
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_pk_buf.clone(),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
                signing_metadata: vec![],
            };
            assert!(
                unpack_user_decrypt_req(&req)
                    .unwrap_err()
                    .to_string()
                    .contains(&RequestIdParsingErr::UserDecRequestBadKeyId.to_string())
            );
        }

        // empty request ID
        {
            let req = UserDecryptionRequest {
                signing_schemes: vec![SigningSchemeType::Ecdsa256k1 as i32],
                request_id: None,
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_pk_buf.clone(),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
                signing_metadata: vec![],
            };
            assert!(
                unpack_user_decrypt_req(&req)
                    .unwrap_err()
                    .to_string()
                    .contains(&RequestIdParsingErr::UserDecRequest.to_string())
            );
        }

        // invalid request ID
        {
            let bad_req_id = v1::RequestId {
                request_id: ['x'; ID_LENGTH].iter().collect(),
            };
            let req = UserDecryptionRequest {
                signing_schemes: vec![SigningSchemeType::Ecdsa256k1 as i32],
                request_id: Some(bad_req_id),
                typed_ciphertexts: vec![],
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_pk_buf.clone(),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
                signing_metadata: vec![],
            };
            assert!(
                unpack_user_decrypt_req(&req)
                    .unwrap_err()
                    .to_string()
                    .contains(&RequestIdParsingErr::UserDecRequest.to_string())
            );
        }

        // empty ciphertext
        {
            let req = UserDecryptionRequest {
                signing_schemes: vec![SigningSchemeType::Ecdsa256k1 as i32],
                request_id: Some(request_id.into()),
                typed_ciphertexts: vec![],
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_pk_buf.clone(),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
                signing_metadata: vec![],
            };
            assert!(
                unpack_user_decrypt_req(&req)
                    .unwrap_err()
                    .to_string()
                    .contains(ERR_VALIDATE_USER_DECRYPTION_EMPTY_CTS)
            );
        }

        // bad client address
        {
            let req = UserDecryptionRequest {
                signing_schemes: vec![SigningSchemeType::Ecdsa256k1 as i32],
                request_id: Some(request_id.into()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(Some(1)),
                enc_key: enc_pk_buf.clone(),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
                signing_metadata: vec![],
            };
            assert!(
                unpack_user_decrypt_req(&req).unwrap_err().to_string().contains(
                    "Error parsing checksummed client address: 0xD8Da6bf26964Af9d7EEd9e03e53415d37AA96045 - Bad address checksum"
                )
            );
        }

        // bad public key
        {
            // note that we're serializing the inner mlkem512 public key, which is not supported
            let inner_key = match &enc_pk {
                UnifiedPublicEncKey::MlKem512(pk) => pk,
                _ => panic!("expected MlKem512 key"),
            };
            let bad_enc_pk_buf = bc2wrap::serialize(&inner_key).unwrap();
            let req = UserDecryptionRequest {
                signing_schemes: vec![SigningSchemeType::Ecdsa256k1 as i32],
                request_id: Some(request_id.into()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: bad_enc_pk_buf,
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
                signing_metadata: vec![],
            };
            assert!(
                unpack_user_decrypt_req(&req)
                    .unwrap_err()
                    .to_string()
                    .contains("Error deserializing")
            ); // the error message that is returned from trying to decode the bad encoding
        }

        // finally everything is ok
        {
            let req = UserDecryptionRequest {
                signing_schemes: vec![], // empty signing schemes defaults to ECDSA
                request_id: Some(request_id.into()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_pk_buf.clone(),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
                signing_metadata: vec![],
            };
            assert!(unpack_user_decrypt_req(&req).is_ok());
        }

        // EVM routing rejects handles that carry the Solana chain-kind bit while preserving the
        // existing EVM handle-padding behavior.
        {
            let mut evm_handle = [0xabu8; 32];
            let solana_chain_id = (1u64 << 63) | 12_345;
            evm_handle[22..30].copy_from_slice(&solana_chain_id.to_be_bytes());
            let evm_req = UserDecryptionRequest {
                request_id: Some(request_id.into()),
                typed_ciphertexts: vec![TypedCiphertext {
                    ciphertext: vec![],
                    fhe_type: 0,
                    external_handle: evm_handle.to_vec(),
                    ciphertext_format: 0,
                }],
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: enc_pk_buf.clone(),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
                signing_metadata: vec![],
                signing_schemes: vec![],
            };
            assert!(
                unpack_user_decrypt_req(&evm_req)
                    .unwrap_err()
                    .to_string()
                    .contains("embeds Solana chain ID")
            );
        }

        // Typed Solana requests require exact 32-byte handles with one common high-bit chain ID.
        {
            const SOLANA_CHAIN_ID: u64 = (1 << 63) | 12_345;
            let mut handle = [0xabu8; 32];
            handle[22..30].copy_from_slice(&SOLANA_CHAIN_ID.to_be_bytes());
            let solana_req = UserDecryptionRequest {
                request_id: Some(request_id.into()),
                typed_ciphertexts: vec![TypedCiphertext {
                    ciphertext: vec![],
                    fhe_type: 0,
                    external_handle: handle.to_vec(),
                    ciphertext_format: 0,
                }],
                key_id: Some(key_id.into()),
                domain: Some(domain.clone()),
                client_address: String::new(),
                enc_key: enc_pk_buf.clone(),
                extra_data: vec![],
                context_id: None,
                epoch_id: None,
                signing_metadata: vec![kms_grpc::kms::v1::SigningMetadata::solana(
                    vec![0x11; 32],
                    vec![0x22; 32],
                )],
                signing_schemes: vec![],
            };
            assert!(unpack_user_decrypt_req(&solana_req).is_ok());

            for client_address in [
                client_address.to_checksum(None),
                format!("solana:{}", alloy_primitives::hex::encode([0x11; 32])),
            ] {
                let mut mixed_identity = solana_req.clone();
                mixed_identity.client_address = client_address;
                assert_eq!(
                    unpack_user_decrypt_req(&mixed_identity)
                        .unwrap_err()
                        .to_string(),
                    "Solana user decryption request must not set client_address"
                );
            }

            for actual in [31, 33] {
                let mut invalid_identity = solana_req.clone();
                invalid_identity.signing_metadata =
                    vec![kms_grpc::kms::v1::SigningMetadata::solana(
                        vec![0x11; actual],
                        vec![0x22; 32],
                    )];
                assert_eq!(
                    unpack_user_decrypt_req(&invalid_identity)
                        .unwrap_err()
                        .to_string(),
                    format!("Solana client identity must be a 32-byte pubkey, got {actual} bytes")
                );
            }

            // A purely legacy request: no signing metadata at all, so the request falls to the
            // EVM path and the legacy string is judged there.
            let mut legacy_string = solana_req.clone();
            legacy_string.signing_metadata = vec![];
            legacy_string.client_address =
                format!("solana:{}", alloy_primitives::hex::encode([0x11; 32]));
            assert!(
                unpack_user_decrypt_req(&legacy_string)
                    .unwrap_err()
                    .to_string()
                    .contains("Error parsing checksummed client address")
            );

            let mut low_bit = solana_req.clone();
            low_bit.typed_ciphertexts[0].external_handle[22..30]
                .copy_from_slice(&12_345u64.to_be_bytes());
            let error = unpack_user_decrypt_req(&low_bit).unwrap_err();
            assert_eq!(
                error.downcast_ref::<SolanaUserDecryptBindingError>(),
                Some(&SolanaUserDecryptBindingError::InvalidHandleChainId {
                    index: 0,
                    chain_id: 12_345,
                })
            );

            let mut mixed = solana_req.clone();
            let mut other_handle = handle;
            other_handle[22..30].copy_from_slice(&(SOLANA_CHAIN_ID + 1).to_be_bytes());
            mixed.typed_ciphertexts.push(TypedCiphertext {
                ciphertext: vec![],
                fhe_type: 0,
                external_handle: other_handle.to_vec(),
                ciphertext_format: 0,
            });
            let error = unpack_user_decrypt_req(&mixed).unwrap_err();
            assert_eq!(
                error.downcast_ref::<SolanaUserDecryptBindingError>(),
                Some(&SolanaUserDecryptBindingError::MixedChainIds {
                    index: 1,
                    expected: SOLANA_CHAIN_ID,
                    actual: SOLANA_CHAIN_ID + 1,
                })
            );

            let mut short = solana_req;
            short.typed_ciphertexts[0].external_handle.pop();
            let error = unpack_user_decrypt_req(&short).unwrap_err();
            assert_eq!(
                error.downcast_ref::<SolanaUserDecryptBindingError>(),
                Some(&SolanaUserDecryptBindingError::InvalidHandleLength {
                    index: 0,
                    actual: 31,
                })
            );
        }
    }

    #[test]
    fn solana_link_binds_the_tuple_own_extra_data() {
        // Pins that the link is computed over the values the returned tuple actually carries —
        // the same handles, transport key and extra_data the rest of the engine goes on to use —
        // so the adapter cannot quietly bind a second parse of the request.
        let mut rng = AesRng::from_random_seed();
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_enc_sk, enc_pk) = encryption.keygen().unwrap();
        let mut enc_pk_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(
            &enc_pk,
            &mut enc_pk_buf,
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();

        let mut handle = [0xabu8; 32];
        handle[22..30].copy_from_slice(&((1u64 << 63) | 12_345).to_be_bytes());

        let req = UserDecryptionRequest {
            request_id: Some(derive_request_id("request_id").unwrap().into()),
            typed_ciphertexts: vec![TypedCiphertext {
                ciphertext: vec![],
                fhe_type: 0,
                external_handle: handle.to_vec(),
                ciphertext_format: 0,
            }],
            key_id: Some(derive_request_id("key_id").unwrap().into()),
            domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
            client_address: String::new(),
            enc_key: enc_pk_buf,
            extra_data: vec![0x77; 4],
            context_id: None,
            epoch_id: None,
            signing_metadata: vec![kms_grpc::kms::v1::SigningMetadata::solana(
                vec![0x11; 32],
                vec![0x22; 32],
            )],
            signing_schemes: vec![],
        };

        let (
            cts,
            link,
            enc_key,
            _receiver,
            _req_id,
            _key_id,
            _context_id,
            _epoch_id,
            _domain,
            extra_data,
            _signing_schemes,
        ) = unpack_user_decrypt_req(&req).unwrap();

        let binding = SolanaUserDecryptBinding::new(
            &[0x22; 32],
            &[0x11; 32],
            cts.iter().map(|ct| ct.external_handle.as_slice()),
            &enc_key,
            &extra_data,
        )
        .unwrap();

        assert_eq!(
            link,
            binding.compute_link(),
            "the link must bind the extra_data the tuple carries, not a second parse",
        );
    }

    #[test]
    fn test_validate_request_id() {
        // not hex
        let bad_req_id1 = v1::RequestId {
            request_id: ['x'; ID_LENGTH].iter().collect(),
        };
        assert!(
            parse_grpc_request_id::<RequestId>(&bad_req_id1, RequestIdParsingErr::Epoch).is_err()
        );

        // wrong length
        let bad_req_id2 = v1::RequestId {
            request_id: ['a'; ID_LENGTH - 1].iter().collect(),
        };
        assert!(
            parse_grpc_request_id::<RequestId>(&bad_req_id2, RequestIdParsingErr::Epoch).is_err()
        );

        let good_req_id = v1::RequestId {
            request_id: ['a'; ID_LENGTH].iter().collect(),
        };
        assert!(
            parse_grpc_request_id::<RequestId>(&good_req_id, RequestIdParsingErr::Epoch).is_err()
        );
    }

    #[test]
    fn test_user_decrypt_link_validation() {
        let mut rng = AesRng::from_random_seed();
        let (client_pk, _client_sk) = gen_sig_keys(&mut rng);
        let client_address = client_pk.address();
        let ciphertext = vec![1, 2, 3];
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_enc_sk, enc_pk) = encryption.keygen().unwrap();
        let key_id = derive_request_id("key_id").unwrap();

        let typed_ciphertext = TypedCiphertext {
            ciphertext,
            fhe_type: tfhe::FheTypes::Uint4 as i32,
            ciphertext_format: 0,
            external_handle: vec![123],
        };
        let domain = dummy_domain();
        let domain_msg = alloy_to_protobuf_domain(&domain).unwrap();

        let inner_key = match &enc_pk {
            UnifiedPublicEncKey::MlKem512(pk) => pk,
            _ => panic!("expected MlKem512 key"),
        };
        let req = UserDecryptionRequest {
            signing_schemes: vec![SigningSchemeType::Ecdsa256k1 as i32],
            request_id: Some(v1::RequestId {
                request_id: "dummy request ID".to_owned(),
            }),
            enc_key: bc2wrap::serialize(&inner_key).unwrap(),
            client_address: client_address.to_checksum(None),
            key_id: Some(key_id.into()),
            typed_ciphertexts: vec![typed_ciphertext],
            domain: Some(domain_msg),
            extra_data: vec![],
            context_id: None,
            epoch_id: None,
            signing_metadata: vec![],
        };

        {
            // happy path
            req.compute_link_checked().unwrap();
        }
        {
            // use a wrong client address (invalid string length)
            let mut bad_req = req.clone();
            bad_req.client_address = "66f9664f97F2b50F62D13eA064982f936dE76657".to_string();
            match bad_req.compute_link_checked() {
                Ok(_) => panic!("expected failure"),
                Err(e) => {
                    assert_eq!(
                        e.to_string(),
                        "error parsing checksummed address: 66f9664f97F2b50F62D13eA064982f936dE76657 - invalid string length"
                    );
                }
            }
        }
        {
            // use the same address for verifying contract and client address should fail
            // we don't explicitly test the error string, it is tested in the grpc crate
            let mut bad_domain = domain.clone();
            bad_domain.verifying_contract = Some(client_address);
            let mut bad_req = req.clone();
            bad_req.domain = Some(alloy_to_protobuf_domain(&bad_domain).unwrap());
            match bad_req.compute_link_checked() {
                Ok(_) => panic!("expected failure"),
                Err(_e) => {}
            }
        }
    }

    #[test]
    fn test_validate_public_decrypt_meta_response() {
        let mut rng = AesRng::seed_from_u64(0);
        let (vk0, sk0) = gen_sig_keys(&mut rng);
        let (vk1, sk1) = gen_sig_keys(&mut rng);
        let (vk2, _sk2) = gen_sig_keys(&mut rng);

        let pks: HashMap<u32, PublicSigKey> = HashMap::from_iter(
            [vk0, vk1, vk2]
                .into_iter()
                .enumerate()
                .map(|(i, k)| (i as u32 + 1, k)),
        );

        let request_id = Some(
            derive_request_id("test_validate_public_decrypt_meta_response")
                .unwrap()
                .into(),
        );
        let pivot = PublicDecryptionResponsePayload {
            verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
            plaintexts: vec![TypedPlaintext {
                bytes: vec![1],
                fhe_type: tfhe::FheTypes::Uint4 as i32,
            }],
            request_id: request_id.clone(),
        };

        let pivot_buf = bc2wrap::serialize(&pivot).unwrap();

        // `verify_public_decrypt_signature` checks *authenticity* only (the internal ECDSA / external
        // EIP-712 signature); agreement with the consensus invariants is checked separately in the
        // match pass of `partition_public_decrypt_responses` (exercised by
        // `test_validate_public_decrypt_responses`).

        // use a bad signature (signed with wrong private key)
        {
            let signature = &internal_sign(&DSEP_PUBLIC_DECRYPTION, &pivot_buf, &sk1).unwrap();
            let signature_buf = signature.to_bytes();

            assert!(!verify_public_decrypt_signature(
                &[],
                &pivot,
                &vk_of(&pivot),
                &signature_buf,
                None,
            ));
        }

        // use a bad signature (malformed signature)
        {
            let signature = &internal_sign(&DSEP_PUBLIC_DECRYPTION, &pivot_buf, &sk0).unwrap();
            // The signature is malformed because it's using bincode to serialize instead of `signature.to_bytes()`.
            let signature_buf = bc2wrap::serialize(&signature).unwrap();

            assert!(!verify_public_decrypt_signature(
                &[],
                &pivot,
                &vk_of(&pivot),
                &signature_buf,
                None,
            ));
        }

        // use a bad signature (signing the wrong value): the signature is over `bad_value` but we
        // verify it against `pivot`, so the internal signature does not match.
        {
            let bad_request_id = Some(
                derive_request_id("bad_test_validate_public_decrypt_meta_response")
                    .unwrap()
                    .into(),
            );
            let bad_value = PublicDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
                plaintexts: vec![TypedPlaintext {
                    bytes: vec![1],
                    fhe_type: tfhe::FheTypes::Uint4 as i32,
                }],
                request_id: bad_request_id,
            };
            let bad_value_buf = bc2wrap::serialize(&bad_value).unwrap();

            let bad_signature =
                &internal_sign(&DSEP_PUBLIC_DECRYPTION, &bad_value_buf, &sk0).unwrap();
            let bad_signature_buf = bad_signature.to_bytes();

            assert!(!verify_public_decrypt_signature(
                &[],
                &pivot,
                &vk_of(&pivot),
                &bad_signature_buf,
                None,
            ));
        }

        // use a bad response whose key did not actually sign it: the payload carries a fresh key
        // `vk` but the signature is by `sk0`, so it does not verify under `vk`.
        {
            let (vk, _sk0) = gen_sig_keys(&mut rng);
            let bad_value = PublicDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&vk).unwrap(),
                plaintexts: vec![TypedPlaintext {
                    bytes: vec![1],
                    fhe_type: tfhe::FheTypes::Uint4 as i32,
                }],
                request_id,
            };
            let bad_value_buf = bc2wrap::serialize(&bad_value).unwrap();

            let signature = &internal_sign(&DSEP_PUBLIC_DECRYPTION, &bad_value_buf, &sk0).unwrap();
            let signature_buf = signature.to_bytes();

            assert!(!verify_public_decrypt_signature(
                &[],
                &bad_value,
                &vk_of(&bad_value),
                &signature_buf,
                None,
            ));
        }

        // happy path
        {
            let signature = &internal_sign(&DSEP_PUBLIC_DECRYPTION, &pivot_buf, &sk0).unwrap();
            let signature_buf = signature.to_bytes(); // NOTE: signatures are not serialized with bincode

            assert!(verify_public_decrypt_signature(
                &[],
                &pivot,
                &vk_of(&pivot),
                &signature_buf,
                None,
            ));
        }
    }

    #[test]
    fn test_validate_public_decrypt_responses() {
        let mut rng = AesRng::seed_from_u64(0);
        let (vk0, sk0) = gen_sig_keys(&mut rng);
        let (vk1, sk1) = gen_sig_keys(&mut rng);
        let (vk2, _sk2) = gen_sig_keys(&mut rng);

        let pks = HashMap::from_iter(
            [vk0, vk1, vk2]
                .into_iter()
                .enumerate()
                .map(|(i, k)| (i as u32 + 1, k)),
        );

        let alloy_domain = dummy_domain();
        let ext_handles_bytes = vec![vec![1, 2, 3, 4]];

        let request_id = Some(
            derive_request_id("test_validate_public_decrypt_responses")
                .unwrap()
                .into(),
        );
        let extra_data_0 = vec![1, 2, 3, 4];
        let extra_data_1 = vec![1, 2, 3, 4]; // same extra_data as resp0
        let plaintexts = vec![TypedPlaintext {
            bytes: vec![1],
            fhe_type: tfhe::FheTypes::Uint8 as i32, // Uint8, supported for ABI encoding
        }];

        let trusted_ctx = PublicDecTrustedValidationContext {
            server_pks: &pks,
            eip712_domain: Some(&alloy_domain),
            ext_handles_bytes: &ext_handles_bytes,
            extra_data: Some(&extra_data_0),
            request: None,
        };

        // NOTE: the pks map uses 1-based index while the others use 0-based index like sk0
        let resp0 = signed_public_decrypt_response(
            &sk0,
            PublicDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
                plaintexts: plaintexts.clone(),
                request_id: request_id.clone(),
            },
            &ext_handles_bytes,
            extra_data_0.clone(),
            &alloy_domain,
        );
        let resp1 = signed_public_decrypt_response(
            &sk1,
            PublicDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&2]).unwrap(),
                plaintexts: plaintexts.clone(),
                request_id: request_id.clone(),
            },
            &ext_handles_bytes,
            extra_data_1.clone(),
            &alloy_domain,
        );

        // in this test we just want to test that we can catch a duplicate validation key
        // the signature authentication itself is tested in `test_validate_public_decrypt_meta_response`

        // using an empty payload, we should only get 1 valid response
        {
            let mut empty_resp = resp1.clone();
            empty_resp.payload = None;
            let mut bad_agg_resp = vec![resp0.clone(), empty_resp];
            assert_eq!(
                validate_public_decrypt_responses(&trusted_ctx, 1, &bad_agg_resp)
                    .unwrap()
                    .accepted
                    .len(),
                1
            );

            // reverse the aggregate response so the empty one is the first
            bad_agg_resp.reverse();
            assert_eq!(
                validate_public_decrypt_responses(&trusted_ctx, 1, &bad_agg_resp)
                    .unwrap()
                    .accepted
                    .len(),
                1
            );
        }

        // use the same response twice, we should only get 1 valid response
        {
            let bad_agg_resp = vec![resp0.clone(), resp0.clone()];
            assert_eq!(
                validate_public_decrypt_responses(&trusted_ctx, 1, &bad_agg_resp)
                    .unwrap()
                    .accepted
                    .len(),
                1
            );
        }

        // if one of the responses have a wrong number of plaintext, we should only get 1 valid response
        {
            let bad_resp = {
                let payload = PublicDecryptionResponsePayload {
                    verification_key: bc2wrap::serialize(&pks[&2]).unwrap(),
                    plaintexts: vec![
                        TypedPlaintext {
                            bytes: vec![1],
                            fhe_type: tfhe::FheTypes::Uint8 as i32,
                        },
                        TypedPlaintext {
                            bytes: vec![1],
                            fhe_type: tfhe::FheTypes::Uint8 as i32,
                        },
                    ],
                    request_id,
                };
                let payload_buf = bc2wrap::serialize(&payload).unwrap();
                let signature =
                    &internal_sign(&DSEP_PUBLIC_DECRYPTION, &payload_buf, &sk1).unwrap();
                let signature_buf = signature.to_bytes();

                PublicDecryptionResponse {
                    signature: signature_buf,
                    signatures: vec![],
                    payload: Some(payload),
                    external_signature: vec![],
                    extra_data: vec![],
                }
            };
            let agg_resp = vec![resp0.clone(), bad_resp];
            assert_eq!(
                validate_public_decrypt_responses(&trusted_ctx, 1, &agg_resp,)
                    .unwrap()
                    .accepted
                    .len(),
                1
            );
        }

        // one of the response has the wrong extra_data
        {
            let mut bad_resp = resp1.clone();
            bad_resp.extra_data = vec![0];
            let agg_resp = vec![resp0.clone(), bad_resp];
            assert_eq!(
                validate_public_decrypt_responses(&trusted_ctx, 1, &agg_resp,)
                    .unwrap()
                    .accepted
                    .len(),
                1 // instead of 2
            );
        }

        // No request id
        {
            let mut bad_resp = resp1.clone();
            bad_resp.payload.as_mut().unwrap().request_id = None;
            let agg_resp = vec![resp0.clone(), bad_resp];
            assert_eq!(
                validate_public_decrypt_responses(&trusted_ctx, 1, &agg_resp,)
                    .unwrap()
                    .accepted
                    .len(),
                1 // instead of 2
            );
        }

        // happy path
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            assert_eq!(
                validate_public_decrypt_responses(&trusted_ctx, 1, &agg_resp,)
                    .unwrap()
                    .accepted
                    .len(),
                2
            );
        }
    }

    #[test]
    fn test_validate_public_decrypt_responses_against_request() {
        let mut rng = AesRng::seed_from_u64(0);
        let (vk0, sk0) = gen_sig_keys(&mut rng);
        let (vk1, sk1) = gen_sig_keys(&mut rng);
        let (vk2, _sk2) = gen_sig_keys(&mut rng);

        let pks = HashMap::from_iter(
            [vk0, vk1, vk2]
                .into_iter()
                .enumerate()
                .map(|(i, k)| (i as u32 + 1, k)),
        );

        let request_id = Some(derive_request_id("PublicDecryptionRequest").unwrap().into());
        let ciphertexts = vec![TypedCiphertext {
            ciphertext: vec![1, 2, 3, 4],
            fhe_type: tfhe::FheTypes::Uint8 as i32,
            external_handle: vec![1, 2, 3, 4],
            ciphertext_format: 1,
        }];
        let ext_handles_bytes = ciphertexts
            .iter()
            .map(|c| c.external_handle.to_owned())
            .collect::<Vec<_>>();
        let extra_data = vec![1, 2, 3];
        let alloy_domain = dummy_domain();
        let domain = Some(alloy_to_protobuf_domain(&alloy_domain).unwrap());
        let request = PublicDecryptionRequest {
            signing_schemes: vec![SigningSchemeType::Ecdsa256k1 as i32],
            request_id: request_id.clone(),
            ciphertexts,
            key_id: Some(
                derive_request_id("PublicDecryptionRequest key_id")
                    .unwrap()
                    .into(),
            ),
            domain: domain.clone(),
            extra_data: extra_data.clone(),
            context_id: None,
            epoch_id: None,
        };

        let plaintexts = vec![TypedPlaintext {
            bytes: vec![1],
            fhe_type: tfhe::FheTypes::Uint8 as i32,
        }];
        let resp0 = signed_public_decrypt_response(
            &sk0,
            PublicDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
                plaintexts: plaintexts.clone(),
                request_id: request_id.clone(),
            },
            &ext_handles_bytes,
            extra_data.clone(),
            &alloy_domain,
        );
        let resp1 = signed_public_decrypt_response(
            &sk1,
            PublicDecryptionResponsePayload {
                verification_key: bc2wrap::serialize(&pks[&2]).unwrap(),
                plaintexts,
                request_id: request_id.clone(),
            },
            &ext_handles_bytes,
            extra_data.clone(),
            &alloy_domain,
        );

        let trusted_ctx = PublicDecTrustedValidationContext {
            server_pks: &pks,
            eip712_domain: Some(&alloy_domain),
            ext_handles_bytes: &ext_handles_bytes,
            extra_data: Some(&extra_data),
            request: Some(&request),
        };

        // invalid aggregate response, e.g., when there are none
        {
            let agg_resp = vec![];
            assert!(
                validate_public_decrypt_responses(&trusted_ctx, 1, &agg_resp)
                    .unwrap_err()
                    .to_string()
                    .contains(ERR_VALIDATE_PUBLIC_DECRYPTION_NO_RESP)
            );
        }

        // not enough decryption responses
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            assert!(
                validate_public_decrypt_responses(&trusted_ctx, 3, &agg_resp)
                    .unwrap_err()
                    .to_string()
                    .contains("Not enough authenticated public decryption responses")
            );
        }

        // plaintext type is wrong
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            let bad_request = PublicDecryptionRequest {
                signing_schemes: vec![],
                request_id: Some(derive_request_id("PublicDecryptionRequest").unwrap().into()),
                ciphertexts: vec![TypedCiphertext {
                    ciphertext: vec![1, 2, 3, 4],
                    fhe_type: 3, // we change the fhe_type so it's the wrong request
                    external_handle: vec![1, 2, 3, 4],
                    ciphertext_format: 1,
                }],
                key_id: Some(
                    derive_request_id("PublicDecryptionRequest key_id")
                        .unwrap()
                        .into(),
                ),
                domain: domain.clone(),
                extra_data: extra_data.clone(),
                context_id: None,
                epoch_id: None,
            };
            let bad_ctx = PublicDecTrustedValidationContext {
                server_pks: &pks,
                eip712_domain: Some(&alloy_domain),
                ext_handles_bytes: &ext_handles_bytes,
                extra_data: Some(&extra_data),
                request: Some(&bad_request),
            };
            assert!(
                validate_public_decrypt_responses(&bad_ctx, 2, &agg_resp)
                    .unwrap_err()
                    .to_string()
                    .contains(ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_FHE_TYPE)
            );
        }

        // bad external signature
        {
            let mut bad_resp = resp1.clone();
            bad_resp.external_signature[0] ^= 1;
            let agg_resp = vec![resp0.clone(), bad_resp];
            validate_public_decrypt_responses(&trusted_ctx, 1, &agg_resp).unwrap();
        }

        // request ID
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            let bad_request = PublicDecryptionRequest {
                signing_schemes: vec![],
                // wrong request ID
                request_id: Some(
                    derive_request_id("bad PublicDecryptionRequest")
                        .unwrap()
                        .into(),
                ),
                ciphertexts: vec![TypedCiphertext {
                    ciphertext: vec![1, 2, 3, 4],
                    fhe_type: tfhe::FheTypes::Uint8 as i32,
                    external_handle: vec![1, 2, 3, 4],
                    ciphertext_format: 1,
                }],
                key_id: Some(
                    derive_request_id("PublicDecryptionRequest key_id")
                        .unwrap()
                        .into(),
                ),
                domain: domain.clone(),
                extra_data: extra_data.clone(),
                context_id: None,
                epoch_id: None,
            };
            let bad_ctx = PublicDecTrustedValidationContext {
                server_pks: &pks,
                eip712_domain: Some(&alloy_domain),
                ext_handles_bytes: &ext_handles_bytes,
                extra_data: Some(&extra_data),
                request: Some(&bad_request),
            };
            assert!(
                validate_public_decrypt_responses(&bad_ctx, 2, &agg_resp)
                    .unwrap_err()
                    .to_string()
                    .contains(ERR_VALIDATE_PUBLIC_DECRYPTION_BAD_LINK)
            );
        }

        // request is empty, which should pass
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            let none_ctx = PublicDecTrustedValidationContext {
                server_pks: &pks,
                eip712_domain: None,
                ext_handles_bytes: &[],
                extra_data: None,
                request: None,
            };
            validate_public_decrypt_responses(&none_ctx, 2, &agg_resp).unwrap();
        }

        // happy path
        {
            let agg_resp = vec![resp0.clone(), resp1.clone()];
            validate_public_decrypt_responses(&trusted_ctx, 2, &agg_resp).unwrap();
        }
    }

    #[test]
    fn test_validate_public_decrypt_meta_response_with_eip712() {
        let mut rng = AesRng::seed_from_u64(9999);
        let (vk0, sk0) = gen_sig_keys(&mut rng);
        let (vk1, _sk1) = gen_sig_keys(&mut rng);
        let (vk2, _sk2) = gen_sig_keys(&mut rng);

        let pks: HashMap<u32, PublicSigKey> = HashMap::from_iter(
            [vk0, vk1, vk2]
                .into_iter()
                .enumerate()
                .map(|(i, k)| (i as u32 + 1, k)),
        );

        let request_id = Some(
            derive_request_id("test_validate_public_decrypt_meta_response_with_eip712")
                .unwrap()
                .into(),
        );
        let pivot = PublicDecryptionResponsePayload {
            verification_key: bc2wrap::serialize(&pks[&1]).unwrap(),
            plaintexts: vec![TypedPlaintext {
                bytes: vec![1],
                fhe_type: tfhe::FheTypes::Uint8 as i32,
            }],
            request_id: request_id.clone(),
        };

        let alloy_domain = dummy_domain();
        let ext_handles_bytes = vec![vec![1, 2, 3, 4]];
        let extra_data = vec![1, 2, 3, 4];

        let signed = sign_ecdsa_public_decrypt_result(
            &sk0,
            pivot.clone(),
            &ext_handles_bytes,
            extra_data.clone(),
            &alloy_domain,
        );

        // NOTE: signatures are not serialized with bincode
        let signature_buf = signed.signature;
        let external_signature = signed.external_signature;

        let mut bad_external_signature = external_signature.clone();
        bad_external_signature[0] ^= 1;

        // return false for empty external signature
        assert!(!verify_public_decrypt_signature(
            &ext_handles_bytes,
            &pivot,
            &vk_of(&pivot),
            &signature_buf,
            Some(&Eip712VerificationParams {
                response_external_signature: &[],
                response_extra_data: &extra_data,
                trusted_eip712_domain: &alloy_domain,
            }),
        ));

        // return false for bad external signature
        assert!(!verify_public_decrypt_signature(
            &ext_handles_bytes,
            &pivot,
            &vk_of(&pivot),
            &signature_buf,
            Some(&Eip712VerificationParams {
                response_external_signature: &bad_external_signature,
                response_extra_data: &extra_data,
                trusted_eip712_domain: &alloy_domain,
            }),
        ));

        // happy path
        assert!(verify_public_decrypt_signature(
            &ext_handles_bytes,
            &pivot,
            &vk_of(&pivot),
            &signature_buf,
            Some(&Eip712VerificationParams {
                response_external_signature: &external_signature,
                response_extra_data: &extra_data,
                trusted_eip712_domain: &alloy_domain,
            }),
        ));
    }

    #[test]
    fn test_validate_new_mpc_epoch_request() {
        // When previous_epoch is set but domain is None, optional_protobuf_to_alloy_domain
        // should fail, and validate_new_mpc_epoch_request should surface InvalidArgument.
        {
            let req = NewMpcEpochRequest {
                signing_schemes: vec![kms_grpc::kms::v1::SigningSchemeType::Ecdsa256k1 as i32],
                previous_epoch: Some(PreviousEpochInfo::default()),
                domain: None,
                ..Default::default()
            };
            let err = validate_new_mpc_epoch_request(req)
                .expect_err("request without domain must be rejected");
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
        // Happy path
        {
            let req = NewMpcEpochRequest {
                signing_schemes: vec![kms_grpc::kms::v1::SigningSchemeType::Ecdsa256k1 as i32],
                previous_epoch: Some(PreviousEpochInfo::default()),
                domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
                ..Default::default()
            };
            let err = validate_new_mpc_epoch_request(req)
                .expect_err("request without domain must be rejected");
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
    }

    #[test]
    fn test_new_mpc_epoch_request_signing_schemes() {
        let epoch_id = derive_request_id("new_mpc_epoch_signing_schemes").unwrap();
        // Duplicates are removed and the requested order is kept.
        {
            let req = NewMpcEpochRequest {
                signing_schemes: vec![
                    kms_grpc::kms::v1::SigningSchemeType::Mldsa65 as i32,
                    kms_grpc::kms::v1::SigningSchemeType::Ecdsa256k1 as i32,
                    kms_grpc::kms::v1::SigningSchemeType::Mldsa65 as i32,
                ],
                epoch_id: Some(epoch_id.into()),
                ..Default::default()
            };
            let verified = validate_new_mpc_epoch_request(req).unwrap();
            assert_eq!(
                verified.signing_schemes,
                vec![SigningSchemeType::MlDsa65, SigningSchemeType::Ecdsa256k1]
            );
        }
        // An unknown scheme is rejected before any epoch work starts.
        {
            let req = NewMpcEpochRequest {
                signing_schemes: vec![9999],
                epoch_id: Some(epoch_id.into()),
                ..Default::default()
            };
            let err = validate_new_mpc_epoch_request(req)
                .expect_err("unknown signing scheme must be rejected");
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
    }

    #[test]
    fn test_select_most_common_dec() {
        let request_id = Some(
            derive_request_id("test_select_most_common_dec")
                .unwrap()
                .into(),
        );
        let plaintexts = vec![TypedPlaintext {
            bytes: vec![1],
            fhe_type: tfhe::FheTypes::Uint4 as i32,
        }];
        let resp0 = {
            let payload = PublicDecryptionResponsePayload {
                verification_key: vec![],
                plaintexts: plaintexts.clone(),
                request_id: request_id.clone(),
            };
            PublicDecryptionResponse {
                signature: vec![],
                signatures: vec![],
                payload: Some(payload),
                external_signature: vec![],
                extra_data: vec![],
            }
        };

        // two responses, second response has modified digest
        {
            let mut resp1 = resp0.clone();
            resp1.payload.iter_mut().for_each(|x| {
                x.request_id = Some(
                    derive_request_id("bad_select_most_common_dec")
                        .unwrap()
                        .into(),
                )
            });
            let agg_resp = vec![resp0.clone(), resp1];
            assert_eq!(find_most_common_invariants_pubdec(2, &agg_resp), None);
        }

        // two responses, second response has modified plaintext
        {
            let mut resp1 = resp0.clone();
            resp1.payload.iter_mut().for_each(|x| {
                x.plaintexts = vec![TypedPlaintext {
                    bytes: vec![0],
                    fhe_type: tfhe::FheTypes::Uint4 as i32,
                }]
            });
            let agg_resp = vec![resp0.clone(), resp1];
            assert_eq!(find_most_common_invariants_pubdec(2, &agg_resp), None);
        }

        // happy path
        {
            let resp1 = resp0.clone();
            let agg_resp = vec![resp0.clone(), resp1];
            assert_eq!(
                find_most_common_invariants_pubdec(2, &agg_resp),
                Some(resp0.payload.as_ref().unwrap().clone().try_into().unwrap())
            );
        }

        let resp1 = resp0.clone();
        let resp2 = {
            let bad_request_id = Some(
                derive_request_id("bad_select_most_common_dec")
                    .unwrap()
                    .into(),
            );
            let payload = PublicDecryptionResponsePayload {
                verification_key: vec![],
                plaintexts: plaintexts.clone(),
                request_id: bad_request_id,
            };
            PublicDecryptionResponse {
                signature: vec![],
                signatures: vec![],
                payload: Some(payload),
                external_signature: vec![],
                extra_data: vec![],
            }
        };

        // threshold is too high
        {
            let agg_resp = vec![resp0.clone(), resp1.clone(), resp2.clone()];
            assert_eq!(find_most_common_invariants_pubdec(3, &agg_resp), None);
        }

        // second response has a modified field unrelated to the hashmap key
        {
            let mut resp1 = resp1.clone();
            resp1.signatures = kms_grpc::rpc_types::ecdsa_signatures(vec![2, 2, 2, 2]);
            let agg_resp = vec![resp0.clone(), resp1.clone(), resp2.clone()];
            assert_eq!(
                find_most_common_invariants_pubdec(2, &agg_resp),
                Some(resp1.payload.as_ref().unwrap().clone().try_into().unwrap())
            );
        }
    }

    #[test]
    fn test_public_decrypt_trusted_validation_context() {
        let mut rng = AesRng::seed_from_u64(0);
        let (vk0, _sk0) = gen_sig_keys(&mut rng);
        let (vk1, _sk1) = gen_sig_keys(&mut rng);
        let server_pks = HashMap::from([(1, vk0.clone()), (2, vk1.clone())]);

        PublicDecTrustedValidationContext::new(&server_pks, None, &[], None, None).unwrap();

        // Error if the server_pks has duplicate keys
        let server_pks = HashMap::from([(1, vk1.clone()), (2, vk1)]);
        assert!(
            PublicDecTrustedValidationContext::new(&server_pks, None, &[], None, None).is_err()
        );
    }

    #[test]
    fn test_max_num_bits_verification() {
        // max_num_bits should be at most 2048
        assert!(verify_max_num_bits(2048).is_ok());
        assert!(verify_max_num_bits(1024).is_ok());
        assert!(verify_max_num_bits(1).is_ok());
        assert!(verify_max_num_bits(0).is_err());
        assert!(verify_max_num_bits(2049).is_err());
        assert!(verify_max_num_bits(123).is_err());
    }
}
