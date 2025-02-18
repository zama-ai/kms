use alloy_dyn_abi::Eip712Domain;
use alloy_primitives::Address;
use kms_grpc::{
    kms::v1::{DecryptionRequest, ReencryptionRequest, RequestId, TypedCiphertext},
    rpc_types::protobuf_to_alloy_domain_option,
};
use tonic::Status;

use crate::{
    anyhow_error_and_log, anyhow_error_and_warn_log,
    cryptography::internal_crypto_types::PublicEncKey, engine::base::BaseKmsStruct,
    engine::traits::BaseKms, tonic_handle_potential_err, tonic_some_or_err, tonic_some_ref_or_err,
};

/// Validates a request ID and returns an appropriate tonic error if it is invalid.
pub(crate) fn validate_request_id(request_id: &RequestId) -> Result<(), Status> {
    if !request_id.is_valid() {
        tracing::warn!(
            "The value {} is not a valid request ID!",
            request_id.to_string()
        );
        return Err(tonic::Status::new(
            tonic::Code::InvalidArgument,
            format!("The value {} is not a valid request ID!", request_id),
        ));
    }
    Ok(())
}

/// Validates a reencryption request and returns ciphertext, FheType, request digest, client
/// encryption key, client verification key, key_id and request_id if valid.
///
/// Observe that the key handle is NOT checked for existence here.
/// This is instead currently handled in `decrypt`` where the retrival of the secret decryption key
/// is needed.
pub async fn validate_reencrypt_req(
    req: &ReencryptionRequest,
) -> anyhow::Result<(
    Vec<TypedCiphertext>,
    Vec<u8>,
    PublicEncKey,
    alloy_primitives::Address,
    RequestId,
    RequestId,
    alloy_sol_types::Eip712Domain,
)> {
    let payload = tonic_some_ref_or_err(
        req.payload.as_ref(),
        format!("The request {:?} does not have a payload", req),
    )?;
    let request_id = tonic_some_or_err(
        req.request_id.clone(),
        "Request ID is not set (validate reencrypt req)".to_string(),
    )?;
    if !request_id.is_valid() {
        return Err(anyhow_error_and_warn_log(format!(
            "The value {} is not a valid request ID!",
            request_id
        )));
    }

    let client_verf_key =
        alloy_primitives::Address::parse_checksummed(&payload.client_address, None)?;

    let domain = match verify_reencryption_eip712(req) {
        Ok(domain) => {
            tracing::debug!("🔒 Signature verified successfully");
            domain
        }
        Err(e) => {
            return Err(anyhow_error_and_log(format!(
                "Signature verification failed with error {e} for request: {req:?}"
            )));
        }
    };

    let (link, _) = req.compute_link_checked()?;
    let client_enc_key: PublicEncKey = bincode::deserialize(&payload.enc_key)?;
    let key_id = tonic_some_or_err(
        payload.key_id.clone(),
        format!("The request {:?} does not have a key_id", req),
    )?;
    Ok((
        payload.typed_ciphertexts.clone(),
        link,
        client_enc_key,
        client_verf_key,
        key_id,
        request_id,
        domain,
    ))
}

/// Validates a decryption request and unpacks and returns
/// the ciphertext, FheType, digest, key_id and request_id if it is valid.
///
/// Observe that the key handle is NOT checked for existence here.
/// This is instead currently handled in `decrypt`` where the retrival of the secret decryption key
/// is needed.
#[allow(clippy::type_complexity)]
pub(crate) fn validate_decrypt_req(
    req: &DecryptionRequest,
) -> anyhow::Result<(
    Vec<TypedCiphertext>,
    Vec<u8>,
    RequestId,
    RequestId,
    Option<Eip712Domain>,
    Option<Address>,
)> {
    let key_id = tonic_some_or_err(
        req.key_id.clone(),
        format!("The request {:?} does not have a key_id", req),
    )?;
    let serialized_req = tonic_handle_potential_err(
        bincode::serialize(&req),
        format!("Could not serialize payload {:?}", req),
    )?;
    let req_digest = tonic_handle_potential_err(
        BaseKmsStruct::digest(&serialized_req),
        format!("Could not hash payload {:?}", req),
    )?;
    let request_id = tonic_some_or_err(
        req.request_id.clone(),
        "Request ID is not set (validate decrypt req)".to_string(),
    )?;
    if !request_id.is_valid() {
        return Err(anyhow_error_and_warn_log(format!(
            "The value {} is not a valid request ID!",
            request_id
        )));
    }

    let eip712_domain = protobuf_to_alloy_domain_option(req.domain.as_ref());

    let acl_address = if let Some(address) = req.acl_address.as_ref() {
        match Address::parse_checksummed(address, None) {
            Ok(address) => Some(address),
            Err(e) => {
                tracing::warn!(
                    "Could not parse ACL address: {:?}. Error: {:?}. Returning None.",
                    address,
                    e
                );
                None
            }
        }
    } else {
        None
    };

    Ok((
        req.ciphertexts.clone(),
        req_digest,
        key_id,
        request_id,
        eip712_domain,
        acl_address,
    ))
}

/// Verify the EIP-712 encoded payload in the request.
pub(crate) fn verify_reencryption_eip712(
    request: &ReencryptionRequest,
) -> anyhow::Result<alloy_sol_types::Eip712Domain> {
    let (_, domain) = request.compute_link_checked()?;
    Ok(domain)
}
