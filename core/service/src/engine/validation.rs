use alloy_dyn_abi::Eip712Domain;
use alloy_primitives::{Address, B256};
use alloy_sol_types::SolStruct;
use anyhow::Context;
use kms_grpc::{
    kms::v1::{DecryptionRequest, ReencryptionRequest, RequestId, TypedCiphertext},
    rpc_types::{protobuf_to_alloy_domain_option, Reencrypt},
};
use tonic::Status;

use crate::{
    anyhow_error_and_log, anyhow_error_and_warn_log,
    cryptography::internal_crypto_types::{PublicEncKey, Signature},
    engine::base::BaseKmsStruct,
    engine::check_normalized,
    engine::traits::BaseKms,
    tonic_handle_potential_err, tonic_some_or_err, tonic_some_ref_or_err,
};

// TODO: we should organize our code so that we can unit test our error messages
pub(crate) const ERR_CLIENT_ADDR_EQ_CONTRACT_ADDR: &str =
    "client address is the same as verifying contract address";

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

    match verify_reencryption_eip712(req) {
        Ok(()) => {
            tracing::debug!("🔒 Signature verified successfully");
        }
        Err(e) => {
            return Err(anyhow_error_and_log(format!(
                "Signature verification failed with error {e} for request: {req:?}"
            )));
        }
    }

    let link = req.compute_link_checked()?;
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
///
/// Fist we need to extract the client public key from the signature.
/// Then the public key is converted into an address and we check
/// whether the address matches the address in the request.
/// We assume the `domain` is trusted since tkms core does not run a light client.
pub(crate) fn verify_reencryption_eip712(request: &ReencryptionRequest) -> anyhow::Result<()> {
    let payload = request
        .payload
        .as_ref()
        .context("Failed to get payload from ReencryptionRequest")?;
    let signature_bytes = &request.signature;

    // print out the req.signature in hex string
    tracing::debug!("🔒 req.signature: {:?}", hex::encode(signature_bytes));

    let client_address =
        alloy_primitives::Address::parse_checksummed(&payload.client_address, None)?;

    // print out the client address
    // note that the alloy address should format to hex already
    tracing::debug!("🔒 client address in payload: {:?}", client_address);

    let enc_key_bytes = payload.enc_key.clone();
    // print out the hex string of the enc_key_bytes
    tracing::debug!("🔒 enc_key_bytes: {:?}", hex::encode(&enc_key_bytes));

    let message = Reencrypt {
        publicKey: alloy_primitives::Bytes::copy_from_slice(&payload.enc_key),
    };

    let wrapped_domain = request
        .domain
        .as_ref()
        .context("Failed to get domain message from request")?;
    tracing::debug!("🔒 wrapped_domain: {:?}", wrapped_domain);

    let chain_id = alloy_primitives::U256::try_from_be_slice(&wrapped_domain.chain_id)
        .context("invalid chain ID")?;
    tracing::debug!("🔒 chain_id: {:?}", chain_id);
    let verifying_contract_address = alloy_primitives::Address::parse_checksummed(
        wrapped_domain.verifying_contract.as_str(),
        None,
    )
    .context("Failed to convert wrappted domain message into address")?;

    let domain = alloy_sol_types::Eip712Domain::new(
        Some(wrapped_domain.name.clone().into()),
        Some(wrapped_domain.version.clone().into()),
        Some(chain_id),
        Some(verifying_contract_address),
        wrapped_domain
            .salt
            .as_ref()
            .map(|inner_salt| B256::from_slice(inner_salt)),
    );

    // this is to prevent malicious dapp
    if client_address == verifying_contract_address {
        return Err(anyhow_error_and_log(ERR_CLIENT_ADDR_EQ_CONTRACT_ADDR));
    }

    // Derive the EIP-712 signing hash.
    let message_hash = message.eip712_signing_hash(&domain);

    // We need to use the alloy signature type since
    // it will let us call `recover_address_from_prehash` later
    // but this signature cannot be wrapper into our own `Signature`
    // type since our own type uses k256::ecdsa, which is not the same
    // as the one in alloy.
    let alloy_signature =
        alloy_primitives::PrimitiveSignature::try_from(signature_bytes.as_slice())
            .inspect_err(|e| tracing::error!("Failed to parse alloy signature with error: {e}"))?;

    check_normalized(&Signature {
        sig: alloy_signature.to_k256()?,
    })?;

    let recovered_address = alloy_signature.recover_address_from_prehash(&message_hash)?;
    tracing::debug!("🔒 Recovered address: {:?}", recovered_address);

    // Note that `recover_from_prehash` also verifies the signature
    let recovered_verifying_key = alloy_signature.recover_from_prehash(&message_hash)?;
    tracing::debug!("🔒 Recovered verifying key: {:?}", recovered_verifying_key);
    let client_address_from_key =
        alloy_primitives::Address::from_public_key(&recovered_verifying_key);

    let consistent_public_key = client_address_from_key == client_address;
    if !consistent_public_key {
        return Err(anyhow::anyhow!("address is not consistent"));
    }
    Ok(())
}
