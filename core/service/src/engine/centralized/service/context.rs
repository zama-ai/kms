use kms_grpc::{
    kms::v1::{DestroyKmsContextRequest, Empty, NewKmsContextRequest},
    utils::tonic_result::tonic_handle_potential_err,
};
use tonic::{Request, Response, Status};

use crate::{
    engine::{
        context::ContextInfo,
        validation::{parse_optional_proto_request_id, RequestIdParsingErr},
    },
    vault::storage::{
        crypto_material::CentralizedCryptoMaterialStorage, delete_context_at_request_id, Storage,
    },
};

/// Implementation of the new_kms_context GRPC endpoint.
/// It will verify the new context and store it in the crypto storage.
pub async fn new_kms_context_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
>(
    crypto_storage: &CentralizedCryptoMaterialStorage<PubS, PrivS>,
    request: Request<NewKmsContextRequest>,
) -> Result<Response<Empty>, Status> {
    // first verify that the context is valid
    let NewKmsContextRequest {
        active_context,
        new_context,
    } = request.into_inner();

    let new_context =
        new_context.ok_or_else(|| Status::invalid_argument("new_context is required"))?;
    let new_context = ContextInfo::try_from(new_context)
        .map_err(|e| Status::invalid_argument(format!("Invalid context info: {e}")))?;

    // verify new context
    {
        let storage_ref = crypto_storage.inner.private_storage.clone();
        let guarded_priv_storage = storage_ref.lock().await;
        // my_id is always 1 in the centralized case
        new_context
            .verify(
                1,
                &(*guarded_priv_storage),
                active_context
                    .and_then(|c| ContextInfo::try_from(c).ok())
                    .as_ref(),
            )
            .await
            .map_err(|e| Status::invalid_argument(format!("Failed to verify new context: {e}")))?;
    }

    // store the new context
    let res = crypto_storage
        .inner
        .write_context_info(new_context.context_id(), &new_context, false)
        .await;

    tonic_handle_potential_err(
        res,
        format!(
            "Failed to write new KMS context for ID {}",
            new_context.context_id()
        ),
    )?;

    Ok(Response::new(Empty {}))
}

/// Implementation of the delete_kms_context GRPC endpoint.
pub async fn delete_kms_context_impl<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
>(
    crypto_storage: &CentralizedCryptoMaterialStorage<PubS, PrivS>,
    request: Request<DestroyKmsContextRequest>,
) -> Result<Response<Empty>, Status> {
    let context_id = parse_optional_proto_request_id(
        &request.into_inner().context_id,
        RequestIdParsingErr::Context,
    )?;
    let storage_ref = crypto_storage.inner.private_storage.clone();
    let mut guarded_priv_storage = storage_ref.lock().await;

    delete_context_at_request_id(&mut *guarded_priv_storage, &context_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to delete context: {e}")))?;
    Ok(Response::new(Empty {}))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use kms_grpc::{rpc_types::PrivDataType, RequestId};
    use rand::rngs::OsRng;

    use crate::{
        cryptography::{
            internal_crypto_types::{gen_sig_keys, PublicSigKey},
            signcryption::ephemeral_encryption_key_generation,
        },
        engine::context::{NodeInfo, SoftwareVersion},
        vault::storage::{
            crypto_material::get_core_signing_key, ram::RamStorage, read_context_at_request_id,
            store_versioned_at_request_id,
        },
    };

    use super::*;

    const DUMMY_SIGNING_KEY_REQ_ID: [u8; 32] = [1u8; 32];

    async fn setup_crypto_storage() -> (
        PublicSigKey,
        CentralizedCryptoMaterialStorage<RamStorage, RamStorage>,
    ) {
        let priv_storage = RamStorage::new();
        let pub_storage = RamStorage::new();

        let crypto_storage = CentralizedCryptoMaterialStorage::<_, _>::new(
            priv_storage,
            pub_storage,
            None,
            HashMap::new(),
            HashMap::new(),
        );

        // store private signing key
        let (pk, sk) = gen_sig_keys(&mut OsRng);

        let req_id = RequestId::from_bytes(DUMMY_SIGNING_KEY_REQ_ID);
        {
            let mut guarded_priv_storage = crypto_storage.inner.private_storage.lock().await;
            store_versioned_at_request_id(
                &mut *guarded_priv_storage,
                &req_id,
                &sk,
                &PrivDataType::SigningKey.to_string(),
            )
            .await
            .unwrap();

            // check that the signing key exists
            let _ = get_core_signing_key(&*guarded_priv_storage).await.unwrap();
        }

        (pk, crypto_storage)
    }

    #[tokio::test]
    async fn test_kms_context() {
        let (backup_encryption_public_key, _) = ephemeral_encryption_key_generation(&mut OsRng);
        let (verification_key, crypto_storage) = setup_crypto_storage().await;

        let req_id = RequestId::from_bytes([4u8; 32]);
        let new_context = ContextInfo {
            kms_nodes: vec![NodeInfo {
                name: "Node1".to_string(),
                party_id: 1,
                verification_key: verification_key.clone(),
                backup_encryption_public_key: backup_encryption_public_key.clone(),
                external_url: "localhost:12345".to_string(),
                tls_cert: vec![],
                public_storage_url: "http://storage".to_string(),
                extra_verification_keys: vec![],
            }],
            context_id: req_id,
            previous_context_id: None,
            software_version: SoftwareVersion {
                major: 0,
                minor: 1,
                patch: 0,
                tag: None,
            },
            threshold: 0,
        };

        let request = Request::new(NewKmsContextRequest {
            active_context: None,
            new_context: Some(new_context.try_into().unwrap()),
        });

        let response = new_kms_context_impl(&crypto_storage, request).await;
        response.unwrap();

        // check that the context is stored
        {
            let storage_ref = crypto_storage.inner.private_storage.clone();
            let guarded_priv_storage = storage_ref.lock().await;
            let stored_context = read_context_at_request_id(&*guarded_priv_storage, &req_id)
                .await
                .unwrap();

            assert_eq!(*stored_context.context_id(), req_id);
            assert_eq!(stored_context.kms_nodes.len(), 1);
            assert_eq!(stored_context.kms_nodes[0].party_id, 1);
            assert_eq!(
                stored_context.kms_nodes[0].verification_key,
                verification_key
            );
        }

        // now that it is stored, we try to delete it
        let request = Request::new(DestroyKmsContextRequest {
            context_id: Some(req_id.into()),
        });

        let response = delete_kms_context_impl(&crypto_storage, request).await;
        response.unwrap();

        // check that the context is deleted
        {
            let storage_ref = crypto_storage.inner.private_storage.clone();
            let guarded_priv_storage = storage_ref.lock().await;
            let _ = read_context_at_request_id(&*guarded_priv_storage, &req_id)
                .await
                .unwrap_err();
        }
    }
}
