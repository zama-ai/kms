use std::collections::HashMap;

use kms_grpc::{
    kms::v1::{Empty, OperatorPublicKey},
    rpc_types::PrivDataType,
    RequestId,
};
use tonic::{Code, Request, Response, Status};

use crate::{
    cryptography::attestation::{SecurityModule, SecurityModuleProxy},
    engine::threshold::{service::ThresholdFheKeys, traits::BackupOperator},
    vault::{
        keychain::KeychainProxy,
        storage::{
            crypto_material::ThresholdCryptoMaterialStorage, read_all_data_versioned,
            store_versioned_at_request_id, Storage,
        },
    },
};

pub struct RealBackupOperator<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
> {
    pub crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
    pub security_module: Option<SecurityModuleProxy>,
}

#[tonic::async_trait]
impl<PubS, PrivS> BackupOperator for RealBackupOperator<PubS, PrivS>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
{
    async fn get_operator_public_key(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<OperatorPublicKey>, Status> {
        match self.crypto_storage.inner.backup_vault {
            Some(ref v) => {
                let v = v.lock().await;
                match v.keychain {
                    Some(KeychainProxy::SecretSharing(ref k)) => {
                        let public_key = k.operator_public_key_bytes();
                        let attestation_document = match &self.security_module {
                            Some(sm) => sm.attest_pk_bytes(public_key.clone()).await.map_err(|e| Status::new(Code::Internal, format!("Could not issue attestation document for operator backup public key: {e}")))?,
                            None => vec![],
                        };
                        Ok(Response::new(OperatorPublicKey {
                            public_key,
                            attestation_document,
                        }))
                    }
                    _ => Err(Status::new(
                        tonic::Code::Unimplemented,
                        "Backup vault does not support operator public key retrieval",
                    )),
                }
            }
            None => Err(Status::new(
                tonic::Code::Unavailable,
                "Backup vault is not configured",
            )),
        }
    }

    async fn custodian_backup_restore(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Empty>, Status> {
        match self.crypto_storage.inner.backup_vault {
            Some(ref backup_vault) => {
                let private_storage = self.crypto_storage.get_private_storage().clone();
                let mut private_storage = private_storage.lock().await;
                let backup_vault = backup_vault.lock().await;
                let key_info_versioned: HashMap<RequestId, ThresholdFheKeys> =
                    read_all_data_versioned(&*backup_vault, &PrivDataType::FheKeyInfo.to_string())
                        .await
                        .map_err(|e| {
                            Status::new(
                                tonic::Code::Internal,
                                format!("Failed to read FHE keys from backup: {e}"),
                            )
                        })?;
                for (request_id, fhe_keys) in key_info_versioned.iter() {
                    store_versioned_at_request_id(&mut (*private_storage), request_id, fhe_keys, &PrivDataType::FheKeyInfo.to_string()).await.map_err(|e| {
                        Status::new(tonic::Code::Internal, format!("Failed to write FHE keys to private storage during backup recovery: {e}"))
                    })?;
                }
                Ok(Response::new(Empty {}))
            }
            None => Err(Status::new(
                tonic::Code::Unavailable,
                "Backup vault is not configured",
            )),
        }
    }
}
