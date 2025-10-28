use crate::cryptography::encryption::UnifiedCipher;
use kms_grpc::rpc_types::PrivDataType;
use serde::{Deserialize, Serialize};
use tfhe_versionable::{Versionize, VersionsDispatch};
pub mod custodian;
pub mod error;
pub mod operator;
pub mod secretsharing;
pub mod seed_phrase;
use crate::cryptography::signcryption::UnifiedSigncryption;
use kms_grpc::kms::v1::OperatorBackupOutput;
use kms_grpc::RequestId;
use tfhe::named::Named;

#[cfg(test)]
mod tests;

pub const KMS_CUSTODIAN: &str = "kms-custodian";
pub const SEED_PHRASE_DESC: &str = "The SECRET seed phrase for the custodian keys is: ";

#[derive(Debug, Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum BackupCiphertextVersioned {
    V0(BackupCiphertext),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(BackupCiphertextVersioned)]
pub struct BackupCiphertext {
    pub ciphertext: UnifiedCipher,
    pub priv_data_type: PrivDataType,
    pub backup_id: RequestId,
}

impl Named for BackupCiphertext {
    const NAME: &'static str = "cryptography::BackupCiphertext";
}

impl TryFrom<OperatorBackupOutput> for UnifiedSigncryption {
    type Error = anyhow::Error;

    fn try_from(value: OperatorBackupOutput) -> Result<Self, Self::Error> {
        let encryption_type = value.encryption_type().into();
        let signing_type = value.signing_type().into();
        Ok(UnifiedSigncryption::new(
            value.signcryption,
            encryption_type,
            signing_type,
        ))
    }
}

impl TryFrom<&OperatorBackupOutput> for UnifiedSigncryption {
    type Error = anyhow::Error;

    fn try_from(value: &OperatorBackupOutput) -> Result<Self, Self::Error> {
        let encryption_type = value.encryption_type.try_into()?;
        let signing_type = value.signing_type.try_into()?;
        Ok(UnifiedSigncryption::new(
            value.signcryption.clone(),
            encryption_type,
            signing_type,
        ))
    }
}
