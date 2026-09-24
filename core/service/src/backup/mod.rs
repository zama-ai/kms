use crate::cryptography::encryption::{PkeSchemeType, UnifiedCipher};
use hashing::DomainSep;
use kms_grpc::rpc_types::PrivDataType;
use serde::{Deserialize, Serialize};
use tfhe_versionable::{Versionize, VersionsDispatch};
pub mod custodian;
pub mod error;
pub mod operator;
pub mod secretsharing;
pub mod seed_phrase;
use crate::cryptography::signcryption::UnifiedSigncryption;
use kms_grpc::RequestId;
use kms_grpc::kms::v1::OperatorBackupOutput;
use tfhe::named::Named;

#[cfg(test)]
mod tests;

pub const KMS_CUSTODIAN: &str = "kms-custodian";
pub const SEED_PHRASE_DESC: &str = "The SECRET seed phrase for the custodian keys is: ";
pub const SETUP_MESSAGE_DESC: &str = "The custodian setup message is: ";
pub const RECOVERY_OUTPUT_DESC: &str = "The custodian recovery output is: ";

/// Public-key encryption scheme for every key in the custodian-backup chain: the custodian's
/// long-term key, the operator's ephemeral recovery key, and the operator's per-context backup
/// vault key.
///
/// Backup material stays confidential for the lifetime of a deployment, so it is worth hedging the
/// lattice assumption: this is the composite of ML-KEM-1024 and P-384 rather than the ML-KEM-512
/// that user decryption uses for its short-lived responses.
pub const BACKUP_PKE_SCHEME: PkeSchemeType = PkeSchemeType::MlKem1024P384;

/// Domain separator for the digest of the operator's backup encryption key that
/// `GetOperatorPublicKey` places in its attestation document.
///
/// A digest rather than the key itself, because the composite key does not fit in the attestation
/// document's `public_key` field. Shared with `kms-core-client`, which recomputes it to check the
/// response against the attestation.
pub const DSEP_ATTESTED_BACKUP_PK: DomainSep = *b"ATTESTPK";

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, VersionsDispatch)]
pub enum BackupCiphertextVersions {
    V0(BackupCiphertext),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(BackupCiphertextVersions)]
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
        // TODO stop gap https://github.com/zama-ai/kms-internal/issues/3168
        let pke_type = value.pke_type.try_into()?;
        Ok(UnifiedSigncryption::new(value.signcryption, pke_type))
    }
}

impl TryFrom<&OperatorBackupOutput> for UnifiedSigncryption {
    type Error = anyhow::Error;

    fn try_from(value: &OperatorBackupOutput) -> Result<Self, Self::Error> {
        let pke_type = value.pke_type.try_into()?;
        Ok(UnifiedSigncryption::new(
            value.signcryption.clone(),
            pke_type,
        ))
    }
}
