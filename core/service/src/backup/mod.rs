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
use crate::cryptography::signatures::SigningSchemeType;
use crate::cryptography::signcryption::{SigncryptionFormat, UnifiedSigncryption};
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

/// The envelope format an [`OperatorBackupOutput`] describes.
pub(crate) fn backup_format_from_wire(signing_type: i32) -> anyhow::Result<SigncryptionFormat> {
    let scheme: SigningSchemeType = signing_type.try_into()?;
    Ok(SigncryptionFormat::for_schemes(&[scheme]))
}

/// The `signing_type` an [`OperatorBackupOutput`] must carry for `format`.
///
/// TODO stop gap: the proto field names a single scheme, so only the frozen
/// ECDSA layout can be described by it. Fail rather than mislabel a
/// multi-signature envelope as a single-scheme one. Removing this needs the
/// proto field to name a layout (or a scheme list) instead.
pub(crate) fn backup_format_to_wire(format: SigncryptionFormat) -> anyhow::Result<i32> {
    match format {
        SigncryptionFormat::EcdsaV0 => Ok(SigningSchemeType::Ecdsa256k1.as_wire()),
        SigncryptionFormat::CompositeV1 => Err(anyhow::anyhow!(
            "cannot represent a {format} signcryption in an OperatorBackupOutput, \
             whose signing_type names a single signing scheme"
        )),
    }
}

impl TryFrom<OperatorBackupOutput> for UnifiedSigncryption {
    type Error = anyhow::Error;

    fn try_from(value: OperatorBackupOutput) -> Result<Self, Self::Error> {
        // As above for `pke_type`: the fallible conversion reports an unknown
        // discriminant instead of silently relabelling it as ML-KEM-512.
        let pke_type = value.pke_type.try_into()?;
        Ok(UnifiedSigncryption::new(
            value.signcryption,
            pke_type,
            backup_format_from_wire(value.signing_type)?,
        ))
    }
}

impl TryFrom<&OperatorBackupOutput> for UnifiedSigncryption {
    type Error = anyhow::Error;

    fn try_from(value: &OperatorBackupOutput) -> Result<Self, Self::Error> {
        let pke_type = value.pke_type.try_into()?;
        Ok(UnifiedSigncryption::new(
            value.signcryption.clone(),
            pke_type,
            backup_format_from_wire(value.signing_type)?,
        ))
    }
}
