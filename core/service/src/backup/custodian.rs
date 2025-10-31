use crate::backup::operator::DSEP_BACKUP_RECOVERY;
use crate::cryptography::{
    encryption::{UnifiedPrivateEncKey, UnifiedPublicEncKey},
    signatures::PrivateSigKey,
    signcryption::{
        Signcrypt, UnifiedSigncryption, UnifiedSigncryptionKey, UnifiedUnsigncryptionKey,
        Unsigncrypt,
    },
};
use crate::engine::validation::{parse_optional_proto_request_id, RequestIdParsingErr};
use crate::{consts::SAFE_SER_SIZE_LIMIT, cryptography::signatures::PublicSigKey};
use kms_grpc::kms::v1::{
    CustodianContext, CustodianRecoveryOutput, CustodianSetupMessage, OperatorBackupOutput,
};
use kms_grpc::RequestId;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tfhe::safe_serialization::safe_serialize;
use tfhe::{named::Named, safe_serialization::safe_deserialize, Versionize};
use tfhe_versionable::VersionsDispatch;
use threshold_fhe::{execution::runtime::party::Role, hashing::DomainSep};

use super::{
    error::BackupError,
    operator::{BackupMaterial, InnerOperatorBackupOutput},
};

pub(crate) const HEADER: &str = "ZAMA TKMS SETUP TEST OPERATORS-CUSTODIAN";
pub(crate) const DSEP_BACKUP_CUSTODIAN: DomainSep = *b"BKUPCUST";

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum InternalCustodianRecoveryOutputVersioned {
    V0(InternalCustodianRecoveryOutput),
}

/// This is the message that a custodian sends to an operator after starting recovery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(InternalCustodianRecoveryOutputVersioned)]
pub struct InternalCustodianRecoveryOutput {
    pub signcryption: UnifiedSigncryption,
    pub custodian_role: Role,
    pub operator_role: Role,
}

impl Named for InternalCustodianRecoveryOutput {
    const NAME: &'static str = "backup::CustodianRecoveryOutput";
}

impl TryFrom<CustodianRecoveryOutput> for InternalCustodianRecoveryOutput {
    type Error = anyhow::Error;

    fn try_from(value: CustodianRecoveryOutput) -> Result<Self, Self::Error> {
        if value.custodian_role == 0 {
            return Err(anyhow::anyhow!(
                "Invalid custodian role in CustodianRecoveryOutput"
            ));
        }
        if value.operator_role == 0 {
            return Err(anyhow::anyhow!(
                "Invalid operator role in CustodianRecoveryOutput"
            ));
        }
        let backup_output = &value.backup_output.ok_or_else(|| {
            anyhow::anyhow!("backup output not part of the custodian recovery output")
        })?;
        Ok(InternalCustodianRecoveryOutput {
            signcryption: UnifiedSigncryption::new(
                backup_output.signcryption.clone(),
                backup_output.encryption_type().into(),
                backup_output.signing_type().into(),
            ),
            custodian_role: Role::indexed_from_one(value.custodian_role as usize),
            operator_role: Role::indexed_from_one(value.operator_role as usize),
        })
    }
}

impl TryFrom<InternalCustodianRecoveryOutput> for CustodianRecoveryOutput {
    type Error = anyhow::Error;

    fn try_from(value: InternalCustodianRecoveryOutput) -> Result<Self, Self::Error> {
        Ok(CustodianRecoveryOutput {
            backup_output: Some(OperatorBackupOutput {
                signcryption: value.signcryption.payload,
                encryption_type: value.signcryption.encryption_type as i32,
                signing_type: value.signcryption.signing_type as i32,
            }),
            custodian_role: value.custodian_role.one_based() as u64,
            operator_role: value.operator_role.one_based() as u64,
        })
    }
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum CustodianSetupMessagePayloadVersioned {
    V0(CustodianSetupMessagePayload),
}

/// This is payload in the setup message that the custodian sends to the operators.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CustodianSetupMessagePayloadVersioned)]
pub struct CustodianSetupMessagePayload {
    pub header: String,
    pub random_value: [u8; 32],
    pub timestamp: u64,
    pub public_enc_key: UnifiedPublicEncKey,
    pub verification_key: PublicSigKey,
}

impl Named for CustodianSetupMessagePayload {
    const NAME: &'static str = "backup::CustodianSetupMessagePayload";
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum InternalCustodianSetupMessageVersioned {
    V0(InternalCustodianSetupMessage),
}

/// This is the internal representation of the custodian setup message.
/// More specifically the content of this is serialized into [`CustodianSetupMessagePayload`]
/// which part of the protobuf [`CustodianSetupMessage`] sent to the operators.
///
/// The operators need to persist this message in their storage
/// so that they can run the backup procedure when needed.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(InternalCustodianSetupMessageVersioned)]
pub struct InternalCustodianSetupMessage {
    pub header: String,
    pub custodian_role: Role,
    pub name: String, // This is the human readable name of the custodian
    pub random_value: [u8; 32],
    pub timestamp: u64,
    pub public_enc_key: UnifiedPublicEncKey, // The public encrypt key of the custodian
    pub public_verf_key: PublicSigKey,       // The custodian's verification key
}

impl Named for InternalCustodianSetupMessage {
    const NAME: &'static str = "backup::InternalCustodianSetupMessage";
}

impl TryFrom<CustodianSetupMessage> for InternalCustodianSetupMessage {
    type Error = anyhow::Error;

    fn try_from(value: CustodianSetupMessage) -> Result<Self, Self::Error> {
        // Deserialize the payload
        let mut buf = std::io::Cursor::new(value.payload);
        let payload: CustodianSetupMessagePayload =
            safe_deserialize(&mut buf, SAFE_SER_SIZE_LIMIT).map_err(|e| anyhow::anyhow!(e))?;
        Ok(InternalCustodianSetupMessage {
            header: payload.header,
            name: value.name,
            custodian_role: Role::indexed_from_one(value.custodian_role as usize),
            random_value: payload.random_value,
            timestamp: payload.timestamp,
            public_enc_key: payload.public_enc_key,
            public_verf_key: payload.verification_key,
        })
    }
}

impl TryFrom<InternalCustodianSetupMessage> for CustodianSetupMessage {
    type Error = anyhow::Error;

    fn try_from(value: InternalCustodianSetupMessage) -> Result<Self, Self::Error> {
        let payload = CustodianSetupMessagePayload {
            header: value.header,
            random_value: value.random_value,
            timestamp: value.timestamp,
            public_enc_key: value.public_enc_key.clone(),
            verification_key: value.public_verf_key.clone(),
        };
        let mut serialized_payload = Vec::new();
        safe_serialize(&payload, &mut serialized_payload, SAFE_SER_SIZE_LIMIT)?;
        Ok(CustodianSetupMessage {
            custodian_role: value.custodian_role.one_based() as u64,
            name: value.name,
            payload: serialized_payload,
        })
    }
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum InternalCustodianContextVersioned {
    V0(InternalCustodianContext),
}

/// This is the internal representation of the custodian context.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(InternalCustodianContextVersioned)]
pub struct InternalCustodianContext {
    pub threshold: u32,
    pub context_id: RequestId,
    pub previous_context_id: Option<RequestId>,
    pub custodian_nodes: BTreeMap<Role, InternalCustodianSetupMessage>,
    pub backup_enc_key: UnifiedPublicEncKey,
}

impl Named for InternalCustodianContext {
    const NAME: &'static str = "backup::CustodianContext";
}

impl InternalCustodianContext {
    pub fn new(
        custodian_context: CustodianContext,
        backup_enc_key: UnifiedPublicEncKey,
    ) -> anyhow::Result<Self> {
        if custodian_context.threshold == 0
            || 2 * custodian_context.threshold as usize >= custodian_context.custodian_nodes.len()
        {
            return Err(anyhow::anyhow!(
                "Invalid threshold in custodian context: threshold is {}, but there are {} custodian nodes",
                custodian_context.threshold,
                custodian_context.custodian_nodes.len()
            ));
        }
        let mut node_map = BTreeMap::new();
        for setup_message in custodian_context.custodian_nodes.iter() {
            let internal_msg: InternalCustodianSetupMessage =
                setup_message.to_owned().try_into()?;
            if setup_message.custodian_role == 0 {
                return Err(anyhow::anyhow!(
                    "Custodian role cannot be zero in custodian context"
                ));
            }
            if setup_message.custodian_role > custodian_context.custodian_nodes.len() as u64 {
                return Err(anyhow::anyhow!(
                        "Custodian role {} is greater than the number of custodians in custodian context", setup_message.custodian_role
                    ));
            }
            let old_msg = node_map.insert(
                Role::indexed_from_one(setup_message.custodian_role as usize),
                internal_msg,
            );
            if old_msg.is_some() {
                return Err(anyhow::anyhow!(
                    "Duplicate custodian role found in custodian context"
                ));
            }
        }
        let context_id: RequestId = parse_optional_proto_request_id(
            &custodian_context.context_id,
            RequestIdParsingErr::CustodianContext,
        )?;
        let prev_context_id = custodian_context
            .previous_context_id
            .as_ref()
            .map(|id| id.clone().try_into())
            .transpose()?;
        Ok(InternalCustodianContext {
            context_id,
            threshold: custodian_context.threshold,
            previous_context_id: prev_context_id,
            custodian_nodes: node_map,
            backup_enc_key,
        })
    }
}

pub struct Custodian {
    role: Role,
    signing_key: PrivateSigKey,
    enc_key: UnifiedPublicEncKey,
    dec_key: UnifiedPrivateEncKey,
}

/// The custodian is the entity can sign and decrypt messages,
/// which are usually secret shares that are needed for recovery.
/// Since the secrets should be kept safe for a long time, the
/// public key encryption scheme should be post quantum.
///
/// The signing key is stored on AWS KMS
///
/// For decryption, there are two keys, the RSA OAEP decryption
/// is stored on AWS KMS, the ML-KEM decryption key is stored on
/// AWS Secret Manager because post quantum algorithms are not
/// supported on AWS KMS at the moment.
impl Custodian {
    pub fn new(
        role: Role,
        signing_key: PrivateSigKey,
        enc_key: UnifiedPublicEncKey,
        dec_key: UnifiedPrivateEncKey,
    ) -> Result<Self, BackupError> {
        Ok(Self {
            role,
            signing_key,
            enc_key,
            dec_key,
        })
    }

    // We allow the following lints because we are fine with mutating the rng even if
    // we end up returning an error when signing the encrypted share.
    #[allow(unknown_lints)]
    #[allow(non_local_effect_before_error_return)]
    /// Obtain the operator ephemeral public key for reencryption,
    /// unsigncrypt the signcryption encrypted under the custodian's public key
    /// and then signcrypt it it under the operator's public key
    pub fn verify_reencrypt<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        backup: &InnerOperatorBackupOutput,
        operator_verification_key: &PublicSigKey,
        operator_ephem_enc_key: &UnifiedPublicEncKey,
        backup_id: RequestId,
        operator_role: Role,
    ) -> Result<InternalCustodianRecoveryOutput, BackupError> {
        tracing::debug!(
            "Verifying and re-encrypting backup for operator: {}",
            operator_role
        );
        let custodian_id = self.verification_key().verf_key_id();
        let unsigncrypt_key = UnifiedUnsigncryptionKey::new(
            &self.dec_key,
            &self.enc_key,
            operator_verification_key,
            &custodian_id,
        );
        let backup_material: BackupMaterial = unsigncrypt_key
            .unsigncrypt(&DSEP_BACKUP_CUSTODIAN, &backup.signcryption)
            .map_err(|e| {
                tracing::warn!(
                    "Unsigncryption failed for backup {backup_id} for operator {operator_role}: {e}"
                );
                BackupError::CustodianRecoveryError
            })?;
        tracing::debug!("Decrypted ciphertext for operator: {}", operator_role);
        // check the decrypted result
        if !backup_material.matches_expected_metadata(
            backup_id,
            &self.signing_key.verf_key(),
            self.role,
            &operator_verification_key.verf_key_id(),
            operator_role,
        ) {
            tracing::error!(
                "Backup material did not match expected metadata for operator: {}",
                operator_role
            );
            return Err(BackupError::CustodianRecoveryError);
        }

        // re-encrypted share and sign it
        let operator_verf_id = operator_verification_key.verf_key_id();
        let signcrypt_key = UnifiedSigncryptionKey::new(
            &self.signing_key,
            operator_ephem_enc_key,
            &operator_verf_id,
        );
        let signcryption = signcrypt_key.signcrypt(rng, &DSEP_BACKUP_RECOVERY, &backup_material)?;
        tracing::debug!("Signed re-encrypted share for operator: {}", operator_role);
        Ok(InternalCustodianRecoveryOutput {
            signcryption,
            custodian_role: self.role,
            operator_role,
        })
    }

    // We allow the following lints because we are fine with mutating the rng even if
    // we end up returning an error when signing the encrypted share.
    #[allow(unknown_lints)]
    #[allow(non_local_effect_before_error_return)]
    pub fn generate_setup_message<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        custodian_name: String, // This is the human readable name of the custodian to be used in the setup message
    ) -> Result<InternalCustodianSetupMessage, BackupError> {
        let mut random_value = [0u8; 32];
        rng.fill_bytes(&mut random_value);

        Ok(InternalCustodianSetupMessage {
            header: HEADER.to_string(),
            custodian_role: self.role,
            random_value,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            public_enc_key: self.enc_key.clone(),
            public_verf_key: self.verification_key().clone(),
            name: custodian_name,
        })
    }

    pub fn public_dec_key(&self) -> &UnifiedPrivateEncKey {
        &self.dec_key
    }

    pub fn public_enc_key(&self) -> &UnifiedPublicEncKey {
        &self.enc_key
    }

    pub fn verification_key(&self) -> PublicSigKey {
        self.signing_key.verf_key()
    }

    pub fn role(&self) -> Role {
        self.role
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::encryption::{Encryption, EncryptionScheme, EncryptionSchemeType};
    use aes_prng::AesRng;
    use rand::SeedableRng;

    #[test]
    fn internal_custodian_context_zero_role_should_fail() {
        let mut rng = AesRng::seed_from_u64(40);
        let mut enc = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
        let (_, backup_pk) = enc.keygen().unwrap();
        let setup_msg = CustodianSetupMessage {
            custodian_role: 0, // Invalid role
            name: "Custodian-1".to_string(),
            payload: vec![],
        };
        let context = CustodianContext {
            custodian_nodes: vec![setup_msg],
            context_id: None,
            previous_context_id: None,
            threshold: 1,
        };
        let result = InternalCustodianContext::new(context, backup_pk.clone());
        assert!(result.is_err());
    }

    #[test]
    fn invalid_threshold_should_fail() {
        let mut rng = AesRng::seed_from_u64(40);
        let mut enc = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
        let (_, backup_pk) = enc.keygen().unwrap();
        let setup_msg1 = CustodianSetupMessage {
            custodian_role: 1,
            name: "Custodian-1".to_string(),
            payload: vec![],
        };
        let setup_msg2 = CustodianSetupMessage {
            custodian_role: 2,
            name: "Custodian-2".to_string(),
            payload: vec![],
        };
        let context = CustodianContext {
            custodian_nodes: vec![setup_msg1, setup_msg2],
            context_id: None,
            previous_context_id: None,
            threshold: 1, // Invalid threshold, since 1 is not less than 2/2
        };
        let result = InternalCustodianContext::new(context, backup_pk.clone());
        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("Invalid threshold in custodian context"));
    }

    #[test]
    fn internal_custodian_context_duplicate_role_should_fail() {
        let mut rng = AesRng::seed_from_u64(40);
        let mut enc = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
        let (_, backup_pk) = enc.keygen().unwrap();
        let payload = vec![];
        let setup_msg1 = CustodianSetupMessage {
            custodian_role: 1,
            name: "Custodian-1".to_string(),
            payload: payload.clone(),
        };
        let setup_msg2 = CustodianSetupMessage {
            custodian_role: 1, // Duplicate role
            name: "Custodian-2".to_string(),
            payload,
        };
        let context = CustodianContext {
            custodian_nodes: vec![setup_msg1, setup_msg2],
            context_id: None,
            previous_context_id: None,
            threshold: 2,
        };
        let result = InternalCustodianContext::new(context, backup_pk.clone());
        assert!(result.is_err());
    }

    #[test]
    fn internal_custodian_context_role_greater_than_nodes_should_fail() {
        let mut rng = AesRng::seed_from_u64(40);
        let mut enc = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
        let (_, backup_pk) = enc.keygen().unwrap();
        let setup_msg = CustodianSetupMessage {
            custodian_role: 5, // Greater than number of nodes
            name: "Custodian-1".to_string(),
            payload: vec![],
        };
        let context = CustodianContext {
            custodian_nodes: vec![setup_msg],
            context_id: None,
            previous_context_id: None,
            threshold: 1,
        };
        let result = InternalCustodianContext::new(context, backup_pk.clone());
        assert!(result.is_err());
    }
}
