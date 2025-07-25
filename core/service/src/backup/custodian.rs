use kms_grpc::kms::v1::CustodianSetupMessage;
use kms_grpc::RequestId;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tfhe::{named::Named, safe_serialization::safe_deserialize, Versionize};
use tfhe_versionable::VersionsDispatch;
use threshold_fhe::{execution::runtime::party::Role, hashing::DomainSep};

use crate::{
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::{
        backup_pke::BackupPublicKey,
        internal_crypto_types::{PublicSigKey, Signature},
        signcryption::internal_verify_sig,
    },
};

use super::{
    error::BackupError,
    operator::{BackupMaterial, OperatorBackupOutput, DSEP_BACKUP_OPERATOR},
    traits::{BackupDecryptor, BackupSigner},
};

pub(crate) const HEADER: &str = "ZAMA TKMS SETUP TEST OPERATORS-CUSTODIAN";
pub(crate) const DSEP_BACKUP_CUSTODIAN: DomainSep = *b"BKUPCUST";

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum CustodianRecoveryOutputVersioned {
    V0(CustodianRecoveryOutput),
}

/// This is the message that custodian sends to the operators
/// near the end of the recovery step.
#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CustodianRecoveryOutputVersioned)]
pub struct CustodianRecoveryOutput {
    pub signature: Vec<u8>,  // sigt_i_j
    pub ciphertext: Vec<u8>, // st_i_j
}

impl Named for CustodianRecoveryOutput {
    const NAME: &'static str = "backup::CustodianRecoveryOutput";
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
    pub public_enc_key: BackupPublicKey,
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
    pub public_enc_key: BackupPublicKey,
    pub public_verf_key: PublicSigKey,
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

pub struct Custodian<S: BackupSigner, D: BackupDecryptor> {
    role: Role,
    decryptor: D,
    nested_pk: BackupPublicKey,
    signer: S,
    verification_key: PublicSigKey,
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
impl<S: BackupSigner, D: BackupDecryptor> Custodian<S, D> {
    pub fn new(
        role: Role,
        signer: S,
        verification_key: PublicSigKey,
        decryptor: D,
        nested_pk: BackupPublicKey,
    ) -> Result<Self, BackupError> {
        Ok(Self {
            role,
            decryptor,
            nested_pk,
            signer,
            verification_key,
        })
    }

    // We allow the following lints because we are fine with mutating the rng even if
    // we end up returning an error when signing the encrypted share.
    #[allow(unknown_lints)]
    #[allow(non_local_effect_before_error_return)]
    /// Obtain the operator public key for reencryption,
    /// decrypt the given ciphertext encrypted under the custodian's public key
    /// and then encrypt it under the operator's public key
    /// finally sign the ciphertext under the custodian's signing key.
    /// - `ciphertext`: ct_{i, j}, for i-th operator and j-th custodian
    /// - `operator_pk`: pk^{D_i}, for i-th operator
    pub fn verify_reencrypt<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        backup: &OperatorBackupOutput,
        operator_verification_key: &PublicSigKey,
        operator_pk: &BackupPublicKey,
        backup_id: RequestId,
        operator_role: Role,
    ) -> Result<CustodianRecoveryOutput, BackupError> {
        tracing::debug!(
            "Verifying and re-encrypting backup for operator: {}",
            operator_role
        );
        // check the signature
        let signature = Signature {
            sig: k256::ecdsa::Signature::from_slice(&backup.signature)?,
        };
        internal_verify_sig(
            &DSEP_BACKUP_OPERATOR,
            &backup.ciphertext,
            &signature,
            operator_verification_key,
        )
        .map_err(|e| BackupError::SignatureVerificationError(e.to_string()))?;
        tracing::debug!("Signature verified for operator: {}", operator_role);
        // recovered share
        let s_i_j = self.decryptor.decrypt(&backup.ciphertext)?;
        tracing::debug!("Decrypted ciphertext for operator: {}", operator_role);
        // check the decrypted result
        let backup_material: BackupMaterial = tfhe::safe_serialization::safe_deserialize(
            std::io::Cursor::new(&s_i_j),
            SAFE_SER_SIZE_LIMIT,
        )
        .map_err(BackupError::SafeDeserializationError)?;
        tracing::debug!(
            "Deserialized backup material for operator: {}",
            operator_role
        );
        if !backup_material.matches_expected_metadata(
            backup_id,
            &self.verification_key,
            self.role,
            operator_verification_key,
            operator_role,
        ) {
            tracing::error!(
                "Backup material did not match expected metadate for operator: {}",
                operator_role
            );
            return Err(BackupError::CustodianRecoveryError);
        }

        // re-encrypted share and sign it
        let st_i_j = operator_pk.encrypt(rng, &s_i_j)?;
        let sigt_i_j = self.signer.sign(&DSEP_BACKUP_CUSTODIAN, &st_i_j)?;
        tracing::debug!("Signed re-encrypted share for operator: {}", operator_role);
        Ok(CustodianRecoveryOutput {
            signature: sigt_i_j,
            ciphertext: st_i_j,
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
            public_enc_key: self.nested_pk.clone(),
            public_verf_key: self.verification_key().clone(),
            name: custodian_name,
        })
    }

    pub fn public_key(&self) -> &BackupPublicKey {
        &self.nested_pk
    }

    pub fn verification_key(&self) -> &PublicSigKey {
        &self.verification_key
    }

    pub fn role(&self) -> Role {
        self.role
    }
}
