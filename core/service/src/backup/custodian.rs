use std::time::{SystemTime, UNIX_EPOCH};

use kms_grpc::RequestId;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use tfhe::{named::Named, Versionize};
use tfhe_versionable::VersionsDispatch;
use threshold_fhe::{execution::runtime::party::Role, hashing::DomainSep};

use crate::{
    backup::seed_phrase,
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::{
        backup_pke::{BackupPrivateKey, BackupPublicKey},
        internal_crypto_types::{PrivateSigKey, PublicSigKey, Signature},
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
pub(crate) const DSEP_BACKUP_SETUP: DomainSep = *b"BKUPSETU";

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum InnerCustodianSetupMessageVersioned {
    V0(InnerCustodianSetupMessage),
}

/// This is the message that is signed by the custodian during setup.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(InnerCustodianSetupMessageVersioned)]
pub struct InnerCustodianSetupMessage {
    pub header: String,
    pub custodian_role: Role,
    pub random_value: [u8; 32],
    pub timestamp: u64,
    pub public_key: BackupPublicKey,
}

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
pub enum CustodianSetupMessageVersioned {
    V0(CustodianSetupMessage),
}

/// This is the setup message sent from the custodian to the operator.
///
/// The operators need to persist these messages in their storage
/// so that they can run the backup procedure when needed.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CustodianSetupMessageVersioned)]
pub struct CustodianSetupMessage {
    pub msg: InnerCustodianSetupMessage,
    /// The signature is on the bincode serialized [msg].
    pub signature: Vec<u8>,
    pub verification_key: PublicSigKey,
}

impl Named for CustodianSetupMessage {
    const NAME: &'static str = "backup::CustodianSetupMessage";
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

    pub fn from_seed_phrase(role: Role, seed_phrase: &str) -> Result<Self, BackupError>
    where
        S: From<PrivateSigKey>,
        D: From<BackupPrivateKey>,
    {
        let custodian_keys = seed_phrase::generate_keys_from_seed_phrase(seed_phrase)
            .map_err(|e| BackupError::SetupError(e.to_string()))?;
        Self::new(
            role,
            S::from(custodian_keys.sig_key),
            custodian_keys.verf_key,
            D::from(custodian_keys.nested_dec_key),
            custodian_keys.nested_enc_key,
        )
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

        // recovered share
        let s_i_j = self.decryptor.decrypt(&backup.ciphertext)?;

        // check the decrypted result
        let backup_material: BackupMaterial = tfhe::safe_serialization::safe_deserialize(
            std::io::Cursor::new(&s_i_j),
            SAFE_SER_SIZE_LIMIT,
        )
        .map_err(BackupError::SafeDeserializationError)?;

        if !backup_material.matches_expected_metadata(
            backup_id,
            &self.verification_key,
            self.role,
            operator_verification_key,
            operator_role,
        ) {
            return Err(BackupError::CustodianRecoveryError);
        }

        // re-encrypted share and sign it
        let st_i_j = operator_pk.encrypt(rng, &s_i_j)?;
        let sigt_i_j = self.signer.sign(&DSEP_BACKUP_CUSTODIAN, &st_i_j)?;

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
    ) -> Result<CustodianSetupMessage, BackupError> {
        let mut random_value = [0u8; 32];
        rng.fill_bytes(&mut random_value);
        let msg = InnerCustodianSetupMessage {
            header: HEADER.to_string(),
            custodian_role: self.role,
            random_value,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            public_key: self.nested_pk.clone(),
        };

        let msg_buf = bc2wrap::serialize(&msg)?;
        let signature = self.signer.sign(&DSEP_BACKUP_SETUP, &msg_buf)?;

        Ok(CustodianSetupMessage {
            msg,
            signature,
            verification_key: self.verification_key().clone(),
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
