use super::{EnvelopeLoad, EnvelopeStore, Keychain};
use crate::{
    anyhow_error_and_log,
    backup::{custodian::CustodianSetupMessage, operator::Operator},
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::{
        backup_pke::{self, BackupPrivateKey},
        internal_crypto_types::{PrivateSigKey, PublicSigKey},
    },
};
use k256::ecdsa::SigningKey;
use kms_grpc::RequestId;
use rand::rngs::OsRng;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::BTreeSet;
use tfhe::{
    named::Named,
    safe_serialization::{safe_deserialize, safe_serialize},
    Unversionize, Versionize,
};
use threshold_fhe::execution::runtime::party::Role;

pub struct SecretShareKeychain {
    operator: Operator<PrivateSigKey, BackupPrivateKey>,
    num_shares: usize,
}

impl SecretShareKeychain {
    pub fn new(
        custodian_messages: Vec<CustodianSetupMessage>,
        my_role: Role,
        signer: PrivateSigKey,
        threshold: usize,
    ) -> anyhow::Result<Self> {
        let (decryptor, public_key) = backup_pke::keygen(&mut OsRng).unwrap();
        let verification_key = PublicSigKey::new(*SigningKey::verifying_key(signer.sk()));
        let num_shares = custodian_messages.len();
        let operator = Operator::new(
            my_role,
            custodian_messages,
            signer,
            verification_key,
            decryptor,
            public_key,
            threshold,
        )?;
        Ok(Self {
            operator,
            num_shares,
        })
    }

    pub fn operator_public_key_bytes(&self) -> Vec<u8> {
        self.operator.public_key_bytes()
    }
}

impl Keychain for SecretShareKeychain {
    fn envelope_share_ids(&self) -> Option<BTreeSet<Role>> {
        Some(BTreeSet::from_iter(
            (0..self.num_shares).map(Role::indexed_from_zero),
        ))
    }

    async fn encrypt<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        payload_id: &RequestId,
        payload: &T,
    ) -> anyhow::Result<EnvelopeStore> {
        let mut payload_bytes = Vec::new();
        safe_serialize(payload, &mut payload_bytes, SAFE_SER_SIZE_LIMIT)?;
        self.operator
            .secret_share_and_encrypt(&mut OsRng, &payload_bytes, *payload_id)
            .map(EnvelopeStore::OperatorBackupOutput)
            .map_err(|e| anyhow_error_and_log(format!("Cannot encrypt backup: {e}")))
    }

    async fn decrypt<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        payload_id: &RequestId,
        envelope: &mut EnvelopeLoad,
    ) -> anyhow::Result<T> {
        let EnvelopeLoad::OperatorRecoveryInput(rs, cs) = envelope else {
            anyhow::bail!("Expected multi-share encrypted data")
        };
        let payload_bytes =
            self.operator
                .verify_and_recover(rs.clone(), cs.clone(), *payload_id)?;
        let mut buf = std::io::Cursor::new(&payload_bytes);
        safe_deserialize(&mut buf, SAFE_SER_SIZE_LIMIT)
            .map_err(|e| anyhow_error_and_log(format!("Cannot decrypt backup: {e}")))
    }
}
