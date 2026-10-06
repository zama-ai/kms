use crate::backup::operator::DSEP_BACKUP_MATERIAL;
use crate::backup::{BACKUP_PKE_SCHEME, BACKUP_SIGNING_SCHEMES, ensure_backup_schemes};
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::signatures::{NodeSigningIdentity, VerfKeySet};
use crate::cryptography::{
    encryption::{HasPkeScheme, UnifiedPrivateEncKey, UnifiedPublicEncKey},
    signcryption::{
        Signcrypt, UnifiedSigncryption, UnifiedSigncryptionKey, UnifiedUnsigncryptionKey,
        Unsigncrypt,
    },
};
use crate::engine::validation::{RequestIdParsingErr, parse_optional_grpc_request_id};
use hashing::DomainSep;
use kms_grpc::RequestId;
use kms_grpc::kms::v1::{
    CustodianContext, CustodianRecoveryOutput, CustodianSetupMessage, OperatorBackupOutput,
};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;
use tfhe::safe_serialization::safe_serialize;
use tfhe::{Versionize, named::Named, safe_serialization::safe_deserialize};
use tfhe_versionable::VersionsDispatch;
use threshold_types::role::Role;
use zeroize::Zeroizing;

use super::{
    error::BackupError,
    operator::{BackupMaterial, InnerOperatorBackupOutput},
};

pub(crate) const HEADER: &str = "ZAMA TKMS SETUP TEST OPERATORS-CUSTODIAN";
pub(crate) const DSEP_BACKUP_CUSTODIAN: DomainSep = *b"BKUPCUST";
const ERR_DUPLICATE_CUSTODIAN_ENCRYPTION_KEYS: &str =
    "Duplicate custodian encryption key found in custodian context";
const ERR_DUPLICATE_CUSTODIAN_VERIFICATION_KEYS: &str =
    "Duplicate custodian verification key found in custodian context";
const ERR_WEAK_CUSTODIAN_ENCRYPTION_KEY: &str =
    "Custodian encryption key does not use the backup encryption scheme";
const ERR_WEAK_BACKUP_ENCRYPTION_KEY: &str =
    "Backup encryption key does not use the backup encryption scheme";

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum InternalCustodianRecoveryOutputVersions {
    V0(InternalCustodianRecoveryOutput),
}

/// This is the message that a custodian sends to an operator after starting recovery.
///
/// The payload of the signcryption is a `BackupMaterial` that contains the decrypted backup share for an operator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(InternalCustodianRecoveryOutputVersions)]
pub struct InternalCustodianRecoveryOutput {
    pub signcryption: UnifiedSigncryption,
    pub custodian_role: Role,
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
        let backup_output = &value.backup_output.ok_or_else(|| {
            anyhow::anyhow!("backup output not part of the custodian recovery output")
        })?;
        Ok(InternalCustodianRecoveryOutput {
            signcryption: UnifiedSigncryption::new(
                backup_output.signcryption.clone(),
                backup_output.pke_type.try_into()?,
            ),
            custodian_role: Role::indexed_from_one(value.custodian_role as usize),
        })
    }
}

impl TryFrom<InternalCustodianRecoveryOutput> for CustodianRecoveryOutput {
    type Error = anyhow::Error;

    fn try_from(value: InternalCustodianRecoveryOutput) -> Result<Self, Self::Error> {
        Ok(CustodianRecoveryOutput {
            backup_output: Some(OperatorBackupOutput {
                signcryption: value.signcryption.payload,
                pke_type: value.signcryption.pke_type as i32,
            }),
            custodian_role: value.custodian_role.one_based() as u64,
        })
    }
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum CustodianSetupMessagePayloadVersions {
    V0(CustodianSetupMessagePayload),
}

/// This is payload in the setup message that the custodian sends to the operators.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CustodianSetupMessagePayloadVersions)]
pub struct CustodianSetupMessagePayload {
    pub header: String,
    pub random_value: [u8; 32],
    pub timestamp: SystemTime,
    pub public_enc_key: UnifiedPublicEncKey,
    pub verification_key: VerfKeySet,
}

impl Named for CustodianSetupMessagePayload {
    const NAME: &'static str = "backup::CustodianSetupMessagePayload";
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum InternalCustodianSetupMessageVersions {
    V0(InternalCustodianSetupMessage),
}

/// This is the internal representation of the custodian setup message.
/// More specifically the content of this is serialized into [`CustodianSetupMessagePayload`]
/// which part of the protobuf [`CustodianSetupMessage`] sent to the operators.
///
/// The operators need to persist this message in their storage
/// so that they can run the backup procedure when needed.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(InternalCustodianSetupMessageVersions)]
pub struct InternalCustodianSetupMessage {
    pub header: String,
    pub custodian_role: Role,
    pub name: String, // This is the human readable name of the custodian
    pub random_value: [u8; 32],
    pub timestamp: SystemTime,
    pub public_enc_key: UnifiedPublicEncKey, // The public encrypt key of the custodian
    pub public_verf_key: VerfKeySet,         // The custodian's published verification keys
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
        let message = InternalCustodianSetupMessage {
            header: payload.header,
            name: value.name,
            custodian_role: Role::indexed_from_one(value.custodian_role as usize),
            random_value: payload.random_value,
            timestamp: payload.timestamp,
            public_enc_key: payload.public_enc_key,
            public_verf_key: payload.verification_key,
        };
        // A peer's key set crosses a boundary here, so it is checked rather than trusted.
        ensure_backup_schemes(&message.public_verf_key)
            .map_err(|e| anyhow::anyhow!("custodian role {}: {e}", message.custodian_role))?;
        Ok(message)
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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, VersionsDispatch)]
pub enum InternalCustodianContextVersions {
    V0(InternalCustodianContext),
}

/// This is the internal representation of the custodian context.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(InternalCustodianContextVersions)]
pub struct InternalCustodianContext {
    /// The custodian threshold for recovery
    pub threshold: u32,
    /// The custodian context ID that will identify this custodian context
    pub context_id: RequestId,
    /// The information received by the custodians during custodian context setup
    pub custodian_nodes: BTreeMap<Role, InternalCustodianSetupMessage>,
    /// The backup encryption key used to encrypt the backup shares
    pub backup_enc_key: UnifiedPublicEncKey,
}

impl Named for InternalCustodianContext {
    const NAME: &'static str = "backup::InternalCustodianContext";
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, VersionsDispatch)]
pub enum CustodianContextAnchorVersions {
    V0(CustodianContextAnchor),
}

/// Names the custodian context the node backs up under.
///
/// The backup vault also holds material for retired contexts and public storage is modifiable, so
/// neither can be asked which one is current. Only private storage can.
///
/// `sequence` orders anchors written by this node, so replacing one can add the new record before
/// removing the old and never leave the node with none. It orders trusted local writes only, and
/// is not a defence against anything.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CustodianContextAnchorVersions)]
pub struct CustodianContextAnchor {
    /// Also the storage id of the record.
    pub context_id: RequestId,
    /// Higher wins when several records exist; see `store_custodian_context_anchor`.
    pub sequence: u64,
}

impl Named for CustodianContextAnchor {
    const NAME: &'static str = "backup::CustodianContextAnchor";
}

impl InternalCustodianContext {
    /// Validate the threshold, roles, payloads, and cryptographic identities of custodian nodes.
    pub(crate) fn validate_nodes(custodian_context: &CustodianContext) -> anyhow::Result<()> {
        Self::validated_nodes(custodian_context).map(drop)
    }

    fn validated_nodes(
        custodian_context: &CustodianContext,
    ) -> anyhow::Result<BTreeMap<Role, InternalCustodianSetupMessage>> {
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
        for setup_message in &custodian_context.custodian_nodes {
            if setup_message.custodian_role == 0 {
                return Err(anyhow::anyhow!(
                    "Custodian role cannot be zero in custodian context"
                ));
            }
            if setup_message.custodian_role > custodian_context.custodian_nodes.len() as u64 {
                return Err(anyhow::anyhow!(
                    "Custodian role {} is greater than the number of custodians in custodian context",
                    setup_message.custodian_role
                ));
            }
            let internal_msg: InternalCustodianSetupMessage =
                setup_message.to_owned().try_into()?;
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

        let nodes = node_map.values().collect::<Vec<_>>();
        for node in &nodes {
            ensure_backup_schemes(&node.public_verf_key)
                .map_err(|e| anyhow::anyhow!("custodian role {}: {e}", node.custodian_role))?;
            // Reject a custodian whose encryption key is weaker than the scheme
            // this path is built around, rather than encrypting its share of the
            // backup key under it anyway.
            let scheme = node.public_enc_key.encryption_scheme_type();
            if scheme != BACKUP_PKE_SCHEME {
                return Err(anyhow::anyhow!(
                    "{}: role {} published a {scheme} key, but {BACKUP_PKE_SCHEME} is required",
                    ERR_WEAK_CUSTODIAN_ENCRYPTION_KEY,
                    node.custodian_role,
                ));
            }
        }

        for (index, node) in nodes.iter().enumerate() {
            for previous_node in &nodes[..index] {
                if previous_node.public_enc_key == node.public_enc_key {
                    return Err(anyhow::anyhow!(
                        "{}: roles {} and {}",
                        ERR_DUPLICATE_CUSTODIAN_ENCRYPTION_KEYS,
                        previous_node.custodian_role,
                        node.custodian_role
                    ));
                }
                // Two custodians must not share *any* verification keys
                let mut test_set: HashSet<_> =
                    node.public_verf_key.iter().map(|(_, key)| key).collect();
                for (scheme, cur_key) in previous_node.public_verf_key.iter() {
                    if !test_set.insert(cur_key) {
                        return Err(anyhow::anyhow!(
                            "{}: roles {} and {} share their {scheme} key {}",
                            ERR_DUPLICATE_CUSTODIAN_VERIFICATION_KEYS,
                            previous_node.custodian_role,
                            node.custodian_role,
                            cur_key.address_text()
                        ));
                    }
                }
            }
        }

        Ok(node_map)
    }

    pub fn new(
        custodian_context: CustodianContext,
        backup_enc_key: UnifiedPublicEncKey,
    ) -> anyhow::Result<Self> {
        let backup_scheme = backup_enc_key.encryption_scheme_type();
        if backup_scheme != BACKUP_PKE_SCHEME {
            return Err(anyhow::anyhow!(
                "{ERR_WEAK_BACKUP_ENCRYPTION_KEY}: got {backup_scheme}, but {BACKUP_PKE_SCHEME} is required",
            ));
        }
        let node_map = Self::validated_nodes(&custodian_context)?;
        let context_id: RequestId = parse_optional_grpc_request_id(
            &custodian_context.custodian_context_id,
            RequestIdParsingErr::CustodianContext,
        )?;
        Ok(InternalCustodianContext {
            context_id,
            threshold: custodian_context.threshold,
            custodian_nodes: node_map,
            backup_enc_key,
        })
    }
}

#[derive(Debug)]
pub struct Custodian {
    role: Role,
    signing_identity: NodeSigningIdentity,
    verification_keys: VerfKeySet,
    enc_key: UnifiedPublicEncKey,
    dec_key: UnifiedPrivateEncKey,
}

/// The custodian is the entity that signs and decrypts messages,
/// which are usually secret shares that are needed for recovery.
/// Since the secrets should be kept safe for a long time, the
/// public key encryption scheme is post quantum: MLKEM1024-P384, the composite of ML-KEM-1024 and
/// P-384 (see [`crate::backup::BACKUP_PKE_SCHEME`]), and the custodian signs under every scheme in
/// [`crate::backup::BACKUP_SIGNING_SCHEMES`]. Its encryption key pair and its signing identity are
/// both derived from the custodian's BIP-39 seed phrase by
/// [`crate::backup::seed_phrase::custodian_from_seed_phrase`].
impl Custodian {
    /// A custodian for `role` that signs with `signing_identity`.
    pub fn new(
        role: Role,
        signing_identity: NodeSigningIdentity,
        enc_key: UnifiedPublicEncKey,
        dec_key: UnifiedPrivateEncKey,
    ) -> Result<Self, BackupError> {
        let verification_keys =
            VerfKeySet::from_identity(&signing_identity, BACKUP_SIGNING_SCHEMES).map_err(|e| {
                BackupError::SetupError(format!(
                    "custodian role {role} cannot publish the backup signing schemes: {e}"
                ))
            })?;
        Ok(Self {
            role,
            signing_identity,
            verification_keys,
            enc_key,
            dec_key,
        })
    }

    pub fn verify_reencrypt<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        backup: &InnerOperatorBackupOutput,
        operator_verification_key: &VerfKeySet,
        operator_ephem_enc_key: &UnifiedPublicEncKey,
    ) -> Result<InternalCustodianRecoveryOutput, BackupError> {
        for fingerprint in operator_verification_key.all_fingerprints() {
            tracing::info!("Verifying and re-encrypting backup for operator {fingerprint}");
        }
        let custodian_id = self
            .verification_key_set()
            .id(BACKUP_SIGNING_SCHEMES)
            .map_err(|e| {
                BackupError::SetupError(format!("could not compute the custodian key set id: {e}"))
            })?;
        let unsigncrypt_key = UnifiedUnsigncryptionKey::new_multi(
            Arc::new(self.dec_key.clone()),
            self.enc_key.clone(),
            operator_verification_key.clone(),
            custodian_id,
        );

        // BackupMaterial contains secret shares which should be zeroized when dropped
        // so we put it behind a Zeroizing.
        let backup_material: Zeroizing<BackupMaterial> = Zeroizing::new(
            unsigncrypt_key
                .unsigncrypt_composite(
                    &DSEP_BACKUP_CUSTODIAN,
                    BACKUP_SIGNING_SCHEMES,
                    &backup.signcryption,
                )
                .map_err(|e| {
                    tracing::warn!(
                        "Unsigncryption failed for operator id {}: {e}",
                        hex::encode(&operator_id)
                    );
                    BackupError::CustodianRecoveryError
                })?,
        );
        if !backup_material.backup_id.is_valid() {
            tracing::error!(
                "Invalid backup_id {} in the decrypted backup material for operator with id: {}",
                backup_material.backup_id,
                hex::encode(&operator_id)
            );
            return Err(BackupError::CustodianRecoveryError);
        }
        if !backup_material.mpc_context_id.is_valid() {
            tracing::error!(
                "Invalid MPC context ID {} in the decrypted backup material for operator with id: {}",
                backup_material.mpc_context_id,
                hex::encode(&operator_id)
            );
            return Err(BackupError::CustodianRecoveryError);
        }
        // check the decrypted result
        if let Err(e) = backup_material.check_expected_metadata(
            self.verification_key_set(),
            self.role,
            &operator_id,
        ) {
            tracing::error!(
                "Backup material did not match expected metadata ({e:?}) for operator id: {}",
                hex::encode(&operator_id)
            );
            return Err(BackupError::CustodianRecoveryError);
        }

        // re-encrypted share and sign it
        let signcrypt_key = UnifiedSigncryptionKey::new(
            Arc::new(self.signing_identity.clone()),
            operator_ephem_enc_key.clone(),
            operator_id.clone(),
        );
        // Sealed under every scheme in `BACKUP_SIGNING_SCHEMES`
        let signcryption = signcrypt_key.signcrypt_composite(
            rng,
            &DSEP_BACKUP_MATERIAL,
            BACKUP_SIGNING_SCHEMES,
            &*backup_material,
        )?;
        tracing::debug!(
            "Signed re-encrypted share for operator id: {}",
            hex::encode(&operator_id)
        );
        Ok(InternalCustodianRecoveryOutput {
            signcryption,
            custodian_role: self.role,
        })
    }

    pub fn generate_setup_message<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        custodian_name: String, // This is the human readable name of the custodian to be used in the setup message
    ) -> Result<InternalCustodianSetupMessage, BackupError> {
        Ok(self.generate_setup_message_with_timestamp(rng, custodian_name, SystemTime::now()))
    }

    // The timestamp is taken as an explicit argument so that callers needing deterministic
    // output (e.g. backward-compatibility data generators) can pass a fixed value.
    pub fn generate_setup_message_with_timestamp<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        custodian_name: String,
        timestamp: SystemTime,
    ) -> InternalCustodianSetupMessage {
        let mut random_value = [0u8; 32];
        rng.fill_bytes(&mut random_value);

        InternalCustodianSetupMessage {
            header: HEADER.to_string(),
            custodian_role: self.role,
            random_value,
            timestamp,
            public_enc_key: self.enc_key.clone(),
            public_verf_key: self.verification_key_set().clone(),
            name: custodian_name,
        }
    }

    pub fn private_dec_key(&self) -> &UnifiedPrivateEncKey {
        &self.dec_key
    }

    pub fn public_enc_key(&self) -> &UnifiedPublicEncKey {
        &self.enc_key
    }

    /// The keys this custodian publishes, one per scheme in [`BACKUP_SIGNING_SCHEMES`].
    pub fn verification_key_set(&self) -> &VerfKeySet {
        &self.verification_keys
    }

    pub fn role(&self) -> Role {
        self.role
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::BACKUP_PKE_SCHEME;
    use crate::cryptography::signing::SigningSchemeType;
    use crate::cryptography::{
        encryption::{Encryption, PkeScheme, PkeSchemeType},
        signatures::{gen_sig_keys, test_support::seeded_verf_key_set},
    };
    use aes_prng::AesRng;
    use rand::SeedableRng;

    #[test]
    fn internal_custodian_context_zero_role_should_fail() {
        let mut rng = AesRng::seed_from_u64(40);
        let mut enc = Encryption::new(BACKUP_PKE_SCHEME, &mut rng);
        let (_, backup_pk) = enc.keygen().unwrap();
        let setup_msg1 = CustodianSetupMessage {
            custodian_role: 0, // Invalid role
            name: "Custodian-1".to_string(),
            payload: vec![],
        };
        let setup_msg2 = CustodianSetupMessage {
            custodian_role: 2,
            name: "Custodian-2".to_string(),
            payload: vec![],
        };
        let setup_msg3 = CustodianSetupMessage {
            custodian_role: 3,
            name: "Custodian-3".to_string(),
            payload: vec![],
        };
        let context = CustodianContext {
            custodian_nodes: vec![setup_msg1, setup_msg2, setup_msg3],
            custodian_context_id: None,
            threshold: 1,
        };
        let result = InternalCustodianContext::new(context, backup_pk);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Custodian role cannot be zero")
        );
    }

    #[test]
    fn invalid_threshold_should_fail() {
        let mut rng = AesRng::seed_from_u64(40);
        let mut enc = Encryption::new(BACKUP_PKE_SCHEME, &mut rng);
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
            custodian_context_id: None,
            threshold: 1, // Invalid threshold, since 1 is not less than 2/2
        };
        let result = InternalCustodianContext::new(context, backup_pk.clone());
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("Invalid threshold in custodian context")
        );
    }

    #[test]
    fn internal_custodian_context_duplicate_role_should_fail() {
        let mut rng = AesRng::seed_from_u64(40);
        let mut enc = Encryption::new(BACKUP_PKE_SCHEME, &mut rng);
        let (_, backup_pk) = enc.keygen().unwrap();
        let (_, payload_pk) = enc.keygen().unwrap();
        let payload_verf_key = seeded_verf_key_set(&mut rng, BACKUP_SIGNING_SCHEMES);
        let payload = CustodianSetupMessagePayload {
            header: HEADER.to_string(),
            random_value: [0u8; 32],
            timestamp: SystemTime::now(),
            public_enc_key: payload_pk,
            verification_key: payload_verf_key,
        };
        let mut ser_payload = Vec::new();
        safe_serialize(&payload, &mut ser_payload, SAFE_SER_SIZE_LIMIT).unwrap();
        let setup_msg1 = CustodianSetupMessage {
            custodian_role: 1,
            name: "Custodian-1".to_string(),
            payload: ser_payload.clone(),
        };
        let setup_msg2 = CustodianSetupMessage {
            custodian_role: 1, // Duplicate role
            name: "Custodian-2".to_string(),
            payload: ser_payload.clone(),
        };
        let setup_msg3 = CustodianSetupMessage {
            custodian_role: 3,
            name: "Custodian-3".to_string(),
            payload: ser_payload,
        };
        let context = CustodianContext {
            custodian_nodes: vec![setup_msg1, setup_msg2, setup_msg3],
            custodian_context_id: None,
            threshold: 1,
        };
        let result = InternalCustodianContext::new(context, backup_pk.clone());
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("Duplicate custodian role found")
        );
    }

    #[test]
    fn internal_custodian_context_duplicate_cryptographic_identity_should_fail() {
        let mut rng = AesRng::seed_from_u64(41);
        let (_, backup_pk) = {
            let mut enc = Encryption::new(BACKUP_PKE_SCHEME, &mut rng);
            enc.keygen().unwrap()
        };
        let mut setup_messages = Vec::new();
        for role in 1..=3 {
            let (_, public_enc_key) = {
                let mut enc = Encryption::new(BACKUP_PKE_SCHEME, &mut rng);
                enc.keygen().unwrap()
            };
            let public_verf_key = seeded_verf_key_set(&mut rng, BACKUP_SIGNING_SCHEMES);
            setup_messages.push(InternalCustodianSetupMessage {
                header: HEADER.to_string(),
                custodian_role: Role::indexed_from_one(role),
                name: format!("Custodian-{role}"),
                random_value: [role as u8; 32],
                timestamp: SystemTime::now(),
                public_enc_key,
                public_verf_key,
            });
        }

        let mut duplicate_encryption_key = setup_messages.clone();
        duplicate_encryption_key[1].public_enc_key =
            duplicate_encryption_key[0].public_enc_key.clone();
        let mut duplicate_verification_key = setup_messages;
        duplicate_verification_key[1].public_verf_key =
            duplicate_verification_key[0].public_verf_key.clone();

        for (messages, expected_error) in [
            (
                duplicate_encryption_key,
                ERR_DUPLICATE_CUSTODIAN_ENCRYPTION_KEYS,
            ),
            (
                duplicate_verification_key,
                ERR_DUPLICATE_CUSTODIAN_VERIFICATION_KEYS,
            ),
        ] {
            let context = CustodianContext {
                custodian_nodes: messages
                    .into_iter()
                    .map(|message| message.try_into().unwrap())
                    .collect(),
                custodian_context_id: None,
                threshold: 1,
            };

            let error = InternalCustodianContext::new(context, backup_pk.clone())
                .expect_err("duplicate custodian cryptographic identities must be rejected");
            assert!(error.to_string().contains(expected_error));
            assert!(error.to_string().contains("roles 1 and 2"));
        }
    }

    /// A custodian that publishes a key weaker than [`BACKUP_PKE_SCHEME`] is
    /// refused at context creation.
    #[test]
    fn custodian_encryption_key_below_the_backup_scheme_should_fail() {
        let mut rng = AesRng::seed_from_u64(42);
        let (_, backup_pk) = {
            let mut enc = Encryption::new(BACKUP_PKE_SCHEME, &mut rng);
            enc.keygen().unwrap()
        };

        let mut setup_messages = Vec::new();
        for role in 1..=3 {
            // Role 2 publishes an ML-KEM-512 key; the others are correct, so the
            // context fails on that role alone rather than on its overall shape.
            let scheme = if role == 2 {
                PkeSchemeType::MlKem512
            } else {
                BACKUP_PKE_SCHEME
            };
            let (_, public_enc_key) = {
                let mut enc = Encryption::new(scheme, &mut rng);
                enc.keygen().unwrap()
            };
            let public_verf_key = seeded_verf_key_set(&mut rng, BACKUP_SIGNING_SCHEMES);
            setup_messages.push(InternalCustodianSetupMessage {
                header: HEADER.to_string(),
                custodian_role: Role::indexed_from_one(role),
                name: format!("Custodian-{role}"),
                random_value: [role as u8; 32],
                timestamp: SystemTime::now(),
                public_enc_key,
                public_verf_key,
            });
        }

        let context = CustodianContext {
            custodian_nodes: setup_messages
                .into_iter()
                .map(|message| message.try_into().unwrap())
                .collect(),
            custodian_context_id: None,
            threshold: 1,
        };

        let error = InternalCustodianContext::new(context, backup_pk)
            .expect_err("a custodian key below the backup scheme must be rejected");
        let error = error.to_string();
        assert!(
            error.contains(ERR_WEAK_CUSTODIAN_ENCRYPTION_KEY),
            "unexpected error: {error}"
        );
        assert!(
            error.contains("role 2"),
            "the error does not name the role: {error}"
        );
    }

    /// A custodian that publishes fewer schemes than [`BACKUP_SIGNING_SCHEMES`] is refused at
    /// context creation, rather than having its weaker signatures accepted later.
    /// A custodian with a superset of [`BACKUP_SIGNING_SCHEMES`] is however accepted to ensure
    /// backwards compatibility with future releases expanding [`BACKUP_SIGNING_SCHEMES`].
    #[test]
    fn a_custodian_key_set_must_cover_the_backup_schemes() {
        let cases: [(&str, &[SigningSchemeType], bool); 3] = [
            ("fewer", &[SigningSchemeType::Ecdsa256k1], false),
            (
                "exact",
                &[SigningSchemeType::MlDsa87, SigningSchemeType::Ecdsa256k1],
                true,
            ),
            (
                "more",
                &[
                    SigningSchemeType::Ecdsa256k1,
                    SigningSchemeType::Ed25519,
                    SigningSchemeType::MlDsa87,
                ],
                true,
            ),
        ];

        for (case, role_two_schemes, should_be_accepted) in cases {
            let mut rng = AesRng::seed_from_u64(44);
            let (_, backup_pk) = {
                let mut enc = Encryption::new(BACKUP_PKE_SCHEME, &mut rng);
                enc.keygen().unwrap()
            };

            let mut setup_messages = Vec::new();
            for role in 1..=3 {
                let (_, public_enc_key) = {
                    let mut enc = Encryption::new(BACKUP_PKE_SCHEME, &mut rng);
                    enc.keygen().unwrap()
                };
                // Only role 2 deviates, so a rejection is attributable to that role rather than
                // to the overall shape of the context.
                let schemes: &[SigningSchemeType] = if role == 2 {
                    role_two_schemes
                } else {
                    BACKUP_SIGNING_SCHEMES
                };
                setup_messages.push(InternalCustodianSetupMessage {
                    header: HEADER.to_string(),
                    custodian_role: Role::indexed_from_one(role),
                    name: format!("Custodian-{role}"),
                    random_value: [role as u8; 32],
                    timestamp: SystemTime::now(),
                    public_enc_key,
                    public_verf_key: seeded_verf_key_set(&mut rng, schemes),
                });
            }

            let context = CustodianContext {
                custodian_nodes: setup_messages
                    .into_iter()
                    .map(|message| message.try_into().unwrap())
                    .collect(),
                // The accepted cases get past node validation, so they need a valid ID.
                custodian_context_id: Some(RequestId::from_bytes([44; 32]).into()),
                threshold: 1,
            };

            match (
                should_be_accepted,
                InternalCustodianContext::new(context, backup_pk),
            ) {
                (true, Ok(_)) => {}
                (true, Err(error)) => {
                    panic!(
                        "{case}: a key set covering the backup schemes must be accepted: {error}"
                    )
                }
                (false, Ok(_)) => {
                    panic!("{case}: a key set below the backup schemes must be rejected")
                }
                (false, Err(error)) => {
                    let error = error.to_string();
                    assert!(
                        error.contains("custodian role 2"),
                        "{case}: the error does not name the role: {error}"
                    );
                }
            }
        }
    }

    /// A custodian whose identity holds no root seed cannot publish
    /// [`BACKUP_SIGNING_SCHEMES`], so it cannot be constructed at all.
    #[test]
    fn a_seedless_custodian_cannot_be_constructed() {
        let mut rng = AesRng::seed_from_u64(45);
        let (dec_key, enc_key) = {
            let mut enc = Encryption::new(BACKUP_PKE_SCHEME, &mut rng);
            enc.keygen().unwrap()
        };
        let (_verf_key, sig_key) = gen_sig_keys(&mut rng);
        let seedless = NodeSigningIdentity::ecdsa_only(sig_key);

        let error = Custodian::new(Role::indexed_from_one(1), seedless, enc_key, dec_key)
            .expect_err("a seedless custodian cannot publish the backup signing schemes");
        assert!(
            matches!(error, BackupError::SetupError(_)),
            "unexpected error: {error}"
        );
    }

    /// The operator's own backup key is checked too, so a future change that
    /// threaded a weaker key through cannot produce a vault that looks healthy.
    #[test]
    fn backup_encryption_key_below_the_backup_scheme_should_fail() {
        let mut rng = AesRng::seed_from_u64(43);
        let (_, weak_backup_pk) = {
            let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
            enc.keygen().unwrap()
        };

        // The node list is irrelevant here: the backup key is checked before
        // the nodes are, so this fails on the key rather than on the shape.
        let context = CustodianContext {
            custodian_nodes: vec![],
            custodian_context_id: None,
            threshold: 1,
        };

        let error = InternalCustodianContext::new(context, weak_backup_pk)
            .expect_err("a backup key below the backup scheme must be rejected");
        assert!(
            error.to_string().contains(ERR_WEAK_BACKUP_ENCRYPTION_KEY),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn internal_custodian_context_role_greater_than_nodes_should_fail() {
        let mut rng = AesRng::seed_from_u64(40);
        let mut enc = Encryption::new(BACKUP_PKE_SCHEME, &mut rng);
        let (_, backup_pk) = enc.keygen().unwrap();
        let setup_msg1 = CustodianSetupMessage {
            custodian_role: 5, // Greater than number of nodes
            name: "Custodian-1".to_string(),
            payload: vec![],
        };
        let setup_msg2 = CustodianSetupMessage {
            custodian_role: 2,
            name: "Custodian-2".to_string(),
            payload: vec![],
        };
        let setup_msg3 = CustodianSetupMessage {
            custodian_role: 3,
            name: "Custodian-3".to_string(),
            payload: vec![],
        };
        let context = CustodianContext {
            custodian_nodes: vec![setup_msg1, setup_msg2, setup_msg3],
            custodian_context_id: None,
            threshold: 1,
        };
        let result = InternalCustodianContext::new(context, backup_pk.clone());
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains(
            "Custodian role 5 is greater than the number of custodians in custodian context"
        ));
    }
}
