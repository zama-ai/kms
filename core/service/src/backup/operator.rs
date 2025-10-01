use super::{
    custodian::{InternalCustodianSetupMessage, DSEP_BACKUP_CUSTODIAN, HEADER},
    error::BackupError,
    secretsharing,
    traits::BackupDecryptor,
};
use crate::backup::custodian::InternalCustodianContext;
use crate::{
    anyhow_error_and_log,
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::{
        backup_pke::{BackupPrivateKey, BackupPublicKey},
        internal_crypto_types::{PrivateSigKey, PublicSigKey, Signature},
        signcryption::{internal_sign, internal_verify_sig},
    },
    engine::{
        base::safe_serialize_hash_element_versioned,
        validation::{parse_optional_proto_request_id, RequestIdParsingErr},
    },
};
use kms_grpc::{
    kms::v1::{OperatorBackupOutput, RecoveryRequest},
    rpc_types::InternalCustodianRecoveryOutput,
    RequestId,
};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
    time::{SystemTime, UNIX_EPOCH},
};
use tfhe::{
    named::Named,
    safe_serialization::{safe_deserialize, safe_serialize},
    Versionize,
};
use tfhe_versionable::VersionsDispatch;
use threshold_fhe::{
    algebra::galois_rings::degree_4::ResiduePolyF4Z64,
    execution::{
        runtime::party::Role,
        sharing::{shamir::ShamirSharings, share::Share},
    },
    hashing::DomainSep,
};

pub const DSEP_BACKUP_COMMITMENT: DomainSep = *b"BKUPCOMM";
pub(crate) const DSEP_BACKUP_RECOVERY: DomainSep = *b"BKUPRECO";
const TIMESTAMP_VALIDATION_WINDOW_SECS: u64 = 24 * 3600; // 1 day

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum InternalRecoveryRequestVersioned {
    V0(InternalRecoveryRequest),
}

impl Named for InternalRecoveryRequest {
    const NAME: &'static str = "backup::InternalRecoveryRequest";
}

/// The backup data returned to the custodians during recovery.
/// WARNING: It is crucial that this is transported safely as it does not
/// contain any authentication on the ephemeral encryption key [`enc_key`].
/// This is because we have to assume that the operator has no access to the private storage
/// when creating this object.
#[derive(Debug, Clone, Serialize, Deserialize, Versionize)]
#[versionize(InternalRecoveryRequestVersioned)]
pub struct InternalRecoveryRequest {
    enc_key: BackupPublicKey,
    cts: BTreeMap<Role, InnerOperatorBackupOutput>,
    backup_id: RequestId,
    operator_role: Role,
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum RecoveryRequestPayloadVersioned {
    V0(RecoveryRequestPayload),
}

/// The backup data constructed whenever a new custodian context is created.
/// It is meant to be stored in the public storage as it is self-trusted via the signatures
/// It is different from what is returned to custodians during recovery since it is then augmented with
/// an ephemeral encryption key during that point in time.
#[derive(Debug, Clone, Serialize, Deserialize, Versionize)]
#[versionize(RecoveryRequestPayloadVersioned)]
pub struct RecoveryRequestPayload {
    /// The ciphertexts that are the backup. Indexed by the custodian role.
    pub cts: BTreeMap<Role, InnerOperatorBackupOutput>,
    pub backup_enc_key: BackupPublicKey,
}

impl Named for RecoveryRequestPayload {
    const NAME: &'static str = "backup::RecoveryRequestPayload";
}

impl InternalRecoveryRequest {
    pub fn new(
        enc_key: BackupPublicKey,
        cts: BTreeMap<Role, InnerOperatorBackupOutput>,
        backup_id: RequestId,
        operator_role: Role,
        verf_key: Option<&PublicSigKey>,
    ) -> anyhow::Result<Self> {
        let res = InternalRecoveryRequest {
            enc_key,
            cts,
            backup_id,
            operator_role,
        };
        if let Some(verf_key) = verf_key {
            if !res.is_valid(verf_key)? {
                return Err(anyhow_error_and_log("Invalid RecoveryRequest data"));
            }
        }
        Ok(res)
    }

    /// Validate that the data in the request is sensible.
    pub fn is_valid(&self, verf_key: &PublicSigKey) -> anyhow::Result<bool> {
        if !self.backup_id.is_valid() {
            tracing::warn!("InternalRecoveryRequest has an invalid backup ID");
            return Ok(false);
        }
        if self.operator_role.one_based() == 0 {
            tracing::warn!("InternalRecoveryRequest has an invalid operator role");
            return Ok(false);
        }
        for cur in self.cts.values() {
            if internal_verify_sig(
                &DSEP_BACKUP_RECOVERY,
                &cur.ciphertext,
                &Signature {
                    sig: k256::ecdsa::Signature::from_slice(&cur.signature)?,
                },
                verf_key,
            )
            .is_err()
            {
                tracing::warn!("InternalRecoveryRequest signature verification failed");
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn encryption_key(&self) -> &BackupPublicKey {
        &self.enc_key
    }

    pub fn ciphertexts(&self) -> HashMap<Role, &InnerOperatorBackupOutput> {
        self.cts.iter().map(|(role, ct)| (*role, ct)).collect()
    }

    pub fn backup_id(&self) -> RequestId {
        self.backup_id
    }

    pub fn operator_role(&self) -> Role {
        self.operator_role
    }
}

impl Display for InternalRecoveryRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "InternalRecoveryRequest with:\n backup id: {}\n operator role: {}",
            self.backup_id, self.operator_role,
        )
    }
}

impl TryFrom<RecoveryRequest> for InternalRecoveryRequest {
    type Error = anyhow::Error;

    fn try_from(value: RecoveryRequest) -> Result<InternalRecoveryRequest, Self::Error> {
        let enc_key: BackupPublicKey =
            safe_deserialize(std::io::Cursor::new(&value.enc_key), SAFE_SER_SIZE_LIMIT).map_err(
                |e| anyhow_error_and_log(format!("Could not deserialize enc_key: {e:?}")),
            )?;
        let cts = value
            .cts
            .iter()
            .map(|(cur_role_idx, cur_backup_out)| {
                (
                    Role::indexed_from_one(*cur_role_idx as usize),
                    cur_backup_out.clone().into(),
                )
            })
            .collect();
        let backup_id: RequestId =
            parse_optional_proto_request_id(&value.backup_id, RequestIdParsingErr::BackupRecovery)?;
        Ok(Self {
            enc_key,
            cts,
            backup_id,
            operator_role: Role::indexed_from_one(value.operator_role as usize),
        })
    }
}

#[derive(Clone)]
pub struct Operator {
    my_role: Role,
    custodian_keys: HashMap<Role, (BackupPublicKey, PublicSigKey)>,
    signer: PrivateSigKey,
    // the public component of [signer] above
    verification_key: PublicSigKey,
    threshold: usize,
}

impl std::fmt::Debug for Operator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Operator")
            .field("my_id", &self.my_role)
            .field("custodian_keys", &self.custodian_keys)
            .field("signer", &"ommitted")
            .field("verification_key", &self.verification_key)
            .field("threshold", &self.threshold)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum InnerOperatorBackupOutputVersioned {
    V0(InnerOperatorBackupOutput),
}

/// The output from the operator after it has completed a backup.
/// This data needs to be persisted on some public storage so that
/// new operators can download and recover.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(InnerOperatorBackupOutputVersioned)]
pub struct InnerOperatorBackupOutput {
    /// Ciphertext under the custodian's public key, using nested encryption.
    pub ciphertext: Vec<u8>,
    /// Signature by the operator.
    pub signature: Vec<u8>,
}

impl Named for InnerOperatorBackupOutput {
    const NAME: &'static str = "backup::InnerOperatorBackupOutput";
}

impl From<OperatorBackupOutput> for InnerOperatorBackupOutput {
    fn from(value: OperatorBackupOutput) -> Self {
        Self {
            ciphertext: value.ciphertext,
            signature: value.signature,
        }
    }
}
impl From<InnerOperatorBackupOutput> for OperatorBackupOutput {
    fn from(value: InnerOperatorBackupOutput) -> Self {
        Self {
            ciphertext: value.ciphertext,
            signature: value.signature,
        }
    }
}

fn verify_n_t(n: usize, t: usize) -> Result<(), BackupError> {
    if n == 0 {
        return Err(BackupError::SetupError("n cannot be 0".to_string()));
    }
    if t == 0 {
        return Err(BackupError::SetupError("t cannot be 0".to_string()));
    }
    if t * 2 >= n {
        return Err(BackupError::SetupError(format!(
            "t < n/2 is not satisfied, t is {t} and n is {n}"
        )));
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum RecoveryValidationMaterialVersioned {
    V0(RecoveryValidationMaterial),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(RecoveryValidationMaterialVersioned)]
pub struct RecoveryValidationMaterial {
    pub(crate) payload: RecoveryValidationMaterialPayload,
    signature: Vec<u8>,
}

impl Named for RecoveryValidationMaterial {
    const NAME: &'static str = "backup::RecoveryValidationMaterial";
}

impl RecoveryValidationMaterial {
    pub fn new(
        commitments: BTreeMap<Role, Vec<u8>>,
        custodian_context: InternalCustodianContext,
        sk: &PrivateSigKey,
    ) -> anyhow::Result<Self> {
        let payload = RecoveryValidationMaterialPayload {
            commitments,
            custodian_context,
        };
        let serialized_payload = bc2wrap::serialize(&payload).map_err(|e| {
            anyhow_error_and_log(format!("Could not serialize inner recovery request: {e:?}"))
        })?;
        let signature = &crate::cryptography::signcryption::internal_sign(
            &DSEP_BACKUP_RECOVERY,
            &serialized_payload,
            sk,
        )?;
        let signature_buf = signature.sig.to_vec();
        let res = Self {
            payload,
            signature: signature_buf,
        };
        // Sanity check
        if !res.validate(&PublicSigKey::from_sk(sk)) {
            return Err(anyhow_error_and_log(
                "Could not validate newly created recovery validation material",
            ));
        }
        Ok(res)
    }

    /// Get the commitment for a specific role.
    pub fn get(&self, role: &Role) -> anyhow::Result<&[u8]> {
        if role.one_based() > self.payload.commitments.len() {
            anyhow::bail!("Role {} is out of bounds for commitments", role);
        }
        let res = self
            .payload
            .commitments
            .get(role)
            .ok_or_else(|| anyhow::anyhow!("No commitment found for role {}", role))?;
        Ok(res)
    }

    pub fn custodian_context(&self) -> &InternalCustodianContext {
        &self.payload.custodian_context
    }

    /// Validated the signature on the recovery validation material.
    /// This is useful after deserializing from untrusted storage such as public storage
    pub fn validate(&self, verf_key: &PublicSigKey) -> bool {
        let serialized_payload = match bc2wrap::serialize(&self.payload) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Could not serialize recovery validation material payload: {e:?}");
                return false;
            }
        };
        let sig = match k256::ecdsa::Signature::from_slice(&self.signature) {
            Ok(sig) => sig,
            Err(e) => {
                tracing::warn!("Could not parse recovery validation material signature: {e:?}");
                return false;
            }
        };
        let signature = Signature { sig };
        match internal_verify_sig(
            &DSEP_BACKUP_RECOVERY,
            &serialized_payload,
            &signature,
            verf_key,
        ) {
            Ok(_) => true,
            Err(e) => {
                tracing::info!("Could not verify recovery validation material signature: {e:?}");
                false
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum RecoveryValidationMaterialPayloadVersioned {
    V0(RecoveryValidationMaterialPayload),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(RecoveryValidationMaterialPayloadVersioned)]
pub struct RecoveryValidationMaterialPayload {
    pub commitments: BTreeMap<Role, Vec<u8>>,
    pub custodian_context: InternalCustodianContext,
}
impl Named for RecoveryValidationMaterialPayload {
    const NAME: &'static str = "backup::RecoveryValidationMaterialPayload";
}

#[allow(clippy::too_many_arguments)]
fn checked_decryption_deserialize<D: BackupDecryptor>(
    sk: &D,
    ct: &[u8],
    commitment: &[u8],
    backup_id: RequestId,
    custodian_pk: &PublicSigKey,
    custodian_role: Role,
    operator_pk: &PublicSigKey,
    operator_role: Role,
) -> Result<Vec<Share<ResiduePolyF4Z64>>, BackupError> {
    let pt_buf = sk.decrypt(ct)?;
    let backup_material: BackupMaterial = tfhe::safe_serialization::safe_deserialize(
        std::io::Cursor::new(&pt_buf),
        SAFE_SER_SIZE_LIMIT,
    )
    .map_err(BackupError::SafeDeserializationError)?;

    // check metadata
    if !backup_material.matches_expected_metadata(
        backup_id,
        custodian_pk,
        custodian_role,
        operator_pk,
        operator_role,
    ) {
        return Err(BackupError::OperatorError(
            "backup metadata check failure".to_string(),
        ));
    }

    // check commitment
    let actual_commitment =
        safe_serialize_hash_element_versioned(&DSEP_BACKUP_COMMITMENT, &backup_material)
            .map_err(|e| BackupError::OperatorError(e.to_string()))?;
    if actual_commitment != commitment {
        return Err(BackupError::OperatorError(
            "backup commitment check failure".to_string(),
        ));
    }

    Ok(backup_material.shares)
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum BackupMaterialVersioned {
    V0(BackupMaterial),
}

#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(BackupMaterialVersioned)]
pub struct BackupMaterial {
    pub(crate) backup_id: RequestId,
    // receiver
    pub(crate) custodian_pk: PublicSigKey,
    pub(crate) custodian_role: Role,
    // sender
    pub(crate) operator_pk: PublicSigKey,
    pub(crate) operator_role: Role,
    pub(crate) shares: Vec<Share<ResiduePolyF4Z64>>,
}

impl BackupMaterial {
    pub fn matches_expected_metadata(
        &self,
        backup_id: RequestId,
        custodian_pk: &PublicSigKey,
        custodian_role: Role,
        operator_pk: &PublicSigKey,
        operator_role: Role,
    ) -> bool {
        if self.backup_id != backup_id {
            tracing::error!(
                "backup_id mismatch: expected {} but got {}",
                self.backup_id,
                backup_id
            );
            return false;
        }
        if self.custodian_role != custodian_role {
            tracing::error!(
                "custodian_role mismatch: expected {} but got {}",
                self.custodian_role,
                custodian_role
            );
            return false;
        }
        if self.operator_role != operator_role {
            tracing::error!(
                "operator_role mismatch: expected {} but got {}",
                self.operator_role,
                operator_role,
            );
            return false;
        }
        if &self.custodian_pk != custodian_pk {
            tracing::error!("custodian_pk mismatch");
            return false;
        }
        if &self.operator_pk != operator_pk {
            tracing::error!("operator_pk mismatch");
            return false;
        }
        true
    }
}

impl Named for BackupMaterial {
    const NAME: &'static str = "backup::BackupShares";
}

impl Operator {
    pub fn new(
        my_role: Role,
        custodian_messages: Vec<InternalCustodianSetupMessage>,
        signer: PrivateSigKey,
        threshold: usize,
        amount_custodians: usize,
    ) -> Result<Self, BackupError> {
        verify_n_t(amount_custodians, threshold)?;
        if custodian_messages.len() != amount_custodians {
            tracing::warn!(
                "An incorrect amount of custodian messages were received: expected at least {} but got {}",
                amount_custodians,
                custodian_messages.len()
            );
            if custodian_messages.len() < threshold + 1 {
                let msg = format!(
                    "Not enough custodian setup messages: expected at least {} but got {}",
                    threshold + 1,
                    custodian_messages.len()
                );
                tracing::error!("{msg}");
                return Err(BackupError::SetupError(msg));
            }
        }

        let mut custodian_keys = HashMap::new();
        for msg in custodian_messages.into_iter() {
            let InternalCustodianSetupMessage {
                header,
                custodian_role,
                random_value: _,
                timestamp,
                name: _,
                public_enc_key,
                public_verf_key,
            } = msg;

            if header != HEADER {
                tracing::warn!("Invalid header in custodian setup message from custodian {custodian_role}. Expected header {HEADER} but got {header}");
                continue;
            }

            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            if !(now - TIMESTAMP_VALIDATION_WINDOW_SECS < timestamp
                && timestamp < now + TIMESTAMP_VALIDATION_WINDOW_SECS)
            {
                tracing::warn!(
                    "Invalid timestamp in custodian setup message from custodian {}: expected within {} seconds of now, but got {}",
                    custodian_role,
                    TIMESTAMP_VALIDATION_WINDOW_SECS,
                    timestamp
                );
                continue;
            }

            if custodian_role.one_based() > amount_custodians {
                tracing::warn!(
                    "Invalid custodian role in custodian setup message: {custodian_role}. Expected role between 1 and {amount_custodians}"
                );
                continue;
            }

            if let Some(old_val) =
                custodian_keys.insert(custodian_role, (public_enc_key, public_verf_key))
            {
                tracing::warn!(
                        "Duplicate custodian role in custodian setup message: {custodian_role}. Will use first value for this role"
                    );
                let _ = custodian_keys.insert(custodian_role, old_val);
                continue;
            }
        }
        if custodian_keys.len() < threshold + 1 {
            let msg = format!(
                "Not enough valid custodian setup messages: expected at least {} but got {}",
                threshold + 1,
                custodian_keys.len()
            );
            tracing::error!("{msg}");
            return Err(BackupError::SetupError(msg));
        }
        let verf_key = signer.clone().into();
        Ok(Self {
            my_role,
            custodian_keys,
            signer,
            verification_key: verf_key,
            threshold,
        })
    }

    pub fn verification_key(&self) -> &PublicSigKey {
        &self.verification_key
    }

    pub fn role(&self) -> Role {
        self.my_role
    }

    // We allow the following lints because we are fine with mutating the rng even if
    // the function fails afterwards.
    #[allow(unknown_lints)]
    #[allow(non_local_effect_before_error_return)]
    #[allow(clippy::type_complexity)]
    /// Construct a secret sharing of a `secret` and return a map of the basic backup recovery material,
    /// indexed by the role of each custodian. Also return a map of each commitment to the secret share,
    /// indexed by the role of each custodian.
    pub fn secret_share_and_encrypt<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        secret: &[u8],
        backup_id: RequestId,
    ) -> Result<
        (
            BTreeMap<Role, InnerOperatorBackupOutput>,
            BTreeMap<Role, Vec<u8>>,
        ),
        BackupError,
    > {
        let n = self.custodian_keys.len();
        let t = self.threshold;

        // 1. Each player/operator `P_i` selects `n` other custodians `B_j` for `[j=1..n]`
        // of which he assumes `t < n/2` are dishonest.
        // 2. Custodian `B_j` generates a one time __post-quantum IND-CCA__ secure public/private key pair `(pk^{E_j}, sk^{E_j})`
        // and a EUF-CMA secure signing key pair `(pk^{S_j}, pk^{S_j})` and sends `(pk^{E_j}, pk^{S_j})` to `P_i`.
        // The steps above are assumed to be given by [self.custodian_keys].

        // 3. Player `P_i` splits their share `s_i` (the input named `secret`) via a degree `t` sharing
        // among `n` players, to get shares `s_ij`.
        let shares = secretsharing::share(rng, secret, n, t)?;

        // For all `s_ij, j \in [n]`
        // 4.1 Player `P_i` encrypts `s_ij` to custodian `B_j` to get `ct_ij = Enc(pk^{E_j}, s_ij)`.
        // 4.2 Sign the ciphertext with the player's own signing key `sig_ij = Sign(sk^{S_i}, ct_ij)`.
        // 4.3 Commit to all the shares `c_ij = Commit(s_ij)`.
        //
        // This is done by preparing a map, mapping the 0-indexed party-id to their corresponding vector of shares.
        // Observer that the sharing is a vector since a sharing must be constructed for each byte in the secret.
        let mut plain_ij: BTreeMap<Role, Vec<Share<ResiduePolyF4Z64>>> = BTreeMap::new();
        for share in shares.into_iter() {
            for inner in share.shares {
                let role_inner = inner.owner();
                if let Some(v) = plain_ij.get_mut(&role_inner) {
                    v.push(inner);
                } else {
                    plain_ij.insert(role_inner, vec![inner]);
                }
            }
        }

        let mut ct_shares: BTreeMap<Role, _> = BTreeMap::new();
        let mut commitments: BTreeMap<Role, _> = BTreeMap::new();

        // Zip_eq will panic in case the two iterators are not of the same length.
        // Since `plain_ij` is created in this method from `shares` such a panic can only happen in case of a bug in this method
        for (role_j, shares) in plain_ij.into_iter() {
            // Do a sanity check that we expect enough entropy in the shares
            // s.t. hashing these cannot allow a feasible brute-force attack.
            //
            // At the moment we only have a length check that ensures they have at least
            // 256 bits of pseudorandom values per shares.
            // There are shares.len() shares, each has 256 bits and 64 bits for the role
            // the extra 8 bytes is used by bincode to encode the length.
            let minimum_expected_length = shares.len() * (32 + 8) + 8;
            let actual_length = bc2wrap::serialize(&shares)?.len();
            if actual_length < minimum_expected_length {
                return Err(BackupError::OperatorError(format!(
                    "share is not long enough: actual={actual_length} < minimum={minimum_expected_length}"
                )));
            }
            let (enc_pk, sig_pk) = match self.custodian_keys.get(&role_j) {
                Some((enc_pk, sig_pk)) => (enc_pk, sig_pk),
                None => {
                    // Note that we do not error out since we might now have gotten all the expected correct custodian setup messages
                    tracing::warn!("Could not find custodian keys for role {role_j}");
                    continue;
                }
            };
            let backup_material = BackupMaterial {
                backup_id,
                custodian_pk: sig_pk.clone(),
                custodian_role: role_j,
                operator_pk: self.verification_key.clone(),
                operator_role: self.my_role,
                shares,
            };

            let mut msg = Vec::new();
            safe_serialize(&backup_material, &mut msg, SAFE_SER_SIZE_LIMIT)
                .map_err(|e| BackupError::BincodeError(e.to_string()))?;
            let ciphertext = enc_pk.encrypt(rng, &msg)?;
            let signature = internal_sign(&DSEP_BACKUP_RECOVERY, &ciphertext, &self.signer)
                .map_err(|e| BackupError::OperatorError(e.to_string()))?
                .sig
                .to_vec();
            // Commitment by the operator, which is a hash of [BackupMaterial].
            //
            // We cannot use the regular commitment routines from commitment.rs
            // because the operator cannot keep the opening and it cannot make it public.
            // As such, we need to ensure the material that is being committed
            // has enough entropy.
            //
            // we simply use the digest as the commitment
            // since the share should have enough entropy
            // is simply a sha3 hash with some metadata of the share
            let msg_digest =
                safe_serialize_hash_element_versioned(&DSEP_BACKUP_COMMITMENT, &backup_material)
                    .map_err(|e| BackupError::OperatorError(e.to_string()))?;

            // 5. The ciphertext is stored by `Pij`, or stored on a non-malleable storage, e.g. a blockchain or a secure bank vault.
            ct_shares.insert(
                role_j,
                InnerOperatorBackupOutput {
                    ciphertext,
                    signature,
                },
            );
            commitments.insert(role_j, msg_digest);
        }

        if ct_shares.len() < self.threshold + 1 {
            return Err(BackupError::OperatorError(format!(
                "Not enough valid custodian shares were created: expected at least {} but got {}",
                self.threshold + 1,
                ct_shares.len()
            )));
        }
        // 6. The commitments are stored by `P_i` and can be used to verify the shares later.
        Ok((ct_shares, commitments))
    }

    /// Operators that does the recovery collects all the materials
    /// used during the backup protocol such as shares, keys and ciphertexts,
    /// and then uses them to verify whether the shares are correct before
    /// doing the reconstruction.
    ///
    /// Commitments do not come from the same location as the custodian message
    /// so the are a separate input.
    pub fn verify_and_recover(
        &self,
        custodian_recovery_output: &[InternalCustodianRecoveryOutput],
        recovery_material: &RecoveryValidationMaterial,
        backup_id: RequestId,
        dec_key: &BackupPrivateKey, // Note that this is the ephemeral decryption key, NOT the actual backup decryption key
    ) -> Result<Vec<u8>, BackupError> {
        // the output is ordered by custodian ID, from 0 to n-1
        // first check the signature and decrypt
        // decrypted_buf[j][i] where j = jth custodian, i = ith block
        let decrypted_buf = custodian_recovery_output
            .iter()
            .map(|ct| {
                let (_enc_key, verf_key) = self.custodian_keys.get(&ct.custodian_role).ok_or(
                    BackupError::OperatorError(format!(
                        "missing custodian key for {}",
                        ct.custodian_role
                    )),
                )?;
                // sigt_ij
                let signature = Signature {
                    sig: k256::ecdsa::Signature::from_slice(&ct.signature)?,
                };
                let commitment = recovery_material
                    .get(&ct.custodian_role)
                    .map_err(|_| BackupError::OperatorError("missing commitment".to_string()))?;
                internal_verify_sig(&DSEP_BACKUP_CUSTODIAN, &ct.ciphertext, &signature, verf_key)
                    .map_err(|e| BackupError::SignatureVerificationError(e.to_string()))?;
                // st_ij
                checked_decryption_deserialize(
                    dec_key,
                    &ct.ciphertext,
                    commitment,
                    backup_id,
                    verf_key,
                    ct.custodian_role,
                    &self.verification_key,
                    self.my_role,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        let num_blocks = if let Some(x) = decrypted_buf.iter().map(|v| v.len()).min() {
            x
        } else {
            // This is normally impossible to happen because if it did
            // then it would mean the validation on expected_shares above failed
            return Err(BackupError::NoBlocksError);
        };

        let mut all_sharings = vec![];
        for b in 0..num_blocks {
            let mut shamir_sharing = ShamirSharings::new();
            for blocks in decrypted_buf.iter() {
                // we should be able to safely add shares since it checks whether the role is repeated
                shamir_sharing.add_share(blocks[b]);
            }
            all_sharings.push(shamir_sharing);
        }
        let out = secretsharing::reconstruct(all_sharings, self.threshold)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backup::custodian::CustodianSetupMessagePayload,
        cryptography::{backup_pke::keygen, internal_crypto_types::gen_sig_keys},
        engine::base::derive_request_id,
    };
    use aes_prng::AesRng;
    use kms_grpc::kms::v1::{CustodianContext, CustodianSetupMessage};
    use rand::SeedableRng;

    #[test]
    fn validate_recovery_validation_material() {
        let mut rng = AesRng::seed_from_u64(0);
        let (verf_key, sig_key) = gen_sig_keys(&mut rng);
        let (enc_key, _dec_key) = keygen(&mut rng).unwrap();
        let backup_id = derive_request_id("test").unwrap();
        // Dummy payload; but needs to be a properly serialized payload
        let payload = CustodianSetupMessagePayload {
            header: HEADER.to_string(),
            random_value: [4_u8; 32],
            timestamp: 0,
            public_enc_key: enc_key.clone(),
            verification_key: verf_key.clone(),
        };
        let mut payload_serial = Vec::new();
        safe_serialize(&payload, &mut payload_serial, SAFE_SER_SIZE_LIMIT).unwrap();
        let setup_msg1 = CustodianSetupMessage {
            custodian_role: 1,
            name: "Custodian-1".to_string(),
            payload: payload_serial.clone(),
        };
        let setup_msg2 = CustodianSetupMessage {
            custodian_role: 2,
            name: "Custodian-2".to_string(),
            payload: payload_serial.clone(),
        };
        let setup_msg3 = CustodianSetupMessage {
            custodian_role: 3,
            name: "Custodian-3".to_string(),
            payload: payload_serial.clone(),
        };
        let commitments = BTreeMap::new();
        let custodian_context = CustodianContext {
            custodian_nodes: vec![setup_msg1, setup_msg2, setup_msg3],
            context_id: Some(backup_id.into()),
            previous_context_id: None,
            threshold: 1,
        };
        let internal_custodian_context =
            InternalCustodianContext::new(custodian_context, enc_key).unwrap();
        let rvm =
            RecoveryValidationMaterial::new(commitments, internal_custodian_context, &sig_key)
                .unwrap();
        assert!(rvm.validate(&verf_key));
    }

    fn valid_custodian_msg(
        role: Role,
        enc_key: BackupPublicKey,
        verf_key: PublicSigKey,
    ) -> InternalCustodianSetupMessage {
        InternalCustodianSetupMessage {
            header: HEADER.to_owned(),
            custodian_role: role,
            random_value: [9_u8; 32],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            name: format!("custodian_{}", role.one_based()),
            public_enc_key: enc_key,
            public_verf_key: verf_key,
        }
    }

    #[test]
    fn operator_new_fails_with_bad_n_t() {
        let mut rng = AesRng::seed_from_u64(1);
        let (_, sig_key) = gen_sig_keys(&mut rng);
        // 1 is not less than 2/2
        let result = Operator::new(Role::indexed_from_one(1), vec![], sig_key, 1, 2);
        assert!(matches!(result, Err(BackupError::SetupError(_))));
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("t < n/2 is not satisfied"));
    }

    #[test]
    fn operator_new_fails_with_zero_t() {
        let mut rng = AesRng::seed_from_u64(2);
        let (_, sig_key) = gen_sig_keys(&mut rng);
        let result = Operator::new(Role::indexed_from_one(1), vec![], sig_key, 0, 2);
        assert!(matches!(result, Err(BackupError::SetupError(_))));
        assert!(result.err().unwrap().to_string().contains("t cannot be 0"));
    }

    #[test]
    fn operator_new_fails_with_zero_n() {
        let mut rng = AesRng::seed_from_u64(3);
        let (_, sig_key) = gen_sig_keys(&mut rng);
        let result = Operator::new(Role::indexed_from_one(1), vec![], sig_key, 1, 0);
        assert!(matches!(result, Err(BackupError::SetupError(_))));
        assert!(result.err().unwrap().to_string().contains("n cannot be 0"));
    }

    #[test]
    fn operator_new_fails_with_insufficient_messages() {
        let mut rng = AesRng::seed_from_u64(4);
        let (enc_key, _) = keygen(&mut rng).unwrap();
        let (verf_key, _) = gen_sig_keys(&mut rng);
        let msg = valid_custodian_msg(Role::indexed_from_one(1), enc_key.clone(), verf_key.clone());
        let (_, sig_key) = gen_sig_keys(&mut rng);
        let result = Operator::new(Role::indexed_from_one(1), vec![msg], sig_key, 1, 3);
        assert!(matches!(result, Err(BackupError::SetupError(_))));
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("Not enough custodian setup messages"));
    }

    #[tracing_test::traced_test]
    #[test]
    fn operator_new_fails_with_invalid_header() {
        let mut rng = AesRng::seed_from_u64(5);
        let (enc_key, _) = keygen(&mut rng).unwrap();
        let (verf_key, _) = gen_sig_keys(&mut rng);
        let mut msg1 =
            valid_custodian_msg(Role::indexed_from_one(1), enc_key.clone(), verf_key.clone());
        let msg2 =
            valid_custodian_msg(Role::indexed_from_one(2), enc_key.clone(), verf_key.clone());
        let msg3 =
            valid_custodian_msg(Role::indexed_from_one(3), enc_key.clone(), verf_key.clone());
        msg1.header = "wrong header".to_string();
        let (_, sig_key) = gen_sig_keys(&mut rng);
        let result = Operator::new(
            Role::indexed_from_one(1),
            vec![msg1, msg2, msg3],
            sig_key,
            1,
            3,
        );
        // The result is ok since we only fail in one message
        assert!(result.is_ok());
        assert!(logs_contain("Invalid header in custodian setup message"));
    }

    #[tracing_test::traced_test]
    #[test]
    fn operator_new_fails_with_invalid_timestamp_past() {
        let mut rng = AesRng::seed_from_u64(6);
        let (enc_key, _) = keygen(&mut rng).unwrap();
        let (verf_key, _) = gen_sig_keys(&mut rng);
        let mut msg1 =
            valid_custodian_msg(Role::indexed_from_one(1), enc_key.clone(), verf_key.clone());
        msg1.timestamp = 0; // too far in the past
        let msg2 =
            valid_custodian_msg(Role::indexed_from_one(2), enc_key.clone(), verf_key.clone());
        let msg3 =
            valid_custodian_msg(Role::indexed_from_one(3), enc_key.clone(), verf_key.clone());
        let (_, sig_key) = gen_sig_keys(&mut rng);
        let result = Operator::new(
            Role::indexed_from_one(1),
            vec![msg1.clone(), msg2.clone(), msg3.clone()],
            sig_key,
            1,
            3,
        );
        // The result is ok since we only fail in one message
        assert!(result.is_ok());
        assert!(logs_contain("Invalid timestamp in custodian setup message"));
    }

    #[tracing_test::traced_test]
    #[test]
    fn operator_new_fails_with_invalid_timestamp_future() {
        let mut rng = AesRng::seed_from_u64(6);
        let (enc_key, _) = keygen(&mut rng).unwrap();
        let (verf_key, _) = gen_sig_keys(&mut rng);
        let mut msg1 =
            valid_custodian_msg(Role::indexed_from_one(1), enc_key.clone(), verf_key.clone());
        let present = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        msg1.timestamp = present + 24 * 3600 + 2; // too far in the future by 2 seconds
        let msg2 =
            valid_custodian_msg(Role::indexed_from_one(2), enc_key.clone(), verf_key.clone());
        let msg3 =
            valid_custodian_msg(Role::indexed_from_one(3), enc_key.clone(), verf_key.clone());
        let (_, sig_key) = gen_sig_keys(&mut rng);
        let result = Operator::new(
            Role::indexed_from_one(1),
            vec![msg1.clone(), msg2.clone(), msg3.clone()],
            sig_key,
            1,
            3,
        );
        // The result is ok since we only fail in one message
        assert!(result.is_ok());
        assert!(logs_contain("Invalid timestamp in custodian setup message"));
    }

    #[tracing_test::traced_test]
    #[test]
    fn operator_new_fails_with_invalid_role() {
        let mut rng = AesRng::seed_from_u64(7);
        let (enc_key, _) = keygen(&mut rng).unwrap();
        let (verf_key, _) = gen_sig_keys(&mut rng);
        let msg1 = valid_custodian_msg(
            Role::indexed_from_one(10),
            enc_key.clone(),
            verf_key.clone(),
        );
        let msg2 = valid_custodian_msg(
            Role::indexed_from_one(11),
            enc_key.clone(),
            verf_key.clone(),
        );
        let msg3 = valid_custodian_msg(
            Role::indexed_from_one(12),
            enc_key.clone(),
            verf_key.clone(),
        );
        let (_, sig_key) = gen_sig_keys(&mut rng);
        let result = Operator::new(
            Role::indexed_from_one(1),
            vec![msg1.clone(), msg2.clone(), msg3.clone()],
            sig_key,
            1,
            3,
        );
        assert!(matches!(result, Err(BackupError::SetupError(_))));
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("Not enough valid custodian setup messages"));
        assert!(logs_contain(
            "Invalid custodian role in custodian setup message"
        ));
    }

    #[tracing_test::traced_test]
    #[test]
    fn operator_new_fails_with_duplicate_roles() {
        let mut rng = AesRng::seed_from_u64(8);
        let (enc_key, _) = keygen(&mut rng).unwrap();
        let (verf_key, _) = gen_sig_keys(&mut rng);
        let msg1 =
            valid_custodian_msg(Role::indexed_from_one(1), enc_key.clone(), verf_key.clone());
        let msg2 =
            valid_custodian_msg(Role::indexed_from_one(1), enc_key.clone(), verf_key.clone());
        let msg3 =
            valid_custodian_msg(Role::indexed_from_one(3), enc_key.clone(), verf_key.clone());
        let (_, sig_key) = gen_sig_keys(&mut rng);
        let result = Operator::new(
            Role::indexed_from_one(1),
            vec![msg1, msg2, msg3],
            sig_key,
            1,
            3,
        );
        assert!(logs_contain(
            "Duplicate custodian role in custodian setup message"
        ));
        // Things still pass since we have 2 custodians with unique roles
        assert!(result.is_ok());
    }

    #[tracing_test::traced_test]
    #[test]
    fn operator_new_fails_with_not_enough() {
        let mut rng = AesRng::seed_from_u64(8);
        let (enc_key, _) = keygen(&mut rng).unwrap();
        let (verf_key, _) = gen_sig_keys(&mut rng);
        let msg1 =
            valid_custodian_msg(Role::indexed_from_one(1), enc_key.clone(), verf_key.clone());
        let msg2 =
            valid_custodian_msg(Role::indexed_from_one(1), enc_key.clone(), verf_key.clone());
        let msg3 =
            valid_custodian_msg(Role::indexed_from_one(1), enc_key.clone(), verf_key.clone());
        let (_, sig_key) = gen_sig_keys(&mut rng);
        let result = Operator::new(
            Role::indexed_from_one(1),
            vec![msg1, msg2, msg3],
            sig_key,
            1,
            3,
        );
        assert!(matches!(result, Err(BackupError::SetupError(_))));
        assert!(logs_contain(
            "Duplicate custodian role in custodian setup message"
        ));
        // Everyone shares the same role
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("Not enough valid custodian setup messages"));
    }
}
