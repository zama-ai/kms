use super::{
    custodian::{HEADER, InternalCustodianSetupMessage},
    error::{BackupError, SetupSkipReason},
    secretsharing,
};
use crate::backup::{
    custodian::{InternalCustodianContext, InternalCustodianRecoveryOutput},
    error::RecoverySkipReason,
};
use crate::{
    anyhow_error_and_log,
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::encryption::{UnifiedPrivateEncKey, UnifiedPublicEncKey},
    cryptography::signatures::{PrivateSigKey, PublicSigKey, Signature},
    cryptography::signcryption::{
        Signcrypt, UnifiedSigncryption, UnifiedSigncryptionKey, UnifiedUnsigncryptionKey,
        Unsigncrypt,
    },
    engine::base::safe_serialize_hash_element_versioned,
};
use crate::{
    backup::custodian::DSEP_BACKUP_CUSTODIAN,
    cryptography::signatures::{internal_sign, internal_verify_sig},
};
use algebra::{
    galois_rings::degree_4::ResiduePolyF4Z64,
    sharing::{shamir::ShamirSharings, share::Share},
};
use hashing::DomainSep;
use kms_grpc::{
    ContextId, RequestId,
    kms::v1::{OperatorBackupOutput, RecoveryRequest},
};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
    time::{SystemTime, UNIX_EPOCH},
};
use tfhe::{named::Named, safe_serialization::safe_deserialize};
use tfhe_versionable::{Versionize, VersionsDispatch};
use threshold_types::role::Role;

pub const DSEP_BACKUP_COMMITMENT: DomainSep = *b"BKUPCOMM";
pub(crate) const DSEP_BACKUP_RECOVERY: DomainSep = *b"BKUPRECO";
const TIMESTAMP_VALIDATION_WINDOW_SECS: u64 = 24 * 3600; // 1 day

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, VersionsDispatch)]
pub enum InternalRecoveryRequestVersioned {
    V0(InternalRecoveryRequest),
}

impl Named for InternalRecoveryRequest {
    const NAME: &'static str = "backup::InternalRecoveryRequest";
}

/// The backup data returned to the custodians during recovery.
/// WARNING: It is crucial that this is transported safely as it does not
/// contain any authentication on the backup encryption key [`ephem_op_enc_key`].
/// This is because we have to assume that the operator has no access to the private storage
/// when creating this object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(InternalRecoveryRequestVersioned)]
pub struct InternalRecoveryRequest {
    ephem_op_enc_key: UnifiedPublicEncKey,
    cts: BTreeMap<Role, InnerOperatorBackupOutput>,
}

impl InternalRecoveryRequest {
    /// Optimistically create a new internal recovery request, WITHOUT validating it against the custodians' unsigncryption keys.
    pub fn new(
        ephem_op_enc_key: UnifiedPublicEncKey,
        cts: BTreeMap<Role, InnerOperatorBackupOutput>,
    ) -> anyhow::Result<Self> {
        let res = InternalRecoveryRequest {
            ephem_op_enc_key,
            cts,
        };
        Ok(res)
    }

    /// Validate that the data in the request is sensible.
    pub fn is_valid(
        &self,
        custodian_role: Role,
        unsigncrypt_key: &UnifiedUnsigncryptionKey,
    ) -> anyhow::Result<bool> {
        let output = match self.cts.get(&custodian_role) {
            Some(output) => output,
            None => {
                tracing::warn!(
                    "InternalRecoveryRequest is missing ciphertext for custodian role {}",
                    custodian_role
                );
                return Ok(false);
            }
        };
        // We ignore the result, but just ensure that unsigncryption works
        if unsigncrypt_key
            .validate_signcryption(&DSEP_BACKUP_CUSTODIAN, &output.signcryption)
            .is_err()
        {
            tracing::warn!("InternalRecoveryRequest contains an invalid signcryption");
            return Ok(false);
        }
        Ok(true)
    }

    pub fn backup_enc_key(&self) -> &UnifiedPublicEncKey {
        &self.ephem_op_enc_key
    }

    pub fn signcryptions(&self) -> HashMap<Role, &InnerOperatorBackupOutput> {
        self.cts.iter().map(|(role, ct)| (*role, ct)).collect()
    }
}

impl Display for InternalRecoveryRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InternalRecoveryRequest",)
    }
}

impl TryFrom<RecoveryRequest> for InternalRecoveryRequest {
    type Error = anyhow::Error;

    fn try_from(value: RecoveryRequest) -> Result<InternalRecoveryRequest, Self::Error> {
        let ephem_op_enc_key: UnifiedPublicEncKey = safe_deserialize(
            std::io::Cursor::new(&value.ephem_op_enc_key),
            SAFE_SER_SIZE_LIMIT,
        )
        .map_err(|e| anyhow_error_and_log(format!("Could not deserialize enc_key: {e:?}")))?;
        let mut cts = BTreeMap::new();
        for (cur_role_idx, cur_backup_out) in value.cts {
            let role = Role::indexed_from_one(cur_role_idx as usize);
            let inner_ct: InnerOperatorBackupOutput = cur_backup_out.try_into()?;
            cts.insert(role, inner_ct);
        }
        Ok(Self {
            ephem_op_enc_key,
            cts,
        })
    }
}

#[derive(Clone)]
pub struct Operator {
    custodian_keys: HashMap<Role, (UnifiedPublicEncKey, PublicSigKey)>,
    signing_key: Option<PrivateSigKey>,
    // the public component of [signing_key] above
    verification_key: PublicSigKey,
    threshold: usize,
}

impl std::fmt::Debug for Operator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Operator")
            .field("custodian_keys", &self.custodian_keys)
            .field("signing_key", &"ommitted")
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
    pub signcryption: UnifiedSigncryption,
}

impl Named for InnerOperatorBackupOutput {
    const NAME: &'static str = "backup::InnerOperatorBackupOutput";
}

impl TryFrom<OperatorBackupOutput> for InnerOperatorBackupOutput {
    type Error = anyhow::Error;

    fn try_from(value: OperatorBackupOutput) -> Result<Self, Self::Error> {
        Ok(Self {
            signcryption: UnifiedSigncryption {
                payload: value.signcryption,
                pke_type: value.pke_type.try_into()?,
                signing_type: value.signing_type.try_into()?,
            },
        })
    }
}
impl TryFrom<InnerOperatorBackupOutput> for OperatorBackupOutput {
    type Error = anyhow::Error;

    fn try_from(value: InnerOperatorBackupOutput) -> Result<Self, Self::Error> {
        Ok(Self {
            signcryption: value.signcryption.payload,
            pke_type: value.signcryption.pke_type as i32,
            signing_type: value.signcryption.signing_type as i32,
        })
    }
}

/// Result of [`Operator::secret_share_and_signcrypt`] including roles that
/// were skipped because no custodian key was available.
#[derive(Debug, Clone)]
pub struct SigncryptResult {
    pub ct_shares: BTreeMap<Role, InnerOperatorBackupOutput>,
    pub commitments: BTreeMap<Role, Vec<u8>>,
    pub skipped_roles: Vec<Role>,
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

/// The data stored by an operator after a custodian context switch.
/// The data contains the contains the signcrypted shares for each custodian
/// along with information about the custodians.
/// Furthermore, the data is signed by the operator to allow it to verify the
/// data upon load.
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
        cts: BTreeMap<Role, InnerOperatorBackupOutput>,
        commitments: BTreeMap<Role, Vec<u8>>,
        custodian_context: InternalCustodianContext,
        sk: &PrivateSigKey,
        mpc_context: ContextId,
    ) -> anyhow::Result<Self> {
        if custodian_context.custodian_nodes.len() != cts.len() {
            return Err(anyhow::anyhow!(
                "Mismatch between number of custodian nodes ({}) and number of backup signcrypted shares ({})",
                custodian_context.custodian_nodes.len(),
                cts.len()
            ));
        }
        for role in 1..=custodian_context.custodian_nodes.len() {
            let r = Role::indexed_from_one(role);
            if !cts.contains_key(&r) {
                return Err(anyhow::anyhow!(
                    "Missing backup signcrypted share for custodian role {}",
                    role
                ));
            }
        }
        let payload = RecoveryValidationMaterialPayload {
            cts,
            commitments,
            custodian_context,
            mpc_context,
        };
        let serialized_payload = bc2wrap::serialize(&payload).map_err(|e| {
            anyhow_error_and_log(format!("Could not serialize inner recovery request: {e:?}"))
        })?;
        let signature = &internal_sign(&DSEP_BACKUP_RECOVERY, &serialized_payload, sk)?;
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

    pub fn mpc_context(&self) -> ContextId {
        self.payload.mpc_context
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
    /// The signcrypted shares of the operators' private backup decryption key towards each custodian.
    /// I.e. the key to the map is the role of the custodian.
    pub cts: BTreeMap<Role, InnerOperatorBackupOutput>,
    /// The commitments to each operator's share, secret shared to each custodian. Hence custodian indexed
    pub commitments: BTreeMap<Role, Vec<u8>>,
    /// The custodian context used during backup
    pub custodian_context: InternalCustodianContext,
    /// The MPC context used when constructing the backup (i.e. identifying the verification key of the operator)
    pub mpc_context: ContextId,
}
impl Named for RecoveryValidationMaterialPayload {
    const NAME: &'static str = "backup::RecoveryValidationMaterialPayload";
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum BackupMaterialVersioned {
    V0(BackupMaterial),
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(BackupMaterialVersioned)]
pub struct BackupMaterial {
    /// The custodian context this backup is associated with.
    pub backup_id: RequestId,
    /// The MPC context this backup was produced under.
    pub mpc_context_id: ContextId,
    // receiver
    pub custodian_pk: PublicSigKey,
    pub custodian_role: Role,
    // sender
    pub operator_pk: PublicSigKey,
    pub shares: Vec<Share<ResiduePolyF4Z64>>,
}

impl BackupMaterial {
    /// Verify the operator-/custodian-bound metadata fields of a freshly unsigncrypted
    /// `BackupMaterial` against the expected routing parameters.
    pub fn check_expected_metadata(
        &self,
        custodian_verf_key: &PublicSigKey,
        custodian_role: Role,
        operator_pk_id: &[u8],
    ) -> Result<(), RecoverySkipReason> {
        if self.custodian_role != custodian_role {
            tracing::error!(
                "custodian_role mismatch: expected {} but got {}",
                self.custodian_role,
                custodian_role
            );
            return Err(RecoverySkipReason::CustodianRoleMismatchInPayload);
        }
        if &self.custodian_pk != custodian_verf_key {
            tracing::error!("custodian_pk mismatch");
            return Err(RecoverySkipReason::CustodianKeyMismatchInPayload);
        }
        if self.operator_pk.verf_key_id() != operator_pk_id {
            tracing::error!("operator_pk_id mismatch");
            return Err(RecoverySkipReason::OperatorMismatchInPayload);
        }
        Ok(())
    }
}

impl Named for BackupMaterial {
    const NAME: &'static str = "backup::BackupShares";
}

impl Operator {
    /// Construct a new Operator for creating backups.
    /// This requires a signing key.
    /// Futhermore, this will also require validating the timestamps of the custodian setup messages.
    /// This is done in this method.
    /// If you want to create an operator for recovery/restore operations (which does not require a signing key), use [Self::new_for_validating]
    /// as this method does not require a signing key, nor will it validate (the likely expired) timestamps.
    pub fn new_for_sharing(
        custodian_messages: Vec<InternalCustodianSetupMessage>,
        signing_key: PrivateSigKey,
        threshold: usize,
        amount_custodians: usize,
    ) -> Result<Self, BackupError> {
        let verf_key = signing_key.verf_key();
        let validated =
            validate_custodian_messages(custodian_messages, threshold, amount_custodians, true)?;
        Ok(Self {
            custodian_keys: validated.keys,
            signing_key: Some(signing_key),
            verification_key: verf_key,
            threshold,
        })
    }

    /// Construct a new Operator for validating backups.
    /// This does not require a signing key.
    /// Furthermore, this will not validate the timestamps of the custodian setup messages.
    pub fn new_for_validating(
        custodian_messages: Vec<InternalCustodianSetupMessage>,
        verf_key: PublicSigKey,
        threshold: usize,
        amount_custodians: usize,
    ) -> Result<Self, BackupError> {
        let validated =
            validate_custodian_messages(custodian_messages, threshold, amount_custodians, false)?;
        Ok(Self {
            custodian_keys: validated.keys,
            signing_key: None,
            verification_key: verf_key,
            threshold,
        })
    }

    pub fn verification_key(&self) -> &PublicSigKey {
        &self.verification_key
    }

    #[cfg(test)]
    pub fn num_custodian_keys(&self) -> usize {
        self.custodian_keys.len()
    }

    // We allow the following lints because we are fine with mutating the rng even if
    // the function fails afterwards.
    #[allow(unknown_lints)]
    #[allow(non_local_effect_before_error_return)]
    /// Construct a secret sharing of a `secret` and return a map of the basic backup recovery material,
    /// indexed by the role of each custodian. Also return a map of each commitment to the secret share,
    /// indexed by the role of each custodian.
    /// The payload is then signcrypted
    pub fn secret_share_and_signcrypt<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        secret: &[u8],
        backup_id: RequestId,
        mpc_context_id: ContextId,
    ) -> Result<SigncryptResult, BackupError> {
        let sk = match &self.signing_key {
            None => {
                return Err(BackupError::OperatorError(
                    "Operator has no signing key".to_string(),
                ));
            }
            Some(sk) => sk,
        };
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
        // 4.1 Player `P_i` signcrypts `s_ij` to custodian `B_j` to get `ct_ij = Signcrypt(sk^{S_i}, pk^{E_j}, s_ij)`.
        // 4.2 Commit to all the shares `c_ij = Commit(s_ij)`.
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
        let mut skipped_roles: Vec<Role> = Vec::new();

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
            let (cus_enc_key, custodian_verf_key) = match self.custodian_keys.get(&role_j) {
                Some((enc_pk, sig_pk)) => (enc_pk, sig_pk),
                None => {
                    // Note that we do not error out since we might now have gotten all the expected correct custodian setup messages
                    tracing::warn!("Could not find custodian keys for role {role_j}");
                    skipped_roles.push(role_j);
                    continue;
                }
            };
            let backup_material = BackupMaterial {
                backup_id,
                mpc_context_id,
                custodian_pk: custodian_verf_key.clone(),
                custodian_role: role_j,
                operator_pk: self.verification_key.clone(),
                shares,
            };
            let custodian_verf_id = custodian_verf_key.verf_key_id();
            let signcryption_key = UnifiedSigncryptionKey::new(sk, cus_enc_key, &custodian_verf_id);
            let signcryption = signcryption_key
                .signcrypt(rng, &DSEP_BACKUP_CUSTODIAN, &backup_material)
                .map_err(BackupError::InternalCryptographyError)?;
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
            ct_shares.insert(role_j, InnerOperatorBackupOutput { signcryption });
            commitments.insert(role_j, msg_digest);
        }

        if ct_shares.len() < self.threshold + 1 {
            return Err(BackupError::OperatorError(format!(
                "Not enough valid custodian shares were created: expected at least {} but got {}, skipped roles: {skipped_roles:?}",
                self.threshold + 1,
                ct_shares.len()
            )));
        }
        // 6. The commitments are stored by `P_i` and can be used to verify the shares later.
        Ok(SigncryptResult {
            ct_shares,
            commitments,
            skipped_roles,
        })
    }

    /// Validate a single signcrypted custodian recovery output.
    ///
    /// Runs every check the operator-side recovery path requires: unsigncryption (which also
    /// enforces the signcryption's receiver-id binding), `backup_id` / `mpc_context_id` validity +
    /// equality against the operator-signed `RecoveryValidationMaterial`, custodian / operator key
    /// equality inside the decrypted payload, and the commitment match. Returns the precise
    /// `RecoverySkipReason` on the first failure.
    pub(crate) fn validate_one_recovery_output(
        &self,
        output: &InternalCustodianRecoveryOutput,
        recovery_material: &RecoveryValidationMaterial,
        ephm_dec_key: &UnifiedPrivateEncKey,
        ephm_enc_key: &UnifiedPublicEncKey,
    ) -> Result<BackupMaterial, RecoverySkipReason> {
        let (_, custodian_verf_key) = self.custodian_keys.get(&output.custodian_role).ok_or({
            tracing::warn!("missing custodian key for role {}", output.custodian_role);
            RecoverySkipReason::MissingVerificationKey
        })?;
        let operator_id = self.verification_key.verf_key_id();
        let unsign_key = UnifiedUnsigncryptionKey::new(
            ephm_dec_key,
            ephm_enc_key,
            custodian_verf_key,
            &operator_id,
        );
        let backup_material: BackupMaterial = unsign_key
            .unsigncrypt(&DSEP_BACKUP_RECOVERY, &output.signcryption)
            .map_err(|e| {
                tracing::warn!(
                    "Could not unsigncrypt backup share for custodian role {} (wrong operator or tampered): {e}",
                    output.custodian_role
                );
                RecoverySkipReason::InvalidSigncryption
            })?;
        let expected_backup_id: RequestId = recovery_material.custodian_context().context_id;
        let expected_mpc_context_id = recovery_material.mpc_context();
        if !backup_material.backup_id.is_valid() {
            tracing::warn!(
                "BackupMaterial.backup_id {} is malformed for custodian role {}",
                backup_material.backup_id,
                output.custodian_role
            );
            return Err(RecoverySkipReason::BackupIdMalformed);
        }
        if !backup_material.mpc_context_id.is_valid() {
            tracing::warn!(
                "BackupMaterial.mpc_context_id {} is malformed for custodian role {}",
                backup_material.mpc_context_id,
                output.custodian_role
            );
            return Err(RecoverySkipReason::MpcContextIdMalformed);
        }
        if backup_material.backup_id != expected_backup_id {
            tracing::warn!(
                "BackupMaterial.backup_id mismatch for custodian role {}: expected {} got {}",
                output.custodian_role,
                expected_backup_id,
                backup_material.backup_id
            );
            return Err(RecoverySkipReason::BackupIdMismatch);
        }
        if backup_material.mpc_context_id != expected_mpc_context_id {
            tracing::warn!(
                "BackupMaterial.mpc_context_id mismatch for custodian role {}: expected {} got {}",
                output.custodian_role,
                expected_mpc_context_id,
                backup_material.mpc_context_id
            );
            return Err(RecoverySkipReason::MpcContextIdMismatch);
        }
        if let Err(mismatch) = backup_material.check_expected_metadata(
            custodian_verf_key,
            output.custodian_role,
            &operator_id,
        ) {
            tracing::warn!(
                "Metadata check ({mismatch:?}) failed for custodian role {}",
                output.custodian_role
            );
            return Err(mismatch);
        }
        let actual_commitment =
            safe_serialize_hash_element_versioned(&DSEP_BACKUP_COMMITMENT, &backup_material)
                .map_err(|e| {
                    tracing::warn!(
                        "Could not hash BackupMaterial for commitment check (role {}): {e}",
                        output.custodian_role
                    );
                    RecoverySkipReason::ParseError
                })?;
        let expected_commitment = recovery_material.get(&output.custodian_role).map_err(|_| {
            tracing::warn!(
                "No stored commitment for custodian role {}",
                output.custodian_role
            );
            RecoverySkipReason::MissingVerificationKey
        })?;
        if actual_commitment.as_slice() != expected_commitment {
            tracing::warn!(
                "Commitment mismatch for custodian role {}: BackupMaterial hash does not match the operator-signed commitment",
                output.custodian_role
            );
            return Err(RecoverySkipReason::CommitmentMismatch);
        }
        Ok(backup_material)
    }

    /// Validate every signcrypted custodian recovery output and reconstruct the operator's secret.
    pub fn verify_and_recover(
        &self,
        custodian_recovery_output: &[InternalCustodianRecoveryOutput],
        recovery_material: &RecoveryValidationMaterial,
        ephm_dec_key: &UnifiedPrivateEncKey,
        ephm_enc_key: &UnifiedPublicEncKey,
    ) -> Result<Vec<u8>, BackupError> {
        let mut validated: HashMap<Role, BackupMaterial> = HashMap::new();
        let mut skip_reasons: Vec<RecoverySkipReason> = Vec::new();
        for output in custodian_recovery_output {
            match self.validate_one_recovery_output(
                output,
                recovery_material,
                ephm_dec_key,
                ephm_enc_key,
            ) {
                Ok(bm) => match validated.entry(output.custodian_role) {
                    std::collections::hash_map::Entry::Occupied(_) => {
                        tracing::warn!(
                            "Received multiple recovery outputs for custodian role {}. Only the first one will be used.",
                            output.custodian_role
                        );
                        skip_reasons.push(RecoverySkipReason::DuplicateRole);
                    }
                    std::collections::hash_map::Entry::Vacant(v) => {
                        v.insert(bm);
                    }
                },
                Err(reason) => skip_reasons.push(reason),
            }
        }
        let threshold = recovery_material.custodian_context().threshold as usize;
        let required_min = threshold + 1;
        if validated.len() < required_min {
            let received = validated.len();
            tracing::error!(
                received,
                threshold,
                ?skip_reasons,
                "Cannot recover the backup decryption key: not enough valid recovery outputs"
            );
            return Err(BackupError::RecoveryThresholdNotMet {
                required_min,
                received,
                threshold,
                skipped: skip_reasons,
            });
        }
        self.recover_from_validated(&validated)
    }

    /// Reconstruct the operator's secret from already-validated per-role `BackupMaterial`s.
    pub fn recover_from_validated(
        &self,
        validated: &HashMap<Role, BackupMaterial>,
    ) -> Result<Vec<u8>, BackupError> {
        let decrypted_buf: Vec<&Vec<Share<ResiduePolyF4Z64>>> =
            validated.values().map(|bm| &bm.shares).collect();

        let num_blocks = if let Some(x) = decrypted_buf.iter().map(|v| v.len()).min() {
            x
        } else {
            return Err(BackupError::NoBlocksError);
        };

        let mut all_sharings = vec![];
        for b in 0..num_blocks {
            let mut shamir_sharing = ShamirSharings::new();
            for blocks in decrypted_buf.iter() {
                shamir_sharing.add_share(blocks[b]);
            }
            all_sharings.push(shamir_sharing);
        }
        let out = secretsharing::reconstruct(all_sharings, self.threshold)?;
        Ok(out)
    }
}

/// Helper function to validate custodian setup messages and parameters.
/// The function returns a HashMap mapping the valid custodian roles to their encryption and verification keys.
/// That is, the method precludes any invalid custodian messages, and returns an error if not enough valid.
/// Successful result from [`validate_custodian_messages`] carrying both the
/// validated keys and the reasons any messages were skipped.
#[derive(Debug)]
struct CustodianValidationResult {
    keys: HashMap<Role, (UnifiedPublicEncKey, PublicSigKey)>,
    #[cfg_attr(not(test), allow(dead_code))]
    skip_reasons: Vec<SetupSkipReason>,
}

fn validate_custodian_messages(
    custodian_messages: Vec<InternalCustodianSetupMessage>,
    threshold: usize,
    amount_custodians: usize,
    validate_timestamps: bool,
) -> Result<CustodianValidationResult, BackupError> {
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
    let mut skip_reasons: Vec<SetupSkipReason> = Vec::new();
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

        if validate_timestamps {
            tracing::debug!(
                "Validating timestamp {} in custodian setup message from custodian {}",
                timestamp,
                custodian_role
            );
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            if !(now.saturating_sub(TIMESTAMP_VALIDATION_WINDOW_SECS) < timestamp
                && timestamp < now.saturating_add(TIMESTAMP_VALIDATION_WINDOW_SECS))
            {
                tracing::warn!(
                    "Invalid timestamp in custodian setup message from custodian {}: expected within {} seconds of now, but got {}",
                    custodian_role,
                    TIMESTAMP_VALIDATION_WINDOW_SECS,
                    timestamp
                );
                skip_reasons.push(SetupSkipReason::InvalidTimestamp);
                continue;
            }
        }
        if header != HEADER {
            tracing::warn!(
                "Invalid header in custodian setup message from custodian {custodian_role}. Expected header {HEADER} but got {header}"
            );
            skip_reasons.push(SetupSkipReason::InvalidHeader);
            continue;
        }

        if custodian_role.one_based() > amount_custodians {
            tracing::warn!(
                "Invalid custodian role in custodian setup message: {custodian_role}. Expected role between 1 and {amount_custodians}"
            );
            skip_reasons.push(SetupSkipReason::InvalidRole);
            continue;
        }

        if let Some(old_val) =
            custodian_keys.insert(custodian_role, (public_enc_key, public_verf_key))
        {
            tracing::warn!(
                "Duplicate custodian role in custodian setup message: {custodian_role}. Will use first value for this role"
            );
            let _ = custodian_keys.insert(custodian_role, old_val);
            skip_reasons.push(SetupSkipReason::DuplicateRole);
            continue;
        }
    }
    if custodian_keys.len() < threshold + 1 {
        let expected_min = threshold + 1;
        let received = custodian_keys.len();
        tracing::error!(
            expected_min,
            received,
            ?skip_reasons,
            "Not enough valid custodian setup messages"
        );
        return Err(BackupError::SetupValidationFailed {
            expected_min,
            received,
            skipped: skip_reasons,
        });
    }
    Ok(CustodianValidationResult {
        keys: custodian_keys,
        skip_reasons,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backup::{custodian::CustodianSetupMessagePayload, operator::RecoveryValidationMaterial},
        consts::DEFAULT_MPC_CONTEXT,
        cryptography::{
            encryption::{Encryption, PkeScheme, PkeSchemeType},
            signatures::{SigningSchemeType, gen_sig_keys},
        },
        engine::base::derive_request_id,
    };
    use aes_prng::AesRng;
    use kms_grpc::kms::v1::{CustodianContext, CustodianSetupMessage};
    use rand::SeedableRng;
    use tfhe::safe_serialization::safe_serialize;

    #[test]
    fn validate_recovery_validation_material() {
        let mut rng = AesRng::seed_from_u64(0);
        let (verf_key, sig_key) = gen_sig_keys(&mut rng);
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_dec_key, enc_key) = encryption.keygen().unwrap();
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
        let mut commitments = BTreeMap::new();
        commitments.insert(Role::indexed_from_one(1), vec![1_u8; 32]);
        commitments.insert(Role::indexed_from_one(2), vec![2_u8; 32]);
        commitments.insert(Role::indexed_from_one(3), vec![3_u8; 32]);
        let mut cts = BTreeMap::new();
        let cts_out = InnerOperatorBackupOutput {
            signcryption: UnifiedSigncryption {
                payload: vec![1, 2, 3],
                pke_type: PkeSchemeType::MlKem512,
                signing_type: SigningSchemeType::Ecdsa256k1,
            },
        };
        cts.insert(Role::indexed_from_one(1), cts_out.clone());
        cts.insert(Role::indexed_from_one(2), cts_out.clone());
        cts.insert(Role::indexed_from_one(3), cts_out.clone());
        let custodian_context = CustodianContext {
            custodian_nodes: vec![setup_msg1, setup_msg2, setup_msg3],
            custodian_context_id: Some(backup_id.into()),
            threshold: 1,
        };
        let internal_custodian_context =
            InternalCustodianContext::new(custodian_context, enc_key).unwrap();
        let rvm = RecoveryValidationMaterial::new(
            cts,
            commitments,
            internal_custodian_context,
            &sig_key,
            *DEFAULT_MPC_CONTEXT,
        )
        .unwrap();
        assert!(rvm.validate(&verf_key));
    }

    fn valid_custodian_msg(
        role: Role,
        enc_key: UnifiedPublicEncKey,
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

    fn expect_setup_validation_failed(err: BackupError) -> (usize, Vec<SetupSkipReason>) {
        match err {
            BackupError::SetupValidationFailed {
                received, skipped, ..
            } => (received, skipped),
            other => {
                panic!("expected SetupValidationFailed, got: {other}");
            }
        }
    }

    #[test]
    fn operator_new_fails_with_bad_n_t() {
        // 1 is not less than 2/2
        let result = validate_custodian_messages(vec![], 1, 2, true);
        assert!(matches!(result, Err(BackupError::SetupError(_))));
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("t < n/2 is not satisfied")
        );
    }

    #[test]
    fn operator_new_fails_with_zero_t() {
        let result = validate_custodian_messages(vec![], 0, 2, true);
        assert!(matches!(result, Err(BackupError::SetupError(_))));
        assert!(result.err().unwrap().to_string().contains("t cannot be 0"));
    }

    #[test]
    fn operator_new_fails_with_zero_n() {
        let result = validate_custodian_messages(vec![], 1, 0, true);
        assert!(matches!(result, Err(BackupError::SetupError(_))));
        assert!(result.err().unwrap().to_string().contains("n cannot be 0"));
    }

    #[test]
    fn operator_new_fails_with_insufficient_messages() {
        let mut rng = AesRng::seed_from_u64(4);
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_dec_key, enc_key) = encryption.keygen().unwrap();
        let (verf_key, _) = gen_sig_keys(&mut rng);
        let msg = valid_custodian_msg(Role::indexed_from_one(1), enc_key.clone(), verf_key.clone());
        let result = validate_custodian_messages(vec![msg], 1, 3, true);
        assert!(matches!(result, Err(BackupError::SetupError(_))));
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("Not enough custodian setup messages")
        );
    }

    #[test]
    fn operator_new_fails_with_invalid_header() {
        let mut rng = AesRng::seed_from_u64(5);
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_dec_key, enc_key) = encryption.keygen().unwrap();
        let (verf_key, _) = gen_sig_keys(&mut rng);
        let mut msg1 =
            valid_custodian_msg(Role::indexed_from_one(1), enc_key.clone(), verf_key.clone());
        let msg2 =
            valid_custodian_msg(Role::indexed_from_one(2), enc_key.clone(), verf_key.clone());
        let msg3 =
            valid_custodian_msg(Role::indexed_from_one(3), enc_key.clone(), verf_key.clone());
        msg1.header = "wrong header".to_string();
        let result = validate_custodian_messages(vec![msg1, msg2, msg3], 1, 3, true).unwrap();
        assert_eq!(result.keys.len(), 2);
        assert!(
            !result.keys.contains_key(&Role::indexed_from_one(1)),
            "Role 1 with invalid header should have been filtered"
        );
        assert!(
            result
                .skip_reasons
                .contains(&SetupSkipReason::InvalidHeader),
            "expected InvalidHeader in skip reasons: {:?}",
            result.skip_reasons
        );
    }

    #[test]
    fn operator_new_fails_with_invalid_timestamp_past() {
        let mut rng = AesRng::seed_from_u64(6);
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_dec_key, enc_key) = encryption.keygen().unwrap();
        let (verf_key, _) = gen_sig_keys(&mut rng);
        let mut msg1 =
            valid_custodian_msg(Role::indexed_from_one(1), enc_key.clone(), verf_key.clone());
        msg1.timestamp = 0; // too far in the past
        let msg2 =
            valid_custodian_msg(Role::indexed_from_one(2), enc_key.clone(), verf_key.clone());
        let msg3 =
            valid_custodian_msg(Role::indexed_from_one(3), enc_key.clone(), verf_key.clone());
        let result = validate_custodian_messages(vec![msg1, msg2, msg3], 1, 3, true).unwrap();
        assert_eq!(result.keys.len(), 2);
        assert!(
            !result.keys.contains_key(&Role::indexed_from_one(1)),
            "Role 1 with past timestamp should have been filtered"
        );
        assert!(
            result
                .skip_reasons
                .contains(&SetupSkipReason::InvalidTimestamp),
            "expected InvalidTimestamp in skip reasons: {:?}",
            result.skip_reasons
        );
    }

    #[test]
    fn operator_new_fails_with_invalid_timestamp_future() {
        let mut rng = AesRng::seed_from_u64(6);
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_dec_key, enc_key) = encryption.keygen().unwrap();
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
        let result = validate_custodian_messages(vec![msg1, msg2, msg3], 1, 3, true).unwrap();
        assert_eq!(result.keys.len(), 2);
        assert!(
            !result.keys.contains_key(&Role::indexed_from_one(1)),
            "Role 1 with future timestamp should have been filtered"
        );
        assert!(
            result
                .skip_reasons
                .contains(&SetupSkipReason::InvalidTimestamp),
            "expected InvalidTimestamp in skip reasons: {:?}",
            result.skip_reasons
        );
    }

    #[test]
    fn operator_timestamp_validation() {
        let mut rng = AesRng::seed_from_u64(5);
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_dec_key, enc_key) = encryption.keygen().unwrap();
        let (verf_key, _) = gen_sig_keys(&mut rng);
        let present = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut msg1 =
            valid_custodian_msg(Role::indexed_from_one(1), enc_key.clone(), verf_key.clone());
        msg1.timestamp = present + 24 * 3600 + 2; // too far in the future by 2 seconds
        let mut msg2 =
            valid_custodian_msg(Role::indexed_from_one(2), enc_key.clone(), verf_key.clone());
        msg2.timestamp = present + 24 * 3600 + 2; // too far in the future by 2 seconds
        let mut msg3 =
            valid_custodian_msg(Role::indexed_from_one(3), enc_key.clone(), verf_key.clone());
        msg3.timestamp = present + 24 * 3600 + 2; // too far in the future by 2 seconds
        let result = validate_custodian_messages(vec![msg1, msg2, msg3], 1, 3, false).unwrap();
        assert_eq!(result.keys.len(), 3);
        assert!(
            result.skip_reasons.is_empty(),
            "no messages should be skipped when timestamp validation is off: {:?}",
            result.skip_reasons
        );
    }

    #[test]
    fn operator_new_fails_with_invalid_role() {
        let mut rng = AesRng::seed_from_u64(7);
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_dec_key, enc_key) = encryption.keygen().unwrap();
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
        let (received, skipped) = expect_setup_validation_failed(
            validate_custodian_messages(vec![msg1, msg2, msg3], 1, 3, true).unwrap_err(),
        );
        assert_eq!(received, 0);
        assert!(
            skipped.contains(&SetupSkipReason::InvalidRole),
            "expected InvalidRole in skip reasons: {skipped:?}"
        );
    }

    #[test]
    fn operator_new_fails_with_duplicate_roles() {
        let mut rng = AesRng::seed_from_u64(8);
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_dec_key, enc_key) = encryption.keygen().unwrap();
        let (verf_key, _) = gen_sig_keys(&mut rng);
        let msg1 =
            valid_custodian_msg(Role::indexed_from_one(1), enc_key.clone(), verf_key.clone());
        let msg2 =
            valid_custodian_msg(Role::indexed_from_one(1), enc_key.clone(), verf_key.clone());
        let msg3 =
            valid_custodian_msg(Role::indexed_from_one(3), enc_key.clone(), verf_key.clone());
        let result = validate_custodian_messages(vec![msg1, msg2, msg3], 1, 3, true).unwrap();
        assert_eq!(result.keys.len(), 2);
        assert!(
            result.keys.contains_key(&Role::indexed_from_one(1)),
            "Role 1 should be present (first occurrence kept)"
        );
        assert!(
            result.keys.contains_key(&Role::indexed_from_one(3)),
            "Role 3 should be present"
        );
        assert!(
            result
                .skip_reasons
                .contains(&SetupSkipReason::DuplicateRole),
            "expected DuplicateRole in skip reasons: {:?}",
            result.skip_reasons
        );
    }

    #[test]
    fn operator_new_fails_with_not_enough() {
        let mut rng = AesRng::seed_from_u64(8);
        let mut encryption = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_dec_key, enc_key) = encryption.keygen().unwrap();
        let (verf_key, _) = gen_sig_keys(&mut rng);
        let msg1 =
            valid_custodian_msg(Role::indexed_from_one(1), enc_key.clone(), verf_key.clone());
        let msg2 =
            valid_custodian_msg(Role::indexed_from_one(1), enc_key.clone(), verf_key.clone());
        let msg3 =
            valid_custodian_msg(Role::indexed_from_one(1), enc_key.clone(), verf_key.clone());
        let (received, skipped) = expect_setup_validation_failed(
            validate_custodian_messages(vec![msg1, msg2, msg3], 1, 3, true).unwrap_err(),
        );
        assert_eq!(received, 1);
        assert!(
            skipped.contains(&SetupSkipReason::DuplicateRole),
            "expected DuplicateRole in skip reasons: {skipped:?}"
        );
    }
}
