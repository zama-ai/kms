use super::{
    custodian::{
        CustodianRecoveryOutput, InternalCustodianSetupMessage, DSEP_BACKUP_CUSTODIAN, HEADER,
    },
    error::BackupError,
    secretsharing,
    traits::{BackupDecryptor, BackupSigner},
};
use crate::{
    anyhow_error_and_log,
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::{
        backup_pke::BackupPublicKey,
        internal_crypto_types::{PrivateSigKey, PublicSigKey, Signature},
        signcryption::internal_verify_sig,
    },
    engine::base::{safe_serialize_hash_element_versioned, DSEP_PUBDATA_KEY},
};
use itertools::Itertools;
use k256::ecdsa::SigningKey;
use kms_grpc::RequestId;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
    time::{SystemTime, UNIX_EPOCH},
};
use tfhe::{named::Named, safe_serialization::safe_serialize, Versionize};
use tfhe_versionable::VersionsDispatch;
use threshold_fhe::{
    algebra::galois_rings::degree_4::ResiduePolyF4Z64,
    execution::{
        runtime::party::Role,
        sharing::{shamir::ShamirSharings, share::Share},
    },
    hashing::{hash_element, DomainSep},
};

pub const DSEP_BACKUP_COMMITMENT: DomainSep = *b"BKUPCOMM";
pub(crate) const DSEP_BACKUP_CIPHER: DomainSep = *b"BKUPCIPH";
pub(crate) const DSEP_BACKUP_RECOVERY: DomainSep = *b"BKUPRREQ";

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum RecoveryRequestVersioned {
    V0(RecoveryRequest),
}

impl Named for RecoveryRequest {
    const NAME: &'static str = "backup::RecoveryRequest";
}

/// The data sent to the custodians by the operator during the recovery procedure.
#[derive(Debug, Clone, Serialize, Deserialize, Versionize)]
#[versionize(RecoveryRequestVersioned)]
pub struct RecoveryRequest {
    payload: InnerRecoveryRequest,
    signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
enum InnerRecoveryRequestVersioned {
    V0(InnerRecoveryRequest),
}

/// The data sent to the custodians by the operator during the recovery procedure.
#[derive(Debug, Clone, Serialize, Deserialize, Versionize)]
#[versionize(InnerRecoveryRequestVersioned)]
struct InnerRecoveryRequest {
    /// The ephemeral key used to signcrypt the recovered data during transit to the operator.
    enc_key: BackupPublicKey,
    /// The public key of the operator that was originally used to sign the backup.
    /// The ciphertexts that are the backup. Indexed by the custodian role.
    /// NOTE: since BTreeMap does not implement Versionize, we use a Vec here.
    cts: Vec<(Role, OperatorBackupOutput)>,
    /// The request ID under which the backup was created.
    backup_id: RequestId,
    /// The role of the operator
    operator_role: Role,
}

impl RecoveryRequest {
    pub fn new(
        enc_key: BackupPublicKey,
        sig_key: &PrivateSigKey,
        cts: BTreeMap<Role, OperatorBackupOutput>,
        backup_id: RequestId,
        operator_role: Role,
    ) -> anyhow::Result<Self> {
        // Observe that we use a Vec here instead of a BTreeMap since it does not support Versionize.
        let inner_cts = cts.into_iter().collect::<Vec<_>>();
        let inner_req = InnerRecoveryRequest {
            enc_key,
            cts: inner_cts,
            backup_id,
            operator_role,
        };
        let serialized_inner_req = bc2wrap::serialize(&inner_req).map_err(|e| {
            anyhow_error_and_log(format!("Could not serialize inner recovery request: {e:?}"))
        })?;
        let signature = &crate::cryptography::signcryption::internal_sign(
            &DSEP_BACKUP_RECOVERY,
            &serialized_inner_req,
            sig_key,
        )?;
        let signature_buf = signature.sig.to_vec();
        let res = Self {
            payload: inner_req,
            signature: signature_buf,
        };
        let verf_key = PublicSigKey::new(*SigningKey::verifying_key(sig_key.sk()));
        if !res.is_valid(&verf_key)? {
            return Err(anyhow_error_and_log("Invalid RecoveryRequest data"));
        }
        Ok(res)
    }

    /// Validate that the data in the request is sensible.
    pub fn is_valid(&self, verf_key: &PublicSigKey) -> anyhow::Result<bool> {
        if !self.payload.backup_id.is_valid() {
            tracing::warn!("RecoveryRequest has an invalid backup ID");
            return Ok(false);
        }
        if self.payload.operator_role.one_based() == 0 {
            tracing::warn!("RecoveryRequest has an invalid operator role");
            return Ok(false);
        }
        let serialized_inner_req = bc2wrap::serialize(&self.payload).map_err(|e| {
            anyhow_error_and_log(format!("Could not serialize inner recovery request: {e:?}"))
        })?;
        if internal_verify_sig(
            &DSEP_BACKUP_RECOVERY,
            &serialized_inner_req,
            &Signature {
                sig: k256::ecdsa::Signature::from_slice(&self.signature)?,
            },
            verf_key,
        )
        .is_err()
        {
            tracing::warn!("RecoveryRequest signature verification failed");
            return Ok(false);
        }
        Ok(true)
    }

    pub fn encryption_key(&self) -> &BackupPublicKey {
        &self.payload.enc_key
    }

    pub fn ciphertexts(&self) -> HashMap<Role, &OperatorBackupOutput> {
        self.payload
            .cts
            .iter()
            .map(|(role, ct)| (*role, ct))
            .collect()
    }

    pub fn backup_id(&self) -> RequestId {
        self.payload.backup_id
    }

    pub fn operator_role(&self) -> Role {
        self.payload.operator_role
    }
}

impl Display for RecoveryRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RecoveryRequest with:\n backup id: {}\n operator role: {}\n signature: {}\n ciphertext digest: {}\n encryption key digest: {}",
            self.payload.backup_id,
            self.payload.operator_role,
            hex::encode(&self.signature),
            hex::encode(hash_element(&DSEP_PUBDATA_KEY, &bc2wrap::serialize(&self.payload.cts).unwrap())),
            hex::encode(hash_element(&DSEP_PUBDATA_KEY,  &bc2wrap::serialize(&self.payload.enc_key).unwrap()))
        )
    }
}

#[derive(Clone)]
pub struct Operator<D: BackupDecryptor> {
    my_role: Role,
    custodian_keys: Vec<(BackupPublicKey, PublicSigKey)>,
    signer: PrivateSigKey,
    // the public component of [signer] above
    verification_key: PublicSigKey,
    decryptor: D,
    public_key: BackupPublicKey,
    threshold: usize,
}

impl<D: BackupDecryptor> std::fmt::Debug for Operator<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Operator")
            .field("my_id", &self.my_role)
            .field("custodian_keys", &self.custodian_keys)
            .field("signer", &"ommitted")
            .field("verification_key", &self.verification_key)
            .field("decryptor", &"ommitted")
            .field("public_key", &self.public_key)
            .field("threshold", &self.threshold)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum OperatorBackupOutputVersioned {
    V0(OperatorBackupOutput),
}

/// The output from the operator after it has completed a backup.
/// This data needs to be persisted on some public storage so that
/// new operators can download and recover.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(OperatorBackupOutputVersioned)]
pub struct OperatorBackupOutput {
    /// Ciphertext under the custodian's public key, using nested encryption.
    pub ciphertext: Vec<u8>,
    /// Signature by the operator.
    pub signature: Vec<u8>,
}

impl Named for OperatorBackupOutput {
    const NAME: &'static str = "backup::OperatorBackupOutput";
}

fn verify_n_t(n: usize, t: usize) -> Result<(), BackupError> {
    if n == 0 {
        return Err(BackupError::SetupError("n cannot be 0".to_string()));
    }
    if t == 0 {
        return Err(BackupError::SetupError("t cannot be 0".to_string()));
    }
    if t * 2 >= n {
        return Err(BackupError::SetupError(
            "t < n/2 is not satisfied".to_string(),
        ));
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum BackupCommitmentsVersioned {
    V0(BackupCommitments),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(BackupCommitmentsVersioned)]
pub struct BackupCommitments {
    // Note that ideally we want to use a BTreeMap here,
    // but it does not implement Versionize yet.
    commitments: Vec<Vec<u8>>,
    signature: Vec<u8>, // TODO should be made to signature type
}

impl Named for BackupCommitments {
    const NAME: &'static str = "backup::BackupCommitments";
}

impl BackupCommitments {
    pub fn new(commitments: Vec<Vec<u8>>, sk: &PrivateSigKey) -> anyhow::Result<Self> {
        let serialized_coms = bc2wrap::serialize(&commitments).map_err(|e| {
            anyhow_error_and_log(format!("Could not serialize inner recovery request: {e:?}"))
        })?;
        let signature = &crate::cryptography::signcryption::internal_sign(
            &DSEP_BACKUP_RECOVERY,
            &serialized_coms,
            sk,
        )?;
        let signature_buf = signature.sig.to_vec();
        Ok(Self {
            commitments,
            signature: signature_buf,
        })
    }

    pub fn from_btree(
        commitments: BTreeMap<Role, Vec<u8>>,
        sk: &PrivateSigKey,
    ) -> anyhow::Result<Self> {
        let mut commitments_vec = Vec::new();
        for i in 1..=commitments.len() {
            commitments_vec.push(commitments[&Role::indexed_from_one(i)].to_owned());
        }
        let serialized_coms = bc2wrap::serialize(&commitments).map_err(|e| {
            anyhow_error_and_log(format!("Could not serialize inner recovery request: {e:?}"))
        })?;
        let signature = &crate::cryptography::signcryption::internal_sign(
            &DSEP_BACKUP_RECOVERY,
            &serialized_coms,
            sk,
        )?;
        let signature_buf = signature.sig.to_vec();
        Ok(Self {
            commitments: commitments_vec,
            signature: signature_buf,
        })
    }

    pub fn get(&self, role: &Role) -> anyhow::Result<&[u8]> {
        if role.one_based() > self.commitments.len() {
            anyhow::bail!("Role {} is out of bounds for commitments", role);
        }
        Ok(self.commitments[role.one_based() - 1].as_slice())
    }
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

impl<D: BackupDecryptor> Operator<D> {
    pub fn new(
        my_role: Role,
        custodian_messages: Vec<InternalCustodianSetupMessage>,
        signer: PrivateSigKey,
        operator_verf_key: PublicSigKey,
        decryptor: D,
        operator_enc_key: BackupPublicKey,
        threshold: usize,
    ) -> Result<Self, BackupError> {
        verify_n_t(custodian_messages.len(), threshold)?;

        let mut custodian_keys = vec![];
        for (i, msg) in custodian_messages.into_iter().enumerate() {
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
                tracing::error!("Invalid header in custodian setup message from custodian {custodian_role}. Expected header {HEADER} but got {header}");
                return Err(BackupError::CustodianSetupError);
            }

            if custodian_role != Role::indexed_from_zero(i) {
                tracing::error!(
                    "Invalid custodian role in setup message: expected {} but got {}",
                    Role::indexed_from_zero(i),
                    custodian_role
                );
                return Err(BackupError::CustodianSetupError);
            }

            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            const ONE_HOUR_SECS: u64 = 3600;
            if !(now - ONE_HOUR_SECS < timestamp && timestamp < now + ONE_HOUR_SECS) {
                tracing::error!(
                    "Invalid timestamp in custodian setup message: expected within one hour of now, but got {}",
                    timestamp
                );
                return Err(BackupError::CustodianSetupError);
            }

            custodian_keys.push((public_enc_key, public_verf_key));
        }

        Ok(Self {
            my_role,
            custodian_keys,
            signer,
            verification_key: operator_verf_key,
            decryptor,
            public_key: operator_enc_key,
            threshold,
        })
    }

    pub fn verification_key(&self) -> &PublicSigKey {
        &self.verification_key
    }

    pub fn public_key(&self) -> &BackupPublicKey {
        &self.public_key
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.encapsulation_key.clone()
    }

    pub fn role(&self) -> Role {
        self.my_role
    }

    // We allow the following lints because we are fine with mutating the rng even if
    // the function fails afterwards.
    #[allow(unknown_lints)]
    #[allow(non_local_effect_before_error_return)]
    pub fn secret_share_and_encrypt<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        secret: &[u8],
        backup_id: RequestId,
    ) -> Result<(BTreeMap<Role, OperatorBackupOutput>, BackupCommitments), BackupError> {
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
        for ((role_j, shares), (enc_pk, sig_pk)) in
            plain_ij.into_iter().zip_eq(&self.custodian_keys)
        {
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
            let signature = self.signer.sign(&DSEP_BACKUP_CIPHER, &ciphertext)?;

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
                OperatorBackupOutput {
                    ciphertext,
                    signature,
                },
            );
            commitments.insert(role_j, msg_digest);
        }

        // 6. The commitments are stored by `P_i` and can be used to verify the shares later.
        let commitments = BackupCommitments::from_btree(commitments, &self.signer)
            .map_err(|e| BackupError::OperatorError(format!("Could not sign commitments: {e}")))?;
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
        custodian_recovery_output: &BTreeMap<Role, CustodianRecoveryOutput>,
        commitments: &BackupCommitments,
        backup_id: RequestId,
    ) -> Result<Vec<u8>, BackupError> {
        // the output is ordered by custodian ID, from 0 to n-1
        // first check the signature and decrypt
        // decrypted_buf[j][i] where j = jth custodian, i = ith block
        let decrypted_buf = custodian_recovery_output
            .iter()
            .map(|(custodian_role, ct)| {
                let key = custodian_role.get_from(&self.custodian_keys).ok_or(
                    BackupError::OperatorError(format!(
                        "missing custodian key for {custodian_role}"
                    )),
                )?;
                // sigt_ij
                let signature = Signature {
                    sig: k256::ecdsa::Signature::from_slice(&ct.signature)?,
                };
                let commitment = commitments
                    .get(custodian_role)
                    .map_err(|_| BackupError::OperatorError("missing commitment".to_string()))?;
                internal_verify_sig(&DSEP_BACKUP_CUSTODIAN, &ct.ciphertext, &signature, &key.1)
                    .map_err(|e| BackupError::SignatureVerificationError(e.to_string()))?;
                // st_ij
                checked_decryption_deserialize(
                    &self.decryptor,
                    &ct.ciphertext,
                    commitment,
                    backup_id,
                    &key.1,
                    *custodian_role,
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
