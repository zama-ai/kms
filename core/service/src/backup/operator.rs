use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use kms_grpc::RequestId;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use tfhe::{named::Named, safe_serialization::safe_serialize, Versionize};
use tfhe_versionable::VersionsDispatch;
use threshold_fhe::{
    algebra::galois_rings::degree_4::ResiduePolyF4Z64,
    execution::sharing::{shamir::ShamirSharings, share::Share},
    hashing::DomainSep,
};

use crate::{
    backup::custodian::DSEP_BACKUP_SETUP,
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::{
        internal_crypto_types::{PublicSigKey, Signature},
        nested_pke::NestedPublicKey,
        signcryption::internal_verify_sig,
    },
    engine::base::safe_serialize_hash_element_versioned,
};

use super::{
    custodian::{
        CustodianRecoveryOutput, CustodianSetupMessage, InnerCustodianSetupMessage,
        DSEP_BACKUP_CUSTODIAN, HEADER,
    },
    error::BackupError,
    secretsharing,
    traits::{BackupDecryptor, BackupSigner},
};

const DSEP_BACKUP_COMMITMENT: DomainSep = *b"BKUPCOMM";
pub(crate) const DSEP_BACKUP_OPERATOR: DomainSep = *b"BKUPOPER";

pub struct Operator<S: BackupSigner, D: BackupDecryptor> {
    my_id: usize,
    custodian_keys: Vec<(NestedPublicKey, PublicSigKey)>,
    signer: S,
    // the public component of [signer] above
    verification_key: PublicSigKey,
    decryptor: D,
    public_key: NestedPublicKey,
    threshold: usize,
}

impl<S: BackupSigner, D: BackupDecryptor> std::fmt::Debug for Operator<S, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Operator")
            .field("my_id", &self.my_id)
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
    /// Commitment by the operator, which is a hash of [BackupMaterial].
    ///
    /// We cannot use the regular commitment routines from commitment.rs
    /// because the operator cannot keep the opening and it cannot make it public.
    /// As such, we need to ensure the material that is being committed
    /// has enough entorpy.
    pub commitment: Vec<u8>,
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

#[allow(clippy::too_many_arguments)]
fn checked_decryption_deserialize<D: BackupDecryptor>(
    sk: &D,
    ct: &[u8],
    commitment: &[u8],
    backup_id: RequestId,
    custodian_pk: &PublicSigKey,
    custodian_id: usize,
    operator_pk: &PublicSigKey,
    operator_id: usize,
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
        custodian_id,
        operator_pk,
        operator_id,
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
    pub(crate) custodian_id: usize,
    // sender
    pub(crate) operator_pk: PublicSigKey,
    pub(crate) operator_id: usize,
    pub(crate) shares: Vec<Share<ResiduePolyF4Z64>>,
}

impl BackupMaterial {
    pub fn matches_expected_metadata(
        &self,
        backup_id: RequestId,
        custodian_pk: &PublicSigKey,
        custodian_id: usize,
        operator_pk: &PublicSigKey,
        operator_id: usize,
    ) -> bool {
        if self.backup_id != backup_id {
            return false;
        }
        if self.custodian_id != custodian_id {
            return false;
        }
        if self.operator_id != operator_id {
            return false;
        }
        if &self.custodian_pk != custodian_pk {
            return false;
        }
        if &self.operator_pk != operator_pk {
            return false;
        }
        true
    }
}

impl Named for BackupMaterial {
    const NAME: &'static str = "backup::BackupShares";
}

impl<S: BackupSigner, D: BackupDecryptor> Operator<S, D> {
    pub fn new(
        my_id: usize,
        custodian_messages: Vec<CustodianSetupMessage>,
        signer: S,
        verification_key: PublicSigKey,
        decryptor: D,
        public_key: NestedPublicKey,
        threshold: usize,
    ) -> Result<Self, BackupError> {
        verify_n_t(custodian_messages.len(), threshold)?;

        let mut custodian_keys = vec![];
        for (i, msg) in custodian_messages.into_iter().enumerate() {
            let InnerCustodianSetupMessage {
                header,
                custodian_id,
                random_value: _,
                timestamp,
                public_key,
            } = msg.msg.clone();

            if header != HEADER {
                return Err(BackupError::CustodianSetupError);
            }

            if custodian_id != i {
                return Err(BackupError::CustodianSetupError);
            }

            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            const ONE_HOUR_SECS: u64 = 3600;
            if !(now - ONE_HOUR_SECS < timestamp && timestamp < now + ONE_HOUR_SECS) {
                return Err(BackupError::CustodianSetupError);
            }

            let msg_buf = bincode::serialize(&msg.msg)?;
            let signature = Signature {
                sig: k256::ecdsa::Signature::from_slice(&msg.signature)?,
            };
            internal_verify_sig(
                &DSEP_BACKUP_SETUP,
                &msg_buf,
                &signature,
                &msg.verification_key,
            )
            .map_err(|e| BackupError::SignatureVerificationError(e.to_string()))?;

            custodian_keys.push((public_key, msg.verification_key));
        }

        Ok(Self {
            my_id,
            custodian_keys,
            signer,
            verification_key,
            decryptor,
            public_key,
            threshold,
        })
    }

    pub fn verification_key(&self) -> &PublicSigKey {
        &self.verification_key
    }

    pub fn public_key(&self) -> &NestedPublicKey {
        &self.public_key
    }

    pub fn secret_share_and_encrypt<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        secret: &[u8],
        backup_id: RequestId,
    ) -> Result<BTreeMap<usize, OperatorBackupOutput>, BackupError> {
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
        let mut plain_ij: BTreeMap<usize, Vec<Share<ResiduePolyF4Z64>>> = BTreeMap::new();
        for share in shares.into_iter() {
            for inner in share.shares {
                let j = inner.owner().zero_based();
                if let Some(v) = plain_ij.get_mut(&j) {
                    v.push(inner);
                } else {
                    plain_ij.insert(j, vec![inner]);
                }
            }
        }

        let mut ct_shares: BTreeMap<usize, _> = BTreeMap::new();

        for ((j, shares), (enc_pk, sig_pk)) in plain_ij.into_iter().zip(&self.custodian_keys) {
            // Do a sanity check that we expect enough entropy in the shares
            // s.t. hashing these cannot allow a feasible brute-force attack.
            //
            // At the moment we only have a length check that ensures they have at least
            // 256 bits of pseudorandom values per shares.
            // There are shares.len() shares, each has 256 bits and 64 bits for the role
            // the extra 8 bytes is used by bincode to encode the length.
            let minimum_expected_length = shares.len() * (32 + 8) + 8;
            let actual_length = bincode::serialize(&shares)?.len();
            if actual_length < minimum_expected_length {
                return Err(BackupError::OperatorError(format!(
                    "share is not long enough: actual={actual_length} < minimum={minimum_expected_length}"
                )));
            }

            let backup_material = BackupMaterial {
                backup_id,
                custodian_pk: sig_pk.clone(),
                custodian_id: j,
                operator_pk: self.verification_key.clone(),
                operator_id: self.my_id,
                shares,
            };

            let mut msg = Vec::new();
            safe_serialize(&backup_material, &mut msg, SAFE_SER_SIZE_LIMIT)?;
            let ciphertext = enc_pk.encrypt(rng, &msg)?;
            let signature = self.signer.sign(&DSEP_BACKUP_OPERATOR, &ciphertext)?;

            // we simply use the digest as the commitment
            // since the share should have enough entropy
            // is simply a sha3 hash with some metadata of the share
            let msg_digest =
                safe_serialize_hash_element_versioned(&DSEP_BACKUP_COMMITMENT, &backup_material)
                    .map_err(|e| BackupError::OperatorError(e.to_string()))?;

            ct_shares.insert(
                j,
                OperatorBackupOutput {
                    ciphertext,
                    signature,
                    commitment: msg_digest,
                },
            );
        }

        // 5. The ciphertext is stored by `Pij`, or stored on a non-malleable storage, e.g. a blockchain or a secure bank vault.
        Ok(ct_shares)
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
        custodian_recovery_output: BTreeMap<usize, CustodianRecoveryOutput>,
        commitments: BTreeMap<usize, Vec<u8>>,
        backup_id: RequestId,
    ) -> Result<Vec<u8>, BackupError> {
        // the output is ordered by custodian ID, from 0 to n-1
        // first check the signature and decrypt
        // decrypted_buf[j][i] where j = jth custodian, i = ith block
        let decrypted_buf = custodian_recovery_output
            .iter()
            .map(|(j, ct)| {
                let key = &self
                    .custodian_keys
                    .get(*j)
                    .ok_or(BackupError::OperatorError(format!(
                        "missing custodian key at index {j}"
                    )))?;
                // sigt_ij
                let signature = Signature {
                    sig: k256::ecdsa::Signature::from_slice(&ct.signature)?,
                };
                let commitment = commitments
                    .get(j)
                    .ok_or(BackupError::OperatorError("missing commitment".to_string()))?;
                internal_verify_sig(&DSEP_BACKUP_CUSTODIAN, &ct.ciphertext, &signature, &key.1)
                    .map_err(|e| BackupError::SignatureVerificationError(e.to_string()))?;
                // st_ij
                checked_decryption_deserialize(
                    &self.decryptor,
                    &ct.ciphertext,
                    commitment,
                    backup_id,
                    &key.1,
                    *j,
                    &self.verification_key,
                    self.my_id,
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
                shamir_sharing
                    .add_share(blocks[b])
                    .map_err(|e| BackupError::AddShareError(e.to_string()))?;
            }
            all_sharings.push(shamir_sharing);
        }
        let out = secretsharing::reconstruct(all_sharings, self.threshold)?;
        Ok(out)
    }
}
