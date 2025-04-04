use std::collections::BTreeMap;

use aws_lc_rs::kem;
use error::BackupError;
use pke::{dec, enc, BackupCiphertext};
use rand::{CryptoRng, Rng};
use secretsharing::reconstruct;
use threshold_fhe::{
    algebra::galois_rings::degree_4::ResiduePolyF4Z64,
    execution::sharing::{shamir::ShamirSharings, share::Share},
};

pub mod error;
pub mod pke;
pub mod secretsharing;

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

/// This function runs the setup procedure of the backup protocol,
/// it should be executed by the party that wants to initiate a backup.
///
/// In more detail we secret share the input [secrets] under a n-out-of-t
/// secret sharing scheme where n is the length of [pks].
/// Then each share is encrypted using one of the [pks].
pub fn setup<R>(
    rng: &mut R,
    secret: &[u8],
    pks: &[kem::EncapsulationKey],
    t: usize,
) -> Result<BTreeMap<usize, BackupCiphertext>, BackupError>
where
    R: Rng + CryptoRng,
{
    // 1. Each player `Pi` selects `n` other people `Pij` for `[j=1..n]` of which he assumes `t < n/2` are dishonest.
    // 2. Player `Pij` generates a one time __post-quantum IND-CCA__ secure public/private key pair `(pkij,skij)` and sends `pkij` to `Pi`.
    // the steps above are given by the input, i.e. `pks` is the list of each of the `n` public keys received from the other parties.
    // Note that in the original spec `n'` and `t'` are used, here we simplify it to `n` and `t`.

    let n = pks.len();
    verify_n_t(n, t)?;

    // 3. Player `Pi` splits their share `si` (the input named `secret`) via a degree `t` sharing
    // among `n` players, to get shares `sij`.
    let shares = secretsharing::share(rng, secret, n, t)?;

    // 4. Player `Pi` encrypts `sij` to player `Pij` to get `ctij = Enc(pkij, sij)`.
    // First we prepare a map, mapping the 0-indexed party-id to their corresponding vector of shares.
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

    let mut ct_shares: BTreeMap<usize, BackupCiphertext> = BTreeMap::new();
    // is it ordered, it needs to be ordered to match pk_ij
    for ((j, shares), pk) in plain_ij.into_iter().zip(pks) {
        let msg = bincode::serialize(&shares)?;
        let ct = enc(&msg, pk)?;
        ct_shares.insert(j, ct);
    }

    // 5. The ciphertext is stored by `Pij`, or stored on a non-malleable storage, e.g. a blockchain or a secure bank vault.
    Ok(ct_shares)
}

fn dec_deserialize(
    sk: &kem::DecapsulationKey,
    ct: BackupCiphertext,
) -> Result<Vec<Share<ResiduePolyF4Z64>>, BackupError> {
    let pt_buf = dec(ct, sk)?;
    let shares = bincode::deserialize(&pt_buf)?;
    Ok(shares)
}

/// Recover one of the shares. This function should be executed
/// by the party that holds the secret key for one of the backup shares.
///
/// Since we only recover a Vec<Share<ResiduePolyF4Z64>>,
/// this function needs to be executed by all parties to recover the original plaintext
/// using [combine_all].
pub fn recover_one(
    sk: &kem::DecapsulationKey,
    ct: BackupCiphertext,
) -> Result<Vec<Share<ResiduePolyF4Z64>>, BackupError> {
    // 1. Player `Pij` decrypts `ctij` to get `sij` where `sij = Dec(skij, ctij)`.
    // 2. Player `Pij` sends `sij` and `skij` to player `Pi`.
    let shares = dec_deserialize(sk, ct)?;
    Ok(shares)
}

/// This is executed by the party that initially initiated the backup,
/// i.e., the one that called [setup]. It collects all the materials
/// used during the backup protocol such as shares, keys and ciphertexts,
/// and then uses them to verify whether the shares are correct before
/// doing the reconstruction.
pub fn verify_and_combine_all(
    pks: &[kem::EncapsulationKey],
    cts: BTreeMap<usize, BackupCiphertext>,
    identified_shares: BTreeMap<usize, Vec<Share<ResiduePolyF4Z64>>>,
    identified_sks: BTreeMap<usize, kem::DecapsulationKey>,
    t: usize,
) -> Result<Vec<u8>, BackupError> {
    let n = pks.len();
    verify_n_t(n, t)?;

    // 3. Player `Pi` checks that the decryption is valid, using `skij`.
    // This is simply done by decrypting again using the initial
    // ciphertexts produced in [setup].
    for (j, shares) in &identified_shares {
        let pk = &pks[*j];
        let pk_key_bytes = pk.key_bytes()?;
        let pk_buf = (*pk_key_bytes).as_ref();

        if let Some(sk) = identified_sks.get(j) {
            let other_pk = sk.encapsulation_key()?;
            let other_pk_key_bytes = other_pk.key_bytes()?;
            let other_pk_buf = (*other_pk_key_bytes).as_ref();
            if *pk_buf != *other_pk_buf {
                return Err(BackupError::KeyValidationError);
            }

            let ct = cts[j].clone();
            let expected_shares = dec_deserialize(sk, ct)?;
            if expected_shares != *shares {
                return Err(BackupError::ShareValidationError);
            }
        }
    }

    // 4. Player Pi now knows a bunch of values `sij` from each `Pij`, and if `Pij` is
    // honest these can be used to recover `si`.
    let num_blocks = if let Some(x) = identified_shares.values().map(|v| v.len()).min() {
        x
    } else {
        // This is normally impossible to happen because if it did
        // then it would mean the validation on expected_shares above failed
        return Err(BackupError::NoBlocksError);
    };

    let mut all_sharings = vec![];
    for b in 0..num_blocks {
        let mut shamir_sharing = ShamirSharings::new();
        for blocks in identified_shares.values() {
            // we should be able to safely add shares since it checks whether the role is repeated
            shamir_sharing
                .add_share(blocks[b])
                .map_err(|e| BackupError::AddShareError(e.to_string()))?;
        }
        all_sharings.push(shamir_sharing);
    }
    let out = reconstruct(all_sharings, t)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use core::panic;

    use aes_prng::AesRng;
    use proptest::prelude::*;
    use rand::SeedableRng;

    use super::*;

    const NTS: [(usize, usize); 3] = [(4, 1), (7, 3), (10, 4)];

    #[test]
    fn backup_setup_failure() {
        let mut rng = AesRng::seed_from_u64(0);
        let secrets = vec![2u8];
        if let Err(e) = setup(&mut rng, &secrets, &[], 1) {
            assert!(matches!(e, BackupError::SetupError(..)));
        } else {
            panic!("expected error");
        }

        if let Err(e) = setup(&mut rng, &secrets, &[pke::keygen().unwrap().1], 0) {
            assert!(matches!(e, BackupError::SetupError(..)));
        } else {
            panic!("expected error");
        }

        if let Err(e) = setup(
            &mut rng,
            &secrets,
            &[pke::keygen().unwrap().1, pke::keygen().unwrap().1],
            1,
        ) {
            assert!(matches!(e, BackupError::SetupError(..)));
        } else {
            panic!("expected error");
        }
    }

    #[test]
    fn backup_aead_failure() {
        let n = 4;
        let t = 1;
        let (sks, pks): (Vec<_>, Vec<_>) = (0..n).map(|_| pke::keygen().unwrap()).unzip();

        // share the secrets and encrypt them
        let mut rng = AesRng::seed_from_u64(0);
        let secrets = vec![2u8];
        let cts = setup(&mut rng, &secrets, &pks, t).unwrap();

        // recover the shares correctly
        let identified_shares = cts
            .clone()
            .into_iter()
            .map(|(j, ct)| (j, recover_one(&sks[j], ct).unwrap()))
            .collect::<BTreeMap<_, _>>();
        let identified_sks: BTreeMap<_, _> = sks.into_iter().enumerate().collect();

        // tweak the ciphertext to cause aead validation to fail
        let mut cts_bad = cts.clone();
        let ct0 = cts_bad.get_mut(&0).unwrap();
        ct0.ct[0] ^= 1;
        let err = verify_and_combine_all(&pks, cts_bad, identified_shares, identified_sks, t)
            .unwrap_err();
        assert!(matches!(err, BackupError::UnspecifiedError(..)));
    }

    #[test]
    fn backup_bad_pks() {
        let n = 4;
        let t = 1;
        let (sks, pks): (Vec<_>, Vec<_>) = (0..n).map(|_| pke::keygen().unwrap()).unzip();

        // share the secrets and encrypt them
        let mut rng = AesRng::seed_from_u64(0);
        let secrets = vec![2u8];
        let cts = setup(&mut rng, &secrets, &pks, t).unwrap();

        // recover the shares correctly
        let identified_shares = cts
            .clone()
            .into_iter()
            .map(|(j, ct)| (j, recover_one(&sks[j], ct).unwrap()))
            .collect::<BTreeMap<_, _>>();
        let identified_sks: BTreeMap<_, _> = sks.into_iter().enumerate().collect();

        // tweak the pk to cause validation to fail
        let (_sks, pks_bad): (Vec<_>, Vec<_>) = (0..n).map(|_| pke::keygen().unwrap()).unzip();
        let err = verify_and_combine_all(&pks_bad, cts, identified_shares, identified_sks, t)
            .unwrap_err();
        assert!(matches!(err, BackupError::KeyValidationError));
    }

    #[test]
    fn backup_bad_cts() {
        let n = 4;
        let t = 1;
        let (sks, pks): (Vec<_>, Vec<_>) = (0..n).map(|_| pke::keygen().unwrap()).unzip();

        // share the secrets and encrypt them
        let mut rng = AesRng::seed_from_u64(0);
        let secrets = vec![2u8];
        let secrets2 = vec![3u8];
        let cts = setup(&mut rng, &secrets, &pks, t).unwrap();
        let cts2 = setup(&mut rng, &secrets2, &pks, t).unwrap();

        // recover the shares correctly
        let identified_shares = cts
            .clone()
            .into_iter()
            .map(|(j, ct)| (j, recover_one(&sks[j], ct).unwrap()))
            .collect::<BTreeMap<_, _>>();
        let identified_sks: BTreeMap<_, _> = sks.into_iter().enumerate().collect();

        // using the wrong cts
        let err =
            verify_and_combine_all(&pks, cts2, identified_shares, identified_sks, t).unwrap_err();
        assert!(matches!(err, BackupError::ShareValidationError));
    }

    proptest! {
        #[test]
        fn backup_sunshine(seed: u64, secrets: Vec<u8>) {
            let mut rng = AesRng::seed_from_u64(seed);
            for (n, t) in NTS {
                // generate all keys
                let (sks, pks): (Vec<_>, Vec<_>) = (0..n).map(|_| pke::keygen().unwrap()).unzip();

                // share the secrets and encrypt them
                let cts = setup(&mut rng, &secrets, &pks, t).unwrap();

                let identified_shares = cts.clone().into_iter()
                    .map(|(j, ct)| (j, recover_one(&sks[j], ct).unwrap()))
                    .collect::<BTreeMap<_, _>>();
                let identified_sks: BTreeMap<_, _> = sks.into_iter().enumerate().collect();

                let pt = verify_and_combine_all(&pks, cts, identified_shares, identified_sks, t).unwrap();
                assert_eq!(pt, secrets);
            }
        }

        #[test]
        fn backup_missing_shares_sunshine(seed: u64, secrets: Vec<u8>, first_shares: bool) {
            let mut rng = AesRng::seed_from_u64(seed);
            for (n, t) in NTS {
                // generate all keys
                let (sks, pks): (Vec<_>, Vec<_>) = (0..n).map(|_| pke::keygen().unwrap()).unzip();

                // share the secrets and encrypt them
                let mut cts = setup(&mut rng, &secrets, &pks, t).unwrap();

                // reconstruct with missing shares
                // we need to keep t + 1 shares, so remove n - (t + 1)
                for _ in 0..(n - t - 1) {
                    if first_shares {
                        let _ = cts.pop_last().unwrap();
                    } else {
                        let _ = cts.pop_first().unwrap();
                    }
                }
                assert_eq!(cts.len(), t + 1);

                let identified_shares = cts.clone().into_iter()
                    .map(|(j, ct)| (j, recover_one(&sks[j], ct).unwrap()))
                    .collect::<BTreeMap<_, _>>();
                let identified_sks: BTreeMap<_, _> = sks.into_iter().enumerate().collect();

                let pt = verify_and_combine_all(&pks, cts.clone(), identified_shares, identified_sks, t).unwrap();
                assert_eq!(pt, secrets);
            }
        }
    }
}
