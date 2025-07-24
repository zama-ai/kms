use crate::{
    backup::custodian::Custodian,
    consts::RND_SIZE,
    cryptography::{
        backup_pke::{self, BackupPrivateKey},
        internal_crypto_types::{gen_sig_keys, PrivateSigKey},
    },
};
use aes_prng::AesRng;
use bip39::Mnemonic;
use rand::{CryptoRng, Rng, SeedableRng};
use std::str::FromStr;
use threshold_fhe::{
    execution::runtime::party::Role,
    hashing::{hash_element, DomainSep},
};

pub const DSEP_MNEMONIC_ENC: DomainSep = *b"MNEM_ENC";
pub const DSEP_MNEMONIC_SIG: DomainSep = *b"MNEM_SIG";

// Allow the rng to be used even if an error happens later on
#[allow(unknown_lints)]
#[allow(non_local_effect_before_error_return)]
pub fn seed_phrase_from_rng<R>(rng: &mut R) -> anyhow::Result<String>
where
    R: Rng + CryptoRng,
{
    let mut entropy = [0u8; RND_SIZE];
    rng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy)?;
    Ok(mnemonic.to_string())
}

pub fn custodian_from_seed_phrase(
    seed_phrase: &str,
    role: Role,
) -> anyhow::Result<Custodian<PrivateSigKey, BackupPrivateKey>> {
    let mnemonic = Mnemonic::from_str(&seed_phrase.trim().to_lowercase())?;
    let entropy = mnemonic.to_entropy();
    assert!(
        entropy.len() >= RND_SIZE,
        "Seed phrase entropy must be at least {RND_SIZE} bytes long",
    );
    let mut entropy_arr = [0u8; RND_SIZE];
    entropy_arr.copy_from_slice(&entropy[..RND_SIZE]);
    let mut enc_rng = rng_from_dsep_entropy::<AesRng>(&DSEP_MNEMONIC_ENC, &entropy_arr)?;
    let (priv_key, pub_key) = backup_pke::keygen(&mut enc_rng)?;
    let mut sig_rng = rng_from_dsep_entropy::<AesRng>(&DSEP_MNEMONIC_SIG, &entropy_arr)?;
    let (verf_key, sig_key) = gen_sig_keys(&mut sig_rng);

    Custodian::new(role, sig_key, verf_key, priv_key, pub_key).map_err(|e| {
        anyhow::anyhow!(
            "Failed to create custodian from seed phrase: {}",
            e.to_string()
        )
    })
}

#[allow(dead_code)]
fn rng_from_dsep_entropy<R>(dsep: &DomainSep, entropy: &[u8; RND_SIZE]) -> anyhow::Result<R>
where
    R: SeedableRng<Seed = [u8; RND_SIZE]> + Rng + CryptoRng,
{
    let dsep_entropy: Vec<u8> = hash_element(dsep, entropy);
    assert!(
        dsep_entropy.len() >= RND_SIZE,
        "DSEP entropy must be at least {RND_SIZE} bytes long",
    );
    // Observe that the [`AesRng`] requires a 16-byte seed which is `RND_SIZE` in our case.
    let mut rng_entropy = [0u8; RND_SIZE];
    rng_entropy.copy_from_slice(&dsep_entropy[..RND_SIZE]);
    Ok(R::from_seed(rng_entropy))
}

#[cfg(test)]
mod tests {
    use crate::backup::seed_phrase::{custodian_from_seed_phrase, seed_phrase_from_rng};
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use threshold_fhe::execution::runtime::party::Role;

    #[test]
    fn sunshine() {
        let mut rng = AesRng::seed_from_u64(42);
        let mnemonic = seed_phrase_from_rng(&mut rng).unwrap();
        let custodian = custodian_from_seed_phrase(&mnemonic, Role::indexed_from_one(1)).unwrap();
        let regenerated_custodian =
            custodian_from_seed_phrase(&mnemonic, Role::indexed_from_one(1)).unwrap();
        assert_eq!(custodian.public_key(), regenerated_custodian.public_key());
        assert_eq!(
            custodian.verification_key(),
            regenerated_custodian.verification_key()
        )
    }

    #[test]
    fn difference() {
        let mut rng = AesRng::seed_from_u64(42);
        let mnemonic = seed_phrase_from_rng(&mut rng).unwrap();
        let mut rng2 = AesRng::seed_from_u64(43);
        let mnemonic2 = seed_phrase_from_rng(&mut rng2).unwrap();
        assert_ne!(mnemonic, mnemonic2);
    }

    #[test]
    fn mnemonic_robustness() {
        // Observe the whitespace and mixed cases
        let weird_mnemonic =
            "   fun OFFICE sHop caught frown special wave razor crunch ahead nuclear  another  ";
        let regeneratred_custodian =
            custodian_from_seed_phrase(weird_mnemonic, Role::indexed_from_one(1)).unwrap();
        let prune_custodian = custodian_from_seed_phrase(
            weird_mnemonic.to_lowercase().trim(),
            Role::indexed_from_one(1),
        )
        .unwrap();
        assert_eq!(
            regeneratred_custodian.public_key(),
            prune_custodian.public_key()
        );
        assert_eq!(
            regeneratred_custodian.verification_key(),
            prune_custodian.verification_key()
        );
    }
}
