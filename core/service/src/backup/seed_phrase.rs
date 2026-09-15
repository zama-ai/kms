use crate::{
    backup::custodian::Custodian,
    consts::{CUSTODIAN_ENTROPY_SIZE, RND_SIZE},
    cryptography::{
        composite_mlkem1024_p384::{self, PRIVATE_KEY_LENGTH},
        encryption::{UnifiedPrivateEncKey, UnifiedPublicEncKey},
        signatures::gen_sig_keys,
    },
};
use aes_prng::AesRng;
use bip39::Mnemonic;
use hashing::{DomainSep, hash_element, hash_element_w_size};
use rand::{CryptoRng, Rng, SeedableRng};
use std::str::FromStr;
use threshold_types::role::Role;
use zeroize::Zeroizing;

pub const DSEP_MNEMONIC_ENC: DomainSep = *b"MNEM_ENC";
pub const DSEP_MNEMONIC_SIG: DomainSep = *b"MNEM_SIG";

// Allow the rng to be used even if an error happens later on
#[allow(unknown_lints)]
#[allow(non_local_effect_before_error_return)]
pub fn seed_phrase_from_rng<R>(rng: &mut R) -> anyhow::Result<String>
where
    R: Rng + CryptoRng,
{
    let mut entropy = Zeroizing::new([0u8; CUSTODIAN_ENTROPY_SIZE]);
    rng.fill_bytes(&mut *entropy);
    seed_phrase_from_entropy(&entropy)
}

/// Encode `entropy` as a BIP-39 seed phrase.
///
/// Callers that must not narrow the phrase's entropy use this instead of [`seed_phrase_from_rng`],
/// which is only as wide as the RNG handed to it.
pub fn seed_phrase_from_entropy(entropy: &[u8; CUSTODIAN_ENTROPY_SIZE]) -> anyhow::Result<String> {
    let mnemonic = Mnemonic::from_entropy(entropy)?;
    Ok(mnemonic.to_string())
}

/// Re-derive a custodian's keys from its BIP-39 seed phrase.
///
/// The seed phrase is the only durable secret a custodian holds, so every key comes from it and
/// nothing else. The phrase must carry [`CUSTODIAN_ENTROPY_SIZE`] bytes of entropy — a 24-word
/// mnemonic. Shorter phrases are rejected rather than stretched, because silently deriving a
/// 128-bit key for a scheme whose security level assumes 256 bits is exactly the failure this
/// length check exists to prevent.
///
/// Derivation can fail, with probability below 2^-192, if the phrase expands to a P-384 scalar that
/// rejection sampling refuses; see [`composite_mlkem1024_p384::keygen_from_seed`]. There is no
/// retry for a phrase already in a custodian's hands, so `kms-custodian generate` regenerates the
/// mnemonic instead of surfacing it.
pub fn custodian_from_seed_phrase(seed_phrase: &str, role: Role) -> anyhow::Result<Custodian> {
    let mnemonic = Mnemonic::from_str(&seed_phrase.trim().to_lowercase())?;
    let entropy = Zeroizing::new(mnemonic.to_entropy());
    if entropy.len() != CUSTODIAN_ENTROPY_SIZE {
        anyhow::bail!(
            "Seed phrase carries {} bytes of entropy, but {CUSTODIAN_ENTROPY_SIZE} are required \
             (a {}-word mnemonic). A shorter phrase would yield a weaker key than the custodian \
             encryption scheme assumes.",
            entropy.len(),
            CUSTODIAN_ENTROPY_SIZE * 3 / 4,
        );
    }

    // Derive the encryption key's seed straight from the phrase. The seed *is* the MLKEM1024-P384
    // private key, so going through an intermediate `AesRng` would cap the reachable key space at
    // that RNG's 128-bit seed and waste half the entropy the phrase carries.
    let mut enc_seed = Zeroizing::new([0u8; PRIVATE_KEY_LENGTH]);
    enc_seed.copy_from_slice(&hash_element_w_size(
        &DSEP_MNEMONIC_ENC,
        &*entropy,
        PRIVATE_KEY_LENGTH,
    ));
    let (dec_key, enc_key) = composite_mlkem1024_p384::keygen_from_seed(&enc_seed)
        .map_err(|e| anyhow::anyhow!("Failed to generate custodian keys from seed phrase: {e}"))?;

    // The signing key keeps the narrower `AesRng` derivation: it is ECDSA over secp256k1, which
    // offers about 128 bits of security itself, so widening its seed would buy nothing.
    let mut sig_rng = rng_from_dsep_entropy::<AesRng>(&DSEP_MNEMONIC_SIG, &entropy)?;
    let (_verf_key, sig_key) = gen_sig_keys(&mut sig_rng);

    Custodian::new(
        role,
        sig_key,
        UnifiedPublicEncKey::MlKem1024P384(enc_key),
        UnifiedPrivateEncKey::MlKem1024P384(dec_key),
    )
    .map_err(|e| anyhow::anyhow!("Failed to create custodian from seed phrase: {e}"))
}

#[allow(dead_code)]
fn rng_from_dsep_entropy<R>(dsep: &DomainSep, entropy: &[u8]) -> anyhow::Result<R>
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
    use crate::backup::BACKUP_PKE_SCHEME;
    use crate::backup::seed_phrase::{
        custodian_from_seed_phrase, seed_phrase_from_entropy, seed_phrase_from_rng,
    };
    use crate::consts::CUSTODIAN_ENTROPY_SIZE;
    use crate::cryptography::encryption::HasPkeScheme;
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use threshold_types::role::Role;

    /// A valid mnemonic carrying only 128 bits of entropy, which is no longer enough.
    const TWELVE_WORD_MNEMONIC: &str =
        "fun office shop caught frown special wave razor crunch ahead nuclear another";

    #[test]
    fn sunshine() {
        let mut rng = AesRng::seed_from_u64(42);
        let mnemonic = seed_phrase_from_rng(&mut rng).unwrap();
        let custodian = custodian_from_seed_phrase(&mnemonic, Role::indexed_from_one(1)).unwrap();
        // Observe that keys don't depend directly on name or role
        let regenerated_custodian =
            custodian_from_seed_phrase(&mnemonic, Role::indexed_from_one(2)).unwrap();
        assert_eq!(
            custodian.public_enc_key(),
            regenerated_custodian.public_enc_key()
        );
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
    fn mnemonic_is_twenty_four_words() {
        let mut rng = AesRng::seed_from_u64(42);
        let mnemonic = seed_phrase_from_rng(&mut rng).unwrap();
        assert_eq!(
            mnemonic.split_whitespace().count(),
            24,
            "a custodian phrase must carry {CUSTODIAN_ENTROPY_SIZE} bytes of entropy"
        );
    }

    /// A 12-word phrase must be refused, not stretched: deriving a 128-bit key for a scheme whose
    /// security level assumes 256 bits would be silent and irreversible once published.
    #[test]
    fn short_seed_phrase_is_rejected() {
        // Matched rather than `expect_err`-ed: `Custodian` holds a private key and deliberately
        // does not implement `Debug`.
        let error =
            match custodian_from_seed_phrase(TWELVE_WORD_MNEMONIC, Role::indexed_from_one(1)) {
                Ok(_) => panic!("a 128-bit seed phrase must be rejected"),
                Err(error) => error,
            };
        assert!(
            error.to_string().contains("bytes of entropy"),
            "unexpected error: {error}"
        );
    }

    /// Pins the seed-phrase derivation to the scheme the rest of the backup chain uses. The
    /// derivation calls the composite keygen directly rather than going through
    /// `Encryption::new(BACKUP_PKE_SCHEME, ..)`, so nothing else would catch the two drifting apart.
    #[test]
    fn derived_keys_use_the_backup_scheme() {
        let mut rng = AesRng::seed_from_u64(42);
        let mnemonic = seed_phrase_from_rng(&mut rng).unwrap();
        let custodian = custodian_from_seed_phrase(&mnemonic, Role::indexed_from_one(1)).unwrap();
        assert_eq!(
            custodian.public_enc_key().encryption_scheme_type(),
            BACKUP_PKE_SCHEME
        );
        assert_eq!(
            custodian.public_dec_key().encryption_scheme_type(),
            BACKUP_PKE_SCHEME
        );
    }

    #[test]
    fn mnemonic_robustness() {
        // Build the phrase rather than hard-coding one, so the test cannot go stale if the
        // required entropy changes again. Observe the whitespace and mixed cases.
        let mnemonic = seed_phrase_from_entropy(&[7u8; CUSTODIAN_ENTROPY_SIZE]).unwrap();
        let weird_mnemonic = format!("   {}  ", mnemonic.to_uppercase());
        let regeneratred_custodian =
            custodian_from_seed_phrase(&weird_mnemonic, Role::indexed_from_one(1)).unwrap();
        let prune_custodian = custodian_from_seed_phrase(
            weird_mnemonic.to_lowercase().trim(),
            Role::indexed_from_one(1),
        )
        .unwrap();
        assert_eq!(
            regeneratred_custodian.public_enc_key(),
            prune_custodian.public_enc_key()
        );
        assert_eq!(
            regeneratred_custodian.verification_key(),
            prune_custodian.verification_key()
        );
    }
}
