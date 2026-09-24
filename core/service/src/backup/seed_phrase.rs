use crate::{
    backup::custodian::Custodian,
    consts::CUSTODIAN_ENTROPY_SIZE,
    cryptography::{
        composite_mlkem1024_p384::{self, COMPOSITE_NIST_LEVEL_5_PRIVATE_KEY_LENGTH},
        encryption::{UnifiedPrivateEncKey, UnifiedPublicEncKey},
        signatures::{NodeSigningIdentity, ROOT_SEED_LEN, RootSigningSeed},
    },
};
use bip39::Mnemonic;
use hashing::{DomainSep, hash_element_w_size};
#[cfg(test)]
use rand::{CryptoRng, Rng};
use rand::{RngCore, rngs::OsRng};
use std::str::FromStr;
use threshold_types::role::Role;
use zeroize::Zeroizing;

pub const DSEP_MNEMONIC: DomainSep = *b"MNEMONIC";
const DSEP_ENTROPY: DomainSep = *b"ENTROPY_";

/// Draw [`CUSTODIAN_ENTROPY_SIZE`] bytes of system entropy, folding in a user-supplied string.
///
/// This is the entropy source for everything a custodian keeps: its seed phrase, and the RNG the
/// CLI uses for setup messages and recovery re-signcryption. It goes to the OS rather than to a
/// caller's RNG because a phrase can never carry more entropy than whatever it was drawn from,
/// and the keys derived from it must reach the full key space the encryption scheme assumes.
///
/// The optional user-supplied string is folded in over the full width with SHAKE-256, so providing
/// it can only add entropy and never replaces the system's.
pub fn system_entropy_for_custodian(
    randomness: Option<&str>,
) -> anyhow::Result<Zeroizing<[u8; CUSTODIAN_ENTROPY_SIZE]>> {
    let mut entropy = Zeroizing::new([0u8; CUSTODIAN_ENTROPY_SIZE]);
    OsRng.try_fill_bytes(&mut *entropy)?;
    let Some(user_seed) = randomness else {
        return Ok(entropy);
    };
    let user_bytes = Zeroizing::new(hash_element_w_size(
        &DSEP_ENTROPY,
        user_seed,
        CUSTODIAN_ENTROPY_SIZE,
    ));
    for (byte, user_byte) in entropy.iter_mut().zip(user_bytes.iter()) {
        *byte ^= user_byte;
    }
    Ok(entropy)
}

/// Draw a seed phrase from `rng`, for tests that need a reproducible custodian.
///
/// Test-only: a phrase carries no more entropy than the RNG it was drawn from, and the seeded
/// RNGs tests use are narrower than [`CUSTODIAN_ENTROPY_SIZE`]. Production phrases come from
/// [`system_entropy_for_custodian`].
#[cfg(test)]
pub(crate) fn seed_phrase_from_rng<R>(rng: &mut R) -> anyhow::Result<String>
where
    R: Rng + CryptoRng,
{
    let mut entropy = Zeroizing::new([0u8; CUSTODIAN_ENTROPY_SIZE]);
    rng.fill_bytes(&mut *entropy);
    seed_phrase_from_entropy(&entropy)
}

/// Encode `entropy` as a BIP-39 seed phrase.
///
/// The phrase is exactly as wide as `entropy`, so callers draw it from
/// [`system_entropy_for_custodian`] rather than from an RNG of their own, whose seed would cap it.
pub fn seed_phrase_from_entropy(entropy: &[u8; CUSTODIAN_ENTROPY_SIZE]) -> anyhow::Result<String> {
    let mnemonic = Mnemonic::from_entropy(entropy)?;
    Ok(mnemonic.to_string())
}

/// Re-derive a custodian's keys from its BIP-39 seed phrase.
///
/// The seed phrase is the only durable secret a custodian holds. The phrase
/// must carry [`CUSTODIAN_ENTROPY_SIZE`] bytes of entropy — a 24-word mnemonic.
/// Shorter phrases are rejected rather than stretched.
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

    // Expand the phrase's entropy once, then split the stream. The phrase is the only input to
    // both keys, so a single SHAKE-256 draw separates them and the raw entropy is read once.
    let key_material = Zeroizing::new(hash_element_w_size(
        &DSEP_MNEMONIC,
        &*entropy,
        COMPOSITE_NIST_LEVEL_5_PRIVATE_KEY_LENGTH + ROOT_SEED_LEN,
    ));
    let (enc_bytes, sig_bytes) = key_material.split_at(COMPOSITE_NIST_LEVEL_5_PRIVATE_KEY_LENGTH);

    // The encryption key's seed *is* the MLKEM1024-P384 private key.
    let mut enc_seed = Zeroizing::new([0u8; COMPOSITE_NIST_LEVEL_5_PRIVATE_KEY_LENGTH]);
    enc_seed.copy_from_slice(enc_bytes);
    let (dec_key, enc_key) = composite_mlkem1024_p384::keygen_from_seed(&enc_seed)
        .map_err(|e| anyhow::anyhow!("Failed to generate custodian keys from seed phrase: {e}"))?;

    // The second half is a full root signing seed, and it is retained in the identity, so the
    // custodian can sign under every scheme in `crate::backup::BACKUP_SIGNING_SCHEMES` rather
    // than only ECDSA.
    let mut sig_seed = Zeroizing::new([0u8; ROOT_SEED_LEN]);
    sig_seed.copy_from_slice(sig_bytes);
    let root = RootSigningSeed::from_seed_bytes(&sig_seed);
    let sig_key = root
        .derive_ecdsa_signing_key()
        .map_err(|e| anyhow::anyhow!("Failed to derive the custodian signing key: {e}"))?;

    Custodian::new(
        role,
        NodeSigningIdentity::new(sig_key, root),
        UnifiedPublicEncKey::MlKem1024P384(enc_key),
        UnifiedPrivateEncKey::MlKem1024P384(dec_key),
    )
    .map_err(|e| anyhow::anyhow!("Failed to create custodian from seed phrase: {e}"))
}

#[cfg(test)]
mod tests {
    use crate::backup::BACKUP_PKE_SCHEME;
    use crate::backup::seed_phrase::{
        custodian_from_seed_phrase, seed_phrase_from_entropy, seed_phrase_from_rng,
        system_entropy_for_custodian,
    };
    use crate::consts::CUSTODIAN_ENTROPY_SIZE;
    use crate::cryptography::composite_mlkem1024_p384::{
        self, COMPOSITE_NIST_LEVEL_5_PRIVATE_KEY_LENGTH,
    };
    use crate::cryptography::encryption::HasPkeScheme;
    use crate::cryptography::encryption::UnifiedPublicEncKey;
    use crate::cryptography::signatures::{PublicSigKey, ROOT_SEED_LEN, RootSigningSeed};
    use aes_prng::AesRng;
    use bip39::Mnemonic;
    use hashing::hash_element_w_size;
    use rand::SeedableRng;
    use std::str::FromStr;
    use threshold_types::role::Role;
    use zeroize::Zeroizing;

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

    /// The expansion is locked: one SHAKE-256 draw of 64 bytes, a 32-byte encryption key seed
    /// first and a 32-byte root signing seed second.
    #[test]
    fn seed_phrase_expansion_is_locked() {
        // Pinned against literals: every custodian key rotates silently if either width moves.
        assert_eq!(COMPOSITE_NIST_LEVEL_5_PRIVATE_KEY_LENGTH, 32);
        assert_eq!(ROOT_SEED_LEN, 32);

        let mnemonic = seed_phrase_from_entropy(&[9u8; CUSTODIAN_ENTROPY_SIZE]).unwrap();
        let custodian = custodian_from_seed_phrase(&mnemonic, Role::indexed_from_one(1)).unwrap();

        let entropy = Zeroizing::new(Mnemonic::from_str(&mnemonic).unwrap().to_entropy());
        let material = Zeroizing::new(hash_element_w_size(
            &crate::backup::seed_phrase::DSEP_MNEMONIC,
            &*entropy,
            COMPOSITE_NIST_LEVEL_5_PRIVATE_KEY_LENGTH + ROOT_SEED_LEN,
        ));
        let (enc_bytes, sig_bytes) = material.split_at(COMPOSITE_NIST_LEVEL_5_PRIVATE_KEY_LENGTH);

        // First half: the MLKEM1024-P384 private key, used as its own seed.
        let mut enc_seed = Zeroizing::new([0u8; COMPOSITE_NIST_LEVEL_5_PRIVATE_KEY_LENGTH]);
        enc_seed.copy_from_slice(enc_bytes);
        let (_dec, enc) = composite_mlkem1024_p384::keygen_from_seed(&enc_seed).unwrap();
        assert_eq!(
            custodian.public_enc_key(),
            &UnifiedPublicEncKey::MlKem1024P384(enc),
            "the encryption key is no longer the first half of the draw"
        );

        // Second half: a root signing seed, and the ECDSA key is the one it derives.
        let mut sig_seed = Zeroizing::new([0u8; ROOT_SEED_LEN]);
        sig_seed.copy_from_slice(sig_bytes);
        let expected = RootSigningSeed::from_seed_bytes(&sig_seed)
            .derive_ecdsa_signing_key()
            .unwrap();
        assert_eq!(
            custodian.verification_key(),
            PublicSigKey::from_sk(&expected),
            "the signing key no longer comes from the root seed in the second half"
        );
    }

    /// The user-supplied string is folded into system entropy, never a replacement for it: two
    /// draws with the same string must still differ.
    #[test]
    fn user_randomness_does_not_fix_the_entropy() {
        let first = system_entropy_for_custodian(Some("the same string")).unwrap();
        let second = system_entropy_for_custodian(Some("the same string")).unwrap();
        assert_ne!(*first, *second);
    }
}
