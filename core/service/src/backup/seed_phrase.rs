use crate::{
    consts::RND_SIZE,
    cryptography::{
        backup_pke,
        internal_crypto_types::{gen_sig_keys, PrivateSigKey, PublicSigKey},
    },
};
use aes_prng::AesRng;
use bip39::Mnemonic;
use rand::{CryptoRng, Rng, SeedableRng};
use threshold_fhe::hashing::{hash_element, DomainSep};

pub const DSEP_MNEMONIC_ENC: DomainSep = *b"MNEM_ENC";
pub const DSEP_MNEMONIC_SIG: DomainSep = *b"MNEM_SIG";

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CustodianKeySet {
    pub(crate) sig_key: PrivateSigKey,
    pub(crate) verf_key: PublicSigKey,
    pub(crate) nested_dec_key: backup_pke::BackupPrivateKey,
    pub(crate) nested_enc_key: backup_pke::BackupPublicKey,
}

#[allow(dead_code)]
pub(crate) fn generate_keys_from_rng<R>(rng: &mut R) -> anyhow::Result<(CustodianKeySet, Mnemonic)>
where
    R: Rng + CryptoRng,
{
    let mut entropy = [0u8; RND_SIZE];
    rng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy)?;

    let custodian_keys = custodian_keys_from_entropy(&entropy)?;
    Ok((custodian_keys, mnemonic))
}

#[allow(dead_code)]
pub(crate) fn generate_keys_from_seed_phrase(
    seed_phrase: &Mnemonic,
) -> anyhow::Result<CustodianKeySet> {
    let entropy = seed_phrase.to_entropy();
    assert!(
        entropy.len() >= RND_SIZE,
        "Seed phrase entropy must be at least {} bytes long",
        RND_SIZE
    );
    let mut entropy_arr = [0u8; RND_SIZE];
    entropy_arr.copy_from_slice(&entropy[..RND_SIZE]);
    custodian_keys_from_entropy(&entropy_arr)
}

#[allow(dead_code)]
fn rng_from_dsep_entropy<R>(dsep: &DomainSep, entropy: &[u8; RND_SIZE]) -> anyhow::Result<R>
where
    R: SeedableRng<Seed = [u8; RND_SIZE]> + Rng + CryptoRng,
{
    let dsep_entropy: Vec<u8> = hash_element(dsep, entropy);
    assert!(
        dsep_entropy.len() >= RND_SIZE,
        "DSEP entropy must be at least {} bytes long",
        RND_SIZE
    );
    // Observe that the [`AesRng`] requires a 16-byte seed which is `RND_SIZE` in our case.
    let mut rng_entropy = [0u8; RND_SIZE];
    rng_entropy.copy_from_slice(&dsep_entropy[..RND_SIZE]);
    Ok(R::from_seed(rng_entropy))
}

#[allow(dead_code)]
fn custodian_keys_from_entropy(entropy: &[u8; RND_SIZE]) -> anyhow::Result<CustodianKeySet> {
    let mut enc_rng = rng_from_dsep_entropy::<AesRng>(&DSEP_MNEMONIC_ENC, entropy)?;
    let (priv_key, pub_key) = backup_pke::keygen(&mut enc_rng)?;
    let mut sig_rng = rng_from_dsep_entropy::<AesRng>(&DSEP_MNEMONIC_SIG, entropy)?;
    let (verf_key, sig_key) = gen_sig_keys(&mut sig_rng);

    Ok(CustodianKeySet {
        sig_key,
        verf_key,
        nested_dec_key: priv_key,
        nested_enc_key: pub_key,
    })
}

#[cfg(test)]
mod tests {
    use crate::backup::seed_phrase::{generate_keys_from_rng, generate_keys_from_seed_phrase};
    use aes_prng::AesRng;
    use bip39::Mnemonic;
    use rand::SeedableRng;
    use std::str::FromStr;

    #[test]
    fn sunshine() {
        let mut rng = AesRng::seed_from_u64(42);
        let (custodian_keys, mnemonic) = generate_keys_from_rng(&mut rng).unwrap();
        let mnemonic = Mnemonic::from_str(&mnemonic.to_string()).unwrap();
        let regenerated_custodian_keys = generate_keys_from_seed_phrase(&mnemonic).unwrap();
        assert_eq!(custodian_keys, regenerated_custodian_keys)
    }

    #[test]
    fn difference() {
        let mut rng = AesRng::seed_from_u64(42);
        let (_custodian_keys, mnemonic) = generate_keys_from_rng(&mut rng).unwrap();
        let mut rng2 = AesRng::seed_from_u64(43);
        let (_custodian_keys, mnemonic2) = generate_keys_from_rng(&mut rng2).unwrap();
        assert_ne!(mnemonic, mnemonic2);
    }
}
