use deep_space::error::HdWalletError;
use deep_space::error::PrivateKeyError;
use deep_space::utils::hex_str_to_bytes;
use deep_space::Mnemonic;
use secp256k1::Scalar;
use secp256k1::Secp256k1;
use secp256k1::{PublicKey as PublicKeyEC, SecretKey};
use sha2::Sha512;
use std::str::FromStr;

/// Derives a private key from a mnemonic phrase and passphrase, using a BIP-44 HDPath
/// The actual seed bytes are derived from the mnemonic phrase, which are then used to derive
/// the root of a Bip32 HD wallet. From that application private keys are derived
/// on the given hd_path (e.g. Cosmos' m/44'/118'/0'/0/a where a=0 is the most common value used).
/// Most Cosmos wallets do not even expose a=1..n much less the rest of
/// the potential key space.
pub fn derive_key(
    hd_path: &str,
    phrase: &str,
    passphrase: &str,
) -> Result<[u8; 32], PrivateKeyError> {
    if !hd_path.starts_with('m') || hd_path.contains('\\') {
        return Err(HdWalletError::InvalidPathSpec(hd_path.to_string()).into());
    }
    let mut iterator = hd_path.split('/');
    // discard the m
    let _ = iterator.next();

    let key_import = Mnemonic::from_str(phrase)?;
    let seed_bytes = key_import.to_seed(passphrase);
    let (master_secret_key, master_chain_code) = master_key_from_seed(&seed_bytes);
    let mut secret_key = master_secret_key;
    let mut chain_code = master_chain_code;

    for mut val in iterator {
        let mut hardened = false;
        if val.contains('\'') {
            hardened = true;
            val = val.trim_matches('\'');
        }
        if let Ok(parsed_int) = val.parse() {
            let (s, c) = get_child_key(secret_key, chain_code, parsed_int, hardened);
            secret_key = s;
            chain_code = c;
        } else {
            return Err(HdWalletError::InvalidPathSpec(hd_path.to_string()).into());
        }
    }
    Ok(secret_key)
}

/// This derives the master key from seed bytes, the actual usage is typically
/// for Cosmos key_import support, where we import a seed phrase.
fn master_key_from_seed(seed_bytes: &[u8]) -> ([u8; 32], [u8; 32]) {
    use hmac::Hmac;
    use hmac::Mac;
    type HmacSha512 = Hmac<Sha512>;

    let mut hasher = HmacSha512::new_from_slice(b"Bitcoin seed").unwrap();
    hasher.update(seed_bytes);
    let hash = hasher.finalize().into_bytes();
    let mut master_secret_key: [u8; 32] = [0; 32];
    let mut master_chain_code: [u8; 32] = [0; 32];
    master_secret_key.copy_from_slice(&hash[0..32]);
    master_chain_code.copy_from_slice(&hash[32..64]);

    // key check
    let _ = SecretKey::from_slice(&master_secret_key).unwrap();

    (master_secret_key, master_chain_code)
}

/// This keys the child key following the bip32 https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
/// specified derivation method. This method is internal because you should really be using the public API that
/// handles key path parsing.
fn get_child_key(
    k_parent: [u8; 32],
    c_parent: [u8; 32],
    i: u32,
    hardened: bool,
) -> ([u8; 32], [u8; 32]) {
    use hmac::Hmac;
    use hmac::Mac;
    type HmacSha512 = Hmac<Sha512>;

    let i = if hardened { 2u32.pow(31) + i } else { i };
    let mut hasher = HmacSha512::new_from_slice(&c_parent).unwrap();
    if hardened {
        hasher.update(&[0u8]);
        hasher.update(&k_parent);
    } else {
        let scep = Secp256k1::new();
        let private_key = SecretKey::from_slice(&k_parent).unwrap();
        let public_key = PublicKeyEC::from_secret_key(&scep, &private_key);
        hasher.update(&public_key.serialize());
    }
    hasher.update(&i.to_be_bytes());

    let l_param = hasher.finalize().into_bytes();
    let k_parent = Scalar::from_be_bytes(k_parent).unwrap();

    let mut parse_i_l = SecretKey::from_slice(&l_param[0..32]).unwrap();
    parse_i_l = parse_i_l.add_tweak(&k_parent).unwrap();
    let child_key = parse_i_l;

    let mut child_key_res: [u8; 32] = [0; 32];
    child_key_res
        .copy_from_slice(&hex_str_to_bytes(&child_key.display_secret().to_string()).unwrap());
    let mut chain_code_res: [u8; 32] = [0; 32];
    chain_code_res.copy_from_slice(&l_param[32..64]);
    (child_key_res, chain_code_res)
}
