//! KEM+DEM encryption with the MLKEM1024-P384 composite KEM.
//!
//! The ciphertext type is [HybridKemCt], which this module shares with
//! [crate::cryptography::hybrid_ml_kem].

use super::composite_mlkem1024_p384::{self, MlKem1024P384PrivateKey, MlKem1024P384PublicKey};
use super::error::CryptographyError;
use super::hybrid_ml_kem::HybridKemCt;
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, aead::Aead};
use rand::{CryptoRng, Rng};
use zeroize::Zeroizing;

/// Encrypt with the MLKEM1024-P384 composite KEM and AES-256-GCM payload layer.
pub(crate) fn enc_ml_kem_1024_p384<R: Rng + CryptoRng>(
    rng: &mut R,
    msg: &[u8],
    public_key: &MlKem1024P384PublicKey,
) -> Result<HybridKemCt, CryptographyError> {
    let (kem_ct, kem_shared_secret) = composite_mlkem1024_p384::encapsulate(rng, public_key)?;
    // Borrow the key out of the guarded buffer; copying it out would leave an
    // unwiped duplicate on the stack.
    let aead_key: &Key<Aes256Gcm> = (&*kem_shared_secret).into();
    let cipher = Aes256Gcm::new(aead_key);
    let nonce = Aes256Gcm::generate_nonce(rng);
    let payload_ct = cipher.encrypt(&nonce, msg)?;

    Ok(HybridKemCt {
        nonce: nonce.into(),
        kem_ct,
        payload_ct,
    })
}

/// Decrypt the AES-256-GCM payload using the MLKEM1024-P384 composite KEM.
pub(crate) fn dec_ml_kem_1024_p384(
    ct: HybridKemCt,
    private_key: &MlKem1024P384PrivateKey,
) -> Result<Zeroizing<Vec<u8>>, CryptographyError> {
    let kem_shared_secret = composite_mlkem1024_p384::decapsulate(&ct.kem_ct, private_key)?;
    // Borrow the key out of the guarded buffer; copying it out would leave an
    // unwiped duplicate on the stack.
    let aead_key: &Key<Aes256Gcm> = (&*kem_shared_secret).into();
    let cipher = Aes256Gcm::new(aead_key);
    let out = cipher.decrypt(&ct.nonce.into(), &*ct.payload_ct)?;
    Ok(Zeroizing::new(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_prng::AesRng;
    use rand::SeedableRng;

    #[test]
    fn mlkem1024_p384_pke_sunshine() {
        let mut rng = AesRng::seed_from_u64(0);
        let (private_key, public_key) = composite_mlkem1024_p384::keygen(&mut rng).unwrap();
        let msg = b"a message for the composite KEM";

        let ct = enc_ml_kem_1024_p384(&mut rng, msg, &public_key).unwrap();
        let pt = dec_ml_kem_1024_p384(ct, &private_key).unwrap();
        assert_eq!(msg.as_slice(), &*pt);
    }

    #[test]
    fn mlkem1024_p384_pke_wrong_key() {
        let mut rng = AesRng::seed_from_u64(0);
        let (_, public_key) = composite_mlkem1024_p384::keygen(&mut rng).unwrap();
        let (other_private_key, _) = composite_mlkem1024_p384::keygen(&mut rng).unwrap();

        let ct = enc_ml_kem_1024_p384(&mut rng, b"a message", &public_key).unwrap();
        let err = dec_ml_kem_1024_p384(ct, &other_private_key).unwrap_err();
        // ML-KEM rejects implicitly, so the failure surfaces as an AEAD tag error.
        assert!(matches!(err, CryptographyError::AesGcmError(..)));
    }

    #[test]
    fn mlkem1024_p384_pke_wrong_payload() {
        let mut rng = AesRng::seed_from_u64(0);
        let (private_key, public_key) = composite_mlkem1024_p384::keygen(&mut rng).unwrap();

        let mut ct = enc_ml_kem_1024_p384(&mut rng, b"a message", &public_key).unwrap();
        ct.payload_ct[0] ^= 1;
        assert!(dec_ml_kem_1024_p384(ct, &private_key).is_err());
    }

    #[test]
    fn mlkem1024_p384_pke_wrong_kem_ct_length() {
        let mut rng = AesRng::seed_from_u64(0);
        let (private_key, public_key) = composite_mlkem1024_p384::keygen(&mut rng).unwrap();

        let mut ct = enc_ml_kem_1024_p384(&mut rng, b"a message", &public_key).unwrap();
        ct.kem_ct.pop();
        assert!(matches!(
            dec_ml_kem_1024_p384(ct, &private_key),
            Err(CryptographyError::LengthError(_))
        ));
    }
}
