use aws_lc_rs::aead;
use aws_lc_rs::kem;

use crate::error::BackupError;

pub fn keygen() -> Result<(kem::DecapsulationKey, kem::EncapsulationKey), BackupError> {
    let dec_k = kem::DecapsulationKey::generate(&kem::ML_KEM_512)?;
    let enc_k = dec_k.encapsulation_key()?;
    Ok((dec_k, enc_k))
}

pub struct BackupCiphertext {
    pub kem_ct: Vec<u8>,
    pub ct: Vec<u8>,
    pub nonce: aead::Nonce,
}

impl Clone for BackupCiphertext {
    fn clone(&self) -> Self {
        // There seems to be no easy way to clone the nonce
        let cloned_nonce = aead::Nonce::from(self.nonce.as_ref());
        Self {
            kem_ct: self.kem_ct.clone(),
            ct: self.ct.clone(),
            nonce: cloned_nonce,
        }
    }
}

pub fn enc(msg: &[u8], enc_k: &kem::EncapsulationKey) -> Result<BackupCiphertext, BackupError> {
    let (kem_ct, kem_shared_secret) = enc_k.encapsulate()?;
    let keylen = aead::AES_128_GCM.key_len();
    debug_assert!(kem_shared_secret.as_ref().len() >= keylen);

    let aead_key =
        aead::RandomizedNonceKey::new(&aead::AES_128_GCM, &kem_shared_secret.as_ref()[..keylen])?;
    let mut buf = msg.to_vec();
    let nonce = aead_key.seal_in_place_append_tag(aead::Aad::empty(), &mut buf)?;

    Ok(BackupCiphertext {
        kem_ct: kem_ct.as_ref().to_vec(),
        ct: buf,
        nonce,
    })
}

pub fn dec(ct: BackupCiphertext, dec_k: &kem::DecapsulationKey) -> Result<Vec<u8>, BackupError> {
    let BackupCiphertext {
        kem_ct,
        mut ct,
        nonce,
    } = ct;

    let kem_shared_secret = dec_k.decapsulate(kem::Ciphertext::from(&kem_ct[..]))?;
    let keylen = aead::AES_128_GCM.key_len();
    debug_assert!(kem_shared_secret.as_ref().len() >= keylen);

    let aead_key =
        aead::RandomizedNonceKey::new(&aead::AES_128_GCM, &kem_shared_secret.as_ref()[..keylen])?;

    let out = aead_key.open_in_place(nonce, aead::Aad::empty(), &mut ct)?;
    Ok(out.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn pke_sunshine(msg: Vec<u8>) {
            let (sk, pk) = keygen().unwrap();
            let ct = enc(&msg, &pk).unwrap();
            let pt = dec(ct, &sk).unwrap();
            assert_eq!(msg, pt);
        }

        #[test]
        fn pke_wrong_key(msg: Vec<u8>) {
            let (_sk, pk) = keygen().unwrap();
            let (sk, _pk) = keygen().unwrap();
            let ct = enc(&msg, &pk).unwrap();
            let err = dec(ct, &sk).unwrap_err();
            assert!(matches!(err, BackupError::UnspecifiedError(..)));
        }

        #[test]
        fn pke_wrong_ct(msg: Vec<u8>) {
            let (sk, pk) = keygen().unwrap();
            let mut ct = enc(&msg, &pk).unwrap();
            ct.ct[0] ^= 1;
            let err = dec(ct, &sk).unwrap_err();
            assert!(matches!(err, BackupError::UnspecifiedError(..)));
        }
    }
}
