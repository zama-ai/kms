use crate::computation::SessionId;
use crate::error::error_handler::anyhow_error_and_log;
use crate::execution::agree_random::xor_u8_arr_in_place;
use crate::execution::constants::{CHI_XOR_CONSTANT, PHI_XOR_CONSTANT};
use crate::execution::small_execution::prss::PrfKey;
use crate::residue_poly::{ResiduePoly, F_DEG};
use crate::{Zero, Z128};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use std::num::Wrapping;

#[derive(Debug, Clone)]
pub(crate) struct PhiAes {
    aes: Aes128,
}

impl PhiAes {
    pub fn new(key: &PrfKey, sid: SessionId) -> Self {
        // initialize AES cipher here to do the key schedule just once.
        let mut phi_key = key.0;

        // XOR key with 2 to ensure domain separation, since we're using the same key for two kinds of PRSS and a PRZS
        phi_key[0] ^= PHI_XOR_CONSTANT;

        // XOR sid into key
        xor_u8_arr_in_place(&mut phi_key, &sid.0.to_le_bytes());

        PhiAes {
            aes: Aes128::new(&phi_key.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ChiAes {
    aes: Aes128,
}

impl ChiAes {
    pub fn new(key: &PrfKey, sid: SessionId) -> Self {
        // initialize AES cipher here to do the key schedule just once.
        let mut chi_key = key.0;
        // XOR key with 1 to ensure domain separation, since we're using the same key for two kinds of PRSS and a PRZS
        chi_key[0] ^= CHI_XOR_CONSTANT;

        // XOR sid into key
        xor_u8_arr_in_place(&mut chi_key, &sid.0.to_le_bytes());

        ChiAes {
            aes: Aes128::new(&chi_key.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PsiAes {
    aes: Aes128,
}

impl PsiAes {
    pub fn new(key: &PrfKey, sid: SessionId) -> Self {
        // initialize AES cipher here to do the key schedule just once.
        let mut psi_key = key.0;

        // deliberately no tweak/constant XOR here as we use the key in psi as-is.

        // XOR sid into key
        xor_u8_arr_in_place(&mut psi_key, &sid.0.to_le_bytes());

        PsiAes {
            aes: Aes128::new(&psi_key.into()),
        }
    }
}

/// Function Phi that generates bounded randomness for PRSS-Mask.Next()
/// This currently assumes that the value Bd_1 in the NIST doc is a power of two
pub(crate) fn phi(pa: &PhiAes, ctr: u128, bd1: u128) -> anyhow::Result<i128> {
    // we currently assume that Bd1 is a power of two and at most 126 bits large, so we only need a single block of AES and can fit the result in an i128.

    // check that bd1 is a power of two
    if 1 << bd1.ilog2() != bd1.next_power_of_two() {
        return Err(anyhow_error_and_log(
            "Bd1 must be a power of two, but is not.".to_string(),
        ));
    }

    // check that bd1 is small enough to not cause overflow of the result
    if bd1 > (1 << 126) {
        return Err(anyhow_error_and_log(
            "Bd1 must be at most 2^126 to not overflow, but is larger".to_string(),
        ));
    }

    // number of AES blocks, currently limited to 1. This will grow once BGV decryption is implemented
    let v = (((bd1 + 1) as f32).log2() / 128_f32).ceil() as u32;
    debug_assert_eq!(v, 1);

    // TODO iterate over blocks form 0..v here, once we have big number arithmetic for BGV in place
    let mut ctr_bytes = ctr.to_le_bytes();
    ctr_bytes[15] = 0; // v - the block counter, currently fixed to zero
    let mut to_enc = GenericArray::from(ctr_bytes);
    pa.aes.encrypt_block(&mut to_enc);
    let out = u128::from_le_bytes(to_enc.into());

    // compute output as -BD1 + (AES (mod 2*BD1)), a uniform random value in [-BD1 .. BD1)
    let ret: i128 = -(bd1 as i128) + (out % (2 * bd1)) as i128;

    Ok(ret)
}

/// Function Psi that generates bounded randomness for PRSS.next()
/// This currently assumes that q is 2^128
pub(crate) fn psi(pa: &PsiAes, ctr: u128) -> ResiduePoly<Z128> {
    let mut coefs = [Z128::ZERO; F_DEG];

    for (i, c) in coefs.iter_mut().enumerate().take(F_DEG) {
        *c = inner_psi(pa, ctr, i as u8);
    }

    ResiduePoly::<Z128> { coefs }
}

/// Inner function Psi^(i) that generates bounded randomness for PRSS.next()
/// This currently assumes that q = 2^128
fn inner_psi(pa: &PsiAes, ctr: u128, i: u8) -> Z128 {
    let mut ctr_bytes = ctr.to_le_bytes();

    // pad/truncate ctr value and put v and i in the MSBs
    ctr_bytes[15] = 0; // v - the block counter, currently fixed to zero
    ctr_bytes[14] = i; // i - the dimension index
    let mut to_enc = GenericArray::from(ctr_bytes);
    pa.aes.encrypt_block(&mut to_enc);
    let out = u128::from_le_bytes(to_enc.into());

    Wrapping(out)
}

/// Function Chi that generates bounded randomness for PRZS.next()
/// This currently assumes that q = 2^128
pub(crate) fn chi(pa: &ChiAes, ctr: u128, j: u8) -> ResiduePoly<Z128> {
    let mut coefs = [Z128::ZERO; F_DEG];

    for (i, c) in coefs.iter_mut().enumerate().take(F_DEG) {
        *c = inner_chi(pa, ctr, i as u8, j);
    }

    ResiduePoly::<Z128> { coefs }
}

/// Inner function Chi^(i) that generates bounded randomness for PRZS.next()
/// This currently assumes that q is 2^128
fn inner_chi(pa: &ChiAes, ctr: u128, i: u8, j: u8) -> Z128 {
    // shift ctr by 8 bits, so we can put j in the LSBs, as described in the NIST doc
    let mut ctr_bytes = (ctr << 8).to_le_bytes();

    // pad/truncate ctr value and put v and i in the MSBs, and j in the LSBs
    ctr_bytes[15] = 0; // v - the block counter, currently fixed to zero
    ctr_bytes[14] = i; // i - the dimension index
    ctr_bytes[0] = j; // j - the threshold index
    let mut to_enc = GenericArray::from(ctr_bytes);
    pa.aes.encrypt_block(&mut to_enc);
    let out = u128::from_le_bytes(to_enc.into());

    Wrapping(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::constants::{BD1, LOG_BD, STATSEC};

    #[test]
    fn test_phi() {
        let key = PrfKey([123_u8; 16]);
        let aes = PhiAes::new(&key, SessionId(0));
        let mut prev = 0_i128;
        for ctr in 0..100 {
            let res = phi(&aes, ctr, BD1).unwrap();
            let log = res.abs().ilog2();
            assert!(log < (LOG_BD + STATSEC));
            assert!(-(BD1 as i128) <= res);
            assert!(BD1 as i128 > res);
            assert_ne!(prev, res);
            prev = res;
        }

        assert_eq!(phi(&aes, 0, BD1).unwrap(), phi(&aes, 0, BD1).unwrap());

        let aes_2 = PhiAes::new(&key, SessionId(2));
        assert_ne!(phi(&aes, 0, BD1).unwrap(), phi(&aes_2, 0, BD1).unwrap());
    }

    #[test]
    fn test_phi_error() {
        let key = PrfKey([123_u8; 16]);
        let aes = PhiAes::new(&key, SessionId(0));

        let err_overflow = phi(&aes, 0, 1 << 127).unwrap_err().to_string();
        assert!(err_overflow.contains("Bd1 must be at most 2^126 to not overflow, but is larger"));

        let err_overflow = phi(&aes, 0, 3).unwrap_err().to_string();
        assert!(err_overflow.contains("Bd1 must be a power of two, but is not."));
    }

    #[test]
    fn test_psi() {
        let key = PrfKey([23_u8; 16]);
        let aes = PsiAes::new(&key, SessionId(0));
        assert_ne!(psi(&aes, 0), psi(&aes, 1));
        assert_eq!(psi(&aes, 0), psi(&aes, 0));

        let aes_2 = PsiAes::new(&key, SessionId(2));
        assert_ne!(psi(&aes, 0), psi(&aes_2, 0));
    }

    #[test]
    fn test_chi() {
        let key = PrfKey([23_u8; 16]);
        let aes = ChiAes::new(&key, SessionId(0));
        assert_ne!(chi(&aes, 0, 0), chi(&aes, 1, 0));
        assert_ne!(chi(&aes, 0, 0), chi(&aes, 0, 1));
        assert_eq!(chi(&aes, 0, 0), chi(&aes, 0, 0));

        let aes_2 = ChiAes::new(&key, SessionId(2));
        assert_ne!(chi(&aes, 0, 0), chi(&aes_2, 0, 0));
    }

    /// check that all three PRFs cause different encryptions, even when initialized from the same key
    #[test]
    fn test_all_prfs_differ() {
        // init PRFs with identical key
        let key = PrfKey([123_u8; 16]);
        let chiaes = ChiAes::new(&key, SessionId(0));
        let psiaes = PsiAes::new(&key, SessionId(0));
        let phiaes = PhiAes::new(&key, SessionId(0));

        // test direct PRF calls
        assert_ne!(chi(&chiaes, 0, 0), psi(&psiaes, 0));

        // initialize identical 128-bit block
        let mut chi_block = GenericArray::from([42u8; 16]);
        let mut psi_block = GenericArray::from([42u8; 16]);
        let mut phi_block = GenericArray::from([42u8; 16]);

        // encrypt with different PRFs
        chiaes.aes.encrypt_block(&mut chi_block);
        psiaes.aes.encrypt_block(&mut psi_block);
        phiaes.aes.encrypt_block(&mut phi_block);

        // encryptions must differ
        assert_ne!(chi_block, psi_block);
        assert_ne!(chi_block, phi_block);
        assert_ne!(phi_block, psi_block);
    }
}
