use crate::algebra::structure_traits::Ring;
use crate::commitment::KEY_BYTE_LEN;
use crate::error::error_handler::anyhow_error_and_log;
use crate::execution::constants::{CHI_XOR_CONSTANT, PHI_XOR_CONSTANT};
use crate::session_id::SessionId;
#[allow(deprecated)]
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use serde::{Deserialize, Serialize};
use tfhe::Versionize;
use tfhe_versionable::VersionsDispatch;

/// Trait required for PRSS executions
pub trait PRSSConversions {
    fn from_u128_chunks(coefs: Vec<u128>) -> Self;
    fn from_i128(value: i128) -> Self;
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum PrfKeyVersioned {
    V0(PrfKey),
}

/// key for the PRF
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash, Eq, Versionize)]
#[versionize(PrfKeyVersioned)]
pub struct PrfKey(pub [u8; 16]);

/// helper function that compute bit-wise xor of two byte arrays in place (overwriting the first argument `arr1`)
/// TODO maybe not the best place for this function
pub(crate) fn xor_u8_arr_in_place(arr1: &mut [u8; KEY_BYTE_LEN], arr2: &[u8; KEY_BYTE_LEN]) {
    for i in 0..KEY_BYTE_LEN {
        arr1[i] ^= arr2[i];
    }
}

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
        xor_u8_arr_in_place(&mut phi_key, &sid.to_le_bytes());

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
        xor_u8_arr_in_place(&mut chi_key, &sid.to_le_bytes());

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
        xor_u8_arr_in_place(&mut psi_key, &sid.to_le_bytes());

        PsiAes {
            aes: Aes128::new(&psi_key.into()),
        }
    }
}

//NOTE: I BELIEVE WE NEVER NEED PRSS-MASK TO GENERATE MASK BIGGER THAN 2^126 EVEN FOR BGV
//AFAICT, ONLY USED IN BGV DDEC WITH BD1<Q1 AND Q1 IS 94BIT LONG
/// Function Phi that generates bounded randomness for PRSS-Mask.Next()
/// This currently assumes that the value Bd_1 in the NIST doc is smaller than 2^126
pub(crate) fn phi(pa: &PhiAes, ctr: u128, bd1: u128) -> anyhow::Result<i128> {
    // we currently assume that Bd1 is at most 126 bits large, so we only need a single block of AES and can fit the result in an i128.
    // check that bd1 is small enough to not cause overflow of the result
    if bd1 > (1 << 126) {
        return Err(anyhow_error_and_log(
            "Bd1 must be at most 2^126 to not overflow, but is larger".to_string(),
        ));
    }

    // check ctr is smaller 2^120, so nothing gets overwritten by setting the index below
    if ctr >= 1 << 120 {
        return Err(anyhow_error_and_log(format!(
            "ctr in phi must be smaller than 2^120 but was {ctr}."
        )));
    }

    // number of AES blocks, currently limited to 1. See NOTE above.
    let v = (((bd1 + 1) as f32).log2() / 128_f32).ceil() as u32;
    debug_assert_eq!(v, 1);

    // TODO iterate over blocks form 0..v here if we ever need Bd1 > 2^126
    let mut ctr_bytes = ctr.to_le_bytes();
    ctr_bytes[15] = 0; // v - the block counter, currently fixed to zero
    #[allow(deprecated)]
    let mut to_enc = GenericArray::from(ctr_bytes);
    pa.aes.encrypt_block(&mut to_enc);
    let out = u128::from_le_bytes(to_enc.into());

    // compute output as -BD1 + (AES (mod 2*BD1)), a uniform random value in [-BD1 .. BD1)
    let ret: i128 = -(bd1 as i128) + (out % (2 * bd1)) as i128;

    Ok(ret)
}

/// Function Psi that generates bounded randomness for PRSS.next()
pub(crate) fn psi<Z: Ring + PRSSConversions>(pa: &PsiAes, ctr: u128) -> anyhow::Result<Z> {
    // check ctr is smaller 2^112, so nothing gets overwritten by setting the indices in inner_psi
    if ctr >= 1 << 112 {
        return Err(anyhow_error_and_log(format!(
            "ctr in psi must be smaller than 2^112 but was {ctr}."
        )));
    }

    //Compute v = ceil(log(q)/128) if q power of 2, v = (dist + log(q)/128) else
    let num_u128_base_ring = Z::NUM_BITS_STAT_SEC_BASE_RING.div_ceil(128);
    let mut coefs = vec![0_u128; Z::EXTENSION_DEGREE * num_u128_base_ring];

    //Loop over psi^(i)
    for i in 0..Z::EXTENSION_DEGREE {
        //loop over block counter for each base ring element
        for block_ctr in 0..num_u128_base_ring {
            coefs[i * num_u128_base_ring + block_ctr] =
                inner_psi(pa, ctr, i as u8, block_ctr as u8);
        }
    }

    Ok(Z::from_u128_chunks(coefs))
}

/// Inner function Psi^(i) that generates bounded randomness for PRSS.next()
fn inner_psi(pa: &PsiAes, ctr: u128, i: u8, block_ctr: u8) -> u128 {
    let mut ctr_bytes = ctr.to_le_bytes();

    // pad/truncate ctr value and put v and i in the MSBs
    ctr_bytes[15] = block_ctr; // v - the block counter
    ctr_bytes[14] = i; // i - the dimension index
    #[allow(deprecated)]
    let mut to_enc = GenericArray::from(ctr_bytes);
    pa.aes.encrypt_block(&mut to_enc);
    u128::from_le_bytes(to_enc.into())
}

/// Function Chi that generates bounded randomness for PRZS.next()
/// This currently assumes that q = 2^128
pub(crate) fn chi<Z: Ring + PRSSConversions>(pa: &ChiAes, ctr: u128, j: u8) -> anyhow::Result<Z> {
    // check ctr is smaller 2^104, so nothing gets overwritten by setting the indices in inner_chi
    if ctr >= 1 << 104 {
        return Err(anyhow_error_and_log(format!(
            "ctr in chi must be smaller than 2^104 but was {ctr}."
        )));
    }

    //Compute v = ceil(log(q)/128) if q power of 2, v = (dist + log(q)/128) else
    let num_u128_base_ring = Z::NUM_BITS_STAT_SEC_BASE_RING.div_ceil(128);
    let mut coefs = vec![0_u128; Z::EXTENSION_DEGREE * num_u128_base_ring];

    //Loop over chi^(i)
    for i in 0..Z::EXTENSION_DEGREE {
        //loop over block counter for each base ring element
        for block_ctr in 0..num_u128_base_ring {
            coefs[i * num_u128_base_ring + block_ctr] =
                inner_chi(pa, ctr, i as u8, j, block_ctr as u8);
        }
    }

    Ok(Z::from_u128_chunks(coefs))
}

/// Inner function Chi^(i) that generates bounded randomness for PRZS.next()
fn inner_chi(pa: &ChiAes, ctr: u128, i: u8, j: u8, block_ctr: u8) -> u128 {
    let mut ctr_bytes = ctr.to_le_bytes();

    // pad/truncate ctr value and put v and i in the MSBs, and j in the LSBs
    ctr_bytes[15] = block_ctr; // v - the block counter
    ctr_bytes[14] = i; // i - the dimension index
    ctr_bytes[13] = j; // j - the threshold index
    #[allow(deprecated)]
    let mut to_enc = GenericArray::from(ctr_bytes);
    pa.aes.encrypt_block(&mut to_enc);
    u128::from_le_bytes(to_enc.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
        execution::constants::{B_SWITCH_SQUASH, LOG_B_SWITCH_SQUASH, STATSEC},
    };

    #[test]
    fn test_phi() {
        let key = PrfKey([123_u8; 16]);
        let aes = PhiAes::new(&key, SessionId::from(0));
        let mut prev = 0_i128;

        // test for B_SWITCH_SQUASH * 2^STATSEC  (currently even, so we can count bits using ilog2)
        for ctr in 0..100 {
            let bd1 = B_SWITCH_SQUASH * (1 << STATSEC);
            let res = phi(&aes, ctr, bd1).unwrap();
            let log = res.abs().ilog2();
            assert!(log < (LOG_B_SWITCH_SQUASH + STATSEC));
            assert!(-(bd1 as i128) <= res);
            assert!(bd1 as i128 > res);
            assert_ne!(prev, res);
            prev = res;
        }

        // test for some odd bound value
        let odd_bound = (1 << 113) + 23;
        for ctr in 0..100 {
            let res = phi(&aes, ctr, odd_bound).unwrap();
            assert!(-(odd_bound as i128) <= res);
            assert!(odd_bound as i128 > res);
            assert_ne!(prev, res);
            prev = res;
        }

        assert_eq!(
            phi(&aes, 0, B_SWITCH_SQUASH).unwrap(),
            phi(&aes, 0, B_SWITCH_SQUASH).unwrap()
        );

        let aes_2 = PhiAes::new(&key, SessionId::from(2));
        assert_ne!(
            phi(&aes, 0, B_SWITCH_SQUASH).unwrap(),
            phi(&aes_2, 0, B_SWITCH_SQUASH).unwrap()
        );

        let err_overflow = phi(&aes, 0, 1 << 127).unwrap_err().to_string();
        assert!(err_overflow.contains("Bd1 must be at most 2^126 to not overflow, but is larger"));

        let err_ctr = phi(&aes, 1 << 123, B_SWITCH_SQUASH)
            .unwrap_err()
            .to_string();
        assert!(err_ctr.contains(
            "ctr in phi must be smaller than 2^120 but was 10633823966279326983230456482242756608."
        ));
    }

    fn test_psi<Z: Ring + PRSSConversions>() {
        let key = PrfKey([23_u8; 16]);
        let aes = PsiAes::new(&key, SessionId::from(0));
        assert_ne!(psi::<Z>(&aes, 0).unwrap(), psi(&aes, 1).unwrap());
        assert_eq!(psi::<Z>(&aes, 0).unwrap(), psi(&aes, 0).unwrap());

        let aes_2 = PsiAes::new(&key, SessionId::from(2));
        assert_ne!(psi::<Z>(&aes, 0).unwrap(), psi(&aes_2, 0).unwrap());

        let err_ctr = psi::<Z>(&aes, 1 << 123).unwrap_err().to_string();
        assert!(err_ctr.contains(
            "ctr in psi must be smaller than 2^112 but was 10633823966279326983230456482242756608."
        ));
    }

    #[test]
    fn test_pi_z128() {
        test_psi::<ResiduePolyF4Z128>();
    }

    #[test]
    fn test_pi_64() {
        test_psi::<ResiduePolyF4Z64>();
    }

    fn test_chi<Z: Ring + PRSSConversions>() {
        let key = PrfKey([23_u8; 16]);
        let aes = ChiAes::new(&key, SessionId::from(0));
        assert_ne!(chi::<Z>(&aes, 0, 0).unwrap(), chi(&aes, 1, 0).unwrap());
        assert_ne!(chi::<Z>(&aes, 0, 0).unwrap(), chi(&aes, 0, 1).unwrap());
        assert_eq!(chi::<Z>(&aes, 0, 0).unwrap(), chi(&aes, 0, 0).unwrap());

        let aes_2 = ChiAes::new(&key, SessionId::from(2));
        assert_ne!(chi::<Z>(&aes, 0, 0).unwrap(), chi(&aes_2, 0, 0).unwrap());

        let err_ctr = chi::<Z>(&aes, 1 << 123, 0).unwrap_err().to_string();
        assert!(err_ctr.contains(
            "ctr in chi must be smaller than 2^104 but was 10633823966279326983230456482242756608."
        ));
    }

    #[test]
    fn test_chi_z128() {
        test_chi::<ResiduePolyF4Z128>();
    }

    #[test]
    fn test_chi_z64() {
        test_chi::<ResiduePolyF4Z128>();
    }

    /// check that all three PRFs cause different encryptions, even when initialized from the same key
    fn test_all_prfs_differ<Z: Ring + PRSSConversions>() {
        // init PRFs with identical key
        let key = PrfKey([123_u8; 16]);
        let chiaes = ChiAes::new(&key, SessionId::from(0));
        let psiaes = PsiAes::new(&key, SessionId::from(0));
        let phiaes = PhiAes::new(&key, SessionId::from(0));

        // test direct PRF calls
        assert_ne!(chi::<Z>(&chiaes, 0, 0).unwrap(), psi(&psiaes, 0).unwrap());

        // initialize identical 128-bit block
        #[allow(deprecated)]
        let mut chi_block = GenericArray::from([42u8; 16]);
        #[allow(deprecated)]
        let mut psi_block = GenericArray::from([42u8; 16]);
        #[allow(deprecated)]
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

    #[test]
    fn test_all_prfs_differ_z128() {
        test_all_prfs_differ::<ResiduePolyF4Z128>();
    }

    #[test]
    fn test_all_prfs_differ_z64() {
        test_all_prfs_differ::<ResiduePolyF4Z64>();
    }
}
