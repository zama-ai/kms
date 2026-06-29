use crate::constants::{CHI_XOR_CONSTANT, PHI_XOR_CONSTANT};
use aes::{
    Aes128, Block as AesBlock,
    cipher::{BlockCipherEncrypt, KeyInit},
};
pub use algebra::PRSSConversions;
use algebra::structure_traits::Ring;
use error_utils::anyhow_error_and_log;
use serde::{Deserialize, Serialize};
use tfhe_versionable::{Versionize, VersionsDispatch};
use threshold_types::commitment::KEY_BYTE_LEN;
use threshold_types::session_id::SessionId;

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum PrfKeyVersions {
    V0(PrfKey),
}

/// key for the PRF
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash, Eq, Versionize)]
#[versionize(PrfKeyVersions)]
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
/// Function Phi that generates bounded randomness for PRSS-Mask.Next(), evaluated over the
/// contiguous counter range `[start, start + count)`.
///
/// This currently assumes and checks that the value Bd_1 in the NIST doc is smaller than 2^126.
/// A single `encrypt_blocks` call is issued so the AES-NI backend can pipeline the blocks,
/// and the (loop-invariant) bounds are checked only once for the whole range.
pub(crate) fn phi_range(
    pa: &PhiAes,
    start: u128,
    count: usize,
    bd1: u128,
) -> anyhow::Result<Vec<i128>> {
    if count == 0 {
        return Ok(Vec::new());
    }

    // check that bd1 is within expected bounds, to avoid overflow when computing -Bd1 + (AES mod 2*Bd1)
    if bd1 > (1 << 126) {
        return Err(anyhow_error_and_log(
            "Bd1 must be at most 2^126 to not overflow, but is larger".to_string(),
        ));
    }

    // We assume the block counter is stored in ctr_bytes[15] (even though it's currently fixed to zero, given our parameters)
    // Thus, we need to check that ctr is smaller 2^120, so nothing gets overwritten by setting the index below.
    // Also ensure it doesn't overflow when adding count-1 to it.
    let max_ctr = start.saturating_add(count as u128 - 1);
    if max_ctr >= 1 << 120 {
        return Err(anyhow_error_and_log(format!(
            "ctr in phi must be smaller than 2^120 but was {max_ctr}."
        )));
    }

    // Number of AES blocks per value, currently limited to 1. See NOTE above.
    let v = (((bd1 + 1) as f32).log2() / 128_f32).ceil() as u32;
    debug_assert_eq!(v, 1);

    // TODO iterate over blocks from 0..v here, if we ever need Bd1 > 2^126
    let mut blocks = Vec::with_capacity(count);
    for k in 0..count {
        let mut ctr_bytes = (start + k as u128).to_le_bytes();
        ctr_bytes[15] = 0; // v - the block counter, currently fixed to zero
        let block = AesBlock::from(ctr_bytes);
        blocks.push(block);
    }

    // single pipelined AES call over the whole range
    pa.aes.encrypt_blocks(&mut blocks);

    let modulus = 2 * bd1;
    let neg_bd1 = -(bd1 as i128);
    let mut res = Vec::with_capacity(count);
    for block in blocks {
        let out = u128::from_le_bytes(block.into());
        // compute output as -BD1 + (AES (mod 2*BD1)), a uniform random value in [-BD1 .. BD1)
        res.push(neg_bd1 + (out % modulus) as i128);
    }
    Ok(res)
}

/// Number of AES blocks encrypted per `encrypt_blocks` call in psi/chi. Sized to the AES-NI /
/// ARMv8 parallel width so a single batch covers the common degree-8 case, while a stack buffer
/// (rather than a per-call heap allocation) holds the blocks.
const AES_BATCH: usize = 8;

#[inline(always)]
fn encrypt_indexed_prf_blocks<Z, F>(aes: &Aes128, ctr: u128, mut encode_block_indices: F) -> Z
where
    Z: Ring + PRSSConversions,
    F: FnMut(&mut AesBlock, usize, usize),
{
    // Compute v = ceil(log(q)/128) if q is a power of 2, v = dist + log(q)/128 otherwise.
    let num_u128_base_ring = Z::NUM_BITS_STAT_SEC_BASE_RING.div_ceil(128);
    let n_blocks = Z::EXTENSION_DEGREE * num_u128_base_ring;
    let base = ctr.to_le_bytes();

    let mut chunks = Vec::with_capacity(n_blocks);
    let mut buf = [AesBlock::from([0u8; 16]); AES_BATCH];
    let mut start = 0;
    while start < n_blocks {
        let chunk = (n_blocks - start).min(AES_BATCH);
        for (slot, block) in buf[..chunk].iter_mut().enumerate() {
            let idx = start + slot;
            block.copy_from_slice(&base);
            let v = idx % num_u128_base_ring;
            let i = idx / num_u128_base_ring;
            encode_block_indices(block, i, v);
        }
        aes.encrypt_blocks(&mut buf[..chunk]);
        for block in &buf[..chunk] {
            chunks.push(u128::from_le_bytes((*block).into()));
        }
        start += chunk;
    }

    Z::from_u128_chunks(chunks)
}

/// Function Psi that generates bounded randomness for PRSS.next()
pub(crate) fn psi<Z: Ring + PRSSConversions>(pa: &PsiAes, ctr: u128) -> anyhow::Result<Z> {
    // Bytes 14 and 15 are reserved for the dimension index and block counter. Keep ctr below
    // 2^112 so those bytes are zero before we write the indices below.
    if ctr >= 1 << 112 {
        return Err(anyhow_error_and_log(format!(
            "ctr in psi must be smaller than 2^112 but was {ctr}."
        )));
    }

    Ok(encrypt_indexed_prf_blocks(&pa.aes, ctr, |block, i, v| {
        block[15] = v as u8;
        block[14] = i as u8;
    }))
}

/// Function Chi that generates bounded randomness for PRZS.next()
/// This currently assumes that q = 2^128
pub(crate) fn chi<Z: Ring + PRSSConversions>(pa: &ChiAes, ctr: u128, j: u8) -> anyhow::Result<Z> {
    // Bytes 13, 14, and 15 are reserved for the threshold index, dimension index, and block
    // counter. Keep ctr below 2^104 so those bytes are zero before we write the indices below.
    if ctr >= 1 << 104 {
        return Err(anyhow_error_and_log(format!(
            "ctr in chi must be smaller than 2^104 but was {ctr}."
        )));
    }

    Ok(encrypt_indexed_prf_blocks(&pa.aes, ctr, |block, i, v| {
        block[15] = v as u8;
        block[14] = i as u8;
        block[13] = j;
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{B_SWITCH_SQUASH, LOG_B_SWITCH_SQUASH, STATSEC};
    use algebra::galois_rings::degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128};

    /// Single-value convenience wrapper over [`phi_range`] used by the phi tests.
    fn phi(pa: &PhiAes, ctr: u128, bd1: u128) -> anyhow::Result<i128> {
        Ok(phi_range(pa, ctr, 1, bd1)?[0])
    }

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
        test_chi::<ResiduePolyF4Z64>();
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
        let mut chi_block = AesBlock::from([42u8; 16]);
        let mut psi_block = AesBlock::from([42u8; 16]);
        let mut phi_block = AesBlock::from([42u8; 16]);

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
