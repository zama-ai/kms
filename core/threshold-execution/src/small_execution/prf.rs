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
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum PrfKeyVersions {
    V0(PrfKey),
}

/// key for the PRF.
#[derive(
    Debug, Clone, Serialize, Deserialize, PartialEq, Hash, Eq, Versionize, Zeroize, ZeroizeOnDrop,
)]
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

/// Builds the complete block before writing it, avoiding overlapping writes to its counter and index bytes.
#[inline(always)]
fn write_block(block: &mut AesBlock, word: u128) {
    *block = AesBlock::from(word.to_le_bytes());
}

/// Number of AES blocks encrypted per `encrypt_blocks` call in scalar psi/chi.
/// One stack buffer covers the degree-eight case; the backend chooses how to parallelize these blocks.
const AES_BATCH: usize = 8;

#[inline(always)]
fn encrypt_indexed_prf_blocks<Z, F>(aes: &Aes128, ctr: u128, block_indices: F) -> Z
where
    Z: Ring + PRSSConversions,
    F: Fn(usize, usize) -> u128,
{
    // Compute v = ceil(log(q)/128) if q is a power of 2, v = dist + log(q)/128 otherwise.
    let num_u128_base_ring = Z::NUM_BITS_STAT_SEC_BASE_RING.div_ceil(128);
    let n_blocks = Z::EXTENSION_DEGREE * num_u128_base_ring;
    let mut chunks = Vec::with_capacity(n_blocks);
    let mut buf = [AesBlock::from([0u8; 16]); AES_BATCH];
    let mut start = 0;
    while start < n_blocks {
        let chunk = (n_blocks - start).min(AES_BATCH);
        for (slot, block) in buf[..chunk].iter_mut().enumerate() {
            let idx = start + slot;
            let v = idx % num_u128_base_ring;
            let i = idx / num_u128_base_ring;
            // Counter bounds leave the index bytes zero. Construct the complete input before writing the block.
            write_block(block, ctr | block_indices(i, v));
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

    Ok(encrypt_indexed_prf_blocks(&pa.aes, ctr, |i, v| {
        ((v as u8) as u128) << 120 | ((i as u8) as u128) << 112
    }))
}

/// Evaluates one counter, converting encrypted blocks directly into fixed-size ring coefficients.
pub(crate) fn psi_iter<Z: Ring + PRSSConversions>(pa: &PsiAes, ctr: u128) -> anyhow::Result<Z> {
    // These rings use one AES block per coefficient. Other shapes use the general encoding and conversion.
    if !matches!(Z::EXTENSION_DEGREE, 4 | 8) || !matches!(Z::NUM_BITS_STAT_SEC_BASE_RING, 64 | 128)
    {
        return psi(pa, ctr);
    }
    if ctr >= 1 << 112 {
        return Err(anyhow_error_and_log(format!(
            "ctr in psi must be smaller than 2^112 but was {ctr}."
        )));
    }

    // Four or eight coefficients fit in one stack buffer and one encrypt_blocks call.
    let mut blocks = [AesBlock::default(); AES_BATCH];
    let blocks = &mut blocks[..Z::EXTENSION_DEGREE];
    for (coefficient, block) in blocks.iter_mut().enumerate() {
        write_block(block, ctr | ((coefficient as u8) as u128) << 112);
    }
    pa.aes.encrypt_blocks(blocks);

    // Fill the ring's coefficient array directly, without allocating a conversion buffer.
    Ok(Z::from_u128_iter(
        blocks
            .iter()
            .map(|block| u128::from_le_bytes((*block).into())),
    ))
}

/// Evaluates consecutive counters under one key, preserving the encoding of individual calls to [`psi`].
/// Returns an error if any counter reaches 2^112. Panics if `COUNTERS` is zero.
pub(crate) fn psi_counters<Z: Ring + PRSSConversions, const COUNTERS: usize>(
    pa: &PsiAes,
    ctr: u128,
) -> anyhow::Result<[Z; COUNTERS]> {
    assert!(
        COUNTERS > 0,
        "a PRF group must contain at least one counter"
    );
    let limit = 1_u128 << 112;
    if ctr >= limit || COUNTERS as u128 > limit - ctr {
        let invalid = ctr.max(limit);
        return Err(anyhow_error_and_log(format!(
            "ctr in psi must be smaller than 2^112 but was {invalid}."
        )));
    }
    if !matches!(Z::EXTENSION_DEGREE, 4 | 8) || !matches!(Z::NUM_BITS_STAT_SEC_BASE_RING, 64 | 128)
    {
        let mut values = [Z::ZERO; COUNTERS];
        for (offset, value) in values.iter_mut().enumerate() {
            *value = psi(pa, ctr + offset as u128)?;
        }
        return Ok(values);
    }

    // Nested arrays allow a const counter count without generic const arithmetic. Only the first
    // COUNTERS * degree blocks are used; both encryption and conversion use stack storage.
    let mut storage = [[AesBlock::default(); 8]; COUNTERS];
    let degree = Z::EXTENSION_DEGREE;
    let blocks = &mut storage.as_flattened_mut()[..COUNTERS * degree];
    for (offset, output_blocks) in blocks.chunks_exact_mut(degree).enumerate() {
        for (coefficient, block) in output_blocks.iter_mut().enumerate() {
            let word = (ctr + offset as u128) | ((coefficient as u8) as u128) << 112;
            write_block(block, word);
        }
    }
    // Give the backend the complete group so it can interleave independent AES round chains.
    // Four counters supply 16 blocks for F4 and 32 for F8.
    pa.aes.encrypt_blocks(blocks);
    Ok(std::array::from_fn(|offset| {
        let first = offset * degree;
        Z::from_u128_iter(
            blocks[first..first + degree]
                .iter()
                .map(|block| u128::from_le_bytes((*block).into())),
        )
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

    Ok(encrypt_indexed_prf_blocks(&pa.aes, ctr, |i, v| {
        ((v as u8) as u128) << 120 | ((i as u8) as u128) << 112 | (j as u128) << 104
    }))
}

/// Evaluates consecutive PRZS counters at one threshold index, preserving individual [`chi`] encodings.
/// Returns an error if any counter reaches 2^104. Panics if `COUNTERS` is zero.
pub(crate) fn chi_counters<Z: Ring + PRSSConversions, const COUNTERS: usize>(
    pa: &ChiAes,
    ctr: u128,
    j: u8,
) -> anyhow::Result<[Z; COUNTERS]> {
    assert!(
        COUNTERS > 0,
        "a PRF group must contain at least one counter"
    );
    let limit = 1_u128 << 104;
    if ctr >= limit || COUNTERS as u128 > limit - ctr {
        let invalid = ctr.max(limit);
        return Err(anyhow_error_and_log(format!(
            "ctr in chi must be smaller than 2^104 but was {invalid}."
        )));
    }
    if !matches!(Z::EXTENSION_DEGREE, 4 | 8) || !matches!(Z::NUM_BITS_STAT_SEC_BASE_RING, 64 | 128)
    {
        let mut values = [Z::ZERO; COUNTERS];
        for (offset, value) in values.iter_mut().enumerate() {
            *value = chi(pa, ctr + offset as u128, j)?;
        }
        return Ok(values);
    }

    // Nested arrays allow a const counter count without generic const arithmetic. Only the first
    // COUNTERS * degree blocks are used; both encryption and conversion use stack storage.
    let mut storage = [[AesBlock::default(); 8]; COUNTERS];
    let degree = Z::EXTENSION_DEGREE;
    let blocks = &mut storage.as_flattened_mut()[..COUNTERS * degree];
    for (offset, output_blocks) in blocks.chunks_exact_mut(degree).enumerate() {
        for (coefficient, block) in output_blocks.iter_mut().enumerate() {
            let word =
                (ctr + offset as u128) | (j as u128) << 104 | ((coefficient as u8) as u128) << 112;
            write_block(block, word);
        }
    }
    // Give the backend the complete group so it can interleave independent AES round chains.
    // Four counters supply 16 blocks for F4 and 32 for F8.
    pa.aes.encrypt_blocks(blocks);
    Ok(std::array::from_fn(|offset| {
        let first = offset * degree;
        Z::from_u128_iter(
            blocks[first..first + degree]
                .iter()
                .map(|block| u128::from_le_bytes((*block).into())),
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{B_SWITCH_SQUASH, LOG_B_SWITCH_SQUASH, STATSEC};
    use algebra::galois_rings::degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128};

    //tododp the comment doesn't work for a PR: reviewers do not know about all the candidate block writers
    // tododp maybe we should prepare a set of known-answer tests as well?
    // Keep the original byte-by-byte encoder independent of all candidate block writers.
    fn original_encoding<Z: Ring + PRSSConversions>(aes: &Aes128, ctr: u128, j: Option<u8>) -> Z {
        let num = Z::NUM_BITS_STAT_SEC_BASE_RING.div_ceil(128);
        let mut blocks: Vec<AesBlock> = (0..Z::EXTENSION_DEGREE * num)
            .map(|idx| {
                let mut block = AesBlock::from(ctr.to_le_bytes());
                block[15] = (idx % num) as u8;
                block[14] = (idx / num) as u8;
                if let Some(j) = j {
                    block[13] = j;
                }
                block
            })
            .collect();
        aes.encrypt_blocks(&mut blocks);
        Z::from_u128_chunks(
            blocks
                .iter()
                .map(|b| u128::from_le_bytes((*b).into()))
                .collect(),
        )
    }

    //tododp needs comments inline and a few lines here as well
    #[test]
    fn store_construction_matches_original_encoding() {
        fn check<Z: Ring + PRSSConversions>() {
            check_group::<Z, 8>();
            check_group::<Z, 16>();
        }
        fn check_group<Z: Ring + PRSSConversions, const COUNTERS: usize>() {
            for sid in [0, 42] {
                let psi_key = PsiAes::new(&PrfKey([23; 16]), SessionId::from(sid));
                let chi_key = ChiAes::new(&PrfKey([23; 16]), SessionId::from(sid));
                for start in [
                    0,
                    1,
                    255,
                    (1_u128 << 64) - 3,
                    (1_u128 << 112) - COUNTERS as u128,
                ] {
                    let values = psi_counters::<Z, COUNTERS>(&psi_key, start).unwrap();
                    for (offset, value) in values.iter().enumerate() {
                        let ctr = start + offset as u128;
                        let expected = original_encoding::<Z>(&psi_key.aes, ctr, None);
                        assert_eq!(psi::<Z>(&psi_key, ctr).unwrap(), expected);
                        assert_eq!(psi_iter::<Z>(&psi_key, ctr).unwrap(), expected);
                        assert_eq!(*value, expected);
                    }
                }
                for start in [
                    0,
                    1,
                    255,
                    (1_u128 << 64) - 3,
                    (1_u128 << 104) - COUNTERS as u128,
                ] {
                    for j in [0, 1, 4, 255] {
                        let values = chi_counters::<Z, COUNTERS>(&chi_key, start, j).unwrap();
                        for (offset, value) in values.iter().enumerate() {
                            let ctr = start + offset as u128;
                            let expected = original_encoding::<Z>(&chi_key.aes, ctr, Some(j));
                            assert_eq!(chi::<Z>(&chi_key, ctr, j).unwrap(), expected);
                            assert_eq!(*value, expected);
                        }
                    }
                }
            }
        }
        check::<ResiduePolyF4Z64>();
        check::<ResiduePolyF4Z128>();
        check::<algebra::galois_rings::degree_8::ResiduePolyF8Z64>();
        check::<algebra::galois_rings::degree_8::ResiduePolyF8Z128>();
        check::<algebra::galois_rings::degree_3::ResiduePolyF3Z64>();
        check::<algebra::galois_rings::degree_3::ResiduePolyF3Z128>();
    }

    #[test]
    fn four_counters_match_scalar_encoding() {
        fn check<Z: Ring + PRSSConversions>() {
            let limit = 1_u128 << 112;
            for sid in [0, 42] {
                let key = PsiAes::new(&PrfKey([23; 16]), SessionId::from(sid));
                for start in [0, 255, (1_u128 << 64) - 1, limit - 4] {
                    let expected = std::array::from_fn(|offset| {
                        psi::<Z>(&key, start + offset as u128).unwrap()
                    });
                    assert_eq!(psi_counters::<Z, 4>(&key, start).unwrap(), expected);
                    for (offset, expected) in expected.into_iter().enumerate() {
                        assert_eq!(
                            psi_iter::<Z>(&key, start + offset as u128).unwrap(),
                            expected
                        );
                    }
                }
                assert_eq!(
                    psi_iter::<Z>(&key, limit - 1).unwrap(),
                    psi::<Z>(&key, limit - 1).unwrap()
                );
                for start in [limit - 3, limit - 1, limit, u128::MAX] {
                    assert!(psi_counters::<Z, 4>(&key, start).is_err());
                }
                for start in [limit, u128::MAX] {
                    assert!(psi_iter::<Z>(&key, start).is_err());
                }
            }
        }
        check::<ResiduePolyF4Z64>();
        check::<ResiduePolyF4Z128>();
        check::<algebra::galois_rings::degree_8::ResiduePolyF8Z64>();
        check::<algebra::galois_rings::degree_8::ResiduePolyF8Z128>();
        // Degree three uses the scalar fallback, which must retain the same encoding and counter bounds.
        check::<algebra::galois_rings::degree_3::ResiduePolyF3Z64>();
        check::<algebra::galois_rings::degree_3::ResiduePolyF3Z128>();
    }

    #[test]
    fn four_chi_counters_match_scalar_encoding() {
        fn check<Z: Ring + PRSSConversions>() {
            let limit = 1_u128 << 104;
            for sid in [0, 42] {
                let key = ChiAes::new(&PrfKey([23; 16]), SessionId::from(sid));
                for j in [1, 4, 255] {
                    for start in [0, 255, (1_u128 << 64) - 1, limit - 4] {
                        let expected = std::array::from_fn(|offset| {
                            chi::<Z>(&key, start + offset as u128, j).unwrap()
                        });
                        assert_eq!(chi_counters::<Z, 4>(&key, start, j).unwrap(), expected);
                    }
                    for start in [limit - 3, limit - 1, limit, u128::MAX] {
                        assert!(chi_counters::<Z, 4>(&key, start, j).is_err());
                    }
                }
            }
        }
        check::<ResiduePolyF4Z64>();
        check::<ResiduePolyF4Z128>();
        check::<algebra::galois_rings::degree_8::ResiduePolyF8Z64>();
        check::<algebra::galois_rings::degree_8::ResiduePolyF8Z128>();
        // Other extension degrees use the scalar fallback with the same threshold byte and counter bounds.
        check::<algebra::galois_rings::degree_3::ResiduePolyF3Z64>();
        check::<algebra::galois_rings::degree_3::ResiduePolyF3Z128>();
    }

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
