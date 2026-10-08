//! AES-based PRFs: psi for PRSS, chi for PRZS and phi for PRSS-Mask.
//!
//! Hot paths: `accumulate_psi_counters` and `accumulate_chi_counters`, called from the inner loops of the PRSS and
//! PRZS kernels in `prss.rs`, and `phi_range` for masks. `psi` and `chi` evaluate one counter. They serve the
//! checks, rings with several AES blocks per coefficient, and tests.
//!
//! Request entry points check counter ranges once with `check_counter_range`. The PRFs assert the same bounds.

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

/// Counters of psi stay below 2^112: bytes 14 and 15 of its AES input hold the coefficient and block indices.
pub(crate) const PSI_COUNTER_BITS: u32 = 112;
/// Counters of chi stay below 2^104: byte 13 also holds the threshold index.
pub(crate) const CHI_COUNTER_BITS: u32 = 104;
/// Counters of phi stay below 2^120: byte 15 holds the block index.
pub(crate) const PHI_COUNTER_BITS: u32 = 120;
/// Largest phi bound: `-bd1 + (AES mod 2 * bd1)` must not overflow an `i128`.
pub(crate) const PHI_MAX_BOUND: u128 = 1 << 126;

/// Returns true if the `count` counters starting at `ctr` are all below `2^bits`.
fn counters_fit(ctr: u128, count: u128, bits: u32) -> bool {
    count == 0 || ctr.checked_add(count).is_some_and(|end| end <= 1 << bits)
}

/// Returns an error unless the `count` counters starting at `ctr` are all below `2^bits`.
/// Request entry points call this once per request. The PRFs below then assert the same bound, so a failure there is
/// a bug: a larger counter would overlap the index bytes and repeat PRF inputs.
pub(crate) fn check_counter_range(
    prf: &str,
    ctr: u128,
    count: u128,
    bits: u32,
) -> anyhow::Result<()> {
    if counters_fit(ctr, count, bits) {
        Ok(())
    } else {
        Err(anyhow_error_and_log(format!(
            "{prf} counters must stay below 2^{bits}, but the request needs {count} counters from {ctr}"
        )))
    }
}

/// Panics unless the `count` counters starting at `ctr` are all below `2^bits`.
#[inline(always)]
fn assert_counter_range(prf: &str, ctr: u128, count: u128, bits: u32) {
    // Request entry points reject such ranges with an error first (see `check_counter_range`).
    assert!(
        counters_fit(ctr, count, bits),
        "{prf} counters from {ctr} (count {count}) reach 2^{bits}; the caller did not check the range"
    );
}

//NOTE: I BELIEVE WE NEVER NEED PRSS-MASK TO GENERATE MASK BIGGER THAN 2^126 EVEN FOR BGV
//AFAICT, ONLY USED IN BGV DDEC WITH BD1<Q1 AND Q1 IS 94BIT LONG
/// Function Phi that generates bounded randomness for PRSS-Mask.Next(), evaluated over the
/// contiguous counter range `[start, start + count)`.
///
/// Each output is `-bd1 + (AES(ctr) mod 2 * bd1)`, uniform in `[-bd1, bd1)`. One `encrypt_blocks` call covers the
/// whole range. Panics if `bd1` exceeds [`PHI_MAX_BOUND`] or a counter reaches `2^PHI_COUNTER_BITS`; the caller
/// checks both.
pub(crate) fn phi_range(pa: &PhiAes, start: u128, count: usize, bd1: u128) -> Vec<i128> {
    // mask_next_vec rejects larger bounds with an error first.
    assert!(bd1 <= PHI_MAX_BOUND, "phi bound {bd1} exceeds 2^126");
    assert_counter_range("phi", start, count as u128, PHI_COUNTER_BITS);

    // Number of AES blocks per value, currently limited to 1. See NOTE above.
    let v = (((bd1 + 1) as f32).log2() / 128_f32).ceil() as u32;
    debug_assert_eq!(v, 1);

    // TODO iterate over blocks from 0..v here, if we ever need Bd1 > 2^126
    // The counter bound keeps byte 15, the block index v, zero.
    let mut blocks: Vec<AesBlock> = (0..count)
        .map(|k| AesBlock::from((start + k as u128).to_le_bytes()))
        .collect();

    // single pipelined AES call over the whole range
    pa.aes.encrypt_blocks(&mut blocks);

    let modulus = 2 * bd1;
    let neg_bd1 = -(bd1 as i128);
    blocks
        .into_iter()
        .map(|block| neg_bd1 + (u128::from_le_bytes(block.into()) % modulus) as i128)
        .collect()
}

/// Builds the complete block before writing it, avoiding overlapping writes to its counter and index bytes.
#[inline(always)]
fn write_block(block: &mut AesBlock, word: u128) {
    *block = AesBlock::from(word.to_le_bytes());
}

/// Number of AES blocks per `encrypt_blocks` call in scalar psi/chi. One buffer covers a degree-eight ring.
const AES_BATCH: usize = 8;

/// Cold path: scalar psi/chi for checks and for rings with several AES blocks per coefficient.
/// The PRSS/PRZS kernels use [`accumulate_psi_counters`] and [`accumulate_chi_counters`] instead.
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

/// Evaluates the PRSS function psi at `ctr` for one subset key.
///
/// Each coefficient, and each 128-bit limb of it, is one AES-128 block with input `ctr | v << 120 | i << 112`,
/// where `i` is the coefficient index and `v` the limb index.
/// Panics if `ctr >= 2^112`, because larger counters would overlap the index bytes. Request entry points check the
/// range first.
pub(crate) fn psi<Z: Ring + PRSSConversions>(pa: &PsiAes, ctr: u128) -> Z {
    assert_counter_range("psi", ctr, 1, PSI_COUNTER_BITS);
    // Byte 15 (bits 120..128) holds the limb index v, byte 14 (bits 112..120) the coefficient index i.
    // The u8 casts keep the original one-byte fields; ctr < 2^112 leaves both bytes zero, so OR places them.
    encrypt_indexed_prf_blocks(&pa.aes, ctr, |i, v| {
        ((v as u8) as u128) << 120 | ((i as u8) as u128) << 112
    })
}

/// Evaluates the PRZS function chi at `ctr` and threshold index `j` for one subset key.
///
/// The AES inputs are those of [`psi`], plus `j << 104`.
/// Panics if `ctr >= 2^104`, because larger counters would overlap the index bytes. Request entry points check the
/// range first.
pub(crate) fn chi<Z: Ring + PRSSConversions>(pa: &ChiAes, ctr: u128, j: u8) -> Z {
    assert_counter_range("chi", ctr, 1, CHI_COUNTER_BITS);
    // As in psi, plus j in byte 13 (bits 104..112); ctr < 2^104 leaves that byte zero too.
    encrypt_indexed_prf_blocks(&pa.aes, ctr, |i, v| {
        ((v as u8) as u128) << 120 | ((i as u8) as u128) << 112 | (j as u128) << 104
    })
}

/// Hot path: encrypts `COUNTERS` consecutive counters with one AES call and adds `coefficient` times each output to
/// `sums`. Each counter uses `DEGREE` blocks, one per coefficient, with the coefficient index in byte 14.
///
/// The outputs are read directly from the encrypted blocks. Returning them as an array instead makes LLVM copy large
/// Z128 groups when it does not unroll the caller's loop.
#[inline(always)]
fn accumulate_counter_blocks<
    Z: Ring + PRSSConversions,
    const COUNTERS: usize,
    const DEGREE: usize,
>(
    aes: &Aes128,
    ctr: u128,
    indices: u128,
    coefficient: Z,
    sums: &mut [Z; COUNTERS],
) {
    // The caller selects DEGREE from Z, so this folds away.
    assert_eq!(DEGREE, Z::EXTENSION_DEGREE);
    // Every block is written below, so the compiler drops the zero initialization.
    let mut blocks = [[AesBlock::default(); DEGREE]; COUNTERS];
    for (offset, counter_blocks) in blocks.iter_mut().enumerate() {
        for (coefficient_index, block) in counter_blocks.iter_mut().enumerate() {
            let word =
                (ctr + offset as u128) | indices | ((coefficient_index as u8) as u128) << 112;
            write_block(block, word);
        }
    }
    // Give the backend the complete group so it can interleave independent AES round chains.
    aes.encrypt_blocks(blocks.as_flattened_mut());
    for (sum, counter_blocks) in sums.iter_mut().zip(&blocks) {
        *sum += coefficient
            * Z::from_u128_iter(
                counter_blocks
                    .iter()
                    .map(|block| u128::from_le_bytes((*block).into())),
            );
    }
}

/// Adds `coefficient * scalar(ctr + offset)` to `sums[offset]`, using one AES call for the whole group when each
/// coefficient fits in one block. `indices` holds the PRF's fixed index bytes; `scalar` evaluates one counter of the
/// same PRF.
#[inline(always)]
fn accumulate_counters<Z: Ring + PRSSConversions, const COUNTERS: usize>(
    aes: &Aes128,
    ctr: u128,
    indices: u128,
    coefficient: Z,
    sums: &mut [Z; COUNTERS],
    scalar: impl Fn(u128) -> Z,
) {
    match (Z::EXTENSION_DEGREE, Z::NUM_BITS_STAT_SEC_BASE_RING) {
        (4, 64 | 128) => {
            accumulate_counter_blocks::<Z, COUNTERS, 4>(aes, ctr, indices, coefficient, sums)
        }
        (8, 64 | 128) => {
            accumulate_counter_blocks::<Z, COUNTERS, 8>(aes, ctr, indices, coefficient, sums)
        }
        // Cold path: other rings use the general encoding, one counter at a time.
        _ => {
            for (offset, sum) in sums.iter_mut().enumerate() {
                *sum += coefficient * scalar(ctr + offset as u128);
            }
        }
    }
}

/// Adds `coefficient * psi(pa, ctr + offset)` to `sums[offset]` for each offset, with the encoding of [`psi`].
/// Panics if `COUNTERS` is zero or a counter reaches `2^PSI_COUNTER_BITS`; the caller checks the range.
pub(crate) fn accumulate_psi_counters<Z: Ring + PRSSConversions, const COUNTERS: usize>(
    pa: &PsiAes,
    ctr: u128,
    coefficient: Z,
    sums: &mut [Z; COUNTERS],
) {
    assert!(
        COUNTERS > 0,
        "a PRF group must contain at least one counter"
    );
    assert_counter_range("psi", ctr, COUNTERS as u128, PSI_COUNTER_BITS);
    accumulate_counters(&pa.aes, ctr, 0, coefficient, sums, |ctr| psi(pa, ctr));
}

/// Adds `coefficient * chi(pa, ctr + offset, j)` to `sums[offset]` for each offset, with the encoding of [`chi`].
/// Panics if `COUNTERS` is zero or a counter reaches `2^CHI_COUNTER_BITS`; the caller checks the range.
pub(crate) fn accumulate_chi_counters<Z: Ring + PRSSConversions, const COUNTERS: usize>(
    pa: &ChiAes,
    ctr: u128,
    j: u8,
    coefficient: Z,
    sums: &mut [Z; COUNTERS],
) {
    assert!(
        COUNTERS > 0,
        "a PRF group must contain at least one counter"
    );
    assert_counter_range("chi", ctr, COUNTERS as u128, CHI_COUNTER_BITS);
    accumulate_counters(&pa.aes, ctr, (j as u128) << 104, coefficient, sums, |ctr| {
        chi(pa, ctr, j)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{B_SWITCH_SQUASH, LOG_B_SWITCH_SQUASH, STATSEC};
    use algebra::galois_rings::degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128};

    // Encode the counter and indices byte by byte, without using the production block writer.
    // This provides an independent reference for the scalar and batched PRFs' input layout.
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

    // Evaluates consecutive counters through the grouped PRF with a unit coefficient.
    fn psi_group<Z: Ring + PRSSConversions, const N: usize>(key: &PsiAes, ctr: u128) -> [Z; N] {
        let mut values = [Z::ZERO; N];
        accumulate_psi_counters(key, ctr, Z::ONE, &mut values);
        values
    }

    fn chi_group<Z: Ring + PRSSConversions, const N: usize>(
        key: &ChiAes,
        ctr: u128,
        j: u8,
    ) -> [Z; N] {
        let mut values = [Z::ZERO; N];
        accumulate_chi_counters(key, ctr, j, Z::ONE, &mut values);
        values
    }

    // Scalar and batched evaluation must preserve the same counter/index encoding and coefficient order.
    // Compare each output with the byte-wise reference, including carries between counter bytes and the last valid group.
    // F4/F8 exercise the grouped path; F3 exercises its scalar fallback. Both base rings check coefficient conversion.
    #[test]
    fn store_construction_matches_original_encoding() {
        fn check<Z: Ring + PRSSConversions>() {
            // Check both group sizes against the same reference, independently of the size used by the PRSS kernel.
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
                    // Carry into the second byte within a group.
                    255,
                    // Carry between the two halves of the AES block.
                    (1_u128 << 64) - 3,
                    // The final output uses psi's last valid counter.
                    (1_u128 << 112) - COUNTERS as u128,
                ] {
                    let values = psi_group::<Z, COUNTERS>(&psi_key, start);
                    for (offset, value) in values.iter().enumerate() {
                        let ctr = start + offset as u128;
                        let expected = original_encoding::<Z>(&psi_key.aes, ctr, None);
                        assert_eq!(psi::<Z>(&psi_key, ctr), expected);
                        // A group of one is the short-final-group path of the PRSS kernel.
                        assert_eq!(psi_group::<Z, 1>(&psi_key, ctr), [expected]);
                        assert_eq!(*value, expected);
                    }
                }
                // Chi reserves an extra byte for j, so its counter bound is 2^104 rather than psi's 2^112.
                for start in [
                    0,
                    1,
                    255,
                    (1_u128 << 64) - 3,
                    (1_u128 << 104) - COUNTERS as u128,
                ] {
                    // Include zero and all bits set to catch misplaced or truncated threshold-index bytes.
                    for j in [0, 1, 4, 255] {
                        let values = chi_group::<Z, COUNTERS>(&chi_key, start, j);
                        for (offset, value) in values.iter().enumerate() {
                            let ctr = start + offset as u128;
                            let expected = original_encoding::<Z>(&chi_key.aes, ctr, Some(j));
                            assert_eq!(chi::<Z>(&chi_key, ctr, j), expected);
                            assert_eq!(chi_group::<Z, 1>(&chi_key, ctr, j), [expected]);
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

    // Fixed AES-128-ECB outputs generated with OpenSSL, independently of the Rust encoders and AES backend.
    // These pin session/domain key derivation, input byte order, coefficient order, and Z64's low-half truncation.
    // Generator: OpenSSL 4.0.3 29 Sep 2026 (Library: OpenSSL 4.0.3 29 Sep 2026).
    // Host: macOS 27.0.1 (build 26A434), Apple M5 Max (Mac17,7; 18 cores).
    // Commands used, wrapped for readability; printf concatenates the hex blocks without separators.
    // psi:
    // printf '%s' \
    //   'ffffffffffffffff0000000000000000ffffffffffffffff0000000000000100' \
    //   'ffffffffffffffff0000000000000200ffffffffffffffff0000000000000300' \
    //   '0000000000000000010000000000000000000000000000000100000000000100' \
    //   '0000000000000000010000000000020000000000000000000100000000000300' \
    //   | xxd -r -p | openssl enc -aes-128-ecb -K 072543618fadcbe9f8dabc9e70523416 -nosalt -nopad | xxd -p -c 256
    // chi:
    // printf '%s' \
    //   'ffffffffffffffff0000000000a50000ffffffffffffffff0000000000a50100' \
    //   'ffffffffffffffff0000000000a50200ffffffffffffffff0000000000a50300' \
    //   '00000000000000000100000000a5000000000000000000000100000000a50100' \
    //   '00000000000000000100000000a5020000000000000000000100000000a50300' \
    //   | xxd -r -p | openssl enc -aes-128-ecb -K 062543618fadcbe9f8dabc9e70523416 -nosalt -nopad | xxd -p -c 256
    #[test]
    fn psi_chi_known_answers() {
        let key = PrfKey([0x17; 16]);
        let sid = SessionId::from(0x0123456789abcdef_fedcba9876543210_u128);
        let psi_key = PsiAes::new(&key, sid);
        let chi_key = ChiAes::new(&key, sid);
        // Consecutive counters cross the 64-bit carry; j sets both low and high bits of chi's index byte.
        let first_counter = u64::MAX as u128;
        let j = 0xa5;
        // OpenSSL keys: psi=072543618fadcbe9f8dabc9e70523416, chi=062543618fadcbe9f8dabc9e70523416.
        // Each row contains four encrypted blocks interpreted as little-endian u128 coefficients.
        let expected_psi = [
            [
                0xbd97cd92845ede50fb3b62d1b6fcec8a_u128,
                0x92335305f109de4b97143f475b826968,
                0xa92c6ab666a1fcf0026c9b8efcbe3b9d,
                0xb76b2a4cfcf86b34d0da67caa8248926,
            ],
            [
                0x0cecd5013c98a503f8bfbab2ed7bde52,
                0x4aeb14867a1b9adef700a61e59f6893f,
                0x3aaeb5c53f83feb24fbc9791b9a6c90b,
                0xa3060312f0c5dd36695906a5d839ce96,
            ],
        ];
        let expected_chi = [
            [
                0x7029f3ae30775cd217b90f1c45625783_u128,
                0xf3cfd51e048aba13e3241ac878a5e43e,
                0xcdfabff0e7036b6ca56ffde04ae7f699,
                0xb1c9ef830777eafb93b8354ac88a2ec4,
            ],
            [
                0x4964b524f5851c6184153d98c849120e,
                0xb8e796e503e7409f6eb3279b3be9a72b,
                0x2cc7457d00028ee7e22241d5f2e451c2,
                0x31af557614a25a6488bfd8547f8c033f,
            ],
        ];
        for (offset, (psi_coefs, chi_coefs)) in
            expected_psi.into_iter().zip(expected_chi).enumerate()
        {
            let counter = first_counter + offset as u128;
            assert_eq!(
                psi::<ResiduePolyF4Z128>(&psi_key, counter)
                    .coefs
                    .map(|c| c.0),
                psi_coefs
            );
            assert_eq!(
                psi_group::<ResiduePolyF4Z128, 1>(&psi_key, counter)[0]
                    .coefs
                    .map(|c| c.0),
                psi_coefs
            );
            assert_eq!(
                chi::<ResiduePolyF4Z128>(&chi_key, counter, j)
                    .coefs
                    .map(|c| c.0),
                chi_coefs
            );
            // Compare coefficient arrays directly: expected values must not use the production conversion helpers.
            assert_eq!(
                psi::<ResiduePolyF4Z64>(&psi_key, counter)
                    .coefs
                    .map(|c| c.0),
                psi_coefs.map(|c| c as u64)
            );
            assert_eq!(
                psi_group::<ResiduePolyF4Z64, 1>(&psi_key, counter)[0]
                    .coefs
                    .map(|c| c.0),
                psi_coefs.map(|c| c as u64)
            );
            assert_eq!(
                chi::<ResiduePolyF4Z64>(&chi_key, counter, j)
                    .coefs
                    .map(|c| c.0),
                chi_coefs.map(|c| c as u64)
            );
        }
    }

    // The grouped PRFs add coefficient times each output to existing sums, in counter order.
    #[test]
    fn grouped_prfs_accumulate_scaled_outputs() {
        fn check<Z: Ring + PRSSConversions>() {
            let psi_key = PsiAes::new(&PrfKey([23; 16]), SessionId::from(42));
            let chi_key = ChiAes::new(&PrfKey([23; 16]), SessionId::from(42));
            for start in [0, 255, (1_u128 << 64) - 1] {
                // Nonzero sums and a non-unit coefficient check that outputs are scaled and added in place.
                let coefficient = psi::<Z>(&psi_key, 7);
                let initial: [Z; 4] =
                    std::array::from_fn(|offset| psi(&psi_key, 100 + offset as u128));
                let mut sums = initial;
                accumulate_psi_counters(&psi_key, start, coefficient, &mut sums);
                for (offset, sum) in sums.into_iter().enumerate() {
                    let ctr = start + offset as u128;
                    assert_eq!(sum, initial[offset] + coefficient * psi(&psi_key, ctr));
                }
                for j in [1, 4, 255] {
                    let mut sums = initial;
                    accumulate_chi_counters(&chi_key, start, j, coefficient, &mut sums);
                    for (offset, sum) in sums.into_iter().enumerate() {
                        let ctr = start + offset as u128;
                        assert_eq!(sum, initial[offset] + coefficient * chi(&chi_key, ctr, j));
                    }
                }
            }
        }
        check::<ResiduePolyF4Z64>();
        check::<ResiduePolyF4Z128>();
        check::<algebra::galois_rings::degree_8::ResiduePolyF8Z64>();
        check::<algebra::galois_rings::degree_8::ResiduePolyF8Z128>();
        // Degree three uses the scalar fallback.
        check::<algebra::galois_rings::degree_3::ResiduePolyF3Z64>();
        check::<algebra::galois_rings::degree_3::ResiduePolyF3Z128>();
    }

    #[test]
    fn counter_range_check_covers_the_whole_request() {
        let bits = PSI_COUNTER_BITS;
        let limit = 1_u128 << bits;
        for (ctr, count) in [
            (0, 0),
            (0, 1),
            (limit - 1, 1),
            (limit - 4, 4),
            (limit, 0),
            (u128::MAX, 0),
        ] {
            assert!(
                check_counter_range("psi", ctr, count, bits).is_ok(),
                "{ctr} + {count}"
            );
        }
        // The last case would wrap around without checked addition.
        for (ctr, count) in [
            (limit, 1),
            (limit - 1, 2),
            (limit - 3, 4),
            (u128::MAX, 1),
            (1, u128::MAX),
        ] {
            let error = check_counter_range("psi", ctr, count, bits).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("psi counters must stay below 2^112")
            );
        }
    }

    // The PRFs panic on counters past their limit: request entry points must reject those ranges first.
    #[test]
    #[should_panic(expected = "psi counters from")]
    fn psi_panics_at_its_counter_limit() {
        let key = PsiAes::new(&PrfKey([23; 16]), SessionId::from(0));
        psi::<ResiduePolyF4Z64>(&key, 1 << PSI_COUNTER_BITS);
    }

    #[test]
    #[should_panic(expected = "chi counters from")]
    fn chi_panics_at_its_counter_limit() {
        let key = ChiAes::new(&PrfKey([23; 16]), SessionId::from(0));
        chi::<ResiduePolyF4Z64>(&key, 1 << CHI_COUNTER_BITS, 1);
    }

    #[test]
    #[should_panic(expected = "psi counters from")]
    fn psi_group_panics_if_its_last_counter_reaches_the_limit() {
        let key = PsiAes::new(&PrfKey([23; 16]), SessionId::from(0));
        psi_group::<ResiduePolyF4Z128, 4>(&key, (1 << PSI_COUNTER_BITS) - 3);
    }

    #[test]
    #[should_panic(expected = "chi counters from")]
    fn chi_group_panics_if_its_last_counter_reaches_the_limit() {
        let key = ChiAes::new(&PrfKey([23; 16]), SessionId::from(0));
        chi_group::<ResiduePolyF4Z128, 4>(&key, (1 << CHI_COUNTER_BITS) - 3, 1);
    }

    #[test]
    #[should_panic(expected = "phi counters from")]
    fn phi_panics_at_its_counter_limit() {
        let key = PhiAes::new(&PrfKey([23; 16]), SessionId::from(0));
        phi_range(&key, (1 << PHI_COUNTER_BITS) - 1, 2, B_SWITCH_SQUASH);
    }

    #[test]
    #[should_panic(expected = "phi bound")]
    fn phi_panics_on_a_bound_that_could_overflow() {
        let key = PhiAes::new(&PrfKey([23; 16]), SessionId::from(0));
        phi_range(&key, 0, 1, PHI_MAX_BOUND + 1);
    }

    /// Single-value convenience wrapper over [`phi_range`] used by the phi tests.
    fn phi(pa: &PhiAes, ctr: u128, bd1: u128) -> i128 {
        phi_range(pa, ctr, 1, bd1)[0]
    }

    #[test]
    fn test_phi() {
        let key = PrfKey([123_u8; 16]);
        let aes = PhiAes::new(&key, SessionId::from(0));
        let mut prev = 0_i128;

        // test for B_SWITCH_SQUASH * 2^STATSEC  (currently even, so we can count bits using ilog2)
        for ctr in 0..100 {
            let bd1 = B_SWITCH_SQUASH * (1 << STATSEC);
            let res = phi(&aes, ctr, bd1);
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
            let res = phi(&aes, ctr, odd_bound);
            assert!(-(odd_bound as i128) <= res);
            assert!(odd_bound as i128 > res);
            assert_ne!(prev, res);
            prev = res;
        }

        assert_eq!(phi(&aes, 0, B_SWITCH_SQUASH), phi(&aes, 0, B_SWITCH_SQUASH));

        let aes_2 = PhiAes::new(&key, SessionId::from(2));
        assert_ne!(
            phi(&aes, 0, B_SWITCH_SQUASH),
            phi(&aes_2, 0, B_SWITCH_SQUASH)
        );
    }

    fn test_psi<Z: Ring + PRSSConversions>() {
        let key = PrfKey([23_u8; 16]);
        let aes = PsiAes::new(&key, SessionId::from(0));
        assert_ne!(psi::<Z>(&aes, 0), psi(&aes, 1));
        assert_eq!(psi::<Z>(&aes, 0), psi(&aes, 0));

        let aes_2 = PsiAes::new(&key, SessionId::from(2));
        assert_ne!(psi::<Z>(&aes, 0), psi(&aes_2, 0));
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
        assert_ne!(chi::<Z>(&aes, 0, 0), chi(&aes, 1, 0));
        assert_ne!(chi::<Z>(&aes, 0, 0), chi(&aes, 0, 1));
        assert_eq!(chi::<Z>(&aes, 0, 0), chi(&aes, 0, 0));

        let aes_2 = ChiAes::new(&key, SessionId::from(2));
        assert_ne!(chi::<Z>(&aes, 0, 0), chi(&aes_2, 0, 0));
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
        assert_ne!(chi::<Z>(&chiaes, 0, 0), psi(&psiaes, 0));

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
