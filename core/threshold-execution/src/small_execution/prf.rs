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

/// Number of AES blocks encrypted per `encrypt_blocks` call in psi/chi.
/// One stack buffer covers the common degree-8 case. This is not the ARM backend's
/// parallel width: its AES-128 implementation processes 21 blocks at a time.
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

/// Scalar comparison kernel: keep one counter per encryption call, but avoid the conversion Vec.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn psi_iter<Z: Ring + PRSSConversions>(pa: &PsiAes, ctr: u128) -> anyhow::Result<Z> {
    // Match the paired experiment's ring coverage. Other shapes retain the
    // original block encoding and conversion rather than broadening this detour.
    if !matches!(Z::EXTENSION_DEGREE, 4 | 8) || !matches!(Z::NUM_BITS_STAT_SEC_BASE_RING, 64 | 128)
    {
        return psi(pa, ctr);
    }
    if ctr >= 1 << 112 {
        return Err(anyhow_error_and_log(format!(
            "ctr in psi must be smaller than 2^112 but was {ctr}."
        )));
    }

    // For these rings, the original helper's outer loop executes once: one
    // AES block per coefficient, with four or eight coefficients. Keep the same
    // stack-buffer capacity and one encrypt_blocks call for this counter.
    let mut blocks = [AesBlock::default(); AES_BATCH];
    let blocks = &mut blocks[..Z::EXTENSION_DEGREE];
    for (coefficient, block) in blocks.iter_mut().enumerate() {
        block.copy_from_slice(&ctr.to_le_bytes());
        block[14] = coefficient as u8;
        block[15] = 0;
    }
    pa.aes.encrypt_blocks(blocks);

    // The only intended algorithmic difference is direct conversion from the
    // encrypted blocks. There is no second counter or second accumulator here.
    Ok(Z::from_u128_iter(
        blocks
            .iter()
            .map(|block| u128::from_le_bytes((*block).into())),
    ))
}

/// Experimental full-group kernel for comparing counter counts under the same AES key.
#[cfg(any(test, feature = "testing"))]
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

    // Nested arrays allow a const counter count on stable Rust without generic
    // const arithmetic in the type. Only the first COUNTERS * degree blocks are
    // used. Nothing is heap-allocated, including the conversion to ring values.
    let mut storage = [[AesBlock::default(); 8]; COUNTERS];
    let degree = Z::EXTENSION_DEGREE;
    let blocks = &mut storage.as_flattened_mut()[..COUNTERS * degree];
    for (offset, output_blocks) in blocks.chunks_exact_mut(degree).enumerate() {
        for (coefficient, block) in output_blocks.iter_mut().enumerate() {
            block.copy_from_slice(&(ctr + offset as u128).to_le_bytes());
            block[14] = coefficient as u8;
            block[15] = 0;
        }
    }
    // Present the complete group to the backend. Splitting here at AES_BATCH=8
    // would prevent the ARM backend from ever reaching its 21-block path.
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

/// Experimental PRSS kernel: encrypt two consecutive counters under the same key.
/// The outputs have exactly the same encoding as two calls to `psi`.
pub(crate) fn psi_pair<Z: Ring + PRSSConversions>(
    pa: &PsiAes,
    ctr: u128,
) -> anyhow::Result<[Z; 2]> {
    // Keep this first experiment limited to the rings covered by our benchmarks.
    // Other ring shapes retain the scalar implementation and its validation.
    if !matches!(Z::EXTENSION_DEGREE, 4 | 8) || !matches!(Z::NUM_BITS_STAT_SEC_BASE_RING, 64 | 128)
    {
        return Ok([psi(pa, ctr)?, psi(pa, ctr + 1)?]);
    }

    // A full pair needs both counters to be valid. Checking before addition also
    // prevents overflow for an invalid starting counter near u128::MAX.
    // Report the first invalid counter, as sequential scalar calls would do.
    let limit = 1_u128 << 112;
    if ctr >= limit - 1 {
        let invalid = ctr.max(limit);
        return Err(anyhow_error_and_log(format!(
            "ctr in psi must be smaller than 2^112 but was {invalid}."
        )));
    }

    // Both Z64 and Z128 use one AES block per coefficient. F4 therefore needs
    // 2 * 4 = 8 blocks, which reaches the AES-NI backend's parallel batch width.
    // F8 needs 16 blocks. This is one encryption call over the combined slice,
    // rather than two calls that each present too few blocks on F4.
    let degree = Z::EXTENSION_DEGREE;
    let mut blocks = [AesBlock::default(); 16];
    let blocks = &mut blocks[..2 * degree];
    for (offset, output_blocks) in blocks.chunks_exact_mut(degree).enumerate() {
        for (coefficient, block) in output_blocks.iter_mut().enumerate() {
            block.copy_from_slice(&(ctr + offset as u128).to_le_bytes());
            block[14] = coefficient as u8;
            block[15] = 0; // First and only block for this coefficient.
        }
    }
    pa.aes.encrypt_blocks(blocks);

    // Read coefficients straight from the encrypted blocks into
    // each ring value. The Vec-taking conversion did not get optimized away in
    // this paired loop: it allocated and freed two buffers for every subset.
    // The iterator conversion fills the fixed-size ring arrays without that heap traffic.
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

    Ok(encrypt_indexed_prf_blocks(&pa.aes, ctr, |block, i, v| {
        block[15] = v as u8;
        block[14] = i as u8;
        block[13] = j;
    }))
}

/// Access to PRF kernels for component benchmarks.
#[cfg(feature = "testing")]
pub mod benchmarking {
    pub use super::PrfKey;
    use super::*;

    /// Holds the expanded key for the mask PRF.
    pub struct PhiAes(super::PhiAes);
    impl PhiAes {
        /// Expands a session key outside benchmark timing.
        pub fn new(key: &PrfKey, sid: SessionId) -> Self {
            Self(super::PhiAes::new(key, sid))
        }
    }
    /// Holds the expanded key for the PRSS PRF.
    pub struct PsiAes(super::PsiAes);
    impl PsiAes {
        /// Expands a session key outside benchmark timing.
        pub fn new(key: &PrfKey, sid: SessionId) -> Self {
            Self(super::PsiAes::new(key, sid))
        }
    }
    /// Holds the expanded key for the PRZS PRF.
    pub struct ChiAes(super::ChiAes);
    impl ChiAes {
        /// Expands a session key outside benchmark timing.
        pub fn new(key: &PrfKey, sid: SessionId) -> Self {
            Self(super::ChiAes::new(key, sid))
        }
    }
    /// Evaluates the PRSS PRF at one counter.
    #[inline]
    pub fn psi<Z: Ring + PRSSConversions>(pa: &PsiAes, ctr: u128) -> anyhow::Result<Z> {
        super::psi(&pa.0, ctr)
    }
    /// Evaluates the PRZS PRF at one counter and index.
    #[inline]
    pub fn chi<Z: Ring + PRSSConversions>(pa: &ChiAes, ctr: u128, j: u8) -> anyhow::Result<Z> {
        super::chi(&pa.0, ctr, j)
    }

    /// Encrypts consecutive counters together for the grouped-PRF experiment.
    /// Panics for invalid counters, group sizes outside 1..=8, or rings other than F4/F8 over Z64/Z128.
    pub fn psi_group<Z: Ring + PRSSConversions, const N: usize>(
        pa: &PsiAes,
        start: u128,
    ) -> [Z; N] {
        encrypt_counter_group(&pa.0.aes, start, None)
    }

    /// Encrypts consecutive counters with one threshold index for the grouped-PRF experiment.
    /// Panics for invalid counters, group sizes outside 1..=8, or rings other than F4/F8 over Z64/Z128.
    pub fn chi_group<Z: Ring + PRSSConversions, const N: usize>(
        pa: &ChiAes,
        start: u128,
        j: u8,
    ) -> [Z; N] {
        encrypt_counter_group(&pa.0.aes, start, Some(j))
    }

    fn encrypt_counter_group<Z: Ring + PRSSConversions, const N: usize>(
        aes: &Aes128,
        start: u128,
        threshold_index: Option<u8>,
    ) -> [Z; N] {
        assert!((1..=8).contains(&N));
        assert!(matches!(Z::EXTENSION_DEGREE, 4 | 8));
        assert!(matches!(Z::NUM_BITS_STAT_SEC_BASE_RING, 64 | 128));
        let limit = if threshold_index.is_some() {
            1 << 104
        } else {
            1 << 112
        };
        assert!(start < limit && (N as u128) <= limit - start);

        // One block per coefficient; keep scratch space off the heap for all measured groups.
        let mut blocks = [AesBlock::default(); 8 * 8];
        let blocks = &mut blocks[..N * Z::EXTENSION_DEGREE];
        for (offset, output_blocks) in blocks.chunks_exact_mut(Z::EXTENSION_DEGREE).enumerate() {
            for (coefficient, block) in output_blocks.iter_mut().enumerate() {
                block.copy_from_slice(&(start + offset as u128).to_le_bytes());
                block[14] = coefficient as u8;
                block[15] = 0;
                if let Some(j) = threshold_index {
                    block[13] = j;
                }
            }
        }
        aes.encrypt_blocks(blocks);
        std::array::from_fn(|offset| {
            let first = offset * Z::EXTENSION_DEGREE;
            Z::from_u128_chunks(
                blocks[first..first + Z::EXTENSION_DEGREE]
                    .iter()
                    .map(|block| u128::from_le_bytes((*block).into()))
                    .collect(),
            )
        })
    }

    /// Evaluates the mask PRF over a counter range.
    #[inline]
    pub fn phi_range(
        pa: &PhiAes,
        start: u128,
        count: usize,
        bd1: u128,
    ) -> anyhow::Result<Vec<i128>> {
        super::phi_range(&pa.0, start, count, bd1)
    }
    #[cfg(test)]
    mod grouped_tests {
        use super::*;
        use algebra::galois_rings::{
            degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128},
            degree_8::{ResiduePolyF8Z64, ResiduePolyF8Z128},
        };

        fn check_group<Z: Ring + PRSSConversions, const N: usize>() {
            let key = PrfKey([23; 16]);
            let psi_key = PsiAes::new(&key, SessionId::from(42));
            let chi_key = ChiAes::new(&key, SessionId::from(42));
            for start in [0, 255, (1 << 64) - 1, (1 << 112) - N as u128] {
                assert_eq!(
                    psi_group::<Z, N>(&psi_key, start),
                    std::array::from_fn(|i| { psi::<Z>(&psi_key, start + i as u128).unwrap() })
                );
            }
            for start in [0, 255, (1 << 64) - 1, (1 << 104) - N as u128] {
                for j in [1, 4, 255] {
                    assert_eq!(
                        chi_group::<Z, N>(&chi_key, start, j),
                        std::array::from_fn(|i| {
                            chi::<Z>(&chi_key, start + i as u128, j).unwrap()
                        })
                    );
                }
            }
        }

        #[test]
        fn groups_match_scalar_prfs() {
            fn check_ring<Z: Ring + PRSSConversions>() {
                check_group::<Z, 1>();
                check_group::<Z, 2>();
                check_group::<Z, 4>();
                check_group::<Z, 8>();
            }
            check_ring::<ResiduePolyF4Z64>();
            check_ring::<ResiduePolyF4Z128>();
            check_ring::<ResiduePolyF8Z64>();
            check_ring::<ResiduePolyF8Z128>();
        }

        #[test]
        #[should_panic]
        fn psi_group_rejects_crossing_limit() {
            let key = PsiAes::new(&PrfKey([23; 16]), SessionId::from(42));
            psi_group::<ResiduePolyF4Z128, 2>(&key, (1 << 112) - 1);
        }

        #[test]
        #[should_panic]
        fn chi_group_rejects_counter_overflow() {
            let key = ChiAes::new(&PrfKey([23; 16]), SessionId::from(42));
            chi_group::<ResiduePolyF4Z128, 2>(&key, u128::MAX, 1);
        }
    }
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
